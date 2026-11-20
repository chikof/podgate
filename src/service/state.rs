//! Runtime state of services: what balancers, health checks and outlier ejection read and write
//! per server, kept outside the routing table so a snapshot push does not reset it.
//!
//! # What lives here
//!
//! - [`ServerState`]: per server, all atomics, so every writer owns its field and none reshapes
//!   the struct. `healthy` is written by health checks, `ejected_until_ms` by outlier
//!   ejection, `active` by every [`Lease`], `ewma_us` and `ewma_at_ms` by the `p2c_ewma`
//!   balancer. Balancers read [`ServerState::available`] and nothing else about health.
//! - [`ServiceState`]: per service, the turn counter of the cyclic balancers (`round_robin`,
//!   `weighted_round_robin`) and the source of pseudo-random numbers of the random ones.
//! - [`Lease`]: what one request holds of the server it was sent to. Taking it counts the
//!   request in `active`, dropping it uncounts it, and [`Lease::responded`] feeds the latency
//!   to the balancer that asked for it.
//!
//! # Lifetime: the registry
//!
//! A service compiles with fresh state. At the one swap site ([`crate::table::TableHandle`]
//! calls `Registry::settle` just before a table goes live, like the canary) every server and
//! service that the previous table also had, with the same fingerprint of its declaration
//! ([`fingerprint`]), takes over the previous state; anything else keeps the fresh state and
//! replaces the old entry. A push that does not touch a service keeps its counters, its health
//! and its ejections; a service whose declaration changes, or that moves to another revision,
//! starts fresh.
//!
//! The key of a server is `(app, revision, service, server URL, fingerprint)`; `revision` is
//! empty for a service the app declares for all its revisions. The fingerprint covers the whole
//! declaration except the `servers` list, so adding a server keeps the state of the others and
//! changing the algorithm, a health check or anything else starts every server fresh. A spec
//! whose state must outlive a change of another part of the declaration (health state across an
//! algorithm change, say) refines [`fingerprint`] there.
//!
//! # Extending it
//!
//! - New per-server state: an atomic field on [`ServerState`], initialised in its `Default`. A
//!   spec never replaces the `Arc`: tables, requests and background tasks share it.
//! - A background task that writes state reads the live table and walks
//!   [`crate::service::Service::servers`]; it holds no registry handle and needs no lock.
//! - A request holds its server through a [`Lease`], which owns an `Arc<ServerState>`, so a
//!   request whose table was swapped away, or whose server left the table, still finishes
//!   against the state it started with and never panics or underflows.
//! - A new service type that needs state adds one arm to the `match` in `Registry::settle`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::Service;
use crate::router::digest;
use crate::table::CompiledApp;
use podgate_model::Declared;

/// Milliseconds since the process started, at least `1` (`0` means "not ejected" in
/// [`ServerState::ejected_until_ms`]).
#[must_use]
pub fn now_ms() -> u64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    u64::try_from(START.elapsed().as_millis())
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1)
}

/// What the balancer, the health checker and the outlier detector share about one server.
#[derive(Debug)]
pub struct ServerState {
    /// Cleared by an active health check that fails.
    pub healthy: AtomicBool,
    /// [`now_ms`] time until which the server is ejected; `0`: not ejected. Written by passive
    /// outlier detection; a value in the past means the ejection is over.
    pub ejected_until_ms: AtomicU64,
    /// Requests in flight to the server: every [`Lease`] counts one.
    pub active: AtomicU32,
    /// Exponentially weighted moving average of response latency in microseconds, written by the
    /// `p2c_ewma` balancer; `0`: no sample yet.
    pub ewma_us: AtomicU64,
    /// [`now_ms`] time of the last write of `ewma_us`, which decays with the time since.
    pub ewma_at_ms: AtomicU64,
    /// Passive outlier counters, owned by `outlier.rs`.
    pub outlier: super::outlier::State,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            ejected_until_ms: AtomicU64::new(0),
            active: AtomicU32::new(0),
            ewma_us: AtomicU64::new(0),
            ewma_at_ms: AtomicU64::new(0),
            outlier: super::outlier::State::default(),
        }
    }
}

impl ServerState {
    /// Whether the server may take a new request: healthy and not ejected.
    #[must_use]
    pub fn available(&self) -> bool {
        if !self.healthy.load(Ordering::Relaxed) {
            return false;
        }
        let until = self.ejected_until_ms.load(Ordering::Relaxed);
        until == 0 || until <= now_ms()
    }
}

/// What the balancers of one service share: a counter that survives snapshot pushes.
#[derive(Debug, Default)]
pub struct ServiceState {
    next: AtomicU64,
}

impl ServiceState {
    /// A state whose counter starts at `seed`, for tests that need a known sequence.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self {
            next: AtomicU64::new(seed),
        }
    }

    /// The next turn: `0`, `1`, `2`, and so on, shared by every request of the service.
    #[must_use]
    pub fn turn(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// The next pseudo-random number: SplitMix64 of the next turn, so concurrent callers never
    /// get the same one and nothing is locked or allocated.
    #[must_use]
    pub fn random(&self) -> u64 {
        let mut z = self
            .turn()
            .wrapping_add(1)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// What a balancer does with the latency of a finished response; see [`Lease::responded`].
pub(crate) type Observe = fn(&ServerState, Duration, u64);

/// One request's claim on a server. It counts the request in [`ServerState::active`] from the
/// pick until it is dropped, so it must live as long as the request is on the server.
///
/// It owns the state, not an index into a table: it stays valid across snapshot swaps and
/// after its server left the table.
#[derive(Debug)]
pub struct Lease {
    state: Arc<ServerState>,
    started: Instant,
    observe: Option<Observe>,
}

impl Lease {
    /// Counts one more request on `state`.
    pub(crate) fn take(state: &Arc<ServerState>, observe: Option<Observe>) -> Self {
        state.active.fetch_add(1, Ordering::Relaxed);
        Self {
            state: Arc::clone(state),
            started: Instant::now(),
            observe,
        }
    }

    /// The server's state, for code that writes flags on behalf of this request (outlier
    /// detection counts a failure against it).
    #[must_use]
    pub fn server(&self) -> &Arc<ServerState> {
        &self.state
    }

    /// Time since the request took this lease: the latency of the response once it came.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// The server answered with `status`. A response below `500` hands the time since the pick
    /// to the balancer that asked for it; a `5xx` is not a latency sample, because a server
    /// that fails fast would look fast. Only the first call counts.
    pub fn responded(&mut self, status: u16) {
        if let Some(observe) = self.observe.take().filter(|_| status < 500) {
            observe(&self.state, self.started.elapsed(), now_ms());
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A digest of everything a service declares except its `servers`: equal digests mean the
/// state of equal servers carries over a push.
#[must_use]
pub fn fingerprint(declared: &Declared) -> u64 {
    let mut config = declared.config.clone();
    config.remove("servers");
    digest((
        &*declared.kind,
        serde_json::Value::Object(config).to_string(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    app: Box<str>,
    revision: Option<Box<str>>,
    service: Box<str>,
    server: Option<Box<str>>,
    fingerprint: u64,
}

#[derive(Debug, Default)]
struct Settled {
    servers: HashMap<Key, Arc<ServerState>>,
    services: HashMap<Key, Arc<ServiceState>>,
}

/// The state of every service of the live table; touched only at the swap site.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    settled: Mutex<Settled>,
}

impl Registry {
    /// Settles the state of a table about to go live: each server and service the previous table
    /// had under the same key and fingerprint hands over its state, every other keeps the fresh
    /// state compiled for it. Entries the new table does not have are dropped; requests that
    /// still hold them keep them through their [`Lease`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        let mut settled = self.settled.lock().unwrap_or_else(PoisonError::into_inner);
        let mut kept = Settled::default();
        for app in apps {
            let app_id: Box<str> = app.id().into();
            for (revision, named) in app.services_mut() {
                match &mut named.service {
                    Service::LoadBalancer(balancer) => {
                        let (fingerprint, shared, servers) = balancer.state_mut();
                        let key = Key {
                            app: app_id.clone(),
                            revision: revision.map(Into::into),
                            service: named.name.clone(),
                            server: None,
                            fingerprint,
                        };
                        if let Some(old) = settled.services.get(&key) {
                            *shared = Arc::clone(old);
                        }
                        kept.services.insert(key.clone(), Arc::clone(shared));
                        for server in servers {
                            let key = Key {
                                server: Some(server.url.clone()),
                                ..key.clone()
                            };
                            // Two entries naming one URL share one state, so they keep doing so.
                            if let Some(old) =
                                kept.servers.get(&key).or_else(|| settled.servers.get(&key))
                            {
                                server.state = Arc::clone(old);
                            }
                            kept.servers.insert(key, Arc::clone(&server.state));
                        }
                    }
                }
            }
        }
        *settled = kept;
    }
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;
    use crate::service::PickCx;
    use crate::table::{RoutingTable, TableHandle};
    use podgate_model::Snapshot;

    fn snapshot(version: u64, algorithm: &str, urls: &[&str]) -> Snapshot {
        let servers: Vec<Value> = urls.iter().map(|url| json!({ "url": url })).collect();
        serde_json::from_value(json!({
            "version": version,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": [
                {
                    "id": "a", "tenant": "t", "declared_by": "test", "tls": {"mode": "acme"},
                    "routers": [{"name": "all", "match": {"host": "a.test"}, "service": "web"}],
                    "revisions": [{"id": "r", "weight": 1, "state": "serving", "services": [
                        {"name": "web", "type": "loadbalancer", "algorithm": algorithm, "servers": servers}]}]
                },
                {
                    "id": "other", "tenant": "t", "declared_by": "test", "tls": {"mode": "acme"},
                    "routers": [{"name": "all", "match": {"host": "o.test"}, "service": "web"}],
                    "revisions": [{"id": "r", "weight": 1, "state": "serving", "services": [
                        {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:9"}]}]}]
                }
            ]
        }))
        .expect("snapshot")
    }

    fn lease_on(table: &RoutingTable, port: u16) -> Lease {
        let request = pingora::http::RequestHeader::build("GET", b"/", None).expect("request");
        let app = table.app(0).expect("app");
        let service = app.service(0, 0).expect("service");
        // Picks that land elsewhere are dropped, which uncounts them.
        (0..200)
            .find_map(|_| {
                let (addr, lease) = service.pick(PickCx::new(&request))?;
                (addr.port() == port).then_some(lease)
            })
            .expect("a pick reaches the server")
    }

    fn active(table: &RoutingTable, port: u16) -> u32 {
        table
            .app(0)
            .and_then(|app| app.service(0, 0))
            .and_then(|service| {
                service
                    .servers()
                    .iter()
                    .find(|server| server.addr.port() == port)
            })
            .map_or(u32::MAX, |server| {
                server.state.active.load(Ordering::Relaxed)
            })
    }

    #[test]
    fn server_state_survives_unrelated_push() {
        let handle = TableHandle::new();
        handle
            .apply(&snapshot(1, "least_conn", &["http://127.0.0.1:1"]))
            .expect("applies");
        let before = handle.load();
        let lease = lease_on(&before, 1);
        assert_eq!(active(&before, 1), 1);

        let mut other = snapshot(2, "least_conn", &["http://127.0.0.1:1"]);
        other.apps[1].declared_by = "changed elsewhere".into();
        handle.apply(&other).expect("applies");
        let after = handle.load();
        assert_eq!(
            active(&after, 1),
            1,
            "the request in flight is still counted"
        );
        drop(lease);
        assert_eq!(active(&after, 1), 0, "and uncounted on the new table");
    }

    #[test]
    fn server_state_survives_a_new_sibling() {
        let handle = TableHandle::new();
        handle
            .apply(&snapshot(1, "least_conn", &["http://127.0.0.1:1"]))
            .expect("applies");
        let lease = lease_on(&handle.load(), 1);

        handle
            .apply(&snapshot(
                2,
                "least_conn",
                &["http://127.0.0.1:1", "http://127.0.0.1:2"],
            ))
            .expect("applies");
        assert_eq!(
            active(&handle.load(), 1),
            1,
            "adding a server keeps the others"
        );
        assert_eq!(active(&handle.load(), 2), 0);
        drop(lease);
    }

    #[test]
    fn server_state_resets_when_service_changes() {
        let handle = TableHandle::new();
        handle
            .apply(&snapshot(1, "least_conn", &["http://127.0.0.1:1"]))
            .expect("applies");
        let lease = lease_on(&handle.load(), 1);
        assert_eq!(active(&handle.load(), 1), 1);

        handle
            .apply(&snapshot(
                3,
                "p2c_ewma",
                &["http://127.0.0.1:1", "http://127.0.0.1:2"],
            ))
            .expect("applies");
        assert_eq!(
            active(&handle.load(), 1),
            0,
            "a changed service starts with fresh state"
        );
        drop(lease);
        assert_eq!(
            active(&handle.load(), 1),
            0,
            "and the old request never touches the new state"
        );
    }

    #[test]
    fn done_for_removed_server_is_harmless() {
        let handle = TableHandle::new();
        handle
            .apply(&snapshot(
                1,
                "p2c_ewma",
                &["http://127.0.0.1:1", "http://127.0.0.1:2"],
            ))
            .expect("applies");
        let mut lease = lease_on(&handle.load(), 1);
        let left = Arc::clone(lease.server());

        handle
            .apply(&snapshot(2, "p2c_ewma", &["http://127.0.0.1:2"]))
            .expect("applies");
        lease.responded(200);
        assert!(left.ewma_us.load(Ordering::Relaxed) > 0);
        assert_eq!(left.active.load(Ordering::Relaxed), 1);
        drop(lease);
        assert_eq!(left.active.load(Ordering::Relaxed), 0);
        assert_eq!(active(&handle.load(), 1), u32::MAX, "the server is gone");
        assert_eq!(active(&handle.load(), 2), 0);
    }

    #[test]
    fn turns_count_up_and_random_numbers_do_not_repeat() {
        let state = ServiceState::with_seed(5);
        assert_eq!([state.turn(), state.turn()], [5, 6]);
        let numbers: std::collections::HashSet<u64> = (0..1000).map(|_| state.random()).collect();
        assert_eq!(numbers.len(), 1000);
    }

    #[test]
    fn ejection_in_the_past_is_over() {
        let state = ServerState::default();
        assert!(state.available());
        state.ejected_until_ms.store(u64::MAX, Ordering::Relaxed);
        assert!(!state.available());
        state.ejected_until_ms.store(1, Ordering::Relaxed);
        assert!(state.available());
        state.healthy.store(false, Ordering::Relaxed);
        assert!(!state.available());
    }
}
