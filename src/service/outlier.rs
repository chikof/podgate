//! Passive outlier ejection: `passive` on a `loadbalancer` takes a server out of rotation after
//! it fails real requests, without waiting for a probe. Reference: `docs/ref/svc-outlier.md`.
//!
//! ```json
//! { "consecutive_failures": 5, "ejection_secs": 30, "max_ejection_percent": 50,
//!   "failure_statuses": [502, 503, 504], "latency_ms": 2000 }
//! ```
//!
//! # How it works
//!
//! `logging` calls [`observe`] for every request that was sent to a server. The outcome is a
//! failure when the upstream connection failed or timed out (an error whose source is the
//! upstream), when the upstream answered a status in `failure_statuses` (default `502`, `503`,
//! `504`), or when the request took longer than `latency_ms`. Anything else is a success.
//! Requests that say nothing about the server are skipped: capacity refusals (never sent to a
//! server), client aborts and proxy-internal errors.
//!
//! The counters are [`State`], one per server and part of [`super::ServerState`], so they keep
//! the registry's lifetime: a push that leaves the service alone keeps them and a changed `passive`
//! (which changes the service fingerprint) starts them fresh. The only thing balancers read is
//! `ejected_until_ms`; ejection is that one write.
//!
//! The hot path is a handful of relaxed atomics. Only the decision to eject takes a lock, and it
//! is rare.
//!
//! # Ejection time and the ceiling
//!
//! The n-th consecutive ejection of a server lasts `ejection_secs * min(n, 8)`. The count resets
//! once the server has succeeded for one full `ejection_secs` after its last ejection ended or
//! its last failure, whichever is later. A server is ejected only if after it no more than
//! `max_ejection_percent` of the service's servers are ejected and at least one other server is
//! still available (healthy and not ejected), so the service degrades instead of going dark.
//! Observations of a server that is already ejected are ignored: requests that were in flight
//! when it was ejected neither extend nor shorten the ejection.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use pingora::proxy::Session;
use pingora::{Error, ErrorSource};
use serde::Deserialize;
use serde_json::Value;

use super::Service;
use super::loadbalancer::Server;
use super::state::{ServerState, now_ms};
use crate::budget::Escaped;
use crate::compile::Invalid;
use crate::proxy::Ctx;
use crate::table::{CompiledApp, RoutingTable};

/// The largest multiplier of `ejection_secs`.
const MAX_BACKOFF: u32 = 8;

/// Statuses that count as failures when `failure_statuses` is not set.
const DEFAULT_FAILURE_STATUSES: [u16; 3] = [502, 503, 504];

/// Serializes the decision to eject, so that two servers that reach their threshold together
/// cannot both pass the ceiling. Ejections are rare, so one lock for all services is cheap.
static EJECTING: Mutex<()> = Mutex::new(());

/// What passive outlier detection keeps per server.
#[derive(Debug, Default)]
pub struct State {
    /// Failures in a row since the last success or ejection.
    failures: AtomicU32,
    /// Consecutive ejections, which sets the next ejection's length.
    ejections: AtomicU32,
    /// [`now_ms`] time of the last counted failure.
    failed_at_ms: AtomicU64,
}

const _: () = assert!(std::mem::size_of::<State>() == 16);

/// The configuration of `passive`, as written.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    consecutive_failures: u32,
    ejection_secs: u32,
    max_ejection_percent: u8,
    #[serde(default)]
    failure_statuses: Option<Vec<u16>>,
    #[serde(default)]
    latency_ms: Option<u64>,
}

/// A compiled `passive` setting.
#[derive(Debug)]
pub struct Passive {
    consecutive_failures: u32,
    ejection_ms: u64,
    max_ejection_percent: u8,
    failure_statuses: Box<[u16]>,
    latency: Option<Duration>,
}

impl Passive {
    /// Parses the `passive` object of a `loadbalancer`.
    ///
    /// # Errors
    ///
    /// `invalid_service` for an unknown or missing field, a zero threshold or duration, a
    /// percentage outside `1..=100`, or a failure status outside `400..=599`.
    pub(super) fn compile(value: &Value) -> Result<Self, Invalid> {
        let invalid = |why: String| Invalid::new("invalid_service", format!("passive: {why}"));
        let config: Config =
            serde_json::from_value(value.clone()).map_err(|err| invalid(err.to_string()))?;
        if config.consecutive_failures == 0 {
            return Err(invalid("consecutive_failures must be at least 1".into()));
        }
        if config.ejection_secs == 0 {
            return Err(invalid("ejection_secs must be at least 1".into()));
        }
        if !(1..=100).contains(&config.max_ejection_percent) {
            return Err(invalid("max_ejection_percent must be 1 to 100".into()));
        }
        if config.latency_ms == Some(0) {
            return Err(invalid("latency_ms must be at least 1".into()));
        }
        let failure_statuses = match config.failure_statuses {
            None => DEFAULT_FAILURE_STATUSES.to_vec(),
            Some(list) if list.is_empty() => {
                return Err(invalid("failure_statuses must not be empty".into()));
            }
            Some(list) => list,
        };
        if let Some(status) = failure_statuses
            .iter()
            .find(|status| !(400..=599).contains(*status))
        {
            return Err(invalid(format!(
                "failure_statuses: {status} is not a 4xx or 5xx status"
            )));
        }
        Ok(Self {
            consecutive_failures: config.consecutive_failures,
            ejection_ms: u64::from(config.ejection_secs) * 1000,
            max_ejection_percent: config.max_ejection_percent,
            failure_statuses: failure_statuses.into(),
            latency: config.latency_ms.map(Duration::from_millis),
        })
    }

    /// Whether an upstream answer of `status` after `elapsed` is a failure of the server. An
    /// upgraded connection (`101`) lives as long as the client wants, so its length says nothing.
    fn is_failure(&self, status: u16, elapsed: Duration) -> bool {
        self.failure_statuses.contains(&status)
            || (status != 101 && self.latency.is_some_and(|limit| elapsed > limit))
    }

    /// Counts one finished request against `me`, a server of `servers`, at time `now` (in the
    /// scale of [`now_ms`]). Returns the time until which `me` is ejected when this request
    /// ejected it.
    pub(super) fn record(
        &self,
        servers: &[Server],
        me: &Arc<ServerState>,
        failed: bool,
        now: u64,
    ) -> Option<u64> {
        if me.ejected_until_ms.load(Ordering::Relaxed) > now {
            return None;
        }
        let state = &me.outlier;
        if !failed {
            state.failures.store(0, Ordering::Relaxed);
            if state.ejections.load(Ordering::Relaxed) > 0 {
                let since = me
                    .ejected_until_ms
                    .load(Ordering::Relaxed)
                    .max(state.failed_at_ms.load(Ordering::Relaxed));
                if now.saturating_sub(since) >= self.ejection_ms {
                    state.ejections.store(0, Ordering::Relaxed);
                }
            }
            return None;
        }
        state.failed_at_ms.store(now, Ordering::Relaxed);
        let count = state
            .failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if count < self.consecutive_failures {
            return None;
        }
        let _deciding = EJECTING.lock().unwrap_or_else(PoisonError::into_inner);
        if me.ejected_until_ms.load(Ordering::Relaxed) > now {
            return None;
        }
        if !self.has_room(servers, me, now) {
            // Keeps the counter at the threshold: the next failure asks again.
            state
                .failures
                .store(self.consecutive_failures, Ordering::Relaxed);
            return None;
        }
        let ejections = state.ejections.load(Ordering::Relaxed).saturating_add(1);
        state.ejections.store(ejections, Ordering::Relaxed);
        state.failures.store(0, Ordering::Relaxed);
        let until = now + self.ejection_ms * u64::from(ejections.min(MAX_BACKOFF));
        me.ejected_until_ms.store(until, Ordering::Relaxed);
        Some(until)
    }

    /// Whether ejecting `me` keeps the ceiling and leaves another server available.
    fn has_room(&self, servers: &[Server], me: &Arc<ServerState>, now: u64) -> bool {
        let others = || {
            servers
                .iter()
                .filter(|server| !Arc::ptr_eq(&server.state, me))
        };
        let ejected = others()
            .filter(|server| server.state.ejected_until_ms.load(Ordering::Relaxed) > now)
            .count();
        let spare = others().any(|server| {
            server.state.healthy.load(Ordering::Relaxed)
                && server.state.ejected_until_ms.load(Ordering::Relaxed) <= now
        });
        let allowed = servers.len() * usize::from(self.max_ejection_percent) / 100;
        spare && ejected < allowed
    }
}

/// The `passive` setting of `service`, if it has one.
fn passive_of(service: &Service) -> Option<&Passive> {
    match service {
        Service::LoadBalancer(balancer) => balancer.passive(),
        Service::Static(_) => None,
    }
}

/// Counts the finished request against the server it was sent to, when that server's service
/// has `passive`. `logging` calls this once per request, after the response is written.
pub fn observe(session: &Session, error: Option<&Error>, ctx: &Ctx) {
    let (Some(lease), Some(selected)) = (ctx.lease.as_ref(), ctx.route) else {
        return;
    };
    if ctx.capacity_refusal {
        return;
    }
    let Some(service) = ctx
        .table
        .app(selected.app)
        .and_then(|app| app.service(selected.revision, selected.router))
    else {
        return;
    };
    let Some(passive) = passive_of(service) else {
        return;
    };
    let failed = match (error, session.response_written()) {
        (Some(error), _) if *error.esource() == ErrorSource::Upstream => true,
        (Some(_), _) | (None, None) => return,
        (None, Some(head)) => passive.is_failure(head.status.as_u16(), lease.elapsed()),
    };
    passive.record(service.servers(), lease.server(), failed, now_ms());
}

/// How long `server` stays ejected from now, or `None` when it is not ejected.
#[must_use]
pub fn ejected_for(server: &Server) -> Option<Duration> {
    let until = server.state.ejected_until_ms.load(Ordering::Relaxed);
    until
        .checked_sub(now_ms())
        .filter(|left| *left > 0)
        .map(Duration::from_millis)
}

/// Prometheus text exposition of how many servers of each service with `passive` are ejected.
#[must_use]
pub fn render(table: &RoutingTable) -> String {
    use std::fmt::Write;

    let name = "podgate_outlier_ejected_servers";
    let mut out = format!(
        "# HELP {name} Servers of the service that passive outlier detection has ejected now.\n# TYPE {name} gauge\n"
    );
    for app in table.apps() {
        for (revision, named) in services(app) {
            if passive_of(&named.service).is_none() {
                continue;
            }
            let ejected = named
                .service
                .servers()
                .iter()
                .filter(|server| ejected_for(server).is_some())
                .count();
            // Writing to a `String` cannot fail.
            let _ = writeln!(
                out,
                "{name}{{tenant=\"{}\",app=\"{}\",revision=\"{}\",service=\"{}\"}} {ejected}",
                Escaped(app.tenant()),
                Escaped(app.id()),
                Escaped(revision.unwrap_or("")),
                Escaped(&named.name),
            );
        }
    }
    out
}

/// Every service of `app` with the revision it belongs to (`None`: shared by all revisions).
fn services(app: &CompiledApp) -> impl Iterator<Item = (Option<&str>, &super::Named)> {
    let shared = app.services().iter().map(|named| (None, named));
    let own = app.revisions().iter().flat_map(|revision| {
        revision
            .services()
            .iter()
            .map(move |named| (Some(revision.id()), named))
    });
    shared.chain(own)
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn passive(extra: &Value) -> Passive {
        let mut config = json!({
            "consecutive_failures": 2, "ejection_secs": 10, "max_ejection_percent": 100
        });
        if let (Some(config), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
            config.extend(extra.clone());
        }
        Passive::compile(&config).expect("valid passive")
    }

    fn servers(count: usize) -> Vec<Server> {
        (0..count)
            .map(|index| Server {
                url: format!("http://127.0.0.1:{}", index + 1).into(),
                addr: std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    1 + u16::try_from(index).unwrap_or(0),
                )),
                tls: false,
                h2c: false,
                weight: 1,
                state: Arc::default(),
            })
            .collect()
    }

    fn fail(passive: &Passive, all: &[Server], index: usize, now: u64) -> Option<u64> {
        passive.record(all, &all[index].state, true, now)
    }

    fn succeed(passive: &Passive, all: &[Server], index: usize, now: u64) {
        assert_eq!(passive.record(all, &all[index].state, false, now), None);
    }

    fn ejected(all: &[Server], index: usize, now: u64) -> bool {
        all[index].state.ejected_until_ms.load(Ordering::Relaxed) > now
    }

    #[test]
    fn outlier_state_ejects_at_threshold_for_ejection_secs() {
        let (passive, all) = (passive(&json!({})), servers(2));
        assert_eq!(fail(&passive, &all, 0, 1_000), None);
        assert_eq!(fail(&passive, &all, 0, 1_001), Some(1_001 + 10_000));
        assert!(ejected(&all, 0, 5_000));
        assert!(!ejected(&all, 0, 11_001), "over after ejection_secs");
        assert!(!ejected(&all, 1, 5_000));
    }

    #[test]
    fn outlier_state_success_resets_counter() {
        let (passive, all) = (passive(&json!({})), servers(2));
        for step in 0..10 {
            assert_eq!(fail(&passive, &all, 0, 1_000 + step * 2), None);
            succeed(&passive, &all, 0, 1_001 + step * 2);
        }
        assert!(!ejected(&all, 0, 1_030));
    }

    #[test]
    fn outlier_state_ignores_requests_in_flight_during_an_ejection() {
        let (passive, all) = (passive(&json!({})), servers(2));
        fail(&passive, &all, 0, 1_000);
        let until = fail(&passive, &all, 0, 1_001).expect("ejected");
        for now in 1_002..1_010 {
            assert_eq!(fail(&passive, &all, 0, now), None);
        }
        assert_eq!(all[0].state.ejected_until_ms.load(Ordering::Relaxed), until);
        assert_eq!(all[0].state.outlier.ejections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn outlier_never_ejects_last_server_unit() {
        let (passive, all) = (passive(&json!({})), servers(3));
        for index in 0..3 {
            fail(&passive, &all, index, 1_000);
            fail(&passive, &all, index, 1_001);
        }
        let gone: Vec<bool> = (0..3).map(|index| ejected(&all, index, 2_000)).collect();
        assert_eq!(gone, [true, true, false]);
        // It keeps failing and still stays.
        for now in 2_000..2_050 {
            assert_eq!(fail(&passive, &all, 2, now), None);
        }
        assert!(!ejected(&all, 2, 2_050));
    }

    #[test]
    fn outlier_state_unhealthy_peers_count_as_gone() {
        let (passive, all) = (passive(&json!({})), servers(2));
        all[1].state.healthy.store(false, Ordering::Relaxed);
        fail(&passive, &all, 0, 1_000);
        assert_eq!(fail(&passive, &all, 0, 1_001), None, "no spare server");
    }

    #[test]
    fn outlier_max_ejection_percent_is_a_hard_ceiling() {
        let (passive, all) = (passive(&json!({ "max_ejection_percent": 50 })), servers(5));
        for index in 0..5 {
            fail(&passive, &all, index, 1_000);
            fail(&passive, &all, index, 1_001);
        }
        let count = (0..5).filter(|index| ejected(&all, *index, 2_000)).count();
        assert_eq!(count, 2, "50% of 5 servers rounds down");
        let strict = Passive::compile(&json!({
            "consecutive_failures": 1, "ejection_secs": 10, "max_ejection_percent": 10
        }))
        .expect("valid");
        let few = servers(3);
        assert_eq!(fail(&strict, &few, 0, 1_000), None, "10% of 3 is none");
    }

    #[test]
    fn outlier_backoff_grows_and_caps() {
        let (passive, all) = (passive(&json!({ "consecutive_failures": 1 })), servers(2));
        let mut now = 1_000;
        let mut lengths = Vec::new();
        for _ in 0..10 {
            let until = fail(&passive, &all, 0, now).expect("ejected");
            lengths.push((until - now) / 10_000);
            now = until;
        }
        assert_eq!(lengths, [1, 2, 3, 4, 5, 6, 7, 8, 8, 8]);

        succeed(&passive, &all, 0, now + 1);
        assert_eq!(
            all[0].state.outlier.ejections.load(Ordering::Relaxed),
            10,
            "not yet a full ejection_secs of success"
        );
        succeed(&passive, &all, 0, now + 10_000);
        assert_eq!(all[0].state.outlier.ejections.load(Ordering::Relaxed), 0);
        let until = fail(&passive, &all, 0, now + 10_001).expect("ejected");
        assert_eq!(until - (now + 10_001), 10_000, "back to one ejection_secs");
    }

    #[test]
    fn outlier_state_a_failure_delays_the_backoff_reset() {
        let (passive, all) = (passive(&json!({ "consecutive_failures": 2 })), servers(2));
        fail(&passive, &all, 0, 1_000);
        let until = fail(&passive, &all, 0, 1_001).expect("ejected");
        fail(&passive, &all, 0, until + 5_000);
        succeed(&passive, &all, 0, until + 10_000);
        assert_eq!(
            all[0].state.outlier.ejections.load(Ordering::Relaxed),
            1,
            "the failure restarts the clock"
        );
        succeed(&passive, &all, 0, until + 15_000);
        assert_eq!(all[0].state.outlier.ejections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn outlier_state_failure_classes() {
        let plain = passive(&json!({}));
        let quick = Duration::from_millis(1);
        assert!(plain.is_failure(502, quick));
        assert!(plain.is_failure(504, quick));
        assert!(!plain.is_failure(500, quick), "500 is not listed");
        assert!(!plain.is_failure(200, Duration::from_secs(600)));
        let custom = passive(&json!({ "failure_statuses": [500, 429], "latency_ms": 100 }));
        assert!(custom.is_failure(500, quick));
        assert!(custom.is_failure(429, quick));
        assert!(!custom.is_failure(502, quick));
        assert!(custom.is_failure(200, Duration::from_millis(101)));
        assert!(!custom.is_failure(200, Duration::from_millis(100)));
        assert!(
            !custom.is_failure(101, Duration::from_secs(60)),
            "upgrades are long"
        );
    }

    #[test]
    fn outlier_state_refuses_bad_settings() {
        let bad = |value: Value| Passive::compile(&value).expect_err("refused").code;
        let base =
            || json!({ "consecutive_failures": 1, "ejection_secs": 1, "max_ejection_percent": 50 });
        assert!(Passive::compile(&base()).is_ok());
        for (field, value) in [
            ("consecutive_failures", json!(0)),
            ("ejection_secs", json!(0)),
            ("max_ejection_percent", json!(0)),
            ("max_ejection_percent", json!(101)),
            ("latency_ms", json!(0)),
            ("failure_statuses", json!([])),
            ("failure_statuses", json!([200])),
            ("unknown_field", json!(1)),
        ] {
            let mut config = base();
            config[field] = value;
            assert_eq!(bad(config), "invalid_service", "{field}");
        }
        assert_eq!(bad(json!({ "ejection_secs": 1 })), "invalid_service");
    }
}
