//! The JWKS of `jwt_auth`: where it is fetched from, how it is fetched, and when.
//!
//! # The fetch
//!
//! One `GET` through the bounded HTTP/1.1 client of `forward_auth`
//! ([`Client::call`]): the connection is made with the peer of
//! [`crate::service::Upstream::peer`] (so the named transport gives an `https://` endpoint its
//! trust anchors and server name), the exact IP is checked against the upstream address policy on
//! every call, the answer is read up to [`MAX_BODY`] bytes under a 5 second timeout, and a
//! redirect is a failure. The memory of the call is charged to the tenant's `max_buffer_bytes`
//! before the connection is made. `jwks_uri` is fixed configuration. Its host is an IP literal,
//! dialled as it is, or a host name, resolved once per fetch with the node's resolver: every
//! answer is checked against the policy for the tenant, the first permitted address is dialled,
//! and the name is the `Host` and the SNI.
//!
//! # The cache
//!
//! [`Cache`] is a state machine on a clock the caller passes in, so every rule below is tested
//! without sleeping. It never does I/O: [`Cache::plan`] says what a request should do and
//! [`Cache::finish`] takes the result of a fetch that a background task made.
//!
//! - A set younger than `jwks_refresh_secs` is used as it is.
//! - An older set is still used (stale), and the first request that finds it so starts one
//!   refresh in the background. A set older than the refresh interval plus [`STALE_FOR`] is
//!   dropped.
//! - With no set, a request waits for the fetch (one fetch is in flight at a time, every other
//!   request joins it); when it fails the answer is `503`, and no new fetch starts for
//!   [`BACKOFF`].
//! - A token whose `kid` no key has starts a fetch at most once per [`KID_MISS`], and waits for
//!   it.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::sync::watch;

use super::verify::{KeySet, SetError};
use crate::budget::TenantBudget;
use crate::compile::Invalid;
use crate::middleware::errors::fetch::{ALLOWANCE as HEAD_ALLOWANCE, Failure as CallFailure};
use crate::middleware::forward_auth::{Client, Parsed, Route, parse_url};
use crate::service::resolve::Resolver;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::service::{Server, Transport};

/// The most bytes of a JWKS answer.
pub(super) const MAX_BODY: usize = 256 * 1024;

/// The bytes besides the body that a fetch holds: the request, the head and the read buffers.
const ALLOWANCE: u64 = HEAD_ALLOWANCE + 2048;

/// The bytes one fetch charges to the tenant.
pub(super) const CHARGE: u64 = ALLOWANCE + MAX_BODY as u64;

/// How long a fetch may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The longest `jwks_uri`.
const MAX_URI: usize = 512;

/// The least time between two fetches that a `kid` miss starts.
pub(super) const KID_MISS: Duration = Duration::from_secs(10);

/// The least time between a failed fetch and the next attempt.
pub(super) const BACKOFF: Duration = Duration::from_secs(10);

/// How long a set is kept after it is due for a refresh, when refreshing fails.
pub(super) const STALE_FOR: Duration = Duration::from_secs(24 * 3600);

/// The smallest and largest `jwks_refresh_secs`, and the default.
pub(super) const REFRESH_MIN: u64 = 60;
pub(super) const REFRESH_MAX: u64 = 86400;
pub(super) const REFRESH_DEFAULT: u64 = 3600;

/// Where the JWKS is: the server, how to reach it and what to ask for.
#[derive(Debug)]
pub(super) struct Target {
    pub(super) server: Server,
    pub(super) transport: Arc<Transport>,
    /// The `Host` header: the authority as written.
    pub(super) host: Box<str>,
    /// The request target: the path and query of the URI.
    pub(super) path: Box<str>,
    /// The URI as written, for the plan's comparison; never shown with its query.
    pub(super) uri: Box<str>,
}

impl Target {
    /// The URI without its query, which may carry a key for the endpoint.
    pub(super) fn display(&self) -> String {
        let scheme = if self.server.tls { "https" } else { "http" };
        let path = self.path.split('?').next().unwrap_or_default();
        format!("{scheme}://{}{path}", self.host)
    }

    /// The address of the endpoint when its URL has an IP literal; `None` for a host name, which
    /// is resolved and checked against the upstream policy on every fetch.
    pub(super) fn ip(&self) -> Option<IpAddr> {
        self.server.host().is_none().then(|| self.server.addr.ip())
    }
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("jwt_auth: {message}"))
}

/// Reads `jwks_uri`.
///
/// # Errors
///
/// `invalid_middleware` for anything but an absolute `http://` or `https://` URL whose host is an
/// IP literal or a host name (an `h2c://` one too: the fetch is HTTP/1.1, which an h2c server
/// cannot answer), for credentials in the URL, and for a transport that sets TLS options on a
/// plain `http://` URL.
pub(super) fn parse_uri(text: &str, transport: Arc<Transport>) -> Result<Target, Invalid> {
    let Parsed {
        server,
        host,
        target,
    } = parse_url(text, "jwks_uri", MAX_URI).map_err(invalid)?;
    if !server.tls && transport.has_tls_settings() {
        return Err(invalid(
            "the transport sets TLS options and jwks_uri is plain http://",
        ));
    }
    Ok(Target {
        server,
        transport,
        host,
        path: target,
        uri: text.into(),
    })
}

/// Why a fetch gave no keys. Logged, never sent to a client.
#[derive(Debug, Error)]
pub(super) enum FetchError {
    #[error("the tenant has no room in its buffer budget for the fetch")]
    Budget,
    #[error("{0}")]
    Call(#[from] CallFailure),
    #[error("the endpoint answered {0}")]
    Status(u16),
    #[error("{0}")]
    Set(#[from] SetError),
}

/// What a background fetch needs, all owned.
pub(super) struct Fetch {
    pub(super) target: Arc<Target>,
    pub(super) client: Client,
    pub(super) policy: UpstreamPolicy,
    pub(super) resolver: Resolver,
    pub(super) tenant: Box<str>,
    pub(super) budget: Arc<TenantBudget>,
}

impl Fetch {
    /// Fetches and reads the set. Returns it with the number of keys that were left out.
    pub(super) async fn run(&self) -> Result<(KeySet, usize), FetchError> {
        let _charge = self.budget.charge(CHARGE).ok_or(FetchError::Budget)?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            self.target.path, self.target.host
        );
        let route = Route {
            server: &self.target.server,
            transport: &self.target.transport,
            resolver: &self.resolver,
            policy: &self.policy,
            tenant: &self.tenant,
        };
        let answer = self
            .client
            .call(&route, request.as_bytes(), MAX_BODY, TIMEOUT)
            .await?;
        if answer.status != 200 {
            return Err(FetchError::Status(answer.status));
        }
        Ok(KeySet::remote(&answer.body)?)
    }
}

#[derive(Debug)]
struct Stored {
    keys: Arc<KeySet>,
    fetched: Instant,
}

#[derive(Debug, Default)]
struct State {
    stored: Option<Stored>,
    flight: Option<watch::Receiver<()>>,
    last_kid_fetch: Option<Instant>,
    last_failure: Option<Instant>,
}

/// A fetch in progress. Dropping it wakes everyone who waits for it.
#[derive(Debug)]
pub(super) struct Flight {
    _done: watch::Sender<()>,
}

impl Flight {
    /// A receiver that is woken (with an error) when this fetch ends.
    pub(super) fn subscribe(&self) -> watch::Receiver<()> {
        self._done.subscribe()
    }
}

/// What a request does about the JWKS.
#[derive(Debug)]
pub(super) enum Plan {
    /// Use this set.
    Ready(Arc<KeySet>),
    /// Use this (stale) set, and start this fetch in the background.
    Background(Arc<KeySet>, Flight),
    /// Start this fetch and wait for it.
    Foreground(Flight),
    /// Wait for the fetch in progress.
    Wait(watch::Receiver<()>),
    /// There are no keys and no fetch is due: answer `503`.
    Unavailable,
}

/// Why a request asks for keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Demand {
    /// To check a token.
    Keys,
    /// A token named a `kid` that the set has not: a fresh set may have it.
    KidMiss,
}

/// The keys of one `jwks_uri` of one middleware.
#[derive(Debug)]
pub(super) struct Cache {
    refresh: Duration,
    state: Mutex<State>,
}

impl Cache {
    pub(super) fn new(refresh_secs: u64) -> Self {
        Self {
            refresh: Duration::from_secs(refresh_secs),
            state: Mutex::new(State::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The set a request may use at `now`: fresh or stale, not dropped.
    pub(super) fn current(&self, now: Instant) -> Option<Arc<KeySet>> {
        let state = self.lock();
        self.usable(&state, now).map(|(keys, _)| keys)
    }

    /// The set at `now`, and whether it is past its refresh time.
    fn usable(&self, state: &State, now: Instant) -> Option<(Arc<KeySet>, bool)> {
        let stored = state.stored.as_ref()?;
        let age = now.saturating_duration_since(stored.fetched);
        (age < self.refresh + STALE_FOR).then(|| (Arc::clone(&stored.keys), age >= self.refresh))
    }

    /// What a request should do at `now`.
    pub(super) fn plan(&self, now: Instant, demand: Demand) -> Plan {
        let mut state = self.lock();
        let joinable = state
            .flight
            .as_ref()
            .filter(|flight| flight.has_changed().is_ok())
            .cloned();
        let backing_off = state
            .last_failure
            .is_some_and(|at| now.saturating_duration_since(at) < BACKOFF);
        let set = self.usable(&state, now);
        match (set, demand) {
            (Some((keys, _)), Demand::KidMiss) => {
                if let Some(flight) = joinable {
                    return Plan::Wait(flight);
                }
                let spaced = state
                    .last_kid_fetch
                    .is_none_or(|at| now.saturating_duration_since(at) >= KID_MISS);
                if backing_off || !spaced {
                    return Plan::Ready(keys);
                }
                state.last_kid_fetch = Some(now);
                Plan::Foreground(Self::start(&mut state))
            }
            (Some((keys, false)), Demand::Keys) => Plan::Ready(keys),
            (Some((keys, true)), Demand::Keys) => {
                if joinable.is_some() || backing_off {
                    Plan::Ready(keys)
                } else {
                    Plan::Background(keys, Self::start(&mut state))
                }
            }
            (None, _) => match joinable {
                Some(flight) => Plan::Wait(flight),
                None if backing_off => Plan::Unavailable,
                None => Plan::Foreground(Self::start(&mut state)),
            },
        }
    }

    fn start(state: &mut State) -> Flight {
        let (done, flight) = watch::channel(());
        state.flight = Some(flight);
        Flight { _done: done }
    }

    /// Takes the result of a fetch that [`Self::plan`] started at `now`, then wakes the
    /// requests that wait for it. A failure keeps the set it had.
    pub(super) fn finish<E>(&self, flight: Flight, now: Instant, result: Result<KeySet, E>) {
        {
            let mut state = self.lock();
            match result {
                Ok(keys) => {
                    state.stored = Some(Stored {
                        keys: Arc::new(keys),
                        fetched: now,
                    });
                    state.last_failure = None;
                }
                Err(_) => state.last_failure = Some(now),
            }
            state.flight = None;
        }
        drop(flight);
    }

    /// The number of keys held, `0` with no set.
    pub(super) fn held(&self) -> usize {
        self.lock()
            .stored
            .as_ref()
            .map_or(0, |stored| stored.keys.len())
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;
    use crate::middleware::jwt_auth::fixture::Signer;

    fn keys() -> KeySet {
        KeySet::inline(&json!({"keys": [Signer::es256("k1").jwk()]})).expect("keys")
    }

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    /// Plans, and when the plan starts a fetch, finishes it with `result`.
    fn run(
        cache: &Cache,
        now: Instant,
        demand: Demand,
        result: Result<KeySet, ()>,
    ) -> &'static str {
        match cache.plan(now, demand) {
            Plan::Ready(_) => "ready",
            Plan::Background(_, flight) => {
                cache.finish(flight, now, result);
                "background"
            }
            Plan::Foreground(flight) => {
                cache.finish(flight, now, result);
                "foreground"
            }
            Plan::Wait(_) => "wait",
            Plan::Unavailable => "unavailable",
        }
    }

    #[test]
    fn jwks_kid_miss_refresh_rate_limited() {
        let cache = Cache::new(3600);
        let t0 = Instant::now();
        assert_eq!(run(&cache, t0, Demand::Keys, Ok(keys())), "foreground");
        // The first miss refreshes, the following ones within 10 seconds do not.
        assert_eq!(
            run(&cache, at(t0, 1), Demand::KidMiss, Ok(keys())),
            "foreground"
        );
        for secs in [2, 5, 10] {
            assert_eq!(
                run(&cache, at(t0, secs), Demand::KidMiss, Ok(keys())),
                "ready",
                "{secs}"
            );
        }
        assert_eq!(
            run(&cache, at(t0, 11), Demand::KidMiss, Ok(keys())),
            "foreground"
        );
        // A miss while a fetch is running joins it instead of starting another.
        let Plan::Foreground(flight) = cache.plan(at(t0, 30), Demand::KidMiss) else {
            panic!("a miss after 10 seconds fetches");
        };
        assert!(matches!(
            cache.plan(at(t0, 31), Demand::KidMiss),
            Plan::Wait(_)
        ));
        assert!(matches!(
            cache.plan(at(t0, 31), Demand::Keys),
            Plan::Ready(_)
        ));
        cache.finish(flight, at(t0, 30), Ok::<_, ()>(keys()));
    }

    #[test]
    fn jwks_stale_on_error() {
        let cache = Cache::new(60);
        let t0 = Instant::now();
        assert_eq!(run(&cache, t0, Demand::Keys, Ok(keys())), "foreground");
        assert_eq!(run(&cache, at(t0, 59), Demand::Keys, Ok(keys())), "ready");
        // Past the refresh time the old keys serve while a refresh runs, and it fails.
        assert_eq!(run(&cache, at(t0, 61), Demand::Keys, Err(())), "background");
        assert!(cache.current(at(t0, 62)).is_some());
        // No new attempt for ten seconds, and the keys still serve.
        assert_eq!(run(&cache, at(t0, 65), Demand::Keys, Err(())), "ready");
        assert_eq!(run(&cache, at(t0, 72), Demand::Keys, Err(())), "background");
        // Kept for 24 hours after they were due, then dropped.
        assert!(cache.current(at(t0, 60 + 24 * 3600 - 1)).is_some());
        assert!(cache.current(at(t0, 60 + 24 * 3600)).is_none());
        // A success replaces them.
        assert_eq!(
            run(&cache, at(t0, 100), Demand::Keys, Ok(keys())),
            "background"
        );
        assert_eq!(run(&cache, at(t0, 101), Demand::Keys, Ok(keys())), "ready");
    }

    #[test]
    fn jwks_unreachable_no_cache_503() {
        let cache = Cache::new(3600);
        let t0 = Instant::now();
        assert_eq!(run(&cache, t0, Demand::Keys, Err(())), "foreground");
        assert!(cache.current(at(t0, 1)).is_none());
        // Closed: nothing to verify with, and no new fetch for 10 seconds.
        assert_eq!(
            run(&cache, at(t0, 1), Demand::Keys, Ok(keys())),
            "unavailable"
        );
        assert_eq!(
            run(&cache, at(t0, 9), Demand::KidMiss, Ok(keys())),
            "unavailable"
        );
        assert_eq!(
            run(&cache, at(t0, 10), Demand::Keys, Ok(keys())),
            "foreground"
        );
        assert!(cache.current(at(t0, 11)).is_some());
    }

    #[test]
    fn one_fetch_is_in_flight_and_waiters_wake_when_it_ends() {
        let cache = Cache::new(3600);
        let t0 = Instant::now();
        let Plan::Foreground(flight) = cache.plan(t0, Demand::Keys) else {
            panic!("the first request fetches");
        };
        let Plan::Wait(waiter) = cache.plan(t0, Demand::Keys) else {
            panic!("the second joins");
        };
        assert!(matches!(cache.plan(t0, Demand::Keys), Plan::Wait(_)));
        cache.finish(flight, t0, Ok::<_, ()>(keys()));
        // The sender is gone: the waiter is woken with an error, and the set is there.
        assert!(waiter.has_changed().is_err());
        assert!(cache.current(t0).is_some());
        assert_eq!(cache.held(), 1);
    }

    #[test]
    fn a_dropped_fetch_does_not_wedge_the_cache() {
        let cache = Cache::new(3600);
        let t0 = Instant::now();
        let Plan::Foreground(flight) = cache.plan(t0, Demand::Keys) else {
            panic!("fetches");
        };
        // The task died without finishing.
        drop(flight);
        assert!(matches!(cache.plan(t0, Demand::Keys), Plan::Foreground(_)));
    }

    fn target(text: &str) -> Result<Target, Invalid> {
        parse_uri(text, Arc::new(Transport::default()))
    }

    #[test]
    fn a_jwks_uri_is_an_absolute_http_url_with_an_ip_or_host_name() {
        let t = target("https://10.0.0.5:8443/.well-known/jwks.json?x=1").expect("uri");
        assert_eq!(t.server.addr, "10.0.0.5:8443".parse().expect("addr"));
        assert!(t.server.tls);
        assert_eq!(&*t.path, "/.well-known/jwks.json?x=1");
        assert_eq!(t.display(), "https://10.0.0.5:8443/.well-known/jwks.json");
        assert!(target("http://10.0.0.5/jwks").is_ok());
        assert!(target("https://[2001:db8::5]/jwks").is_ok());
        for bad in [
            "/jwks",
            "10.0.0.5/jwks",
            "ftp://10.0.0.5/",
            "https://",
            "https://user:pw@10.0.0.5/",
            "https://10.0.0.5:99999/",
            "h2c://10.0.0.5/",
            "",
        ] {
            assert_eq!(
                target(bad).expect_err(bad).code,
                "invalid_middleware",
                "{bad:?}"
            );
        }
        let named = target("https://IdP.Example./jwks").expect("a name");
        assert_eq!(named.server.host(), Some("idp.example"));
        assert_eq!(named.server.sni_name().as_deref(), Some("idp.example"));
        assert_eq!(named.ip(), None);
        assert_eq!(named.server.addr.port(), 443);
        assert_eq!(t.ip(), Some("10.0.0.5".parse().expect("ip")));
        for bad in [
            "https://-bad-.example/jwks",
            "https://[idp.example]/jwks",
            "https://10.0.0.999/",
        ] {
            assert_eq!(
                target(bad).expect_err(bad).code,
                "invalid_middleware",
                "{bad:?}"
            );
        }
    }
}

#[cfg(test)]
mod dial {
    use std::net::TcpListener;

    use podgate_model::Budget;

    use super::*;
    use crate::budget::Budgets;

    fn fetch(uri: &str, policy: UpstreamPolicy, max_buffer_bytes: u64) -> Fetch {
        Fetch {
            target: Arc::new(parse_uri(uri, Arc::new(Transport::default())).expect("uri")),
            client: Client::new(Duration::from_secs(5)),
            resolver: Resolver::default(),
            policy,
            tenant: "t1".into(),
            budget: Budgets::new().tenant(
                "t1",
                Budget {
                    max_inflight: 1,
                    max_buffer_bytes,
                },
            ),
        }
    }

    /// A listener nobody accepts from, and whether a client got as far as connecting.
    fn bound() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let uri = format!("http://{}/jwks", listener.local_addr().expect("addr"));
        (listener, uri)
    }

    #[tokio::test]
    async fn jwks_loopback_refused() {
        let (listener, uri) = bound();
        let result = fetch(&uri, UpstreamPolicy::builtin(), CHARGE).run().await;
        assert!(
            matches!(result, Err(FetchError::Call(CallFailure::Policy))),
            "{result:?}"
        );
        assert!(
            listener.accept().is_err(),
            "the policy refused before any dial"
        );
        // Link-local is refused the same way.
        let result = fetch(
            "http://169.254.169.254/jwks",
            UpstreamPolicy::builtin(),
            CHARGE,
        )
        .run()
        .await;
        assert!(
            matches!(result, Err(FetchError::Call(CallFailure::Policy))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn jwks_outside_allowlist_refused() {
        let (listener, uri) = bound();
        let policy =
            UpstreamPolicy::parse(r#"{"deny": [], "tenants": {"t1": {"allow": ["10.4.0.0/16"]}}}"#)
                .expect("policy");
        let result = fetch(&uri, policy, CHARGE).run().await;
        assert!(
            matches!(result, Err(FetchError::Call(CallFailure::Policy))),
            "{result:?}"
        );
        assert!(listener.accept().is_err());
    }

    #[tokio::test]
    async fn a_fetch_that_does_not_fit_the_budget_dials_nothing() {
        let (listener, uri) = bound();
        let result = fetch(&uri, UpstreamPolicy::allow_all(), CHARGE - 1)
            .run()
            .await;
        assert!(matches!(result, Err(FetchError::Budget)), "{result:?}");
        assert!(listener.accept().is_err());
    }
}
