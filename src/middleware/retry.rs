//! The `retry` middleware: when an attempt to reach a server fails before any response byte
//! arrived, the request goes to another server of the same service, with backoff, as long as
//! that cannot repeat something the first server already did. Full reference:
//! `docs/ref/mw-retry.md`.
//!
//! ```json
//! { "name": "r", "type": "retry", "attempts": 3, "initial_interval_ms": 100,
//!   "methods": ["GET", "HEAD", "PUT"] }
//! ```
//!
//! # What retries, and what never does
//!
//! Pingora marks an error retryable only when no response byte arrived. This kind narrows that
//! further, per [`Failure`]:
//!
//! - **Connect** (refused, unreachable, handshake failed): nothing was sent. Any method, as long
//!   as the body was not already streamed to a server ([`Body::Streamed`]).
//! - **Reused** (a pooled connection died): the server may have read the request. Only a method
//!   in `methods` (default: the idempotent set of RFC 9110) and only a body that can be sent
//!   again: none, or one the `buffering` middleware holds ([`Body::Held`]). A streamed body is
//!   never replayed.
//!
//! There is no retry on a response status: once the upstream has produced a response head,
//! Pingora cannot retry and replaying would duplicate the request. `retry_statuses` is
//! `unsupported_setting`.
//!
//! # Bounds
//!
//! `attempts` counts the first try and is at most [`MAX_ATTEMPTS`]. The wait before retry `n` is
//! `initial_interval_ms * 2^(n-1)` with jitter (half to all of it). A retry whose backoff would
//! not end before the request deadline (`REQUEST_TIMEOUT_SECS`, measured from the start of the
//! chain) is not made.
//!
//! # How an attempt moves on
//!
//! [`on_upstream_error`] runs in Pingora's `fail_to_connect` and `error_while_proxy` callbacks.
//! It asks the chain ([`middleware::run_upstream_error`]), then picks the next server in the
//! request's revision and service, excluding the servers already tried
//! ([`crate::route::reselect`], which goes through [`crate::service::PickCx::allows`]), and
//! checks it against the upstream address policy. Only when all of that holds does it count the
//! failed attempt (outlier ejection and every stage's [`Kind::attempt_failed`]) and mark the
//! error retryable. [`begin_attempt`] then runs at the top of `upstream_peer`: it waits out the
//! backoff, returns the failed attempt's backend slot, admits the request to the next server's
//! backend again and makes that server the route. The tenant's in-flight slot is taken once per
//! request, so retries never raise it. With one server, or when every other server was tried,
//! only a connect failure is retried on a server already tried.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::Method;
use pingora::proxy::Session;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Body, CompileCx, ErrorCx, FinishCx, Flow, Kind, RequestCx, Verdict};
use crate::compile::Invalid;
use crate::events::EventFeed;
use crate::fairq::Backends;
use crate::proxy::Ctx;
use crate::respond;
use crate::route::{self, Selected};
use crate::service::{Lease, outlier};
use crate::table::RoutingTable;
use podgate_model::Declared;

pub use super::Failure;

/// Most attempts, the first included.
pub const MAX_ATTEMPTS: u32 = 5;

/// The wait before the first retry when `initial_interval_ms` is not set.
const DEFAULT_INTERVAL_MS: u32 = 100;

/// Longest `initial_interval_ms`.
const MAX_INTERVAL_MS: u32 = 10_000;

/// Most entries in `methods`.
const MAX_METHODS: usize = 16;

/// The methods retried after a reused connection died: RFC 9110's idempotent set.
const IDEMPOTENT: [Method; 6] = [
    Method::GET,
    Method::HEAD,
    Method::OPTIONS,
    Method::PUT,
    Method::DELETE,
    Method::TRACE,
];

/// The configuration of a `retry` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// Attempts including the first, 1 to 5. `1` never retries.
    attempts: u32,
    /// Wait before the first retry, in milliseconds; each further retry waits twice as long.
    /// Default `100`, at most `10000`. `0` retries at once.
    #[serde(default)]
    initial_interval_ms: Option<u32>,
    /// Methods retried after a reused connection died. Default: `GET`, `HEAD`, `OPTIONS`,
    /// `PUT`, `DELETE`, `TRACE`. A connect failure is retried for any method.
    #[serde(default)]
    methods: Option<Vec<String>>,
}

/// A compiled `retry` middleware.
#[derive(Debug)]
pub struct Retry {
    attempts: u32,
    initial: Duration,
    methods: Box<[Method]>,
}

/// Per-request state: how many attempts have failed and when the chain started.
#[derive(Debug, Default)]
pub struct State {
    started: Option<Instant>,
    failed: u32,
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("retry: {message}"))
}

impl Retry {
    /// The wait before the retry that follows the `failed`-th failed attempt (from 1), with
    /// `jitter_permille` (0 to 1000) choosing a point between half the wait and all of it.
    fn backoff(&self, failed: u32, jitter_permille: u32) -> Duration {
        let wait = self
            .initial
            .saturating_mul(1_u32 << failed.saturating_sub(1).min(MAX_ATTEMPTS));
        let half = wait / 2;
        half + half * jitter_permille.min(1000) / 1000
    }

    /// What to do about the `failed`-th failed attempt, `elapsed` after the chain started.
    fn verdict(
        &self,
        failed: u32,
        elapsed: Duration,
        cx: &ErrorCx<'_>,
        jitter_permille: u32,
    ) -> Verdict {
        if failed >= self.attempts {
            return Verdict::No;
        }
        let safe = match cx.failure {
            Failure::Connect => cx.body != Body::Streamed,
            Failure::Reused => cx.body.replayable() && self.methods.contains(&cx.request.method),
        };
        if !safe {
            return Verdict::No;
        }
        let backoff = self.backoff(failed, jitter_permille);
        if elapsed.saturating_add(backoff) >= cx.deadline {
            return Verdict::No;
        }
        Verdict::Yes { backoff }
    }
}

/// A point in `0..=1000`, uniform enough for jitter.
fn jitter_permille() -> u32 {
    let mut bytes = [0_u8; 2];
    match getrandom::fill(&mut bytes) {
        Ok(()) => u32::from(u16::from_le_bytes(bytes)) % 1001,
        Err(_) => 500,
    }
}

fn parse_methods(names: &[String]) -> Result<Box<[Method]>, Invalid> {
    if names.len() > MAX_METHODS {
        return Err(invalid(format!(
            "`methods` has more than {MAX_METHODS} entries"
        )));
    }
    let mut methods: Vec<Method> = Vec::with_capacity(names.len());
    for name in names {
        let method = Method::from_bytes(name.to_ascii_uppercase().as_bytes())
            .map_err(|_| invalid(format!("`methods`: {name:?} is not an HTTP method")))?;
        if !methods.contains(&method) {
            methods.push(method);
        }
    }
    Ok(methods.into())
}

impl Kind for Retry {
    type State = State;

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        if declared.config.contains_key("retry_statuses") {
            return Err(Invalid::new(
                "unsupported_setting",
                "retry: `retry_statuses` is not supported: once an upstream has answered, Pingora cannot retry, and replaying after a response started duplicates the request",
            ));
        }
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        if !(1..=MAX_ATTEMPTS).contains(&config.attempts) {
            return Err(invalid(format!(
                "`attempts` must be 1 to {MAX_ATTEMPTS}, the first try included"
            )));
        }
        let interval = config.initial_interval_ms.unwrap_or(DEFAULT_INTERVAL_MS);
        if interval > MAX_INTERVAL_MS {
            return Err(invalid(format!(
                "`initial_interval_ms` must be at most {MAX_INTERVAL_MS}"
            )));
        }
        let methods = match &config.methods {
            Some(names) => parse_methods(names)?,
            None => IDEMPOTENT.to_vec().into(),
        };
        Ok(Self {
            attempts: config.attempts,
            initial: Duration::from_millis(u64::from(interval)),
            methods,
        })
    }

    async fn request(&self, _cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        state.started = Some(Instant::now());
        Ok(Flow::Continue)
    }

    fn on_upstream_error(&self, cx: &ErrorCx<'_>, state: &mut State) -> Verdict {
        state.failed = state.failed.saturating_add(1);
        let elapsed = state.started.map_or(Duration::ZERO, |at| at.elapsed());
        self.verdict(state.failed, elapsed, cx, jitter_permille())
    }

    fn describe(&self) -> Value {
        json!({
            "attempts": self.attempts,
            "initial_interval_ms": u64::try_from(self.initial.as_millis()).unwrap_or(u64::MAX),
            "methods": self.methods.iter().map(Method::as_str).collect::<Vec<_>>(),
        })
    }
}

/// What a retried request keeps in its [`Ctx`].
#[derive(Debug, Default)]
pub struct Progress {
    /// The servers an attempt already went to.
    tried: Vec<SocketAddr>,
    /// The attempt to start next, chosen when the last one failed.
    next: Option<Next>,
}

/// The next attempt of a retried request.
#[derive(Debug)]
struct Next {
    selected: Selected,
    lease: Lease,
    backoff: Duration,
}

/// What is left of the request body to send, as [`Body`].
fn body_of(session: &mut Session, held: bool) -> Body {
    if session.is_body_empty() {
        Body::Absent
    } else if held {
        Body::Held
    } else if session.body_bytes_read() == 0 {
        Body::Unread
    } else {
        Body::Streamed
    }
}

/// Asks the request's chain whether the attempt that failed with `failure` is retried, and when
/// it is, sets the next attempt up. `Some(true)`: retry (the error is marked so; `upstream_peer`
/// runs [`begin_attempt`] next); `Some(false)`: do not; `None`: no stage of the chain has a say
/// and Pingora's own rule stands. `deadline` is how long the whole request may take;
/// `policy_allows` is the upstream address policy for the next server.
pub fn on_upstream_error(
    session: &mut Session,
    ctx: &mut Ctx,
    failure: Failure,
    deadline: Duration,
    events: &EventFeed,
    policy_allows: impl Fn(&RoutingTable, &Selected) -> bool,
) -> Option<bool> {
    let table = Arc::clone(&ctx.table);
    let (app, router) = ctx.matched.and_then(|matched| table.router(matched))?;
    if router.chain().is_empty() {
        return None;
    }
    let body = body_of(session, ctx.body_held);
    let cx = ErrorCx {
        request: session.req_header(),
        failure,
        body,
        deadline,
    };
    let backoff = match super::run_upstream_error(app.stages(), router.chain(), &cx, &mut ctx.chain)
    {
        Verdict::Abstain => return None,
        Verdict::No => return Some(false),
        Verdict::Yes { backoff } => backoff,
    };
    // A response the client already has cannot be taken back.
    if session.response_written().is_some() {
        return Some(false);
    }
    let Some(selected) = ctx.route else {
        return Some(false);
    };
    if !ctx.retry.tried.contains(&selected.upstream) {
        ctx.retry.tried.push(selected.upstream);
    }
    let request = session.req_header();
    let client = ctx.forwarded.known_client();
    let mut pick = route::reselect(&table, &selected, request, client, &ctx.retry.tried);
    if pick.is_none() && failure == Failure::Connect {
        // One server, or every other one tried or down: nothing was sent, so the same server
        // may be asked again after the backoff.
        pick = route::reselect(&table, &selected, request, client, &[]);
    }
    let Some((next, lease)) = pick else {
        return Some(false);
    };
    if !policy_allows(&table, &next) {
        return Some(false);
    }
    outlier::observe_failed_attempt(ctx);
    let finish = FinishCx {
        events,
        status: None,
        upstream_error: true,
    };
    super::run_attempt_failed(app.stages(), router.chain(), &finish, &mut ctx.chain);
    ctx.retry.next = Some(Next {
        selected: next,
        lease,
        backoff,
    });
    Some(true)
}

/// Starts the attempt [`on_upstream_error`] prepared, if one is pending: waits out the backoff,
/// returns the failed attempt's backend slot, admits the request to the next server's backend
/// and makes that server the route. Does nothing for the first attempt.
///
/// # Errors
///
/// The error that ends the request when the next server's backend refuses it (`503`).
pub async fn begin_attempt(
    backends: &Backends,
    session: &mut Session,
    ctx: &mut Ctx,
) -> pingora::Result<()> {
    let Some(next) = ctx.retry.next.take() else {
        return Ok(());
    };
    // Before the wait and before admission: a request must not queue behind its own slot.
    ctx.backend.release();
    tokio::time::sleep(next.backoff).await;
    match backends.admit(&ctx.table, &next.selected).await {
        Ok(slot) => ctx.backend = slot,
        Err(err) => {
            ctx.capacity_refusal = err.is_capacity_refusal();
            ctx.access.refused(&err);
            return Err(respond::abort(session, &err).await);
        }
    }
    ctx.route = Some(next.selected);
    ctx.lease = Some(next.lease);
    ctx.access.retry_attempts = ctx.access.retry_attempts.saturating_add(1);
    if let Some(route) = ctx
        .matched
        .and_then(|matched| ctx.table.series().route(matched))
    {
        route.service().retry();
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;

    use super::*;

    fn compiled(config: &Value) -> Result<Retry, Invalid> {
        let mut object = config.as_object().cloned().unwrap_or_default();
        object.insert("name".into(), json!("r"));
        object.insert("type".into(), json!("retry"));
        let declared: Declared = serde_json::from_value(Value::Object(object)).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        Retry::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    fn request(method: &str) -> RequestHeader {
        RequestHeader::build(method, b"/", None).expect("request")
    }

    fn error_cx(request: &RequestHeader, failure: Failure, body: Body) -> ErrorCx<'_> {
        ErrorCx {
            request,
            failure,
            body,
            deadline: Duration::from_secs(30),
        }
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn retry_decision() {
        let retry = compiled(&json!({"attempts": 3, "methods": ["GET", "post"]})).expect("valid");
        let yes = |method: &str, failure: Failure, body: Body, failed: u32| {
            let request = request(method);
            matches!(
                retry.verdict(
                    failed,
                    Duration::ZERO,
                    &error_cx(&request, failure, body),
                    0
                ),
                Verdict::Yes { .. }
            )
        };
        // Connect: any method, any body that was not streamed.
        for method in ["GET", "POST", "PATCH"] {
            for body in [Body::Absent, Body::Held, Body::Unread] {
                assert!(yes(method, Failure::Connect, body, 1), "{method} {body:?}");
            }
            assert!(
                !yes(method, Failure::Connect, Body::Streamed, 1),
                "{method}"
            );
        }
        // Reused: a listed method and a body that can be sent again.
        assert!(yes("GET", Failure::Reused, Body::Absent, 1));
        assert!(
            yes("POST", Failure::Reused, Body::Held, 1),
            "listed and held"
        );
        assert!(!yes("POST", Failure::Reused, Body::Streamed, 1));
        assert!(!yes("GET", Failure::Reused, Body::Streamed, 1));
        assert!(!yes("GET", Failure::Reused, Body::Unread, 1));
        assert!(!yes("PUT", Failure::Reused, Body::Absent, 1), "not listed");
        // Attempts include the first: three attempts allow two retries.
        assert!(yes("GET", Failure::Connect, Body::Absent, 2));
        assert!(!yes("GET", Failure::Connect, Body::Absent, 3));
    }

    #[test]
    fn retry_decision_default_methods_are_the_idempotent_set() {
        let retry = compiled(&json!({"attempts": 2})).expect("valid");
        for (method, retried) in [
            ("GET", true),
            ("HEAD", true),
            ("OPTIONS", true),
            ("PUT", true),
            ("DELETE", true),
            ("TRACE", true),
            ("POST", false),
            ("PATCH", false),
        ] {
            let request = request(method);
            let cx = error_cx(&request, Failure::Reused, Body::Absent);
            let verdict = retry.verdict(1, Duration::ZERO, &cx, 0);
            assert_eq!(matches!(verdict, Verdict::Yes { .. }), retried, "{method}");
        }
    }

    #[test]
    fn retry_decision_stops_at_the_request_deadline() {
        let retry = compiled(&json!({"attempts": 5, "initial_interval_ms": 1000})).expect("valid");
        let request = request("GET");
        let cx = ErrorCx {
            deadline: 10 * SECOND,
            ..error_cx(&request, Failure::Connect, Body::Absent)
        };
        // Retry 1 waits 500..=1000 ms; with 9.4 s gone the wait does not fit, with 8 s it does.
        assert_eq!(
            retry.verdict(1, Duration::from_millis(9_400), &cx, 1000),
            Verdict::No
        );
        assert_eq!(
            retry.verdict(1, 8 * SECOND, &cx, 1000),
            Verdict::Yes { backoff: SECOND }
        );
        // The wait is whole-request bounded: nothing is left once the deadline passed.
        assert_eq!(retry.verdict(1, 11 * SECOND, &cx, 0), Verdict::No);
    }

    #[test]
    fn retry_backoff_spacing() {
        let retry = compiled(&json!({"attempts": 5, "initial_interval_ms": 100})).expect("valid");
        // Doubling from the initial interval; jitter picks between half and all of each wait.
        for (failed, full_ms) in [(1_u32, 100_u64), (2, 200), (3, 400), (4, 800)] {
            let full = Duration::from_millis(full_ms);
            assert_eq!(retry.backoff(failed, 1000), full, "retry {failed}, no cut");
            assert_eq!(
                retry.backoff(failed, 0),
                full / 2,
                "retry {failed}, most cut"
            );
            assert!((full / 2..=full).contains(&retry.backoff(failed, 500)));
        }
        // Even the least wait of a retry is not shorter than the most of the one before.
        for failed in 1..4 {
            assert!(retry.backoff(failed + 1, 0) >= retry.backoff(failed, 1000));
        }
        let at_once = compiled(&json!({"attempts": 3, "initial_interval_ms": 0})).expect("valid");
        assert_eq!(at_once.backoff(2, 700), Duration::ZERO);
    }

    #[test]
    fn retry_attempts_over_cap_rejected() {
        for attempts in [0, MAX_ATTEMPTS + 1, 100] {
            let err = compiled(&json!({ "attempts": attempts })).expect_err("refused");
            assert_eq!(err.code, "invalid_middleware", "{attempts}");
        }
        for attempts in 1..=MAX_ATTEMPTS {
            assert!(
                compiled(&json!({ "attempts": attempts })).is_ok(),
                "{attempts}"
            );
        }
    }

    #[test]
    fn retry_statuses_unsupported() {
        let err = compiled(&json!({"attempts": 2, "retry_statuses": [502]})).expect_err("refused");
        assert_eq!(err.code, "unsupported_setting");
        assert!(err.message.contains("retry_statuses"), "{}", err.message);
    }

    #[test]
    fn retry_invalid_configs_are_invalid_middleware() {
        let ok = json!({"attempts": 2});
        let with = |key: &str, value: Value| {
            let mut config = ok.clone();
            config[key] = value;
            config
        };
        for config in [
            json!({}),
            with("initial_interval_ms", json!(MAX_INTERVAL_MS + 1)),
            with("initial_interval_ms", json!(-1)),
            with("methods", json!(["GE T"])),
            with("methods", json!([""])),
            with("methods", json!(vec!["GET"; MAX_METHODS + 1])),
            with("initialInterval", json!(100)),
            with("attempts", json!("3")),
        ] {
            let err = compiled(&config).expect_err(&config.to_string());
            assert_eq!(err.code, "invalid_middleware", "{config}");
        }
        assert!(
            compiled(&with("methods", json!([]))).is_ok(),
            "connect errors only"
        );
    }

    #[test]
    fn retry_methods_are_case_insensitive_and_deduplicated() {
        let retry =
            compiled(&json!({"attempts": 2, "methods": ["get", "GET", "Post"]})).expect("valid");
        assert_eq!(retry.methods.as_ref(), [Method::GET, Method::POST]);
    }
}
