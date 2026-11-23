//! What the middlewares that ask an external guard share: the verdict, the strict reader of the
//! guard's answer, `on_error`, the bounded call to one guard, the fan-out over several guards
//! and the posture of a guard. Used by `llm_guard`; the classifier of `content_guard` is one
//! [`Endpoint`] too. Reference: `docs/ref/mw-llm-guard.md`.
//!
//! The wire: podgate sends `POST <address>` with `{"phase": "request" | "response", "text":
//! "<text>"}`; the guard answers `200` and exactly `{"verdict": "allow" | "block", "category"?,
//! "reason"?}`. Anything else is a [`Failure`], and a failure closes the door unless that guard
//! says [`OnError::Allow`]. The text, the verdict's reason and the answer are never put into a
//! log line, a metric or explain by this file, except the guard's own `reason` (see
//! [`settle`]).
//!
//! A call dials through [`forward_auth::Client`] (the upstream address policy is checked for the
//! calling tenant on the exact address, every call), holds one permit of `max_concurrent`, goes
//! through a circuit and is charged to the tenant's buffer budget before a byte is sent.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::Semaphore;

use super::errors::fetch::{Failure as CallFailure, HEAD_LIMIT, READ};
use super::forward_auth::{self, Parsed, Route, parse_url};
use super::plugin::limits::{CIRCUIT_AFTER, CIRCUIT_FOR, Circuit, Permit};
use crate::budget::TenantBudget;
use crate::compile::Invalid;
use crate::error::AppError;
use crate::plan;
use crate::service::resolve::Resolver;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::service::{Server, Transport};

/// The most bytes of a guard's answer. A verdict is a few dozen bytes; more is a failure.
pub(in crate::middleware) const ANSWER_LIMIT: usize = 4 * 1024;
/// The most bytes of one call (head and JSON body). A longer call is not sent.
pub(in crate::middleware) const CALL_LIMIT: usize = 8 * 1024 * 1024;
/// The longest `address`.
pub(in crate::middleware) const MAX_ADDRESS: usize = 512;
/// The longest `reason` that is kept.
const MAX_REASON: usize = 1024;
/// The longest `category`.
const MAX_CATEGORY: usize = 64;
/// How much of a `reason` reaches the log.
const LOGGED_REASON: usize = 200;
/// What a call holds besides its own bytes: the answer head, the read buffers and the answer.
pub(in crate::middleware) const OVERHEAD: u64 = (HEAD_LIMIT + 2 * READ + ANSWER_LIMIT) as u64;

/// Posture change kinds of every guard-calling middleware, see
/// [`Kind::posture`](super::Kind::posture).
pub(in crate::middleware) mod kind {
    /// A guard that denied when it could not answer now lets the request through.
    pub(in crate::middleware) const FAIL_OPEN: &str = "guard_fail_open";
    /// A guard, or one of its phases, no longer judges the exchange.
    pub(in crate::middleware) const DROPPED: &str = "guard_dropped";
    /// A guard's server or path changed: another decision-maker answers.
    pub(in crate::middleware) const MOVED: &str = "guard_moved";
}

/// What a guard is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(in crate::middleware) enum Phase {
    /// The prompt, before the model is dialled.
    Request,
    /// The answer, before the client gets any byte of it.
    Response,
}

impl Phase {
    /// The word in the wire and in logs.
    pub(in crate::middleware) fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// What to do when a guard cannot answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(in crate::middleware) enum OnError {
    /// Close the door: `503`.
    #[default]
    Deny,
    /// Let the exchange through. A posture change in the plan.
    Allow,
}

/// What a guard says about a category, a short label that is safe to show a client:
/// `[a-z0-9][a-z0-9_.:-]{0,63}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::middleware) struct Category(Box<str>);

impl Category {
    fn parse(text: &str) -> Option<Self> {
        let mut bytes = text.bytes();
        let first = bytes.next()?;
        let ok = (first.is_ascii_lowercase() || first.is_ascii_digit())
            && text.len() <= MAX_CATEGORY
            && bytes.all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'_' | b'.' | b':' | b'-')
            });
        ok.then(|| Self(text.into()))
    }

    /// The label.
    pub(in crate::middleware) fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a guard decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::middleware) enum Verdict {
    /// Let it through.
    Allow,
    /// Stop it.
    Block {
        /// A label for the client.
        category: Option<Category>,
        /// Why, for the log; never sent to the client.
        reason: Option<Box<str>>,
    },
}

/// A guard's answer that is not a verdict.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub(in crate::middleware) struct Malformed(pub(in crate::middleware) &'static str);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    verdict: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// Reads a guard's `200` body: one JSON object with `verdict` `allow` or `block` and at most a
/// `category` and a `reason`. An unknown field, a repeated field, another verdict, a category
/// that is not a short label, a reason over 1 KiB or trailing bytes is [`Malformed`].
///
/// # Errors
///
/// [`Malformed`] naming what is wrong.
pub(in crate::middleware) fn parse_verdict(body: &[u8]) -> Result<Verdict, Malformed> {
    let wire: Wire = serde_json::from_slice(body)
        .map_err(|_| Malformed("the answer is not a verdict object"))?;
    let category = match wire.category.as_deref() {
        None => None,
        Some(text) => Some(Category::parse(text).ok_or(Malformed("the category is not a label"))?),
    };
    if wire
        .reason
        .as_ref()
        .is_some_and(|reason| reason.len() > MAX_REASON)
    {
        return Err(Malformed("the reason is over 1 KiB"));
    }
    match wire.verdict.as_str() {
        "allow" => Ok(Verdict::Allow),
        "block" => Ok(Verdict::Block {
            category,
            reason: wire.reason.map(Into::into),
        }),
        _ => Err(Malformed("the verdict is neither allow nor block")),
    }
}

/// Why a call did not produce a verdict. Every variant is a failure, never a pass.
#[derive(Debug, Error)]
pub(in crate::middleware) enum Failure {
    /// The guard has `max_concurrent` calls in flight.
    #[error("the guard is at max_concurrent")]
    Saturated,
    /// No tenant budget, or no room in it right now.
    #[error("the tenant's buffer budget has no room for the call")]
    OverBudget,
    /// The circuit is open.
    #[error("the guard's circuit is open")]
    Circuit,
    /// The call would be over [`CALL_LIMIT`].
    #[error("the call is too large to send")]
    TooLarge,
    /// The call itself failed (policy, connection, timeout, a malformed or oversized answer).
    #[error("{0}")]
    Call(#[from] CallFailure),
    /// The guard answered a status other than `200`.
    #[error("the guard answered status {0}")]
    Status(u16),
    /// The answer is not a verdict.
    #[error("{0}")]
    Malformed(#[from] Malformed),
}

impl Failure {
    /// Whether this says podgate or the tenant has no room right now, not that the guard is
    /// broken: `503` with `retry-after`, and auto-revert does not count it.
    #[must_use]
    pub(in crate::middleware) fn is_capacity(&self) -> bool {
        matches!(self, Self::Saturated | Self::OverBudget)
    }
}

/// Who is asking, for log lines.
#[derive(Debug, Clone, Copy)]
pub(in crate::middleware) struct Who<'a> {
    /// The app.
    pub(in crate::middleware) app: &'a str,
    /// The guard's name.
    pub(in crate::middleware) guard: &'a str,
    /// What it was shown.
    pub(in crate::middleware) phase: Phase,
}

/// What one guard's answer comes to once `on_error` is applied.
#[allow(
    variant_size_differences,
    reason = "a block carries the guard's label, the other two are one flag"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::middleware) enum Settled {
    /// Let it through; `degraded` when a guard could not answer and `on_error` is `allow`.
    Allow {
        /// A failure was waved through.
        degraded: bool,
    },
    /// The guard says stop.
    Block {
        /// A label for the client.
        category: Option<Category>,
    },
    /// The guard could not answer and `on_error` is `deny`.
    Closed {
        /// No room (busy), as opposed to broken.
        capacity: bool,
    },
}

impl Settled {
    /// The refusal this comes to, `Ok` for a pass.
    ///
    /// # Errors
    ///
    /// [`AppError::GuardBlocked`], [`AppError::GuardSaturated`] or [`AppError::GuardUnavailable`].
    pub(in crate::middleware) fn refusal(self) -> Result<(), AppError> {
        match self {
            Self::Allow { .. } => Ok(()),
            Self::Block { category } => Err(AppError::GuardBlocked {
                category: category.map(|category| category.0),
            }),
            Self::Closed { capacity: true } => Err(AppError::GuardSaturated),
            Self::Closed { capacity: false } => Err(AppError::GuardUnavailable),
        }
    }
}

/// Applies `on_error` to one call's result. A block's `reason` goes to the log, shortened and
/// stripped of control characters; a failure is logged with what failed, never with the text.
#[must_use]
pub(in crate::middleware) fn settle(
    result: Result<Verdict, Failure>,
    on_error: OnError,
    who: &Who<'_>,
) -> Settled {
    match result {
        Ok(Verdict::Allow) => Settled::Allow { degraded: false },
        Ok(Verdict::Block { category, reason }) => {
            let reason: String = reason
                .as_deref()
                .unwrap_or_default()
                .chars()
                .filter(|c| !c.is_control())
                .take(LOGGED_REASON)
                .collect();
            tracing::info!(
                app = who.app,
                guard = who.guard,
                phase = who.phase.name(),
                category = category.as_ref().map_or("", Category::as_str),
                reason = %reason,
                "guard blocked"
            );
            Settled::Block { category }
        }
        Err(why) => {
            tracing::warn!(
                app = who.app,
                guard = who.guard,
                phase = who.phase.name(),
                %why,
                fail_open = on_error == OnError::Allow,
                "guard could not answer"
            );
            match on_error {
                OnError::Allow => Settled::Allow { degraded: true },
                OnError::Deny => Settled::Closed {
                    capacity: why.is_capacity(),
                },
            }
        }
    }
}

/// What outlives a snapshot push for one guard: its permits and its circuit.
#[derive(Debug)]
pub(in crate::middleware) struct Runtime {
    permits: Semaphore,
    circuit: Circuit,
}

impl Runtime {
    /// A fresh runtime with `max_concurrent` permits.
    #[must_use]
    pub(in crate::middleware) fn new(max_concurrent: u32) -> Self {
        Self {
            permits: Semaphore::new(usize::try_from(max_concurrent).unwrap_or(usize::MAX)),
            circuit: Circuit::new(CIRCUIT_AFTER, CIRCUIT_FOR),
        }
    }
}

/// The runtimes of every guard of one middleware, in declaration order: the unit the swap site
/// carries over when a push leaves the middleware's declaration alone.
#[derive(Debug)]
pub(in crate::middleware) struct Runtimes(pub(in crate::middleware) Box<[Runtime]>);

/// What a call is made with.
#[derive(Debug, Clone, Copy)]
pub(in crate::middleware) struct Env<'a> {
    /// The bounded HTTP/1.1 client.
    pub(in crate::middleware) client: &'a forward_auth::Client,
    /// The operator's rule for the addresses the proxy may dial.
    pub(in crate::middleware) policy: &'a UpstreamPolicy,
    /// The tenant's budget; `None` closes the call, there is nothing to charge it to.
    pub(in crate::middleware) tenant: Option<&'a Arc<TenantBudget>>,
    /// The tenant the policy is applied for.
    pub(in crate::middleware) tenant_id: &'a str,
}

/// The settings every guard has, whatever middleware declares it.
#[derive(Debug, Clone, Copy)]
pub(in crate::middleware) struct EndpointSpec<'a> {
    /// The guard's name, for logs and explain.
    pub(in crate::middleware) name: &'a str,
    /// Its URL.
    pub(in crate::middleware) address: &'a str,
    /// What to do when it cannot answer.
    pub(in crate::middleware) on_error: OnError,
    /// The app's `servers_transport` to reach it with.
    pub(in crate::middleware) transport: Option<&'a str>,
    /// The bound on one call.
    pub(in crate::middleware) timeout: Duration,
    /// Calls in flight at once.
    pub(in crate::middleware) max_concurrent: u32,
}

/// A compiled guard.
#[derive(Debug)]
pub(in crate::middleware) struct Endpoint {
    name: Box<str>,
    server: Server,
    /// Resolves the address's host name; bound at compile ([`Self::bind`]).
    resolver: Resolver,
    transport: Arc<Transport>,
    transport_name: Option<Box<str>>,
    /// The `Host` header of the call: the authority as written.
    host: Box<str>,
    /// The request target of the call.
    target: Box<str>,
    on_error: OnError,
    timeout: Duration,
    max_concurrent: u32,
}

/// The call being made, with its place in the circuit: dropped before it is settled (the
/// fan-out cancelled it) it says nothing about the guard.
struct Pending<'a>(Option<Permit<'a>>);

impl Pending<'_> {
    fn settle(mut self, ok: bool) {
        if let Some(permit) = self.0.take() {
            permit.settle(ok);
        }
    }

    fn forget(mut self) {
        if let Some(permit) = self.0.take() {
            permit.forget();
        }
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if let Some(permit) = self.0.take() {
            permit.forget();
        }
    }
}

#[derive(Serialize)]
struct Call<'a> {
    phase: Phase,
    text: &'a str,
}

impl Endpoint {
    /// Compiles one guard. `what` prefixes every message (`"llm_guard: guard safety"`).
    ///
    /// # Errors
    ///
    /// `invalid_middleware` for an address that is not an absolute `http(s)://` URL, or a
    /// transport with TLS options on a plain address; `unknown_transport` for a transport the
    /// app does not declare.
    pub(in crate::middleware) fn compile(
        spec: &EndpointSpec<'_>,
        app: &podgate_model::App,
        what: &str,
    ) -> Result<Self, Invalid> {
        let invalid =
            |message: String| Invalid::new("invalid_middleware", format!("{what}: {message}"));
        let Parsed {
            server,
            host,
            target,
        } = parse_url(spec.address, "address", MAX_ADDRESS).map_err(invalid)?;
        let transport = match spec.transport {
            None => Arc::new(Transport::default()),
            Some(name) => {
                let declared = app
                    .transports
                    .iter()
                    .find(|declared| &*declared.name == name)
                    .ok_or_else(|| {
                        Invalid::new(
                            "unknown_transport",
                            format!("{what}: transport {name} is not declared by the app"),
                        )
                    })?;
                let transport = Transport::compile(declared)?;
                if !server.tls && transport.has_tls_settings() {
                    return Err(invalid(
                        "the transport sets TLS options and the address is plain http://".into(),
                    ));
                }
                Arc::new(transport)
            }
        };
        Ok(Self {
            name: spec.name.into(),
            server,
            resolver: Resolver::default(),
            transport,
            transport_name: spec.transport.map(Into::into),
            host,
            target,
            on_error: spec.on_error,
            timeout: spec.timeout,
            max_concurrent: spec.max_concurrent,
        })
    }

    /// Gives the guard the resolver its host name (when `address` has one) is resolved with.
    pub(in crate::middleware) fn bind(&mut self, resolver: &Resolver) {
        self.resolver = resolver.clone();
    }

    /// The guard's name.
    pub(in crate::middleware) fn name(&self) -> &str {
        &self.name
    }

    /// A fresh [`Runtime`] sized for this guard.
    pub(in crate::middleware) fn runtime(&self) -> Runtime {
        Runtime::new(self.max_concurrent)
    }

    /// Explain's view: where it is and its limits, never a text.
    pub(in crate::middleware) fn describe(&self) -> Value {
        let scheme = if self.server.tls { "https" } else { "http" };
        json!({
            "name": &*self.name,
            "address": format!(
                "{scheme}://{}{}",
                self.host,
                self.target.split('?').next().unwrap_or_default()
            ),
            "on_error": match self.on_error {
                OnError::Deny => "deny",
                OnError::Allow => "allow",
            },
            "timeout_ms": u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX),
            "transport": self.transport_name,
            "max_concurrent": self.max_concurrent,
        })
    }

    /// What got weaker when `new` (`None`: the guard is gone) replaces this guard.
    #[must_use]
    pub(in crate::middleware) fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::DROPPED];
        };
        let mut kinds = Vec::new();
        if self.server.url != new.server.url || self.target != new.target {
            kinds.push(kind::MOVED);
        }
        if self.on_error == OnError::Deny && new.on_error == OnError::Allow {
            kinds.push(kind::FAIL_OPEN);
        }
        if new.server.tls
            && new.transport.insecure_skip_verify()
            && !(self.server.tls && self.transport.insecure_skip_verify())
        {
            kinds.push(plan::kind::UPSTREAM_TLS_VERIFICATION_DISABLED);
        }
        kinds
    }

    /// The call: head and JSON body, `None` when together they pass [`CALL_LIMIT`].
    fn build(&self, phase: Phase, text: &str) -> Option<Vec<u8>> {
        let body = serde_json::to_vec(&Call { phase, text }).ok()?;
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\n\r\n",
            self.target,
            self.host,
            body.len()
        );
        if head.len() + body.len() > CALL_LIMIT {
            return None;
        }
        let mut call = Vec::with_capacity(head.len() + body.len());
        call.extend_from_slice(head.as_bytes());
        call.extend_from_slice(&body);
        Some(call)
    }

    /// Asks the guard about `text`: a permit of `max_concurrent`, the circuit, the tenant's
    /// charge, the call, the status and the verdict.
    ///
    /// # Errors
    ///
    /// A [`Failure`]; the caller applies `on_error` ([`settle`]).
    pub(in crate::middleware) async fn ask(
        &self,
        runtime: &Runtime,
        env: &Env<'_>,
        phase: Phase,
        text: &str,
    ) -> Result<Verdict, Failure> {
        let tenant = env.tenant.ok_or(Failure::OverBudget)?;
        let _slot = runtime
            .permits
            .try_acquire()
            .map_err(|_| Failure::Saturated)?;
        let pending = Pending(Some(runtime.circuit.admit().ok_or(Failure::Circuit)?));
        let Some(call) = self.build(phase, text) else {
            pending.forget();
            return Err(Failure::TooLarge);
        };
        let Some(_charge) = tenant.charge(OVERHEAD.saturating_add(len(&call))) else {
            pending.forget();
            return Err(Failure::OverBudget);
        };
        let route = Route {
            server: &self.server,
            transport: &self.transport,
            resolver: &self.resolver,
            policy: env.policy,
            tenant: env.tenant_id,
        };
        let answer = env
            .client
            .call(&route, &call, ANSWER_LIMIT, self.timeout)
            .await;
        match answer {
            // The policy refusing an address is the operator's rule, not the guard failing.
            Err(CallFailure::Policy) => {
                pending.forget();
                Err(CallFailure::Policy.into())
            }
            Err(why) => {
                pending.settle(false);
                Err(why.into())
            }
            Ok(answer) if answer.status != 200 => {
                pending.settle(false);
                Err(Failure::Status(answer.status))
            }
            Ok(answer) => match parse_verdict(&answer.body) {
                Ok(verdict) => {
                    pending.settle(true);
                    Ok(verdict)
                }
                Err(why) => {
                    pending.settle(false);
                    Err(why.into())
                }
            },
        }
    }
}

fn len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// A guard and its runtime, for [`run`].
#[derive(Debug, Clone, Copy)]
pub(in crate::middleware) struct Armed<'a> {
    /// The guard.
    pub(in crate::middleware) endpoint: &'a Endpoint,
    /// Its permits and circuit.
    pub(in crate::middleware) runtime: &'a Runtime,
}

/// Asks every guard of `guards` about `text` in parallel. The first refusal (a block, or a
/// failure that is `deny`) is the answer and the calls still pending are dropped, which closes
/// their connections; when every guard answered, the text passes, `degraded` if a failure was
/// waved through. Each call is bounded by its own timeout and they run together, so the phase
/// is bounded by the longest of them.
pub(in crate::middleware) async fn run(
    guards: &[Armed<'_>],
    env: &Env<'_>,
    phase: Phase,
    text: &str,
    app: &str,
) -> Settled {
    race(guards.iter().map(
        |armed| -> Pin<Box<dyn Future<Output = Settled> + Send + '_>> {
            Box::pin(async move {
                let result = armed.endpoint.ask(armed.runtime, env, phase, text).await;
                settle(
                    result,
                    armed.endpoint.on_error,
                    &Who {
                        app,
                        guard: &armed.endpoint.name,
                        phase,
                    },
                )
            })
        },
    ))
    .await
}

/// The first refusal among `calls`, or a pass when none refuses. Dropping the rest is what
/// cancels them.
async fn race<F: Future<Output = Settled>>(calls: impl IntoIterator<Item = F>) -> Settled {
    let mut pending: FuturesUnordered<F> = calls.into_iter().collect();
    let mut degraded = false;
    while let Some(settled) = pending.next().await {
        match settled {
            Settled::Allow { degraded: this } => degraded |= this,
            refusal => return refusal,
        }
    }
    Settled::Allow { degraded }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    use super::*;

    fn who() -> Who<'static> {
        Who {
            app: "a",
            guard: "g",
            phase: Phase::Request,
        }
    }

    fn parse(text: &str) -> Result<Verdict, Malformed> {
        parse_verdict(text.as_bytes())
    }

    #[test]
    fn guard_verdict_parser_is_strict() {
        assert_eq!(parse(r#"{"verdict":"allow"}"#), Ok(Verdict::Allow));
        assert_eq!(
            parse(r#"{"verdict":"block","category":"violence","reason":"because"}"#),
            Ok(Verdict::Block {
                category: Category::parse("violence"),
                reason: Some("because".into()),
            })
        );
        assert_eq!(
            parse(r#" {"verdict":"allow","category":null,"reason":null} "#),
            Ok(Verdict::Allow)
        );
        for bad in [
            "",
            "null",
            "[]",
            "true",
            r#"{}"#,
            r#"{"verdict":"Allow"}"#,
            r#"{"verdict":"deny"}"#,
            r#"{"verdict":"block","extra":1}"#,
            r#"{"verdict":"allow","verdict":"block"}"#,
            r#"{"verdict":"allow"} x"#,
            r#"{"verdict":"allow"}{"verdict":"allow"}"#,
            r#"{"verdict":1}"#,
            r#"{"verdict":"block","category":"Has Space"}"#,
            r#"{"verdict":"block","category":7}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let long = "a".repeat(MAX_REASON + 1);
        assert!(parse(&format!(r#"{{"verdict":"block","reason":"{long}"}}"#)).is_err());
    }

    #[test]
    fn guard_category_pattern() {
        for good in ["violence", "s1", "a", "self-harm", "pii:email", "x_y.z"] {
            assert!(Category::parse(good).is_some(), "{good}");
        }
        for bad in ["", "-a", "_a", "A", "a b", "a/b", "é", &"a".repeat(65)] {
            assert!(Category::parse(bad).is_none(), "{bad}");
        }
        assert!(Category::parse(&"a".repeat(64)).is_some());
    }

    #[test]
    fn guard_unknown_verdict_fails_closed() {
        let malformed = parse(r#"{"verdict":"maybe"}"#).expect_err("unknown verdict");
        let denied = settle(Err(malformed.into()), OnError::Deny, &who());
        assert_eq!(denied, Settled::Closed { capacity: false });
        assert!(matches!(denied.refusal(), Err(AppError::GuardUnavailable)));
    }

    #[test]
    fn guard_settle_follows_on_error() {
        let down = || Err(Failure::Status(500));
        assert_eq!(
            settle(down(), OnError::Deny, &who()),
            Settled::Closed { capacity: false }
        );
        assert_eq!(
            settle(down(), OnError::Allow, &who()),
            Settled::Allow { degraded: true }
        );
        assert_eq!(
            settle(Err(Failure::Saturated), OnError::Deny, &who()),
            Settled::Closed { capacity: true }
        );
        assert_eq!(
            settle(Ok(Verdict::Allow), OnError::Deny, &who()),
            Settled::Allow { degraded: false }
        );
        let block = Verdict::Block {
            category: Category::parse("pii"),
            reason: Some("secret text".into()),
        };
        let settled = settle(Ok(block), OnError::Allow, &who());
        assert_eq!(
            settled,
            Settled::Block {
                category: Category::parse("pii")
            },
            "a block is a block whatever on_error says"
        );
        let Err(AppError::GuardBlocked { category }) = settled.refusal() else {
            panic!("a block refuses");
        };
        assert_eq!(category.as_deref(), Some("pii"));
    }

    async fn after(wait: u64, settled: Settled) -> Settled {
        tokio::time::sleep(Duration::from_millis(wait)).await;
        settled
    }

    #[tokio::test]
    async fn guard_fanout_is_concurrent() {
        let start = Instant::now();
        let settled = race((0..3).map(|_| after(150, Settled::Allow { degraded: false }))).await;
        assert_eq!(settled, Settled::Allow { degraded: false });
        assert!(
            start.elapsed() < Duration::from_millis(300),
            "{:?}",
            start.elapsed()
        );
        let degraded = race([
            after(10, Settled::Allow { degraded: true }),
            after(10, Settled::Allow { degraded: false }),
        ])
        .await;
        assert_eq!(degraded, Settled::Allow { degraded: true });
    }

    struct Flag(Arc<AtomicBool>);

    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn guard_fanout_first_block_drops_the_rest() {
        let dropped = Arc::new(AtomicBool::new(false));
        let slow = {
            let flag = Flag(Arc::clone(&dropped));
            Box::pin(async move {
                let _flag = flag;
                tokio::time::sleep(Duration::from_secs(30)).await;
                Settled::Allow { degraded: false }
            }) as Pin<Box<dyn Future<Output = Settled> + Send>>
        };
        let block = Box::pin(after(
            20,
            Settled::Block {
                category: Category::parse("x"),
            },
        )) as Pin<Box<dyn Future<Output = Settled> + Send>>;
        let start = Instant::now();
        let settled = race([slow, block]).await;
        assert_eq!(
            settled,
            Settled::Block {
                category: Category::parse("x")
            }
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "the pending call is dropped"
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        let closed = race([
            Box::pin(after(10, Settled::Closed { capacity: false }))
                as Pin<Box<dyn Future<Output = Settled> + Send>>,
            Box::pin(after(5000, Settled::Allow { degraded: false })),
        ])
        .await;
        assert_eq!(
            closed,
            Settled::Closed { capacity: false },
            "a failure also ends the run"
        );
    }

    #[test]
    fn guard_cancelled_call_does_not_open_circuit() {
        let circuit = Circuit::new(CIRCUIT_AFTER, CIRCUIT_FOR);
        let cancelled = AtomicUsize::new(0);
        for _ in 0..CIRCUIT_AFTER * 3 {
            let pending = Pending(circuit.admit());
            assert!(
                pending.0.is_some(),
                "a cancelled call never opens the circuit"
            );
            drop(pending);
            cancelled.fetch_add(1, Ordering::SeqCst);
        }
        assert!(!circuit.is_open());
        for _ in 0..CIRCUIT_AFTER {
            Pending(circuit.admit()).settle(false);
        }
        assert!(circuit.is_open(), "real failures still open it");
    }

    fn endpoint(extra: &Value) -> Result<Endpoint, Invalid> {
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
        }))
        .expect("app");
        let on_error = if extra["on_error"] == "allow" {
            OnError::Allow
        } else {
            OnError::Deny
        };
        Endpoint::compile(
            &EndpointSpec {
                name: "g",
                address: extra["address"]
                    .as_str()
                    .unwrap_or("http://10.0.0.9:8080/check"),
                on_error,
                transport: None,
                timeout: Duration::from_millis(100),
                max_concurrent: 4,
            },
            &app,
            "test",
        )
    }

    #[test]
    fn guard_posture_lists_fail_open_dropped_moved() {
        let base = endpoint(&json!({})).expect("compiled");
        assert_eq!(base.posture(None), [kind::DROPPED]);
        assert!(
            base.posture(Some(&endpoint(&json!({})).expect("same")))
                .is_empty()
        );
        let open = endpoint(&json!({"on_error": "allow"})).expect("open");
        assert_eq!(base.posture(Some(&open)), [kind::FAIL_OPEN]);
        assert!(
            open.posture(Some(&base)).is_empty(),
            "stricter is not a relaxation"
        );
        let moved = endpoint(&json!({"address": "http://10.0.0.10:8080/check"})).expect("moved");
        assert_eq!(base.posture(Some(&moved)), [kind::MOVED]);
        let path = endpoint(&json!({"address": "http://10.0.0.9:8080/other"})).expect("path");
        assert_eq!(base.posture(Some(&path)), [kind::MOVED]);
    }

    #[test]
    fn guard_describe_hides_the_query() {
        let guard = endpoint(&json!({"address": "http://10.0.0.9:8080/check?key=hunter2"}))
            .expect("compiled");
        let shown = guard.describe().to_string();
        assert!(shown.contains("http://10.0.0.9:8080/check"), "{shown}");
        assert!(!shown.contains("hunter2"), "{shown}");
    }

    #[test]
    fn the_call_is_the_documented_wire() {
        let guard = endpoint(&json!({})).expect("compiled");
        let call = guard.build(Phase::Response, "say \"hi\"\n").expect("built");
        let text = String::from_utf8(call).expect("utf-8");
        let (head, body) = text.split_once("\r\n\r\n").expect("head and body");
        assert!(
            head.starts_with("POST /check HTTP/1.1\r\nHost: 10.0.0.9:8080\r\n"),
            "{head}"
        );
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        let body: Value = serde_json::from_str(body).expect("json");
        assert_eq!(body, json!({"phase": "response", "text": "say \"hi\"\n"}));
        let huge = "a".repeat(CALL_LIMIT);
        assert!(guard.build(Phase::Request, &huge).is_none());
    }
}
