//! The `ai_token_limit` middleware: each key may use `limit` tokens of a model per calendar
//! window, counted from what the model says it used, across all nodes in the shared store.
//! Reference: `docs/ref/mw-ai-token-limit.md`; the counter is [`crate::ratelimit_store::quota`].
//!
//! ```json
//! { "name": "tokens", "type": "ai_token_limit",
//!   "limits": [ { "limit": 100000, "period": "minute" }, { "limit": 5000000, "period": "month" } ],
//!   "source": { "header": "authorization" }, "store": "main", "on_store_error": "deny",
//!   "store_timeout_ms": 20, "max_prompt_bytes": 65536 }
//! ```
//!
//! - **Before the model.** A key whose remaining budget is zero in any window gets `429` with
//!   `retry-after` the seconds until every spent window resets, and no upstream is contacted. A
//!   JSON prompt over `max_prompt_bytes` gets `413`. Nothing else is refused: a request is never
//!   sized by a guess.
//! - **After the model.** The answer's `usage` (chat completions and the Responses API, a
//!   stream included) is charged to every window once the answer is over. An answer with no
//!   usable `usage` is charged an estimate of one token per 4 bytes of the exchange
//!   ([`usage`]).
//! - **Streams.** A streamed chat completion reports `usage` only when the request has
//!   `stream_options.include_usage`. When the client did not set it podgate adds it to the
//!   request ([`request`]) and takes the usage-only chunk out of the answer as it passes
//!   ([`sse`]), so the client sees the stream it asked for, unbuffered.
//! - **Compression.** The model is asked for `identity` and the count reads its bytes before the
//!   compressor ([`Kind::response_body_raw`]), which then encodes for the client.
//! - The tenant names a store and sets the limits; the address, credentials and the tenants that
//!   may use a store are the operator's (`RATE_LIMIT_STORES_FILE`). `store` and `on_store_error`
//!   are required.

mod request;
mod sse;
mod usage;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, EXPECT};
use pingora::http::{Method, RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use self::request::Plan;
use self::sse::Sse;
use self::usage::{MAX_TOKENS, Reported, estimate, reported};
use super::buffering::{declared_length, expects_continue};
use super::quota::{Keying, QuotaSource};
use super::{
    CompileCx, FinishCx, Flow, HeldSeen, Kind, Named, RequestCx, ResponseCx, Stage, state,
};
use crate::budget::{BufferGuard, Escaped};
use crate::compile::{Invalid, Rejected};
use crate::error::AppError;
use crate::ratelimit_store::quota::{
    Admission, Bound, Counter, MAX_LIMIT, Period, SourceId, Usage, now_secs,
};
use crate::ratelimit_store::{MAX_TIMEOUT_MS, Mode, Store, StoreError, Stores};
use crate::respond;
use crate::table::{CompiledApp, RoutingTable};
use podgate_model::{Declared, Snapshot};

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: nothing counts the route's tokens.
    pub const REMOVED: &str = "ai_tokens_removed";
    /// More tokens pass per unit of time: a higher limit, a window gone, or a longer period at
    /// the same limit (periods compare at their nominal length, a month counting 31 days).
    pub const LOOSENED: &str = "ai_tokens_loosened";
    /// Tokens are counted per another source, which can let a client leave its count.
    pub const SOURCE_CHANGED: &str = "ai_tokens_source_changed";
    /// A limit that did not admit requests when its store fails now does.
    pub const FAIL_OPEN: &str = "ai_tokens_fail_open";
}

/// The most windows one middleware counts.
const MAX_WINDOWS: usize = 4;

/// The largest prompt `max_prompt_bytes` may allow: Pingora's request replay buffer.
const MAX_PROMPT_BYTES: u32 = 64 * 1024;

/// The most bytes of one non-streaming answer read for its `usage` (about 64k tokens). A longer
/// answer is counted by the estimate.
const MAX_COUNTED_BODY: u64 = 256 * 1024;

/// What the event scanner may hold of one event, charged to the tenant.
const SSE_CARRY: u64 = sse::EVENT_MAX as u64;

/// How long a client has to send a prompt that is being read.
const REQUEST_BODY_DEADLINE: Duration = Duration::from_secs(30);

/// One window of a configuration.
#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WindowConfig {
    /// Tokens one key may use per window: 1 to 2^40.
    limit: u64,
    /// The calendar window, UTC.
    period: Period,
}

/// The configuration of an `ai_token_limit` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// One to four windows, one per period; a key is refused when any is spent.
    limits: Vec<WindowConfig>,
    source: QuotaSource,
    #[serde(default)]
    store: Option<String>,
    #[serde(default)]
    on_store_error: Option<Mode>,
    #[serde(default)]
    store_timeout_ms: Option<u16>,
    /// The most bytes of prompt that are held and judged (default and most 65536); a larger
    /// prompt is refused with `413`.
    #[serde(default)]
    max_prompt_bytes: Option<u32>,
}

/// One compiled window and its counter.
#[derive(Debug)]
struct Window {
    limit: u64,
    period: Period,
    counter: Arc<Counter>,
}

/// What the stage counts for the metrics, kept across snapshot pushes.
#[derive(Debug, Default)]
struct Stats {
    prompt: AtomicU64,
    completion: AtomicU64,
    other: AtomicU64,
    estimated: AtomicU64,
    estimated_answers: AtomicU64,
    refused: AtomicU64,
}

/// The state of one stage that outlives a snapshot push (see [`state`]).
#[derive(Debug)]
pub(crate) struct Runtime {
    tenant: Box<str>,
    app: Box<str>,
    stats: Stats,
}

/// Keeps the [`Runtime`] of every `ai_token_limit` across pushes, settled at the swap site.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtime>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            Stage::AiTokenLimit(limit) => Some((limit.fingerprint, &mut limit.runtime)),
            _ => None,
        });
    }
}

/// A compiled `ai_token_limit` middleware.
#[derive(Debug)]
pub struct AiTokenLimit {
    windows: Box<[Window]>,
    keying: Keying,
    store: Box<str>,
    mode: Mode,
    timeout_ms: Option<u16>,
    max_prompt_bytes: u32,
    fingerprint: u64,
    runtime: Arc<Runtime>,
}

/// What an answer costs, in tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Charge {
    /// The model's own report.
    Reported(Reported),
    /// The estimate, because the model reported nothing usable.
    Estimated(u64),
}

/// What the head of the upstream's answer says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Json,
    Events,
    Other,
}

/// The body to send in place of the client's, once per upstream attempt.
#[derive(Debug)]
struct Rewrite {
    body: Bytes,
    pending: bool,
}

/// A non-streaming answer being read for its `usage`.
#[derive(Debug)]
struct JsonBody {
    data: Vec<u8>,
    room: usize,
    _charge: Option<BufferGuard>,
}

/// How the answer is being counted.
#[derive(Debug)]
enum Answer {
    /// Read whole, up to the room reserved for it.
    Json(JsonBody),
    /// Scanned event by event.
    Stream(Box<Sse>),
    /// Only its bytes are counted.
    Blind,
}

/// What a request keeps of its stage once the stage admitted it.
#[derive(Debug, Default)]
struct Active {
    store: Option<Arc<Store>>,
    bounds: Vec<Bound>,
    /// The window with the least left at admission, for the response headers.
    tightest: Option<Usage>,
    /// What the held prompt and the scanner's carry are charged as, until the request ends.
    reservation: Vec<BufferGuard>,
    request_bytes: u64,
    rewrite: Option<Rewrite>,
    /// podgate added `include_usage`: the usage-only chunk is not the client's.
    drop_usage: bool,
    /// The request reached the model.
    forwarded: bool,
    /// The status of the model's answer; 0 before one arrived.
    status: u16,
    response_bytes: u64,
    answer: Option<Answer>,
    /// What the answer cost, counted from the complete raw body of a held answer before any
    /// verdict ([`Kind::response_held_seen`]); the charge, whatever happened to the answer after.
    held: Option<Charge>,
}

/// What a request keeps of its `ai_token_limit` stage: nothing until the stage admitted it.
#[derive(Debug, Default)]
pub struct State(Option<Box<Active>>);

/// Why a request is not admitted.
enum Refusal {
    Exceeded(Usage),
    Unavailable,
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("ai_token_limit: {message}"))
}

/// The `x-ratelimit-*-tokens` headers for `usage`, in the names OpenAI's own limits use.
fn headers(usage: &Usage) -> [(&'static str, String); 3] {
    [
        ("x-ratelimit-limit-tokens", usage.limit.to_string()),
        (
            "x-ratelimit-remaining-tokens",
            usage.remaining().to_string(),
        ),
        ("x-ratelimit-reset-tokens", usage.reset_secs.to_string()),
    ]
}

fn len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// Whether the request carries a JSON body podgate should read: not a tunnel, not empty.
fn reads_prompt(session: &mut Session) -> bool {
    if session.is_upgrade_req()
        || session.req_header().method == Method::CONNECT
        || session.is_body_empty()
    {
        return false;
    }
    media_type_is_json(session.req_header().headers.get(CONTENT_TYPE))
}

fn media_type_is_json(value: Option<&http::HeaderValue>) -> bool {
    let Some(value) = value.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let media = value.split(';').next().unwrap_or_default().trim();
    media.eq_ignore_ascii_case("application/json")
        || media
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
}

impl Shape {
    fn of(head: &ResponseHeader) -> Self {
        let media = head
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .unwrap_or_default();
        if media.eq_ignore_ascii_case("text/event-stream") {
            Self::Events
        } else if media_type_is_json(head.headers.get(CONTENT_TYPE)) {
            Self::Json
        } else {
            Self::Other
        }
    }
}

impl Shape {
    /// The shape of an answer a stage can read: a `2xx` that is not encoded. Anything else is
    /// only counted by size.
    fn classify(head: &ResponseHeader) -> Self {
        let plain = head
            .headers
            .get(CONTENT_ENCODING)
            .is_none_or(|value| value.as_bytes().eq_ignore_ascii_case(b"identity"));
        if plain && head.status.is_success() {
            Self::of(head)
        } else {
            Self::Other
        }
    }
}

/// What a held answer costs, from its complete body (`None` when the hold was dropped before the
/// answer ended: `body_bytes` is what had arrived): the same reading the streaming path ends in,
/// so a held answer and an unheld one are charged alike.
fn held_charge(shape: Shape, body: Option<&Bytes>, body_bytes: u64, request_bytes: u64) -> Charge {
    let found = body.and_then(|body| match shape {
        Shape::Json if len(body) <= MAX_COUNTED_BODY => serde_json::from_slice::<Whole>(body)
            .ok()
            .and_then(|whole| whole.usage)
            .as_ref()
            .and_then(reported),
        Shape::Events => {
            let mut events = Sse::new(false);
            events.push(body.clone(), true);
            events.best()
        }
        Shape::Json | Shape::Other => None,
    });
    found.map_or_else(
        || Charge::Estimated(estimate(request_bytes, body_bytes)),
        Charge::Reported,
    )
}

/// The `usage` of a whole JSON answer.
#[derive(Deserialize)]
struct Whole {
    #[serde(default)]
    usage: Option<Value>,
}

impl Active {
    /// What this request is charged, `None` when nothing is: it never reached the model, no
    /// answer came, or the model answered with an error.
    fn charge(&self) -> Option<Charge> {
        if let Some(held) = self.held
            && self.forwarded
            && (200..300).contains(&self.status)
        {
            return Some(held);
        }
        if !self.forwarded || !(200..300).contains(&self.status) {
            return None;
        }
        let found = match &self.answer {
            Some(Answer::Json(json)) => serde_json::from_slice::<Whole>(&json.data)
                .ok()
                .and_then(|whole| whole.usage)
                .as_ref()
                .and_then(reported),
            Some(Answer::Stream(sse)) => sse.best(),
            Some(Answer::Blind) | None => None,
        };
        Some(found.map_or_else(
            || Charge::Estimated(estimate(self.request_bytes, self.response_bytes)),
            Charge::Reported,
        ))
    }
}

impl AiTokenLimit {
    /// What the tenant needs to hold a prompt and the scanner's carry at once.
    fn reservation(&self) -> u64 {
        u64::from(self.max_prompt_bytes) + SSE_CARRY
    }

    async fn admit(
        &self,
        store: Option<&Arc<Store>>,
        id: SourceId,
    ) -> Result<Option<Box<Active>>, Refusal> {
        let Some(store) = store else {
            // The compiler checked the name against the same stores: this cannot be reached.
            return self.on_store_error(None, None).map(|()| None);
        };
        let now = now_secs();
        let mut bounds = Vec::with_capacity(self.windows.len());
        let mut tightest: Option<Usage> = None;
        let mut spent: Option<Usage> = None;
        for window in &self.windows {
            let bound = window.counter.bind(store, id);
            match bound.admit(0, now).await {
                Ok(Admission::Admitted(usage)) => {
                    if tightest.is_none_or(|best| {
                        (usage.remaining(), usage.reset_secs) < (best.remaining(), best.reset_secs)
                    }) {
                        tightest = Some(usage);
                    }
                }
                Ok(Admission::Exhausted(usage)) => {
                    // The key is back only when every spent window has reset.
                    if spent.is_none_or(|worst| usage.reset_secs > worst.reset_secs) {
                        spent = Some(usage);
                    }
                }
                Err(error) => {
                    return self
                        .on_store_error(Some(store), Some(&error))
                        .map(|()| None);
                }
            }
            bounds.push(bound);
        }
        if let Some(usage) = spent {
            return Err(Refusal::Exceeded(usage));
        }
        Ok(Some(Box::new(Active {
            store: Some(Arc::clone(store)),
            bounds,
            tightest,
            ..Active::default()
        })))
    }

    fn on_store_error(
        &self,
        store: Option<&Arc<Store>>,
        error: Option<&StoreError>,
    ) -> Result<(), Refusal> {
        if let Some(store) = store {
            store.count_quota_error(self.mode);
            if let Some(error) = error {
                tracing::debug!(store = store.name(), %error, "ai token limit store error");
            }
        }
        match self.mode {
            Mode::Allow => {
                if let Some(store) = store {
                    store.count_quota_unmetered();
                }
                Ok(())
            }
            Mode::Deny => Err(Refusal::Unavailable),
        }
    }

    /// Reads the JSON prompt into the replay buffer, so the stage and the model both have it,
    /// and decides what to do to it. The inner `Err` is the refusal to write.
    async fn hold(
        &self,
        cx: &mut RequestCx<'_>,
        active: &mut Active,
        declared: Option<u64>,
    ) -> pingora::Result<Result<(), AppError>> {
        let max = u64::from(self.max_prompt_bytes);
        let Some(tenant) = cx.tenant else {
            *cx.capacity_refusal = true;
            return Ok(Err(AppError::BufferingOverBudget));
        };
        let Some(guard) = tenant.reserve_buffering(declared.unwrap_or(max)) else {
            *cx.capacity_refusal = true;
            return Ok(Err(AppError::BufferingOverBudget));
        };
        active.reservation.push(guard);
        let session = &mut *cx.session;
        if !*cx.body_held {
            if expects_continue(session.req_header()) {
                // The client waits for this before it sends the body; the model never sees the
                // expectation, because the body is complete when its request starts.
                session.write_continue_response().await?;
                session.req_header_mut().remove_header(&EXPECT);
            }
            session.enable_retry_buffering();
            let read = timeout(REQUEST_BODY_DEADLINE, async {
                let mut total = 0_u64;
                while let Some(chunk) = session.read_request_body().await? {
                    total = total.saturating_add(len(&chunk));
                    if total > max {
                        return Ok(Err(AppError::PayloadTooLarge));
                    }
                }
                Ok::<_, Box<pingora::Error>>(Ok(()))
            })
            .await;
            match read {
                Ok(read) => {
                    if let Err(refusal) = read? {
                        return Ok(Err(refusal));
                    }
                }
                Err(_) => return Ok(Err(AppError::RequestTimeout)),
            }
            if session.retry_buffer_truncated() {
                return Err(pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    "request body does not fit the replay buffer",
                ));
            }
            *cx.body_held = true;
        }
        let body = session.get_retry_buffer().unwrap_or_default();
        if len(&body) > max {
            return Ok(Err(AppError::PayloadTooLarge));
        }
        active.request_bytes = len(&body);
        if let Plan::Rewrite(new) = request::plan(&body) {
            // The scanner must always be able to hold a partial event: charged before the model
            // is asked for the extra chunk.
            let Some(carry) = tenant.reserve_buffering(SSE_CARRY) else {
                *cx.capacity_refusal = true;
                return Ok(Err(AppError::BufferingOverBudget));
            };
            active.reservation.push(carry);
            active.drop_usage = true;
            active.rewrite = Some(Rewrite {
                body: new,
                pending: false,
            });
        }
        Ok(Ok(()))
    }

    /// Charges the tokens of a finished request to every window, in a task of its own: the
    /// response is already served.
    fn settle(&self, active: Active, charge: Charge) {
        let (prompt, completion, other, estimated) = match charge {
            Charge::Reported(found) => (found.prompt, found.completion, found.other, 0),
            Charge::Estimated(tokens) => (0, 0, 0, tokens),
        };
        let stats = &self.runtime.stats;
        stats.prompt.fetch_add(prompt, Ordering::Relaxed);
        stats.completion.fetch_add(completion, Ordering::Relaxed);
        stats.other.fetch_add(other, Ordering::Relaxed);
        if estimated > 0 {
            stats.estimated.fetch_add(estimated, Ordering::Relaxed);
            stats.estimated_answers.fetch_add(1, Ordering::Relaxed);
        }
        let amount = (prompt + completion + other + estimated).min(MAX_TOKENS);
        let (bounds, store, mode) = (active.bounds, active.store, self.mode);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            let now = now_secs();
            let mut lost = false;
            for bound in bounds {
                if let Err(error) = bound.charge(amount, now).await {
                    lost = true;
                    if let Some(store) = &store {
                        tracing::debug!(store = store.name(), %error, "ai token charge failed");
                    }
                }
            }
            if lost && let Some(store) = &store {
                store.count_quota_error(mode);
                store.count_quota_unmetered();
            }
        });
    }
}

impl Kind for AiTokenLimit {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        if !declared.config.contains_key("store") {
            return Err(invalid(
                "`store` is required, the name of a store: a token budget has no node scope, because a budget that resets when the process restarts is not a budget",
            ));
        }
        if !declared.config.contains_key("on_store_error") {
            return Err(invalid(
                "`on_store_error` is required: `allow` (requests pass, and are counted in podgate_quota_unmetered_total, while the store is unavailable) or `deny` (`503`); failing open removes the protection exactly when something is wrong, and failing closed turns a store outage into a site outage, so there is no default",
            ));
        }
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        if !(1..=MAX_WINDOWS).contains(&config.limits.len()) {
            return Err(invalid(format!(
                "`limits` must hold 1 to {MAX_WINDOWS} windows"
            )));
        }
        for (at, window) in config.limits.iter().enumerate() {
            if !(1..=MAX_LIMIT).contains(&window.limit) {
                return Err(invalid(format!(
                    "`limits[{at}].limit` must be 1 to {MAX_LIMIT}"
                )));
            }
            if config.limits[..at]
                .iter()
                .any(|earlier| earlier.period == window.period)
            {
                return Err(invalid(format!(
                    "`limits` has the period {} twice: one window per period",
                    window.period.name()
                )));
            }
        }
        let Some(store) = config.store.filter(|store| !store.is_empty()) else {
            return Err(invalid("`store` must name a store"));
        };
        let Some(mode) = config.on_store_error else {
            return Err(invalid("`on_store_error` must be `allow` or `deny`"));
        };
        if let Some(timeout_ms) = config.store_timeout_ms
            && !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms)
        {
            return Err(invalid(format!(
                "`store_timeout_ms` must be 1 to {MAX_TIMEOUT_MS}"
            )));
        }
        let max_prompt_bytes = config.max_prompt_bytes.unwrap_or(MAX_PROMPT_BYTES);
        if !(1..=MAX_PROMPT_BYTES).contains(&max_prompt_bytes) {
            return Err(invalid(format!(
                "`max_prompt_bytes` must be 1 to {MAX_PROMPT_BYTES}: Pingora hands a body read ahead of the upstream request over through a 64 KiB replay buffer"
            )));
        }
        let keying = Keying::compile(config.source, "ai_token_limit")?;
        let timeout = config
            .store_timeout_ms
            .map(|millis| Duration::from_millis(u64::from(millis)));
        let windows = config
            .limits
            .iter()
            .map(|window| {
                // Only what names the counter: the limit, the timeout and the failure choice
                // change nothing a client has used. `admit` compares the count with the current
                // limit, so a lowered limit never hands out what was used already.
                let identity = json!({
                    "period": window.period.name(),
                    "source": keying.describe(),
                    "store": store,
                })
                .to_string();
                let fingerprint = u64::from_be_bytes(
                    Sha256::digest(identity.as_bytes())[..8]
                        .try_into()
                        .unwrap_or_default(),
                );
                Window {
                    limit: window.limit,
                    period: window.period,
                    counter: Counter::new(
                        &cx.app.tenant,
                        &cx.app.id,
                        &declared.name,
                        fingerprint,
                        window.period,
                        window.limit,
                        timeout,
                    ),
                }
            })
            .collect();
        Ok(Self {
            windows,
            keying,
            store: store.into(),
            mode,
            timeout_ms: config.store_timeout_ms,
            max_prompt_bytes,
            fingerprint: state::fingerprint(declared),
            runtime: Arc::new(Runtime {
                tenant: Box::from(&*cx.app.tenant),
                app: Box::from(&*cx.app.id),
                stats: Stats::default(),
            }),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        let reads = reads_prompt(cx.session);
        let declared = declared_length(&cx.session.req_header().headers);
        if reads && declared.is_some_and(|declared| declared > u64::from(self.max_prompt_bytes)) {
            let refusal = if expects_continue(cx.session.req_header()) {
                AppError::ExpectationFailed
            } else {
                AppError::PayloadTooLarge
            };
            respond::write_error(cx.session, &refusal).await?;
            return Ok(Flow::Respond);
        }
        let id = self.keying.id(cx);
        let admitted = self.admit(cx.stores.get(&self.store), id).await;
        let mut active = match admitted {
            Ok(Some(active)) => active,
            Ok(None) => return Ok(Flow::Continue),
            Err(refusal) => {
                *cx.capacity_refusal = true;
                match refusal {
                    Refusal::Exceeded(usage) => {
                        self.runtime.stats.refused.fetch_add(1, Ordering::Relaxed);
                        let err = AppError::AiTokensExceeded {
                            retry_after_secs: usage.reset_secs,
                        };
                        *cx.reason = Some(err.log_reason());
                        respond::write_error_with(cx.session, &err, &headers(&usage)).await?;
                    }
                    Refusal::Unavailable => {
                        let err = AppError::AiTokensUnavailable;
                        *cx.reason = Some(err.log_reason());
                        respond::write_error(cx.session, &err).await?;
                    }
                }
                return Ok(Flow::Respond);
            }
        };
        if reads && let Err(refusal) = self.hold(cx, &mut active, declared).await? {
            respond::write_error(cx.session, &refusal).await?;
            return Ok(Flow::Respond);
        }
        state.0 = Some(active);
        Ok(Flow::Continue)
    }

    fn upstream_request(
        &self,
        request: &mut RequestHeader,
        state: &mut State,
    ) -> pingora::Result<()> {
        let Some(active) = state.0.as_deref_mut() else {
            return Ok(());
        };
        active.forwarded = true;
        // A model that answers plain text can be read; podgate's own compressor encodes for the
        // client afterwards, from the client's own `Accept-Encoding`.
        request.insert_header(ACCEPT_ENCODING, "identity")?;
        if let Some(rewrite) = &mut active.rewrite {
            rewrite.pending = true;
            if request.headers.contains_key(CONTENT_LENGTH) {
                request.insert_header(CONTENT_LENGTH, rewrite.body.len().to_string())?;
            }
        }
        Ok(())
    }

    fn request_body(&self, bytes_read: u64, state: &mut State) -> Result<(), AppError> {
        if let Some(active) = state.0.as_deref_mut() {
            active.request_bytes = active.request_bytes.max(bytes_read);
        }
        Ok(())
    }

    fn request_body_chunk(
        &self,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        state: &mut State,
    ) -> Result<(), AppError> {
        if let Some(active) = state.0.as_deref_mut()
            && let Some(rewrite) = &mut active.rewrite
            && body.is_some()
            && std::mem::take(&mut rewrite.pending)
        {
            // Pingora replays a held body as one chunk: this is the whole body, on a retry too.
            *body = Some(rewrite.body.clone());
        }
        Ok(())
    }

    fn response_head(&self, cx: &ResponseCx<'_>, state: &mut State) -> Result<(), AppError> {
        let Some(active) = state.0.as_deref_mut() else {
            return Ok(());
        };
        let head = cx.response;
        active.status = head.status.as_u16();
        let shape = Shape::classify(head);
        active.answer = Some(match shape {
            Shape::Events => Answer::Stream(Box::new(Sse::new(active.drop_usage))),
            // A held answer was counted whole already: no second reading.
            Shape::Json if active.held.is_none() => {
                let declared = declared_length(&head.headers);
                let room =
                    declared.map_or(MAX_COUNTED_BODY, |declared| declared.min(MAX_COUNTED_BODY));
                match cx.tenant.and_then(|tenant| tenant.charge(room)) {
                    Some(charge) => Answer::Json(JsonBody {
                        data: Vec::new(),
                        room: usize::try_from(room).unwrap_or(usize::MAX),
                        _charge: Some(charge),
                    }),
                    None => Answer::Blind,
                }
            }
            Shape::Json | Shape::Other => Answer::Blind,
        });
        // A stream read event by event holds a partial event: charged now when no rewrite
        // reserved the carry at admission.
        if matches!(active.answer, Some(Answer::Stream(_)))
            && !active.drop_usage
            && let Some(carry) = cx.tenant.and_then(|tenant| tenant.charge(SSE_CARRY))
        {
            active.reservation.push(carry);
        }
        Ok(())
    }

    fn response_held_seen(&self, cx: &HeldSeen<'_>, state: &mut State) {
        let Some(active) = state.0.as_deref_mut() else {
            return;
        };
        // The answer is judged next, and may never reach the client or the hooks above: what
        // the model spent is counted now, from its complete raw body, whatever the verdict.
        active.status = cx.head.status.as_u16();
        active.held = Some(held_charge(
            Shape::classify(cx.head),
            cx.body,
            cx.body_bytes,
            active.request_bytes,
        ));
    }

    fn response(&self, response: &mut ResponseHeader, state: &mut State) -> pingora::Result<()> {
        let Some(active) = state.0.as_deref() else {
            return Ok(());
        };
        for name in [
            "x-ratelimit-limit-tokens",
            "x-ratelimit-remaining-tokens",
            "x-ratelimit-reset-tokens",
        ] {
            response.remove_header(name);
        }
        if let Some(usage) = &active.tightest {
            for (name, value) in headers(usage) {
                response.insert_header(name, value)?;
            }
        }
        // An event may be taken out of the stream: the length the model declared is no longer
        // the length that is sent.
        if active.drop_usage && matches!(active.answer, Some(Answer::Stream(_))) {
            response.remove_header(&CONTENT_LENGTH);
        }
        Ok(())
    }

    fn response_body_raw(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        state: &mut State,
    ) -> pingora::Result<()> {
        let Some(active) = state.0.as_deref_mut() else {
            return Ok(());
        };
        active.response_bytes = active
            .response_bytes
            .saturating_add(body.as_ref().map_or(0, |chunk| len(chunk)));
        match &mut active.answer {
            Some(Answer::Stream(sse)) => {
                let out = sse.push(body.take().unwrap_or_default(), end_of_stream);
                *body = (!out.is_empty()).then_some(out);
            }
            Some(Answer::Json(json)) => {
                if let Some(chunk) = body.as_ref() {
                    if json.data.len().saturating_add(chunk.len()) > json.room {
                        // Too long to read: counted by the estimate.
                        active.answer = Some(Answer::Blind);
                    } else {
                        json.data.extend_from_slice(chunk);
                    }
                }
            }
            Some(Answer::Blind) | None => {}
        }
        Ok(())
    }

    fn finished(&self, _cx: &FinishCx<'_>, state: &mut State) {
        let Some(active) = state.0.take() else {
            return;
        };
        if let Some(charge) = active.charge() {
            self.settle(*active, charge);
        }
    }

    /// Dropping the middleware stops counting; a higher limit, a window gone or a longer period
    /// lets more through; another source puts requests in other counts; a budget that starts
    /// failing open lets a client past its count while the store is down.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let mut kinds = Vec::new();
        // An old window is still bounded when some new window passes no more tokens per second:
        // new.limit / new.period <= old.limit / old.period, as a cross product.
        let loosened = self.windows.iter().any(|old| {
            !new.windows.iter().any(|next| {
                u128::from(next.limit) * u128::from(old.period.nominal_secs())
                    <= u128::from(old.limit) * u128::from(next.period.nominal_secs())
            })
        });
        if loosened {
            kinds.push(kind::LOOSENED);
        }
        if self.keying.differs(&new.keying) {
            kinds.push(kind::SOURCE_CHANGED);
        }
        if new.mode == Mode::Allow && self.mode != Mode::Allow {
            kinds.push(kind::FAIL_OPEN);
        }
        kinds
    }

    fn describe(&self) -> Value {
        json!({
            "limits": self
                .windows
                .iter()
                .map(|window| json!({ "limit": window.limit, "period": window.period.name() }))
                .collect::<Vec<_>>(),
            "source": self.keying.describe(),
            "store": self.store,
            "on_store_error": match self.mode {
                Mode::Allow => "allow",
                Mode::Deny => "deny",
            },
            "store_timeout_ms": self.timeout_ms,
            "max_prompt_bytes": self.max_prompt_bytes,
        })
    }
}

/// Refuses the budgets whose store the tenant may not use, and the apps whose tenant cannot
/// hold one prompt and a scanner's carry. A store that does not exist and one the tenant is not
/// listed for give the same answer, so a tenant cannot find out which stores other tenants use.
pub(crate) fn check_snapshot(
    snapshot: &Snapshot,
    stages: &[&[Named]],
    stores: &Stores,
) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    for (app, stages) in snapshot.apps.iter().zip(stages) {
        let budget = snapshot
            .tenants
            .iter()
            .find(|tenant| tenant.id == app.tenant)
            .map(|tenant| tenant.budget.max_buffer_bytes);
        for named in *stages {
            let Stage::AiTokenLimit(limit) = &named.stage else {
                continue;
            };
            let at = format!("middleware {}", named.name);
            if !stores.allows(&limit.store, &app.tenant) {
                rejected.push(Rejected::new(
                    app,
                    at,
                    invalid(format!(
                        "store {:?} is not available to tenant {}; stores are listed in the operator's RATE_LIMIT_STORES_FILE",
                        limit.store, app.tenant
                    )),
                ));
            } else if let Some(budget) = budget
                && budget < limit.reservation()
            {
                rejected.push(Rejected::new(
                    app,
                    at,
                    invalid(format!(
                        "tenant {} may buffer {budget} bytes (`max_buffer_bytes`), less than the {} bytes one request needs to hold a prompt of `max_prompt_bytes` and the scanner's carry of one event",
                        app.tenant,
                        limit.reservation()
                    )),
                ));
            }
        }
    }
    rejected
}

/// Refuses a chain that holds two `ai_token_limit` stages: the first to see the usage-only chunk
/// would hide it from the second, so only one counts. One stage counts several windows.
///
/// # Errors
///
/// `invalid_middleware` naming both stages.
pub(crate) fn check_one_per_chain(stages: &[Named], chain: &[usize]) -> Result<(), Invalid> {
    let mut found = chain.iter().filter_map(|index| {
        let named = stages.get(*index)?;
        matches!(named.stage, Stage::AiTokenLimit(_)).then_some(&named.name)
    });
    match (found.next(), found.next()) {
        (Some(first), Some(second)) => Err(invalid(format!(
            "middlewares {first} and {second} are both in one chain: only one counts the tokens of an answer, and it takes several windows in `limits`"
        ))),
        _ => Ok(()),
    }
}

/// The Prometheus exposition of every `ai_token_limit` stage of `live`, summed per app:
/// `podgate_ai_tokens_total` (by `kind`), `podgate_ai_tokens_estimated_total` and
/// `podgate_ai_tokens_refused_total`. No key, model or route is a label, so the series per app
/// do not grow with traffic.
pub(crate) fn render(live: &RoutingTable) -> String {
    let mut rows: BTreeMap<(&str, &str), [u64; 6]> = BTreeMap::new();
    for app in live.apps() {
        for named in app.stages() {
            let Stage::AiTokenLimit(limit) = &named.stage else {
                continue;
            };
            let runtime = &limit.runtime;
            let stats = &runtime.stats;
            let row = rows.entry((&*runtime.tenant, &*runtime.app)).or_default();
            for (slot, counter) in row.iter_mut().zip([
                &stats.prompt,
                &stats.completion,
                &stats.other,
                &stats.estimated,
                &stats.estimated_answers,
                &stats.refused,
            ]) {
                *slot += counter.load(Ordering::Relaxed);
            }
        }
    }
    let mut out = String::new();
    if rows.is_empty() {
        return out;
    }
    // Writing to a `String` cannot fail.
    let _ = writeln!(
        out,
        "# HELP podgate_ai_tokens_total Tokens charged to keys, by kind: what the model reported for the prompt and the completion, a total it did not split, and the estimate used when it reported nothing usable.\n# TYPE podgate_ai_tokens_total counter"
    );
    for ((tenant, app), row) in &rows {
        for (kind, value) in ["prompt", "completion", "other", "estimated"]
            .into_iter()
            .zip(row)
        {
            let _ = writeln!(
                out,
                "podgate_ai_tokens_total{{tenant=\"{}\",app=\"{}\",kind=\"{kind}\"}} {value}",
                Escaped(tenant),
                Escaped(app)
            );
        }
    }
    for (name, help, at) in [
        (
            "podgate_ai_tokens_estimated_total",
            "Answers charged the estimate because the model reported no usable usage.",
            4,
        ),
        (
            "podgate_ai_tokens_refused_total",
            "Requests refused with 429 because a key's token budget was spent.",
            5,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
        for ((tenant, app), row) in &rows {
            let _ = writeln!(
                out,
                "{name}{{tenant=\"{}\",app=\"{}\"}} {}",
                Escaped(tenant),
                Escaped(app),
                row.get(at).copied().unwrap_or_default()
            );
        }
    }
    out
}

#[cfg(test)]
mod test {
    use super::*;

    fn active(status: u16, answer: Option<Answer>) -> Active {
        Active {
            forwarded: true,
            status,
            request_bytes: 40,
            response_bytes: 80,
            answer,
            ..Active::default()
        }
    }

    fn json_answer(body: &str) -> Answer {
        Answer::Json(JsonBody {
            data: body.as_bytes().to_vec(),
            room: body.len(),
            _charge: None,
        })
    }

    #[test]
    fn ai_charge_follows_the_answer() {
        let reported = r#"{"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}"#;
        assert_eq!(
            active(200, Some(json_answer(reported))).charge(),
            Some(Charge::Reported(Reported {
                prompt: 3,
                completion: 4,
                other: 0
            }))
        );
        // The estimate: (40 + 80) / 4.
        for body in [
            r#"{"usage":{"total_tokens":-1}}"#,
            r#"{"id":1}"#,
            "not json",
        ] {
            assert_eq!(
                active(200, Some(json_answer(body))).charge(),
                Some(Charge::Estimated(30)),
                "{body}"
            );
        }
        assert_eq!(
            active(200, Some(Answer::Blind)).charge(),
            Some(Charge::Estimated(30))
        );
        // The model failed or refused: nothing was spent. No answer yet: nothing either.
        assert_eq!(active(500, Some(Answer::Blind)).charge(), None);
        assert_eq!(active(429, Some(json_answer(reported))).charge(), None);
        assert_eq!(active(0, None).charge(), None);
        let mut never_sent = active(200, Some(json_answer(reported)));
        never_sent.forwarded = false;
        assert_eq!(never_sent.charge(), None);
    }

    #[test]
    fn ai_held_charge_is_the_streaming_function() {
        // A whole answer read once and the same answer streamed in pieces cost the same.
        let json = |usage: &str| format!(r#"{{"id":"c","usage":{usage}}}"#);
        for usage in [
            r#"{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}"#,
            r#"{"total_tokens":-1}"#,
            r#"{"input_tokens":5,"output_tokens":6}"#,
            "null",
        ] {
            let body = json(usage);
            let held = held_charge(
                Shape::Json,
                Some(&Bytes::from(body.clone())),
                len(body.as_bytes()),
                40,
            );
            let mut streamed = active(200, Some(json_answer(&body)));
            streamed.response_bytes = len(body.as_bytes());
            assert_eq!(streamed.charge(), Some(held), "{usage}");
        }
        let events = format!(
            "data: {{\"choices\":[{{\"delta\":{{}}}}],\"usage\":null}}\n\ndata: {{\"choices\":[],\"usage\":{{\"prompt_tokens\":3,\"completion_tokens\":4,\"total_tokens\":7}}}}\n\ndata: [DONE]\n\n"
        );
        let held = held_charge(
            Shape::Events,
            Some(&Bytes::from(events.clone())),
            len(events.as_bytes()),
            40,
        );
        let mut sse = Sse::new(true);
        for piece in events.as_bytes().chunks(13) {
            sse.push(Bytes::copy_from_slice(piece), false);
        }
        sse.push(Bytes::new(), true);
        let streamed = active(200, Some(Answer::Stream(Box::new(sse))));
        assert_eq!(streamed.charge(), Some(held));
        assert_eq!(
            held,
            Charge::Reported(Reported {
                prompt: 3,
                completion: 4,
                other: 0
            })
        );
        // A hold dropped before the answer ended is the estimate of what had arrived.
        assert_eq!(
            held_charge(Shape::Json, None, 160, 40),
            Charge::Estimated(50)
        );
        // A held answer is charged once: its own count wins over the streamed one.
        let mut both = active(200, Some(json_answer(&json(r#"{"total_tokens":999}"#))));
        both.held = Some(Charge::Estimated(5));
        assert_eq!(both.charge(), Some(Charge::Estimated(5)));
        let mut refused_upstream = both;
        refused_upstream.status = 500;
        assert_eq!(refused_upstream.charge(), None);
    }

    #[test]
    fn ai_config_requires_store_and_failure_choice() {
        let compile = |config: Value| -> Result<AiTokenLimit, Invalid> {
            let declared: Declared = serde_json::from_value(json!({
                "name": "t", "type": "ai_token_limit",
                "limits": [{"limit": 10, "period": "day"}],
                "source": {"header": "x-key"},
            }))
            .map(|mut declared: Declared| {
                declared
                    .config
                    .extend(config.as_object().cloned().unwrap_or_default());
                declared
            })
            .expect("declared");
            let app = test_app();
            let mut engine = crate::wasm::Compiler::default();
            AiTokenLimit::compile(
                &declared,
                &mut CompileCx {
                    app: &app,
                    engine: &mut engine,
                },
            )
        };
        let message = |config: Value| compile(config).expect_err("refused").message;
        assert!(message(json!({})).contains("`store` is required"));
        assert!(message(json!({"store": "main"})).contains("`on_store_error` is required"));
        assert!(compile(json!({"store": "main", "on_store_error": "deny"})).is_ok());
        assert!(message(json!({"store": "", "on_store_error": "deny"})).contains("name a store"));
        assert!(
            message(json!({"store": "m", "on_store_error": "deny", "scope": "node"}))
                .contains("scope")
        );
    }

    #[test]
    fn ai_config_rejects_bad_windows() {
        let compile = |limits: Value, extra: Value| -> Option<String> {
            let mut config = json!({
                "name": "t", "type": "ai_token_limit", "limits": limits,
                "source": {"header": "x-key"}, "store": "main", "on_store_error": "deny",
            });
            config
                .as_object_mut()
                .expect("object")
                .extend(extra.as_object().cloned().unwrap_or_default());
            let declared: Declared = serde_json::from_value(config).expect("declared");
            let app = test_app();
            let mut engine = crate::wasm::Compiler::default();
            AiTokenLimit::compile(
                &declared,
                &mut CompileCx {
                    app: &app,
                    engine: &mut engine,
                },
            )
            .err()
            .map(|invalid| invalid.message)
        };
        let day = |limit: u64| json!({"limit": limit, "period": "day"});
        assert_eq!(compile(json!([day(1)]), json!({})), None);
        let four = json!([
            {"limit": 1, "period": "minute"}, {"limit": 1, "period": "hour"},
            day(1), {"limit": 1, "period": "month"},
        ]);
        assert_eq!(compile(four, json!({})), None);
        for limits in [
            json!([]),
            json!([day(0)]),
            json!([day((1_u64 << 40) + 1)]),
            json!([day(1), day(2)]),
        ] {
            assert!(compile(limits.clone(), json!({})).is_some(), "{limits}");
        }
        for bad in [0_u32, 65_537] {
            let why = compile(json!([day(1)]), json!({"max_prompt_bytes": bad}));
            assert!(
                why.is_some_and(|why| why.contains("max_prompt_bytes")),
                "{bad}"
            );
        }
        assert_eq!(
            compile(json!([day(1)]), json!({"max_prompt_bytes": 65_536})),
            None
        );
    }

    fn compiled(limits: Value, mode: &str) -> AiTokenLimit {
        let declared: Declared = serde_json::from_value(json!({
            "name": "t", "type": "ai_token_limit", "limits": limits,
            "source": {"header": "x-key"}, "store": "main", "on_store_error": mode,
        }))
        .expect("declared");
        let app = test_app();
        let mut engine = crate::wasm::Compiler::default();
        AiTokenLimit::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
        .expect("compiles")
    }

    #[test]
    fn ai_posture_lists_removed_loosened_source_fail_open() {
        let day = |limit: u64| json!([{"limit": limit, "period": "day"}]);
        let old = compiled(day(100), "deny");
        assert_eq!(old.posture(None), [kind::REMOVED]);
        assert!(old.posture(Some(&compiled(day(100), "deny"))).is_empty());
        assert!(old.posture(Some(&compiled(day(50), "deny"))).is_empty());
        assert_eq!(
            old.posture(Some(&compiled(day(101), "deny"))),
            [kind::LOOSENED]
        );
        assert_eq!(
            old.posture(Some(&compiled(day(100), "allow"))),
            [kind::FAIL_OPEN]
        );
        // A tighter rate in a shorter period still bounds the old window; a month at the same
        // number does not.
        let hourly = json!([{"limit": 1, "period": "hour"}]);
        assert!(old.posture(Some(&compiled(hourly, "deny"))).is_empty());
        let month = json!([{"limit": 100, "period": "month"}]);
        assert!(old.posture(Some(&compiled(month, "deny"))).is_empty());
        let hour = json!([{"limit": 100, "period": "hour"}]);
        assert_eq!(old.posture(Some(&compiled(hour, "deny"))), [kind::LOOSENED]);
        let other = {
            let declared: Declared = serde_json::from_value(json!({
                "name": "t", "type": "ai_token_limit", "limits": day(100),
                "source": {"header": "x-other"}, "store": "main", "on_store_error": "deny",
            }))
            .expect("declared");
            let app = test_app();
            let mut engine = crate::wasm::Compiler::default();
            AiTokenLimit::compile(
                &declared,
                &mut CompileCx {
                    app: &app,
                    engine: &mut engine,
                },
            )
            .expect("compiles")
        };
        assert_eq!(old.posture(Some(&other)), [kind::SOURCE_CHANGED]);
    }

    fn test_app() -> podgate_model::App {
        podgate_model::App {
            id: "a".into(),
            tenant: "t".into(),
            declared_by: "test".into(),
            tls: serde_json::from_str(r#"{"mode": "acme"}"#).expect("valid tls policy"),
            routers: Vec::new(),
            middlewares: Vec::new(),
            default_chain: Vec::new(),
            services: Vec::new(),
            transports: Vec::new(),
            revisions: Vec::new(),
            allow_domain_fronting: false,
            record_bodies: false,
            scale_to_zero: None,
            canary: None,
            tcp: None,
            udp: None,
            forwarded: None,
            apis: Vec::new(),
        }
    }
}
