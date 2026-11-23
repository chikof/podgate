//! The `llm_guard` middleware: sends each prompt (and, if asked, each answer) of an OpenAI-style
//! chat route to one or more guard models and blocks the exchange when any of them says so.
//! Full reference: `docs/ref/mw-llm-guard.md`. What every guard-calling kind shares (the wire,
//! the verdict, `on_error`, the fan-out, the posture) is in `super::guard`.
//!
//! ```json
//! { "name": "safety", "type": "llm_guard",
//!   "guards": [ { "name": "llama-guard", "address": "http://10.0.0.9:8080/check",
//!                 "phases": ["request", "response"], "on_error": "deny" } ],
//!   "timeout_ms": 2000, "max_prompt_bytes": 65536, "max_response_bytes": 262144 }
//! ```
//!
//! - **Request phase.** The body is held (up to `max_prompt_bytes`, charged to the tenant) before
//!   any route admission, so the model is never dialled before the guards answered. The text is
//!   the string `content` of `messages[]` (or the `text` parts of an array). A body that cannot
//!   be read that way is refused, never passed.
//! - **Response phase.** A `2xx` answer is held whole, before any byte of it reaches the client
//!   (the vendored `ProxyHttp::hold_response`, see [`Kind::response_hold`]), and read as
//!   `choices[].message.content`, or `choices[].delta.content` for an event stream.
//! - **Verdicts.** The first block is `403 {"error":"blocked by guard","category":...}` and the
//!   other guards are cancelled; the guard's reason is never sent or logged. A guard that cannot
//!   answer is `503 {"error":"guard unavailable"}` unless its `on_error` is `allow`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_TYPE, UPGRADE};
use http::{HeaderMap, Method};
use pingora::http::RequestHeader;
use serde::Deserialize;
use serde_json::{Value, json};

use super::buffering::{self, declared_length, expects_continue};
use super::guard::{self, Armed, Endpoint, EndpointSpec, Env, OnError, Phase, Runtimes};
use super::{CompileCx, Flow, HeldCx, Hold, Kind, RequestCx, ResponseCx, state};
use crate::budget::BufferGuard;
use crate::compile::Invalid;
use crate::error::AppError;
use crate::respond;
use crate::table::CompiledApp;
use podgate_model::Declared;

/// The default `timeout_ms`.
const DEFAULT_TIMEOUT_MS: u64 = 2000;
/// The longest `timeout_ms`.
const MAX_TIMEOUT_MS: u64 = 10_000;
/// The default and largest `max_prompt_bytes`: Pingora's replay buffer takes 64 KiB.
const MAX_PROMPT: usize = 64 * 1024;
/// The default `max_response_bytes`.
const DEFAULT_MAX_RESPONSE: usize = 256 * 1024;
/// The largest `max_response_bytes`.
const MAX_RESPONSE: usize = 1024 * 1024;
/// The default `max_concurrent`.
const DEFAULT_MAX_CONCURRENT: u32 = 64;
/// The largest `max_concurrent`.
const MAX_CONCURRENT: u32 = 4096;
/// The most guards of one middleware.
const MAX_GUARDS: usize = 8;
/// The longest guard name.
const MAX_NAME: usize = 32;

/// The configuration of an `llm_guard` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The guards, one to eight, called in parallel.
    guards: Vec<GuardConfig>,
    /// The deadline of one call, in milliseconds: `plugin` 1 to 1000 (default 50), `llm_guard`
    /// 1 to 10000 (default 2000), and never more than `REQUEST_TIMEOUT_SECS`.
    #[serde(default)]
    timeout_ms: Option<u32>,
    /// The most bytes of prompt that are held and judged (default and most 65536); a larger
    /// prompt is refused with `413`.
    #[serde(default)]
    max_prompt_bytes: Option<usize>,
    /// The most bytes of answer that are held and judged (default 262144, at most 1048576); a
    /// larger answer is `502`. Needs a guard with the `response` phase.
    #[serde(default)]
    max_response_bytes: Option<usize>,
    /// Calls in flight at once, per guard (default 64, at most 4096).
    #[serde(default)]
    max_concurrent: Option<u32>,
}

/// One guard of an `llm_guard` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct GuardConfig {
    /// Names the guard in logs and explain: `[a-z0-9_-]`, at most 32 bytes, unique.
    name: String,
    /// The guard's URL, `http://` or `https://`. Dialled through the upstream address policy.
    address: String,
    /// What the guard judges: `request` (default), `response`, or both.
    #[serde(default)]
    phases: Option<Vec<Phase>>,
    /// What to do when it cannot answer: `deny` (default, `503`) or `allow`.
    #[serde(default)]
    on_error: OnError,
    /// A `servers_transport` of the app: CA, server name and client certificate of an `https://`
    /// address.
    #[serde(default)]
    transport: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct Phases {
    request: bool,
    response: bool,
}

impl Phases {
    fn has(self, phase: Phase) -> bool {
        match phase {
            Phase::Request => self.request,
            Phase::Response => self.response,
        }
    }
}

#[derive(Debug)]
struct Guarded {
    endpoint: Endpoint,
    phases: Phases,
}

#[derive(Debug)]
struct Parts {
    guards: Box<[Guarded]>,
    timeout: Duration,
    max_prompt: usize,
    max_response: usize,
    max_concurrent: u32,
    /// Whether any guard judges the answer.
    judges_response: bool,
    /// What outlives a snapshot push: one runtime per guard, in order.
    runtimes: Arc<Runtimes>,
    fingerprint: u64,
}

/// A compiled `llm_guard` middleware.
#[derive(Debug)]
pub struct LlmGuard(Box<Parts>);

/// What a request keeps of its `llm_guard` stage.
#[derive(Debug, Default)]
pub struct State {
    /// The charge for the prompt held in memory, until the request ends.
    request_charge: Option<BufferGuard>,
    /// This stage asked the proxy to hold the response.
    holding: bool,
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("llm_guard: {message}"))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// A body or header that says the body is encoded: the guard could not read it.
fn encoded(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
}

/// A body that is not what the guards can read.
#[derive(Debug, PartialEq, Eq)]
struct Unreadable;

#[derive(Deserialize)]
#[serde(untagged)]
enum Content {
    Text(String),
    Parts(Vec<Part>),
}

#[derive(Deserialize)]
struct Part {
    #[serde(default)]
    text: Option<String>,
}

impl Content {
    fn push_into(self, out: &mut Vec<String>) {
        match self {
            Self::Text(text) => out.push(text),
            Self::Parts(parts) => out.extend(parts.into_iter().filter_map(|part| part.text)),
        }
    }
}

#[derive(Deserialize)]
struct Message {
    #[serde(default)]
    content: Option<Content>,
}

#[derive(Deserialize)]
struct Chat {
    messages: Vec<Message>,
}

/// The text of a chat request: every `messages[].content` that is a string, or the `text` parts
/// of an array, joined with a newline. `null` and absent content are skipped, parts that are
/// not text are ignored.
fn extract_request(body: &[u8]) -> Result<String, Unreadable> {
    let chat: Chat = serde_json::from_slice(body).map_err(|_| Unreadable)?;
    let mut texts = Vec::new();
    for message in chat.messages {
        if let Some(content) = message.content {
            content.push_into(&mut texts);
        }
    }
    Ok(texts.join("\n"))
}

#[derive(Deserialize)]
struct Choice {
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    message: Option<Message>,
    #[serde(default)]
    delta: Option<Message>,
}

#[derive(Deserialize)]
struct Completion {
    choices: Vec<Choice>,
}

/// The text of a chat answer: `choices[].message.content`, or for an event stream
/// (`text/event-stream`) the `choices[].delta.content` of every `data:` event, joined per choice.
fn extract_response(content_type: Option<&str>, body: &[u8]) -> Result<String, Unreadable> {
    let stream = content_type.is_some_and(|value| {
        value
            .trim_start()
            .get(..17)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("text/event-stream"))
    });
    let mut per_choice: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut absorb = |completion: Completion| {
        for (at, choice) in completion.choices.into_iter().enumerate() {
            let texts = per_choice.entry(choice.index.unwrap_or(at)).or_default();
            for message in [choice.message, choice.delta].into_iter().flatten() {
                if let Some(content) = message.content {
                    content.push_into(texts);
                }
            }
        }
    };
    if stream {
        let text = std::str::from_utf8(body).map_err(|_| Unreadable)?;
        for line in text.lines() {
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            absorb(serde_json::from_str(data).map_err(|_| Unreadable)?);
        }
    } else {
        absorb(serde_json::from_slice(body).map_err(|_| Unreadable)?);
    }
    let joined: Vec<String> = per_choice
        .into_values()
        .map(|texts| texts.concat())
        .collect();
    Ok(joined.join("\n"))
}

impl LlmGuard {
    /// Gives each guard the resolver its host name (when `address` has one) is resolved with.
    pub(crate) fn bind(&mut self, resolver: &crate::service::resolve::Resolver) {
        for guarded in &mut self.0.guards {
            guarded.endpoint.bind(resolver);
        }
    }

    /// Refuses a configuration that could never be charged: the largest thing the stage holds
    /// plus one call's overhead is more than the tenant's whole `max_buffer_bytes`. A budget
    /// that is only full right now is not judged here; the request is refused with `503`.
    ///
    /// # Errors
    ///
    /// `invalid_middleware` naming the tenant, the bytes needed and the budget.
    pub(crate) fn check_budget(&self, tenant: &str, max_buffer_bytes: u64) -> Result<(), Invalid> {
        let parts = &*self.0;
        let prompt = len_of(parts.max_prompt).saturating_add(guard::OVERHEAD);
        let answer = if parts.judges_response {
            len_of(parts.max_response)
                .saturating_mul(2)
                .saturating_add(guard::OVERHEAD)
        } else {
            0
        };
        let needed = prompt.max(answer);
        if max_buffer_bytes >= needed {
            return Ok(());
        }
        Err(invalid(format!(
            "tenant {tenant} has max_buffer_bytes {max_buffer_bytes}, below the {needed} bytes the guard holds for one exchange (max_prompt_bytes {} and max_response_bytes {} plus the call overhead); lower them or raise the budget",
            parts.max_prompt, parts.max_response,
        ))
        .with("tenant", tenant)
        .with("needed_bytes", needed)
        .with("max_buffer_bytes", max_buffer_bytes))
    }

    /// The guards that judge `phase`, with their runtimes.
    fn armed(&self, phase: Phase) -> Vec<Armed<'_>> {
        self.0
            .guards
            .iter()
            .zip(self.0.runtimes.0.iter())
            .filter(|(guarded, _)| guarded.phases.has(phase))
            .map(|(guarded, runtime)| Armed {
                endpoint: &guarded.endpoint,
                runtime,
            })
            .collect()
    }

    /// Holds the request body (up to `max_prompt_bytes`) and returns it: when another stage
    /// already held it, it is read back from the replay buffer ([`buffering::hold_body`]).
    async fn hold_prompt(
        &self,
        cx: &mut RequestCx<'_>,
        state: &mut State,
    ) -> pingora::Result<Result<Bytes, AppError>> {
        let max = len_of(self.0.max_prompt);
        let request = cx.session.req_header();
        if encoded(&request.headers) {
            return Ok(Err(unreadable_request()));
        }
        let expects = expects_continue(request);
        let declared = declared_length(&request.headers);
        if declared.is_some_and(|declared| declared > max) {
            return Ok(Err(if expects {
                AppError::ExpectationFailed
            } else {
                AppError::PayloadTooLarge
            }));
        }
        let Some(tenant) = cx.tenant else {
            return Ok(Err(AppError::GuardSaturated));
        };
        let Some(charge) = tenant.charge(declared.unwrap_or(max)) else {
            return Ok(Err(AppError::GuardSaturated));
        };
        state.request_charge = Some(charge);
        buffering::hold_body(cx.session, cx.body_held, max).await
    }

    /// Judges the prompt of the request on `cx`.
    async fn judge_prompt(
        &self,
        cx: &mut RequestCx<'_>,
        state: &mut State,
    ) -> pingora::Result<Result<(), AppError>> {
        let body = match self.hold_prompt(cx, state).await? {
            Ok(body) => body,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Ok(text) = extract_request(&body) else {
            return Ok(Err(unreadable_request()));
        };
        if text.is_empty() {
            return Ok(Ok(()));
        }
        let guards = self.armed(Phase::Request);
        let env = Env {
            client: cx.auth,
            policy: cx.policy,
            tenant: cx.tenant,
            tenant_id: cx.app.tenant(),
        };
        let settled = guard::run(&guards, &env, Phase::Request, &text, cx.app.id()).await;
        Ok(settled.refusal())
    }
}

fn unreadable_request() -> AppError {
    AppError::BadRequest("unreadable request".into())
}

fn len_of(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// Whether the response to `request` is one the guards judge: a `2xx` that is not a tunnel, to a
/// request that is not a `HEAD`, and has a body.
fn judged(request: &RequestHeader, status: http::StatusCode) -> bool {
    status.is_success()
        && status != http::StatusCode::NO_CONTENT
        && status != http::StatusCode::RESET_CONTENT
        && request.method != Method::HEAD
        && !request.headers.contains_key(UPGRADE)
}

impl Kind for LlmGuard {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        if !(1..=MAX_GUARDS).contains(&config.guards.len()) {
            return Err(invalid(format!(
                "`guards` lists one to {MAX_GUARDS} guards"
            )));
        }
        let timeout_ms = config.timeout_ms.map_or(DEFAULT_TIMEOUT_MS, u64::from);
        if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(invalid(format!("`timeout_ms` is in 1..={MAX_TIMEOUT_MS}")));
        }
        let max_prompt = config.max_prompt_bytes.unwrap_or(MAX_PROMPT);
        if !(1..=MAX_PROMPT).contains(&max_prompt) {
            return Err(invalid(format!(
                "`max_prompt_bytes` is in 1..={MAX_PROMPT}: the held prompt travels to the model through Pingora's 64 KiB replay buffer"
            )));
        }
        let max_response = config.max_response_bytes.unwrap_or(DEFAULT_MAX_RESPONSE);
        if !(1..=MAX_RESPONSE).contains(&max_response) {
            return Err(invalid(format!(
                "`max_response_bytes` is in 1..={MAX_RESPONSE}"
            )));
        }
        let max_concurrent = config.max_concurrent.unwrap_or(DEFAULT_MAX_CONCURRENT);
        if !(1..=MAX_CONCURRENT).contains(&max_concurrent) {
            return Err(invalid(format!(
                "`max_concurrent` is in 1..={MAX_CONCURRENT}"
            )));
        }
        let mut guards: Vec<Guarded> = Vec::with_capacity(config.guards.len());
        for entry in &config.guards {
            if !valid_name(&entry.name) {
                return Err(invalid(format!(
                    "guard name {:?} is not 1 to {MAX_NAME} bytes of a-z, 0-9, `_` and `-`",
                    entry.name
                )));
            }
            if guards
                .iter()
                .any(|known| known.endpoint.name() == entry.name)
            {
                return Err(invalid(format!("guard {} is declared twice", entry.name)));
            }
            let phases = match entry.phases.as_deref() {
                None => Phases {
                    request: true,
                    response: false,
                },
                Some([]) => {
                    return Err(invalid(format!("guard {}: `phases` is empty", entry.name)));
                }
                Some(list) => {
                    let phases = Phases {
                        request: list.contains(&Phase::Request),
                        response: list.contains(&Phase::Response),
                    };
                    let distinct = usize::from(phases.request) + usize::from(phases.response);
                    if distinct != list.len() {
                        return Err(invalid(format!(
                            "guard {}: `phases` repeats a phase",
                            entry.name
                        )));
                    }
                    phases
                }
            };
            let endpoint = Endpoint::compile(
                &EndpointSpec {
                    name: &entry.name,
                    address: &entry.address,
                    on_error: entry.on_error,
                    transport: entry.transport.as_deref(),
                    timeout: Duration::from_millis(timeout_ms),
                    max_concurrent,
                },
                cx.app,
                &format!("llm_guard: guard {}", entry.name),
            )?;
            guards.push(Guarded { endpoint, phases });
        }
        let judges_response = guards.iter().any(|guarded| guarded.phases.response);
        if config.max_response_bytes.is_some() && !judges_response {
            return Err(invalid(
                "`max_response_bytes` needs a guard with the `response` phase",
            ));
        }
        let runtimes = Runtimes(
            guards
                .iter()
                .map(|guarded| guarded.endpoint.runtime())
                .collect(),
        );
        Ok(Self(Box::new(Parts {
            guards: guards.into_boxed_slice(),
            timeout: Duration::from_millis(timeout_ms),
            max_prompt,
            max_response,
            max_concurrent,
            judges_response,
            runtimes: Arc::new(runtimes),
            fingerprint: state::fingerprint(declared),
        })))
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        let parts = &*self.0;
        if !parts.guards.iter().any(|guarded| guarded.phases.request)
            || cx.session.is_upgrade_req()
            || cx.session.req_header().method == Method::CONNECT
            || cx.session.is_body_empty()
        {
            return Ok(Flow::Continue);
        }
        match self.judge_prompt(cx, state).await? {
            Ok(()) => Ok(Flow::Continue),
            Err(err) => {
                *cx.capacity_refusal = err.is_capacity_refusal();
                *cx.reason = Some(err.log_reason());
                respond::write_error(cx.session, &err).await?;
                Ok(Flow::Respond)
            }
        }
    }

    /// The model answers in the clear, so the guard reads what it sent.
    fn upstream_request(
        &self,
        request: &mut RequestHeader,
        _state: &mut State,
    ) -> pingora::Result<()> {
        if self.0.judges_response {
            request.remove_header(&http::header::ACCEPT_ENCODING);
        }
        Ok(())
    }

    fn response_hold(&self, cx: &ResponseCx<'_>, state: &mut State) -> Result<Hold, AppError> {
        if !self.0.judges_response || !judged(cx.request, cx.response.status) {
            return Ok(Hold::No);
        }
        let max = len_of(self.0.max_response);
        let declared = declared_length(&cx.response.headers);
        if declared == Some(0) {
            return Ok(Hold::No);
        }
        if declared.is_some_and(|declared| declared > max) {
            return Err(AppError::UpstreamResponseTooLarge);
        }
        let tenant = cx.tenant.ok_or(AppError::GuardSaturated)?;
        // The held chunks and the one joined copy the guard reads.
        let charge = tenant
            .charge(declared.unwrap_or(max).saturating_mul(2))
            .ok_or(AppError::GuardSaturated)?;
        state.holding = true;
        Ok(Hold::Yes {
            max_body: max,
            charge,
        })
    }

    async fn response_held(&self, cx: &mut HeldCx<'_>, state: &mut State) -> Result<(), AppError> {
        if !std::mem::take(&mut state.holding) {
            return Ok(());
        }
        if encoded(&cx.head.headers) {
            return Err(AppError::GuardResponseUnreadable);
        }
        let content_type = cx
            .head
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let text = extract_response(content_type, cx.body)
            .map_err(|Unreadable| AppError::GuardResponseUnreadable)?;
        if text.is_empty() {
            return Ok(());
        }
        let guards = self.armed(Phase::Response);
        let app: &CompiledApp = cx.app;
        let env = Env {
            client: cx.auth,
            policy: cx.policy,
            tenant: cx.tenant,
            tenant_id: app.tenant(),
        };
        guard::run(&guards, &env, Phase::Response, &text, app.id())
            .await
            .refusal()
    }

    /// Dropping a guard or one of its phases stops judging; another server or path is another
    /// decision-maker; `on_error: allow` opens the door when a guard is down.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let mut kinds: Vec<&'static str> = Vec::new();
        for old in &self.0.guards {
            let newer = new.and_then(|new| {
                new.0
                    .guards
                    .iter()
                    .find(|guarded| guarded.endpoint.name() == old.endpoint.name())
            });
            kinds.extend(old.endpoint.posture(newer.map(|guarded| &guarded.endpoint)));
            if let Some(newer) = newer
                && ((old.phases.request && !newer.phases.request)
                    || (old.phases.response && !newer.phases.response))
            {
                kinds.push(guard::kind::DROPPED);
            }
        }
        let mut seen = Vec::new();
        kinds.retain(|kind| {
            let new = !seen.contains(kind);
            seen.push(*kind);
            new
        });
        kinds
    }

    fn describe(&self) -> Value {
        let guards: Vec<Value> = self
            .0
            .guards
            .iter()
            .map(|guarded| {
                let mut shown = guarded.endpoint.describe();
                if let Some(object) = shown.as_object_mut() {
                    let mut phases = Vec::new();
                    for phase in [Phase::Request, Phase::Response] {
                        if guarded.phases.has(phase) {
                            phases.push(phase.name());
                        }
                    }
                    object.insert("phases".into(), json!(phases));
                }
                shown
            })
            .collect();
        json!({
            "guards": guards,
            "timeout_ms": u64::try_from(self.0.timeout.as_millis()).unwrap_or(u64::MAX),
            "max_prompt_bytes": self.0.max_prompt,
            "max_response_bytes": self.0.max_response,
            "max_concurrent": self.0.max_concurrent,
        })
    }
}

/// The permits and circuits of every `llm_guard` middleware of the live table, kept by the shared
/// [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]). A push that
/// leaves a middleware's declaration as it was keeps its circuits.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtimes>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            super::Stage::LlmGuard(stage) => Some((stage.0.fingerprint, &mut stage.0.runtimes)),
            _ => None,
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wasm as engine;

    fn app() -> podgate_model::App {
        serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
            "transports": [{"name": "t", "type": "servers_transport", "server_name": "guard.internal"}],
        }))
        .expect("app")
    }

    fn compile(config: &Value) -> Result<LlmGuard, Invalid> {
        let mut declared = json!({"name": "g", "type": "llm_guard"});
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app = app();
        let mut compiler = engine::Compiler::default();
        LlmGuard::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut compiler,
            },
        )
    }

    fn one(extra: &Value) -> Value {
        let mut config =
            json!({"guards": [{"name": "g1", "address": "http://10.0.0.9:8080/check"}]});
        if let (Some(object), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
            object.extend(extra.clone());
        }
        config
    }

    fn code(config: &Value) -> &'static str {
        compile(config).expect_err("refused").code
    }

    #[test]
    fn guard_config_rejects_bad_limits() {
        assert!(compile(&one(&json!({}))).is_ok());
        assert!(
            compile(&one(
                &json!({"timeout_ms": 10000, "max_prompt_bytes": 65536, "max_concurrent": 4096})
            ))
            .is_ok()
        );
        for bad in [
            json!({"timeout_ms": 0}),
            json!({"timeout_ms": 10001}),
            json!({"max_prompt_bytes": 0}),
            json!({"max_prompt_bytes": 65537}),
            json!({"max_response_bytes": 1024}),
            json!({"max_concurrent": 0}),
            json!({"max_concurrent": 4097}),
            json!({"nope": 1}),
            json!({"guards": []}),
            json!({"guards": [{"name": "A", "address": "http://10.0.0.9/x"}]}),
            json!({"guards": [{"name": "g", "address": "http://10.0.0.9/x"}, {"name": "g", "address": "http://10.0.0.8/x"}]}),
            json!({"guards": [{"name": "g", "address": "/relative"}]}),
            json!({"guards": [{"name": "g", "address": "h2c://10.0.0.9/x"}]}),
            json!({"guards": [{"name": "g", "address": "http://10.0.0.9/x", "on_error": "maybe"}]}),
            json!({"guards": [{"name": "g", "address": "http://10.0.0.9/x", "phases": []}]}),
            json!({"guards": [{"name": "g", "address": "http://10.0.0.9/x", "phases": ["request", "request"]}]}),
            json!({"guards": [{"name": "g", "address": "http://10.0.0.9/x", "extra": true}]}),
            json!({"guards": [{"name": "g", "address": "http://10.0.0.9/x", "transport": "t"}]}),
        ] {
            assert_eq!(code(&one(&bad)), "invalid_middleware", "{bad}");
        }
        let nine: Vec<Value> = (0..9)
            .map(|n| json!({"name": format!("g{n}"), "address": "http://10.0.0.9/x"}))
            .collect();
        assert_eq!(code(&json!({"guards": nine})), "invalid_middleware");
        assert_eq!(
            code(
                &json!({"guards": [{"name": "g", "address": "http://10.0.0.9/x", "transport": "missing"}]})
            ),
            "unknown_transport"
        );
        assert!(
            compile(&json!({"guards": [{"name": "g", "address": "https://guard.internal/x",
                "phases": ["request", "response"], "transport": "t"}], "max_response_bytes": 1048576}))
            .is_ok()
        );
    }

    #[test]
    fn guard_budget_must_hold_one_call() {
        let stage = compile(&one(&json!({"max_prompt_bytes": 1024}))).expect("compiled");
        let needed = 1024 + guard::OVERHEAD;
        assert!(stage.check_budget("t1", needed).is_ok());
        let refused = stage.check_budget("t1", needed - 1).expect_err("refused");
        assert_eq!(refused.code, "invalid_middleware");
        let both = compile(&json!({"guards": [{"name": "g", "address": "http://10.0.0.9/x",
            "phases": ["request", "response"]}], "max_prompt_bytes": 1024, "max_response_bytes": 4096}))
        .expect("compiled");
        let needed = 2 * 4096 + guard::OVERHEAD;
        assert!(both.check_budget("t1", needed).is_ok());
        assert!(
            both.check_budget("t1", needed - 1).is_err(),
            "the answer is held twice"
        );
    }

    #[test]
    fn guard_request_text_from_chat_messages() {
        let body = json!({
            "model": "m", "stream": true, "unrelated": {"content": "ignored"},
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": [
                    {"type": "text", "text": "hello"},
                    {"type": "image_url", "image_url": {"url": "http://x/y.png"}},
                    {"type": "text", "text": "world"}]},
                {"role": "assistant", "content": null, "tool_calls": []},
                {"role": "tool"},
            ],
        });
        assert_eq!(
            extract_request(body.to_string().as_bytes()),
            Ok("be brief\nhello\nworld".to_owned())
        );
        assert_eq!(extract_request(br#"{"messages":[]}"#), Ok(String::new()));
    }

    #[test]
    fn guard_unreadable_request_is_400() {
        for bad in [
            "",
            "not json",
            "[]",
            r#"{"prompt":"x"}"#,
            r#"{"messages":"x"}"#,
            r#"{"messages":[{"content":7}]}"#,
            r#"{"messages":[{"content":{"a":1}}]}"#,
            r#"{"messages":[{"content":"a","content":"b"}]}"#,
            r#"{"messages":[],"messages":[]}"#,
        ] {
            assert_eq!(extract_request(bad.as_bytes()), Err(Unreadable), "{bad:?}");
        }
        let err = unreadable_request();
        assert_eq!(err.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(err.body(), json!({"error": "unreadable request"}));
    }

    #[test]
    fn guard_response_text_from_choices_and_events() {
        let answer = json!({"choices": [
            {"index": 0, "message": {"role": "assistant", "content": "first"}},
            {"index": 1, "message": {"role": "assistant", "content": [{"type": "text", "text": "second"}]}},
        ]});
        assert_eq!(
            extract_response(Some("application/json"), answer.to_string().as_bytes()),
            Ok("first\nsecond".to_owned())
        );
        let events = "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n\
                      data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Good \"}}]}\n\n\
                      : keep-alive\n\n\
                      data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"morning\"}}]}\n\r\n\
                      data: [DONE]\n\n";
        assert_eq!(
            extract_response(Some("Text/Event-Stream; charset=utf-8"), events.as_bytes()),
            Ok("Good morning".to_owned())
        );
        for bad in [
            "",
            "ok",
            "{}",
            r#"{"choices":"x"}"#,
            r#"{"error":{"message":"m"}}"#,
        ] {
            assert_eq!(
                extract_response(Some("application/json"), bad.as_bytes()),
                Err(Unreadable),
                "{bad:?}"
            );
        }
        assert_eq!(
            extract_response(Some("text/event-stream"), b"data: {oops}\n"),
            Err(Unreadable)
        );
        assert_eq!(
            extract_response(Some("application/json"), br#"{"choices":[]}"#),
            Ok(String::new())
        );
    }

    #[test]
    fn guard_stage_posture_follows_guards_and_phases() {
        let base = compile(&json!({"guards": [
            {"name": "a", "address": "http://10.0.0.9/x", "phases": ["request", "response"]},
            {"name": "b", "address": "http://10.0.0.8/x"}]}))
        .expect("base");
        let same = |new: &LlmGuard| base.posture(Some(new));
        assert_eq!(base.posture(None), [guard::kind::DROPPED]);
        assert!(
            same(
                &compile(&json!({"guards": [
            {"name": "a", "address": "http://10.0.0.9/x", "phases": ["request", "response"]},
            {"name": "b", "address": "http://10.0.0.8/x"},
            {"name": "c", "address": "http://10.0.0.7/x"}]}))
                .expect("more")
            )
            .is_empty()
        );
        assert_eq!(
            same(
                &compile(&json!({"guards": [
                {"name": "a", "address": "http://10.0.0.9/x", "phases": ["request"]},
                {"name": "b", "address": "http://10.0.0.8/x"}]}))
                .expect("phase dropped")
            ),
            [guard::kind::DROPPED]
        );
        assert_eq!(
            same(
                &compile(&json!({"guards": [
                {"name": "a", "address": "http://10.0.0.9/x", "phases": ["request", "response"]}]}))
                .expect("guard dropped")
            ),
            [guard::kind::DROPPED]
        );
        assert_eq!(
            same(&compile(&json!({"guards": [
                {"name": "a", "address": "http://10.0.0.9/x", "phases": ["request", "response"], "on_error": "allow"},
                {"name": "b", "address": "http://10.0.0.8/x"}]}))
            .expect("fail open")),
            [guard::kind::FAIL_OPEN]
        );
    }
}
