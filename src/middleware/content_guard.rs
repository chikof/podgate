//! The `content_guard` middleware: scans request and response bodies for sensitive content with
//! regex rules that run inside podgate and an external classifier the operator names, and for
//! each match blocks the exchange or redacts the match. Full reference:
//! `docs/ref/mw-content-guard.md`.
//!
//! ```json
//! { "name": "pii", "type": "content_guard", "max_body_bytes": 65536,
//!   "rules": [ {"name": "email", "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
//!               "phase": "both", "action": "redact", "category": "pii"} ],
//!   "classifier": {"name": "toxicity", "phase": "request", "on_error": "deny"} }
//! ```
//!
//! - **What is scanned.** The string values of a JSON body (every other part of the document is
//!   copied byte for byte, so a redaction keeps the JSON valid). A body that cannot be scanned
//!   (not JSON-typed, encoded, not valid JSON, over `max_body_bytes`) is refused, never passed
//!   on: skipping it would be a bypass. See `rules` for the rule engine and its caps.
//! - **Request.** Held whole before the upstream is chosen or dialled
//!   (`buffering::hold_body`), scanned on the blocking pool, then blocked (`403`), rewritten
//!   (the upstream gets the redacted body and its exact `Content-Length`) or passed.
//! - **Response.** Held whole and raw by the proxy before the client sees a byte of it
//!   ([`Kind::response_hold`], docs/ref/pingora-patches.md section 6), scanned, then blocked,
//!   rewritten or passed. Compression, the cache and the failed-request recorder only ever see
//!   what it let through.
//! - **Classifier.** `classifier` names an entry of `CONTENT_CLASSIFIERS_FILE` ([`Classifiers`]).
//!   It is one `guard::Endpoint`: the same wire, address policy, circuit, permits and tenant
//!   charge as an `llm_guard` guard. It sees the text the rules left, once per phase.
//! - **What never leaves.** A matched value reaches no log line, metric, recorded failure,
//!   mirror copy, cache entry or explain output: only rule names and categories do.

mod classifier;
mod json;
mod rules;

pub use classifier::{Classifiers, LoadError};

use std::sync::Arc;

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use http::{HeaderMap, Method, StatusCode};
use pingora::http::RequestHeader;
use serde::Deserialize;
use serde_json::{Value, json};

use self::rules::{Outcome, Phase as Scope, RuleConfig, Rules, Scan, Unscannable};
use super::buffering::{self, declared_length, expects_continue};
use super::guard::{
    self, Armed, Endpoint, EndpointSpec, Env, OnError, Phase as Wire, Runtimes, Settled,
};
use super::{
    BodyCopy, CompileCx, Flow, HeldCx, Hold, Kind, Named, RequestCx, ResponseCx, Stage, state,
};
use crate::budget::BufferGuard;
use crate::compile::{Invalid, Rejected};
use crate::error::AppError;
use crate::respond;
use crate::service::resolve::Resolver;
use crate::table::CompiledApp;
use podgate_model::{App, Declared, Snapshot};

/// The default and largest `max_body_bytes`: a held request body travels to the upstream
/// through Pingora's 64 KiB replay buffer.
const MAX_BODY: usize = 64 * 1024;

/// The longest classifier name.
const MAX_CLASSIFIER_NAME: usize = 64;

/// Posture change kinds this middleware reports, see [`Kind::posture`]. A classifier's own
/// changes are the shared `guard_*` kinds of `guard::kind`.
pub mod kind {
    /// The middleware is gone: bodies are no longer scanned.
    pub const REMOVED: &str = "content_guard_removed";
    /// A rule is gone, has another pattern, redacts where it blocked, or runs in fewer phases.
    pub const RULE_WEAKENED: &str = "content_guard_rule_weakened";
}

/// The configuration of a `content_guard` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The rules, at most 64, run in declaration order. At least one rule or a classifier is
    /// required.
    #[serde(default)]
    rules: Vec<RuleConfig>,
    /// An external classifier the operator named in `CONTENT_CLASSIFIERS_FILE`.
    #[serde(default)]
    classifier: Option<ClassifierConfig>,
    /// The most body bytes that are held and scanned, 1 to 65536 (default 65536). A larger
    /// request is `413`, a larger response `502`.
    #[serde(default)]
    max_body_bytes: Option<usize>,
}

/// The classifier a `content_guard` calls.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClassifierConfig {
    /// The name of an entry of `CONTENT_CLASSIFIERS_FILE` that lists the app's tenant.
    name: String,
    /// What it judges: `request`, `response` or `both` (default).
    #[serde(default)]
    phase: Option<Scope>,
    /// What to do when it cannot answer: `deny` (default, `503`) or `allow`.
    #[serde(default)]
    on_error: OnError,
}

/// The classifier of a compiled stage.
#[derive(Debug)]
struct Classified {
    name: Box<str>,
    phase: Scope,
    on_error: OnError,
    /// Built when the snapshot is bound to the operator's classifiers.
    bound: Option<Endpoint>,
}

#[derive(Debug)]
struct Parts {
    rules: Arc<Rules>,
    classifier: Option<Classified>,
    max_body: usize,
    /// What outlives a snapshot push: the permit and circuit of the classifier, if any.
    runtimes: Arc<Runtimes>,
    fingerprint: u64,
}

/// A compiled `content_guard` middleware.
#[derive(Debug)]
pub struct ContentGuard(Box<Parts>);

/// What a request keeps of its `content_guard` stage: nothing at all unless it scanned a body.
#[derive(Debug, Default)]
pub struct State(Option<Box<Active>>);

#[derive(Debug, Default)]
struct Active {
    /// The charge for what the stage holds, until the request ends.
    charge: Option<BufferGuard>,
    /// The request body the upstream gets instead of the client's.
    redacted: Option<Bytes>,
    /// This stage asked the proxy to hold the response.
    holding: bool,
}

impl State {
    fn active(&mut self) -> &mut Active {
        self.0.get_or_insert_with(Box::default)
    }
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("content_guard: {message}"))
}

fn len_of(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// What a stage holds for a body of `bytes`: the held copy, the copy the scan reads and the one
/// it writes, plus the scan's own state.
fn hold_charge(bytes: u64) -> u64 {
    bytes.saturating_mul(3).saturating_add(4096)
}

/// What one classifier call may take: its call overhead and the text it sends, which is at most
/// twice the body for ordinary text (escapes can make it larger; a call that does not fit the
/// budget is `503`, and the budget check at compile only judges the ordinary case).
fn classifier_charge(max_body: usize) -> u64 {
    guard::OVERHEAD.saturating_add(len_of(max_body).saturating_mul(2))
}

/// Whether the headers describe a UTF-8 JSON body that is not encoded.
fn is_json(headers: &HeaderMap) -> bool {
    let encoded = headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"));
    if encoded {
        return false;
    }
    let Some(value) = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let mut parts = value.split(';');
    let essence = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    if essence != "application/json" && !essence.ends_with("+json") {
        return false;
    }
    parts.all(|param| {
        let Some((name, value)) = param.split_once('=') else {
            return true;
        };
        !name.trim().eq_ignore_ascii_case("charset")
            || value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
    })
}

/// Whether a response with this status and for this method has a body to scan.
fn has_body(request: &RequestHeader, status: StatusCode) -> bool {
    request.method != Method::HEAD
        && (!status.is_informational() || status == StatusCode::SWITCHING_PROTOCOLS)
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED
}

fn valid_classifier_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CLASSIFIER_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

impl ContentGuard {
    /// Whether the stage scans bodies of `phase`.
    fn scans(&self, phase: Scope) -> bool {
        self.0.rules.has(phase)
            || self
                .0
                .classifier
                .as_ref()
                .is_some_and(|classifier| classifier.phase.covers(phase))
    }

    /// Whether the classifier judges `phase`.
    fn classifies(&self, phase: Scope) -> bool {
        self.0
            .classifier
            .as_ref()
            .is_some_and(|classifier| classifier.phase.covers(phase))
    }

    /// The most bytes the rewritten body may take: every match may grow.
    fn output_limit(&self) -> usize {
        self.0.max_body.saturating_mul(2).saturating_add(4096)
    }

    /// Resolves the classifier this stage names against the operator's and builds its endpoint.
    fn bind(
        &mut self,
        app: &App,
        snapshot: &Snapshot,
        classifiers: &Classifiers,
        resolver: &Resolver,
    ) -> Result<(), Invalid> {
        let parts = &mut *self.0;
        let mut needed = hold_charge(len_of(parts.max_body));
        if let Some(classifier) = &mut parts.classifier {
            // One message for an unknown name and for a tenant the entry does not list: the
            // tenant learns nothing about the operator's file.
            let entry = classifiers
                .get(&classifier.name)
                .filter(|entry| entry.allows(&app.tenant))
                .ok_or_else(|| {
                    invalid(format!(
                        "classifier {} is not available to this app",
                        classifier.name
                    ))
                    .with("classifier", &*classifier.name)
                })?;
            let mut endpoint = Endpoint::compile(
                &EndpointSpec {
                    name: &classifier.name,
                    address: entry.url(),
                    on_error: classifier.on_error,
                    transport: None,
                    timeout: entry.timeout(),
                    max_concurrent: entry.max_concurrent(),
                },
                app,
                &format!("content_guard: classifier {}", classifier.name),
            )?;
            endpoint.bind(resolver);
            parts.runtimes = Arc::new(Runtimes(Box::new([endpoint.runtime()])));
            classifier.bound = Some(endpoint);
            needed = needed.saturating_add(classifier_charge(parts.max_body));
        }
        let max_buffer_bytes = snapshot
            .tenants
            .iter()
            .find(|tenant| tenant.id == app.tenant)
            .map_or(u64::MAX, |tenant| tenant.budget.max_buffer_bytes);
        if max_buffer_bytes >= needed {
            return Ok(());
        }
        Err(invalid(format!(
            "tenant {} has max_buffer_bytes {max_buffer_bytes}, below the {needed} bytes one scan holds (max_body_bytes {}); lower max_body_bytes or raise the budget",
            app.tenant, parts.max_body,
        ))
        .with("tenant", &*app.tenant)
        .with("needed_bytes", needed)
        .with("max_buffer_bytes", max_buffer_bytes))
    }

    /// Runs the rules on the blocking pool, so a hostile body cannot stall a proxy worker.
    async fn scan(&self, scope: Scope, body: Bytes) -> Result<Result<Scan, Unscannable>, AppError> {
        let rules = Arc::clone(&self.0.rules);
        let want_text = self.classifies(scope);
        let limit = self.output_limit();
        tokio::task::spawn_blocking(move || rules.scan(scope, &body, limit, want_text))
            .await
            .map_err(|_| {
                tracing::warn!("content guard scan did not finish");
                AppError::GuardUnavailable
            })
    }

    /// Asks the classifier about `text`.
    async fn classify(
        &self,
        env: &Env<'_>,
        phase: Wire,
        text: &str,
        app: &str,
    ) -> Result<(), AppError> {
        let Some(classifier) = &self.0.classifier else {
            return Ok(());
        };
        if text.is_empty() {
            return Ok(());
        }
        let (Some(endpoint), Some(runtime)) = (&classifier.bound, self.0.runtimes.0.first()) else {
            // Not bound to the operator's classifiers: nothing can answer, so the door is shut.
            return Err(AppError::GuardUnavailable);
        };
        let armed = [Armed { endpoint, runtime }];
        match guard::run(&armed, env, phase, text, app).await {
            Settled::Block { category } => {
                Err(AppError::ContentBlocked(category.as_ref().map_or_else(
                    || classifier.name.clone(),
                    |category| category.as_str().into(),
                )))
            }
            other => other.refusal(),
        }
    }

    /// Holds, scans and judges the request body of `cx`. The inner `Err` is the refusal to
    /// write.
    async fn judge_request(
        &self,
        cx: &mut RequestCx<'_>,
        state: &mut State,
    ) -> pingora::Result<Result<(), AppError>> {
        let upgrade = cx.session.is_upgrade_req();
        let empty = cx.session.is_body_empty();
        let request = cx.session.req_header();
        // A tunnel carries bytes no scan can see.
        if upgrade || request.method == Method::CONNECT {
            return Ok(Err(AppError::UnsupportedMediaType));
        }
        if empty {
            return Ok(Ok(()));
        }
        if !is_json(&request.headers) {
            return Ok(Err(AppError::UnsupportedMediaType));
        }
        let max = len_of(self.0.max_body);
        let declared = declared_length(&request.headers);
        if declared.is_some_and(|declared| declared > max) {
            return Ok(Err(if expects_continue(request) {
                AppError::ExpectationFailed
            } else {
                AppError::PayloadTooLarge
            }));
        }
        let Some(tenant) = cx.tenant else {
            return Ok(Err(AppError::GuardSaturated));
        };
        let Some(charge) = tenant.charge(hold_charge(declared.unwrap_or(max))) else {
            return Ok(Err(AppError::GuardSaturated));
        };
        state.active().charge = Some(charge);
        let body = match buffering::hold_body(cx.session, cx.body_held, max).await? {
            Ok(body) => body,
            Err(refusal) => return Ok(Err(refusal)),
        };
        *cx.body_copy = BodyCopy::AfterChain;
        let scanned = match self.scan(Scope::Request, body).await {
            Ok(Ok(scanned)) => scanned,
            Ok(Err(Unscannable::NotJson)) => {
                return Ok(Err(AppError::BadRequest(
                    "the body is not valid JSON".into(),
                )));
            }
            Ok(Err(Unscannable::TooMuchOutput)) => return Ok(Err(AppError::PayloadTooLarge)),
            Err(refusal) => return Ok(Err(refusal)),
        };
        match scanned.outcome {
            Outcome::Blocked { category } => return Ok(Err(AppError::ContentBlocked(category))),
            Outcome::Redacted(bytes) => state.active().redacted = Some(Bytes::from(bytes)),
            Outcome::Clean => {}
        }
        if !self.classifies(Scope::Request) {
            return Ok(Ok(()));
        }
        let env = Env {
            client: cx.auth,
            policy: cx.policy,
            tenant: cx.tenant,
            tenant_id: cx.app.tenant(),
        };
        Ok(self
            .classify(&env, Wire::Request, &scanned.text, cx.app.id())
            .await)
    }
}

impl Kind for ContentGuard {
    type State = State;

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        let max_body = config.max_body_bytes.unwrap_or(MAX_BODY);
        if !(1..=MAX_BODY).contains(&max_body) {
            return Err(invalid(format!(
                "`max_body_bytes` is in 1..={MAX_BODY}: a held body travels to the upstream through Pingora's 64 KiB replay buffer"
            )));
        }
        let rules = Rules::compile(&config.rules).map_err(invalid)?;
        let classifier = match config.classifier {
            None => None,
            Some(classifier) => {
                if !valid_classifier_name(&classifier.name) {
                    return Err(invalid(format!(
                        "classifier name is 1 to {MAX_CLASSIFIER_NAME} bytes of a-z, 0-9, `_` and `-`"
                    )));
                }
                Some(Classified {
                    name: classifier.name.into(),
                    phase: classifier.phase.unwrap_or(Scope::Both),
                    on_error: classifier.on_error,
                    bound: None,
                })
            }
        };
        if config.rules.is_empty() && classifier.is_none() {
            return Err(invalid("needs at least one rule or a classifier"));
        }
        Ok(Self(Box::new(Parts {
            rules: Arc::new(rules),
            classifier,
            max_body,
            runtimes: Arc::new(Runtimes(Box::default())),
            fingerprint: state::fingerprint(declared),
        })))
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        if !self.scans(Scope::Request) {
            return Ok(Flow::Continue);
        }
        match self.judge_request(cx, state).await? {
            Ok(()) => Ok(Flow::Continue),
            Err(err) => {
                *cx.capacity_refusal = err.is_capacity_refusal();
                *cx.reason = Some(err.log_reason());
                respond::write_error(cx.session, &err).await?;
                Ok(Flow::Respond)
            }
        }
    }

    /// The upstream gets the redacted body with its exact length, whatever framing the client
    /// used; and answers in the clear when the response is scanned.
    fn upstream_request(
        &self,
        request: &mut RequestHeader,
        state: &mut State,
    ) -> pingora::Result<()> {
        if let Some(redacted) = state.0.as_ref().and_then(|active| active.redacted.as_ref()) {
            request.remove_header(&TRANSFER_ENCODING);
            request.insert_header(CONTENT_LENGTH, redacted.len().to_string())?;
        }
        if self.scans(Scope::Response) {
            request.remove_header(&http::header::ACCEPT_ENCODING);
        }
        Ok(())
    }

    /// The held request body is replayed to the upstream as one chunk, and again on a retry:
    /// the redacted bytes stand in for it each time, and any other chunk is emptied.
    fn request_body_chunk(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        state: &mut State,
    ) -> Result<(), AppError> {
        let Some(redacted) = state.0.as_ref().and_then(|active| active.redacted.as_ref()) else {
            return Ok(());
        };
        // `None` would end the upstream request: an empty chunk stays empty bytes.
        *body = Some(if end_of_stream {
            redacted.clone()
        } else {
            Bytes::new()
        });
        Ok(())
    }

    fn response_hold(&self, cx: &ResponseCx<'_>, state: &mut State) -> Result<Hold, AppError> {
        if !self.scans(Scope::Response) || !has_body(cx.request, cx.response.status) {
            return Ok(Hold::No);
        }
        let headers = &cx.response.headers;
        let declared = declared_length(headers);
        if declared == Some(0) && cx.response.status != StatusCode::SWITCHING_PROTOCOLS {
            return Ok(Hold::No);
        }
        // A tunnel, or a body in a form the rules cannot read: never passed on unseen.
        if cx.response.status == StatusCode::SWITCHING_PROTOCOLS || !is_json(headers) {
            return Err(AppError::UpstreamResponseUnscannable);
        }
        let max = len_of(self.0.max_body);
        if declared.is_some_and(|declared| declared > max) {
            return Err(AppError::UpstreamResponseTooLarge);
        }
        let tenant = cx.tenant.ok_or(AppError::GuardSaturated)?;
        let charge = tenant
            .charge(hold_charge(declared.unwrap_or(max)))
            .ok_or(AppError::GuardSaturated)?;
        state.active().holding = true;
        Ok(Hold::Yes {
            max_body: max,
            charge,
        })
    }

    async fn response_held(&self, cx: &mut HeldCx<'_>, state: &mut State) -> Result<(), AppError> {
        if !state
            .0
            .as_mut()
            .is_some_and(|active| std::mem::take(&mut active.holding))
        {
            return Ok(());
        }
        let scanned = match self.scan(Scope::Response, cx.body.clone()).await? {
            Ok(scanned) => scanned,
            Err(Unscannable::NotJson) => return Err(AppError::UpstreamResponseUnscannable),
            Err(Unscannable::TooMuchOutput) => return Err(AppError::UpstreamResponseTooLarge),
        };
        match scanned.outcome {
            Outcome::Blocked { category } => return Err(AppError::ContentBlocked(category)),
            Outcome::Redacted(bytes) => {
                let framed_by_length = cx.head.headers.contains_key(CONTENT_LENGTH)
                    || !cx.head.headers.contains_key(TRANSFER_ENCODING);
                *cx.body = Bytes::from(bytes);
                if framed_by_length {
                    cx.head
                        .insert_header(CONTENT_LENGTH, cx.body.len().to_string())
                        .map_err(|_| AppError::GuardUnavailable)?;
                }
            }
            Outcome::Clean => {}
        }
        if !self.classifies(Scope::Response) {
            return Ok(());
        }
        let app: &CompiledApp = cx.app;
        let env = Env {
            client: cx.auth,
            policy: cx.policy,
            tenant: cx.tenant,
            tenant_id: app.tenant(),
        };
        self.classify(&env, Wire::Response, &scanned.text, app.id())
            .await
    }

    /// Dropping the stage stops scanning; a rule that is gone, differs, redacts where it blocked
    /// or runs in fewer phases checks less; a classifier that is dropped, narrowed, moved or
    /// allowed to fail open judges less.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let mut kinds = Vec::new();
        if self.0.rules.weakened_by(&new.0.rules) {
            kinds.push(kind::RULE_WEAKENED);
        }
        if let Some(old) = &self.0.classifier {
            match &new.0.classifier {
                None => kinds.push(guard::kind::DROPPED),
                Some(now) => {
                    let narrowed = [Scope::Request, Scope::Response]
                        .into_iter()
                        .any(|at| old.phase.covers(at) && !now.phase.covers(at));
                    if narrowed {
                        kinds.push(guard::kind::DROPPED);
                    }
                    match (&old.bound, &now.bound) {
                        (Some(before), Some(after)) => kinds.extend(before.posture(Some(after))),
                        _ => {
                            if old.on_error == OnError::Deny && now.on_error == OnError::Allow {
                                kinds.push(guard::kind::FAIL_OPEN);
                            }
                        }
                    }
                }
            }
        }
        let mut seen = Vec::new();
        kinds.retain(|kind| {
            let first = !seen.contains(kind);
            seen.push(*kind);
            first
        });
        kinds
    }

    fn describe(&self) -> Value {
        let rules: Vec<Value> = self
            .0
            .rules
            .declared()
            .iter()
            .map(|rule| {
                json!({
                    "name": &*rule.name,
                    "phase": rule.phase.name(),
                    "action": rule.action.name(),
                    "category": &*rule.category,
                })
            })
            .collect();
        let classifier = self.0.classifier.as_ref().map(|classifier| {
            json!({
                "name": &*classifier.name,
                "phase": classifier.phase.name(),
                "on_error": match classifier.on_error {
                    OnError::Deny => "deny",
                    OnError::Allow => "allow",
                },
            })
        });
        json!({
            "rules": rules,
            "classifier": classifier,
            "max_body_bytes": self.0.max_body,
        })
    }
}

/// Binds every `content_guard` middleware of the snapshot (`stages` are the compiled stages of
/// each app, in the snapshot's order): the classifier it names must exist and list the app's
/// tenant, and the tenant's budget must hold one scan.
pub(crate) fn bind<'a>(
    snapshot: &Snapshot,
    classifiers: &Classifiers,
    resolver: &Resolver,
    stages: impl Iterator<Item = &'a mut [Named]>,
) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    for (app, stages) in snapshot.apps.iter().zip(stages) {
        for named in stages {
            if let Stage::ContentGuard(guard) = &mut named.stage
                && let Err(invalid) = guard.bind(app, snapshot, classifiers, resolver)
            {
                rejected.push(Rejected::new(
                    app,
                    format!("middleware {}", named.name),
                    invalid,
                ));
            }
        }
    }
    rejected
}

/// The permit and circuit of every `content_guard` classifier of the live table, kept by the
/// shared [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]). A
/// push that leaves a middleware's declaration as it was keeps its circuit.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtimes>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            Stage::ContentGuard(stage) => Some((stage.0.fingerprint, &mut stage.0.runtimes)),
            _ => None,
        });
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;
    use crate::wasm as engine;

    fn app() -> App {
        serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
        }))
        .expect("app")
    }

    fn compile(config: &Value) -> Result<ContentGuard, Invalid> {
        let mut declared = json!({"name": "g", "type": "content_guard"});
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app = app();
        let mut compiler = engine::Compiler::default();
        ContentGuard::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut compiler,
            },
        )
    }

    fn rule(name: &str, pattern: &str, action: &str) -> Value {
        json!({"name": name, "pattern": pattern, "action": action})
    }

    fn guard(config: &Value) -> ContentGuard {
        compile(config).expect("compiled")
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
                http::HeaderValue::from_str(value).expect("value"),
            );
        }
        map
    }

    #[test]
    fn content_guard_rule_caps() {
        let one = json!([rule("a", "x", "block")]);
        assert!(compile(&json!({"rules": one})).is_ok());
        let many: Vec<Value> = (0..65)
            .map(|at| rule(&format!("r{at}"), "x", "block"))
            .collect();
        let long = "x".repeat(1025);
        for bad in [
            json!({"rules": many}),
            json!({"rules": [rule("a", &long, "block")]}),
            json!({"rules": [rule("a", r"\p{L}{2000}", "block")]}),
            json!({"rules": [rule("a", "x", "log")]}),
            json!({"rules": [{"name": "a", "pattern": "x"}]}),
            json!({"rules": [rule("a", "x", "block"), rule("a", "y", "block")]}),
            json!({"rules": [rule("A b", "x", "block")]}),
            json!({"rules": [rule("a", "x*", "block")]}),
            json!({"rules": one, "max_body_bytes": 0}),
            json!({"rules": one, "max_body_bytes": MAX_BODY + 1}),
            json!({"rules": []}),
            json!({}),
            json!({"rules": one, "nope": 1}),
            json!({"rules": one, "classifier": {"name": "Bad Name"}}),
            json!({"rules": one, "classifier": {"name": "c", "on_error": "maybe"}}),
        ] {
            assert_eq!(
                compile(&bad).expect_err("refused").code,
                "invalid_middleware",
                "{bad}"
            );
        }
        assert!(
            compile(&json!({"rules": one, "max_body_bytes": MAX_BODY})).is_ok()
                && compile(&json!({"classifier": {"name": "c"}})).is_ok(),
            "a classifier alone is enough"
        );
    }

    #[test]
    fn content_guard_json_media_check() {
        for ok in [
            "application/json",
            "Application/JSON; charset=utf-8",
            "application/vnd.api+json",
            r#"application/json; charset="UTF-8""#,
            "application/json; profile=x",
        ] {
            assert!(is_json(&headers(&[("content-type", ok)])), "{ok}");
        }
        for bad in [
            "text/plain",
            "application/json; charset=latin1",
            "application/x-www-form-urlencoded",
            "application/grpc",
            "",
        ] {
            assert!(!is_json(&headers(&[("content-type", bad)])), "{bad}");
        }
        assert!(!is_json(&HeaderMap::new()), "no content type");
        assert!(!is_json(&headers(&[
            ("content-type", "application/json"),
            ("content-encoding", "gzip")
        ])));
        assert!(is_json(&headers(&[
            ("content-type", "application/json"),
            ("content-encoding", "identity")
        ])));
    }

    #[test]
    fn content_guard_budget_must_hold_one_scan() {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "version": 1,
            "tenants": [{"id": "t1", "weight": 1, "budget": {"max_inflight": 4, "max_buffer_bytes": 1000}}],
            "apps": [],
        }))
        .expect("snapshot");
        let mut stage = guard(&json!({"rules": [rule("a", "x", "block")], "max_body_bytes": 100}));
        let needed = hold_charge(100);
        let mut tight = |bytes: u64| {
            let mut snapshot = snapshot.clone();
            snapshot.tenants[0].budget.max_buffer_bytes = bytes;
            stage.bind(
                &app(),
                &snapshot,
                &Classifiers::default(),
                &Resolver::default(),
            )
        };
        assert!(tight(needed).is_ok());
        let refused = tight(needed - 1).expect_err("refused");
        assert_eq!(refused.code, "invalid_middleware");
    }

    #[test]
    fn content_guard_unknown_or_unlisted_classifier_is_one_error() {
        let classifiers = Classifiers::parse(
            r#"{"mine": {"url": "http://10.0.0.9/c", "tenants": ["t1"]},
                "theirs": {"url": "http://10.0.0.9/c", "tenants": ["t2"]}}"#,
        )
        .expect("classifiers");
        let snapshot: Snapshot = serde_json::from_value(json!({
            "version": 1,
            "tenants": [{"id": "t1", "weight": 1, "budget": {"max_inflight": 4, "max_buffer_bytes": 100000000}}],
            "apps": [],
        }))
        .expect("snapshot");
        let bind = |name: &str| {
            let mut stage = guard(&json!({"classifier": {"name": name}}));
            stage.bind(&app(), &snapshot, &classifiers, &Resolver::default())
        };
        assert!(bind("mine").is_ok());
        let unlisted = bind("theirs").expect_err("unlisted");
        let unknown = bind("nobody").expect_err("unknown");
        assert_eq!(unlisted.code, "invalid_middleware");
        assert_eq!(unknown.code, "invalid_middleware");
        let words = |invalid: &Invalid, name: &str| invalid.message.replace(name, "<name>");
        assert_eq!(words(&unlisted, "theirs"), words(&unknown, "nobody"));
    }

    #[test]
    fn content_guard_posture_lists_relaxations() {
        let with = |rules: Value, classifier: Value| {
            let mut config = json!({"rules": rules});
            if !classifier.is_null() {
                config["classifier"] = classifier;
            }
            guard(&config)
        };
        let base = with(
            json!([rule("a", "x", "block")]),
            json!({"name": "c", "phase": "both"}),
        );
        assert_eq!(base.posture(None), [kind::REMOVED]);
        let same = with(
            json!([rule("a", "x", "block"), rule("b", "y", "block")]),
            json!({"name": "c", "phase": "both"}),
        );
        assert!(base.posture(Some(&same)).is_empty());
        let redacts = with(
            json!([rule("a", "x", "redact")]),
            json!({"name": "c", "phase": "both"}),
        );
        assert_eq!(base.posture(Some(&redacts)), [kind::RULE_WEAKENED]);
        let no_classifier = with(json!([rule("a", "x", "block")]), Value::Null);
        assert_eq!(base.posture(Some(&no_classifier)), [guard::kind::DROPPED]);
        let narrow = with(
            json!([rule("a", "x", "block")]),
            json!({"name": "c", "phase": "request"}),
        );
        assert_eq!(base.posture(Some(&narrow)), [guard::kind::DROPPED]);
        let open = with(
            json!([rule("a", "x", "block")]),
            json!({"name": "c", "phase": "both", "on_error": "allow"}),
        );
        assert_eq!(base.posture(Some(&open)), [guard::kind::FAIL_OPEN]);
        let wider = with(
            json!([rule("a", "x", "block")]),
            json!({"name": "c", "phase": "both", "on_error": "deny"}),
        );
        assert!(narrow.posture(Some(&wider)).is_empty());
    }

    #[test]
    fn content_guard_describe_hides_patterns() {
        let stage = guard(&json!({
            "rules": [{"name": "ssn", "pattern": "sentinel-pattern-[0-9]+", "action": "redact", "category": "pii"}],
            "classifier": {"name": "c"},
        }));
        let shown = stage.describe().to_string();
        assert!(!shown.contains("sentinel"), "{shown}");
        for expected in ["ssn", "redact", "pii", "both", "deny", "65536"] {
            assert!(shown.contains(expected), "{expected} in {shown}");
        }
    }

    #[test]
    fn content_guard_state_is_one_pointer() {
        assert_eq!(size_of::<State>(), size_of::<usize>());
        assert_eq!(size_of::<ContentGuard>(), size_of::<usize>());
    }
}
