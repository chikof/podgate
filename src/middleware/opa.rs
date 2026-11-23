//! The `opa` middleware: asks an Open Policy Agent (or any server that speaks its Data API)
//! whether a request may continue. Full reference: `docs/ref/mw-opa.md`.
//!
//! ```json
//! { "name": "policy", "type": "opa", "address": "http://10.0.0.7:8181/v1/data/podgate/allow",
//!   "request_headers": ["x-api-key"], "include_query": false, "timeout_secs": 2 }
//! ```
//!
//! The call is the OPA REST Data API: `POST <address>` with `{"input": {...}}`, answered with
//! `{"result": ...}`. A boolean, or an object `{"allow": bool, "status"?, "headers"?}`, is a
//! verdict; a missing `result` (an undefined document) is a deny. A deny is `403` (or the
//! policy's `status`), and a failure is always `503 {"error":"authorizer unavailable"}`, never
//! the same code, so an operator can tell a policy from an outage. The stage fails closed:
//! whatever goes wrong with the call, the request is never passed on.
//!
//! - **Where.** `address` is fixed configuration, dialled with the bounded client of
//!   `forward_auth` ([`forward_auth::Client`]) under the upstream address policy on every call.
//! - **What is sent.** `method`, `path`, `query` (with `include_query`), `host`, `source_ip`,
//!   `tenant`, `app`, `headers` (the names of `request_headers`, as lists), and `claims`, the
//!   verified claims of a `jwt_auth` stage earlier in the chain. The body is never sent, and a
//!   claim is never read from a request header ([`RequestCx::claims`]).
//! - **How much.** The call holds one permit of `max_concurrent`, and its bytes are charged to
//!   the tenant's buffer budget before the connection is made.

mod verdict;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, Method, StatusCode};
use pingora::http::{RequestHeader, ResponseHeader};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::Semaphore;

use self::verdict::{Headers, Verdict};
use super::forward_auth::{self, ALLOWANCE, Parsed, REQUEST_LIMIT, Route, parse_url};
use super::{CompileCx, Flow, Kind, RequestCx, state};
use crate::budget::BufferGuard;
use crate::client_ip::{ForwardedView, UNKNOWN};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::plan;
use crate::service::resolve::Resolver;
use crate::service::{Server, Transport};
use crate::table::CompiledApp;
use podgate_model::Declared;

/// The default time for one call.
const DEFAULT_TIMEOUT_SECS: u64 = 2;
/// The longest `timeout_secs`.
const MAX_TIMEOUT_SECS: u64 = 10;
/// The default cap of an answer's body.
const DEFAULT_MAX_RESPONSE: usize = 16 * 1024;
/// The largest `max_response_bytes`.
const MAX_RESPONSE: usize = 1024 * 1024;
/// The default `max_concurrent`.
const DEFAULT_MAX_CONCURRENT: u32 = 64;
/// The largest `max_concurrent`.
const MAX_CONCURRENT: u32 = 4096;
/// The most names in `request_headers` and in `response_headers`.
const MAX_NAMES: usize = 64;
/// The longest `address`.
const MAX_ADDRESS: usize = 512;
/// What the path of `address` must hold, followed by the policy path.
const DATA_PATH: &str = "/v1/data/";

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: requests are no longer judged by the policy.
    pub const REMOVED: &str = "opa_removed";
    /// The server or the policy path of `address` changed: another policy decides.
    pub const POLICY_CHANGED: &str = "opa_policy_changed";
    /// The policy sees less of the request (a header or the query is no longer sent), so a rule
    /// that denied on it can no longer do so.
    pub const INPUT_REDUCED: &str = "opa_input_reduced";
}

/// The configuration of an `opa` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The Data API URL of the policy, ending in `/v1/data/<policy path>`, with no query.
    address: String,
    /// Send the request's query string as `input.query`.
    #[serde(default)]
    include_query: bool,
    /// Request headers sent as `input.headers`.
    #[serde(default)]
    request_headers: Vec<String>,
    /// Headers the policy may set in its result.
    #[serde(default)]
    response_headers: Vec<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    max_response_bytes: Option<usize>,
    #[serde(default)]
    max_concurrent: Option<u32>,
}

/// What outlives a snapshot push: the permits of `max_concurrent`.
#[derive(Debug)]
struct Runtime {
    permits: Semaphore,
}

#[derive(Debug)]
struct Parts {
    server: Server,
    /// Resolves the address's host name; bound at compile ([`Opa::bind`]).
    resolver: Resolver,
    transport: Arc<Transport>,
    transport_name: Option<Box<str>>,
    /// The `Host` header of the call: the authority as written.
    host: Box<str>,
    /// The request target of the call: the path of the address.
    target: Box<str>,
    include_query: bool,
    request_headers: Box<[HeaderName]>,
    response_headers: Box<[HeaderName]>,
    timeout: Duration,
    max_response: usize,
    max_concurrent: u32,
    runtime: Arc<Runtime>,
    fingerprint: u64,
}

/// A compiled `opa` middleware.
#[derive(Debug)]
pub struct Opa(Box<Parts>);

/// What a request keeps of its `opa` stage.
#[derive(Debug, Default)]
pub struct State {
    /// The policy allowed the request and set at least one header on it: the request now carries
    /// an identity the cache key does not know.
    identified: bool,
}

impl State {
    /// Whether the request carries headers the policy set.
    #[must_use]
    pub fn identified(&self) -> bool {
        self.identified
    }
}

/// The `input` of the call.
#[derive(Serialize)]
struct Input<'a> {
    method: &'a str,
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<&'a str>,
    host: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<IpAddr>,
    tenant: &'a str,
    app: &'a str,
    headers: BTreeMap<&'a str, Vec<Cow<'a, str>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<&'a Map<String, Value>>,
}

/// The body of the call.
#[derive(Serialize)]
struct Query<'a> {
    input: Input<'a>,
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("opa: {message}"))
}

/// Parses a list of header names: valid, not reserved, no repeats.
fn names(list: &[String], field: &str) -> Result<Box<[HeaderName]>, Invalid> {
    if list.len() > MAX_NAMES {
        return Err(invalid(format!(
            "`{field}` lists more than {MAX_NAMES} names"
        )));
    }
    let mut out: Vec<HeaderName> = Vec::with_capacity(list.len());
    for raw in list {
        let name = HeaderName::from_bytes(raw.as_bytes())
            .map_err(|_| invalid(format!("`{field}`: {raw:?} is not a header name")))?;
        if forward_auth::reserved(&name) {
            return Err(invalid(format!(
                "`{field}`: {name} frames the message, belongs to the connection or is written by podgate"
            )));
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out.into_boxed_slice())
}

/// Reads `address`: a Data API URL, `.../v1/data/<policy path>`, with no query string.
fn parse_address(address: &str) -> Result<Parsed, Invalid> {
    let parsed = parse_url(address, "address", MAX_ADDRESS).map_err(invalid)?;
    if parsed.target.contains('?') {
        return Err(invalid(
            "`address` has a query string; the call sends none of OPA's options",
        ));
    }
    let names_a_policy = parsed
        .target
        .find(DATA_PATH)
        .is_some_and(|at| parsed.target.len() > at + DATA_PATH.len());
    if !names_a_policy {
        return Err(invalid(format!(
            "`address` must end in {DATA_PATH}<policy path>: the Data API of a policy"
        )));
    }
    Ok(parsed)
}

/// The transport named `name` of `app`, compiled for the call.
fn transport_of(
    app: &podgate_model::App,
    name: Option<&str>,
    tls: bool,
) -> Result<Arc<Transport>, Invalid> {
    let Some(name) = name else {
        return Ok(Arc::new(Transport::default()));
    };
    let declared = app
        .transports
        .iter()
        .find(|declared| &*declared.name == name)
        .ok_or_else(|| {
            Invalid::new(
                "unknown_transport",
                format!("opa: transport {name} is not declared by the app"),
            )
        })?;
    let transport = Transport::compile(declared)?;
    if !tls && transport.has_tls_settings() {
        return Err(invalid(
            "the transport sets TLS options and the address is plain http://",
        ));
    }
    Ok(Arc::new(transport))
}

impl Opa {
    /// Gives the stage the resolver its host name (when `address` has one) is resolved with.
    pub(crate) fn bind(&mut self, resolver: &Resolver) {
        self.0.resolver = resolver.clone();
    }

    /// Refuses a call that could never be charged: the allowances plus the body cap are more
    /// than the tenant's whole `max_buffer_bytes`. A budget that is only full right now is not
    /// judged here; the request is refused with `503` when its charge is refused.
    ///
    /// # Errors
    ///
    /// `invalid_middleware` naming the tenant, the bytes a call needs and the budget.
    pub(crate) fn check_budget(&self, tenant: &str, max_buffer_bytes: u64) -> Result<(), Invalid> {
        let needed = self.charge();
        if max_buffer_bytes >= needed {
            return Ok(());
        }
        Err(invalid(format!(
            "tenant {tenant} has max_buffer_bytes {max_buffer_bytes}, below the {needed} bytes one policy call reserves (max_response_bytes {} plus {ALLOWANCE}); lower max_response_bytes or raise the budget",
            self.0.max_response,
        ))
        .with("tenant", tenant)
        .with("needed_bytes", needed)
        .with("max_buffer_bytes", max_buffer_bytes))
    }

    /// The bytes one call charges to the tenant.
    fn charge(&self) -> u64 {
        ALLOWANCE.saturating_add(u64::try_from(self.0.max_response).unwrap_or(u64::MAX))
    }

    /// Whether the policy may set the header `name`.
    fn sets(&self, name: &HeaderName) -> bool {
        self.0.response_headers.contains(name)
    }

    /// Removes from `request` every header the policy could set, so none survives from the
    /// client.
    fn strip(&self, request: &mut RequestHeader) {
        for name in &self.0.response_headers {
            request.remove_header(name);
        }
    }

    /// The call: the request head and the JSON body, `None` when together they would pass
    /// [`REQUEST_LIMIT`].
    fn build(
        &self,
        request: &RequestHeader,
        view: &ForwardedView,
        subject: (&str, &str),
        claims: Option<&Map<String, Value>>,
    ) -> Option<Vec<u8>> {
        let own_host = crate::route::request_host(request);
        let mut headers: BTreeMap<&str, Vec<Cow<'_, str>>> = BTreeMap::new();
        for name in &self.0.request_headers {
            let values: Vec<Cow<'_, str>> = request
                .headers
                .get_all(name)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()))
                .collect();
            if !values.is_empty() {
                headers.insert(name.as_str(), values);
            }
        }
        let body = serde_json::to_vec(&Query {
            input: Input {
                method: request.method.as_str(),
                path: request.uri.path(),
                query: request.uri.query().filter(|_| self.0.include_query),
                host: view
                    .host
                    .as_deref()
                    .or(own_host.as_deref())
                    .unwrap_or_default(),
                source_ip: (view.client_ip != UNKNOWN).then_some(view.client_ip),
                tenant: subject.0,
                app: subject.1,
                headers,
                claims,
            },
        })
        .ok()?;
        let mut call = Vec::with_capacity(body.len() + self.0.target.len() + 256);
        call.extend_from_slice(b"POST ");
        call.extend_from_slice(self.0.target.as_bytes());
        call.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        call.extend_from_slice(self.0.host.as_bytes());
        call.extend_from_slice(
            format!(
                "\r\nConnection: close\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        call.extend_from_slice(&body);
        (call.len() <= REQUEST_LIMIT).then_some(call)
    }

    /// Asks the policy about the request on `cx`.
    async fn decide(&self, cx: &mut RequestCx<'_>) -> Result<Verdict, AppError> {
        // No budget for the tenant means nothing to charge the call to: closed.
        let tenant = cx.tenant.ok_or(AppError::AuthorizerSaturated)?;
        let _permit = self
            .0
            .runtime
            .permits
            .try_acquire()
            .map_err(|_| AppError::AuthorizerSaturated)?;
        let _charge: BufferGuard = tenant
            .charge(self.charge())
            .ok_or(AppError::AuthorizerSaturated)?;
        let request = self
            .build(
                cx.session.req_header(),
                cx.forwarded,
                (cx.app.tenant(), cx.app.id()),
                cx.claims.as_ref(),
            )
            .ok_or_else(|| {
                tracing::warn!(app = cx.app.id(), "opa request is too large");
                AppError::AuthorizerUnavailable
            })?;
        let route = Route {
            server: &self.0.server,
            transport: &self.0.transport,
            resolver: &self.0.resolver,
            policy: cx.policy,
            tenant: cx.app.tenant(),
        };
        let answer = cx
            .auth
            .call(&route, &request, self.0.max_response, self.0.timeout)
            .await
            .map_err(|why| {
                tracing::warn!(app = cx.app.id(), %why, "opa call failed");
                AppError::AuthorizerUnavailable
            })?;
        if answer.status != 200 {
            tracing::warn!(
                app = cx.app.id(),
                status = answer.status,
                "opa answered a status other than 200"
            );
            return Err(AppError::AuthorizerUnavailable);
        }
        verdict::parse(&answer.body, |name| self.sets(name)).map_err(|why| {
            tracing::warn!(app = cx.app.id(), reason = why.0, "opa answer is malformed");
            AppError::AuthorizerUnavailable
        })
    }

    /// Writes the refusal: `status`, the headers of the policy that a refusal may carry, and a
    /// JSON body naming the status.
    async fn refuse(cx: &mut RequestCx<'_>, status: u16, headers: Headers) -> pingora::Result<()> {
        let reason = StatusCode::from_u16(status)
            .ok()
            .and_then(|code| code.canonical_reason())
            .unwrap_or("forbidden")
            .to_ascii_lowercase();
        let body = Bytes::from(json!({ "error": reason }).to_string());
        let bodyless = cx.session.req_header().method == Method::HEAD;
        let mut head = ResponseHeader::build(status, Some(headers.len() + 3))?;
        for (name, value) in headers {
            if forward_auth::relayable(&name) {
                head.append_header(name, value)?;
            }
        }
        head.insert_header("content-type", "application/json")?;
        head.insert_header("content-length", body.len().to_string())?;
        head.insert_header("cache-control", "no-store")?;
        cx.session
            .write_response_header(Box::new(head), bodyless)
            .await?;
        if bodyless {
            return Ok(());
        }
        cx.session.write_response_body(Some(body), true).await
    }
}

impl Kind for Opa {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        let Parsed {
            server,
            host,
            target,
        } = parse_address(&config.address)?;
        let transport = transport_of(cx.app, config.transport.as_deref(), server.tls)?;
        let request_headers = names(&config.request_headers, "request_headers")?;
        let response_headers = names(&config.response_headers, "response_headers")?;
        if let Some(both) = response_headers
            .iter()
            .find(|name| request_headers.contains(name))
        {
            return Err(invalid(format!(
                "{both} is in `request_headers` and `response_headers`: the client's copy is removed before the call, so the policy would never see it"
            )));
        }
        let timeout_secs = config.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if !(1..=MAX_TIMEOUT_SECS).contains(&timeout_secs) {
            return Err(invalid(format!(
                "`timeout_secs` is in 1..={MAX_TIMEOUT_SECS}"
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
        let permits = usize::try_from(max_concurrent).unwrap_or(usize::MAX);
        Ok(Self(Box::new(Parts {
            server,
            resolver: Resolver::default(),
            transport,
            transport_name: config.transport.map(Into::into),
            host,
            target,
            include_query: config.include_query,
            request_headers,
            response_headers,
            timeout: Duration::from_secs(timeout_secs),
            max_response,
            max_concurrent,
            runtime: Arc::new(Runtime {
                permits: Semaphore::new(permits),
            }),
            fingerprint: state::fingerprint(declared),
        })))
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        // First, whatever the verdict: nothing the client wrote under a name the policy sets
        // may reach the upstream.
        self.strip(cx.session.req_header_mut());
        match self.decide(cx).await {
            Ok(Verdict::Allow { headers }) => {
                let request = cx.session.req_header_mut();
                for (name, value) in headers {
                    request.append_header(name, value)?;
                    state.identified = true;
                }
                Ok(Flow::Continue)
            }
            Ok(Verdict::Deny { status, headers }) => {
                *cx.reason = Some("opa_denied");
                Self::refuse(cx, status, headers).await?;
                Ok(Flow::Respond)
            }
            Err(err) => {
                *cx.capacity_refusal = err.is_capacity_refusal();
                *cx.reason = Some(err.log_reason());
                crate::respond::write_error(cx.session, &err).await?;
                Ok(Flow::Respond)
            }
        }
    }

    /// Dropping the middleware stops asking; another server or policy path is another
    /// decision-maker; a policy that sees less of the request can no longer deny on it; a
    /// transport that stops verifying the policy server lets anyone on the path answer for it.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let (old, now) = (&*self.0, &*new.0);
        let mut kinds = Vec::new();
        if old.server.url != now.server.url || old.target != now.target {
            kinds.push(kind::POLICY_CHANGED);
        }
        let header_dropped = old
            .request_headers
            .iter()
            .any(|name| !now.request_headers.contains(name));
        if header_dropped || (old.include_query && !now.include_query) {
            kinds.push(kind::INPUT_REDUCED);
        }
        if now.server.tls
            && now.transport.insecure_skip_verify()
            && !(old.server.tls && old.transport.insecure_skip_verify())
        {
            kinds.push(plan::kind::UPSTREAM_TLS_VERIFICATION_DISABLED);
        }
        kinds
    }

    fn carries_identity(&self, name: &HeaderName) -> bool {
        self.sets(name)
    }

    fn describe(&self) -> Value {
        let scheme = if self.0.server.tls { "https" } else { "http" };
        let names = |list: &[HeaderName]| -> Vec<String> {
            list.iter().map(|name| name.as_str().to_owned()).collect()
        };
        json!({
            "address": format!("{scheme}://{}{}", self.0.host, self.0.target),
            "include_query": self.0.include_query,
            "request_headers": names(&self.0.request_headers),
            "response_headers": names(&self.0.response_headers),
            "timeout_secs": self.0.timeout.as_secs(),
            "transport": self.0.transport_name,
            "max_response_bytes": self.0.max_response,
            "max_concurrent": self.0.max_concurrent,
        })
    }
}

/// The permits of every `opa` middleware of the live table, kept by the shared
/// [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]). A push that
/// leaves a middleware's declaration as it was keeps its permits.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtime>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            super::Stage::Opa(opa) => Some((opa.0.fingerprint, &mut opa.0.runtime)),
            _ => None,
        });
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::client_ip::Proto;
    use crate::wasm as engine;

    fn app() -> podgate_model::App {
        serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
            "transports": [{"name": "t", "type": "servers_transport", "server_name": "opa.internal"}],
        }))
        .expect("app")
    }

    fn compile(config: &Value) -> Result<Opa, Invalid> {
        let mut declared = json!({"name": "policy", "type": "opa"});
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app = app();
        let mut compiler = engine::Compiler::default();
        Opa::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut compiler,
            },
        )
    }

    fn code(config: &Value) -> &'static str {
        compile(config).expect_err("refused").code
    }

    fn opa(extra: &Value) -> Opa {
        let mut config = json!({"address": "http://10.0.0.7:8181/v1/data/podgate/allow"});
        if let (Some(object), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
            object.extend(extra.clone());
        }
        compile(&config).expect("compiled")
    }

    fn with(extra: &Value) -> Value {
        let mut config = json!({"address": "http://10.0.0.7:8181/v1/data/p"});
        config
            .as_object_mut()
            .expect("object")
            .extend(extra.as_object().expect("object").clone());
        config
    }

    fn view() -> ForwardedView {
        ForwardedView {
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            proto: Proto::Https,
            ..ForwardedView::default()
        }
    }

    fn body_of(call: &[u8]) -> Value {
        let at = call
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("head end");
        serde_json::from_slice(&call[at + 4..]).expect("json body")
    }

    #[test]
    fn opa_config_rejects_bad_address() {
        assert!(compile(&json!({"address": "http://10.0.0.7:8181/v1/data/a"})).is_ok());
        assert!(compile(&json!({"address": "https://opa.internal/prefix/v1/data/a/b"})).is_ok());
        for bad in [
            "http://10.0.0.7:8181/",
            "http://10.0.0.7:8181",
            "http://10.0.0.7:8181/v1/data",
            "http://10.0.0.7:8181/v1/data/",
            "http://10.0.0.7:8181/v1/policies/a",
            "http://10.0.0.7:8181/v1/data/a?pretty=true",
            "h2c://10.0.0.7:8181/v1/data/a",
            "http://user:pw@10.0.0.7/v1/data/a",
            "/v1/data/a",
            "",
        ] {
            assert_eq!(
                code(&json!({"address": bad})),
                "invalid_middleware",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn opa_config_rejects_bad_limits() {
        assert!(
            compile(&with(
                &json!({"timeout_secs": 10, "max_response_bytes": MAX_RESPONSE, "max_concurrent": 4096})
            ))
            .is_ok()
        );
        for bad in [
            json!({"timeout_secs": 0}),
            json!({"timeout_secs": 11}),
            json!({"max_response_bytes": 0}),
            json!({"max_response_bytes": MAX_RESPONSE + 1}),
            json!({"max_concurrent": 0}),
            json!({"max_concurrent": 4097}),
            json!({"include_body": true}),
            json!({"nope": 1}),
        ] {
            assert_eq!(code(&with(&bad)), "invalid_middleware", "{bad}");
        }
        assert_eq!(
            code(&with(&json!({"transport": "missing"}))),
            "unknown_transport"
        );
        assert_eq!(
            code(&with(&json!({"transport": "t"}))),
            "invalid_middleware",
            "TLS options on a plain address"
        );
    }

    #[test]
    fn opa_config_rejects_reserved_header_names() {
        assert!(
            compile(&with(
                &json!({"request_headers": ["Authorization", "cookie", "x-api-key"], "response_headers": ["x-user", "www-authenticate"]})
            ))
            .is_ok()
        );
        for bad in [
            json!({"request_headers": ["host"]}),
            json!({"request_headers": ["x-forwarded-for"]}),
            json!({"request_headers": ["not a name"]}),
            json!({"response_headers": ["connection"]}),
            json!({"response_headers": ["content-length"]}),
            json!({"response_headers": ["proxy-authorization"]}),
            json!({"request_headers": ["x-user"], "response_headers": ["X-User"]}),
        ] {
            assert_eq!(code(&with(&bad)), "invalid_middleware", "{bad}");
        }
    }

    #[test]
    fn input_has_exactly_the_documented_keys() {
        let stage = opa(&json!({"request_headers": ["x-api-key", "authorization", "x-absent"]}));
        let mut request = RequestHeader::build("POST", b"/orders?id=7", None).expect("request");
        request.append_header("host", "A.test:8443").expect("host");
        request.append_header("x-api-key", "k1").expect("header");
        request.append_header("x-api-key", "k2").expect("header");
        request.append_header("x-other", "no").expect("header");
        let claims = json!({"sub": "ann"});
        let claims = claims.as_object().expect("object");

        let call = stage
            .build(&request, &view(), ("t1", "a"), Some(claims))
            .expect("built");
        let text = String::from_utf8(call.clone()).expect("text");
        assert!(
            text.starts_with("POST /v1/data/podgate/allow HTTP/1.1\r\nHost: 10.0.0.7:8181\r\n"),
            "{text}"
        );
        assert_eq!(
            body_of(&call),
            json!({"input": {
                "method": "POST", "path": "/orders", "host": "a.test",
                "source_ip": "192.0.2.7", "tenant": "t1", "app": "a",
                "headers": {"x-api-key": ["k1", "k2"]},
                "claims": {"sub": "ann"},
            }})
        );

        let with_query = opa(&json!({"include_query": true}));
        let call = with_query
            .build(&request, &ForwardedView::default(), ("t1", "a"), None)
            .expect("built");
        assert_eq!(
            body_of(&call),
            json!({"input": {
                "method": "POST", "path": "/orders", "query": "id=7", "host": "a.test",
                "tenant": "t1", "app": "a", "headers": {},
            }}),
            "no claims, no client address, no listed header: those keys are absent or empty"
        );
    }

    #[test]
    fn a_request_over_the_limit_is_not_sent() {
        let stage = opa(&json!({"request_headers": ["x-big"]}));
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request
            .append_header("x-big", "a".repeat(REQUEST_LIMIT))
            .expect("header");
        assert!(stage.build(&request, &view(), ("t1", "a"), None).is_none());
    }

    #[test]
    fn opa_budget_must_hold_one_call() {
        let stage = opa(&json!({"max_response_bytes": 1024}));
        let needed = ALLOWANCE + 1024;
        assert!(stage.check_budget("t1", needed).is_ok());
        let refused = stage.check_budget("t1", needed - 1).expect_err("refused");
        assert_eq!(refused.code, "invalid_middleware");
    }

    #[test]
    fn opa_posture_lists_relaxations() {
        let base = opa(&json!({"request_headers": ["x-a", "x-b"], "include_query": true}));
        let kinds = |new: Option<&Opa>| base.posture(new);
        assert_eq!(kinds(None), [kind::REMOVED]);
        assert!(
            kinds(Some(&opa(
                &json!({"request_headers": ["x-a", "x-b"], "include_query": true})
            )))
            .is_empty()
        );
        assert!(kinds(Some(&opa(&json!({"request_headers": ["x-a", "x-b", "x-c"], "include_query": true, "response_headers": ["x-user"]})))).is_empty());
        assert_eq!(
            kinds(Some(&opa(
                &json!({"request_headers": ["x-a"], "include_query": true})
            ))),
            [kind::INPUT_REDUCED]
        );
        assert_eq!(
            kinds(Some(&opa(&json!({"request_headers": ["x-a", "x-b"]})))),
            [kind::INPUT_REDUCED]
        );
        let other = compile(&json!({"address": "http://10.0.0.7:8181/v1/data/other", "request_headers": ["x-a", "x-b"], "include_query": true})).expect("compiled");
        assert_eq!(kinds(Some(&other)), [kind::POLICY_CHANGED]);
        let moved = compile(&json!({"address": "http://10.0.0.8:8181/v1/data/podgate/allow", "request_headers": ["x-a", "x-b"], "include_query": true})).expect("compiled");
        assert_eq!(kinds(Some(&moved)), [kind::POLICY_CHANGED]);
    }
}
