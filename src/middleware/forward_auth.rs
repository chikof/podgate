//! The `forward_auth` middleware: asks an auth service of the same app whether a request may
//! continue. Full reference: `docs/ref/mw-forward-auth.md`.
//!
//! ```json
//! { "name": "sso", "type": "forward_auth", "address": "http://10.0.0.5:9091/verify",
//!   "response_headers": ["x-user", "x-groups"], "timeout_secs": 5, "transport": "internal" }
//! ```
//!
//! The stage fails closed. Whatever goes wrong with the call (the upstream address policy refuses
//! the address, no connection, a timeout, an answer that is over its cap or is not clean
//! HTTP/1.1, no room under `max_concurrent` or in the tenant's buffer budget) the request gets
//! `503 {"error":"auth service unavailable"}` and is never passed on. Only a `2xx` answer lets it
//! continue; every other status is relayed to the client.
//!
//! - **Where.** `address` is fixed configuration, an `http://` or `https://` URL whose host is an
//!   IP literal. It is never derived from the request. The connection is made with the peer of
//!   [`Upstream::peer`] (so `transport` gives an `https://` address its trust anchors, SNI and
//!   client certificate) and the exact IP is checked against the upstream address policy on every
//!   call.
//! - **What is sent.** `GET` with `Host` of the address, `X-Forwarded-Method`, `-Proto`, `-Host`,
//!   `-Uri` and `-For` written from the connection and the resolved client address
//!   ([`ForwardedView`]), never from a raw `X-Forwarded-*` of the client, and the request headers
//!   `request_headers` allows (default: all but the connection's own and the forwarding set).
//!   The request body is never sent.
//! - **What comes back.** Headers named by `response_headers` (or matching
//!   `response_headers_regex`) of a `2xx` answer are copied into the request that goes on. Before
//!   anything else the same names are removed from the client's request, so a client cannot
//!   present `X-User` and have it survive when the auth service leaves it out.
//! - **How much.** The call holds one permit of `max_concurrent`, and its bytes (the request and
//!   head allowances, the body cap) are charged to the tenant's buffer budget before the
//!   connection is made.

mod client;

pub use client::Client;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, Method, Uri};
use pingora::http::{RequestHeader, ResponseHeader};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use super::{CompileCx, Flow, Kind, RequestCx, headers, state};
use crate::budget::BufferGuard;
use crate::client_ip::{ForwardedView, UNKNOWN};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::plan;
use crate::service::{Server, Transport, Upstream};
use crate::table::CompiledApp;
use podgate_model::Declared;

/// The default time for one call.
const DEFAULT_TIMEOUT_SECS: u64 = 5;
/// The longest `timeout_secs`; a call also never runs past the process's `REQUEST_TIMEOUT_SECS`.
const MAX_TIMEOUT_SECS: u64 = 3600;
/// The default cap of an answer's body.
const DEFAULT_MAX_RESPONSE: usize = 64 * 1024;
/// The largest `max_response_bytes`.
const MAX_RESPONSE: usize = 1024 * 1024;
/// The default `max_concurrent`.
const DEFAULT_MAX_CONCURRENT: u32 = 64;
/// The largest `max_concurrent`.
const MAX_CONCURRENT: u32 = 4096;
/// The most names in `request_headers` and in `response_headers`.
const MAX_NAMES: usize = 64;
/// The longest `response_headers_regex`.
const MAX_REGEX: usize = 256;
/// The largest compiled size of `response_headers_regex`.
const REGEX_SIZE_LIMIT: usize = 1 << 16;
/// The longest `address`.
const MAX_ADDRESS: usize = 512;

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: requests are no longer judged by the auth service.
    pub const REMOVED: &str = "forward_auth_removed";
    /// Fewer headers of the auth service's answer reach the upstream, so an upstream that reads
    /// the identity from them may see an anonymous request.
    pub const RESPONSE_HEADERS_REMOVED: &str = "forward_auth_response_headers_removed";
}

/// The configuration of a `forward_auth` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    address: String,
    #[serde(default)]
    trust_forward_header: bool,
    #[serde(default)]
    request_headers: Option<Vec<String>>,
    #[serde(default)]
    response_headers: Vec<String>,
    #[serde(default)]
    response_headers_regex: Option<String>,
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
    /// The server the address names; the transport decides how to talk to it.
    server: Server,
    transport: Arc<Transport>,
    transport_name: Option<Box<str>>,
    /// The `Host` header of the call: the authority as written.
    host: Box<str>,
    /// The request target of the call: the path and query of the address.
    target: Box<str>,
    trust_forward_header: bool,
    request_headers: Option<Box<[HeaderName]>>,
    response_headers: Box<[HeaderName]>,
    response_regex: Option<Regex>,
    timeout: Duration,
    max_response: usize,
    max_concurrent: u32,
    runtime: Arc<Runtime>,
    fingerprint: u64,
}

/// A compiled `forward_auth` middleware.
#[derive(Debug)]
pub struct ForwardAuth(Box<Parts>);

/// What a request keeps of its `forward_auth` stage.
#[derive(Debug, Default)]
pub struct State {
    /// The auth service answered `2xx` and its answer put at least one header into the request:
    /// the request now carries an identity the cache key does not know.
    identified: bool,
}

impl State {
    /// Whether the request carries headers copied from the auth service.
    #[must_use]
    pub fn identified(&self) -> bool {
        self.identified
    }
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("forward_auth: {message}"))
}

/// The headers a middleware never sends to the auth service, never copies from its answer and
/// never lets `response_headers` name: those that frame the message or belong to the connection,
/// and the forwarding set podgate writes itself.
fn reserved(name: &HeaderName) -> bool {
    let name = name.as_str();
    headers::FORBIDDEN.contains(&name)
        || name.starts_with("proxy-")
        || matches!(
            name,
            "forwarded"
                | "x-real-ip"
                | "expect"
                | "x-forwarded-for"
                | "x-forwarded-proto"
                | "x-forwarded-host"
                | "x-forwarded-port"
                | "x-forwarded-uri"
                | "x-forwarded-method"
        )
}

/// Whether a header of the auth service's refusal reaches the client: not the connection's own,
/// not what describes the auth service itself, not what podgate sets.
fn relayable(name: &HeaderName) -> bool {
    let name = name.as_str();
    !(headers::FORBIDDEN.contains(&name)
        || name.starts_with("proxy-")
        || matches!(
            name,
            "content-encoding" | "alt-svc" | "server" | "date" | "forwarded" | "x-real-ip"
        ))
}

/// Parses a list of header names: valid, not reserved, no repeats.
fn names(list: &[String], field: &str) -> Result<Vec<HeaderName>, Invalid> {
    if list.len() > MAX_NAMES {
        return Err(invalid(format!(
            "`{field}` lists more than {MAX_NAMES} names"
        )));
    }
    let mut out: Vec<HeaderName> = Vec::with_capacity(list.len());
    for raw in list {
        let name = HeaderName::from_bytes(raw.as_bytes())
            .map_err(|_| invalid(format!("`{field}`: {raw:?} is not a header name")))?;
        if reserved(&name) {
            return Err(invalid(format!(
                "`{field}`: {name} frames the message, belongs to the connection or is written by podgate"
            )));
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

/// Splits `address` into the server it names, the `Host` of the call and its request target.
fn parse_address(address: &str) -> Result<(Server, Box<str>, Box<str>), Invalid> {
    let bad = || {
        invalid(format!(
            "address {address:?} must be an absolute http:// or https:// URL with an IP address host"
        ))
    };
    if address.len() > MAX_ADDRESS {
        return Err(invalid(format!(
            "address is longer than {MAX_ADDRESS} bytes"
        )));
    }
    let uri: Uri = address.parse().map_err(|_| bad())?;
    let tls = match uri.scheme_str() {
        Some("http") => false,
        Some("https") => true,
        Some("h2c") => {
            return Err(invalid(
                "address is h2c://: the call is written as HTTP/1.1, which an h2c server cannot answer",
            ));
        }
        _ => return Err(bad()),
    };
    let authority = uri.authority().ok_or_else(bad)?;
    if authority.as_str().contains('@') {
        return Err(invalid("address carries credentials; the call sends none"));
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let named = !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
            return Err(if named {
                Invalid::new(
                    "invalid_middleware",
                    format!(
                        "forward_auth: address {address}: a host name is not supported yet, the DNS resolver is not wired for forward_auth; use an IP address"
                    ),
                )
            } else {
                bad()
            });
        }
    };
    let default_port = if tls { 443 } else { 80 };
    // `Uri` reads a port out of range as no port: look at the text, so it is never dropped.
    let tail = authority
        .as_str()
        .get(authority.host().len()..)
        .unwrap_or_default();
    let port = match tail.strip_prefix(':') {
        None if tail.is_empty() => default_port,
        Some(digits) => digits.parse::<u16>().map_err(|_| bad())?,
        None => return Err(bad()),
    };
    let target = uri.path_and_query().map_or("/", |target| target.as_str());
    if !target.bytes().all(|b| b.is_ascii_graphic() && b != b'#') {
        return Err(invalid("address path is not printable ASCII"));
    }
    let server = Server {
        url: address.into(),
        addr: SocketAddr::new(ip, port),
        tls,
        h2c: false,
        weight: 1,
        state: Arc::default(),
    };
    Ok((server, authority.as_str().into(), target.into()))
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
                format!("forward_auth: transport {name} is not declared by the app"),
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

impl ForwardAuth {
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
            "tenant {tenant} has max_buffer_bytes {max_buffer_bytes}, below the {needed} bytes one auth call reserves (max_response_bytes {} plus {}); lower max_response_bytes or raise the budget",
            self.0.max_response,
            client::ALLOWANCE
        ))
        .with("tenant", tenant)
        .with("needed_bytes", needed)
        .with("max_buffer_bytes", max_buffer_bytes))
    }

    /// The bytes one call charges to the tenant.
    fn charge(&self) -> u64 {
        client::ALLOWANCE.saturating_add(u64::try_from(self.0.max_response).unwrap_or(u64::MAX))
    }

    /// Whether a header of the auth service's answer goes to the upstream, and so is removed from
    /// the client's request first.
    fn copies(&self, name: &HeaderName) -> bool {
        !reserved(name)
            && (self.0.response_headers.contains(name)
                || self
                    .0
                    .response_regex
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(name.as_str())))
    }

    /// Whether a header of the client's request goes to the auth service.
    fn sends(&self, name: &HeaderName) -> bool {
        !reserved(name)
            && self
                .0
                .request_headers
                .as_ref()
                .is_none_or(|allowed| allowed.contains(name))
    }

    /// Removes from `request` every header an answer could set, so none survives from the client.
    fn strip(&self, request: &mut RequestHeader) {
        let doomed: Vec<HeaderName> = request
            .headers
            .keys()
            .filter(|name| self.copies(name))
            .cloned()
            .collect();
        for name in &doomed {
            request.remove_header(name);
        }
    }

    /// The `X-Forwarded-For` of the call: the resolved client, or, when this stage trusts
    /// forwarding headers and the entry point trusts the peer, the whole chain the peer sent and
    /// then the peer itself. `None` for a connection with no IP peer.
    fn forwarded_for(&self, view: &ForwardedView) -> Option<String> {
        if self.0.trust_forward_header && view.trusted {
            let mut hops: Vec<String> = view.chain.iter().map(ToString::to_string).collect();
            if view.peer != UNKNOWN {
                hops.push(view.peer.to_string());
            }
            return (!hops.is_empty()).then(|| hops.join(", "));
        }
        (view.client_ip != UNKNOWN).then(|| view.client_ip.to_string())
    }

    /// The request head of the call, `None` when it would pass [`client::REQUEST_LIMIT`].
    fn build(&self, request: &RequestHeader, view: &ForwardedView) -> Option<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(1024);
        let mut line = |name: &str, value: &[u8]| {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        };
        line("Host", self.0.host.as_bytes());
        line("Connection", b"close");
        line("X-Forwarded-Method", request.method.as_str().as_bytes());
        line("X-Forwarded-Proto", view.proto.as_str().as_bytes());
        let own_host = request
            .uri
            .authority()
            .map(|authority| authority.as_str().as_bytes())
            .or_else(|| request.headers.get("host").map(http::HeaderValue::as_bytes));
        if let Some(host) = view.host.as_deref().map(str::as_bytes).or(own_host) {
            line("X-Forwarded-Host", host);
        }
        let uri = request.uri.path_and_query().map_or("/", |uri| uri.as_str());
        line("X-Forwarded-Uri", uri.as_bytes());
        if let Some(chain) = self.forwarded_for(view) {
            line("X-Forwarded-For", chain.as_bytes());
        }
        for (name, value) in &request.headers {
            if self.sends(name) {
                line(name.as_str(), value.as_bytes());
            }
        }
        let mut head = Vec::with_capacity(out.len() + self.0.target.len() + 16);
        head.extend_from_slice(b"GET ");
        head.extend_from_slice(self.0.target.as_bytes());
        head.extend_from_slice(b" HTTP/1.1\r\n");
        head.extend_from_slice(&out);
        head.extend_from_slice(b"\r\n");
        (head.len() <= client::REQUEST_LIMIT).then_some(head)
    }

    /// Asks the auth service about the request on `cx`.
    async fn ask(&self, cx: &mut RequestCx<'_>) -> Result<client::Answer, AppError> {
        // No budget for the tenant means nothing to charge the call to: closed.
        let tenant = cx.tenant.ok_or(AppError::AuthSaturated)?;
        let _permit = self
            .0
            .runtime
            .permits
            .try_acquire()
            .map_err(|_| AppError::AuthSaturated)?;
        let _charge: BufferGuard = tenant
            .charge(self.charge())
            .ok_or(AppError::AuthSaturated)?;
        let request = self
            .build(cx.session.req_header(), cx.forwarded)
            .ok_or_else(|| {
                tracing::warn!(app = cx.app.id(), "forward_auth request head is too large");
                AppError::AuthUnavailable
            })?;
        let peer = Upstream {
            server: &self.0.server,
            transport: &self.0.transport,
        }
        .peer();
        cx.auth
            .call(
                peer,
                cx.policy,
                cx.app.tenant(),
                &request,
                self.0.max_response,
                self.0.timeout,
            )
            .await
            .map_err(|why| {
                tracing::warn!(app = cx.app.id(), %why, "forward_auth call failed");
                AppError::AuthUnavailable
            })
    }

    /// Writes the auth service's refusal to the client: its status, the headers that are safe to
    /// relay and the capped body.
    async fn relay(cx: &mut RequestCx<'_>, answer: client::Answer) -> pingora::Result<()> {
        let bodyless =
            matches!(answer.status, 204 | 304) || cx.session.req_header().method == Method::HEAD;
        let mut header = ResponseHeader::build(answer.status, Some(answer.headers.len() + 1))?;
        for (name, value) in &answer.headers {
            if relayable(name) {
                header.append_header(name.clone(), value.clone())?;
            }
        }
        if !matches!(answer.status, 204 | 304) {
            header.insert_header("content-length", answer.body.len().to_string())?;
        }
        cx.session
            .write_response_header(Box::new(header), bodyless)
            .await?;
        if bodyless {
            return Ok(());
        }
        cx.session
            .write_response_body(Some(Bytes::from(answer.body)), true)
            .await
    }
}

impl Kind for ForwardAuth {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        let (server, host, target) = parse_address(&config.address)?;
        let transport = transport_of(cx.app, config.transport.as_deref(), server.tls)?;
        let request_headers = match &config.request_headers {
            None => None,
            Some(list) if list.is_empty() => {
                return Err(invalid(
                    "`request_headers` is empty; leave it out to send every header",
                ));
            }
            Some(list) => Some(names(list, "request_headers")?.into_boxed_slice()),
        };
        let response_headers = names(&config.response_headers, "response_headers")?;
        let response_regex = match &config.response_headers_regex {
            None => None,
            Some(pattern) => {
                if pattern.is_empty() || pattern.len() > MAX_REGEX {
                    return Err(invalid(format!(
                        "`response_headers_regex` is 1 to {MAX_REGEX} bytes"
                    )));
                }
                // Header names are lower case in the proxy; the pattern need not be.
                Some(
                    RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .size_limit(REGEX_SIZE_LIMIT)
                        .build()
                        .map_err(|err| invalid(format!("`response_headers_regex`: {err}")))?,
                )
            }
        };
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
            transport,
            transport_name: config.transport.map(Into::into),
            host,
            target,
            trust_forward_header: config.trust_forward_header,
            request_headers,
            response_headers: response_headers.into_boxed_slice(),
            response_regex,
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
        // First, whatever the answer: nothing the client wrote under a name the auth service
        // sets may reach the upstream.
        self.strip(cx.session.req_header_mut());
        match self.ask(cx).await {
            Ok(answer) if (200..300).contains(&answer.status) => {
                let request = cx.session.req_header_mut();
                for (name, value) in &answer.headers {
                    if self.copies(name) {
                        request.append_header(name.clone(), value.clone())?;
                        state.identified = true;
                    }
                }
                Ok(Flow::Continue)
            }
            Ok(answer) => {
                Self::relay(cx, answer).await?;
                Ok(Flow::Respond)
            }
            Err(err) => {
                *cx.capacity_refusal = err.is_capacity_refusal();
                crate::respond::write_error(cx.session, &err).await?;
                Ok(Flow::Respond)
            }
        }
    }

    /// Dropping the middleware stops asking; fewer copied headers can leave an upstream that
    /// trusts them looking at an anonymous request; a transport that stops verifying the auth
    /// service lets anyone on the path answer for it.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let mut kinds = Vec::new();
        let names_kept = self
            .0
            .response_headers
            .iter()
            .all(|name| new.0.response_headers.contains(name));
        let regex_kept = match (&self.0.response_regex, &new.0.response_regex) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(old), Some(new)) => old.as_str() == new.as_str(),
        };
        if !names_kept || !regex_kept {
            kinds.push(kind::RESPONSE_HEADERS_REMOVED);
        }
        if new.0.server.tls
            && new.0.transport.insecure_skip_verify()
            && !(self.0.server.tls && self.0.transport.insecure_skip_verify())
        {
            kinds.push(plan::kind::UPSTREAM_TLS_VERIFICATION_DISABLED);
        }
        kinds
    }

    fn carries_identity(&self, name: &HeaderName) -> bool {
        self.copies(name)
    }

    /// The address without its query string, which may carry a key for the auth service.
    fn describe(&self) -> Value {
        let scheme = if self.0.server.tls { "https" } else { "http" };
        let path = self.0.target.split('?').next().unwrap_or_default();
        json!({
            "address": format!("{scheme}://{}{path}", self.0.host),
            "trust_forward_header": self.0.trust_forward_header,
            "request_headers": self.0.request_headers.as_ref().map(|names| {
                names.iter().map(HeaderName::as_str).collect::<Vec<_>>()
            }),
            "response_headers": self.0.response_headers.iter().map(HeaderName::as_str).collect::<Vec<_>>(),
            "response_headers_regex": self.0.response_regex.as_ref().map(Regex::as_str),
            "timeout_secs": self.0.timeout.as_secs(),
            "transport": self.0.transport_name,
            "max_response_bytes": self.0.max_response,
            "max_concurrent": self.0.max_concurrent,
        })
    }
}

/// The permits of every `forward_auth` middleware of the live table, kept by the shared
/// [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]). A push that
/// leaves a middleware's declaration as it was keeps its permits, so calls that started under
/// the old table return theirs to the count the new one uses.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtime>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            super::Stage::ForwardAuth(auth) => Some((auth.0.fingerprint, &mut auth.0.runtime)),
            _ => None,
        });
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::client_ip::Proto;
    use crate::wasm as engine;

    fn app() -> podgate_model::App {
        serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
            "transports": [{"name": "t", "type": "servers_transport", "server_name": "auth.internal"}],
        }))
        .expect("app")
    }

    fn compile(config: &Value) -> Result<ForwardAuth, Invalid> {
        let mut declared = json!({"name": "sso", "type": "forward_auth"});
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app = app();
        let mut compiler = engine::Compiler::default();
        ForwardAuth::compile(
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

    fn auth(extra: &Value) -> ForwardAuth {
        let mut config = json!({"address": "http://10.0.0.5:9091/verify"});
        if let (Some(object), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
            object.extend(extra.clone());
        }
        compile(&config).expect("compiled")
    }

    fn view() -> ForwardedView {
        ForwardedView {
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            proto: Proto::Https,
            ..ForwardedView::default()
        }
    }

    fn head(auth: &ForwardAuth, request: &RequestHeader, view: &ForwardedView) -> String {
        String::from_utf8(auth.build(request, view).expect("built")).expect("text")
    }

    #[test]
    fn an_address_is_an_absolute_http_url_with_an_ip_host() {
        assert!(compile(&json!({"address": "http://10.0.0.5:9091/verify?k=1"})).is_ok());
        assert!(compile(&json!({"address": "https://[2001:db8::5]/v"})).is_ok());
        assert!(compile(&json!({"address": "http://10.0.0.5"})).is_ok());
        for bad in [
            "/verify",
            "verify",
            "10.0.0.5:9091",
            "ftp://10.0.0.5/",
            "http://",
            "http:///verify",
            "http://user:pw@10.0.0.5/",
            "http://10.0.0.5:99999/",
            "http://10.0 .0.5/",
            "h2c://10.0.0.5/",
            "",
        ] {
            assert_eq!(
                code(&json!({"address": bad})),
                "invalid_middleware",
                "{bad:?}"
            );
        }
        assert_eq!(
            code(&json!({"address": "http://auth.internal:9091/"})),
            "invalid_middleware"
        );
    }

    #[test]
    fn limits_and_unknown_fields_are_refused() {
        let with = |extra: Value| {
            let mut config = json!({"address": "http://10.0.0.5:9091/"});
            config
                .as_object_mut()
                .expect("object")
                .extend(extra.as_object().expect("object").clone());
            config
        };
        assert!(compile(&with(json!({"timeout_secs": 3600, "max_response_bytes": MAX_RESPONSE, "max_concurrent": 4096}))).is_ok());
        for bad in [
            json!({"timeout_secs": 0}),
            json!({"timeout_secs": 3601}),
            json!({"max_response_bytes": 0}),
            json!({"max_response_bytes": MAX_RESPONSE + 1}),
            json!({"max_concurrent": 0}),
            json!({"max_concurrent": 4097}),
            json!({"request_headers": []}),
            json!({"request_headers": ["host"]}),
            json!({"request_headers": ["x-forwarded-for"]}),
            json!({"response_headers": ["connection"]}),
            json!({"response_headers": ["content-length"]}),
            json!({"response_headers": ["proxy-authorization"]}),
            json!({"response_headers": ["not a name"]}),
            json!({"response_headers_regex": "("}),
            json!({"response_headers_regex": ""}),
            json!({"forward_body": true}),
            json!({"nope": 1}),
        ] {
            assert_eq!(code(&with(bad.clone())), "invalid_middleware", "{bad}");
        }
        assert_eq!(
            code(&with(json!({"transport": "missing"}))),
            "unknown_transport"
        );
        assert_eq!(
            code(&with(json!({"transport": "t"}))),
            "invalid_middleware",
            "TLS options on a plain address"
        );
        assert!(compile(&json!({"address": "https://10.0.0.5/", "transport": "t"})).is_ok());
    }

    #[test]
    fn a_call_that_can_never_be_charged_is_refused() {
        let auth = auth(&json!({"max_response_bytes": 1000}));
        let needed = client::ALLOWANCE + 1000;
        assert!(auth.check_budget("t1", needed).is_ok());
        let refused = auth.check_budget("t1", needed - 1).expect_err("refused");
        assert_eq!(refused.code, "invalid_middleware");
    }

    #[test]
    fn the_call_is_built_from_the_connection_and_never_the_client_forwarding_headers() {
        let auth = auth(&json!({}));
        let mut request = RequestHeader::build("POST", b"/a/b?x=1", None).expect("request");
        for (name, value) in [
            ("Host", "app.test"),
            ("Authorization", "Bearer t"),
            ("Cookie", "sid=1"),
            ("X-Forwarded-For", "1.2.3.4"),
            ("X-Forwarded-Host", "evil.test"),
            ("X-Forwarded-Proto", "http"),
            ("X-Forwarded-Uri", "/admin"),
            ("X-Forwarded-Method", "DELETE"),
            ("X-Real-IP", "5.6.7.8"),
            ("Forwarded", "for=9.9.9.9"),
            ("Connection", "keep-alive"),
            ("Content-Length", "5"),
            ("Proxy-Authorization", "Basic x"),
        ] {
            request.append_header(name, value).expect("header");
        }
        let sent = head(&auth, &request, &view());
        assert!(
            sent.starts_with("GET /verify HTTP/1.1\r\nHost: 10.0.0.5:9091\r\n"),
            "{sent}"
        );
        assert!(sent.ends_with("\r\n\r\n"));
        for line in [
            "X-Forwarded-Method: POST",
            "X-Forwarded-Proto: https",
            "X-Forwarded-Host: app.test",
            "X-Forwarded-Uri: /a/b?x=1",
            "X-Forwarded-For: 192.0.2.7",
            "authorization: Bearer t",
            "cookie: sid=1",
        ] {
            assert!(
                sent.contains(&format!("\r\n{line}\r\n")),
                "{line} in {sent}"
            );
        }
        for absent in [
            "evil.test",
            "1.2.3.4",
            "/admin",
            "DELETE",
            "5.6.7.8",
            "9.9.9.9",
            "keep-alive",
        ] {
            assert!(!sent.contains(absent), "{absent} in {sent}");
        }
        for absent in ["content-length", "proxy-authorization"] {
            assert!(
                !sent.to_ascii_lowercase().contains(absent),
                "{absent} in {sent}"
            );
        }
        assert_eq!(sent.matches("X-Forwarded-For").count(), 1);
    }

    #[test]
    fn request_headers_is_an_allow_list() {
        let auth = auth(&json!({"request_headers": ["Authorization"]}));
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request
            .append_header("Authorization", "Bearer t")
            .expect("header");
        request.append_header("Cookie", "sid=1").expect("header");
        let sent = head(&auth, &request, &view());
        assert!(sent.contains("authorization: Bearer t"));
        assert!(!sent.contains("cookie"), "{sent}");
    }

    #[test]
    fn forward_for_trusts_a_chain_only_for_a_trusted_peer() {
        let plain = auth(&json!({}));
        let trusting = auth(&json!({"trust_forward_header": true}));
        let mut trusted = view();
        trusted.trusted = true;
        trusted.client_ip = "203.0.113.9".parse().expect("ip");
        trusted.chain = vec![
            "203.0.113.9".parse().expect("ip"),
            "10.1.1.1".parse().expect("ip"),
        ];
        assert_eq!(
            plain.forwarded_for(&trusted).as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            trusting.forwarded_for(&trusted).as_deref(),
            Some("203.0.113.9, 10.1.1.1, 192.0.2.7")
        );
        // The flag alone never believes a peer the entry point does not trust.
        let mut stranger = view();
        stranger.chain = trusted.chain.clone();
        assert_eq!(
            trusting.forwarded_for(&stranger).as_deref(),
            Some("192.0.2.7")
        );
        let mut none = view();
        none.peer = UNKNOWN;
        none.client_ip = UNKNOWN;
        assert_eq!(trusting.forwarded_for(&none), None);
    }

    #[test]
    fn a_trusted_peers_host_is_what_the_auth_service_sees() {
        let auth = auth(&json!({}));
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request.append_header("Host", "inner.test").expect("header");
        let mut trusted = view();
        trusted.host = Some("public.test".into());
        assert!(head(&auth, &request, &trusted).contains("X-Forwarded-Host: public.test\r\n"));
    }

    #[test]
    fn an_oversized_request_is_not_sent() {
        let auth = auth(&json!({}));
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request
            .append_header("Cookie", "a".repeat(client::REQUEST_LIMIT))
            .expect("header");
        assert!(auth.build(&request, &view()).is_none());
    }

    #[test]
    fn names_and_the_regex_decide_what_is_copied_and_stripped() {
        let auth = auth(&json!({
            "response_headers": ["X-User"],
            "response_headers_regex": "^x-auth-",
        }));
        for copied in ["x-user", "x-auth-groups", "x-auth-"] {
            let name = HeaderName::from_bytes(copied.as_bytes()).expect("name");
            assert!(auth.copies(&name), "{copied}");
        }
        for kept in [
            "cookie",
            "authorization",
            "x-users",
            "host",
            "x-forwarded-for",
            "x-other-x-auth-y",
        ] {
            let name = HeaderName::from_bytes(kept.as_bytes()).expect("name");
            assert!(!auth.copies(&name), "{kept}");
        }
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        for (name, value) in [
            ("X-User", "admin"),
            ("X-Auth-Groups", "root"),
            ("Cookie", "sid=1"),
            ("Host", "app.test"),
        ] {
            request.append_header(name, value).expect("header");
        }
        request.append_header("X-User", "second").expect("header");
        auth.strip(&mut request);
        let mut left: Vec<&str> = request.headers.keys().map(HeaderName::as_str).collect();
        left.sort_unstable();
        assert_eq!(left, ["cookie", "host"]);
    }

    #[test]
    fn a_refusal_relays_only_safe_headers() {
        for safe in [
            "www-authenticate",
            "location",
            "set-cookie",
            "content-type",
            "retry-after",
            "x-reason",
        ] {
            assert!(
                relayable(&HeaderName::from_bytes(safe.as_bytes()).expect("name")),
                "{safe}"
            );
        }
        for unsafe_ in [
            "connection",
            "transfer-encoding",
            "content-length",
            "keep-alive",
            "upgrade",
            "proxy-authenticate",
            "content-encoding",
            "alt-svc",
            "server",
            "date",
            "host",
        ] {
            assert!(
                !relayable(&HeaderName::from_bytes(unsafe_.as_bytes()).expect("name")),
                "{unsafe_}"
            );
        }
    }

    #[test]
    fn posture_lists_removal_and_fewer_copied_headers() {
        let old = auth(&json!({"response_headers": ["x-user", "x-groups"]}));
        assert_eq!(old.posture(None), [kind::REMOVED]);
        let same = auth(&json!({"response_headers": ["x-groups", "x-user"], "timeout_secs": 9}));
        assert!(old.posture(Some(&same)).is_empty());
        let more = auth(&json!({"response_headers": ["x-user", "x-groups", "x-org"]}));
        assert!(old.posture(Some(&more)).is_empty());
        let fewer = auth(&json!({"response_headers": ["x-user"]}));
        assert_eq!(old.posture(Some(&fewer)), [kind::RESPONSE_HEADERS_REMOVED]);
        let regex = auth(&json!({"response_headers_regex": "^x-"}));
        let regex_gone = auth(&json!({}));
        assert_eq!(
            regex.posture(Some(&regex_gone)),
            [kind::RESPONSE_HEADERS_REMOVED]
        );
        let elsewhere = auth(
            &json!({"address": "http://10.0.0.6:1/other", "response_headers": ["x-user", "x-groups"]}),
        );
        assert!(
            old.posture(Some(&elsewhere)).is_empty(),
            "an address change is not a loosening"
        );
    }

    #[test]
    fn describe_hides_the_query_and_the_certificate() {
        let auth =
            auth(&json!({"address": "https://10.0.0.5:9091/verify?key=hunter2", "transport": "t"}));
        let shown = auth.describe().to_string();
        assert!(shown.contains("https://10.0.0.5:9091/verify"), "{shown}");
        assert!(!shown.contains("hunter2"), "{shown}");
    }
}
