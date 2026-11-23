//! The `mcp_gateway` middleware: one MCP endpoint over a registry of MCP servers. Full
//! reference: `docs/ref/mw-mcp-gateway.md`.
//!
//! ```json
//! { "name": "tools", "type": "mcp_gateway",
//!   "servers": [ { "name": "search", "address": "http://10.0.0.5:8080/mcp" },
//!                { "name": "files", "address": "http://10.0.0.6:8080/mcp", "timeout_ms": 5000 } ] }
//! ```
//!
//! A client speaks the Model Context Protocol (streamable HTTP, revisions 2025-11-25 and
//! 2025-06-18, JSON-RPC 2.0) to the router that carries the middleware and sees one server:
//! `tools/list` returns the tools of every registered server under the name
//! `<server>__<tool>` (see `tools.rs`), and `tools/call` goes to the server that owns the tool, with
//! the tool's own name, and the result comes back untouched. The middleware answers the request
//! itself and never contacts the app's own service; stages declared before it (`jwt_auth`,
//! `ip_allow_list`, `rate_limit`) judge the request first.
//!
//! Fail closed. A server that is down, slow, refused by the upstream address policy, over a cap
//! or not speaking MCP is left out of `tools/list` and its calls are `-32603`; a tool nobody owns
//! is `-32602` and nothing leaves podgate. No exchange runs without a permit of the server's
//! `max_concurrent` and a charge to the tenant's buffer budget. Sessions are bounded per tenant
//! (see `sessions.rs`).
//!
//! # Hook points
//!
//! Per-tool authorization and the audit log attach at three places, all in this file:
//! `McpGateway::authorize` (a call is known, before any byte leaves; for `tools/call`),
//! `McpGateway::expose` (the merged list is known, before it is serialized; for `tools/list`),
//! both over `McpGateway::visible`, and the `Outcome` of `McpGateway::invoke` in `tools_call`
//! (a result is known, before it is written).

mod rpc;
mod server;
mod sessions;
mod sse;
mod tools;

pub use sessions::Sessions;

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Method;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use tokio::time::timeout;

use super::{CompileCx, Flow, Kind, RequestCx, forward_auth, state};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::service::Transport;
use crate::service::resolve::Resolver;
use crate::table::CompiledApp;
use podgate_model::Declared;
use rpc::{Answer, Message, Refused};
use server::{Env, Failure, Health, Runtime, Spec};
use sessions::Handle;
use tools::{Listed, Tool, ToolRef};

/// The largest request body of a client.
const REQUEST_CAP: u64 = 1024 * 1024;
/// How long a client may take to send its body.
const BODY_DEADLINE: Duration = Duration::from_secs(30);
/// How long a server's list of tools is trusted by `tools/call`.
const CATALOG_TTL: Duration = Duration::from_secs(60);
/// The most servers in one registry.
const MAX_SERVERS: usize = 16;
/// The longest server name.
const MAX_NAME: usize = 32;
/// The longest `address`.
const MAX_ADDRESS: usize = 512;
/// The most `allowed_origins`.
const MAX_ORIGINS: usize = 16;
/// The longest origin.
const MAX_ORIGIN: usize = 256;
/// The default `timeout_ms`.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// The shortest and longest `timeout_ms`.
const TIMEOUT_MS: std::ops::RangeInclusive<u64> = 100..=600_000;
/// The default `max_concurrent`.
const DEFAULT_MAX_CONCURRENT: u32 = 32;
/// The largest `max_concurrent`.
const MAX_CONCURRENT: u32 = 1024;

/// The configuration of an `mcp_gateway` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The registered servers: 1 to 16, each with a unique name.
    servers: Vec<ServerConfig>,
    /// Origins (`scheme://host[:port]`) that may call the endpoint from a browser besides its own
    /// host. A request with any other `Origin` is `403`.
    #[serde(default)]
    allowed_origins: Vec<String>,
}

/// One registered server.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    /// The name clients see before the tool: 1 to 32 characters of `a-z`, `0-9` and `-`,
    /// starting and ending with a letter or digit.
    name: String,
    /// The server's MCP endpoint: an absolute `http://` or `https://` URL whose host is an IP
    /// address or a name.
    address: String,
    /// The time one exchange with the server may take, 100 to 600000. Default 30000.
    #[serde(default)]
    timeout_ms: Option<u64>,
    /// The most exchanges with the server at once, 1 to 1024. Default 32.
    #[serde(default)]
    max_concurrent: Option<u32>,
}

#[derive(Debug)]
struct Parts {
    servers: Box<[Spec]>,
    runtime: Arc<Runtime>,
    resolver: Resolver,
    transport: Transport,
    origins: Box<[Box<str>]>,
    fingerprint: u64,
    /// A tool the test filter hides, standing in for what per-tool authorization decides.
    #[cfg(test)]
    hidden: Option<(Box<str>, Box<str>)>,
}

/// A compiled `mcp_gateway` middleware.
#[derive(Debug)]
pub struct McpGateway(Box<Parts>);

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("mcp_gateway: {message}"))
}

/// Whether `name` is a usable server name.
fn valid_name(name: &str) -> bool {
    let edge = |byte: Option<&u8>| {
        byte.is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    };
    let bytes = name.as_bytes();
    (1..=MAX_NAME).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && edge(bytes.first())
        && edge(bytes.last())
}

/// An origin as the `Origin` header writes it, lower cased.
fn origin(raw: &str) -> Result<Box<str>, Invalid> {
    let lower = raw.to_ascii_lowercase();
    let host = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));
    let usable = host.is_some_and(|host| {
        !host.is_empty()
            && host.len() <= MAX_ORIGIN
            && host.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
            })
    });
    if usable {
        Ok(lower.into())
    } else {
        Err(invalid(format!(
            "allowed_origins: {raw:?} is not scheme://host[:port] with an http or https scheme"
        )))
    }
}

fn spec(config: ServerConfig, seen: &mut HashSet<String>) -> Result<Spec, Invalid> {
    if !valid_name(&config.name) {
        return Err(invalid(format!(
            "server name {:?} is 1 to {MAX_NAME} characters of a-z, 0-9 and -, starting and ending with a letter or digit",
            config.name
        )));
    }
    if !seen.insert(config.name.clone()) {
        return Err(invalid(format!(
            "server name {} is declared twice",
            config.name
        )));
    }
    let parsed = forward_auth::parse_url(&config.address, "address", MAX_ADDRESS)
        .map_err(|why| invalid(format!("server {}: {why}", config.name)))?;
    let timeout_ms = config.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !TIMEOUT_MS.contains(&timeout_ms) {
        return Err(invalid(format!(
            "server {}: timeout_ms is in {}..={}",
            config.name,
            TIMEOUT_MS.start(),
            TIMEOUT_MS.end()
        )));
    }
    let max_concurrent = config.max_concurrent.unwrap_or(DEFAULT_MAX_CONCURRENT);
    if !(1..=MAX_CONCURRENT).contains(&max_concurrent) {
        return Err(invalid(format!(
            "server {}: max_concurrent is in 1..={MAX_CONCURRENT}",
            config.name
        )));
    }
    Ok(Spec {
        name: config.name.into(),
        parsed,
        timeout: Duration::from_millis(timeout_ms),
        max_concurrent,
    })
}

/// What one `tools/call` reserves at most: the client's body, the request to the server, and the
/// largest result, besides the exchange's own buffers.
fn call_bytes() -> u64 {
    2 * REQUEST_CAP
        + u64::try_from(server::RESULT_CAP).unwrap_or(u64::MAX)
        + forward_auth::ALLOWANCE
}

impl McpGateway {
    /// Gives the stage the resolver the host names of its servers are resolved with.
    pub(crate) fn bind(&mut self, resolver: &Resolver) {
        self.0.resolver = resolver.clone();
    }

    /// Refuses a registry no call could be charged for: the tenant's whole `max_buffer_bytes` is
    /// below what one `tools/call` reserves. A budget that is only full right now is not judged
    /// here; the call is answered `-32000` when its charge is refused.
    ///
    /// # Errors
    ///
    /// `invalid_middleware` naming the tenant, the bytes a call reserves and the budget.
    pub(crate) fn check_budget(&self, tenant: &str, max_buffer_bytes: u64) -> Result<(), Invalid> {
        let needed = call_bytes();
        if max_buffer_bytes >= needed {
            return Ok(());
        }
        Err(invalid(format!(
            "tenant {tenant} has max_buffer_bytes {max_buffer_bytes}, below the {needed} bytes one tools/call reserves (the request body cap, the request to the server and the result cap); raise the budget"
        ))
        .with("tenant", tenant)
        .with("needed_bytes", needed)
        .with("max_buffer_bytes", max_buffer_bytes))
    }

    fn index_of(&self, server: &str) -> Option<(usize, &Spec)> {
        self.0
            .servers
            .iter()
            .enumerate()
            .find(|(_, spec)| &*spec.name == server)
    }
}

/// What a request is, to the hooks that decide about it: who asks, for which app, in which
/// session, and the request head.
#[derive(Debug)]
struct Caller<'a> {
    tenant: &'a str,
    app: &'a str,
    session: &'a str,
    head: &'a RequestHeader,
}

/// Everything the methods of one request need.
struct Call<'a> {
    caller: Caller<'a>,
    env: Env<'a>,
    handle: &'a Handle,
}

/// Why a tool name does not lead to a tool.
#[derive(Debug, PartialEq, Eq)]
enum Unresolved {
    /// No registered server has that prefix. Nothing was dialled.
    UnknownServer,
    /// The server is known and its catalog does not have the tool, or the caller may not see it.
    UnknownTool,
    /// The server's catalog is not known and the server did not give it.
    Unavailable(Box<str>, Failure),
}

/// What a server said to a `tools/call`.
#[derive(Debug)]
enum Outcome {
    /// The `result`, as the server wrote it.
    Result(Box<RawValue>),
    /// A JSON-RPC `error` the server chose to answer with.
    Error(Box<RawValue>),
    /// The exchange failed.
    Failed(Failure),
}

#[derive(Deserialize)]
struct ListParams {
    #[serde(default)]
    cursor: Option<Value>,
}

#[derive(Deserialize)]
struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
}

#[derive(Serialize)]
struct ToolList<'a> {
    tools: Vec<&'a Value>,
}

/// One answer to the client.
#[derive(Debug)]
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    fn accepted() -> Self {
        Self::new(202, Vec::new())
    }

    fn rpc(status: u16, id: Option<&RawValue>, code: i32, message: &str) -> Self {
        Self::new(status, rpc::error(id, code, message, None))
    }

    fn app(err: &AppError) -> Self {
        Self::new(err.status().as_u16(), err.body().to_string().into_bytes())
    }

    fn busy_http() -> Self {
        Self::rpc(503, None, rpc::BUSY, "server busy").with("retry-after", "1")
    }

    fn not_allowed() -> Self {
        Self::new(405, br#"{"error":"method not allowed"}"#.to_vec()).with("allow", "POST, DELETE")
    }
}

/// Writes `reply` to the client.
async fn write(session: &mut Session, reply: Reply) -> pingora::Result<()> {
    let mut head = ResponseHeader::build(reply.status, Some(reply.headers.len() + 3))?;
    head.insert_header("cache-control", "no-store")?;
    for (name, value) in &reply.headers {
        head.insert_header(*name, value.clone())?;
    }
    if !reply.body.is_empty() {
        head.insert_header("content-type", "application/json")?;
    }
    if reply.status != 204 {
        head.insert_header("content-length", reply.body.len().to_string())?;
    }
    let empty = reply.body.is_empty();
    session.write_response_header(Box::new(head), empty).await?;
    if !empty {
        session
            .write_response_body(Some(Bytes::from(reply.body)), true)
            .await?;
    }
    Ok(())
}

/// Reads the request body, at most [`REQUEST_CAP`] bytes, within [`BODY_DEADLINE`].
async fn collect(session: &mut Session) -> pingora::Result<Result<Vec<u8>, Reply>> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = session.read_request_body().await? {
        let total = u64::try_from(body.len() + chunk.len()).unwrap_or(u64::MAX);
        if total > REQUEST_CAP {
            return Ok(Err(Reply::app(&AppError::PayloadTooLarge)));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Ok(body))
}

fn header<'a>(head: &'a RequestHeader, name: &str) -> Option<&'a str> {
    head.headers.get(name)?.to_str().ok()
}

fn declared_length(head: &RequestHeader) -> Option<u64> {
    header(head, "content-length")?.trim().parse().ok()
}

fn is_json(head: &RequestHeader) -> bool {
    header(head, "content-type").is_some_and(|kind| {
        kind.trim_start()
            .to_ascii_lowercase()
            .starts_with("application/json")
    })
}

impl McpGateway {
    /// `403` for a browser origin that is neither the endpoint's own host nor allowed: the
    /// transport's defence against DNS rebinding.
    fn origin_refused(&self, head: &RequestHeader) -> Option<Reply> {
        let value = head.headers.get(http::header::ORIGIN)?;
        let refused = || {
            Some(Reply::rpc(
                403,
                None,
                rpc::INVALID_REQUEST,
                "origin not allowed",
            ))
        };
        let Ok(text) = value.to_str() else {
            return refused();
        };
        let lower = text.to_ascii_lowercase();
        if self.0.origins.iter().any(|allowed| **allowed == *lower) {
            return None;
        }
        let host = head
            .uri
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| header(head, "host"))
            .map(str::to_ascii_lowercase);
        let own = lower
            .strip_prefix("https://")
            .or_else(|| lower.strip_prefix("http://"));
        if own.is_some() && own == host.as_deref() {
            return None;
        }
        refused()
    }

    /// The session the request names, or the reply that refuses it: `400` with none, `404` with
    /// one that is unknown, expired or not this stage's.
    fn session(&self, cx: &RequestCx<'_>, head: &RequestHeader) -> Result<Handle, Reply> {
        let Some(id) = header(head, "mcp-session-id") else {
            return Err(Reply::rpc(
                400,
                None,
                rpc::INVALID_REQUEST,
                "Mcp-Session-Id is required",
            ));
        };
        cx.sessions
            .lookup(
                cx.app.tenant(),
                id,
                cx.app.id(),
                self.0.fingerprint,
                Instant::now(),
            )
            .ok_or_else(|| Reply::rpc(404, None, rpc::INVALID_REQUEST, "unknown session"))
    }

    fn delete(&self, cx: &RequestCx<'_>) -> Reply {
        let Some(id) = header(cx.session.req_header(), "mcp-session-id") else {
            return Reply::rpc(
                400,
                None,
                rpc::INVALID_REQUEST,
                "Mcp-Session-Id is required",
            );
        };
        if cx
            .sessions
            .close(cx.app.tenant(), id, cx.app.id(), self.0.fingerprint)
        {
            Reply::new(204, Vec::new())
        } else {
            Reply::rpc(404, None, rpc::INVALID_REQUEST, "unknown session")
        }
    }

    async fn post(&self, cx: &mut RequestCx<'_>) -> pingora::Result<Reply> {
        let head = cx.session.req_header();
        if !is_json(head) {
            return Ok(Reply::new(
                415,
                br#"{"error":"unsupported media type"}"#.to_vec(),
            ));
        }
        let declared = declared_length(head);
        if declared.is_some_and(|length| length > REQUEST_CAP) {
            return Ok(Reply::app(&AppError::PayloadTooLarge));
        }
        let Some(budget) = cx.tenant else {
            *cx.capacity_refusal = true;
            return Ok(Reply::busy_http());
        };
        let Some(_held) = budget.charge(declared.unwrap_or(REQUEST_CAP)) else {
            *cx.capacity_refusal = true;
            return Ok(Reply::busy_http());
        };
        let body = match timeout(BODY_DEADLINE, collect(cx.session)).await {
            Ok(read) => match read? {
                Ok(body) => body,
                Err(refusal) => return Ok(refusal),
            },
            Err(_) => return Ok(Reply::app(&AppError::RequestTimeout)),
        };
        Ok(self.dispatch(cx, &body).await)
    }

    /// Answers one client message.
    async fn dispatch(&self, cx: &mut RequestCx<'_>, body: &[u8]) -> Reply {
        let message = match rpc::parse(body) {
            Ok(message) => message,
            Err(Refused::Parse) => {
                return Reply::rpc(400, None, rpc::PARSE_ERROR, "parse error");
            }
            Err(Refused::Invalid(why)) => {
                return Reply::rpc(400, None, rpc::INVALID_REQUEST, why);
            }
        };
        let head = cx.session.req_header();
        if let Message::Request {
            id,
            method: "initialize",
            params,
        } = &message
        {
            return self.initialize(cx, id, *params);
        }
        let handle = match self.session(cx, head) {
            Ok(handle) => handle,
            Err(refusal) => return refusal,
        };
        if let Some(version) = header(head, "mcp-protocol-version")
            && !rpc::SUPPORTED.contains(&version)
        {
            return Reply::rpc(
                400,
                None,
                rpc::INVALID_REQUEST,
                "unsupported MCP-Protocol-Version",
            );
        }
        let Message::Request { id, method, params } = message else {
            return Reply::accepted();
        };
        let call = Call {
            caller: Caller {
                tenant: cx.app.tenant(),
                app: cx.app.id(),
                session: &handle.id,
                head,
            },
            env: Env {
                client: cx.auth,
                policy: cx.policy,
                resolver: &self.0.resolver,
                transport: &self.0.transport,
                tenant: cx.app.tenant(),
                budget: cx.tenant,
                runtime: &self.0.runtime,
            },
            handle: &handle,
        };
        match method {
            "ping" => Reply::new(200, rpc::result(id, &json!({}))),
            "tools/list" => self.tools_list(&call, id, params).await,
            "tools/call" => self.tools_call(&call, id, params).await,
            _ => Reply::rpc(200, Some(id), rpc::METHOD_NOT_FOUND, "method not found"),
        }
    }

    fn initialize(&self, cx: &RequestCx<'_>, id: &RawValue, params: Option<&RawValue>) -> Reply {
        let Some(asked) =
            params.and_then(|params| serde_json::from_str::<InitializeParams>(params.get()).ok())
        else {
            return Reply::rpc(
                200,
                Some(id),
                rpc::INVALID_PARAMS,
                "initialize needs params with a protocolVersion",
            );
        };
        let version = rpc::SUPPORTED
            .iter()
            .copied()
            .find(|version| *version == asked.protocol_version)
            .unwrap_or(rpc::LATEST);
        let Some(handle) = cx.sessions.open(
            cx.app.tenant(),
            cx.app.id(),
            self.0.fingerprint,
            Instant::now(),
        ) else {
            return Reply::rpc(
                200,
                Some(id),
                rpc::INTERNAL_ERROR,
                "no session could be created",
            );
        };
        let result = json!({
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "podgate", "version": env!("CARGO_PKG_VERSION")},
        });
        Reply::new(200, rpc::result(id, &result)).with("mcp-session-id", &*handle.id)
    }

    /// The session this gateway session holds with server `index`, opened on first use.
    async fn upstream(
        &self,
        call: &Call<'_>,
        index: usize,
        spec: &Spec,
    ) -> Result<server::Up, Failure> {
        let cell = call.handle.upstreams.cell(&spec.name);
        let mut slot = cell.lock().await;
        if let Some(up) = &*slot {
            return Ok(up.clone());
        }
        let up = server::handshake(&call.env, index, spec).await?;
        *slot = Some(up.clone());
        Ok(up)
    }

    /// Forgets `dead`, the session a server no longer knows, unless another request already
    /// replaced it.
    async fn forget(&self, call: &Call<'_>, spec: &Spec, dead: &server::Up) {
        let cell = call.handle.upstreams.cell(&spec.name);
        let mut slot = cell.lock().await;
        if slot.as_ref() == Some(dead) {
            *slot = None;
        }
    }

    /// Asks server `index` for its tools and keeps the answer as its catalog. A server that
    /// cannot answer has no catalog.
    async fn refresh(&self, call: &Call<'_>, index: usize) -> Result<Arc<[Tool]>, Failure> {
        let spec = self.0.servers.get(index).ok_or(Failure::Busy)?;
        let mut renewed = false;
        let result = loop {
            let up = match self.upstream(call, index, spec).await {
                Ok(up) => up,
                Err(failure) => break Err(failure),
            };
            match Box::pin(server::list(&call.env, index, spec, &up)).await {
                Err(Failure::SessionGone) if !renewed => {
                    renewed = true;
                    self.forget(call, spec, &up).await;
                }
                other => break other,
            }
        };
        match result {
            Ok(catalog) => {
                let tools = Arc::clone(&catalog.tools);
                self.0.runtime.set_catalog(index, Some(catalog));
                Ok(tools)
            }
            Err(Failure::Busy) => Err(Failure::Busy),
            Err(failure) => {
                self.0.runtime.set_catalog(index, None);
                tracing::warn!(
                    app = call.caller.app,
                    server = &*spec.name,
                    reason = failure.code(),
                    detail = %failure,
                    "mcp server left out of the list"
                );
                Err(failure)
            }
        }
    }

    /// The tools of server `index`: its catalog while that is fresh, else a new one.
    async fn catalog(&self, call: &Call<'_>, index: usize) -> Result<Arc<[Tool]>, Failure> {
        match self.0.runtime.fresh(index, CATALOG_TTL) {
            Some(tools) => Ok(tools),
            None => self.refresh(call, index).await,
        }
    }

    async fn tools_list(&self, call: &Call<'_>, id: &RawValue, params: Option<&RawValue>) -> Reply {
        let allowed = match params {
            None => true,
            Some(params) => serde_json::from_str::<ListParams>(params.get())
                .is_ok_and(|asked| asked.cursor.as_ref().is_none_or(Value::is_null)),
        };
        if !allowed {
            return Reply::rpc(
                200,
                Some(id),
                rpc::INVALID_PARAMS,
                "params must be an object and cursors are not supported",
            );
        }
        let fetched = futures_util::future::join_all(
            (0..self.0.servers.len()).map(|index| self.refresh(call, index)),
        )
        .await;
        let catalogs: Vec<(&str, Arc<[Tool]>)> = fetched
            .into_iter()
            .zip(self.0.servers.iter())
            .filter_map(|(fetched, spec)| Some((&*spec.name, fetched.ok()?)))
            .collect();
        let listed = tools::merge(catalogs.iter().map(|(server, tools)| (*server, &**tools)));
        let shown = self.expose(&call.caller, listed);
        let list = ToolList {
            tools: shown.iter().map(|listed| &listed.value).collect(),
        };
        Reply::new(200, rpc::result(id, &list))
    }

    /// Hook point (C): the tools of the merged list that `caller` is shown.
    fn expose(&self, caller: &Caller<'_>, listed: Vec<Listed>) -> Vec<Listed> {
        listed
            .into_iter()
            .filter(|listed| self.visible(caller, &listed.tool))
            .collect()
    }

    /// Hook point (A): whether `caller` may call `tool`. A tool it may not call is answered as a
    /// tool that does not exist, so a name says nothing about what is registered.
    ///
    /// # Errors
    ///
    /// [`Unresolved::UnknownTool`] for a tool the caller may not call.
    fn authorize(
        &self,
        caller: &Caller<'_>,
        tool: &ToolRef,
        _arguments: Option<&RawValue>,
    ) -> Result<(), Unresolved> {
        if self.visible(caller, tool) {
            Ok(())
        } else {
            Err(Unresolved::UnknownTool)
        }
    }

    /// The one rule behind [`Self::expose`] and [`Self::authorize`].
    fn visible(&self, _caller: &Caller<'_>, tool: &ToolRef) -> bool {
        !self.hides(tool)
    }

    #[cfg(test)]
    fn hides(&self, tool: &ToolRef) -> bool {
        self.0
            .hidden
            .as_ref()
            .is_some_and(|(server, name)| **server == *tool.server && **name == *tool.tool)
    }

    #[cfg(not(test))]
    fn hides(&self, _tool: &ToolRef) -> bool {
        false
    }

    /// The tool a client's qualified name leads to, from the registry alone: the prefix must be
    /// a registered server's name and the rest a tool of that server's catalog.
    async fn resolve(&self, call: &Call<'_>, qualified: &str) -> Result<ToolRef, Unresolved> {
        let (prefix, rest) = tools::split(qualified).ok_or(Unresolved::UnknownServer)?;
        let (index, spec) = self.index_of(prefix).ok_or(Unresolved::UnknownServer)?;
        let tools = self
            .catalog(call, index)
            .await
            .map_err(|failure| Unresolved::Unavailable(spec.name.clone(), failure))?;
        let tool = tools
            .iter()
            .find(|tool| &*tool.name == rest)
            .ok_or(Unresolved::UnknownTool)?;
        Ok(ToolRef {
            server: spec.name.clone(),
            tool: tool.name.clone(),
        })
    }

    /// The answer to a name that leads nowhere.
    fn refusal(id: &RawValue, why: &Unresolved) -> Reply {
        match why {
            Unresolved::UnknownServer | Unresolved::UnknownTool => {
                Reply::rpc(200, Some(id), rpc::INVALID_PARAMS, "unknown tool")
            }
            Unresolved::Unavailable(server, failure) => Self::failed(id, server, *failure),
        }
    }

    /// The answer to an exchange that failed.
    fn failed(id: &RawValue, server: &str, failure: Failure) -> Reply {
        if failure == Failure::Busy {
            return Reply::rpc(200, Some(id), rpc::BUSY, "server busy");
        }
        Reply::new(
            200,
            rpc::error(
                Some(id),
                rpc::INTERNAL_ERROR,
                "tool server unavailable",
                Some(json!({"server": server, "reason": failure.code()})),
            ),
        )
    }

    /// Sends `body`, a `tools/call` request, to server `index`.
    async fn invoke(&self, call: &Call<'_>, index: usize, spec: &Spec, body: &str) -> Outcome {
        let mut renewed = false;
        loop {
            let up = match self.upstream(call, index, spec).await {
                Ok(up) => up,
                Err(failure) => return Outcome::Failed(failure),
            };
            match Box::pin(server::call(&call.env, index, spec, &up, body)).await {
                Err(Failure::SessionGone) if !renewed => {
                    renewed = true;
                    self.forget(call, spec, &up).await;
                }
                Ok(Answer::Result(raw)) => return Outcome::Result(raw),
                Ok(Answer::Error(raw)) => return Outcome::Error(raw),
                Err(failure) => return Outcome::Failed(failure),
            }
        }
    }

    async fn tools_call(&self, call: &Call<'_>, id: &RawValue, params: Option<&RawValue>) -> Reply {
        let invalid_params = |why: &str| Reply::rpc(200, Some(id), rpc::INVALID_PARAMS, why);
        let Some(mut params) = params.and_then(|params| {
            serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(params.get()).ok()
        }) else {
            return invalid_params("params must be an object");
        };
        let Some(name) = params
            .get("name")
            .and_then(|name| serde_json::from_str::<String>(name.get()).ok())
        else {
            return invalid_params("params.name must be a string");
        };
        let tool = match self.resolve(call, &name).await {
            Ok(tool) => tool,
            Err(why) => return Self::refusal(id, &why),
        };
        let arguments = params.get("arguments").map(|raw| &**raw);
        if let Err(why) = self.authorize(&call.caller, &tool, arguments) {
            return Self::refusal(id, &why);
        }
        let Some((index, spec)) = self.index_of(&tool.server) else {
            return Self::refusal(id, &Unresolved::UnknownServer);
        };
        let Ok(original) = serde_json::value::to_raw_value(&*tool.tool) else {
            return invalid_params("the tool name cannot be forwarded");
        };
        params.insert("name".into(), original);
        let Ok(params) = serde_json::to_string(&params) else {
            return invalid_params("params cannot be forwarded");
        };
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{params}}}"#,
            rpc::UPSTREAM_ID
        );
        tracing::debug!(
            tenant = call.caller.tenant,
            app = call.caller.app,
            session = call.caller.session,
            path = call.caller.head.uri.path(),
            server = &*tool.server,
            tool = &*tool.tool,
            "mcp tools/call"
        );
        // Hook point (B): the outcome of the call is known here, before it is written.
        match self.invoke(call, index, spec, &body).await {
            Outcome::Result(raw) => Reply::new(200, rpc::passthrough(id, "result", &raw)),
            Outcome::Error(raw) => Reply::new(200, rpc::passthrough(id, "error", &raw)),
            Outcome::Failed(failure) => {
                tracing::warn!(
                    app = call.caller.app,
                    server = &*tool.server,
                    tool = &*tool.tool,
                    reason = failure.code(),
                    detail = %failure,
                    "mcp tools/call failed"
                );
                Self::failed(id, &tool.server, failure)
            }
        }
    }

    async fn serve(&self, cx: &mut RequestCx<'_>) -> pingora::Result<Reply> {
        if let Some(refusal) = self.origin_refused(cx.session.req_header()) {
            return Ok(refusal);
        }
        let method = cx.session.req_header().method.clone();
        if method == Method::POST {
            self.post(cx).await
        } else if method == Method::DELETE {
            Ok(self.delete(cx))
        } else {
            Ok(Reply::not_allowed())
        }
    }
}

impl Kind for McpGateway {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(serde_json::Value::Object(declared.config.clone()))
                .map_err(invalid)?;
        if !(1..=MAX_SERVERS).contains(&config.servers.len()) {
            return Err(invalid(format!(
                "`servers` lists 1 to {MAX_SERVERS} servers"
            )));
        }
        if config.allowed_origins.len() > MAX_ORIGINS {
            return Err(invalid(format!(
                "`allowed_origins` lists at most {MAX_ORIGINS} origins"
            )));
        }
        let mut seen = HashSet::new();
        let servers = config
            .servers
            .into_iter()
            .map(|server| spec(server, &mut seen))
            .collect::<Result<Vec<_>, _>>()?;
        let origins = config
            .allowed_origins
            .iter()
            .map(|raw| origin(raw))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(Box::new(Parts {
            runtime: Arc::new(Runtime::new(&servers)),
            servers: servers.into_boxed_slice(),
            resolver: Resolver::default(),
            transport: Transport::default(),
            origins: origins.into_boxed_slice(),
            fingerprint: state::fingerprint(declared),
            #[cfg(test)]
            hidden: None,
        })))
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let reply = self.serve(cx).await?;
        write(cx.session, reply).await?;
        Ok(Flow::Respond)
    }

    /// The registry as the overview shows it: names, addresses without their query, limits and
    /// the last observed health. No query string, and nothing else of the declaration.
    fn describe(&self) -> Value {
        let servers: Vec<Value> = self
            .0
            .servers
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                let scheme = if spec.parsed.server.tls {
                    "https"
                } else {
                    "http"
                };
                let path = spec.parsed.target.split('?').next().unwrap_or_default();
                let (health, catalog) = self.0.runtime.view(index);
                let mut view = json!({
                    "name": spec.name,
                    "address": format!("{scheme}://{}{path}", spec.parsed.host),
                    "timeout_ms": u64::try_from(spec.timeout.as_millis()).unwrap_or(u64::MAX),
                    "max_concurrent": spec.max_concurrent,
                    "health": match health {
                        Health::Unknown => "unknown",
                        Health::Healthy => "healthy",
                        Health::Down(_) => "down",
                    },
                });
                if let (Health::Down(reason), Some(object)) = (health, view.as_object_mut()) {
                    object.insert("reason".into(), json!(reason));
                }
                if let (Some((tools, skipped)), Some(object)) = (catalog, view.as_object_mut()) {
                    object.insert("tools".into(), json!(tools));
                    if skipped > 0 {
                        object.insert("skipped_tools".into(), json!(skipped));
                    }
                }
                view
            })
            .collect();
        json!({"servers": servers, "allowed_origins": self.0.origins})
    }
}

/// The state of every `mcp_gateway` of the live table (health, catalogs, permits), kept by the
/// shared [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]). A
/// push that leaves a middleware's declaration as it was keeps what its servers showed.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtime>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            super::Stage::McpGateway(gateway) => {
                Some((gateway.0.fingerprint, &mut gateway.0.runtime))
            }
            _ => None,
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::upstream_policy::UpstreamPolicy;
    use crate::wasm as engine;

    fn app() -> podgate_model::App {
        serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
        }))
        .expect("app")
    }

    fn compile(config: &Value) -> Result<McpGateway, Invalid> {
        let mut declared = json!({"name": "tools", "type": "mcp_gateway"});
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app = app();
        let mut compiler = engine::Compiler::default();
        McpGateway::compile(
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

    fn two() -> Value {
        json!({"servers": [
            {"name": "alpha", "address": "http://10.0.0.5:8080/mcp"},
            {"name": "beta", "address": "https://10.0.0.6/mcp?key=k", "timeout_ms": 500, "max_concurrent": 2},
        ]})
    }

    #[test]
    fn mcp_config_accepts_a_registry() {
        let gateway = compile(&two()).expect("compiled");
        let shown = gateway.describe();
        assert_eq!(shown["servers"][0]["name"], "alpha");
        assert_eq!(shown["servers"][0]["address"], "http://10.0.0.5:8080/mcp");
        assert_eq!(shown["servers"][0]["timeout_ms"], 30_000);
        assert_eq!(shown["servers"][0]["max_concurrent"], 32);
        assert_eq!(shown["servers"][0]["health"], "unknown");
        // The query of an address may carry a key: it is never shown.
        assert_eq!(shown["servers"][1]["address"], "https://10.0.0.6/mcp");
        assert!(!shown.to_string().contains("key=k"));
    }

    #[test]
    fn mcp_config_refuses_a_bad_registry() {
        let address = "http://10.0.0.5/mcp";
        for bad in [
            json!({}),
            json!({"servers": []}),
            json!({"servers": [{"name": "a", "address": address}], "extra": 1}),
            json!({"servers": [{"name": "a", "address": address, "extra": 1}]}),
            json!({"servers": [{"name": "A", "address": address}]}),
            json!({"servers": [{"name": "a_b", "address": address}]}),
            json!({"servers": [{"name": "-a", "address": address}]}),
            json!({"servers": [{"name": "a-", "address": address}]}),
            json!({"servers": [{"name": "", "address": address}]}),
            json!({"servers": [{"name": "a".repeat(33), "address": address}]}),
            json!({"servers": [{"name": "a", "address": address}, {"name": "a", "address": address}]}),
            json!({"servers": [{"name": "a", "address": "ftp://10.0.0.5/"}]}),
            json!({"servers": [{"name": "a", "address": "/mcp"}]}),
            json!({"servers": [{"name": "a", "address": "http://user:pw@10.0.0.5/"}]}),
            json!({"servers": [{"name": "a", "address": "h2c://10.0.0.5/"}]}),
            json!({"servers": [{"name": "a", "address": address, "timeout_ms": 99}]}),
            json!({"servers": [{"name": "a", "address": address, "timeout_ms": 600_001}]}),
            json!({"servers": [{"name": "a", "address": address, "max_concurrent": 0}]}),
            json!({"servers": [{"name": "a", "address": address, "max_concurrent": 1025}]}),
            json!({"servers": [{"name": "a", "address": address}], "allowed_origins": ["example.com"]}),
            json!({"servers": [{"name": "a", "address": address}], "allowed_origins": ["https://a.test/path"]}),
            json!({"servers": [{"name": "a", "address": address}], "allowed_origins": ["ftp://a.test"]}),
        ] {
            assert_eq!(code(&bad), "invalid_middleware", "{bad}");
        }
        let many: Vec<Value> = (0..=MAX_SERVERS)
            .map(|index| json!({"name": format!("s{index}"), "address": "http://10.0.0.5/mcp"}))
            .collect();
        assert_eq!(code(&json!({"servers": many})), "invalid_middleware");
        let origins: Vec<String> = (0..=MAX_ORIGINS)
            .map(|n| format!("https://a{n}.test"))
            .collect();
        assert_eq!(
            code(
                &json!({"servers": [{"name": "a", "address": "http://10.0.0.5/mcp"}], "allowed_origins": origins})
            ),
            "invalid_middleware"
        );
    }

    #[test]
    fn mcp_config_origins_are_lower_cased() {
        let gateway = compile(&json!({
            "servers": [{"name": "a", "address": "http://10.0.0.5/mcp"}],
            "allowed_origins": ["HTTPS://App.Example.com:8443"],
        }))
        .expect("compiled");
        assert_eq!(&*gateway.0.origins[0], "https://app.example.com:8443");
    }

    #[test]
    fn mcp_config_a_budget_below_one_call_is_refused() {
        let gateway = compile(&two()).expect("compiled");
        let needed = call_bytes();
        assert!(gateway.check_budget("t1", needed).is_ok());
        let refused = gateway.check_budget("t1", needed - 1).expect_err("refused");
        assert_eq!(refused.code, "invalid_middleware");
    }

    fn head(origin: Option<&str>, host: &str) -> RequestHeader {
        let mut head = RequestHeader::build("POST", b"/mcp", None).expect("head");
        head.insert_header("host", host).expect("host");
        if let Some(origin) = origin {
            head.insert_header("origin", origin).expect("origin");
        }
        head
    }

    #[test]
    fn mcp_origin_rule() {
        let gateway = compile(&json!({
            "servers": [{"name": "a", "address": "http://10.0.0.5/mcp"}],
            "allowed_origins": ["https://app.example.com"],
        }))
        .expect("compiled");
        let allowed = |origin: Option<&str>| {
            gateway
                .origin_refused(&head(origin, "gw.example.com"))
                .is_none()
        };
        assert!(allowed(None));
        assert!(allowed(Some("https://gw.example.com")));
        assert!(allowed(Some("http://GW.example.com")));
        assert!(allowed(Some("https://app.example.com")));
        assert!(!allowed(Some("https://evil.test")));
        assert!(!allowed(Some("null")));
        assert!(!allowed(Some("https://gw.example.com.evil.test")));
        assert!(!allowed(Some("https://app.example.com:444")));
    }

    #[tokio::test]
    async fn mcp_hidden_tool_is_unlisted_and_unknown_to_call() {
        let mut gateway = compile(&two()).expect("compiled");
        let now = Instant::now();
        let tool = |name: &str| json!({"name": name, "inputSchema": {"type": "object"}});
        gateway.0.runtime.set_catalog(
            0,
            Some(tools::catalog(
                "alpha",
                vec![tool("search"), tool("read")],
                now,
            )),
        );
        gateway
            .0
            .runtime
            .set_catalog(1, Some(tools::catalog("beta", vec![tool("search")], now)));
        gateway.0.hidden = Some(("beta".into(), "search".into()));

        let sessions = Sessions::new();
        let handle = sessions
            .open("t1", "a", gateway.0.fingerprint, now)
            .expect("a session");
        let client = forward_auth::Client::new(Duration::from_secs(1));
        let policy = UpstreamPolicy::builtin();
        let request = head(None, "gw.example.com");
        let call = Call {
            caller: Caller {
                tenant: "t1",
                app: "a",
                session: &handle.id,
                head: &request,
            },
            env: Env {
                client: &client,
                policy: &policy,
                resolver: &gateway.0.resolver,
                transport: &gateway.0.transport,
                tenant: "t1",
                budget: None,
                runtime: &gateway.0.runtime,
            },
            handle: &handle,
        };

        // The list drops exactly the hidden tool.
        let alpha = gateway.0.runtime.fresh(0, CATALOG_TTL).expect("fresh");
        let beta = gateway.0.runtime.fresh(1, CATALOG_TTL).expect("fresh");
        let listed = tools::merge([("alpha", &*alpha), ("beta", &*beta)].into_iter());
        assert_eq!(listed.len(), 3);
        let shown = gateway.expose(&call.caller, listed);
        let names: Vec<&str> = shown
            .iter()
            .filter_map(|tool| tool.value["name"].as_str())
            .collect();
        assert_eq!(names, ["alpha__search", "alpha__read"]);

        // The call of the hidden tool is answered as a tool nobody owns.
        let id = serde_json::from_str::<Box<RawValue>>("7").expect("id");
        let hidden = gateway
            .resolve(&call, "beta__search")
            .await
            .expect("resolved");
        let denied = gateway
            .authorize(&call.caller, &hidden, None)
            .expect_err("hidden");
        let missing_tool = gateway
            .resolve(&call, "beta__nothing")
            .await
            .expect_err("no such tool");
        let missing_server = gateway
            .resolve(&call, "gamma__search")
            .await
            .expect_err("no such server");
        let unprefixed = gateway
            .resolve(&call, "search")
            .await
            .expect_err("no prefix");
        let body = |why: &Unresolved| McpGateway::refusal(&id, why).body;
        assert_eq!(denied, Unresolved::UnknownTool);
        assert_eq!(body(&denied), body(&missing_tool));
        assert_eq!(body(&denied), body(&missing_server));
        assert_eq!(body(&denied), body(&unprefixed));

        // Every other tool stays callable.
        for name in ["alpha__search", "alpha__read"] {
            let tool = gateway.resolve(&call, name).await.expect("resolved");
            assert!(
                gateway.authorize(&call.caller, &tool, None).is_ok(),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_resolve_takes_the_server_from_the_registry_alone() {
        let gateway = compile(&two()).expect("compiled");
        let now = Instant::now();
        let tool = |name: &str| json!({"name": name});
        gateway.0.runtime.set_catalog(
            0,
            Some(tools::catalog(
                "alpha",
                vec![tool("search"), tool("a__b")],
                now,
            )),
        );
        gateway
            .0
            .runtime
            .set_catalog(1, Some(tools::catalog("beta", vec![tool("search")], now)));
        let sessions = Sessions::new();
        let handle = sessions
            .open("t1", "a", gateway.0.fingerprint, now)
            .expect("a session");
        let client = forward_auth::Client::new(Duration::from_secs(1));
        let policy = UpstreamPolicy::builtin();
        let request = head(None, "gw.example.com");
        let call = Call {
            caller: Caller {
                tenant: "t1",
                app: "a",
                session: &handle.id,
                head: &request,
            },
            env: Env {
                client: &client,
                policy: &policy,
                resolver: &gateway.0.resolver,
                transport: &gateway.0.transport,
                tenant: "t1",
                budget: None,
                runtime: &gateway.0.runtime,
            },
            handle: &handle,
        };
        let pair = |tool: ToolRef| (tool.server.to_string(), tool.tool.to_string());
        assert_eq!(
            gateway.resolve(&call, "alpha__search").await.map(pair),
            Ok(("alpha".into(), "search".into()))
        );
        assert_eq!(
            gateway.resolve(&call, "beta__search").await.map(pair),
            Ok(("beta".into(), "search".into()))
        );
        // The first separator ends the server; a tool name may hold more of them.
        assert_eq!(
            gateway.resolve(&call, "alpha__a__b").await.map(pair),
            Ok(("alpha".into(), "a__b".into()))
        );
        // A prefix is the whole server name: not a longer, a shorter or a differently cased one.
        for name in [
            "al__search",
            "alpha1__search",
            "Alpha__search",
            "__search",
            "alpha__",
        ] {
            assert!(gateway.resolve(&call, name).await.is_err(), "{name}");
        }
        // A tool of one server is not a tool of the other.
        assert_eq!(
            gateway.resolve(&call, "beta__a__b").await.err(),
            Some(Unresolved::UnknownTool)
        );
    }
}
