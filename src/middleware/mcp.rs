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

mod access;
mod rpc;
mod server;
mod sessions;
mod sse;
mod tools;

pub use sessions::Sessions;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
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
use crate::budget::{Escaped, TenantBudget};
use crate::compile::{Invalid, Rejected};
use crate::error::AppError;
use crate::mcp_audit::{self, ArgumentsState, Audit, Record};
use crate::service::Transport;
use crate::service::resolve::Resolver;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::table::{CompiledApp, RoutingTable};
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
    /// Which tools a caller may see and call, by the claims of the token a `jwt_auth` stage
    /// earlier in the chain verified. Absent: every tool of every healthy server is open. Present,
    /// even as `[]`: a tool is open only when some rule lists it and the caller's claims hold.
    #[serde(default)]
    tool_access: Option<Vec<access::RuleConfig>>,
    /// Keep the `arguments` of every `tools/call` in the audit log (`docs/ref/mcp-audit.md`), at
    /// most 16 KiB, with the value under any key that looks secret replaced by `[redacted]`.
    /// Default `false`: arguments are not recorded.
    #[serde(default)]
    record_arguments: bool,
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
    /// `None`: no per-tool authorization.
    access: Option<access::Access>,
    /// The name the middleware was declared under: what an audit record finds its gateway by.
    name: Box<str>,
    /// Whether the audit log keeps the arguments of a call, secrets redacted.
    record_arguments: bool,
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
/// session, and the request head. `claims` are those of the token a `jwt_auth` stage verified
/// (`RequestCx::claims`), never a header: the one input of per-tool authorization.
#[derive(Debug)]
struct Caller<'a> {
    tenant: &'a str,
    app: &'a str,
    session: &'a str,
    head: &'a RequestHeader,
    claims: Option<&'a serde_json::Map<String, Value>>,
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
    /// The server is known and its catalog does not have the tool.
    UnknownTool,
    /// The rules of `tool_access` refuse the caller the tool, or every tool of its server. It is
    /// answered exactly as a name that leads nowhere ([`McpGateway::refusal`]); the variant only
    /// lets the code that counts and logs tell them apart.
    Denied,
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
                claims: cx.claims.as_ref(),
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
        let trail = Trail {
            audit: cx.audit,
            router: cx.router,
        };
        match method {
            "ping" => Reply::new(200, rpc::result(id, &json!({}))),
            "tools/list" => self.tools_list(&call, id, params).await,
            "tools/call" => Box::pin(self.tools_call(&call, &trail, id, params)).await,
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
        let reachable: Vec<(usize, &Spec)> = self
            .0
            .servers
            .iter()
            .enumerate()
            .filter(|(_, spec)| self.reaches(&call.caller, &spec.name))
            .collect();
        let fetched = futures_util::future::join_all(
            reachable
                .iter()
                .map(|(index, _)| self.refresh(call, *index)),
        )
        .await;
        let catalogs: Vec<(&str, Arc<[Tool]>)> = fetched
            .into_iter()
            .zip(reachable)
            .filter_map(|(fetched, (_, spec))| Some((&*spec.name, fetched.ok()?)))
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
    /// [`Unresolved::Denied`] for a tool the caller may not call.
    fn authorize(
        &self,
        caller: &Caller<'_>,
        tool: &ToolRef,
        _arguments: Option<&RawValue>,
    ) -> Result<(), Unresolved> {
        if self.visible(caller, tool) {
            Ok(())
        } else {
            self.denied(caller, &tools::qualify(&tool.server, &tool.tool));
            Err(Unresolved::Denied)
        }
    }

    /// The one rule behind [`Self::expose`] and [`Self::authorize`]: with `tool_access`, the
    /// caller's verified claims must hold for a rule that lists the (server, tool) pair.
    fn visible(&self, caller: &Caller<'_>, tool: &ToolRef) -> bool {
        self.0
            .access
            .as_ref()
            .is_none_or(|access| access.allows(caller.claims, &tool.server, &tool.tool))
    }

    /// Whether `caller` may use some tool of `server`. A server it may use none of is, to it, a
    /// server nobody registered: nothing is dialled for it.
    fn reaches(&self, caller: &Caller<'_>, server: &str) -> bool {
        self.0
            .access
            .as_ref()
            .is_none_or(|access| access.reaches(caller.claims, server))
    }

    /// Whether a call of `tool` may be sent again by someone other than the caller who made it
    /// (a replay, an audit): with `tool_access`, only when some rule lists it, whatever the
    /// claims it asks for.
    fn replayable(&self, tool: &ToolRef) -> bool {
        self.0
            .access
            .as_ref()
            .is_none_or(|access| access.lists(&tool.server, &tool.tool))
    }

    /// Counts and logs a call the rules refused.
    fn denied(&self, caller: &Caller<'_>, name: &str) {
        self.0.runtime.count_denied();
        let sub = caller
            .claims
            .and_then(|claims| claims.get("sub"))
            .and_then(Value::as_str)
            .map(cut);
        tracing::info!(
            tenant = caller.tenant,
            app = caller.app,
            tool = ?cut(name),
            sub = ?sub,
            "mcp tool access denied"
        );
    }

    /// The tool a client's qualified name leads to, from the registry alone: the prefix must be
    /// a registered server's name the caller may use, and the rest a tool of that server's
    /// catalog.
    async fn resolve(&self, call: &Call<'_>, qualified: &str) -> Result<ToolRef, Unresolved> {
        let (prefix, rest) = tools::split(qualified).ok_or(Unresolved::UnknownServer)?;
        let (index, spec) = self.index_of(prefix).ok_or(Unresolved::UnknownServer)?;
        if !self.reaches(&call.caller, &spec.name) {
            self.denied(&call.caller, qualified);
            return Err(Unresolved::Denied);
        }
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

    /// The answer to a name that leads nowhere. A refusal by the rules is the same bytes as a
    /// name nobody registered.
    fn refusal(id: &RawValue, why: &Unresolved) -> Reply {
        match why {
            Unresolved::UnknownServer | Unresolved::UnknownTool | Unresolved::Denied => {
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

    /// Answers a `tools/call` and leaves one audit record of it, whatever way it ends.
    async fn tools_call(
        &self,
        call: &Call<'_>,
        trail: &Trail<'_>,
        id: &RawValue,
        params: Option<&RawValue>,
    ) -> Reply {
        let started = Instant::now();
        let mut record = Record::new(
            call.caller.tenant,
            call.caller.app,
            trail.router,
            &self.0.name,
            "",
        );
        record.request_bytes = params.map_or(0, |params| len(params.get()));
        if let Some(sub) = call
            .caller
            .claims
            .and_then(|claims| claims.get("sub"))
            .and_then(Value::as_str)
        {
            record.set_sub(sub);
        }
        record.set_session(call.caller.session);
        let reply = self.answer(call, id, params, &mut record).await;
        record.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        drop(trail.audit.record(record));
        reply
    }

    /// The answer to a `tools/call`; `record` is told what happened as it goes. It starts as a
    /// call with bad params, so a path that leaves early needs to say nothing.
    async fn answer(
        &self,
        call: &Call<'_>,
        id: &RawValue,
        params: Option<&RawValue>,
        record: &mut Record,
    ) -> Reply {
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
        record.set_name(&name);
        let arguments = params.get("arguments").map(|raw| &**raw);
        record.set_arguments(mcp_audit::arguments(arguments, self.0.record_arguments));
        let tool = match self.resolve(call, &name).await {
            Ok(tool) => tool,
            Err(why) => {
                refused(record, &why);
                return Self::refusal(id, &why);
            }
        };
        record.server = Some(tool.server.clone());
        record.tool = Some(tool.tool.clone());
        if let Err(why) = self.authorize(&call.caller, &tool, arguments) {
            refused(record, &why);
            return Self::refusal(id, &why);
        }
        let Some((index, spec)) = self.index_of(&tool.server) else {
            refused(record, &Unresolved::UnknownServer);
            return Self::refusal(id, &Unresolved::UnknownServer);
        };
        let Ok(original) = serde_json::value::to_raw_value(&*tool.tool) else {
            return invalid_params("the tool name cannot be forwarded");
        };
        params.insert("name".into(), original);
        let Ok(params) = serde_json::to_string(&params) else {
            return invalid_params("params cannot be forwarded");
        };
        let body = call_body(&params);
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
        let outcome = self.invoke(call, index, spec, &body).await;
        settle(record, &outcome);
        match outcome {
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
        let access = config
            .tool_access
            .map(|rules| {
                let names: Vec<&str> = servers.iter().map(|spec| &*spec.name).collect();
                access::Access::compile(rules, &names)
            })
            .transpose()
            .map_err(invalid)?;
        Ok(Self(Box::new(Parts {
            runtime: Arc::new(Runtime::new(&servers)),
            servers: servers.into_boxed_slice(),
            resolver: Resolver::default(),
            transport: Transport::default(),
            origins: origins.into_boxed_slice(),
            fingerprint: state::fingerprint(declared),
            access,
            name: declared.name.clone(),
            record_arguments: config.record_arguments,
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
        json!({
            "servers": servers,
            "allowed_origins": self.0.origins,
            "tool_access": self.0.access.as_ref().map(access::Access::describe),
            "record_arguments": self.0.record_arguments,
        })
    }

    /// A `tool_access` that opens more than the one it replaces, and one that is gone.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        match (&self.0.access, new.map(|new| &new.0.access)) {
            (Some(_), Some(None)) => vec![access::REMOVED],
            (Some(old), Some(Some(new))) if new.widens(old) => vec![access::WIDENED],
            _ => Vec::new(),
        }
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

/// The longest name or subject a denial logs.
const LOGGED: usize = 128;

/// `text` cut to at most [`LOGGED`] bytes at a character boundary.
fn cut(text: &str) -> &str {
    let mut end = text.len().min(LOGGED);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}

impl McpGateway {
    /// Whether the middleware has `tool_access`, and so needs an identity before it.
    fn has_tool_access(&self) -> bool {
        self.0.access.is_some()
    }
}

/// Refuses a router whose chain runs a gateway with `tool_access` and no `jwt_auth` before it:
/// the claims the rules read are the ones a `jwt_auth` stage verified, so without one every
/// tool would be denied, or worse, someone would later add a way to fill them. `chains` are the
/// routers of `app` with their effective chains (indices into `stages`).
pub(crate) fn check_identity(
    app: &podgate_model::App,
    stages: &[super::Named],
    chains: &[(&str, Vec<usize>)],
) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    for (router, chain) in chains {
        for (position, &index) in chain.iter().enumerate() {
            let Some(super::Named {
                name,
                stage: super::Stage::McpGateway(gateway),
            }) = stages.get(index)
            else {
                continue;
            };
            if !gateway.has_tool_access() {
                continue;
            }
            let verified = chain.get(..position).is_some_and(|before| {
                before.iter().any(|earlier| {
                    matches!(
                        stages.get(*earlier),
                        Some(super::Named {
                            stage: super::Stage::JwtAuth(_),
                            ..
                        })
                    )
                })
            });
            if !verified {
                rejected.push(Rejected::new(
                    app,
                    format!("router {router}"),
                    invalid(format!(
                        "middleware {name}: tool_access_requires_identity: `tool_access` reads the claims of a verified token and needs a `jwt_auth` earlier in the chain of router {router}"
                    ))
                    .with("reason", "tool_access_requires_identity"),
                ));
            }
        }
    }
    rejected
}

/// The Prometheus exposition of the gateways of `live` that have `tool_access`:
/// `podgate_mcp_denied_total{tenant,app}`, the calls the rules refused, summed over the
/// gateways of an app. Each tenant gets `per_tenant` apps of its own; the rest of its apps
/// are summed into `app="other"`.
pub(crate) fn render(out: &mut String, live: &RoutingTable, per_tenant: usize) {
    let mut rows: Vec<(&str, &str, u64)> = Vec::new();
    for app in live.apps() {
        let mut seen = false;
        let mut count = 0_u64;
        for named in app.stages() {
            if let super::Stage::McpGateway(gateway) = &named.stage
                && gateway.has_tool_access()
            {
                seen = true;
                count = count.saturating_add(gateway.0.runtime.denied());
            }
        }
        if seen {
            rows.push((app.tenant(), app.id(), count));
        }
    }
    if rows.is_empty() {
        return;
    }
    let mut own: HashMap<&str, usize> = HashMap::new();
    let mut other: Vec<(&str, u64)> = Vec::new();
    let _ = writeln!(
        out,
        "# HELP podgate_mcp_denied_total Calls of an mcp_gateway that its tool_access refused.\n# TYPE podgate_mcp_denied_total counter"
    );
    for (tenant, app, count) in rows {
        let taken = own.entry(tenant).or_default();
        if *taken < per_tenant {
            *taken += 1;
            let _ = writeln!(
                out,
                "podgate_mcp_denied_total{{tenant=\"{}\",app=\"{}\"}} {count}",
                Escaped(tenant),
                Escaped(app)
            );
        } else if let Some((_, sum)) = other.iter_mut().find(|(name, _)| *name == tenant) {
            *sum = sum.saturating_add(count);
        } else {
            other.push((tenant, count));
        }
    }
    for (tenant, count) in other {
        let _ = writeln!(
            out,
            "podgate_mcp_denied_total{{tenant=\"{}\",app=\"other\"}} {count}",
            Escaped(tenant)
        );
    }
}

/// Where a `tools/call` is audited: the log and the router that carried the request.
struct Trail<'a> {
    audit: &'a Audit,
    router: &'a str,
}

fn len(text: &str) -> u64 {
    u64::try_from(text.len()).unwrap_or(u64::MAX)
}

/// The `tools/call` request a server is sent, with `params` as its params.
fn call_body(params: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{params}}}"#,
        rpc::UPSTREAM_ID
    )
}

/// Notes in `record` that the name did not lead to a tool the call could be sent to.
fn refused(record: &mut Record, why: &Unresolved) {
    match why {
        Unresolved::UnknownServer | Unresolved::UnknownTool => {
            record.outcome = mcp_audit::Outcome::RpcError;
            record.reason = Some("unknown_tool");
        }
        Unresolved::Denied => {
            record.outcome = mcp_audit::Outcome::Denied;
            record.reason = None;
        }
        Unresolved::Unavailable(server, failure) => {
            record.outcome = mcp_audit::Outcome::UpstreamFailed;
            record.reason = Some(failure.code());
            record.server = Some(server.clone());
        }
    }
}

/// Whether a result says `isError: true`. The result is only scanned, never kept.
fn is_tool_error(raw: &RawValue) -> bool {
    #[derive(Deserialize)]
    struct Flag {
        #[serde(rename = "isError", default)]
        is_error: bool,
    }
    raw.get().contains("isError")
        && serde_json::from_str::<Flag>(raw.get()).is_ok_and(|flag| flag.is_error)
}

/// The JSON-RPC `code` of an error a server answered.
fn error_code(raw: &RawValue) -> Option<i64> {
    #[derive(Deserialize)]
    struct Code {
        code: i64,
    }
    serde_json::from_str::<Code>(raw.get())
        .ok()
        .map(|code| code.code)
}

/// Notes in `record` what the server said.
fn settle(record: &mut Record, outcome: &Outcome) {
    match outcome {
        Outcome::Result(raw) => {
            record.response_bytes = len(raw.get());
            record.outcome = if is_tool_error(raw) {
                mcp_audit::Outcome::ToolError
            } else {
                mcp_audit::Outcome::Ok
            };
            record.reason = None;
        }
        Outcome::Error(raw) => {
            record.response_bytes = len(raw.get());
            record.outcome = mcp_audit::Outcome::RpcError;
            record.reason = Some("server");
            record.rpc_code = error_code(raw);
        }
        Outcome::Failed(failure) => {
            record.outcome = mcp_audit::Outcome::UpstreamFailed;
            record.reason = Some(failure.code());
        }
    }
}

/// What an operator's replay of a recorded call needs from the admin side.
pub struct Replay<'a> {
    /// The app of the live table the record belongs to.
    pub app: &'a CompiledApp,
    /// Dials the server.
    pub client: &'a forward_auth::Client,
    /// The operator's upstream address policy.
    pub policy: &'a UpstreamPolicy,
    /// The tenant's budget; without one nothing is sent.
    pub budget: Option<&'a Arc<TenantBudget>>,
    /// Where the replay is audited.
    pub audit: &'a Audit,
    /// The call to send again.
    pub record: &'a Record,
    /// `force=true`: send a tool its server does not mark `readOnlyHint`.
    pub force: bool,
}

/// Why a replay was refused before anything was sent.
#[derive(Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// The call never reached a server (denied, or the name did not resolve).
    NotReplayable,
    /// The arguments are not kept whole: redacted, not recorded or too large.
    RedactedArguments(ArgumentsState),
    /// The app no longer has the `mcp_gateway` the call went through.
    GatewayGone,
    /// The server is no longer in the registry.
    ServerGone,
    /// The server no longer lists the tool.
    ToolGone,
    /// Authorization says nobody may call the tool: `tool_access` has no rule that lists it.
    NotPermitted,
    /// The tool is not marked `readOnlyHint` and `force` is not set.
    NeedsForce,
    /// The tenant has no in-flight slot or budget left.
    Busy,
    /// A request head could not be built.
    Internal,
}

/// What a replay got from the server.
#[derive(Debug)]
pub enum ReplayAnswer {
    /// The server's `result`, as it came.
    Result(Box<RawValue>),
    /// The server's JSON-RPC `error`, as it came.
    Error(Box<RawValue>),
    /// The exchange failed with this code (`busy`, `policy`, `connect`, `timeout`, `status`,
    /// `malformed`, `too_large`, `version` or `session`).
    Failed(&'static str),
}

/// A replay that was sent and audited.
#[derive(Debug)]
pub struct Replayed {
    /// The `seq` of the record of the replay.
    pub audit_seq: u64,
    /// How it ended.
    pub outcome: mcp_audit::Outcome,
    /// Why, as in the record.
    pub reason: Option<&'static str>,
    /// What the server said.
    pub answer: ReplayAnswer,
}

/// Sends the call of `replay.record` again to the server it went to, through the gateway of the
/// live app that carried it, and audits the new call with `replay_of`. See
/// `docs/ref/mcp-audit.md`.
///
/// # Errors
///
/// [`ReplayError`] when the replay is refused before anything is sent.
pub async fn replay(replay: Replay<'_>) -> Result<Replayed, ReplayError> {
    let record = replay.record;
    let (Some(server), Some(tool)) = (record.server.as_deref(), record.tool.as_deref()) else {
        return Err(ReplayError::NotReplayable);
    };
    if record.outcome == mcp_audit::Outcome::Denied {
        return Err(ReplayError::NotReplayable);
    }
    if !matches!(
        record.arguments_state,
        ArgumentsState::Absent | ArgumentsState::Kept
    ) {
        return Err(ReplayError::RedactedArguments(record.arguments_state));
    }
    let gateway = replay
        .app
        .stages()
        .iter()
        .find_map(|named| match &named.stage {
            super::Stage::McpGateway(gateway) if *named.name == *record.middleware => Some(gateway),
            _ => None,
        })
        .ok_or(ReplayError::GatewayGone)?;
    gateway.replay(&replay, server, tool).await
}

impl McpGateway {
    /// [`replay`] on the gateway the record went through. The (server, tool) pair is looked up in
    /// the registry and the server's catalog as they are now, never taken from text.
    async fn replay(
        &self,
        replay: &Replay<'_>,
        server: &str,
        tool: &str,
    ) -> Result<Replayed, ReplayError> {
        let (index, spec) = self.index_of(server).ok_or(ReplayError::ServerGone)?;
        let _slot = replay
            .budget
            .and_then(TenantBudget::admit)
            .ok_or(ReplayError::Busy)?;
        let head = RequestHeader::build("POST", b"/", None).map_err(|_| ReplayError::Internal)?;
        let handle = Handle {
            id: "replay".into(),
            upstreams: Arc::default(),
        };
        let tenant = replay.app.tenant();
        let call = Call {
            caller: Caller {
                tenant,
                app: replay.app.id(),
                session: "replay",
                head: &head,
                claims: None,
            },
            env: Env {
                client: replay.client,
                policy: replay.policy,
                resolver: &self.0.resolver,
                transport: &self.0.transport,
                tenant,
                budget: replay.budget,
                runtime: &self.0.runtime,
            },
            handle: &handle,
        };
        let mut record = Record::new(
            tenant,
            replay.app.id(),
            "",
            &replay.record.middleware,
            &tools::qualify(server, tool),
        );
        record.server = Some(spec.name.clone());
        record.tool = Some(tool.into());
        record.replay_of = Some(replay.record.seq);
        record.set_arguments(mcp_audit::Arguments {
            state: replay.record.arguments_state,
            value: replay.record.arguments.clone(),
        });
        let started = Instant::now();
        let catalog = match self.catalog(&call, index).await {
            Ok(catalog) => catalog,
            Err(failure) => {
                let outcome = Outcome::Failed(failure);
                return Ok(self.sent(replay, record, started, outcome));
            }
        };
        let found = catalog
            .iter()
            .find(|listed| &*listed.name == tool)
            .ok_or(ReplayError::ToolGone)?;
        let tool_ref = ToolRef {
            server: spec.name.clone(),
            tool: found.name.clone(),
        };
        if !self.replayable(&tool_ref) {
            return Err(ReplayError::NotPermitted);
        }
        let read_only = found
            .value
            .pointer("/annotations/readOnlyHint")
            .and_then(Value::as_bool)
            == Some(true);
        if !(replay.force || read_only) {
            return Err(ReplayError::NeedsForce);
        }
        let name = serde_json::to_string(&*found.name).map_err(|_| ReplayError::Internal)?;
        let params = match &replay.record.arguments {
            Some(arguments) => format!(r#"{{"name":{name},"arguments":{}}}"#, arguments.get()),
            None => format!(r#"{{"name":{name}}}"#),
        };
        record.request_bytes = len(&params);
        let outcome = self.invoke(&call, index, spec, &call_body(&params)).await;
        Ok(self.sent(replay, record, started, outcome))
    }

    /// Audits a replay that was sent, or that failed trying, and answers it.
    fn sent(
        &self,
        replay: &Replay<'_>,
        mut record: Record,
        started: Instant,
        outcome: Outcome,
    ) -> Replayed {
        settle(&mut record, &outcome);
        record.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let stored = replay.audit.record(record);
        Replayed {
            audit_seq: stored.seq,
            outcome: stored.outcome,
            reason: stored.reason,
            answer: match outcome {
                Outcome::Result(raw) => ReplayAnswer::Result(raw),
                Outcome::Error(raw) => ReplayAnswer::Error(raw),
                Outcome::Failed(failure) => ReplayAnswer::Failed(failure.code()),
            },
        }
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

    /// What a `Call` borrows, for a gateway whose two servers have the catalogs of [`stocked`].
    struct Rig {
        sessions: Sessions,
        handle: Handle,
        client: forward_auth::Client,
        policy: UpstreamPolicy,
        request: RequestHeader,
    }

    impl Rig {
        fn new(gateway: &McpGateway) -> Self {
            let sessions = Sessions::new();
            let handle = sessions
                .open("t1", "a", gateway.0.fingerprint, Instant::now())
                .expect("a session");
            Self {
                sessions,
                handle,
                client: forward_auth::Client::new(Duration::from_secs(1)),
                policy: UpstreamPolicy::builtin(),
                request: head(None, "gw.example.com"),
            }
        }

        fn call<'a>(
            &'a self,
            gateway: &'a McpGateway,
            claims: Option<&'a serde_json::Map<String, Value>>,
        ) -> Call<'a> {
            let _ = &self.sessions;
            Call {
                caller: Caller {
                    tenant: "t1",
                    app: "a",
                    session: &self.handle.id,
                    head: &self.request,
                    claims,
                },
                env: Env {
                    client: &self.client,
                    policy: &self.policy,
                    resolver: &gateway.0.resolver,
                    transport: &gateway.0.transport,
                    tenant: "t1",
                    budget: None,
                    runtime: &gateway.0.runtime,
                },
                handle: &self.handle,
            }
        }
    }

    /// A gateway over `two()` with `tool_access` `rules` and catalogs: alpha has `search` and
    /// `read`, beta has `search`.
    fn stocked(rules: Option<Value>) -> McpGateway {
        let mut config = two();
        if let (Some(rules), Some(object)) = (rules, config.as_object_mut()) {
            object.insert("tool_access".into(), rules);
        }
        let gateway = compile(&config).expect("compiled");
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
        gateway
    }

    fn claims(value: &Value) -> serde_json::Map<String, Value> {
        value.as_object().expect("object").clone()
    }

    /// The qualified names `claims` is shown of the merged list.
    fn shown(
        gateway: &McpGateway,
        rig: &Rig,
        claims: Option<&serde_json::Map<String, Value>>,
    ) -> Vec<String> {
        let call = rig.call(gateway, claims);
        let alpha = gateway.0.runtime.fresh(0, CATALOG_TTL).expect("fresh");
        let beta = gateway.0.runtime.fresh(1, CATALOG_TTL).expect("fresh");
        let listed = tools::merge([("alpha", &*alpha), ("beta", &*beta)].into_iter());
        gateway
            .expose(&call.caller, listed)
            .iter()
            .filter_map(|tool| tool.value["name"].as_str().map(str::to_owned))
            .collect()
    }

    fn roles() -> Value {
        json!([
            {"tools": ["alpha__*"], "allow": {"roles": ["dev", "admin"]}},
            {"tools": ["beta__search"], "allow": {"roles": ["admin"]}},
        ])
    }

    #[test]
    fn tbac_list_filtered_by_claims() {
        let gateway = stocked(Some(roles()));
        let rig = Rig::new(&gateway);
        let dev = claims(&json!({"roles": ["dev"]}));
        let admin = claims(&json!({"roles": "admin"}));
        assert_eq!(
            shown(&gateway, &rig, Some(&dev)),
            ["alpha__search", "alpha__read"]
        );
        assert_eq!(
            shown(&gateway, &rig, Some(&admin)),
            ["alpha__search", "alpha__read", "beta__search"]
        );
        assert!(shown(&gateway, &rig, Some(&claims(&json!({"roles": ["x"]})))).is_empty());
        assert!(shown(&gateway, &rig, None).is_empty());
        // No `tool_access`: everything, as in 0132.
        let open = stocked(None);
        let rig = Rig::new(&open);
        assert_eq!(shown(&open, &rig, None).len(), 3);
    }

    #[tokio::test]
    async fn tbac_denied_equals_unknown() {
        let gateway = stocked(Some(json!([
            {"tools": ["alpha__read"], "allow": {"roles": ["dev"]}},
            {"tools": ["beta__search"], "allow": {"roles": ["admin"]}},
        ])));
        let rig = Rig::new(&gateway);
        let dev = claims(&json!({"roles": ["dev"]}));
        let call = rig.call(&gateway, Some(&dev));
        let id = serde_json::from_str::<Box<RawValue>>("7").expect("id");
        let body = |why: &Unresolved| McpGateway::refusal(&id, why).body;

        // A tool of a server the caller reaches, which a rule does not list.
        let hidden = gateway
            .resolve(&call, "alpha__search")
            .await
            .expect("resolved");
        let denied = gateway
            .authorize(&call.caller, &hidden, None)
            .expect_err("hidden");
        assert_eq!(denied, Unresolved::Denied);
        // A server the caller has no rule for is denied before its catalog is asked for.
        let unreached = gateway
            .resolve(&call, "beta__search")
            .await
            .expect_err("denied");
        assert_eq!(unreached, Unresolved::Denied);
        let missing_tool = gateway
            .resolve(&call, "alpha__nothing")
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
        for why in [&unreached, &missing_tool, &missing_server, &unprefixed] {
            assert_eq!(body(&denied), body(why), "{why:?}");
        }

        // What the rules list stays callable.
        let read = gateway
            .resolve(&call, "alpha__read")
            .await
            .expect("resolved");
        assert!(gateway.authorize(&call.caller, &read, None).is_ok());
    }

    #[tokio::test]
    async fn tbac_unreachable_server_is_not_dialled() {
        // No catalog is cached and the addresses lead nowhere: a caller that reaches no tool of
        // beta is refused without a fetch, so the answer is `Denied`, never `Unavailable`.
        let config = json!({
            "servers": two()["servers"],
            "tool_access": [{"tools": ["alpha__read"], "allow": {"roles": ["dev"]}}],
        });
        let gateway = compile(&config).expect("compiled");
        let rig = Rig::new(&gateway);
        let dev = claims(&json!({"roles": ["dev"]}));
        let call = rig.call(&gateway, Some(&dev));
        assert_eq!(
            gateway.resolve(&call, "beta__search").await.err(),
            Some(Unresolved::Denied)
        );
        assert_eq!(
            gateway.resolve(&call, "beta__anything").await.err(),
            Some(Unresolved::Denied)
        );
    }

    #[tokio::test]
    async fn tbac_denied_counted() {
        let gateway = stocked(Some(roles()));
        let rig = Rig::new(&gateway);
        let dev = claims(&json!({"roles": ["dev"], "sub": "ann"}));
        let call = rig.call(&gateway, Some(&dev));
        assert_eq!(gateway.0.runtime.denied(), 0);
        gateway
            .resolve(&call, "beta__search")
            .await
            .expect_err("denied");
        assert_eq!(gateway.0.runtime.denied(), 1);
        // A name that leads nowhere for everyone is not a denial.
        gateway
            .resolve(&call, "gamma__x")
            .await
            .expect_err("unknown");
        gateway
            .resolve(&call, "alpha__nothing")
            .await
            .expect_err("unknown");
        assert_eq!(gateway.0.runtime.denied(), 1);
        let tool = ToolRef {
            server: "alpha".into(),
            tool: "search".into(),
        };
        let dev_only = stocked(Some(json!([
            {"tools": ["alpha__read"], "allow": {"roles": ["dev"]}}
        ])));
        let rig = Rig::new(&dev_only);
        let call = rig.call(&dev_only, Some(&dev));
        dev_only
            .authorize(&call.caller, &tool, None)
            .expect_err("denied");
        assert_eq!(dev_only.0.runtime.denied(), 1);
    }

    #[test]
    fn tbac_replayable() {
        let tool = |server: &str, name: &str| ToolRef {
            server: server.into(),
            tool: name.into(),
        };
        let open = stocked(None);
        assert!(open.replayable(&tool("gamma", "anything")));
        let gateway = stocked(Some(json!([
            {"tools": ["alpha__read"], "allow": {"roles": ["dev"]}},
            {"tools": ["beta__*"], "allow": {"roles": ["admin"]}},
        ])));
        assert!(gateway.replayable(&tool("alpha", "read")));
        assert!(gateway.replayable(&tool("beta", "anything")));
        assert!(!gateway.replayable(&tool("alpha", "search")));
        assert!(!stocked(Some(json!([]))).replayable(&tool("alpha", "read")));
    }

    #[test]
    fn tbac_requires_claims_for_every_tool() {
        let gateway = stocked(Some(roles()));
        let rig = Rig::new(&gateway);
        let call = rig.call(&gateway, None);
        for (server, name) in [("alpha", "search"), ("beta", "search")] {
            let tool = ToolRef {
                server: server.into(),
                tool: name.into(),
            };
            assert!(!gateway.visible(&call.caller, &tool), "{server}__{name}");
        }
    }

    #[test]
    fn tbac_posture_follows_the_rules() {
        let narrow = json!([{"tools": ["alpha__read"], "allow": {"roles": ["dev"]}}]);
        let wide =
            json!([{"tools": ["alpha__read", "alpha__search"], "allow": {"roles": ["dev"]}}]);
        let kinds = |old: Option<Value>, new: Option<Value>| {
            let (old, new) = (stocked(old), stocked(new));
            old.posture(Some(&new))
        };
        assert_eq!(
            kinds(Some(narrow.clone()), Some(wide.clone())),
            ["mcp_tool_access_widened"]
        );
        assert!(kinds(Some(wide), Some(narrow.clone())).is_empty());
        assert!(kinds(None, Some(narrow.clone())).is_empty());
        assert_eq!(
            kinds(Some(narrow.clone()), None),
            ["mcp_tool_access_removed"]
        );
        assert_eq!(kinds(Some(json!([])), None), ["mcp_tool_access_removed"]);
        assert!(kinds(None, None).is_empty());
        // A gateway that is gone relaxes nothing.
        assert!(stocked(Some(narrow)).posture(None).is_empty());
    }

    #[test]
    fn tbac_describe_shows_rules() {
        let shown = stocked(Some(roles())).describe();
        assert_eq!(
            shown["tool_access"],
            json!([
                {"tools": ["alpha__*"], "allow": {"roles": ["dev", "admin"]}},
                {"tools": ["beta__search"], "allow": {"roles": ["admin"]}},
            ])
        );
        assert_eq!(stocked(None).describe()["tool_access"], Value::Null);
    }

    #[test]
    fn tbac_rules_are_checked_against_the_registry() {
        let mut config = two();
        config["tool_access"] = json!([{"tools": ["gamma__x"], "allow": {"roles": ["dev"]}}]);
        assert_eq!(code(&config), "invalid_middleware");
        config["tool_access"] =
            json!([{"tools": ["alpha__x"], "allow": {"roles": ["dev"]}, "extra": 1}]);
        assert_eq!(code(&config), "invalid_middleware");
        config["tool_access"] = json!([]);
        assert!(compile(&config).is_ok());
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
                claims: None,
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
