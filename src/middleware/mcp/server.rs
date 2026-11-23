//! One registered MCP server: the exchanges the gateway has with it and what it remembers of
//! them.
//!
//! Every exchange is one HTTP/1.1 `POST` on a fresh connection ([`forward_auth::Client`]: the
//! upstream address policy checks the address about to be dialled, one timeout covers the whole
//! exchange, nothing is pooled). Before the connection is made the exchange takes one permit of
//! the server's `max_concurrent` and charges its bytes to the tenant's buffer budget. Nothing of
//! the client's request is copied into it: the headers are the gateway's own.
//!
//! The answer is `application/json` (one JSON-RPC answer) or `text/event-stream` (the event that
//! holds the answer, see [`super::sse`]). A server that answers anything else, or something that
//! is not the answer to the request, has failed.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use http::HeaderMap;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use super::rpc::{self, Answer};
use super::sse;
use super::tools::{self, Catalog, Tool};
use crate::budget::TenantBudget;
use crate::middleware::errors::fetch;
use crate::middleware::forward_auth::{self, ALLOWANCE, Parsed, Route};
use crate::service::Transport;
use crate::service::resolve::Resolver;
use crate::service::upstream_policy::UpstreamPolicy;

/// The largest answer to `initialize`.
pub(super) const HANDSHAKE_CAP: usize = 64 * 1024;

/// The largest page of `tools/list`.
pub(super) const LIST_CAP: usize = 1024 * 1024;

/// The largest answer to `tools/call`.
pub(super) const RESULT_CAP: usize = 4 * 1024 * 1024;

/// The most pages of `tools/list` followed for one server.
const MAX_PAGES: usize = 8;

/// The longest `Mcp-Session-Id` a server may issue.
const MAX_SESSION_ID: usize = 256;

/// How a registered server failed, with a stable code for the overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failure {
    /// No room: the server is at `max_concurrent`, or the tenant's buffer budget is full. Not the
    /// server's fault.
    Busy,
    /// The upstream address policy refuses the server.
    Policy,
    /// No connection, or the connection broke.
    Connect,
    /// The exchange ran past `timeout_ms`.
    Timeout,
    /// The server answered a status the exchange does not accept.
    Status(u16),
    /// The answer is not a well-formed answer to the request.
    Malformed,
    /// The answer is over its cap.
    TooLarge,
    /// The server speaks no protocol version the gateway does.
    Version,
    /// The server forgot the session the gateway holds with it (`404`): a new one is needed.
    SessionGone,
}

impl Failure {
    /// The code the overview shows.
    #[must_use]
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Policy => "policy",
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Status(_) => "status",
            Self::Malformed => "malformed",
            Self::TooLarge => "too_large",
            Self::Version => "version",
            Self::SessionGone => "session",
        }
    }
}

impl From<fetch::Failure> for Failure {
    fn from(failure: fetch::Failure) -> Self {
        match failure {
            fetch::Failure::Policy => Self::Policy,
            fetch::Failure::NotInet | fetch::Failure::Connect(_) | fetch::Failure::Io(_) => {
                Self::Connect
            }
            fetch::Failure::Timeout => Self::Timeout,
            fetch::Failure::Status(status) => Self::Status(status),
            fetch::Failure::TooLarge => Self::TooLarge,
            fetch::Failure::Malformed(_) => Self::Malformed,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(status) => write!(f, "the server answered {status}"),
            Self::Malformed => f.write_str("the answer is not a well-formed MCP answer"),
            other => f.write_str(other.code()),
        }
    }
}

/// What the gateway last saw of a server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum Health {
    /// No exchange has happened since the registry was declared.
    #[default]
    Unknown,
    /// The last exchange got a well-formed answer.
    Healthy,
    /// The last exchange failed with this code.
    Down(&'static str),
}

/// A registered server, as declared.
#[derive(Debug)]
pub(super) struct Spec {
    pub(super) name: Box<str>,
    pub(super) parsed: Parsed,
    pub(super) timeout: Duration,
    pub(super) max_concurrent: u32,
}

/// The session a server issued to the gateway for one client session, and the protocol version
/// they settled on. A server that issues no session id has `session: None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Up {
    pub(super) session: Option<Box<str>>,
    pub(super) version: &'static str,
}

#[derive(Debug, Default)]
struct State {
    health: Health,
    catalog: Option<Catalog>,
}

#[derive(Debug)]
struct Slot {
    permits: Semaphore,
    state: Mutex<State>,
}

/// What outlives a snapshot push for the servers of one `mcp_gateway`: their permits, health and
/// catalogs, one slot per declared server in declaration order.
#[derive(Debug)]
pub(super) struct Runtime {
    slots: Box<[Slot]>,
}

impl Runtime {
    pub(super) fn new(specs: &[Spec]) -> Self {
        Self {
            slots: specs
                .iter()
                .map(|spec| Slot {
                    permits: Semaphore::new(usize::try_from(spec.max_concurrent).unwrap_or(1)),
                    state: Mutex::new(State::default()),
                })
                .collect(),
        }
    }

    fn state(&self, index: usize) -> Option<std::sync::MutexGuard<'_, State>> {
        self.slots
            .get(index)
            .map(|slot| slot.state.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// The tools server `index` reported, when that was less than `ttl` ago.
    pub(super) fn fresh(&self, index: usize, ttl: Duration) -> Option<Arc<[Tool]>> {
        let state = self.state(index)?;
        let catalog = state.catalog.as_ref()?;
        (catalog.fetched.elapsed() < ttl).then(|| Arc::clone(&catalog.tools))
    }

    /// Replaces the catalog of server `index`.
    pub(super) fn set_catalog(&self, index: usize, catalog: Option<Catalog>) {
        if let Some(mut state) = self.state(index) {
            state.catalog = catalog;
        }
    }

    /// Records how the last exchange with server `index` went. Running out of room, or a
    /// forgotten session the caller recovers from, says nothing about the server.
    fn observe<T>(&self, index: usize, outcome: &Result<T, Failure>) {
        let health = match outcome {
            Ok(_) => Health::Healthy,
            Err(Failure::Busy | Failure::SessionGone) => return,
            Err(failure) => Health::Down(failure.code()),
        };
        if let Some(mut state) = self.state(index) {
            state.health = health;
        }
    }

    /// Health, tool count and skipped count of server `index`, for the overview.
    pub(super) fn view(&self, index: usize) -> (Health, Option<(usize, usize)>) {
        self.state(index).map_or((Health::Unknown, None), |state| {
            (
                state.health,
                state
                    .catalog
                    .as_ref()
                    .map(|catalog| (catalog.tools.len(), catalog.skipped)),
            )
        })
    }
}

/// What every exchange of one request needs: who dials, under which rule and for whom.
pub(super) struct Env<'a> {
    pub(super) client: &'a forward_auth::Client,
    pub(super) policy: &'a UpstreamPolicy,
    pub(super) resolver: &'a Resolver,
    pub(super) transport: &'a Transport,
    pub(super) tenant: &'a str,
    /// `None` when the table has no budget for the tenant: nothing can be charged, so nothing is
    /// dialled.
    pub(super) budget: Option<&'a Arc<TenantBudget>>,
    pub(super) runtime: &'a Runtime,
}

/// The request head of one exchange.
fn head(spec: &Spec, up: Option<&Up>, body: &str) -> Vec<u8> {
    let mut out = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        spec.parsed.target,
        spec.parsed.host,
        body.len()
    );
    if let Some(up) = up {
        out.push_str("MCP-Protocol-Version: ");
        out.push_str(up.version);
        out.push_str("\r\n");
        if let Some(session) = &up.session {
            out.push_str("Mcp-Session-Id: ");
            out.push_str(session);
            out.push_str("\r\n");
        }
    }
    out.push_str("\r\n");
    out.push_str(body);
    out.into_bytes()
}

fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn is_event_stream(headers: &HeaderMap) -> bool {
    content_type(headers).starts_with("text/event-stream")
}

/// Sends one JSON-RPC message and reads the HTTP answer, within the permit and the budget.
async fn send(
    env: &Env<'_>,
    index: usize,
    spec: &Spec,
    up: Option<&Up>,
    body: &str,
    cap: usize,
) -> Result<forward_auth::Answer, Failure> {
    let slot = env.runtime.slots.get(index).ok_or(Failure::Busy)?;
    let _permit = slot.permits.try_acquire().map_err(|_| Failure::Busy)?;
    let budget = env.budget.ok_or(Failure::Busy)?;
    let bytes = ALLOWANCE
        .saturating_add(u64::try_from(body.len()).unwrap_or(u64::MAX))
        .saturating_add(u64::try_from(cap).unwrap_or(u64::MAX));
    let _charge = budget.charge(bytes).ok_or(Failure::Busy)?;
    let request = head(spec, up, body);
    let route = Route {
        server: &spec.parsed.server,
        transport: env.transport,
        resolver: env.resolver,
        policy: env.policy,
        tenant: env.tenant,
    };
    env.client
        .call_until(&route, &request, cap, spec.timeout, |status, headers| {
            (status == 200 && is_event_stream(headers)).then(sse::stop)
        })
        .await
        .map_err(Failure::from)
}

/// The answer to the request in an HTTP answer.
fn read(http: &forward_auth::Answer, up: Option<&Up>) -> Result<Answer, Failure> {
    match http.status {
        200 => {}
        404 if up.is_some_and(|up| up.session.is_some()) => return Err(Failure::SessionGone),
        status => return Err(Failure::Status(status)),
    }
    let kind = content_type(&http.headers);
    let found = if kind.starts_with("text/event-stream") {
        sse::find(&http.body)
    } else if kind.starts_with("application/json") {
        std::str::from_utf8(&http.body).ok().and_then(rpc::answer)
    } else {
        return Err(Failure::Malformed);
    };
    found.ok_or(Failure::Malformed)
}

/// Sends the JSON-RPC request `body` to server `index` and reads its answer; `cap` bounds the
/// answer's body. Records the outcome as the server's health.
async fn request(
    env: &Env<'_>,
    index: usize,
    spec: &Spec,
    up: Option<&Up>,
    body: &str,
    cap: usize,
) -> Result<(Answer, HeaderMap), Failure> {
    let outcome: Result<(Answer, HeaderMap), Failure> = async {
        let http = send(env, index, spec, up, body, cap).await?;
        let answer = read(&http, up)?;
        Ok((answer, http.headers))
    }
    .await;
    env.runtime.observe(index, &outcome);
    outcome
}

#[derive(Deserialize)]
struct Initialized {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
}

/// A server-issued session id the gateway may write into a request: visible ASCII, bounded.
fn session_id(headers: &HeaderMap) -> Result<Option<Box<str>>, Failure> {
    let Some(value) = headers.get("mcp-session-id") else {
        return Ok(None);
    };
    let id = value
        .to_str()
        .ok()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= MAX_SESSION_ID
                && id.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        })
        .ok_or(Failure::Malformed)?;
    Ok(Some(id.into()))
}

/// Opens a session with server `index`: `initialize`, the version it picks, then
/// `notifications/initialized`.
pub(super) async fn handshake(env: &Env<'_>, index: usize, spec: &Spec) -> Result<Up, Failure> {
    let body = rpc::request(
        "initialize",
        &json!({
            "protocolVersion": rpc::LATEST,
            "capabilities": {},
            "clientInfo": {"name": "podgate", "version": env!("CARGO_PKG_VERSION")},
        }),
    );
    let (answer, headers) = request(env, index, spec, None, &body, HANDSHAKE_CAP).await?;
    let Answer::Result(raw) = answer else {
        return Err(Failure::Malformed);
    };
    let initialized: Initialized =
        serde_json::from_str(raw.get()).map_err(|_| Failure::Malformed)?;
    let version = rpc::SUPPORTED
        .iter()
        .copied()
        .find(|version| *version == initialized.protocol_version)
        .ok_or(Failure::Version)?;
    let up = Up {
        session: session_id(&headers)?,
        version,
    };
    let note = rpc::notification("notifications/initialized");
    let outcome = send(env, index, spec, Some(&up), &note, HANDSHAKE_CAP)
        .await
        .and_then(|http| match http.status {
            200..=299 => Ok(()),
            status => Err(Failure::Status(status)),
        });
    env.runtime.observe(index, &outcome);
    outcome?;
    Ok(up)
}

#[derive(Deserialize)]
struct Page {
    tools: Vec<Value>,
    #[serde(rename = "nextCursor", default)]
    next_cursor: Option<String>,
}

/// Asks server `index` for its tools, following its pages.
pub(super) async fn list(
    env: &Env<'_>,
    index: usize,
    spec: &Spec,
    up: &Up,
) -> Result<Catalog, Failure> {
    let mut reported = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |cursor| json!({"cursor": cursor}));
        let body = rpc::request("tools/list", &params);
        let (answer, _) = request(env, index, spec, Some(up), &body, LIST_CAP).await?;
        let Answer::Result(raw) = answer else {
            return Err(Failure::Malformed);
        };
        let page: Page = serde_json::from_str(raw.get()).map_err(|_| Failure::Malformed)?;
        reported.extend(page.tools);
        match page.next_cursor {
            Some(next) if !next.is_empty() => cursor = Some(next),
            _ => return Ok(tools::catalog(&spec.name, reported, Instant::now())),
        }
    }
    Err(Failure::Malformed)
}

/// Sends the `tools/call` request `body` to server `index`. A result must be a JSON object.
pub(super) async fn call(
    env: &Env<'_>,
    index: usize,
    spec: &Spec,
    up: &Up,
    body: &str,
) -> Result<Answer, Failure> {
    let (answer, _) = request(env, index, spec, Some(up), body, RESULT_CAP).await?;
    if let Answer::Result(raw) = &answer
        && !raw.get().starts_with('{')
    {
        return Err(Failure::Malformed);
    }
    Ok(answer)
}

#[cfg(test)]
mod test {
    use super::*;

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

    fn http_answer(status: u16, kind: &str, body: &str) -> forward_auth::Answer {
        forward_auth::Answer {
            status,
            headers: headers(&[("content-type", kind)]),
            body: body.as_bytes().to_vec(),
        }
    }

    const JSON: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

    #[test]
    fn mcp_server_reads_json_and_event_stream_answers() {
        let json = http_answer(200, "application/json; charset=utf-8", JSON);
        assert!(matches!(read(&json, None), Ok(Answer::Result(_))));
        let stream = http_answer(200, "Text/Event-Stream", &format!("data: {JSON}\n\n"));
        assert!(matches!(read(&stream, None), Ok(Answer::Result(_))));
    }

    #[test]
    fn mcp_server_refuses_what_is_not_an_answer() {
        let up = Up {
            session: Some("s".into()),
            version: rpc::LATEST,
        };
        assert_eq!(
            read(&http_answer(500, "application/json", JSON), None).err(),
            Some(Failure::Status(500))
        );
        assert_eq!(
            read(&http_answer(404, "application/json", ""), Some(&up)).err(),
            Some(Failure::SessionGone)
        );
        assert_eq!(
            read(&http_answer(404, "application/json", ""), None).err(),
            Some(Failure::Status(404))
        );
        for (kind, body) in [
            ("text/html", JSON),
            ("application/json", "not json"),
            (
                "application/json",
                r#"{"jsonrpc":"2.0","id":9,"result":{}}"#,
            ),
            ("text/event-stream", "data: nothing\n\n"),
            ("", JSON),
        ] {
            assert!(
                matches!(
                    read(&http_answer(200, kind, body), None),
                    Err(Failure::Malformed)
                ),
                "{kind} {body}"
            );
        }
    }

    #[test]
    fn mcp_server_session_ids_are_checked_before_they_are_sent() {
        assert_eq!(session_id(&headers(&[])), Ok(None));
        assert_eq!(
            session_id(&headers(&[("mcp-session-id", "abc-123")])),
            Ok(Some("abc-123".into()))
        );
        for bad in ["", "has space", &"x".repeat(MAX_SESSION_ID + 1)] {
            assert!(
                session_id(&headers(&[("mcp-session-id", bad)])).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn mcp_server_request_head_carries_only_the_gateways_headers() {
        let parsed = forward_auth::parse_url("http://10.0.0.5:8080/mcp?key=k", "address", 512)
            .expect("parsed");
        let spec = Spec {
            name: "alpha".into(),
            parsed,
            timeout: Duration::from_secs(1),
            max_concurrent: 1,
        };
        let up = Up {
            session: Some("sess".into()),
            version: rpc::LATEST,
        };
        let bytes = head(&spec, Some(&up), "{}");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.starts_with("POST /mcp?key=k HTTP/1.1\r\nHost: 10.0.0.5:8080\r\n"));
        assert!(text.contains("\r\nMcp-Session-Id: sess\r\n"));
        assert!(text.contains("\r\nMCP-Protocol-Version: 2025-11-25\r\n"));
        assert!(text.contains("\r\nContent-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\n{}"));
        let first = head(&spec, None, "{}");
        let text = String::from_utf8(first).expect("utf8");
        assert!(!text.contains("Mcp-Session-Id") && !text.contains("MCP-Protocol-Version"));
    }

    #[test]
    fn mcp_server_health_follows_the_last_real_exchange() {
        let parsed =
            forward_auth::parse_url("http://10.0.0.5/mcp", "address", 512).expect("parsed");
        let spec = Spec {
            name: "alpha".into(),
            parsed,
            timeout: Duration::from_secs(1),
            max_concurrent: 2,
        };
        let runtime = Runtime::new(&[spec]);
        assert_eq!(runtime.view(0).0, Health::Unknown);
        runtime.observe(0, &Err::<(), _>(Failure::Timeout));
        assert_eq!(runtime.view(0).0, Health::Down("timeout"));
        // Out of room, or a session to renew, is not the server's doing.
        runtime.observe(0, &Err::<(), _>(Failure::Busy));
        runtime.observe(0, &Err::<(), _>(Failure::SessionGone));
        assert_eq!(runtime.view(0).0, Health::Down("timeout"));
        runtime.observe(0, &Ok::<(), Failure>(()));
        assert_eq!(runtime.view(0).0, Health::Healthy);
    }
}
