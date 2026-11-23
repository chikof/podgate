//! Fake MCP servers on raw TCP, a client of the gateway and snapshot builders. Shared by
//! `tests/mcp_gateway.rs` and `tests/mcp_tool_access.rs`, which both include this file with
//! `#[path]`.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "each includer uses some of the helpers, and `pub` is what the includers need"
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::common::{Podgate, app, serving, snapshot, with_middleware};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

pub const BIG_BUDGET: u64 = 64 * 1024 * 1024;

/// What one `tools/call` reserves at most (`call_bytes` in `src/middleware/mcp.rs`): two request
/// caps, the result cap and the exchange allowance.
pub const ONE_CALL: u64 = 6 * 1024 * 1024 + 49_152;

// ---- a fake MCP server ---------------------------------------------------------------------

/// A request a fake server got.
#[derive(Debug, Clone)]
pub struct Seen {
    pub head: String,
    pub body: String,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(": ")?;
            key.eq_ignore_ascii_case(name).then_some(value)
        })
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    pub fn method(&self) -> String {
        self.json()["method"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

/// What a fake server answers.
pub enum Out {
    Json {
        status: u16,
        content_type: &'static str,
        headers: Vec<(String, String)>,
        body: String,
    },
    /// An event stream of these raw events; held open afterwards when `hold_open`.
    Sse {
        headers: Vec<(String, String)>,
        events: Vec<String>,
        hold_open: bool,
    },
}

pub type Handler = dyn Fn(&Seen) -> (Duration, Out) + Send + Sync;

pub struct Fake {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub accepts: Arc<AtomicUsize>,
    pub task: JoinHandle<()>,
}

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

impl Fake {
    pub async fn start(handler: impl Fn(&Seen) -> (Duration, Out) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let accepts = Arc::new(AtomicUsize::new(0));
        let handler: Arc<Handler> = Arc::new(handler);
        let task = tokio::spawn({
            let (seen, accepts) = (Arc::clone(&seen), Arc::clone(&accepts));
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    accepts.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(serve(stream, Arc::clone(&handler), Arc::clone(&seen)));
                }
            }
        });
        Self {
            addr,
            seen,
            accepts,
            task,
        }
    }

    pub async fn mcp(behavior: &Arc<Behavior>) -> Self {
        let behavior = Arc::clone(behavior);
        Self::start(move |seen| behavior.answer(seen)).await
    }

    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen").clone()
    }

    /// The requests whose JSON-RPC method is `method`.
    pub fn calls(&self, method: &str) -> Vec<Seen> {
        self.requests()
            .into_iter()
            .filter(|seen| seen.method() == method)
            .collect()
    }

    pub fn accepted(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Stops listening: the port is refused from now on.
    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn serve(mut stream: TcpStream, handler: Arc<Handler>, seen: Arc<Mutex<Vec<Seen>>>) {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        if let Some(end) = find(&buf, b"\r\n\r\n") {
            break end + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => buf.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < head_end + length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => buf.extend_from_slice(&chunk[..read]),
        }
    }
    let body = String::from_utf8_lossy(&buf[head_end..head_end + length]).into_owned();
    let request = Seen { head, body };
    seen.lock().expect("seen").push(request.clone());
    let (delay, out) = handler(&request);
    if !delay.is_zero() {
        sleep(delay).await;
    }
    match out {
        Out::Json {
            status,
            content_type,
            headers,
            body,
        } => {
            let mut text = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (name, value) in headers {
                text.push_str(&format!("{name}: {value}\r\n"));
            }
            text.push_str("\r\n");
            text.push_str(&body);
            drop(stream.write_all(text.as_bytes()).await);
            drop(stream.shutdown().await);
        }
        Out::Sse {
            headers,
            events,
            hold_open,
        } => {
            let mut head = String::from(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n",
            );
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            if stream.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            for event in events {
                let framed = format!("{:x}\r\n{event}\r\n", event.len());
                if stream.write_all(framed.as_bytes()).await.is_err() {
                    return;
                }
            }
            if hold_open {
                sleep(Duration::from_secs(30)).await;
            } else {
                drop(stream.write_all(b"0\r\n\r\n").await);
                drop(stream.shutdown().await);
            }
        }
    }
}

pub const NORMAL: u8 = 0;
pub const NOT_JSON: u8 = 1;
pub const WRONG_ID: u8 = 2;
pub const HTML: u8 = 3;
pub const STRING_RESULT: u8 = 4;
pub const STATUS_500: u8 = 5;
pub const NO_ANSWER: u8 = 6;

/// How a fake MCP server behaves, switchable while it runs.
pub struct Behavior {
    pub name: &'static str,
    pub tools: Vec<Value>,
    pub sse: bool,
    pub hold_open: bool,
    /// Sessions issued so far; the next is `<name>-s<n>`.
    pub sessions: AtomicUsize,
    /// Requests that carry a session numbered below this answer `404`.
    pub expired_before: AtomicUsize,
    pub call_delay_ms: AtomicU64,
    pub delay_all_ms: AtomicU64,
    pub mode: AtomicU8,
}

impl Behavior {
    pub fn new(name: &'static str, tools: &[&str]) -> Arc<Self> {
        Self::custom(name, tools, false, false)
    }

    pub fn custom(name: &'static str, tools: &[&str], sse: bool, hold_open: bool) -> Arc<Self> {
        Self::build(
            name,
            tools.iter().map(|tool| tool_object(tool)).collect(),
            sse,
            hold_open,
        )
    }

    /// A server whose tools are exactly `tools`, tool objects as it lists them (to carry
    /// annotations such as `readOnlyHint`).
    pub fn with_tools(name: &'static str, tools: Vec<Value>) -> Arc<Self> {
        Self::build(name, tools, false, false)
    }

    fn build(name: &'static str, tools: Vec<Value>, sse: bool, hold_open: bool) -> Arc<Self> {
        Arc::new(Self {
            name,
            tools,
            sse,
            hold_open,
            sessions: AtomicUsize::new(0),
            expired_before: AtomicUsize::new(0),
            call_delay_ms: AtomicU64::new(0),
            delay_all_ms: AtomicU64::new(0),
            mode: AtomicU8::new(NORMAL),
        })
    }

    pub fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    pub fn session_number(&self, seen: &Seen) -> Option<usize> {
        let id = seen.header("mcp-session-id")?;
        id.strip_prefix(self.name)?.strip_prefix("-s")?.parse().ok()
    }

    pub fn answer(&self, seen: &Seen) -> (Duration, Out) {
        let request = seen.json();
        let method = request["method"].as_str().unwrap_or_default();
        let id = request["id"].to_string();
        let mut delay = Duration::from_millis(self.delay_all_ms.load(Ordering::SeqCst));
        let plain = |status: u16, body: &str| {
            (
                Duration::ZERO,
                Out::Json {
                    status,
                    content_type: "application/json",
                    headers: Vec::new(),
                    body: body.to_owned(),
                },
            )
        };
        if self
            .session_number(seen)
            .is_some_and(|number| number < self.expired_before.load(Ordering::SeqCst))
        {
            return plain(404, "");
        }
        if method == "notifications/initialized" {
            return plain(202, "");
        }
        let mut headers = Vec::new();
        let mode = self.mode.load(Ordering::SeqCst);
        let handshake = method == "initialize";
        let result = match method {
            "initialize" => {
                let number = self.sessions.fetch_add(1, Ordering::SeqCst);
                headers.push((
                    "Mcp-Session-Id".to_owned(),
                    format!("{}-s{number}", self.name),
                ));
                format!(
                    r#"{{"protocolVersion":{},"capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"{}","version":"1"}}}}"#,
                    request["params"]["protocolVersion"], self.name
                )
            }
            "tools/list" => json!({"tools": self.tools}).to_string(),
            "tools/call" => {
                delay += Duration::from_millis(self.call_delay_ms.load(Ordering::SeqCst));
                let tool = request["params"]["name"].as_str().unwrap_or_default();
                // Raw text on purpose: the gateway must pass these digits through untouched.
                format!(
                    r#"{{"content":[{{"type":"text","text":"{}:{tool}"}}],"structuredContent":{{"arguments":{},"meta":{},"big":18446744073709551616,"f":1.50}},"isError":false}}"#,
                    self.name, request["params"]["arguments"], request["params"]["_meta"]
                )
            }
            _ => {
                return plain(
                    200,
                    &format!(
                        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"method not found"}}}}"#
                    ),
                );
            }
        };
        let answer_id = if mode == WRONG_ID && !handshake {
            "99"
        } else {
            &id
        };
        let mut body = format!(r#"{{"jsonrpc":"2.0","id":{answer_id},"result":{result}}}"#);
        let mut content_type = "application/json";
        let mut status = 200;
        if !handshake {
            match mode {
                NOT_JSON => body = "nonsense".to_owned(),
                HTML => content_type = "text/html",
                STRING_RESULT if method == "tools/call" => {
                    body = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":"oops"}}"#);
                }
                STATUS_500 => status = 500,
                NO_ANSWER => body = format!(r#"{{"jsonrpc":"2.0","id":{id}}}"#),
                _ => {}
            }
        }
        if self.sse && status == 200 && content_type == "application/json" {
            let notice = r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"working"}}"#;
            return (
                delay,
                Out::Sse {
                    headers,
                    events: vec![
                        format!("event: message\ndata: {notice}\n\n"),
                        format!("id: 1\nevent: message\ndata: {body}\n\n"),
                    ],
                    hold_open: self.hold_open,
                },
            );
        }
        (
            delay,
            Out::Json {
                status,
                content_type,
                headers,
                body,
            },
        )
    }
}

pub fn tool_object(name: &str) -> Value {
    json!({
        "name": name,
        "title": format!("The {name} tool"),
        "description": format!("{name} does a thing"),
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
    })
}

/// An address nothing listens on.
pub fn refused_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

// ---- a client of the gateway ---------------------------------------------------------------

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {:?}", self.body))
    }
}

pub struct Client {
    pub addr: SocketAddr,
    pub host: String,
    /// Sent as `Authorization: Bearer <token>` on every request when set.
    pub token: Option<String>,
    /// Sent on every request, after the token.
    pub headers: Vec<(String, String)>,
}

impl Client {
    pub fn new(podgate: &Podgate, host: &str) -> Self {
        Self {
            addr: podgate.proxy_addr,
            host: host.to_owned(),
            token: None,
            headers: Vec::new(),
        }
    }

    /// The same client, carrying `token`.
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_owned());
        self
    }

    /// The same client, sending `name: value` on every request (a session cookie, say).
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// One request on its own connection; the body is written whole, and a refusal that arrives
    /// before the body is written out is still read.
    pub async fn send(&self, method: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
        let stream = TcpStream::connect(self.addr).await.expect("connect");
        let mut head = format!(
            "{method} /mcp HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.host
        );
        if let Some(token) = &self.token {
            head.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        let mut request = head.into_bytes();
        request.extend_from_slice(body);
        let mut raw = Vec::new();
        let (mut reader, mut writer) = stream.into_split();
        // A refusal that comes before the body is read arrives while the body is still being
        // written, so the two run together and a failed write is not an error.
        timeout(Duration::from_secs(20), async {
            tokio::join!(
                async {
                    drop(writer.write_all(&request).await);
                },
                async {
                    drop(reader.read_to_end(&mut raw).await);
                }
            );
        })
        .await
        .expect("an answer in time");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("no header end in {text:?}"));
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("bad status line in {text:?}"));
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        Resp {
            status,
            headers,
            body: body.to_owned(),
        }
    }

    /// `POST` of a JSON body, with a session when there is one.
    pub async fn post(&self, session: Option<&str>, extra: &[(&str, &str)], body: &Value) -> Resp {
        let mut headers = vec![
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
        ];
        if let Some(session) = session {
            headers.push(("Mcp-Session-Id", session));
        }
        headers.extend_from_slice(extra);
        self.send("POST", &headers, body.to_string().as_bytes())
            .await
    }

    pub async fn initialize(&self) -> String {
        let answer = self
            .post(
                None,
                &[],
                &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"}}}),
            )
            .await;
        assert_eq!(answer.status, 200, "{answer:?}");
        answer
            .header("mcp-session-id")
            .unwrap_or_else(|| panic!("no session id: {answer:?}"))
            .to_owned()
    }

    /// A request of an open session; the whole JSON-RPC answer.
    pub async fn rpc(&self, session: &str, method: &str, params: Value) -> Value {
        let answer = self
            .post(
                Some(session),
                &[("MCP-Protocol-Version", "2025-11-25")],
                &json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params}),
            )
            .await;
        assert_eq!(answer.status, 200, "{answer:?}");
        answer.json()
    }

    pub async fn list(&self, session: &str) -> Vec<String> {
        let answer = self.rpc(session, "tools/list", json!({})).await;
        answer["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("no tools in {answer}"))
            .iter()
            .map(|tool| tool["name"].as_str().expect("name").to_owned())
            .collect()
    }

    pub async fn call(&self, session: &str, name: &str, arguments: Value) -> Value {
        self.rpc(
            session,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
        .await
    }
}

// ---- snapshots -----------------------------------------------------------------------------

pub fn server(name: &str, addr: SocketAddr) -> Value {
    json!({"name": name, "address": format!("http://{addr}/mcp")})
}

pub fn with_timeout(mut server: Value, millis: u64) -> Value {
    server["timeout_ms"] = json!(millis);
    server
}

/// An app of `tenant` for `host` whose router carries one `mcp_gateway` over `servers`.
pub fn gateway_app(id: &str, tenant: &str, host: &str, servers: &[Value], extra: &Value) -> Value {
    let mut config = json!({ "servers": servers });
    if let (Some(config), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
        config.extend(extra.clone());
    }
    let unused: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let mut declared = with_middleware(
        app(id, &[host], &[serving("r1", unused)]),
        "mcp",
        "mcp_gateway",
        config,
    );
    declared["tenant"] = json!(tenant);
    declared
}

pub fn budgeted(version: u64, apps: &[Value], budget: u64) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["tenants"] = json!([
        {"id": "t1", "weight": 1, "budget": {"max_inflight": 100, "max_buffer_bytes": budget}},
        {"id": "t2", "weight": 1, "budget": {"max_inflight": 100, "max_buffer_bytes": budget}},
    ]);
    pushed
}

pub async fn push(podgate: &Podgate, pushed: &Value) {
    let answer = podgate.push_snapshot(pushed).await;
    assert_eq!(answer.status, 200, "{answer:?}");
}

/// A running daemon with one gateway app `mcp.test` over `servers`.
pub async fn gateway(servers: &[Value]) -> (Podgate, Client) {
    let podgate = Podgate::start().await;
    push(
        &podgate,
        &budgeted(
            1,
            &[gateway_app("mcp", "t1", "mcp.test", servers, &json!({}))],
            BIG_BUDGET,
        ),
    )
    .await;
    let client = Client::new(&podgate, "mcp.test");
    (podgate, client)
}

pub fn code(answer: &Value) -> i64 {
    answer["error"]["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("no error in {answer}"))
}

/// The text of the first content block of a tool result.
pub fn text(answer: &Value) -> &str {
    answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no result text in {answer}"))
}
