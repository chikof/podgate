//! The `content_guard` middleware, end to end on the real binary: regex rules that
//! block or redact in both directions, bodies that cannot be scanned are refused, an external
//! classifier answers the guard wire, and a matched value reaches nothing but the one place the
//! rules put it. The rule engine, its caps and its linear time are unit-tested in
//! `src/middleware/content_guard/rules.rs`.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Podgate, app, refused, router, service, serving, snapshot, with_middleware};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

// ---------------------------------------------------------------------------------------
// Fake servers
// ---------------------------------------------------------------------------------------

/// What a test server answers with.
enum Reply {
    /// These bytes, then the connection closes.
    Raw(Vec<u8>),
    /// These bytes after a pause.
    Delay(Duration, Vec<u8>),
}

fn http(status: u16, content_type: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: {content_type}\r\n{extra}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn json_reply(status: u16, body: &str) -> Reply {
    Reply::Raw(http(status, "application/json", "", body.as_bytes()))
}

/// A response whose body is sent as `Transfer-Encoding: chunked` pieces.
fn chunked_reply(content_type: &str, pieces: &[&[u8]]) -> Reply {
    let mut out = format!(
        "HTTP/1.1 200 X\r\nConnection: close\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .into_bytes();
    for piece in pieces {
        out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    Reply::Raw(out)
}

/// What a test server saw.
struct Call {
    head: String,
    body: Vec<u8>,
}

impl Call {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        header_of(&self.head, name)
    }
}

type Handler = dyn Fn(&Call) -> Reply + Send + Sync;

/// A server that records each request and answers by `handler`.
struct Server {
    addr: SocketAddr,
    calls: Arc<Mutex<Vec<Call>>>,
}

impl Server {
    async fn start(handler: impl Fn(&Call) -> Reply + Send + Sync + 'static) -> Self {
        Self::start_on("127.0.0.1", handler).await
    }

    async fn start_on(ip: &str, handler: impl Fn(&Call) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind(format!("{ip}:0")).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let shared = Arc::clone(&calls);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(stream, Arc::clone(&handler), Arc::clone(&shared)));
            }
        });
        Self { addr, calls }
    }

    fn requests(&self) -> usize {
        self.calls.lock().expect("calls").len()
    }

    fn with<T>(&self, index: usize, read: impl FnOnce(&Call) -> T) -> T {
        read(&self.calls.lock().expect("calls")[index])
    }

    fn last_text(&self) -> String {
        let calls = self.calls.lock().expect("calls");
        calls.last().map(Call::text).unwrap_or_default()
    }

    /// Every body this server was sent, joined.
    fn bodies(&self) -> String {
        self.calls
            .lock()
            .expect("calls")
            .iter()
            .map(Call::text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Waits until the server has seen `count` requests.
    async fn wait_for(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.requests() < count {
            assert!(
                Instant::now() < deadline,
                "{} requests, wanted {count}",
                self.requests()
            );
            sleep(Duration::from_millis(20)).await;
        }
    }
}

fn header_of<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(": ")?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let at = rest.windows(2).position(|window| window == b"\r\n")?;
        let size = usize::from_str_radix(String::from_utf8_lossy(&rest[..at]).trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        let end = at + 2 + size;
        if rest.len() < end + 2 {
            return None;
        }
        out.extend_from_slice(&rest[at + 2..end]);
        rest = &rest[end + 2..];
    }
}

async fn serve(mut stream: TcpStream, handler: Arc<Handler>, calls: Arc<Mutex<Vec<Call>>>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end + 4]).into_owned();
            let chunked = header_of(&head, "transfer-encoding")
                .is_some_and(|value| value.eq_ignore_ascii_case("chunked"));
            let length: usize = header_of(&head, "content-length")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let body = loop {
                let rest = &seen[end + 4..];
                if chunked {
                    if let Some(body) = dechunk(rest) {
                        break body;
                    }
                } else if rest.len() >= length {
                    break rest[..length].to_vec();
                }
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => seen.extend_from_slice(&chunk[..read]),
                }
            };
            let call = Call { head, body };
            let reply = handler(&call);
            calls.lock().expect("calls").push(call);
            let bytes = match reply {
                Reply::Raw(bytes) => bytes,
                Reply::Delay(pause, bytes) => {
                    sleep(pause).await;
                    bytes
                }
            };
            drop(stream.write_all(&bytes).await);
            drop(stream.shutdown().await);
            return;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// An upstream that answers every request `200` with `body` as JSON.
async fn echoing(body: &'static str) -> Server {
    Server::start(move |_| json_reply(200, body)).await
}

/// An `h2c://` upstream that answers `200` with `pieces` as separate DATA frames.
async fn h2c_upstream(
    status: u16,
    content_type: &'static str,
    pieces: Vec<bytes::Bytes>,
) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let pieces = pieces.clone();
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(stream).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let pieces = pieces.clone();
                    let recorded = Arc::clone(&recorded);
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        let mut got = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            got.extend_from_slice(&chunk);
                            drop(body.flow_control().release_capacity(chunk.len()));
                        }
                        recorded.lock().expect("recorded").push(got);
                        let head = http::Response::builder()
                            .status(status)
                            .header("content-type", content_type)
                            .body(())
                            .expect("response");
                        let Ok(mut send) = respond.send_response(head, false) else {
                            return;
                        };
                        for piece in pieces {
                            if send.send_data(piece, false).is_err() {
                                return;
                            }
                            sleep(Duration::from_millis(5)).await;
                        }
                        drop(send.send_data(bytes::Bytes::new(), true));
                    });
                }
            });
        }
    });
    (addr, seen)
}

// ---------------------------------------------------------------------------------------
// The proxy side
// ---------------------------------------------------------------------------------------

fn rule(name: &str, pattern: &str, action: &str, phase: &str, category: &str) -> Value {
    json!({"name": name, "pattern": pattern, "action": action, "phase": phase, "category": category})
}

/// `ann@example.com` becomes `[redacted:email]`.
fn email() -> Value {
    rule("email", r"[a-z]+@[a-z]+\.com", "redact", "both", "pii")
}

/// A social security number blocks.
fn ssn() -> Value {
    rule("ssn", r"\d{3}-\d{2}-\d{4}", "block", "both", "ssn")
}

fn site(id: &str, host: &str, upstream: SocketAddr, config: &Value) -> Value {
    with_middleware(
        app(id, &[host], &[serving("r1", upstream)]),
        "guard",
        "content_guard",
        config.clone(),
    )
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{response:?}");
}

/// What a raw exchange with the proxy returned.
struct Answer {
    status: u16,
    head: String,
    body: Vec<u8>,
    /// Every byte the proxy sent.
    wire: Vec<u8>,
}

impl Answer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {:?}", self.text()))
    }

    fn header(&self, name: &str) -> Option<&str> {
        header_of(&self.head, name)
    }

    fn wire_text(&self) -> String {
        String::from_utf8_lossy(&self.wire).into_owned()
    }
}

fn parse(wire: Vec<u8>) -> Answer {
    let end = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(wire.len(), |end| end + 4);
    let head = String::from_utf8_lossy(&wire[..end]).into_owned();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let mut body = wire[end..].to_vec();
    if header_of(&head, "transfer-encoding").is_some_and(|value| value.contains("chunked")) {
        body = dechunk(&body).unwrap_or_default();
    }
    Answer {
        status,
        head,
        body,
        wire,
    }
}

/// Sends `request` (every byte as given) to the proxy and reads until the connection ends.
async fn send(podgate: &Podgate, request: &[u8]) -> Answer {
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect to the proxy");
    stream.write_all(request).await.expect("send");
    let mut wire = Vec::new();
    timeout(Duration::from_secs(15), stream.read_to_end(&mut wire))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "no answer to {}",
                String::from_utf8_lossy(&request[..request.len().min(300)])
            )
        })
        .expect("read the answer");
    parse(wire)
}

/// Like [`send`] for a request that asks for an upgrade, whose connection the proxy keeps open: reads
/// until the answer has gone quiet.
async fn send_brief(podgate: &Podgate, request: &[u8]) -> Answer {
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect to the proxy");
    stream.write_all(request).await.expect("send");
    let mut wire = Vec::new();
    let mut chunk = vec![0_u8; 4096];
    while let Ok(Ok(read)) = timeout(Duration::from_millis(1500), stream.read(&mut chunk)).await {
        if read == 0 {
            break;
        }
        wire.extend_from_slice(&chunk[..read]);
    }
    parse(wire)
}

/// `POST path` with `headers` (lines without the line end) and `body`, with a `Content-Length`.
async fn post_with(
    podgate: &Podgate,
    host: &str,
    path: &str,
    headers: &[&str],
    body: &[u8],
) -> Answer {
    let mut request = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for line in headers {
        request.push_str(line);
        request.push_str("\r\n");
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    send(podgate, &bytes).await
}

async fn post_json(podgate: &Podgate, host: &str, body: &str) -> Answer {
    post_with(
        podgate,
        host,
        "/",
        &["Content-Type: application/json"],
        body.as_bytes(),
    )
    .await
}

/// A chunked `POST` whose body is sent in `pieces`.
async fn post_chunked(podgate: &Podgate, host: &str, pieces: &[&[u8]]) -> Answer {
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    for piece in pieces {
        request.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        request.extend_from_slice(piece);
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"0\r\n\r\n");
    send(podgate, &request).await
}

async fn get(podgate: &Podgate, host: &str, path: &str) -> Answer {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    send(podgate, request.as_bytes()).await
}

fn blocked(category: &str) -> Value {
    json!({"error": "blocked by content guard", "category": category})
}

// ---------------------------------------------------------------------------------------
// Rules: block and redact
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn content_guard_block_rule() {
    let podgate = Podgate::start().await;
    let up = echoing(r#"{"ok":true}"#).await;
    let config = json!({"rules": [ssn()]});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, &config)]),
    )
    .await;

    let answer = post_json(&podgate, "a.test", r#"{"note": "my ssn is 123-45-6789"}"#).await;
    assert_eq!(answer.status, 403, "{}", answer.wire_text());
    assert_eq!(answer.json(), blocked("ssn"));
    assert!(
        !answer.wire_text().contains("123-45"),
        "{}",
        answer.wire_text()
    );
    assert_eq!(up.requests(), 0, "the upstream was never dialled");

    let clean = r#"{"note": "nothing to see"}"#;
    let passed = post_json(&podgate, "a.test", clean).await;
    assert_eq!(passed.status, 200, "{}", passed.wire_text());
    assert_eq!(
        up.last_text(),
        clean,
        "a clean body goes through byte for byte"
    );
}

#[tokio::test]
async fn content_guard_redact_rule() {
    let podgate = Podgate::start().await;
    let up = echoing(r#"{"ok":true}"#).await;
    let config = json!({"rules": [email()]});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, &config)]),
    )
    .await;

    let sent = "{ \"to\": \"ann@example.com\",  \"n\": 12345678901234567890123456, \"msg\": \"hi\\u00e9\" }";
    let wanted = "{ \"to\": \"[redacted:email]\",  \"n\": 12345678901234567890123456, \"msg\": \"hi\\u00e9\" }";

    let declared = post_json(&podgate, "a.test", sent).await;
    assert_eq!(declared.status, 200, "{}", declared.wire_text());
    assert_eq!(up.with(0, Call::text), wanted);
    assert_eq!(
        up.with(0, |call| call.header("content-length").map(str::to_owned)),
        Some(wanted.len().to_string()),
        "the upstream is told the redacted length"
    );
    assert_eq!(
        up.with(0, |call| call
            .header("transfer-encoding")
            .map(str::to_owned)),
        None
    );

    let chunked = post_chunked(
        &podgate,
        "a.test",
        &[&sent.as_bytes()[..20], &sent.as_bytes()[20..]],
    )
    .await;
    assert_eq!(chunked.status, 200, "{}", chunked.wire_text());
    assert_eq!(up.with(1, Call::text), wanted);
    assert_eq!(
        up.with(1, |call| call.header("content-length").map(str::to_owned)),
        Some(wanted.len().to_string())
    );
    assert_eq!(
        up.with(1, |call| call
            .header("transfer-encoding")
            .map(str::to_owned)),
        None
    );
}

#[tokio::test]
async fn content_guard_redact_keeps_json_valid_end_to_end() {
    let podgate = Podgate::start().await;
    let up = echoing(r#"{"ok":true}"#).await;
    let config = json!({"rules": [email()]});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, &config)]),
    )
    .await;
    let sent = json!({"list": ["ann@example.com", "x \"q\" bob@site.com y", 7, null],
                      "nested": {"deep": {"k": "carl@home.com"}}})
    .to_string();
    assert_eq!(post_json(&podgate, "a.test", &sent).await.status, 200);
    let received = up.with(0, Call::json);
    assert_eq!(
        received,
        json!({"list": ["[redacted:email]", "x \"q\" [redacted:email] y", 7, null],
               "nested": {"deep": {"k": "[redacted:email]"}}})
    );
}

// ---------------------------------------------------------------------------------------
// The response phase
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn content_guard_response_redact() {
    let podgate = Podgate::start().await;
    let body = r#"{"user": "ann@example.com", "n": 1}"#;
    let up = Server::start(move |_| json_reply(200, body)).await;
    let config = json!({"rules": [email()]});
    let a = site("a", "a.test", up.addr, &config);
    let squeezed = with_middleware(
        site("z", "z.test", up.addr, &config),
        "squeeze",
        "compress",
        json!({"min_bytes": 1, "algorithms": ["zstd"]}),
    );
    push(&podgate, &snapshot(1, &[a, squeezed])).await;

    let wanted = r#"{"user": "[redacted:email]", "n": 1}"#;
    let answer = get(&podgate, "a.test", "/").await;
    assert_eq!(answer.status, 200, "{}", answer.wire_text());
    assert_eq!(answer.text(), wanted);
    assert_eq!(
        answer.header("content-length"),
        Some(wanted.len().to_string().as_str()),
        "{}",
        answer.head
    );
    assert!(
        !answer.wire_text().contains("ann@"),
        "{}",
        answer.wire_text()
    );

    // The compressor runs after the guard, on the redacted answer.
    let request =
        "GET / HTTP/1.1\r\nHost: z.test\r\nAccept-Encoding: zstd\r\nConnection: close\r\n\r\n";
    let squeezed = send(&podgate, request.as_bytes()).await;
    assert_eq!(squeezed.status, 200, "{}", squeezed.wire_text());
    assert_eq!(
        squeezed.header("content-encoding"),
        Some("zstd"),
        "{}",
        squeezed.head
    );
    let plain = zstd::stream::decode_all(&squeezed.body[..]).expect("valid zstd");
    assert_eq!(String::from_utf8_lossy(&plain), wanted);
    let upstream_head = up.with(1, |call| call.head.to_ascii_lowercase());
    assert!(
        !upstream_head.contains("accept-encoding"),
        "the upstream answers in the clear so the rules can read it: {upstream_head}"
    );
}

#[tokio::test]
async fn content_guard_response_block() {
    let podgate = Podgate::start().await;
    let secret = r#"{"card": "123-45-6789", "pad": "LEAKED-BYTES"}"#;
    let up = Server::start(move |_| json_reply(200, secret)).await;
    let (h2c, _) = h2c_upstream(
        200,
        "application/json",
        vec![bytes::Bytes::from(secret.as_bytes().to_vec())],
    )
    .await;
    let config = json!({"rules": [ssn()]});
    let mut over_h2c = site("h", "h.test", h2c, &config);
    over_h2c["revisions"] = json!([{
        "id": "r1", "state": "serving", "weight": 100,
        "services": [{"name": "web", "type": "loadbalancer",
                      "servers": [{"url": format!("h2c://{h2c}")}]}],
    }]);
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, &config), over_h2c]),
    )
    .await;

    for host in ["a.test", "h.test"] {
        let answer = get(&podgate, host, "/").await;
        assert_eq!(answer.status, 403, "{host}: {}", answer.wire_text());
        assert_eq!(answer.json(), blocked("ssn"));
        let wire = answer.wire_text();
        assert!(
            !wire.contains("123-45") && !wire.contains("LEAKED"),
            "{host}: no byte of the answer reached the client: {wire}"
        );
        assert_eq!(
            wire.matches("HTTP/1.1").count(),
            1,
            "{host}: one response head: {wire}"
        );
    }
    assert_eq!(
        up.requests(),
        1,
        "the upstream was asked: the request passed"
    );
}

// ---------------------------------------------------------------------------------------
// Bodies that cannot be scanned
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn content_guard_non_json_refused() {
    let podgate = Podgate::start().await;
    let up = Server::start(|call| {
        let path = call.head.split(' ').nth(1).unwrap_or("/").to_owned();
        match path.as_str() {
            "/text" => Reply::Raw(http(200, "text/plain", "", b"just text")),
            "/gzip" => Reply::Raw(http(
                200,
                "application/json",
                "Content-Encoding: gzip\r\n",
                b"\x1f\x8b",
            )),
            "/bad" => Reply::Raw(http(200, "application/json", "", b"{\"a\": ")),
            _ => json_reply(200, r#"{"ok":true}"#),
        }
    })
    .await;
    let config = json!({"rules": [email()]});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, &config)]),
    )
    .await;

    let cases: [(&[&str], &[u8], u16); 6] = [
        (&["Content-Type: text/plain"], br#"{"a":1}"#, 415),
        (
            &["Content-Type: application/json", "Content-Encoding: gzip"],
            b"\x1f\x8b\x08\x00",
            415,
        ),
        (&["Content-Type: application/grpc"], b"\0\0\0\0\x01x", 415),
        (&[], br#"{"a":1}"#, 415),
        (&["Content-Type: application/json"], b"{\"a\": ", 400),
        (&["Content-Type: application/json"], b"[\"\xff\xfe\"]", 400),
    ];
    for (headers, body, status) in cases {
        let answer = post_with(&podgate, "a.test", "/", headers, body).await;
        assert_eq!(answer.status, status, "{headers:?}: {}", answer.wire_text());
    }
    let upgrade = "GET / HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let answer = send_brief(&podgate, upgrade.as_bytes()).await;
    assert_eq!(
        answer.status,
        415,
        "a tunnel cannot be scanned: {}",
        answer.wire_text()
    );
    assert_eq!(up.requests(), 0, "none of them reached the upstream");

    // Nothing to scan is not refused.
    assert_eq!(get(&podgate, "a.test", "/").await.status, 200);

    // The same on the way back.
    for path in ["/text", "/gzip", "/bad"] {
        let answer = get(&podgate, "a.test", path).await;
        assert_eq!(answer.status, 502, "{path}: {}", answer.wire_text());
        assert_eq!(
            answer.json(),
            json!({"error": "upstream response cannot be scanned"})
        );
        assert!(
            !answer.wire_text().contains("just text"),
            "{}",
            answer.wire_text()
        );
    }
}

#[tokio::test]
async fn content_guard_switching_protocols_response_is_refused() {
    let podgate = Podgate::start().await;
    let up = Server::start(|_| {
        Reply::Raw(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                .to_vec(),
        )
    })
    .await;
    // Only the response phase is judged, so the handshake itself is let by.
    let config =
        json!({"rules": [rule("email", r"[a-z]+@[a-z]+\.com", "redact", "response", "pii")]});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, &config)]),
    )
    .await;
    let upgrade = "GET / HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let answer = send_brief(&podgate, upgrade.as_bytes()).await;
    assert_eq!(answer.status, 502, "{}", answer.wire_text());
}

#[tokio::test]
async fn content_guard_over_cap_refused() {
    let podgate = Podgate::start().await;
    let big = "x".repeat(3000);
    let up = Server::start({
        let big = big.clone();
        move |call| {
            let path = call.head.split(' ').nth(1).unwrap_or("/").to_owned();
            match path.as_str() {
                "/declared" => json_reply(200, &format!(r#"{{"pad": "{big}"}}"#)),
                "/chunked" => {
                    let piece = format!(r#"{{"pad": "{}"#, "y".repeat(800));
                    let more = "z".repeat(800);
                    chunked_reply(
                        "application/json",
                        &[piece.as_bytes(), more.as_bytes(), more.as_bytes(), b"\"}"],
                    )
                }
                _ => json_reply(200, r#"{"ok":true}"#),
            }
        }
    })
    .await;
    let config = json!({"rules": [email()], "max_body_bytes": 1024});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, &config)]),
    )
    .await;

    let body = format!(r#"{{"pad": "{big}"}}"#);
    let declared = post_json(&podgate, "a.test", &body).await;
    assert_eq!(declared.status, 413, "{}", declared.wire_text());
    let expecting = format!(
        "POST / HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let expected = send(&podgate, expecting.as_bytes()).await;
    assert_eq!(expected.status, 417, "{}", expected.wire_text());
    let pieces = [
        br#"{"pad": ""#.as_slice(),
        &[b'a'; 700],
        &[b'a'; 700],
        b"\"}",
    ];
    let chunked = post_chunked(&podgate, "a.test", &pieces).await;
    assert_eq!(chunked.status, 413, "{}", chunked.wire_text());
    assert_eq!(up.requests(), 0);

    for path in ["/declared", "/chunked"] {
        let answer = get(&podgate, "a.test", path).await;
        assert_eq!(answer.status, 502, "{path}: {}", answer.wire_text());
        assert_eq!(answer.wire_text().matches("HTTP/1.1").count(), 1, "{path}");
        assert!(
            !answer.wire_text().contains("zzzz")
                && !answer.wire_text().contains("yyyy")
                && !answer.wire_text().contains("xxxx"),
            "{path}: nothing of the oversized answer was sent"
        );
    }
    assert_eq!(get(&podgate, "a.test", "/small").await.status, 200);
}

// ---------------------------------------------------------------------------------------
// The classifier
// ---------------------------------------------------------------------------------------

/// A temp file that is removed when it goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    fn write(name: &str, contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-content-guard-{name}-{}-{}.json",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("write");
        Self(path)
    }

    fn text(&self) -> &str {
        self.0.to_str().expect("utf-8")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(std::fs::remove_file(&self.0));
    }
}

fn allow() -> Reply {
    json_reply(200, r#"{"verdict":"allow"}"#)
}

/// A classifier that blocks text with `toxic` in it, with a category when asked.
async fn classifier(category: Option<&'static str>) -> Server {
    Server::start(move |call| {
        let text = call.json()["text"].as_str().unwrap_or_default().to_owned();
        if text.contains("toxic") {
            let mut verdict = json!({"verdict": "block", "reason": format!("said: {text}")});
            if let Some(category) = category {
                verdict["category"] = json!(category);
            }
            json_reply(200, &verdict.to_string())
        } else {
            allow()
        }
    })
    .await
}

fn entries(list: &[(&str, SocketAddr, &[&str])]) -> Scratch {
    let mut file = serde_json::Map::new();
    for (name, addr, tenants) in list {
        file.insert(
            (*name).to_owned(),
            json!({"url": format!("http://{addr}/classify"), "timeout_ms": 400, "tenants": tenants}),
        );
    }
    Scratch::write("classifiers", &Value::Object(file).to_string())
}

fn with_classifier(rules: &[Value], name: &str, extra: &Value) -> Value {
    let mut classifier = json!({"name": name});
    if let (Some(classifier), Some(extra)) = (classifier.as_object_mut(), extra.as_object()) {
        classifier.extend(extra.clone());
    }
    json!({"rules": rules, "classifier": classifier})
}

async fn start_with(file: &Scratch) -> Podgate {
    Podgate::start_with_env(&[("CONTENT_CLASSIFIERS_FILE", file.text())]).await
}

#[tokio::test]
async fn content_guard_classifier_blocks() {
    let nlp = classifier(Some("toxicity")).await;
    let bare = classifier(None).await;
    let file = entries(&[("nlp", nlp.addr, &["t1"]), ("bare", bare.addr, &["t1"])]);
    let podgate = start_with(&file).await;
    let up = Server::start(|call| {
        // An answer that only the response phase finds toxic.
        if call.text().contains("fine") {
            json_reply(200, r#"{"reply": "a fine answer"}"#)
        } else {
            json_reply(200, r#"{"reply": "toxic reply"}"#)
        }
    })
    .await;
    let rules = [email()];
    push(
        &podgate,
        &snapshot(
            1,
            &[
                site(
                    "a",
                    "a.test",
                    up.addr,
                    &with_classifier(&rules, "nlp", &json!({})),
                ),
                site(
                    "b",
                    "b.test",
                    up.addr,
                    &with_classifier(&rules, "bare", &json!({"phase": "request"})),
                ),
            ],
        ),
    )
    .await;

    // The classifier sees the text the rules left, and a block is a content block.
    let toxic = post_json(
        &podgate,
        "a.test",
        r#"{"msg": "you are toxic", "mail": "ann@example.com"}"#,
    )
    .await;
    assert_eq!(toxic.status, 403, "{}", toxic.wire_text());
    assert_eq!(toxic.json(), blocked("toxicity"));
    assert!(
        !toxic.wire_text().contains("said"),
        "the reason stays with the operator"
    );
    assert_eq!(
        nlp.with(0, Call::json),
        json!({"phase": "request", "text": "you are toxic\n[redacted:email]"})
    );
    assert_eq!(up.requests(), 0);

    // A verdict without a category is named by the classifier.
    let bare_block = post_json(&podgate, "b.test", r#"{"msg": "toxic"}"#).await;
    assert_eq!(bare_block.json(), blocked("bare"));

    let fine = post_json(
        &podgate,
        "a.test",
        r#"{"msg": "fine", "mail": "ann@example.com"}"#,
    )
    .await;
    assert_eq!(fine.status, 200, "{}", fine.wire_text());
    assert_eq!(
        up.last_text(),
        r#"{"msg": "fine", "mail": "[redacted:email]"}"#
    );

    // The response phase asks again, about the answer, and the answer never goes out.
    let toxic_reply = post_json(&podgate, "a.test", r#"{"msg": "hello"}"#).await;
    assert_eq!(toxic_reply.status, 403, "{}", toxic_reply.wire_text());
    assert_eq!(toxic_reply.json(), blocked("toxicity"));
    assert!(!toxic_reply.wire_text().contains("toxic reply"));
    let phases: Vec<Value> = (0..nlp.requests())
        .map(|at| nlp.with(at, Call::json)["phase"].clone())
        .collect();
    assert!(phases.contains(&json!("response")), "{phases:?}");
    // `b` judges requests only: its answer is not sent anywhere.
    let before = bare.requests();
    assert_eq!(
        post_json(&podgate, "b.test", r#"{"msg": "fine"}"#)
            .await
            .status,
        200
    );
    assert_eq!(
        bare.requests(),
        before + 1,
        "one request call, no response call"
    );
}

#[tokio::test]
async fn content_guard_classifier_down_fails_closed() {
    let slow = Server::start(|_| Reply::Delay(Duration::from_secs(2), allow_bytes())).await;
    let status = Server::start(|_| json_reply(500, "{}")).await;
    let malformed = Server::start(|_| json_reply(200, "not a verdict")).await;
    let unknown = Server::start(|_| json_reply(200, r#"{"verdict":"maybe"}"#)).await;
    let dead = refused();
    let file = entries(&[
        ("dead", dead.addr, &["t1"]),
        ("slow", slow.addr, &["t1"]),
        ("status", status.addr, &["t1"]),
        ("malformed", malformed.addr, &["t1"]),
        ("unknown", unknown.addr, &["t1"]),
    ]);
    let podgate = start_with(&file).await;
    let up = echoing(r#"{"ok":true}"#).await;
    let rules = [email()];
    let mut apps: Vec<Value> = ["dead", "slow", "status", "malformed", "unknown"]
        .iter()
        .map(|name| {
            site(
                name,
                &format!("{name}.test"),
                up.addr,
                &with_classifier(&rules, name, &json!({"phase": "request"})),
            )
        })
        .collect();
    apps.push(site(
        "open",
        "open.test",
        up.addr,
        &with_classifier(
            &rules,
            "dead",
            &json!({"phase": "request", "on_error": "allow"}),
        ),
    ));
    push(&podgate, &snapshot(1, &apps)).await;

    for name in ["dead", "slow", "status", "malformed", "unknown"] {
        let answer = post_json(&podgate, &format!("{name}.test"), r#"{"msg": "hi"}"#).await;
        assert_eq!(answer.status, 503, "{name}: {}", answer.wire_text());
        assert_eq!(
            answer.json(),
            json!({"error": "guard unavailable"}),
            "{name}"
        );
    }
    assert_eq!(up.requests(), 0, "no failure let the request through");

    let open = post_json(
        &podgate,
        "open.test",
        r#"{"msg": "hi", "m": "ann@example.com"}"#,
    )
    .await;
    assert_eq!(
        open.status,
        200,
        "on_error allow lets it through: {}",
        open.wire_text()
    );
    assert_eq!(
        up.last_text(),
        r#"{"msg": "hi", "m": "[redacted:email]"}"#,
        "the rules still ran"
    );
}

fn allow_bytes() -> Vec<u8> {
    http(200, "application/json", "", br#"{"verdict":"allow"}"#)
}

#[tokio::test]
async fn content_guard_classifier_forbidden_for_tenant() {
    let nlp = classifier(None).await;
    let file = entries(&[("theirs", nlp.addr, &["t2"]), ("mine", nlp.addr, &["t1"])]);
    let podgate = start_with(&file).await;
    let up = echoing("{}").await;
    let rules = [email()];
    let refusal = |name: &str| {
        let config = with_classifier(&rules, name, &json!({}));
        let pushed = snapshot(9, &[site("a", "a.test", up.addr, &config)]);
        let podgate = &podgate;
        async move { podgate.push_snapshot(&pushed).await }
    };
    let unlisted = refusal("theirs").await;
    let unknown = refusal("nobody").await;
    for (name, response) in [("theirs", &unlisted), ("nobody", &unknown)] {
        assert_eq!(response.status, 422, "{name}: {response:?}");
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_middleware",
            "{name}"
        );
    }
    let message = |response: &common::Response, name: &str| {
        response.json()["conflicts"][0]["message"]
            .as_str()
            .unwrap_or_default()
            .replace(name, "<name>")
    };
    assert_eq!(
        message(&unlisted, "theirs"),
        message(&unknown, "nobody"),
        "a tenant cannot tell an unlisted entry from a missing one"
    );
    let config = with_classifier(&rules, "mine", &json!({}));
    push(
        &podgate,
        &snapshot(10, &[site("a", "a.test", up.addr, &config)]),
    )
    .await;
}

/// Runs `podgate` with `env`; it must stop by itself. Returns whether it failed, and stderr.
fn startup_failure(dir: &Path, env: &[(&str, &str)]) -> (bool, String) {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let admin = dir.join(format!(
        "admin-{}.sock",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_podgate"))
        .env_remove("ENTRY_POINTS")
        .env("PROXY_ADDR", "127.0.0.1:0")
        .env("ADMIN_SOCKET", &admin)
        .env("RUST_LOG", "warn")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn podgate");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll podgate") {
            break Some(status);
        }
        if Instant::now() > deadline {
            drop(child.kill());
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        std::io::Read::read_to_string(&mut pipe, &mut stderr).expect("stderr");
    }
    drop(child.wait());
    (status.is_some_and(|status| !status.success()), stderr)
}

#[test]
fn content_guard_bad_classifiers_file_stops_startup() {
    let dir = std::env::temp_dir().join(format!("podgate-cg-startup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let url = r#""url": "http://10.0.0.9/c", "tenants": ["t1"]"#;
    let cases = [
        ("not json".to_owned(), "CONTENT_CLASSIFIERS_FILE"),
        (format!(r#"{{"nlp": {{{url}, "bogus": 1}}}}"#), "bogus"),
        (format!(r#"{{"Bad Name": {{{url}}}}}"#), "Bad Name"),
        (r#"{"nlp": {"tenants": ["t1"]}}"#.to_owned(), "url"),
        (
            r#"{"nlp": {"url": "ftp://x/c", "tenants": ["t1"]}}"#.to_owned(),
            "url",
        ),
        (
            r#"{"nlp": {"url": "http://10.0.0.9/c", "tenants": []}}"#.to_owned(),
            "tenants",
        ),
        (
            format!(r#"{{"nlp": {{{url}, "timeout_ms": 0}}}}"#),
            "timeout_ms",
        ),
    ];
    for (contents, wanted) in cases {
        let file = dir.join("bad.json");
        std::fs::write(&file, &contents).expect("write");
        let (failed, stderr) = startup_failure(
            &dir,
            &[("CONTENT_CLASSIFIERS_FILE", file.to_str().expect("utf-8"))],
        );
        assert!(failed, "{contents}: podgate did not stop:\n{stderr}");
        assert!(
            stderr.contains("CONTENT_CLASSIFIERS_FILE") && stderr.contains(wanted),
            "{contents}: expected CONTENT_CLASSIFIERS_FILE and {wanted:?} in:\n{stderr}"
        );
    }
    let (failed, stderr) = startup_failure(
        &dir,
        &[("CONTENT_CLASSIFIERS_FILE", "/nonexistent/classifiers.json")],
    );
    assert!(
        failed && stderr.contains("/nonexistent/classifiers.json"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir).expect("clean up");
}

#[tokio::test]
async fn content_guard_classifier_charged_to_tenant() {
    let slow = Server::start(|_| Reply::Delay(Duration::from_millis(700), allow_bytes())).await;
    let file = Scratch::write(
        "charged",
        &json!({"slow": {"url": format!("http://{}/classify", slow.addr), "timeout_ms": 5000, "tenants": ["t1"]}})
            .to_string(),
    );
    let podgate = start_with(&file).await;
    let up = echoing("{}").await;
    let config = with_classifier(&[email()], "slow", &json!({"phase": "request"}));
    let config = {
        let mut config = config;
        config["max_body_bytes"] = json!(64);
        config
    };
    let a = site("a", "a.test", up.addr, &config);

    // Far too small a budget: the compiler says what one scan needs.
    let mut tiny = snapshot(1, std::slice::from_ref(&a));
    tiny["tenants"][0]["budget"]["max_buffer_bytes"] = json!(1000);
    let refused = podgate.push_snapshot(&tiny).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert_eq!(refused.json()["conflicts"][0]["code"], "invalid_middleware");
    let needed = refused.json()["conflicts"][0]["needed_bytes"]
        .as_u64()
        .expect("needed_bytes");
    let mut just_short = snapshot(2, std::slice::from_ref(&a));
    just_short["tenants"][0]["budget"]["max_buffer_bytes"] = json!(needed - 1);
    assert_eq!(podgate.push_snapshot(&just_short).await.status, 422);

    // Room for one exchange and a little more: the second finds the budget full.
    let mut fits = snapshot(3, &[a]);
    fits["tenants"][0]["budget"]["max_buffer_bytes"] = json!(needed + 100);
    push(&podgate, &fits).await;
    let body = r#"{"msg": "hi"}"#;
    let (first, second) = tokio::join!(post_json(&podgate, "a.test", body), async {
        sleep(Duration::from_millis(200)).await;
        post_json(&podgate, "a.test", body).await
    });
    assert_eq!(first.status, 200, "{}", first.wire_text());
    assert_eq!(second.status, 503, "{}", second.wire_text());
    assert_eq!(second.header("retry-after"), Some("1"));
    assert_eq!(slow.requests(), 1, "the second call was never made");
    assert_eq!(up.requests(), 1);
}

#[tokio::test]
async fn content_guard_address_policy_enforced() {
    // Tenant t1 may dial 127.0.0.1 only; t2 may also dial 127.0.0.2, where the classifier is.
    let policy = Scratch::write(
        "policy",
        r#"{"deny": [], "default": {"allow": ["127.0.0.1/32"]}, "tenants": {"t2": {"allow": ["127.0.0.1/32", "127.0.0.2/32"]}}}"#,
    );
    let nlp = Server::start_on("127.0.0.2", |_| allow()).await;
    let file = entries(&[("nlp", nlp.addr, &["t1", "t2"])]);
    let podgate = Podgate::start_with_env(&[
        ("UPSTREAM_POLICY_FILE", policy.text()),
        ("CONTENT_CLASSIFIERS_FILE", file.text()),
    ])
    .await;
    let up = echoing("{}").await;
    let config = with_classifier(&[email()], "nlp", &json!({"phase": "request"}));
    let mine = site("mine", "mine.test", up.addr, &config);
    let mut theirs = site("theirs", "theirs.test", up.addr, &config);
    theirs["tenant"] = json!("t2");
    let pushed = json!({
        "version": 1,
        "tenants": [
            {"id": "t1", "weight": 1, "budget": {"max_inflight": 100, "max_buffer_bytes": 4_194_304}},
            {"id": "t2", "weight": 1, "budget": {"max_inflight": 100, "max_buffer_bytes": 4_194_304}},
        ],
        "apps": [mine, theirs],
    });
    push(&podgate, &pushed).await;

    let refused = post_json(&podgate, "mine.test", r#"{"msg": "hi"}"#).await;
    assert_eq!(refused.status, 503, "{}", refused.wire_text());
    assert_eq!(
        nlp.requests(),
        0,
        "the policy refused the address: nothing was dialled"
    );
    assert_eq!(up.requests(), 0);
    let allowed = post_json(&podgate, "theirs.test", r#"{"msg": "hi"}"#).await;
    assert_eq!(allowed.status, 200, "{}", allowed.wire_text());
    assert_eq!(nlp.requests(), 1);
}

// ---------------------------------------------------------------------------------------
// What a match never reaches
// ---------------------------------------------------------------------------------------

async fn failures_of(podgate: &Podgate, app: &str) -> Vec<Value> {
    let response = podgate.admin_get(&format!("/v1/apps/{app}/failures")).await;
    assert_eq!(response.status, 200, "{response:?}");
    response.json()["failures"]
        .as_array()
        .expect("failures")
        .clone()
}

#[tokio::test]
async fn content_guard_match_never_logged() {
    let podgate = Podgate::start_logged(&[("RUST_LOG", "trace")]).await;
    let canary = "CANARY-9f3a1c77";
    let leaky = Server::start(move |call| {
        // An upstream that fails and echoes whatever it was sent.
        json_reply(500, &json!({"echo": call.text()}).to_string())
    })
    .await;
    let unreached = echoing("{}").await;
    let config = json!({"rules": [
        rule("canary", "CANARY-[0-9a-f]{8}", "redact", "both", "secret"),
        rule("tripwire", "TRIPWIRE-[0-9a-f]{8}", "block", "both", "tripwire"),
    ]});
    let mut redacting = site("redacting", "redacting.test", leaky.addr, &config);
    let mut blocking = site("blocking", "blocking.test", unreached.addr, &config);
    for app in [&mut redacting, &mut blocking] {
        app["record_bodies"] = json!(true);
    }
    push(&podgate, &snapshot(1, &[redacting, blocking])).await;
    let tripwire = "TRIPWIRE-5b1e90d2";

    let redacted = post_json(
        &podgate,
        "redacting.test",
        &json!({"a": format!("x {canary} y")}).to_string(),
    )
    .await;
    assert_eq!(redacted.status, 500, "{}", redacted.wire_text());
    let blocked_one = post_json(
        &podgate,
        "blocking.test",
        &json!({"a": format!("x {tripwire} y")}).to_string(),
    )
    .await;
    assert_eq!(blocked_one.status, 403, "{}", blocked_one.wire_text());
    assert!(
        leaky.bodies().contains("[redacted:canary]") && !leaky.bodies().contains(canary),
        "the upstream got the redacted body: {}",
        leaky.bodies()
    );
    for wire in [redacted.wire_text(), blocked_one.wire_text()] {
        assert!(!wire.contains(canary) && !wire.contains(tripwire), "{wire}");
    }

    let log = podgate.log();
    for value in [canary, tripwire] {
        assert!(!log.contains(value), "a log line carries {value}:\n{log}");
    }
    let metrics = podgate.admin_get("/metrics").await.body;
    for value in [canary, tripwire] {
        assert!(!metrics.contains(value), "a metric carries {value}");
    }
    for app in ["redacting", "blocking"] {
        let recorded = serde_json::to_string(&failures_of(&podgate, app).await).expect("json");
        for value in [canary, tripwire] {
            assert!(
                !recorded.contains(value),
                "{app}: the recorder kept {value}: {recorded}"
            );
        }
    }
    let recorded = failures_of(&podgate, "redacting").await;
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert!(
        recorded[0]["request_body"]
            .as_str()
            .unwrap_or_default()
            .contains("[redacted:canary]"),
        "{recorded:?}"
    );
    for app in ["redacting.test", "blocking.test"] {
        let explain = podgate
            .admin_get(&format!("/v1/explain?url=http://{app}/&method=POST"))
            .await;
        assert_eq!(explain.status, 200, "{explain:?}");
        assert!(
            !explain.body.contains(canary) && !explain.body.contains("CANARY-[0-9a-f]"),
            "explain shows a pattern or a value: {}",
            explain.body
        );
        assert!(explain.body.contains("content_guard"), "{}", explain.body);
    }
    assert_eq!(unreached.requests(), 0);
}

/// An app on `a.test` through the mirroring service `m`, whose main service `web` is on `main`
/// and whose one mirror gets every request, with `config` as its `content_guard`.
fn mirrored_site(main: Value, shadow: SocketAddr, middleware: Value, kind: &str) -> Value {
    let services = vec![
        main,
        service("shadow", &[shadow]),
        json!({"name": "m", "type": "mirroring", "service": "web",
               "mirror_body": true, "max_body_size": 4096, "mirrors": [{"service": "shadow", "percent": 100.0}]}),
    ];
    let revision = json!({"id": "r1", "state": "serving", "weight": 100, "services": services});
    let mut app = app("a", &["a.test"], &[revision]);
    app["routers"] = json!([router("default", json!({"host": ["a.test"]}), "m")]);
    app["record_bodies"] = json!(true);
    with_middleware(app, "guard", kind, middleware)
}

#[tokio::test]
async fn content_guard_recorder_and_mirror_see_redacted() {
    let podgate = Podgate::start().await;
    let up = Server::start(|_| json_reply(500, r#"{"error": "boom"}"#)).await;
    let shadow = echoing("{}").await;
    let config = json!({"rules": [email()]});
    push(
        &podgate,
        &snapshot(
            1,
            &[mirrored_site(
                service("web", &[up.addr]),
                shadow.addr,
                config,
                "content_guard",
            )],
        ),
    )
    .await;

    let sent = r#"{"to": "ann@example.com"}"#;
    let wanted = r#"{"to": "[redacted:email]"}"#;
    assert_eq!(post_json(&podgate, "a.test", sent).await.status, 500);
    assert_eq!(up.last_text(), wanted);
    shadow.wait_for(1).await;
    assert_eq!(
        shadow.last_text(),
        wanted,
        "the mirror copy is the redacted body"
    );
    assert_eq!(
        shadow.with(0, |call| call.header("content-length").map(str::to_owned)),
        Some(wanted.len().to_string())
    );
    let recorded = failures_of(&podgate, "a").await;
    assert_eq!(recorded[0]["request_body"], wanted, "{recorded:?}");
    assert!(
        !serde_json::to_string(&recorded)
            .expect("json")
            .contains("ann@")
    );
}

#[tokio::test]
async fn content_guard_replay_sends_redacted_body() {
    let nlp = Server::start(|_| allow()).await;
    let file = entries(&[("nlp", nlp.addr, &["t1"])]);
    let podgate = start_with(&file).await;
    let status = Arc::new(AtomicUsize::new(500));
    let seen = Arc::clone(&status);
    let up = Server::start(move |_| {
        json_reply(
            u16::try_from(seen.load(Ordering::SeqCst)).unwrap_or(500),
            r#"{"n":1}"#,
        )
    })
    .await;
    let mut config = with_classifier(&[email()], "nlp", &json!({"phase": "request"}));
    config["max_body_bytes"] = json!(4096);
    let mut a = site("a", "a.test", up.addr, &config);
    a["record_bodies"] = json!(true);
    push(&podgate, &snapshot(1, &[a])).await;

    let sent = r#"{"to": "ann@example.com", "pad": "xx"}"#;
    let wanted = r#"{"to": "[redacted:email]", "pad": "xx"}"#;
    assert_eq!(post_json(&podgate, "a.test", sent).await.status, 500);
    let id = failures_of(&podgate, "a").await[0]["id"]
        .as_u64()
        .expect("id");
    assert_eq!(nlp.requests(), 1);

    status.store(200, Ordering::SeqCst);
    let replayed = podgate
        .admin_post(
            &format!("/v1/apps/a/failures/{id}/replay?revision=r1&force=true"),
            &json!({}),
        )
        .await;
    assert_eq!(replayed.status, 200, "{replayed:?}");
    assert_eq!(replayed.json()["status"], 200);
    assert_eq!(up.requests(), 2);
    assert_eq!(
        up.with(1, Call::text),
        wanted,
        "the replay carries the redacted body"
    );
    assert_eq!(
        up.with(1, |call| call.header("content-length").map(str::to_owned)),
        Some(wanted.len().to_string())
    );
    assert_eq!(
        nlp.requests(),
        1,
        "a replay goes straight to the upstream: no guard runs"
    );
}

#[tokio::test]
async fn content_guard_leaves_grpc_web_mirror_unchanged() {
    let podgate = Podgate::start().await;
    let (upstream, seen) =
        h2c_upstream(500, "text/plain", vec![bytes::Bytes::from_static(b"boom")]).await;
    let shadow = echoing("{}").await;
    let mut frame = vec![0_u8, 0, 0, 0, 5];
    frame.extend_from_slice(b"hello");
    let encoded = STANDARD.encode(&frame);
    push(
        &podgate,
        &snapshot(
            1,
            &[mirrored_site(
                json!({"name": "web", "type": "loadbalancer", "servers": [{"url": format!("h2c://{upstream}")}]}),
                shadow.addr,
                json!({}),
                "grpc_web",
            )],
        ),
    )
    .await;

    let answer = post_with(
        &podgate,
        "a.test",
        "/test.Echo/Unary",
        &["Content-Type: application/grpc-web-text"],
        encoded.as_bytes(),
    )
    .await;
    assert_eq!(answer.status, 500, "{}", answer.wire_text());
    assert_eq!(
        seen.lock().expect("seen")[0],
        frame,
        "the upstream gets the decoded frame"
    );
    shadow.wait_for(1).await;
    assert_eq!(
        shadow.last_text(),
        encoded,
        "the mirror copy is what the client sent, as it was before content_guard existed"
    );
    let recorded = failures_of(&podgate, "a").await;
    assert_eq!(recorded[0]["request_body"], encoded, "{recorded:?}");
}

#[tokio::test]
async fn content_guard_recorder_keeps_nothing_of_blocked_response() {
    let podgate = Podgate::start().await;
    let up = Server::start(|call| {
        let path = call.head.split(' ').nth(1).unwrap_or("/").to_owned();
        match path.as_str() {
            "/blocked" => json_reply(500, r#"{"card": "123-45-6789", "UPSTREAM-SECRET": 1}"#),
            _ => Reply::Raw(http(500, "text/plain", "", b"UPSTREAM-SECRET page")),
        }
    })
    .await;
    let config = json!({"rules": [ssn()]});
    let mut a = site("a", "a.test", up.addr, &config);
    a["record_bodies"] = json!(true);
    push(&podgate, &snapshot(1, &[a])).await;

    // A blocked 5xx is a 403 podgate wrote: not a failure, and nothing of it is kept.
    let blocked_one = get(&podgate, "a.test", "/blocked").await;
    assert_eq!(blocked_one.status, 403, "{}", blocked_one.wire_text());
    assert!(failures_of(&podgate, "a").await.is_empty());
    // An unscannable 5xx is a 502 podgate wrote: recorded with podgate's own body.
    let unscannable = get(&podgate, "a.test", "/page").await;
    assert_eq!(unscannable.status, 502, "{}", unscannable.wire_text());
    let recorded = serde_json::to_string(&failures_of(&podgate, "a").await).expect("json");
    assert!(recorded.contains("502"), "{recorded}");
    assert!(
        !recorded.contains("UPSTREAM-SECRET") && !recorded.contains("123-45"),
        "the recorder kept the upstream's answer: {recorded}"
    );
}

#[tokio::test]
async fn content_guard_cache_stores_only_guarded_answers() {
    let podgate = Podgate::start().await;
    let up = Server::start(|call| {
        let path = call.head.split(' ').nth(1).unwrap_or("/").to_owned();
        let body = if path == "/flagged" {
            r#"{"card": "123-45-6789"}"#
        } else {
            r#"{"user": "ann@example.com"}"#
        };
        Reply::Raw(http(
            200,
            "application/json",
            "Cache-Control: max-age=60\r\n",
            body.as_bytes(),
        ))
    })
    .await;
    let config = json!({"rules": [email(), ssn()]});
    let a = with_middleware(
        site("a", "a.test", up.addr, &config),
        "store",
        "cache",
        json!({}),
    );
    push(&podgate, &snapshot(1, &[a])).await;

    let first = get(&podgate, "a.test", "/page").await;
    assert_eq!(first.text(), r#"{"user": "[redacted:email]"}"#);
    let second = get(&podgate, "a.test", "/page").await;
    assert_eq!(second.status, 200, "{}", second.wire_text());
    assert_eq!(
        second.text(),
        first.text(),
        "a hit serves the redacted copy"
    );
    assert_eq!(up.requests(), 1, "the second request was a cache hit");

    // A blocked answer is not stored: the next request asks the upstream again.
    assert_eq!(get(&podgate, "a.test", "/flagged").await.status, 403);
    assert_eq!(get(&podgate, "a.test", "/flagged").await.status, 403);
    assert_eq!(up.requests(), 3);
}
