//! The `llm_guard` middleware, end to end on the real binary: guards called in
//! parallel, a block is `403` and never reaches the model, every way a guard can fail closes the
//! door, the answer is judged before any byte of it reaches the client, and what is held is
//! bounded and charged. The pure rules (verdict parser, text extraction, config limits,
//! posture) are unit-tested in `src/middleware/guard.rs` and `src/middleware/llm_guard.rs`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Podgate, app, refused, serving, snapshot, with_middleware};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

/// What a test server answers with.
enum Reply {
    /// These bytes, then the connection closes.
    Raw(Vec<u8>),
    /// These bytes after a pause, unless the peer hangs up first.
    Delay(Duration, Vec<u8>),
}

fn raw(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn verdict(text: &str) -> Reply {
    Reply::Raw(raw(200, text))
}

fn allow() -> Reply {
    verdict(r#"{"verdict":"allow"}"#)
}

fn block(category: &str, reason: &str) -> Reply {
    verdict(&json!({"verdict": "block", "category": category, "reason": reason}).to_string())
}

/// What a test server saw.
struct Call {
    head: String,
    body: String,
}

impl Call {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    /// The `text` a guard was asked about.
    fn text(&self) -> String {
        self.json()["text"].as_str().unwrap_or_default().to_owned()
    }
}

type Handler = dyn Fn(&Call) -> Reply + Send + Sync;

/// A server that records each request and answers by `handler`.
struct Server {
    addr: SocketAddr,
    calls: Arc<Mutex<Vec<Call>>>,
    /// Connections the peer closed before the answer was sent.
    hung_up: Arc<AtomicUsize>,
}

impl Server {
    async fn start(handler: impl Fn(&Call) -> Reply + Send + Sync + 'static) -> Self {
        Self::start_on("127.0.0.1", handler).await
    }

    async fn start_on(ip: &str, handler: impl Fn(&Call) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind(format!("{ip}:0")).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let hung_up = Arc::new(AtomicUsize::new(0));
        let handler: Arc<Handler> = Arc::new(handler);
        let (shared_calls, shared_hung) = (Arc::clone(&calls), Arc::clone(&hung_up));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(
                    stream,
                    Arc::clone(&handler),
                    Arc::clone(&shared_calls),
                    Arc::clone(&shared_hung),
                ));
            }
        });
        Self {
            addr,
            calls,
            hung_up,
        }
    }

    fn requests(&self) -> usize {
        self.calls.lock().expect("calls").len()
    }

    fn head(&self, index: usize) -> String {
        self.calls.lock().expect("calls")[index].head.clone()
    }

    /// Every body this server was sent, joined.
    fn bodies(&self) -> String {
        self.calls
            .lock()
            .expect("calls")
            .iter()
            .map(|call| call.body.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn hung_up(&self) -> usize {
        self.hung_up.load(Ordering::SeqCst)
    }
}

async fn serve(
    mut stream: TcpStream,
    handler: Arc<Handler>,
    calls: Arc<Mutex<Vec<Call>>>,
    hung_up: Arc<AtomicUsize>,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end + 4]).into_owned();
            let length: usize = header_of(&head, "content-length")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            while seen.len() < end + 4 + length {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => seen.extend_from_slice(&chunk[..read]),
                }
            }
            let body = String::from_utf8_lossy(&seen[end + 4..end + 4 + length]).into_owned();
            let call = Call { head, body };
            let reply = handler(&call);
            calls.lock().expect("calls").push(call);
            let bytes = match reply {
                Reply::Raw(bytes) => bytes,
                Reply::Delay(pause, bytes) => {
                    let mut probe = [0_u8; 1];
                    tokio::select! {
                        () = sleep(pause) => bytes,
                        // The request is fully read, so anything the peer does now is a hang-up.
                        _ = stream.read(&mut probe) => {
                            hung_up.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                    }
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

fn header_of<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(": ")?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

/// A chat completion with `text` as the assistant's answer.
fn completion(text: &str) -> String {
    json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": text}}]})
        .to_string()
}

/// The model: answers every request with a completion saying `ANSWER`.
async fn model() -> Server {
    Server::start(|_| Reply::Raw(raw(200, &completion("ANSWER")))).await
}

fn chat(prompt: &str) -> String {
    json!({"model": "m", "messages": [{"role": "user", "content": prompt}]}).to_string()
}

/// A guard entry of the middleware's config.
fn guard(name: &str, addr: SocketAddr, extra: &Value) -> Value {
    let mut entry = json!({"name": name, "address": format!("http://{addr}/check")});
    if let (Some(entry), Some(extra)) = (entry.as_object_mut(), extra.as_object()) {
        entry.extend(extra.clone());
    }
    entry
}

fn site(id: &str, host: &str, upstream: SocketAddr, guards: &[Value], extra: &Value) -> Value {
    let mut config = json!({ "guards": guards });
    if let (Some(config), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
        config.extend(extra.clone());
    }
    with_middleware(
        app(id, &[host], &[serving("r1", upstream)]),
        "safety",
        "llm_guard",
        config,
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
    body: String,
    /// Every byte the proxy sent.
    wire: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {:?}", self.body))
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
        body = dechunk(&body);
    }
    Answer {
        status,
        head,
        body: String::from_utf8_lossy(&body).into_owned(),
        wire,
    }
}

fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(at) = rest.windows(2).position(|window| window == b"\r\n") {
        let size =
            usize::from_str_radix(String::from_utf8_lossy(&rest[..at]).trim(), 16).unwrap_or(0);
        if size == 0 || rest.len() < at + 2 + size {
            break;
        }
        out.extend_from_slice(&rest[at + 2..at + 2 + size]);
        rest = &rest[(at + 2 + size + 2).min(rest.len())..];
    }
    out
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
        .expect("an answer in time")
        .expect("read the answer");
    parse(wire)
}

async fn post(podgate: &Podgate, host: &str, path: &str, body: &str) -> Answer {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    send(podgate, request.as_bytes()).await
}

fn assert_closed(answer: &Answer) {
    assert_eq!(answer.status, 503, "{}", answer.wire_text());
    assert_eq!(answer.body, r#"{"error":"guard unavailable"}"#);
}

#[tokio::test]
async fn guard_allow_reaches_the_model_with_the_documented_call() {
    let podgate = Podgate::start().await;
    let (up, g) = (model().await, Server::start(|_| allow()).await);
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                &[guard("g1", g.addr, &Value::Null)],
                &Value::Null,
            )],
        ),
    )
    .await;
    let prompt = json!({"model": "m", "stream": false, "messages": [
        {"role": "system", "content": "be brief"},
        {"role": "user", "content": [{"type": "text", "text": "hello"}, {"type": "image_url", "image_url": {"url": "http://x/y"}}]},
    ]})
    .to_string();

    let answer = post(&podgate, "a.test", "/v1/chat/completions", &prompt).await;
    assert_eq!(answer.status, 200, "{}", answer.wire_text());
    assert!(answer.body.contains("ANSWER"), "{}", answer.body);
    assert_eq!(up.requests(), 1);
    assert_eq!(
        up.calls.lock().expect("calls")[0].body,
        prompt,
        "the model gets the held body untouched"
    );
    assert_eq!(g.requests(), 1);
    let head = g.head(0);
    assert!(head.starts_with("POST /check HTTP/1.1\r\n"), "{head}");
    assert_eq!(header_of(&head, "content-type"), Some("application/json"));
    let call = g.calls.lock().expect("calls")[0].json();
    assert_eq!(call, json!({"phase": "request", "text": "be brief\nhello"}));
}

#[tokio::test]
async fn guard_calls_run_in_parallel() {
    let podgate = Podgate::start().await;
    let up = model().await;
    let slow = || {
        Server::start(|_| {
            Reply::Delay(
                Duration::from_millis(300),
                raw(200, r#"{"verdict":"allow"}"#),
            )
        })
    };
    let (a, b, c) = (slow().await, slow().await, slow().await);
    let guards = [
        guard("g1", a.addr, &Value::Null),
        guard("g2", b.addr, &Value::Null),
        guard("g3", c.addr, &Value::Null),
    ];
    let plain = app("plain", &["plain.test"], &[serving("r1", up.addr)]);
    push(
        &podgate,
        &snapshot(
            1,
            &[site("a", "a.test", up.addr, &guards, &Value::Null), plain],
        ),
    )
    .await;
    // Warm both routes, then compare a guarded request with an unguarded one.
    post(&podgate, "plain.test", "/", &chat("hi")).await;
    let start = Instant::now();
    post(&podgate, "plain.test", "/", &chat("hi")).await;
    let baseline = start.elapsed();

    let start = Instant::now();
    let answer = post(&podgate, "a.test", "/", &chat("hi")).await;
    let guarded = start.elapsed();
    assert_eq!(answer.status, 200, "{}", answer.wire_text());
    assert_eq!((a.requests(), b.requests(), c.requests()), (1, 1, 1));
    let added = guarded.saturating_sub(baseline);
    assert!(
        added < Duration::from_millis(450),
        "three 300 ms guards added {added:?}, sequential would be 900 ms"
    );
    assert!(
        added >= Duration::from_millis(250),
        "the guards really ran: {added:?}"
    );
}

#[tokio::test]
async fn guard_block_is_403() {
    let podgate = Podgate::start().await;
    let (up, g) = (
        model().await,
        Server::start(|_| block("violence", "rule 7 of the policy")).await,
    );
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                &[guard("g1", g.addr, &Value::Null)],
                &Value::Null,
            )],
        ),
    )
    .await;

    let answer = post(
        &podgate,
        "a.test",
        "/v1/chat/completions",
        &chat("do something bad"),
    )
    .await;
    assert_eq!(answer.status, 403, "{}", answer.wire_text());
    assert_eq!(
        answer.json(),
        json!({"error": "blocked by guard", "category": "violence"})
    );
    assert_eq!(up.requests(), 0, "the model never saw the request");
}

#[tokio::test]
async fn guard_block_hides_reason() {
    let podgate = Podgate::start().await;
    let (up, g) = (
        model().await,
        Server::start(|_| block("violence", "rule 7 of the policy")).await,
    );
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                &[guard("g1", g.addr, &Value::Null)],
                &Value::Null,
            )],
        ),
    )
    .await;

    let answer = post(&podgate, "a.test", "/", &chat("do something bad")).await;
    assert_eq!(answer.status, 403);
    let wire = answer.wire_text();
    assert!(
        !wire.contains("rule 7"),
        "the reason is for the log only: {wire}"
    );
    assert!(!wire.contains("policy"), "{wire}");
}

#[tokio::test]
async fn guard_first_block_cancels_rest() {
    let podgate = Podgate::start().await;
    let up = model().await;
    let blocker = Server::start(|_| {
        Reply::Delay(
            Duration::from_millis(50),
            raw(200, r#"{"verdict":"block","category":"pii"}"#),
        )
    })
    .await;
    let slow =
        Server::start(|_| Reply::Delay(Duration::from_secs(4), raw(200, r#"{"verdict":"allow"}"#)))
            .await;
    let guards = [
        guard("fast", blocker.addr, &Value::Null),
        guard("slow", slow.addr, &Value::Null),
    ];
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                &guards,
                &json!({"timeout_ms": 10000}),
            )],
        ),
    )
    .await;

    let start = Instant::now();
    let answer = post(&podgate, "a.test", "/", &chat("my ssn")).await;
    assert_eq!(answer.status, 403, "{}", answer.wire_text());
    assert_eq!(answer.json()["category"], "pii");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(up.requests(), 0);
    for _ in 0..40 {
        if slow.hung_up() == 1 {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("the slow guard's connection was never closed by podgate");
}

#[tokio::test]
async fn guard_down_fails_closed() {
    let podgate = Podgate::start().await;
    let up = model().await;
    let dead = refused();
    let hung =
        Server::start(|_| Reply::Delay(Duration::from_secs(5), raw(200, r#"{"verdict":"allow"}"#)))
            .await;
    let errors = Server::start(|_| Reply::Raw(raw(500, r#"{"verdict":"allow"}"#))).await;
    let not_json = Server::start(|_| verdict("allow")).await;
    let huge = Server::start(|_| {
        verdict(&format!(
            r#"{{"verdict":"allow","reason":"{}"}}"#,
            "x".repeat(8000)
        ))
    })
    .await;
    let redirect = Server::start(|_| Reply::Raw(b"HTTP/1.1 302 X\r\nLocation: http://x/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec())).await;
    let cases: [(&str, SocketAddr); 6] = [
        ("dead", dead.addr),
        ("hung", hung.addr),
        ("errors", errors.addr),
        ("not-json", not_json.addr),
        ("huge", huge.addr),
        ("redirect", redirect.addr),
    ];
    let apps: Vec<Value> = cases
        .iter()
        .map(|(name, addr)| {
            site(
                name,
                &format!("{name}.test"),
                up.addr,
                &[guard("g1", *addr, &Value::Null)],
                &json!({"timeout_ms": 400}),
            )
        })
        .collect();
    push(&podgate, &snapshot(1, &apps)).await;

    for (name, _) in cases {
        let answer = post(&podgate, &format!("{name}.test"), "/", &chat("hello")).await;
        assert_closed(&answer);
        assert_eq!(
            answer.header("retry-after"),
            None,
            "{name}: a broken guard is not a capacity refusal"
        );
    }
    assert_eq!(up.requests(), 0, "no request reached the model");
}

#[tokio::test]
async fn guard_unknown_verdict_fails_closed() {
    let podgate = Podgate::start().await;
    let up = model().await;
    let replies = [
        ("maybe", r#"{"verdict":"maybe"}"#),
        ("upper", r#"{"verdict":"ALLOW"}"#),
        ("extra", r#"{"verdict":"allow","score":0.1}"#),
        ("empty", r"{}"),
        ("array", r"[]"),
        (
            "badcategory",
            r#"{"verdict":"block","category":"Not A Label"}"#,
        ),
    ];
    let mut guards = Vec::new();
    for (name, body) in replies {
        guards.push((name, Server::start(move |_| verdict(body)).await));
    }
    let apps: Vec<Value> = guards
        .iter()
        .map(|(name, g)| {
            site(
                name,
                &format!("{name}.test"),
                up.addr,
                &[guard("g1", g.addr, &Value::Null)],
                &Value::Null,
            )
        })
        .collect();
    push(&podgate, &snapshot(1, &apps)).await;

    for (name, _) in &guards {
        assert_closed(&post(&podgate, &format!("{name}.test"), "/", &chat("hello")).await);
    }
    assert_eq!(up.requests(), 0);
}

#[tokio::test]
async fn guard_on_error_allow_passes() {
    let podgate = Podgate::start().await;
    let up = model().await;
    let dead = refused();
    let healthy = Server::start(|_| allow()).await;
    let blocker = Server::start(|_| block("pii", "x")).await;
    let open = json!({"on_error": "allow"});
    let apps = [
        site(
            "a",
            "a.test",
            up.addr,
            &[guard("g1", dead.addr, &open)],
            &Value::Null,
        ),
        site(
            "b",
            "b.test",
            up.addr,
            &[
                guard("g1", dead.addr, &open),
                guard("g2", healthy.addr, &Value::Null),
            ],
            &Value::Null,
        ),
        site(
            "c",
            "c.test",
            up.addr,
            &[
                guard("g1", dead.addr, &open),
                guard("g2", blocker.addr, &Value::Null),
            ],
            &Value::Null,
        ),
        site(
            "d",
            "d.test",
            up.addr,
            &[
                guard("g1", dead.addr, &open),
                guard("g2", dead.addr, &Value::Null),
            ],
            &Value::Null,
        ),
    ];
    push(&podgate, &snapshot(1, &apps)).await;

    assert_eq!(
        post(&podgate, "a.test", "/", &chat("hi")).await.status,
        200,
        "an allow guard that is down lets it through"
    );
    assert_eq!(post(&podgate, "b.test", "/", &chat("hi")).await.status, 200);
    let blocked = post(&podgate, "c.test", "/", &chat("hi")).await;
    assert_eq!(
        blocked.status, 403,
        "a block from another guard still blocks"
    );
    assert_closed(&post(&podgate, "d.test", "/", &chat("hi")).await);
    assert_eq!(up.requests(), 2);
}

#[tokio::test]
async fn guard_allow_is_a_posture_change() {
    let podgate = Podgate::start().await;
    let (up, g) = (model().await, Server::start(|_| allow()).await);
    let strict = snapshot(
        1,
        &[site(
            "a",
            "a.test",
            up.addr,
            &[guard("g1", g.addr, &Value::Null)],
            &Value::Null,
        )],
    );
    push(&podgate, &strict).await;

    let open = snapshot(
        2,
        &[site(
            "a",
            "a.test",
            up.addr,
            &[guard("g1", g.addr, &json!({"on_error": "allow"}))],
            &Value::Null,
        )],
    );
    let plan = podgate.admin_post("/v1/snapshot/plan", &open).await;
    assert_eq!(plan.status, 200, "{plan:?}");
    let changes = plan.json()["posture_changes"].clone();
    assert_eq!(
        changes,
        json!([{"host": "a.test", "app": "a", "kind": "guard_fail_open"}]),
        "{plan:?}"
    );

    let dropped = snapshot(1000, &[app("a", &["a.test"], &[serving("r1", up.addr)])]);
    let plan = podgate.admin_post("/v1/snapshot/plan", &dropped).await;
    assert_eq!(plan.status, 200, "{plan:?}");
    assert_eq!(
        plan.json()["posture_changes"][0]["kind"],
        "guard_dropped",
        "{plan:?}"
    );

    let stricter = snapshot(
        2,
        &[site(
            "a",
            "a.test",
            up.addr,
            &[
                guard("g1", g.addr, &Value::Null),
                guard("g2", g.addr, &json!({"on_error": "allow"})),
            ],
            &Value::Null,
        )],
    );
    let plan = podgate.admin_post("/v1/snapshot/plan", &stricter).await;
    assert_eq!(
        plan.json()["posture_changes"],
        json!([]),
        "a new guard is stricter: {plan:?}"
    );
}

/// A model that answers with `body` as an `application/json` response of known length.
async fn model_saying(text: &'static str) -> Server {
    Server::start(move |_| Reply::Raw(raw(200, &completion(text)))).await
}

/// A guard that judges `phase` and blocks any text with `FLAGGED` in it.
async fn flag_guard() -> Server {
    Server::start(|call| {
        if call.text().contains("FLAGGED") {
            block("leak", "found FLAGGED")
        } else {
            allow()
        }
    })
    .await
}

fn both() -> Value {
    json!({"phases": ["request", "response"]})
}

#[tokio::test]
async fn guard_response_phase_blocks() {
    let podgate = Podgate::start().await;
    let (bad, fine, g) = (
        model_saying("FLAGGED secret answer").await,
        model_saying("a harmless answer").await,
        flag_guard().await,
    );
    let apps = [
        site(
            "bad",
            "bad.test",
            bad.addr,
            &[guard("g1", g.addr, &both())],
            &Value::Null,
        ),
        site(
            "fine",
            "fine.test",
            fine.addr,
            &[guard("g1", g.addr, &both())],
            &Value::Null,
        ),
    ];
    push(&podgate, &snapshot(1, &apps)).await;

    let blocked = post(&podgate, "bad.test", "/", &chat("tell me")).await;
    assert_eq!(blocked.status, 403, "{}", blocked.wire_text());
    assert_eq!(
        blocked.json(),
        json!({"error": "blocked by guard", "category": "leak"})
    );
    assert!(
        !blocked.wire_text().contains("FLAGGED") && !blocked.wire_text().contains("secret"),
        "no byte of the flagged answer reached the client: {}",
        blocked.wire_text()
    );
    assert_eq!(bad.requests(), 1, "the model was asked: the prompt passed");
    let asked = g
        .calls
        .lock()
        .expect("calls")
        .iter()
        .map(Call::json)
        .collect::<Vec<_>>();
    assert!(
        asked
            .iter()
            .any(|call| call["phase"] == "response" && call["text"] == "FLAGGED secret answer"),
        "{asked:?}"
    );

    let passed = post(&podgate, "fine.test", "/", &chat("tell me")).await;
    assert_eq!(passed.status, 200, "{}", passed.wire_text());
    assert_eq!(passed.body, completion("a harmless answer"));
}

#[tokio::test]
async fn guard_response_over_cap_502() {
    let podgate = Podgate::start().await;
    let up = model_saying("an answer that is much longer than the cap of the guard").await;
    let g = Server::start(|_| allow()).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                &[guard("g1", g.addr, &both())],
                &json!({"max_response_bytes": 16}),
            )],
        ),
    )
    .await;

    let answer = post(&podgate, "a.test", "/", &chat("hi")).await;
    assert_eq!(answer.status, 502, "{}", answer.wire_text());
    assert_eq!(
        answer.json(),
        json!({"error": "upstream response too large"})
    );
    assert!(!answer.wire_text().contains("much longer"));
    assert_eq!(g.requests(), 1, "only the prompt was judged");
}

/// A model that answers `body` chunked, in pieces of `piece` bytes, `pause` apart.
async fn chunked_model(
    content_type: &'static str,
    pieces: Vec<Vec<u8>>,
    pause: Duration,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let pieces = pieces.clone();
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
                let head = String::from_utf8_lossy(&seen).into_owned();
                let length: usize = header_of(&head, "content-length")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let have =
                    seen.len() - seen.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) - 4;
                let mut missing = length.saturating_sub(have);
                while missing > 0 {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => missing = missing.saturating_sub(read),
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                );
                if stream.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                for piece in pieces {
                    let mut framed = format!("{:x}\r\n", piece.len()).into_bytes();
                    framed.extend_from_slice(&piece);
                    framed.extend_from_slice(b"\r\n");
                    if stream.write_all(&framed).await.is_err() {
                        return;
                    }
                    sleep(pause).await;
                }
                drop(stream.write_all(b"0\r\n\r\n").await);
                drop(stream.shutdown().await);
            });
        }
    });
    addr
}

#[tokio::test]
async fn guard_response_stream_held_until_end() {
    let podgate = Podgate::start().await;
    let event = |text: &str| {
        format!(
            "data: {}\n\n",
            json!({"choices": [{"index": 0, "delta": {"content": text}}]})
        )
        .into_bytes()
    };
    let allowed = chunked_model(
        "text/event-stream",
        vec![
            event("Good "),
            event("morning "),
            event("all"),
            b"data: [DONE]\n\n".to_vec(),
        ],
        Duration::from_millis(200),
    )
    .await;
    let flagged = chunked_model(
        "text/event-stream",
        vec![
            event("fine so far "),
            event("then FLAG"),
            event("GED"),
            b"data: [DONE]\n\n".to_vec(),
        ],
        Duration::from_millis(100),
    )
    .await;
    let g = flag_guard().await;
    let apps = [
        site(
            "ok",
            "ok.test",
            allowed,
            &[guard("g1", g.addr, &both())],
            &Value::Null,
        ),
        site(
            "bad",
            "bad.test",
            flagged,
            &[guard("g1", g.addr, &both())],
            &Value::Null,
        ),
    ];
    push(&podgate, &snapshot(1, &apps)).await;

    let start = Instant::now();
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    let body = chat("stream please");
    stream
        .write_all(format!("POST / HTTP/1.1\r\nHost: ok.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .expect("send");
    let mut first = [0_u8; 1];
    timeout(Duration::from_secs(10), stream.read_exact(&mut first))
        .await
        .expect("a first byte")
        .expect("read");
    assert!(
        start.elapsed() >= Duration::from_millis(700),
        "the first byte came {:?} in, before the stream had ended (800 ms of events)",
        start.elapsed()
    );
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.expect("read");
    let mut wire = first.to_vec();
    wire.extend(rest);
    let answer = parse(wire);
    assert_eq!(answer.status, 200, "{}", answer.wire_text());
    assert!(
        answer.body.contains("Good ") && answer.body.contains("[DONE]"),
        "{}",
        answer.body
    );
    let asked = g
        .calls
        .lock()
        .expect("calls")
        .iter()
        .map(Call::text)
        .collect::<Vec<_>>();
    assert!(asked.contains(&"Good morning all".to_owned()), "{asked:?}");

    let blocked = post(&podgate, "bad.test", "/", &body).await;
    assert_eq!(blocked.status, 403, "{}", blocked.wire_text());
    assert!(
        !blocked.wire_text().contains("fine so far"),
        "{}",
        blocked.wire_text()
    );
}

async fn metric(podgate: &Podgate, name: &str) -> u64 {
    let body = podgate.admin_get("/metrics").await.body;
    let prefix = format!("{name}{{tenant=\"t1\"}} ");
    body.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.parse().expect("integer sample"))
}

async fn wait_for_metric(podgate: &Podgate, name: &str, wanted: u64) {
    for _ in 0..100 {
        if metric(podgate, name).await == wanted {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "{name} never reached {wanted}, now {}",
        metric(podgate, name).await
    );
}

#[tokio::test]
async fn guard_held_response_over_cap_is_502_nothing_sent() {
    let podgate = Podgate::start().await;
    let cap = 16 * 1024;
    // Four times the cap, in 4 KiB chunks of a marker no header of ours can contain.
    let up = chunked_model(
        "application/json",
        (0..16).map(|_| b"UPSTREAM-SECRET-".repeat(256)).collect(),
        Duration::from_millis(5),
    )
    .await;
    let g = Server::start(|_| allow()).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up,
                &[guard("g1", g.addr, &both())],
                &json!({"max_response_bytes": cap}),
            )],
        ),
    )
    .await;

    let answer = post(&podgate, "a.test", "/", &chat("hi")).await;
    assert_eq!(
        answer.status,
        502,
        "{}",
        &answer.wire_text()[..answer.wire.len().min(300)]
    );
    assert_eq!(
        answer.json(),
        json!({"error": "upstream response too large"})
    );
    assert_eq!(
        answer.wire_text().matches("HTTP/1.1").count(),
        1,
        "exactly one response"
    );
    assert!(
        !answer.wire_text().contains("UPSTREAM-SECRET"),
        "no byte of the model's body was sent"
    );
    assert_eq!(g.requests(), 1, "only the prompt was judged");
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 0).await;
}

#[tokio::test]
async fn guard_held_response_dying_midway_is_a_clean_502() {
    let podgate = Podgate::start().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let up = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut chunk = [0_u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
                sleep(Duration::from_millis(100)).await;
                // The head and half of a body, then the connection drops.
                drop(stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\nContent-Type: application/json\r\n\r\n{\"choices\":[{\"message\":{\"content\":\"HALF").await);
            });
        }
    });
    let g = Server::start(|_| allow()).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up,
                &[guard("g1", g.addr, &both())],
                &Value::Null,
            )],
        ),
    )
    .await;

    let answer = post(&podgate, "a.test", "/", &chat("hi")).await;
    assert_eq!(answer.status, 502, "{}", answer.wire_text());
    assert!(
        !answer.wire_text().contains("HALF"),
        "{}",
        answer.wire_text()
    );
}

#[tokio::test]
async fn guard_response_head_only_is_not_held() {
    let podgate = Podgate::start().await;
    let up = Server::start(|call| {
        if call.head.starts_with("POST /nothing") {
            Reply::Raw(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec())
        } else {
            Reply::Raw(raw(404, r#"{"error":"nope"}"#))
        }
    })
    .await;
    let g = Server::start(|_| allow()).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                &[guard("g1", g.addr, &both())],
                &Value::Null,
            )],
        ),
    )
    .await;

    assert_eq!(
        post(&podgate, "a.test", "/nothing", &chat("hi"))
            .await
            .status,
        204
    );
    let missing = post(&podgate, "a.test", "/other", &chat("hi")).await;
    assert_eq!(missing.status, 404, "a non-2xx answer passes untouched");
    assert_eq!(missing.body, r#"{"error":"nope"}"#);
    assert_eq!(g.requests(), 2, "only the two prompts were judged");
}

#[tokio::test]
async fn guard_held_response_reaches_hooks_after_the_verdict() {
    let podgate = Podgate::start().await;
    let up = model_saying("a plain answer").await;
    let g = Server::start(|_| allow()).await;
    let a = site(
        "a",
        "a.test",
        up.addr,
        &[guard("g1", g.addr, &both())],
        &Value::Null,
    );
    // `compress` runs after the guard, on the answer that was let through.
    let a = with_middleware(a, "squeeze", "compress", json!({"min_bytes": 1}));
    push(&podgate, &snapshot(1, &[a])).await;

    let request = {
        let body = chat("hi");
        format!(
            "POST / HTTP/1.1\r\nHost: a.test\r\nAccept-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let answer = send(&podgate, request.as_bytes()).await;
    assert_eq!(answer.status, 200, "{}", answer.wire_text());
    assert_eq!(
        answer.header("content-encoding"),
        Some("gzip"),
        "{}",
        answer.head
    );
    let upstream_head = up.head(0);
    assert!(
        !upstream_head
            .to_ascii_lowercase()
            .contains("accept-encoding"),
        "the model is asked for plain text so the guard can read it: {upstream_head}"
    );
    assert_eq!(g.calls.lock().expect("calls")[1].text(), "a plain answer");
}

#[tokio::test]
async fn guard_cache_stores_only_allowed_answers() {
    let podgate = Podgate::start().await;
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);
    let up = Server::start(move |_| {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        let text = if n == 0 { "FLAGGED first answer" } else { "a fine second answer" };
        Reply::Raw(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: max-age=60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                completion(text).len(),
                completion(text)
            )
            .into_bytes(),
        )
    })
    .await;
    let g = flag_guard().await;
    let a = with_middleware(
        site(
            "a",
            "a.test",
            up.addr,
            &[guard("g1", g.addr, &json!({"phases": ["response"]}))],
            &Value::Null,
        ),
        "store",
        "cache",
        json!({}),
    );
    push(&podgate, &snapshot(1, &[a])).await;

    let get = |path: &'static str| {
        let request = format!("GET {path} HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n");
        let podgate = &podgate;
        async move { send(podgate, request.as_bytes()).await }
    };
    let first = get("/v1/x").await;
    assert_eq!(first.status, 403, "{}", first.wire_text());
    let second = get("/v1/x").await;
    assert_eq!(second.status, 200, "{}", second.wire_text());
    assert!(
        second.body.contains("fine second"),
        "the flagged answer was never stored: {}",
        second.body
    );
    assert_eq!(up.requests(), 2);
    let third = get("/v1/x").await;
    assert!(third.body.contains("fine second"), "{}", third.body);
    assert_eq!(
        up.requests(),
        2,
        "the allowed answer is what the cache kept"
    );
}

/// The failed requests of app `app`, as JSON text.
async fn failures_of(podgate: &Podgate, app: &str) -> String {
    let mut stream = tokio::net::UnixStream::connect(&podgate.admin_socket)
        .await
        .expect("connect admin");
    let request = format!(
        "GET /v1/apps/{app}/failures HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.expect("send");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    String::from_utf8_lossy(&raw).into_owned()
}

#[tokio::test]
async fn guard_recorder_never_keeps_held_answer() {
    let podgate = Podgate::start().await;
    let up = model_saying("MODEL-SECRET answer").await;
    let g = Server::start(|call| {
        if call.json()["phase"] == "response" {
            Reply::Raw(raw(500, "{}"))
        } else {
            allow()
        }
    })
    .await;
    let mut a = site(
        "a",
        "a.test",
        up.addr,
        &[guard("g1", g.addr, &both())],
        &Value::Null,
    );
    a["record_bodies"] = json!(true);
    push(&podgate, &snapshot(1, &[a])).await;

    let answer = post(&podgate, "a.test", "/", &chat("PROMPT-ONE")).await;
    assert_closed(&answer);
    let recorded = failures_of(&podgate, "a").await;
    assert!(
        recorded.contains("\"status\":503") || recorded.contains("503"),
        "the 503 is recorded: {recorded}"
    );
    assert!(recorded.contains("503"), "{recorded}");
    assert!(
        !recorded.contains("MODEL-SECRET"),
        "the recorder kept the model's answer that the guard never let through: {recorded}"
    );
}

#[tokio::test]
async fn guard_prompt_over_cap_413() {
    let podgate = Podgate::start().await;
    let (up, g) = (model().await, Server::start(|_| allow()).await);
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                &[guard("g1", g.addr, &Value::Null)],
                &json!({"max_prompt_bytes": 1024}),
            )],
        ),
    )
    .await;

    let big = chat(&"x".repeat(2000));
    let answer = post(&podgate, "a.test", "/", &big).await;
    assert_eq!(answer.status, 413, "{}", answer.wire_text());
    let chunked = {
        let piece = &big[..1500];
        let rest = &big[1500..];
        format!(
            "POST / HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{piece}\r\n{:x}\r\n{rest}\r\n0\r\n\r\n",
            piece.len(),
            rest.len()
        )
    };
    assert_eq!(send(&podgate, chunked.as_bytes()).await.status, 413);
    assert_eq!(
        (up.requests(), g.requests()),
        (0, 0),
        "neither the model nor a guard saw it"
    );

    let fits = post(&podgate, "a.test", "/", &chat(&"y".repeat(500))).await;
    assert_eq!(fits.status, 200, "{}", fits.wire_text());
}

#[tokio::test]
async fn guard_unreadable_request_is_refused_not_passed() {
    let podgate = Podgate::start().await;
    let (up, g) = (model().await, Server::start(|_| allow()).await);
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                &[guard("g1", g.addr, &Value::Null)],
                &Value::Null,
            )],
        ),
    )
    .await;

    for body in [
        "not json",
        r#"{"prompt":"a completion prompt"}"#,
        r#"{"messages":[{"content":7}]}"#,
    ] {
        let answer = post(&podgate, "a.test", "/", body).await;
        assert_eq!(answer.status, 400, "{body}: {}", answer.wire_text());
        assert_eq!(answer.json(), json!({"error": "unreadable request"}));
    }
    let gzipped = "POST / HTTP/1.1\r\nHost: a.test\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd";
    assert_eq!(send(&podgate, gzipped.as_bytes()).await.status, 400);
    assert_eq!((up.requests(), g.requests()), (0, 0));
    let get = send(
        &podgate,
        b"GET /v1/models HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        get.status,
        200,
        "a request with no body has nothing to judge: {}",
        get.wire_text()
    );
}

/// A policy file in its own temp path.
struct PolicyFile(PathBuf);

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-llm-guard-policy-{}-{}.json",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("write the policy file");
        Self(path)
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        drop(std::fs::remove_file(&self.0));
    }
}

#[tokio::test]
async fn guard_address_policy_enforced() {
    // Tenant t1 may dial 127.0.0.1 only; t2 may dial 127.0.0.1 and 127.0.0.2, where the guard is.
    let policy = PolicyFile::write(
        r#"{"deny": [], "default": {"allow": ["127.0.0.1/32"]}, "tenants": {"t2": {"allow": ["127.0.0.1/32", "127.0.0.2/32"]}}}"#,
    );
    let podgate =
        Podgate::start_with_env(&[("UPSTREAM_POLICY_FILE", policy.0.to_str().expect("utf-8"))])
            .await;
    let up = model().await;
    let g = Server::start_on("127.0.0.2", |_| allow()).await;
    let mine = site(
        "mine",
        "mine.test",
        up.addr,
        &[guard("g1", g.addr, &Value::Null)],
        &Value::Null,
    );
    let mut theirs = site(
        "theirs",
        "theirs.test",
        up.addr,
        &[guard("g1", g.addr, &Value::Null)],
        &Value::Null,
    );
    theirs["tenant"] = json!("t2");
    let pushed = json!({
        "version": 1,
        "tenants": [
            { "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
            { "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
        ],
        "apps": [mine, theirs],
    });
    // The compiler judges only the model's address; a guard is judged where it is dialled.
    push(&podgate, &pushed).await;

    assert_closed(&post(&podgate, "mine.test", "/", &chat("hi")).await);
    assert_eq!(
        g.requests(),
        0,
        "the policy refused the address: nothing was dialled"
    );
    assert_eq!(up.requests(), 0);
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metrics
            .lines()
            .any(|line| line.starts_with("podgate_upstream_refused_total{tenant=\"t1\"} 1")),
        "{metrics}"
    );
    assert_eq!(
        post(&podgate, "theirs.test", "/", &chat("hi")).await.status,
        200,
        "the tenant the operator allowed reaches it"
    );
    assert_eq!(g.requests(), 1);
}

#[tokio::test]
async fn guard_charged_to_tenant_budget() {
    let podgate = Podgate::start().await;
    let up = model().await;
    let g = Server::start(|_| {
        Reply::Delay(
            Duration::from_millis(800),
            raw(200, r#"{"verdict":"allow"}"#),
        )
    })
    .await;
    let a = site(
        "a",
        "a.test",
        up.addr,
        &[guard("g1", g.addr, &Value::Null)],
        &json!({"max_prompt_bytes": 1024, "timeout_ms": 5000}),
    );
    // One exchange needs 1024 + 20 KiB of room; this tenant has a little more than one.
    let mut pushed = snapshot(1, std::slice::from_ref(&a));
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(1024 + 20 * 1024 - 1);
    let refused = podgate.push_snapshot(&pushed).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert_eq!(
        refused.json()["conflicts"][0]["code"],
        "invalid_middleware",
        "{refused:?}"
    );
    assert_eq!(
        refused.json()["conflicts"][0]["needed_bytes"],
        1024 + 20 * 1024
    );

    let mut pushed = snapshot(2, &[a]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(1024 + 20 * 1024 + 600);
    push(&podgate, &pushed).await;
    let body = chat("hello");
    let (first, second) = tokio::join!(post(&podgate, "a.test", "/", &body), async {
        sleep(Duration::from_millis(200)).await;
        post(&podgate, "a.test", "/", &body).await
    });
    assert_eq!(first.status, 200, "{}", first.wire_text());
    assert_eq!(
        second.status,
        503,
        "the budget was full: {}",
        second.wire_text()
    );
    assert_eq!(second.body, r#"{"error":"guard unavailable"}"#);
    assert_eq!(second.header("retry-after"), Some("1"));
    assert_eq!(g.requests(), 1, "the second call was never made");
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 0).await;
}

#[tokio::test]
async fn guard_blocked_prompt_never_logged() {
    let podgate = Podgate::start_logged(&[("RUST_LOG", "trace")]).await;
    let up = model().await;
    let blocker = Server::start(|_| block("pii", "rule 3")).await;
    let dead = refused();
    let mut blocked = site(
        "blocked",
        "blocked.test",
        up.addr,
        &[guard("g1", blocker.addr, &Value::Null)],
        &Value::Null,
    );
    let mut broken = site(
        "broken",
        "broken.test",
        up.addr,
        &[guard("g1", dead.addr, &Value::Null)],
        &Value::Null,
    );
    for app in [&mut blocked, &mut broken] {
        app["record_bodies"] = json!(true);
    }
    push(&podgate, &snapshot(1, &[blocked, broken])).await;
    let canary = "CANARY-9f3a1c77-prompt";

    assert_eq!(
        post(
            &podgate,
            "blocked.test",
            "/secret?q=1",
            &chat(&format!("tell {canary}"))
        )
        .await
        .status,
        403
    );
    assert_closed(
        &post(
            &podgate,
            "broken.test",
            "/secret?q=1",
            &chat(&format!("tell {canary}")),
        )
        .await,
    );
    // The guard was shown the text; nothing else may be.
    assert!(
        blocker.bodies().contains(canary),
        "the guard is the one place the prompt goes"
    );

    let log = podgate.log();
    assert!(
        !log.contains(canary),
        "a log line carries the prompt:\n{log}"
    );
    for app in ["blocked", "broken"] {
        let recorded = failures_of(&podgate, app).await;
        assert!(
            !recorded.contains(canary),
            "{app}: the recorder kept the prompt: {recorded}"
        );
    }
    let explain = podgate
        .admin_get("/v1/explain?url=http://blocked.test/secret&method=POST")
        .await;
    assert_eq!(explain.status, 200, "{explain:?}");
    assert!(!explain.body.contains(canary), "{}", explain.body);
    assert!(explain.body.contains("llm_guard"), "{}", explain.body);
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(!metrics.contains(canary), "a metric carries the prompt");
    assert_eq!(up.requests(), 0);
}

#[tokio::test]
async fn guard_reason_echoing_prompt_never_logged() {
    let podgate = Podgate::start_logged(&[("RUST_LOG", "trace")]).await;
    let up = model().await;
    let canary = "CANARY-5b1e90d2-reason";
    let blocker =
        Server::start(|call| block("pii", &format!("the prompt said: {}", call.text()))).await;
    let app = site(
        "echo",
        "echo.test",
        up.addr,
        &[guard("g1", blocker.addr, &Value::Null)],
        &Value::Null,
    );
    push(&podgate, &snapshot(1, &[app])).await;

    let answer = post(&podgate, "echo.test", "/", &chat(&format!("tell {canary}"))).await;
    assert_eq!(answer.status, 403, "{}", answer.wire_text());
    assert!(
        blocker.bodies().contains(canary),
        "the guard saw the prompt"
    );
    assert!(!answer.wire_text().contains(canary), "the client saw it");
    let log = podgate.log();
    assert!(
        !log.contains(canary),
        "the log carries the guard's reason:\n{log}"
    );
    assert!(log.contains("guard blocked"), "the block is logged:\n{log}");
}

/// An `h2c://` model that answers `200` with `pieces` as separate DATA frames.
async fn h2c_model(content_type: &'static str, pieces: Vec<bytes::Bytes>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let pieces = pieces.clone();
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(stream).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let pieces = pieces.clone();
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        while let Some(Ok(chunk)) = body.data().await {
                            drop(body.flow_control().release_capacity(chunk.len()));
                        }
                        let head = http::Response::builder()
                            .status(200)
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
    addr
}

/// An app whose service speaks `h2c://` to `upstream`.
fn h2c_site(id: &str, host: &str, upstream: SocketAddr, guards: &[Value], extra: &Value) -> Value {
    let mut app = site(id, host, upstream, guards, extra);
    app["revisions"] = json!([{
        "id": "r1", "state": "serving", "weight": 100,
        "services": [{"name": "web", "type": "loadbalancer",
                      "servers": [{"url": format!("h2c://{upstream}")}]}],
    }]);
    app
}

#[tokio::test]
async fn guard_response_phase_over_an_h2c_upstream() {
    let podgate = Podgate::start().await;
    let in_pieces = |text: &str| -> Vec<bytes::Bytes> {
        completion(text)
            .as_bytes()
            .chunks(16)
            .map(bytes::Bytes::copy_from_slice)
            .collect()
    };
    let fine = h2c_model("application/json", in_pieces("a harmless answer")).await;
    let bad = h2c_model("application/json", in_pieces("FLAGGED secret answer")).await;
    let long = h2c_model(
        "application/json",
        (0..8)
            .map(|_| bytes::Bytes::from(b"UPSTREAM-SECRET-".repeat(256)))
            .collect(),
    )
    .await;
    let g = flag_guard().await;
    let apps = [
        h2c_site(
            "fine",
            "fine.test",
            fine,
            &[guard("g1", g.addr, &both())],
            &Value::Null,
        ),
        h2c_site(
            "bad",
            "bad.test",
            bad,
            &[guard("g1", g.addr, &both())],
            &Value::Null,
        ),
        h2c_site(
            "long",
            "long.test",
            long,
            &[guard("g1", g.addr, &both())],
            &json!({"max_response_bytes": 4096}),
        ),
    ];
    push(&podgate, &snapshot(1, &apps)).await;

    let passed = post(&podgate, "fine.test", "/", &chat("hi")).await;
    assert_eq!(passed.status, 200, "{}", passed.wire_text());
    assert_eq!(passed.body, completion("a harmless answer"));

    let blocked = post(&podgate, "bad.test", "/", &chat("hi")).await;
    assert_eq!(blocked.status, 403, "{}", blocked.wire_text());
    assert!(
        !blocked.wire_text().contains("FLAGGED"),
        "{}",
        blocked.wire_text()
    );

    let over = post(&podgate, "long.test", "/", &chat("hi")).await;
    assert_eq!(over.status, 502, "{}", over.wire_text());
    assert_eq!(over.wire_text().matches("HTTP/1.1").count(), 1);
    assert!(!over.wire_text().contains("UPSTREAM-SECRET"));
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 0).await;
}
