//! The `ai_token_limit` middleware through the real binary, a real `valkey-server` and
//! fake model servers on raw sockets: tokens counted from `usage` (plain, streamed, compressed),
//! the estimate for a model that reports nothing usable, the budget refused before the model, the
//! rewrite of a streaming request and the removal of the usage chunk the client did not ask for,
//! two nodes sharing a budget, and the store failing under `allow` and `deny`. The pure parts
//! (usage bounds, the event scanner, the body edit) are unit-tested in
//! `src/middleware/ai_token_limit/`.

// The builders take the JSON they are given, as the ones in `common` do.
#![allow(clippy::needless_pass_by_value)]

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::valkey::{self, Valkey};
use common::{Podgate, Response, app, middleware, serving, snapshot, with_chain};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

/// What a fake model answers with.
#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    /// Pieces of the body, each written after its delay.
    parts: Vec<(Duration, Vec<u8>)>,
    /// Sent as HTTP/1.1 chunks, else with a `Content-Length`.
    chunked: bool,
}

impl Reply {
    fn json(body: &Value) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            parts: vec![(Duration::ZERO, body.to_string().into_bytes())],
            chunked: false,
        }
    }

    fn events(events: &[(u64, String)]) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), "text/event-stream".into())],
            parts: events
                .iter()
                .map(|(wait, event)| (Duration::from_millis(*wait), event.clone().into_bytes()))
                .collect(),
            chunked: true,
        }
    }
}

/// What a fake model saw.
#[derive(Clone)]
struct Seen {
    head: String,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("the model got a JSON body")
    }
}

type Handler = dyn Fn(&Seen) -> Reply + Send + Sync;

struct Model {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Model {
    async fn start(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(stream, Arc::clone(&handler), Arc::clone(&log)));
            }
        });
        Self { addr, seen }
    }

    fn calls(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn serve(mut stream: TcpStream, handler: Arc<Handler>, log: Arc<Mutex<Vec<Seen>>>) {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        if let Some(at) = find(&raw, b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    while raw.len() < head_end + length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
        }
    }
    let seen = Seen {
        head,
        body: raw[head_end..].to_vec(),
    };
    log.lock().expect("lock").push(seen.clone());
    let reply = handler(&seen);
    let mut out = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", reply.status);
    for (name, value) in &reply.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    if reply.chunked {
        out.push_str("Transfer-Encoding: chunked\r\n\r\n");
    } else {
        let total: usize = reply.parts.iter().map(|(_, part)| part.len()).sum();
        out.push_str(&format!("Content-Length: {total}\r\n\r\n"));
    }
    if stream.write_all(out.as_bytes()).await.is_err() {
        return;
    }
    for (wait, part) in &reply.parts {
        sleep(*wait).await;
        let framed = if reply.chunked {
            let mut framed = format!("{:x}\r\n", part.len()).into_bytes();
            framed.extend_from_slice(part);
            framed.extend_from_slice(b"\r\n");
            framed
        } else {
            part.clone()
        };
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
    if reply.chunked {
        drop(stream.write_all(b"0\r\n\r\n").await);
    }
    drop(stream.shutdown().await);
}

/// A usage-reporting chat answer.
fn chat(prompt: u64, completion: u64) -> Value {
    json!({
        "id": "c1", "object": "chat.completion",
        "choices": [{"message": {"role": "assistant", "content": "hello"}}],
        "usage": {
            "prompt_tokens": prompt, "completion_tokens": completion,
            "total_tokens": prompt + completion,
        },
    })
}

fn content_event(text: &str) -> String {
    format!(
        "data: {{\"id\":\"c1\",\"choices\":[{{\"delta\":{{\"content\":\"{text}\"}}}}],\"usage\":null}}\n\n"
    )
}

fn usage_event(prompt: u64, completion: u64) -> String {
    format!(
        "data: {{\"id\":\"c1\",\"choices\":[],\"usage\":{{\"prompt_tokens\":{prompt},\"completion_tokens\":{completion},\"total_tokens\":{}}}}}\n\n",
        prompt + completion
    )
}

const DONE: &str = "data: [DONE]\n\n";

/// A node whose `RATE_LIMIT_STORES_FILE` is `stores`.
async fn node(stores: &Path) -> Podgate {
    Podgate::start_with_env(&[(
        "RATE_LIMIT_STORES_FILE",
        stores.to_str().expect("utf-8 path"),
    )])
    .await
}

fn one_store(dir: &Path, valkey: &Valkey) -> std::path::PathBuf {
    valkey::stores_file(dir, &json!({ "main": valkey::entry(valkey.addr()) }))
}

/// The config of a budget of `limit` tokens a day per `x-api-key`, store `main`.
fn limited(limit: u64, failure: &str) -> Value {
    json!({
        "limits": [{"limit": limit, "period": "day"}],
        "source": {"header": "x-api-key"},
        "store": "main", "on_store_error": failure,
    })
}

fn route(model: SocketAddr, config: Value) -> Value {
    with_chain(
        app("a", &["a.test"], &[serving("r1", model)]),
        &[middleware("tokens", "ai_token_limit", config)],
    )
}

async fn push(podgate: &Podgate, pushed: &Value) {
    let response = podgate.push_snapshot(pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// Waits out the last seconds of a UTC day, so a test that counts in the day window is not split
/// by midnight.
async fn clear_of_midnight() {
    let left = 86_400 - podgate::ratelimit_store::quota::now_secs() % 86_400;
    if left < 8 {
        sleep(Duration::from_secs(left + 1)).await;
    }
}

/// The charge lands in a task after the answer ends.
async fn settled() {
    sleep(Duration::from_millis(300)).await;
}

/// A chat request body.
fn prompt(stream: bool, extra: &str) -> String {
    format!(
        "{{\"model\":\"m\",\"stream\":{stream},\"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]{extra}}}"
    )
}

fn decode_chunked(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(at) = find(body, b"\r\n") {
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..at]).expect("utf-8").trim(), 16)
                .expect("chunk size");
        if size == 0 {
            break;
        }
        out.extend_from_slice(&body[at + 2..at + 2 + size]);
        body = &body[at + 2 + size + 2..];
    }
    out
}

/// A response with its body bytes, chunked framing removed.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }

    fn number(&self, name: &str) -> u64 {
        self.header(name)
            .unwrap_or_else(|| panic!("no {name} in {:?}", self.headers))
            .parse()
            .expect("a number")
    }
}

fn parse(raw: &[u8]) -> Answer {
    let end = find(raw, b"\r\n\r\n").expect("a response head");
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status");
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let body = &raw[end + 4..];
    let chunked = headers
        .iter()
        .any(|(key, value)| key == "transfer-encoding" && value.contains("chunked"));
    Answer {
        status,
        headers,
        body: if chunked {
            decode_chunked(body)
        } else {
            body.to_vec()
        },
    }
}

fn request(key: &str, content_type: &str, body: &[u8], extra: &str) -> Vec<u8> {
    let mut out = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: a.test\r\nx-api-key: {key}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

async fn send(podgate: &Podgate, bytes: &[u8]) -> Answer {
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    stream.write_all(bytes).await.expect("send");
    let mut raw = Vec::new();
    timeout(Duration::from_secs(15), stream.read_to_end(&mut raw))
        .await
        .expect("an answer in time")
        .expect("read");
    parse(&raw)
}

async fn post(podgate: &Podgate, key: &str, body: &str) -> Answer {
    send(
        podgate,
        &request(key, "application/json", body.as_bytes(), ""),
    )
    .await
}

/// One request through a node with the budget `limit`, answered by `reply`.
struct Rig {
    podgate: Podgate,
    model: Model,
    valkey: Valkey,
}

async fn rig(config: Value, reply: Reply) -> Rig {
    let valkey = Valkey::start().await;
    let model = Model::start(move |_| reply.clone()).await;
    let dir = valkey::scratch("ai-tokens");
    let podgate = node(&one_store(&dir, &valkey)).await;
    push(&podgate, &snapshot(1, &[route(model.addr, config)])).await;
    Rig {
        podgate,
        model,
        valkey,
    }
}

fn metric(text: &str, series: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(series)?.trim().parse().ok())
}

#[tokio::test]
async fn ai_tokens_counted_from_usage() {
    clear_of_midnight().await;
    let rig = rig(limited(1000, "deny"), Reply::json(&chat(11, 31))).await;
    let first = post(&rig.podgate, "k", &prompt(false, "")).await;
    assert_eq!(first.status, 200);
    assert_eq!(first.json()["usage"]["total_tokens"], 42);
    settled().await;
    let second = post(&rig.podgate, "k", &prompt(false, "")).await;
    assert_eq!(second.number("x-ratelimit-remaining-tokens"), 1000 - 42);
    settled().await;
    let metrics = rig.podgate.admin_get("/metrics").await.body;
    let series = |kind: &str| {
        metric(
            &metrics,
            &format!(r#"podgate_ai_tokens_total{{tenant="t1",app="a",kind="{kind}"}}"#),
        )
    };
    assert_eq!(series("prompt"), Some(22), "two answers of 11");
    assert_eq!(series("completion"), Some(62), "and 31");
    assert_eq!(series("estimated"), Some(0));
}

#[tokio::test]
async fn ai_remaining_header_drops() {
    clear_of_midnight().await;
    let rig = rig(limited(100, "deny"), Reply::json(&chat(4, 6))).await;
    let mut left = Vec::new();
    for _ in 0..3 {
        let answer = post(&rig.podgate, "k", &prompt(false, "")).await;
        assert_eq!(answer.status, 200);
        assert_eq!(answer.number("x-ratelimit-limit-tokens"), 100);
        assert!((1..=86_400).contains(&answer.number("x-ratelimit-reset-tokens")));
        left.push(answer.number("x-ratelimit-remaining-tokens"));
        settled().await;
    }
    assert_eq!(left, [100, 90, 80]);
    let other = post(&rig.podgate, "other-key", &prompt(false, "")).await;
    assert_eq!(other.number("x-ratelimit-remaining-tokens"), 100);
}

fn stream_events() -> Vec<(u64, String)> {
    vec![
        (0, content_event("he")),
        (0, content_event("llo")),
        (0, usage_event(3, 4)),
        (0, DONE.to_owned()),
    ]
}

#[tokio::test]
async fn ai_stream_counted_from_final_chunk() {
    clear_of_midnight().await;
    let rig = rig(limited(1000, "deny"), Reply::events(&stream_events())).await;
    let first = post(&rig.podgate, "k", &prompt(true, "")).await;
    assert_eq!(first.status, 200);
    assert_eq!(first.header("content-type"), Some("text/event-stream"));
    assert!(first.text().ends_with(DONE), "{}", first.text());
    settled().await;
    let second = post(&rig.podgate, "k", &prompt(true, "")).await;
    assert_eq!(second.number("x-ratelimit-remaining-tokens"), 1000 - 7);
}

#[tokio::test]
async fn ai_stream_include_usage_added() {
    clear_of_midnight().await;
    let rig = rig(limited(1000, "deny"), Reply::events(&stream_events())).await;
    let body = prompt(true, ",\"stream_options\":{\"foo\":1}");
    assert_eq!(post(&rig.podgate, "k", &body).await.status, 200);
    let bare = prompt(true, "");
    assert_eq!(post(&rig.podgate, "k", &bare).await.status, 200);
    let calls = rig.model.calls();
    assert_eq!(calls.len(), 2);
    let kept = calls[0].json();
    assert_eq!(
        kept["stream_options"],
        json!({"foo": 1, "include_usage": true})
    );
    assert_eq!(kept["messages"][0]["content"], "hi");
    assert_eq!(
        calls[1].json()["stream_options"],
        json!({"include_usage": true})
    );
    for call in &calls {
        assert_eq!(
            call.header("content-length"),
            Some(call.body.len().to_string()),
            "the length is the rewritten body's"
        );
        assert_eq!(call.header("accept-encoding").as_deref(), Some("identity"));
    }
    // A body that does not stream is not touched.
    let plain = prompt(false, "");
    assert_eq!(post(&rig.podgate, "k", &plain).await.status, 200);
    assert_eq!(rig.model.calls()[2].body, plain.as_bytes());
}

#[tokio::test]
async fn ai_stream_usage_chunk_hidden_when_added() {
    clear_of_midnight().await;
    let events = stream_events();
    let rig = rig(limited(1000, "deny"), Reply::events(&events)).await;
    let hidden = post(&rig.podgate, "k", &prompt(true, "")).await;
    let expected: String = events
        .iter()
        .filter(|(_, event)| !event.contains("total_tokens"))
        .map(|(_, event)| event.as_str())
        .collect();
    assert_eq!(
        hidden.text(),
        expected,
        "the client sees what the model would send alone"
    );
    // The chunk was read before it was removed: it was counted.
    settled().await;
    let next = post(&rig.podgate, "k", &prompt(true, "")).await;
    assert_eq!(next.number("x-ratelimit-remaining-tokens"), 1000 - 7);
}

#[tokio::test]
async fn ai_stream_usage_chunk_kept_when_client_asked() {
    clear_of_midnight().await;
    let events = stream_events();
    let rig = rig(limited(1000, "deny"), Reply::events(&events)).await;
    let body = prompt(true, ",\"stream_options\":{\"include_usage\":true}");
    let kept = post(&rig.podgate, "k", &body).await;
    let all: String = events.iter().map(|(_, event)| event.as_str()).collect();
    assert_eq!(
        kept.text(),
        all,
        "nothing is removed from a client that asked"
    );
    assert_eq!(
        rig.model.calls()[0].body,
        body.as_bytes(),
        "and the request is untouched"
    );
}

#[tokio::test]
async fn ai_stream_chunks_not_delayed() {
    clear_of_midnight().await;
    let events = vec![
        (0, content_event("first")),
        (400, content_event("second")),
        (400, content_event("third")),
        (400, usage_event(1, 1)),
        (0, DONE.to_owned()),
    ];
    let rig = rig(limited(1000, "deny"), Reply::events(&events)).await;
    let mut stream = TcpStream::connect(rig.podgate.proxy_addr)
        .await
        .expect("connect");
    let started = Instant::now();
    stream
        .write_all(&request(
            "k",
            "application/json",
            prompt(true, "").as_bytes(),
            "",
        ))
        .await
        .expect("send");
    let mut text = String::new();
    let mut arrivals: Vec<(&str, Duration)> = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = timeout(Duration::from_secs(15), stream.read(&mut buffer))
            .await
            .expect("in time")
            .expect("read");
        if read == 0 {
            break;
        }
        text.push_str(&String::from_utf8_lossy(&buffer[..read]));
        for word in ["first", "second", "third"] {
            if text.contains(word) && !arrivals.iter().any(|(seen, _)| *seen == word) {
                arrivals.push((word, started.elapsed()));
            }
        }
    }
    let at = |word: &str| {
        arrivals
            .iter()
            .find(|(seen, _)| *seen == word)
            .expect(word)
            .1
    };
    assert!(at("first") < Duration::from_millis(300), "{arrivals:?}");
    assert!(at("second") >= Duration::from_millis(350), "{arrivals:?}");
    assert!(
        at("third") - at("first") >= Duration::from_millis(700),
        "each event reaches the client as the model sends it: {arrivals:?}"
    );
    assert!(!text.contains("total_tokens"), "the usage chunk is hidden");
}

#[tokio::test]
async fn ai_spent_budget_refused_before_model() {
    clear_of_midnight().await;
    let rig = rig(limited(100, "deny"), Reply::json(&chat(100, 50))).await;
    assert_eq!(
        post(&rig.podgate, "k", &prompt(false, "")).await.status,
        200
    );
    settled().await;
    let refused = post(&rig.podgate, "k", &prompt(false, "")).await;
    assert_eq!(refused.status, 429);
    assert_eq!(refused.json(), json!({"error": "token budget exceeded"}));
    assert_eq!(refused.number("x-ratelimit-remaining-tokens"), 0);
    let retry = refused.number("retry-after");
    assert!((1..=86_400).contains(&retry), "{retry}");
    assert_eq!(rig.model.calls().len(), 1, "the model saw one request");
    let other = post(&rig.podgate, "fresh", &prompt(false, "")).await;
    assert_eq!(other.status, 200, "another key has its own budget");
    let metrics = rig.podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_ai_tokens_refused_total{tenant="t1",app="a"}"#
        ),
        Some(1)
    );
}

#[tokio::test]
async fn ai_prompt_too_large_413() {
    clear_of_midnight().await;
    let mut config = limited(1000, "deny");
    config["max_prompt_bytes"] = json!(100);
    let rig = rig(config, Reply::json(&chat(1, 1))).await;
    let big = prompt(false, &format!(",\"pad\":\"{}\"", "x".repeat(200)));
    let refused = post(&rig.podgate, "k", &big).await;
    assert_eq!(refused.status, 413, "{}", refused.text());
    assert!(rig.model.calls().is_empty());
    let small = post(&rig.podgate, "k", &prompt(false, "")).await;
    assert_eq!(small.status, 200);
    assert_eq!(rig.model.calls().len(), 1);
}

#[tokio::test]
async fn ai_non_json_body_is_not_held() {
    clear_of_midnight().await;
    let mut config = limited(1_000_000, "deny");
    config["max_prompt_bytes"] = json!(100);
    let rig = rig(config, Reply::json(&chat(5, 5))).await;
    let blob = vec![b'a'; 20_000];
    let answer = send(
        &rig.podgate,
        &request("k", "application/octet-stream", &blob, ""),
    )
    .await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(rig.model.calls()[0].body, blob);
}

#[tokio::test]
async fn ai_missing_usage_estimated() {
    clear_of_midnight().await;
    let body = json!({"id": "c1", "choices": [{"message": {"content": "no usage here"}}]});
    let answer_len = body.to_string().len() as u64;
    let rig = rig(limited(1000, "deny"), Reply::json(&body)).await;
    let request_body = prompt(false, "");
    assert_eq!(post(&rig.podgate, "k", &request_body).await.status, 200);
    settled().await;
    let expected = (request_body.len() as u64 + answer_len).div_ceil(4);
    let next = post(&rig.podgate, "k", &request_body).await;
    assert_eq!(next.number("x-ratelimit-remaining-tokens"), 1000 - expected);
    settled().await;
    let metrics = rig.podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_ai_tokens_estimated_total{tenant="t1",app="a"}"#
        ),
        Some(2)
    );
}

#[tokio::test]
async fn ai_negative_usage_ignored() {
    clear_of_midnight().await;
    let mut body = chat(10, 10);
    body["usage"] =
        json!({"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": -1_000_000});
    let rig = rig(limited(1000, "deny"), Reply::json(&body)).await;
    let request_body = prompt(false, "");
    for key in ["negative", "huge"] {
        assert_eq!(post(&rig.podgate, key, &request_body).await.status, 200);
    }
    settled().await;
    // The parts are usable: the negative total cannot refund them.
    let next = post(&rig.podgate, "negative", &request_body).await;
    assert_eq!(next.number("x-ratelimit-remaining-tokens"), 1000 - 20);

    let only = json!({"id": "c1", "usage": {"total_tokens": -5}});
    let answer_len = only.to_string().len() as u64;
    let rig = self::rig(limited(1000, "deny"), Reply::json(&only)).await;
    assert_eq!(post(&rig.podgate, "k", &request_body).await.status, 200);
    settled().await;
    let next = post(&rig.podgate, "k", &request_body).await;
    let spent = (request_body.len() as u64 + answer_len).div_ceil(4);
    assert_eq!(
        next.number("x-ratelimit-remaining-tokens"),
        1000 - spent,
        "a negative total is the estimate, never a refund"
    );
}

#[tokio::test]
async fn ai_budget_shared_across_nodes() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let model = Model::start(|_| Reply::json(&chat(100, 50))).await;
    let dir = valkey::scratch("ai-shared");
    let stores = one_store(&dir, &valkey);
    let (first, second) = (node(&stores).await, node(&stores).await);
    let pushed = snapshot(1, &[route(model.addr, limited(100, "deny"))]);
    push(&first, &pushed).await;
    push(&second, &pushed).await;
    assert_eq!(post(&first, "k", &prompt(false, "")).await.status, 200);
    settled().await;
    let refused = post(&second, "k", &prompt(false, "")).await;
    assert_eq!(
        refused.status, 429,
        "the other node counted the first node's tokens"
    );
    assert_eq!(model.calls().len(), 1);
}

#[tokio::test]
async fn ai_store_down_deny() {
    clear_of_midnight().await;
    let mut rig = rig(limited(1000, "deny"), Reply::json(&chat(1, 1))).await;
    assert_eq!(
        post(&rig.podgate, "k", &prompt(false, "")).await.status,
        200
    );
    rig.valkey.stop();
    for _ in 0..4 {
        let answer = post(&rig.podgate, "k", &prompt(false, "")).await;
        assert_eq!(answer.status, 503, "{}", answer.text());
        assert_eq!(answer.header("retry-after"), Some("1"));
        assert_eq!(answer.json(), json!({"error": "token budget unavailable"}));
    }
    assert_eq!(
        rig.model.calls().len(),
        1,
        "the model saw nothing while the store was down"
    );
}

#[tokio::test]
async fn ai_store_down_allow() {
    clear_of_midnight().await;
    let mut rig = rig(limited(1000, "allow"), Reply::json(&chat(1, 1))).await;
    assert_eq!(
        post(&rig.podgate, "k", &prompt(false, "")).await.status,
        200
    );
    rig.valkey.stop();
    for _ in 0..3 {
        let answer = post(&rig.podgate, "k", &prompt(false, "")).await;
        assert_eq!(answer.status, 200, "{}", answer.text());
        assert!(answer.header("x-ratelimit-remaining-tokens").is_none());
    }
    assert_eq!(rig.model.calls().len(), 4);
    let metrics = rig.podgate.admin_get("/metrics").await.body;
    assert!(
        metric(&metrics, r#"podgate_quota_unmetered_total{store="main"}"#).unwrap_or(0) >= 3,
        "{metrics}"
    );
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(&bytes[..2], [0x1f, 0x8b], "a gzip frame");
    miniz_oxide::inflate::decompress_to_vec(&bytes[10..bytes.len() - 8]).expect("valid deflate")
}

#[tokio::test]
async fn ai_compressed_response_counted() {
    clear_of_midnight().await;
    let mut body = chat(30, 40);
    body["choices"][0]["message"]["content"] = json!("lorem ipsum ".repeat(300));
    let rig = rig(limited(1000, "deny"), Reply::json(&body)).await;
    let answer = send(
        &rig.podgate,
        &request(
            "k",
            "application/json",
            prompt(false, "").as_bytes(),
            "Accept-Encoding: gzip\r\n",
        ),
    )
    .await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.header("content-encoding"),
        Some("gzip"),
        "the client still gets gzip"
    );
    let plain: Value = serde_json::from_slice(&gunzip(&answer.body)).expect("json");
    assert_eq!(plain["usage"]["total_tokens"], 70);
    assert_eq!(
        rig.model.calls()[0].header("accept-encoding").as_deref(),
        Some("identity"),
        "the model is asked for plain text, so the count can read it"
    );
    settled().await;
    let next = post(&rig.podgate, "k", &prompt(false, "")).await;
    assert_eq!(next.number("x-ratelimit-remaining-tokens"), 1000 - 70);
    let metrics = rig.podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_ai_tokens_estimated_total{tenant="t1",app="a"}"#
        ),
        Some(0)
    );
}

#[tokio::test]
async fn ai_encoded_upstream_estimated() {
    clear_of_midnight().await;
    // A model that ignores `identity` and answers gzip anyway: nothing is read, the bytes are
    // estimated.
    let mut reply = Reply::json(&chat(1, 1));
    reply
        .headers
        .push(("Content-Encoding".into(), "gzip".into()));
    reply.parts = vec![(Duration::ZERO, vec![7_u8; 400])];
    let rig = rig(limited(1000, "deny"), reply).await;
    let request_body = prompt(false, "");
    assert_eq!(post(&rig.podgate, "k", &request_body).await.status, 200);
    settled().await;
    let metrics = rig.podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_ai_tokens_estimated_total{tenant="t1",app="a"}"#
        ),
        Some(1)
    );
    let next = post(&rig.podgate, "k", &request_body).await;
    let spent = (request_body.len() as u64 + 400).div_ceil(4);
    assert_eq!(next.number("x-ratelimit-remaining-tokens"), 1000 - spent);
}

#[tokio::test]
async fn ai_two_windows_tightest_reported() {
    clear_of_midnight().await;
    let config = json!({
        "limits": [{"limit": 1000, "period": "minute"}, {"limit": 500, "period": "day"}],
        "source": {"header": "x-api-key"}, "store": "main", "on_store_error": "deny",
    });
    let rig = rig(config, Reply::json(&chat(40, 60))).await;
    let first = post(&rig.podgate, "k", &prompt(false, "")).await;
    assert_eq!(first.number("x-ratelimit-limit-tokens"), 500);
    assert_eq!(first.number("x-ratelimit-remaining-tokens"), 500);
    settled().await;
    let second = post(&rig.podgate, "k", &prompt(false, "")).await;
    assert_eq!(
        second.number("x-ratelimit-limit-tokens"),
        500,
        "the day is the tighter window"
    );
    assert_eq!(second.number("x-ratelimit-remaining-tokens"), 400);
}

#[tokio::test]
async fn ai_metrics_series_fixed_per_app() {
    clear_of_midnight().await;
    let rig = rig(limited(1_000_000, "deny"), Reply::json(&chat(1, 1))).await;
    let count = |metrics: &str| {
        metrics
            .lines()
            .filter(|line| line.starts_with("podgate_ai_tokens"))
            .filter(|line| !line.starts_with('#'))
            .count()
    };
    assert_eq!(
        post(&rig.podgate, "key-0", &prompt(false, "")).await.status,
        200
    );
    let before = count(&rig.podgate.admin_get("/metrics").await.body);
    for key in 1..40 {
        post(&rig.podgate, &format!("key-{key}"), &prompt(false, "")).await;
    }
    let metrics = rig.podgate.admin_get("/metrics").await.body;
    assert_eq!(count(&metrics), before, "no key is a label");
    assert_eq!(
        before, 6,
        "four kinds, the estimates and the refusals of one app"
    );
    assert!(!metrics.contains("key-1"), "no key reaches the metrics");
}

#[tokio::test]
async fn ai_plan_lists_fail_open() {
    let valkey = Valkey::start().await;
    let model = Model::start(|_| Reply::json(&chat(1, 1))).await;
    let dir = valkey::scratch("ai-plan");
    let podgate = node(&one_store(&dir, &valkey)).await;
    push(
        &podgate,
        &snapshot(1, &[route(model.addr, limited(100, "deny"))]),
    )
    .await;
    let plan = |config: Value| {
        let podgate = &podgate;
        let pushed = snapshot(2, &[route(model.addr, config)]);
        async move { podgate.admin_post("/v1/snapshot/plan", &pushed).await }
    };
    let kinds = |response: &Response| -> Vec<String> {
        assert_eq!(response.status, 200, "{}", response.body);
        response.json()["posture_changes"]
            .as_array()
            .expect("posture_changes")
            .iter()
            .map(|change| change["kind"].as_str().expect("kind").to_owned())
            .collect()
    };
    assert_eq!(
        kinds(&plan(limited(100, "allow")).await),
        ["ai_tokens_fail_open"]
    );
    assert_eq!(
        kinds(&plan(limited(101, "deny")).await),
        ["ai_tokens_loosened"]
    );
    assert!(kinds(&plan(limited(50, "deny")).await).is_empty());
}

#[tokio::test]
async fn ai_one_per_chain_is_refused() {
    let valkey = Valkey::start().await;
    let model = Model::start(|_| Reply::json(&chat(1, 1))).await;
    let dir = valkey::scratch("ai-chain");
    let podgate = node(&one_store(&dir, &valkey)).await;
    let two = with_chain(
        app("a", &["a.test"], &[serving("r1", model.addr)]),
        &[
            middleware("one", "ai_token_limit", limited(100, "deny")),
            middleware("two", "ai_token_limit", limited(100, "deny")),
        ],
    );
    let refused = podgate.push_snapshot(&snapshot(1, &[two])).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    let message = refused.json()["conflicts"][0]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(message.contains("only one counts"), "{message}");
}

// With `llm_guard`: a held answer is counted from its complete raw body before the
// guard judges it, whatever the verdict.

/// A guard that blocks a response whose text holds `FLAGGED`, and allows everything else.
async fn flag_guard() -> Model {
    Model::start(|seen| {
        let asked = seen.json();
        let flagged = asked["phase"] == "response"
            && asked["text"]
                .as_str()
                .unwrap_or_default()
                .contains("FLAGGED");
        Reply::json(&if flagged {
            json!({"verdict": "block", "category": "leak", "reason": "secret"})
        } else {
            json!({"verdict": "allow"})
        })
    })
    .await
}

/// A model whose answer to a prompt that mentions `flag` says `FLAGGED`, with usage 100 and 50.
async fn flagging_model() -> Model {
    Model::start(|seen| {
        let text = if String::from_utf8_lossy(&seen.body).contains("flag") {
            "FLAGGED secret"
        } else {
            "a harmless answer"
        };
        let mut body = chat(100, 50);
        body["choices"][0]["message"]["content"] = json!(text);
        Reply::json(&body)
    })
    .await
}

fn guarded_route(
    model: SocketAddr,
    guard: SocketAddr,
    guard_config: Value,
    tokens_first: bool,
    tokens: Value,
) -> Value {
    let mut safety = json!({
        "guards": [{"name": "g1", "address": format!("http://{guard}/check"), "phases": ["request", "response"]}],
    });
    safety
        .as_object_mut()
        .expect("object")
        .extend(guard_config.as_object().cloned().unwrap_or_default());
    let mut chain = vec![
        middleware("tokens", "ai_token_limit", tokens),
        middleware("safety", "llm_guard", safety),
    ];
    if !tokens_first {
        chain.reverse();
    }
    with_chain(app("a", &["a.test"], &[serving("r1", model)]), &chain)
}

async fn guarded(snapshot_of: impl FnOnce(&Model, &Model) -> Value) -> (Rig, Model) {
    let valkey = Valkey::start().await;
    let (model, guard) = (flagging_model().await, flag_guard().await);
    let dir = valkey::scratch("ai-guard");
    let podgate = node(&one_store(&dir, &valkey)).await;
    push(&podgate, &snapshot(1, &[snapshot_of(&model, &guard)])).await;
    (
        Rig {
            podgate,
            model,
            valkey,
        },
        guard,
    )
}

#[tokio::test]
async fn ai_tokens_blocked_answer_is_charged() {
    clear_of_midnight().await;
    let (rig, _guard) = guarded(|model, guard| {
        guarded_route(
            model.addr,
            guard.addr,
            json!({}),
            true,
            limited(1000, "deny"),
        )
    })
    .await;
    let blocked = post(&rig.podgate, "k", &prompt_of("flag me")).await;
    assert_eq!(blocked.status, 403, "{}", blocked.text());
    assert!(!blocked.text().contains("FLAGGED"), "{}", blocked.text());
    assert_eq!(
        rig.model.calls().len(),
        1,
        "the model answered, and spent tokens"
    );
    settled().await;
    let next = post(&rig.podgate, "k", &prompt_of("hello")).await;
    assert_eq!(next.status, 200, "{}", next.text());
    assert_eq!(
        next.number("x-ratelimit-remaining-tokens"),
        1000 - 150,
        "the blocked answer cost the key what the model used"
    );
}

#[tokio::test]
async fn ai_tokens_chain_order_does_not_change_the_charge() {
    clear_of_midnight().await;
    let (rig, _guard) = guarded(|model, guard| {
        guarded_route(
            model.addr,
            guard.addr,
            json!({}),
            false,
            limited(1000, "deny"),
        )
    })
    .await;
    let blocked = post(&rig.podgate, "k", &prompt_of("flag me")).await;
    assert_eq!(blocked.status, 403, "{}", blocked.text());
    settled().await;
    let next = post(&rig.podgate, "k", &prompt_of("hello")).await;
    assert_eq!(next.status, 200, "{}", next.text());
    assert_eq!(next.number("x-ratelimit-remaining-tokens"), 1000 - 150);
}

#[tokio::test]
async fn ai_tokens_allowed_held_answer_is_charged_once() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let events = stream_events();
    let model = Model::start({
        let reply = Reply::events(&events);
        move |_| reply.clone()
    })
    .await;
    let guard = flag_guard().await;
    let dir = valkey::scratch("ai-guard-once");
    let podgate = node(&one_store(&dir, &valkey)).await;
    let pushed = guarded_route(
        model.addr,
        guard.addr,
        json!({}),
        true,
        limited(1000, "deny"),
    );
    push(&podgate, &snapshot(1, &[pushed])).await;
    let answer = post(&podgate, "k", &prompt(true, "")).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let expected: String = events
        .iter()
        .filter(|(_, event)| !event.contains("total_tokens"))
        .map(|(_, event)| event.as_str())
        .collect();
    assert_eq!(
        answer.text(),
        expected,
        "a held stream still loses the usage chunk it did not ask for"
    );
    settled().await;
    let next = post(&podgate, "k", &prompt(true, "")).await;
    assert_eq!(
        next.number("x-ratelimit-remaining-tokens"),
        1000 - 7,
        "charged once, not twice"
    );
}

#[tokio::test]
async fn ai_tokens_guard_unavailable_answer_is_charged() {
    clear_of_midnight().await;
    let down = common::refused();
    let (rig, _guard) = guarded(|model, _| {
        guarded_route(
            model.addr,
            down.addr,
            json!({"guards": [{"name": "g1", "address": format!("http://{}/check", down.addr), "phases": ["response"]}]}),
            true,
            limited(1000, "deny"),
        )
    })
    .await;
    let answer = post(&rig.podgate, "k", &prompt_of("hello")).await;
    assert_eq!(answer.status, 503, "{}", answer.text());
    settled().await;
    let metrics = rig.podgate.admin_get("/metrics").await.body;
    let series = |kind: &str| {
        metric(
            &metrics,
            &format!(r#"podgate_ai_tokens_total{{tenant="t1",app="a",kind="{kind}"}}"#),
        )
    };
    assert_eq!(
        series("prompt"),
        Some(100),
        "the model's usage, though the client got a 503"
    );
    assert_eq!(series("completion"), Some(50));
}

#[tokio::test]
async fn ai_tokens_held_over_cap_is_charged_estimated() {
    clear_of_midnight().await;
    let (rig, _guard) = guarded(|model, guard| {
        guarded_route(
            model.addr,
            guard.addr,
            json!({"max_response_bytes": 16}),
            true,
            limited(1000, "deny"),
        )
    })
    .await;
    let answer = post(&rig.podgate, "k", &prompt_of("hello")).await;
    assert_eq!(answer.status, 502, "{}", answer.text());
    settled().await;
    let metrics = rig.podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_ai_tokens_estimated_total{tenant="t1",app="a"}"#
        ),
        Some(1)
    );
    let estimated = metric(
        &metrics,
        r#"podgate_ai_tokens_total{tenant="t1",app="a",kind="estimated"}"#,
    )
    .unwrap_or(0);
    assert!(estimated >= 16 / 4, "at least the cap's worth: {estimated}");
}

/// A chat body with `text` as the user's prompt.
fn prompt_of(text: &str) -> String {
    json!({"model": "m", "messages": [{"role": "user", "content": text}]}).to_string()
}
