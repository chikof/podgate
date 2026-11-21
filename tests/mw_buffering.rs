//! The `buffering` middleware: body size limits, holding a request or response in
//! memory, and charging every held byte to the tenant.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use common::grpc::Client;
use common::{Podgate, TestCert, app, serving, snapshot, with_buffering};
use http::{HeaderMap, HeaderValue, Response};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// What an upstream answers with once it has the whole request.
#[derive(Clone)]
enum Reply {
    /// `200` with this body and a `Content-Length`.
    Body(Vec<u8>),
    /// `200`, `Transfer-Encoding: chunked`: the head at once, then each chunk after a pause.
    Chunked(Vec<Vec<u8>>),
}

/// One request an upstream saw.
#[derive(Clone, Debug)]
struct Seen {
    head: String,
    body: Vec<u8>,
}

/// An upstream that records what it receives. It reads the request body by its framing
/// (`Content-Length` or chunked) and answers when the body is complete.
struct Recorder {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Recorder {
    async fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (counter, log) = (Arc::clone(&connections), Arc::clone(&seen));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(record(stream, reply.clone(), Arc::clone(&log)));
            }
        });
        Self {
            addr,
            connections,
            seen,
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("log").clone()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The body in `raw` (what follows the head) when it is complete under `head`'s framing.
fn complete_body(head: &str, raw: &[u8]) -> Option<Vec<u8>> {
    let lower = head.to_ascii_lowercase();
    if lower.contains("transfer-encoding: chunked") {
        return dechunk(raw);
    }
    let length = lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(0, |value| value.trim().parse().expect("content-length"));
    (raw.len() >= length).then(|| raw[..length].to_vec())
}

/// The decoded body of a chunked stream, once its last chunk is in.
fn dechunk(mut raw: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = find(raw, b"\r\n")?;
        let size = usize::from_str_radix(std::str::from_utf8(&raw[..line_end]).ok()?, 16).ok()?;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        if raw.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

async fn record(mut stream: TcpStream, reply: Reply, log: Arc<Mutex<Vec<Seen>>>) {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    let mut index = None;
    loop {
        if let Some(end) = find(&raw, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..end]).into_owned();
            let after = raw[end + 4..].to_vec();
            let body = complete_body(&head, &after);
            {
                let mut log = log.lock().expect("log");
                let at = *index.get_or_insert_with(|| {
                    log.push(Seen {
                        head: head.clone(),
                        body: Vec::new(),
                    });
                    log.len() - 1
                });
                log[at].body = body.clone().unwrap_or(after);
            }
            if body.is_some() {
                break;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
        }
    }
    match reply {
        Reply::Body(body) => {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            drop(stream.write_all(head.as_bytes()).await);
            drop(stream.write_all(&body).await);
        }
        Reply::Chunked(chunks) => {
            let head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            drop(stream.write_all(head.as_bytes()).await);
            for chunk in chunks {
                sleep(Duration::from_millis(150)).await;
                let framed = [
                    format!("{:x}\r\n", chunk.len()).into_bytes(),
                    chunk,
                    b"\r\n".to_vec(),
                ]
                .concat();
                if stream.write_all(&framed).await.is_err() {
                    return;
                }
            }
            drop(stream.write_all(b"0\r\n\r\n").await);
        }
    }
    drop(stream.shutdown().await);
}

/// A response as the proxy sent it: status, lowercase headers, and everything after the head.
struct Raw {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Raw {
    fn parse(raw: &[u8]) -> Self {
        let end = find(raw, b"\r\n\r\n")
            .unwrap_or_else(|| panic!("no head in {:?}", String::from_utf8_lossy(raw)));
        let head = String::from_utf8_lossy(&raw[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("bad status line in {head:?}"));
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        Self {
            status,
            headers,
            body: raw[end + 4..].to_vec(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {:?}", self.body))
    }

    /// The body, decoded when the response is chunked.
    fn text(&self) -> String {
        let body = if self.header("transfer-encoding") == Some("chunked") {
            dechunk(&self.body).unwrap_or_else(|| self.body.clone())
        } else {
            self.body.clone()
        };
        String::from_utf8_lossy(&body).into_owned()
    }
}

async fn connect(podgate: &Podgate) -> TcpStream {
    TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect to the proxy")
}

async fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    timeout(IO_TIMEOUT, async {
        // A connection the proxy resets after answering still delivered the answer.
        drop(stream.read_to_end(&mut raw).await);
    })
    .await
    .expect("response in time");
    raw
}

/// Sends `request` as it is and reads until the proxy closes.
async fn exchange(podgate: &Podgate, request: &[u8]) -> Raw {
    let mut stream = connect(podgate).await;
    stream.write_all(request).await.expect("send request");
    Raw::parse(&read_all(&mut stream).await)
}

fn post(host: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut request =
        format!("POST / HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n").into_bytes();
    request.extend_from_slice(body);
    request
}

fn chunked(chunks: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for chunk in chunks {
        body.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        body.extend_from_slice(chunk);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    body
}

/// Tenant `t1` with `max_buffer_bytes`, one app per `(host, upstream, buffering config)`.
async fn serve(max_buffer_bytes: u64, apps: &[(&str, SocketAddr, Value)]) -> Podgate {
    let podgate = Podgate::start().await;
    let apps: Vec<Value> = apps
        .iter()
        .map(|(host, addr, config)| {
            with_buffering(app(host, &[host], &[serving("r1", *addr)]), config.clone())
        })
        .collect();
    let mut pushed = snapshot(1, &apps);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(max_buffer_bytes);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    podgate
}

fn series(metrics: &str, name: &str) -> u64 {
    let prefix = format!("{name}{{tenant=\"t1\"}} ");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.parse().expect("integer sample"))
}

async fn metric(podgate: &Podgate, name: &str) -> u64 {
    series(&podgate.admin_get("/metrics").await.body, name)
}

async fn wait_for_metric(podgate: &Podgate, name: &str, wanted: u64) {
    for _ in 0..200 {
        if metric(podgate, name).await == wanted {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "{name} never reached {wanted}; it is {}",
        metric(podgate, name).await
    );
}

#[tokio::test]
async fn buffering_413_on_content_length() {
    let upstream = Recorder::start(Reply::Body(b"ok".to_vec())).await;
    let podgate = serve(
        1 << 20,
        &[(
            "a.test",
            upstream.addr,
            json!({ "max_request_body_bytes": 10 }),
        )],
    )
    .await;

    let refused = exchange(
        &podgate,
        &post("a.test", "Content-Length: 20\r\n", &[b'x'; 20]),
    )
    .await;
    assert_eq!(refused.status, 413);
    assert_eq!(refused.json(), json!({ "error": "request body too large" }));
    assert_eq!(upstream.connections(), 0, "the upstream was never dialled");

    let allowed = exchange(
        &podgate,
        &post("a.test", "Content-Length: 10\r\n", &[b'y'; 10]),
    )
    .await;
    assert_eq!(allowed.status, 200);
    assert_eq!(upstream.seen()[0].body, [b'y'; 10]);
}

#[tokio::test]
async fn buffering_413_on_chunked_overflow() {
    let upstream = Recorder::start(Reply::Body(b"ok".to_vec())).await;
    let podgate = serve(
        1 << 20,
        &[(
            "a.test",
            upstream.addr,
            json!({ "max_request_body_bytes": 10 }),
        )],
    )
    .await;
    let te = "Transfer-Encoding: chunked\r\n";

    let refused = exchange(&podgate, &post("a.test", te, &chunked(&[&[b'x'; 20]]))).await;
    assert_eq!(refused.status, 413);
    assert_eq!(refused.json(), json!({ "error": "request body too large" }));
    assert!(
        upstream.seen().iter().all(|seen| seen.body.is_empty()),
        "the upstream never saw the over-limit chunk: {:?}",
        upstream.seen()
    );

    let allowed = exchange(&podgate, &post("a.test", te, &chunked(&[b"hello"]))).await;
    assert_eq!(allowed.status, 200);
    assert!(upstream.seen().iter().any(|seen| seen.body == b"hello"));
}

#[tokio::test]
async fn buffer_request_hides_slow_client_from_upstream() {
    let buffered = Recorder::start(Reply::Body(b"ok".to_vec())).await;
    let streamed = Recorder::start(Reply::Body(b"ok".to_vec())).await;
    let podgate = serve(
        1 << 20,
        &[
            (
                "buffered.test",
                buffered.addr,
                json!({ "max_request_body_bytes": 1000, "buffer_request": true }),
            ),
            (
                "streamed.test",
                streamed.addr,
                json!({ "max_request_body_bytes": 1000 }),
            ),
        ],
    )
    .await;

    let mut slow = Vec::new();
    for host in ["buffered.test", "streamed.test"] {
        let mut stream = connect(&podgate).await;
        stream
            .write_all(&post(host, "Content-Length: 10\r\n", b"01234"))
            .await
            .expect("first half");
        slow.push(stream);
    }
    sleep(Duration::from_millis(500)).await;
    assert_eq!(
        buffered.connections(),
        0,
        "the upstream saw nothing of a body that is not complete"
    );
    assert_eq!(
        streamed.connections(),
        1,
        "control: without buffer_request the upstream is held by the slow client"
    );

    for stream in &mut slow {
        stream.write_all(b"56789").await.expect("second half");
    }
    for stream in &mut slow {
        let response = Raw::parse(&read_all(stream).await);
        assert_eq!(response.status, 200);
    }
    let seen = buffered.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body, b"0123456789");
    assert!(
        seen[0]
            .head
            .to_ascii_lowercase()
            .contains("content-length: 10"),
        "{}",
        seen[0].head
    );
}

#[tokio::test]
async fn buffering_charged_to_tenant_budget() {
    let upstream = Recorder::start(Reply::Body(b"ok".to_vec())).await;
    let podgate = serve(
        4096,
        &[(
            "a.test",
            upstream.addr,
            json!({ "max_request_body_bytes": 1000, "buffer_request": true }),
        )],
    )
    .await;

    let mut stream = connect(&podgate).await;
    stream
        .write_all(&post("a.test", "Content-Length: 1000\r\n", &[b'a'; 400]))
        .await
        .expect("part of the body");
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 1000).await;
    assert_eq!(upstream.connections(), 0);

    stream.write_all(&[b'a'; 600]).await.expect("the rest");
    assert_eq!(Raw::parse(&read_all(&mut stream).await).status, 200);
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 0).await;
    let peak = metric(&podgate, "podgate_tenant_buffer_bytes_peak").await;
    assert_eq!(peak, 1000, "the charge was the declared length, taken once");
}

#[tokio::test]
async fn buffering_over_budget_503() {
    let upstream = Recorder::start(Reply::Body(b"ok".to_vec())).await;
    let podgate = serve(
        1500,
        &[(
            "a.test",
            upstream.addr,
            json!({ "max_request_body_bytes": 1000, "buffer_request": true }),
        )],
    )
    .await;

    let mut holder = connect(&podgate).await;
    holder
        .write_all(&post("a.test", "Content-Length: 1000\r\n", &[b'a'; 100]))
        .await
        .expect("part of the body");
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 1000).await;

    let refused = exchange(
        &podgate,
        &post("a.test", "Content-Length: 1000\r\n", &[b'b'; 1000]),
    )
    .await;
    assert_eq!(refused.status, 503);
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(
        refused.json(),
        json!({ "error": "buffering is over the tenant's budget" })
    );
    assert_eq!(
        metric(&podgate, "podgate_tenant_buffering_refused_total").await,
        1
    );
    assert_eq!(metric(&podgate, "podgate_tenant_buffer_bytes").await, 1000);

    holder.write_all(&[b'a'; 900]).await.expect("the rest");
    assert_eq!(Raw::parse(&read_all(&mut holder).await).status, 200);
}

#[tokio::test]
async fn response_content_length_over_limit_502() {
    let big = Recorder::start(Reply::Body(vec![b'x'; 100])).await;
    let small = Recorder::start(Reply::Body(vec![b'y'; 30])).await;
    let config = json!({ "max_response_body_bytes": 50, "buffer_response": true });
    let podgate = serve(
        1 << 20,
        &[
            ("big.test", big.addr, config.clone()),
            ("small.test", small.addr, config),
        ],
    )
    .await;

    let refused = exchange(&podgate, &post("big.test", "Content-Length: 0\r\n", b"")).await;
    assert_eq!(refused.status, 502);
    assert_eq!(
        refused.json(),
        json!({ "error": "upstream response too large" })
    );

    let allowed = exchange(&podgate, &post("small.test", "Content-Length: 0\r\n", b"")).await;
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.text(), "y".repeat(30));
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 0).await;
}

#[tokio::test]
async fn buffering_response_over_budget_503() {
    let upstream = Recorder::start(Reply::Body(vec![b'x'; 200])).await;
    let podgate = serve(
        100,
        &[(
            "a.test",
            upstream.addr,
            json!({ "max_response_body_bytes": 1000, "buffer_response": true }),
        )],
    )
    .await;

    let refused = exchange(&podgate, &post("a.test", "Content-Length: 0\r\n", b"")).await;
    assert_eq!(refused.status, 503);
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(
        metric(&podgate, "podgate_tenant_buffering_refused_total").await,
        1
    );
}

/// Pingora sends the response head before the body, so a chunked response over the limit cannot
/// become a `502`: the body is withheld and the connection is reset (change 0052 Decisions).
#[tokio::test]
async fn buffer_response_chunked_over_limit_resets() {
    let over = Recorder::start(Reply::Chunked(vec![vec![b'a'; 30], vec![b'b'; 30]])).await;
    let within = Recorder::start(Reply::Chunked(vec![vec![b'c'; 10], vec![b'd'; 10]])).await;
    let config = json!({ "max_response_body_bytes": 40, "buffer_response": true });
    let podgate = serve(
        1 << 20,
        &[
            ("over.test", over.addr, config.clone()),
            ("within.test", within.addr, config),
        ],
    )
    .await;

    let mut stream = connect(&podgate).await;
    stream
        .write_all(&post("over.test", "Content-Length: 0\r\n", b""))
        .await
        .expect("request");
    let raw = read_all(&mut stream).await;
    let text = String::from_utf8_lossy(&raw);
    assert!(
        !text.contains("0\r\n\r\n"),
        "the response was not completed: {text:?}"
    );
    assert!(
        !text.contains(&"a".repeat(30)),
        "no part of the body got out: {text:?}"
    );
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 0).await;

    let allowed = exchange(&podgate, &post("within.test", "Content-Length: 0\r\n", b"")).await;
    assert_eq!(allowed.status, 200);
    assert_eq!(
        allowed.text(),
        format!("{}{}", "c".repeat(10), "d".repeat(10))
    );
    assert_eq!(
        dechunk(&allowed.body).map(|body| body.len()),
        Some(20),
        "{:?}",
        allowed.body
    );
    assert_eq!(
        allowed.body,
        chunked(&[&[b"c".repeat(10), b"d".repeat(10)].concat()]),
        "the held body goes out as one chunk"
    );
}

#[tokio::test]
async fn response_limit_without_buffer_rejected() {
    let upstream = Recorder::start(Reply::Body(b"ok".to_vec())).await;
    let podgate = Podgate::start().await;
    for (config, mentions) in [
        (
            json!({ "max_response_body_bytes": 10 }),
            "needs buffer_response",
        ),
        (
            json!({ "max_request_body_bytes": 70000, "buffer_request": true }),
            "replay buffer",
        ),
        (json!({ "buffer_request": true }), "buffer_request needs"),
        (json!({}), "set max_request_body_bytes"),
    ] {
        let pushed = snapshot(
            1,
            &[with_buffering(
                app("a.test", &["a.test"], &[serving("r1", upstream.addr)]),
                config,
            )],
        );
        let response = podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 422, "{}", response.body);
        let rejection = &response.json()["conflicts"][0];
        assert_eq!(rejection["code"], "invalid_middleware", "{rejection}");
        assert!(
            rejection["message"]
                .as_str()
                .is_some_and(|m| m.contains(mentions)),
            "{rejection}"
        );
    }
}

#[tokio::test]
async fn buffering_skips_upgrade() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 4096];
                let mut head = Vec::new();
                while find(&head, b"\r\n\r\n").is_none() {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&buf[..read]),
                    }
                }
                let reply = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
                if stream.write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buf[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    let podgate = serve(
        1 << 20,
        &[(
            "a.test",
            addr,
            json!({ "max_request_body_bytes": 1, "buffer_request": true,
                    "max_response_body_bytes": 1, "buffer_response": true }),
        )],
    )
    .await;

    let mut stream = connect(&podgate).await;
    stream
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .expect("handshake");
    let mut head = Vec::new();
    let mut buf = [0_u8; 1024];
    timeout(IO_TIMEOUT, async {
        while find(&head, b"\r\n\r\n").is_none() {
            let read = stream.read(&mut buf).await.expect("read handshake");
            assert!(read > 0, "closed during the handshake: {head:?}");
            head.extend_from_slice(&buf[..read]);
        }
    })
    .await
    .expect("handshake answered");
    assert_eq!(Raw::parse(&head).status, 101);

    let frames = [b'z'; 200];
    stream.write_all(&frames).await.expect("frames");
    let mut echoed = Raw::parse(&head).body;
    timeout(IO_TIMEOUT, async {
        while echoed.len() < frames.len() {
            let read = stream.read(&mut buf).await.expect("read echo");
            assert!(
                read > 0,
                "closed while echoing: {} bytes back",
                echoed.len()
            );
            echoed.extend_from_slice(&buf[..read]);
        }
    })
    .await
    .expect("echo in time");
    assert_eq!(
        echoed, frames,
        "frames far over the cap went through both ways"
    );
}

#[tokio::test]
async fn expect_continue_over_cap_417() {
    let upstream = Recorder::start(Reply::Body(b"ok".to_vec())).await;
    let podgate = serve(
        1 << 20,
        &[(
            "a.test",
            upstream.addr,
            json!({ "max_request_body_bytes": 10, "buffer_request": true }),
        )],
    )
    .await;

    let mut stream = connect(&podgate).await;
    stream
        .write_all(&post(
            "a.test",
            "Expect: 100-continue\r\nContent-Length: 100\r\n",
            b"",
        ))
        .await
        .expect("head only: the client waits for the verdict");
    let refused = Raw::parse(&read_all(&mut stream).await);
    assert_eq!(refused.status, 417);
    assert_eq!(refused.json(), json!({ "error": "request body too large" }));
    assert_eq!(upstream.connections(), 0);

    let mut stream = connect(&podgate).await;
    stream
        .write_all(&post(
            "a.test",
            "Expect: 100-continue\r\nContent-Length: 5\r\n",
            b"",
        ))
        .await
        .expect("head");
    let mut interim = Vec::new();
    let mut buf = [0_u8; 256];
    timeout(IO_TIMEOUT, async {
        while find(&interim, b"\r\n\r\n").is_none() {
            let read = stream.read(&mut buf).await.expect("read interim");
            assert!(read > 0, "closed before 100 Continue");
            interim.extend_from_slice(&buf[..read]);
        }
    })
    .await
    .expect("100 Continue in time");
    assert!(
        String::from_utf8_lossy(&interim).starts_with("HTTP/1.1 100"),
        "{interim:?}"
    );
    stream.write_all(b"hello").await.expect("body");
    let rest = read_all(&mut stream).await;
    let allowed = String::from_utf8_lossy(&rest);
    assert!(allowed.contains("200 OK"), "{allowed}");
    let seen = upstream.seen();
    assert_eq!(seen[0].body, b"hello");
    assert!(
        !seen[0].head.to_ascii_lowercase().contains("expect:"),
        "the upstream never sees an expectation the proxy already answered: {}",
        seen[0].head
    );
}

/// An HTTP/2 cleartext upstream whose every response is a `text/plain` body in two DATA frames
/// (`first`, `second`, a pause between) that do not end the stream, then the trailers
/// `x-checksum: abc123` and `x-done: yes`. `declared` also sends a `Content-Length`.
async fn trailer_upstream(first: &'static str, second: &'static str, declared: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(tcp).await else {
                    return;
                };
                while let Some(Ok((_request, mut respond))) = connection.accept().await {
                    tokio::spawn(async move {
                        let mut head = Response::builder()
                            .status(200)
                            .header("content-type", "text/plain");
                        if declared {
                            head = head.header("content-length", first.len() + second.len());
                        }
                        let Ok(mut send) =
                            respond.send_response(head.body(()).expect("head"), false)
                        else {
                            return;
                        };
                        drop(send.send_data(Bytes::from_static(first.as_bytes()), false));
                        sleep(Duration::from_millis(20)).await;
                        drop(send.send_data(Bytes::from_static(second.as_bytes()), false));
                        sleep(Duration::from_millis(20)).await;
                        let mut trailers = HeaderMap::new();
                        trailers.insert("x-checksum", HeaderValue::from_static("abc123"));
                        trailers.insert("x-done", HeaderValue::from_static("yes"));
                        drop(send.send_trailers(trailers));
                    });
                }
            });
        }
    });
    addr
}

/// A held HTTP/2 response that ends in trailers reaches the client whole: the body first, the
/// trailers after it; an HTTP/1.1 client gets the body. With and without a declared length.
#[tokio::test]
async fn buffer_response_releases_body_before_h2_trailers() {
    const HOST: &str = "t.test";
    for declared in [false, true] {
        let upstream = trailer_upstream("hello ", "trailers", declared).await;
        let podgate = Podgate::start().await;
        let cert = TestCert::new(&[HOST]);
        let mut revision = serving("r1", upstream);
        revision["services"][0]["servers"][0]["url"] = json!(format!("h2c://{upstream}"));
        let config = json!({ "max_response_body_bytes": 65536, "buffer_response": true });
        let mut pushed = snapshot(1, &[with_buffering(app("t", &[HOST], &[revision]), config)]);
        pushed["certificates"] = json!([cert.entry(&[HOST])]);
        let reply = podgate.push_snapshot(&pushed).await;
        assert_eq!(reply.status, 200, "{}", reply.body);

        let client = Client::tls(podgate.tls_addr, HOST, &cert.der).await;
        let mut call = client.start_request("GET", "text/plain", "/", &[]).await;
        call.finish();
        let raw = call.raw().await;
        assert_eq!(raw.status, 200, "declared {declared}");
        assert_eq!(
            String::from_utf8_lossy(&raw.body),
            "hello trailers",
            "declared {declared}"
        );
        let trailers = raw.trailers.expect("the trailers arrive");
        assert_eq!(trailers.get("x-checksum").expect("checksum"), "abc123");
        assert_eq!(trailers.get("x-done").expect("done"), "yes");

        // An HTTP/1.1 client has no trailers to receive, but gets the whole body.
        let plain = exchange(&podgate, &post(HOST, "Content-Length: 0\r\n", b"")).await;
        assert_eq!(plain.status, 200, "declared {declared}");
        assert_eq!(plain.text(), "hello trailers", "declared {declared}");
        wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 0).await;
    }
}
