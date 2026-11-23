//! The `mirroring` service: copies of a share of the requests go to other services
//! of the app, and never change the real response or take capacity from real traffic. The pure
//! rules (names, percent, budget, sampling, the HTTP/1.1 exchange) are unit-tested in
//! `src/service/mirroring.rs` and its `run.rs` and `send.rs`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Podgate, app, refused, router, service, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// When a test server answers.
#[derive(Clone, Copy)]
enum Delay {
    /// At once.
    Never,
    /// After this long, every request.
    All(Duration),
    /// After this long, requests whose path starts with `/slow`.
    Slow(Duration),
}

/// What a test server saw of one request.
#[derive(Clone, Debug)]
struct Seen {
    head: String,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    }

    fn path(&self) -> &str {
        self.head.split(' ').nth(1).unwrap_or_default()
    }
}

/// A server that records what it receives, body included, and answers `body`.
struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    async fn start(body: &'static str, delay: Delay) -> Self {
        Self::answering(body, 200, delay).await
    }

    async fn answering(body: &'static str, status: u16, delay: Delay) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(stream, (status, body), delay, Arc::clone(&log)));
            }
        });
        Self { addr, seen }
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen").clone()
    }

    fn count(&self) -> usize {
        self.requests().len()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The body of a chunked message once it is complete, else `None`.
fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find(rest, b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).ok()?.trim(), 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return find(rest, b"\r\n").map(|_| out);
        }
        if rest.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

async fn serve(
    mut stream: TcpStream,
    (status, body): (u16, &'static str),
    delay: Delay,
    log: Arc<Mutex<Vec<Seen>>>,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let (head, payload) = loop {
        if let Some(end) = find(&buffer, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end + 4]).into_owned();
            let rest = &buffer[end + 4..];
            let probe = Seen {
                head: head.clone(),
                body: Vec::new(),
            };
            if let Some(length) = probe
                .header("content-length")
                .and_then(|v| v.parse::<usize>().ok())
            {
                if rest.len() >= length {
                    break (head, rest[..length].to_vec());
                }
            } else if probe
                .header("transfer-encoding")
                .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
            {
                if let Some(payload) = dechunk(rest) {
                    break (head, payload);
                }
            } else {
                break (head, Vec::new());
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    };
    let seen = Seen {
        head,
        body: payload,
    };
    let pause = match delay {
        Delay::Never => None,
        Delay::All(pause) => Some(pause),
        Delay::Slow(pause) => seen.path().starts_with("/slow").then_some(pause),
    };
    log.lock().expect("seen").push(seen);
    if let Some(pause) = pause {
        sleep(pause).await;
    }
    let reply = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    drop(stream.write_all(reply.as_bytes()).await);
    drop(stream.shutdown().await);
}

/// The mirroring service `m`: `config` holds fields next to the name and type.
fn mirroring(shadows: &[(&str, f64)], config: Value) -> Value {
    let mirrors: Vec<Value> = shadows
        .iter()
        .map(|(service, percent)| json!({ "service": service, "percent": percent }))
        .collect();
    let mut declared =
        json!({ "name": "m", "type": "mirroring", "service": "web", "mirrors": mirrors });
    if let (Some(object), Value::Object(extra)) = (declared.as_object_mut(), config) {
        object.extend(extra);
    }
    declared
}

/// An app answering `a.test` through the mirroring service `m`, whose main service `web` is on
/// `main` and which has the services `extra` besides.
fn mirrored_app(main: SocketAddr, extra: &[Value], mirror: Value) -> Value {
    let mut services = vec![service("web", &[main])];
    services.extend(extra.iter().cloned());
    services.push(mirror);
    let revision = json!({ "id": "r1", "state": "serving", "weight": 100, "services": services });
    let mut app = app("a", &["a.test"], &[revision]);
    app["routers"] = json!([router("default", json!({ "host": ["a.test"] }), "m")]);
    app
}

fn with_budget(mut snapshot: Value, max_inflight: u32, max_buffer_bytes: u64) -> Value {
    snapshot["tenants"][0]["budget"] =
        json!({ "max_inflight": max_inflight, "max_buffer_bytes": max_buffer_bytes });
    snapshot
}

async fn push(podgate: &Podgate, version: u64, app: Value) {
    let pushed = podgate.push_snapshot(&snapshot(version, &[app])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
}

/// Waits until `condition` holds, up to five seconds.
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        sleep(Duration::from_millis(20)).await;
    }
}

/// Waits until `server` stops receiving, so a count taken after it is final.
async fn settled(server: &Server) -> usize {
    let mut last = server.count();
    loop {
        sleep(Duration::from_millis(400)).await;
        let now = server.count();
        if now == last {
            return now;
        }
        last = now;
    }
}

/// The value of the sample `series` on `GET /metrics`.
async fn metric(podgate: &Podgate, series: &str) -> u64 {
    let text = podgate.admin_get("/metrics").await.body;
    text.lines()
        .find_map(|line| line.strip_prefix(series)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("no {series} in /metrics"))
}

async fn dropped(podgate: &Podgate, reason: &str) -> u64 {
    metric(
        podgate,
        &format!("podgate_mirror_dropped_total{{reason=\"{reason}\"}}"),
    )
    .await
}

/// Waits until `shadow` has received `copies` copies or `podgate` has shed them for the tenant,
/// up to five seconds. A copy is decided and sent on its own task, so the count of the shadow
/// alone does not say whether one is still on its way.
async fn copies_decided(podgate: &Podgate, shadow: &Server, copies: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let shed = dropped(podgate, "tenant").await;
        let decided = shadow.count() as u64 + shed;
        if decided == copies as u64 {
            return;
        }
        assert!(
            decided < copies as u64 && Instant::now() < deadline,
            "{copies} copies were wanted, the shadow saw {} and {shed} were shed",
            shadow.count()
        );
        sleep(Duration::from_millis(20)).await;
    }
}

/// Waits until `podgate` has shed `shed` copies for `reason` in all, up to five seconds.
async fn shed_reaches(podgate: &Podgate, reason: &str, shed: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while dropped(podgate, reason).await < shed {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {shed} copies shed for {reason}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

/// The paths `server` has received so far.
fn paths(server: &Server) -> Vec<String> {
    server
        .requests()
        .iter()
        .map(|seen| seen.path().to_string())
        .collect()
}

/// Sends raw bytes to the proxy and returns the status and the whole response text.
async fn raw(podgate: &Podgate, request: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    stream.write_all(request).await.expect("send");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("response in time")
        .expect("read");
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_default();
    (status, text)
}

/// The status of a websocket-style request the upstream answers with a plain `200`. The
/// connection is not read to its end: an upgrade request keeps it open.
async fn upgrade_status(podgate: &Podgate, path: &str) -> u16 {
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.expect("send");
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    while find(&seen, b"\r\n\r\n").is_none() {
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("response in time")
            .expect("read");
        assert!(read > 0, "the proxy closed without answering");
        seen.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8_lossy(&seen)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_default()
}

fn post(path: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut request =
        format!("POST {path} HTTP/1.1\r\nHost: a.test\r\n{headers}Connection: close\r\n\r\n")
            .into_bytes();
    request.extend_from_slice(body);
    request
}

fn rejection(response: &common::Response) -> Value {
    assert_eq!(response.status, 422, "{}", response.body);
    response.json()["conflicts"][0].clone()
}

#[tokio::test]
async fn mirror_percent_sampling() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Never).await;
    let shadow = Server::start("shadow", Delay::Never).await;
    let app = |percent: f64| {
        mirrored_app(
            main.addr,
            &[service("shadow", &[shadow.addr])],
            mirroring(&[("shadow", percent)], json!({})),
        )
    };

    push(&podgate, 1, app(30.0)).await;
    for _ in 0..1000 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!((response.status, response.body.as_str()), (200, "main"));
    }
    let mirrored = settled(&shadow).await;
    assert!(
        (225..=375).contains(&mirrored),
        "30% of 1000 requests, got {mirrored}"
    );
    assert_eq!(
        main.count(),
        1000,
        "every request reaches the main service once"
    );

    push(&podgate, 2, app(100.0)).await;
    for _ in 0..100 {
        podgate.get("a.test", "/").await;
    }
    assert_eq!(settled(&shadow).await, mirrored + 100, "100% is exact");

    push(&podgate, 3, app(0.0)).await;
    for _ in 0..100 {
        podgate.get("a.test", "/").await;
    }
    assert_eq!(settled(&shadow).await, mirrored + 100, "0% is exact");

    push(&podgate, 4, app(0.1)).await;
    for _ in 0..50 {
        podgate.get("a.test", "/").await;
    }
    assert!(
        settled(&shadow).await <= mirrored + 100 + 3,
        "decimals are accepted: 0.1% of 50"
    );
    assert_eq!(dropped(&podgate, "backend").await, 0);
}

#[tokio::test]
async fn mirror_failure_does_not_affect_response() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Never).await;
    let closed = refused();
    let failing = Server::answering("shadow broke", 500, Delay::Never).await;
    let app = mirrored_app(
        main.addr,
        &[
            service("closed", &[closed.addr]),
            service("failing", &[failing.addr]),
        ],
        mirroring(&[("closed", 100.0), ("failing", 100.0)], json!({})),
    );
    push(&podgate, 1, app).await;
    for _ in 0..20 {
        let response = podgate.get("a.test", "/page?x=1").await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "main");
        assert_eq!(response.header("content-type"), Some("text/plain"));
    }
    eventually("the failing shadow to see its copies", || {
        failing.count() == 20
    })
    .await;
    let series = "podgate_mirror_sent_total{result=\"error\"}";
    let deadline = Instant::now() + Duration::from_secs(5);
    while metric(&podgate, series).await < 20 {
        assert!(
            Instant::now() < deadline,
            "the refused copies were not counted"
        );
        sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        metric(&podgate, series).await,
        20,
        "a copy that cannot connect is counted as an error"
    );
    let answered = "podgate_mirror_sent_total{result=\"ok\"}";
    while metric(&podgate, answered).await < 20 {
        assert!(
            Instant::now() < deadline,
            "the 500 answers were not counted"
        );
        sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(main.count(), 20);
}

#[tokio::test]
async fn mirror_never_slows_primary() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Never).await;
    let slow = Server::start("slow", Delay::All(Duration::from_secs(3))).await;
    let app = mirrored_app(
        main.addr,
        &[service("slow", &[slow.addr])],
        mirroring(&[("slow", 100.0)], json!({})),
    );
    push(&podgate, 1, app).await;
    for _ in 0..5 {
        let started = Instant::now();
        let response = podgate.get("a.test", "/").await;
        let took = started.elapsed();
        assert_eq!((response.status, response.body.as_str()), (200, "main"));
        assert!(
            took < Duration::from_millis(1500),
            "a slow shadow delayed the answer: {took:?}"
        );
    }
    eventually("the slow shadow to hold its copies", || slow.count() == 5).await;
}

#[tokio::test]
async fn mirror_body_forwarded() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Never).await;
    let shadow = Server::start("shadow", Delay::Never).await;
    let app = mirrored_app(
        main.addr,
        &[service("shadow", &[shadow.addr])],
        mirroring(
            &[("shadow", 100.0)],
            json!({ "mirror_body": true, "max_body_size": 4096 }),
        ),
    );
    push(&podgate, 1, app).await;
    let (status, _) = raw(
        &podgate,
        &post(
            "/send?a=1",
            "Content-Length: 11\r\nContent-Type: text/plain\r\n",
            b"hello world",
        ),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = raw(
        &podgate,
        &post(
            "/chunked",
            "Transfer-Encoding: chunked\r\n",
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        ),
    )
    .await;
    assert_eq!(status, 200);
    eventually("both copies", || shadow.count() == 2).await;
    let copies = shadow.requests();
    let by_path = |path: &str| {
        copies
            .iter()
            .find(|seen| seen.path().starts_with(path))
            .expect(path)
    };
    let sent = by_path("/send");
    assert_eq!(sent.path(), "/send?a=1");
    assert_eq!(sent.body, b"hello world");
    assert_eq!(sent.header("content-length"), Some("11"));
    assert_eq!(sent.header("content-type"), Some("text/plain"));
    assert_eq!(by_path("/chunked").body, b"hello world");
    let at_main = main.requests();
    assert!(
        at_main.iter().all(|seen| seen.body == b"hello world"),
        "the main service got the bodies too"
    );
    assert_eq!(dropped(&podgate, "incomplete").await, 0);
}

#[tokio::test]
async fn mirror_body_over_limit_skipped() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Never).await;
    let shadow = Server::start("shadow", Delay::Never).await;
    let with_body = mirrored_app(
        main.addr,
        &[service("shadow", &[shadow.addr])],
        mirroring(
            &[("shadow", 100.0)],
            json!({ "mirror_body": true, "max_body_size": 1024 }),
        ),
    );
    push(&podgate, 1, with_body).await;
    let big = vec![b'x'; 2000];
    let (status, _) = raw(&podgate, &post("/big", "Content-Length: 2000\r\n", &big)).await;
    assert_eq!(status, 200, "the real request is served");
    let mut chunked = Vec::new();
    for _ in 0..4 {
        chunked.extend_from_slice(format!("{:x}\r\n", 600).as_bytes());
        chunked.extend_from_slice(&vec![b'y'; 600]);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let (status, _) = raw(
        &podgate,
        &post("/big-chunked", "Transfer-Encoding: chunked\r\n", &chunked),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = raw(
        &podgate,
        &post("/small", "Content-Length: 1024\r\n", &vec![b'z'; 1024]),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        settled(&shadow).await,
        1,
        "only the body at the limit is mirrored"
    );
    assert_eq!(shadow.requests()[0].path(), "/small");
    assert_eq!(dropped(&podgate, "body_too_large").await, 2);
    assert_eq!(main.count(), 3);
    assert_eq!(main.requests()[0].body.len(), 2000);
    assert_eq!(main.requests()[1].body.len(), 2400);

    // An upgrade request is not mirrored when the body is mirrored.
    assert_eq!(upgrade_status(&podgate, "/ws").await, 200);
    assert_eq!(settled(&shadow).await, 1);
    assert_eq!(dropped(&podgate, "upgrade").await, 1);

    // Without `mirror_body` the copy has a method and headers and no body.
    let without = mirrored_app(
        main.addr,
        &[service("shadow", &[shadow.addr])],
        mirroring(&[("shadow", 100.0)], json!({})),
    );
    push(&podgate, 2, without).await;
    let (status, _) = raw(
        &podgate,
        &post("/nobody", "Content-Length: 5\r\n", b"hello"),
    )
    .await;
    assert_eq!(status, 200);
    eventually("the bodiless copy", || shadow.count() == 2).await;
    let copy = shadow.requests()[1].clone();
    assert_eq!(copy.path(), "/nobody");
    assert!(copy.body.is_empty());
    assert_eq!(copy.header("content-length"), Some("0"));
    assert_eq!(upgrade_status(&podgate, "/ws").await, 200);
    eventually("the upgrade request without its body mirrored", || {
        shadow.count() == 3
    })
    .await;
    let copy = shadow.requests()[2].clone();
    assert!(copy.header("upgrade").is_none() && copy.header("connection") == Some("close"));
}

#[tokio::test]
async fn mirror_bounded_by_budget() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Never).await;
    let shadow = Server::start("shadow", Delay::All(Duration::from_secs(2))).await;
    let app = mirrored_app(
        main.addr,
        &[service("shadow", &[shadow.addr])],
        mirroring(
            &[("shadow", 100.0)],
            json!({ "mirror_body": true, "max_body_size": 65536 }),
        ),
    );
    // Fits one copy (16 KiB head + 40 KiB of body in blocks) and not two.
    let limited = with_budget(snapshot(1, std::slice::from_ref(&app)), 100, 100 * 1024);
    let pushed = podgate.push_snapshot(&limited).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let body = vec![b'b'; 40 * 1024];
    let length = format!("Content-Length: {}\r\n", body.len());
    for _ in 0..2 {
        let (status, _) = raw(&podgate, &post("/big", &length, &body)).await;
        assert_eq!(
            status, 200,
            "the real requests are served whatever the mirror budget"
        );
    }
    eventually("the first copy", || shadow.count() == 1).await;
    assert_eq!(
        settled(&shadow).await,
        1,
        "the second copy did not fit and was dropped"
    );
    assert_eq!(dropped(&podgate, "budget").await, 1);
    let peak = metric(&podgate, "podgate_tenant_buffer_bytes_peak{tenant=\"t1\"}").await;
    assert!(
        peak <= 100 * 1024,
        "the tenant never held more than its budget: {peak}"
    );
    assert_eq!(shadow.requests()[0].body.len(), 40 * 1024);

    // A cap that can never fit is refused when the snapshot compiles.
    let tiny = with_budget(snapshot(2, &[app]), 100, 20 * 1024);
    let refusal = rejection(&podgate.push_snapshot(&tiny).await);
    assert_eq!(refusal["code"], "invalid_service", "{refusal}");
    assert_eq!(refusal["tenant"], "t1");
    assert_eq!(refusal["needed_bytes"], 16 * 1024 + 65536);
    assert_eq!(refusal["max_buffer_bytes"], 20 * 1024);
}

#[tokio::test]
async fn mirror_shed_before_real_requests_when_the_tenant_is_busy() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Slow(Duration::from_secs(2))).await;
    let shadow = Server::start("shadow", Delay::Never).await;
    let app = mirrored_app(
        main.addr,
        &[service("shadow", &[shadow.addr])],
        mirroring(&[("shadow", 100.0)], json!({})),
    );
    // Four in flight at most: mirrors stop at three, so the fourth real request still runs.
    let limited = with_budget(snapshot(1, &[app]), 4, 1 << 20);
    let pushed = podgate.push_snapshot(&limited).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let holders: Vec<_> = (0..3)
        .map(|index| {
            let podgate_addr = podgate.proxy_addr;
            tokio::spawn(async move {
                let mut stream = TcpStream::connect(podgate_addr).await.expect("connect");
                let request = format!(
                    "GET /slow{index} HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(request.as_bytes()).await.expect("send");
                let mut response = Vec::new();
                drop(stream.read_to_end(&mut response).await);
            })
        })
        .collect();
    eventually("three slow requests at the main service", || {
        main.count() == 3
    })
    .await;
    // Each request's copy is decided and sent on its own task, so one of the first three can
    // still be on its way to the shadow here. Wait until all three are decided.
    copies_decided(&podgate, &shadow, 3).await;
    let shed_before = dropped(&podgate, "tenant").await;
    let response = podgate.get("a.test", "/quick").await;
    assert_eq!((response.status, response.body.as_str()), (200, "main"));
    // Shed copies are counted before anything is sent, so once the fourth is counted it is gone.
    shed_reaches(&podgate, "tenant", shed_before + 1).await;
    let at_shadow = paths(&shadow);
    assert!(
        at_shadow.iter().all(|path| path.starts_with("/slow")),
        "the copy of the fourth request was shed: {at_shadow:?}"
    );
    for holder in holders {
        holder.await.expect("holder");
    }
}

#[tokio::test]
async fn mirror_cross_revision() {
    let podgate = Podgate::start().await;
    let current = Server::start("current", Delay::Never).await;
    let next = Server::start("next", Delay::Never).await;
    let revisions = json!([
        { "id": "r1", "state": "serving", "weight": 100, "services": [service("web", &[current.addr])] },
        { "id": "r2", "state": "serving", "weight": 0, "services": [service("web", &[next.addr])] },
    ]);
    let mut app = app("a", &["a.test"], &[]);
    app["revisions"] = revisions;
    app["routers"] = json!([router("default", json!({ "host": ["a.test"] }), "m")]);
    app["services"] = json!([mirroring(&[("web@r2", 100.0)], json!({}))]);
    push(&podgate, 1, app.clone()).await;
    for _ in 0..10 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!((response.status, response.body.as_str()), (200, "current"));
    }
    eventually("the successor to see the copies", || next.count() == 10).await;
    assert_eq!(current.count(), 10);

    let mut missing = app.clone();
    missing["services"] = json!([mirroring(&[("web@r9", 100.0)], json!({}))]);
    let refusal = rejection(&podgate.push_snapshot(&snapshot(2, &[missing])).await);
    assert_eq!(refusal["code"], "unknown_service", "{refusal}");
    let mut absent = app;
    absent["revisions"][1]["services"] = json!([service("other", &[next.addr])]);
    absent["services"] = json!([mirroring(&[("web@r2", 100.0)], json!({}))]);
    let refusal = rejection(&podgate.push_snapshot(&snapshot(3, &[absent])).await);
    assert_eq!(refusal["code"], "unknown_service", "{refusal}");
}

#[tokio::test]
async fn mirror_marker_header() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Never).await;
    let shadow = Server::start("shadow", Delay::Never).await;
    let app = |config: Value| {
        mirrored_app(
            main.addr,
            &[service("shadow", &[shadow.addr])],
            mirroring(&[("shadow", 100.0)], config),
        )
    };
    push(&podgate, 1, app(json!({}))).await;
    let credentials = [
        ("Authorization", "Bearer secret"),
        ("Cookie", "sid=1"),
        ("X-Custom", "kept"),
    ];
    let response = podgate
        .get_with_headers("a.test", "/p?q=1", &credentials)
        .await;
    assert_eq!((response.status, response.body.as_str()), (200, "main"));
    assert!(
        response.header("x-podgate-mirrored").is_none(),
        "the mirror's marker never reaches the client"
    );
    eventually("the copy", || shadow.count() == 1).await;
    let copy = shadow.requests()[0].clone();
    assert_eq!(copy.header("x-podgate-mirrored"), Some("1"));
    assert_eq!(copy.path(), "/p?q=1");
    assert_eq!(copy.header("host"), Some("a.test"));
    assert_eq!(copy.header("x-custom"), Some("kept"));
    assert!(
        copy.header("authorization").is_none() && copy.header("cookie").is_none(),
        "credentials are not copied by default: {}",
        copy.head
    );
    let at_main = main.requests()[0].clone();
    assert!(
        at_main.header("x-podgate-mirrored").is_none(),
        "the real request has no marker"
    );
    assert_eq!(at_main.header("authorization"), Some("Bearer secret"));

    // A request that is itself a mirror is not mirrored again.
    podgate
        .get_with_headers("a.test", "/again", &[("X-Podgate-Mirrored", "1")])
        .await;
    assert_eq!(settled(&shadow).await, 1);
    assert_eq!(dropped(&podgate, "mirror").await, 1);

    push(&podgate, 2, app(json!({ "forward_credentials": true }))).await;
    podgate
        .get_with_headers("a.test", "/creds", &credentials)
        .await;
    eventually("the second copy", || shadow.count() == 2).await;
    let copy = shadow.requests()[1].clone();
    assert_eq!(copy.header("authorization"), Some("Bearer secret"));
    assert_eq!(copy.header("cookie"), Some("sid=1"));
    assert_eq!(copy.header("x-podgate-mirrored"), Some("1"));
}

struct PolicyFile(PathBuf);

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-mirroring-policy-{}-{}.json",
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
async fn mirror_obeys_upstream_policy() {
    let policy = PolicyFile::write(r#"{"deny": ["10.9.0.0/16"]}"#);
    let podgate =
        Podgate::start_with_env(&[("UPSTREAM_POLICY_FILE", policy.0.to_str().expect("utf-8"))])
            .await;
    let main = Server::start("main", Delay::Never).await;
    let forbidden: SocketAddr = "10.9.0.1:80".parse().expect("addr");
    let app = mirrored_app(
        main.addr,
        &[service("shadow", &[forbidden])],
        mirroring(&[("shadow", 100.0)], json!({})),
    );
    let refusal = rejection(&podgate.push_snapshot(&snapshot(1, &[app])).await);
    assert_eq!(refusal["code"], "upstream_forbidden", "{refusal}");
    assert_eq!(refusal["service"], "shadow", "{refusal}");
    // The connect-time check on the exact address is unit-tested in `src/service/mirroring/send.rs`
    // (`mirror_obeys_upstream_policy_before_anything_is_dialled`): the compiler never sees an
    // address the snapshot did not write.
}

#[tokio::test]
async fn mirror_config_refusals_at_compile() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Never).await;
    let shadow = Server::start("shadow", Delay::Never).await;
    let shadow_service = [service("shadow", &[shadow.addr])];
    let refused_code = |declared: Value| {
        let app = mirrored_app(main.addr, &shadow_service, declared);
        let podgate = &podgate;
        async move {
            let response = podgate.push_snapshot(&snapshot(1, &[app])).await;
            rejection(&response)["code"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        }
    };
    assert_eq!(
        refused_code(mirroring(&[("shadow", 101.0)], json!({}))).await,
        "invalid_service"
    );
    assert_eq!(
        refused_code(mirroring(&[("shadow", -1.0)], json!({}))).await,
        "invalid_service"
    );
    assert_eq!(
        refused_code(mirroring(&[("nowhere", 10.0)], json!({}))).await,
        "unknown_service"
    );
    assert_eq!(
        refused_code(mirroring(&[("m", 10.0)], json!({}))).await,
        "service_cycle"
    );
    assert_eq!(
        refused_code(mirroring(
            &[("shadow", 10.0)],
            json!({ "service": "nowhere" })
        ))
        .await,
        "unknown_service"
    );
    assert_eq!(
        refused_code(mirroring(
            &[("shadow", 10.0)],
            json!({ "max_body_size": 10 })
        ))
        .await,
        "invalid_service"
    );
    assert_eq!(
        refused_code(mirroring(
            &[("shadow", 10.0)],
            json!({ "mirror_timeout_secs": 0 })
        ))
        .await,
        "invalid_service"
    );
    assert_eq!(
        refused_code(mirroring(
            &[("shadow", 10.0)],
            json!({ "mirror_bodies": true })
        ))
        .await,
        "invalid_service"
    );
    let ok = mirrored_app(
        main.addr,
        &shadow_service,
        mirroring(&[("shadow", 10.5)], json!({})),
    );
    let pushed = podgate.push_snapshot(&snapshot(2, &[ok])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let schema = podgate.admin_get("/v1/schema").await;
    assert_eq!(schema.status, 200, "{}", schema.body);
    assert!(
        schema.body.contains("mirror_body"),
        "the schema describes the service"
    );
}

#[tokio::test]
async fn plan_lists_mirroring_changes() {
    let podgate = Podgate::start().await;
    let main = Server::start("main", Delay::Never).await;
    let shadow = Server::start("shadow", Delay::Never).await;
    let other = Server::start("other", Delay::Never).await;
    let services = [
        service("shadow", &[shadow.addr]),
        service("other", &[other.addr]),
    ];
    let candidate = |version: u64, mirrors: &[(&str, f64)], config: Value| {
        snapshot(
            version,
            &[mirrored_app(
                main.addr,
                &services,
                mirroring(mirrors, config),
            )],
        )
    };
    push(
        &podgate,
        1,
        mirrored_app(
            main.addr,
            &services,
            mirroring(&[("shadow", 10.0)], json!({})),
        ),
    )
    .await;
    let kinds = |plan: Value| -> Vec<String> {
        plan["posture_changes"]
            .as_array()
            .expect("list")
            .iter()
            .map(|change| {
                assert_eq!(change["host"], "a.test");
                change["kind"].as_str().expect("kind").to_owned()
            })
            .collect()
    };
    let plan = |version: u64, mirrors: &[(&str, f64)], config: Value| {
        let body = candidate(version, mirrors, config);
        let podgate = &podgate;
        async move {
            let response = podgate.admin_post("/v1/snapshot/plan", &body).await;
            assert_eq!(response.status, 200, "{}", response.body);
            kinds(response.json())
        }
    };
    let none: Vec<String> = Vec::new();
    assert_eq!(plan(2, &[("shadow", 10.0)], json!({})).await, none);
    assert_eq!(
        plan(2, &[("shadow", 5.0)], json!({})).await,
        none,
        "less is not listed"
    );
    assert_eq!(plan(2, &[("shadow", 0.0)], json!({})).await, none);
    assert_eq!(
        plan(2, &[("shadow", 10.5)], json!({})).await,
        ["mirror_percent_raised"]
    );
    assert_eq!(
        plan(2, &[("shadow", 10.0), ("other", 1.0)], json!({})).await,
        ["mirror_added"]
    );
    assert_eq!(
        plan(2, &[("shadow", 10.0), ("other", 0.0)], json!({})).await,
        none,
        "a mirror that copies nothing exposes nothing"
    );
    assert_eq!(
        plan(2, &[("other", 10.0)], json!({})).await,
        ["mirror_added"],
        "moving the copies to another service is a new mirror"
    );
    assert_eq!(
        plan(
            2,
            &[("shadow", 10.0)],
            json!({ "forward_credentials": true })
        )
        .await,
        ["mirror_credentials_forwarded"]
    );
    assert_eq!(
        plan(
            2,
            &[("shadow", 20.0), ("other", 5.0)],
            json!({ "forward_credentials": true })
        )
        .await,
        [
            "mirror_credentials_forwarded",
            "mirror_added",
            "mirror_percent_raised"
        ]
    );

    // Credentials already forwarded stay unlisted; turning them off is a tightening.
    push(
        &podgate,
        2,
        mirrored_app(
            main.addr,
            &services,
            mirroring(&[("shadow", 10.0)], json!({ "forward_credentials": true })),
        ),
    )
    .await;
    assert_eq!(
        plan(
            3,
            &[("shadow", 10.0)],
            json!({ "forward_credentials": true })
        )
        .await,
        none
    );
    assert_eq!(plan(3, &[("shadow", 10.0)], json!({})).await, none);
}

/// An auth service that answers `401` to a request with `x-deny` and else `200` with
/// `X-User: ann`.
async fn auth_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 2048];
                while find(&seen, b"\r\n\r\n").is_none() {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
                let head = String::from_utf8_lossy(&seen).to_ascii_lowercase();
                let reply: &[u8] = if head.contains("x-deny") {
                    b"HTTP/1.1 401 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nX-User: ann\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                drop(stream.write_all(reply).await);
                drop(stream.shutdown().await);
            });
        }
    });
    addr
}

#[tokio::test]
async fn mirror_identity_from_forward_auth() {
    let podgate = Podgate::start().await;
    let auth = auth_server().await;
    let main = Server::start("main", Delay::Never).await;
    let shadow = Server::start("shadow", Delay::Never).await;
    let site = |config: Value| {
        common::with_forward_auth(
            mirrored_app(
                main.addr,
                &[service("shadow", &[shadow.addr])],
                mirroring(&[("shadow", 100.0)], config),
            ),
            auth,
            &json!({ "response_headers": ["x-user"] }),
        )
    };
    push(&podgate, 1, site(json!({}))).await;

    let response = podgate
        .get_with_headers(
            "a.test",
            "/ok",
            &[("Authorization", "Bearer t"), ("X-User", "forged")],
        )
        .await;
    assert_eq!((response.status, response.body.as_str()), (200, "main"));
    eventually("the copy", || shadow.count() == 1).await;
    assert_eq!(
        main.requests()[0].header("x-user"),
        Some("ann"),
        "the main service sees the identity"
    );
    let copy = shadow.requests()[0].clone();
    assert!(
        copy.header("x-user").is_none() && copy.header("authorization").is_none(),
        "the identity forward_auth added is a credential too: {}",
        copy.head
    );

    // A request the auth service refused is answered by the chain and never mirrored.
    let denied = podgate
        .get_with_headers("a.test", "/denied", &[("X-Deny", "1")])
        .await;
    assert_eq!(denied.status, 401);
    assert_eq!(settled(&shadow).await, 1);
    assert_eq!(main.count(), 1);

    push(&podgate, 2, site(json!({ "forward_credentials": true }))).await;
    podgate
        .get_with_headers("a.test", "/with", &[("Authorization", "Bearer t")])
        .await;
    eventually("the second copy", || shadow.count() == 2).await;
    let copy = shadow.requests()[1].clone();
    assert_eq!(copy.header("x-user"), Some("ann"));
    assert_eq!(copy.header("authorization"), Some("Bearer t"));
}
