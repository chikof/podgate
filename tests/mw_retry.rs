//! The `retry` middleware through the real proxy: a failed attempt moves on to
//! another server only when that is safe, the next attempt passes backend admission again, every
//! failed attempt counts against its server, and the number of retries reaches the access log.
//! The decision table and the backoff arithmetic are unit tests in `src/middleware/retry.rs`.
//!
//! No test here depends on which server a balancer picks first. A test that needs a request to
//! meet a failing server sends requests until one does, and checks what every server saw: which
//! requests reached it, how often, and with which body.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Podgate, app, middleware, revision_on, snapshot, with_chain};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{sleep, timeout};

/// Most requests a test sends while it waits for one to meet a failing server.
const MAX_TRIES: usize = 40;

/// How a backend treats the requests it reads.
#[derive(Clone, Copy)]
enum Mode {
    /// Answers every request.
    Answer,
    /// Answers the first request of a connection and, on any later request of the same
    /// connection, reads it and closes without answering: a pooled connection that died.
    DropReused,
    /// Reads every request and closes without answering.
    DropAlways,
    /// Answers after a delay.
    Slow(Duration),
}

/// What a backend saw.
#[derive(Default)]
struct Seen {
    /// Requests read.
    hits: AtomicUsize,
    /// Requests read and not answered.
    dropped: AtomicUsize,
    /// The body of every request read, in order.
    bodies: Mutex<Vec<Vec<u8>>>,
}

/// A backend that records what it received.
struct Backend {
    addr: SocketAddr,
    seen: Arc<Seen>,
}

impl Backend {
    async fn start(label: &'static str, mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        Self::serving(listener, label, mode)
    }

    fn serving(listener: TcpListener, label: &'static str, mode: Mode) -> Self {
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Seen::default());
        tokio::spawn({
            let seen = Arc::clone(&seen);
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(stream, mode, label, Arc::clone(&seen)));
                }
            }
        });
        Self { addr, seen }
    }

    async fn good() -> Self {
        Self::start("good", Mode::Answer).await
    }

    fn hits(&self) -> usize {
        self.seen.hits.load(Ordering::SeqCst)
    }

    fn dropped(&self) -> usize {
        self.seen.dropped.load(Ordering::SeqCst)
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.seen.bodies.lock().expect("bodies").clone()
    }

    /// How many requests with exactly `body` were read.
    fn count_of(&self, body: &[u8]) -> usize {
        self.bodies().iter().filter(|seen| *seen == body).count()
    }
}

/// An address that refuses connections until [`Self::listen`]: bound, not listening.
struct Deferred {
    socket: TcpSocket,
    addr: SocketAddr,
}

impl Deferred {
    fn new() -> Self {
        let socket = TcpSocket::new_v4().expect("socket");
        socket
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind");
        let addr = socket.local_addr().expect("addr");
        Self { socket, addr }
    }

    fn listen(self, label: &'static str, mode: Mode) -> Backend {
        Backend::serving(self.socket.listen(16).expect("listen"), label, mode)
    }
}

/// Reads one request: its head, and its body when it has a length or is chunked.
async fn read_request(stream: &mut TcpStream, seen: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut chunk = [0_u8; 1024];
    let end = loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok());
    let chunked = head.contains("transfer-encoding: chunked");
    let mut body = Vec::new();
    seen.drain(..end);
    if chunked {
        loop {
            // `size\r\n data \r\n`, ended by a zero size.
            let Some(line_end) = seen.windows(2).position(|window| window == b"\r\n") else {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return None,
                    Ok(read) => seen.extend_from_slice(&chunk[..read]),
                }
                continue;
            };
            let size = usize::from_str_radix(String::from_utf8_lossy(&seen[..line_end]).trim(), 16)
                .ok()?;
            let frame = line_end + 2 + size + 2;
            while seen.len() < frame {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return None,
                    Ok(read) => seen.extend_from_slice(&chunk[..read]),
                }
            }
            body.extend_from_slice(&seen[line_end + 2..line_end + 2 + size]);
            seen.drain(..frame);
            if size == 0 {
                break;
            }
        }
    } else if let Some(length) = length {
        while seen.len() < length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(read) => seen.extend_from_slice(&chunk[..read]),
            }
        }
        body.extend_from_slice(&seen[..length]);
        seen.drain(..length);
    }
    Some(body)
}

async fn serve(mut stream: TcpStream, mode: Mode, label: &'static str, seen: Arc<Seen>) {
    let mut buffered = Vec::new();
    let mut on_connection = 0_u32;
    while let Some(body) = read_request(&mut stream, &mut buffered).await {
        seen.hits.fetch_add(1, Ordering::SeqCst);
        seen.bodies.lock().expect("bodies").push(body);
        on_connection += 1;
        match mode {
            Mode::DropAlways => {
                seen.dropped.fetch_add(1, Ordering::SeqCst);
                return;
            }
            Mode::DropReused if on_connection > 1 => {
                seen.dropped.fetch_add(1, Ordering::SeqCst);
                return;
            }
            Mode::Slow(delay) => sleep(delay).await,
            Mode::Answer | Mode::DropReused => {}
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{label}",
            label.len()
        );
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// App `a.test` whose `web` service balances `servers` round robin, with
/// `middlewares` in its chain.
fn guarded(
    version: u64,
    servers: &[SocketAddr],
    middlewares: &[Value],
    max_inflight: u64,
) -> Value {
    guarded_with(version, servers, middlewares, max_inflight, None)
}

fn guarded_with(
    version: u64,
    servers: &[SocketAddr],
    middlewares: &[Value],
    max_inflight: u64,
    passive: Option<Value>,
) -> Value {
    let mut revision = revision_on("r1", servers, 100, "serving");
    revision["services"][0]["algorithm"] = json!("round_robin");
    if let Some(passive) = passive {
        revision["services"][0]["passive"] = passive;
    }
    let guarded = with_chain(app("a.test", &["a.test"], &[revision]), middlewares);
    let mut pushed = snapshot(version, &[guarded]);
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(max_inflight);
    pushed
}

fn retry(config: &Value) -> Value {
    middleware("r", "retry", config.clone())
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let pushed = podgate.push_snapshot(snapshot).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
}

/// A scratch directory for an access log, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-retry-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create the log directory");
        Self(path)
    }

    fn log(&self) -> PathBuf {
        self.0.join("access.log")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// Podgate with an access log in `dir`.
async fn logged(dir: &Dir) -> Podgate {
    Podgate::start_with_env(&[("ACCESS_LOG_FILE", dir.log().to_str().expect("utf-8 path"))]).await
}

/// Pushes `pushed` with the access log on.
async fn push_logged(podgate: &Podgate, mut pushed: Value) {
    pushed["observability"] = json!({ "access_log": {} });
    push(podgate, &pushed).await;
}

/// The first `count` access log lines, once they are written.
async fn log_lines(dir: &Dir, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let lines: Vec<Value> = std::fs::read_to_string(dir.log())
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if lines.len() >= count || Instant::now() > deadline {
            assert!(
                lines.len() >= count,
                "{} lines, wanted {count}",
                lines.len()
            );
            return lines;
        }
        sleep(Duration::from_millis(25)).await;
    }
}

/// `POST /` with `body` as `a.test`, over a connection of its own. Returns the status and body.
async fn post(podgate: &Podgate, body: &[u8], chunked: bool) -> (u16, String) {
    let mut request = b"POST / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n".to_vec();
    if chunked {
        request.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        for part in body.chunks(1000) {
            request.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            request.extend_from_slice(part);
            request.extend_from_slice(b"\r\n");
        }
        request.extend_from_slice(b"0\r\n\r\n");
    } else {
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
    }
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    stream.write_all(&request).await.expect("send the request");
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut raw))
        .await
        .expect("an answer in time")
        .ok();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    (status, body.to_owned())
}

/// How many retries the services of app `a.test` have counted, the router's service (`web`, or
/// the `mirroring` service in front of it) being the one that counts.
async fn retries(podgate: &Podgate) -> u64 {
    let metrics = podgate.admin_get("/metrics").await.body;
    metrics
        .lines()
        .filter_map(|line| line.strip_prefix("podgate_service_retries_total{app=\"a.test\","))
        .filter_map(|rest| rest.split("} ").nth(1)?.trim().parse::<u64>().ok())
        .sum()
}

/// What one request got.
struct Answer {
    status: u16,
    body: String,
}

/// `GET /` as `a.test`.
async fn get(podgate: &Podgate) -> Answer {
    let response = podgate.get("a.test", "/").await;
    Answer {
        status: response.status,
        body: response.body,
    }
}

/// `POST` as [`post`], as an [`Answer`].
async fn posted(podgate: &Podgate, body: &[u8], chunked: bool) -> Answer {
    let (status, body) = post(podgate, body, chunked).await;
    Answer { status, body }
}

/// A body unique to request `index`, `len` bytes long.
fn body_of(index: usize, len: usize) -> Vec<u8> {
    let mut body = format!("request {index}|").into_bytes();
    let mut next = 0_u8;
    while body.len() < len {
        body.push(b'a' + next % 26);
        next = next.wrapping_add(7);
    }
    body
}

fn buffer() -> Value {
    middleware(
        "buffer",
        "buffering",
        json!({"max_request_body_bytes": 65536, "buffer_request": true}),
    )
}

/// POSTs `len` byte bodies (each unique) through `podgate` until `stale` has dropped a request
/// on a dead pooled connection, then returns every body with its answer. Fails when no request
/// ever meets the dead connection.
async fn posts_until_dropped(
    podgate: &Podgate,
    stale: &Backend,
    len: usize,
    chunked: bool,
) -> Vec<(Vec<u8>, Answer)> {
    let mut sent = Vec::new();
    for index in 0..MAX_TRIES {
        let body = body_of(index, len);
        let answer = posted(podgate, &body, chunked).await;
        sent.push((body, answer));
        if stale.dropped() > 0 {
            return sent;
        }
    }
    panic!("no request ever reused the dead connection of the stale server");
}

#[tokio::test]
async fn retry_moves_to_another_server_on_connect_error() {
    let podgate = Podgate::start().await;
    let (dead, good) = (common::refused(), Backend::good().await);
    let chain = [retry(&json!({"attempts": 3, "initial_interval_ms": 1}))];
    push(&podgate, &guarded(1, &[dead.addr, good.addr], &chain, 100)).await;
    for _ in 0..6 {
        let answer = get(&podgate).await;
        assert_eq!((answer.status, answer.body.as_str()), (200, "good"));
    }
    assert_eq!(
        good.hits(),
        6,
        "every request was answered by the good server"
    );
    assert!(
        retries(&podgate).await >= 1,
        "some request met the dead server first"
    );

    // Nothing was sent to the dead server, so any method moves on, a body included: every POST is
    // answered once, by the good server, with its whole body.
    let before = retries(&podgate).await;
    for index in 0..MAX_TRIES {
        let body = body_of(index, 64);
        let answer = posted(&podgate, &body, false).await;
        assert_eq!((answer.status, answer.body.as_str()), (200, "good"));
        assert_eq!(good.count_of(&body), 1, "post {index} arrived once");
        if retries(&podgate).await > before {
            break;
        }
    }
    assert!(
        retries(&podgate).await > before,
        "a POST met the dead server first"
    );

    // Without the middleware a request that meets the dead server is a 502.
    push(&podgate, &guarded(2, &[dead.addr, good.addr], &[], 100)).await;
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(get(&podgate).await.status);
    }
    assert!(statuses.contains(&502), "{statuses:?}");
    assert!(statuses.contains(&200), "{statuses:?}");
}

#[tokio::test]
async fn retry_not_on_post_after_send() {
    let podgate = Podgate::start().await;
    let (broken, good) = (
        Backend::start("broken", Mode::DropAlways).await,
        Backend::good().await,
    );
    let chain = [retry(&json!({"attempts": 3, "initial_interval_ms": 1}))];
    push(
        &podgate,
        &guarded(1, &[broken.addr, good.addr], &chain, 100),
    )
    .await;
    let mut failed = 0;
    for index in 0..8 {
        let body = body_of(index, 64);
        let answer = posted(&podgate, &body, false).await;
        match answer.status {
            200 => {
                assert_eq!(good.count_of(&body), 1);
                assert_eq!(broken.count_of(&body), 0);
            }
            502 => {
                failed += 1;
                assert_eq!(
                    broken.count_of(&body),
                    1,
                    "the body reached the broken server"
                );
                assert_eq!(good.count_of(&body), 0, "and was not sent to another");
            }
            other => panic!("status {other}"),
        }
    }
    assert!(failed > 0, "some POST met the broken server");
    assert_eq!(broken.hits(), failed);
}

#[tokio::test]
async fn retry_idempotent_on_stale_connection() {
    let podgate = Podgate::start().await;
    let (stale, good) = (
        Backend::start("stale", Mode::DropReused).await,
        Backend::good().await,
    );
    let chain = [retry(&json!({"attempts": 2, "initial_interval_ms": 1}))];
    push(&podgate, &guarded(1, &[stale.addr, good.addr], &chain, 100)).await;
    // GETs until the stale server has dropped one on a dead pooled connection.
    let (mut by_stale, mut by_good) = (0, 0);
    for _ in 0..MAX_TRIES {
        let answer = get(&podgate).await;
        assert_eq!(answer.status, 200, "no request is lost: {}", answer.body);
        match answer.body.as_str() {
            "stale" => by_stale += 1,
            "good" => by_good += 1,
            other => panic!("answered by {other}"),
        }
        if stale.dropped() > 0 {
            break;
        }
    }
    assert!(stale.dropped() > 0, "a request reused the dead connection");
    // Every request was answered once: by the stale server, or by the good server, which also took
    // each request the stale server dropped.
    assert_eq!(by_stale, stale.hits() - stale.dropped());
    assert_eq!(good.hits(), by_good);
}

#[tokio::test]
async fn retry_post_only_when_buffered_and_listed() {
    let listed = json!({"attempts": 2, "initial_interval_ms": 1, "methods": ["POST"]});
    let default = json!({"attempts": 2, "initial_interval_ms": 1});

    // Listed and buffered: replayed, so no POST is lost and each is read by one server to the end.
    let (podgate, stale, good) = stale_pair(&[buffer(), retry(&listed)]).await;
    let sent = posts_until_dropped(&podgate, &stale, 64, false).await;
    for (body, answer) in &sent {
        assert_eq!(answer.status, 200, "{}", answer.body);
        if answer.body == "good" {
            assert_eq!(good.count_of(body), 1);
        }
    }
    let replayed = sent
        .iter()
        .filter(|(body, answer)| answer.body == "good" && stale.count_of(body) == 1)
        .count();
    assert_eq!(
        replayed,
        stale.dropped(),
        "each dropped POST went to the good server"
    );

    // Listed, but the body streams: never replayed. Buffered, but POST is not in the defaults.
    for chain in [vec![retry(&listed)], vec![buffer(), retry(&default)]] {
        let (podgate, stale, good) = stale_pair(&chain).await;
        let sent = posts_until_dropped(&podgate, &stale, 64, false).await;
        let mut refused = 0;
        for (body, answer) in &sent {
            if stale.count_of(body) == 1 && answer.body != "stale" {
                refused += 1;
                assert_eq!(answer.status, 502, "dropped POST: {}", answer.body);
                assert_eq!(good.count_of(body), 0, "it was not sent to the good server");
            }
        }
        assert_eq!(refused, stale.dropped());
    }
}

/// Podgate with the stale server and a good one, `chain` in the app.
async fn stale_pair(chain: &[Value]) -> (Podgate, Backend, Backend) {
    let podgate = Podgate::start().await;
    let (stale, good) = (
        Backend::start("stale", Mode::DropReused).await,
        Backend::good().await,
    );
    push(&podgate, &guarded(1, &[stale.addr, good.addr], chain, 100)).await;
    (podgate, stale, good)
}

#[tokio::test]
async fn buffered_body_replayed_on_retry() {
    // Bigger than any single read, framed both ways.
    for chunked in [false, true] {
        let chain = [
            buffer(),
            retry(&json!({"attempts": 2, "initial_interval_ms": 1, "methods": ["POST"]})),
        ];
        let (podgate, stale, good) = stale_pair(&chain).await;
        let sent = posts_until_dropped(&podgate, &stale, 40_000, chunked).await;
        let mut replayed = 0;
        for (body, answer) in &sent {
            assert_eq!(answer.status, 200, "chunked {chunked}: {}", answer.body);
            if answer.body == "good" && stale.count_of(body) == 1 {
                replayed += 1;
                assert_eq!(
                    good.count_of(body),
                    1,
                    "the second server got the whole body, chunked: {chunked}"
                );
            }
        }
        assert!(replayed >= 1, "chunked: {chunked}");
    }
}

#[tokio::test]
async fn retry_attempts_capped() {
    let dir = Dir::new();
    let podgate = logged(&dir).await;
    let (first, second) = (common::refused(), common::refused());
    let mut seen = 0;
    // `attempts` counts the first try: n attempts are n - 1 retries. Above 5 is refused, so 5 is
    // the most a request is ever tried, whatever the servers.
    for attempts in [1_u32, 3, 5] {
        let chain = [retry(
            &json!({"attempts": attempts, "initial_interval_ms": 0}),
        )];
        let pushed = guarded(u64::from(attempts), &[first.addr, second.addr], &chain, 100);
        push_logged(&podgate, pushed).await;
        let response = podgate.get("a.test", "/").await;
        assert_eq!(response.status, 502, "attempts {attempts}: {response:?}");
        seen += 1;
        let lines = log_lines(&dir, seen).await;
        assert_eq!(
            lines[seen - 1]["retry_attempts"],
            attempts - 1,
            "attempts {attempts}: {}",
            lines[seen - 1]
        );
    }
}

#[tokio::test]
async fn retry_backoff_spacing() {
    let podgate = Podgate::start().await;
    let dead = common::refused();
    let timed = |attempts: u32| {
        let chain = [retry(
            &json!({"attempts": attempts, "initial_interval_ms": 100}),
        )];
        guarded(u64::from(attempts), &[dead.addr], &chain, 100)
    };
    let mut took = Vec::new();
    for attempts in [1_u32, 2, 4] {
        push(&podgate, &timed(attempts)).await;
        let started = Instant::now();
        assert_eq!(podgate.get("a.test", "/").await.status, 502);
        took.push(started.elapsed());
    }
    // Waits of 100, 200 and 400 ms, each cut by jitter to between half and all of it: one retry
    // waits at least 50 ms, three at least 350 ms and at most 700 ms.
    assert!(took[1] >= Duration::from_millis(50), "{took:?}");
    assert!(took[2] >= Duration::from_millis(350), "{took:?}");
    assert!(took[2] < Duration::from_millis(3000), "{took:?}");
    assert!(took[0] < took[2], "{took:?}");
}

#[tokio::test]
async fn retry_backoff_fits_the_request_deadline() {
    let dir = Dir::new();
    let podgate = Podgate::start_with_env(&[
        ("ACCESS_LOG_FILE", dir.log().to_str().expect("utf-8 path")),
        ("REQUEST_TIMEOUT_SECS", "1"),
    ])
    .await;
    let dead = common::refused();
    // The shortest wait before the first retry is 5 s, past the 1 s deadline.
    let chain = [retry(
        &json!({"attempts": 3, "initial_interval_ms": 10_000}),
    )];
    push_logged(&podgate, guarded(1, &[dead.addr], &chain, 100)).await;
    let started = Instant::now();
    assert_eq!(podgate.get("a.test", "/").await.status, 502);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "no wait was started"
    );
    assert_eq!(log_lines(&dir, 1).await[0]["retry_attempts"], 0);
}

#[tokio::test]
async fn retry_single_server_connect_only() {
    let dir = Dir::new();
    let podgate = logged(&dir).await;
    // One server that refuses: a connect error is tried again on it, up to `attempts`.
    let dead = common::refused();
    let chain = [retry(&json!({"attempts": 3, "initial_interval_ms": 1}))];
    push_logged(&podgate, guarded(1, &[dead.addr], &chain, 100)).await;
    assert_eq!(podgate.get("a.test", "/").await.status, 502);
    assert_eq!(log_lines(&dir, 1).await[0]["retry_attempts"], 2);

    // One server whose reused connection died: nothing else to send the request to.
    let stale = Backend::start("stale", Mode::DropReused).await;
    push_logged(&podgate, guarded(2, &[stale.addr], &chain, 100)).await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 502, "{response:?}");
    assert_eq!(stale.hits(), 2, "not sent a third time");
    assert_eq!(log_lines(&dir, 3).await[2]["retry_attempts"], 0);
}

#[tokio::test]
async fn retry_reenters_backend_admission() {
    let podgate = Podgate::start().await;
    // Both servers refuse until the test lets them listen, so whichever the request meets first
    // fails, and the other one, which listens by then, is the retry's target.
    let (first, second) = (Deferred::new(), Deferred::new());
    let addrs = [first.addr, second.addr];
    // The wait before the retry is 1 to 2 s; the tenant allows one request in flight.
    let chain = [retry(&json!({"attempts": 2, "initial_interval_ms": 2000}))];
    push(&podgate, &guarded(1, &addrs, &chain, 1)).await;
    let request = tokio::spawn({
        let addr = podgate.proxy_addr;
        async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
                .await
                .expect("send");
            let mut raw = String::new();
            stream.read_to_string(&mut raw).await.expect("read");
            raw
        }
    });
    let find = |metrics: &str, name: &str, label: &str| -> Option<u64> {
        metrics
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}{{{label}}} ")))
            .and_then(|value| value.trim().parse().ok())
    };
    let tenant = "tenant=\"t1\"";
    let tenant_inflight = |metrics: &str| {
        find(metrics, "podgate_tenant_inflight", tenant)
            .unwrap_or_else(|| panic!("no tenant series in:\n{metrics}"))
    };
    // A backend's series appears when its first request is admitted.
    let inflight = |metrics: &str, addr: SocketAddr| {
        find(
            metrics,
            "podgate_backend_inflight",
            &format!("backend=\"{addr}\""),
        )
        .unwrap_or(0)
    };

    // During the wait the first attempt has failed: the request holds its tenant slot and no
    // backend slot, the failed attempt's slot having gone back before the wait.
    sleep(Duration::from_millis(500)).await;
    let waiting = podgate.admin_get("/metrics").await.body;
    assert_eq!(tenant_inflight(&waiting), 1);
    for addr in addrs {
        assert_eq!(inflight(&waiting, addr), 0, "{addr}");
    }
    // The retry holds the tenant's only slot, so a second request is refused for capacity.
    let refused = podgate.get("a.test", "/").await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert_eq!(refused.header("retry-after"), Some("1"));

    // The servers start listening; the one that was not tried takes the retry, slowly.
    let servers = [
        first.listen("slow", Mode::Slow(Duration::from_millis(1500))),
        second.listen("slow", Mode::Slow(Duration::from_millis(1500))),
    ];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let metrics = podgate.admin_get("/metrics").await.body;
        let taken: Vec<u64> = addrs.iter().map(|addr| inflight(&metrics, *addr)).collect();
        if taken.iter().sum::<u64>() == 1 {
            assert_eq!(tenant_inflight(&metrics), 1, "still one");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the retry never took a backend slot: {taken:?}"
        );
        sleep(Duration::from_millis(50)).await;
    }
    let raw = request.await.expect("the request");
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    assert_eq!(
        servers.iter().map(Backend::hits).sum::<usize>(),
        1,
        "one server answered, once"
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(tenant_inflight(&metrics), 0);
    for addr in addrs {
        assert_eq!(inflight(&metrics, addr), 0, "{addr}");
    }
}

#[tokio::test]
async fn retry_statuses_unsupported() {
    let podgate = Podgate::start().await;
    let good = Backend::good().await;
    let chain = [retry(&json!({"attempts": 2, "retry_statuses": [502]}))];
    let response = podgate
        .push_snapshot(&guarded(1, &[good.addr], &chain, 100))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert!(
        response.body.contains("unsupported_setting"),
        "{}",
        response.body
    );
}

#[tokio::test]
async fn retry_attempts_over_cap_rejected() {
    let podgate = Podgate::start().await;
    let good = Backend::good().await;
    for attempts in [0, 6] {
        let chain = [retry(&json!({ "attempts": attempts }))];
        let response = podgate
            .push_snapshot(&guarded(1, &[good.addr], &chain, 100))
            .await;
        assert_eq!(
            response.status, 422,
            "attempts {attempts}: {}",
            response.body
        );
        assert!(
            response.body.contains("invalid_middleware"),
            "{}",
            response.body
        );
    }
    let chain = [retry(&json!({ "attempts": 5 }))];
    push(&podgate, &guarded(1, &[good.addr], &chain, 100)).await;
}

#[tokio::test]
async fn retry_failure_feeds_outlier() {
    let podgate = Podgate::start().await;
    let (dead, good) = (common::refused(), Backend::good().await);
    let chain = [retry(&json!({"attempts": 2, "initial_interval_ms": 1}))];
    let passive =
        json!({ "consecutive_failures": 2, "ejection_secs": 30, "max_ejection_percent": 50 });
    let pushed = guarded_with(1, &[dead.addr, good.addr], &chain, 100, Some(passive));
    push(&podgate, &pushed).await;
    let servers = |explained: Value| explained["revisions"][0]["servers"].clone();
    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/")
        .await
        .json();
    assert_eq!(servers(explained)[0]["available"], true);
    // A request that meets the dead server fails there once and succeeds on the good one: the
    // client never sees an error, and the dead server is ejected after its second failed attempt.
    let mut sent = 0;
    for _ in 0..MAX_TRIES {
        assert_eq!(get(&podgate).await.status, 200);
        sent += 1;
        let explained = podgate
            .admin_get("/v1/explain?url=http://a.test/")
            .await
            .json();
        if servers(explained)[0]["available"] == false {
            break;
        }
    }
    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/")
        .await
        .json();
    let servers = servers(explained);
    assert_eq!(servers[0]["available"], false, "{servers}");
    assert_eq!(servers[1]["available"], true, "{servers}");
    assert_eq!(
        retries(&podgate).await,
        2,
        "exactly the two failed attempts that ejected it"
    );
    assert_eq!(
        good.hits(),
        sent,
        "every request was answered by the good server"
    );
}

#[tokio::test]
async fn retry_failure_feeds_circuit_breaker() {
    let podgate = Podgate::start().await;
    let dead = common::refused();
    // Three attempts per request, each a network error. The circuit needs 4 outcomes and judges
    // every 10 ms. Counted once per attempt, the first request leaves 3 and the second request's
    // first outcome makes the fourth, which opens it for the third request. Counted once per
    // request (only `finished`) the second request would leave 2 and the third would still pass.
    // That a request is not counted twice is the unit test `circuit_counts_each_retried_attempt_once`.
    let chain = [
        retry(&json!({"attempts": 3, "initial_interval_ms": 0})),
        middleware(
            "cb",
            "circuit_breaker",
            json!({
                "trip_when": { "network_error_ratio": 0.5 },
                "check_period_ms": 10,
                "min_requests": 4,
                "fallback_secs": 60,
            }),
        ),
    ];
    push(&podgate, &guarded(1, &[dead.addr], &chain, 100)).await;
    let mut statuses = Vec::new();
    for _ in 0..3 {
        statuses.push(podgate.get("a.test", "/").await.status);
        sleep(Duration::from_millis(40)).await;
    }
    assert_eq!(statuses, [502, 502, 503]);
}

#[tokio::test]
async fn retry_attempts_in_access_log() {
    let (dead, good) = (common::refused(), Backend::good().await);
    let chain = [retry(&json!({"attempts": 3, "initial_interval_ms": 1}))];
    let direct = app(
        "b.test",
        &["b.test"],
        &[revision_on("r1", &[good.addr], 100, "serving")],
    );
    let with_direct = |mut pushed: Value| {
        if let Some(apps) = pushed["apps"].as_array_mut() {
            apps.push(direct.clone());
        }
        pushed
    };

    // Every request is logged with its own count: `b.test` has one server and is never retried;
    // `a.test` is retried when it meets the dead server first.
    let dir = Dir::new();
    let podgate = logged(&dir).await;
    let pushed = with_direct(guarded(1, &[dead.addr, good.addr], &chain, 100));
    push_logged(&podgate, pushed.clone()).await;
    for host in ["a.test", "b.test", "a.test", "b.test", "a.test", "a.test"] {
        assert_eq!(podgate.get(host, "/").await.status, 200);
    }
    let lines = log_lines(&dir, 6).await;
    let mut retried = 0;
    for line in &lines {
        let count = line["retry_attempts"].as_u64().expect("a count");
        if line["host"] == "b.test" {
            assert_eq!(count, 0, "{line}");
        } else {
            assert!(count <= 1, "{line}");
        }
        if count == 1 {
            retried += 1;
            assert_eq!(
                line["server"],
                good.addr.to_string(),
                "the server that answered"
            );
        }
    }
    assert!(retried >= 1, "{lines:?}");
    assert_eq!(
        retried,
        retries(&podgate).await,
        "the metric counts the same retries"
    );

    // The `retry_attempts` filter keeps only the requests that were retried.
    let dir = Dir::new();
    let podgate = logged(&dir).await;
    let mut filtered = pushed;
    filtered["observability"] = json!({ "access_log": { "filters": { "retry_attempts": 1 } } });
    push(&podgate, &filtered).await;
    for host in ["b.test", "a.test", "b.test", "a.test", "a.test", "b.test"] {
        assert_eq!(podgate.get(host, "/").await.status, 200);
    }
    let wanted = usize::try_from(retries(&podgate).await).expect("a small count");
    assert!(wanted >= 1);
    let lines = log_lines(&dir, wanted).await;
    sleep(Duration::from_millis(300)).await;
    let lines_later = log_lines(&dir, wanted).await;
    assert_eq!(
        lines_later.len(),
        wanted,
        "only the retried requests are logged: {lines:?}"
    );
    for line in &lines_later {
        assert_eq!(
            (&line["host"], &line["retry_attempts"]),
            (&json!("a.test"), &json!(1))
        );
    }
}

/// A listener whose accept queue is full, so a connect to it hangs until the dial timeout. The
/// listener and the filler connections must live as long as the test.
async fn blackhole() -> (SocketAddr, TcpListener, Vec<TcpStream>) {
    let socket = TcpSocket::new_v4().expect("socket");
    socket
        .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("bind");
    let listener = socket.listen(1).expect("listen");
    let addr = listener.local_addr().expect("addr");
    let mut held = Vec::new();
    for _ in 0..16 {
        match timeout(Duration::from_millis(300), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => held.push(stream),
            _ => return (addr, listener, held),
        }
    }
    panic!("the accept queue never filled");
}

/// `pushed` with every service using a transport with `fields` (`dial_timeout_secs`, ...).
fn with_transport(mut pushed: Value, fields: &Value) -> Value {
    let mut declared = json!({ "name": "t", "type": "servers_transport" });
    if let (Some(object), Some(extra)) = (declared.as_object_mut(), fields.as_object()) {
        object.extend(extra.clone());
    }
    pushed["apps"][0]["transports"] = json!([declared]);
    pushed["apps"][0]["revisions"][0]["services"][0]["transport"] = json!("t");
    pushed
}

#[tokio::test]
async fn retry_dial_timeout_retried_read_timeout_not() {
    let podgate = Podgate::start().await;
    let chain = [retry(&json!({"attempts": 2, "initial_interval_ms": 1}))];
    let good = Backend::good().await;

    // A dial that times out sent nothing, so another server takes the request.
    let (hung, _listener, _held) = blackhole().await;
    let pushed = with_transport(
        guarded(1, &[hung, good.addr], &chain, 100),
        &json!({"dial_timeout_secs": 1}),
    );
    push(&podgate, &pushed).await;
    let started = Instant::now();
    for _ in 0..4 {
        let answer = get(&podgate).await;
        assert_eq!((answer.status, answer.body.as_str()), (200, "good"));
    }
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "a request met the hung server and waited for its dial to time out"
    );
    assert!(retries(&podgate).await >= 1);
    assert_eq!(
        good.hits(),
        4,
        "each request was answered once by the good server"
    );

    // A response that never comes may have been caused by the request: a `504`, no retry. The
    // good server answers exactly the requests that were not sent to the silent one.
    let silent = Backend::start("silent", Mode::Slow(Duration::from_secs(60))).await;
    let pushed = with_transport(
        guarded(2, &[silent.addr, good.addr], &chain, 100),
        &json!({"read_timeout_secs": 1}),
    );
    push(&podgate, &pushed).await;
    let before = good.hits();
    let mut answered = 0;
    let mut timed_out = 0;
    for _ in 0..4 {
        match get(&podgate).await.status {
            200 => answered += 1,
            504 => timed_out += 1,
            other => panic!("status {other}"),
        }
    }
    assert!(timed_out >= 1, "a request met the silent server");
    assert_eq!(silent.hits(), timed_out);
    assert_eq!(
        good.hits() - before,
        answered,
        "a timed out request was not sent to the good server"
    );
}

/// `guarded`, with the router answered by a `mirroring` service that copies every request,
/// body included, to a service holding `shadow`.
fn mirrored(
    version: u64,
    servers: &[SocketAddr],
    shadow: SocketAddr,
    middlewares: &[Value],
) -> Value {
    let mut pushed = guarded(version, servers, middlewares, 100);
    if let Some(services) = pushed["apps"][0]["revisions"][0]["services"].as_array_mut() {
        services.push(json!({
            "name": "shadow", "type": "loadbalancer",
            "servers": [{ "url": format!("http://{shadow}") }],
        }));
        services.push(json!({
            "name": "m", "type": "mirroring", "service": "web",
            "mirrors": [{ "service": "shadow", "percent": 100 }],
            "mirror_body": true, "max_body_size": 65536,
        }));
    }
    pushed["apps"][0]["routers"][0]["service"] = json!("m");
    pushed
}

/// Waits until `server` stops receiving, so a count taken after it is final.
async fn settled(server: &Backend) -> usize {
    let mut last = server.hits();
    loop {
        sleep(Duration::from_millis(400)).await;
        let now = server.hits();
        if now == last {
            return now;
        }
        last = now;
    }
}

#[tokio::test]
async fn retry_mirrors_once() {
    // A connect error: the request is retried on another server, and mirrored once.
    let podgate = Podgate::start().await;
    let (dead, good, shadow) = (
        common::refused(),
        Backend::good().await,
        Backend::good().await,
    );
    let chain = [retry(&json!({"attempts": 3, "initial_interval_ms": 1}))];
    push(
        &podgate,
        &mirrored(1, &[dead.addr, good.addr], shadow.addr, &chain),
    )
    .await;
    let mut bodies = Vec::new();
    for index in 0..6 {
        assert_eq!(get(&podgate).await.status, 200);
        let body = body_of(index, 200);
        assert_eq!(posted(&podgate, &body, false).await.status, 200);
        bodies.push(body);
    }
    assert!(
        retries(&podgate).await >= 1,
        "some request met the dead server first"
    );
    assert_eq!(
        settled(&shadow).await,
        12,
        "one copy of each of the 12 requests, retried or not"
    );
    for body in &bodies {
        assert_eq!(
            shadow.count_of(body),
            1,
            "a retried POST was copied once, whole"
        );
    }

    // A dead pooled connection: the buffered body is replayed to the second server, and the copy
    // of the request is still one, with the body once.
    let podgate = Podgate::start().await;
    let (stale, good, shadow) = (
        Backend::start("stale", Mode::DropReused).await,
        Backend::good().await,
        Backend::good().await,
    );
    let chain = [
        buffer(),
        retry(&json!({"attempts": 2, "initial_interval_ms": 1, "methods": ["POST"]})),
    ];
    push(
        &podgate,
        &mirrored(1, &[stale.addr, good.addr], shadow.addr, &chain),
    )
    .await;
    let sent = posts_until_dropped(&podgate, &stale, 5_000, false).await;
    for (body, answer) in &sent {
        assert_eq!(answer.status, 200, "{}", answer.body);
        let _ = body;
    }
    assert_eq!(
        settled(&shadow).await,
        sent.len(),
        "one copy of every request"
    );
    for (body, _) in &sent {
        assert_eq!(
            shadow.count_of(body),
            1,
            "the copy has the body once, not once per attempt"
        );
    }
}
