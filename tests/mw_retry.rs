//! The `retry` middleware through the real proxy: a failed attempt moves on to
//! another server only when that is safe, the next attempt passes backend admission again, every
//! failed attempt counts against its server, and the number of retries reaches the access log.
//! The decision table and the backoff arithmetic are unit tests in `src/middleware/retry.rs`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Podgate, app, middleware, revision_on, snapshot, with_chain};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

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

/// A backend that records what it received.
struct Backend {
    addr: SocketAddr,
    label: &'static str,
    hits: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Backend {
    async fn start(label: &'static str, mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn({
            let (hits, bodies) = (Arc::clone(&hits), Arc::clone(&bodies));
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(
                        stream,
                        mode,
                        label,
                        Arc::clone(&hits),
                        Arc::clone(&bodies),
                    ));
                }
            }
        });
        Self {
            addr,
            label,
            hits,
            bodies,
        }
    }

    async fn good() -> Self {
        Self::start("good", Mode::Answer).await
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().expect("bodies").clone()
    }
}

/// Reads one request: its head, and its body when it has a length or is chunked.
async fn read_request(stream: &mut TcpStream, seen: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut chunk = [0_u8; 4096];
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

async fn serve(
    mut stream: TcpStream,
    mode: Mode,
    label: &'static str,
    hits: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
) {
    let mut seen = Vec::new();
    let mut on_connection = 0_u32;
    while let Some(body) = read_request(&mut stream, &mut seen).await {
        hits.fetch_add(1, Ordering::SeqCst);
        bodies.lock().expect("bodies").push(body);
        on_connection += 1;
        match mode {
            Mode::DropAlways => return,
            Mode::DropReused if on_connection > 1 => return,
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

/// App `a.test` whose `web` service balances `servers` round robin (in that order), with
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

/// Server 0 of the pair is the one whose pooled connection dies on its second request: the first
/// request goes to it (and leaves a connection in the pool), the second to the other server, so
/// the third request reuses the dead one.
async fn prime(podgate: &Podgate) {
    for expected in ["stale", "good"] {
        let response = podgate.get("a.test", "/").await;
        assert_eq!(
            (response.status, response.body.as_str()),
            (200, expected),
            "{response:?}"
        );
    }
}

#[tokio::test]
async fn retry_moves_to_another_server_on_connect_error() {
    let podgate = Podgate::start().await;
    let (dead, good) = (common::refused(), Backend::good().await);
    let chain = [retry(&json!({"attempts": 3, "initial_interval_ms": 1}))];
    push(&podgate, &guarded(1, &[dead.addr, good.addr], &chain, 100)).await;
    for _ in 0..4 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!((response.status, response.body.as_str()), (200, "good"));
    }
    assert_eq!(good.hits(), 4);
    // Nothing was sent to the dead server, so any method moves on, a body included.
    let (status, body) = post(&podgate, b"sent once", false).await;
    assert_eq!((status, body.as_str()), (200, "good"));
    assert_eq!(
        good.bodies().last().map(Vec::as_slice),
        Some(&b"sent once"[..])
    );
    // Each of the five requests was retried once, which the service's series counts.
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metrics.contains("podgate_service_retries_total{app=\"a.test\",service=\"web\"} 5\n"),
        "{metrics}"
    );
    // Without the middleware a connect error is a 502.
    push(&podgate, &guarded(2, &[dead.addr, good.addr], &[], 100)).await;
    assert_eq!(podgate.get("a.test", "/").await.status, 502);
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
    let (status, _) = post(&podgate, b"charge the card", false).await;
    assert_eq!(status, 502);
    assert_eq!(broken.hits(), 1, "the body reached the first server");
    assert_eq!(good.hits(), 0, "and was not sent to another");
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
    prime(&podgate).await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(
        (response.status, response.body.as_str()),
        (200, "good"),
        "{response:?}"
    );
    assert_eq!(stale.hits(), 2, "the dead connection read the request");
    assert_eq!(good.hits(), 2);
}

/// Podgate with the stale server first, `chain` in the app, and the pool primed.
async fn stale_pair(chain: &[Value]) -> (Podgate, Backend, Backend) {
    let podgate = Podgate::start().await;
    let (stale, good) = (
        Backend::start("stale", Mode::DropReused).await,
        Backend::good().await,
    );
    push(&podgate, &guarded(1, &[stale.addr, good.addr], chain, 100)).await;
    prime(&podgate).await;
    (podgate, stale, good)
}

fn buffer() -> Value {
    middleware(
        "buffer",
        "buffering",
        json!({"max_request_body_bytes": 65536, "buffer_request": true}),
    )
}

#[tokio::test]
async fn retry_post_only_when_buffered_and_listed() {
    let listed = json!({"attempts": 2, "initial_interval_ms": 1, "methods": ["POST"]});

    // Listed and buffered: replayed.
    let (podgate, _stale, good) = stale_pair(&[buffer(), retry(&listed)]).await;
    let (status, body) = post(&podgate, b"replay me", false).await;
    assert_eq!((status, body.as_str()), (200, "good"));
    assert_eq!(
        good.bodies().last().map(Vec::as_slice),
        Some(&b"replay me"[..])
    );

    // Listed, but the body streams: never replayed.
    let (podgate, stale, good) = stale_pair(&[retry(&listed)]).await;
    let (status, _) = post(&podgate, b"streamed", false).await;
    assert_eq!(status, 502);
    assert_eq!(
        (stale.hits(), good.hits()),
        (2, 1),
        "only the priming reached them"
    );

    // Buffered, but POST is not in the default methods.
    let default = json!({"attempts": 2, "initial_interval_ms": 1});
    let (podgate, stale, good) = stale_pair(&[buffer(), retry(&default)]).await;
    let (status, _) = post(&podgate, b"buffered", false).await;
    assert_eq!(status, 502);
    assert_eq!((stale.hits(), good.hits()), (2, 1));
}

#[tokio::test]
async fn buffered_body_replayed_on_retry() {
    // Bigger than any single read, framed both ways.
    let body: Vec<u8> = (0..40_000_u32)
        .map(|n| b'a' + u8::try_from(n % 26).unwrap_or(0))
        .collect();
    for chunked in [false, true] {
        let chain = [
            buffer(),
            retry(&json!({"attempts": 2, "initial_interval_ms": 1, "methods": ["POST"]})),
        ];
        let (podgate, stale, good) = stale_pair(&chain).await;
        let (status, answer) = post(&podgate, &body, chunked).await;
        assert_eq!(
            (status, answer.as_str()),
            (200, "good"),
            "chunked: {chunked}"
        );
        let received = stale.bodies();
        assert_eq!(
            received.last(),
            Some(&body),
            "the first server read all of it"
        );
        let replayed = good.bodies();
        assert_eq!(
            replayed.last(),
            Some(&body),
            "the second server got the whole body, chunked: {chunked}"
        );
        assert_eq!(good.label, "good");
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
    let (dead, slow) = (
        common::refused(),
        Backend::start("slow", Mode::Slow(Duration::from_millis(1500))).await,
    );
    // The wait before the retry is 1 to 2 s; the tenant allows one request in flight.
    let chain = [retry(&json!({"attempts": 2, "initial_interval_ms": 2000}))];
    push(&podgate, &guarded(1, &[dead.addr, slow.addr], &chain, 1)).await;
    let first = tokio::spawn({
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

    // During the wait: the request holds its tenant slot, and no backend slot, not even the
    // dead server's, which went back before the wait.
    sleep(Duration::from_millis(500)).await;
    let waiting = podgate.admin_get("/metrics").await.body;
    assert_eq!(tenant_inflight(&waiting), 1);
    assert_eq!(inflight(&waiting, dead.addr), 0);
    assert_eq!(inflight(&waiting, slow.addr), 0);
    // The retry holds the tenant's only slot, so a second request is refused for capacity.
    let refused = podgate.get("a.test", "/").await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert_eq!(refused.header("retry-after"), Some("1"));

    // After the wait: the retry took a slot of the second server's backend.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let metrics = podgate.admin_get("/metrics").await.body;
        if inflight(&metrics, slow.addr) == 1 {
            assert_eq!(tenant_inflight(&metrics), 1, "still one");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the retry never took a backend slot"
        );
        sleep(Duration::from_millis(50)).await;
    }
    let raw = first.await.expect("first request");
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(tenant_inflight(&metrics), 0);
    assert_eq!(inflight(&metrics, slow.addr), 0);
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
    // Each request fails once on the dead server and succeeds on the good one: the client never
    // sees an error, and the dead server is ejected after its second failed attempt.
    for _ in 0..2 {
        assert_eq!(podgate.get("a.test", "/").await.status, 200);
    }
    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/")
        .await
        .json();
    let servers = servers(explained);
    assert_eq!(servers[0]["available"], false, "{servers}");
    assert_eq!(servers[1]["available"], true, "{servers}");
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

    // Every request is logged with its own count: `a.test` goes to the dead server first.
    let dir = Dir::new();
    let podgate = logged(&dir).await;
    let pushed = with_direct(guarded(1, &[dead.addr, good.addr], &chain, 100));
    push_logged(&podgate, pushed.clone()).await;
    for host in ["a.test", "b.test", "a.test"] {
        assert_eq!(podgate.get(host, "/").await.status, 200);
    }
    let lines = log_lines(&dir, 3).await;
    let counts: Vec<(&Value, &Value)> = lines
        .iter()
        .map(|line| (&line["host"], &line["retry_attempts"]))
        .collect();
    assert_eq!(
        counts,
        [
            (&json!("a.test"), &json!(1)),
            (&json!("b.test"), &json!(0)),
            (&json!("a.test"), &json!(1)),
        ]
    );
    assert_eq!(
        lines[0]["server"],
        good.addr.to_string(),
        "the server that answered"
    );

    // The `retry_attempts` filter keeps only the requests that were retried.
    let dir = Dir::new();
    let podgate = logged(&dir).await;
    let mut filtered = pushed;
    filtered["observability"] = json!({ "access_log": { "filters": { "retry_attempts": 1 } } });
    push(&podgate, &filtered).await;
    for host in ["b.test", "a.test", "b.test"] {
        assert_eq!(podgate.get(host, "/").await.status, 200);
    }
    let lines = log_lines(&dir, 1).await;
    sleep(Duration::from_millis(300)).await;
    let lines_later = log_lines(&dir, 1).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(
        lines_later.len(),
        1,
        "the requests that were not retried are not logged"
    );
    assert_eq!(
        (&lines[0]["host"], &lines[0]["retry_attempts"]),
        (&json!("a.test"), &json!(1))
    );
}
