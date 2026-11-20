//! End to end: per-tenant in-flight and buffer budgets, enforced on the real binary and observed
//! through `GET /metrics` on its admin socket.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::{Podgate, app, serving, snapshot};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

const MIB: u64 = 1024 * 1024;

/// A response as received: status, lowercase headers, and the body after chunked and gzip
/// decoding.
struct Fetched {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Fetched {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let line_end = find(raw, b"\r\n").expect("chunk size line");
        let size = usize::from_str_radix(
            std::str::from_utf8(&raw[..line_end]).expect("ascii size"),
            16,
        )
        .expect("hex chunk size");
        raw = &raw[line_end + 2..];
        if size == 0 {
            return body;
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(bytes[..3], [0x1f, 0x8b, 8], "gzip header");
    let inflated = miniz_oxide::inflate::decompress_to_vec(&bytes[10..bytes.len() - 8])
        .expect("valid deflate stream");
    assert_eq!(
        bytes[bytes.len() - 8..bytes.len() - 4],
        crc32fast::hash(&inflated).to_le_bytes(),
        "gzip crc"
    );
    inflated
}

/// `GET /` with `Host: host`, offering gzip, and decodes what comes back.
async fn fetch(proxy: SocketAddr, host: &str) -> Fetched {
    timeout(Duration::from_secs(20), async {
        let mut stream = TcpStream::connect(proxy).await.expect("connect");
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let split = find(&raw, b"\r\n\r\n").expect("header end");
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status line");
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let mut body = raw[split + 4..].to_vec();
        let find_header = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        if find_header("transfer-encoding") == Some("chunked") {
            body = dechunk(&body);
        }
        if find_header("content-encoding") == Some("gzip") {
            body = gunzip(&body);
        }
        Fetched {
            status,
            headers,
            body,
        }
    })
    .await
    .expect("response in time")
}

/// A backend that sends its headers and half of its body, waits, then sends the rest, so
/// responses overlap in the proxy.
struct SlowUpstream {
    addr: SocketAddr,
}

impl SlowUpstream {
    async fn start(body: Arc<[u8]>, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(stream, Arc::clone(&body), delay));
            }
        });
        Self { addr }
    }
}

async fn serve(mut stream: TcpStream, body: Arc<[u8]>, delay: Duration) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let (first, second) = body.split_at(body.len() / 2);
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = find(&seen, b"\r\n\r\n") {
            seen.drain(..end + 4);
            let sent = async {
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(first).await?;
                stream.flush().await?;
                sleep(delay).await;
                stream.write_all(second).await
            }
            .await;
            if sent.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// Value of the series `name{tenant="t1"}` in a Prometheus text body. A tenant that has not
/// served a request has no series yet, which reads as 0.
fn series(metrics: &str, name: &str) -> u64 {
    let prefix = format!("{name}{{tenant=\"t1\"}} ");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.parse().expect("integer sample"))
}

fn compressible_body() -> Arc<[u8]> {
    (0..12_000_u32)
        .flat_map(|n| format!("line {n}: some text that compresses well\n").into_bytes())
        .collect::<Vec<u8>>()
        .into()
}

/// Tenant `t1` with the given budget, one app `a.test` on `addr`.
fn tenant_snapshot(addr: SocketAddr, max_inflight: u64, max_buffer_bytes: u64) -> Value {
    let mut snapshot = snapshot(1, &[app("a", &["a.test"], &[serving("r1", addr)])]);
    snapshot["tenants"][0]["budget"] =
        serde_json::json!({ "max_inflight": max_inflight, "max_buffer_bytes": max_buffer_bytes });
    snapshot
}

#[tokio::test]
async fn buffer_budget_holds() {
    let podgate = Arc::new(Podgate::start().await);
    let body = compressible_body();
    let upstream = SlowUpstream::start(Arc::clone(&body), Duration::from_millis(400)).await;
    let pushed = podgate
        .push_snapshot(&tenant_snapshot(upstream.addr, 1000, MIB))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");

    // The highest gauge value seen while the requests run, sampled from outside.
    let sampled_max = Arc::new(AtomicU64::new(0));
    let sampler = tokio::spawn({
        let (podgate, sampled_max) = (Arc::clone(&podgate), Arc::clone(&sampled_max));
        async move {
            loop {
                let metrics = podgate.admin_get("/metrics").await.body;
                let now = series(&metrics, "podgate_tenant_buffer_bytes");
                sampled_max.fetch_max(now, Ordering::Relaxed);
                sleep(Duration::from_millis(10)).await;
            }
        }
    });

    let proxy = podgate.proxy_addr;
    let requests: Vec<_> = (0..200)
        .map(|_| tokio::spawn(fetch(proxy, "a.test")))
        .collect();
    let mut compressed = 0;
    let mut identity = 0;
    for request in requests {
        let response = request.await.expect("request task");
        assert_eq!(response.status, 200, "every response is served");
        assert_eq!(response.body, *body, "the body arrives intact either way");
        match response.header("content-encoding") {
            Some("gzip") => compressed += 1,
            None => identity += 1,
            Some(other) => panic!("unexpected content-encoding {other}"),
        }
        assert_eq!(response.header("vary"), Some("accept-encoding"));
    }
    sampler.abort();

    assert!(compressed > 0, "some responses fit the budget");
    assert!(identity > 0, "the rest degrade to identity, not to errors");

    let metrics = podgate.admin_get("/metrics").await.body;
    let peak = series(&metrics, "podgate_tenant_buffer_bytes_peak");
    assert!(peak > 0, "compression was charged: {metrics}");
    assert!(peak <= MIB, "peak {peak} passed the budget: {metrics}");
    assert!(sampled_max.load(Ordering::Relaxed) <= MIB);
    assert_eq!(series(&metrics, "podgate_tenant_buffer_bytes"), 0);
    assert_eq!(series(&metrics, "podgate_tenant_inflight"), 0);
    assert!(series(&metrics, "podgate_tenant_compression_skipped_total") >= identity);
}

#[tokio::test]
async fn inflight_cap_503() {
    let podgate = Arc::new(Podgate::start().await);
    let upstream = SlowUpstream::start(compressible_body(), Duration::from_millis(1500)).await;
    let pushed = podgate
        .push_snapshot(&tenant_snapshot(upstream.addr, 2, MIB))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");

    let held: Vec<_> = (0..2)
        .map(|_| {
            let podgate = Arc::clone(&podgate);
            tokio::spawn(async move { podgate.get("a.test", "/").await })
        })
        .collect();
    for _ in 0..100 {
        let metrics = podgate.admin_get("/metrics").await.body;
        if series(&metrics, "podgate_tenant_inflight") == 2 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }

    let refused = podgate.get("a.test", "/").await;
    assert_eq!(refused.status, 503);
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(
        refused.body,
        r#"{"error":"tenant is over its in-flight limit"}"#
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        series(&metrics, "podgate_tenant_inflight_rejected_total"),
        1
    );

    for request in held {
        assert_eq!(request.await.expect("request task").status, 200);
    }
    let again = podgate.get("a.test", "/").await;
    assert_eq!(again.status, 200, "finished requests free their slots");
}
