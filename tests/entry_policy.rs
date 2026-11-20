//! Entry point policies through the real binary: redirect, timeouts, HTTP/2 limits,
//! header rules and the encoded-slash opt-in, and the snapshots that must be refused.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;

const LISTENERS: [(&str, &str); 2] = [("plain", "http"), ("secure", "https")];

/// `apps` as a snapshot of `version` with the entry point policies `policies`.
fn with_policies(version: u64, apps: &[Value], policies: &Value) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["entry_points"] = policies.clone();
    pushed
}

fn codes(body: &Value) -> Vec<String> {
    body["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code").to_owned())
        .collect()
}

/// The first `message` of a rejected snapshot.
fn message(body: &Value) -> String {
    body["conflicts"][0]["message"]
        .as_str()
        .expect("message")
        .to_owned()
}

async fn start() -> Podgate {
    Podgate::start_with_entry_points(&LISTENERS, &[]).await
}

/// A backend that reads each request in full and answers with its head as the body.
struct Echo {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
    /// Requests whose whole body arrived.
    completed: Arc<AtomicUsize>,
}

impl Echo {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let completed = Arc::new(AtomicUsize::new(0));
        let (seen, done) = (Arc::clone(&heads), Arc::clone(&completed));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(echo_one(stream, Arc::clone(&seen), Arc::clone(&done)));
            }
        });
        Self {
            addr,
            heads,
            completed,
        }
    }

    async fn heads(&self) -> Vec<String> {
        self.heads.lock().await.clone()
    }
}

async fn echo_one(mut stream: TcpStream, heads: Arc<Mutex<Vec<String>>>, done: Arc<AtomicUsize>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 4096];
    let end = loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&seen[..end]).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::to_owned)
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while seen.len() < end + length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
    heads.lock().await.push(head.clone());
    done.fetch_add(1, Ordering::SeqCst);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{head}",
        head.len()
    );
    drop(stream.write_all(response.as_bytes()).await);
}

/// A backend that answers with `size` bytes as fast as the proxy reads them.
async fn big_upstream(size: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind big");
    let addr = listener.local_addr().expect("big addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = [0_u8; 4096];
                if stream.read(&mut head).await.unwrap_or(0) == 0 {
                    return;
                }
                let start = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\n\r\n"
                );
                if stream.write_all(start.as_bytes()).await.is_err() {
                    return;
                }
                let block = vec![b'x'; 64 * 1024];
                let mut sent = 0;
                while sent < size {
                    let take = block.len().min(size - sent);
                    if stream.write_all(&block[..take]).await.is_err() {
                        return;
                    }
                    sent += take;
                }
            });
        }
    });
    addr
}

fn plain_app(up: SocketAddr) -> Value {
    app("a", &["a.test"], &[serving("r1", up)])
}

async fn push_ok(podgate: &Podgate, pushed: &Value) {
    let accepted = podgate.push_snapshot(pushed).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
}

#[tokio::test]
async fn redirect_entry_point_keeps_path_and_query() {
    let podgate = start().await;
    let up = Upstream::start("never").await;
    let secure = podgate.entry_addr("secure").port();
    let policies = json!([{ "name": "plain", "redirect": { "to": "secure" } }]);
    push_ok(
        &podgate,
        &with_policies(1, &[plain_app(up.addr)], &policies),
    )
    .await;

    let moved = podgate.get("Ex.Test", "/a/./b//c?q=1&r=%20x").await;
    assert_eq!(moved.status, 302, "{moved:?}");
    assert_eq!(
        moved.header("location"),
        Some(format!("https://ex.test:{secure}/a/b/c?q=1&r=%20x").as_str())
    );
    assert_eq!(moved.body, "", "a redirect has no body");
    for method in ["POST", "HEAD", "PUT"] {
        let other = podgate.request(method, "a.test", "/x", &[]).await;
        assert_eq!(other.status, 302, "{method}: {other:?}");
    }

    let permanent = json!([{ "name": "plain", "redirect": { "to": "secure", "permanent": true } }]);
    push_ok(
        &podgate,
        &with_policies(2, &[plain_app(up.addr)], &permanent),
    )
    .await;
    let moved = podgate.get("a.test", "/").await;
    assert_eq!(moved.status, 301, "{moved:?}");
    assert_eq!(
        moved.header("location"),
        Some(format!("https://a.test:{secure}/").as_str())
    );

    let none = json!([]);
    push_ok(&podgate, &with_policies(3, &[plain_app(up.addr)], &none)).await;
    let served = podgate.get("a.test", "/").await;
    assert_eq!((served.status, served.body.as_str()), (200, "never"));
}

#[tokio::test]
async fn redirect_target_port() {
    let podgate = start().await;
    let up = Upstream::start("never").await;
    let secure = podgate.entry_addr("secure").port();
    let policies = json!([{ "name": "plain", "redirect": { "to": "secure" } }]);
    push_ok(
        &podgate,
        &with_policies(1, &[plain_app(up.addr)], &policies),
    )
    .await;

    let named = podgate.get("a.test:9999", "/p").await;
    assert_eq!(
        named.header("location"),
        Some(format!("https://a.test:{secure}/p").as_str()),
        "the target's port replaces the one the request named: {named:?}"
    );
    let forged = podgate
        .get_with_headers(
            "a.test",
            "/p",
            &[
                ("X-Forwarded-Host", "evil.test"),
                ("X-Forwarded-Port", "1"),
                ("X-Forwarded-Proto", "https"),
            ],
        )
        .await;
    assert_eq!(
        forged.header("location"),
        Some(format!("https://a.test:{secure}/p").as_str()),
        "a peer that is not trusted cannot choose the host: {forged:?}"
    );
}

#[tokio::test]
async fn redirect_refuses_unsafe_hosts_and_paths() {
    let podgate = start().await;
    let up = Upstream::start("never").await;
    let policies = json!([{ "name": "plain", "redirect": { "to": "secure" } }]);
    push_ok(
        &podgate,
        &with_policies(1, &[plain_app(up.addr)], &policies),
    )
    .await;

    for host in ["a.test/evil", "user@a.test", "a.test\u{7f}x", "a b.test"] {
        let refused = podgate.get(host, "/").await;
        assert_eq!(refused.status, 400, "{host:?}: {refused:?}");
        assert!(refused.header("location").is_none(), "{host:?}");
    }
    let crlf = podgate.get("a.test", "/a%0d%0aSet-Cookie:%20x=1").await;
    assert_eq!(crlf.status, 400, "{crlf:?}");
    assert!(crlf.header("location").is_none());
}

#[tokio::test]
async fn redirect_spares_acme_challenge() {
    let podgate = start().await;
    let up = Upstream::start("never").await;
    let secure = podgate.entry_addr("secure").port();
    let mut pushed = with_policies(
        1,
        &[plain_app(up.addr)],
        &json!([{ "name": "plain", "redirect": { "to": "secure" } }]),
    );
    pushed["acme"] = json!({
        "issuer_node": "some-other-node",
        "directory_url": "https://127.0.0.1:1/directory",
        "challenges": [{ "token": "tok123", "key_authorization": "tok123.thumb" }],
    });
    push_ok(&podgate, &pushed).await;

    let answered = podgate
        .get("a.test", "/.well-known/acme-challenge/tok123")
        .await;
    assert_eq!(answered.status, 200, "{answered:?}");
    assert_eq!(answered.body, "tok123.thumb");
    let unknown = podgate
        .get("a.test", "/.well-known/acme-challenge/not-pushed")
        .await;
    assert_eq!(unknown.status, 302, "{unknown:?}");
    assert_eq!(
        unknown.header("location"),
        Some(format!("https://a.test:{secure}/.well-known/acme-challenge/not-pushed").as_str())
    );
}

#[tokio::test]
async fn redirect_loop_rejected() {
    let podgate = start().await;
    let up = Upstream::start("x").await;
    let apps = [plain_app(up.addr)];
    for (version, policies) in [
        (
            1,
            json!([
                { "name": "plain", "redirect": { "to": "secure" } },
                { "name": "secure", "redirect": { "to": "plain" } },
            ]),
        ),
        (
            2,
            json!([{ "name": "plain", "redirect": { "to": "plain" } }]),
        ),
    ] {
        let rejected = podgate
            .push_snapshot(&with_policies(version, &apps, &policies))
            .await;
        assert_eq!(rejected.status, 422, "{}", rejected.body);
        assert!(
            codes(&rejected.json())
                .iter()
                .all(|code| code == "redirect_loop"),
            "{}",
            rejected.body
        );
        assert!(!codes(&rejected.json()).is_empty());
    }
    let chain = json!([{ "name": "plain", "redirect": { "to": "secure" } }]);
    push_ok(&podgate, &with_policies(3, &apps, &chain)).await;
}

#[tokio::test]
async fn redirect_unknown_target_rejected() {
    let podgate = start().await;
    let up = Upstream::start("x").await;
    let apps = [plain_app(up.addr)];
    let unknown = json!([{ "name": "plain", "redirect": { "to": "nowhere" } }]);
    let rejected = podgate
        .push_snapshot(&with_policies(1, &apps, &unknown))
        .await;
    assert_eq!(rejected.status, 422, "{}", rejected.body);
    assert_eq!(codes(&rejected.json()), ["unknown_entry_point"]);
    assert!(message(&rejected.json()).contains("nowhere"));

    let scheme = json!([{ "name": "plain", "redirect": { "to": "secure", "scheme": "https" } }]);
    let rejected = podgate
        .push_snapshot(&with_policies(2, &apps, &scheme))
        .await;
    assert_eq!(codes(&rejected.json()), ["invalid_redirect"]);
}

#[tokio::test]
async fn policy_unknown_entry_point_rejected() {
    let podgate = start().await;
    let up = Upstream::start("x").await;
    let rejected = podgate
        .push_snapshot(&with_policies(
            1,
            &[plain_app(up.addr)],
            &json!([{ "name": "nowhere", "allow_encoded_slash": true }]),
        ))
        .await;
    assert_eq!(rejected.status, 422, "{}", rejected.body);
    assert_eq!(codes(&rejected.json()), ["unknown_entry_point"]);
}

#[tokio::test]
async fn policy_unsupported_knob_rejected() {
    let podgate = start().await;
    let up = Upstream::start("served").await;
    let apps = [plain_app(up.addr)];
    push_ok(&podgate, &snapshot(1, &apps)).await;

    let cases = [
        (
            json!({ "name": "plain", "timeouts": { "header_secs": 5 } }),
            "timeouts.header_secs",
        ),
        (
            json!({ "name": "secure", "timeouts": { "read_secs": 5 } }),
            "timeouts.read_secs",
        ),
        (
            json!({ "name": "plain", "http2": { "max_concurrent_streams": 10 } }),
            "http2.max_concurrent_streams",
        ),
        (
            json!({ "name": "plain", "max_header_bytes": 4_000_000 }),
            "max_header_bytes",
        ),
    ];
    for (version, (policy, knob)) in (2..).zip(cases) {
        let rejected = podgate
            .push_snapshot(&with_policies(version, &apps, &json!([policy.clone()])))
            .await;
        assert_eq!(rejected.status, 422, "{policy}: {}", rejected.body);
        assert_eq!(codes(&rejected.json()), ["unsupported_setting"], "{policy}");
        assert!(
            message(&rejected.json()).contains(knob),
            "the error names the knob {knob}: {}",
            rejected.body
        );
    }
    let invalid = json!([{ "name": "plain", "timeouts": { "read_secs": 0 } }]);
    let rejected = podgate
        .push_snapshot(&with_policies(9, &apps, &invalid))
        .await;
    assert_eq!(codes(&rejected.json()), ["invalid_timeouts"]);
    let typo = json!([{ "name": "plain", "timeouts": { "read_second": 3 } }]);
    let rejected = podgate.push_snapshot(&with_policies(9, &apps, &typo)).await;
    assert_eq!(codes(&rejected.json()), ["invalid_timeouts"]);

    let still = podgate.get("a.test", "/").await;
    assert_eq!(
        (still.status, still.body.as_str()),
        (200, "served"),
        "a refused snapshot leaves the live one serving"
    );
}

#[tokio::test]
async fn policy_read_timeout_closes_slow_client() {
    let podgate = start().await;
    let echo = Echo::start().await;
    let policies = json!([{ "name": "plain", "timeouts": { "read_secs": 1 } }]);
    push_ok(
        &podgate,
        &with_policies(1, &[plain_app(echo.addr)], &policies),
    )
    .await;

    let mut client = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    client
        .write_all(
            b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc",
        )
        .await
        .expect("send head and part of the body");
    let started = Instant::now();
    let mut seen = Vec::new();
    timeout(Duration::from_secs(8), client.read_to_end(&mut seen))
        .await
        .expect("the proxy gave up on the stalled body")
        .ok();
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(800) && waited < Duration::from_secs(6),
        "closed after about the read timeout, not before and not at Pingora's 60 s: {waited:?}"
    );
    assert_eq!(
        echo.completed.load(Ordering::SeqCst),
        0,
        "the body never completed"
    );

    let mut fine = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    fine.write_all(
        b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
    )
    .await
    .expect("send");
    let mut answer = Vec::new();
    fine.read_to_end(&mut answer).await.expect("read");
    assert!(
        String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200"),
        "a client that sends in time is served"
    );
}

async fn read_until(client: &mut TcpStream, marker: &[u8]) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !seen.windows(marker.len()).any(|window| window == marker) {
        let read = timeout(Duration::from_secs(5), client.read(&mut chunk))
            .await
            .expect("response in time")
            .expect("read");
        assert_ne!(read, 0, "closed before {marker:?}: {seen:?}");
        seen.extend_from_slice(&chunk[..read]);
    }
    seen
}

/// How long `client` takes to see the proxy close it; `None` when it is still open after `limit`.
async fn closed_after(client: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let started = Instant::now();
    let mut chunk = [0_u8; 64];
    match timeout(limit, client.read(&mut chunk)).await {
        Ok(Ok(0) | Err(_)) => Some(started.elapsed()),
        Ok(Ok(_)) | Err(_) => None,
    }
}

#[tokio::test]
async fn policy_idle_timeout() {
    let podgate = start().await;
    let up = Upstream::start("ok").await;
    let policies = json!([{ "name": "plain", "timeouts": { "idle_secs": 1 } }]);
    push_ok(
        &podgate,
        &with_policies(1, &[plain_app(up.addr)], &policies),
    )
    .await;

    let mut kept = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    kept.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
        .await
        .expect("send");
    read_until(&mut kept, b"ok").await;
    let idle = closed_after(&mut kept, Duration::from_secs(8)).await;
    assert!(
        idle.is_some_and(|waited| waited < Duration::from_secs(4)),
        "a kept-alive connection closes after idle_secs, not Pingora's 60 s: {idle:?}"
    );

    let mut silent = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    let silent_for = closed_after(&mut silent, Duration::from_secs(8)).await;
    assert!(
        silent_for.is_some_and(|waited| waited < Duration::from_secs(4)),
        "a connection that never sends is closed too: {silent_for:?}"
    );

    let mut busy = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    for _ in 0..3 {
        busy.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .expect("send");
        read_until(&mut busy, b"ok").await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

/// The settings of an HTTP/2 connection to `podgate`: the server's stream limit once its first
/// response arrived, and whether the connection closed within `idle_wait` afterwards.
async fn h2_probe(podgate: &Podgate, cert: &TestCert, idle_wait: Duration) -> (usize, bool) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).expect("trust the certificate");
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let name = rustls::pki_types::ServerName::try_from("a.test".to_owned()).expect("name");
    let tcp = TcpStream::connect(podgate.tls_addr).await.expect("connect");
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .expect("handshake");
    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    let closed = tokio::spawn(connection);
    let request = http::Request::get("https://a.test/")
        .body(())
        .expect("request");
    let (response, _) = client.send_request(request, true).expect("send");
    let response = response.await.expect("response");
    assert_eq!(response.status().as_u16(), 200);
    let mut body = response.into_body();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("chunk");
        body.flow_control()
            .release_capacity(chunk.len())
            .expect("capacity");
    }
    let limit = client.current_max_send_streams();
    let ended = timeout(idle_wait, closed).await.is_ok();
    (limit, ended)
}

async fn tls_start() -> (Podgate, TestCert, Upstream) {
    let podgate = start().await;
    let up = Upstream::start("ok").await;
    let cert = TestCert::new(&["a.test"]);
    (podgate, cert, up)
}

fn secured(version: u64, up: &Upstream, cert: &TestCert, policies: &Value) -> Value {
    let mut pushed = with_policies(version, &[plain_app(up.addr)], policies);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    pushed
}

#[tokio::test]
async fn policy_http2_stream_limit() {
    let (podgate, cert, up) = tls_start().await;
    push_ok(&podgate, &secured(1, &up, &cert, &json!([]))).await;
    let (default, _) = Box::pin(h2_probe(&podgate, &cert, Duration::from_millis(100))).await;
    assert_eq!(default, 100, "Pingora's default limit without a policy");

    let policies = json!([{ "name": "secure", "http2": { "max_concurrent_streams": 3 } }]);
    push_ok(&podgate, &secured(2, &up, &cert, &policies)).await;
    let (limited, _) = Box::pin(h2_probe(&podgate, &cert, Duration::from_millis(100))).await;
    assert_eq!(
        limited, 3,
        "the snapshot's limit is what the server advertises"
    );

    push_ok(&podgate, &secured(3, &up, &cert, &json!([]))).await;
    let (back, _) = Box::pin(h2_probe(&podgate, &cert, Duration::from_millis(100))).await;
    assert_eq!(back, 100, "removing the policy restores the default");
}

#[tokio::test]
async fn policy_idle_timeout_h2() {
    let (podgate, cert, up) = tls_start().await;
    let policies = json!([{ "name": "secure", "timeouts": { "idle_secs": 1 } }]);
    push_ok(&podgate, &secured(1, &up, &cert, &policies)).await;
    let (_, closed) = Box::pin(h2_probe(&podgate, &cert, Duration::from_secs(6))).await;
    assert!(
        closed,
        "an idle HTTP/2 connection is closed after idle_secs"
    );

    push_ok(&podgate, &secured(2, &up, &cert, &json!([]))).await;
    let (_, closed) = Box::pin(h2_probe(&podgate, &cert, Duration::from_secs(3))).await;
    assert!(!closed, "without a policy the connection stays open");
}

#[tokio::test]
async fn policy_write_timeout_closes_stalled_reader() {
    let podgate = start().await;
    let size = 96 * 1024 * 1024;
    let big = big_upstream(size).await;
    let policies = json!([{ "name": "plain", "timeouts": { "write_secs": 1 } }]);
    push_ok(&podgate, &with_policies(1, &[plain_app(big)], &policies)).await;

    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket
        .set_recv_buffer_size(4096)
        .expect("small receive buffer");
    let mut client = socket.connect(podgate.proxy_addr).await.expect("connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_secs(4)).await;
    let mut received = 0_usize;
    let mut chunk = vec![0_u8; 256 * 1024];
    let ended = timeout(Duration::from_secs(20), async {
        loop {
            match client.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => received += read,
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the proxy ended the stalled response");
    assert!(
        received < size,
        "the response was cut short by the write timeout: {received} of {size} bytes"
    );
}

#[tokio::test]
async fn underscore_headers_delete() {
    let podgate = start().await;
    let echo = Echo::start().await;
    let sent = [("X_Forwarded_For", "1.2.3.4"), ("X-Plain", "1")];

    push_ok(
        &podgate,
        &with_policies(1, &[plain_app(echo.addr)], &json!([])),
    )
    .await;
    let kept = podgate.get_with_headers("a.test", "/", &sent).await;
    assert!(
        kept.body
            .to_ascii_lowercase()
            .contains("x_forwarded_for: 1.2.3.4"),
        "{kept:?}"
    );

    let policies = json!([{ "name": "plain", "underscore_headers": "delete" }]);
    push_ok(
        &podgate,
        &with_policies(2, &[plain_app(echo.addr)], &policies),
    )
    .await;
    let deleted = podgate.get_with_headers("a.test", "/", &sent).await;
    assert_eq!(deleted.status, 200, "{deleted:?}");
    let body = deleted.body.to_ascii_lowercase();
    assert!(
        !body.contains("x_forwarded_for") && !body.contains("1.2.3.4"),
        "{body}"
    );
    assert!(
        body.contains("x-plain: 1"),
        "other headers are kept: {body}"
    );
    assert!(!echo.heads().await.is_empty());

    let policies = json!([{ "name": "plain", "underscore_headers": "keep" }]);
    push_ok(
        &podgate,
        &with_policies(3, &[plain_app(echo.addr)], &policies),
    )
    .await;
    let kept = podgate.get_with_headers("a.test", "/", &sent).await;
    assert!(
        kept.body.to_ascii_lowercase().contains("x_forwarded_for"),
        "{kept:?}"
    );

    let word = json!([{ "name": "plain", "underscore_headers": "mangle" }]);
    let rejected = podgate
        .push_snapshot(&with_policies(4, &[plain_app(echo.addr)], &word))
        .await;
    assert!(
        rejected.status == 400 || rejected.status == 422,
        "{rejected:?}"
    );
}

#[tokio::test]
async fn underscore_headers_reject() {
    let podgate = start().await;
    let echo = Echo::start().await;
    let policies = json!([{ "name": "plain", "underscore_headers": "reject" }]);
    push_ok(
        &podgate,
        &with_policies(1, &[plain_app(echo.addr)], &policies),
    )
    .await;

    let refused = podgate
        .get_with_headers("a.test", "/", &[("X_Forwarded_For", "1.2.3.4")])
        .await;
    assert_eq!(refused.status, 400, "{refused:?}");
    assert!(
        echo.heads().await.is_empty(),
        "the upstream never saw the request"
    );

    let clean = podgate
        .get_with_headers("a.test", "/", &[("X-Forwarded-For", "1.2.3.4")])
        .await;
    assert_eq!(clean.status, 200, "{clean:?}");
}

#[tokio::test]
async fn max_header_bytes_refuses_a_large_head() {
    let podgate = start().await;
    let echo = Echo::start().await;
    let policies = json!([{ "name": "plain", "max_header_bytes": 512 }]);
    push_ok(
        &podgate,
        &with_policies(1, &[plain_app(echo.addr)], &policies),
    )
    .await;

    let small = podgate.get("a.test", "/").await;
    assert_eq!(small.status, 200, "{small:?}");
    let long = "x".repeat(600);
    let big = podgate
        .get_with_headers("a.test", "/", &[("X-Long", long.as_str())])
        .await;
    assert_eq!(big.status, 431, "{big:?}");
    assert_eq!(
        echo.heads().await.len(),
        1,
        "only the small request reached the upstream"
    );
}

/// An app whose router matches `a.test` under `prefix`.
fn under(prefix: &str, up: SocketAddr) -> Value {
    let mut under = plain_app(up);
    under["routers"][0]["match"] =
        json!({ "all": [{ "host": "a.test" }, { "path_prefix": prefix }] });
    under
}

#[tokio::test]
async fn encoded_slash_allowed_by_policy() {
    let podgate =
        Podgate::start_with_entry_points(&[("strict", "http"), ("lax", "http")], &[]).await;
    let echo = Echo::start().await;
    let policies = json!([{ "name": "lax", "allow_encoded_slash": true }]);
    push_ok(
        &podgate,
        &with_policies(1, &[under("/files", echo.addr)], &policies),
    )
    .await;

    let refused = podgate.get_on("strict", "a.test", "/files/a%2Fb").await;
    assert_eq!(
        refused.status, 400,
        "no policy: an encoded slash is refused: {refused:?}"
    );
    let refused = podgate.get_on("strict", "a.test", "/files/a%2fb").await;
    assert_eq!(refused.status, 400, "{refused:?}");

    let allowed = podgate.get_on("lax", "a.test", "/files/a%2fb/c?q=1").await;
    assert_eq!(allowed.status, 200, "{allowed:?}");
    assert!(
        allowed.body.starts_with("GET /files/a%2Fb/c?q=1 HTTP/1.1"),
        "the upstream gets the slash as an escape, never as a separator: {}",
        allowed.body
    );

    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/files/a%252Fb&entry_point=lax")
        .await;
    assert_eq!(
        explained.status, 200,
        "explain agrees with the proxy: {}",
        explained.body
    );
    assert_eq!(explained.json()["path"], "/files/a%2Fb");
    let strict = podgate
        .admin_get("/v1/explain?url=http://a.test/files/a%252Fb&entry_point=strict")
        .await;
    assert_eq!(strict.status, 400, "{}", strict.body);

    let other_escapes = podgate.get_on("lax", "a.test", "/files/a%5Cb").await;
    assert_eq!(
        other_escapes.status, 400,
        "an encoded backslash stays refused: {other_escapes:?}"
    );
    let nul = podgate.get_on("lax", "a.test", "/files/a%00b").await;
    assert_eq!(nul.status, 400, "an encoded NUL stays refused: {nul:?}");
    let dots = podgate.get_on("lax", "a.test", "/files/%2e%2e/x").await;
    assert_eq!(
        dots.status, 400,
        "an encoded dot segment stays refused: {dots:?}"
    );
}

#[tokio::test]
async fn encoded_slash_is_never_a_separator_for_matching() {
    let podgate = Podgate::start_with_entry_points(&[("lax", "http")], &[]).await;
    let echo = Echo::start().await;
    let policies = json!([{ "name": "lax", "allow_encoded_slash": true }]);
    push_ok(
        &podgate,
        &with_policies(1, &[under("/api", echo.addr)], &policies),
    )
    .await;

    let decoded_would_match = podgate.get_on("lax", "a.test", "/api%2Fadmin").await;
    assert_eq!(
        decoded_would_match.status, 404,
        "`/api%2Fadmin` is one segment, not `/api/admin`: {decoded_would_match:?}"
    );
    let real = podgate.get_on("lax", "a.test", "/api/admin").await;
    assert_eq!(real.status, 200, "{real:?}");
}

#[tokio::test]
async fn plan_lists_allow_encoded_slash() {
    let podgate = start().await;
    let up = Upstream::start("x").await;
    let apps = [plain_app(up.addr)];
    push_ok(&podgate, &snapshot(1, &apps)).await;

    let lax = with_policies(
        2,
        &apps,
        &json!([{ "name": "plain", "allow_encoded_slash": true }]),
    );
    let plan = podgate.admin_post("/v1/snapshot/plan", &lax).await;
    assert_eq!(plan.status, 200, "{}", plan.body);
    assert_eq!(
        plan.json()["posture_changes"],
        json!([{ "host": "entry_point:plain", "app": "", "kind": "allow_encoded_slash" }])
    );
    assert_eq!(
        podgate.get("a.test", "/x%2Fy").await.status,
        400,
        "a plan applies nothing"
    );

    push_ok(&podgate, &lax).await;
    let strict = with_policies(3, &apps, &json!([]));
    let plan = podgate.admin_post("/v1/snapshot/plan", &strict).await;
    assert_eq!(
        plan.json()["posture_changes"],
        json!([]),
        "tightening is not listed"
    );

    let weaker = with_policies(
        4,
        &apps,
        &json!([{ "name": "plain", "allow_encoded_slash": true, "underscore_headers": "reject" }]),
    );
    push_ok(&podgate, &weaker).await;
    let relaxed = with_policies(
        5,
        &apps,
        &json!([{ "name": "plain", "allow_encoded_slash": true, "underscore_headers": "keep" }]),
    );
    let plan = podgate.admin_post("/v1/snapshot/plan", &relaxed).await;
    assert_eq!(
        plan.json()["posture_changes"],
        json!([{ "host": "entry_point:plain", "app": "", "kind": "underscore_headers_relaxed" }])
    );
}

#[tokio::test]
async fn plan_lists_a_removed_https_redirect() {
    let podgate = start().await;
    let up = Upstream::start("x").await;
    let apps = [plain_app(up.addr)];
    let redirecting = with_policies(
        1,
        &apps,
        &json!([{ "name": "plain", "redirect": { "to": "secure" } }]),
    );
    push_ok(&podgate, &redirecting).await;
    let plan = podgate
        .admin_post("/v1/snapshot/plan", &with_policies(2, &apps, &json!([])))
        .await;
    assert_eq!(
        plan.json()["posture_changes"],
        json!([{ "host": "entry_point:plain", "app": "", "kind": "entry_point_https_redirect_removed" }])
    );
}

#[tokio::test]
async fn explain_reports_the_entry_point_redirect() {
    let podgate = start().await;
    let up = Upstream::start("x").await;
    let secure = podgate.entry_addr("secure").port();
    let policies = json!([{ "name": "plain", "redirect": { "to": "secure", "permanent": true } }]);
    push_ok(
        &podgate,
        &with_policies(1, &[plain_app(up.addr)], &policies),
    )
    .await;

    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/x&entry_point=plain")
        .await;
    assert_eq!(explained.status, 200, "{}", explained.body);
    let body = explained.json();
    assert_eq!(
        body["entry_redirect"],
        json!({ "to": "secure", "status": 301, "scheme": "https", "port": secure })
    );
    let over_tls = podgate
        .admin_get("/v1/explain?url=https://a.test/x&entry_point=secure")
        .await;
    assert!(
        over_tls.json().get("entry_redirect").is_none(),
        "{}",
        over_tls.body
    );
}
