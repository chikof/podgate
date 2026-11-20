//! Failed-request recording and replay, end to end through the real binary.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Podgate, Response, app, serving, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::time::timeout;

/// One request an upstream received.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A backend whose status can be changed during the test. It answers with a body naming the
/// status, a `Set-Cookie` header, and remembers every request it got.
struct FlakyUpstream {
    addr: SocketAddr,
    status: Arc<AtomicU16>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl FlakyUpstream {
    async fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let status = Arc::new(AtomicU16::new(status));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (shared_status, shared_seen) = (status.clone(), seen.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, shared_status.clone(), shared_seen.clone()));
            }
        });
        Self { addr, status, seen }
    }

    fn set_status(&self, status: u16) {
        self.status.store(status, Ordering::Relaxed);
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
}

async fn serve(mut stream: TcpStream, status: Arc<AtomicU16>, seen: Arc<Mutex<Vec<Seen>>>) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let head_end = loop {
            if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break end;
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next().unwrap_or_default().split(' ');
        let method = request_line.next().unwrap_or_default().to_owned();
        let target = request_line.next().unwrap_or_default().to_owned();
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let length: usize = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);
        buffer.drain(..head_end + 4);
        while buffer.len() < length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
        let body: Vec<u8> = buffer.drain(..length).collect();
        let is_head = method == "HEAD";
        seen.lock().expect("lock").push(Seen {
            method,
            target,
            headers,
            body,
        });
        let code = status.load(Ordering::Relaxed);
        let text = format!("upstream says {code}");
        let payload = if is_head { "" } else { text.as_str() };
        let response = format!(
            "HTTP/1.1 {code} X\r\nContent-Type: text/plain\r\nSet-Cookie: session=s3cret\r\n\
             Content-Length: {}\r\n\r\n{payload}",
            text.len()
        );
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// Reads everything the server sends until it closes and parses one HTTP/1.1 response.
async fn finish<S: AsyncReadExt + Unpin>(stream: &mut S) -> Response {
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("response in time")
        .expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("header end");
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    Response {
        status,
        headers,
        body: body.to_owned(),
    }
}

/// Sends `method path` with `Host: a.test`, `extra` header lines and `body` through the proxy.
async fn proxy(
    podgate: &Podgate,
    method: &str,
    path: &str,
    extra: &[&str],
    body: &[u8],
) -> Response {
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n");
    for line in extra {
        request.push_str(line);
        request.push_str("\r\n");
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send head");
    stream.write_all(body).await.expect("send body");
    finish(&mut stream).await
}

async fn admin(podgate: &Podgate, method: &str, path: &str) -> Response {
    let mut stream = UnixStream::connect(&podgate.admin_socket)
        .await
        .expect("connect admin");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.expect("send");
    finish(&mut stream).await
}

async fn failures(podgate: &Podgate, app: &str) -> Vec<Value> {
    let response = admin(podgate, "GET", &format!("/v1/apps/{app}/failures")).await;
    assert_eq!(response.status, 200, "{response:?}");
    response.json()["failures"]
        .as_array()
        .expect("failures array")
        .clone()
}

/// App `a` on host `a.test`, with `record_bodies` when asked.
fn app_a(revisions: &[Value], record_bodies: bool) -> Value {
    let mut app = app("a", &["a.test"], revisions);
    if record_bodies {
        app["record_bodies"] = json!(true);
    }
    app
}

async fn start(upstream: &FlakyUpstream, record_bodies: bool) -> Podgate {
    let podgate = Podgate::start().await;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[app_a(&[serving("r1", upstream.addr)], record_bodies)],
        ))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    podgate
}

fn header<'a>(headers: &'a Value, name: &str) -> Option<&'a str> {
    headers
        .as_array()?
        .iter()
        .find(|pair| pair["name"] == name)
        .and_then(|pair| pair["value"].as_str())
}

#[tokio::test]
async fn failures_ring() {
    let upstream = FlakyUpstream::start(500).await;
    let podgate = start(&upstream, false).await;
    assert!(failures(&podgate, "a").await.is_empty());

    for n in 0..150 {
        let response = proxy(&podgate, "GET", &format!("/p{n}"), &[], b"").await;
        assert_eq!(response.status, 500);
    }
    upstream.set_status(200);
    assert_eq!(proxy(&podgate, "GET", "/fine", &[], b"").await.status, 200);

    let listed = failures(&podgate, "a").await;
    assert_eq!(listed.len(), 100);
    assert_eq!(listed[0]["uri"], "/p149");
    assert_eq!(listed[99]["uri"], "/p50");
    let first = &listed[0];
    assert_eq!(first["method"], "GET");
    assert_eq!(first["host"], "a.test");
    assert_eq!(first["status"], 500);
    assert_eq!(first["revision"], "r1");
    assert_eq!(first["origin"], "upstream");
    assert_eq!(first["upstream"], upstream.addr.to_string());
    assert!(listed[0]["id"].as_u64() > listed[1]["id"].as_u64());

    // The ring survives a swap that keeps the app, and goes with the app otherwise.
    let kept = snapshot(2, &[app_a(&[serving("r1", upstream.addr)], false)]);
    assert_eq!(podgate.push_snapshot(&kept).await.status, 200);
    assert_eq!(failures(&podgate, "a").await.len(), 100);
    assert_eq!(podgate.push_snapshot(&snapshot(3, &[])).await.status, 200);
    let gone = admin(&podgate, "GET", "/v1/apps/a/failures").await;
    assert_eq!(gone.status, 404);
    let back = snapshot(4, &[app_a(&[serving("r1", upstream.addr)], false)]);
    assert_eq!(podgate.push_snapshot(&back).await.status, 200);
    assert!(failures(&podgate, "a").await.is_empty());
}

#[tokio::test]
async fn failures_records_podgate_generated_5xx() {
    let refused = common::refused();
    let podgate = Podgate::start().await;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[app_a(&[serving("r1", refused.addr)], false)],
        ))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    assert!(proxy(&podgate, "GET", "/x", &[], b"").await.status >= 500);

    let listed = failures(&podgate, "a").await;
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0]["origin"], "podgate");
    assert!(listed[0]["status"].as_u64() >= Some(500));
}

#[tokio::test]
async fn failures_redacted() {
    let upstream = FlakyUpstream::start(500).await;
    let podgate = start(&upstream, true).await;
    let response = proxy(
        &podgate,
        "POST",
        "/login",
        &[
            "Authorization: Bearer s3cret-token",
            "Proxy-Authorization: Basic s3cret-proxy",
            "Cookie: sid=s3cret-cookie",
            "X-Visible: yes",
        ],
        b"user=a",
    )
    .await;
    assert_eq!(response.status, 500);

    let listed = failures(&podgate, "a").await;
    let record = &listed[0];
    let request = &record["request_headers"];
    for name in ["authorization", "proxy-authorization", "cookie"] {
        assert_eq!(header(request, name), Some("[redacted]"), "{request}");
    }
    assert_eq!(header(request, "x-visible"), Some("yes"));
    assert_eq!(
        header(&record["response_headers"], "set-cookie"),
        Some("[redacted]")
    );
    let everything = record.to_string();
    assert!(!everything.contains("s3cret"), "{everything}");
}

#[tokio::test]
async fn failures_bodies_opt_in() {
    let upstream = FlakyUpstream::start(500).await;
    let off = start(&upstream, false).await;
    proxy(&off, "POST", "/p", &[], b"payload").await;
    let record = failures(&off, "a").await.remove(0);
    assert_eq!(record["request_body"], Value::Null);
    assert_eq!(record["response_body"], Value::Null);
    assert_eq!(record["request_body_too_large"], false);

    let on = start(&upstream, true).await;
    proxy(&on, "POST", "/p", &[], b"payload").await;
    let record = failures(&on, "a").await.remove(0);
    assert_eq!(record["request_body"], "payload");
    assert_eq!(record["response_body"], "upstream says 500");

    let exactly = vec![b'x'; 64 * 1024];
    proxy(&on, "POST", "/exact", &[], &exactly).await;
    let record = failures(&on, "a").await.remove(0);
    assert_eq!(record["uri"], "/exact");
    assert_eq!(
        record["request_body"].as_str().map(str::len),
        Some(64 * 1024)
    );

    let over = vec![b'x'; 64 * 1024 + 1];
    let response = proxy(&on, "POST", "/over", &[], &over).await;
    assert_eq!(response.status, 500);
    let record = failures(&on, "a").await.remove(0);
    assert_eq!(record["uri"], "/over");
    assert_eq!(record["request_body"], Value::Null);
    assert_eq!(record["request_body_too_large"], true);
    let seen = upstream.seen();
    assert_eq!(
        seen.last().expect("seen").body.len(),
        over.len(),
        "upstream got the full body"
    );
}

#[tokio::test]
async fn failures_replay() {
    let upstream = FlakyUpstream::start(500).await;
    let other = FlakyUpstream::start(200).await;
    let podgate = Podgate::start().await;
    let revisions = [
        serving("r1", upstream.addr),
        common::revision("r2", other.addr, 0, "retiring"),
    ];
    let pushed = podgate
        .push_snapshot(&snapshot(1, &[app_a(&revisions, true)]))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");

    let first = proxy(
        &podgate,
        "GET",
        "/thing?q=1",
        &["Authorization: Bearer s3cret-token", "X-Trace: abc"],
        b"",
    )
    .await;
    assert_eq!(first.status, 500);
    let id = failures(&podgate, "a").await[0]["id"].as_u64().expect("id");
    let url = |revision: &str| format!("/v1/apps/a/failures/{id}/replay?revision={revision}");

    upstream.set_status(200);
    let replayed = admin(&podgate, "POST", &url("r1")).await;
    assert_eq!(replayed.status, 200, "{replayed:?}");
    let body = replayed.json();
    assert_eq!(body["status"], 200);
    assert_eq!(body["body"], "upstream says 200");
    assert_eq!(body["body_truncated"], false);
    assert_eq!(header(&body["headers"], "content-type"), Some("text/plain"));
    let seen = upstream.seen();
    let sent = seen.last().expect("replayed request");
    assert_eq!(
        (sent.method.as_str(), sent.target.as_str()),
        ("GET", "/thing?q=1")
    );
    assert_eq!(sent.header("x-trace"), Some("abc"));
    assert_eq!(sent.header("host"), Some("a.test"));
    assert_eq!(
        sent.header("authorization"),
        None,
        "redacted headers are dropped, not sent"
    );

    let elsewhere = admin(&podgate, "POST", &url("r2")).await;
    assert_eq!(elsewhere.status, 200, "{elsewhere:?}");
    assert_eq!(other.seen().last().expect("r2 got it").target, "/thing?q=1");

    assert_eq!(admin(&podgate, "POST", &url("nope")).await.status, 404);
    assert_eq!(
        admin(
            &podgate,
            "POST",
            &format!("/v1/apps/a/failures/{}/replay?revision=r1", id + 1000)
        )
        .await
        .status,
        404
    );
    assert_eq!(
        admin(
            &podgate,
            "POST",
            "/v1/apps/a/failures/abc/replay?revision=r1"
        )
        .await
        .status,
        404
    );
    assert_eq!(
        admin(
            &podgate,
            "POST",
            &format!("/v1/apps/zzz/failures/{id}/replay?revision=r1")
        )
        .await
        .status,
        404
    );
    assert_eq!(
        admin(&podgate, "GET", "/v1/apps/zzz/failures").await.status,
        404
    );
    let missing = admin(
        &podgate,
        "POST",
        &format!("/v1/apps/a/failures/{id}/replay"),
    )
    .await;
    assert_eq!(missing.status, 400);
    assert!(missing.json()["error"].is_string());
}

#[tokio::test]
async fn failures_replay_safe_methods() {
    let upstream = FlakyUpstream::start(500).await;
    let podgate = start(&upstream, true).await;
    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        proxy(&podgate, method, "/write", &[], b"data").await;
    }
    proxy(&podgate, "HEAD", "/head", &[], b"").await;
    let listed = failures(&podgate, "a").await;
    assert_eq!(listed.len(), 5);
    let id_of = |method: &str| {
        listed
            .iter()
            .find(|record| record["method"] == method)
            .expect("recorded")["id"]
            .as_u64()
            .expect("id")
    };
    upstream.set_status(200);
    let before = upstream.seen().len();

    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        let refused = admin(
            &podgate,
            "POST",
            &format!("/v1/apps/a/failures/{}/replay?revision=r1", id_of(method)),
        )
        .await;
        assert_eq!(refused.status, 409, "{method}: {refused:?}");
        assert!(
            refused.json()["error"]
                .as_str()
                .expect("error")
                .contains("force=true")
        );
    }
    assert_eq!(upstream.seen().len(), before, "nothing was sent");

    let forced = admin(
        &podgate,
        "POST",
        &format!(
            "/v1/apps/a/failures/{}/replay?revision=r1&force=true",
            id_of("POST")
        ),
    )
    .await;
    assert_eq!(forced.status, 200, "{forced:?}");
    let seen = upstream.seen();
    assert_eq!(seen.len(), before + 1);
    let sent = seen.last().expect("forced request");
    assert_eq!(
        (sent.method.as_str(), sent.body.as_slice()),
        ("POST", b"data".as_slice())
    );

    let head = admin(
        &podgate,
        "POST",
        &format!("/v1/apps/a/failures/{}/replay?revision=r1", id_of("HEAD")),
    )
    .await;
    assert_eq!(head.status, 200, "{head:?}");
    assert_eq!(upstream.seen().last().expect("head").method, "HEAD");
}
