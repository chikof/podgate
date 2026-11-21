//! The `forward_auth` middleware: the auth service of the same app decides, and every
//! way the call can fail closes the door. The pure rules (address, headers, posture, the HTTP/1.1
//! reader) are unit-tested in `src/middleware/forward_auth.rs` and its `client.rs`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    Podgate, Response, app, refused, serving, snapshot, with_forward_auth, with_middleware,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// What a test server answers with.
enum Reply {
    /// These bytes, then the connection closes.
    Raw(Vec<u8>),
    /// These bytes after a pause.
    Delay(Duration, Vec<u8>),
}

fn raw(status: u16, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    out.into_bytes()
}

fn http(status: u16, headers: &[(&str, &str)], body: &str) -> Reply {
    Reply::Raw(raw(status, headers, body))
}

type Handler = dyn Fn(&str) -> Reply + Send + Sync;

/// A server that records each request head and answers by `handler`, which gets the head.
struct Server {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
    peak: Arc<AtomicUsize>,
}

impl Server {
    async fn start(handler: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let handler: Arc<Handler> = Arc::new(handler);
        let shared = (Arc::clone(&heads), live, Arc::clone(&peak));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (heads, live, peak) = shared.clone();
                tokio::spawn(serve(stream, Arc::clone(&handler), heads, live, peak));
            }
        });
        Self { addr, heads, peak }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("heads").clone()
    }

    fn requests(&self) -> usize {
        self.heads().len()
    }

    fn peak_concurrency(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

async fn serve(
    mut stream: TcpStream,
    handler: Arc<Handler>,
    heads: Arc<Mutex<Vec<String>>>,
    live: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end + 4]).into_owned();
            heads.lock().expect("heads").push(head.clone());
            peak.fetch_max(live.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            let bytes = match handler(&head) {
                Reply::Raw(bytes) => bytes,
                Reply::Delay(pause, bytes) => {
                    sleep(pause).await;
                    bytes
                }
            };
            drop(stream.write_all(&bytes).await);
            live.fetch_sub(1, Ordering::SeqCst);
            drop(stream.shutdown().await);
            return;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

fn path_of(head: &str) -> &str {
    head.split(' ').nth(1).unwrap_or_default()
}

/// The value of header `name` (lower case) in a request head.
fn header_of<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(": ")?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

/// The app's upstream: answers `200` with the request head it got as the body, so a test sees
/// exactly what reached it.
async fn echo() -> Server {
    Server::start(|head| http(200, &[], head)).await
}

/// An auth service that answers by the path of the forwarded URI: `/deny` is a `401` with a
/// challenge, a cookie and a page, `/err` a `500`, anything else `200` with `X-User: ann`.
async fn auth() -> Server {
    Server::start(|head| {
        match header_of(head, "x-forwarded-uri").map(|uri| uri.split('?').next().unwrap_or(uri)) {
            Some("/deny") => http(
                401,
                &[
                    ("WWW-Authenticate", "Bearer realm=\"sso\""),
                    ("Set-Cookie", "login=1; Path=/"),
                    ("Server", "internal-auth/9"),
                    ("Content-Type", "text/plain"),
                ],
                "please log in",
            ),
            Some("/err") => http(500, &[], "auth broke"),
            _ => http(
                200,
                &[
                    ("X-User", "ann"),
                    ("X-Auth-Groups", "dev"),
                    ("X-Other", "nope"),
                ],
                "",
            ),
        }
    })
    .await
}

fn site(id: &str, host: &str, upstream: SocketAddr, auth: SocketAddr, extra: &Value) -> Value {
    with_forward_auth(app(id, &[host], &[serving("r1", upstream)]), auth, extra)
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{response:?}");
}

fn rejection(response: &Response) -> Value {
    assert_eq!(response.status, 422, "{response:?}");
    response.json()["conflicts"][0].clone()
}

fn assert_closed(response: &Response) {
    assert_eq!(response.status, 503, "{response:?}");
    assert_eq!(response.body, r#"{"error":"auth service unavailable"}"#);
}

#[tokio::test]
async fn forward_auth_allows_on_2xx() {
    let podgate = Podgate::start().await;
    let (up, auth) = (echo().await, auth().await);
    let extra = json!({"response_headers": ["X-User"], "response_headers_regex": "^x-auth-"});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, auth.addr, &extra)]),
    )
    .await;

    let answer = podgate.get("a.test", "/ok").await;
    assert_eq!(answer.status, 200, "{answer:?}");
    // The listed name and the regex match reach the upstream; the rest of the answer does not.
    assert_eq!(
        header_of(&answer.body, "x-user"),
        Some("ann"),
        "{}",
        answer.body
    );
    assert_eq!(
        header_of(&answer.body, "x-auth-groups"),
        Some("dev"),
        "{}",
        answer.body
    );
    assert_eq!(header_of(&answer.body, "x-other"), None, "{}", answer.body);
    assert_eq!(up.requests(), 1);
    assert_eq!(auth.requests(), 1);
}

#[tokio::test]
async fn forward_auth_relays_denial() {
    let podgate = Podgate::start().await;
    let (up, auth) = (echo().await, auth().await);
    let extra = json!({"response_headers": ["X-User"]});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, auth.addr, &extra)]),
    )
    .await;

    let denied = podgate.get("a.test", "/deny").await;
    assert_eq!(denied.status, 401, "{denied:?}");
    assert_eq!(denied.body, "please log in");
    assert_eq!(
        denied.header("www-authenticate"),
        Some("Bearer realm=\"sso\"")
    );
    assert_eq!(denied.header("set-cookie"), Some("login=1; Path=/"));
    assert_eq!(denied.header("content-type"), Some("text/plain"));
    assert_eq!(denied.header("content-length"), Some("13"));
    assert_ne!(
        denied.header("server"),
        Some("internal-auth/9"),
        "{denied:?}"
    );
    // Any non-2xx is a verdict, not a failure.
    let broke = podgate.get("a.test", "/err").await;
    assert_eq!((broke.status, broke.body.as_str()), (500, "auth broke"));
    assert_eq!(
        up.requests(),
        0,
        "a denied request never reaches the upstream"
    );
}

#[tokio::test]
async fn forward_auth_strips_client_supplied_response_headers() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    // The auth service says nothing about identity: whatever the client claims must die.
    let quiet = Server::start(|_| http(200, &[], "")).await;
    let extra = json!({"response_headers": ["X-User"], "response_headers_regex": "^x-auth-"});
    let forged = [
        ("X-User", "admin"),
        ("x-user", "root"),
        ("X-Auth-Role", "superuser"),
        ("X-Kept", "yes"),
    ];
    let apps = [
        site("a", "a.test", up.addr, quiet.addr, &extra),
        site("b", "b.test", up.addr, auth().await.addr, &extra),
    ];
    push(&podgate, &snapshot(1, &apps)).await;

    let answer = podgate.get_with_headers("a.test", "/ok", &forged).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    for gone in ["x-user", "x-auth-role"] {
        assert_eq!(
            header_of(&answer.body, gone),
            None,
            "{gone} in {}",
            answer.body
        );
    }
    for gone in ["admin", "root", "superuser"] {
        assert!(!answer.body.contains(gone), "{gone} in {}", answer.body);
    }
    assert_eq!(
        header_of(&answer.body, "x-kept"),
        Some("yes"),
        "{}",
        answer.body
    );
    for head in quiet.heads() {
        assert!(
            !head.contains("admin") && !head.contains("superuser"),
            "the auth service never sees the forged copies: {head}"
        );
    }

    // When the service does set it, only its value arrives, once.
    let answer = podgate.get_with_headers("b.test", "/ok", &forged).await;
    assert_eq!(
        answer
            .body
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("x-user:"))
            .count(),
        1,
        "{}",
        answer.body
    );
    assert_eq!(
        header_of(&answer.body, "x-user"),
        Some("ann"),
        "{}",
        answer.body
    );
    assert!(!answer.body.contains("superuser"), "{}", answer.body);
}

#[tokio::test]
async fn forward_auth_unreachable_503() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let dead = refused();
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, dead.addr, &Value::Null)]),
    )
    .await;

    assert_closed(&podgate.get("a.test", "/ok").await);
    assert_eq!(up.requests(), 0);
    drop(dead);
}

#[tokio::test]
async fn forward_auth_timeout_503() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let slow = Server::start(|_| Reply::Delay(Duration::from_secs(6), raw(200, &[], ""))).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                slow.addr,
                &json!({"timeout_secs": 1}),
            )],
        ),
    )
    .await;

    let started = Instant::now();
    assert_closed(&podgate.get("a.test", "/ok").await);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the call is bounded by timeout_secs: {:?}",
        started.elapsed()
    );
    assert_eq!(up.requests(), 0);
}

#[tokio::test]
async fn forward_auth_body_cap_503() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let big = "x".repeat(2000);
    let allowing = {
        let big = big.clone();
        Server::start(move |_| http(200, &[], &big)).await
    };
    let denying = Server::start(move |_| http(403, &[], &big)).await;
    let apps = [
        site(
            "a",
            "a.test",
            up.addr,
            allowing.addr,
            &json!({"max_response_bytes": 1024}),
        ),
        site(
            "b",
            "b.test",
            up.addr,
            denying.addr,
            &json!({"max_response_bytes": 1024}),
        ),
        site(
            "c",
            "c.test",
            up.addr,
            denying.addr,
            &json!({"max_response_bytes": 4096}),
        ),
    ];
    push(&podgate, &snapshot(1, &apps)).await;

    // Over the cap is a failure whatever the status was: closed, not relayed, not allowed.
    assert_closed(&podgate.get("a.test", "/ok").await);
    assert_closed(&podgate.get("b.test", "/ok").await);
    assert_eq!(up.requests(), 0);
    // Within the cap the same answer is a verdict.
    let relayed = podgate.get("c.test", "/ok").await;
    assert_eq!((relayed.status, relayed.body.len()), (403, 2000));
}

#[tokio::test]
async fn forward_auth_malformed_answer_503() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let garbage = Server::start(|_| Reply::Raw(b"not http at all\r\n\r\n".to_vec())).await;
    let ambiguous = Server::start(|_| {
        Reply::Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec())
    })
    .await;
    let early_close = Server::start(|_| Reply::Raw(Vec::new())).await;
    let apps = [
        site("a", "a.test", up.addr, garbage.addr, &Value::Null),
        site("b", "b.test", up.addr, ambiguous.addr, &Value::Null),
        site("c", "c.test", up.addr, early_close.addr, &Value::Null),
    ];
    push(&podgate, &snapshot(1, &apps)).await;

    for host in ["a.test", "b.test", "c.test"] {
        assert_closed(&podgate.get(host, "/ok").await);
    }
    assert_eq!(up.requests(), 0);
}

#[tokio::test]
async fn forward_auth_concurrency_cap_503() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let slow = Server::start(|_| Reply::Delay(Duration::from_millis(800), raw(200, &[], ""))).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                slow.addr,
                &json!({"max_concurrent": 1}),
            )],
        ),
    )
    .await;

    let (first, second) = tokio::join!(podgate.get("a.test", "/1"), async {
        sleep(Duration::from_millis(250)).await;
        podgate.get("a.test", "/2").await
    });
    assert_eq!(first.status, 200, "{first:?}");
    assert_closed(&second);
    assert_eq!(second.header("retry-after"), Some("1"));
    assert_eq!(slow.peak_concurrency(), 1);
    assert_eq!(
        up.requests(),
        1,
        "only the admitted request reached the upstream"
    );
    // The permit came back.
    assert_eq!(podgate.get("a.test", "/3").await.status, 200);
}

#[tokio::test]
async fn forward_auth_sends_forwarded_headers() {
    let podgate = Podgate::start().await;
    let (up, auth) = (echo().await, auth().await);
    let extra = json!({"request_headers": ["Authorization", "Cookie", "X-Forwarded-User"]});
    push(
        &podgate,
        &snapshot(
            1,
            &[
                site("a", "a.test", up.addr, auth.addr, &extra),
                site("b", "b.test", up.addr, auth.addr, &Value::Null),
            ],
        ),
    )
    .await;

    let spoof = [
        ("Authorization", "Bearer t0ken"),
        ("Cookie", "sid=1"),
        ("User-Agent", "probe"),
        ("X-Forwarded-User", "claimed"),
        ("X-Forwarded-For", "203.0.113.9"),
        ("X-Forwarded-Host", "evil.test"),
        ("X-Forwarded-Proto", "https"),
        ("X-Forwarded-Uri", "/admin"),
        ("X-Forwarded-Method", "DELETE"),
        ("X-Real-IP", "198.51.100.1"),
        ("Forwarded", "for=198.51.100.2"),
    ];
    assert_eq!(
        podgate
            .get_with_headers("a.test", "/a/b?x=1", &spoof)
            .await
            .status,
        200
    );
    assert_eq!(
        podgate
            .get_with_headers("b.test", "/c", &spoof)
            .await
            .status,
        200
    );
    let heads = auth.heads();
    let (listed, everything) = (&heads[0], &heads[1]);

    // From the connection, never from the client: the entry point trusts nobody.
    for head in [listed, everything] {
        assert!(head.starts_with("GET /verify HTTP/1.1\r\n"), "{head}");
        assert_eq!(header_of(head, "x-forwarded-method"), Some("GET"), "{head}");
        assert_eq!(header_of(head, "x-forwarded-proto"), Some("http"), "{head}");
        assert_eq!(
            header_of(head, "x-forwarded-for"),
            Some("127.0.0.1"),
            "{head}"
        );
        for forged in ["evil.test", "203.0.113.9", "/admin", "DELETE", "198.51.100"] {
            assert!(!head.contains(forged), "{forged} in {head}");
        }
        assert_eq!(
            header_of(head, "authorization"),
            Some("Bearer t0ken"),
            "{head}"
        );
    }
    assert_eq!(header_of(listed, "x-forwarded-host"), Some("a.test"));
    assert_eq!(header_of(listed, "x-forwarded-uri"), Some("/a/b?x=1"));
    assert_eq!(
        header_of(listed, "user-agent"),
        None,
        "an allow list sends only its names"
    );
    assert_eq!(header_of(everything, "user-agent"), Some("probe"));
    assert_eq!(header_of(everything, "x-forwarded-uri"), Some("/c"));
}

#[tokio::test]
async fn forward_auth_trusts_forward_header_only_for_trusted_peers() {
    let auth = auth().await;
    let up = echo().await;
    let apps = [
        site(
            "a",
            "a.test",
            up.addr,
            auth.addr,
            &json!({"trust_forward_header": true}),
        ),
        site("b", "b.test", up.addr, auth.addr, &Value::Null),
    ];
    let trusting = |trusted: &str| {
        let mut pushed = snapshot(1, &apps);
        pushed["entry_points"] =
            json!([{"name": "web", "forwarded_headers": {"trusted_ips": [trusted]}}]);
        pushed
    };
    let podgate = Podgate::start().await;
    let chain = [
        ("X-Forwarded-For", "203.0.113.9, 10.1.1.1"),
        ("X-Forwarded-Proto", "https"),
    ];

    // The peer (loopback) is trusted: the stage that asks for it passes the chain on.
    push(&podgate, &trusting("127.0.0.0/8")).await;
    for host in ["a.test", "b.test"] {
        assert_eq!(
            podgate.get_with_headers(host, "/ok", &chain).await.status,
            200
        );
    }
    let heads = auth.heads();
    assert_eq!(
        header_of(&heads[0], "x-forwarded-for"),
        Some("203.0.113.9, 10.1.1.1, 127.0.0.1")
    );
    assert_eq!(header_of(&heads[0], "x-forwarded-proto"), Some("https"));
    assert_eq!(
        header_of(&heads[1], "x-forwarded-for"),
        Some("10.1.1.1"),
        "without the flag the resolved client is sent, not the chain"
    );

    // Another peer is trusted: the flag changes nothing, the client's header is dropped.
    let mut other = trusting("192.0.2.0/24");
    other["version"] = json!(2);
    push(&podgate, &other).await;
    assert_eq!(
        podgate
            .get_with_headers("a.test", "/ok", &chain)
            .await
            .status,
        200
    );
    let heads = auth.heads();
    let last = heads.last().expect("a call");
    assert_eq!(
        header_of(last, "x-forwarded-for"),
        Some("127.0.0.1"),
        "{last}"
    );
    assert_eq!(header_of(last, "x-forwarded-proto"), Some("http"), "{last}");
}

#[tokio::test]
async fn forward_auth_never_sends_body() {
    let podgate = Podgate::start().await;
    let (up, auth) = (echo().await, auth().await);
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, auth.addr, &Value::Null)]),
    )
    .await;

    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect to the proxy");
    let body = "SECRET-BODY-0123456789";
    let request = format!(
        "POST /submit HTTP/1.1\r\nHost: a.test\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.expect("send");
    let mut answer = Vec::new();
    drop(stream.read_to_end(&mut answer).await);
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    let heads = auth.heads();
    let head = heads.first().expect("one call");
    assert!(head.starts_with("GET /verify HTTP/1.1\r\n"), "{head}");
    assert_eq!(header_of(head, "x-forwarded-method"), Some("POST"));
    assert!(!head.contains("SECRET-BODY"), "{head}");
    assert_eq!(header_of(head, "content-length"), None, "{head}");
    assert_eq!(header_of(head, "transfer-encoding"), None, "{head}");
    // The upstream still gets the whole request, body included.
    assert!(answer.contains("POST /submit"), "{answer}");
}

/// A policy file in its own temp directory.
struct PolicyFile(PathBuf);

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-forward-auth-policy-{}-{}.json",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("write the policy file");
        Self(path)
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        // Best effort: a leftover temp file is harmless.
        drop(std::fs::remove_file(&self.0));
    }
}

#[tokio::test]
async fn forward_auth_obeys_upstream_policy() {
    let policy = PolicyFile::write(r#"{"deny": ["10.9.0.0/16"]}"#);
    let podgate =
        Podgate::start_with_env(&[("UPSTREAM_POLICY_FILE", policy.0.to_str().expect("utf-8"))])
            .await;
    let (up, auth) = (echo().await, auth().await);
    let forbidden: SocketAddr = "10.9.0.1:80".parse().expect("addr");
    let apps = [
        site("a", "a.test", up.addr, forbidden, &Value::Null),
        site("b", "b.test", up.addr, auth.addr, &Value::Null),
    ];
    // The address is only judged where it is dialled, on the exact IP: the snapshot compiles.
    push(&podgate, &snapshot(1, &apps)).await;

    assert_closed(&podgate.get("a.test", "/ok").await);
    assert_eq!(up.requests(), 0, "a forbidden auth address fails closed");
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metrics
            .lines()
            .any(|line| line.starts_with("podgate_upstream_refused_total{tenant=\"t1\"} 1")),
        "{metrics}"
    );
    // An allowed address next to it works.
    assert_eq!(podgate.get("b.test", "/ok").await.status, 200);
}

/// A certificate authority and what it issues, for an auth server that speaks TLS.
struct Pki {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().expect("CA key"),
        )
        .expect("CA");
        Self { issuer }
    }

    /// A certificate for `names` signed by this CA: its PEM and its key's PEM.
    fn issue(&self, names: &[&str]) -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("key");
        let params = rcgen::CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("params");
        let cert = params.signed_by(&key, &self.issuer).expect("sign");
        (cert.pem(), key.serialize_pem())
    }
}

/// A TLS auth server that insists on a client certificate from `pki` and says, in `X-Seen`,
/// which server name and client certificate it saw.
async fn tls_auth(pki: &Pki, server: (String, String)) -> SocketAddr {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pki.issuer.pem().as_bytes()).expect("CA DER"))
        .expect("trust the CA");
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()
    .expect("client verifier");
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(server.0.as_bytes())
        .collect::<Result<_, _>>()
        .expect("chain");
    let key = PrivateKeyDer::from_pem_slice(server.1.as_bytes()).expect("key");
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let (_, connection) = stream.get_ref();
                let seen = format!(
                    "sni={} client={}",
                    connection.server_name().unwrap_or("none"),
                    connection
                        .peer_certificates()
                        .is_some_and(|chain| !chain.is_empty())
                );
                let mut head = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&chunk[..read]),
                    }
                }
                drop(stream.write_all(&raw(200, &[("X-Seen", &seen)], "")).await);
                drop(stream.shutdown().await);
            });
        }
    });
    addr
}

#[tokio::test]
async fn forward_auth_over_tls_transport() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let pki = Pki::new();
    let addr = tls_auth(&pki, pki.issue(&["127.0.0.1", "auth.internal"])).await;
    let client = pki.issue(&[]);
    let transports = json!([{
        "name": "t", "type": "servers_transport", "server_name": "auth.internal",
        "ca_pem": pki.issuer.pem(),
        "client_cert": {"cert_pem": client.0, "key_pem": client.1},
    }]);
    let with = |id: &str, host: &str, transport: Option<&str>| {
        let mut config = json!({
            "address": format!("https://{addr}/verify"),
            "response_headers": ["x-seen"],
        });
        if let Some(name) = transport {
            config["transport"] = json!(name);
        }
        let mut app = app(id, &[host], &[serving("r1", up.addr)]);
        app["transports"] = transports.clone();
        with_middleware(app, "auth", "forward_auth", config)
    };
    push(
        &podgate,
        &snapshot(
            1,
            &[with("a", "a.test", Some("t")), with("b", "b.test", None)],
        ),
    )
    .await;

    // The private CA, the server name and the client certificate of the named transport.
    let answer = podgate.get("a.test", "/ok").await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(
        header_of(&answer.body, "x-seen"),
        Some("sni=auth.internal client=true"),
        "{}",
        answer.body
    );
    // No transport: only the platform roots are trusted, the handshake fails, the request closes.
    assert_closed(&podgate.get("b.test", "/ok").await);
    assert_eq!(up.requests(), 1);

    // A transport on a plain address is refused: a setting is never silently unused.
    let mut plain = with("c", "c.test", Some("t"));
    plain["middlewares"][0]["address"] = json!(format!("http://{addr}/verify"));
    let refused = podgate.push_snapshot(&snapshot(2, &[plain])).await;
    assert_eq!(rejection(&refused)["code"], "invalid_middleware");
}

#[tokio::test]
async fn forward_auth_before_admission() {
    let podgate = Podgate::start().await;
    let slow_up = Server::start(|head| {
        if path_of(head) == "/slow" {
            Reply::Delay(Duration::from_millis(900), raw(200, &[], "slow"))
        } else {
            http(200, &[], "fast")
        }
    })
    .await;
    let auth = auth().await;
    let mut pushed = snapshot(
        1,
        &[site("a", "a.test", slow_up.addr, auth.addr, &Value::Null)],
    );
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(1);
    push(&podgate, &pushed).await;

    // One authenticated request holds the tenant's only slot.
    let (held, denied) = tokio::join!(podgate.get("a.test", "/slow"), async {
        sleep(Duration::from_millis(300)).await;
        let denied = podgate.get("a.test", "/deny").await;
        // The slot is taken, so an authenticated request is turned away for capacity...
        let busy = podgate.get("a.test", "/other").await;
        (denied, busy)
    });
    assert_eq!(held.status, 200, "{held:?}");
    // ...but a refused one is answered by the auth service, untouched by the tenant's limit.
    assert_eq!(denied.0.status, 401, "{:?}", denied.0);
    assert_eq!(denied.0.body, "please log in");
    assert_eq!(denied.1.status, 503, "{:?}", denied.1);
    assert_eq!(
        slow_up.requests(),
        1,
        "neither the denied nor the busy request reached the backend"
    );
}

#[tokio::test]
async fn forward_auth_invalid_address_rejected() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    for (version, address) in (1..).zip([
        "/verify",
        "auth:9091/verify",
        "ftp://10.0.0.5/verify",
        "http://user:pw@10.0.0.5/verify",
        "http://",
        "",
    ]) {
        let candidate = with_middleware(
            app("a", &["a.test"], &[serving("r1", up.addr)]),
            "auth",
            "forward_auth",
            json!({"address": address}),
        );
        let refused = podgate
            .push_snapshot(&snapshot(version, &[candidate]))
            .await;
        let entry = rejection(&refused);
        assert_eq!(entry["code"], "invalid_middleware", "{address:?}: {entry}");
    }
    let unknown = with_middleware(
        app("a", &["a.test"], &[serving("r1", up.addr)]),
        "auth",
        "forward_auth",
        json!({"address": "http://10.0.0.5/v", "forward_body": true}),
    );
    let refused = podgate.push_snapshot(&snapshot(10, &[unknown])).await;
    assert_eq!(rejection(&refused)["code"], "invalid_middleware");
}

#[tokio::test]
async fn forward_auth_cap_over_tenant_budget_rejected() {
    let podgate = Podgate::start().await;
    let (up, auth) = (echo().await, auth().await);
    let site_with = |extra: Value| site("a", "a.test", up.addr, auth.addr, &extra);
    let with_budget = |version: u64, bytes: u64, app: Value| {
        let mut pushed = snapshot(version, &[app]);
        pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(bytes);
        pushed
    };

    // 64 KiB of body plus the 48 KiB allowance never fits 100 KiB.
    let refused = podgate
        .push_snapshot(&with_budget(1, 100 * 1024, site_with(Value::Null)))
        .await;
    let entry = rejection(&refused);
    assert_eq!(entry["code"], "invalid_middleware", "{entry}");
    assert_eq!(entry["needed_bytes"], 64 * 1024 + 48 * 1024, "{entry}");
    assert_eq!(entry["max_buffer_bytes"], 100 * 1024, "{entry}");
    assert_eq!(entry["tenant"], "t1", "{entry}");

    // Exactly the budget fits; one byte less does not.
    let needed = 8192 + 48 * 1024;
    push(
        &podgate,
        &with_budget(2, needed, site_with(json!({"max_response_bytes": 8192}))),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/ok").await.status, 200);
    let refused = podgate
        .push_snapshot(&with_budget(
            3,
            needed - 1,
            site_with(json!({"max_response_bytes": 8192})),
        ))
        .await;
    assert_eq!(rejection(&refused)["code"], "invalid_middleware");
}

#[tokio::test]
async fn plan_lists_forward_auth_removal() {
    let podgate = Podgate::start().await;
    let (up, auth) = (echo().await, auth().await);
    let guarded = |names: &[&str]| {
        site(
            "a",
            "a.test",
            up.addr,
            auth.addr,
            &json!({"response_headers": names}),
        )
    };
    push(&podgate, &snapshot(1, &[guarded(&["x-user", "x-groups"])])).await;

    let removed = snapshot(2, &[app("a", &["a.test"], &[serving("r1", up.addr)])]);
    let plan = podgate.admin_post("/v1/snapshot/plan", &removed).await;
    assert_eq!(plan.status, 200, "{}", plan.body);
    assert_eq!(
        plan.json()["posture_changes"],
        json!([{ "host": "a.test", "app": "a", "kind": "forward_auth_removed" }])
    );

    let fewer = snapshot(2, &[guarded(&["x-user"])]);
    let plan = podgate.admin_post("/v1/snapshot/plan", &fewer).await;
    assert_eq!(
        plan.json()["posture_changes"],
        json!([{ "host": "a.test", "app": "a", "kind": "forward_auth_response_headers_removed" }])
    );

    let more = snapshot(2, &[guarded(&["x-user", "x-groups", "x-org"])]);
    let plan = podgate.admin_post("/v1/snapshot/plan", &more).await;
    assert_eq!(plan.json()["posture_changes"], json!([]), "{}", plan.body);
    // Nothing was applied.
    assert_eq!(podgate.get("a.test", "/ok").await.status, 200);
}

#[tokio::test]
async fn forward_auth_runs_before_cache_hit() {
    let podgate = Podgate::start().await;
    let up = Server::start(|_| http(200, &[("Cache-Control", "max-age=60")], "cached page")).await;
    // The auth service allows the first call and denies every later one.
    let calls = Arc::new(AtomicUsize::new(0));
    let auth = Server::start(move |_| {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            http(200, &[], "")
        } else {
            http(401, &[("WWW-Authenticate", "Bearer")], "revoked")
        }
    })
    .await;
    let guarded = with_middleware(
        app("a", &["a.test"], &[serving("r1", up.addr)]),
        "auth",
        "forward_auth",
        json!({"address": format!("http://{}/verify", auth.addr)}),
    );
    let app = with_middleware(guarded, "c", "cache", json!({}));
    push(&podgate, &snapshot(1, &[app])).await;

    let filled = podgate.get("a.test", "/page").await;
    assert_eq!((filled.status, filled.body.as_str()), (200, "cached page"));
    assert_eq!(up.requests(), 1);
    // The entry is stored and fresh, yet the next request is judged by the auth service first.
    let denied = podgate.get("a.test", "/page").await;
    assert_eq!(
        (denied.status, denied.body.as_str()),
        (401, "revoked"),
        "{denied:?}"
    );
    assert_eq!(auth.requests(), 2);
    assert_eq!(
        up.requests(),
        1,
        "neither request reached the upstream twice"
    );
}

#[tokio::test]
async fn forward_auth_identity_bypasses_cache() {
    let podgate = Podgate::start().await;
    // The page depends on who is asking and says it may be shared.
    let up = Server::start(|head| {
        let user = header_of(head, "x-user").unwrap_or("anonymous");
        http(
            200,
            &[("Cache-Control", "public, max-age=60")],
            &format!("page for {user}"),
        )
    })
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let auth = Server::start(move |_| {
        let user = if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            "a"
        } else {
            "b"
        };
        http(200, &[("X-User", user)], "")
    })
    .await;
    let guarded = with_middleware(
        app("a", &["a.test"], &[serving("r1", up.addr)]),
        "auth",
        "forward_auth",
        json!({"address": format!("http://{}/verify", auth.addr), "response_headers": ["x-user"]}),
    );
    let app = with_middleware(guarded, "c", "cache", json!({}));
    push(&podgate, &snapshot(1, &[app])).await;

    let first = podgate.get("a.test", "/page").await;
    assert_eq!((first.status, first.body.as_str()), (200, "page for a"));
    assert_eq!(
        first.header("cache-status"),
        Some("podgate; bypass"),
        "{first:?}"
    );
    let second = podgate.get("a.test", "/page").await;
    assert_eq!(
        (second.status, second.body.as_str()),
        (200, "page for b"),
        "{second:?}"
    );
    assert_eq!(
        second.header("cache-status"),
        Some("podgate; bypass"),
        "{second:?}"
    );
    assert_eq!(up.requests(), 2, "both requests reached the upstream");
}
