//! Upstream HTTP/2 and timeouts: a service reaches `h2c://` servers by prior
//! knowledge and `https://` servers by ALPN, and its `servers_transport` bounds the dial, the
//! response and the idle pool.
//!
//! The test upstream serves HTTP/1.1 and HTTP/2 on one port. Over TCP it tells the two apart by
//! the HTTP/2 preface, over TLS by the negotiated ALPN protocol. Every response carries
//! `x-proto` (`h2` or `http/1.1`) and `x-conn` (the number of the connection it came on), and
//! the [`Stats`] count connections, streams in flight and requests.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{Podgate, app, router, snapshot};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::PrivateKeyDer;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

/// What the test upstream counted.
#[derive(Default)]
struct Stats {
    connections: AtomicU64,
    h2_connections: AtomicU64,
    closed: AtomicU64,
    streams_now: AtomicU64,
    streams_peak: AtomicU64,
    status: AtomicU16,
    /// `(protocol, path)` of every request, in arrival order.
    requests: Mutex<Vec<(&'static str, String)>>,
}

impl Stats {
    fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    fn closed(&self) -> u64 {
        self.closed.load(Ordering::Relaxed)
    }

    fn requests(&self) -> Vec<(&'static str, String)> {
        self.requests.lock().expect("requests").clone()
    }

    fn record(&self, protocol: &'static str, path: &str) {
        self.requests
            .lock()
            .expect("requests")
            .push((protocol, path.to_owned()));
    }

    fn stream_started(&self) {
        let now = self.streams_now.fetch_add(1, Ordering::Relaxed) + 1;
        self.streams_peak.fetch_max(now, Ordering::Relaxed);
    }

    fn stream_ended(&self) {
        self.streams_now.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A private certificate authority.
struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    pem: String,
}

impl Ca {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("CA key"))
            .expect("self-signed CA");
        let pem = issuer.pem();
        Self { issuer, pem }
    }

    /// An acceptor for 127.0.0.1 that offers `alpn`.
    fn acceptor(&self, alpn: &[&[u8]]) -> TlsAcceptor {
        let key = KeyPair::generate().expect("leaf key");
        let params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("leaf params");
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        let key = PrivateKeyDer::try_from(key.serialize_der()).expect("key");
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .expect("server config");
        config.alpn_protocols = alpn.iter().map(|proto| proto.to_vec()).collect();
        TlsAcceptor::from(Arc::new(config))
    }
}

/// How a connection arrives.
#[derive(Clone)]
enum Wire {
    Plain,
    Tls(TlsAcceptor),
}

struct Backend {
    addr: SocketAddr,
    stats: Arc<Stats>,
}

impl Backend {
    /// Serves every request after `delay`.
    async fn start(wire: Wire, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let stats = Arc::new(Stats::default());
        stats.status.store(200, Ordering::Relaxed);
        let shared = Arc::clone(&stats);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let number = shared.connections.fetch_add(1, Ordering::Relaxed) + 1;
                tokio::spawn(connection(
                    wire.clone(),
                    tcp,
                    number,
                    Arc::clone(&shared),
                    delay,
                ));
            }
        });
        Self { addr, stats }
    }

    async fn plain(delay: Duration) -> Self {
        Self::start(Wire::Plain, delay).await
    }

    fn set_status(&self, status: u16) {
        self.stats.status.store(status, Ordering::Relaxed);
    }
}

async fn connection(wire: Wire, tcp: TcpStream, number: u64, stats: Arc<Stats>, delay: Duration) {
    match wire {
        Wire::Plain => {
            let mut preface = [0_u8; 4];
            loop {
                match tcp.peek(&mut preface).await {
                    Ok(4) => break,
                    Ok(0) | Err(_) => return,
                    Ok(_) => sleep(Duration::from_millis(5)).await,
                }
            }
            if &preface == b"PRI " {
                serve_h2(tcp, number, stats, delay).await;
            } else {
                serve_h1(tcp, number, stats, delay).await;
            }
        }
        Wire::Tls(acceptor) => {
            let Ok(stream) = acceptor.accept(tcp).await else {
                return;
            };
            if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                serve_h2(stream, number, stats, delay).await;
            } else {
                serve_h1(stream, number, stats, delay).await;
            }
        }
    }
}

async fn serve_h1<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    number: u64,
    stats: Arc<Stats>,
    delay: Duration,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            seen.drain(..end + 4);
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split(' ').nth(1))
                .unwrap_or("?")
                .to_owned();
            stats.record("http/1.1", &path);
            sleep(delay).await;
            let status = stats.status.load(Ordering::Relaxed);
            let response = format!(
                "HTTP/1.1 {status} Status\r\nContent-Length: 2\r\nx-proto: http/1.1\r\n\
                 x-conn: {number}\r\n\r\nok"
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                stats.closed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => {
                stats.closed.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    number: u64,
    stats: Arc<Stats>,
    delay: Duration,
) {
    stats.h2_connections.fetch_add(1, Ordering::Relaxed);
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        let stats = Arc::clone(&stats);
        stats.record("h2", request.uri().path());
        stats.stream_started();
        tokio::spawn(async move {
            sleep(delay).await;
            let status = stats.status.load(Ordering::Relaxed);
            let response = http::Response::builder()
                .status(status)
                .header("content-length", "2")
                .header("x-proto", "h2")
                .header("x-conn", number.to_string())
                .body(())
                .expect("response");
            if let Ok(mut send) = respond.send_response(response, false) {
                drop(send.send_data(Bytes::from_static(b"ok"), true));
            }
            stats.stream_ended();
        });
    }
    stats.closed.fetch_add(1, Ordering::Relaxed);
}

/// A revision whose service `web` has `servers` (URLs) and names `transport` when given.
fn revision(servers: &[String], transport: Option<&str>) -> Value {
    json!({ "id": "r1", "state": "serving", "weight": 100, "services": [service("web", servers, transport)] })
}

fn service(name: &str, servers: &[String], transport: Option<&str>) -> Value {
    let servers: Vec<Value> = servers.iter().map(|url| json!({ "url": url })).collect();
    let mut service = json!({ "name": name, "type": "loadbalancer", "servers": servers });
    if let Some(transport) = transport {
        service["transport"] = json!(transport);
    }
    service
}

fn transport(name: &str, fields: &Value) -> Value {
    let mut declared = json!({ "name": name, "type": "servers_transport" });
    if let (Some(object), Some(extra)) = (declared.as_object_mut(), fields.as_object()) {
        object.extend(extra.clone());
    }
    declared
}

/// App `a` on `a.test`: service `web` over `servers`, through transport `t` when `fields` is set.
fn one_service(servers: &[String], fields: Option<&Value>) -> Value {
    let mut app = app("a", &["a.test"], &[revision(servers, fields.map(|_| "t"))]);
    if let Some(fields) = fields {
        app["transports"] = json!([transport("t", fields)]);
    }
    app
}

async fn push(podgate: &Podgate, version: u64, app: Value) {
    let response = podgate.push_snapshot(&snapshot(version, &[app])).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

async fn rejection(podgate: &Podgate, app: Value) -> (u16, String) {
    let response = podgate.push_snapshot(&snapshot(1000, &[app])).await;
    let conflicts = &response.json()["conflicts"];
    (
        response.status,
        conflicts[0]["code"].as_str().unwrap_or_default().to_owned(),
    )
}

fn h2c(backend: &Backend) -> String {
    format!("h2c://{}", backend.addr)
}

fn http(backend: &Backend) -> String {
    format!("http://{}", backend.addr)
}

fn https(backend: &Backend) -> String {
    format!("https://{}", backend.addr)
}

#[tokio::test]
async fn h2c_upstream_served() {
    let backend = Backend::plain(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    push(&podgate, 1, one_service(&[h2c(&backend)], None)).await;

    let response = podgate.get("a.test", "/hello").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "ok");
    assert_eq!(response.header("x-proto"), Some("h2"));
    assert_eq!(backend.stats.requests(), [("h2", "/hello".to_owned())]);
}

#[tokio::test]
async fn h2_alpn_upstream_served() {
    let ca = Ca::new();
    let backend = Backend::start(
        Wire::Tls(ca.acceptor(&[b"h2", b"http/1.1"])),
        Duration::ZERO,
    )
    .await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        one_service(&[https(&backend)], Some(&json!({ "ca_pem": ca.pem }))),
    )
    .await;

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.header("x-proto"), Some("h2"), "http2 defaults on");

    // A server that offers only http/1.1 is spoken to in HTTP/1.1.
    let old = Backend::start(Wire::Tls(ca.acceptor(&[b"http/1.1"])), Duration::ZERO).await;
    push(
        &podgate,
        2,
        one_service(&[https(&old)], Some(&json!({ "ca_pem": ca.pem }))),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.header("x-proto"), Some("http/1.1"));
}

#[tokio::test]
async fn http2_false_forces_http1() {
    let ca = Ca::new();
    let backend = Backend::start(
        Wire::Tls(ca.acceptor(&[b"h2", b"http/1.1"])),
        Duration::ZERO,
    )
    .await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        one_service(
            &[https(&backend)],
            Some(&json!({ "ca_pem": ca.pem, "http2": false })),
        ),
    )
    .await;

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.header("x-proto"), Some("http/1.1"));
    assert_eq!(backend.stats.h2_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn plain_http_server_is_never_spoken_h2_to() {
    let backend = Backend::plain(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    push(&podgate, 1, one_service(&[http(&backend)], None)).await;

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.header("x-proto"), Some("http/1.1"));
    assert_eq!(backend.stats.h2_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn an_upgrade_request_asks_a_tls_server_for_http1() {
    let ca = Ca::new();
    let backend = Backend::start(
        Wire::Tls(ca.acceptor(&[b"h2", b"http/1.1"])),
        Duration::ZERO,
    )
    .await;
    let podgate = Arc::new(Podgate::start().await);
    push(
        &podgate,
        1,
        one_service(&[https(&backend)], Some(&json!({ "ca_pem": ca.pem }))),
    )
    .await;

    // The test upstream answers 200, not 101, so the exchange never ends: watch what arrives.
    let asking = Arc::clone(&podgate);
    let upgrade = tokio::spawn(async move {
        asking
            .get_with_headers(
                "a.test",
                "/socket",
                &[("Connection", "Upgrade"), ("Upgrade", "websocket")],
            )
            .await
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while backend.stats.requests().is_empty() {
        assert!(Instant::now() < deadline, "the request never arrived");
        sleep(Duration::from_millis(20)).await;
    }
    upgrade.abort();
    assert_eq!(
        backend.stats.requests(),
        [("http/1.1", "/socket".to_owned())],
        "Pingora's HTTP/2 client has no Upgrade"
    );
    assert_eq!(backend.stats.h2_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn h2_multiplexes_on_few_connections() {
    let backend = Backend::plain(Duration::from_secs(1)).await;
    let podgate = Arc::new(Podgate::start().await);
    push(&podgate, 1, one_service(&[h2c(&backend)], None)).await;

    // Pingora takes a pooled connection out of its pool while it opens a stream on it, and a
    // request that arrives in that window finds none and dials its own
    // (pingora-core `connectors/http/v2.rs`, `reused_http_session`). A fixed spacing only makes
    // the window unlikely to be hit; a descheduled thread under load hits it. So each request
    // starts after the upstream has the previous one: that stream is open and its connection is
    // back in the pool, and the first request's dial is the only one. All twenty stay in
    // flight at once because the upstream holds each for a second.
    let mut burst = JoinSet::new();
    for number in 0..20 {
        let podgate = Arc::clone(&podgate);
        burst.spawn(async move { podgate.get("a.test", &format!("/{number}")).await.status });
        let deadline = Instant::now() + Duration::from_secs(10);
        while backend.stats.requests().len() <= number {
            assert!(Instant::now() < deadline, "request {number} never arrived");
            sleep(Duration::from_millis(1)).await;
        }
    }
    while let Some(status) = burst.join_next().await {
        assert_eq!(status.expect("request"), 200);
    }
    assert!(
        backend.stats.connections() <= 2,
        "20 requests used {} connections",
        backend.stats.connections()
    );
    assert!(
        backend.stats.streams_peak.load(Ordering::Relaxed) >= 10,
        "the requests were in flight together: peak {}",
        backend.stats.streams_peak.load(Ordering::Relaxed)
    );
}

/// A listener whose accept queue is full: a connect to it hangs without being refused. The
/// held connections keep the queue full.
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

#[tokio::test]
async fn dial_timeout_504() {
    let (addr, _listener, _held) = blackhole().await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        one_service(
            &[format!("http://{addr}")],
            Some(&json!({ "dial_timeout_secs": 1 })),
        ),
    )
    .await;

    let started = Instant::now();
    let response = podgate.get("a.test", "/").await;
    let took = started.elapsed();
    assert_eq!(response.status, 504, "{response:?}");
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(5),
        "answered after {took:?}"
    );
}

#[tokio::test]
async fn read_timeout_504() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    // Accepts and never answers.
    let silent = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        one_service(
            &[format!("http://{addr}")],
            Some(&json!({ "read_timeout_secs": 1 })),
        ),
    )
    .await;

    let started = Instant::now();
    let response = podgate.get("a.test", "/").await;
    let took = started.elapsed();
    assert_eq!(response.status, 504, "{response:?}");
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(5),
        "answered after {took:?}"
    );
    silent.abort();

    // The same over HTTP/2.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let silent = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    push(
        &podgate,
        2,
        one_service(
            &[format!("h2c://{addr}")],
            Some(&json!({ "read_timeout_secs": 1 })),
        ),
    )
    .await;
    let started = Instant::now();
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 504, "{response:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    silent.abort();
}

#[tokio::test]
async fn idle_timeout_closes_pooled_connection() {
    let (short, long) = (
        Backend::plain(Duration::ZERO).await,
        Backend::plain(Duration::ZERO).await,
    );
    let podgate = Podgate::start().await;
    let mut both = app(
        "a",
        &["short.test", "long.test"],
        &[
            json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
            service("short", &[http(&short)], Some("quick")),
            service("long", &[http(&long)], None),
        ] }),
        ],
    );
    both["routers"] = json!([
        router("short", json!({ "host": ["short.test"] }), "short"),
        router("long", json!({ "host": ["long.test"] }), "long"),
    ]);
    both["transports"] = json!([transport("quick", &json!({ "idle_timeout_secs": 1 }))]);
    push(&podgate, 1, both).await;

    assert_eq!(podgate.get("short.test", "/").await.status, 200);
    assert_eq!(podgate.get("long.test", "/").await.status, 200);
    assert_eq!(
        (short.stats.closed(), long.stats.closed()),
        (0, 0),
        "both connections are pooled"
    );
    sleep(Duration::from_millis(2500)).await;
    assert_eq!(short.stats.closed(), 1, "the idle timeout closed it");
    assert_eq!(long.stats.closed(), 0, "no idle timeout: still pooled");

    assert_eq!(podgate.get("short.test", "/").await.status, 200);
    assert_eq!(short.stats.connections(), 2, "a new connection was needed");
    assert_eq!(podgate.get("long.test", "/").await.status, 200);
    assert_eq!(long.stats.connections(), 1, "the pooled one was reused");
}

#[tokio::test]
async fn max_idle_per_host_enforced_or_unsupported() {
    let backend = Backend::plain(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    let app = one_service(&[http(&backend)], Some(&json!({ "max_idle_per_host": 2 })));
    let response = podgate.push_snapshot(&snapshot(1, &[app])).await;
    assert_eq!(response.status, 422, "{response:?}");
    let conflict = &response.json()["conflicts"][0];
    assert_eq!(conflict["code"], "unsupported_setting");
    assert!(
        conflict["message"]
            .as_str()
            .is_some_and(|message| message.contains("UPSTREAM_POOL_SIZE")),
        "{conflict}"
    );

    // The process setting that replaces it starts the proxy and serves.
    let sized = Podgate::start_with_env(&[("UPSTREAM_POOL_SIZE", "4")]).await;
    push(&sized, 1, one_service(&[http(&backend)], None)).await;
    assert_eq!(sized.get("a.test", "/").await.status, 200);
}

#[tokio::test]
async fn h2c_with_tls_fields_rejected() {
    let backend = Backend::plain(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    let h2c_server = [h2c(&backend)];
    for fields in [
        json!({ "server_name": "backend.test" }),
        json!({ "insecure_skip_verify": true }),
        json!({ "http2": false }),
    ] {
        let rejected = rejection(&podgate, one_service(&h2c_server, Some(&fields))).await;
        assert_eq!(rejected, (422, "invalid_transport".to_owned()), "{fields}");
    }
    // Timeouts are fine with h2c, and so is the bare scheme.
    push(
        &podgate,
        1,
        one_service(&h2c_server, Some(&json!({ "dial_timeout_secs": 3 }))),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);

    // The health probe speaks HTTP/1.1: it is refused rather than left to fail.
    let mut probed = one_service(&h2c_server, None);
    probed["revisions"][0]["services"][0]["health_check"] =
        json!({ "path": "/healthz", "interval_secs": 1, "timeout_secs": 1 });
    assert_eq!(
        rejection(&podgate, probed).await,
        (422, "service_not_built".to_owned())
    );

    // One address has one scheme.
    let both = [h2c(&backend), http(&backend)];
    assert_eq!(
        rejection(&podgate, one_service(&both, None)).await,
        (422, "invalid_service".to_owned())
    );
}

#[tokio::test]
async fn timeouts_are_checked_when_the_snapshot_is_compiled() {
    let backend = Backend::plain(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    for fields in [
        json!({ "dial_timeout_secs": 0 }),
        json!({ "read_timeout_secs": 3601 }),
        json!({ "write_timeout_secs": -1 }),
        json!({ "idle_timeout_secs": "soon" }),
        json!({ "http2": "yes" }),
    ] {
        let rejected = rejection(&podgate, one_service(&[http(&backend)], Some(&fields))).await;
        assert_eq!(rejected, (422, "invalid_transport".to_owned()), "{fields}");
    }
}

#[tokio::test]
async fn pooled_connections_are_never_shared_across_transports() {
    let ca = Ca::new();
    let backend = Backend::start(
        Wire::Tls(ca.acceptor(&[b"h2", b"http/1.1"])),
        Duration::ZERO,
    )
    .await;
    let url = https(&backend);
    let podgate = Podgate::start().await;
    let mut shared = app(
        "a",
        &["a.test", "b.test", "c.test", "d.test"],
        &[
            json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
            service("sa", std::slice::from_ref(&url), Some("plain")),
            service("sb", std::slice::from_ref(&url), Some("h1")),
            service("sc", std::slice::from_ref(&url), Some("slow")),
            service("sd", std::slice::from_ref(&url), Some("plain")),
        ] }),
        ],
    );
    shared["routers"] = json!([
        router("a", json!({ "host": ["a.test"] }), "sa"),
        router("b", json!({ "host": ["b.test"] }), "sb"),
        router("c", json!({ "host": ["c.test"] }), "sc"),
        router("d", json!({ "host": ["d.test"] }), "sd"),
    ]);
    shared["transports"] = json!([
        transport("plain", &json!({ "ca_pem": ca.pem })),
        transport("h1", &json!({ "ca_pem": ca.pem, "http2": false })),
        transport(
            "slow",
            &json!({ "ca_pem": ca.pem, "read_timeout_secs": 45 })
        ),
    ]);
    push(&podgate, 1, shared).await;

    let conn = |response: common::Response| {
        (
            response.header("x-proto").map(str::to_owned),
            response.header("x-conn").map(str::to_owned),
        )
    };
    let a = conn(podgate.get("a.test", "/").await);
    sleep(Duration::from_millis(150)).await;
    assert_eq!(a, (Some("h2".into()), Some("1".into())));
    // Another HTTP version, and another timeout, each get a connection of their own.
    let b = conn(podgate.get("b.test", "/").await);
    assert_eq!(b, (Some("http/1.1".into()), Some("2".into())));
    let c = conn(podgate.get("c.test", "/").await);
    assert_eq!(c, (Some("h2".into()), Some("3".into())));
    // Two services with the same transport share theirs.
    let d = conn(podgate.get("d.test", "/").await);
    assert_eq!(d, (Some("h2".into()), Some("1".into())));
    assert_eq!(backend.stats.connections(), 3);
}

#[tokio::test]
async fn health_probe_keeps_speaking_http1_to_an_h2_server() {
    let ca = Ca::new();
    let backend = Backend::start(
        Wire::Tls(ca.acceptor(&[b"h2", b"http/1.1"])),
        Duration::ZERO,
    )
    .await;
    let podgate = Podgate::start().await;
    let mut probed = one_service(&[https(&backend)], Some(&json!({ "ca_pem": ca.pem })));
    probed["revisions"][0]["services"][0]["health_check"] =
        json!({ "path": "/healthz", "interval_secs": 1, "timeout_secs": 2 });
    push(&podgate, 1, probed).await;

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let probes: Vec<_> = backend
            .stats
            .requests()
            .into_iter()
            .filter(|(_, path)| path == "/healthz")
            .collect();
        if !probes.is_empty() {
            assert!(
                probes.iter().all(|(proto, _)| *proto == "http/1.1"),
                "{probes:?}"
            );
            break;
        }
        assert!(Instant::now() < deadline, "the server was never probed");
        sleep(Duration::from_millis(100)).await;
    }
    let response = podgate.get("a.test", "/real").await;
    assert_eq!(response.status, 200, "healthy: {response:?}");
    assert_eq!(response.header("x-proto"), Some("h2"), "traffic uses h2");
}

#[tokio::test]
async fn failure_replay_stays_http1_and_refuses_an_h2c_server() {
    let ca = Ca::new();
    let backend = Backend::start(
        Wire::Tls(ca.acceptor(&[b"h2", b"http/1.1"])),
        Duration::ZERO,
    )
    .await;
    backend.set_status(500);
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        one_service(&[https(&backend)], Some(&json!({ "ca_pem": ca.pem }))),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/thing").await.status, 500);

    let listed = podgate.admin_get("/v1/apps/a/failures").await;
    assert_eq!(listed.status, 200, "{listed:?}");
    let id = listed.json()["failures"][0]["id"].as_u64().expect("id");
    let replay = format!("/v1/apps/a/failures/{id}/replay?revision=r1");
    backend.set_status(200);
    let replayed = podgate.admin_post(&replay, &json!({})).await;
    assert_eq!(replayed.status, 200, "{replayed:?}");
    assert_eq!(replayed.json()["status"], 200);
    assert_eq!(replayed.json()["body"], "ok");
    assert_eq!(
        backend.stats.requests(),
        [
            ("h2", "/thing".to_owned()),
            ("http/1.1", "/thing".to_owned())
        ],
        "the proxied request used h2, the hand-written replay HTTP/1.1"
    );

    // The replay cannot speak to an h2c server, and says so.
    let flaky = Backend::plain(Duration::ZERO).await;
    flaky.set_status(500);
    push(&podgate, 2, one_service(&[h2c(&flaky)], None)).await;
    assert_eq!(podgate.get("a.test", "/thing").await.status, 500);
    let listed = podgate.admin_get("/v1/apps/a/failures").await;
    let id = listed.json()["failures"][0]["id"].as_u64().expect("id");
    let refused = podgate
        .admin_post(
            &format!("/v1/apps/a/failures/{id}/replay?revision=r1"),
            &json!({}),
        )
        .await;
    assert_eq!(refused.status, 409, "{refused:?}");
}

/// App `a` whose service `web` is the plain `main` backend and service `pages` is `pages`, with
/// an `errors` middleware for 404 that fetches from `pages`.
fn error_pages_app(main: &Backend, pages: &[String], transport: Option<&Value>) -> Value {
    let mut app = common::with_chain(
        app(
            "a",
            &["a.test"],
            &[
                json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
                service("web", &[http(main)], None),
                service("pages", pages, transport.map(|_| "t")),
            ] }),
            ],
        ),
        &[common::middleware(
            "pages",
            "errors",
            json!({ "status": ["404"], "service": "pages" }),
        )],
    );
    if let Some(fields) = transport {
        app["transports"] = json!([self::transport("t", fields)]);
    }
    app
}

#[tokio::test]
async fn error_page_fetch_keeps_speaking_http1_to_an_h2_server() {
    let ca = Ca::new();
    let pages = Backend::start(
        Wire::Tls(ca.acceptor(&[b"h2", b"http/1.1"])),
        Duration::ZERO,
    )
    .await;
    let main = Backend::plain(Duration::ZERO).await;
    main.set_status(404);
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        error_pages_app(&main, &[https(&pages)], Some(&json!({ "ca_pem": ca.pem }))),
    )
    .await;

    let response = podgate.get("a.test", "/missing").await;
    assert_eq!(response.status, 404, "{response:?}");
    assert_eq!(response.body, "ok", "the page replaced the answer");
    assert_eq!(
        pages.stats.requests(),
        [("http/1.1", "/404.html".to_owned())]
    );
}

#[tokio::test]
async fn errors_middleware_refuses_an_h2c_page_server() {
    let pages = Backend::plain(Duration::ZERO).await;
    let main = Backend::plain(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    let rejected = rejection(&podgate, error_pages_app(&main, &[h2c(&pages)], None)).await;
    assert_eq!(rejected, (422, "invalid_middleware".to_owned()));
    // The same service over http:// is fine.
    push(&podgate, 2, error_pages_app(&main, &[http(&pages)], None)).await;
}

#[tokio::test]
async fn an_upstream_timeout_is_a_504_that_the_errors_middleware_can_replace() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let silent_addr = listener.local_addr().expect("addr");
    let silent = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let pages = Backend::plain(Duration::ZERO).await;
    let mut slow = common::with_chain(
        app(
            "a",
            &["a.test"],
            &[
                json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
                service("web", &[format!("http://{silent_addr}")], Some("t")),
                service("pages", &[http(&pages)], None),
            ] }),
            ],
        ),
        &[common::middleware(
            "pages",
            "errors",
            json!({ "status": ["504"], "service": "pages" }),
        )],
    );
    slow["transports"] = json!([transport("t", &json!({ "read_timeout_secs": 1 }))]);
    let podgate = Podgate::start().await;
    push(&podgate, 1, slow).await;

    let response = podgate.get("a.test", "/slow").await;
    assert_eq!(response.status, 504, "{response:?}");
    assert_eq!(response.body, "ok", "the page for 504 replaced the answer");
    assert_eq!(
        pages.stats.requests(),
        [("http/1.1", "/504.html".to_owned())]
    );
    silent.abort();
}
