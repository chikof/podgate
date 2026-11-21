//! Health checks of TCP services through the real binary: a server that fails its
//! probe stops taking connections and starts again when it passes, `send` and `expect`, the TLS
//! probe, the port override and the PROXY header, the bounds of a probe, the state across pushes,
//! the refusal when every server is down and the compile rules.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Podgate, app, snapshot};
use podgate::l4::health::{Check, TcpProbe};
use podgate::service::health::{HttpProbe, Verdict};
use podgate::service::upstream_policy::UpstreamPolicy;
use podgate::service::{Server, Transport, Upstream};
use podgate_model::Declared;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

const ENTRY_POINTS: [(&str, &str); 3] = [("web", "http"), ("pg", "tcp"), ("dns", "udp")];
const WAIT: Duration = Duration::from_secs(5);
/// What a probe waits for before a test gives up on seeing its effect: a probe runs every second
/// and a flip needs one or two of them.
const EVENTUALLY: Duration = Duration::from_secs(20);
/// The service every test declares, and the app that owns it.
const UP: &str = "podgate_l4_service_servers{app=\"t\",service=\"svc\",state=\"up\"}";
const DOWN: &str = "podgate_l4_service_servers{app=\"t\",service=\"svc\",state=\"down\"}";
const NO_HEALTHY: &str = "podgate_l4_refused_total{reason=\"no_healthy_server\"}";

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// A TCP server on a loopback port.
struct Backend {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    /// The first bytes each connection sent, as the server read them.
    first: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Backend {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn sent(&self, bytes: &[u8]) -> usize {
        self.first
            .lock()
            .expect("lock")
            .iter()
            .filter(|chunk| chunk.starts_with(bytes))
            .count()
    }
}

/// Runs `handle` for each connection `listener` accepts; `handle` gets the stream and the list of
/// first chunks to record into.
fn spawn_backend<F, Fut>(listener: TcpListener, handle: F) -> Backend
where
    F: Fn(TcpStream, Arc<Mutex<Vec<Vec<u8>>>>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let addr = listener.local_addr().expect("server addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let first = Arc::new(Mutex::new(Vec::new()));
    let (count, seen) = (Arc::clone(&accepted), Arc::clone(&first));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(handle(stream, Arc::clone(&seen)));
        }
    });
    Backend {
        addr,
        accepted,
        first,
    }
}

async fn serve<F, Fut>(handle: F) -> Backend
where
    F: Fn(TcpStream, Arc<Mutex<Vec<Vec<u8>>>>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    spawn_backend(
        TcpListener::bind("127.0.0.1:0").await.expect("bind server"),
        handle,
    )
}

/// How a controllable server answers its probe.
const GOOD: u8 = 0;
const BAD: u8 = 1;

struct Mode(AtomicU8);

impl Mode {
    fn new(initial: u8) -> Arc<Self> {
        Arc::new(Self(AtomicU8::new(initial)))
    }

    fn set(&self, mode: u8) {
        self.0.store(mode, Ordering::SeqCst);
    }

    fn good(&self) -> bool {
        self.0.load(Ordering::SeqCst) == GOOD
    }
}

/// Reads what a connection sends first: whatever arrives within two seconds.
async fn first_chunk(stream: &mut TcpStream, seen: &Mutex<Vec<Vec<u8>>>) -> Vec<u8> {
    let mut buf = [0_u8; 64];
    let read = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(read)) => read,
        _ => 0,
    };
    let chunk = buf[..read].to_vec();
    seen.lock().expect("lock").push(chunk.clone());
    chunk
}

/// A server that answers `PING\n` with `PONG\n` while `mode` is good and with `NOPE\n` otherwise,
/// and anything else (a client of the proxy) with `tag\n`.
async fn ping_server(tag: &'static str, mode: Arc<Mode>) -> Backend {
    serve(move |mut stream, seen| {
        let mode = Arc::clone(&mode);
        async move {
            let chunk = first_chunk(&mut stream, &seen).await;
            let reply = if chunk.starts_with(b"PING") {
                if mode.good() { "PONG\n" } else { "NOPE\n" }.to_owned()
            } else {
                format!("{tag}\n")
            };
            drop(stream.write_all(reply.as_bytes()).await);
        }
    })
    .await
}

/// A server that speaks first: `220 tag` while `mode` is good, `421 tag` otherwise. A client of the
/// proxy sees the same banner.
async fn banner_server(tag: &'static str, mode: Arc<Mode>) -> Backend {
    serve(move |mut stream, _| {
        let mode = Arc::clone(&mode);
        async move {
            let code = if mode.good() { 220 } else { 421 };
            if stream
                .write_all(format!("{code} {tag}\r\n").as_bytes())
                .await
                .is_err()
            {
                return;
            }
            let mut buf = [0_u8; 64];
            while matches!(stream.read(&mut buf).await, Ok(read) if read > 0) {}
        }
    })
    .await
}

/// A server on `listener` that greets with `tag\n` and holds the connection until the client
/// closes.
fn greet_on(listener: TcpListener, tag: &'static str) -> Backend {
    spawn_backend(listener, move |mut stream, _| async move {
        if stream
            .write_all(format!("{tag}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
        let mut buf = [0_u8; 64];
        while matches!(stream.read(&mut buf).await, Ok(read) if read > 0) {}
    })
}

async fn greeter(tag: &'static str) -> Backend {
    greet_on(
        TcpListener::bind("127.0.0.1:0").await.expect("bind server"),
        tag,
    )
}

/// An app of tenant `t1` with the TCP service `svc`, which has `health_check` (absent: none).
fn tcp_app(servers: &[SocketAddr], health_check: Option<Value>) -> Value {
    let mut app = app("t", &["t.test"], &[]);
    app["routers"] = json!([]);
    let servers: Vec<Value> = servers
        .iter()
        .map(|addr| json!({ "address": addr.to_string() }))
        .collect();
    let mut service = json!({ "name": "svc", "type": "loadbalancer", "servers": servers });
    if let Some(check) = health_check {
        service["health_check"] = check;
    }
    app["tcp"] = json!({
        "routers": [{ "name": "r", "entry_points": ["pg"], "service": "svc" }],
        "services": [service],
    });
    app
}

/// A snapshot of tenant `t1` that reserves the `pg` and `dns` entry points to it.
fn reserved(version: u64, apps: &[Value]) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["entry_points"] =
        json!([{ "name": "pg", "tenants": ["t1"] }, { "name": "dns", "tenants": ["t1"] }]);
    pushed
}

/// `{interval_secs: 1, timeout_secs: 1}` with `extra` fields.
fn check(extra: &Value) -> Value {
    let mut value = json!({ "interval_secs": 1, "timeout_secs": 1 });
    if let (Some(base), Some(more)) = (value.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    value
}

async fn start() -> Podgate {
    Podgate::start_with_entry_points(&ENTRY_POINTS, &[]).await
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// The first line a server sends back through the entry point after the client wrote `hello\n`;
/// `None` when podgate closed the connection without a byte.
async fn ask(podgate: &Podgate) -> Option<String> {
    let mut stream = timeout(WAIT, TcpStream::connect(podgate.entry_addr("pg")))
        .await
        .expect("connect in time")
        .expect("connect to the tcp entry point");
    drop(stream.write_all(b"hello\n").await);
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match timeout(WAIT, stream.read(&mut byte)).await {
            Ok(Ok(1)) if byte[0] == b'\n' => break,
            Ok(Ok(1)) => line.push(byte[0]),
            Ok(Ok(0) | Err(_)) => break,
            other => panic!("no answer, got {other:?}"),
        }
    }
    (!line.is_empty()).then(|| String::from_utf8_lossy(&line).trim_end().to_owned())
}

/// The value of the sample `series` (a name with its labels) in the metrics of `podgate`.
async fn metric(podgate: &Podgate, series: &str) -> u64 {
    let body = podgate.admin_get("/metrics").await.body;
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("no sample {series} in:\n{body}"))
}

/// Waits until `condition` holds, up to [`EVENTUALLY`].
async fn eventually(what: &str, mut condition: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + EVENTUALLY;
    while Instant::now() < deadline {
        if condition().await {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("not within {EVENTUALLY:?}: {what}");
}

/// Waits until the service `svc` has `up` servers that may take a connection and `down` that may
/// not.
async fn servers(podgate: &Podgate, up: u64, down: u64) {
    eventually(&format!("{up} servers up and {down} down"), async || {
        metric(podgate, UP).await == up && metric(podgate, DOWN).await == down
    })
    .await;
}

#[tokio::test]
async fn l4_health_marks_down_and_up() {
    let podgate = start().await;
    // A bound socket that does not listen refuses every connect, until it does.
    let socket = TcpSocket::new_v4().expect("socket");
    socket
        .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("bind");
    let refusing = socket.local_addr().expect("addr");
    let b = greeter("b").await;
    push(
        &podgate,
        &reserved(1, &[tcp_app(&[refusing, b.addr], Some(check(&json!({}))))]),
    )
    .await;

    servers(&podgate, 1, 1).await;
    let failures = metric(&podgate, "podgate_tcp_connect_failures_total").await;
    for _ in 0..6 {
        assert_eq!(ask(&podgate).await.as_deref(), Some("b"));
    }
    assert_eq!(
        metric(&podgate, "podgate_tcp_connect_failures_total").await,
        failures,
        "a server marked down is not dialled"
    );

    let recovered = greet_on(socket.listen(16).expect("listen"), "a");
    servers(&podgate, 2, 0).await;
    eventually("connections reach the recovered server", async || {
        ask(&podgate).await.as_deref() == Some("a")
    })
    .await;
    assert!(recovered.accepted() >= 1);
}

#[tokio::test]
async fn l4_health_send_expect() {
    let podgate = start().await;
    let mode = Mode::new(GOOD);
    let server = ping_server("svc-a", Arc::clone(&mode)).await;
    let rule = check(&json!({ "send": b64(b"PING\n"), "expect": b64(b"PONG") }));
    push(
        &podgate,
        &reserved(1, &[tcp_app(&[server.addr], Some(rule))]),
    )
    .await;

    eventually("the server was probed twice", async || {
        server.sent(b"PING\n") >= 2
    })
    .await;
    servers(&podgate, 1, 0).await;
    assert_eq!(ask(&podgate).await.as_deref(), Some("svc-a"));

    mode.set(BAD);
    servers(&podgate, 0, 1).await;
    assert_eq!(ask(&podgate).await, None);
    mode.set(GOOD);
    servers(&podgate, 1, 0).await;
    eventually("connections follow", async || {
        ask(&podgate).await.as_deref() == Some("svc-a")
    })
    .await;
}

#[tokio::test]
async fn l4_health_banner_expect() {
    let podgate = start().await;
    let mode = Mode::new(GOOD);
    let server = banner_server("mail ready", Arc::clone(&mode)).await;
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &[server.addr],
                Some(check(&json!({ "expect": b64(b"220 ") }))),
            )],
        ),
    )
    .await;

    // The probe sends nothing and waits for the greeting; a client sees the same banner.
    eventually("the server was probed", async || server.accepted() >= 2).await;
    servers(&podgate, 1, 0).await;
    assert_eq!(ask(&podgate).await.as_deref(), Some("220 mail ready"));

    mode.set(BAD);
    servers(&podgate, 0, 1).await;
    assert_eq!(ask(&podgate).await, None);
    mode.set(GOOD);
    servers(&podgate, 1, 0).await;
}

#[tokio::test]
async fn l4_health_wrong_reply_fails() {
    let podgate = start().await;
    let server = ping_server("svc-a", Mode::new(BAD)).await;
    let rule = check(&json!({ "send": b64(b"PING\n"), "expect": b64(b"PONG") }));
    push(
        &podgate,
        &reserved(1, &[tcp_app(&[server.addr], Some(rule))]),
    )
    .await;

    servers(&podgate, 0, 1).await;
    assert!(server.sent(b"PING\n") >= 1, "the server was asked");
    assert_eq!(ask(&podgate).await, None);
}

/// A private certificate authority and what it issues for the TLS servers.
struct Ca {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    pem: String,
}

impl Ca {
    fn new(name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().expect("CA key"),
        )
        .expect("self-signed CA");
        let pem = issuer.pem();
        Self { issuer, pem }
    }

    /// An acceptor presenting a certificate for 127.0.0.1 issued by this CA.
    fn acceptor(&self) -> TlsAcceptor {
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("leaf params");
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        let chain = vec![cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).expect("key");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server config");
        TlsAcceptor::from(Arc::new(config))
    }
}

/// A TLS server: how many handshakes completed, and it writes `HELLO` after each.
async fn tls_server(acceptor: TlsAcceptor) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handshakes = Arc::new(AtomicUsize::new(0));
    let done = Arc::clone(&handshakes);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, done) = (acceptor.clone(), Arc::clone(&done));
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(tcp).await {
                    done.fetch_add(1, Ordering::SeqCst);
                    drop(stream.write_all(b"HELLO").await);
                    let mut buf = [0_u8; 16];
                    while matches!(stream.read(&mut buf).await, Ok(read) if read > 0) {}
                }
            });
        }
    });
    (addr, handshakes)
}

/// A probe by the check `extra` of the server at `addr`, reached through `transport`.
fn probe_with(
    addr: SocketAddr,
    extra: &Value,
    transport: &Transport,
    policy: UpstreamPolicy,
) -> TcpProbe {
    let rule = Arc::new(Check::compile(&check(extra)).expect("compiles"));
    let server = Server {
        url: Box::default(),
        addr,
        tls: false,
        h2c: false,
        weight: 1,
        state: Arc::default(),
    };
    let peer = rule.peer(Upstream {
        server: &server,
        transport,
    });
    TcpProbe::new(rule, "t1", peer, policy, HttpProbe::connector())
}

fn trusting(ca: &Ca) -> Transport {
    let Value::Object(config) = json!({ "ca_pem": ca.pem }) else {
        unreachable!("an object literal");
    };
    Transport::compile(&Declared {
        name: "private".into(),
        kind: "servers_transport".into(),
        config,
    })
    .expect("transport")
}

#[tokio::test]
async fn l4_health_tls_probe() {
    let ca = Ca::new("private ca");
    let (addr, handshakes) = tls_server(ca.acceptor()).await;
    let trusted = trusting(&ca);
    let probe = |extra: Value| probe_with(addr, &extra, &trusted, UpstreamPolicy::allow_all());

    // The handshake with the service's transport is the whole probe.
    assert_eq!(probe(json!({ "tls": true })).run().await, Verdict::Pass);
    timeout(WAIT, async {
        while handshakes.load(Ordering::SeqCst) < 1 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the server completed the handshake");
    // Over the TLS stream `expect` reads the decrypted bytes.
    let hello = json!({ "tls": true, "expect": b64(b"HELLO") });
    assert_eq!(probe(hello).run().await, Verdict::Pass);
    let wrong = json!({ "tls": true, "expect": b64(b"BYE") });
    assert!(matches!(probe(wrong).run().await, Verdict::Fail(_)));

    // A transport that does not trust the server's CA fails the handshake.
    let stranger = trusting(&Ca::new("stranger"));
    let verdict = probe_with(
        addr,
        &json!({ "tls": true }),
        &stranger,
        UpstreamPolicy::allow_all(),
    )
    .run()
    .await;
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");

    // A cleartext server is not a TLS server.
    let plain = greeter("plain").await;
    let verdict = probe_with(
        plain.addr,
        &json!({ "tls": true }),
        &trusted,
        UpstreamPolicy::allow_all(),
    )
    .run()
    .await;
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
}

#[tokio::test]
async fn l4_health_tls_probe_through_the_service() {
    let podgate = start().await;
    let ca = Ca::new("private ca");
    let (addr, handshakes) = tls_server(ca.acceptor()).await;
    let plain = greeter("plain").await;
    // A TCP service has the default transport, which trusts the platform roots and not this CA:
    // the verified handshake fails, the server is down and nothing completed on its side.
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &[addr, plain.addr],
                Some(check(&json!({ "tls": true }))),
            )],
        ),
    )
    .await;
    servers(&podgate, 0, 2).await;
    assert_eq!(handshakes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn l4_health_port_override() {
    let podgate = start().await;
    let traffic = greeter("traffic").await;
    let mode = Mode::new(GOOD);
    let management = ping_server("mgmt", Arc::clone(&mode)).await;
    let rule = check(&json!({
        "port": management.addr.port(),
        "send": b64(b"PING\n"),
        "expect": b64(b"PONG"),
    }));
    push(
        &podgate,
        &reserved(1, &[tcp_app(&[traffic.addr], Some(rule))]),
    )
    .await;

    eventually("the management port was probed", async || {
        management.sent(b"PING\n") >= 1
    })
    .await;
    servers(&podgate, 1, 0).await;
    assert_eq!(ask(&podgate).await.as_deref(), Some("traffic"));
    assert_eq!(
        traffic.accepted(),
        1,
        "only the client reached the server's port"
    );

    // The management port fails, so the server is down though its own port is fine.
    mode.set(BAD);
    servers(&podgate, 0, 1).await;
    assert_eq!(ask(&podgate).await, None);
    assert_eq!(
        traffic.accepted(),
        1,
        "the probe never touched the server's port"
    );
}

/// The 12 bytes every PROXY protocol v2 header starts with.
const V2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

#[tokio::test]
async fn l4_health_proxy_header() {
    let podgate = start().await;
    // Answers `OK` to a PROXY v2 `LOCAL` header and nothing to a probe without one.
    let server = serve(|mut stream, seen| async move {
        let chunk = first_chunk(&mut stream, &seen).await;
        let local = chunk.len() >= 16 && chunk.starts_with(V2_SIGNATURE) && chunk[12] == 0x20;
        let reply: &[u8] = if local { b"OK\n" } else { b"tag\n" };
        if local || chunk.starts_with(b"hello") {
            drop(stream.write_all(reply).await);
        }
    })
    .await;
    let rule = check(&json!({ "send_proxy_header": true, "expect": b64(b"OK") }));
    push(
        &podgate,
        &reserved(1, &[tcp_app(&[server.addr], Some(rule))]),
    )
    .await;

    eventually("the server was probed twice with the header", async || {
        server.sent(V2_SIGNATURE) >= 2
    })
    .await;
    servers(&podgate, 1, 0).await;
    assert_eq!(ask(&podgate).await.as_deref(), Some("tag"));

    // The same check without the header gets no answer.
    push(
        &podgate,
        &reserved(
            2,
            &[tcp_app(
                &[server.addr],
                Some(check(&json!({ "expect": b64(b"OK") }))),
            )],
        ),
    )
    .await;
    servers(&podgate, 0, 1).await;
}

#[tokio::test]
async fn l4_health_timeout() {
    let podgate = start().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let ended = Arc::clone(&closed);
    // Accepts and never speaks.
    let silent = serve(move |mut stream, _| {
        let ended = Arc::clone(&ended);
        async move {
            let mut buf = [0_u8; 16];
            while matches!(stream.read(&mut buf).await, Ok(read) if read > 0) {}
            ended.fetch_add(1, Ordering::SeqCst);
        }
    })
    .await;
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &[silent.addr],
                Some(check(&json!({ "expect": b64(b"hi") }))),
            )],
        ),
    )
    .await;

    servers(&podgate, 0, 1).await;
    eventually("the prober gave up on the connection", async || {
        closed.load(Ordering::SeqCst) >= 1
    })
    .await;
}

#[tokio::test]
async fn l4_health_read_capped() {
    let podgate = start().await;
    let written = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&written);
    // Greets with `AB` and then never stops writing: a probe that read it all would never finish.
    let flood = serve(move |mut stream, _| {
        let log = Arc::clone(&log);
        async move {
            let mut total = 0_usize;
            let mut chunk = vec![0_u8; 16 * 1024];
            chunk[..2].copy_from_slice(b"AB");
            while total < 64 * 1024 * 1024 {
                if stream.write_all(&chunk).await.is_err() {
                    break;
                }
                total += chunk.len();
                chunk[..2].fill(0);
            }
            log.lock().expect("lock").push(total);
        }
    })
    .await;
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &[flood.addr],
                Some(check(&json!({ "expect": b64(b"AB") }))),
            )],
        ),
    )
    .await;

    eventually("a probe closed on the writer", async || {
        !written.lock().expect("lock").is_empty()
    })
    .await;
    // The probe read two bytes and closed: the writer fails once the socket buffers are full,
    // far below what it was ready to send.
    for total in written.lock().expect("lock").iter() {
        assert!(*total < 32 * 1024 * 1024, "the writer sent {total} bytes");
    }
    servers(&podgate, 1, 0).await;
}

#[tokio::test]
async fn l4_health_obeys_upstream_policy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let transport = Transport::default();
    let probe = |policy: UpstreamPolicy| probe_with(addr, &json!({}), &transport, policy);

    let denying = UpstreamPolicy::parse(r#"{"deny": ["127.0.0.0/8"]}"#).expect("policy");
    let verdict = probe(denying.clone()).run().await;
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
    let dialled = timeout(Duration::from_millis(300), listener.accept()).await;
    assert!(dialled.is_err(), "a denied address was dialled");
    assert!(
        denying
            .render()
            .contains("podgate_upstream_refused_total{tenant=\"t1\"} 1"),
        "{}",
        denying.render()
    );

    // The same probe with a policy that allows the address connects and passes.
    let allowing = probe(UpstreamPolicy::allow_all());
    let allowed = tokio::spawn(async move { allowing.run().await });
    timeout(WAIT, listener.accept())
        .await
        .expect("connected")
        .expect("accept");
    assert_eq!(allowed.await.expect("probe"), Verdict::Pass);
}

#[tokio::test]
async fn l4_health_probe_concurrency_capped() {
    let podgate =
        Podgate::start_with_entry_points(&ENTRY_POINTS, &[("HEALTH_MAX_CONCURRENT", "2")]).await;
    let current = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut addrs = Vec::new();
    let mut backends = Vec::new();
    for _ in 0..8 {
        let (current, peak) = (Arc::clone(&current), Arc::clone(&peak));
        // Silent: every probe runs until the prober's timeout.
        let backend = serve(move |mut stream, _| {
            let (current, peak) = (Arc::clone(&current), Arc::clone(&peak));
            async move {
                let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                let mut buf = [0_u8; 16];
                while matches!(stream.read(&mut buf).await, Ok(read) if read > 0) {}
                current.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;
        addrs.push(backend.addr);
        backends.push(backend);
    }
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &addrs,
                Some(check(&json!({ "expect": b64(b"hi") }))),
            )],
        ),
    )
    .await;

    eventually("every server was probed", async || {
        backends.iter().all(|backend| backend.accepted() >= 1)
    })
    .await;
    assert_eq!(
        peak.load(Ordering::SeqCst),
        2,
        "eight silent probes run two at a time"
    );
}

/// Pushes version 1 with a single server that fails its probe and waits until it is down.
async fn marked_down(podgate: &Podgate, server: &Backend, rule: &Value) {
    push(
        podgate,
        &reserved(1, &[tcp_app(&[server.addr], Some(rule.clone()))]),
    )
    .await;
    servers(podgate, 0, 1).await;
    assert_eq!(ask(podgate).await, None);
}

#[tokio::test]
async fn l4_health_state_survives_unrelated_push() {
    let podgate = start().await;
    let server = ping_server("svc-a", Mode::new(BAD)).await;
    let rule = check(&json!({ "send": b64(b"PING\n"), "expect": b64(b"PONG") }));
    marked_down(&podgate, &server, &rule).await;

    // Another app changes and this one does not: the verdict is kept, so no connection reaches
    // the server in between (a fresh state would be healthy until the next probe).
    let mut other = app("y", &["y.test"], &[]);
    other["declared_by"] = json!("bumped");
    push(
        &podgate,
        &reserved(2, &[tcp_app(&[server.addr], Some(rule)), other]),
    )
    .await;
    for _ in 0..5 {
        assert_eq!(ask(&podgate).await, None);
    }
}

#[tokio::test]
async fn l4_health_state_resets_on_change() {
    let podgate = start().await;
    let server = ping_server("svc-a", Mode::new(BAD)).await;
    let rule = check(&json!({ "send": b64(b"PING\n"), "expect": b64(b"PONG") }));
    marked_down(&podgate, &server, &rule).await;

    // A different check starts healthy and needs five failures in a row to go down, so the very
    // next connection goes through.
    let changed = json!({
        "interval_secs": 5, "timeout_secs": 1, "unhealthy_threshold": 5,
        "send": b64(b"PING\n"), "expect": b64(b"PONG"),
    });
    push(
        &podgate,
        &reserved(2, &[tcp_app(&[server.addr], Some(changed))]),
    )
    .await;
    assert_eq!(ask(&podgate).await.as_deref(), Some("svc-a"));
}

#[tokio::test]
async fn l4_all_unhealthy_closes_connections() {
    let podgate = start().await;
    let (a, b) = (
        ping_server("a", Mode::new(BAD)).await,
        ping_server("b", Mode::new(BAD)).await,
    );
    let rule = check(&json!({ "send": b64(b"PING\n"), "expect": b64(b"PONG") }));
    push(
        &podgate,
        &reserved(1, &[tcp_app(&[a.addr, b.addr], Some(rule))]),
    )
    .await;

    servers(&podgate, 0, 2).await;
    let (before, other) = (
        metric(&podgate, NO_HEALTHY).await,
        metric(&podgate, "podgate_l4_refused_total{reason=\"no_server\"}").await,
    );
    for _ in 0..3 {
        assert_eq!(ask(&podgate).await, None);
    }
    assert_eq!(metric(&podgate, NO_HEALTHY).await, before + 3);
    assert_eq!(
        metric(&podgate, "podgate_l4_refused_total{reason=\"no_server\"}").await,
        other,
        "a connection refused for health is not a connect failure"
    );
    assert_eq!(
        a.sent(b"hello") + b.sent(b"hello"),
        0,
        "no client reached a server"
    );
}

#[tokio::test]
async fn l4_health_config_invalid_rejected() {
    let podgate = start().await;
    let server = greeter("a").await;
    let cases = [
        json!({ "send": b64(&[1; 257]) }),
        json!({ "expect": b64(&[1; 257]) }),
        json!({ "send": "not base64!" }),
        json!({ "send": "" }),
        json!({ "interval_secs": 0 }),
        json!({ "timeout_secs": 301 }),
        json!({ "unhealthy_interval_secs": 0 }),
        json!({ "healthy_threshold": 0 }),
        json!({ "port": 0 }),
        json!({ "path": "/healthz" }),
        json!({ "tls": true, "send_proxy_header": true }),
    ];
    for (version, extra) in (1_u64..).zip(cases) {
        let pushed = podgate
            .push_snapshot(&reserved(
                version,
                &[tcp_app(&[server.addr], Some(check(&extra)))],
            ))
            .await;
        assert_eq!(pushed.status, 422, "{extra}: {pushed:?}");
        assert_eq!(
            pushed.json()["conflicts"][0]["code"],
            "invalid_service",
            "{extra}"
        );
    }
    // 256 bytes each is the limit and fits.
    let full = check(&json!({ "send": b64(&[1; 256]), "expect": b64(&[2; 256]) }));
    let pushed = podgate
        .push_snapshot(&reserved(20, &[tcp_app(&[server.addr], Some(full))]))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");

    // A datagram service has no health check to declare.
    let mut udp = app("u", &["u.test"], &[]);
    udp["routers"] = json!([]);
    udp["udp"] = json!({
        "routers": [{ "name": "r", "entry_points": ["dns"], "service": "svc" }],
        "services": [{
            "name": "svc", "type": "loadbalancer",
            "servers": [{ "address": "127.0.0.1:5353" }],
            "health_check": check(&json!({})),
        }],
    });
    let pushed = podgate.push_snapshot(&reserved(21, &[udp])).await;
    assert_eq!(pushed.status, 422, "{pushed:?}");
    assert_eq!(pushed.json()["conflicts"][0]["code"], "invalid_service");
    assert!(pushed.body.contains("health_check"), "{}", pushed.body);
}
