//! Transport extras through the real binary: the PROXY protocol header towards an
//! HTTP upstream, and the limits of a tunnel (idle timeout, lifetime, close delay after the
//! server was removed).
//!
//! The PROXY upstream is a raw server that requires a header before anything else, plain or
//! under TLS, and records every header and request it sees. Tunnels run against the WebSocket
//! echo of `tests/common/ws.rs`.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::ws::{self, Echo};
use common::{
    Podgate, TestCert, app, middleware, refused, revision, serving, snapshot, with_chain,
};
use podgate::entry::proxy_protocol::{Header, Parse, parse};
use rustls::ServerConfig;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

/// Time for Pingora to move a finished upstream connection into its pool.
const POOL_SETTLE: Duration = Duration::from_millis(250);

// --- A server that requires a PROXY header ----------------------------------------------------

/// One header the upstream received, with the connection it came on.
#[derive(Debug, Clone)]
struct Seen {
    conn: usize,
    raw: Vec<u8>,
    header: Header,
}

#[derive(Default)]
struct Log {
    headers: Mutex<Vec<Seen>>,
    requests: Mutex<Vec<(usize, String)>>,
    connections: AtomicUsize,
    without_header: AtomicUsize,
}

/// A loopback server that expects a PROXY header first, then HTTP/1.1 keep-alive requests that
/// it answers `200 ok` with `x-conn` naming the connection.
struct Upstream {
    addr: SocketAddr,
    log: Arc<Log>,
}

/// Reads exactly one PROXY header off `stream`, byte by byte so nothing behind it is consumed.
async fn read_header(stream: &mut TcpStream) -> Option<(Vec<u8>, Header)> {
    let mut raw = Vec::new();
    loop {
        match parse(&raw) {
            Ok(Parse::Header(header, used)) if used == raw.len() => return Some((raw, header)),
            Ok(Parse::Header(..)) | Err(_) => return None,
            Ok(Parse::More(_)) => {
                let mut byte = [0_u8; 1];
                timeout(Duration::from_secs(5), stream.read_exact(&mut byte))
                    .await
                    .ok()?
                    .ok()?;
                raw.push(byte[0]);
            }
        }
    }
}

async fn answer<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, conn: usize, log: Arc<Log>) {
    let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nx-conn: {conn}\r\n\r\nok");
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            let line = head.lines().next().unwrap_or_default().to_owned();
            log.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((conn, line));
            seen.drain(..end + 4);
            if stream.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

impl Upstream {
    async fn start() -> Self {
        Self::start_with(None).await
    }

    /// The same under TLS: the header comes first, the handshake after it.
    async fn start_tls(cert: &TestCert) -> Self {
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .expect("chain");
        let key = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).expect("key");
        let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        Self::start_with(Some(TlsAcceptor::from(Arc::new(config)))).await
    }

    async fn start_with(acceptor: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let log = Arc::new(Log::default());
        let shared = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let conn = shared.connections.fetch_add(1, Ordering::SeqCst) + 1;
                let (log, acceptor) = (Arc::clone(&shared), acceptor.clone());
                tokio::spawn(async move {
                    let Some((raw, header)) = read_header(&mut tcp).await else {
                        log.without_header.fetch_add(1, Ordering::SeqCst);
                        return;
                    };
                    log.headers
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(Seen { conn, raw, header });
                    match acceptor {
                        None => answer(tcp, conn, log).await,
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(tcp).await {
                                answer(stream, conn, log).await;
                            }
                        }
                    }
                });
            }
        });
        Self { addr, log }
    }

    fn headers(&self) -> Vec<Seen> {
        self.log
            .headers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn requests(&self) -> Vec<(usize, String)> {
        self.log
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn connections(&self) -> usize {
        self.log.connections.load(Ordering::SeqCst)
    }

    fn without_header(&self) -> usize {
        self.log.without_header.load(Ordering::SeqCst)
    }
}

// --- Snapshots and clients --------------------------------------------------------------------

fn transport(fields: &Value) -> Value {
    let mut declared = json!({ "name": "t", "type": "servers_transport" });
    if let (Some(object), Some(extra)) = (declared.as_object_mut(), fields.as_object()) {
        object.extend(extra.clone());
    }
    declared
}

/// App `a` on `a.test`, whose revision `r1` reaches `upstream` through the transport `fields`.
fn with_transport(upstream: SocketAddr, fields: &Value) -> Value {
    let mut declared = app("a", &["a.test"], &[serving("r1", upstream)]);
    declared["transports"] = json!([transport(fields)]);
    declared["revisions"][0]["services"][0]["transport"] = json!("t");
    declared
}

async fn push(podgate: &Podgate, version: u64, apps: &[Value]) {
    let response = podgate.push_snapshot(&snapshot(version, apps)).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// A downstream connection that stays open between requests.
struct Client {
    stream: TcpStream,
}

impl Client {
    async fn connect(podgate: &Podgate) -> Self {
        let stream = TcpStream::connect(podgate.proxy_addr)
            .await
            .expect("connect");
        Self { stream }
    }

    fn local(&self) -> SocketAddr {
        self.stream.local_addr().expect("local address")
    }

    /// One `GET /` on `a.test`; the status line and the `x-conn` of the answer.
    async fn get(&mut self) -> (String, String) {
        self.stream
            .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .expect("write");
        let mut seen = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n")
                && seen.len() >= end + 4 + 2
            {
                let text = String::from_utf8_lossy(&seen).into_owned();
                let status = text.lines().next().unwrap_or_default().to_owned();
                let conn = text
                    .lines()
                    .find_map(|line| line.strip_prefix("x-conn: "))
                    .unwrap_or_default()
                    .to_owned();
                return (status, conn);
            }
            let read = timeout(Duration::from_secs(10), self.stream.read(&mut chunk))
                .await
                .expect("an answer in time")
                .expect("read");
            assert!(
                read > 0,
                "the proxy closed: {:?}",
                String::from_utf8_lossy(&seen)
            );
            seen.extend_from_slice(&chunk[..read]);
        }
    }
}

// --- PROXY protocol ---------------------------------------------------------------------------

#[tokio::test]
async fn upstream_proxy_protocol_v1() {
    let upstream = Upstream::start().await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        &[with_transport(
            upstream.addr,
            &json!({ "proxy_protocol": { "version": 1 } }),
        )],
    )
    .await;

    let mut client = Client::connect(&podgate).await;
    let (status, _) = client.get().await;
    assert_eq!(status, "HTTP/1.1 200 OK");

    let seen = upstream.headers();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let (source, destination) = (client.local(), podgate.proxy_addr);
    assert_eq!(
        String::from_utf8_lossy(&seen[0].raw),
        format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            source.ip(),
            destination.ip(),
            source.port(),
            destination.port()
        )
    );
    assert_eq!(seen[0].header.source(), Some(source));
    assert_eq!(seen[0].header.destination(), Some(destination));
    assert_eq!(upstream.requests().len(), 1);
    assert_eq!(
        upstream.without_header(),
        0,
        "the request never came before a header"
    );
}

#[tokio::test]
async fn upstream_proxy_protocol_v2() {
    let upstream = Upstream::start().await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        &[with_transport(
            upstream.addr,
            &json!({ "proxy_protocol": { "version": 2 } }),
        )],
    )
    .await;

    let mut client = Client::connect(&podgate).await;
    let (status, _) = client.get().await;
    assert_eq!(status, "HTTP/1.1 200 OK");

    let seen = upstream.headers();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        &seen[0].raw[..12],
        b"\r\n\r\n\0\r\nQUIT\n",
        "the v2 signature"
    );
    assert_eq!(seen[0].header.source(), Some(client.local()));
    assert_eq!(seen[0].header.destination(), Some(podgate.proxy_addr));
    assert_eq!(upstream.without_header(), 0);
}

#[tokio::test]
async fn upstream_proxy_protocol_precedes_the_tls_handshake() {
    let cert = TestCert::new(&["127.0.0.1"]);
    let upstream = Upstream::start_tls(&cert).await;
    let podgate = Podgate::start().await;
    let mut declared = with_transport(
        upstream.addr,
        &json!({ "proxy_protocol": { "version": 2 }, "insecure_skip_verify": true }),
    );
    declared["revisions"][0]["services"][0]["servers"] =
        json!([{ "url": format!("https://{}", upstream.addr) }]);
    push(&podgate, 1, &[declared]).await;

    let mut client = Client::connect(&podgate).await;
    let (status, _) = client.get().await;
    assert_eq!(status, "HTTP/1.1 200 OK");
    let seen = upstream.headers();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].header.source(), Some(client.local()));
    assert_eq!(upstream.without_header(), 0);
}

#[tokio::test]
async fn proxy_protocol_supported_or_unsupported() {
    let upstream = Upstream::start().await;
    let podgate = Podgate::start().await;
    for (version, fields) in [
        (1, json!({ "proxy_protocol": { "version": 1 } })),
        (2, json!({ "proxy_protocol": { "version": 2 } })),
    ] {
        let response = podgate
            .push_snapshot(&snapshot(
                version,
                &[with_transport(upstream.addr, &fields)],
            ))
            .await;
        assert_eq!(
            response.status, 200,
            "Pingora's custom_l4 dial makes proxy_protocol buildable: {}",
            response.body
        );
    }
    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/&method=GET")
        .await
        .json();
    assert!(
        explained.to_string().contains("\"proxy_protocol\":2"),
        "explain shows the version: {explained}"
    );
}

#[tokio::test]
async fn proxy_protocol_connections_not_shared_across_clients() {
    let upstream = Upstream::start().await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        &[with_transport(
            upstream.addr,
            &json!({ "proxy_protocol": { "version": 1 } }),
        )],
    )
    .await;

    // One client, two requests on one downstream connection: one upstream connection, one
    // header.
    let mut first = Client::connect(&podgate).await;
    let (_, conn_a) = first.get().await;
    sleep(POOL_SETTLE).await;
    let (_, again) = first.get().await;
    assert_eq!(
        conn_a, again,
        "the same client reuses its upstream connection"
    );
    assert_eq!(upstream.connections(), 1);

    // Another client address must not draw that idle connection: it would be shown the first
    // client's address.
    let mut second = Client::connect(&podgate).await;
    let (_, conn_b) = second.get().await;
    assert_ne!(conn_a, conn_b);
    assert_eq!(upstream.connections(), 2);
    sleep(POOL_SETTLE).await;
    let (_, conn_b_again) = second.get().await;
    assert_eq!(conn_b, conn_b_again);

    let seen = upstream.headers();
    assert_eq!(seen.len(), 2, "one header per connection: {seen:?}");
    let source = |conn: &str| {
        seen.iter()
            .find(|header| header.conn.to_string() == conn)
            .and_then(|header| header.header.source())
    };
    assert_eq!(source(&conn_a), Some(first.local()));
    assert_eq!(source(&conn_b), Some(second.local()));
    assert_ne!(first.local(), second.local());
}

#[tokio::test]
async fn proxy_protocol_retry_sends_same_client() {
    let upstream = Upstream::start().await;
    let dead = refused();
    let podgate = Podgate::start().await;
    let mut declared = with_chain(
        with_transport(
            upstream.addr,
            &json!({ "proxy_protocol": { "version": 1 } }),
        ),
        &[middleware(
            "r",
            "retry",
            json!({ "attempts": 3, "initial_interval_ms": 1 }),
        )],
    );
    declared["revisions"][0]["services"][0]["algorithm"] = json!("round_robin");
    declared["revisions"][0]["services"][0]["servers"] = json!([
        { "url": format!("http://{}", dead.addr) },
        { "url": format!("http://{}", upstream.addr) },
    ]);
    push(&podgate, 1, &[declared]).await;

    // Round robin tries the dead server for every other request, which the retry moves on.
    let mut clients = Vec::new();
    for _ in 0..4 {
        let mut client = Client::connect(&podgate).await;
        let (status, _) = client.get().await;
        assert_eq!(status, "HTTP/1.1 200 OK");
        clients.push(client.local());
    }
    let seen = upstream.headers();
    assert_eq!(seen.len(), 4, "one connection per client: {seen:?}");
    for client in clients {
        assert!(
            seen.iter()
                .any(|header| header.header.source() == Some(client)),
            "{client} reached the upstream with its own header: {seen:?}"
        );
    }
    assert_eq!(upstream.without_header(), 0);
}

#[tokio::test]
async fn proxy_protocol_probes_send_local() {
    let upstream = Upstream::start().await;
    let podgate = Podgate::start().await;
    let mut declared = with_transport(
        upstream.addr,
        &json!({ "proxy_protocol": { "version": 2 } }),
    );
    declared["revisions"][0]["services"][0]["health_check"] =
        json!({ "path": "/up", "interval_secs": 1, "timeout_secs": 1 });
    push(&podgate, 1, &[declared]).await;

    let deadline = Instant::now() + Duration::from_secs(10);
    while !upstream
        .requests()
        .iter()
        .any(|(_, line)| line.contains("/up"))
    {
        assert!(Instant::now() < deadline, "no probe arrived");
        sleep(Duration::from_millis(50)).await;
    }
    let probe_conn = upstream
        .requests()
        .iter()
        .find(|(_, line)| line.contains("/up"))
        .map(|(conn, _)| *conn)
        .expect("a probe");
    let seen = upstream.headers();
    let header = seen
        .iter()
        .find(|header| header.conn == probe_conn)
        .expect("the probe's header");
    assert_eq!(header.header, Header::Local, "{header:?}");
    assert_eq!(
        upstream.without_header(),
        0,
        "no probe came without a header"
    );
}

#[tokio::test]
async fn proxy_protocol_mirror_refused() {
    let main = Upstream::start().await;
    let shadow = Upstream::start().await;
    let podgate = Podgate::start().await;
    let mut declared = app(
        "a",
        &["a.test"],
        &[
            json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
            { "name": "web", "type": "loadbalancer", "servers": [{ "url": format!("http://{}", main.addr) }] },
            { "name": "shadow", "type": "loadbalancer", "transport": "t",
              "servers": [{ "url": format!("http://{}", shadow.addr) }] },
            { "name": "m", "type": "mirroring", "service": "web",
              "mirrors": [{ "service": "shadow", "percent": 100 }] },
        ] }),
        ],
    );
    declared["routers"][0]["service"] = json!("m");
    declared["transports"] = json!([transport(&json!({ "proxy_protocol": { "version": 1 } }))]);
    let response = podgate.push_snapshot(&snapshot(1, &[declared])).await;
    assert_eq!(response.status, 422, "{}", response.body);
    let conflict = &response.json()["conflicts"][0];
    assert_eq!(conflict["code"], "invalid_service", "{conflict}");
    assert!(
        conflict["message"]
            .as_str()
            .is_some_and(|message| message.contains("proxy_protocol")),
        "{conflict}"
    );
}

// --- Validation -------------------------------------------------------------------------------

#[tokio::test]
async fn transport_extras_invalid_rejected() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start().await;
    for (what, fields) in [
        ("zero idle", json!({ "tunnel_idle_timeout_secs": 0 })),
        (
            "over a day idle",
            json!({ "tunnel_idle_timeout_secs": 86_401 }),
        ),
        ("zero lifetime", json!({ "max_stream_lifetime_secs": 0 })),
        (
            "over a day lifetime",
            json!({ "max_stream_lifetime_secs": 86_401 }),
        ),
        ("zero delay", json!({ "stream_close_delay_secs": 0 })),
        (
            "over a day delay",
            json!({ "stream_close_delay_secs": 86_401 }),
        ),
        ("negative", json!({ "max_stream_lifetime_secs": -1 })),
        ("fractional", json!({ "tunnel_idle_timeout_secs": 1.5 })),
        ("version 0", json!({ "proxy_protocol": { "version": 0 } })),
        ("version 3", json!({ "proxy_protocol": { "version": 3 } })),
        (
            "version text",
            json!({ "proxy_protocol": { "version": "1" } }),
        ),
        ("no version", json!({ "proxy_protocol": {} })),
        (
            "unknown field",
            json!({ "proxy_protocol": { "version": 1, "x": 1 } }),
        ),
        ("not an object", json!({ "proxy_protocol": 1 })),
    ] {
        let response = podgate
            .push_snapshot(&snapshot(1000, &[with_transport(upstream.addr, &fields)]))
            .await;
        assert_eq!(response.status, 422, "{what}: {}", response.body);
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_transport",
            "{what}: {}",
            response.body
        );
    }
    push(
        &podgate,
        1,
        &[with_transport(
            upstream.addr,
            &json!({ "tunnel_idle_timeout_secs": 86_400, "max_stream_lifetime_secs": 1,
                     "stream_close_delay_secs": 86_400, "proxy_protocol": { "version": 2 } }),
        )],
    )
    .await;
}

// --- Tunnels ----------------------------------------------------------------------------------

async fn tunnel(podgate: &Podgate) -> ws::Tunnel<TcpStream> {
    let stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    ws::open(stream, "a.test", "/", &[]).await.tunnel()
}

async fn closed_total(podgate: &Podgate, reason: &str) -> f64 {
    let series = format!("podgate_tunnel_closed_total{{reason=\"{reason}\"}} ");
    let body = podgate.admin_get("/metrics").await.body;
    body.lines()
        .find_map(|line| line.strip_prefix(&series)?.parse().ok())
        .unwrap_or_else(|| panic!("no {series}in {body}"))
}

fn within(lived: Duration, low_ms: u64, high_ms: u64) -> bool {
    (Duration::from_millis(low_ms)..Duration::from_millis(high_ms)).contains(&lived)
}

#[tokio::test]
async fn tunnel_closed_at_max_lifetime() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        &[with_transport(
            echo.addr,
            &json!({ "max_stream_lifetime_secs": 2 }),
        )],
    )
    .await;

    // A silent tunnel.
    let mut quiet = tunnel(&podgate).await;
    let lived = quiet
        .closes_within(Duration::from_secs(6))
        .await
        .expect("a silent tunnel closes at its lifetime");
    assert!(within(lived, 1800, 3500), "{lived:?}");

    // A busy one: traffic in both directions does not extend it.
    let mut busy = tunnel(&podgate).await;
    let started = Instant::now();
    let mut closed = None;
    while started.elapsed() < Duration::from_secs(6) {
        busy.send(ws::PING, b"keep").await;
        closed = busy.closes_within(Duration::from_millis(300)).await;
        if closed.is_some() {
            break;
        }
    }
    assert!(closed.is_some(), "a busy tunnel closes at its lifetime too");
    assert!(
        within(started.elapsed(), 1800, 3500),
        "{:?}",
        started.elapsed()
    );
    assert!(echo.wait_open(0, Duration::from_secs(3)).await);
    assert_eq!(closed_total(&podgate, "max_lifetime").await, 2.0);
}

#[tokio::test]
async fn tunnel_lifetime_ignores_short_requests() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        &[with_transport(
            echo.addr,
            &json!({ "max_stream_lifetime_secs": 1 }),
        )],
    )
    .await;

    let mut client = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    for round in 0..3 {
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .expect("write");
        let mut seen = vec![0_u8; 1024];
        let read = timeout(Duration::from_secs(5), client.read(&mut seen))
            .await
            .expect("an answer")
            .expect("read");
        assert!(
            String::from_utf8_lossy(&seen[..read]).starts_with("HTTP/1.1 200"),
            "round {round}"
        );
        sleep(Duration::from_millis(700)).await;
    }
    assert_eq!(closed_total(&podgate, "max_lifetime").await, 0.0);
}

/// Snapshot version `version`: app `a` whose revision `r1` is `state` on `r1_server`, and a
/// serving `r2` on `r2_server`, both through the transport with `fields`.
fn two_revisions(
    version: u64,
    r1: (SocketAddr, &str),
    r2_server: SocketAddr,
    fields: &Value,
) -> Value {
    let mut declared = app(
        "a",
        &["a.test"],
        &[revision("r1", r1.0, 100, r1.1), serving("r2", r2_server)],
    );
    declared["transports"] = json!([transport(fields)]);
    for index in 0..2 {
        declared["revisions"][index]["services"][0]["transport"] = json!("t");
    }
    snapshot(version, &[declared])
}

async fn apply(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

#[tokio::test]
async fn tunnel_closed_after_server_removed_delay() {
    let old = Echo::start().await;
    let new = Echo::start().await;
    let other = Echo::start().await;
    let podgate = Podgate::start().await;
    let fields = json!({ "stream_close_delay_secs": 2 });
    apply(
        &podgate,
        &two_revisions(1, (old.addr, "serving"), new.addr, &fields),
    )
    .await;
    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"hi").await;
    assert_eq!(tunnel.recv().await.payload, b"hi");

    // Draining alone, with the server still in the table, starts nothing.
    apply(
        &podgate,
        &two_revisions(2, (old.addr, "draining"), new.addr, &fields),
    )
    .await;
    assert!(
        tunnel
            .closes_within(Duration::from_millis(3000))
            .await
            .is_none(),
        "a draining revision keeps its tunnel"
    );
    tunnel.send(ws::PING, b"x").await;
    assert_eq!(tunnel.recv().await.opcode, ws::PONG);

    // The server leaves the revision: the delay starts.
    apply(
        &podgate,
        &two_revisions(3, (other.addr, "draining"), new.addr, &fields),
    )
    .await;
    let removed = Instant::now();
    assert!(
        tunnel
            .closes_within(Duration::from_millis(1000))
            .await
            .is_none(),
        "still inside the delay"
    );
    tunnel
        .closes_within(Duration::from_secs(5))
        .await
        .expect("the tunnel closes after the delay");
    assert!(
        within(removed.elapsed(), 1800, 3500),
        "{:?}",
        removed.elapsed()
    );
    assert!(old.wait_open(0, Duration::from_secs(3)).await);
    assert_eq!(closed_total(&podgate, "server_removed").await, 1.0);
}

#[tokio::test]
async fn drained_event_after_tunnel_close() {
    let old = Echo::start().await;
    let new = Echo::start().await;
    let other = Echo::start().await;
    let podgate = Podgate::start().await;
    let fields = json!({ "stream_close_delay_secs": 2 });
    apply(
        &podgate,
        &two_revisions(1, (old.addr, "serving"), new.addr, &fields),
    )
    .await;
    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"hi").await;
    assert_eq!(tunnel.recv().await.payload, b"hi");

    apply(
        &podgate,
        &two_revisions(2, (other.addr, "draining"), new.addr, &fields),
    )
    .await;
    let early = podgate
        .admin_get("/v1/events?after=0&timeout_secs=1")
        .await
        .json();
    assert_eq!(
        early["events"],
        json!([]),
        "not drained while the tunnel lives: {early}"
    );

    tunnel
        .closes_within(Duration::from_secs(5))
        .await
        .expect("closed by the delay");
    let drained = podgate
        .admin_get("/v1/events?after=0&timeout_secs=5")
        .await
        .json();
    let events = drained["events"].as_array().expect("events");
    assert_eq!(events.len(), 1, "{drained}");
    assert_eq!(
        (
            events[0]["kind"].as_str(),
            events[0]["app"].as_str(),
            events[0]["revision"].as_str()
        ),
        (Some("revision_drained"), Some("a"), Some("r1"))
    );
}

/// An upstream that reads a request and never answers it.
async fn mute_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    addr
}

#[tokio::test]
async fn tunnel_idle_timeout_applies_after_upgrade() {
    let echo = Echo::start().await;

    // A short tunnel idle timeout ends an idle tunnel although the read timeout is long.
    let podgate = Podgate::start().await;
    push(
        &podgate,
        1,
        &[with_transport(
            echo.addr,
            &json!({ "read_timeout_secs": 30, "tunnel_idle_timeout_secs": 2 }),
        )],
    )
    .await;
    let mut idle = tunnel(&podgate).await;
    let lived = idle
        .closes_within(Duration::from_secs(8))
        .await
        .expect("idle tunnel closes at tunnel_idle_timeout_secs");
    assert!(within(lived, 1800, 3500), "{lived:?}");
    assert_eq!(closed_total(&podgate, "idle_timeout").await, 1.0);

    // A long one outlives a short read timeout: after the 101 the read timeout is not the
    // tunnel's.
    push(
        &podgate,
        2,
        &[with_transport(
            echo.addr,
            &json!({ "read_timeout_secs": 1, "tunnel_idle_timeout_secs": 4 }),
        )],
    )
    .await;
    let mut long = tunnel(&podgate).await;
    assert!(
        long.closes_within(Duration::from_millis(2500))
            .await
            .is_none(),
        "open past the 1 s read timeout"
    );
    long.send(ws::PING, b"x").await;
    assert_eq!(long.recv().await.opcode, ws::PONG);
    let lived = long
        .closes_within(Duration::from_secs(8))
        .await
        .expect("then the idle timeout closes it");
    assert!(within(lived, 3000, 5200), "{lived:?}");

    // The operator's `read_secs` stays a ceiling on the client side.
    let mut capped = snapshot(
        3,
        &[with_transport(
            echo.addr,
            &json!({ "tunnel_idle_timeout_secs": 8 }),
        )],
    );
    capped["entry_points"] = json!([{ "name": "web", "timeouts": { "read_secs": 2 } }]);
    apply(&podgate, &capped).await;
    let mut ceiling = tunnel(&podgate).await;
    let lived = ceiling
        .closes_within(Duration::from_secs(6))
        .await
        .expect("closed at the entry point's read_secs");
    assert!(within(lived, 1800, 3500), "{lived:?}");

    // The read timeout still bounds the wait for the 101.
    let mute = mute_upstream().await;
    push(
        &podgate,
        4,
        &[with_transport(
            mute,
            &json!({ "read_timeout_secs": 1, "tunnel_idle_timeout_secs": 30 }),
        )],
    )
    .await;
    let stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    let started = Instant::now();
    let refused = ws::open(stream, "a.test", "/", &[]).await.refused();
    assert_eq!(refused.status, 504, "{refused:?}");
    assert!(
        within(started.elapsed(), 800, 2500),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn tunnels_unbounded_by_default() {
    let echo = Echo::start().await;
    // A request timeout of 1 s used to close an idle tunnel after 1 s.
    let podgate = Podgate::start_with_env(&[("REQUEST_TIMEOUT_SECS", "1")]).await;
    push(
        &podgate,
        1,
        &[app("a", &["a.test"], &[serving("r1", echo.addr)])],
    )
    .await;

    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"hi").await;
    assert_eq!(tunnel.recv().await.payload, b"hi");
    assert!(
        tunnel.closes_within(Duration::from_secs(4)).await.is_none(),
        "no timer closes an idle tunnel: not the request timeout, not a lifetime"
    );
    assert_eq!(echo.open_tunnels(), 1);
    tunnel.send(ws::PING, b"x").await;
    assert_eq!(
        tunnel.recv().await.opcode,
        ws::PONG,
        "and it still carries traffic"
    );

    // An active one is no different.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        tunnel.send(ws::PING, b"x").await;
        assert_eq!(tunnel.recv().await.opcode, ws::PONG);
        sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(closed_total(&podgate, "max_lifetime").await, 0.0);
    assert_eq!(closed_total(&podgate, "idle_timeout").await, 0.0);
    drop(tunnel);
}
