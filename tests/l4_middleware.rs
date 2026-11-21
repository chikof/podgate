//! TCP middlewares and what a TCP service does towards its servers, through the real
//! binary: `in_flight_conn` and `ip_allow_list` before any dial and before the tenant's slot, the
//! PROXY protocol header, TLS to a server with the transport's CA, server name and client
//! certificate, `termination_delay_ms`, and the posture entries of a plan.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Podgate, app, snapshot};
use podgate::entry::proxy_protocol::{Header, Parse, parse};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

const ENTRY_POINTS: [(&str, &str); 2] = [("web", "http"), ("pg", "tcp")];
const WAIT: Duration = Duration::from_secs(5);
const REFUSED: &str = "podgate_l4_refused_total";

/// A TCP server on a loopback port and how many connections it accepted.
struct Server {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

impl Server {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// Starts a server on `listener` that runs `handle` for each connection.
fn spawn_server<F, Fut>(listener: TcpListener, handle: F) -> Server
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let addr = listener.local_addr().expect("server addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(handle(stream));
        }
    });
    Server { addr, accepted }
}

async fn serve<F, Fut>(handle: F) -> Server
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    spawn_server(
        TcpListener::bind("127.0.0.1:0").await.expect("bind server"),
        handle,
    )
}

/// A server that greets with `tag\n` and then echoes until the client closes.
async fn greeter(tag: &'static str) -> Server {
    serve(move |mut stream| async move {
        if stream
            .write_all(format!("{tag}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
        let mut buf = [0_u8; 4096];
        while let Ok(read) = stream.read(&mut buf).await {
            if read == 0 || stream.write_all(&buf[..read]).await.is_err() {
                return;
            }
        }
    })
    .await
}

/// An app of tenant `t1` and id `t` with the TCP service `svc` over `servers`, the TCP router `r`
/// on `pg`, and `middlewares`. `router` and `service` add fields to them.
fn tcp_app(servers: &[Value], router: &Value, service: &Value, middlewares: &[Value]) -> Value {
    let mut app = app("t", &["t.test"], &[]);
    app["routers"] = json!([]);
    let mut router_config = json!({ "name": "r", "entry_points": ["pg"], "service": "svc" });
    let mut service_config = json!({ "name": "svc", "type": "loadbalancer", "servers": servers });
    for (config, extra) in [(&mut router_config, router), (&mut service_config, service)] {
        if let (Some(config), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
            config.extend(extra.clone());
        }
    }
    app["tcp"] = json!({
        "routers": [router_config],
        "services": [service_config],
        "middlewares": middlewares,
    });
    app
}

fn servers_of(addrs: &[SocketAddr]) -> Vec<Value> {
    addrs
        .iter()
        .map(|addr| json!({ "address": addr.to_string() }))
        .collect()
}

fn middleware(name: &str, kind: &str, config: &Value) -> Value {
    common::middleware(name, kind, config.clone())
}

/// A snapshot of tenant `t1` that reserves the `pg` entry point to it.
fn reserved(version: u64, apps: &[Value]) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["entry_points"] = json!([{ "name": "pg", "tenants": ["t1"] }]);
    pushed
}

fn with_inflight(mut pushed: Value, max_inflight: u32) -> Value {
    pushed["tenants"][0]["budget"] =
        json!({ "max_inflight": max_inflight, "max_buffer_bytes": 1_048_576 });
    pushed
}

async fn start() -> Podgate {
    Podgate::start_with_entry_points(&ENTRY_POINTS, &[]).await
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

async fn connect(podgate: &Podgate) -> TcpStream {
    timeout(WAIT, TcpStream::connect(podgate.entry_addr("pg")))
        .await
        .expect("connect in time")
        .expect("connect to the tcp entry point")
}

/// A connection to the entry point whose source address is `source` (any 127.0.0.0/8 address).
async fn connect_from(podgate: &Podgate, source: &str) -> TcpStream {
    let socket = TcpSocket::new_v4().expect("socket");
    socket
        .bind(format!("{source}:0").parse().expect("source address"))
        .expect("bind the source address");
    timeout(WAIT, socket.connect(podgate.entry_addr("pg")))
        .await
        .expect("connect in time")
        .expect("connect from the source")
}

/// The first line a connection delivers, `None` when it ends or fails without one.
async fn line(stream: &mut TcpStream) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match timeout(WAIT, stream.read(&mut byte)).await {
            Ok(Ok(1)) if byte[0] == b'\n' => {
                return Some(String::from_utf8_lossy(&line).into_owned());
            }
            Ok(Ok(1)) => line.push(byte[0]),
            _ => return None,
        }
    }
}

/// Whether the connection ends without a byte: podgate closed it, as it does a refusal.
async fn closed_without_data(stream: &mut TcpStream) -> bool {
    let mut buf = [0_u8; 16];
    matches!(
        timeout(WAIT, stream.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// The value of the sample `series` (a name with its labels) in the metrics of `podgate`.
async fn metric(podgate: &Podgate, series: &str) -> u64 {
    let body = podgate.admin_get("/metrics").await.body;
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("no sample {series} in:\n{body}"))
}

fn refused(reason: &str) -> String {
    format!("{REFUSED}{{reason=\"{reason}\"}}")
}

fn limiter(name: &str, middleware: &str) -> String {
    format!("{name}{{app=\"t\",middleware=\"{middleware}\",type=\"in_flight_conn\"}}")
}

/// A greeting from a fresh connection from the default source, retried until one comes: a slot
/// returned by a closed connection is seen by the next one a moment later.
async fn served_eventually(podgate: &Podgate) -> TcpStream {
    let deadline = Instant::now() + WAIT;
    loop {
        let mut stream = connect(podgate).await;
        if line(&mut stream).await.is_some() {
            return stream;
        }
        assert!(Instant::now() < deadline, "the slot was never returned");
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn l4_in_flight_conn_caps_per_source() {
    let podgate = start().await;
    let up = greeter("up").await;
    let cap = middleware("cap", "in_flight_conn", &json!({ "amount": 2 }));
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[up.addr]),
                &json!({ "chain": ["cap"] }),
                &json!({}),
                &[cap],
            )],
        ),
    )
    .await;
    let mut first = connect(&podgate).await;
    let mut second = connect(&podgate).await;
    assert_eq!(line(&mut first).await.as_deref(), Some("up"));
    assert_eq!(line(&mut second).await.as_deref(), Some("up"));
    let mut third = connect(&podgate).await;
    assert!(
        closed_without_data(&mut third).await,
        "the third connection of a source is closed"
    );
    assert_eq!(
        up.accepted(),
        2,
        "the refused connection never reached a server"
    );
    assert_eq!(metric(&podgate, &refused("in_flight_conn")).await, 1);
    assert_eq!(
        metric(&podgate, &limiter("podgate_limiter_rejected_total", "cap")).await,
        1
    );
    // Another source address has a count of its own.
    let mut other = connect_from(&podgate, "127.0.0.2").await;
    assert_eq!(line(&mut other).await.as_deref(), Some("up"));
    drop((first, second));
}

#[tokio::test]
async fn l4_in_flight_conn_releases() {
    let podgate = start().await;
    let up = greeter("up").await;
    let cap = middleware("cap", "in_flight_conn", &json!({ "amount": 1 }));
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[up.addr]),
                &json!({ "chain": ["cap"] }),
                &json!({}),
                &[cap],
            )],
        ),
    )
    .await;
    let mut held = connect(&podgate).await;
    assert_eq!(line(&mut held).await.as_deref(), Some("up"));
    let mut over = connect(&podgate).await;
    assert!(closed_without_data(&mut over).await, "the cap is 1");
    // A client that closes returns its slot.
    drop(held);
    let reset = served_eventually(&podgate).await;
    // A client that aborts (RST) returns it too.
    reset.set_zero_linger().expect("abort on close");
    drop(reset);
    let last = served_eventually(&podgate).await;
    drop(last);
}

#[tokio::test]
async fn l4_in_flight_conn_table_bounded() {
    let podgate = start().await;
    let up = greeter("up").await;
    let cap = middleware(
        "cap",
        "in_flight_conn",
        &json!({ "amount": 1, "max_sources": 8 }),
    );
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[up.addr]),
                &json!({ "chain": ["cap"] }),
                &json!({}),
                std::slice::from_ref(&cap),
            )],
        ),
    )
    .await;
    let bytes = limiter("podgate_limiter_table_bytes", "cap");
    assert_eq!(
        metric(&podgate, &bytes).await,
        0,
        "nothing before a connection"
    );
    // Twelve sources hold a connection each: eight have an entry, the next one the table's one
    // shared overflow slot, and the rest find it taken.
    let mut held = Vec::new();
    let mut closed = 0;
    for last in 1..=12 {
        let mut stream = connect_from(&podgate, &format!("127.0.0.{last}")).await;
        if line(&mut stream).await.is_some() {
            held.push(stream);
        } else {
            closed += 1;
        }
    }
    assert_eq!(held.len(), 9, "eight entries and one overflow slot");
    assert_eq!(closed, 3);
    let table = metric(&podgate, &bytes).await;
    assert!(table > 0 && table <= 1_048_576, "{table}");
    assert!(
        metric(&podgate, &limiter("podgate_limiter_overflow_total", "cap")).await >= 4,
        "the overflow slot was used by four connections"
    );
    // The table never grows: more sources change nothing about its size.
    let mut extra = connect_from(&podgate, "127.0.0.40").await;
    assert!(closed_without_data(&mut extra).await);
    assert_eq!(metric(&podgate, &bytes).await, table);
    drop(held);
    // A table that does not fit the tenant's `max_buffer_bytes` is refused at apply time.
    let huge = middleware(
        "cap",
        "in_flight_conn",
        &json!({ "amount": 1, "max_sources": 1_000_000 }),
    );
    let response = podgate
        .push_snapshot(&reserved(
            2,
            &[tcp_app(
                &servers_of(&[up.addr]),
                &json!({ "chain": ["cap"] }),
                &json!({}),
                &[huge],
            )],
        ))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert!(
        response.body.contains("invalid_middleware"),
        "{}",
        response.body
    );
}

#[tokio::test]
async fn l4_ip_allow_list_closes_refused() {
    let podgate = start().await;
    let up = greeter("up").await;
    let office = middleware(
        "office",
        "ip_allow_list",
        &json!({ "source_range": ["127.0.0.2/32"] }),
    );
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[up.addr]),
                &json!({ "chain": ["office"] }),
                &json!({}),
                &[office],
            )],
        ),
    )
    .await;
    let mut listed = connect_from(&podgate, "127.0.0.2").await;
    assert_eq!(line(&mut listed).await.as_deref(), Some("up"));
    let mut unlisted = connect(&podgate).await;
    assert!(
        closed_without_data(&mut unlisted).await,
        "a peer outside the list is closed without a byte"
    );
    assert_eq!(metric(&podgate, &refused("ip_not_allowed")).await, 1);
}

#[tokio::test]
async fn l4_refused_never_dials() {
    let podgate = start().await;
    let up = greeter("up").await;
    let office = middleware(
        "office",
        "ip_allow_list",
        &json!({ "source_range": ["127.0.0.2/32"] }),
    );
    let pushed = with_inflight(
        reserved(
            1,
            &[tcp_app(
                &servers_of(&[up.addr]),
                &json!({ "chain": ["office"] }),
                &json!({}),
                &[office],
            )],
        ),
        1,
    );
    push(&podgate, &pushed).await;
    // The tenant's one slot is taken by the listed peer...
    let mut listed = connect_from(&podgate, "127.0.0.2").await;
    assert_eq!(line(&mut listed).await.as_deref(), Some("up"));
    assert_eq!(up.accepted(), 1);
    // ...so a refusal by the chain, which runs before the slot, is the list's and not the budget's.
    let mut unlisted = connect(&podgate).await;
    assert!(closed_without_data(&mut unlisted).await);
    assert_eq!(metric(&podgate, &refused("ip_not_allowed")).await, 1);
    assert_eq!(metric(&podgate, &refused("over_inflight")).await, 0);
    assert_eq!(
        up.accepted(),
        1,
        "no server was dialled for the refused connection"
    );
    assert_eq!(
        metric(&podgate, "podgate_tcp_connect_failures_total").await,
        0
    );
}

#[tokio::test]
async fn l4_chain_sees_the_proxy_protocol_source() {
    let podgate =
        Podgate::start_with_entry_points(&[("web", "http"), ("pg", "tcp;proxy_protocol")], &[])
            .await;
    let up = greeter("up").await;
    let office = middleware(
        "office",
        "ip_allow_list",
        &json!({ "source_range": ["203.0.113.0/24"] }),
    );
    let mut pushed = reserved(
        1,
        &[tcp_app(
            &servers_of(&[up.addr]),
            &json!({ "chain": ["office"] }),
            &json!({}),
            &[office],
        )],
    );
    pushed["entry_points"] = json!([{ "name": "pg", "tenants": ["t1"], "proxy_protocol": { "trusted_ips": ["127.0.0.1"] } }]);
    push(&podgate, &pushed).await;
    // The peer is 127.0.0.1, which the list does not name; the address in the header does.
    let mut behind = connect(&podgate).await;
    behind
        .write_all(b"PROXY TCP4 203.0.113.9 127.0.0.1 40000 5432\r\n")
        .await
        .expect("write the header");
    assert_eq!(line(&mut behind).await.as_deref(), Some("up"));
    let mut elsewhere = connect(&podgate).await;
    elsewhere
        .write_all(b"PROXY TCP4 198.51.100.1 127.0.0.1 40000 5432\r\n")
        .await
        .expect("write the header");
    assert!(closed_without_data(&mut elsewhere).await);
}

/// What a server that expects a PROXY protocol header saw first.
#[derive(Debug, Clone)]
struct Seen {
    header: Header,
    /// The header's own bytes.
    raw: Vec<u8>,
}

/// Reads a PROXY protocol header from `stream`: the header and the bytes behind it that arrived
/// with it.
async fn read_header(stream: &mut TcpStream) -> Option<(Seen, Vec<u8>)> {
    let mut bytes = Vec::new();
    loop {
        match parse(&bytes) {
            Ok(Parse::Header(header, used)) => {
                let rest = bytes.split_off(used);
                return Some((Seen { header, raw: bytes }, rest));
            }
            Ok(Parse::More(_)) => {}
            Err(_) => return None,
        }
        let mut chunk = [0_u8; 256];
        match timeout(WAIT, stream.read(&mut chunk)).await {
            Ok(Ok(read)) if read > 0 => bytes.extend_from_slice(&chunk[..read]),
            _ => return None,
        }
    }
}

/// A server that reads a PROXY protocol header, records it, then answers `got:<line>` to the
/// first line that follows.
async fn header_server() -> (Server, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let server = serve(move |mut stream| {
        let record = Arc::clone(&record);
        async move {
            let Some((header, mut payload)) = read_header(&mut stream).await else {
                return;
            };
            record.lock().expect("lock").push(header);
            let mut chunk = [0_u8; 256];
            while !payload.contains(&b'\n') {
                match timeout(WAIT, stream.read(&mut chunk)).await {
                    Ok(Ok(read)) if read > 0 => payload.extend_from_slice(&chunk[..read]),
                    _ => return,
                }
            }
            let mut reply = b"got:".to_vec();
            reply.extend_from_slice(&payload);
            drop(stream.write_all(&reply).await);
        }
    })
    .await;
    (server, seen)
}

/// Pushes a service that writes PROXY protocol `version` to `header_server`'s address and has a
/// client talk through it; returns what the server saw, the client's address and the entry's.
async fn through_proxy_protocol(version: u8) -> (Seen, SocketAddr, SocketAddr) {
    let podgate = start().await;
    let (up, seen) = header_server().await;
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[up.addr]),
                &json!({}),
                &json!({ "proxy_protocol": { "version": version } }),
                &[],
            )],
        ),
    )
    .await;
    let mut client = connect(&podgate).await;
    let local = client.local_addr().expect("client address");
    // Written at once, so the header is the first thing the server sees only if podgate puts it
    // there: the client's bytes are waiting on the connection when the server's dial completes.
    client
        .write_all(b"hello\n")
        .await
        .expect("write the payload");
    assert_eq!(line(&mut client).await.as_deref(), Some("got:hello"));
    let seen = seen
        .lock()
        .expect("lock")
        .first()
        .cloned()
        .expect("a header");
    (seen, local, podgate.entry_addr("pg"))
}

#[tokio::test]
async fn l4_proxy_protocol_v1_to_upstream() {
    let (seen, client, entry) = through_proxy_protocol(1).await;
    assert_eq!(
        String::from_utf8_lossy(&seen.raw),
        format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            client.ip(),
            entry.ip(),
            client.port(),
            entry.port()
        )
    );
    assert_eq!(seen.header.source(), Some(client));
    assert_eq!(seen.header.destination(), Some(entry));
}

#[tokio::test]
async fn l4_proxy_protocol_v2_to_upstream() {
    let (seen, client, entry) = through_proxy_protocol(2).await;
    assert_eq!(&seen.raw[..12], b"\r\n\r\n\0\r\nQUIT\n", "the v2 signature");
    assert_eq!(seen.raw[12], 0x21, "version 2, command PROXY");
    assert_eq!(seen.header.source(), Some(client));
    assert_eq!(seen.header.destination(), Some(entry));
}

#[tokio::test]
async fn l4_proxy_protocol_carries_the_fronted_source() {
    let podgate =
        Podgate::start_with_entry_points(&[("web", "http"), ("pg", "tcp;proxy_protocol")], &[])
            .await;
    let (up, seen) = header_server().await;
    let mut pushed = reserved(
        1,
        &[tcp_app(
            &servers_of(&[up.addr]),
            &json!({}),
            &json!({ "proxy_protocol": { "version": 2 } }),
            &[],
        )],
    );
    pushed["entry_points"] = json!([{ "name": "pg", "tenants": ["t1"], "proxy_protocol": { "trusted_ips": ["127.0.0.1"] } }]);
    push(&podgate, &pushed).await;
    let mut client = connect(&podgate).await;
    client
        .write_all(b"PROXY TCP4 203.0.113.9 127.0.0.1 40001 5432\r\nhello\n")
        .await
        .expect("write");
    assert_eq!(line(&mut client).await.as_deref(), Some("got:hello"));
    let header = seen
        .lock()
        .expect("lock")
        .first()
        .cloned()
        .expect("a header")
        .header;
    assert_eq!(
        header.source(),
        Some("203.0.113.9:40001".parse().expect("address")),
        "the address behind the entry point's header, not the peer's"
    );
}

/// The bytes a TLS client sends first: its ClientHello for `name`, built by rustls.
fn hello(name: &str) -> Vec<u8> {
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let server = ServerName::try_from(name.to_owned()).expect("server name");
    let mut connection = rustls::ClientConnection::new(Arc::new(config), server).expect("client");
    let mut bytes = Vec::new();
    connection.write_tls(&mut bytes).expect("ClientHello");
    bytes
}

#[tokio::test]
async fn l4_proxy_protocol_header_comes_before_a_passthrough_hello() {
    let podgate = start().await;
    let after = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let record = Arc::clone(&after);
    let up = serve(move |mut stream| {
        let record = Arc::clone(&record);
        async move {
            let Some((_, mut rest)) = read_header(&mut stream).await else {
                return;
            };
            let mut chunk = [0_u8; 256];
            while rest.len() < 3 {
                match timeout(WAIT, stream.read(&mut chunk)).await {
                    Ok(Ok(read)) if read > 0 => rest.extend_from_slice(&chunk[..read]),
                    _ => return,
                }
            }
            record.lock().expect("lock").push(rest);
        }
    })
    .await;
    let mut tls_router = json!({ "chain": [], "tls": { "passthrough": true } });
    tls_router["match"] = json!({ "sni": "a.test" });
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[up.addr]),
                &tls_router,
                &json!({ "proxy_protocol": { "version": 2 } }),
                &[],
            )],
        ),
    )
    .await;
    let mut client = connect(&podgate).await;
    client
        .write_all(&hello("a.test"))
        .await
        .expect("ClientHello");
    let deadline = Instant::now() + WAIT;
    while after.lock().expect("lock").is_empty() {
        assert!(Instant::now() < deadline, "the server never saw a hello");
        sleep(Duration::from_millis(20)).await;
    }
    let rest = after.lock().expect("lock")[0].clone();
    assert_eq!(
        &rest[..2],
        [0x16, 0x03],
        "a TLS handshake record follows the header"
    );
}

/// A private certificate authority.
struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    pem: String,
}

/// A certificate (chain) and its key, PEM.
struct Leaf {
    cert_pem: String,
    key_pem: String,
}

impl Ca {
    fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("CA key"))
            .expect("self-signed CA");
        let pem = issuer.pem();
        Self { issuer, pem }
    }

    fn issue(&self, names: &[&str]) -> Leaf {
        let key = KeyPair::generate().expect("leaf key");
        let params = CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("leaf params");
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }
}

fn digest(der: &CertificateDer<'_>) -> String {
    Sha256::digest(der.as_ref())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A TLS server that requires a client certificate of `client_ca` and greets with
/// `sni=<name the client asked for> client=<digest of its certificate>`, then echoes.
async fn tls_server(server: &Leaf, client_ca: &Ca) -> Server {
    let provider = Arc::new(default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(client_ca.pem.as_bytes()).expect("CA DER"))
        .expect("trust the CA");
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .expect("client verifier");
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(server.cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .expect("server chain");
    let key = PrivateKeyDer::from_pem_slice(server.key_pem.as_bytes()).expect("key");
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    serve(move |tcp| {
        let acceptor = acceptor.clone();
        async move {
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                return;
            };
            let (_, connection) = stream.get_ref();
            let greeting = format!(
                "sni={} client={}\n",
                connection.server_name().unwrap_or("none"),
                connection
                    .peer_certificates()
                    .and_then(|chain| chain.first().map(digest))
                    .unwrap_or_else(|| "none".to_owned()),
            );
            if stream.write_all(greeting.as_bytes()).await.is_err() {
                return;
            }
            let mut buf = [0_u8; 1024];
            while let Ok(read) = stream.read(&mut buf).await {
                if read == 0 || stream.write_all(&buf[..read]).await.is_err() {
                    return;
                }
            }
        }
    })
    .await
}

fn transport(name: &str, config: &Value) -> Value {
    common::middleware(name, "servers_transport", config.clone())
}

#[tokio::test]
async fn l4_upstream_tls_with_transport() {
    let podgate = start().await;
    let server_ca = Ca::new("server ca");
    let client_ca = Ca::new("client ca");
    let server = server_ca.issue(&["db.internal"]);
    let client = client_ca.issue(&[]);
    let client_der = CertificateDer::from_pem_slice(client.cert_pem.as_bytes()).expect("DER");
    let up = tls_server(&server, &client_ca).await;
    let tls_servers = [json!({ "address": up.addr.to_string(), "tls": true })];
    let app_with = |transport_config: &Value| {
        let mut app = tcp_app(
            &tls_servers,
            &json!({}),
            &json!({ "transport": "internal" }),
            &[],
        );
        app["transports"] = json!([transport("internal", transport_config)]);
        app
    };
    let complete = json!({
        "server_name": "db.internal",
        "ca_pem": server_ca.pem,
        "client_cert": { "cert_pem": client.cert_pem, "key_pem": client.key_pem },
    });
    push(&podgate, &reserved(1, &[app_with(&complete)])).await;
    let mut stream = connect(&podgate).await;
    assert_eq!(
        line(&mut stream).await,
        Some(format!("sni=db.internal client={}", digest(&client_der))),
        "the server saw the transport's name and client certificate, and its certificate verified against the transport's CA"
    );
    stream.write_all(b"ping").await.expect("write");
    let mut echoed = [0_u8; 4];
    timeout(WAIT, stream.read_exact(&mut echoed))
        .await
        .expect("in time")
        .expect("echo");
    assert_eq!(&echoed, b"ping", "plain bytes in, plain bytes out");
    drop(stream);

    // Each setting is the transport's. Without the client certificate the server ends the
    // connection after the handshake (TLS 1.3 reports a missing certificate to the client only
    // after its handshake is done), so no byte reaches the client. With another CA the server's
    // certificate is not trusted, the handshake fails, and the connection counts as `no_server`.
    let no_server = || async { metric(&podgate, &refused("no_server")).await };
    let before = no_server().await;
    let mut no_cert = complete.clone();
    no_cert
        .as_object_mut()
        .expect("object")
        .remove("client_cert");
    let mut wrong_ca = complete.clone();
    wrong_ca["ca_pem"] = json!(client_ca.pem);
    for (version, transport_config) in [(2, &no_cert), (3, &wrong_ca)] {
        push(&podgate, &reserved(version, &[app_with(transport_config)])).await;
        let mut stream = connect(&podgate).await;
        assert!(
            closed_without_data(&mut stream).await,
            "{transport_config} must not be served"
        );
    }
    assert_eq!(no_server().await, before + 1, "only the untrusted server");

    // `insecure_skip_verify` accepts the unknown CA and still sends the client certificate.
    let mut insecure = complete.clone();
    insecure.as_object_mut().expect("object").remove("ca_pem");
    insecure["insecure_skip_verify"] = json!(true);
    push(&podgate, &reserved(4, &[app_with(&insecure)])).await;
    let mut stream = connect(&podgate).await;
    assert_eq!(
        line(&mut stream).await,
        Some(format!("sni=db.internal client={}", digest(&client_der)))
    );
}

#[tokio::test]
async fn l4_upstream_transport_settings_are_checked() {
    let podgate = start().await;
    let up = greeter("up").await;
    let servers = servers_of(&[up.addr]);
    let refusal = |app: Value| {
        let podgate = &podgate;
        async move {
            let response = podgate.push_snapshot(&reserved(1, &[app])).await;
            assert_eq!(response.status, 422, "{}", response.body);
            response.body
        }
    };
    let mut named = tcp_app(&servers, &json!({}), &json!({ "transport": "t" }), &[]);
    named["transports"] = json!([transport("t", &json!({ "http2": false }))]);
    let body = refusal(named).await;
    assert!(body.contains("invalid_transport"), "{body}");
    let mut with_header = tcp_app(&servers, &json!({}), &json!({ "transport": "t" }), &[]);
    with_header["transports"] = json!([transport(
        "t",
        &json!({ "proxy_protocol": { "version": 1 } })
    )]);
    let body = refusal(with_header).await;
    assert!(body.contains("invalid_transport"), "{body}");
    let body = refusal(tcp_app(
        &servers,
        &json!({}),
        &json!({ "transport": "missing" }),
        &[],
    ))
    .await;
    assert!(body.contains("unknown_transport"), "{body}");
    // TLS settings with a plain server mean nothing and are refused rather than ignored.
    let mut plain = tcp_app(&servers, &json!({}), &json!({ "transport": "t" }), &[]);
    plain["transports"] = json!([transport("t", &json!({ "server_name": "db.internal" }))]);
    let body = refusal(plain).await;
    assert!(body.contains("invalid_service"), "{body}");
}

#[tokio::test]
async fn l4_middleware_declarations_are_checked() {
    let podgate = start().await;
    let up = greeter("up").await;
    let servers = servers_of(&[up.addr]);
    let office = middleware(
        "office",
        "ip_allow_list",
        &json!({ "source_range": ["10.0.0.0/8"] }),
    );
    let cases = [
        (
            "an unknown name in the chain",
            tcp_app(
                &servers,
                &json!({ "chain": ["nope"] }),
                &json!({}),
                std::slice::from_ref(&office),
            ),
            "unknown_middleware_ref",
        ),
        (
            "an HTTP middleware kind",
            tcp_app(
                &servers,
                &json!({ "chain": ["h"] }),
                &json!({}),
                &[middleware("h", "headers", &json!({}))],
            ),
            "invalid_middleware",
        ),
        (
            "a cap of zero",
            tcp_app(
                &servers,
                &json!({ "chain": ["cap"] }),
                &json!({}),
                &[middleware("cap", "in_flight_conn", &json!({ "amount": 0 }))],
            ),
            "invalid_middleware",
        ),
        (
            "a name listed twice in a chain",
            tcp_app(
                &servers,
                &json!({ "chain": ["office", "office"] }),
                &json!({}),
                &[office],
            ),
            "duplicate_name",
        ),
    ];
    for (what, app, code) in cases {
        let response = podgate.push_snapshot(&reserved(1, &[app])).await;
        assert_eq!(response.status, 422, "{what}: {}", response.body);
        assert!(response.body.contains(code), "{what}: {}", response.body);
    }
}

/// A server that waits for the client's FIN, then sends `late` after `delay`.
async fn late_replier(delay: Duration) -> Server {
    serve(move |mut stream| async move {
        let mut request = Vec::new();
        if stream.read_to_end(&mut request).await.is_err() {
            return;
        }
        sleep(delay).await;
        drop(stream.write_all(b"late").await);
    })
    .await
}

/// Sends a request, half-closes, and returns what the client receives until the connection ends.
async fn half_close_and_read(podgate: &Podgate) -> Vec<u8> {
    let mut client = connect(podgate).await;
    client.write_all(b"request").await.expect("write");
    client.shutdown().await.expect("client FIN");
    let mut reply = Vec::new();
    timeout(WAIT, client.read_to_end(&mut reply))
        .await
        .expect("the connection ends")
        .ok();
    reply
}

#[tokio::test]
async fn l4_termination_delay() {
    let podgate = start().await;
    let up = late_replier(Duration::from_millis(400)).await;
    let app = |service: Value| tcp_app(&servers_of(&[up.addr]), &json!({}), &service, &[]);
    // A delay longer than the server's lets the late reply through.
    push(
        &podgate,
        &reserved(1, &[app(json!({ "termination_delay_ms": 3000 }))]),
    )
    .await;
    assert_eq!(half_close_and_read(&podgate).await, b"late");
    // A shorter one cuts it, and the close is counted.
    push(
        &podgate,
        &reserved(2, &[app(json!({ "termination_delay_ms": 50 }))]),
    )
    .await;
    assert!(half_close_and_read(&podgate).await.is_empty());
    // Absent, the delay is 100 ms.
    push(&podgate, &reserved(3, &[app(json!({}))])).await;
    assert!(half_close_and_read(&podgate).await.is_empty());
    let deadline = Instant::now() + WAIT;
    let closed = "podgate_tcp_closed_total{reason=\"termination_delay\"}";
    while metric(&podgate, closed).await < 2 {
        assert!(
            Instant::now() < deadline,
            "the cut connections were not counted"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn plan_lists_l4_middleware_changes() {
    let podgate = start().await;
    let up = greeter("up").await;
    let servers = servers_of(&[up.addr]);
    let office = |ranges: Value| {
        middleware(
            "office",
            "ip_allow_list",
            &json!({ "source_range": ranges }),
        )
    };
    let cap = |amount: u32, bits: u8| {
        middleware(
            "cap",
            "in_flight_conn",
            &json!({ "amount": amount, "source": { "ip": { "ipv6_subnet_bits": bits } } }),
        )
    };
    let guarded = |office: Value, cap: Value, chain: Value| {
        tcp_app(
            &servers,
            &json!({ "chain": chain }),
            &json!({}),
            &[office, cap],
        )
    };
    push(
        &podgate,
        &reserved(
            1,
            &[guarded(
                office(json!(["203.0.113.0/24"])),
                cap(5, 64),
                json!(["office", "cap"]),
            )],
        ),
    )
    .await;
    let kinds = |plan: &common::Response| -> Vec<(String, String)> {
        plan.json()["posture_changes"]
            .as_array()
            .expect("posture_changes")
            .iter()
            .map(|change| {
                (
                    change["host"].as_str().expect("host").to_owned(),
                    change["kind"].as_str().expect("kind").to_owned(),
                )
            })
            .collect()
    };
    let plan = |apps: &[Value]| {
        let podgate = &podgate;
        let pushed = reserved(2, apps);
        async move {
            let response = podgate.admin_post("/v1/snapshot/plan", &pushed).await;
            assert_eq!(response.status, 200, "{}", response.body);
            response
        }
    };
    let host = |kind: &str| ("tcp:t".to_owned(), kind.to_owned());

    let loosened = plan(&[guarded(
        office(json!(["203.0.113.0/24", "198.51.100.0/24"])),
        cap(6, 64),
        json!(["office", "cap"]),
    )])
    .await;
    let mut got = kinds(&loosened);
    got.sort();
    assert_eq!(
        got,
        [
            host("in_flight_conn_loosened"),
            host("ip_allow_list_widened")
        ]
    );

    let narrowed = plan(&[guarded(
        office(json!(["203.0.113.0/25"])),
        cap(4, 64),
        json!(["office", "cap"]),
    )])
    .await;
    assert!(kinds(&narrowed).is_empty(), "tightening is not listed");

    let source = plan(&[guarded(
        office(json!(["203.0.113.0/24"])),
        cap(5, 128),
        json!(["office", "cap"]),
    )])
    .await;
    assert_eq!(kinds(&source), [host("in_flight_conn_source_changed")]);

    let unchained = plan(&[guarded(
        office(json!(["203.0.113.0/24"])),
        cap(5, 64),
        json!([]),
    )])
    .await;
    let mut got = kinds(&unchained);
    got.sort();
    assert_eq!(
        got,
        [
            host("in_flight_conn_removed"),
            host("ip_allow_list_removed")
        ],
        "a middleware left out of every chain no longer runs"
    );

    let gone = plan(&[tcp_app(&servers, &json!({}), &json!({}), &[])]).await;
    let mut got = kinds(&gone);
    got.sort();
    assert_eq!(
        got,
        [
            host("in_flight_conn_removed"),
            host("ip_allow_list_removed")
        ]
    );

    // Nothing was applied: the live table still has the guarded router.
    let mut third = connect(&podgate).await;
    assert!(
        closed_without_data(&mut third).await,
        "the allow list is still live"
    );
}
