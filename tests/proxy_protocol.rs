//! PROXY protocol on entry points, against the real binary.
//!
//! `edge` is a plain entry point and `secure` a TLS one, both with `;proxy_protocol`; `plain` has
//! none. The test client connects from `127.0.0.1`, and the snapshot's `proxy_protocol` policy
//! decides whether that peer may send a header. The upstream echoes the request headers it saw,
//! which is how a test sees the client address podgate believes.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Podgate, TestCert, app, serving, snapshot};
use podgate::entry::proxy_protocol::{Addresses, Header, Version};
use rustls::pki_types::CertificateDer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const ENTRIES: [(&str, &str); 3] = [
    ("edge", "http;proxy_protocol"),
    ("secure", "https;proxy_protocol"),
    ("plain", "http"),
];
const ALPN01: &[u8] = b"acme-tls/1";
const ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A backend that answers with every request header it saw, as `name: value` lines.
struct Echo {
    addr: SocketAddr,
}

impl Echo {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(echo(stream));
            }
        });
        Self { addr }
    }
}

async fn echo(mut stream: TcpStream) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            seen.drain(..end + 4);
            let mut body = String::new();
            for line in head.split("\r\n").skip(1) {
                body.push_str(line);
                body.push('\n');
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// The one value of echoed header `name`; panics when it was sent zero or several times.
fn one(body: &str, name: &str) -> String {
    let values: Vec<String> = body
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
        .collect();
    assert_eq!(values.len(), 1, "{name} must be sent exactly once: {body}");
    values.into_iter().next().unwrap_or_default()
}

fn address(text: &str) -> SocketAddr {
    text.parse().expect("socket address")
}

/// The header a balancer would send for a client at `source`.
fn header(version: Version, source: &str) -> Vec<u8> {
    let destination = if address(source).is_ipv4() {
        "192.0.2.1:443"
    } else {
        "[2001:db8::1]:443"
    };
    let header = Header::Proxied {
        addresses: Addresses::new(address(source), address(destination)).expect("one family"),
        authority: None,
    };
    let mut out = Vec::new();
    header.encode(version, &mut out).expect("encodes");
    out
}

fn local(version: Version) -> Vec<u8> {
    let mut out = Vec::new();
    Header::Local.encode(version, &mut out).expect("encodes");
    out
}

/// A snapshot with app `a` (`a.test`) in front of `echo`, a certificate for it, and `policies`.
fn pushed(version: u64, echo: &Echo, cert: &TestCert, policies: &Value) -> Value {
    let mut pushed = snapshot(
        version,
        &[app("a", &["a.test"], &[serving("r1", echo.addr)])],
    );
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    pushed["entry_points"] = policies.clone();
    pushed
}

fn trusting(peers: &[&str]) -> Value {
    json!([
        {"name": "edge", "proxy_protocol": {"trusted_ips": peers}},
        {"name": "secure", "proxy_protocol": {"trusted_ips": peers}},
    ])
}

struct World {
    podgate: Podgate,
    echo: Echo,
    cert: TestCert,
}

impl World {
    /// A node whose entry points trust `127.0.0.1` to send PROXY headers.
    async fn start() -> Self {
        let world = Self::start_empty().await;
        world.push(1, &trusting(&["127.0.0.0/8"])).await;
        world
    }

    async fn start_empty() -> Self {
        Self {
            podgate: Podgate::start_with_entry_points(&ENTRIES, &[("NODE_NAME", "other")]).await,
            echo: Echo::start().await,
            cert: TestCert::new(&["a.test"]),
        }
    }

    async fn push(&self, version: u64, policies: &Value) {
        let response = self
            .podgate
            .push_snapshot(&pushed(version, &self.echo, &self.cert, policies))
            .await;
        assert_eq!(response.status, 200, "{response:?}");
    }

    fn edge(&self) -> SocketAddr {
        self.podgate.entry_addr("edge")
    }

    fn secure(&self) -> SocketAddr {
        self.podgate.entry_addr("secure")
    }
}

const GET: &str = "GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n";

/// Everything the peer sends back to `preamble` and then `request` on a plain connection, until
/// it closes. Empty when the connection was closed without an answer.
async fn plain_exchange(addr: SocketAddr, preamble: &[u8], request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    // A peer that closes early may reset the connection under the write; the read tells.
    drop(
        stream
            .write_all(&[preamble, request.as_bytes()].concat())
            .await,
    );
    let mut raw = Vec::new();
    let read = timeout(IO_TIMEOUT, stream.read_to_end(&mut raw)).await;
    assert!(read.is_ok(), "the connection must end, not hang");
    String::from_utf8_lossy(&raw).into_owned()
}

fn body_of(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

/// The echo of a `GET /` to `a.test` on the plain entry point after `preamble`.
async fn echo_via(addr: SocketAddr, preamble: &[u8]) -> String {
    let response = plain_exchange(addr, preamble, GET).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
    body_of(&response).to_owned()
}

async fn is_closed(addr: SocketAddr, bytes: &[u8]) -> bool {
    plain_exchange(addr, bytes, "").await.is_empty()
}

/// Accepts any certificate: these tests are about what comes before the handshake.
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

type Client = tokio_rustls::client::TlsStream<TcpStream>;

/// Connects, writes `preamble` as raw bytes, then runs a TLS handshake for `a.test` offering
/// `alpn` (none: the default).
async fn tls_after(addr: SocketAddr, preamble: &[u8], alpn: &[&[u8]]) -> std::io::Result<Client> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let name = rustls::pki_types::ServerName::try_from("a.test").expect("name");
    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    tcp.write_all(preamble).await.expect("write the header");
    timeout(
        IO_TIMEOUT,
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .expect("the handshake ends in time")
}

/// The echo of a `GET /` to `a.test` over TLS after `preamble`.
async fn tls_echo_via(addr: SocketAddr, preamble: &[u8]) -> String {
    let mut tls = tls_after(addr, preamble, &[])
        .await
        .expect("the handshake follows the header");
    tls.write_all(GET.as_bytes()).await.expect("send");
    let mut raw = Vec::new();
    drop(timeout(IO_TIMEOUT, tls.read_to_end(&mut raw)).await);
    let response = String::from_utf8_lossy(&raw).into_owned();
    assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
    body_of(&response).to_owned()
}

#[tokio::test]
async fn pp_sets_client_address() {
    let world = World::start().await;
    let cases = [
        (header(Version::V1, "203.0.113.9:4000"), "203.0.113.9"),
        (header(Version::V2, "203.0.113.10:4000"), "203.0.113.10"),
        (header(Version::V1, "[2001:db8::9]:4000"), "2001:db8::9"),
        (header(Version::V2, "[2001:db8::a]:4000"), "2001:db8::a"),
        (
            b"PROXY TCP4 198.51.100.4 192.0.2.1 65535 80\r\n".to_vec(),
            "198.51.100.4",
        ),
        (local(Version::V1), "127.0.0.1"),
        (local(Version::V2), "127.0.0.1"),
        (b"PROXY UNKNOWN\r\n".to_vec(), "127.0.0.1"),
    ];
    for (preamble, expected) in cases {
        let body = echo_via(world.edge(), &preamble).await;
        assert_eq!(one(&body, "x-forwarded-for"), expected, "{preamble:?}");
    }
}

#[tokio::test]
async fn pp_forwarded_headers_use_proxy_address() {
    let world = World::start().await;
    for version in [Version::V1, Version::V2] {
        let preamble = header(version, "203.0.113.9:4000");
        let plain = echo_via(world.edge(), &preamble).await;
        let tls = tls_echo_via(world.secure(), &preamble).await;
        for (listener, body, proto) in [("plain", plain, "http"), ("TLS", tls, "https")] {
            assert_eq!(
                one(&body, "x-forwarded-for"),
                "203.0.113.9",
                "{listener} {version:?}: {body}"
            );
            assert_eq!(
                one(&body, "x-real-ip"),
                "203.0.113.9",
                "{listener} {version:?}: {body}"
            );
            assert_eq!(one(&body, "x-forwarded-proto"), proto, "{listener}: {body}");
        }
    }
    // A client that forges the headers is not believed: the address the header carries is the
    // peer, and it is not trusted to speak for others.
    let forged = "GET / HTTP/1.1\r\nHost: a.test\r\nX-Forwarded-For: 1.2.3.4\r\n\
                  X-Real-IP: 9.9.9.9\r\nConnection: close\r\n\r\n";
    let response =
        plain_exchange(world.edge(), &header(Version::V2, "203.0.113.9:1"), forged).await;
    let body = body_of(&response);
    assert_eq!(one(body, "x-forwarded-for"), "203.0.113.9", "{body}");
    assert!(
        !body.contains("1.2.3.4") && !body.contains("9.9.9.9"),
        "{body}"
    );
}

#[tokio::test]
async fn pp_forwarded_trust_is_judged_on_the_proxy_address() {
    let world = World::start().await;
    // The TCP peer is 127.0.0.1; only the address in the header is in this list.
    let mut policies = trusting(&["127.0.0.0/8"]);
    policies[0]["forwarded_headers"] = json!({"trusted_ips": ["203.0.113.0/24"]});
    world.push(2, &policies).await;
    let request = "GET / HTTP/1.1\r\nHost: a.test\r\nX-Forwarded-For: 198.51.100.5\r\n\
                   Connection: close\r\n\r\n";

    let trusted =
        plain_exchange(world.edge(), &header(Version::V2, "203.0.113.9:1"), request).await;
    assert_eq!(
        one(body_of(&trusted), "x-forwarded-for"),
        "198.51.100.5, 203.0.113.9",
        "{trusted}"
    );
    let untrusted = plain_exchange(
        world.edge(),
        &header(Version::V2, "198.51.100.77:1"),
        request,
    )
    .await;
    assert_eq!(
        one(body_of(&untrusted), "x-forwarded-for"),
        "198.51.100.77",
        "{untrusted}"
    );
}

#[tokio::test]
async fn pp_header_is_read_once_per_connection() {
    let world = World::start().await;
    let mut stream = TcpStream::connect(world.edge()).await.expect("connect");
    let request = "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";
    stream
        .write_all(
            &[
                &header(Version::V2, "203.0.113.9:1")[..],
                request.as_bytes(),
            ]
            .concat(),
        )
        .await
        .expect("first request");
    for round in 0..3 {
        if round > 0 {
            stream
                .write_all(request.as_bytes())
                .await
                .expect("next request");
        }
        let mut raw = Vec::new();
        let mut chunk = [0_u8; 4096];
        let text = loop {
            let read = timeout(IO_TIMEOUT, stream.read(&mut chunk))
                .await
                .expect("an answer in time")
                .expect("read");
            assert!(read > 0, "the connection closed after {round} requests");
            raw.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&raw).into_owned();
            let length = text
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .and_then(|value| value.trim().parse::<usize>().ok());
            if let (Some(length), Some((_, body))) = (length, text.split_once("\r\n\r\n"))
                && body.len() >= length
            {
                break text;
            }
        };
        assert!(text.starts_with("HTTP/1.1 200"), "round {round}: {text:?}");
        assert_eq!(
            one(body_of(&text), "x-forwarded-for"),
            "203.0.113.9",
            "round {round}"
        );
    }
}

#[tokio::test]
async fn pp_untrusted_peer_closed() {
    let world = World::start().await;
    let valid = header(Version::V2, "203.0.113.9:4000");
    assert!(!is_closed(world.edge(), &[&valid[..], GET.as_bytes()].concat()).await);

    world.push(2, &trusting(&["10.0.0.0/8"])).await;
    for version in [Version::V1, Version::V2] {
        let preamble = [&header(version, "203.0.113.9:4000")[..], GET.as_bytes()].concat();
        assert!(
            is_closed(world.edge(), &preamble).await,
            "{version:?} from a peer outside trusted_ips"
        );
    }
    let tls = tls_after(world.secure(), &valid, &[]).await;
    assert!(tls.is_err(), "the TLS entry point refuses it too");

    // No policy at all trusts nobody.
    world.push(3, &json!([])).await;
    assert!(is_closed(world.edge(), &[&valid[..], GET.as_bytes()].concat()).await);

    // `insecure` trusts every peer, which is what makes it a posture change.
    world
        .push(
            4,
            &json!([{"name": "edge", "proxy_protocol": {"insecure": true}}]),
        )
        .await;
    let body = echo_via(world.edge(), &valid).await;
    assert_eq!(one(&body, "x-forwarded-for"), "203.0.113.9");
}

#[tokio::test]
async fn pp_malformed_closed() {
    let world = World::start().await;
    let valid = header(Version::V2, "203.0.113.9:4000");
    let mut v2_oversize = valid[..12].to_vec();
    v2_oversize.extend_from_slice(&[0x21, 0x11, 0x08, 0x01]);
    v2_oversize.resize(16 + 2049, 0);
    let mut v2_version_1 = valid.clone();
    v2_version_1[12] = 0x11;
    let mut v2_udp = valid.clone();
    v2_udp[13] = 0x12;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("no header", GET.as_bytes().to_vec()),
        ("garbage", b"hello world\r\n\r\n".to_vec()),
        (
            "a TLS ClientHello",
            vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01],
        ),
        (
            "a v1 line with no end",
            [b"PROXY TCP4 ".to_vec(), vec![b'1'; 120]].concat(),
        ),
        (
            "a v1 line over 107 bytes",
            [
                b"PROXY UNKNOWN ".to_vec(),
                vec![b'x'; 100],
                b"\r\n".to_vec(),
            ]
            .concat(),
        ),
        (
            "a v1 line with a bare LF",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n".to_vec(),
        ),
        (
            "a v1 family mismatch",
            b"PROXY TCP4 2001:db8::1 5.6.7.8 1 2\r\n".to_vec(),
        ),
        (
            "a v1 port with a sign",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 +1 2\r\n".to_vec(),
        ),
        ("a v2 header over 2 KiB", v2_oversize),
        ("a v2 header of version 1", v2_version_1),
        ("a v2 datagram transport", v2_udp),
        ("a v2 header cut short", valid[..valid.len() - 1].to_vec()),
        (
            "a v1 header cut short",
            header(Version::V1, "203.0.113.9:4000")[..20].to_vec(),
        ),
    ];
    for (name, bytes) in cases {
        let mut stream = TcpStream::connect(world.edge()).await.expect("connect");
        drop(stream.write_all(&bytes).await);
        // A cut header is only known to be cut once the peer stops sending.
        drop(stream.shutdown().await);
        let mut raw = Vec::new();
        let read = timeout(IO_TIMEOUT, stream.read_to_end(&mut raw)).await;
        assert!(read.is_ok(), "{name}: the connection must end");
        assert!(
            raw.is_empty(),
            "{name}: answered {:?}",
            String::from_utf8_lossy(&raw)
        );
        // And on the TLS entry point: no handshake follows.
        let tls = tls_after(world.secure(), &bytes, &[]).await;
        assert!(
            tls.is_err(),
            "{name}: the TLS entry point completed a handshake"
        );
    }
    // A good connection still works, and the entry point without the option is untouched.
    let body = echo_via(world.edge(), &valid).await;
    assert_eq!(one(&body, "x-forwarded-for"), "203.0.113.9");
    let plain = plain_exchange(world.podgate.entry_addr("plain"), b"", GET).await;
    assert!(plain.starts_with("HTTP/1.1 200"), "{plain:?}");
}

#[tokio::test]
async fn pp_deadline_closes() {
    let world = World::start().await;
    let started = Instant::now();
    let mut silent = TcpStream::connect(world.edge()).await.expect("connect");
    let mut stalled = TcpStream::connect(world.edge()).await.expect("connect");
    stalled
        .write_all(b"PROXY TCP4 203.0.113.9 192.0.2")
        .await
        .expect("start a header");
    for (name, stream) in [("silent", &mut silent), ("stalled", &mut stalled)] {
        let mut raw = Vec::new();
        let read = timeout(Duration::from_secs(8), stream.read_to_end(&mut raw)).await;
        assert!(read.is_ok(), "{name}: still open after 8 s");
        assert!(raw.is_empty(), "{name}: {raw:?}");
    }
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(2500) && waited < Duration::from_secs(7),
        "closed after {waited:?}, expected the 3 s deadline"
    );
}

#[tokio::test]
async fn pp_before_tls_handshake() {
    let world = World::start().await;
    for version in [Version::V1, Version::V2] {
        let body = tls_echo_via(world.secure(), &header(version, "203.0.113.9:4000")).await;
        assert_eq!(one(&body, "x-forwarded-for"), "203.0.113.9", "{version:?}");
    }
    // The handshake bytes alone are not a header, so the entry point never starts the handshake.
    assert!(tls_after(world.secure(), b"", &[]).await.is_err());
}

fn digest_of(key_authorization: &str) -> Vec<u8> {
    let mut value = vec![0x04, 0x20];
    value.extend_from_slice(&Sha256::digest(key_authorization.as_bytes()));
    value
}

fn acme_identifier(der: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parses");
    cert.extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == ACME_IDENTIFIER)
        .map(|extension| extension.value.to_vec())
}

#[tokio::test]
async fn pp_with_acme_hook() {
    // A node that holds a pushed TLS-ALPN-01 answer for a.test: the pre-TLS hook of the TLS entry
    // point reads the ClientHello and answers `acme-tls/1` itself. With the PROXY gate in front,
    // the header must be consumed first or the hook reads it as a ClientHello and gives up.
    let world = World::start_empty().await;
    let mut alpn_app = app("a", &["a.test"], &[serving("r1", world.echo.addr)]);
    alpn_app["tls"]["challenge"] = json!("tls-alpn-01");
    let mut pushed = snapshot(1, &[alpn_app]);
    pushed["entry_points"] = trusting(&["127.0.0.0/8"]);
    pushed["acme"] = json!({
        "issuer_node": "n1",
        "directory_url": "https://127.0.0.1:1/dir",
        "challenges": [{"name": "a.test", "key_authorization": "tok.a"}],
    });
    let response = world.podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");

    let preamble = header(Version::V2, "203.0.113.9:4000");
    let tls = tls_after(world.secure(), &preamble, &[ALPN01])
        .await
        .expect("the challenge handshake follows the header");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(ALPN01),
        "the hook answered acme-tls/1"
    );
    let leaf = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(<[_]>::first)
        .expect("a certificate")
        .clone()
        .into_owned();
    assert_eq!(acme_identifier(&leaf), Some(digest_of("tok.a")));

    assert!(
        tls_after(world.secure(), b"", &[ALPN01]).await.is_err(),
        "the same handshake without a header is closed"
    );
}

#[tokio::test]
async fn plan_lists_proxy_protocol_insecure() {
    let world = World::start().await;
    let plan = |version: u64, policies: Value| {
        let pushed = pushed(version, &world.echo, &world.cert, &policies);
        let podgate = &world.podgate;
        async move {
            let plan = podgate.admin_post("/v1/snapshot/plan", &pushed).await;
            assert_eq!(plan.status, 200, "{}", plan.body);
            plan.json()["posture_changes"].clone()
        }
    };

    assert_eq!(
        plan(
            2,
            json!([{"name": "edge", "proxy_protocol": {"insecure": true}}])
        )
        .await,
        json!([{"host": "entry_point:edge", "app": "", "kind": "proxy_protocol_insecure"}])
    );
    assert_eq!(
        plan(2, trusting(&["127.0.0.0/8", "10.0.0.0/8"])).await,
        json!([
            {"host": "entry_point:edge", "app": "", "kind": "proxy_protocol_trusted_ips_widened"},
            {"host": "entry_point:secure", "app": "", "kind": "proxy_protocol_trusted_ips_widened"},
        ])
    );
    assert_eq!(
        plan(2, trusting(&["127.0.0.1"])).await,
        json!([]),
        "narrowing is not a relaxation"
    );

    // Applying it changes who may send a header, and a plan alone changed nothing.
    let valid = header(Version::V2, "203.0.113.9:4000");
    assert!(!is_closed(world.edge(), &[&valid[..], GET.as_bytes()].concat()).await);
    world
        .push(
            2,
            &json!([{"name": "edge", "proxy_protocol": {"insecure": true}}]),
        )
        .await;
    assert_eq!(
        plan(
            3,
            json!([{"name": "edge", "proxy_protocol": {"insecure": true}}])
        )
        .await,
        json!([]),
        "an unchanged insecure policy is not a new relaxation"
    );
}

#[tokio::test]
async fn pp_policy_must_match_the_entry_point() {
    let world = World::start().await;
    let world = &world;
    let refused = |policies: Value| async move {
        let response = world
            .podgate
            .push_snapshot(&pushed(2, &world.echo, &world.cert, &policies))
            .await;
        assert_eq!(response.status, 422, "{response:?}");
        response.json()["conflicts"][0]["code"].clone()
    };
    assert_eq!(
        refused(json!([{"name": "plain", "proxy_protocol": {"trusted_ips": ["127.0.0.1"]}}])).await,
        json!("unsupported_setting"),
        "an entry point without ;proxy_protocol never reads a header"
    );
    assert_eq!(
        refused(json!([{"name": "edge", "proxy_protocol": {"trusted": ["127.0.0.1"]}}])).await,
        json!("invalid_proxy_protocol")
    );
    assert_eq!(
        refused(json!([{"name": "edge", "proxy_protocol": {"trusted_ips": ["not-an-ip"]}}])).await,
        json!("invalid_proxy_protocol")
    );
}
