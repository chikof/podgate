//! TLS on TCP routers through the real binary: passthrough and termination, `sni`,
//! `sni_regexp` and `alpn` routing, who may claim a server name, the dialect check, and the
//! bounds on the ClientHello read.

// The builders take the JSON literal a test writes at the call site by value.
#![allow(clippy::needless_pass_by_value)]
mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{Podgate, TestCa, TestCert, TestClient, app, serving};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// `edge` is shared between tenants, `own` is reserved to `t1` by the snapshot's policy.
const ENTRY_POINTS: [(&str, &str); 3] = [("web", "http"), ("edge", "tcp"), ("own", "tcp")];
const WAIT: Duration = Duration::from_secs(5);

struct Server {
    addr: SocketAddr,
}

async fn serve<F, Fut>(handle: F) -> Server
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let addr = listener.local_addr().expect("server addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle(stream));
        }
    });
    Server { addr }
}

/// Greets with `tag\n` as soon as a client connects, then holds the connection until it ends.
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
        while matches!(stream.read(&mut buf).await, Ok(read) if read > 0) {}
    })
    .await
}

/// Echoes plain bytes, and sends every chunk it receives to the returned channel.
async fn echo() -> (Server, mpsc::UnboundedReceiver<Vec<u8>>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let server = serve(move |mut stream| {
        let sender = sender.clone();
        async move {
            let mut buf = [0_u8; 4096];
            while let Ok(read) = stream.read(&mut buf).await {
                if read == 0 || stream.write_all(&buf[..read]).await.is_err() {
                    return;
                }
                let _ = sender.send(buf[..read].to_vec());
            }
        }
    })
    .await;
    (server, receiver)
}

/// Collects everything a client sends until it half-closes, and reports it once.
async fn recorder() -> (Server, mpsc::UnboundedReceiver<Vec<u8>>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let server = serve(move |mut stream| {
        let sender = sender.clone();
        async move {
            let mut all = Vec::new();
            let _ = stream.read_to_end(&mut all).await;
            let _ = sender.send(all);
        }
    })
    .await;
    (server, receiver)
}

fn server_config(cert: &TestCert) -> ServerConfig {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .expect("certificate chain");
    let key = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).expect("private key");
    ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server config")
}

/// A TLS server with `cert` that echoes what it reads, as a real backend completing its own
/// handshake would.
async fn tls_echo(cert: &TestCert) -> Server {
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert)));
    serve(move |tcp| {
        let acceptor = acceptor.clone();
        async move {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut buf = [0_u8; 4096];
            while let Ok(read) = tls.read(&mut buf).await {
                if read == 0 || tls.write_all(&buf[..read]).await.is_err() {
                    return;
                }
            }
        }
    })
    .await
}

/// A client that trusts `cert`, offers `alpn`, and presents `identity` when asked.
fn client_config(
    cert: &TestCert,
    alpn: &[&str],
    identity: Option<&TestClient>,
    versions: &[&'static SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(cert.der.clone()).expect("trust the certificate");
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(versions)
        .expect("protocol versions")
        .with_root_certificates(roots);
    let mut config = match identity {
        Some(client) => builder
            .with_client_auth_cert(client.chain.clone(), client.key.clone_key())
            .expect("client identity"),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
    Arc::new(config)
}

fn both_versions() -> &'static [&'static SupportedProtocolVersion] {
    rustls::ALL_VERSIONS
}

/// The bytes a TLS client sends first: its ClientHello with `name` (none: no server name) and
/// `alpn`, built by rustls so the test never writes TLS by hand.
fn hello(name: Option<&str>, alpn: &[&str]) -> Vec<u8> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
    let server = match name {
        Some(name) => ServerName::try_from(name.to_owned()).expect("server name"),
        None => ServerName::try_from("192.0.2.1".to_owned()).expect("address"),
    };
    let mut connection = rustls::ClientConnection::new(Arc::new(config), server).expect("client");
    let mut bytes = Vec::new();
    connection.write_tls(&mut bytes).expect("ClientHello");
    bytes
}

async fn tls_connect(
    podgate: &Podgate,
    entry: &str,
    name: &str,
    config: Arc<ClientConfig>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(podgate.entry_addr(entry)).await?;
    let server = ServerName::try_from(name.to_owned()).expect("server name");
    timeout(WAIT, TlsConnector::from(config).connect(server, tcp))
        .await
        .expect("handshake in time")
}

/// Whether `payload` written over `stream` comes back unchanged: the connection is served.
async fn served<S: AsyncReadExt + AsyncWriteExt + Unpin>(stream: &mut S, payload: &[u8]) -> bool {
    let exchange = async {
        stream.write_all(payload).await.ok()?;
        let mut back = vec![0_u8; payload.len()];
        stream.read_exact(&mut back).await.ok()?;
        Some(back)
    };
    matches!(timeout(WAIT, exchange).await, Ok(Some(back)) if back == payload)
}

fn tenant(id: &str) -> Value {
    json!({ "id": id, "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } })
}

/// A snapshot of tenants `t1` and `t2`; the `own` entry point is reserved to `t1`.
fn snap(version: u64, apps: &[Value]) -> Value {
    json!({
        "version": version,
        "tenants": [tenant("t1"), tenant("t2")],
        "entry_points": [{ "name": "own", "tenants": ["t1"] }],
        "apps": apps,
    })
}

fn tcp_app(id: &str, tenant: &str, routers: &[Value], servers: &[(&str, SocketAddr)]) -> Value {
    let services: Vec<Value> = servers
        .iter()
        .map(|(name, addr)| {
            json!({ "name": name, "type": "loadbalancer",
                    "servers": [{ "address": addr.to_string() }] })
        })
        .collect();
    json!({
        "id": id, "tenant": tenant, "declared_by": format!("tests/{id}"),
        "tls": { "mode": "acme" }, "routers": [], "revisions": [],
        "tcp": { "routers": routers, "services": services },
    })
}

/// A TCP router on `entry` to service `service`, with `extra` fields merged in.
fn router(name: &str, entry: &str, service: &str, extra: Value) -> Value {
    let mut value = json!({ "name": name, "entry_points": [entry], "service": service });
    if let (Some(value), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
        value.extend(extra.clone());
    }
    value
}

fn passthrough(matcher: Value) -> Value {
    json!({ "match": matcher, "tls": { "passthrough": true } })
}

async fn start() -> Podgate {
    Podgate::start_with_entry_points(&ENTRY_POINTS, &[]).await
}

async fn push(podgate: &Podgate, pushed: &Value) {
    let response = podgate.push_snapshot(pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// The codes of the `422` a snapshot is refused with.
async fn refusal(podgate: &Podgate, pushed: &Value) -> Vec<String> {
    let response = podgate.push_snapshot(pushed).await;
    assert_eq!(response.status, 422, "{}", response.body);
    response.json()["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|conflict| conflict["code"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// The tag of the server a connection that starts with `first` reaches, `None` when podgate
/// closes it.
async fn tag_for(podgate: &Podgate, entry: &str, first: &[u8]) -> Option<String> {
    let mut stream = TcpStream::connect(podgate.entry_addr(entry))
        .await
        .expect("connect");
    stream.write_all(first).await.expect("write");
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match timeout(WAIT, stream.read(&mut byte)).await {
            Ok(Ok(1)) if byte[0] == b'\n' => {
                return Some(String::from_utf8_lossy(&line).into_owned());
            }
            Ok(Ok(1)) => line.push(byte[0]),
            Ok(Ok(_) | Err(_)) => return None,
            Err(_) => panic!("neither a greeting nor a close after {line:?}"),
        }
    }
}

async fn metric(podgate: &Podgate, series: &str) -> u64 {
    let body = podgate.admin_get("/metrics").await.body;
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("no sample {series} in:\n{body}"))
}

async fn wait_for(podgate: &Podgate, series: &str, wanted: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let value = metric(podgate, series).await;
        if value >= wanted || Instant::now() > deadline {
            return value;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn l4_passthrough_forwards_untouched() {
    let podgate = start().await;
    let cert = TestCert::new(&["a.test"]);
    let backend = tls_echo(&cert).await;
    let routers = [router(
        "pass",
        "edge",
        "svc",
        passthrough(json!({ "sni": "a.test" })),
    )];
    push(
        &podgate,
        &snap(1, &[tcp_app("a", "t1", &routers, &[("svc", backend.addr)])]),
    )
    .await;

    // The backend completes its own handshake: the client verifies the backend's certificate,
    // which podgate does not hold, and the application bytes make the round trip.
    for versions in [both_versions(), &[&rustls::version::TLS12][..]] {
        let config = client_config(&cert, &[], None, versions);
        let mut tls = tls_connect(&podgate, "edge", "a.test", config)
            .await
            .expect("the backend's handshake");
        let presented = tls.get_ref().1.peer_certificates().expect("certificates");
        assert_eq!(presented[0], cert.der, "the certificate is the backend's");
        assert!(served(&mut tls, b"through the proxy").await);
    }

    // Bit for bit: what a server receives is the ClientHello and everything after it.
    let (record, mut seen) = recorder().await;
    let routers = [router(
        "pass",
        "edge",
        "svc",
        passthrough(json!({ "sni": "a.test" })),
    )];
    push(
        &podgate,
        &snap(2, &[tcp_app("a", "t1", &routers, &[("svc", record.addr)])]),
    )
    .await;
    let mut sent = hello(Some("a.test"), &["h2"]);
    sent.extend((0..40_000_u32).map(|n| u8::try_from(n % 251).expect("byte")));
    let mut client = TcpStream::connect(podgate.entry_addr("edge"))
        .await
        .expect("connect");
    client.write_all(&sent).await.expect("send");
    client.shutdown().await.expect("half-close");
    let received = timeout(WAIT, seen.recv())
        .await
        .expect("the recorder finished")
        .expect("recorded");
    assert_eq!(received.len(), sent.len());
    assert!(received == sent, "the bytes changed on the way");
}

#[tokio::test]
async fn l4_termination_serves_app_certificate() {
    let podgate = start().await;
    let cert = TestCert::new(&["a.test", "b.test"]);
    let (backend, mut plain) = echo().await;
    let routers = [
        router(
            "a",
            "edge",
            "svc",
            json!({ "match": { "sni": "a.test" }, "tls": {} }),
        ),
        router(
            "b",
            "edge",
            "svc",
            json!({ "match": { "all": [{ "sni": "b.test" }, { "alpn": "h2" }] }, "tls": {} }),
        ),
    ];
    let mut pushed = snap(1, &[tcp_app("a", "t1", &routers, &[("svc", backend.addr)])]);
    pushed["certificates"] = json!([cert.entry(&["a.test", "b.test"])]);
    push(&podgate, &pushed).await;

    for versions in [both_versions(), &[&rustls::version::TLS12][..]] {
        let config = client_config(&cert, &[], None, versions);
        let mut tls = tls_connect(&podgate, "edge", "a.test", config)
            .await
            .expect("handshake with the app's certificate");
        let presented = tls.get_ref().1.peer_certificates().expect("certificates");
        assert_eq!(presented[0], cert.der, "the app's certificate is presented");
        assert!(
            tls.get_ref().1.alpn_protocol().is_none(),
            "no alpn leaf: none negotiated"
        );
        assert!(served(&mut tls, b"secret").await);
        // The server sees plain bytes, not TLS records.
        let received = timeout(WAIT, plain.recv())
            .await
            .expect("in time")
            .expect("bytes");
        assert_eq!(received, b"secret");
    }

    // The protocol the router names is negotiated.
    let config = client_config(&cert, &["http/1.1", "h2"], None, both_versions());
    let mut tls = tls_connect(&podgate, "edge", "b.test", config)
        .await
        .expect("handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    assert!(served(&mut tls, b"h2 bytes").await);

    // A name the app has no router for is closed, with no certificate chosen for it.
    let config = client_config(&cert, &[], None, both_versions());
    let mut stranger = tls_connect(&podgate, "edge", "c.test", config).await;
    if let Ok(stream) = stranger.as_mut() {
        assert!(!served(stream, b"x").await);
    }
}

#[tokio::test]
async fn l4_termination_client_auth() {
    let podgate = start().await;
    let cert = TestCert::new(&["a.test"]);
    let ca = TestCa::new("trusted ca");
    let alice = ca.client("alice");
    let mallory = TestCa::new("other ca").client("mallory");
    let (backend, _plain) = echo().await;
    let routers = [router(
        "a",
        "edge",
        "svc",
        json!({ "match": { "sni": "a.test" }, "tls": {} }),
    )];
    let mut mutual = tcp_app("a", "t1", &routers, &[("svc", backend.addr)]);
    mutual["tls"]["client_ca_pem"] = json!(ca.pem);
    let mut pushed = snap(1, &[mutual]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    push(&podgate, &pushed).await;

    for versions in [both_versions(), &[&rustls::version::TLS12][..]] {
        let good = client_config(&cert, &[], Some(&alice), versions);
        let mut tls = tls_connect(&podgate, "edge", "a.test", good)
            .await
            .expect("handshake");
        assert!(
            served(&mut tls, b"hello alice").await,
            "a certificate of the CA"
        );
        for refused in [None, Some(&mallory)] {
            let config = client_config(&cert, &[], refused, versions);
            // With TLS 1.3 the client finishes before the server judges its certificate.
            if let Ok(mut tls) = tls_connect(&podgate, "edge", "a.test", config).await {
                assert!(
                    !served(&mut tls, b"hello").await,
                    "no certificate of the CA"
                );
            }
        }
    }
    assert!(
        wait_for(
            &podgate,
            "podgate_l4_refused_total{reason=\"client_cert\"}",
            4
        )
        .await
            >= 4
    );

    // `request` asks and trusts nothing: a client without a certificate is served.
    let routers = [router(
        "a",
        "edge",
        "svc",
        json!({ "match": { "sni": "a.test" }, "tls": {} }),
    )];
    let mut asking = tcp_app("a", "t1", &routers, &[("svc", backend.addr)]);
    asking["tls"]["client_auth"] = json!("request");
    let mut pushed = snap(2, &[asking]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    push(&podgate, &pushed).await;
    let config = client_config(&cert, &[], None, both_versions());
    let mut tls = tls_connect(&podgate, "edge", "a.test", config)
        .await
        .expect("handshake");
    assert!(served(&mut tls, b"anonymous").await);

    // `require` wants some certificate, whoever signed it.
    let mut requiring = tcp_app("a", "t1", &routers, &[("svc", backend.addr)]);
    requiring["tls"]["client_auth"] = json!("require");
    let mut pushed = snap(3, &[requiring]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    push(&podgate, &pushed).await;
    let with = client_config(&cert, &[], Some(&mallory), both_versions());
    let mut tls = tls_connect(&podgate, "edge", "a.test", with)
        .await
        .expect("handshake");
    assert!(served(&mut tls, b"any certificate").await);
    let without = client_config(&cert, &[], None, both_versions());
    if let Ok(mut tls) = tls_connect(&podgate, "edge", "a.test", without).await {
        assert!(!served(&mut tls, b"none").await);
    }
}

#[tokio::test]
async fn l4_termination_obeys_tls_options() {
    let podgate = start().await;
    let cert = TestCert::new(&["a.test"]);
    let (backend, _plain) = echo().await;
    let routers = [router(
        "a",
        "edge",
        "svc",
        json!({ "match": { "sni": "a.test" }, "tls": {} }),
    )];
    let mut strict = tcp_app("a", "t1", &routers, &[("svc", backend.addr)]);
    strict["tls"]["min_version"] = json!("1.3");
    let mut pushed = snap(1, &[strict]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    push(&podgate, &pushed).await;
    let modern = client_config(&cert, &[], None, &[&rustls::version::TLS13]);
    let mut tls = tls_connect(&podgate, "edge", "a.test", modern)
        .await
        .expect("TLS 1.3");
    assert!(served(&mut tls, b"modern").await);
    let old = client_config(&cert, &[], None, &[&rustls::version::TLS12]);
    assert!(
        tls_connect(&podgate, "edge", "a.test", old).await.is_err(),
        "a TLS 1.2 hello is refused by the app's min_version"
    );
    assert!(
        wait_for(
            &podgate,
            "podgate_l4_refused_total{reason=\"tls_policy\"}",
            1
        )
        .await
            >= 1
    );
}

#[tokio::test]
async fn l4_sni_alpn_routing() {
    let podgate = start().await;
    let [a, b, c, d, e, f] = [
        greeter("exact").await,
        greeter("wild").await,
        greeter("both").await,
        greeter("other-tenant").await,
        greeter("pattern").await,
        greeter("any").await,
    ];
    let routers = [
        router(
            "exact",
            "edge",
            "exact",
            passthrough(json!({ "sni": "a.test" })),
        ),
        router(
            "wild",
            "edge",
            "wild",
            passthrough(json!({ "sni": "*.w.test" })),
        ),
        router(
            "both",
            "edge",
            "both",
            passthrough(json!({ "all": [{ "sni": "c.test" }, { "alpn": "h2" }] })),
        ),
        router(
            "pattern",
            "edge",
            "pattern",
            passthrough(
                json!({ "all": [{ "sni": "p.test" }, { "sni_regexp": "^p\\." }, { "not": { "alpn": "h2" } }] }),
            ),
        ),
        router(
            "any",
            "edge",
            "any",
            passthrough(json!({ "any": [{ "sni": "x.test" }, { "sni": "y.test" }] })),
        ),
    ];
    let other = [router(
        "other",
        "edge",
        "other",
        passthrough(json!({ "sni": "t2.test" })),
    )];
    push(
        &podgate,
        &snap(
            1,
            &[
                tcp_app(
                    "one",
                    "t1",
                    &routers,
                    &[
                        ("exact", a.addr),
                        ("wild", b.addr),
                        ("both", c.addr),
                        ("pattern", e.addr),
                        ("any", f.addr),
                    ],
                ),
                tcp_app("two", "t2", &other, &[("other", d.addr)]),
            ],
        ),
    )
    .await;

    let tag = |name: Option<&str>, alpn: &[&str]| {
        let first = hello(name, alpn);
        let podgate = &podgate;
        async move { tag_for(podgate, "edge", &first).await }
    };
    assert_eq!(tag(Some("a.test"), &[]).await.as_deref(), Some("exact"));
    assert_eq!(
        tag(Some("A.Test"), &[]).await.as_deref(),
        Some("exact"),
        "names fold case"
    );
    assert_eq!(tag(Some("x.w.test"), &[]).await.as_deref(), Some("wild"));
    assert_eq!(
        tag(Some("w.test"), &[]).await,
        None,
        "a wildcard needs a label"
    );
    assert_eq!(tag(Some("x.y.w.test"), &[]).await, None, "one label only");
    assert_eq!(
        tag(Some("t2.test"), &[]).await.as_deref(),
        Some("other-tenant")
    );
    // `all`: both leaves must match.
    assert_eq!(tag(Some("c.test"), &["h2"]).await.as_deref(), Some("both"));
    assert_eq!(
        tag(Some("c.test"), &["http/1.1", "h2"]).await.as_deref(),
        Some("both")
    );
    assert_eq!(tag(Some("c.test"), &["http/1.1"]).await, None);
    assert_eq!(tag(Some("c.test"), &[]).await, None);
    // `all` with `sni_regexp` narrowing the literal name, and `not`.
    assert_eq!(tag(Some("p.test"), &[]).await.as_deref(), Some("pattern"));
    assert_eq!(tag(Some("p.test"), &["h2"]).await, None);
    // `any`.
    assert_eq!(tag(Some("x.test"), &[]).await.as_deref(), Some("any"));
    assert_eq!(tag(Some("y.test"), &[]).await.as_deref(), Some("any"));
    assert_eq!(tag(Some("z.test"), &[]).await, None, "no router takes it");
}

#[tokio::test]
async fn l4_no_sni_matches_sni_free_routers() {
    let podgate = start().await;
    let [named, by_alpn, anything, plain] = [
        greeter("named").await,
        greeter("alpn").await,
        greeter("tls").await,
        greeter("plain").await,
    ];
    // On the entry point of `t1`: an `sni` router, an `alpn` router (no `sni` leaf), a catch-all
    // TLS router, and a router that does not look at TLS.
    let routers = [
        router(
            "named",
            "own",
            "named",
            passthrough(json!({ "sni": "a.test" })),
        ),
        router(
            "alpn",
            "own",
            "alpn",
            passthrough(json!({ "alpn": "postgresql" })),
        ),
        router(
            "tls",
            "own",
            "tls",
            json!({ "tls": { "passthrough": true } }),
        ),
        router("plain", "own", "plain", json!({})),
    ];
    push(
        &podgate,
        &snap(
            1,
            &[tcp_app(
                "one",
                "t1",
                &routers,
                &[
                    ("named", named.addr),
                    ("alpn", by_alpn.addr),
                    ("tls", anything.addr),
                    ("plain", plain.addr),
                ],
            )],
        ),
    )
    .await;
    let tag = |first: Vec<u8>| {
        let podgate = &podgate;
        async move { tag_for(podgate, "own", &first).await }
    };
    // No server name: only routers with no `sni` leaf take it.
    assert_eq!(tag(hello(None, &[])).await.as_deref(), Some("tls"));
    assert_eq!(
        tag(hello(None, &["postgresql"])).await.as_deref(),
        Some("alpn")
    );
    assert_eq!(
        tag(hello(Some("a.test"), &[])).await.as_deref(),
        Some("named")
    );
    assert_eq!(
        tag(hello(Some("other.test"), &[])).await.as_deref(),
        Some("tls")
    );
    // Not TLS at all: the router that does not look at TLS.
    assert_eq!(
        tag(b"SELECT 1\r\n".to_vec()).await.as_deref(),
        Some("plain")
    );

    // Without that router and the catch-all, a hello with no name has nowhere to go.
    let routers = [router(
        "named",
        "own",
        "named",
        passthrough(json!({ "sni": "a.test" })),
    )];
    push(
        &podgate,
        &snap(
            2,
            &[tcp_app("one", "t1", &routers, &[("named", named.addr)])],
        ),
    )
    .await;
    assert_eq!(tag(hello(None, &[])).await, None);
    assert_eq!(
        tag(b"SELECT 1\r\n".to_vec()).await,
        None,
        "not TLS: no router without `tls`"
    );
    assert!(wait_for(&podgate, "podgate_l4_refused_total{reason=\"no_route\"}", 2).await >= 2);
}

#[tokio::test]
async fn l4_cross_tenant_sni_claim_rejected() {
    let podgate = start().await;
    let up = greeter("up").await;
    let on_edge = |id: &str, tenant: &str, sni: &str| {
        tcp_app(
            id,
            tenant,
            &[router(
                "r",
                "edge",
                "svc",
                passthrough(json!({ "sni": sni })),
            )],
            &[("svc", up.addr)],
        )
    };
    // Two tenants, one name.
    assert_eq!(
        refusal(
            &podgate,
            &snap(
                1,
                &[
                    on_edge("one", "t1", "a.test"),
                    on_edge("two", "t2", "a.test")
                ]
            ),
        )
        .await,
        ["host_conflict"]
    );
    // A name under another tenant's wildcard.
    assert_eq!(
        refusal(
            &podgate,
            &snap(
                2,
                &[
                    on_edge("one", "t1", "*.a.test"),
                    on_edge("two", "t2", "x.a.test")
                ]
            ),
        )
        .await,
        ["cross_tenant_wildcard"]
    );
    // An HTTP router of another tenant claims the same name: one owner whichever way it arrives.
    let mut http = app("web", &["a.test"], &[serving("r1", up.addr)]);
    http["tenant"] = json!("t2");
    assert_eq!(
        refusal(
            &podgate,
            &snap(3, &[on_edge("one", "t1", "a.test"), http.clone()])
        )
        .await,
        ["host_conflict"]
    );
    // The same tenant may own both, and two tenants may share the port with different names.
    let mut mine = http;
    mine["tenant"] = json!("t1");
    push(&podgate, &snap(4, &[on_edge("one", "t1", "a.test"), mine])).await;
    push(
        &podgate,
        &snap(
            5,
            &[
                on_edge("one", "t1", "a.test"),
                on_edge("two", "t2", "b.test"),
            ],
        ),
    )
    .await;
    // Every conflict names both declarations.
    let response = podgate
        .push_snapshot(&snap(
            6,
            &[
                on_edge("one", "t1", "a.test"),
                on_edge("two", "t2", "a.test"),
            ],
        ))
        .await;
    assert_eq!(
        response.json()["conflicts"][0]["declared_by"],
        json!(["tests/one", "tests/two"])
    );
}

#[tokio::test]
async fn l4_cross_tenant_regexp_capture() {
    let up = greeter("up").await;
    let podgate = start().await;
    let regexp = |tenant: &str, matcher: Value, entry: &str| {
        tcp_app(
            "one",
            tenant,
            &[router("r", entry, "svc", passthrough(matcher))],
            &[("svc", up.addr)],
        )
    };
    // On the shared entry point a router no literal name bounds is `catch_all_not_allowed`:
    // `sni_regexp` alone, `any` with a regexp, no match at all, and `not`.
    for matcher in [
        json!({ "sni_regexp": ".*" }),
        json!({ "any": [{ "sni": "a.test" }, { "sni_regexp": ".*" }] }),
        json!({ "alpn": "h2" }),
        json!({ "not": { "sni": "a.test" } }),
    ] {
        assert_eq!(
            refusal(&podgate, &snap(1, &[regexp("t1", matcher.clone(), "edge")])).await,
            ["catch_all_not_allowed"],
            "{matcher}"
        );
    }
    let bare = tcp_app(
        "one",
        "t1",
        &[router(
            "r",
            "edge",
            "svc",
            json!({ "tls": { "passthrough": true } }),
        )],
        &[("svc", up.addr)],
    );
    assert_eq!(
        refusal(&podgate, &snap(2, &[bare])).await,
        ["catch_all_not_allowed"]
    );
    // A regexp that narrows a literal name of the same tenant is fine, and so is a catch-all on
    // an entry point the tenant has to itself.
    push(
        &podgate,
        &snap(
            3,
            &[regexp(
                "t1",
                json!({ "all": [{ "sni": "*.a.test" }, { "sni_regexp": "^x" }] }),
                "edge",
            )],
        ),
    )
    .await;
    push(
        &podgate,
        &snap(4, &[regexp("t1", json!({ "sni_regexp": ".*" }), "own")]),
    )
    .await;
    // The reserved entry point is not another tenant's to use.
    assert_eq!(
        refusal(
            &podgate,
            &snap(5, &[regexp("t2", json!({ "sni": "b.test" }), "own")])
        )
        .await,
        ["entry_point_forbidden"]
    );
}

#[tokio::test]
async fn l4_catch_all_never_takes_a_name_another_tenant_claims() {
    // The operator lets `t1` catch whatever nobody claims on the shared entry point.
    let podgate =
        Podgate::start_with_entry_points(&ENTRY_POINTS, &[("CATCH_ALL_TENANTS", "t1")]).await;
    let [theirs, ours] = [greeter("t2").await, greeter("t1").await];
    let guarded = router(
        "b",
        "edge",
        "svc",
        passthrough(json!({ "all": [{ "sni": "b.test" }, { "alpn": "private" }] })),
    );
    let catch_all = router(
        "any",
        "edge",
        "svc",
        passthrough(json!({ "sni_regexp": ".*" })),
    );
    push(
        &podgate,
        &snap(
            1,
            &[
                tcp_app(
                    "one",
                    "t1",
                    std::slice::from_ref(&catch_all),
                    &[("svc", ours.addr)],
                ),
                tcp_app("two", "t2", &[guarded], &[("svc", theirs.addr)]),
            ],
        ),
    )
    .await;
    let tag = |name: &str, alpn: &[&str]| {
        let first = hello(Some(name), alpn);
        let podgate = &podgate;
        async move { tag_for(podgate, "edge", &first).await }
    };
    assert_eq!(
        tag("free.test", &[]).await.as_deref(),
        Some("t1"),
        "unclaimed: the catch-all"
    );
    assert_eq!(tag("b.test", &["private"]).await.as_deref(), Some("t2"));
    // `b.test` is `t2`'s: its router does not match this hello, and the catch-all of `t1`
    // does not get the name instead.
    assert_eq!(tag("b.test", &[]).await, None);
    // Two tenants that can both take any name are a conflict, even with the allowance.
    let both = [
        tcp_app(
            "one",
            "t1",
            std::slice::from_ref(&catch_all),
            &[("svc", ours.addr)],
        ),
        tcp_app("two", "t2", &[catch_all], &[("svc", theirs.addr)]),
    ];
    let mut allowed = snap(2, &both);
    allowed["entry_points"] = json!([]);
    let codes = refusal(&podgate, &allowed).await;
    assert!(
        codes
            .iter()
            .all(|code| code == "catch_all_not_allowed" || code == "cross_tenant_catch_all")
    );
    assert!(codes.contains(&"cross_tenant_catch_all".to_owned()) || codes.len() == 1);
}

#[tokio::test]
async fn l4_termination_never_serves_another_tenants_certificate() {
    let podgate = start().await;
    let (backend, _seen) = echo().await;
    let mine = TestCert::new(&["a.test"]);
    let theirs = TestCert::new(&["b.test"]);
    let nobodys = TestCert::new(&["c.test"]);
    // `t1` terminates for any name on its own entry point; it claims `a.test` through an HTTP
    // router, `b.test` is `t2`'s, and the snapshot holds a certificate for `c.test` that no app
    // claims.
    let catch_all = router(
        "any",
        "own",
        "svc",
        json!({ "match": { "sni_regexp": ".*" }, "tls": {} }),
    );
    let claim = |id: &str, tenant: &str, host: &str| {
        let mut web = app(id, &[host], &[serving("r1", backend.addr)]);
        web["tenant"] = json!(tenant);
        web
    };
    let mut pushed = snap(
        1,
        &[
            tcp_app("one", "t1", &[catch_all], &[("svc", backend.addr)]),
            claim("mine", "t1", "a.test"),
            claim("theirs", "t2", "b.test"),
        ],
    );
    pushed["certificates"] = json!([
        mine.entry(&["a.test"]),
        theirs.entry(&["b.test"]),
        nobodys.entry(&["c.test"])
    ]);
    push(&podgate, &pushed).await;
    // `a.test`: the tenant's own name gets its certificate.
    let config = client_config(&mine, &[], None, both_versions());
    let mut tls = tls_connect(&podgate, "own", "a.test", config)
        .await
        .expect("own name");
    assert!(served(&mut tls, b"mine").await);
    // `b.test` is another tenant's: its router does not give the name to the catch-all.
    let config = client_config(&theirs, &[], None, both_versions());
    assert!(
        tls_connect(&podgate, "own", "b.test", config)
            .await
            .is_err(),
        "tenant t1 terminated TLS for tenant t2's name"
    );
    // `c.test` has a certificate and no owner: the router takes the connection, and the
    // handshake still has no certificate to present for a name the tenant does not claim.
    let config = client_config(&nobodys, &[], None, both_versions());
    assert!(
        tls_connect(&podgate, "own", "c.test", config)
            .await
            .is_err(),
        "a certificate nobody claims was presented to the tenant's connection"
    );
    assert!(
        wait_for(
            &podgate,
            "podgate_l4_refused_total{reason=\"tls_handshake\"}",
            1
        )
        .await
            >= 1
    );
}

#[tokio::test]
async fn matcher_dialect_enforced_in_snapshots() {
    let podgate = start().await;
    let up = greeter("up").await;
    // An HTTP leaf on a TCP router.
    for leaf in [
        json!({ "host": "a.test" }),
        json!({ "path_prefix": "/" }),
        json!({ "all": [{ "client_ip": "10.0.0.0/8" }, { "header": { "name": "x" } }] }),
    ] {
        let routers = [router("r", "own", "svc", json!({ "match": leaf }))];
        assert_eq!(
            refusal(
                &podgate,
                &snap(1, &[tcp_app("one", "t1", &routers, &[("svc", up.addr)])])
            )
            .await,
            ["invalid_matcher"],
            "{leaf}"
        );
    }
    // A TCP leaf on an HTTP router.
    for leaf in [
        json!({ "sni": "a.test" }),
        json!({ "sni_regexp": "a" }),
        json!({ "alpn": "h2" }),
        json!({ "all": [{ "host": "a.test" }, { "not": { "alpn": "h2" } }] }),
    ] {
        let mut web = app("web", &["a.test"], &[serving("r1", up.addr)]);
        web["routers"][0]["match"] = leaf.clone();
        assert_eq!(
            refusal(&podgate, &snap(2, &[web])).await,
            ["invalid_matcher"],
            "{leaf}"
        );
    }
    // `client_ip` and the combinators are both dialects', and a TCP leaf needs `tls`.
    let routers = [router(
        "r",
        "own",
        "svc",
        json!({ "match": { "any": [{ "client_ip": "127.0.0.0/8" }, { "not": { "client_ip": "10.0.0.0/8" } }] } }),
    )];
    push(
        &podgate,
        &snap(3, &[tcp_app("one", "t1", &routers, &[("svc", up.addr)])]),
    )
    .await;
    let routers = [router(
        "r",
        "own",
        "svc",
        json!({ "match": { "sni": "a.test" } }),
    )];
    assert_eq!(
        refusal(
            &podgate,
            &snap(4, &[tcp_app("one", "t1", &routers, &[("svc", up.addr)])])
        )
        .await,
        ["invalid_router"]
    );
}

#[tokio::test]
async fn l4_client_hello_deadline() {
    let podgate = start().await;
    let up = greeter("up").await;
    let routers = [router(
        "r",
        "own",
        "svc",
        json!({ "tls": { "passthrough": true } }),
    )];
    push(
        &podgate,
        &snap(1, &[tcp_app("one", "t1", &routers, &[("svc", up.addr)])]),
    )
    .await;
    // Nothing sent, and half a hello sent: both are closed at the deadline (5 s), and neither
    // reaches the server.
    let silent = TcpStream::connect(podgate.entry_addr("own"))
        .await
        .expect("connect");
    let mut partial = TcpStream::connect(podgate.entry_addr("own"))
        .await
        .expect("connect");
    partial
        .write_all(&hello(Some("a.test"), &[])[..40])
        .await
        .expect("part of a hello");
    let started = Instant::now();
    let wait = |mut stream: TcpStream| async move {
        let mut buf = [0_u8; 16];
        let ended = timeout(Duration::from_secs(10), stream.read(&mut buf)).await;
        (matches!(ended, Ok(Ok(0) | Err(_))), Instant::now())
    };
    let ((silent_closed, silent_at), (partial_closed, partial_at)) =
        tokio::join!(wait(silent), wait(partial));
    assert!(silent_closed && partial_closed, "a stalled hello is closed");
    for at in [silent_at, partial_at] {
        let took = at.duration_since(started);
        assert!(
            took >= Duration::from_secs(4),
            "closed after {took:?}, before the deadline"
        );
        assert!(took < Duration::from_secs(8), "closed after {took:?}");
    }
    assert!(
        wait_for(
            &podgate,
            "podgate_l4_refused_total{reason=\"hello_timeout\"}",
            2
        )
        .await
            >= 2
    );
    // A client that speaks promptly is not affected by the stalled ones.
    assert_eq!(
        tag_for(&podgate, "own", &hello(Some("a.test"), &[]))
            .await
            .as_deref(),
        Some("up")
    );
}

#[tokio::test]
async fn l4_client_hello_oversized() {
    let podgate = start().await;
    let up = greeter("up").await;
    let routers = [router(
        "r",
        "own",
        "svc",
        json!({ "tls": { "passthrough": true } }),
    )];
    push(
        &podgate,
        &snap(1, &[tcp_app("one", "t1", &routers, &[("svc", up.addr)])]),
    )
    .await;
    // A handshake record of the largest size TLS allows (16 KiB of hello, which with its header
    // is past the 16 KiB cap), sent whole.
    let mut big = vec![0x16, 0x03, 0x01, 0x40, 0x00, 0x01, 0x00, 0x3f, 0xfc];
    big.resize(9 + 17_000, 0);
    let mut stream = TcpStream::connect(podgate.entry_addr("own"))
        .await
        .expect("connect");
    let _ = stream.write_all(&big).await;
    let started = Instant::now();
    let mut buf = [0_u8; 16];
    let ended = timeout(WAIT, stream.read(&mut buf)).await;
    assert!(matches!(ended, Ok(Ok(0) | Err(_))), "{ended:?}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "closed at the cap, not at the deadline"
    );
    assert!(
        wait_for(
            &podgate,
            "podgate_l4_refused_total{reason=\"hello_invalid\"}",
            1
        )
        .await
            >= 1
    );
    // Garbage after the handshake byte is closed too, and nothing reached the server.
    let mut junk = TcpStream::connect(podgate.entry_addr("own"))
        .await
        .expect("connect");
    junk.write_all(&[0x16, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        .await
        .expect("junk");
    let ended = timeout(WAIT, junk.read(&mut buf)).await;
    assert!(matches!(ended, Ok(Ok(0) | Err(_))), "{ended:?}");
}

#[tokio::test]
async fn l4_tls_connection_takes_a_tenant_slot() {
    let podgate = start().await;
    let up = greeter("up").await;
    let routers = [router(
        "r",
        "own",
        "svc",
        passthrough(json!({ "sni": "a.test" })),
    )];
    let mut pushed = snap(1, &[tcp_app("one", "t1", &routers, &[("svc", up.addr)])]);
    pushed["tenants"][0]["budget"] = json!({ "max_inflight": 1, "max_buffer_bytes": 1_048_576 });
    push(&podgate, &pushed).await;
    let first = hello(Some("a.test"), &[]);
    let mut held = TcpStream::connect(podgate.entry_addr("own"))
        .await
        .expect("connect");
    held.write_all(&first).await.expect("hello");
    let mut greeting = [0_u8; 3];
    timeout(WAIT, held.read_exact(&mut greeting))
        .await
        .expect("in time")
        .expect("greeting");
    assert_eq!(&greeting, b"up\n");
    assert_eq!(
        tag_for(&podgate, "own", &first).await,
        None,
        "the tenant is at max_inflight"
    );
    assert!(
        wait_for(
            &podgate,
            "podgate_l4_refused_total{reason=\"over_inflight\"}",
            1
        )
        .await
            >= 1
    );
    drop(held);
}

#[tokio::test]
async fn l4_proxy_protocol_header_comes_before_the_client_hello() {
    let podgate =
        Podgate::start_with_entry_points(&[("web", "http"), ("edge", "tcp;proxy_protocol")], &[])
            .await;
    let up = greeter("up").await;
    let routers = [router(
        "r",
        "edge",
        "svc",
        passthrough(json!({ "all": [{ "sni": "a.test" }, { "client_ip": "10.9.8.0/24" }] })),
    )];
    let mut pushed = snap(1, &[tcp_app("one", "t1", &routers, &[("svc", up.addr)])]);
    pushed["entry_points"] =
        json!([{ "name": "edge", "proxy_protocol": { "trusted_ips": ["127.0.0.1"] } }]);
    push(&podgate, &pushed).await;
    let with = |source: &str| {
        let mut bytes = format!("PROXY TCP4 {source} 127.0.0.1 40000 443\r\n").into_bytes();
        bytes.extend(hello(Some("a.test"), &[]));
        bytes
    };
    // The address in the header is the client the router matches, and the hello after it is read.
    assert_eq!(
        tag_for(&podgate, "edge", &with("10.9.8.7"))
            .await
            .as_deref(),
        Some("up")
    );
    assert_eq!(tag_for(&podgate, "edge", &with("10.1.1.1")).await, None);
    // A hello with no header is not served on a gated entry point.
    assert_eq!(
        tag_for(&podgate, "edge", &hello(Some("a.test"), &[])).await,
        None
    );
}
