//! End to end: the HTTP/3 front through the real binary. A QUIC client speaks HTTP/3
//! to an HTTPS entry point with `;http3`; every request goes through the same pipeline a TCP
//! client's does, and the QUIC-specific limits are exercised with raw QUIC streams.

#![allow(
    clippy::large_futures,
    reason = "the quinn and h3 client futures are a few KiB each and a test awaits them once; boxing every call buys nothing"
)]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use common::{Podgate, TestCa, TestCert, Upstream, app, serving, snapshot, with_middleware};
use http::{HeaderMap, HeaderValue, Request, Response};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::time::{sleep, timeout};

const IO: Duration = Duration::from_secs(10);
const H3_EXCESSIVE_LOAD: u64 = 0x107;
const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
/// What a connection reserves of its tenant's `max_buffer_bytes` with the default windows: twice
/// the 256 KiB connection window and the 65535-byte internal window.
const RESERVATION: u64 = 2 * 262_144 + 65_535;

/// The entry points of a node with HTTP/3: plain `web`, and `secure` that also speaks QUIC.
const ENTRIES: [(&str, &str); 2] = [("web", "http"), ("secure", "https;http3")];

// ---------------------------------------------------------------- upstream

/// An HTTP/2 cleartext upstream that answers every request with its own body, the headers the
/// pipeline added as `x-echo-*` response headers, and an `x-end` trailer. After `delay`.
struct Echo {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
}

impl Echo {
    async fn start(delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let Ok(mut connection) = h2::server::handshake(tcp).await else {
                        return;
                    };
                    while let Some(Ok((request, respond))) = connection.accept().await {
                        tokio::spawn(echo(request, respond, Arc::clone(&counter), delay));
                    }
                });
            }
        });
        Self { addr, requests }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }

    fn revision(&self) -> Value {
        json!({
            "id": "r1", "state": "serving", "weight": 100,
            "services": [{
                "name": "web", "type": "loadbalancer",
                "servers": [{ "url": format!("h2c://{}", self.addr) }],
            }],
        })
    }
}

async fn echo(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    counter: Arc<AtomicUsize>,
    delay: Duration,
) {
    counter.fetch_add(1, Ordering::Relaxed);
    let (parts, mut body) = request.into_parts();
    let mut flow = body.flow_control().clone();
    let mut received = Vec::new();
    while let Some(Ok(chunk)) = body.data().await {
        flow.release_capacity(chunk.len()).ok();
        received.extend_from_slice(&chunk);
    }
    let request_trailers = body.trailers().await.ok().flatten();
    sleep(delay).await;
    let seen = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-")
            .to_owned()
    };
    let mut builder = Response::builder()
        .status(200)
        .header("x-echo-xff", seen("x-forwarded-for"))
        .header("x-echo-proto", seen("x-forwarded-proto"))
        .header("x-echo-host", seen("host"))
        .header("x-echo-method", parts.method.as_str())
        .header("x-echo-path", parts.uri.path())
        .header("content-length", received.len().to_string());
    if let Some(trailers) = &request_trailers {
        builder = builder.header("x-echo-request-trailers", trailers.len().to_string());
    }
    let head = builder.body(()).expect("response head");
    let Ok(mut send) = respond.send_response(head, false) else {
        return;
    };
    if send.send_data(Bytes::from(received), false).is_err() {
        return;
    }
    let mut trailers = HeaderMap::new();
    trailers.insert("x-end", HeaderValue::from_static("yes"));
    drop(send.send_trailers(trailers));
}

// ------------------------------------------------------------------ client

/// What an HTTP/3 request got back.
#[derive(Debug)]
struct Reply {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
    trailers: Option<HeaderMap>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

fn client_config(trusted: &[&TestCert]) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in trusted {
        roots.add(cert.der.clone()).expect("trust the server");
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).expect("QUIC client"),
    ))
}

fn endpoint(trusted: &[&TestCert]) -> quinn::Endpoint {
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client endpoint");
    endpoint.set_default_client_config(client_config(trusted));
    endpoint
}

/// An HTTP/3 connection of a test.
struct Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    conn: quinn::Connection,
    _driver: tokio::task::JoinHandle<()>,
}

impl Client {
    /// Connects to `server` with `sni` as the server name, trusting `trusted`.
    async fn connect(server: SocketAddr, sni: &str, trusted: &[&TestCert]) -> Result<Self, String> {
        Self::over(&endpoint(trusted), server, sni).await
    }

    /// [`Self::connect`] on a client endpoint of the caller's, so many connections share a socket.
    async fn over(
        endpoint: &quinn::Endpoint,
        server: SocketAddr,
        sni: &str,
    ) -> Result<Self, String> {
        let connecting = endpoint
            .connect(server, sni)
            .map_err(|err| err.to_string())?;
        let conn = timeout(IO, connecting)
            .await
            .map_err(|_| "the handshake timed out".to_owned())?
            .map_err(|err| err.to_string())?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(|err| err.to_string())?;
        let handle = tokio::spawn(async move {
            driver.wait_idle().await;
        });
        Ok(Self {
            send,
            conn,
            _driver: handle,
        })
    }

    async fn get(&mut self, authority: &str, path: &str) -> Reply {
        self.request("GET", authority, path, &[], &[], None)
            .await
            .expect("a reply")
    }

    async fn request(
        &mut self,
        method: &str,
        authority: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[Bytes],
        trailers: Option<HeaderMap>,
    ) -> Result<Reply, String> {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("https://{authority}{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let head = builder.body(()).map_err(|err| err.to_string())?;
        timeout(IO, async {
            let err = |err: h3::error::StreamError| err.to_string();
            let mut stream = self.send.send_request(head).await.map_err(err)?;
            for chunk in body {
                stream.send_data(chunk.clone()).await.map_err(err)?;
            }
            if let Some(trailers) = trailers {
                stream.send_trailers(trailers).await.map_err(err)?;
            }
            stream.finish().await.map_err(err)?;
            let response = stream.recv_response().await.map_err(err)?;
            let mut data = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.map_err(err)? {
                data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            let trailers = stream.recv_trailers().await.map_err(err)?;
            Ok(Reply {
                status: response.status().as_u16(),
                headers: response.headers().clone(),
                body: data,
                trailers,
            })
        })
        .await
        .map_err(|_| "the request timed out".to_owned())?
    }
}

/// Why a QUIC connection ended, as the application code the peer closed it with.
async fn closed_with(conn: &quinn::Connection) -> Option<u64> {
    match timeout(IO, conn.closed()).await {
        Ok(quinn::ConnectionError::ApplicationClosed(close)) => Some(close.error_code.into_inner()),
        _ => None,
    }
}

// ----------------------------------------------------------------- fixture

/// Podgate with `secure` speaking HTTP/3, and one certificate for `names`.
struct Fixture {
    podgate: Podgate,
    cert: TestCert,
    quic: SocketAddr,
}

impl Fixture {
    async fn start(env: &[(&str, &str)], names: &[&str]) -> Self {
        Self::start_on(&ENTRIES, env, names).await
    }

    async fn start_on(entries: &[(&str, &str)], env: &[(&str, &str)], names: &[&str]) -> Self {
        let podgate = Podgate::start_with_entry_points(entries, env).await;
        let quic = podgate.entry_addr("secure");
        Self {
            podgate,
            cert: TestCert::new(names),
            quic,
        }
    }

    /// Pushes `apps` with the fixture's certificate for `names`, under version `version`.
    async fn push(&self, version: u64, apps: &[Value], names: &[&str]) -> Value {
        let mut pushed = snapshot(version, apps);
        pushed["certificates"] = json!([self.cert.entry(names)]);
        let response = self.podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 200, "{response:?}");
        pushed
    }

    async fn connect(&self, sni: &str) -> Client {
        Client::connect(self.quic, sni, &[&self.cert])
            .await
            .unwrap_or_else(|err| panic!("HTTP/3 connection for {sni} failed: {err}"))
    }

    /// A value of the metrics, by its full series name.
    async fn metric(&self, series: &str) -> u64 {
        let body = self.podgate.admin_get("/metrics").await.body;
        body.lines()
            .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or_else(|| panic!("no series {series} in:\n{body}"))
    }

    async fn wait_for_metric(&self, series: &str, wanted: impl Fn(u64) -> bool) -> u64 {
        let deadline = Instant::now() + IO;
        loop {
            let value = self.metric(series).await;
            if wanted(value) || Instant::now() > deadline {
                assert!(wanted(value), "{series} is {value}");
                return value;
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    fn link_socket(&self) -> PathBuf {
        self.podgate.admin_socket.with_file_name("h3-secure.sock")
    }
}

// ------------------------------------------------------------------- tests

#[tokio::test]
async fn h3_request_served() {
    let upstream = Upstream::start("hello").await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    fx.push(
        1,
        &[app("a", &["a.test"], &[serving("r1", upstream.addr)])],
        &["a.test"],
    )
    .await;

    let over_tcp = fx
        .podgate
        .https_get("a.test", "a.test", "/x", &fx.cert)
        .await;
    let mut client = fx.connect("a.test").await;
    let over_h3 = client.get("a.test", "/x").await;
    assert_eq!(over_h3.status, over_tcp.status);
    assert_eq!(over_h3.body, over_tcp.body.as_bytes());
    assert_eq!(
        (over_h3.status, over_h3.body.as_slice()),
        (200, &b"hello"[..])
    );

    // An unknown path on a known host is the pipeline's answer, not the front's.
    let missing = client.get("zzz.test", "/").await;
    assert_eq!(
        missing.status, 421,
        "a Host that is not the SNI: {missing:?}"
    );
    // The same connection serves one request after another.
    assert_eq!(client.get("a.test", "/again").await.status, 200);
}

#[tokio::test]
async fn h3_streams_body_and_trailers() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    fx.push(1, &[a], &["a.test"]).await;

    let mut client = fx.connect("a.test").await;
    // Larger than the internal window and the stream window, so it needs flow control both ways.
    let chunks: Vec<Bytes> = (0..8)
        .map(|n| Bytes::from(vec![b'a' + n; 64 * 1024]))
        .collect();
    let mut request_trailers = HeaderMap::new();
    request_trailers.insert("x-request-trailer", HeaderValue::from_static("1"));
    let reply = client
        .request(
            "POST",
            "a.test",
            "/echo",
            &[],
            &chunks,
            Some(request_trailers),
        )
        .await
        .expect("a reply");
    assert_eq!(reply.status, 200, "{reply:?}");
    assert_eq!(
        reply.body,
        chunks.concat(),
        "the body comes back byte for byte"
    );
    let trailers = reply
        .trailers
        .as_ref()
        .expect("response trailers reach the client");
    assert_eq!(
        trailers.get("x-end").and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    assert_eq!(reply.header("x-echo-method"), Some("POST"));

    // A GET reaches the upstream with no body, not as a chunked request.
    let get = client.get("a.test", "/plain").await;
    assert_eq!((get.status, get.body.len()), (200, 0));
    assert_eq!(echo.requests(), 2);
}

#[tokio::test]
async fn h3_alt_svc_advertised_per_app() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test", "b.test", "c.test"]).await;
    let on = |id: &str, host: &str| {
        let mut a = app(id, &[host], &[]);
        a["revisions"] = json!([echo.revision()]);
        a
    };
    let mut off = on("b", "b.test");
    off["tls"]["http3"] = json!(false);
    let ca = TestCa::new("clients");
    let mut mtls = on("c", "c.test");
    mtls["tls"]["client_ca_pem"] = json!(ca.pem);
    fx.push(
        1,
        &[on("a", "a.test"), off, mtls],
        &["a.test", "b.test", "c.test"],
    )
    .await;

    let port = fx.quic.port();
    let advertised = format!("h3=\":{port}\"; ma=86400");
    let a = fx
        .podgate
        .https_get("a.test", "a.test", "/", &fx.cert)
        .await;
    assert_eq!(a.header("alt-svc"), Some(advertised.as_str()), "{a:?}");
    let b = fx
        .podgate
        .https_get("b.test", "b.test", "/", &fx.cert)
        .await;
    assert_eq!(
        (b.status, b.header("alt-svc")),
        (200, None),
        "http3: false: {b:?}"
    );
    let c = fx
        .podgate
        .https_get("c.test", "c.test", "/", &fx.cert)
        .await;
    assert_eq!(
        c.header("alt-svc"),
        None,
        "a client CA app is not advertised: {c:?}"
    );

    // Never on a response over HTTP/3 itself.
    let mut client = fx.connect("a.test").await;
    let over_h3 = client.get("a.test", "/").await;
    assert_eq!(over_h3.status, 200);
    assert_eq!(over_h3.header("alt-svc"), None);

    // `http3: true` on an app with a client CA is refused whole, not served with mTLS dropped.
    let mut bad = on("d", "d.test");
    bad["tls"]["client_ca_pem"] = json!(ca.pem);
    bad["tls"]["http3"] = json!(true);
    let mut pushed = snapshot(2, &[bad]);
    pushed["certificates"] = json!([fx.cert.entry(&["d.test"])]);
    let refused = fx.podgate.push_snapshot(&pushed).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert!(refused.body.contains("http3"), "{}", refused.body);
}

#[tokio::test]
async fn h3_alt_svc_not_on_plain_http() {
    let echo = Echo::start(Duration::ZERO).await;
    let entries = [
        ("web", "http"),
        ("secure", "https;http3"),
        ("other", "https"),
    ];
    let fx = Fixture::start_on(&entries, &[], &["a.test"]).await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    fx.push(1, &[a], &["a.test"]).await;

    let plain = fx.podgate.get_on("web", "a.test", "/").await;
    assert_eq!(
        (plain.status, plain.header("alt-svc")),
        (200, None),
        "{plain:?}"
    );
    // An HTTPS entry point without the option does not advertise it either.
    let other = https_raw(fx.podgate.entry_addr("other"), "a.test", &fx.cert).await;
    assert!(other.starts_with("HTTP/1.1 200"), "{other}");
    assert!(!other.to_ascii_lowercase().contains("alt-svc"), "{other}");
    // The one with the option does.
    let secure = https_raw(fx.quic, "a.test", &fx.cert).await;
    assert!(secure.starts_with("HTTP/1.1 200"), "{secure}");
    assert!(
        secure.to_ascii_lowercase().contains("alt-svc: h3="),
        "{secure}"
    );
}

/// `GET /` over TLS to `addr` with `sni` as server name and `Host`, as raw response text.
async fn https_raw(addr: SocketAddr, sni: &str, trusted: &TestCert) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trusted.der.clone()).expect("trust");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = ServerName::try_from(sni.to_owned()).expect("server name");
    timeout(IO, async {
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .expect("handshake");
        stream
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .expect("send");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.ok();
        String::from_utf8_lossy(&raw).into_owned()
    })
    .await
    .expect("a response in time")
}

#[tokio::test]
async fn h3_alt_svc_advertises_the_configured_port() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start_on(
        &[("web", "http"), ("secure", "https;http3=8443")],
        &[],
        &["a.test"],
    )
    .await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    fx.push(1, &[a], &["a.test"]).await;
    let reply = fx
        .podgate
        .https_get("a.test", "a.test", "/", &fx.cert)
        .await;
    assert_eq!(
        reply.header("alt-svc"),
        Some("h3=\":8443\"; ma=86400"),
        "{reply:?}"
    );
}

#[tokio::test]
async fn h3_cached_responses_do_not_carry_another_entry_points_alt_svc() {
    // An upstream that is cacheable and names its own Alt-Svc.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    while let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                        seen.drain(..end + 4);
                        let body = "cached";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nAlt-Svc: h3=\":1\"\r\nContent-Length: {}\r\n\r\n{body}",
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
            });
        }
    });
    let fx = Fixture::start(&[], &["a.test"]).await;
    let a = with_middleware(
        app("a", &["a.test"], &[serving("r1", addr)]),
        "cache",
        "cache",
        json!({}),
    );
    fx.push(1, &[a], &["a.test"]).await;

    let port = fx.quic.port();
    let advertised = format!("h3=\":{port}\"; ma=86400");
    let miss = fx
        .podgate
        .https_get("a.test", "a.test", "/c", &fx.cert)
        .await;
    assert_eq!(
        miss.header("alt-svc"),
        Some(advertised.as_str()),
        "the miss: {miss:?}"
    );
    // Stored through the entry point that advertises: the upstream's own Alt-Svc (`:1`) is not
    // kept, and a hit carries the live entry point's value.
    let hit = fx
        .podgate
        .https_get("a.test", "a.test", "/c", &fx.cert)
        .await;
    assert!(
        hit.header("cache-status")
            .is_some_and(|status| status.contains("hit")),
        "{hit:?}"
    );
    assert_eq!(
        hit.header("alt-svc"),
        Some(advertised.as_str()),
        "a hit on the entry point: {hit:?}"
    );
}

#[tokio::test]
async fn h3_real_client_address() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    fx.push(1, &[a], &["a.test"]).await;

    let mut client = fx.connect("a.test").await;
    let reply = client
        .request(
            "GET",
            "a.test",
            "/",
            // A client cannot choose its address: the entry point trusts nobody.
            &[("x-forwarded-for", "203.0.113.9")],
            &[],
            None,
        )
        .await
        .expect("a reply");
    assert_eq!(reply.status, 200, "{reply:?}");
    assert_eq!(reply.header("x-echo-xff"), Some("127.0.0.1"), "{reply:?}");
    assert_eq!(reply.header("x-echo-proto"), Some("https"), "{reply:?}");
}

#[tokio::test]
async fn h3_sni_host_mismatch_421() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test", "b.test"]).await;
    let on = |id: &str, host: &str| {
        let mut a = app(id, &[host], &[]);
        a["revisions"] = json!([echo.revision()]);
        a
    };
    fx.push(
        1,
        &[on("a", "a.test"), on("b", "b.test")],
        &["a.test", "b.test"],
    )
    .await;

    let mut client = fx.connect("a.test").await;
    assert_eq!(client.get("a.test", "/").await.status, 200);
    let misdirected = client.get("b.test", "/").await;
    assert_eq!(misdirected.status, 421, "{misdirected:?}");
    assert_eq!(
        echo.requests(),
        1,
        "the misdirected request never reached an upstream"
    );
}

#[tokio::test]
async fn h3_client_auth_app_not_served() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test", "m.test"]).await;
    let ca = TestCa::new("clients");
    let mut plain = app("a", &["a.test"], &[]);
    plain["revisions"] = json!([echo.revision()]);
    let mut mtls = app("m", &["m.test"], &[]);
    mtls["revisions"] = json!([echo.revision()]);
    mtls["tls"]["client_ca_pem"] = json!(ca.pem);
    fx.push(1, &[plain, mtls], &["a.test", "m.test"]).await;

    let refused = Client::connect(fx.quic, "m.test", &[&fx.cert]).await;
    assert!(
        refused.is_err(),
        "the QUIC handshake for a client CA app is refused"
    );
    fx.wait_for_metric(
        "podgate_h3_handshake_refused_total{reason=\"not_allowed\"}",
        |count| count >= 1,
    )
    .await;
    let mut served = fx.connect("a.test").await;
    assert_eq!(served.get("a.test", "/").await.status, 200);
    assert_eq!(echo.requests(), 1);
}

#[tokio::test]
async fn h3_connection_memory_bounded() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    let mut pushed = snapshot(1, &[a]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(1_073_741_824_u64);
    pushed["certificates"] = json!([fx.cert.entry(&["a.test"])]);
    let response = fx.podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");

    let before = resident_kib(fx.podgate.pid());
    let endpoint = endpoint(&[&fx.cert]);
    let mut open = Vec::new();
    while open.len() < 1000 {
        let batch: Vec<_> = (0..50)
            .map(|_| {
                let endpoint = endpoint.clone();
                let server = fx.quic;
                async move { Client::over(&endpoint, server, "a.test").await }
            })
            .collect();
        for client in futures_join(batch).await {
            open.push(client.expect("a connection"));
        }
    }
    let held = fx
        .wait_for_metric("podgate_h3_connections", |count| count >= 1000)
        .await;
    assert_eq!(held, 1000);
    let charged = fx
        .metric("podgate_tenant_buffer_bytes{tenant=\"t1\"}")
        .await;
    assert_eq!(
        charged,
        1000 * RESERVATION,
        "every connection holds its reservation"
    );
    let grown = (resident_kib(fx.podgate.pid()).saturating_sub(before)) * 1024;
    assert!(
        grown < 1000 * RESERVATION,
        "1000 idle connections grew the process by {grown} bytes, over the documented {}",
        1000 * RESERVATION
    );
    // The connections are alive, not just counted.
    assert_eq!(open[0].get("a.test", "/").await.status, 200);

    drop(open);
    fx.wait_for_metric("podgate_tenant_buffer_bytes{tenant=\"t1\"}", |bytes| {
        bytes == 0
    })
    .await;
}

/// Resident set of a process in KiB.
fn resident_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .expect("status")
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        .expect("VmRSS")
}

/// Awaits every future of `futures`, concurrently.
async fn futures_join<T: Send + 'static>(
    futures: Vec<impl std::future::Future<Output = T> + Send + 'static>,
) -> Vec<T> {
    let tasks: Vec<_> = futures.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::new();
    for task in tasks {
        out.push(task.await.expect("task"));
    }
    out
}

#[tokio::test]
async fn h3_over_tenant_budget_refused() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    // The default tenant of the harness may buffer 1 MiB: one connection fits, two do not.
    fx.push(1, &[a], &["a.test"]).await;

    let mut first = fx.connect("a.test").await;
    assert_eq!(first.get("a.test", "/").await.status, 200);
    let second = fx.connect("a.test").await;
    assert_eq!(
        closed_with(&second.conn).await,
        Some(H3_EXCESSIVE_LOAD),
        "the tenant's second connection is closed with H3_EXCESSIVE_LOAD"
    );
    assert_eq!(
        fx.metric("podgate_h3_closed_total{reason=\"over_budget\"}")
            .await,
        1
    );
    assert_eq!(
        first.get("a.test", "/").await.status,
        200,
        "the first one is untouched"
    );

    drop(first);
    fx.wait_for_metric("podgate_tenant_buffer_bytes{tenant=\"t1\"}", |bytes| {
        bytes == 0
    })
    .await;
    let mut third = fx.connect("a.test").await;
    assert_eq!(
        third.get("a.test", "/").await.status,
        200,
        "the reservation was released"
    );
}

/// A client whose certificate check takes `delay`, so its handshake stays in flight on the
/// server that long. Returns whether the handshake completed.
fn stalled_handshake(
    server: SocketAddr,
    sni: &'static str,
    delay: Duration,
) -> std::thread::JoinHandle<bool> {
    #[derive(Debug)]
    struct Slow(Duration);
    impl ServerCertVerifier for Slow {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            std::thread::sleep(self.0);
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
    std::thread::spawn(move || {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Slow(delay)))
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let mut endpoint =
                quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
                QuicClientConfig::try_from(tls).expect("QUIC client"),
            )));
            let Ok(connecting) = endpoint.connect(server, sni) else {
                return false;
            };
            matches!(
                timeout(Duration::from_secs(15), connecting).await,
                Ok(Ok(_))
            )
        })
    })
}

#[tokio::test]
async fn h3_retry_token_under_load() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(
        &[("H3_MAX_HANDSHAKES", "2"), ("H3_RETRY", "on_load")],
        &["a.test"],
    )
    .await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    let mut pushed = snapshot(1, &[a]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(64_u64 * 1024 * 1024);
    pushed["certificates"] = json!([fx.cert.entry(&["a.test"])]);
    assert_eq!(fx.podgate.push_snapshot(&pushed).await.status, 200);

    let mut calm = fx.connect("a.test").await;
    assert_eq!(calm.get("a.test", "/").await.status, 200);
    assert_eq!(
        fx.metric("podgate_h3_retries_total").await,
        0,
        "no token is demanded while the node is idle"
    );

    // One handshake in flight is half of the cap: the next client must prove its address.
    let stall = stalled_handshake(fx.quic, "a.test", Duration::from_secs(3));
    fx.wait_for_metric("podgate_h3_handshakes", |count| count == 1)
        .await;
    let mut loaded = fx.connect("a.test").await;
    assert_eq!(
        loaded.get("a.test", "/").await.status,
        200,
        "and it is served once it has"
    );
    assert!(
        fx.metric("podgate_h3_retries_total").await >= 1,
        "a retry token was demanded under load"
    );
    assert!(
        stall.join().expect("thread"),
        "the stalled handshake completed in the end"
    );
}

#[tokio::test]
async fn h3_handshake_cap() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(
        &[("H3_MAX_HANDSHAKES", "1"), ("H3_RETRY", "never")],
        &["a.test"],
    )
    .await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    let mut pushed = snapshot(1, &[a]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(64_u64 * 1024 * 1024);
    pushed["certificates"] = json!([fx.cert.entry(&["a.test"])]);
    assert_eq!(fx.podgate.push_snapshot(&pushed).await.status, 200);

    let stall = stalled_handshake(fx.quic, "a.test", Duration::from_secs(3));
    fx.wait_for_metric("podgate_h3_handshakes", |count| count == 1)
        .await;
    let refused = timeout(
        Duration::from_secs(1),
        Client::connect(fx.quic, "a.test", &[&fx.cert]),
    )
    .await;
    assert!(
        refused.is_err() || refused.is_ok_and(|result| result.is_err()),
        "no second handshake gets in while one is in flight"
    );
    assert!(
        fx.metric("podgate_h3_refused_total{reason=\"handshake_cap\"}")
            .await
            >= 1,
        "the refusal is counted"
    );
    assert!(stall.join().expect("thread"));
    let mut later = fx.connect("a.test").await;
    assert_eq!(
        later.get("a.test", "/").await.status,
        200,
        "the slot was released"
    );
}

/// Reads the SETTINGS the server sends on its control stream: `(id, value)` pairs.
async fn server_settings(conn: &quinn::Connection) -> Vec<(u64, u64)> {
    let mut stream = timeout(IO, async {
        loop {
            let mut stream = conn.accept_uni().await.expect("a server stream");
            let mut kind = [0_u8; 1];
            stream.read_exact(&mut kind).await.expect("stream type");
            if kind[0] == 0 {
                return stream;
            }
        }
    })
    .await
    .expect("the control stream arrives");
    let mut head = [0_u8; 2];
    stream.read_exact(&mut head).await.expect("frame head");
    assert_eq!(head[0], 0x04, "the first frame is SETTINGS");
    let mut payload = vec![0_u8; usize::from(head[1])];
    stream.read_exact(&mut payload).await.expect("settings");
    let mut at = 0;
    let mut pairs = Vec::new();
    while at < payload.len() {
        let (id, used) = varint(&payload[at..]);
        at += used;
        let (value, used) = varint(&payload[at..]);
        at += used;
        pairs.push((id, value));
    }
    pairs
}

/// A QUIC variable-length integer at the start of `bytes`, and its length.
fn varint(bytes: &[u8]) -> (u64, usize) {
    let length = 1 << (bytes[0] >> 6);
    let mut value = u64::from(bytes[0] & 0x3f);
    for byte in &bytes[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    (value, length)
}

#[tokio::test]
async fn h3_qpack_table_capped() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    let mut pushed = snapshot(1, &[a]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(64_u64 * 1024 * 1024);
    pushed["certificates"] = json!([fx.cert.entry(&["a.test"])]);
    assert_eq!(fx.podgate.push_snapshot(&pushed).await.status, 200);

    // A raw QUIC connection: an HTTP/3 client would consume the server's control stream.
    let raw = endpoint(&[&fx.cert])
        .connect(fx.quic, "a.test")
        .expect("connect")
        .await
        .expect("handshake");
    let settings = server_settings(&raw).await;
    let setting = |id: u64| {
        settings
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, v)| *v)
    };
    assert!(
        setting(0x01).unwrap_or(0) <= 4096,
        "QPACK dynamic table capacity: {settings:?}"
    );
    assert!(
        setting(0x07).unwrap_or(0) <= 16,
        "QPACK blocked streams: {settings:?}"
    );
    assert_eq!(
        setting(0x06),
        Some(64 * 1024),
        "the field section limit: {settings:?}"
    );
    for (id, name) in [
        (0x08, "extended CONNECT"),
        (0x33, "datagrams"),
        (0x2b603742, "WebTransport"),
    ] {
        assert_eq!(setting(id).unwrap_or(0), 0, "{name} is off: {settings:?}");
    }

    // A header block that names a dynamic table entry is refused with a connection error.
    let dynamic = Client::connect(fx.quic, "a.test", &[&fx.cert])
        .await
        .expect("connected");
    let (mut send, _recv) = dynamic.conn.open_bi().await.expect("a stream");
    // HEADERS, three bytes: required insert count 1, base 0, an indexed dynamic table line.
    send.write_all(&[0x01, 0x03, 0x02, 0x00, 0x80])
        .await
        .expect("write");
    assert_eq!(
        closed_with(&dynamic.conn).await,
        Some(QPACK_DECOMPRESSION_FAILED),
        "a request that needs the dynamic table closes the connection"
    );

    // A header section over 64 KiB is refused as a request, not a connection.
    let oversized = Client::connect(fx.quic, "a.test", &[&fx.cert])
        .await
        .expect("connected");
    let (mut send, mut recv) = oversized.conn.open_bi().await.expect("a stream");
    let value_len = 70 * 1024;
    let mut block = vec![0x00, 0x00, 0x21, b'x', 0x7f];
    // The value length as a QPACK 7-bit prefix integer.
    let mut rest = value_len - 127;
    while rest >= 128 {
        block.push((rest % 128) as u8 | 0x80);
        rest /= 128;
    }
    block.push(rest as u8);
    block.extend(std::iter::repeat_n(b'v', value_len));
    let mut frame = vec![0x01];
    frame.extend_from_slice(&[
        0x80 | ((block.len() >> 24) as u8 & 0x3f),
        (block.len() >> 16) as u8,
        (block.len() >> 8) as u8,
        block.len() as u8,
    ]);
    frame.extend_from_slice(&block);
    send.write_all(&frame).await.expect("write");
    send.finish().expect("finish");
    let answer = timeout(IO, recv.read_to_end(1024 * 1024)).await;
    assert!(
        oversized.conn.close_reason().is_none(),
        "the connection survives an oversized header section: {answer:?}"
    );
    let mut fresh = fx.connect("a.test").await;
    assert_eq!(fresh.get("a.test", "/").await.status, 200);
}

#[tokio::test]
async fn h3_rapid_reset_limited() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    let mut pushed = snapshot(1, &[a]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(64_u64 * 1024 * 1024);
    pushed["certificates"] = json!([fx.cert.entry(&["a.test"])]);
    assert_eq!(fx.podgate.push_snapshot(&pushed).await.status, 200);

    // A few resets are ordinary: browsers cancel requests.
    let mut calm = fx.connect("a.test").await;
    for _ in 0..20 {
        let (mut send, _recv) = calm.conn.open_bi().await.expect("a stream");
        send.write_all(&[0x01, 0x00]).await.ok();
        send.reset(quinn::VarInt::from_u32(0x10c)).ok();
    }
    assert_eq!(
        calm.get("a.test", "/").await.status,
        200,
        "twenty resets are fine"
    );

    // Hundreds in a second are the attack.
    let abusive = fx.connect("a.test").await;
    let started = Instant::now();
    for _ in 0..400 {
        if started.elapsed() > Duration::from_millis(900) {
            break;
        }
        let Ok((mut send, _recv)) = abusive.conn.open_bi().await else {
            break;
        };
        send.write_all(&[0x01, 0x00]).await.ok();
        send.reset(quinn::VarInt::from_u32(0x10c)).ok();
    }
    assert_eq!(closed_with(&abusive.conn).await, Some(H3_EXCESSIVE_LOAD));
    assert!(
        fx.metric("podgate_h3_closed_total{reason=\"rapid_reset\"}")
            .await
            >= 1,
        "the close is counted"
    );
    assert_eq!(
        calm.get("a.test", "/").await.status,
        200,
        "other connections are unaffected"
    );
}

#[tokio::test]
async fn h3_zero_rtt_disabled() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    let mut pushed = snapshot(1, &[a]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(64_u64 * 1024 * 1024);
    pushed["certificates"] = json!([fx.cert.entry(&["a.test"])]);
    assert_eq!(fx.podgate.push_snapshot(&pushed).await.status, 200);

    // A client that keeps session tickets and wants 0-RTT.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(fx.cert.der.clone()).expect("trust");
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = true;
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).expect("QUIC client"),
    )));

    let first = endpoint
        .connect(fx.quic, "a.test")
        .expect("connect")
        .await
        .expect("handshake");
    // Tickets arrive after the handshake.
    sleep(Duration::from_millis(500)).await;
    drop(first);
    sleep(Duration::from_millis(200)).await;
    let second = endpoint.connect(fx.quic, "a.test").expect("connect");
    match second.into_0rtt() {
        Ok(_) => panic!("the server accepted 0-RTT data"),
        Err(connecting) => {
            let conn = timeout(IO, connecting)
                .await
                .expect("in time")
                .expect("a full handshake");
            assert!(conn.close_reason().is_none());
        }
    }
}

#[tokio::test]
async fn h3_internal_socket_rejects_other_peers() {
    let echo = Echo::start(Duration::ZERO).await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    let mut a = app("a", &["a.test"], &[]);
    a["revisions"] = json!([echo.revision()]);
    fx.push(1, &[a], &["a.test"]).await;

    let socket = fx.link_socket();
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(&socket)
            .expect("the internal socket exists")
            .permissions(),
    );
    assert_eq!(
        mode & 0o777,
        0o600,
        "the internal socket is private to the user"
    );

    // A peer of the same user that knows nothing: a plain HTTP/2 request, no credential.
    let h2_request: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";
    // The credential is wrong: 32 bytes and a well-formed PROXY header.
    let mut wrong = vec![0_u8; 32];
    wrong.extend_from_slice(
        b"\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\x7f\x00\x00\x01\x7f\x00\x00\x01\x01\xbb\x01\xbb",
    );
    wrong.extend_from_slice(h2_request);
    for attempt in [
        h2_request.to_vec(),
        wrong,
        b"PROXY TCP4 127.0.0.1 127.0.0.1 1 2\r\n".to_vec(),
    ] {
        let mut stream = UnixStream::connect(&socket).await.expect("connect");
        stream.write_all(&attempt).await.ok();
        let mut buf = [0_u8; 64];
        let read = timeout(IO, stream.read(&mut buf))
            .await
            .expect("closed in time");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "the pipeline said something to a peer that is not the front: {read:?}"
        );
    }
    assert_eq!(echo.requests(), 0, "nothing reached an upstream");

    // The front itself still gets through.
    let mut client = fx.connect("a.test").await;
    assert_eq!(client.get("a.test", "/").await.status, 200);
    assert_eq!(echo.requests(), 1);
}

#[tokio::test]
async fn h3_goes_through_middlewares_and_budgets() {
    let dir = std::env::temp_dir().join(format!("podgate-h3-log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("log dir");
    let log = dir.join("access.log");
    let echo = Echo::start(Duration::from_millis(600)).await;
    let fx = Fixture::start(
        &[("ACCESS_LOG_FILE", log.to_str().expect("utf-8"))],
        &["limited.test", "closed.test", "busy.test"],
    )
    .await;
    let on = |id: &str, host: &str| {
        let mut a = app(id, &[host], &[]);
        a["revisions"] = json!([echo.revision()]);
        a
    };
    let limited = with_middleware(
        on("limited", "limited.test"),
        "rl",
        "rate_limit",
        json!({"average": 1, "period_secs": 3600, "burst": 1, "source": {"ip": {}}}),
    );
    let closed = with_middleware(
        on("closed", "closed.test"),
        "allow",
        "ip_allow_list",
        json!({"source_range": ["10.0.0.0/8"]}),
    );
    let mut pushed = snapshot(1, &[limited, closed, on("busy", "busy.test")]);
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(1);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(64_u64 * 1024 * 1024);
    pushed["certificates"] = json!([fx.cert.entry(&["limited.test", "closed.test", "busy.test"])]);
    pushed["observability"] = json!({ "access_log": {} });
    assert_eq!(fx.podgate.push_snapshot(&pushed).await.status, 200);

    // The rate limit counts HTTP/3 requests per client like any other.
    let mut client = fx.connect("limited.test").await;
    assert_eq!(client.get("limited.test", "/").await.status, 200);
    let limited = client.get("limited.test", "/").await;
    assert_eq!(limited.status, 429, "{limited:?}");

    // The allow list sees the client's address, not the internal socket.
    let mut other = fx.connect("closed.test").await;
    assert_eq!(other.get("closed.test", "/").await.status, 403);

    // The tenant's in-flight budget is one: a second concurrent request is refused.
    let mut slow = fx.connect("busy.test").await;
    let mut second = fx.connect("busy.test").await;
    let (first, refused) = tokio::join!(slow.get("busy.test", "/slow"), async {
        sleep(Duration::from_millis(200)).await;
        second.get("busy.test", "/slow").await
    });
    assert_eq!(first.status, 200, "{first:?}");
    assert_eq!(refused.status, 503, "{refused:?}");
    assert_eq!(refused.header("retry-after"), Some("1"));

    // And the access log has the real client, the entry point and the host.
    let deadline = Instant::now() + IO;
    let line = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(line) = text
            .lines()
            .find(|line| line.contains("\"limited.test\"") && line.contains("429"))
        {
            break line.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "no access log line for the limited request: {text}"
        );
        sleep(Duration::from_millis(50)).await;
    };
    let entry: Value = serde_json::from_str(&line).expect("one JSON object");
    assert_eq!(entry["client_ip"], "127.0.0.1", "{entry}");
    assert_eq!(entry["entry_point"], "secure", "{entry}");
    drop(std::fs::remove_dir_all(&dir));
}

// ------------------------------------------------------------- measurement

/// Sequential GETs on one connection per protocol, the same upstream and route: HTTP/2 over TLS
/// straight into the pipeline, against HTTP/3 through the front and its internal h2c hop. The
/// two protocols alternate request by request in one loop, so load drift hits both equally.
/// Prints p50, p90 and p99 per protocol; the median difference bounds the hop's cost (it also
/// holds QUIC against TCP+TLS). Run alone, under the build lock: `cargo test --release --test h3
/// h3_hop_latency -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "a measurement, not a check"]
async fn h3_hop_latency() {
    const WARMUP: usize = 200;
    const RUNS: usize = 5_000;
    let upstream = Upstream::start("hello").await;
    let fx = Fixture::start(&[], &["a.test"]).await;
    fx.push(
        1,
        &[app("a", &["a.test"], &[serving("r1", upstream.addr)])],
        &["a.test"],
    )
    .await;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(fx.cert.der.clone()).expect("trust the server");
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = tokio::net::TcpStream::connect(fx.podgate.entry_addr("secure"))
        .await
        .expect("connect");
    tcp.set_nodelay(true).expect("nodelay");
    let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(ServerName::try_from("a.test").expect("name"), tcp)
        .await
        .expect("TLS");
    let (mut h2, connection) = h2::client::handshake(stream).await.expect("h2 handshake");
    tokio::spawn(async move { drop(connection.await) });
    let mut client = fx.connect("a.test").await;
    let mut over_h2 = Vec::with_capacity(RUNS);
    let mut over_h3 = Vec::with_capacity(RUNS);
    // One loop, one request on each protocol per iteration, the order swapping every iteration:
    // load drift and cache state then hit both protocols equally.
    for at in 0..WARMUP + RUNS {
        for h3_first in [at % 2 == 0, at % 2 != 0] {
            let started = Instant::now();
            if h3_first {
                assert_eq!(client.get("a.test", "/x").await.status, 200);
                if at >= WARMUP {
                    over_h3.push(started.elapsed());
                }
            } else {
                let request = Request::get("https://a.test/x").body(()).expect("request");
                h2 = h2.ready().await.expect("ready");
                let (response, _) = h2.send_request(request, true).expect("send");
                let response = response.await.expect("response");
                assert_eq!(response.status(), 200);
                let mut body = response.into_body();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("body");
                    drop(body.flow_control().release_capacity(chunk.len()));
                }
                if at >= WARMUP {
                    over_h2.push(started.elapsed());
                }
            }
        }
    }

    let quantile = |samples: &mut Vec<Duration>, q: f64| {
        samples.sort_unstable();
        let at = ((samples.len() - 1) as f64 * q).round() as usize;
        samples[at]
    };
    let report = |name: &str, samples: &mut Vec<Duration>| {
        let (p50, p90, p99) = (
            quantile(samples, 0.5),
            quantile(samples, 0.9),
            quantile(samples, 0.99),
        );
        println!("h3 hop: {name:<8} p50 {p50:?} p90 {p90:?} p99 {p99:?}");
        p50
    };
    println!("h3 hop: {RUNS} GETs per protocol, alternating in one loop after {WARMUP} warm-up");
    let h2_p50 = report("HTTPS h2", &mut over_h2);
    let h3_p50 = report("HTTP/3", &mut over_h3);
    println!(
        "h3 hop: median difference {:?}",
        h3_p50.saturating_sub(h2_p50)
    );
}
