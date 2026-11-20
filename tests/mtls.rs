//! End to end: an app with `tls.client_ca_pem` only serves clients holding a certificate from
//! that CA, apps without it never ask for one, and fronting cannot get around it.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::{Podgate, TestCa, TestCert, TestClient, Upstream, app, serving, snapshot};
use rustls::client::ResolvesClientCert;
use rustls::crypto::ring::default_provider;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, SignatureScheme, SupportedProtocolVersion};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SUBJECT_HEADER: &str = "x-forwarded-tls-client-cert-subject";

/// Records whether the server asked for a client certificate, and answers with `client`'s.
#[derive(Debug)]
struct Recording {
    asked: Arc<AtomicBool>,
    key: Option<Arc<CertifiedKey>>,
}

impl ResolvesClientCert for Recording {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.asked.store(true, Ordering::SeqCst);
        self.key.clone()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A client trusting `server`, presenting `client` when asked, over `versions`. The flag says
/// whether the server asked for a certificate.
fn client_config(
    server: &TestCert,
    client: Option<&TestClient>,
    versions: &[&'static SupportedProtocolVersion],
) -> (Arc<ClientConfig>, Arc<AtomicBool>) {
    let mut roots = RootCertStore::empty();
    roots.add(server.der.clone()).expect("trust the server");
    let provider = Arc::new(default_provider());
    let key = client.map(|client| {
        let signing = provider
            .key_provider
            .load_private_key(client.key.clone_key())
            .expect("client key");
        Arc::new(CertifiedKey::new(client.chain.clone(), signing))
    });
    let asked = Arc::new(AtomicBool::new(false));
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_client_cert_resolver(Arc::new(Recording {
            asked: Arc::clone(&asked),
            key,
        }));
    (Arc::new(config), asked)
}

fn tls13() -> &'static [&'static SupportedProtocolVersion] {
    static VERSIONS: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
    &VERSIONS
}

fn tls12() -> &'static [&'static SupportedProtocolVersion] {
    static VERSIONS: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
    &VERSIONS
}

/// A backend that answers with the value of [`SUBJECT_HEADER`] in the request, or `none`.
async fn echo_subject_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&chunk[..read]),
                    }
                }
                let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let body = text
                    .lines()
                    .find_map(|line| line.strip_prefix(&format!("{SUBJECT_HEADER}:")))
                    .map_or("none".to_owned(), |value| value.trim().to_owned());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    addr
}

struct Fixture {
    podgate: Podgate,
    server: TestCert,
    ca: TestCa,
    _plain: Upstream,
    _secure: Upstream,
}

/// `plain.test` (no client CA) and `secure.test` (client CA `ca`), one server certificate for
/// both. `fronting` sets `allow_domain_fronting` on the secure app.
async fn start(fronting: bool) -> Fixture {
    let podgate = Podgate::start().await;
    let plain = Upstream::start("plain body").await;
    let secure = Upstream::start("secure body").await;
    let server = TestCert::new(&["plain.test", "secure.test"]);
    let ca = TestCa::new("trusted ca");
    let mut secure_app = app("secure", &["secure.test"], &[serving("r1", secure.addr)]);
    secure_app["tls"]["client_ca_pem"] = json!(ca.pem);
    secure_app["allow_domain_fronting"] = Value::Bool(fronting);
    let plain_app = app("plain", &["plain.test"], &[serving("r1", plain.addr)]);
    let mut pushed = snapshot(1, &[plain_app, secure_app]);
    pushed["certificates"] = json!([server.entry(&["plain.test", "secure.test"])]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
    Fixture {
        podgate,
        server,
        ca,
        _plain: plain,
        _secure: secure,
    }
}

#[tokio::test]
async fn mtls_valid_client_served() {
    let fx = start(false).await;
    let client = fx.ca.client("alice");

    for versions in [tls13(), tls12()] {
        let (config, asked) = client_config(&fx.server, Some(&client), versions);
        let response = fx
            .podgate
            .try_https_get(config, "secure.test", "secure.test", "/")
            .await
            .expect("handshake and response");
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(response.body, "secure body");
        assert!(
            asked.load(Ordering::SeqCst),
            "the server asked for a certificate"
        );
    }
}

#[tokio::test]
async fn mtls_missing_or_wrong_client_refused() {
    let fx = start(false).await;
    let stranger = TestCa::new("other ca").client("mallory");

    let (none, _) = client_config(&fx.server, None, tls13());
    let (wrong, _) = client_config(&fx.server, Some(&stranger), tls13());
    for config in [none, wrong] {
        let response = fx
            .podgate
            .try_https_get(config, "secure.test", "secure.test", "/")
            .await
            .expect("the handshake completes; the request is refused");
        assert_eq!(response.status, 403, "{response:?}");
        assert_eq!(response.body, r#"{"error":"client certificate required"}"#);
    }

    let plain_http = fx.podgate.get("secure.test", "/").await;
    assert_eq!(
        plain_http.status, 403,
        "plain HTTP cannot present a certificate"
    );
}

#[tokio::test]
async fn mtls_not_requested_without_ca() {
    let fx = start(false).await;
    let client = fx.ca.client("alice");

    let (config, asked) = client_config(&fx.server, Some(&client), tls13());
    let response = fx
        .podgate
        .try_https_get(config, "plain.test", "plain.test", "/")
        .await
        .expect("handshake and response");
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "plain body");
    assert!(
        !asked.load(Ordering::SeqCst),
        "a host without client_ca_pem must not request a certificate"
    );

    let (config, asked) = client_config(&fx.server, Some(&client), tls13());
    let response = fx
        .podgate
        .try_https_get(config, "secure.test", "secure.test", "/")
        .await
        .expect("handshake and response");
    assert_eq!(response.status, 200, "{response:?}");
    assert!(
        asked.load(Ordering::SeqCst),
        "the mTLS host on the same listener does"
    );
}

#[tokio::test]
async fn mtls_invalid_ca_rejected() {
    let fx = start(false).await;
    let up = Upstream::start("x").await;
    let bad_cas = [
        "not a pem",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    ];
    for (offset, bad) in (2_u64..).zip(bad_cas) {
        let mut broken = app("broken", &["broken.test"], &[serving("r1", up.addr)]);
        broken["tls"]["client_ca_pem"] = json!(bad);
        let response = fx.podgate.push_snapshot(&snapshot(offset, &[broken])).await;
        assert_eq!(response.status, 422, "{response:?}");
        assert_eq!(response.json()["conflicts"][0]["code"], "invalid_client_ca");
        assert_eq!(response.json()["conflicts"][0]["app"], "broken");
    }

    let (config, _) = client_config(&fx.server, None, tls13());
    let still = fx
        .podgate
        .try_https_get(config, "plain.test", "plain.test", "/")
        .await
        .expect("previous snapshot still serves");
    assert_eq!(still.body, "plain body");
}

#[tokio::test]
async fn mtls_fronting_cannot_bypass() {
    let fx = start(true).await;
    let valid = fx.ca.client("alice");

    // SNI of the app that asks for no certificate, Host of the mTLS app that allows fronting.
    let (config, asked) = client_config(&fx.server, Some(&valid), tls13());
    let response = fx
        .podgate
        .try_https_get(config, "plain.test", "secure.test", "/")
        .await
        .expect("handshake and response");
    assert!(!asked.load(Ordering::SeqCst));
    assert_eq!(response.status, 403, "{response:?}");
    assert_eq!(response.body, r#"{"error":"client certificate required"}"#);
}

/// The client CA belongs to the app of the router that matched, however it matched: an mTLS app
/// reached through a `host_regexp` router (which claims no literal host) still needs a
/// certificate, and a client that presents one is served.
#[tokio::test]
async fn mtls_host_regexp_router_requires_cert() {
    let podgate = Podgate::start_with_env(&[("CATCH_ALL_TENANTS", "t1")]).await;
    let secure = Upstream::start("secure body").await;
    let server = TestCert::new(&["secure.test"]);
    let ca = TestCa::new("trusted ca");
    let mut secure_app = app("secure", &["unused.test"], &[serving("r1", secure.addr)]);
    secure_app["tls"]["client_ca_pem"] = json!(ca.pem);
    secure_app["routers"][0]["match"] = json!({ "host_regexp": "^secure\\.test$" });
    let mut pushed = snapshot(1, &[secure_app]);
    pushed["certificates"] = json!([server.entry(&["secure.test"])]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");

    let (config, _) = client_config(&server, None, tls13());
    let refused = podgate
        .try_https_get(config, "secure.test", "secure.test", "/")
        .await
        .expect("handshake and response");
    assert_eq!(refused.status, 403, "{refused:?}");
    assert_eq!(refused.body, r#"{"error":"client certificate required"}"#);

    let client = ca.client("alice");
    let (config, asked) = client_config(&server, Some(&client), tls13());
    let served = podgate
        .try_https_get(config, "secure.test", "secure.test", "/")
        .await
        .expect("handshake and response");
    assert!(
        asked.load(Ordering::SeqCst),
        "the server asked for a certificate"
    );
    assert_eq!((served.status, served.body.as_str()), (200, "secure body"));
}

#[tokio::test]
async fn mtls_pass_client_cert_subject() {
    let podgate = Podgate::start().await;
    let echo = echo_subject_upstream().await;
    let server = TestCert::new(&["pass.test", "quiet.test"]);
    let ca = TestCa::new("trusted ca");
    let mut pass = app("pass", &["pass.test"], &[serving("r1", echo)]);
    pass["tls"]["client_ca_pem"] = json!(ca.pem);
    pass["tls"]["pass_client_cert"] = json!(true);
    let mut quiet = app("quiet", &["quiet.test"], &[serving("r1", echo)]);
    quiet["tls"]["client_ca_pem"] = json!(ca.pem);
    let open = app("open", &["open.test"], &[serving("r1", echo)]);
    let mut pushed = snapshot(1, &[pass, quiet, open]);
    pushed["certificates"] = json!([server.entry(&["pass.test", "quiet.test"])]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    let alice = ca.client("alice");

    let (config, _) = client_config(&server, Some(&alice), tls13());
    let opted_in = podgate
        .try_https_get(config, "pass.test", "pass.test", "/")
        .await
        .expect("handshake and response");
    assert_eq!(opted_in.status, 200, "{opted_in:?}");
    assert_eq!(
        opted_in.body, "cn=alice",
        "subject of the verified certificate"
    );

    let (config, _) = client_config(&server, Some(&alice), tls13());
    let not_opted_in = podgate
        .try_https_get(config, "quiet.test", "quiet.test", "/")
        .await
        .expect("handshake and response");
    assert_eq!(not_opted_in.body, "none", "no opt-in, no header");

    let spoofed = podgate
        .get_with_headers("open.test", "/", &[(SUBJECT_HEADER, "CN=evil")])
        .await;
    assert_eq!(
        spoofed.body, "none",
        "a client cannot set the header itself"
    );
}
