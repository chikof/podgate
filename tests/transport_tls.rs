//! Upstream TLS: a service with `https://` servers reaches them through a
//! `servers_transport` that sets the server name, the trust anchors, a client certificate and
//! the `insecure_skip_verify` escape hatch.
//!
//! The test upstream is a TLS server that answers every request with headers telling what it saw:
//! `x-conn` (its connection number), `x-sni`, `x-client-cert` (a digest of the client leaf) and
//! `x-tls` (the negotiated version).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{Podgate, TestCert, app, router, snapshot};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion, version};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;

/// Time for Pingora to move a finished upstream connection into its pool.
const POOL_SETTLE: Duration = Duration::from_millis(150);

/// A certificate (chain) and its key, PEM.
struct Leaf {
    cert_pem: String,
    key_pem: String,
}

impl Leaf {
    fn der(&self) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(self.cert_pem.as_bytes()).expect("leaf DER")
    }

    /// The digest the test upstream reports as `x-client-cert`.
    fn digest(&self) -> String {
        digest(&self.der())
    }
}

fn digest(der: &CertificateDer<'_>) -> String {
    Sha256::digest(der.as_ref())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A certificate authority that issues server and client certificates.
struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    pem: String,
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

    fn issue(&self, names: &[&str], serial: Option<u64>) -> Leaf {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("leaf params");
        params.serial_number = serial.map(Into::into);
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    /// A server certificate for the loopback IP and `names`.
    fn server(&self, names: &[&str]) -> Leaf {
        let mut all = vec!["127.0.0.1"];
        all.extend_from_slice(names);
        self.issue(&all, None)
    }

    fn client(&self, serial: u64) -> Leaf {
        self.issue(&[], Some(serial))
    }
}

/// How the test upstream behaves.
struct Backend {
    server: Leaf,
    /// Trusts client certificates from this CA and accepts clients without one.
    client_ca_pem: Option<String>,
    tls12_only: bool,
    status: u16,
}

impl Backend {
    fn new(server: Leaf) -> Self {
        Self {
            server,
            client_ca_pem: None,
            tls12_only: false,
            status: 200,
        }
    }

    fn asking_for_certificates_of(mut self, ca: &Ca) -> Self {
        self.client_ca_pem = Some(ca.pem.clone());
        self
    }

    fn answering(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    fn tls12_only(mut self) -> Self {
        self.tls12_only = true;
        self
    }

    async fn start(self) -> SocketAddr {
        let provider = Arc::new(default_provider());
        let versions: &[&'static SupportedProtocolVersion] = if self.tls12_only {
            &[&version::TLS12]
        } else {
            &[&version::TLS12, &version::TLS13]
        };
        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(versions)
            .expect("protocol versions");
        let builder = match &self.client_ca_pem {
            None => builder.with_no_client_auth(),
            Some(pem) => {
                let mut roots = RootCertStore::empty();
                roots
                    .add(CertificateDer::from_pem_slice(pem.as_bytes()).expect("CA DER"))
                    .expect("trust the CA");
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                        .allow_unauthenticated()
                        .build()
                        .expect("client verifier");
                builder.with_client_cert_verifier(verifier)
            }
        };
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(self.server.cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .expect("server chain");
        let key = PrivateKeyDer::from_pem_slice(self.server.key_pem.as_bytes()).expect("key");
        let config = builder.with_single_cert(chain, key).expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let addr = listener.local_addr().expect("upstream addr");
        tokio::spawn(async move {
            let mut accepted = 0_u64;
            while let Ok((tcp, _)) = listener.accept().await {
                accepted += 1;
                tokio::spawn(serve(acceptor.clone(), tcp, accepted, self.status));
            }
        });
        addr
    }
}

async fn serve(acceptor: TlsAcceptor, tcp: TcpStream, number: u64, status: u16) {
    let Ok(mut stream) = acceptor.accept(tcp).await else {
        return;
    };
    let (_, connection) = stream.get_ref();
    let sni = connection.server_name().unwrap_or("none").to_owned();
    let client = connection
        .peer_certificates()
        .and_then(|chain| chain.first().map(digest))
        .unwrap_or_else(|| "none".to_owned());
    let tls = match connection.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "1.2",
        _ => "other",
    };
    let response = format!(
        "HTTP/1.1 {status} Status\r\nContent-Length: 2\r\nx-conn: {number}\r\nx-sni: {sni}\r\n\
         x-client-cert: {client}\r\nx-tls: {tls}\r\n\r\nok"
    );
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            seen.drain(..end + 4);
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

/// A `servers_transport` named `name`; `fields` holds its own settings.
fn transport(name: &str, fields: &Value) -> Value {
    let mut declared = json!({ "name": name, "type": "servers_transport" });
    if let (Some(object), Some(extra)) = (declared.as_object_mut(), fields.as_object()) {
        object.extend(extra.clone());
    }
    declared
}

/// A loadbalancer service over one `https://` server, naming `transport` when given.
fn https_service(name: &str, addr: SocketAddr, transport: Option<&str>) -> Value {
    let mut service = json!({
        "name": name,
        "type": "loadbalancer",
        "servers": [{ "url": format!("https://{addr}") }],
    });
    if let Some(transport) = transport {
        service["transport"] = json!(transport);
    }
    service
}

/// An app on `host` whose one revision serves `services`, with `transports` declared. The
/// default router sends everything to service `web`.
fn tls_app(id: &str, host: &str, services: &[Value], transports: &[Value]) -> Value {
    let revision = json!({ "id": "r1", "state": "serving", "weight": 100, "services": services });
    let mut app = app(id, &[host], &[revision]);
    app["transports"] = json!(transports);
    app
}

/// An app whose service `web` reaches `addr` through the transport `fields` (none when `None`).
fn one_transport(host: &str, addr: SocketAddr, fields: Option<&Value>) -> Value {
    match fields {
        Some(fields) => tls_app(
            "a",
            host,
            &[https_service("web", addr, Some("t"))],
            &[transport("t", fields)],
        ),
        None => tls_app("a", host, &[https_service("web", addr, None)], &[]),
    }
}

async fn push(podgate: &Podgate, version: u64, app: Value) {
    let response = podgate.push_snapshot(&snapshot(version, &[app])).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

async fn rejection_codes(podgate: &Podgate, app: Value) -> (u16, Vec<String>) {
    let response = podgate.push_snapshot(&snapshot(1000, &[app])).await;
    let codes = response.json()["conflicts"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|entry| entry["code"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    (response.status, codes)
}

#[tokio::test]
async fn upstream_tls_verified_with_ca() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    let addr = Backend::new(ca.server(&[])).start().await;
    push(
        &podgate,
        1,
        one_transport("a.test", addr, Some(&json!({ "ca_pem": ca.pem }))),
    )
    .await;

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body, "ok");
    assert_eq!(response.header("x-tls"), Some("1.3"));
}

#[tokio::test]
async fn upstream_tls_wrong_ca_502() {
    let podgate = Podgate::start().await;
    let (ca, other) = (Ca::new("upstream ca"), Ca::new("someone else"));
    let addr = Backend::new(ca.server(&[])).start().await;
    push(
        &podgate,
        1,
        one_transport("a.test", addr, Some(&json!({ "ca_pem": other.pem }))),
    )
    .await;

    assert_eq!(podgate.get("a.test", "/").await.status, 502);
}

#[tokio::test]
async fn upstream_tls_default_roots_refuse_a_private_ca() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    let addr = Backend::new(ca.server(&[])).start().await;
    push(&podgate, 1, one_transport("a.test", addr, None)).await;

    assert_eq!(podgate.get("a.test", "/").await.status, 502);
}

#[tokio::test]
async fn upstream_tls_sni_sent() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    let addr = Backend::new(ca.server(&["backend.test"])).start().await;
    push(
        &podgate,
        1,
        one_transport(
            "a.test",
            addr,
            Some(&json!({ "ca_pem": ca.pem, "server_name": "backend.test" })),
        ),
    )
    .await;

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.header("x-sni"), Some("backend.test"));

    // The name is verified, not just sent: a certificate without it is refused.
    let wrong = Backend::new(ca.server(&[])).start().await;
    push(
        &podgate,
        2,
        one_transport(
            "a.test",
            wrong,
            Some(&json!({ "ca_pem": ca.pem, "server_name": "backend.test" })),
        ),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 502);
}

#[tokio::test]
async fn upstream_tls_default_sni() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    // The URL host is an IP literal: no SNI is sent, and the certificate is checked against the
    // IP in its SAN (this one carries only 127.0.0.1).
    let addr = Backend::new(ca.server(&[])).start().await;
    push(
        &podgate,
        1,
        one_transport("a.test", addr, Some(&json!({ "ca_pem": ca.pem }))),
    )
    .await;

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.header("x-sni"), Some("none"));

    // An IP literal the certificate does not carry is refused: verification is not skipped.
    let elsewhere = Ca::new("elsewhere").issue(&["10.9.9.9"], None);
    let addr = Backend::new(elsewhere).start().await;
    push(
        &podgate,
        2,
        one_transport("a.test", addr, Some(&json!({ "ca_pem": ca.pem }))),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 502);
}

#[tokio::test]
async fn upstream_mtls_client_cert_presented() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    let client = ca.client(7);
    let addr = Backend::new(ca.server(&[]))
        .asking_for_certificates_of(&ca)
        .start()
        .await;
    push(
        &podgate,
        1,
        one_transport(
            "a.test",
            addr,
            Some(&json!({
                "ca_pem": ca.pem,
                "client_cert": { "cert_pem": client.cert_pem, "key_pem": client.key_pem },
            })),
        ),
    )
    .await;

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.header("x-client-cert"),
        Some(client.digest().as_str())
    );
}

#[tokio::test]
async fn insecure_skip_verify_connects() {
    let podgate = Podgate::start().await;
    let stranger = TestCert::new(&["unrelated.test"]);
    let addr = Backend::new(Leaf {
        cert_pem: stranger.cert_pem,
        key_pem: stranger.key_pem,
    })
    .start()
    .await;

    push(&podgate, 1, one_transport("a.test", addr, None)).await;
    assert_eq!(
        podgate.get("a.test", "/").await.status,
        502,
        "verified by default"
    );

    push(
        &podgate,
        2,
        one_transport(
            "a.test",
            addr,
            Some(&json!({ "insecure_skip_verify": true })),
        ),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body, "ok");
}

#[tokio::test]
async fn plan_lists_insecure_skip_verify() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    let addr = Backend::new(ca.server(&[])).start().await;
    let verified = json!({ "ca_pem": ca.pem });
    push(&podgate, 1, one_transport("a.test", addr, Some(&verified))).await;

    let insecure = one_transport(
        "a.test",
        addr,
        Some(&json!({ "insecure_skip_verify": true })),
    );
    let response = podgate
        .admin_post("/v1/snapshot/plan", &snapshot(2, &[insecure]))
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.json()["posture_changes"],
        json!([{
            "host": "a.test",
            "app": "a",
            "kind": "upstream_tls_verification_disabled",
        }])
    );

    // Tightening back, and staying insecure, are not relaxations.
    let same = one_transport("a.test", addr, Some(&verified));
    let response = podgate
        .admin_post("/v1/snapshot/plan", &snapshot(2, &[same]))
        .await;
    assert_eq!(response.json()["posture_changes"], json!([]));
}

#[tokio::test]
async fn invalid_transport_ca_rejected() {
    let podgate = Podgate::start().await;
    let addr: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    for ca_pem in [
        "not a pem",
        "",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    ] {
        let (status, codes) = rejection_codes(
            &podgate,
            one_transport("a.test", addr, Some(&json!({ "ca_pem": ca_pem }))),
        )
        .await;
        assert_eq!(
            (status, codes),
            (422, vec!["invalid_transport".to_owned()]),
            "{ca_pem:?}"
        );
    }
}

#[tokio::test]
async fn invalid_transport_key_rejected() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("ca");
    let (client, other) = (ca.client(1), ca.client(2));
    let addr: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let with = |cert: &str, key: &str| {
        one_transport(
            "a.test",
            addr,
            Some(&json!({ "client_cert": { "cert_pem": cert, "key_pem": key } })),
        )
    };
    for (what, app) in [
        ("garbage key", with(&client.cert_pem, "not a key")),
        (
            "key of another certificate",
            with(&client.cert_pem, &other.key_pem),
        ),
        ("garbage certificate", with("not a cert", &client.key_pem)),
    ] {
        let (status, codes) = rejection_codes(&podgate, app).await;
        assert_eq!(
            (status, codes),
            (422, vec!["invalid_transport".to_owned()]),
            "{what}"
        );
    }
}

#[tokio::test]
async fn transport_pool_isolated() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    // Same serial number, different keys: Pingora's own reuse hash names a client certificate by
    // its serial alone, so only the transport fingerprint keeps these two apart.
    let (one, two) = (ca.client(42), ca.client(42));
    assert_ne!(one.digest(), two.digest());
    let addr = Backend::new(ca.server(&[]))
        .asking_for_certificates_of(&ca)
        .start()
        .await;
    let with = |name: &str, client: &Leaf| {
        transport(
            name,
            &json!({
                "ca_pem": ca.pem,
                "client_cert": { "cert_pem": client.cert_pem, "key_pem": client.key_pem },
            }),
        )
    };
    let mut app = tls_app(
        "a",
        "a.test",
        &[
            https_service("svc_one", addr, Some("one")),
            https_service("svc_two", addr, Some("two")),
        ],
        &[with("one", &one), with("two", &two)],
    );
    app["routers"] = json!([
        router(
            "one",
            json!({ "all": [{ "host": "a.test" }, { "path_prefix": "/one" }] }),
            "svc_one"
        ),
        router(
            "two",
            json!({ "all": [{ "host": "a.test" }, { "path_prefix": "/two" }] }),
            "svc_two"
        ),
    ]);
    push(&podgate, 1, app).await;

    let conn = |response: &common::Response| -> (String, String) {
        assert_eq!(response.status, 200, "{}", response.body);
        (
            response.header("x-conn").expect("x-conn").to_owned(),
            response
                .header("x-client-cert")
                .expect("x-client-cert")
                .to_owned(),
        )
    };
    let first = conn(&podgate.get("a.test", "/one").await);
    sleep(POOL_SETTLE).await;
    let again = conn(&podgate.get("a.test", "/one").await);
    assert_eq!(first, again, "one transport reuses its pooled connection");
    sleep(POOL_SETTLE).await;
    let other = conn(&podgate.get("a.test", "/two").await);
    assert_ne!(
        first.0, other.0,
        "another transport never draws that connection"
    );
    assert_eq!(first.1, one.digest());
    assert_eq!(other.1, two.digest());
    sleep(POOL_SETTLE).await;
    assert_eq!(conn(&podgate.get("a.test", "/two").await), other);
}

#[tokio::test]
async fn client_cert_key_never_leaks() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    let client = ca.client(7);
    let addr = Backend::new(ca.server(&[])).start().await;
    let key_body = client.key_pem.lines().nth(1).expect("key body").to_owned();
    push(
        &podgate,
        1,
        one_transport(
            "a.test",
            addr,
            Some(&json!({
                "ca_pem": ca.pem,
                "client_cert": { "cert_pem": client.cert_pem, "key_pem": client.key_pem },
            })),
        ),
    )
    .await;

    let explained = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(explained.status, 200, "{}", explained.body);
    assert!(!explained.body.contains(&key_body), "{}", explained.body);
    assert!(
        !explained.body.contains("PRIVATE KEY"),
        "{}",
        explained.body
    );
    assert_eq!(
        explained.json()["revisions"][0]["servers"][0]["transport"],
        json!({ "ca": true, "client_cert": "[redacted]", "insecure_skip_verify": false })
    );

    // A malformed client_cert is refused without quoting what was sent.
    let (status, _) = rejection_codes(
        &podgate,
        one_transport(
            "a.test",
            addr,
            Some(&json!({ "client_cert": client.key_pem })),
        ),
    )
    .await;
    assert_eq!(status, 422);
    let response = podgate
        .push_snapshot(&snapshot(
            3,
            &[one_transport(
                "a.test",
                addr,
                Some(&json!({ "client_cert": client.key_pem })),
            )],
        ))
        .await;
    assert!(!response.body.contains(&key_body), "{}", response.body);
}

#[tokio::test]
async fn min_tls_version_enforced_or_unsupported() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    let old = Backend::new(ca.server(&[])).tls12_only().start().await;

    // Pingora's rustls connector has no knob to drop TLS 1.2, so 1.3 is refused up front.
    let (status, codes) = rejection_codes(
        &podgate,
        one_transport(
            "a.test",
            old,
            Some(&json!({ "ca_pem": ca.pem, "min_tls_version": "1.3" })),
        ),
    )
    .await;
    assert_eq!(
        (status, codes),
        (422, vec!["unsupported_setting".to_owned()])
    );
    let (status, codes) = rejection_codes(
        &podgate,
        one_transport(
            "a.test",
            old,
            Some(&json!({ "ca_pem": ca.pem, "min_tls_version": "1.0" })),
        ),
    )
    .await;
    assert_eq!((status, codes), (422, vec!["invalid_transport".to_owned()]));

    // 1.2 is the floor that is always applied: a 1.2-only upstream is reached.
    push(
        &podgate,
        2,
        one_transport(
            "a.test",
            old,
            Some(&json!({ "ca_pem": ca.pem, "min_tls_version": "1.2" })),
        ),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.header("x-tls"), Some("1.2"));
}

#[tokio::test]
async fn a_transport_with_tls_options_needs_https_servers() {
    let podgate = Podgate::start().await;
    let addr: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let mut plain = https_service("web", addr, Some("t"));
    plain["servers"] = json!([{ "url": format!("http://{addr}") }]);
    let (status, codes) = rejection_codes(
        &podgate,
        tls_app(
            "a",
            "a.test",
            &[plain],
            &[transport("t", &json!({ "server_name": "x.test" }))],
        ),
    )
    .await;
    assert_eq!(status, 422);
    // The refused service also leaves its router without one, which is reported as well.
    assert_eq!(codes.first().map(String::as_str), Some("invalid_service"));

    let (status, codes) = rejection_codes(
        &podgate,
        tls_app(
            "a",
            "a.test",
            &[https_service("web", addr, Some("missing"))],
            &[],
        ),
    )
    .await;
    assert_eq!(status, 422);
    assert_eq!(codes.first().map(String::as_str), Some("unknown_transport"));
}

#[tokio::test]
async fn failure_replay_reaches_a_tls_upstream_through_its_transport() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("upstream ca");
    let addr = Backend::new(ca.server(&[])).answering(500).start().await;
    push(
        &podgate,
        1,
        one_transport("a.test", addr, Some(&json!({ "ca_pem": ca.pem }))),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/boom").await.status, 500);

    let listed = podgate.admin_get("/v1/apps/a/failures").await.json();
    let id = listed["failures"][0]["id"].as_u64().expect("failure id");
    let replayed = podgate
        .admin_post(
            &format!("/v1/apps/a/failures/{id}/replay?revision=r1"),
            &json!({}),
        )
        .await;
    assert_eq!(replayed.status, 200, "{}", replayed.body);
    assert_eq!(replayed.json()["status"], 500);
    assert_eq!(replayed.json()["body"], "ok");
}
