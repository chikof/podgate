//! TLS-ALPN-01 against `pebble`.
//!
//! `pebble` validates for real: its DNS is `pebble-challtestsrv`, which answers every name with
//! 127.0.0.1, and its TLS-ALPN-01 port is the issuer node's TLS listener. The test plays the
//! control plane: it reads the issuer's event feed, pushes every `tls-alpn-01` challenge back in
//! `acme.challenges`, and stores the certificate. A certificate that comes out proves the node
//! answered the CA's `acme-tls/1` handshake with a challenge certificate the CA accepted. A
//! missing `pebble` fails the tests; nothing is skipped.

mod common;

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const ISSUER: &str = "n1";
/// Longest to wait for one step of the ACME round trip.
const STEP: Duration = Duration::from_secs(45);
/// Times to start `pebble` before giving up: its ports come from `common::free_ports`.
const START_ATTEMPTS: u32 = 5;
/// Longest one start attempt waits for pebble's ports to open.
const START_WAIT: Duration = Duration::from_secs(30);

/// Held while a test starts its processes, so the tests of one `cargo test` process (threads)
/// do not race each other for ports. Starting is serialized; running is not.
static STARTUP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A private CA that signs the certificate of pebble's own HTTPS listener.
#[derive(Clone)]
struct Pki {
    dir: PathBuf,
    ca_pem: PathBuf,
    ca_der: CertificateDer<'static>,
    server_pem: PathBuf,
    server_key: PathBuf,
}

impl Pki {
    fn new(dir: &Path) -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "podgate test acme server ca");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca = ca_params.self_signed(&ca_key).expect("ca cert");

        let mut server_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        server_params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().expect("dns name")),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        let server_key = KeyPair::generate().expect("server key");
        let issuer = Issuer::new(ca_params, ca_key);
        let server = server_params
            .signed_by(&server_key, &issuer)
            .expect("server cert");

        let write = |name: &str, content: String| {
            let path = dir.join(name);
            std::fs::write(&path, content).expect("write pki file");
            path
        };
        Self {
            dir: dir.to_owned(),
            ca_pem: write("acme-ca.pem", ca.pem()),
            ca_der: ca.der().clone(),
            server_pem: write("pebble.pem", server.pem()),
            server_key: write("pebble.key", server_key.serialize_pem()),
        }
    }

    /// The text of `name` in the directory, empty when it does not exist.
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }
}

/// `pebble` and `pebble-challtestsrv`, killed on drop.
struct Pebble {
    children: Vec<Child>,
    directory: String,
    management: SocketAddr,
    /// challtestsrv's management API.
    challtest: SocketAddr,
    pki: Pki,
}

impl Pebble {
    /// Starts both, with pebble's TLS-ALPN-01 validation pointed at `tls_port` on 127.0.0.1. The
    /// other ports come from `common::free_ports`, which another process can take between
    /// the probe and the bind, so a process that exits at start is retried with fresh ports.
    async fn start(pki: Pki, tls_port: u16) -> Self {
        let mut failures = Vec::new();
        for attempt in 1..=START_ATTEMPTS {
            match Self::try_start(pki.clone(), tls_port).await {
                Ok(started) => return started,
                Err(reason) => failures.push(format!("attempt {attempt}: {reason}")),
            }
        }
        panic!("pebble did not start:\n{}", failures.join("\n"));
    }

    async fn try_start(pki: Pki, tls_port: u16) -> Result<Self, String> {
        let ports = common::free_ports(5);
        let (acme, management, http) = (ports[0], ports[1], ports[2]);
        let (dns, challtest) = (ports[3], ports[4]);
        let config = json!({"pebble": {
            "listenAddress": format!("127.0.0.1:{acme}"),
            "managementListenAddress": format!("127.0.0.1:{management}"),
            "certificate": pki.server_pem,
            "privateKey": pki.server_key,
            "httpPort": http,
            "tlsPort": tls_port,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
            "retryAfter": {"authz": 1, "order": 1},
            "profiles": {"default": {"description": "test", "validityPeriod": 7_776_000}},
        }});
        let config_path = pki.dir.join("pebble-config.json");
        std::fs::write(&config_path, config.to_string()).expect("write pebble config");
        let log = |name: &str| {
            Stdio::from(std::fs::File::create(pki.dir.join(name)).expect("create log file"))
        };
        let challtestsrv = Command::new("pebble-challtestsrv")
            .args([
                "-dnsserver",
                &format!("127.0.0.1:{dns}"),
                "-management",
                &format!("127.0.0.1:{challtest}"),
                "-http01",
                "",
                "-https01",
                "",
                "-tlsalpn01",
                "",
                "-doh",
                "",
                "-defaultIPv4",
                "127.0.0.1",
                "-defaultIPv6",
                "",
            ])
            .stdout(log("challtestsrv.log"))
            .stderr(log("challtestsrv.err"))
            .spawn()
            .expect("spawn pebble-challtestsrv: it must be on PATH (devenv shell)");
        let pebble = Command::new("pebble")
            .arg("-config")
            .arg(&config_path)
            .args(["-dnsserver", &format!("127.0.0.1:{dns}")])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_AUTHZREUSE", "0")
            // pebble answers badNonce to 5% of requests by default; instant-acme retries a
            // POST only twice, so about 1 in 1000 POSTs would fail an order for nothing.
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .stdout(log("pebble.log"))
            .stderr(log("pebble.err"))
            .spawn()
            .expect("spawn pebble: it must be on PATH (devenv shell)");
        let mut this = Self {
            children: vec![challtestsrv, pebble],
            directory: format!("https://127.0.0.1:{acme}/dir"),
            management: SocketAddr::from(([127, 0, 0, 1], management)),
            challtest: SocketAddr::from(([127, 0, 0, 1], challtest)),
            pki,
        };
        // On `Err`, dropping `this` kills what is left.
        this.wait_until_listening(acme).await?;
        Ok(this)
    }

    /// `Ok` once pebble's and challtestsrv's ports accept connections; `Err` as soon as either
    /// process exits, with its output, or after [`START_WAIT`].
    async fn wait_until_listening(&mut self, acme_port: u16) -> Result<(), String> {
        let deadline = Instant::now() + START_WAIT;
        while Instant::now() < deadline {
            for (child, name) in self.children.iter_mut().zip(["challtestsrv", "pebble"]) {
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(format!(
                        "{name} exited with {status}\n--- {name}.log\n{}\n--- {name}.err\n{}",
                        self.pki.read(&format!("{name}.log")),
                        self.pki.read(&format!("{name}.err")),
                    ));
                }
            }
            let up = TcpStream::connect(("127.0.0.1", acme_port)).await.is_ok()
                && TcpStream::connect(self.management).await.is_ok()
                && TcpStream::connect(self.challtest).await.is_ok();
            if up {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!(
            "no listener after {START_WAIT:?}\n--- pebble.log\n{}\n--- pebble.err\n{}",
            self.pki.read("pebble.log"),
            self.pki.read("pebble.err"),
        ))
    }

    /// pebble's root certificate, for a client that must trust what pebble issues.
    async fn root(&self) -> CertificateDer<'static> {
        let pem = tls_get(self.management, &self.pki.ca_der, "/roots/0").await;
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .next()
            .expect("pebble serves a root")
            .expect("root is PEM")
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        for child in &mut self.children {
            drop(child.kill());
            drop(child.wait());
        }
    }
}

/// `GET path` over TLS to `addr`, trusting only `ca`; returns the body.
async fn tls_get(addr: SocketAddr, ca: &CertificateDer<'static>, path: &str) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).expect("trust the test ca");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .expect("handshake with pebble");
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .expect("send");
    let mut raw = Vec::new();
    // pebble closes without a TLS close_notify; what was read is the whole answer.
    drop(tls.read_to_end(&mut raw).await);
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or(text)
}

const ALPN01: &[u8] = b"acme-tls/1";
const ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";

/// Accepts any certificate: the tests compare what the server sent instead.
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

/// A TLS handshake with `addr` for `name` (`None`: no SNI) offering exactly `alpn`.
async fn handshake(
    addr: SocketAddr,
    name: Option<&str>,
    alpn: &[&[u8]],
) -> std::io::Result<Client> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let server_name = match name {
        Some(name) => rustls::pki_types::ServerName::try_from(name.to_owned()).expect("name"),
        None => rustls::pki_types::ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()),
    };
    let tcp = TcpStream::connect(addr).await.expect("connect");
    tokio::time::timeout(
        Duration::from_secs(10),
        TlsConnector::from(Arc::new(config)).connect(server_name, tcp),
    )
    .await
    .expect("handshake in time")
}

fn leaf(tls: &Client) -> CertificateDer<'static> {
    tls.get_ref()
        .1
        .peer_certificates()
        .and_then(<[_]>::first)
        .expect("the server sent a certificate")
        .clone()
        .into_owned()
}

fn negotiated(tls: &Client) -> Option<Vec<u8>> {
    tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
}

/// The `acmeIdentifier` extension of `der`: whether it is critical, and its value.
fn acme_identifier(der: &CertificateDer<'_>) -> Option<(bool, Vec<u8>)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parses");
    cert.extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == ACME_IDENTIFIER)
        .map(|extension| (extension.critical, extension.value.to_vec()))
}

/// The DER OCTET STRING of the SHA-256 of `key_authorization`, as RFC 8737 puts it in the
/// extension.
fn digest_of(key_authorization: &str) -> Vec<u8> {
    let mut value = vec![0x04, 0x20];
    value.extend_from_slice(&Sha256::digest(key_authorization.as_bytes()));
    value
}

/// An app of tenant `t1` for `hosts` that proves them with TLS-ALPN-01.
fn alpn_app(id: &str, hosts: &[&str], upstream: SocketAddr) -> Value {
    let mut alpn = app(id, hosts, &[serving("r1", upstream)]);
    alpn["tls"]["challenge"] = json!("tls-alpn-01");
    alpn
}

/// The control plane: the snapshot it keeps, pushed to every node, and the issuer's event feed.
struct Plane<'a> {
    /// The issuer first.
    nodes: Vec<&'a Podgate>,
    pebble: &'a Pebble,
    version: u64,
    apps: Vec<Value>,
    certificates: Vec<Value>,
    /// The answers pushed back in `acme.challenges`.
    challenges: Vec<Value>,
    after: u64,
    unclaimed: VecDeque<Value>,
}

impl<'a> Plane<'a> {
    fn new(nodes: Vec<&'a Podgate>, pebble: &'a Pebble, apps: Vec<Value>) -> Self {
        Self {
            nodes,
            pebble,
            version: 0,
            apps,
            certificates: Vec::new(),
            challenges: Vec::new(),
            after: 0,
            unclaimed: VecDeque::new(),
        }
    }

    async fn push(&mut self) {
        self.version += 1;
        let mut pushed = snapshot(self.version, &self.apps);
        pushed["certificates"] = Value::Array(self.certificates.clone());
        pushed["acme"] = json!({
            "issuer_node": ISSUER,
            "directory_url": self.pebble.directory,
            "challenges": self.challenges,
        });
        for node in &self.nodes {
            let response = node.push_snapshot(&pushed).await;
            assert_eq!(response.status, 200, "{response:?}");
        }
    }

    async fn react(&mut self, event: &Value) {
        match (event["kind"].as_str(), event["type"].as_str()) {
            (Some("acme_challenge"), Some("tls-alpn-01")) => {
                self.challenges.push(json!({
                    "name": event["name"], "key_authorization": event["key_authorization"],
                }));
                self.push().await;
            }
            (Some("certificate_issued"), _) => {
                self.certificates.push(json!({
                    "hosts": event["hosts"], "cert_pem": event["cert_pem"], "key_pem": event["key_pem"],
                }));
                self.push().await;
            }
            _ => {}
        }
    }

    /// One long poll of the issuer's feed; reacts to what arrives.
    async fn poll(&mut self) {
        let path = format!("/v1/events?after={}&timeout_secs=1", self.after);
        let response = self.nodes[0].admin_get(&path).await;
        if response.status == 408 {
            return;
        }
        assert_eq!(response.status, 200, "{response:?}");
        for event in response.json()["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            self.after = event["seq"].as_u64().expect("seq");
            self.react(&event).await;
            self.unclaimed.push_back(event);
        }
    }

    /// The next event of `kind`, reacting to everything on the way.
    async fn wait_for(&mut self, kind: &str) -> Value {
        let deadline = Instant::now() + STEP;
        loop {
            if let Some(at) = self
                .unclaimed
                .iter()
                .position(|event| event["kind"] == kind)
            {
                return self.unclaimed.remove(at).expect("position is in range");
            }
            assert!(Instant::now() < deadline, "no {kind} event in time");
            self.poll().await;
        }
    }
}

struct Setup {
    issuer: Podgate,
    pebble: Pebble,
    upstream: Upstream,
    /// Temp directory of the PKI and pebble files; removed on drop.
    dir: PathBuf,
}

impl Drop for Setup {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

/// An issuer node called `n1` that trusts pebble's CA, and a running pebble whose TLS-ALPN-01
/// validation hits that node's TLS listener.
async fn setup() -> Setup {
    let _startup = STARTUP.lock().await;
    static DIRS: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "podgate-acme-alpn-{}-{}",
        std::process::id(),
        DIRS.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let pki = Pki::new(&dir);
    let ca_file = pki.ca_pem.to_string_lossy().into_owned();
    let issuer = Podgate::start_with_env(&[
        ("NODE_NAME", ISSUER),
        ("ACME_CA_FILE", &ca_file),
        ("RUST_LOG", "warn,podgate=debug"),
    ])
    .await;
    let pebble = Pebble::start(pki, issuer.tls_addr.port()).await;
    let upstream = Upstream::start("upstream body").await;
    Setup {
        issuer,
        pebble,
        upstream,
        dir,
    }
}

/// A node that is not the issuer, holding `apps`, an optional certificate for `hosts`,
/// and the pushed `challenges` (`(name, key_authorization)`).
async fn holder(
    apps: &[Value],
    certificate: Option<&TestCert>,
    hosts: &[&str],
    challenges: &[(&str, &str)],
) -> Podgate {
    let node = Podgate::start_with_env(&[("NODE_NAME", "other")]).await;
    let mut pushed = snapshot(1, apps);
    pushed["acme"] = json!({
        "issuer_node": ISSUER,
        "directory_url": "https://127.0.0.1:1/dir",
        "challenges": challenges.iter()
            .map(|(name, key_authorization)| json!({"name": name, "key_authorization": key_authorization}))
            .collect::<Vec<_>>(),
    });
    if let Some(certificate) = certificate {
        pushed["certificates"] = json!([certificate.entry(hosts)]);
    }
    let response = node.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
    node
}

#[tokio::test]
async fn alpn01_issued_against_pebble() {
    let setup = setup().await;
    let apps = vec![alpn_app("a", &["a.test"], setup.upstream.addr)];
    let mut plane = Plane::new(vec![&setup.issuer], &setup.pebble, apps);
    plane.push().await;

    let challenge = plane.wait_for("acme_challenge").await;
    let mut keys: Vec<&str> = challenge
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["key_authorization", "kind", "name", "seq", "type"]);
    assert_eq!(challenge["type"], "tls-alpn-01");
    assert_eq!(challenge["name"], "a.test");

    // pebble connected to the node's TLS port with `acme-tls/1` and checked the certificate, so
    // a certificate that comes out proves the answer was right.
    let issued = plane.wait_for("certificate_issued").await;
    assert_eq!(issued["hosts"], json!(["a.test"]), "{issued}");
    let root = common::TestCert {
        cert_pem: String::new(),
        key_pem: String::new(),
        der: setup.pebble.root().await,
    };
    let response = setup.issuer.https_get("a.test", "a.test", "/", &root).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "upstream body");
}

#[tokio::test]
async fn alpn01_second_node_answers() {
    let setup = setup().await;
    let second = Podgate::start_with_env(&[("NODE_NAME", "n2")]).await;
    let apps = vec![alpn_app("a", &["a.test"], setup.upstream.addr)];
    let mut plane = Plane::new(vec![&setup.issuer, &second], &setup.pebble, apps);
    plane.push().await;

    let challenge = plane.wait_for("acme_challenge").await;
    let key_authorization = challenge["key_authorization"].as_str().expect("key");
    plane.wait_for("certificate_issued").await;

    // The challenge stays in the snapshot, so both nodes answer: the issuer (which pebble
    // validated against) and the node that never ordered anything.
    for node in [&setup.issuer, &second] {
        let tls = handshake(node.tls_addr, Some("a.test"), &[ALPN01])
            .await
            .expect("the node answers acme-tls/1");
        assert_eq!(negotiated(&tls).as_deref(), Some(ALPN01));
        assert_eq!(
            acme_identifier(&leaf(&tls)),
            Some((true, digest_of(key_authorization)))
        );
    }
}

#[tokio::test]
async fn alpn01_normal_clients_unaffected() {
    let upstream = Upstream::start("upstream body").await;
    let cert = TestCert::new(&["a.test"]);
    let apps = [alpn_app("a", &["a.test"], upstream.addr)];
    let node = holder(&apps, Some(&cert), &["a.test"], &[("a.test", "tok.thumb")]).await;

    // A challenge is pending, and clients that do not speak `acme-tls/1` never see it.
    for offered in [
        &[&b"h2"[..], b"http/1.1"][..],
        &[b"http/1.1"],
        &[ALPN01, b"h2", b"http/1.1"],
        &[ALPN01, b"http/1.1"],
        &[],
    ] {
        let tls = handshake(node.tls_addr, Some("a.test"), offered)
            .await
            .expect("a normal handshake");
        let expected: Option<&[u8]> = match offered.first() {
            None => None,
            Some(first) if *first == ALPN01 => offered.get(1).copied(),
            Some(first) => Some(first),
        };
        assert_eq!(negotiated(&tls).as_deref(), expected, "offered {offered:?}");
        assert_eq!(
            leaf(&tls),
            cert.der,
            "the app's certificate, not the challenge's"
        );
        assert_eq!(acme_identifier(&leaf(&tls)), None);
    }

    let response = node.https_get("a.test", "a.test", "/", &cert).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "upstream body");

    let tls = handshake(node.tls_addr, Some("a.test"), &[b"h2"])
        .await
        .expect("h2 handshake");
    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(connection);
    let request = http::Request::get("https://a.test/")
        .body(())
        .expect("request");
    let (response, _) = client.send_request(request, true).expect("send request");
    let response = response.await.expect("h2 response");
    assert_eq!(response.status(), 200);
}

/// A backend that counts the connections it accepts and answers nothing.
async fn counting_upstream() -> (SocketAddr, Arc<AtomicU32>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let count = Arc::new(AtomicU32::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        // Keeps the accepted sockets open so the proxy would see a live backend.
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::Relaxed);
            held.push(stream);
        }
    });
    (addr, count)
}

#[tokio::test]
async fn alpn01_connection_closed_not_routed() {
    let (upstream, connections) = counting_upstream().await;
    let apps = [alpn_app("a", &["a.test"], upstream)];
    let node = holder(&apps, None, &[], &[("a.test", "tok.thumb")]).await;

    let mut tls = handshake(node.tls_addr, Some("a.test"), &[ALPN01])
        .await
        .expect("the challenge handshake completes");
    assert_eq!(negotiated(&tls).as_deref(), Some(ALPN01));
    // A request after the handshake gets no answer: the node already closed the connection.
    drop(
        tls.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
            .await,
    );
    let mut raw = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut raw))
        .await
        .expect("the node closes the connection");
    assert!(raw.is_empty(), "no HTTP answer: {read:?} {raw:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        connections.load(Ordering::Relaxed),
        0,
        "the request never reached routing or the backend"
    );
}

#[tokio::test]
async fn alpn01_wildcard_rejected() {
    let node = Podgate::start_with_env(&[("NODE_NAME", "other")]).await;
    let target: SocketAddr = ([127, 0, 0, 1], 9).into();
    let mut pushed = snapshot(1, &[alpn_app("a", &["*.a.test"], target)]);
    pushed["acme"] = json!({"issuer_node": ISSUER, "directory_url": "https://127.0.0.1:1/dir"});
    let response = node.push_snapshot(&pushed).await;
    assert_eq!(response.status, 422, "{response:?}");
    let conflicts = response.json()["conflicts"].clone();
    let conflicts = conflicts.as_array().expect("conflicts");
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    assert_eq!(conflicts[0]["code"], "tls_alpn_wildcard");
    assert_eq!(conflicts[0]["app"], "a");
    assert_eq!(conflicts[0]["host"], "*.a.test");

    let mut on_demand = alpn_app("a", &["a.test"], target);
    on_demand["tls"]["mode"] = json!("on_demand");
    let mut pushed = snapshot(2, &[on_demand]);
    pushed["acme"] = json!({"issuer_node": ISSUER, "directory_url": "https://127.0.0.1:1/dir"});
    let response = node.push_snapshot(&pushed).await;
    assert_eq!(response.status, 422, "{response:?}");
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "tls_alpn_needs_acme_mode"
    );
}

#[tokio::test]
async fn alpn01_unclaimed_host_no_challenge_cert() {
    let upstream = Upstream::start("upstream body").await;
    let target = upstream.addr;
    let mut http_app = app("h", &["c.test"], &[serving("r1", target)]);
    http_app["tls"]["challenge"] = json!("http-01");
    let apps = [alpn_app("a", &["a.test"], target), http_app];
    // Pushed answers for a name nobody claims (`b.test`) and for a name an http-01 app claims.
    let challenges = [
        ("a.test", "tok.a"),
        ("b.test", "tok.b"),
        ("c.test", "tok.c"),
    ];
    let node = holder(&apps, None, &[], &challenges).await;

    let tls = handshake(node.tls_addr, Some("a.test"), &[ALPN01])
        .await
        .expect("the claimed name is answered");
    assert_eq!(
        acme_identifier(&leaf(&tls)),
        Some((true, digest_of("tok.a")))
    );
    for name in [Some("b.test"), Some("c.test"), Some("d.test"), None] {
        assert!(
            handshake(node.tls_addr, name, &[ALPN01]).await.is_err(),
            "{name:?} gets a handshake failure, not a certificate"
        );
    }

    // Without the pushed answer the claimed name is refused too.
    let bare = holder(&apps, None, &[], &[]).await;
    assert!(
        handshake(bare.tls_addr, Some("a.test"), &[ALPN01])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn alpn01_unsupported_or_working() {
    let upstream = Upstream::start("upstream body").await;
    let apps = [alpn_app("a", &["a.test"], upstream.addr)];
    // Pingora's listener cannot carry `acme-tls/1`, but the pre-TLS hook can answer it, so the
    // setting is accepted (no `unsupported_setting`) and works.
    let node = holder(&apps, None, &[], &[("a.test", "tok.a")]).await;
    let tls = handshake(node.tls_addr, Some("a.test"), &[ALPN01])
        .await
        .expect("acme-tls/1 is answered");
    assert_eq!(negotiated(&tls).as_deref(), Some(ALPN01));
}
