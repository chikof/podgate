//! DNS-01 and wildcard certificates against `pebble`.
//!
//! `pebble-challtestsrv` is pebble's DNS. The test plays the control plane: it reads the issuer's
//! event feed, publishes every `dns-01` challenge as a TXT record through challtestsrv's
//! management API (`/set-txt`), and confirms it in the snapshot (`acme.dns_ready`). pebble
//! validates for real, by querying that DNS, so a certificate that comes out proves the record
//! the event asked for was the one the CA wanted. A missing `pebble` fails the tests; nothing is
//! skipped.

mod common;

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use instant_acme::{Account, Key, RevocationRequest};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const ISSUER: &str = "n1";
/// The zone the operator allows DNS-01 for in these tests.
const ZONE: &str = "wild.test";
/// Longest to wait for one step of the ACME round trip.
const STEP: Duration = Duration::from_secs(45);
/// Times to start `pebble` before giving up: its ports come from [`free_port`].
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
    /// challtestsrv's management API: the control plane's way to publish TXT records.
    challtest: SocketAddr,
    pki: Pki,
}

impl Pebble {
    /// Starts both. The ports come from [`free_port`], which another process can take between
    /// the probe and the bind, so a process that exits at start is retried with fresh ports.
    async fn start(pki: Pki) -> Self {
        let mut failures = Vec::new();
        for attempt in 1..=START_ATTEMPTS {
            match Self::try_start(pki.clone()).await {
                Ok(started) => return started,
                Err(reason) => failures.push(format!("attempt {attempt}: {reason}")),
            }
        }
        panic!("pebble did not start:\n{}", failures.join("\n"));
    }

    async fn try_start(pki: Pki) -> Result<Self, String> {
        let ports = common::free_ports(6);
        let (acme, management, http, tls_alpn) = (ports[0], ports[1], ports[2], ports[3]);
        let (dns, challtest) = (ports[4], ports[5]);
        let config = json!({"pebble": {
            "listenAddress": format!("127.0.0.1:{acme}"),
            "managementListenAddress": format!("127.0.0.1:{management}"),
            "certificate": pki.server_pem,
            "privateKey": pki.server_key,
            "httpPort": http,
            "tlsPort": tls_alpn,
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

    /// A call to challtestsrv's management API; returns the response body.
    async fn dns(&self, path: &str, body: &Value) -> String {
        let body = body.to_string();
        let mut tcp = TcpStream::connect(self.challtest)
            .await
            .expect("connect to challtestsrv");
        tcp.write_all(
            format!(
                "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("send");
        let mut raw = Vec::new();
        tcp.read_to_end(&mut raw).await.expect("read");
        let text = String::from_utf8_lossy(&raw).into_owned();
        text.split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or(text)
    }

    /// Publishes the TXT record `value` at `name`. A name can hold several values.
    async fn set_txt(&self, name: &str, value: &str) {
        self.dns(
            "/set-txt",
            &json!({"host": format!("{name}."), "value": value}),
        )
        .await;
    }

    /// Removes every TXT record at `name`.
    async fn clear_txt(&self, name: &str) {
        self.dns("/clear-txt", &json!({"host": format!("{name}.")}))
            .await;
    }

    /// How many TXT queries the DNS server has answered for `name`: what the CA asked.
    async fn txt_queries(&self, name: &str) -> usize {
        let history = self
            .dns("/dns-request-history", &json!({"host": name}))
            .await;
        let entries: Vec<Value> = serde_json::from_str(&history).expect("history is JSON");
        entries
            .iter()
            .filter(|entry| entry["Question"]["Qtype"] == 16)
            .count()
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

/// What the control plane has published: a TXT record at the DNS server and, once it sees the
/// record there, its confirmation in the snapshot.
#[derive(Clone, PartialEq, Eq)]
struct Record {
    name: String,
    value: String,
}

/// The control plane: the snapshot it keeps, pushed to the issuer, and the issuer's event feed.
struct Plane<'a> {
    issuer: &'a Podgate,
    pebble: &'a Pebble,
    version: u64,
    apps: Vec<Value>,
    account_key_pem: Option<String>,
    certificates: Vec<Value>,
    /// The TXT records set at the DNS server.
    published: Vec<Record>,
    /// Confirm a record in `acme.dns_ready` as soon as it is published. Off: the test does it
    /// with [`Plane::confirm_published`].
    confirm: bool,
    /// Store every issued certificate in the snapshot at once. Off: the test does it.
    auto_store: bool,
    ready: Vec<Record>,
    after: u64,
    unclaimed: VecDeque<Value>,
    /// Every event seen, in order.
    log: Vec<Value>,
}

impl<'a> Plane<'a> {
    fn new(issuer: &'a Podgate, pebble: &'a Pebble, apps: Vec<Value>) -> Self {
        Self {
            issuer,
            pebble,
            version: 0,
            apps,
            account_key_pem: None,
            certificates: Vec::new(),
            published: Vec::new(),
            confirm: true,
            auto_store: true,
            ready: Vec::new(),
            after: 0,
            unclaimed: VecDeque::new(),
            log: Vec::new(),
        }
    }

    fn snapshot(&self) -> Value {
        let mut pushed = snapshot(self.version, &self.apps);
        pushed["certificates"] = Value::Array(self.certificates.clone());
        pushed["acme"] = json!({
            "issuer_node": ISSUER,
            "directory_url": self.pebble.directory,
            "account_key_pem": self.account_key_pem,
            "dns_ready": self.ready.iter()
                .map(|record| json!({"name": record.name, "value": record.value}))
                .collect::<Vec<_>>(),
        });
        pushed
    }

    async fn push(&mut self) {
        self.version += 1;
        let response = self.issuer.push_snapshot(&self.snapshot()).await;
        assert_eq!(response.status, 200, "{response:?}");
    }

    /// Confirms every published record in the snapshot, the way a control plane does once the
    /// zone's authoritative servers answer with it.
    async fn confirm_published(&mut self) {
        self.ready = self.published.clone();
        self.push().await;
    }

    /// Puts the certificate of a `certificate_issued` event in the snapshot and pushes it.
    async fn store(&mut self, event: &Value) {
        self.certificates
            .retain(|cert| cert["hosts"] != event["hosts"]);
        self.certificates.push(json!({
            "hosts": event["hosts"], "cert_pem": event["cert_pem"], "key_pem": event["key_pem"],
        }));
        self.push().await;
    }

    async fn react(&mut self, event: &Value) {
        let record = || Record {
            name: event["name"].as_str().unwrap_or_default().to_owned(),
            value: event["value"].as_str().unwrap_or_default().to_owned(),
        };
        match (event["kind"].as_str(), event["type"].as_str()) {
            (Some("acme_challenge"), Some("dns-01")) => {
                let record = record();
                self.pebble.set_txt(&record.name, &record.value).await;
                self.published.push(record);
                if self.confirm {
                    self.confirm_published().await;
                }
            }
            (Some("acme_challenge_done"), Some("dns-01")) => {
                let done = record();
                self.published.retain(|record| *record != done);
                self.ready.retain(|record| *record != done);
                if !self.published.iter().any(|record| record.name == done.name) {
                    self.pebble.clear_txt(&done.name).await;
                }
                self.push().await;
            }
            (Some("certificate_issued"), _) if self.auto_store => self.store(event).await,
            _ => {}
        }
    }

    /// One long poll of the issuer's feed; reacts to what arrives.
    async fn poll(&mut self) {
        // 1 s long poll: the admin API ends a request at `REQUEST_TIMEOUT_SECS` (5 s in the
        // harness) with `408`, and a loaded machine can stall a longer poll past it.
        let path = format!("/v1/events?after={}&timeout_secs=1", self.after);
        let response = self.issuer.admin_get(&path).await;
        if response.status == 408 {
            // Nothing was consumed: `after` is unchanged, so the next poll loses no event.
            return;
        }
        assert_eq!(response.status, 200, "{response:?}");
        let body = response.json();
        for event in body["events"].as_array().cloned().unwrap_or_default() {
            self.after = event["seq"].as_u64().expect("seq");
            self.react(&event).await;
            self.log.push(event.clone());
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

    /// The next `count` events of `kind`.
    async fn wait_for_n(&mut self, kind: &str, count: usize) -> Vec<Value> {
        let mut found = Vec::new();
        while found.len() < count {
            found.push(self.wait_for(kind).await);
        }
        found
    }

    /// Whether an event of `kind` arrives within `window`.
    async fn sees(&mut self, kind: &str, window: Duration) -> bool {
        self.unclaimed.retain(|event| event["kind"] != kind);
        let deadline = Instant::now() + window;
        while Instant::now() < deadline {
            if self.unclaimed.iter().any(|event| event["kind"] == kind) {
                return true;
            }
            self.poll().await;
        }
        false
    }
}

struct Setup {
    issuer: Podgate,
    pebble: Pebble,
    /// Keeps the upstream the apps point at alive.
    upstream: Upstream,
    /// Temp directory of the PKI and pebble files; removed on drop.
    dir: PathBuf,
}

impl Drop for Setup {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

/// An issuer node called `n1` that trusts pebble's CA and may use DNS-01 for [`ZONE`], and a
/// running pebble whose DNS is challtestsrv. `logged` keeps the issuer's log for
/// [`Podgate::log`].
async fn setup(logged: bool) -> Setup {
    let _startup = STARTUP.lock().await;
    static DIRS: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "podgate-acme-dns01-{}-{}",
        std::process::id(),
        DIRS.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let pki = Pki::new(&dir);
    let ca_file = pki.ca_pem.to_string_lossy().into_owned();
    let env = [
        ("NODE_NAME", ISSUER),
        ("ACME_CA_FILE", ca_file.as_str()),
        ("ACME_DNS_ZONES", ZONE),
        ("RUST_LOG", "warn,podgate=debug"),
    ];
    let issuer = if logged {
        Podgate::start_logged(&env).await
    } else {
        Podgate::start_with_env(&env).await
    };
    let pebble = Pebble::start(pki).await;
    let upstream = Upstream::start("upstream body").await;
    Setup {
        issuer,
        pebble,
        upstream,
        dir,
    }
}

impl Setup {
    /// An `acme` app of tenant `t1` for `hosts`, proven with DNS-01.
    fn dns_app(&self, id: &str, hosts: &[&str]) -> Value {
        let mut dns = app(id, hosts, &[serving("r1", self.upstream.addr)]);
        dns["tls"]["challenge"] = json!("dns-01");
        dns
    }

    fn plane(&self, apps: Vec<Value>) -> Plane<'_> {
        Plane::new(&self.issuer, &self.pebble, apps)
    }
}

fn pem_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("PEM certificates")
}

/// A client trust anchor for `der`.
fn trust(der: CertificateDer<'static>) -> TestCert {
    TestCert {
        cert_pem: String::new(),
        key_pem: String::new(),
        der,
    }
}

/// base64url without padding, the alphabet of a DNS-01 value.
fn is_dns_value(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[tokio::test]
async fn dns01_wildcard_issued_and_served() {
    let setup = setup(false).await;
    let mut plane = setup.plane(vec![setup.dns_app("a", &["wild.test", "*.wild.test"])]);
    plane.push().await;

    let issued = plane.wait_for("certificate_issued").await;
    assert_eq!(
        issued["hosts"],
        json!(["*.wild.test", "wild.test"]),
        "{issued}"
    );
    let chain = pem_certs(issued["cert_pem"].as_str().expect("cert_pem"));
    assert!(chain.len() >= 2, "leaf and intermediate: {}", chain.len());

    // Pushed back, the certificate serves the TLS listener for the apex and any one-label name
    // under the wildcard, and it chains to pebble's root.
    let root = trust(setup.pebble.root().await);
    for host in ["wild.test", "x1.wild.test", "x2.wild.test"] {
        let response = setup.issuer.https_get(host, host, "/", &root).await;
        assert_eq!(response.status, 200, "{host}: {response:?}");
        assert_eq!(response.body, "upstream body");
    }
    assert!(
        !plane.sees("acme_challenge", Duration::from_secs(3)).await,
        "hosts with a certificate are not ordered again"
    );
}

#[tokio::test]
async fn dns01_never_answers_ca_before_dns_ready() {
    let setup = setup(false).await;
    let mut plane = setup.plane(vec![setup.dns_app("a", &["wild.test", "*.wild.test"])]);
    plane.confirm = false;
    plane.push().await;

    // The TXT records are in DNS, as soon as the events arrive; the snapshot does not say so.
    let challenges = plane.wait_for_n("acme_challenge", 2).await;
    assert_eq!(challenges.len(), 2, "{challenges:?}");
    assert_eq!(plane.published.len(), 2, "both records are published");
    let name = "_acme-challenge.wild.test";
    assert!(
        !plane
            .sees("certificate_issued", Duration::from_secs(5))
            .await,
        "no certificate without the confirmation"
    );
    assert_eq!(
        setup.pebble.txt_queries(name).await,
        0,
        "the CA never looked at the record: validating early would burn the authorization"
    );
    // pebble logs a POST to `/chalZ/` when the client says a challenge is ready to validate.
    assert!(
        !setup.pebble.pki.read("pebble.log").contains("/chalZ/"),
        "pebble saw a validation request:\n{}",
        setup.pebble.pki.read("pebble.log")
    );

    plane.confirm_published().await;
    let issued = plane.wait_for("certificate_issued").await;
    assert_eq!(
        issued["hosts"],
        json!(["*.wild.test", "wild.test"]),
        "{issued}"
    );
    assert!(
        setup.pebble.txt_queries(name).await >= 1,
        "the CA validated after the confirmation"
    );
}

#[tokio::test]
async fn dns01_event_name_and_value() {
    let setup = setup(false).await;
    let mut plane = setup.plane(vec![setup.dns_app("a", &["a.wild.test"])]);
    plane.push().await;

    let challenge = plane.wait_for("acme_challenge").await;
    let mut keys: Vec<&str> = challenge
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["kind", "name", "seq", "type", "value"],
        "the event carries the record and nothing else, in particular not the key authorization"
    );
    assert_eq!(challenge["type"], "dns-01");
    assert_eq!(challenge["name"], "_acme-challenge.a.wild.test");
    assert!(
        is_dns_value(challenge["value"].as_str().expect("value")),
        "base64url of a SHA-256 digest: {challenge}"
    );

    // pebble compares what the CA computes with the record this value became, so a certificate
    // proves the value was the right one.
    let issued = plane.wait_for("certificate_issued").await;
    assert_eq!(issued["hosts"], json!(["a.wild.test"]), "{issued}");
}

#[tokio::test]
async fn dns01_apex_and_wildcard_two_values() {
    let setup = setup(false).await;
    let mut plane = setup.plane(vec![setup.dns_app("a", &["wild.test", "*.wild.test"])]);
    plane.push().await;

    let challenges = plane.wait_for_n("acme_challenge", 2).await;
    assert!(
        challenges
            .iter()
            .all(|event| event["type"] == "dns-01" && event["name"] == "_acme-challenge.wild.test"),
        "apex and wildcard share one name: {challenges:?}"
    );
    assert_ne!(
        challenges[0]["value"], challenges[1]["value"],
        "with two values, so the control plane must publish both"
    );
    assert!(
        !plane.sees("acme_challenge", Duration::from_secs(2)).await,
        "exactly two challenges"
    );
    let issued = plane.wait_for("certificate_issued").await;
    assert_eq!(
        issued["hosts"],
        json!(["*.wild.test", "wild.test"]),
        "{issued}"
    );
}

#[tokio::test]
async fn dns01_done_event_after_validation() {
    let setup = setup(false).await;
    let mut plane = setup.plane(vec![setup.dns_app("a", &["wild.test", "*.wild.test"])]);
    plane.push().await;

    let challenges = plane.wait_for_n("acme_challenge", 2).await;
    let issued = plane.wait_for("certificate_issued").await;
    let done = plane.wait_for_n("acme_challenge_done", 2).await;
    for challenge in &challenges {
        assert!(
            done.iter().any(|event| event["type"] == "dns-01"
                && event["name"] == challenge["name"]
                && event["value"] == challenge["value"]),
            "every announced record is released: {done:?}"
        );
    }
    let seq = |event: &Value| event["seq"].as_u64().expect("seq");
    let validated = plane
        .log
        .iter()
        .find(|event| event["kind"] == "acme_challenge_done")
        .map(seq)
        .expect("a done event");
    assert!(
        validated < seq(&issued),
        "the records are released after validation, before the certificate: {:?}",
        plane.log
    );
    assert!(
        plane.published.is_empty(),
        "the control plane removed the records"
    );
}

/// Pushes `apps` with ACME settings to a node that is not the issuer, so nothing is ordered,
/// and returns the `conflicts` of the `422`. `env` is added to the node's environment.
async fn rejected_with(env: &[(&str, &str)], apps: &[Value]) -> Vec<Value> {
    let mut vars = vec![("NODE_NAME", "other")];
    vars.extend_from_slice(env);
    let node = Podgate::start_with_env(&vars).await;
    let mut pushed = snapshot(1, apps);
    pushed["acme"] = json!({"issuer_node": ISSUER, "directory_url": "https://127.0.0.1:1/dir"});
    let response = node.push_snapshot(&pushed).await;
    assert_eq!(response.status, 422, "{response:?}");
    response.json()["conflicts"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn plain_app(id: &str, hosts: &[&str], challenge: &str) -> Value {
    let mut plain = app(id, hosts, &[serving("r1", ([127, 0, 0, 1], 9).into())]);
    plain["tls"]["challenge"] = json!(challenge);
    plain
}

#[tokio::test]
async fn wildcard_needs_dns01_rejected() {
    let conflicts = rejected_with(
        &[("ACME_DNS_ZONES", ZONE)],
        &[plain_app("a", &["*.wild.test"], "http-01")],
    )
    .await;
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    assert_eq!(conflicts[0]["code"], "wildcard_needs_dns01");
    assert_eq!(conflicts[0]["app"], "a");
    assert_eq!(conflicts[0]["host"], "*.wild.test");
}

#[tokio::test]
async fn dns01_zone_not_allowed_rejected() {
    let conflicts = rejected_with(
        &[("ACME_DNS_ZONES", ZONE)],
        &[plain_app("a", &["a.wild.test", "*.other.test"], "dns-01")],
    )
    .await;
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    assert_eq!(conflicts[0]["code"], "dns01_zone_not_allowed");
    assert_eq!(conflicts[0]["host"], "*.other.test");
}

#[tokio::test]
async fn dns01_not_enabled_rejected() {
    let conflicts = rejected_with(&[], &[plain_app("a", &["a.wild.test"], "dns-01")]).await;
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    assert_eq!(conflicts[0]["code"], "dns01_not_enabled");
}

#[tokio::test]
async fn dns01_too_many_hosts_rejected() {
    let hosts = [
        "a.wild.test",
        "b.wild.test",
        "c.wild.test",
        "d.wild.test",
        "e.wild.test",
    ];
    let conflicts = rejected_with(
        &[("ACME_DNS_ZONES", ZONE)],
        &[plain_app("a", &hosts, "dns-01")],
    )
    .await;
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    assert_eq!(conflicts[0]["code"], "dns01_too_many_hosts");
}

#[tokio::test]
async fn dns01_on_demand_rejected() {
    let mut on_demand = plain_app("a", &["*.wild.test"], "dns-01");
    on_demand["tls"]["mode"] = json!("on_demand");
    let conflicts = rejected_with(&[("ACME_DNS_ZONES", ZONE)], &[on_demand]).await;
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    assert_eq!(conflicts[0]["code"], "dns01_needs_acme_mode");
}

/// An app of tenant `t1` whose router claims `host` on the path `path` only, so two of them
/// can share a host without a `host_conflict`.
fn app_at(id: &str, host: &str, path: &str, challenge: &str) -> Value {
    let mut at = plain_app(id, &[host], challenge);
    let matcher = json!({"all": [{"host": host}, {"path": path}]});
    at["routers"] = json!([common::router("default", matcher, "web")]);
    at
}

#[tokio::test]
async fn dns01_shared_wildcard_must_agree_on_the_challenge() {
    let conflicts = rejected_with(
        &[("ACME_DNS_ZONES", ZONE)],
        &[
            app_at("a", "*.wild.test", "/a", "dns-01"),
            app_at("b", "*.wild.test", "/b", "http-01"),
        ],
    )
    .await;
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    assert_eq!(conflicts[0]["code"], "tls_policy_conflict");
}

#[tokio::test]
async fn wildcard_with_a_supplied_certificate_needs_no_dns01() {
    let node = Podgate::start_with_env(&[("NODE_NAME", "other")]).await;
    let mut pushed = snapshot(1, &[plain_app("a", &["*.wild.test"], "http-01")]);
    pushed["certificates"] = json!([TestCert::new(&["*.wild.test"]).entry(&["*.wild.test"])]);
    pushed["acme"] = json!({"issuer_node": ISSUER, "directory_url": "https://127.0.0.1:1/dir"});
    let response = node.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
}

#[tokio::test]
async fn dns01_wildcard_renews_by_ari() {
    let setup = setup(false).await;
    let mut plane = setup.plane(vec![setup.dns_app("a", &["wild.test", "*.wild.test"])]);
    let account_key = KeyPair::generate().expect("account key").serialize_pem();
    plane.account_key_pem = Some(account_key.clone());
    plane.auto_store = false;
    plane.push().await;

    // Issued but not stored yet. The control plane revokes it first, so the CA's renewal
    // information says "renew now" from the first time the issuer asks, which is when the
    // certificate reaches it in the snapshot.
    let first = plane.wait_for("certificate_issued").await;
    revoke(
        &setup.pebble.pki.ca_pem,
        &setup.pebble.directory,
        &account_key,
        first["cert_pem"].as_str().expect("cert_pem"),
    )
    .await;
    plane.store(&first).await;

    // The renewal is the same round trip: new challenges, published and confirmed, then a
    // certificate for the same names.
    let renewed = plane.wait_for("certificate_issued").await;
    assert_eq!(renewed["hosts"], first["hosts"], "{renewed}");
    assert_ne!(
        renewed["cert_pem"], first["cert_pem"],
        "a new certificate, not the old one again"
    );
    // One published challenge per authorization pebble created for the two orders. A reused one
    // needs none and the issuer skips it, see `common::pebble_authorizations_created`.
    let challenges = plane
        .log
        .iter()
        .filter(|event| event["kind"] == "acme_challenge")
        .count();
    let created = common::pebble_authorizations_created(&setup.pebble.pki.read("pebble.log"));
    assert_eq!(
        challenges, created,
        "one per new authorization: {:?}",
        plane.log
    );
    assert!(
        created > 2,
        "the renewal order needs a new authorization to prove the round trip: {:?}",
        plane.log
    );
}

/// Revokes `cert_pem` with the ACME account whose key is `account_key_pem`.
async fn revoke(ca_file: &Path, directory: &str, account_key_pem: &str, cert_pem: &str) {
    let der = PrivatePkcs8KeyDer::from_pem_slice(account_key_pem.as_bytes()).expect("account key");
    let key = Key::from_pkcs8_der(der.clone_key()).expect("usable key");
    let (account, _) = Account::builder_with_root(ca_file)
        .expect("builder")
        .create_from_key((key, PrivateKeyDer::Pkcs8(der)), directory.to_owned())
        .await
        .expect("the issuer's account");
    let leaf = pem_certs(cert_pem).remove(0);
    account
        .revoke(&RevocationRequest {
            certificate: &leaf,
            reason: None,
        })
        .await
        .expect("revoke");
}

#[tokio::test]
async fn dns01_no_secrets_in_events_or_logs() {
    let setup = setup(true).await;
    let mut plane = setup.plane(vec![setup.dns_app("a", &["wild.test", "*.wild.test"])]);
    let account_key = KeyPair::generate().expect("account key").serialize_pem();
    plane.account_key_pem = Some(account_key.clone());
    plane.push().await;
    let issued = plane.wait_for("certificate_issued").await;
    plane.wait_for_n("acme_challenge_done", 2).await;

    // Only `certificate_issued` carries a private key: the certificate's own, as before.
    let key_body = |pem: &str| {
        pem.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>()
    };
    let account_body = key_body(&account_key);
    let cert_key_body = key_body(issued["key_pem"].as_str().expect("key_pem"));
    for event in &plane.log {
        let text = event.to_string();
        assert!(!text.contains(&account_body), "account key in {text}");
        if event["kind"] != "certificate_issued" {
            assert!(!text.contains(&cert_key_body), "certificate key in {text}");
            assert!(!text.contains("PRIVATE KEY"), "a private key in {text}");
        }
    }
    let log = setup.issuer.log();
    assert!(log.contains("acme"), "the issuer logged its work:\n{log}");
    for secret in [&account_body, &cert_key_body] {
        assert!(!log.contains(secret.as_str()), "a key in the log:\n{log}");
    }

    // There is no field a credential could travel in: `dns_ready` entries take a name and a
    // value, and a snapshot that tries to add anything else is refused.
    let mut smuggled = plane.snapshot();
    smuggled["acme"]["dns_ready"] =
        json!([{"name": "_acme-challenge.wild.test", "value": "v", "api_token": "hunter2"}]);
    smuggled["version"] = json!(plane.version + 1);
    let response = setup.issuer.push_snapshot(&smuggled).await;
    assert!(
        (400..500).contains(&response.status),
        "a credential field is refused: {response:?}"
    );

    // `Debug` of the settings hides the account key and shows the records.
    let settings: podgate_model::Acme = serde_json::from_value(json!({
        "issuer_node": ISSUER, "directory_url": "https://ca.test/dir",
        "account_key_pem": account_key,
        "dns_ready": [{"name": "_acme-challenge.wild.test", "value": "abc"}],
    }))
    .expect("valid settings");
    let shown = format!("{settings:?}");
    assert!(!shown.contains(&account_body), "{shown}");
    assert!(shown.contains("_acme-challenge.wild.test"), "{shown}");
}
