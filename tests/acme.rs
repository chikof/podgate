//! HA ACME and on-demand TLS against `pebble`.
//!
//! The test plays the control plane: it pushes snapshots, reads the event feed of the issuer
//! node, answers every `acme_challenge` with a snapshot that carries the token, and stores every
//! `certificate_issued` back in the snapshot. `pebble` validates HTTP-01 for real: its DNS is
//! `pebble-challtestsrv`, which answers every name with 127.0.0.1, and its HTTP-01 port is the
//! issuer's plain HTTP listener. A missing `pebble` fails the tests; nothing is skipped.

mod common;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::pebble::{Pebble, Pki, Validation};
use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use instant_acme::{Account, Key, RevocationRequest};
use rcgen::KeyPair;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};

const ISSUER: &str = "n1";
/// Longest to wait for one step of the ACME round trip.
const STEP: Duration = Duration::from_secs(45);

/// Held while a test starts its processes, so the tests of one `cargo test` process (threads)
/// do not race each other for ports. Starting is serialized; running is not.
static STARTUP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A `podgate` node called `name`, started under [`STARTUP`].
async fn node(name: &str) -> Podgate {
    let _startup = STARTUP.lock().await;
    Podgate::start_with_env(&[("NODE_NAME", name)]).await
}

/// The control plane: the snapshot it keeps, pushed to every node, and the issuer's event feed.
struct Plane {
    nodes: Vec<Arc<Podgate>>,
    version: u64,
    apps: Vec<Value>,
    directory: String,
    account_key_pem: Option<String>,
    challenges: Vec<Value>,
    certificates: Vec<Value>,
    requested: Vec<String>,
    /// Approve `certificate_requested` events by listing the host in `acme.requested_hosts`.
    approve_requests: bool,
    /// Store every issued certificate in the snapshot at once. Off: the test does it.
    auto_store: bool,
    after: u64,
    unclaimed: VecDeque<Value>,
    log: Arc<Mutex<Vec<Value>>>,
}

impl Plane {
    /// A plane over `nodes`; `nodes[0]` is the issuer and the one whose events it reads.
    fn new(nodes: Vec<Arc<Podgate>>, directory: &str, apps: Vec<Value>) -> Self {
        Self {
            nodes,
            version: 0,
            apps,
            directory: directory.to_owned(),
            account_key_pem: None,
            challenges: Vec::new(),
            certificates: Vec::new(),
            requested: Vec::new(),
            approve_requests: false,
            auto_store: true,
            after: 0,
            unclaimed: VecDeque::new(),
            log: Arc::default(),
        }
    }

    fn snapshot(&self) -> Value {
        let mut pushed = snapshot(self.version, &self.apps);
        pushed["certificates"] = Value::Array(self.certificates.clone());
        pushed["acme"] = json!({
            "issuer_node": ISSUER,
            "directory_url": self.directory,
            "account_key_pem": self.account_key_pem,
            "challenges": self.challenges,
            "requested_hosts": self.requested,
        });
        pushed
    }

    /// Pushes the snapshot to every node, the issuer last, so a validation request that
    /// follows the issuer's view of the token finds it everywhere.
    async fn push(&mut self) {
        self.version += 1;
        let pushed = self.snapshot();
        for node in self.nodes.iter().rev() {
            let response = node.push_snapshot(&pushed).await;
            assert_eq!(response.status, 200, "{response:?}");
        }
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
        match event["kind"].as_str() {
            Some("acme_challenge") => {
                self.challenges.push(json!({
                    "token": event["token"], "key_authorization": event["key_authorization"],
                }));
                self.push().await;
            }
            Some("certificate_issued") if self.auto_store => self.store(event).await,
            Some("certificate_requested") if self.approve_requests => {
                if let Some(host) = event["host"].as_str() {
                    self.requested.push(host.to_owned());
                    self.push().await;
                }
            }
            _ => {}
        }
    }

    /// One long poll of the issuer's feed; reacts to what arrives.
    async fn poll(&mut self) {
        // 1 s long poll: the admin API ends a request at `REQUEST_TIMEOUT_SECS` (5 s in the
        // harness) with `408`, and a loaded machine can stall a longer poll past it.
        let path = format!("/v1/events?after={}&timeout_secs=1", self.after);
        let response = self.nodes[0].admin_get(&path).await;
        if response.status == 408 {
            // Nothing was consumed: `after` is unchanged, so the next poll loses no event.
            return;
        }
        assert_eq!(response.status, 200, "{response:?}");
        let body = response.json();
        let events = body["events"].as_array().cloned().unwrap_or_default();
        for event in events {
            self.after = event["seq"].as_u64().expect("seq");
            self.react(&event).await;
            self.log.lock().expect("log lock").push(event.clone());
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
    issuer: Arc<Podgate>,
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

/// An issuer node called `n1` that trusts pebble's CA, and a running pebble whose HTTP-01
/// validation hits that node.
async fn setup() -> Setup {
    let _startup = STARTUP.lock().await;
    static DIRS: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "podgate-acme-{}-{}",
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
    let pebble = Pebble::start(
        pki,
        Validation {
            http: Some(issuer.proxy_addr.port()),
            tls: None,
        },
    )
    .await;
    let upstream = Upstream::start("upstream body").await;
    Setup {
        issuer: Arc::new(issuer),
        pebble,
        upstream,
        dir,
    }
}

impl Setup {
    fn acme_app(&self, id: &str, hosts: &[&str]) -> Value {
        app(id, hosts, &[serving("r1", self.upstream.addr)])
    }

    fn on_demand_app(&self, id: &str, hosts: &[&str]) -> Value {
        let mut on_demand = self.acme_app(id, hosts);
        on_demand["tls"]["mode"] = json!("on_demand");
        on_demand
    }

    fn plane(&self, apps: Vec<Value>) -> Plane {
        Plane::new(vec![Arc::clone(&self.issuer)], &self.pebble.directory, apps)
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

#[tokio::test]
async fn acme_challenge_event() {
    let setup = setup().await;
    let other = node("n2").await;
    let apps = vec![setup.acme_app("a", &["a.test"])];
    let mut plane = Plane::new(
        vec![Arc::clone(&setup.issuer), Arc::new(other)],
        &setup.pebble.directory,
        apps,
    );
    plane.push().await;

    let challenge = plane.wait_for("acme_challenge").await;
    let token = challenge["token"].as_str().expect("token");
    let key_authorization = challenge["key_authorization"]
        .as_str()
        .expect("key authorization");
    assert!(!token.is_empty(), "{challenge}");
    assert!(
        key_authorization.starts_with(&format!("{token}.")),
        "key authorization is the token, a dot and the account thumbprint: {challenge}"
    );

    let quiet = plane.nodes[1].admin_get("/v1/events").await.json();
    assert_eq!(
        quiet["events"],
        json!([]),
        "only the node named in acme.issuer_node orders"
    );
}

#[tokio::test]
async fn acme_http01_served() {
    let setup = setup().await;
    let other = Arc::new(node("n2").await);
    let apps = vec![setup.acme_app("a", &["a.test"])];
    let mut plane = Plane::new(
        vec![Arc::clone(&setup.issuer), Arc::clone(&other)],
        &setup.pebble.directory,
        apps,
    );
    plane.push().await;

    let challenge = plane.wait_for("acme_challenge").await;
    let path = format!(
        "/.well-known/acme-challenge/{}",
        challenge["token"].as_str().expect("token")
    );
    let expected = challenge["key_authorization"]
        .as_str()
        .expect("key authorization");
    for node in &plane.nodes {
        let served = node.get("a.test", &path).await;
        assert_eq!(served.status, 200, "{served:?}");
        assert_eq!(served.body, expected);
        let unrouted = node.get("not-an-app.test", &path).await;
        assert_eq!(
            unrouted.body, expected,
            "the validation host needs no route: {unrouted:?}"
        );
        let unknown = node
            .get("a.test", "/.well-known/acme-challenge/not-a-pushed-token")
            .await;
        assert_eq!(
            unknown.body, "upstream body",
            "a token the snapshot does not hold is routed like any request: {unknown:?}"
        );
        // The answered challenges took no tenant slot, and the routed request gives its slot
        // back when its `logging` callback runs, which can be just after the client has the body.
        let mut metrics = String::new();
        for _ in 0..40 {
            metrics = node.admin_get("/metrics").await.body;
            if metrics.contains("podgate_tenant_inflight{tenant=\"t1\"} 0\n") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            metrics.contains("podgate_tenant_inflight{tenant=\"t1\"} 0\n"),
            "tenant slots leaked:\n{metrics}"
        );
    }

    // pebble validates the token through the issuer's plain HTTP port before it issues.
    let issued = plane.wait_for("certificate_issued").await;
    assert_eq!(issued["hosts"], json!(["a.test"]), "{issued}");
}

#[tokio::test]
async fn acme_certificate_issued() {
    let setup = setup().await;
    let mut plane = setup.plane(vec![setup.acme_app("a", &["a.test", "b.test"])]);
    plane.push().await;

    let issued = plane.wait_for("certificate_issued").await;
    assert_eq!(issued["hosts"], json!(["a.test", "b.test"]), "{issued}");
    let chain = pem_certs(issued["cert_pem"].as_str().expect("cert_pem"));
    assert!(chain.len() >= 2, "leaf and intermediate: {}", chain.len());
    let key_pem = issued["key_pem"].as_str().expect("key_pem");
    assert!(key_pem.contains("PRIVATE KEY"), "{key_pem}");

    // Pushed back, the certificate serves the TLS listener, and it chains to pebble's root.
    let root = trust(setup.pebble.root().await);
    for host in ["a.test", "b.test"] {
        let response = setup.issuer.https_get(host, host, "/", &root).await;
        assert_eq!(response.status, 200, "{host}: {response:?}");
        assert_eq!(response.body, "upstream body");
    }
    assert!(
        !plane.sees("acme_challenge", Duration::from_secs(4)).await,
        "a host with a certificate is not ordered again"
    );
}

#[tokio::test]
async fn acme_ari_renewal() {
    let setup = setup().await;
    let mut plane = setup.plane(vec![
        setup.acme_app("a", &["a.test"]),
        setup.acme_app("b", &["b.test"]),
    ]);
    let account_key = KeyPair::generate().expect("account key").serialize_pem();
    plane.account_key_pem = Some(account_key.clone());
    plane.auto_store = false;
    plane.push().await;

    // Both certificates are issued but not stored yet. The control plane revokes b.test's
    // first, so the CA's renewal information for it says "renew now" from the first time the
    // issuer asks, which is when the certificates reach it in the snapshot.
    let mut issued = Vec::new();
    while issued.len() < 2 {
        issued.push(plane.wait_for("certificate_issued").await);
    }
    let for_b = issued
        .iter()
        .find(|event| event["hosts"] == json!(["b.test"]))
        .expect("b.test was issued")
        .clone();
    revoke(
        &setup.pebble.pki.ca_pem,
        &setup.pebble.directory,
        &account_key,
        for_b["cert_pem"].as_str().expect("cert_pem"),
    )
    .await;
    for event in &issued {
        plane.store(event).await;
    }

    let renewed = plane.wait_for("certificate_issued").await;
    assert_eq!(renewed["hosts"], json!(["b.test"]), "{renewed}");
    assert_ne!(
        renewed["cert_pem"], for_b["cert_pem"],
        "a new certificate, not the old one again"
    );
    // The ARI window of the healthy certificate is weeks away: it is left alone.
    assert!(
        !plane
            .sees("certificate_issued", Duration::from_secs(4))
            .await,
        "a.test is not renewed early"
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
async fn on_demand_issues() {
    let setup = setup().await;
    let mut plane = setup.plane(vec![setup.on_demand_app("p", &["*.preview.test"])]);
    plane.approve_requests = true;
    plane.push().await;
    let log = Arc::clone(&plane.log);
    let control_plane = tokio::spawn(async move {
        loop {
            plane.poll().await;
        }
    });

    // The first handshake for a host under the wildcard waits for the round trip, then serves.
    let root = trust(setup.pebble.root().await);
    let started = Instant::now();
    let response = setup
        .issuer
        .https_get("x1.preview.test", "x1.preview.test", "/", &root)
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "upstream body");
    let first = started.elapsed();

    // The certificate is in the snapshot now: the next handshake does not wait.
    let started = Instant::now();
    let again = setup
        .issuer
        .https_get("x1.preview.test", "x1.preview.test", "/", &root)
        .await;
    assert_eq!(again.status, 200, "{again:?}");
    // Not the wait for issuance (30 s on the server, 1.7 s and up for the first handshake): the
    // bound only has to separate "served at once" from "waited", with room for a loaded machine.
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "second handshake {:?} vs first {first:?}",
        started.elapsed()
    );
    control_plane.abort();

    let issued: Vec<Value> = log
        .lock()
        .expect("log lock")
        .iter()
        .filter(|event| event["kind"] == "certificate_issued")
        .cloned()
        .collect();
    assert_eq!(
        issued.len(),
        1,
        "one certificate, for the one host: {issued:?}"
    );
    assert_eq!(issued[0]["hosts"], json!(["x1.preview.test"]));
    assert!(
        setup.pebble.log().contains(ORDER_PATH),
        "pebble's log must show orders, or the no-order test proves nothing:\n{}",
        setup.pebble.log()
    );
}

/// pebble's new-order endpoint, as its request log names it.
const ORDER_PATH: &str = "order-plz";

#[tokio::test]
async fn on_demand_unapproved_creates_no_order() {
    let setup = setup().await;
    let mut plane = setup.plane(vec![setup.on_demand_app("p", &["*.preview.test"])]);
    plane.push().await;

    // A flood of handshakes for random names under the wildcard hits the issuer node itself.
    let handshakes: Vec<_> = (0..20)
        .map(|n| {
            let issuer = Arc::clone(&setup.issuer);
            tokio::spawn(async move {
                let anchor = TestCert::new(&["unused.test"]);
                issuer
                    .https_handshake_fails(&format!("x{}.preview.test", n % 2), &anchor)
                    .await
            })
        })
        .collect();
    // The control plane sees the requests and approves nothing.
    let mut requested = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        plane.poll().await;
    }
    for event in plane.log.lock().expect("log lock").iter() {
        match event["kind"].as_str() {
            Some("certificate_requested") => requested.push(event["host"].clone()),
            other => panic!("only certificate_requested events are expected, got {other:?}"),
        }
    }
    requested.sort_by_key(Value::to_string);
    assert_eq!(
        requested,
        [json!("x0.preview.test"), json!("x1.preview.test")],
        "once per host, not once per handshake"
    );
    for handshake in handshakes {
        handshake.abort();
    }
    assert!(
        !setup.pebble.log().contains(ORDER_PATH),
        "an unapproved SNI must not reach the CA:\n{}",
        setup.pebble.log()
    );
}

#[tokio::test]
async fn on_demand_refuses_unknown() {
    let setup = setup().await;
    let mut plane = setup.plane(vec![
        setup.on_demand_app("p", &["*.preview.test"]),
        setup.acme_app("a", &["a.test"]),
    ]);
    plane.push().await;
    let log = Arc::clone(&plane.log);
    let control_plane = tokio::spawn(async move {
        loop {
            plane.poll().await;
        }
    });

    // Neither a name no app claims, nor a name two labels under the wildcard, nor the apex
    // gets a certificate, and the handshake fails at once instead of waiting.
    let anchor = TestCert::new(&["unused.test"]);
    for sni in ["unknown.test", "a.b.preview.test", "preview.test"] {
        let started = Instant::now();
        assert!(
            setup.issuer.https_handshake_fails(sni, &anchor).await,
            "{sni} must not get a certificate"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{sni} must be refused at once, took {:?}",
            started.elapsed()
        );
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    control_plane.abort();

    let issued: Vec<Value> = log
        .lock()
        .expect("log lock")
        .iter()
        .filter(|event| event["kind"] == "certificate_issued")
        .cloned()
        .collect();
    // Only a.test, an `acme` app's own host, is ever ordered.
    assert!(
        issued
            .iter()
            .all(|event| event["hosts"] == json!(["a.test"])),
        "{issued:?}"
    );
}

#[tokio::test]
async fn on_demand_non_issuer_requests() {
    // A node that is not the issuer cannot order: it tells the control plane instead.
    let node = Arc::new(node("n2").await);
    let upstream = Upstream::start("upstream body").await;
    let mut on_demand = app("p", &["*.preview.test"], &[serving("r1", upstream.addr)]);
    on_demand["tls"]["mode"] = json!("on_demand");
    let mut plane = Plane::new(
        vec![Arc::clone(&node)],
        "https://127.0.0.1:1/dir",
        vec![on_demand],
    );
    plane.push().await;

    let handshake = tokio::spawn({
        let node = Arc::clone(&node);
        async move {
            let anchor = TestCert::new(&["unused.test"]);
            node.https_handshake_fails("x9.preview.test", &anchor).await
        }
    });
    let requested = plane.wait_for("certificate_requested").await;
    assert_eq!(requested["host"], "x9.preview.test", "{requested}");
    handshake.abort();
}

#[tokio::test]
async fn on_demand_requested_hosts_are_ordered() {
    // What a non-issuer node's `certificate_requested` becomes once the control plane approves
    // it: the host in `acme.requested_hosts` makes the issuer order it.
    let setup = setup().await;
    let mut plane = setup.plane(vec![
        setup.on_demand_app("p", &["*.preview.test"]),
        setup.acme_app("a", &["a.test"]),
    ]);
    plane.requested = vec![
        "x7.preview.test".to_owned(),
        "not-an-app.test".to_owned(),
        "a.test".to_owned(),
    ];
    plane.push().await;

    let mut issued = Vec::new();
    while issued.len() < 2 {
        issued.push(plane.wait_for("certificate_issued").await["hosts"].clone());
    }
    issued.sort_by_key(Value::to_string);
    assert_eq!(issued, [json!(["a.test"]), json!(["x7.preview.test"])]);
    assert!(
        !plane
            .sees("certificate_issued", Duration::from_secs(3))
            .await,
        "a host of no app is never ordered"
    );
}
