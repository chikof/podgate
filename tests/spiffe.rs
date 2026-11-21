//! SPIFFE workload identity, end to end: podgate against a fake Workload API agent
//! (gRPC over a unix socket, served with `h2`) and a TLS upstream that demands a client SVID.
//!
//! The cast: one PKI (`td`) issues every SVID, so the agent's bundle is its root. Tenant `t1`
//! uses the SVID with hint `acme`, tenant `t2` the one with hint `beta`; `mesh` is the server's
//! identity. The upstream reports what it saw of the client in `x-peer-id` and `x-peer-serial`
//! and `x-conn` (its connection number).

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use common::{Podgate, Response, TestCert, app, serving};
use http::{Request, Response as HttpResponse};
use podgate::spiffe::client::{
    FETCH_X509_BUNDLES, FETCH_X509_SVID, SECURITY_HEADER, X509BundlesResponse, X509Svid,
    X509SvidResponse, frame,
};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, SanType, SerialNumber,
};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;

const ACME_ID: &str = "spiffe://td/ns/acme/sa/podgate";
const BETA_ID: &str = "spiffe://td/ns/beta/sa/podgate";
const MESH_ID: &str = "spiffe://td/ns/mesh/sa/db";
const CLIENT_ID: &str = "spiffe://td/ns/client/sa/web";

// --- The PKI -----------------------------------------------------------------------------------

/// What the agent hands out for one identity.
#[derive(Clone)]
struct Issued {
    id: String,
    hint: String,
    chain: Vec<u8>,
    key: Vec<u8>,
}

struct Pki {
    issuer: CertifiedIssuer<'static, KeyPair>,
    root: Vec<u8>,
}

impl Pki {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("CA key"))
            .expect("self-signed CA");
        let root = issuer.der().as_ref().to_vec();
        Self { issuer, root }
    }

    /// A certificate for `id`, valid for `valid_secs` from now.
    fn issue(&self, id: &str, hint: &str, serial: u64, valid_secs: i64) -> Issued {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(id).expect("uri"))];
        params.serial_number = Some(SerialNumber::from(serial));
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::seconds(valid_secs);
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        Issued {
            id: id.to_owned(),
            hint: hint.to_owned(),
            chain: cert.der().as_ref().to_vec(),
            key: key.serialize_der(),
        }
    }

    fn day(&self, id: &str, hint: &str, serial: u64) -> Issued {
        self.issue(id, hint, serial, 86_400)
    }
}

impl Issued {
    fn chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.chain.clone())]
    }

    fn key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.key.clone()).into()
    }

    fn svid(&self, root: &[u8]) -> X509Svid {
        X509Svid {
            spiffe_id: self.id.clone(),
            x509_svid: self.chain.clone(),
            x509_svid_key: self.key.clone(),
            bundle: root.to_vec(),
            hint: self.hint.clone(),
        }
    }
}

// --- The fake Workload API ---------------------------------------------------------------------

/// A Workload API agent: serves whatever was last [`Agent::set`] on both streams and pushes every
/// change to the open ones. [`Agent::stop`] is an outage.
struct Agent {
    path: PathBuf,
    svids: watch::Sender<X509SvidResponse>,
    bundles: watch::Sender<X509BundlesResponse>,
    task: Option<JoinHandle<()>>,
}

fn svid_response(root: &[u8], issued: &[&Issued]) -> X509SvidResponse {
    X509SvidResponse {
        svids: issued.iter().map(|issued| issued.svid(root)).collect(),
        crl: Vec::new(),
        federated_bundles: BTreeMap::new(),
    }
}

fn bundles_response(root: &[u8]) -> X509BundlesResponse {
    X509BundlesResponse {
        crl: Vec::new(),
        bundles: BTreeMap::from([("spiffe://td".to_owned(), root.to_vec())]),
    }
}

fn scratch_dir() -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "podgate-spiffe-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create the scratch dir");
    dir
}

impl Agent {
    fn start(pki: &Pki, issued: &[&Issued]) -> Self {
        let path = scratch_dir().join("agent.sock");
        let (svids, svids_rx) = watch::channel(svid_response(&pki.root, issued));
        let (bundles, bundles_rx) = watch::channel(bundles_response(&pki.root));
        let listener = UnixListener::bind(&path).expect("bind the agent socket");
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                connections.spawn(connection(stream, svids_rx.clone(), bundles_rx.clone()));
            }
        });
        Self {
            path,
            svids,
            bundles,
            task: Some(task),
        }
    }

    /// Hands out `issued` from now on, and tells every open stream.
    fn set(&self, pki: &Pki, issued: &[&Issued]) {
        self.svids.send_replace(svid_response(&pki.root, issued));
    }

    /// Hands out the roots `roots` as the bundle of `td`.
    fn set_bundle(&self, root: &[u8]) {
        self.bundles.send_replace(bundles_response(root));
    }

    /// The agent goes away: the listener and every open stream close.
    fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.path);
    }

    fn endpoint(&self) -> String {
        format!("unix://{}", self.path.display())
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn connection(
    stream: tokio::net::UnixStream,
    svids: watch::Receiver<X509SvidResponse>,
    bundles: watch::Receiver<X509BundlesResponse>,
) {
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    let mut calls = JoinSet::new();
    while let Some(Ok((request, respond))) = connection.accept().await {
        calls.spawn(call(request, respond, svids.clone(), bundles.clone()));
    }
}

async fn call(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    mut svids: watch::Receiver<X509SvidResponse>,
    mut bundles: watch::Receiver<X509BundlesResponse>,
) {
    let secure = request
        .headers()
        .get(SECURITY_HEADER)
        .is_some_and(|value| value == "true");
    let path = request.uri().path().to_owned();
    let mut body = request.into_body();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return };
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    let refuse = |status: &str| {
        HttpResponse::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .header("grpc-status", status)
            .body(())
            .expect("response")
    };
    if !secure {
        let _ = respond.send_response(refuse("3"), true);
        return;
    }
    let ok = HttpResponse::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .expect("response");
    match path.as_str() {
        FETCH_X509_SVID => {
            let Ok(mut out) = respond.send_response(ok, false) else {
                return;
            };
            loop {
                let message = svids.borrow_and_update().clone();
                if out.send_data(frame(&message), false).is_err() {
                    return;
                }
                if svids.changed().await.is_err() {
                    return;
                }
            }
        }
        FETCH_X509_BUNDLES => {
            let Ok(mut out) = respond.send_response(ok, false) else {
                return;
            };
            loop {
                let message = bundles.borrow_and_update().clone();
                if out.send_data(frame(&message), false).is_err() {
                    return;
                }
                if bundles.changed().await.is_err() {
                    return;
                }
            }
        }
        _ => {
            let _ = respond.send_response(refuse("12"), true);
        }
    }
}

// --- The upstream ------------------------------------------------------------------------------

/// A TLS server that demands a client certificate from `client_roots` and tells what it saw.
struct Backend {
    addr: SocketAddr,
    /// TCP connections accepted, handshake or not.
    accepted: Arc<AtomicU64>,
}

impl Backend {
    async fn start(server: &Issued, client_roots: &[&[u8]]) -> Self {
        let provider = Arc::new(default_provider());
        let mut roots = RootCertStore::empty();
        for root in client_roots {
            roots
                .add(CertificateDer::from(root.to_vec()))
                .expect("client root");
        }
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .expect("client verifier");
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(server.chain(), server.key())
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let addr = listener.local_addr().expect("backend addr");
        let accepted = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let number = counter.fetch_add(1, Ordering::Relaxed) + 1;
                tokio::spawn(serve(acceptor.clone(), tcp, number));
            }
        });
        Self { addr, accepted }
    }

    fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }
}

/// The SPIFFE ID and the serial (hex) of the certificate `der`.
fn identity_of(der: &CertificateDer<'_>) -> (String, String) {
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).expect("peer certificate");
    let id = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|extension| {
            extension
                .value
                .general_names
                .iter()
                .find_map(|name| match name {
                    x509_parser::extensions::GeneralName::URI(uri) => Some((*uri).to_owned()),
                    _ => None,
                })
        })
        .unwrap_or_else(|| "none".to_owned());
    (id, format!("{:x}", cert.serial))
}

async fn serve(acceptor: TlsAcceptor, tcp: TcpStream, number: u64) {
    let Ok(mut stream) = acceptor.accept(tcp).await else {
        return;
    };
    let (_, connection) = stream.get_ref();
    let (id, serial) = connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map_or_else(|| ("none".to_owned(), "none".to_owned()), identity_of);
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            seen.drain(..end + 4);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nx-conn: {number}\r\nx-peer-id: {id}\r\n\
                 x-peer-serial: {serial}\r\n\r\n{head}",
                head.len()
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

// --- Podgate and snapshots ---------------------------------------------------------------------

fn tenant(id: &str) -> Value {
    json!({ "id": id, "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } })
}

/// The policy most tests use: `t1` and `t2` have their own SVID, may talk to anything under
/// `spiffe://td/ns/mesh/`, and may verify clients of `td`; `t3` is listed with nothing allowed.
fn policy() -> Value {
    json!({ "tenants": {
        "t1": {
            "svid_hint": "acme",
            "allowed_server_ids": ["spiffe://td/ns/mesh/**"],
            "allowed_client_trust_domains": ["td"],
            "allow": { "upstream_mtls": true, "client_identity": true },
        },
        "t2": {
            "svid_hint": "beta",
            "allowed_server_ids": ["spiffe://td/ns/mesh/**"],
            "allow": { "upstream_mtls": true },
        },
        "t3": {},
    } })
}

async fn start(agent: &Agent, policy: &Value, extra: &[(&str, &str)]) -> Podgate {
    let file = scratch_dir().join("spiffe-policy.json");
    std::fs::write(&file, policy.to_string()).expect("write the policy");
    let endpoint = agent.endpoint();
    let file = file.display().to_string();
    let mut env = vec![
        ("SPIFFE_ENDPOINT_SOCKET", endpoint.as_str()),
        ("SPIFFE_POLICY_FILE", file.as_str()),
    ];
    env.extend_from_slice(extra);
    Podgate::start_logged(&env).await
}

/// An app of `tenant` on `host` whose service `web` is one `https://` server on `addr` reached
/// through the transport `spiffe`.
fn mesh_app(tenant: &str, host: &str, addr: SocketAddr, spiffe: &Value) -> Value {
    let revision = json!({
        "id": "r1", "state": "serving", "weight": 100,
        "services": [{
            "name": "web", "type": "loadbalancer", "transport": "mesh",
            "servers": [{ "url": format!("https://{addr}") }],
        }],
    });
    let mut built = app(&format!("{tenant}-{host}"), &[host], &[revision]);
    built["tenant"] = json!(tenant);
    built["transports"] =
        json!([{ "name": "mesh", "type": "servers_transport", "spiffe": spiffe }]);
    built
}

fn mesh(ids: &[&str]) -> Value {
    json!({ "ids": ids, "trust_domain": "td" })
}

fn multi(version: u64, apps: &[Value]) -> Value {
    json!({
        "version": version,
        "tenants": [tenant("t1"), tenant("t2"), tenant("t3")],
        "apps": apps,
    })
}

async fn push(podgate: &Podgate, snapshot: &Value) -> Response {
    podgate.push_snapshot(snapshot).await
}

/// Requests `host` until it answers `status`, for the first fetch and for rotation to arrive.
async fn until(podgate: &Podgate, host: &str, status: u16) -> Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = podgate.get(host, "/").await;
        if response.status == status || Instant::now() > deadline {
            return response;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// Requests `a.test` until podgate has dialled `backend`: the identity is fetched and the server
/// was judged, so what the answer says is that verdict and not a missing SVID.
async fn until_dialled(podgate: &Podgate, backend: &Backend) -> Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = podgate.get("a.test", "/").await;
        if backend.accepted() >= 1 || Instant::now() > deadline {
            return response;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// Requests `host` until the upstream sees the client serial `serial`.
async fn until_serial(podgate: &Podgate, host: &str, serial: &str) -> Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = podgate.get(host, "/").await;
        if response.header("x-peer-serial") == Some(serial) || Instant::now() > deadline {
            return response;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn codes(response: &Response) -> Vec<String> {
    response.json()["conflicts"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|entry| entry["code"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Time for Pingora to move a finished upstream connection into its pool.
const POOL_SETTLE: Duration = Duration::from_millis(200);

// --- Fetching and rotating ---------------------------------------------------------------------

#[tokio::test]
async fn spiffe_fetches_svid_by_hint() {
    let pki = Pki::new();
    let (acme, beta) = (pki.day(ACME_ID, "acme", 11), pki.day(BETA_ID, "beta", 12));
    let backend = Backend::start(&pki.day(MESH_ID, "", 1), &[&pki.root]).await;
    // The agent issues both identities; the tenant gets the one its hint names, not the first.
    let agent = Agent::start(&pki, &[&beta, &acme]);
    let podgate = start(&agent, &policy(), &[]).await;
    let pushed = multi(
        1,
        &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);

    let response = until(&podgate, "a.test", 200).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.header("x-peer-id"), Some(ACME_ID));
    assert_eq!(response.header("x-peer-serial"), Some("b"));
}

#[tokio::test]
async fn spiffe_rotation_without_restart() {
    let pki = Pki::new();
    let first = pki.day(ACME_ID, "acme", 0x21);
    let backend = Backend::start(&pki.day(MESH_ID, "", 1), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&first]);
    let podgate = start(&agent, &policy(), &[]).await;
    let pushed = multi(
        1,
        &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);
    let before = until(&podgate, "a.test", 200).await;
    assert_eq!(before.header("x-peer-serial"), Some("21"));

    let second = pki.day(ACME_ID, "acme", 0x22);
    agent.set(&pki, &[&second]);
    let after = until_serial(&podgate, "a.test", "22").await;
    assert_eq!(after.header("x-peer-serial"), Some("22"), "{}", after.body);
    assert_eq!(after.header("x-peer-id"), Some(ACME_ID));
}

#[tokio::test]
async fn spiffe_pool_key_includes_svid_serial() {
    let pki = Pki::new();
    let first = pki.day(ACME_ID, "acme", 0x31);
    let backend = Backend::start(&pki.day(MESH_ID, "", 1), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&first]);
    let podgate = start(&agent, &policy(), &[]).await;
    let pushed = multi(
        1,
        &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);

    let one = until(&podgate, "a.test", 200).await;
    sleep(POOL_SETTLE).await;
    let two = podgate.get("a.test", "/").await;
    assert_eq!(
        one.header("x-conn"),
        two.header("x-conn"),
        "same identity, pooled"
    );

    let second = pki.day(ACME_ID, "acme", 0x32);
    agent.set(&pki, &[&second]);
    let rotated = until_serial(&podgate, "a.test", "32").await;
    assert_ne!(
        rotated.header("x-conn"),
        one.header("x-conn"),
        "a rotated identity never reuses a connection made with the old one"
    );
    assert_eq!(rotated.header("x-peer-serial"), Some("32"));
}

// --- Verifying the upstream --------------------------------------------------------------------

#[tokio::test]
async fn spiffe_upstream_mtls_succeeds() {
    let pki = Pki::new();
    let acme = pki.day(ACME_ID, "acme", 1);
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&acme]);
    let podgate = start(&agent, &policy(), &[]).await;
    // A pattern names the server: `*` is one segment.
    let pushed = multi(
        1,
        &[mesh_app(
            "t1",
            "a.test",
            backend.addr,
            &mesh(&["spiffe://td/ns/mesh/sa/*"]),
        )],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);

    let response = until(&podgate, "a.test", 200).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.header("x-peer-id"), Some(ACME_ID));
    assert!(
        response.body.starts_with("GET / HTTP/1.1"),
        "{}",
        response.body
    );
}

#[tokio::test]
async fn spiffe_upstream_wrong_id_refused() {
    let pki = Pki::new();
    let acme = pki.day(ACME_ID, "acme", 1);
    // The server's certificate is valid for the bundle but names another workload.
    let backend =
        Backend::start(&pki.day("spiffe://td/ns/mesh/sa/evil", "", 2), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&acme]);
    let podgate = start(&agent, &policy(), &[]).await;
    let pushed = multi(
        1,
        &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);

    assert_eq!(until_dialled(&podgate, &backend).await.status, 502);
    assert!(
        backend.accepted() >= 1,
        "the refusal came from verifying a server that was dialled"
    );
    assert_eq!(podgate.get("a.test", "/").await.status, 502);
}

#[tokio::test]
async fn spiffe_upstream_wrong_bundle_refused() {
    let pki = Pki::new();
    let stranger = Pki::new();
    let acme = pki.day(ACME_ID, "acme", 1);
    // The right ID, from a CA the trust domain's bundle does not hold.
    let backend = Backend::start(&stranger.day(MESH_ID, "", 2), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&acme]);
    let podgate = start(&agent, &policy(), &[]).await;
    let pushed = multi(
        1,
        &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);

    assert_eq!(until_dialled(&podgate, &backend).await.status, 502);
    assert!(
        backend.accepted() >= 1,
        "the refusal came from verifying a server that was dialled"
    );
}

// --- Policy at compile time --------------------------------------------------------------------

#[tokio::test]
async fn spiffe_not_allowed_for_unmapped_tenant() {
    let pki = Pki::new();
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&pki.day(ACME_ID, "acme", 1)]);
    let podgate = start(&agent, &policy(), &[]).await;
    // `t3` is in the file with nothing allowed, `t4` is not in it at all.
    for tenant_id in ["t3", "t4"] {
        let mut pushed = multi(
            1,
            &[mesh_app(
                tenant_id,
                "a.test",
                backend.addr,
                &mesh(&[MESH_ID]),
            )],
        );
        pushed["tenants"] = json!([tenant(tenant_id)]);
        let response = push(&podgate, &pushed).await;
        assert_eq!(response.status, 422, "{tenant_id}: {}", response.body);
        assert_eq!(codes(&response), ["spiffe_not_allowed"], "{tenant_id}");
    }
    // A tenant that may do upstream mTLS may not verify clients.
    let mut client_app = app("c", &["c.test"], &[serving("r1", backend.addr)]);
    client_app["tenant"] = json!("t2");
    client_app["tls"]["spiffe_client"] = json!({"trust_domain": "td", "allowed_ids": [CLIENT_ID]});
    let response = push(&podgate, &multi(1, &[client_app])).await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(codes(&response), ["spiffe_not_allowed"]);
}

#[tokio::test]
async fn spiffe_server_id_outside_policy_rejected() {
    let pki = Pki::new();
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&pki.day(ACME_ID, "acme", 1)]);
    let podgate = start(&agent, &policy(), &[]).await;
    for ids in [
        // Another namespace.
        vec!["spiffe://td/ns/other/sa/db"],
        // A pattern wider than the grant.
        vec!["spiffe://td/ns/**"],
        // One good ID does not excuse a bad one.
        vec![MESH_ID, "spiffe://td/ns/payments/sa/db"],
    ] {
        let pushed = multi(1, &[mesh_app("t1", "a.test", backend.addr, &mesh(&ids))]);
        let response = push(&podgate, &pushed).await;
        assert_eq!(response.status, 422, "{ids:?}: {}", response.body);
        assert_eq!(
            codes(&response),
            ["spiffe_server_id_not_allowed"],
            "{ids:?}"
        );
    }
    // The grant itself, and anything under it, is fine.
    let pushed = multi(
        1,
        &[mesh_app(
            "t1",
            "a.test",
            backend.addr,
            &mesh(&["spiffe://td/ns/mesh/**"]),
        )],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);
}

#[tokio::test]
async fn spiffe_tenants_use_distinct_svids() {
    let pki = Pki::new();
    let (acme, beta) = (
        pki.day(ACME_ID, "acme", 0x41),
        pki.day(BETA_ID, "beta", 0x42),
    );
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&acme, &beta]);
    let podgate = start(&agent, &policy(), &[]).await;
    let pushed = multi(
        1,
        &[
            mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID])),
            mesh_app("t2", "b.test", backend.addr, &mesh(&[MESH_ID])),
        ],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);

    // Alternate: a pooled connection of one tenant must never carry the other's request.
    for round in 0..4 {
        for (host, want, serial) in [("a.test", ACME_ID, "41"), ("b.test", BETA_ID, "42")] {
            let response = until(&podgate, host, 200).await;
            assert_eq!(
                response.status, 200,
                "round {round} {host}: {}",
                response.body
            );
            assert_eq!(
                response.header("x-peer-id"),
                Some(want),
                "round {round} {host}"
            );
            assert_eq!(
                response.header("x-peer-serial"),
                Some(serial),
                "round {round} {host}"
            );
        }
        sleep(POOL_SETTLE).await;
    }
    // Two tenants, two connections at least: they share the upstream address, not a connection.
    assert!(backend.accepted() >= 2, "{}", backend.accepted());
}

// --- Failing closed ----------------------------------------------------------------------------

#[tokio::test]
async fn spiffe_no_svid_502_no_fallback() {
    let pki = Pki::new();
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    // The agent issues an identity, but not the one with the tenant's hint: no fallback to it.
    let other = pki.day(BETA_ID, "beta", 5);
    let agent = Agent::start(&pki, &[&other]);
    let podgate = start(&agent, &policy(), &[]).await;
    let pushed = multi(
        1,
        &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);

    for _ in 0..3 {
        assert_eq!(podgate.get("a.test", "/").await.status, 502);
        sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(backend.accepted(), 0, "podgate never even dialled");
}

#[tokio::test]
async fn spiffe_expired_svid_not_served() {
    let pki = Pki::new();
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    let short = pki.issue(ACME_ID, "acme", 0x51, 3);
    let agent = Agent::start(&pki, &[&short]);
    let podgate = start(&agent, &policy(), &[]).await;
    let pushed = multi(
        1,
        &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);
    assert_eq!(until(&podgate, "a.test", 200).await.status, 200);

    // The agent is up and keeps sending the same, now expired, identity.
    sleep(Duration::from_secs(4)).await;
    let accepted = backend.accepted();
    for _ in 0..3 {
        assert_eq!(podgate.get("a.test", "/").await.status, 502);
    }
    assert_eq!(
        backend.accepted(),
        accepted,
        "no connection with an expired identity"
    );
}

#[tokio::test]
async fn spiffe_agent_outage_keeps_last_good_until_expiry() {
    let pki = Pki::new();
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    let short = pki.issue(ACME_ID, "acme", 0x61, 6);
    let mut agent = Agent::start(&pki, &[&short]);
    let podgate = start(&agent, &policy(), &[]).await;
    let pushed = multi(
        1,
        &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);
    assert_eq!(until(&podgate, "a.test", 200).await.status, 200);

    agent.stop();
    sleep(Duration::from_millis(700)).await;
    let during = podgate.get("a.test", "/").await;
    assert_eq!(
        during.status, 200,
        "the last good identity still serves: {}",
        during.body
    );
    assert_eq!(during.header("x-peer-serial"), Some("61"));

    // Past its expiry nothing replaces it.
    sleep(Duration::from_secs(6)).await;
    assert_eq!(podgate.get("a.test", "/").await.status, 502);
}

// --- Client identity ---------------------------------------------------------------------------

/// A backend that answers with the head of the request it got.
async fn echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&chunk[..read]),
                    }
                }
                let body = String::from_utf8_lossy(&head).into_owned();
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

fn client_config(server: &TestCert, client: Option<&Issued>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(server.der.clone()).expect("trust the server");
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots);
    Arc::new(match client {
        Some(client) => builder
            .with_client_auth_cert(client.chain(), client.key())
            .expect("client certificate"),
        None => builder.with_no_client_auth(),
    })
}

fn spiffe_client_app(
    host: &str,
    backend: SocketAddr,
    allowed: &[&str],
    trust_domain: &str,
) -> Value {
    let mut built = app("c", &[host], &[serving("r1", backend)]);
    built["tls"]["spiffe_client"] = json!({ "trust_domain": trust_domain, "allowed_ids": allowed });
    built
}

async fn push_client_app(podgate: &Podgate, server: &TestCert, host: &str, built: Value) {
    let mut pushed = multi(1, &[built]);
    pushed["certificates"] = json!([server.entry(&[host])]);
    let response = push(podgate, &pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

fn header_values(echoed: &str, name: &str) -> Vec<String> {
    echoed
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(got, _)| got.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
        .collect()
}

#[tokio::test]
async fn spiffe_client_identity_verified() {
    let pki = Pki::new();
    let agent = Agent::start(&pki, &[&pki.day(ACME_ID, "acme", 1)]);
    let podgate = start(&agent, &policy(), &[]).await;
    let server = TestCert::new(&["c.test"]);
    let backend = echo().await;
    push_client_app(
        &podgate,
        &server,
        "c.test",
        spiffe_client_app("c.test", backend, &["spiffe://td/ns/client/**"], "td"),
    )
    .await;

    let client = pki.day(CLIENT_ID, "", 7);
    // The bundle arrives with the first fetch; until then the client is refused.
    let deadline = Instant::now() + Duration::from_secs(10);
    let response = loop {
        let response = podgate
            .try_https_get(
                client_config(&server, Some(&client)),
                "c.test",
                "c.test",
                "/",
            )
            .await
            .expect("response");
        if response.status == 200 || Instant::now() > deadline {
            break response;
        }
        sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        header_values(&response.body, "x-forwarded-tls-client-spiffe-id"),
        [CLIENT_ID]
    );

    // No certificate at all: the default `require_and_verify` refuses.
    let anonymous = podgate
        .try_https_get(client_config(&server, None), "c.test", "c.test", "/")
        .await;
    assert!(
        anonymous
            .as_ref()
            .map_or(true, |response| response.status == 403),
        "{anonymous:?}"
    );
}

#[tokio::test]
async fn spiffe_client_wrong_trust_domain_refused() {
    let pki = Pki::new();
    let stranger = Pki::new();
    let agent = Agent::start(&pki, &[&pki.day(ACME_ID, "acme", 1)]);
    let podgate = start(&agent, &policy(), &[]).await;
    let server = TestCert::new(&["c.test"]);
    let backend = echo().await;
    push_client_app(
        &podgate,
        &server,
        "c.test",
        spiffe_client_app("c.test", backend, &["spiffe://td/ns/client/**"], "td"),
    )
    .await;
    let good = pki.day(CLIENT_ID, "", 7);
    let ok = loop_until_ok(&podgate, &server, &good).await;
    assert_eq!(ok.status, 200, "{}", ok.body);

    let refused =
        |result: std::io::Result<Response>| result.map_or(true, |response| response.status == 403);
    // Right ID, but from a CA the bundle does not hold.
    let forged = stranger.day(CLIENT_ID, "", 8);
    assert!(refused(
        podgate
            .try_https_get(
                client_config(&server, Some(&forged)),
                "c.test",
                "c.test",
                "/"
            )
            .await
    ));
    // Signed by the right CA, but an ID outside `allowed_ids`.
    let outsider = pki.day("spiffe://td/ns/other/sa/web", "", 9);
    assert!(refused(
        podgate
            .try_https_get(
                client_config(&server, Some(&outsider)),
                "c.test",
                "c.test",
                "/"
            )
            .await
    ));
    // Another trust domain than the one the policy lets the tenant verify.
    let mut pushed = multi(
        2,
        &[spiffe_client_app(
            "c.test",
            backend,
            &["spiffe://elsewhere/a/b"],
            "elsewhere",
        )],
    );
    pushed["certificates"] = json!([server.entry(&["c.test"])]);
    let response = push(&podgate, &pushed).await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(codes(&response), ["spiffe_not_allowed"]);
    // A CA and a SPIFFE rule exclude each other.
    let mut both = spiffe_client_app("c.test", backend, &[CLIENT_ID], "td");
    both["tls"]["client_ca_pem"] = json!(server.cert_pem);
    let mut pushed = multi(2, &[both]);
    pushed["certificates"] = json!([server.entry(&["c.test"])]);
    let response = push(&podgate, &pushed).await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(codes(&response), ["invalid_client_auth"]);
}

async fn loop_until_ok(podgate: &Podgate, server: &TestCert, client: &Issued) -> Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let result = podgate
            .try_https_get(client_config(server, Some(client)), "c.test", "c.test", "/")
            .await;
        if let Ok(response) = result {
            if response.status == 200 || Instant::now() > deadline {
                return response;
            }
        } else {
            assert!(
                Instant::now() < deadline,
                "no response from podgate in time"
            );
        }
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn spiffe_client_id_header_forwarded_and_stripped() {
    let pki = Pki::new();
    let agent = Agent::start(&pki, &[&pki.day(ACME_ID, "acme", 1)]);
    let podgate = start(&agent, &policy(), &[]).await;
    let server = TestCert::new(&["c.test"]);
    let backend = echo().await;
    push_client_app(
        &podgate,
        &server,
        "c.test",
        spiffe_client_app("c.test", backend, &["spiffe://td/ns/client/**"], "td"),
    )
    .await;
    let client = pki.day(CLIENT_ID, "", 7);
    loop_until_ok(&podgate, &server, &client).await;

    // A verified client that also sends the header, in three spellings: only the real ID gets
    // through, once.
    let response = podgate
        .try_https_get_with_headers(
            client_config(&server, Some(&client)),
            "c.test",
            "c.test",
            "/",
            &[
                (
                    "X-Forwarded-Tls-Client-Spiffe-Id",
                    "spiffe://td/ns/client/sa/admin",
                ),
                (
                    "x_forwarded_tls_client_spiffe_id",
                    "spiffe://td/ns/client/sa/admin",
                ),
                ("x-forwarded-tls-client-spiffe-id", "spiffe://evil/x"),
            ],
        )
        .await
        .expect("response");
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        header_values(&response.body, "x-forwarded-tls-client-spiffe-id"),
        [CLIENT_ID]
    );
    assert!(!response.body.contains("evil"), "{}", response.body);
    assert!(!response.body.contains("admin"), "{}", response.body);

    // An app with no client identity: the header never reaches it, whoever sends it.
    let plain = {
        let mut built = app("p", &["p.test"], &[serving("r1", backend)]);
        built["tenant"] = json!("t1");
        built
    };
    assert_eq!(push(&podgate, &multi(2, &[plain])).await.status, 200);
    let response = podgate
        .get_with_headers(
            "p.test",
            "/",
            &[(
                "X-Forwarded-Tls-Client-Spiffe-Id",
                "spiffe://td/ns/client/sa/admin",
            )],
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(
        !response.body.to_ascii_lowercase().contains("spiffe-id"),
        "{}",
        response.body
    );
}

// --- Secrets and the snapshot ------------------------------------------------------------------

#[tokio::test]
async fn spiffe_snapshot_cannot_set_socket_or_policy() {
    let pki = Pki::new();
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&pki.day(ACME_ID, "acme", 1)]);
    let podgate = start(&agent, &policy(), &[]).await;
    for extra in [
        json!({ "socket": "/run/evil.sock" }),
        json!({ "svid_hint": "beta" }),
        json!({ "policy": { "tenants": {} } }),
        json!({ "allowed_server_ids": ["spiffe://td/**"] }),
    ] {
        let mut spiffe = mesh(&[MESH_ID]);
        spiffe
            .as_object_mut()
            .expect("object")
            .extend(extra.as_object().expect("object").clone());
        let response = push(
            &podgate,
            &multi(1, &[mesh_app("t1", "a.test", backend.addr, &spiffe)]),
        )
        .await;
        assert_eq!(response.status, 422, "{extra}: {}", response.body);
        assert_eq!(codes(&response), ["invalid_transport"], "{extra}");
    }
    let mut client = spiffe_client_app("c.test", backend.addr, &[CLIENT_ID], "td");
    client["tls"]["spiffe_client"]["socket"] = json!("/run/evil.sock");
    let response = push(&podgate, &multi(1, &[client])).await;
    assert!(
        response.status == 400 || response.status == 422,
        "{}",
        response.body
    );

    // A process with no SPIFFE configuration refuses every use of it.
    let bare = Podgate::start().await;
    let response = push(
        &bare,
        &multi(
            1,
            &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
        ),
    )
    .await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(codes(&response), ["spiffe_not_allowed"]);
}

#[tokio::test]
async fn spiffe_keys_never_leak() {
    let pki = Pki::new();
    let acme = pki.day(ACME_ID, "acme", 0x71);
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&acme]);
    let podgate = start(&agent, &policy(), &[("RUST_LOG", "debug")]).await;
    let pushed = multi(
        1,
        &[mesh_app("t1", "a.test", backend.addr, &mesh(&[MESH_ID]))],
    );
    assert_eq!(push(&podgate, &pushed).await.status, 200);
    assert_eq!(until(&podgate, "a.test", 200).await.status, 200);

    let key = STANDARD.encode(&acme.key);
    let needle = &key[key.len() / 2..key.len() / 2 + 32];
    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/&method=GET")
        .await;
    assert_eq!(explained.status, 200, "{}", explained.body);
    let shown = explained.body.clone();
    // Explain names the trust domain and the IDs, nothing else of the transport's identity.
    assert!(shown.contains(MESH_ID), "{shown}");
    let overview = podgate.admin_get("/v1/overview").await;
    for (what, text) in [
        ("explain", shown),
        ("overview", overview.body),
        ("log", podgate.log()),
        ("metrics", podgate.admin_get("/metrics").await.body),
    ] {
        assert!(!text.contains(needle), "{what} shows the private key");
        assert!(!text.contains(&key), "{what} shows the private key");
        let hex: String = acme.key[acme.key.len() / 2..][..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(!text.contains(&hex), "{what} shows the private key in hex");
    }
}

// --- Plan --------------------------------------------------------------------------------------

fn kinds(plan: &Value) -> Vec<String> {
    plan["posture_changes"]
        .as_array()
        .expect("posture_changes")
        .iter()
        .map(|change| change["kind"].as_str().expect("kind").to_owned())
        .collect()
}

#[tokio::test]
async fn plan_lists_spiffe_changes() {
    let pki = Pki::new();
    let backend = Backend::start(&pki.day(MESH_ID, "", 2), &[&pki.root]).await;
    let agent = Agent::start(&pki, &[&pki.day(ACME_ID, "acme", 1)]);
    let podgate = start(&agent, &policy(), &[]).await;
    let server = TestCert::new(&["c.test"]);
    let echo_addr = echo().await;

    let live = |ids: &[&str], allowed: &[&str]| {
        let mut pushed = multi(
            1,
            &[
                mesh_app("t1", "a.test", backend.addr, &mesh(ids)),
                spiffe_client_app("c.test", echo_addr, allowed, "td"),
            ],
        );
        pushed["certificates"] = json!([server.entry(&["c.test"])]);
        pushed
    };
    let live_snapshot = live(&[MESH_ID], &["spiffe://td/ns/client/sa/web"]);
    assert_eq!(push(&podgate, &live_snapshot).await.status, 200);

    let plan = |snapshot: Value| {
        let podgate = &podgate;
        async move {
            let mut snapshot = snapshot;
            snapshot["version"] = json!(2);
            let response = podgate.admin_post("/v1/snapshot/plan", &snapshot).await;
            assert_eq!(response.status, 200, "{}", response.body);
            response.json()
        }
    };

    // Nothing changes: nothing is listed.
    let same = plan(live(&[MESH_ID], &["spiffe://td/ns/client/sa/web"])).await;
    assert_eq!(kinds(&same), Vec::<String>::new(), "{same}");

    // Narrowing is not a relaxation.
    let narrower = plan(live(
        &["spiffe://td/ns/mesh/sa/db"],
        &["spiffe://td/ns/client/sa/web"],
    ))
    .await;
    assert_eq!(kinds(&narrower), Vec::<String>::new(), "{narrower}");

    // A new server ID is new trust.
    let more_ids = plan(live(
        &[MESH_ID, "spiffe://td/ns/mesh/sa/cache"],
        &["spiffe://td/ns/client/sa/web"],
    ))
    .await;
    assert_eq!(kinds(&more_ids), ["spiffe_trust_added"], "{more_ids}");
    assert_eq!(more_ids["posture_changes"][0]["host"], "a.test");

    // Loosening the allowed client IDs.
    let loosened = plan(live(&[MESH_ID], &["spiffe://td/ns/client/**"])).await;
    assert_eq!(kinds(&loosened), ["spiffe_client_loosened"], "{loosened}");
    assert_eq!(loosened["posture_changes"][0]["host"], "c.test");

    // Dropping the client rule.
    let mut dropped = live(&[MESH_ID], &["spiffe://td/ns/client/sa/web"]);
    dropped["apps"][1]["tls"]
        .as_object_mut()
        .expect("tls")
        .remove("spiffe_client");
    let removed = plan(dropped).await;
    assert!(
        kinds(&removed).contains(&"spiffe_client_removed".to_owned()),
        "{removed}"
    );
}

#[tokio::test]
async fn spiffe_bundle_rotation_reaches_verification() {
    let pki = Pki::new();
    let agent = Agent::start(&pki, &[&pki.day(ACME_ID, "acme", 1)]);
    let podgate = start(&agent, &policy(), &[]).await;
    let server = TestCert::new(&["c.test"]);
    let backend = echo().await;
    push_client_app(
        &podgate,
        &server,
        "c.test",
        spiffe_client_app("c.test", backend, &["spiffe://td/ns/client/**"], "td"),
    )
    .await;
    let client = pki.day(CLIENT_ID, "", 7);
    assert_eq!(loop_until_ok(&podgate, &server, &client).await.status, 200);

    // The trust domain rotates to a new root: the old client no longer chains to the bundle,
    // with no snapshot push. The per-connection verdict is reused for 30 s, so a new connection
    // is judged against the live bundle.
    let next = Pki::new();
    agent.set_bundle(&next.root);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let result = podgate
            .try_https_get(
                client_config(&server, Some(&client)),
                "c.test",
                "c.test",
                "/",
            )
            .await;
        if result
            .as_ref()
            .map_or(true, |response| response.status == 403)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the rotated bundle never took effect"
        );
        sleep(Duration::from_millis(100)).await;
    }
    let fresh = next.day(CLIENT_ID, "", 8);
    assert_eq!(loop_until_ok(&podgate, &server, &fresh).await.status, 200);
}
