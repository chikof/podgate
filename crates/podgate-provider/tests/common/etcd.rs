//! A fake etcd v3 JSON gateway on a loopback port, for the etcd source's tests. No test talks to
//! a real etcd.
//!
//! It speaks the gateway the way etcd 3.5 does and keeps the semantics the source relies on:
//!
//! - **`POST /v3/kv/range`** with `key`, `range_end` (base64) and `limit`; `int64` fields are
//!   strings, empty lists and values are left out, `more` is set when the limit cut the answer.
//! - **`POST /v3/watch`** with a `create_request`: a chunked stream, one JSON message per line.
//!   The first message says `created`; events from `start_revision` on follow, then new ones as
//!   they happen. A `start_revision` at or below the compaction revision is answered by a
//!   `canceled` message with `compact_revision`, as etcd does. A PUT event has no `type`.
//! - **`POST /v3/auth/authenticate`** once [`FakeEtcd::require_auth`] is called: a valid user and
//!   password get a token, anything else a `400`. Every other call then needs the token in
//!   `Authorization`, else `401 invalid auth token`. [`FakeEtcd::expire_tokens`] makes every
//!   issued token invalid.
//! - **TLS** with a certificate from a private CA ([`Pki`]), optionally demanding a client
//!   certificate of the same CA.
//!
//! Anything that writes (`put`, `deleterange`, `txn`, `compaction`, leases) is answered `200` and
//! recorded in [`FakeEtcd::writes`], which an honest read-only client leaves empty. Every request
//! is logged. [`FakeEtcd::stop`] drops the listener and every open connection, like an etcd that
//! died.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use super::DEADLINE;

// ---------------------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------------------

/// A private certificate authority that signs the fake's server certificate and the client
/// certificates of the tests.
pub struct Pki {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    /// The CA certificate, PEM: the `ca_file` of the source.
    pub ca_pem: String,
}

impl Pki {
    pub fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fake etcd ca");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().expect("CA key"),
        )
        .expect("self-signed CA");
        let ca_pem = issuer.pem();
        Self { issuer, ca_pem }
    }

    /// A server configuration for `127.0.0.1`; with `require_client_cert` it demands a client
    /// certificate of this CA.
    pub fn server_config(&self, require_client_cert: bool) -> Arc<rustls::ServerConfig> {
        let key = rcgen::KeyPair::generate().expect("server key");
        let params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("server params");
        let cert = params.signed_by(&key, &self.issuer).expect("sign server");
        let private = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der())
            .expect("server key der");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("protocol versions");
        let builder = if require_client_cert {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.issuer.der().clone()).expect("CA root");
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .expect("client verifier");
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        Arc::new(
            builder
                .with_single_cert(vec![cert.der().clone()], private)
                .expect("server certificate"),
        )
    }

    /// Writes a client certificate and key of this CA into `dir` and returns their paths.
    pub fn client_files(&self, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let key = rcgen::KeyPair::generate().expect("client key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let cert = params.signed_by(&key, &self.issuer).expect("sign client");
        let cert_path = dir.join(format!("{name}.pem"));
        let key_path = dir.join(format!("{name}-key.pem"));
        std::fs::write(&cert_path, cert.pem()).expect("write client certificate");
        std::fs::write(&key_path, key.serialize_pem()).expect("write client key");
        (cert_path, key_path)
    }

    /// Writes the CA certificate into `dir` and returns its path.
    pub fn ca_file(&self, dir: &Path) -> PathBuf {
        let path = dir.join("ca.pem");
        std::fs::write(&path, &self.ca_pem).expect("write the CA");
        path
    }
}

// ---------------------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------------------

/// A request the fake received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub path: String,
    /// The `Authorization` header, which is the raw token for etcd.
    pub authorization: Option<String>,
    pub body: Value,
    /// Whether the connection was TLS and carried a client certificate.
    pub client_cert: bool,
}

/// A value and the revision that wrote it.
type Stored = (Vec<u8>, u64);

struct Event {
    revision: u64,
    key: Vec<u8>,
    /// `None` for a delete.
    value: Option<Vec<u8>>,
}

struct Inner {
    revision: u64,
    compact_revision: u64,
    kvs: BTreeMap<Vec<u8>, Stored>,
    log: Vec<Event>,
    user: Option<(String, String)>,
    tokens: BTreeSet<String>,
    next_token: u64,
    requests: Vec<Seen>,
    failures: VecDeque<u16>,
    compact_next_watch: bool,
    /// Watches that started under an older epoch end.
    epoch: u64,
}

struct Shared {
    inner: Mutex<Inner>,
    /// Bumped on every change a watch must look at.
    news: watch::Sender<u64>,
}

fn lock(shared: &Shared) -> MutexGuard<'_, Inner> {
    shared.inner.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The running fake.
pub struct FakeEtcd {
    port: u16,
    shared: Arc<Shared>,
    acceptor: Option<TlsAcceptor>,
    server: Mutex<Option<JoinHandle<()>>>,
}

static TOKENS: AtomicU64 = AtomicU64::new(0);

impl FakeEtcd {
    /// Plain HTTP, which the source accepts on loopback only.
    pub async fn start() -> Self {
        Self::start_with(None).await
    }

    /// TLS with a certificate of `pki`; with `require_client_cert` a client certificate of the
    /// same CA is demanded.
    pub async fn start_tls(pki: &Pki, require_client_cert: bool) -> Self {
        Self::start_with(Some(TlsAcceptor::from(
            pki.server_config(require_client_cert),
        )))
        .await
    }

    async fn start_with(acceptor: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake etcd");
        let (news, _) = watch::channel(0);
        let fake = Self {
            port: listener.local_addr().expect("local addr").port(),
            shared: Arc::new(Shared {
                inner: Mutex::new(Inner {
                    revision: 10,
                    compact_revision: 0,
                    kvs: BTreeMap::new(),
                    log: Vec::new(),
                    user: None,
                    tokens: BTreeSet::new(),
                    next_token: TOKENS.fetch_add(1000, Ordering::Relaxed),
                    requests: Vec::new(),
                    failures: VecDeque::new(),
                    compact_next_watch: false,
                    epoch: 0,
                }),
                news,
            }),
            acceptor,
            server: Mutex::new(None),
        };
        fake.serve(listener);
        fake
    }

    /// `http://127.0.0.1:<port>` or `https://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        let scheme = if self.acceptor.is_some() {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://127.0.0.1:{}", self.port)
    }

    fn serve(&self, listener: TcpListener) {
        let shared = Arc::clone(&self.shared);
        let acceptor = self.acceptor.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                connections.spawn(connection(stream, Arc::clone(&shared), acceptor.clone()));
                while connections.try_join_next().is_some() {}
            }
        });
        *self.server.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// Drops the listener and every open connection, like an etcd that died.
    pub fn stop(&self) {
        if let Some(task) = self
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }

    /// Listens again on the same port, after [`Self::stop`].
    pub async fn restart(&self) {
        self.stop();
        let deadline = Instant::now() + DEADLINE;
        let listener = loop {
            match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], self.port))).await {
                Ok(listener) => break listener,
                Err(err) => {
                    assert!(Instant::now() < deadline, "cannot rebind the fake: {err}");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        };
        self.serve(listener);
    }

    fn news(&self) {
        self.shared.news.send_modify(|generation| *generation += 1);
    }

    /// Writes `key`; a watch sees a PUT.
    pub fn put(&self, key: &str, value: &str) {
        self.put_bytes(key.as_bytes(), value.as_bytes());
    }

    pub fn put_bytes(&self, key: &[u8], value: &[u8]) {
        {
            let mut inner = lock(&self.shared);
            inner.revision += 1;
            let revision = inner.revision;
            inner.kvs.insert(key.to_vec(), (value.to_vec(), revision));
            inner.log.push(Event {
                revision,
                key: key.to_vec(),
                value: Some(value.to_vec()),
            });
        }
        self.news();
    }

    /// Deletes `key`; a watch sees a DELETE.
    pub fn delete(&self, key: &str) {
        {
            let mut inner = lock(&self.shared);
            inner.revision += 1;
            let revision = inner.revision;
            inner.kvs.remove(key.as_bytes());
            inner.log.push(Event {
                revision,
                key: key.as_bytes().to_vec(),
                value: None,
            });
        }
        self.news();
    }

    /// Demands authentication: `user` and `password` buy a token, and no call works without one.
    pub fn require_auth(&self, user: &str, password: &str) {
        lock(&self.shared).user = Some((user.to_owned(), password.to_owned()));
    }

    /// Every token issued so far stops working, as when its TTL ran out.
    pub fn expire_tokens(&self) {
        lock(&self.shared).tokens.clear();
    }

    /// Ends every open watch stream.
    pub fn break_watches(&self) {
        lock(&self.shared).epoch += 1;
        self.news();
    }

    /// Compacts the history up to now: a watch that asks for an older revision is cancelled.
    pub fn compact(&self) {
        let mut inner = lock(&self.shared);
        inner.compact_revision = inner.revision;
        inner.log.clear();
    }

    /// The next watch is answered as if the revision it asks for had just been compacted.
    pub fn compact_at_next_watch(&self) {
        lock(&self.shared).compact_next_watch = true;
    }

    /// The next `count` requests get `status`.
    pub fn fail_next(&self, status: u16, count: usize) {
        lock(&self.shared)
            .failures
            .extend(std::iter::repeat_n(status, count));
    }

    /// Every request so far, oldest first.
    pub fn requests(&self) -> Vec<Seen> {
        lock(&self.shared).requests.clone()
    }

    /// How many requests went to `path`.
    pub fn count(&self, path: &str) -> usize {
        self.requests()
            .iter()
            .filter(|seen| seen.path == path)
            .count()
    }

    /// The paths of the requests that would have changed etcd.
    pub fn writes(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .filter(|seen| is_write(&seen.path))
            .map(|seen| seen.path)
            .collect()
    }

    /// Waits until `condition` holds for the requests so far.
    pub async fn wait_requests(&self, what: &str, condition: impl Fn(&[Seen]) -> bool) {
        let deadline = Instant::now() + DEADLINE;
        loop {
            let requests = self.requests();
            if condition(&requests) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the fake to see: {what}; {} requests so far",
                requests.len()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for FakeEtcd {
    fn drop(&mut self) {
        self.stop();
    }
}

fn is_write(path: &str) -> bool {
    path.starts_with("/v3/kv/put")
        || path.starts_with("/v3/kv/deleterange")
        || path.starts_with("/v3/kv/txn")
        || path.starts_with("/v3/kv/compaction")
        || path.starts_with("/v3/lease")
        || path.starts_with("/v3/auth/user")
        || path.starts_with("/v3/auth/role")
        || path.starts_with("/v3/maintenance")
}

fn range_of(body: &Value) -> (Vec<u8>, Vec<u8>) {
    let decode = |name: &str| {
        STANDARD
            .decode(body[name].as_str().unwrap_or_default())
            .unwrap_or_default()
    };
    (decode("key"), decode("range_end"))
}

fn in_range(key: &[u8], start: &[u8], end: &[u8]) -> bool {
    key >= start && (end.is_empty() || end == [0] || key < end)
}

fn header(revision: u64) -> Value {
    json!({ "cluster_id": "1", "member_id": "2", "revision": revision.to_string(), "raft_term": "3" })
}

fn error_body(code: u16, message: &str) -> (u16, Value) {
    let status = match code {
        16 => 401,
        7 => 403,
        _ => 400,
    };
    (
        status,
        json!({ "error": message, "code": code, "message": message }),
    )
}

async fn respond<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, body: &Value) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let text = body.to_string();
    let answer = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(answer.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Option<(String, Option<String>, Value)> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 || raw.len() > 64 * 1024 {
            return None;
        }
        raw.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    if request_line.next()? != "POST" {
        return None;
    }
    let path = request_line.next()?.to_owned();
    let mut length = 0_usize;
    let mut authorization = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().ok()?;
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_owned());
        }
    }
    let mut body = raw[head_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Some((path, authorization, body))
}

async fn connection(stream: TcpStream, shared: Arc<Shared>, acceptor: Option<TlsAcceptor>) {
    match acceptor {
        Some(acceptor) => {
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };
            let client_cert = stream.get_ref().1.peer_certificates().is_some();
            Box::pin(serve(stream, shared, client_cert)).await;
        }
        None => Box::pin(serve(stream, shared, false)).await,
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    shared: Arc<Shared>,
    client_cert: bool,
) {
    let Some((path, authorization, body)) = Box::pin(read_request(&mut stream)).await else {
        return;
    };
    let early: Option<(u16, Value)> = {
        let mut inner = lock(&shared);
        inner.requests.push(Seen {
            path: path.clone(),
            authorization: authorization.clone(),
            body: body.clone(),
            client_cert,
        });
        if let Some(status) = inner.failures.pop_front() {
            Some((status, json!({ "error": "scripted failure", "code": 14 })))
        } else if is_write(&path) {
            Some((200, json!({})))
        } else if path == "/v3/auth/authenticate" {
            Some(authenticate(&mut inner, &body))
        } else if !matches!(path.as_str(), "/v3/kv/range" | "/v3/watch") {
            Some((404, json!({ "error": "Not Found", "code": 5 })))
        } else if inner.user.is_some()
            && !authorization
                .as_ref()
                .is_some_and(|token| inner.tokens.contains(token))
        {
            Some(error_body(16, "etcdserver: invalid auth token"))
        } else {
            None
        }
    };
    match early {
        Some((status, reply)) => respond(&mut stream, status, &reply).await,
        None if path == "/v3/kv/range" => {
            let reply = range(&shared, &body);
            respond(&mut stream, 200, &reply).await;
        }
        None => stream_watch(&mut stream, &shared, &body).await,
    }
}

/// The answer to `authenticate`: a token for the right user and password, `400` otherwise.
fn authenticate(inner: &mut Inner, body: &Value) -> (u16, Value) {
    let Some((user, password)) = inner.user.clone() else {
        return error_body(3, "etcdserver: authentication is not enabled");
    };
    if body["name"] == user && body["password"] == password {
        inner.next_token += 1;
        let token = format!("token-{}", inner.next_token);
        inner.tokens.insert(token.clone());
        (
            200,
            json!({ "header": header(inner.revision), "token": token }),
        )
    } else {
        error_body(
            3,
            "etcdserver: authentication failed, invalid user ID or password",
        )
    }
}

fn range(shared: &Shared, body: &Value) -> Value {
    let inner = lock(shared);
    let (start, end) = range_of(body);
    let limit = body["limit"].as_u64().unwrap_or(0);
    let matching: Vec<(&Vec<u8>, &Stored)> = inner
        .kvs
        .iter()
        .filter(|(key, _)| in_range(key, &start, &end))
        .collect();
    let cut = limit > 0 && matching.len() as u64 > limit;
    let kvs: Vec<Value> = matching
        .iter()
        .take(if limit > 0 {
            limit as usize
        } else {
            usize::MAX
        })
        .map(|(key, (value, modified))| {
            let mut kv = json!({
                "key": STANDARD.encode(key),
                "create_revision": "2",
                "mod_revision": modified.to_string(),
                "version": "1",
            });
            if !value.is_empty() {
                kv["value"] = json!(STANDARD.encode(value));
            }
            kv
        })
        .collect();
    let mut reply =
        json!({ "header": header(inner.revision), "count": matching.len().to_string() });
    if !kvs.is_empty() {
        reply["kvs"] = Value::Array(kvs);
    }
    if cut {
        reply["more"] = json!(true);
    }
    reply
}

async fn chunk<S: AsyncWrite + Unpin>(stream: &mut S, message: &Value) -> bool {
    let text = format!("{message}\n");
    let framed = format!("{:x}\r\n{text}\r\n", text.len());
    stream.write_all(framed.as_bytes()).await.is_ok() && stream.flush().await.is_ok()
}

async fn stream_watch<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    shared: &Shared,
    body: &Value,
) {
    let create = &body["create_request"];
    let (start, end) = range_of(create);
    let (epoch, mut cursor, compacted) = {
        let mut inner = lock(shared);
        let asked = create["start_revision"]
            .as_str()
            .and_then(|text| text.parse().ok())
            .or_else(|| create["start_revision"].as_u64())
            .unwrap_or(0);
        if inner.compact_next_watch {
            inner.compact_next_watch = false;
            inner.compact_revision = inner.revision + 1;
            inner.log.clear();
        }
        let cursor = if asked == 0 {
            inner.revision + 1
        } else {
            asked
        };
        (inner.epoch, cursor, cursor <= inner.compact_revision)
    };
    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    let revision = lock(shared).revision;
    if !chunk(
        stream,
        &json!({ "result": { "header": header(revision), "watch_id": "0", "created": true } }),
    )
    .await
    {
        return;
    }
    if compacted {
        let compact_revision = lock(shared).compact_revision;
        let _ = chunk(
            stream,
            &json!({ "result": {
                "header": header(revision),
                "watch_id": "0",
                "canceled": true,
                "compact_revision": compact_revision.to_string(),
                "cancel_reason": "etcdserver: mvcc: required revision has been compacted",
            } }),
        )
        .await;
        let _ = stream.write_all(b"0\r\n\r\n").await;
        let _ = stream.shutdown().await;
        return;
    }
    let mut news = shared.news.subscribe();
    let mut scratch = [0_u8; 64];
    loop {
        let (events, revision, current) = {
            let inner = lock(shared);
            let events: Vec<Value> = inner
                .log
                .iter()
                .filter(|event| event.revision >= cursor && in_range(&event.key, &start, &end))
                .map(|event| match &event.value {
                    Some(value) => {
                        let mut kv = json!({
                            "key": STANDARD.encode(&event.key),
                            "mod_revision": event.revision.to_string(),
                        });
                        if !value.is_empty() {
                            kv["value"] = json!(STANDARD.encode(value));
                        }
                        json!({ "kv": kv })
                    }
                    None => json!({
                        "type": "DELETE",
                        "kv": { "key": STANDARD.encode(&event.key), "mod_revision": event.revision.to_string() },
                    }),
                })
                .collect();
            (events, inner.revision, inner.epoch)
        };
        if current != epoch {
            let _ = stream.shutdown().await;
            return;
        }
        cursor = revision + 1;
        if !events.is_empty()
            && !chunk(
                stream,
                &json!({ "result": { "header": header(revision), "watch_id": "0", "events": events } }),
            )
            .await
        {
            return;
        }
        tokio::select! {
            changed = news.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            // The client going away ends the stream; it sends nothing else.
            read = stream.read(&mut scratch) => {
                if read.map_or(true, |read| read == 0) {
                    return;
                }
            }
        }
    }
}
