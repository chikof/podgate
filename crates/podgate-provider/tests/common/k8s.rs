//! A fake Kubernetes API server: serves list and watch JSON for any resource kind, with
//! resource versions, bookmarks, `410 Gone`, outages and a bearer-token check. Never a real
//! cluster. Every wait has a deadline.
//!
//! Objects are plain JSON; the fake reads `metadata.name` and `metadata.namespace` and stamps
//! `metadata.resourceVersion` itself, one counter for the whole server like etcd's revision.
//! Kinds are named by their plural (`ingresses`, `services`, `endpointslices`, `secrets`).
//!
//! What it models of the real API:
//! - `LIST` with `limit` and `continue` pages, a list `resourceVersion`, a `fieldSelector` of
//!   the form `type=...` (what the source asks for on Secrets), cluster-wide and per-namespace
//!   paths.
//! - `WATCH` from a `resourceVersion`: replays what changed since, then streams live, sends
//!   `BOOKMARK` frames when told to (only to watches that asked for them), and ends after
//!   `timeoutSeconds`.
//! - History expiry: after [`FakeApi::expire_history`] a watch from an older version gets an
//!   `ERROR` frame with code 410, or an HTTP 410, as the real server does either way.
//! - Outages: [`FakeApi::fail`] answers 503 or resets connections, and cuts open watches.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::DEADLINE;

/// How the fake misbehaves instead of answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Every request gets this status with a Status body.
    Status(u16),
    /// Every connection is closed without an answer.
    Reset,
}

/// How a too-old watch version is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoneAs {
    /// `200`, then one `ERROR` frame with code 410 (what a real API server usually does).
    Frame,
    /// A `410` HTTP status before any frame.
    Status,
}

/// One request the fake saw.
#[derive(Debug, Clone)]
pub struct Seen {
    /// The HTTP method.
    pub method: String,
    /// The path without the query.
    pub path: String,
    /// The query parameters.
    pub query: BTreeMap<String, String>,
    /// The `Authorization` header, if any.
    pub authorization: Option<String>,
    /// The `Content-Type` header, if any.
    pub content_type: Option<String>,
    /// The JSON body, if the request had one.
    pub body: Option<Value>,
}

impl Seen {
    /// Whether this is a watch.
    pub fn is_watch(&self) -> bool {
        self.query.get("watch").is_some_and(|value| value == "true")
    }

    /// The plural resource name the path names.
    pub fn plural(&self) -> &str {
        route(&self.path).map_or("", |route| route.plural)
    }

    /// Whether the request changes something: `POST`, `PUT` or `PATCH`.
    pub fn is_write(&self) -> bool {
        matches!(self.method.as_str(), "POST" | "PUT" | "PATCH")
    }

    /// Whether this writes the `status` subresource.
    pub fn is_status_write(&self) -> bool {
        self.is_write() && self.path.ends_with("/status")
    }

    /// The name of the object the path names, if it names one.
    pub fn object(&self) -> Option<&str> {
        route(&self.path).and_then(|route| route.name)
    }
}

struct Logged {
    seq: u64,
    rv: u64,
    plural: String,
    kind: &'static str,
    object: Value,
}

struct Inner {
    rv: u64,
    seq: u64,
    objects: BTreeMap<String, BTreeMap<(String, String), Value>>,
    log: Vec<Logged>,
    compacted: u64,
    generation: u64,
    failure: Option<Failure>,
    gone_as: GoneAs,
    tokens: Vec<String>,
    requests: Vec<Seen>,
}

struct Shared {
    inner: Mutex<Inner>,
    /// Carries the newest log sequence; watches wait on it.
    news: watch::Sender<u64>,
}

fn lock(shared: &Shared) -> MutexGuard<'_, Inner> {
    shared.inner.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A fake API server on a loopback port.
pub struct FakeApi {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
    /// The PEM of the certificate the server presents, when it speaks TLS.
    pub ca_pem: Option<String>,
}

impl Drop for FakeApi {
    fn drop(&mut self) {
        self.task.abort();
    }
}

static DIR: AtomicU64 = AtomicU64::new(0);

impl FakeApi {
    /// Plain HTTP, which the client accepts on loopback only.
    pub async fn start() -> Self {
        Self::start_with(None).await
    }

    /// TLS with a fresh self-signed certificate for `127.0.0.1`, which the kubeconfig trusts as
    /// its certificate authority.
    pub async fn start_tls() -> Self {
        let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("certificate parameters");
        params.is_ca = rcgen::IsCa::NoCa;
        let key = rcgen::KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key).expect("self-signed certificate");
        let chain = vec![cert.der().clone()];
        let private =
            rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der()).expect("private key");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .expect("server certificate");
        let mut api =
            Self::start_with(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))).await;
        api.ca_pem = Some(cert.pem());
        api
    }

    async fn start_with(tls: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake API");
        let addr = listener.local_addr().expect("address");
        let (news, _) = watch::channel(0);
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                rv: 100,
                seq: 0,
                objects: BTreeMap::new(),
                log: Vec::new(),
                compacted: 0,
                generation: 0,
                failure: None,
                gone_as: GoneAs::Frame,
                tokens: Vec::new(),
                requests: Vec::new(),
            }),
            news,
        });
        let state = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&state);
                let tls = tls.clone();
                tokio::spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(stream).await {
                                Box::pin(serve(stream, state)).await;
                            }
                        }
                        None => Box::pin(serve(stream, state)).await,
                    }
                });
            }
        });
        Self {
            addr,
            shared,
            task,
            ca_pem: None,
        }
    }

    /// Writes a kubeconfig that points at this server, with `token` as the user's bearer token,
    /// and returns its path. The server then rejects requests with any other token, those of
    /// earlier calls included.
    pub fn kubeconfig(&self, dir: &Path, token: &str) -> PathBuf {
        lock(&self.shared).tokens = vec![token.to_owned()];
        self.write_kubeconfig(dir, token)
    }

    /// Like [`Self::kubeconfig`], but the server accepts `token` next to the tokens it accepts
    /// already: several clients (the replicas of a test) with their own credentials.
    pub fn kubeconfig_also(&self, dir: &Path, token: &str) -> PathBuf {
        lock(&self.shared).tokens.push(token.to_owned());
        self.write_kubeconfig(dir, token)
    }

    fn write_kubeconfig(&self, dir: &Path, token: &str) -> PathBuf {
        let scheme = if self.ca_pem.is_some() {
            "https"
        } else {
            "http"
        };
        let ca = self
            .ca_pem
            .as_ref()
            .map(|pem| {
                use base64::Engine as _;
                format!(
                    "    certificate-authority-data: {}\n",
                    base64::engine::general_purpose::STANDARD.encode(pem)
                )
            })
            .unwrap_or_default();
        let text = format!(
            "apiVersion: v1\nkind: Config\ncurrent-context: fake\ncontexts:\n- name: fake\n  context: {{cluster: fake, user: fake}}\nclusters:\n- name: fake\n  cluster:\n    server: {scheme}://{}\n{ca}users:\n- name: fake\n  user:\n    token: {token}\n",
            self.addr
        );
        let path = dir.join(format!(
            "kubeconfig-{}",
            DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, text).expect("write the kubeconfig");
        path
    }

    /// Creates or replaces an object of `plural`; a watch sees ADDED or MODIFIED. Returns the
    /// resource version it got.
    pub fn put(&self, plural: &str, object: Value) -> u64 {
        let stored = store(&self.shared, plural, object);
        stored["metadata"]["resourceVersion"]
            .as_str()
            .and_then(|rv| rv.parse().ok())
            .unwrap_or(0)
    }

    /// The object `namespace/name` of `plural` as the fake holds it now (`namespace` is empty for
    /// a cluster-scoped kind).
    pub fn get(&self, plural: &str, namespace: &str, name: &str) -> Option<Value> {
        lock(&self.shared)
            .objects
            .get(plural)
            .and_then(|objects| objects.get(&(namespace.to_owned(), name.to_owned())))
            .cloned()
    }

    /// Every request that changed something (`POST`, `PUT`, `PATCH`) so far.
    pub fn writes(&self) -> Vec<Seen> {
        self.requests().into_iter().filter(Seen::is_write).collect()
    }

    /// Deletes an object; a watch sees DELETED.
    pub fn remove(&self, plural: &str, namespace: &str, name: &str) {
        let mut inner = lock(&self.shared);
        let Some(mut object) = inner
            .objects
            .get_mut(plural)
            .and_then(|objects| objects.remove(&(namespace.to_owned(), name.to_owned())))
        else {
            return;
        };
        inner.rv += 1;
        let rv = inner.rv;
        object["metadata"]["resourceVersion"] = Value::String(rv.to_string());
        self.log(&mut inner, plural, "DELETED", rv, object);
    }

    fn log(&self, inner: &mut Inner, plural: &str, kind: &'static str, rv: u64, object: Value) {
        push_log(&self.shared, inner, plural, kind, rv, object);
    }

    /// Sends a BOOKMARK with the current version to every open watch of `plural` that asked for
    /// bookmarks.
    pub fn bookmark(&self, plural: &str) {
        let mut inner = lock(&self.shared);
        let rv = inner.rv;
        let object = json!({ "metadata": { "resourceVersion": rv.to_string() } });
        self.log(&mut inner, plural, "BOOKMARK", rv, object);
    }

    /// Forgets the history: a watch from a version older than now is refused as too old.
    pub fn expire_history(&self) {
        let mut inner = lock(&self.shared);
        inner.compacted = inner.rv;
    }

    /// How a too-old watch is refused.
    pub fn gone_as(&self, how: GoneAs) {
        lock(&self.shared).gone_as = how;
    }

    /// Closes every open watch, as a network blip or a server restart would.
    pub fn drop_watches(&self) {
        let mut inner = lock(&self.shared);
        inner.generation += 1;
        let seq = inner.seq;
        drop(inner);
        self.shared.news.send_replace(seq);
    }

    /// Starts failing every request (and cuts the open watches), or stops with `None`.
    pub fn fail(&self, failure: Option<Failure>) {
        lock(&self.shared).failure = failure;
        self.drop_watches();
    }

    /// Every request seen so far.
    pub fn requests(&self) -> Vec<Seen> {
        lock(&self.shared).requests.clone()
    }

    /// How many requests for `plural` were lists (`watch == false`) or watches.
    pub fn count(&self, plural: &str, watch: bool) -> usize {
        self.requests()
            .iter()
            .filter(|seen| seen.plural() == plural && seen.is_watch() == watch)
            .count()
    }

    /// Waits until `condition` holds over the requests seen.
    pub async fn wait_requests(&self, what: &str, condition: impl Fn(&[Seen]) -> bool) {
        let started = Instant::now();
        loop {
            if condition(&lock(&self.shared).requests) {
                return;
            }
            assert!(
                started.elapsed() < DEADLINE,
                "timed out waiting for the fake API to see: {what}; saw {:?}",
                self.requests()
                    .iter()
                    .map(|seen| format!(
                        "{}{}",
                        seen.path,
                        if seen.is_watch() { " (watch)" } else { "" }
                    ))
                    .collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn identity(object: &Value) -> (String, String) {
    let meta = &object["metadata"];
    (
        meta["namespace"].as_str().unwrap_or("").to_owned(),
        meta["name"].as_str().expect("an object name").to_owned(),
    )
}

fn push_log(
    shared: &Shared,
    inner: &mut Inner,
    plural: &str,
    kind: &'static str,
    rv: u64,
    object: Value,
) {
    inner.seq += 1;
    let seq = inner.seq;
    inner.log.push(Logged {
        seq,
        rv,
        plural: plural.to_owned(),
        kind,
        object,
    });
    shared.news.send_replace(seq);
}

/// Stores `object` under its name, stamping the next resource version, and tells the watches.
/// Returns the object as stored.
fn store(shared: &Shared, plural: &str, mut object: Value) -> Value {
    let (namespace, name) = identity(&object);
    let mut inner = lock(shared);
    inner.rv += 1;
    let rv = inner.rv;
    object["metadata"]["resourceVersion"] = Value::String(rv.to_string());
    let kind = if inner
        .objects
        .entry(plural.to_owned())
        .or_default()
        .insert((namespace, name), object.clone())
        .is_some()
    {
        "MODIFIED"
    } else {
        "ADDED"
    };
    push_log(shared, &mut inner, plural, kind, rv, object.clone());
    object
}

/// RFC 7386: `patch` merged into `target`; `null` removes a key, arrays are replaced.
fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(patch) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = json!({});
    }
    let Some(fields) = target.as_object_mut() else {
        return;
    };
    for (key, value) in patch {
        if value.is_null() {
            fields.remove(key);
        } else {
            merge_patch(fields.entry(key.clone()).or_insert(Value::Null), value);
        }
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&text[index + 1..index + 3], 16)
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What a path names.
struct Route<'a> {
    namespace: Option<&'a str>,
    plural: &'a str,
    name: Option<&'a str>,
    subresource: Option<&'a str>,
}

fn route(path: &str) -> Option<Route<'_>> {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let rest = match parts.as_slice() {
        ["api", _, rest @ ..] | ["apis", _, _, rest @ ..] => rest,
        _ => return None,
    };
    let (namespace, rest) = match rest {
        ["namespaces", namespace, rest @ ..] if !rest.is_empty() => (Some(*namespace), rest),
        rest => (None, rest),
    };
    match rest {
        [plural] => Some(Route {
            namespace,
            plural,
            name: None,
            subresource: None,
        }),
        [plural, name] => Some(Route {
            namespace,
            plural,
            name: Some(name),
            subresource: None,
        }),
        [plural, name, subresource] => Some(Route {
            namespace,
            plural,
            name: Some(name),
            subresource: Some(subresource),
        }),
        _ => None,
    }
}

/// The request line and headers of one request, copied out of the read buffer.
struct Head {
    size: usize,
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn parse(buffer: &[u8]) -> Option<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(buffer) {
            Ok(httparse::Status::Complete(size)) => Some(Self {
                size,
                method: request.method?.to_owned(),
                target: request.path?.to_owned(),
                headers: request
                    .headers
                    .iter()
                    .map(|header| {
                        (
                            header.name.to_ascii_lowercase(),
                            String::from_utf8_lossy(header.value).into_owned(),
                        )
                    })
                    .collect(),
            }),
            _ => None,
        }
    }

    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
}

async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Option<Seen> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 1024 * 1024 {
            return None;
        }
        let Some(head) = Head::parse(&buffer) else {
            continue;
        };
        let length: usize = head
            .header("content-length")
            .and_then(|length| length.parse().ok())
            .unwrap_or(0);
        while buffer.len() < head.size + length {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let body = (length > 0)
            .then(|| serde_json::from_slice(&buffer[head.size..head.size + length]).ok())
            .flatten();
        let (path, query) = head
            .target
            .split_once('?')
            .unwrap_or((head.target.as_str(), ""));
        let query = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                (percent_decode(key), percent_decode(value))
            })
            .collect();
        return Some(Seen {
            method: head.method.clone(),
            path: path.to_owned(),
            query,
            authorization: head.header("authorization"),
            content_type: head.header("content-type"),
            body,
        });
    }
}

async fn respond(stream: &mut (impl AsyncWrite + Unpin), status: u16, body: &Value) {
    let body = body.to_string();
    let head = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn status_body(code: u16, message: &str) -> Value {
    json!({ "kind": "Status", "apiVersion": "v1", "status": "Failure", "message": message, "code": code })
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, shared: Arc<Shared>) {
    let Some(seen) = read_head(&mut stream).await else {
        return;
    };
    let (failure, tokens, gone_as) = {
        let mut inner = lock(&shared);
        inner.requests.push(seen.clone());
        (inner.failure, inner.tokens.clone(), inner.gone_as)
    };
    match failure {
        Some(Failure::Reset) => return,
        Some(Failure::Status(code)) => {
            respond(
                &mut stream,
                code,
                &status_body(code, "the fake API is failing"),
            )
            .await;
            return;
        }
        None => {}
    }
    if !tokens.is_empty()
        && !tokens
            .iter()
            .any(|token| seen.authorization.as_deref() == Some(&format!("Bearer {token}")))
    {
        respond(&mut stream, 401, &status_body(401, "Unauthorized")).await;
        return;
    }
    let Some(route) = route(&seen.path) else {
        respond(&mut stream, 404, &status_body(404, "no such path")).await;
        return;
    };
    let namespace = route.namespace.map(str::to_owned);
    let plural = route.plural.to_owned();
    match (seen.method.as_str(), route.name) {
        ("GET", None) if seen.is_watch() => {
            watch_stream(stream, shared, seen, namespace, plural, gone_as).await;
        }
        ("GET", None) => list(&mut stream, &shared, &seen, namespace.as_deref(), &plural).await,
        ("GET", Some(name)) => {
            let found = lock(&shared)
                .objects
                .get(&plural)
                .and_then(|objects| {
                    objects.get(&(namespace.clone().unwrap_or_default(), name.to_owned()))
                })
                .cloned();
            match found {
                Some(object) => respond(&mut stream, 200, &object).await,
                None => respond(&mut stream, 404, &status_body(404, "not found")).await,
            }
        }
        ("POST", None) => {
            let (code, body) = create(&shared, &plural, namespace.as_deref(), seen.body);
            respond(&mut stream, code, &body).await;
        }
        ("PUT" | "PATCH", Some(name)) => {
            let (code, body) = update(
                &shared,
                &plural,
                &(namespace.unwrap_or_default(), name.to_owned()),
                route.subresource,
                &seen,
            );
            respond(&mut stream, code, &body).await;
        }
        _ => respond(&mut stream, 405, &status_body(405, "not supported")).await,
    }
}

/// `POST`: creates the object, `409` when it exists.
fn create(
    shared: &Shared,
    plural: &str,
    namespace: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let Some(mut object) = body.filter(|body| body["metadata"]["name"].is_string()) else {
        return (400, status_body(400, "an object with a name is required"));
    };
    if let Some(namespace) = namespace {
        object["metadata"]["namespace"] = Value::String(namespace.to_owned());
    }
    let key = identity(&object);
    let exists = lock(shared)
        .objects
        .get(plural)
        .is_some_and(|objects| objects.contains_key(&key));
    if exists {
        return (409, status_body(409, "already exists"));
    }
    (201, store(shared, plural, object))
}

/// `PUT` and merge `PATCH` of an object or its `status`: `404` when it does not exist, `409` when
/// the body names another `resourceVersion` than the stored one.
fn update(
    shared: &Shared,
    plural: &str,
    key: &(String, String),
    subresource: Option<&str>,
    seen: &Seen,
) -> (u16, Value) {
    let Some(patch) = seen.body.clone() else {
        return (400, status_body(400, "a JSON body is required"));
    };
    let Some(mut object) = lock(shared)
        .objects
        .get(plural)
        .and_then(|objects| objects.get(key))
        .cloned()
    else {
        return (404, status_body(404, "not found"));
    };
    if let Some(version) = patch["metadata"]["resourceVersion"].as_str()
        && object["metadata"]["resourceVersion"].as_str() != Some(version)
    {
        return (409, status_body(409, "the object has been modified"));
    }
    let merge = seen.method == "PATCH";
    if subresource == Some("status") {
        let status = patch.get("status").cloned().unwrap_or(Value::Null);
        if merge {
            merge_patch(&mut object["status"], &status);
        } else {
            object["status"] = status;
        }
    } else if merge {
        merge_patch(&mut object, &patch);
    } else {
        object = patch;
    }
    (200, store(shared, plural, object))
}

fn selected(object: &Value, namespace: Option<&str>, selector: Option<&String>) -> bool {
    if let Some(namespace) = namespace
        && object["metadata"]["namespace"].as_str() != Some(namespace)
    {
        return false;
    }
    match selector.and_then(|selector| selector.split_once('=')) {
        Some(("type", wanted)) => object["type"].as_str() == Some(wanted),
        Some((field, _)) => panic!("the fake API does not know the field selector {field}"),
        None => true,
    }
}

async fn list(
    stream: &mut (impl AsyncWrite + Unpin),
    shared: &Shared,
    seen: &Seen,
    namespace: Option<&str>,
    plural: &str,
) {
    let (items, rv) = {
        let inner = lock(shared);
        let items: Vec<Value> = inner
            .objects
            .get(plural)
            .into_iter()
            .flat_map(BTreeMap::values)
            .filter(|object| selected(object, namespace, seen.query.get("fieldSelector")))
            .cloned()
            .collect();
        (items, inner.rv)
    };
    let offset: usize = seen
        .query
        .get("continue")
        .and_then(|token| token.parse().ok())
        .unwrap_or(0);
    let limit: usize = seen
        .query
        .get("limit")
        .and_then(|limit| limit.parse().ok())
        .unwrap_or(usize::MAX);
    let end = offset.saturating_add(limit).min(items.len());
    let page: Vec<Value> = items[offset.min(end)..end].to_vec();
    let mut metadata = json!({ "resourceVersion": rv.to_string() });
    if end < items.len() {
        metadata["continue"] = Value::String(end.to_string());
    }
    respond(
        stream,
        200,
        &json!({ "kind": "List", "apiVersion": "v1", "metadata": metadata, "items": page }),
    )
    .await;
}

async fn chunk(stream: &mut (impl AsyncWrite + Unpin), frame: &Value) -> bool {
    let line = format!("{frame}\n");
    let data = format!("{:x}\r\n{line}\r\n", line.len());
    stream.write_all(data.as_bytes()).await.is_ok() && stream.flush().await.is_ok()
}

async fn watch_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    shared: Arc<Shared>,
    seen: Seen,
    namespace: Option<String>,
    plural: String,
    gone_as: GoneAs,
) {
    let from: u64 = seen
        .query
        .get("resourceVersion")
        .and_then(|rv| rv.parse().ok())
        .unwrap_or(0);
    let bookmarks = seen
        .query
        .get("allowWatchBookmarks")
        .is_some_and(|value| value == "true");
    let seconds: u64 = seen
        .query
        .get("timeoutSeconds")
        .and_then(|value| value.parse().ok())
        .unwrap_or(60);
    let (generation, expired) = {
        let inner = lock(&shared);
        (inner.generation, from < inner.compacted)
    };
    if expired && gone_as == GoneAs::Status {
        respond(
            &mut stream,
            410,
            &status_body(410, "too old resource version"),
        )
        .await;
        return;
    }
    let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    if expired {
        let frame =
            json!({ "type": "ERROR", "object": status_body(410, "too old resource version") });
        chunk(&mut stream, &frame).await;
        let _ = stream.write_all(b"0\r\n\r\n").await;
        let _ = stream.shutdown().await;
        return;
    }
    // Everything that changed after `from`, then everything that is logged from now on.
    let mut cursor;
    let replay: Vec<Value> = {
        let inner = lock(&shared);
        cursor = inner.seq;
        inner
            .log
            .iter()
            .filter(|entry| {
                entry.plural == plural
                    && entry.rv > from
                    && entry.kind != "BOOKMARK"
                    && selected(
                        &entry.object,
                        namespace.as_deref(),
                        seen.query.get("fieldSelector"),
                    )
            })
            .map(|entry| json!({ "type": entry.kind, "object": entry.object }))
            .collect()
    };
    for frame in replay {
        if !chunk(&mut stream, &frame).await {
            return;
        }
    }
    let mut news = shared.news.subscribe();
    let ends = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        let batch: Vec<Value> = {
            let inner = lock(&shared);
            if inner.generation != generation {
                return;
            }
            let batch = inner
                .log
                .iter()
                .filter(|entry| entry.seq > cursor && entry.plural == plural)
                .filter(|entry| entry.kind != "BOOKMARK" || bookmarks)
                .filter(|entry| {
                    entry.kind == "BOOKMARK"
                        || selected(
                            &entry.object,
                            namespace.as_deref(),
                            seen.query.get("fieldSelector"),
                        )
                })
                .map(|entry| json!({ "type": entry.kind, "object": entry.object }))
                .collect();
            cursor = inner.seq;
            batch
        };
        for frame in batch {
            if !chunk(&mut stream, &frame).await {
                return;
            }
        }
        match tokio::time::timeout_at(ends, news.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return,
            Err(_) => {
                let _ = stream.write_all(b"0\r\n\r\n").await;
                let _ = stream.shutdown().await;
                return;
            }
        }
    }
}

// ---- builders for the objects the source reads ----------------------------------------------

/// The label that ties an EndpointSlice to its Service.
pub const SERVICE_LABEL: &str = "kubernetes.io/service-name";

/// A TLS-ready Ingress of `class` with one rule per `(host, [(path, pathType, service, port)])`.
pub fn ingress(namespace: &str, name: &str, class: &str, rules: Value) -> Value {
    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": { "namespace": namespace, "name": name, "creationTimestamp": "2026-11-20T12:00:00Z" },
        "spec": { "ingressClassName": class, "rules": rules },
    })
}

/// One rule: `host` (or none) with paths `(path, pathType, service, port)` where `port` is a
/// number or a name.
pub fn rule(host: Option<&str>, paths: &[(&str, &str, &str, Value)]) -> Value {
    let paths: Vec<Value> = paths
        .iter()
        .map(|(path, kind, service, port)| {
            let port = match port {
                Value::Number(number) => json!({ "number": number }),
                other => json!({ "name": other }),
            };
            json!({ "path": path, "pathType": kind, "backend": { "service": { "name": service, "port": port } } })
        })
        .collect();
    let mut rule = json!({ "http": { "paths": paths } });
    if let Some(host) = host {
        rule["host"] = Value::String(host.to_owned());
    }
    rule
}

/// A ClusterIP Service with `(name, port)` ports; `None` names the single port.
pub fn service(namespace: &str, name: &str, ports: &[(Option<&str>, u16)]) -> Value {
    let ports: Vec<Value> = ports
        .iter()
        .map(|(port_name, port)| {
            let mut port_json = json!({ "port": port, "protocol": "TCP" });
            if let Some(port_name) = port_name {
                port_json["name"] = Value::String((*port_name).to_owned());
            }
            port_json
        })
        .collect();
    json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": { "namespace": namespace, "name": name },
        "spec": { "type": "ClusterIP", "selector": { "app": name }, "ports": ports },
    })
}

/// A slice written by the controller for `service`: `ports` are `(service port name, container
/// port)`, `endpoints` are `(address, ready, terminating)`.
pub fn slice(
    namespace: &str,
    service: &str,
    index: u32,
    ports: &[(Option<&str>, u16)],
    endpoints: &[(&str, bool, bool)],
) -> Value {
    let ports: Vec<Value> = ports
        .iter()
        .map(|(name, port)| json!({ "name": name.unwrap_or(""), "port": port, "protocol": "TCP" }))
        .collect();
    let endpoints: Vec<Value> = endpoints
        .iter()
        .map(|(address, ready, terminating)| {
            json!({
                "addresses": [address],
                "conditions": { "ready": ready, "serving": ready, "terminating": terminating },
            })
        })
        .collect();
    json!({
        "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
        "metadata": {
            "namespace": namespace,
            "name": format!("{service}-{index}"),
            "labels": {
                SERVICE_LABEL: service,
                "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
            },
        },
        "addressType": "IPv4",
        "ports": ports,
        "endpoints": endpoints,
    })
}

/// A Secret of `kind` with base64 `data`.
pub fn secret(namespace: &str, name: &str, kind: &str, cert: &str, key: &str) -> Value {
    use base64::Engine as _;
    let encode = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);
    json!({
        "apiVersion": "v1", "kind": "Secret", "type": kind,
        "metadata": { "namespace": namespace, "name": name },
        "data": { "tls.crt": encode(cert), "tls.key": encode(key) },
    })
}
