//! Shared harness for the provider's tests: a fake admin socket that speaks the `PUT`, `validate`
//! and `version` endpoints and can answer `409`, `422`, `5xx` or drop connections, scripted
//! sources, and builders for the model types.
//!
//! Every wait in here has a deadline, so a broken test fails instead of hanging.

// Each test file compiles this module on its own and uses a different subset of it.
#![allow(dead_code, unreachable_pub, clippy::needless_pass_by_value)]

pub mod broker;
pub mod daemon;
pub mod dns_server;
pub mod docker;
pub mod k8s;
pub mod k8s_crd;
pub mod nomad;
// The daemon's harness, one copy for both crates: the provider must not depend on the daemon, so
// the file is included by path. It may use only what both test targets have: the same
// dev-dependencies and `super::free_ports`. The same file is `tests/common/pebble.rs`.
#[path = "../../../../tests/common/pebble.rs"]
pub mod pebble;

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use podgate_model::{App, Certificate};
use podgate_provider::source::{Origin, Source, SourceApp, SourceCertificate, TenantClaim, Update};
use podgate_provider::{Config, Engine, RunError, Status, UpstreamPolicy};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// The longest a test waits for anything.
pub const DEADLINE: Duration = Duration::from_secs(20);

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A socket path under the temp dir that nothing listens on.
pub fn socket_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pgp-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// `count` distinct free loopback ports. All probes stay bound until every port is chosen, so
/// the kernel cannot hand the same port out twice.
pub fn free_ports(count: usize) -> Vec<u16> {
    let probes: Vec<std::net::TcpListener> = (0..count)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("bind free port"))
        .collect();
    probes
        .iter()
        .map(|probe| probe.local_addr().expect("local addr").port())
        .collect()
}

/// One snapshot the fake accepted.
#[derive(Debug, Clone)]
pub struct Put {
    pub version: u64,
    pub writer: Option<String>,
    pub body: Value,
    pub at: Instant,
}

/// What the fake answers instead of its normal behaviour.
#[derive(Debug, Clone)]
pub enum Reply {
    /// A status and a JSON body.
    Status(u16, Value),
    /// Another writer moved the live version to this number: answer `409` stale.
    Stale(u64),
    /// Close the connection without answering.
    Drop,
}

type Rule = Arc<dyn Fn(&Value) -> Vec<Value> + Send + Sync>;

struct Inner {
    live_version: u64,
    boot_id: String,
    writer: Option<String>,
    puts: Vec<Put>,
    attempts: Vec<Value>,
    validations: Vec<Value>,
    script: VecDeque<Reply>,
    busy_validations: u32,
    rule: Rule,
    events: Vec<Value>,
    next_seq: u64,
    oldest_kept: u64,
    polls: Vec<u64>,
}

/// A fake admin socket.
pub struct FakeAdmin {
    pub path: PathBuf,
    inner: Arc<Mutex<Inner>>,
    task: Option<JoinHandle<()>>,
}

fn lock(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeAdmin {
    /// Listens on a fresh socket.
    pub fn start() -> Self {
        Self::start_at(socket_path())
    }

    /// Listens on `path`.
    pub fn start_at(path: PathBuf) -> Self {
        let mut admin = Self::reserve(path);
        admin.listen();
        admin
    }

    /// An admin socket that does not listen yet: nothing is at `path` until [`Self::listen`].
    pub fn reserve(path: PathBuf) -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            live_version: 0,
            boot_id: "boot-1".into(),
            writer: None,
            puts: Vec::new(),
            attempts: Vec::new(),
            validations: Vec::new(),
            script: VecDeque::new(),
            busy_validations: 0,
            rule: Arc::new(|_| Vec::new()),
            events: Vec::new(),
            next_seq: 1,
            oldest_kept: 1,
            polls: Vec::new(),
        }));
        Self {
            path,
            inner,
            task: None,
        }
    }

    /// Starts listening on the reserved path.
    pub fn listen(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let listener = UnixListener::bind(&self.path).expect("bind the fake admin socket");
        let shared = Arc::clone(&self.inner);
        self.task = Some(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move { serve(stream, shared).await });
            }
        }));
    }

    /// Decides which snapshots the compiler refuses: the rule returns the `conflicts` of the
    /// `422`, or nothing to accept.
    pub fn reject_when(&self, rule: impl Fn(&Value) -> Vec<Value> + Send + Sync + 'static) {
        lock(&self.inner).rule = Arc::new(rule);
    }

    /// The next `PUT`s are answered by `replies`, one each, before the normal behaviour.
    pub fn script(&self, replies: impl IntoIterator<Item = Reply>) {
        lock(&self.inner).script.extend(replies);
    }

    /// The next `n` validations answer `503` busy.
    pub fn busy_validations(&self, n: u32) {
        lock(&self.inner).busy_validations = n;
    }

    /// A podgate restart: no snapshot, no pinned writer, a new boot id.
    pub fn restart(&self) {
        let mut inner = lock(&self.inner);
        inner.live_version = 0;
        inner.writer = None;
        inner.boot_id = format!("{}-restarted", inner.boot_id);
        inner.events.clear();
        inner.next_seq = 1;
        inner.oldest_kept = 1;
    }

    /// Another writer pushed `version`.
    pub fn someone_else_pushed(&self, version: u64) {
        lock(&self.inner).live_version = version;
    }

    /// Another writer owns the snapshot.
    pub fn pin_writer(&self, name: &str) {
        lock(&self.inner).writer = Some(name.to_owned());
    }

    pub fn puts(&self) -> Vec<Put> {
        lock(&self.inner).puts.clone()
    }

    /// Every `PUT` that reached the fake, accepted or not (the body only).
    pub fn attempts(&self) -> Vec<Value> {
        lock(&self.inner).attempts.clone()
    }

    pub fn validations(&self) -> Vec<Value> {
        lock(&self.inner).validations.clone()
    }

    /// Appends an event to the feed and returns its sequence number. `event` carries `kind` and
    /// the kind's fields; `seq` is added.
    pub fn emit(&self, mut event: Value) -> u64 {
        let mut inner = lock(&self.inner);
        let seq = inner.next_seq;
        inner.next_seq += 1;
        event["seq"] = json!(seq);
        inner.events.push(event);
        seq
    }

    /// The `after` of every poll of the feed so far.
    pub fn polls(&self) -> Vec<u64> {
        lock(&self.inner).polls.clone()
    }

    /// The feed forgets everything before `oldest`: a poll with an older cursor gets `410`.
    pub fn forget_events_before(&self, oldest: u64) {
        let mut inner = lock(&self.inner);
        inner.oldest_kept = oldest;
        inner.next_seq = inner.next_seq.max(oldest);
        inner
            .events
            .retain(|event| event["seq"].as_u64() >= Some(oldest));
    }

    pub fn live_version(&self) -> u64 {
        lock(&self.inner).live_version
    }

    /// Waits until `condition` holds for the accepted `PUT`s.
    pub async fn wait_puts(&self, what: &str, condition: impl Fn(&[Put]) -> bool) -> Vec<Put> {
        let start = Instant::now();
        loop {
            let puts = self.puts();
            if condition(&puts) {
                return puts;
            }
            assert!(
                start.elapsed() < DEADLINE,
                "timed out waiting for: {what}; puts: {puts:?}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

impl Drop for FakeAdmin {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn read_request(
    stream: &mut UnixStream,
) -> Option<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_owned();
    let path = request_line.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = raw[head_end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((method, path, headers, body))
}

async fn respond(stream: &mut UnixStream, status: u16, body: &Value) {
    let text = body.to_string();
    let reason = match status {
        200 => "OK",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let answer = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(answer.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// `GET /v1/events`: a long poll with the daemon's answers (`200` with events or empty after
/// `timeout_secs`, `410` when `after` is older than what the feed keeps).
async fn events_answer(shared: &Arc<Mutex<Inner>>, path: &str) -> (u16, Value) {
    let query = path.split_once('?').map_or("", |(_, query)| query);
    let param = |name: &str| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let (after, wait) = (param("after"), param("timeout_secs"));
    lock(shared).polls.push(after);
    let start = Instant::now();
    loop {
        {
            let inner = lock(shared);
            if after + 1 < inner.oldest_kept {
                return (
                    410,
                    json!({ "error": "events are no longer retained", "boot_id": inner.boot_id, "oldest": inner.oldest_kept }),
                );
            }
            let events: Vec<Value> = inner
                .events
                .iter()
                .filter(|event| event["seq"].as_u64() > Some(after))
                .cloned()
                .collect();
            if !events.is_empty() || start.elapsed() >= Duration::from_secs(wait) {
                return (200, json!({ "boot_id": inner.boot_id, "events": events }));
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn rejection(conflicts: Vec<Value>) -> Value {
    json!({ "error": "snapshot rejected", "conflicts": conflicts })
}

async fn serve(mut stream: UnixStream, shared: Arc<Mutex<Inner>>) {
    let Some((method, path, headers, body)) = read_request(&mut stream).await else {
        return;
    };
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let route = (method.as_str(), path.split('?').next().unwrap_or_default());
    let (status, answer): (u16, Value) = match route {
        ("GET", "/v1/events") => events_answer(&shared, &path).await,
        ("GET", "/v1/snapshot/version") => {
            let inner = lock(&shared);
            (
                200,
                json!({ "version": inner.live_version, "writer": inner.writer, "boot_id": inner.boot_id }),
            )
        }
        ("POST", "/v1/snapshot/validate") => {
            let mut inner = lock(&shared);
            inner.validations.push(json.clone());
            if inner.busy_validations > 0 {
                inner.busy_validations -= 1;
                (503, json!({ "error": "validate is busy" }))
            } else {
                let conflicts = (inner.rule)(&json);
                if conflicts.is_empty() {
                    (200, json!({ "valid": true, "warnings": [] }))
                } else {
                    (422, rejection(conflicts))
                }
            }
        }
        ("PUT", "/v1/snapshot") => {
            let writer = headers
                .iter()
                .find(|(name, _)| name == "podgate-writer")
                .map(|(_, value)| value.clone());
            let scripted = {
                let mut inner = lock(&shared);
                inner.attempts.push(json.clone());
                let reply = inner.script.pop_front();
                if let Some(Reply::Stale(live)) = &reply {
                    inner.live_version = *live;
                }
                reply
            };
            if let Some(reply) = scripted {
                match reply {
                    Reply::Status(status, body) => respond(&mut stream, status, &body).await,
                    Reply::Stale(live) => {
                        let error = format!("stale snapshot: not newer than live version {live}");
                        respond(&mut stream, 409, &json!({ "error": error })).await;
                    }
                    Reply::Drop => drop(stream),
                }
                return;
            }
            let mut inner = lock(&shared);
            let version = json.get("version").and_then(Value::as_u64).unwrap_or(0);
            if inner.writer.is_some() && inner.writer != writer {
                let owner = inner.writer.clone();
                (
                    409,
                    json!({ "error": format!("snapshot is owned by writer {}", owner.as_deref().unwrap_or("?")), "writer": owner }),
                )
            } else if version <= inner.live_version {
                (
                    409,
                    json!({ "error": format!("stale snapshot: version {version} is not newer than live version {}", inner.live_version) }),
                )
            } else {
                let conflicts = (inner.rule)(&json);
                if conflicts.is_empty() {
                    inner.live_version = version;
                    inner.writer = writer.clone().or(inner.writer.take());
                    inner.puts.push(Put {
                        version,
                        writer,
                        body: json,
                        at: Instant::now(),
                    });
                    (200, json!({ "version": version }))
                } else {
                    (422, rejection(conflicts))
                }
            }
        }
        _ => (404, json!({ "error": "not found" })),
    };
    respond(&mut stream, status, &answer).await;
}

/// The ids of the apps of a pushed snapshot.
pub fn app_ids(snapshot: &Value) -> Vec<String> {
    snapshot["apps"]
        .as_array()
        .map(|apps| {
            apps.iter()
                .filter_map(|app| app["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A `host_conflict`-shaped conflict naming `declared_by`.
pub fn conflict(code: &str, declared_by: &[&str]) -> Value {
    json!({ "code": code, "message": format!("{code} between {declared_by:?}"), "declared_by": declared_by })
}

/// A snapshot-level rejection that names no object.
pub fn unattributed() -> Value {
    json!({ "code": "invalid_acme", "message": "something about the snapshot", "app": "", "declared_by": "", "at": "acme" })
}

/// A configuration with the given extra TOML after the admin socket line.
pub fn config(socket: &Path, extra: &str) -> Config {
    let text = format!("admin_socket = {:?}\n{extra}", socket.display().to_string());
    Config::parse(&text).unwrap_or_else(|err| panic!("test config is invalid: {err}\n{text}"))
}

/// A source whose updates the test sends by hand.
pub struct ScriptedSource {
    name: String,
    inbox: mpsc::UnboundedReceiver<Update>,
}

/// The test's end of a [`ScriptedSource`].
#[derive(Clone)]
pub struct SourceHandle {
    name: String,
    tx: mpsc::UnboundedSender<Update>,
}

pub fn scripted(name: &str) -> (ScriptedSource, SourceHandle) {
    let (tx, inbox) = mpsc::unbounded_channel();
    (
        ScriptedSource {
            name: name.to_owned(),
            inbox,
        },
        SourceHandle {
            name: name.to_owned(),
            tx,
        },
    )
}

impl Source for ScriptedSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(mut self, updates: mpsc::Sender<Update>) {
        while let Some(update) = self.inbox.recv().await {
            if updates.send(update).await.is_err() {
                return;
            }
        }
    }
}

impl SourceHandle {
    pub fn state(&self, apps: Vec<SourceApp>, certificates: Vec<SourceCertificate>) {
        let _ = self.tx.send(Update::state(&self.name, apps, certificates));
    }

    pub fn apps(&self, apps: Vec<SourceApp>) {
        self.state(apps, Vec::new());
    }

    pub fn outage(&self, error: &str) {
        let _ = self.tx.send(Update::outage(&self.name, error));
    }
}

/// An app of `source` named `local`, serving `hosts` from `upstream` (`http://ip:port`).
pub fn app(source: &str, local: &str, hosts: &[&str], upstream: &str) -> SourceApp {
    app_with(source, local, json!({ "host": hosts }), upstream)
}

/// Like [`app`], with the matcher given.
pub fn app_with(source: &str, local: &str, matcher: Value, upstream: &str) -> SourceApp {
    let app: App = serde_json::from_value(json!({
        "id": local,
        "tenant": "ignored",
        "declared_by": "ignored",
        "tls": { "mode": "acme" },
        "routers": [{ "name": "main", "match": matcher, "service": "svc" }],
        "services": [{ "name": "svc", "type": "loadbalancer", "servers": [{ "url": upstream }] }],
        "revisions": [{ "id": "r1", "state": "serving", "weight": 1 }],
    }))
    .expect("test app");
    SourceApp {
        origin: Origin {
            source: source.into(),
            object: local.into(),
            first_seen: 0,
        },
        tenant: TenantClaim::none(),
        app,
    }
}

/// Builder methods on [`SourceApp`] for tests.
pub trait AppExt: Sized {
    /// The same app, claimed by `tenant` through the source's mapping.
    fn mapped(self, tenant: &str) -> Self;
    /// The same app, naming `tenant` in a label.
    fn labelled(self, tenant: &str) -> Self;
    /// The same app with the age stamp `stamp`.
    fn first_seen(self, stamp: u64) -> Self;
    /// The same app, with certificates issued at the first handshake (`tls.mode = on_demand`).
    fn on_demand(self) -> Self;
}

impl AppExt for SourceApp {
    fn mapped(mut self, tenant: &str) -> Self {
        self.tenant = TenantClaim::mapped(tenant);
        self
    }

    fn labelled(mut self, tenant: &str) -> Self {
        self.tenant = std::mem::take(&mut self.tenant).with_label(tenant);
        self
    }

    fn first_seen(mut self, stamp: u64) -> Self {
        self.origin.first_seen = stamp;
        self
    }

    fn on_demand(mut self) -> Self {
        self.app.tls.mode = podgate_model::TlsMode::OnDemand;
        self
    }
}

/// A certificate for `hosts` (the PEM is opaque to the provider).
pub fn certificate(source: &str, object: &str, hosts: &[&str]) -> SourceCertificate {
    let certificate: Certificate = serde_json::from_value(json!({
        "hosts": hosts,
        "cert_pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        "key_pem": "test key material, not a real key\n",
    }))
    .expect("test certificate");
    SourceCertificate {
        origin: Origin {
            source: source.into(),
            object: object.into(),
            first_seen: 0,
        },
        tenant: TenantClaim::none(),
        certificate,
    }
}

/// A running engine with its fake admin socket and scripted sources.
pub struct Harness {
    pub admin: FakeAdmin,
    pub sources: BTreeMap<String, SourceHandle>,
    pub status: watch::Receiver<Status>,
    stop: Option<oneshot::Sender<()>>,
    run: Option<JoinHandle<Result<(), RunError>>>,
}

pub fn fast_tuning() -> podgate_provider::push::Tuning {
    podgate_provider::push::Tuning {
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(80),
        request_timeout: Duration::from_secs(5),
        busy_wait: Duration::from_millis(10),
        event_poll: Duration::from_secs(1),
    }
}

impl Harness {
    /// Starts an engine over a fresh fake socket. `extra` is the configuration after the admin
    /// socket line; `source_names` are scripted sources of kind `fake`.
    pub fn start(extra: &str, source_names: &[&str]) -> Self {
        Self::start_with(FakeAdmin::start(), extra, source_names)
    }

    /// Starts an engine whose admin socket at `path` does not exist yet: call
    /// `harness.admin.listen()` to create it.
    pub fn start_unbound(path: PathBuf, extra: &str, source_names: &[&str]) -> Self {
        Self::start_with(FakeAdmin::reserve(path), extra, source_names)
    }

    pub fn start_with(admin: FakeAdmin, extra: &str, source_names: &[&str]) -> Self {
        let sources_toml: String = source_names
            .iter()
            .map(|name| format!("[[source]]\nkind = \"fake\"\nname = \"{name}\"\n"))
            .collect();
        // Top-level keys must come before any table, so the sources go last.
        let config = config(&admin.path, &format!("{extra}\n{sources_toml}"));
        let mut engine = Engine::new(config, UpstreamPolicy::builtin()).with_tuning(fast_tuning());
        let mut handles = BTreeMap::new();
        for name in source_names {
            let (source, handle) = scripted(name);
            engine.add_source(source).expect("configured source");
            handles.insert((*name).to_owned(), handle);
        }
        let status = engine.status();
        let (stop, stopped) = oneshot::channel::<()>();
        let run = tokio::spawn(async move {
            engine
                .run(async {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            admin,
            sources: handles,
            status,
            stop: Some(stop),
            run: Some(run),
        }
    }

    pub fn source(&self, name: &str) -> &SourceHandle {
        self.sources.get(name).expect("a scripted source")
    }

    /// Waits until the status satisfies `condition`.
    pub async fn wait_status(&mut self, what: &str, condition: impl Fn(&Status) -> bool) -> Status {
        let wait = async {
            loop {
                let status = self.status.borrow_and_update().clone();
                if condition(&status) {
                    return status;
                }
                if self.status.changed().await.is_err() {
                    panic!("the engine ended while waiting for: {what}");
                }
            }
        };
        match tokio::time::timeout(DEADLINE, wait).await {
            Ok(status) => status,
            Err(_) => panic!(
                "timed out waiting for status: {what}; status: {:?}",
                self.status.borrow()
            ),
        }
    }

    /// Stops the engine and returns how it ended.
    pub async fn stop(mut self) -> Result<(), RunError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let run = self.run.take().expect("not stopped yet");
        tokio::time::timeout(DEADLINE, run)
            .await
            .expect("the engine stops")
            .expect("the engine task does not panic")
    }

    /// Stops the engine and hands the admin socket back, for a test that starts a second
    /// engine against the same podgate.
    pub async fn stop_keep_admin(mut self) -> FakeAdmin {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let run = self.run.take().expect("not stopped yet");
        tokio::time::timeout(DEADLINE, run)
            .await
            .expect("the engine stops")
            .expect("the engine task does not panic")
            .expect("the engine stopped cleanly");
        self.admin
    }

    /// Waits for the engine to end by itself (a writer conflict).
    pub async fn finished(&mut self) -> Result<(), RunError> {
        let run = self.run.as_mut().expect("not stopped yet");
        tokio::time::timeout(DEADLINE, run)
            .await
            .expect("the engine ends by itself")
            .expect("the engine task does not panic")
    }
}
