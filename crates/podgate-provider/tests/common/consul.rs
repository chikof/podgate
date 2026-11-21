//! A fake Consul HTTP API on a loopback port, for the Consul source's tests. No test talks to a
//! real Consul.
//!
//! It answers the two `GET` endpoints the source uses, `/v1/catalog/services` and
//! `/v1/health/service/<name>`, in the shape of Consul 1.x, with the semantics the source relies
//! on:
//!
//! - **Blocking queries.** `?index=<n>&wait=<s>s` holds the answer until the index of the data
//!   passes `n`, or the wait is over (never longer than [`FakeConsul::max_hold`], so a broken
//!   test fails instead of hanging), and sends the index in `X-Consul-Index`.
//! - **`passing=true`** drops every instance with a check that is not `passing`.
//! - **`ns`, `partition`, `dc`** select what is listed.
//! - **`X-Consul-Token`** is recorded, and checked when [`FakeConsul::require_token`] says so;
//!   a rejected token is echoed in the `403`, like Consul names what it dislikes.
//!
//! Every request is logged, and anything but `GET` is answered `405`.
//! [`FakeConsul::stop`] drops the listener and every open connection, like a Consul that died.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use super::DEADLINE;

/// One service instance registered with the fake.
#[derive(Debug, Clone)]
pub struct Svc {
    pub id: String,
    pub name: String,
    pub node: String,
    pub node_address: String,
    /// `Service.Address`; empty means "use the node's".
    pub address: String,
    pub port: u16,
    pub tags: Vec<String>,
    pub meta: BTreeMap<String, String>,
    pub kind: String,
    pub namespace: String,
    pub partition: String,
    /// The status of every check of the service, besides the node's `serfHealth`.
    pub checks: Vec<&'static str>,
    /// `serfHealth`'s status.
    pub node_check: &'static str,
}

impl Svc {
    /// Instance `id` of service `name` at `address:port`, passing, with no tags.
    pub fn new(id: &str, name: &str, address: &str, port: u16) -> Self {
        Self {
            id: id.to_owned(),
            name: name.to_owned(),
            node: format!("node-{id}"),
            node_address: "10.254.0.1".to_owned(),
            address: address.to_owned(),
            port,
            tags: Vec::new(),
            meta: BTreeMap::new(),
            kind: String::new(),
            namespace: "default".to_owned(),
            partition: "default".to_owned(),
            checks: vec!["passing"],
            node_check: "passing",
        }
    }

    pub fn tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_owned());
        self
    }

    pub fn tags(mut self, tags: &[&str]) -> Self {
        self.tags.extend(tags.iter().map(|tag| (*tag).to_owned()));
        self
    }

    pub fn meta(mut self, key: &str, value: &str) -> Self {
        self.meta.insert(key.to_owned(), value.to_owned());
        self
    }

    pub fn kind(mut self, kind: &str) -> Self {
        self.kind = kind.to_owned();
        self
    }

    pub fn namespace(mut self, namespace: &str) -> Self {
        self.namespace = namespace.to_owned();
        self
    }

    pub fn partition(mut self, partition: &str) -> Self {
        self.partition = partition.to_owned();
        self
    }

    pub fn node(mut self, node: &str, address: &str) -> Self {
        self.node = node.to_owned();
        self.node_address = address.to_owned();
        self
    }

    /// The statuses of the service's own checks.
    pub fn checks(mut self, checks: &[&'static str]) -> Self {
        self.checks = checks.to_vec();
        self
    }

    /// The status of the node's check.
    pub fn node_check(mut self, status: &'static str) -> Self {
        self.node_check = status;
        self
    }

    fn passing(&self) -> bool {
        self.node_check == "passing" && self.checks.iter().all(|status| *status == "passing")
    }

    fn health_entry(&self, datacenter: &str, create_index: u64) -> Value {
        let mut checks = vec![json!({ "CheckID": "serfHealth", "Status": self.node_check })];
        for (n, status) in self.checks.iter().enumerate() {
            checks.push(json!({ "CheckID": format!("service:{}:{n}", self.id), "Status": status }));
        }
        let mut service = json!({
            "ID": self.id,
            "Service": self.name,
            "Tags": if self.tags.is_empty() { Value::Null } else { json!(self.tags) },
            "Address": self.address,
            "Port": self.port,
            "Meta": if self.meta.is_empty() { Value::Null } else { json!(self.meta) },
            "CreateIndex": create_index,
            "ModifyIndex": create_index,
            "Namespace": self.namespace,
            "Partition": self.partition,
        });
        if !self.kind.is_empty() {
            service["Kind"] = json!(self.kind);
        }
        json!({
            "Node": {
                "ID": format!("id-{}", self.node),
                "Node": self.node,
                "Address": self.node_address,
                "Datacenter": datacenter,
            },
            "Service": service,
            "Checks": checks,
        })
    }
}

/// A request the fake received.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    /// The raw query string, for the flags that have no value (`stale`).
    pub raw_query: String,
    pub token: Option<String>,
}

impl Request {
    pub fn index(&self) -> Option<u64> {
        self.query.get("index").and_then(|index| index.parse().ok())
    }
}

struct Entry {
    svc: Svc,
    create_index: u64,
}

struct Inner {
    datacenter: String,
    entries: Vec<Entry>,
    generation: u64,
    catalog_index: u64,
    service_index: BTreeMap<String, u64>,
    token: Option<String>,
    requests: Vec<Request>,
    failures: VecDeque<u16>,
    honour_passing: bool,
    max_hold: Duration,
}

impl Inner {
    fn bump(&mut self, names: &[&str]) -> u64 {
        self.generation += 1;
        self.catalog_index = self.generation;
        for name in names {
            self.service_index
                .insert((*name).to_owned(), self.generation);
        }
        self.generation
    }
}

/// The running fake.
pub struct FakeConsul {
    port: u16,
    inner: Arc<Mutex<Inner>>,
    changed: watch::Sender<u64>,
    held: Arc<AtomicUsize>,
    server: Mutex<Option<JoinHandle<()>>>,
}

impl FakeConsul {
    /// A fake with datacenter `dc1` and no services, listening.
    pub async fn start() -> Self {
        let (changed, _) = watch::channel(0);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake consul");
        let fake = Self {
            port: listener.local_addr().expect("local addr").port(),
            inner: Arc::new(Mutex::new(Inner {
                datacenter: "dc1".to_owned(),
                entries: Vec::new(),
                generation: 1,
                catalog_index: 1,
                service_index: BTreeMap::new(),
                token: None,
                requests: Vec::new(),
                failures: VecDeque::new(),
                honour_passing: true,
                max_hold: Duration::from_secs(10),
            })),
            changed,
            held: Arc::new(AtomicUsize::new(0)),
            server: Mutex::new(None),
        };
        fake.serve(listener);
        fake
    }

    /// `http://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn serve(&self, listener: TcpListener) {
        let inner = Arc::clone(&self.inner);
        let changed = self.changed.clone();
        let held = Arc::clone(&self.held);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                connections.spawn(handle(
                    stream,
                    Arc::clone(&inner),
                    changed.subscribe(),
                    Arc::clone(&held),
                ));
                while connections.try_join_next().is_some() {}
            }
        });
        *self.server.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// Drops the listener and every open connection, like a Consul that died.
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

    fn notify(&self) {
        self.changed.send_modify(|generation| *generation += 1);
    }

    /// Registers an instance.
    pub fn register(&self, svc: Svc) {
        {
            let mut inner = self.inner();
            let name = svc.name.clone();
            let create_index = inner.bump(&[&name]);
            inner.entries.retain(|entry| entry.svc.id != svc.id);
            inner.entries.push(Entry { svc, create_index });
        }
        self.notify();
    }

    /// Registers several instances.
    pub fn register_all(&self, svcs: impl IntoIterator<Item = Svc>) {
        for svc in svcs {
            self.register(svc);
        }
    }

    /// Removes the instance with `id`.
    pub fn deregister(&self, id: &str) {
        {
            let mut inner = self.inner();
            let name = inner
                .entries
                .iter()
                .find(|entry| entry.svc.id == id)
                .map(|entry| entry.svc.name.clone())
                .unwrap_or_else(|| panic!("no fake instance {id}"));
            inner.entries.retain(|entry| entry.svc.id != id);
            inner.bump(&[&name]);
        }
        self.notify();
    }

    /// Changes the instance with `id`.
    pub fn update(&self, id: &str, change: impl FnOnce(&mut Svc)) {
        {
            let mut inner = self.inner();
            let entry = inner
                .entries
                .iter_mut()
                .find(|entry| entry.svc.id == id)
                .unwrap_or_else(|| panic!("no fake instance {id}"));
            let before = entry.svc.name.clone();
            change(&mut entry.svc);
            let after = entry.svc.name.clone();
            inner.bump(&[&before, &after]);
        }
        self.notify();
    }

    /// Sets the status of the service's own checks.
    pub fn set_checks(&self, id: &str, checks: &[&'static str]) {
        let checks = checks.to_vec();
        self.update(id, move |svc| svc.checks = checks);
    }

    /// Answers every request that has no token, or another one, with `403`.
    pub fn require_token(&self, token: &str) {
        self.inner().token = Some(token.to_owned());
    }

    /// The next `count` requests get `status` and a short text.
    pub fn fail_next(&self, status: u16, count: usize) {
        self.inner().failures.extend(vec![status; count]);
    }

    /// Goes back in time: every index becomes `to`, as after a restore from a snapshot or a
    /// query answered by a server that is behind.
    pub fn rewind_indexes(&self, to: u64) {
        {
            let mut inner = self.inner();
            inner.generation = to;
            inner.catalog_index = to;
            for index in inner.service_index.values_mut() {
                *index = to;
            }
        }
        self.notify();
    }

    /// Stops honouring `passing=true`, so only the source's own check filter is left.
    pub fn ignore_passing_filter(&self) {
        self.inner().honour_passing = false;
    }

    /// The longest a blocking query is held, whatever its `wait` says.
    pub fn max_hold(&self, hold: Duration) {
        self.inner().max_hold = hold;
    }

    /// How many blocking queries are held open right now.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }

    /// Every request so far, oldest first.
    pub fn requests(&self) -> Vec<Request> {
        self.inner().requests.clone()
    }

    /// The requests for the health of `name`.
    pub fn health_requests(&self, name: &str) -> Vec<Request> {
        let path = format!("/v1/health/service/{name}");
        self.requests()
            .into_iter()
            .filter(|request| request.path == path)
            .collect()
    }

    /// The paths of the health requests, one entry per distinct service.
    pub fn health_paths(&self) -> BTreeSet<String> {
        self.requests()
            .into_iter()
            .filter(|request| request.path.starts_with("/v1/health/service/"))
            .map(|request| request.path)
            .collect()
    }

    /// Waits until `condition` holds for the requests so far.
    pub async fn wait_requests(&self, what: &str, condition: impl Fn(&[Request]) -> bool) {
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

    /// Waits until `count` blocking queries are held open.
    pub async fn wait_held(&self, count: usize) {
        let deadline = Instant::now() + DEADLINE;
        while self.held() < count {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {count} held queries; {} held",
                self.held()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for FakeConsul {
    fn drop(&mut self) {
        self.stop();
    }
}

struct HeldGuard(Arc<AtomicUsize>);

impl Drop for HeldGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let hex = bytes
            .get(at + 1..at + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[at], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                at += 3;
            }
            (byte, _) => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 || buffer.len() > 16 * 1024 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buffer).into_owned();
    let mut lines = text.lines();
    let mut parts = lines.next()?.split(' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?;
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let query = raw_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key), decode(value))
        })
        .collect();
    let token = lines.take_while(|line| !line.is_empty()).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("x-consul-token")
            .then(|| value.trim().to_owned())
    });
    Some(Request {
        method,
        path: decode(path),
        query,
        raw_query: raw_query.to_owned(),
        token,
    })
}

async fn respond(stream: &mut TcpStream, status: &str, index: Option<u64>, body: &str) {
    let index = index.map_or_else(String::new, |index| format!("X-Consul-Index: {index}\r\n"));
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{index}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// `10s`, `500ms`, `1m` as a duration.
fn parse_wait(text: &str) -> Option<Duration> {
    if let Some(ms) = text.strip_suffix("ms") {
        return ms.parse().ok().map(Duration::from_millis);
    }
    if let Some(s) = text.strip_suffix('s') {
        return s.parse().ok().map(Duration::from_secs);
    }
    text.strip_suffix('m')?
        .parse::<u64>()
        .ok()
        .map(|m| Duration::from_secs(m * 60))
}

/// The index and body of what `request` asks for, or an error status.
fn answer(inner: &Inner, request: &Request) -> Result<(u64, Value), (&'static str, String)> {
    let get = |key: &str, default: &str| {
        request
            .query
            .get(key)
            .map_or_else(|| default.to_owned(), Clone::clone)
    };
    if let Some(dc) = request.query.get("dc")
        && *dc != inner.datacenter
    {
        return Err((
            "500 Internal Server Error",
            "No path to datacenter".to_owned(),
        ));
    }
    let (namespace, partition) = (get("ns", "default"), get("partition", "default"));
    let visible = || {
        inner
            .entries
            .iter()
            .filter(|entry| entry.svc.namespace == namespace && entry.svc.partition == partition)
    };
    if request.path == "/v1/catalog/services" {
        let mut services: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for entry in visible() {
            services
                .entry(&entry.svc.name)
                .or_default()
                .extend(entry.svc.tags.iter().map(String::as_str));
        }
        return Ok((inner.catalog_index, json!(services)));
    }
    if let Some(name) = request.path.strip_prefix("/v1/health/service/") {
        let passing_only =
            request.query.get("passing").is_some_and(|v| v == "true") && inner.honour_passing;
        let entries: Vec<Value> = visible()
            .filter(|entry| entry.svc.name == name)
            .filter(|entry| !passing_only || entry.svc.passing())
            .map(|entry| {
                entry
                    .svc
                    .health_entry(&inner.datacenter, entry.create_index)
            })
            .collect();
        let index = inner.service_index.get(name).copied().unwrap_or(1);
        return Ok((index, Value::Array(entries)));
    }
    Err(("404 Not Found", "no such endpoint".to_owned()))
}

async fn handle(
    mut stream: TcpStream,
    inner: Arc<Mutex<Inner>>,
    mut changed: watch::Receiver<u64>,
    held: Arc<AtomicUsize>,
) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    let start = Instant::now();
    let (rejection, max_hold) = {
        let mut inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.requests.push(request.clone());
        let rejection = if request.method != "GET" {
            Some((
                "405 Method Not Allowed",
                "the fake only answers GET".to_owned(),
            ))
        } else if let Some(status) = inner.failures.pop_front() {
            Some(match status {
                503 => ("503 Service Unavailable", "Service Unavailable".to_owned()),
                _ => (
                    "500 Internal Server Error",
                    "rpc error: scripted failure".to_owned(),
                ),
            })
        } else if inner
            .token
            .as_ref()
            .is_some_and(|required| request.token.as_ref() != Some(required))
        {
            let who = request.token.as_ref().map_or_else(
                || "the anonymous token".to_owned(),
                |t| format!("token {t}"),
            );
            Some((
                "403 Forbidden",
                format!("Permission denied: {who} lacks service:read"),
            ))
        } else {
            None
        };
        (rejection, inner.max_hold)
    };
    if let Some((status, text)) = rejection {
        respond(&mut stream, status, None, &text).await;
        return;
    }
    let wanted = request.index().unwrap_or(0);
    let wait = request
        .query
        .get("wait")
        .and_then(|wait| parse_wait(wait))
        .unwrap_or(Duration::from_secs(300))
        .min(max_hold);
    let deadline = start + wait;
    let mut guard = None;
    loop {
        let result = {
            let inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
            answer(&inner, &request)
        };
        let (index, body) = match result {
            Ok(answer) => answer,
            Err((status, text)) => {
                respond(&mut stream, status, None, &text).await;
                return;
            }
        };
        if wanted == 0 || index > wanted || Instant::now() >= deadline {
            respond(&mut stream, "200 OK", Some(index), &body.to_string()).await;
            return;
        }
        if guard.is_none() {
            held.fetch_add(1, Ordering::SeqCst);
            guard = Some(HeldGuard(Arc::clone(&held)));
        }
        tokio::select! {
            _ = changed.changed() => {}
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
        }
    }
}
