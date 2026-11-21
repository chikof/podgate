//! A fake Nomad API on a loopback TCP port, for the Nomad source's tests. No test talks to a real
//! cluster.
//!
//! It answers the `GET` endpoints the source uses, `/v1/services` and `/v1/service/<name>`, in
//! Nomad's shape, with Nomad's blocking-query semantics: a request with `index=<n>` is held until
//! the fake's index passes `n` or `wait` (capped by [`FakeNomad::set_max_wait`]) runs out, and
//! every answer carries `X-Nomad-Index`. Every request is logged with the token it carried, and
//! anything but `GET` gets `405`. [`FakeNomad::stop`] drops the listener and every open
//! connection, like a server that died, and [`FakeNomad::restart`] listens again on the same
//! port.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

/// One registration of the fake: an allocation's instance of a service.
#[derive(Debug, Clone)]
pub struct Reg {
    pub namespace: String,
    pub service: String,
    pub alloc: String,
    pub job: String,
    pub address: String,
    pub port: u16,
    pub tags: Vec<String>,
    pub create_index: u64,
}

impl Reg {
    /// An instance of `service` in `namespace` at `address:port`, with an allocation id made from
    /// the three.
    pub fn new(namespace: &str, service: &str, address: &str, port: u16) -> Self {
        Self {
            namespace: namespace.to_owned(),
            service: service.to_owned(),
            alloc: format!(
                "{:08x}-aaaa-bbbb-cccc-{port:012}",
                address.bytes().map(u32::from).sum::<u32>()
            ),
            job: service.to_owned(),
            address: address.to_owned(),
            port,
            tags: Vec::new(),
            create_index: 0,
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

    pub fn alloc(mut self, alloc: &str) -> Self {
        alloc.clone_into(&mut self.alloc);
        self
    }

    pub fn created(mut self, index: u64) -> Self {
        self.create_index = index;
        self
    }

    fn instance(&self) -> Value {
        json!({
            "ID": format!("_nomad-task-{}-group-{}-{}-http", self.alloc, self.service, self.port),
            "ServiceName": self.service,
            "Namespace": self.namespace,
            "NodeID": "0e3a1b2c-0000-0000-0000-000000000000",
            "Datacenter": "dc1",
            "JobID": self.job,
            "AllocID": self.alloc,
            "Tags": if self.tags.is_empty() { Value::Null } else { json!(self.tags) },
            "Address": self.address,
            "Port": self.port,
            "CreateIndex": self.create_index,
            "ModifyIndex": self.create_index,
        })
    }
}

/// One request the fake got.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// The path and the query, as sent.
    pub target: String,
    /// The `X-Nomad-Token` header.
    pub token: Option<String>,
}

impl Request {
    /// The path without the query.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }

    /// The value of the query parameter `name` (`""` for a bare one), if present.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.target
            .split_once('?')?
            .1
            .split('&')
            .find_map(|pair| match pair.split_once('=') {
                Some((key, value)) => (key == name).then_some(value),
                None => (pair == name).then_some(""),
            })
    }
}

struct Inner {
    regs: Vec<Reg>,
    index: u64,
    requests: Vec<Request>,
    /// The token every request must carry, else `403`.
    require_token: Option<String>,
    max_wait: Duration,
}

/// The running fake.
pub struct FakeNomad {
    addr: SocketAddr,
    inner: Arc<Mutex<Inner>>,
    changed: watch::Sender<u64>,
    /// How many blocking queries are held open right now.
    blocked: Arc<AtomicUsize>,
    server: Mutex<Option<JoinHandle<()>>>,
}

impl FakeNomad {
    /// A fake with no registrations, listening.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake nomad port");
        let addr = listener.local_addr().expect("the fake's address");
        let (changed, _) = watch::channel(100);
        let fake = Self {
            addr,
            inner: Arc::new(Mutex::new(Inner {
                regs: Vec::new(),
                index: 100,
                requests: Vec::new(),
                require_token: None,
                max_wait: Duration::from_secs(60),
            })),
            changed,
            blocked: Arc::new(AtomicUsize::new(0)),
            server: Mutex::new(None),
        };
        fake.serve(listener);
        fake
    }

    /// `http://127.0.0.1:<port>`.
    pub fn address(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn serve(&self, listener: TcpListener) {
        let inner = Arc::clone(&self.inner);
        let changed = self.changed.clone();
        let blocked = Arc::clone(&self.blocked);
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
                    Arc::clone(&blocked),
                ));
                while connections.try_join_next().is_some() {}
            }
        });
        *self.server.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// Drops the listener and every open connection, like a server that died.
    pub fn stop(&self) {
        if let Some(task) = self
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
        self.blocked.store(0, Ordering::SeqCst);
    }

    /// Listens again on the same port.
    pub async fn restart(&self) {
        self.stop();
        // The aborted task releases the port when it is dropped, which happens on the runtime's
        // next turn; binding is retried until then.
        let wait = async {
            loop {
                if let Ok(listener) = TcpListener::bind(self.addr).await {
                    return listener;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let listener = tokio::time::timeout(super::DEADLINE, wait)
            .await
            .expect("the fake's port frees up");
        self.serve(listener);
    }

    fn bump(&self, inner: &mut Inner) {
        inner.index += 1;
        self.changed.send_replace(inner.index);
    }

    /// Replaces the registrations.
    pub fn set(&self, regs: Vec<Reg>) {
        let mut inner = self.inner();
        inner.regs = regs;
        self.bump(&mut inner);
    }

    /// Registers one more instance.
    pub fn add(&self, mut reg: Reg) {
        let mut inner = self.inner();
        if reg.create_index == 0 {
            reg.create_index = inner.index + 1;
        }
        inner.regs.push(reg);
        self.bump(&mut inner);
    }

    /// Deregisters every instance of `service` in `namespace`.
    pub fn remove(&self, namespace: &str, service: &str) {
        let mut inner = self.inner();
        inner
            .regs
            .retain(|reg| !(reg.namespace == namespace && reg.service == service));
        self.bump(&mut inner);
    }

    /// Requires `X-Nomad-Token: <token>` on every request.
    pub fn require_token(&self, token: &str) {
        self.inner().require_token = Some(token.to_owned());
    }

    /// The longest a blocking query is held, whatever `wait` says.
    pub fn set_max_wait(&self, wait: Duration) {
        self.inner().max_wait = wait;
    }

    /// How many blocking queries are held open right now.
    pub fn blocked(&self) -> usize {
        self.blocked.load(Ordering::SeqCst)
    }

    /// Every request so far, oldest first.
    pub fn requests(&self) -> Vec<Request> {
        self.inner().requests.clone()
    }

    /// The requests that were blocking queries (`index` given).
    pub fn blocking_queries(&self) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|request| request.path() == "/v1/services" && request.param("index").is_some())
            .collect()
    }

    /// How many `GET /v1/service/<name>` requests there were.
    pub fn instance_reads(&self) -> usize {
        self.requests()
            .iter()
            .filter(|request| request.path().starts_with("/v1/service/"))
            .count()
    }
}

impl Drop for FakeNomad {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Held(Arc<AtomicUsize>);

impl Held {
    fn new(blocked: Arc<AtomicUsize>) -> Self {
        blocked.fetch_add(1, Ordering::SeqCst);
        Self(blocked)
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        // `stop` zeroes the count before the aborted connections drop; never wrap below zero.
        let _ = self
            .0
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
    }
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
    let text = String::from_utf8_lossy(&buffer);
    let mut lines = text.lines();
    let mut parts = lines.next()?.split(' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let token = lines.take_while(|line| !line.is_empty()).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("x-nomad-token")
            .then(|| value.trim().to_owned())
    });
    Some(Request {
        method,
        target,
        token,
    })
}

async fn respond(stream: &mut TcpStream, status: &str, index: u64, body: &Value) {
    let body = body.to_string();
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nX-Nomad-Index: {index}\r\nX-Nomad-KnownLeader: true\r\nX-Nomad-LastContact: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let hex = (bytes[at] == b'%')
            .then(|| text.get(at + 1..at + 3))
            .flatten()
            .and_then(|digits| u8::from_str_radix(digits, 16).ok());
        match hex {
            Some(byte) => {
                out.push(byte);
                at += 3;
            }
            None => {
                out.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `60s` or `500ms`, as Nomad takes them.
fn duration(text: &str) -> Duration {
    if let Some(millis) = text.strip_suffix("ms") {
        return Duration::from_millis(millis.parse().unwrap_or(0));
    }
    Duration::from_secs(text.trim_end_matches('s').parse().unwrap_or(0))
}

async fn handle(
    mut stream: TcpStream,
    inner: Arc<Mutex<Inner>>,
    mut changed: watch::Receiver<u64>,
    blocked: Arc<AtomicUsize>,
) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    let (denied, max_wait) = {
        let mut inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.requests.push(request.clone());
        let denied = inner
            .require_token
            .as_ref()
            .is_some_and(|token| request.token.as_ref() != Some(token));
        (denied, inner.max_wait)
    };
    let current = |inner: &Mutex<Inner>| inner.lock().unwrap_or_else(PoisonError::into_inner).index;
    if denied {
        respond(
            &mut stream,
            "403 Forbidden",
            current(&inner),
            &json!("Permission denied"),
        )
        .await;
        return;
    }
    if request.method != "GET" {
        respond(
            &mut stream,
            "405 Method Not Allowed",
            current(&inner),
            &json!("the fake only answers GET"),
        )
        .await;
        return;
    }
    let namespace = request
        .param("namespace")
        .map_or_else(|| "default".to_owned(), decode);
    let path = request.path().to_owned();
    if path == "/v1/services" {
        if let Some(index) = request.param("index").and_then(|n| n.parse::<u64>().ok()) {
            let wait = request
                .param("wait")
                .map_or(max_wait, duration)
                .min(max_wait);
            let _held = Held::new(Arc::clone(&blocked));
            let deadline = tokio::time::Instant::now() + wait;
            while current(&inner) <= index {
                if tokio::time::timeout_at(deadline, changed.changed())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
        let (index, listing) = {
            let inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
            let mut services: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
            for reg in inner.regs.iter().filter(|reg| reg.namespace == namespace) {
                services
                    .entry(&reg.service)
                    .or_default()
                    .extend(reg.tags.iter().map(String::as_str));
            }
            let listing = if services.is_empty() {
                json!([])
            } else {
                json!([{
                    "Namespace": namespace,
                    "Services": services
                        .iter()
                        .map(|(name, tags)| json!({
                            "ServiceName": name,
                            "Tags": if tags.is_empty() { Value::Null } else { json!(tags) },
                        }))
                        .collect::<Vec<_>>(),
                }])
            };
            (inner.index, listing)
        };
        respond(&mut stream, "200 OK", index, &listing).await;
    } else if let Some(name) = path.strip_prefix("/v1/service/") {
        let name = decode(name);
        let (index, instances) = {
            let inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
            let instances: Vec<Value> = inner
                .regs
                .iter()
                .filter(|reg| reg.namespace == namespace && reg.service == name)
                .map(Reg::instance)
                .collect();
            (inner.index, instances)
        };
        respond(&mut stream, "200 OK", index, &Value::Array(instances)).await;
    } else {
        respond(
            &mut stream,
            "404 Not Found",
            current(&inner),
            &json!("no such endpoint"),
        )
        .await;
    }
}
