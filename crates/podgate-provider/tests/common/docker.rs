//! A fake Docker and Podman API on a unix socket, for the Docker source's tests. No test
//! talks to a real daemon.
//!
//! It answers the `GET` endpoints the source uses (`/containers/json`, `/containers/<id>/json`,
//! `/networks`, `/events`) in the shape of either engine ([`Flavor`]), logs every request it
//! gets, and answers `405` to anything but `GET` (which a test then finds in [`FakeDocker::requests`]).
//! [`FakeDocker::stop`] drops the listener and every open connection, like a daemon that died.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::task::{JoinHandle, JoinSet};

use super::socket_path;

/// Whose API shape the fake speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// Docker Engine.
    Docker,
    /// Podman's Docker-compatible API: names without the leading slash, no `Health` or
    /// `Healthcheck` for a container without a check, `null` labels, offset timestamps and
    /// fields Docker does not send.
    Podman,
}

/// One container of the fake.
#[derive(Debug, Clone)]
pub struct Ctr {
    pub id: String,
    pub name: String,
    pub created: String,
    pub labels: BTreeMap<String, String>,
    pub status: &'static str,
    /// `Some("healthy")`, `Some("starting")`, ... when the image has a health check.
    pub health: Option<&'static str>,
    pub networks: Vec<(String, String)>,
}

impl Ctr {
    pub fn new(name: &str) -> Self {
        let hash = {
            use std::hash::{DefaultHasher, Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            name.hash(&mut hasher);
            hasher.finish()
        };
        Self {
            id: format!("{hash:016x}{:048}", 0),
            name: name.to_owned(),
            created: "2026-11-20T10:00:00.000000000Z".to_owned(),
            labels: BTreeMap::new(),
            status: "running",
            health: None,
            networks: Vec::new(),
        }
    }

    pub fn label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_owned(), value.to_owned());
        self
    }

    /// Several labels at once.
    pub fn labels(mut self, pairs: &[(&str, &str)]) -> Self {
        for (key, value) in pairs {
            self.labels.insert((*key).to_owned(), (*value).to_owned());
        }
        self
    }

    /// Attached to `network` with `address` (empty: attached without an address).
    pub fn network(mut self, network: &str, address: &str) -> Self {
        self.networks.push((network.to_owned(), address.to_owned()));
        self
    }

    pub fn health(mut self, health: &'static str) -> Self {
        self.health = Some(health);
        self
    }

    pub fn status(mut self, status: &'static str) -> Self {
        self.status = status;
        self
    }

    /// Created at `2026-11-20T10:00:<seconds>Z`.
    pub fn created_at(mut self, seconds: u32) -> Self {
        self.created = format!("2026-11-20T10:00:{seconds:02}.000000000Z");
        self
    }

    fn inspect(&self, flavor: Flavor) -> Value {
        let networks: BTreeMap<&str, Value> = self
            .networks
            .iter()
            .map(|(network, address)| {
                let mut endpoint = json!({ "IPAddress": address, "GlobalIPv6Address": "" });
                if flavor == Flavor::Podman {
                    endpoint["SecondaryIPAddresses"] = Value::Null;
                    endpoint["NetworkID"] = json!("0123");
                }
                (network.as_str(), endpoint)
            })
            .collect();
        let running = self.status == "running";
        let mut state = json!({
            "Status": self.status,
            "Running": running,
            "Paused": self.status == "paused",
            "Restarting": self.status == "restarting",
        });
        let mut config = json!({ "Labels": self.labels });
        match (self.health, flavor) {
            (Some(health), _) => {
                state["Health"] = json!({ "Status": health, "FailingStreak": 0 });
                config["Healthcheck"] = json!({ "Test": ["CMD", "true"] });
            }
            (None, Flavor::Podman) => {
                state["Health"] = Value::Null;
                config["Healthcheck"] = Value::Null;
                if self.labels.is_empty() {
                    config["Labels"] = Value::Null;
                }
            }
            (None, Flavor::Docker) => {}
        }
        let mut body = json!({
            "Id": self.id,
            "Name": match flavor {
                Flavor::Docker => format!("/{}", self.name),
                Flavor::Podman => self.name.clone(),
            },
            "Created": match flavor {
                Flavor::Docker => self.created.clone(),
                Flavor::Podman => self.created.replace('Z', "+00:00"),
            },
            "State": state,
            "Config": config,
            "NetworkSettings": { "Networks": networks },
        });
        if flavor == Flavor::Podman {
            body["Pod"] = json!("");
            body["Mounts"] = json!([]);
            body["HostConfig"] = json!({ "NetworkMode": "bridge" });
        }
        body
    }

    fn listed(&self, flavor: Flavor) -> Value {
        json!({
            "Id": self.id,
            "Names": [match flavor {
                Flavor::Docker => format!("/{}", self.name),
                Flavor::Podman => self.name.clone(),
            }],
            "State": self.status,
            "Labels": self.labels,
        })
    }
}

struct Inner {
    flavor: Flavor,
    containers: Vec<Ctr>,
    networks: Vec<String>,
    requests: Vec<(String, String)>,
}

/// The running fake.
pub struct FakeDocker {
    path: PathBuf,
    inner: Arc<Mutex<Inner>>,
    events: broadcast::Sender<String>,
    streams: Arc<AtomicUsize>,
    server: Mutex<Option<JoinHandle<()>>>,
}

impl FakeDocker {
    /// A Docker-shaped fake with no containers, listening.
    pub fn start() -> Self {
        Self::start_as(Flavor::Docker)
    }

    pub fn start_as(flavor: Flavor) -> Self {
        let (events, _) = broadcast::channel(64);
        let fake = Self {
            path: socket_path(),
            inner: Arc::new(Mutex::new(Inner {
                flavor,
                containers: Vec::new(),
                networks: Vec::new(),
                requests: Vec::new(),
            })),
            events,
            streams: Arc::new(AtomicUsize::new(0)),
            server: Mutex::new(None),
        };
        fake.listen();
        fake
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn listen(&self) {
        let _ = std::fs::remove_file(&self.path);
        let listener = UnixListener::bind(&self.path).expect("bind the fake docker socket");
        let inner = Arc::clone(&self.inner);
        let events = self.events.clone();
        let streams = Arc::clone(&self.streams);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                connections.spawn(serve(
                    stream,
                    Arc::clone(&inner),
                    events.subscribe(),
                    Arc::clone(&streams),
                ));
                while connections.try_join_next().is_some() {}
            }
        });
        *self.server.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// Drops the listener and every open connection, like a daemon that died.
    pub fn stop(&self) {
        if let Some(task) = self
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.path);
    }

    /// Listens again on the same path.
    pub fn restart(&self) {
        self.stop();
        self.listen();
    }

    /// Replaces the containers.
    pub fn set(&self, containers: Vec<Ctr>) {
        self.inner().containers = containers;
    }

    pub fn add(&self, container: Ctr) {
        self.inner().containers.push(container);
    }

    pub fn remove(&self, name: &str) {
        self.inner().containers.retain(|c| c.name != name);
    }

    /// Changes the container called `name`.
    pub fn update(&self, name: &str, change: impl FnOnce(&mut Ctr)) {
        let mut inner = self.inner();
        let container = inner
            .containers
            .iter_mut()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no fake container {name}"));
        change(container);
    }

    /// The networks `GET /networks` lists.
    pub fn set_networks(&self, networks: &[&str]) {
        self.inner().networks = networks.iter().map(|n| (*n).to_owned()).collect();
    }

    /// Sends an event to every open `/events` stream.
    pub fn emit(&self, event: &Value) {
        let _ = self.events.send(event.to_string());
    }

    /// A container event in the shape of the fake's flavor.
    pub fn container_event(&self, action: &str, container: &str) -> Value {
        let id = self
            .inner()
            .containers
            .iter()
            .find(|c| c.name == container)
            .map_or_else(|| "unknown".to_owned(), |c| c.id.clone());
        match self.inner().flavor {
            Flavor::Docker => json!({
                "status": action, "id": id, "from": "image", "Type": "container",
                "Action": action, "Actor": { "ID": id, "Attributes": { "name": container } },
                "scope": "local", "time": 1_795_176_000, "timeNano": 1_795_176_000_000_000_000_u64,
            }),
            Flavor::Podman => json!({
                "Type": "container", "Action": action, "status": action, "id": id,
                "Actor": { "ID": id, "Attributes": { "name": container } },
                "time": 1_795_176_000, "timeNano": 1_795_176_000_000_000_000_u64,
            }),
        }
    }

    /// How many `/events` streams are open.
    pub fn event_streams(&self) -> usize {
        self.streams.load(Ordering::SeqCst)
    }

    /// Every request so far as `(method, path)`, oldest first.
    pub fn requests(&self) -> Vec<(String, String)> {
        self.inner().requests.clone()
    }

    /// How many `GET /containers/json` requests there were.
    pub fn lists(&self) -> usize {
        self.requests()
            .iter()
            .filter(|(_, path)| {
                strip_version(path.split('?').next().unwrap_or(path)) == "/containers/json"
            })
            .count()
    }
}

impl Drop for FakeDocker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The path without a `/v1.43` or `/v4.0.0` prefix, which both engines accept.
pub fn strip_version(path: &str) -> &str {
    let Some(rest) = path.strip_prefix("/v") else {
        return path;
    };
    match rest.split_once('/') {
        Some((version, tail)) if version.bytes().all(|b| b.is_ascii_digit() || b == b'.') => {
            &path[path.len() - tail.len() - 1..]
        }
        _ => path,
    }
}

struct StreamGuard(Arc<AtomicUsize>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub async fn read_request(stream: &mut UnixStream) -> Option<(String, String)> {
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
    let line = text.lines().next()?;
    let mut parts = line.split(' ');
    Some((parts.next()?.to_owned(), parts.next()?.to_owned()))
}

pub async fn respond(stream: &mut UnixStream, flavor: Flavor, status: &str, body: &Value) {
    let body = body.to_string();
    let engine = match flavor {
        Flavor::Docker => "Api-Version: 1.43\r\nServer: Docker/27.0 (linux)\r\n",
        Flavor::Podman => "Libpod-Api-Version: 4.9.0\r\nApi-Version: 1.41\r\n",
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{engine}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn serve(
    mut stream: UnixStream,
    inner: Arc<Mutex<Inner>>,
    mut events: broadcast::Receiver<String>,
    streams: Arc<AtomicUsize>,
) {
    let Some((method, path)) = read_request(&mut stream).await else {
        return;
    };
    let (flavor, listed, inspected, networks) = {
        let mut inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.requests.push((method.clone(), path.clone()));
        let flavor = inner.flavor;
        let route = strip_version(path.split('?').next().unwrap_or(&path)).to_owned();
        let listed: Vec<Value> = inner
            .containers
            .iter()
            .filter(|c| !matches!(c.status, "exited" | "created"))
            .map(|c| c.listed(flavor))
            .collect();
        let inspected = route
            .strip_prefix("/containers/")
            .and_then(|rest| rest.strip_suffix("/json"))
            .and_then(|id| inner.containers.iter().find(|c| c.id == id))
            .map(|c| c.inspect(flavor));
        let attached = inner
            .containers
            .iter()
            .flat_map(|c| c.networks.iter().map(|(name, _)| name));
        let names: std::collections::BTreeSet<&String> =
            inner.networks.iter().chain(attached).collect();
        let networks: Vec<Value> = names
            .into_iter()
            .map(|name| json!({ "Name": name }))
            .collect();
        (flavor, listed, inspected, networks)
    };
    let route = strip_version(path.split('?').next().unwrap_or(&path));
    if method != "GET" {
        respond(
            &mut stream,
            flavor,
            "405 Method Not Allowed",
            &json!({ "message": "the fake only answers GET" }),
        )
        .await;
        return;
    }
    match route {
        "/containers/json" => respond(&mut stream, flavor, "200 OK", &Value::Array(listed)).await,
        "/networks" => respond(&mut stream, flavor, "200 OK", &Value::Array(networks)).await,
        "/events" => {
            let _guard = {
                streams.fetch_add(1, Ordering::SeqCst);
                StreamGuard(streams)
            };
            let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            if stream.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            while let Ok(event) = events.recv().await {
                let line = format!("{event}\n");
                let chunk = format!("{:x}\r\n{line}\r\n", line.len());
                if stream.write_all(chunk.as_bytes()).await.is_err() {
                    return;
                }
            }
        }
        _ => match inspected {
            Some(body) => respond(&mut stream, flavor, "200 OK", &body).await,
            None => {
                respond(
                    &mut stream,
                    flavor,
                    "404 Not Found",
                    &json!({ "message": "no such container" }),
                )
                .await;
            }
        },
    }
}
