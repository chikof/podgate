//! A fake Docker Swarm manager API on a unix socket, for the Swarm source's tests. No test talks
//! to a real engine.
//!
//! It answers the `GET` endpoints the source uses (`/services`, `/tasks`, `/nodes`, `/networks`,
//! `/events`) in the shape of the engine's Swarm API, logs every request it gets, and answers
//! `405` to anything but `GET` (which a test then finds in [`FakeSwarm::requests`]). A path can
//! be refused like a socket proxy would ([`FakeSwarm::refuse`]), and [`FakeSwarm::stop`] drops
//! the listener and every open connection, like a manager that died.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::task::{JoinHandle, JoinSet};

use super::docker::{Flavor, read_request, respond, strip_version};
use super::socket_path;

/// The id the fake gives a thing called `name`: stable, and 25 characters like the engine's.
fn id_of(kind: &str, name: &str) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    (kind, name).hash(&mut hasher);
    format!("{:025x}", u128::from(hasher.finish()))
}

/// The id of the network called `name`.
pub fn network_id(name: &str) -> String {
    id_of("network", name)
}

/// The id of the service called `name`.
pub fn service_id(name: &str) -> String {
    id_of("service", name)
}

/// One service of the fake.
#[derive(Debug, Clone)]
pub struct Svc {
    pub name: String,
    pub created: String,
    /// `Spec.Labels`: what the deployer wrote on the service.
    pub labels: BTreeMap<String, String>,
    /// `Spec.TaskTemplate.ContainerSpec.Labels`: what ends up on the containers.
    pub container_labels: BTreeMap<String, String>,
    /// `(network, address)`: the virtual IPs.
    pub vips: Vec<(String, String)>,
}

impl Svc {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            created: "2026-11-20T10:00:00.000000000Z".to_owned(),
            labels: BTreeMap::new(),
            container_labels: BTreeMap::new(),
            vips: Vec::new(),
        }
    }

    pub fn label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_owned(), value.to_owned());
        self
    }

    pub fn labels(mut self, pairs: &[(&str, &str)]) -> Self {
        for (key, value) in pairs {
            self.labels.insert((*key).to_owned(), (*value).to_owned());
        }
        self
    }

    /// A label of the containers, not of the service.
    pub fn container_label(mut self, key: &str, value: &str) -> Self {
        self.container_labels
            .insert(key.to_owned(), value.to_owned());
        self
    }

    /// The virtual IP on `network`.
    pub fn vip(mut self, network: &str, address: &str) -> Self {
        self.vips.push((network.to_owned(), address.to_owned()));
        self
    }

    /// Created at `2026-11-20T10:00:<seconds>Z`.
    pub fn created_at(mut self, seconds: u32) -> Self {
        self.created = format!("2026-11-20T10:00:{seconds:02}.000000000Z");
        self
    }

    fn json(&self) -> Value {
        let vips: Vec<Value> = self
            .vips
            .iter()
            .map(|(network, address)| {
                json!({ "NetworkID": network_id(network), "Addr": format!("{address}/24") })
            })
            .collect();
        json!({
            "ID": service_id(&self.name),
            "Version": { "Index": 11 },
            "CreatedAt": self.created,
            "UpdatedAt": self.created,
            "Spec": {
                "Name": self.name,
                "Labels": self.labels,
                "TaskTemplate": {
                    "ContainerSpec": { "Image": "example/web:1", "Labels": self.container_labels },
                },
                "Mode": { "Replicated": { "Replicas": 2 } },
            },
            "Endpoint": {
                "Spec": { "Mode": "vip" },
                "VirtualIPs": vips,
            },
        })
    }
}

/// One task of the fake.
#[derive(Debug, Clone)]
pub struct Tsk {
    pub id: String,
    pub service: String,
    pub slot: u64,
    pub node: String,
    pub state: &'static str,
    pub desired: &'static str,
    /// `Some("healthy")`, `Some("unhealthy")`, ... when the engine reports a health status.
    pub health: Option<&'static str>,
    /// `(network, address)`.
    pub networks: Vec<(String, String)>,
}

impl Tsk {
    /// The task of `service` in `slot`, running on node `node-1`.
    pub fn new(service: &str, slot: u64) -> Self {
        Self {
            id: id_of("task", &format!("{service}.{slot}")),
            service: service.to_owned(),
            slot,
            node: "node-1".to_owned(),
            state: "running",
            desired: "running",
            health: None,
            networks: Vec::new(),
        }
    }

    /// A different task of the same slot: the replacement a rolling update starts.
    pub fn generation(mut self, generation: u32) -> Self {
        self.id = id_of(
            "task",
            &format!("{}.{}.{generation}", self.service, self.slot),
        );
        self
    }

    /// Attached to `network` with `address` (empty: attached without an address).
    pub fn network(mut self, network: &str, address: &str) -> Self {
        self.networks.push((network.to_owned(), address.to_owned()));
        self
    }

    pub fn state(mut self, state: &'static str) -> Self {
        self.state = state;
        self
    }

    pub fn desired(mut self, desired: &'static str) -> Self {
        self.desired = desired;
        self
    }

    pub fn health(mut self, health: &'static str) -> Self {
        self.health = Some(health);
        self
    }

    pub fn node(mut self, node: &str) -> Self {
        node.clone_into(&mut self.node);
        self
    }

    fn json(&self) -> Value {
        let attachments: Vec<Value> = self
            .networks
            .iter()
            .map(|(network, address)| {
                let addresses: Vec<String> = if address.is_empty() {
                    Vec::new()
                } else {
                    vec![format!("{address}/24")]
                };
                json!({
                    "Network": {
                        "ID": network_id(network),
                        "Spec": { "Name": network, "DriverConfiguration": { "Name": "overlay" } },
                    },
                    "Addresses": addresses,
                })
            })
            .collect();
        let mut status = json!({
            "Timestamp": "2026-11-20T10:00:05.000000000Z",
            "State": self.state,
            "Message": "started",
            "ContainerStatus": { "ContainerID": id_of("container", &self.id), "PID": 4242 },
        });
        if let Some(health) = self.health {
            status["ContainerStatus"]["Health"] = json!({ "Status": health });
        }
        json!({
            "ID": self.id,
            "Version": { "Index": 21 },
            "CreatedAt": "2026-11-20T10:00:04.000000000Z",
            "ServiceID": service_id(&self.service),
            "NodeID": self.node,
            "Slot": self.slot,
            "Status": status,
            "DesiredState": self.desired,
            "NetworksAttachments": attachments,
        })
    }
}

struct Inner {
    services: Vec<Svc>,
    tasks: Vec<Tsk>,
    nodes: Vec<(String, String)>,
    networks: Vec<String>,
    refused: Vec<String>,
    requests: Vec<(String, String)>,
}

/// The running fake.
pub struct FakeSwarm {
    path: PathBuf,
    inner: Arc<Mutex<Inner>>,
    events: broadcast::Sender<String>,
    streams: Arc<AtomicUsize>,
    server: Mutex<Option<JoinHandle<()>>>,
}

impl FakeSwarm {
    /// A fake with nothing in it, listening.
    pub fn start() -> Self {
        let (events, _) = broadcast::channel(64);
        let fake = Self {
            path: socket_path(),
            inner: Arc::new(Mutex::new(Inner {
                services: Vec::new(),
                tasks: Vec::new(),
                nodes: Vec::new(),
                networks: Vec::new(),
                refused: Vec::new(),
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
        let listener = UnixListener::bind(&self.path).expect("bind the fake swarm socket");
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

    /// Drops the listener and every open connection, like a manager that died.
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

    pub fn add_service(&self, service: Svc) {
        self.inner().services.push(service);
    }

    pub fn remove_service(&self, name: &str) {
        self.inner().services.retain(|s| s.name != name);
    }

    pub fn add_task(&self, task: Tsk) {
        self.inner().tasks.push(task);
    }

    /// Changes the task `service.slot` (the newest one if there are several).
    pub fn update_task(&self, service: &str, slot: u64, change: impl FnOnce(&mut Tsk)) {
        let mut inner = self.inner();
        let task = inner
            .tasks
            .iter_mut()
            .rev()
            .find(|t| t.service == service && t.slot == slot)
            .unwrap_or_else(|| panic!("no fake task {service}.{slot}"));
        change(task);
    }

    /// Removes every task of `service` in `slot` that has this id.
    pub fn remove_task(&self, task: &Tsk) {
        self.inner().tasks.retain(|t| t.id != task.id);
    }

    /// The nodes `GET /nodes` lists, as `(id, state)`.
    pub fn set_nodes(&self, nodes: &[(&str, &str)]) {
        self.inner().nodes = nodes
            .iter()
            .map(|(id, state)| ((*id).to_owned(), (*state).to_owned()))
            .collect();
    }

    /// The networks `GET /networks` lists.
    pub fn set_networks(&self, networks: &[&str]) {
        self.inner().networks = networks.iter().map(|n| (*n).to_owned()).collect();
    }

    /// Answers `403` to `path`, like a socket proxy that does not allow it.
    pub fn refuse(&self, path: &str) {
        self.inner().refused.push(path.to_owned());
    }

    /// Sends an event to every open `/events` stream.
    pub fn emit(&self, event: &Value) {
        let _ = self.events.send(event.to_string());
    }

    /// A service event of the engine.
    pub fn service_event(&self, action: &str, service: &str) -> Value {
        json!({
            "Type": "service", "Action": action,
            "Actor": { "ID": service_id(service), "Attributes": { "name": service } },
            "scope": "swarm", "time": 1_795_176_000, "timeNano": 1_795_176_000_000_000_000_u64,
        })
    }

    /// How many `/events` streams are open.
    pub fn event_streams(&self) -> usize {
        self.streams.load(Ordering::SeqCst)
    }

    /// Every request so far as `(method, path)`, oldest first.
    pub fn requests(&self) -> Vec<(String, String)> {
        self.inner().requests.clone()
    }

    /// How many `GET /services` requests there were.
    pub fn lists(&self) -> usize {
        self.requests()
            .iter()
            .filter(|(_, path)| {
                strip_version(path.split('?').next().unwrap_or(path)) == "/services"
            })
            .count()
    }
}

impl Drop for FakeSwarm {
    fn drop(&mut self) {
        self.stop();
    }
}

struct StreamGuard(Arc<AtomicUsize>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
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
    let route = strip_version(path.split('?').next().unwrap_or(&path)).to_owned();
    let (body, refused) = {
        let mut inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.requests.push((method.clone(), path.clone()));
        let refused = inner.refused.contains(&route);
        let body = match route.as_str() {
            "/services" => Some(Value::Array(inner.services.iter().map(Svc::json).collect())),
            "/tasks" => Some(Value::Array(inner.tasks.iter().map(Tsk::json).collect())),
            "/nodes" => Some(Value::Array(
                inner
                    .nodes
                    .iter()
                    .map(|(id, state)| {
                        json!({
                            "ID": id,
                            "Spec": { "Role": "worker", "Availability": "active" },
                            "Status": { "State": state },
                        })
                    })
                    .collect(),
            )),
            "/networks" => Some(Value::Array(
                inner
                    .networks
                    .iter()
                    .map(|name| {
                        json!({
                            "Id": network_id(name), "Name": name,
                            "Scope": "swarm", "Driver": "overlay",
                        })
                    })
                    .collect(),
            )),
            _ => None,
        };
        (body, refused)
    };
    if method != "GET" {
        respond(
            &mut stream,
            Flavor::Docker,
            "405 Method Not Allowed",
            &json!({ "message": "the fake only answers GET" }),
        )
        .await;
        return;
    }
    if refused {
        respond(
            &mut stream,
            Flavor::Docker,
            "403 Forbidden",
            &json!({ "message": "the proxy does not allow this path" }),
        )
        .await;
        return;
    }
    match (route.as_str(), body) {
        (_, Some(body)) => respond(&mut stream, Flavor::Docker, "200 OK", &body).await,
        ("/events", None) => {
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
        _ => {
            respond(
                &mut stream,
                Flavor::Docker,
                "404 Not Found",
                &json!({ "message": "page not found" }),
            )
            .await;
        }
    }
}
