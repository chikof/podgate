#![allow(
    clippy::needless_pass_by_value,
    reason = "the object builders take the JSON they embed, so a call site reads like the manifest"
)]

//! Tests of Gateway API status and leader election.
//!
//! The source runs against the fake API server (`common/k8s.rs`), which keeps what is patched
//! into the status subresource and the Lease, and against a stand-in for the engine that says what
//! podgate did with the pushed snapshot (`FakeEngine`: accept everything, refuse it, quarantine
//! chosen objects, or hold it back). `status_accepted_after_push` runs the real engine and the
//! real daemon. Everything that waits has a deadline.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use common::k8s::{self, Failure, FakeApi};
use common::{DEADLINE, config as base_config};
use podgate_provider::engine::{Accepted, QuarantinedObject};
use podgate_provider::kubernetes::KubernetesSource;
use podgate_provider::kubernetes::gateway::types::CONTROLLER;
use podgate_provider::kubernetes::gateway::writer::Tuning as WriterTuning;
use podgate_provider::kubernetes::lease::Timing;
use podgate_provider::source::{ObjectKind, ObjectRef, Source, State, UpdateBody};
use podgate_provider::{Config, Status, UpstreamPolicy};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]
catch_all = true

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
"#;

const GROUP: &str = "gateway.networking.k8s.io";

// ---- builders ---------------------------------------------------------------------------------

fn gateway(namespace: &str, name: &str, generation: i64, listeners: Value) -> Value {
    json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "Gateway",
            "metadata": { "namespace": namespace, "name": name, "generation": generation,
                          "creationTimestamp": "2026-11-01T00:00:00Z" },
            "spec": { "gatewayClassName": "podgate", "listeners": listeners } })
}

/// A listener that accepts routes of every namespace.
fn listener(name: &str, port: u16, protocol: &str, hostname: Option<&str>) -> Value {
    let mut listener = json!({ "name": name, "port": port, "protocol": protocol,
                               "allowedRoutes": { "namespaces": { "from": "All" } } });
    if let Some(hostname) = hostname {
        listener["hostname"] = json!(hostname);
    }
    listener
}

fn http_route(
    namespace: &str,
    name: &str,
    generation: i64,
    parents: Value,
    hostnames: &[&str],
    rules: Value,
) -> Value {
    json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "HTTPRoute",
            "metadata": { "namespace": namespace, "name": name, "generation": generation,
                          "creationTimestamp": "2026-11-10T00:00:00Z" },
            "spec": { "parentRefs": parents, "hostnames": hostnames, "rules": rules } })
}

fn parent(gateway: &str) -> Value {
    json!({ "namespace": "team-a", "name": gateway })
}

fn to_web() -> Value {
    json!([{ "backendRefs": [{ "name": "web", "port": 80 }] }])
}

fn shop(parents: Value) -> Value {
    http_route("team-a", "shop", 1, parents, &["shop.acme.test"], to_web())
}

/// The class, two namespaces of two tenants, the open Gateway `team-a/gw` and the Service `web`.
fn world(api: &FakeApi) {
    api.put(
        "gatewayclasses",
        json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "GatewayClass",
                "metadata": { "name": "podgate", "generation": 2 },
                "spec": { "controllerName": CONTROLLER } }),
    );
    for name in ["team-a", "team-b"] {
        api.put(
            "namespaces",
            json!({ "apiVersion": "v1", "kind": "Namespace", "metadata": { "name": name } }),
        );
    }
    api.put(
        "gateways",
        gateway(
            "team-a",
            "gw",
            1,
            json!([listener("http", 80, "HTTP", None)]),
        ),
    );
    service(api, "team-a", "web");
}

fn service(api: &FakeApi, namespace: &str, name: &str) {
    api.put("services", k8s::service(namespace, name, &[(None, 80)]));
    api.put(
        "endpointslices",
        k8s::slice(
            namespace,
            name,
            0,
            &[(None, 8080)],
            &[("10.0.0.1", true, false)],
        ),
    );
}

/// Replaces the spec of an object as the API server does: the status stays.
fn update(api: &FakeApi, plural: &str, mut object: Value) {
    let meta = &object["metadata"];
    let namespace = meta["namespace"].as_str().unwrap_or("").to_owned();
    let name = meta["name"].as_str().expect("a name").to_owned();
    if let Some(old) = api.get(plural, &namespace, &name)
        && let Some(status) = old.get("status")
    {
        object["status"] = status.clone();
    }
    api.put(plural, object);
}

// ---- reading status ---------------------------------------------------------------------------

fn condition<'a>(conditions: &'a Value, kind: &str) -> &'a Value {
    conditions
        .as_array()
        .and_then(|list| list.iter().find(|c| c["type"] == kind))
        .unwrap_or(&Value::Null)
}

/// Whether the condition `kind` of `object` (`conditions` pointed at by `at`) has this status
/// and reason.
fn holds(conditions: &Value, kind: &str, status: &str, reason: &str) -> bool {
    let found = condition(conditions, kind);
    found["status"] == status && found["reason"] == reason
}

fn listener_status<'a>(gateway: &'a Value, name: &str) -> &'a Value {
    gateway["status"]["listeners"]
        .as_array()
        .and_then(|list| list.iter().find(|l| l["name"] == name))
        .unwrap_or(&Value::Null)
}

/// Our status entry of the route for the Gateway `name`.
fn parent_status<'a>(route: &'a Value, name: &str) -> &'a Value {
    route["status"]["parents"]
        .as_array()
        .and_then(|list| {
            list.iter()
                .find(|p| p["controllerName"] == CONTROLLER && p["parentRef"]["name"] == name)
        })
        .unwrap_or(&Value::Null)
}

async fn wait_object(
    api: &FakeApi,
    plural: &str,
    namespace: &str,
    name: &str,
    what: &str,
    done: impl Fn(&Value) -> bool,
) -> Value {
    let started = Instant::now();
    loop {
        let object = api.get(plural, namespace, name);
        if let Some(object) = &object
            && done(object)
        {
            return object.clone();
        }
        assert!(
            started.elapsed() < DEADLINE,
            "timed out waiting for: {what}; {plural} {namespace}/{name} is {object:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_route(api: &FakeApi, name: &str, what: &str, done: impl Fn(&Value) -> bool) -> Value {
    wait_object(api, "httproutes", "team-a", name, what, done).await
}

async fn wait_gateway(
    api: &FakeApi,
    name: &str,
    what: &str,
    done: impl Fn(&Value) -> bool,
) -> Value {
    wait_object(api, "gateways", "team-a", name, what, done).await
}

/// How many status patches went to the object `plural/name`.
fn status_writes(api: &FakeApi, plural: &str, name: &str) -> usize {
    api.writes()
        .iter()
        .filter(|seen| {
            seen.is_status_write() && seen.plural() == plural && seen.object() == Some(name)
        })
        .count()
}

// ---- the engine's side ------------------------------------------------------------------------

/// What the stand-in engine does with the state the source sends.
#[derive(Clone)]
enum Mode {
    /// Accepts every object.
    Accept,
    /// Has not pushed yet.
    Hold,
    /// Refuses the snapshot: nothing is accepted and the push fails with this reason.
    Refuse(&'static str),
    /// Accepts everything but the objects named by `declared_by`, which podgate quarantined.
    Quarantine(Vec<&'static str>, &'static str),
}

struct FakeEngine {
    tx: watch::Sender<Status>,
    mode: Mutex<Mode>,
    state: Mutex<State>,
}

fn guard<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeEngine {
    fn new(mode: Mode) -> (Arc<Self>, watch::Receiver<Status>) {
        let (tx, rx) = watch::channel(Status::default());
        let engine = Arc::new(Self {
            tx,
            mode: Mutex::new(mode),
            state: Mutex::new(State::default()),
        });
        (engine, rx)
    }

    fn set(&self, mode: Mode) {
        *guard(&self.mode) = mode;
        self.publish();
    }

    fn feed(&self, state: State) {
        *guard(&self.state) = state;
        self.publish();
    }

    fn publish(&self) {
        let mode = guard(&self.mode).clone();
        let state = guard(&self.state);
        let objects: Vec<(ObjectRef, Box<str>, String)> = state
            .apps
            .iter()
            .map(|app| (ObjectKind::App, &app.origin.object, app.fingerprint()))
            .chain(state.certificates.iter().map(|cert| {
                (
                    ObjectKind::Certificate,
                    &cert.origin.object,
                    cert.fingerprint(),
                )
            }))
            .map(|(kind, object, fingerprint)| {
                (
                    ObjectRef {
                        source: "k8s".into(),
                        kind,
                        object: object.clone(),
                    },
                    fingerprint,
                    format!("kubernetes/k8s:{object}"),
                )
            })
            .collect();
        let accepted = |left_out: &[&str]| {
            Accepted::new(
                objects
                    .iter()
                    .filter(|(_, _, declared_by)| !left_out.contains(&declared_by.as_str()))
                    .map(|(key, fingerprint, _)| (key.clone(), fingerprint.clone())),
            )
        };
        let status = match mode {
            Mode::Hold => Status::default(),
            Mode::Refuse(why) => Status {
                error: Some(why.into()),
                ..Status::default()
            },
            Mode::Accept => Status {
                accepted: accepted(&[]),
                pushed_version: Some(1),
                pushes: 1,
                ..Status::default()
            },
            Mode::Quarantine(left_out, reason) => Status {
                accepted: accepted(&left_out),
                quarantined: left_out
                    .iter()
                    .map(|declared_by| QuarantinedObject {
                        declared_by: (*declared_by).into(),
                        reason: reason.into(),
                    })
                    .collect(),
                pushed_version: Some(1),
                pushes: 1,
                ..Status::default()
            },
        };
        self.tx.send_replace(status);
    }
}

/// One provider replica: the source, and the engine stand-in that feeds on its states.
struct Replica {
    engine: Arc<FakeEngine>,
    tasks: Vec<JoinHandle<()>>,
}

impl Replica {
    fn stop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl Drop for Replica {
    fn drop(&mut self) {
        self.stop();
    }
}

fn dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pgp-gws-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create the test directory");
    path
}

fn tuning() -> podgate_provider::kubernetes::client::Tuning {
    podgate_provider::kubernetes::client::Tuning {
        watch_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(80),
        page_size: 2,
    }
}

fn source_config(api: &FakeApi, dir: &Path, token: &str, extra: &str) -> Config {
    let kubeconfig = api.kubeconfig_also(dir, token);
    base_config(
        &dir.join("admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\nnamespace_tenants = {{ team-a = \"acme\", team-b = \"globex\" }}\ngateway_api = true\nlease_namespace = \"podgate-system\"\n{extra}\n",
            kubeconfig.display().to_string()
        ),
    )
}

fn source(
    config: &Config,
    identity: &str,
    timing: Timing,
    writer: WriterTuning,
) -> KubernetesSource {
    KubernetesSource::from_config(&config.sources[0], config)
        .expect("a valid Kubernetes source")
        .with_tuning(tuning())
        .with_settle(Duration::from_millis(20))
        .with_status_tuning(timing, writer)
        .with_lease_identity(identity)
}

/// The lease timing of most tests: a record that does not change is abandoned after 1.5 s.
fn quick() -> Timing {
    Timing {
        duration: Duration::from_millis(1500),
        renew_deadline: Duration::from_millis(1000),
        retry: Duration::from_millis(100),
    }
}

fn eager() -> WriterTuning {
    WriterTuning {
        min_interval: Duration::from_millis(50),
        retry: Duration::from_millis(200),
    }
}

/// Starts a replica against `api` as `identity`, authenticating with `token`.
fn replica(
    api: &FakeApi,
    dir: &Path,
    token: &str,
    identity: &str,
    mode: Mode,
    timing: Timing,
    writer: WriterTuning,
) -> Replica {
    let config = source_config(api, dir, token, "");
    let mut source = source(&config, identity, timing, writer);
    let (engine, status) = FakeEngine::new(mode);
    source.observe(status);
    let (tx, mut updates) = mpsc::channel(64);
    let run = tokio::spawn(source.run(tx));
    let feed = {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            while let Some(update) = updates.recv().await {
                if let UpdateBody::State(state) = update.body {
                    engine.feed(state);
                }
            }
        })
    };
    Replica {
        engine,
        tasks: vec![run, feed],
    }
}

fn alone(api: &FakeApi, label: &str, mode: Mode) -> Replica {
    replica(api, &dir(label), "token", "a", mode, quick(), eager())
}

// ---- tests ------------------------------------------------------------------------------------

#[tokio::test]
async fn status_accepted_after_push() {
    // The real engine pushes to the real daemon; the status follows what the daemon accepted.
    let api = FakeApi::start().await;
    let dir = dir("accepted");
    let ports = common::free_ports(2);
    let policy = dir.join("policy.json");
    fs::write(&policy, common::daemon::LOOPBACK_POLICY).expect("policy");
    let daemon = common::daemon::Daemon::start(&policy, (ports[0], ports[1]), &[]).await;
    let (upstream, _task) = common::daemon::backend("from-the-backend").await;
    world(&api);
    api.put("services", k8s::service("team-a", "web", &[(None, 80)]));
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(None, upstream.port())],
            &[("127.0.0.1", true, false)],
        ),
    );
    api.put("httproutes", shop(json!([parent("gw")])));
    let kubeconfig = api.kubeconfig_also(&dir, "token");
    let config = base_config(
        &daemon.admin,
        &format!(
            "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 2\nupstream_policy_file = {:?}\n{TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\nnamespace_tenants = {{ team-a = \"acme\" }}\ngateway_api = true\nlease_namespace = \"podgate-system\"\n",
            policy.display().to_string(),
            kubeconfig.display().to_string()
        ),
    );
    let mut engine = podgate_provider::Engine::new(
        config.clone(),
        UpstreamPolicy::load(&policy).expect("policy"),
    )
    .with_tuning(common::fast_tuning());
    engine
        .add_source(source(&config, "a", quick(), eager()))
        .expect("source");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(async move {
        let _ = engine
            .run(async {
                let _ = stopped.await;
            })
            .await;
    });

    let gw = wait_gateway(&api, "gw", "the Gateway programmed", |gw| {
        holds(
            &gw["status"]["conditions"],
            "Programmed",
            "True",
            "Programmed",
        )
    })
    .await;
    assert!(holds(
        &gw["status"]["conditions"],
        "Accepted",
        "True",
        "Accepted"
    ));
    assert_eq!(
        condition(&gw["status"]["conditions"], "Programmed")["observedGeneration"],
        1
    );
    let http = listener_status(&gw, "http");
    assert_eq!(http["attachedRoutes"], 1);
    assert_eq!(
        http["supportedKinds"],
        json!([{ "group": GROUP, "kind": "HTTPRoute" }, { "group": GROUP, "kind": "GRPCRoute" }])
    );
    for (kind, status, reason) in [
        ("Accepted", "True", "Accepted"),
        ("Conflicted", "False", "NoConflicts"),
        ("ResolvedRefs", "True", "ResolvedRefs"),
        ("Programmed", "True", "Programmed"),
    ] {
        assert!(
            holds(&http["conditions"], kind, status, reason),
            "listener {kind}: {http}"
        );
        assert_eq!(
            condition(&http["conditions"], kind)["observedGeneration"],
            1
        );
    }
    let route = wait_route(&api, "shop", "the route's parent status", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    let ours = parent_status(&route, "gw");
    assert_eq!(
        ours["parentRef"],
        json!({ "group": GROUP, "kind": "Gateway", "namespace": "team-a", "name": "gw" })
    );
    assert!(
        holds(&ours["conditions"], "Accepted", "True", "Accepted"),
        "{ours}"
    );
    assert!(
        holds(&ours["conditions"], "ResolvedRefs", "True", "ResolvedRefs"),
        "{ours}"
    );
    let class = api.get("gatewayclasses", "", "podgate").expect("the class");
    assert!(holds(
        &class["status"]["conditions"],
        "Accepted",
        "True",
        "Accepted"
    ));
    assert_eq!(
        condition(&class["status"]["conditions"], "Accepted")["observedGeneration"],
        2
    );

    let _ = stop.send(());
    let _ = tokio::time::timeout(DEADLINE, run).await;
}

#[tokio::test]
async fn status_observed_generation() {
    let api = FakeApi::start().await;
    world(&api);
    api.put(
        "gateways",
        gateway(
            "team-a",
            "gw",
            7,
            json!([listener("http", 80, "HTTP", None)]),
        ),
    );
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "shop",
            4,
            json!([parent("gw")]),
            &["shop.acme.test"],
            to_web(),
        ),
    );
    let _replica = alone(&api, "generation", Mode::Accept);

    let gw = wait_gateway(&api, "gw", "the Gateway programmed", |gw| {
        holds(
            &gw["status"]["conditions"],
            "Programmed",
            "True",
            "Programmed",
        )
    })
    .await;
    for kind in ["Accepted", "Programmed"] {
        assert_eq!(
            condition(&gw["status"]["conditions"], kind)["observedGeneration"],
            7
        );
    }
    let http = listener_status(&gw, "http");
    for kind in ["Accepted", "Conflicted", "ResolvedRefs", "Programmed"] {
        assert_eq!(
            condition(&http["conditions"], kind)["observedGeneration"],
            7,
            "{kind}"
        );
    }
    let route = wait_route(&api, "shop", "the route's status", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    for kind in ["Accepted", "ResolvedRefs"] {
        assert_eq!(
            condition(&parent_status(&route, "gw")["conditions"], kind)["observedGeneration"],
            4
        );
    }

    // A new generation of the spec is observed on every condition.
    update(
        &api,
        "httproutes",
        http_route(
            "team-a",
            "shop",
            5,
            json!([parent("gw")]),
            &["shop.acme.test"],
            to_web(),
        ),
    );
    wait_route(&api, "shop", "generation 5 observed", |route| {
        let conditions = &parent_status(route, "gw")["conditions"];
        ["Accepted", "ResolvedRefs"]
            .iter()
            .all(|kind| condition(conditions, kind)["observedGeneration"] == 5)
    })
    .await;
}

#[tokio::test]
async fn status_unsupported_filter_reason() {
    let api = FakeApi::start().await;
    world(&api);
    // `add` cannot be expressed in podgate: the route is refused, and says why.
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "shop",
            1,
            json!([parent("gw")]),
            &["shop.acme.test"],
            json!([{ "filters": [{ "type": "RequestHeaderModifier",
                                   "requestHeaderModifier": { "add": [{ "name": "x-a", "value": "1" }] } }],
                     "backendRefs": [{ "name": "web", "port": 80 }] }]),
        ),
    );
    let _replica = alone(&api, "filter", Mode::Accept);
    let route = wait_route(&api, "shop", "the refusal", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    let conditions = &parent_status(&route, "gw")["conditions"];
    assert!(
        holds(conditions, "Accepted", "False", "UnsupportedValue"),
        "{conditions}"
    );
    let message = condition(conditions, "Accepted")["message"]
        .as_str()
        .unwrap_or("");
    assert!(
        message.contains("add"),
        "the message names the field: {message}"
    );
    assert!(
        holds(conditions, "ResolvedRefs", "True", "ResolvedRefs"),
        "{conditions}"
    );
    // A refused route is not attached to its listener.
    let gw = wait_gateway(&api, "gw", "the listener status", |gw| {
        listener_status(gw, "http")["conditions"].is_array()
    })
    .await;
    assert_eq!(listener_status(&gw, "http")["attachedRoutes"], 0);
}

#[tokio::test]
async fn status_backend_not_found() {
    let api = FakeApi::start().await;
    world(&api);
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "shop",
            1,
            json!([parent("gw")]),
            &["shop.acme.test"],
            json!([{ "backendRefs": [{ "name": "ghost", "port": 80 }] }]),
        ),
    );
    let _replica = alone(&api, "backend", Mode::Accept);
    let route = wait_route(&api, "shop", "the unresolved reference", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    let conditions = &parent_status(&route, "gw")["conditions"];
    // Attached to the listener, but a reference does not resolve.
    assert!(
        holds(conditions, "Accepted", "True", "Accepted"),
        "{conditions}"
    );
    assert!(
        holds(conditions, "ResolvedRefs", "False", "BackendNotFound"),
        "{conditions}"
    );
    let message = condition(conditions, "ResolvedRefs")["message"]
        .as_str()
        .unwrap_or("");
    assert!(message.contains("ghost"), "{message}");
    let gw = wait_gateway(&api, "gw", "the listener status", |gw| {
        listener_status(gw, "http")["conditions"].is_array()
    })
    .await;
    assert_eq!(listener_status(&gw, "http")["attachedRoutes"], 1);
}

#[tokio::test]
async fn status_ref_not_permitted() {
    let api = FakeApi::start().await;
    world(&api);
    // team-b belongs to another tenant: no ReferenceGrant can make that reference valid.
    service(&api, "team-b", "api");
    api.put(
        "referencegrants",
        json!({ "apiVersion": format!("{GROUP}/v1beta1"), "kind": "ReferenceGrant",
                "metadata": { "namespace": "team-b", "name": "from-a" },
                "spec": { "from": [{ "group": GROUP, "kind": "HTTPRoute", "namespace": "team-a" }],
                          "to": [{ "group": "", "kind": "Service" }] } }),
    );
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "shop",
            1,
            json!([parent("gw")]),
            &["shop.acme.test"],
            json!([{ "backendRefs": [{ "name": "api", "namespace": "team-b", "port": 80 }] }]),
        ),
    );
    let _replica = alone(&api, "refused", Mode::Accept);
    let route = wait_route(&api, "shop", "the refused reference", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    let conditions = &parent_status(&route, "gw")["conditions"];
    assert!(
        holds(conditions, "ResolvedRefs", "False", "RefNotPermitted"),
        "{conditions}"
    );
    assert!(
        holds(conditions, "Accepted", "True", "Accepted"),
        "{conditions}"
    );
}

#[tokio::test]
async fn status_no_matching_hostname() {
    let api = FakeApi::start().await;
    world(&api);
    api.put(
        "gateways",
        gateway(
            "team-a",
            "only-acme",
            1,
            json!([listener("http", 80, "HTTP", Some("*.acme.test"))]),
        ),
    );
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "elsewhere",
            1,
            json!([parent("only-acme"), parent("gw")]),
            &["shop.example.com"],
            to_web(),
        ),
    );
    let _replica = alone(&api, "hostname", Mode::Accept);
    let route = wait_route(&api, "elsewhere", "both parents", |route| {
        parent_status(route, "only-acme")["conditions"].is_array()
            && parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    // The listener's host name excludes the route; each parent reports its own outcome.
    let conditions = &parent_status(&route, "only-acme")["conditions"];
    assert!(
        holds(
            conditions,
            "Accepted",
            "False",
            "NoMatchingListenerHostname"
        ),
        "{conditions}"
    );
    // The open Gateway attaches the route, but its tenant may not claim that host name.
    let conditions = &parent_status(&route, "gw")["conditions"];
    assert!(
        holds(conditions, "Accepted", "False", "NotAllowedByListeners"),
        "{conditions}"
    );
}

#[tokio::test]
async fn programmed_false_when_push_rejected() {
    let api = FakeApi::start().await;
    world(&api);
    api.put(
        "secrets",
        k8s::secret("team-a", "tls", "kubernetes.io/tls", "C", "K"),
    );
    api.put(
        "gateways",
        gateway(
            "team-a",
            "secure",
            1,
            json!([{ "name": "https", "port": 443, "protocol": "HTTPS", "hostname": "secure.acme.test",
                     "tls": { "mode": "Terminate", "certificateRefs": [{ "name": "tls" }] },
                     "allowedRoutes": { "namespaces": { "from": "All" } } }]),
        ),
    );
    api.put("httproutes", shop(json!([parent("gw")])));
    let replica = alone(&api, "programmed", Mode::Hold);

    // Nothing is pushed yet: the Gateway is accepted, and says it is pending.
    let gw = wait_gateway(&api, "gw", "pending", |gw| {
        condition(&gw["status"]["conditions"], "Programmed")["reason"] == "Pending"
    })
    .await;
    assert_eq!(
        condition(&gw["status"]["conditions"], "Programmed")["status"],
        "Unknown"
    );
    assert!(holds(
        &gw["status"]["conditions"],
        "Accepted",
        "True",
        "Accepted"
    ));

    replica.engine.set(Mode::Accept);
    wait_gateway(&api, "gw", "programmed", |gw| {
        holds(
            &gw["status"]["conditions"],
            "Programmed",
            "True",
            "Programmed",
        ) && holds(
            &listener_status(gw, "http")["conditions"],
            "Programmed",
            "True",
            "Programmed",
        )
    })
    .await;
    wait_gateway(&api, "secure", "programmed", |gw| {
        holds(
            &listener_status(gw, "https")["conditions"],
            "Programmed",
            "True",
            "Programmed",
        )
    })
    .await;

    // Podgate refuses the snapshot: Programmed is false, with the daemon's reason.
    let why = "podgate refused the snapshot with 400: the snapshot is invalid";
    replica.engine.set(Mode::Refuse(why));
    let gw = wait_gateway(&api, "gw", "refused", |gw| {
        holds(
            &gw["status"]["conditions"],
            "Programmed",
            "False",
            "Invalid",
        )
    })
    .await;
    assert_eq!(
        condition(&gw["status"]["conditions"], "Programmed")["message"],
        why
    );
    let listener = listener_status(&gw, "http");
    assert!(
        holds(&listener["conditions"], "Programmed", "False", "Invalid"),
        "{listener}"
    );
    assert_eq!(
        condition(&listener["conditions"], "Programmed")["message"],
        why
    );
    // The Gateway is still accepted: this is about podgate, not the Gateway.
    assert!(holds(
        &gw["status"]["conditions"],
        "Accepted",
        "True",
        "Accepted"
    ));

    // Podgate takes the snapshot but quarantines the route and the listener's certificate.
    let reason = "upstream_forbidden: the upstream 10.0.0.1 is not allowed";
    replica.engine.set(Mode::Quarantine(
        vec![
            "kubernetes/k8s:HTTPRoute/team-a/shop",
            "kubernetes/k8s:Gateway/team-a/secure#https-0",
        ],
        reason,
    ));
    let route = wait_route(&api, "shop", "the quarantined route", |route| {
        holds(
            &parent_status(route, "gw")["conditions"],
            "Accepted",
            "False",
            "UnsupportedValue",
        )
    })
    .await;
    let message = condition(&parent_status(&route, "gw")["conditions"], "Accepted")["message"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    assert!(message.contains(reason), "{message}");
    let secure = wait_gateway(&api, "secure", "the quarantined certificate", |gw| {
        condition(&listener_status(gw, "https")["conditions"], "Programmed")["message"]
            .as_str()
            .is_some_and(|message| message.contains(reason))
    })
    .await;
    let message = condition(
        &listener_status(&secure, "https")["conditions"],
        "Programmed",
    )["message"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    assert!(
        message.contains(reason) && message.contains("certificate"),
        "{message}"
    );
    assert!(
        holds(
            &secure["status"]["conditions"],
            "Programmed",
            "False",
            "Invalid"
        ),
        "{secure}"
    );
    // The Gateway whose objects are all in is programmed again.
    wait_gateway(&api, "gw", "programmed again", |gw| {
        holds(
            &gw["status"]["conditions"],
            "Programmed",
            "True",
            "Programmed",
        )
    })
    .await;
}

#[tokio::test]
async fn listeners_in_conflict_are_refused() {
    let api = FakeApi::start().await;
    world(&api);
    api.put(
        "gateways",
        gateway(
            "team-a",
            "dup",
            1,
            json!([
                listener("one", 80, "HTTP", None),
                listener("two", 80, "HTTP", None)
            ]),
        ),
    );
    api.put(
        "gateways",
        gateway(
            "team-a",
            "mixed",
            1,
            json!([listener("plain", 443, "HTTP", Some("a.acme.test")),
                   { "name": "secure", "port": 443, "protocol": "HTTPS", "hostname": "b.acme.test",
                     "tls": { "mode": "Terminate" },
                     "allowedRoutes": { "namespaces": { "from": "All" } } }]),
        ),
    );
    api.put(
        "gateways",
        gateway(
            "team-a",
            "fine",
            1,
            json!([
                listener("a", 80, "HTTP", Some("a.acme.test")),
                listener("b", 80, "HTTP", Some("b.acme.test"))
            ]),
        ),
    );
    api.put("httproutes", shop(json!([parent("dup")])));
    let _replica = alone(&api, "conflict", Mode::Accept);

    let dup = wait_gateway(&api, "dup", "both listeners conflicted", |gw| {
        holds(
            &listener_status(gw, "one")["conditions"],
            "Conflicted",
            "True",
            "HostnameConflict",
        ) && holds(
            &listener_status(gw, "two")["conditions"],
            "Conflicted",
            "True",
            "HostnameConflict",
        )
    })
    .await;
    for name in ["one", "two"] {
        let conditions = &listener_status(&dup, name)["conditions"];
        assert!(
            holds(conditions, "Programmed", "False", "Invalid"),
            "{name}: {conditions}"
        );
        assert!(
            holds(conditions, "Accepted", "True", "Accepted"),
            "{name}: {conditions}"
        );
        assert_eq!(listener_status(&dup, name)["attachedRoutes"], 0);
    }
    assert!(
        holds(
            &dup["status"]["conditions"],
            "Accepted",
            "False",
            "ListenersNotValid"
        ),
        "{dup}"
    );
    assert!(
        holds(
            &dup["status"]["conditions"],
            "Programmed",
            "False",
            "Invalid"
        ),
        "{dup}"
    );

    // The same port with HTTP and HTTPS cannot be shared either.
    let mixed = wait_gateway(&api, "mixed", "protocol conflict", |gw| {
        holds(
            &listener_status(gw, "plain")["conditions"],
            "Conflicted",
            "True",
            "ProtocolConflict",
        ) && holds(
            &listener_status(gw, "secure")["conditions"],
            "Conflicted",
            "True",
            "ProtocolConflict",
        )
    })
    .await;
    assert!(
        holds(
            &mixed["status"]["conditions"],
            "Programmed",
            "False",
            "Invalid"
        ),
        "{mixed}"
    );

    // Different host names on one port are the normal case.
    let fine = wait_gateway(&api, "fine", "no conflict", |gw| {
        holds(
            &listener_status(gw, "b")["conditions"],
            "Programmed",
            "True",
            "Programmed",
        )
    })
    .await;
    for name in ["a", "b"] {
        assert!(
            holds(
                &listener_status(&fine, name)["conditions"],
                "Conflicted",
                "False",
                "NoConflicts"
            ),
            "{fine}"
        );
    }

    // A route that names the conflicted listeners is not attached to them.
    let route = wait_route(&api, "shop", "the route's parent", |route| {
        parent_status(route, "dup")["conditions"].is_array()
    })
    .await;
    let conditions = &parent_status(&route, "dup")["conditions"];
    assert!(
        holds(conditions, "Accepted", "False", "NotAllowedByListeners"),
        "{conditions}"
    );
    let message = condition(conditions, "Accepted")["message"]
        .as_str()
        .unwrap_or("");
    assert!(message.contains("conflict"), "{message}");
}

/// Another controller's entry for the Gateway `name`.
fn foreign(name: &str, controller: &str) -> Value {
    json!({ "parentRef": { "group": GROUP, "kind": "Gateway", "namespace": "team-a", "name": name },
            "controllerName": controller,
            "conditions": [{ "type": "Accepted", "status": "True", "reason": "Accepted",
                             "message": "theirs", "lastTransitionTime": "2026-01-01T00:00:00Z",
                             "observedGeneration": 9 }] })
}

#[tokio::test]
async fn status_leaves_other_controllers_alone() {
    let api = FakeApi::start().await;
    world(&api);
    let others = [
        foreign("gw", "example.com/other-controller"),
        foreign("elsewhere", "example.org/third-controller"),
    ];
    let mut route = shop(json!([parent("gw")]));
    route["status"] = json!({ "parents": others });
    api.put("httproutes", route);
    let _replica = alone(&api, "others", Mode::Accept);

    let route = wait_route(&api, "shop", "our entry", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    let parents = route["status"]["parents"].as_array().expect("parents");
    assert_eq!(parents.len(), 3, "{parents:?}");
    // Both other controllers' entries are what they were, even the one for the same Gateway.
    for other in &others {
        assert!(parents.contains(other), "{other} was changed: {parents:?}");
    }
    assert_eq!(
        parents
            .iter()
            .filter(|p| p["controllerName"] == CONTROLLER)
            .count(),
        1
    );
    // Later writes leave them alone too.
    update(
        &api,
        "httproutes",
        http_route(
            "team-a",
            "shop",
            2,
            json!([parent("gw")]),
            &["shop.acme.test"],
            to_web(),
        ),
    );
    let route = wait_route(&api, "shop", "generation 2", |route| {
        condition(&parent_status(route, "gw")["conditions"], "Accepted")["observedGeneration"] == 2
    })
    .await;
    let parents = route["status"]["parents"].as_array().expect("parents");
    assert!(
        others.iter().all(|other| parents.contains(other)),
        "{parents:?}"
    );
}

#[tokio::test]
async fn status_cleans_removed_parent_refs() {
    let api = FakeApi::start().await;
    world(&api);
    api.put(
        "gateways",
        gateway(
            "team-a",
            "gw2",
            1,
            json!([listener("http", 80, "HTTP", None)]),
        ),
    );
    // A stale entry of ours for a parent the route does not name, and another controller's.
    let mut route = shop(json!([parent("gw"), parent("gw2")]));
    route["status"] = json!({ "parents": [
        foreign("gone", CONTROLLER),
        foreign("gw", "example.com/other-controller"),
    ] });
    api.put("httproutes", route);
    let _replica = alone(&api, "cleanup", Mode::Accept);

    let route = wait_route(&api, "shop", "both parents written", |route| {
        parent_status(route, "gw")["conditions"].is_array()
            && parent_status(route, "gw2")["conditions"].is_array()
    })
    .await;
    assert!(
        parent_status(&route, "gone").is_null(),
        "the stale entry is gone: {}",
        route["status"]
    );
    // The route stops naming gw2: its entry goes, gw's stays, the other controller's stays.
    update(
        &api,
        "httproutes",
        http_route(
            "team-a",
            "shop",
            2,
            json!([parent("gw")]),
            &["shop.acme.test"],
            to_web(),
        ),
    );
    let route = wait_route(&api, "shop", "gw2 removed", |route| {
        parent_status(route, "gw2").is_null()
            && condition(&parent_status(route, "gw")["conditions"], "Accepted")["observedGeneration"] == 2
    })
    .await;
    let parents = route["status"]["parents"].as_array().expect("parents");
    assert_eq!(parents.len(), 2, "{parents:?}");
    assert!(parents.contains(&foreign("gw", "example.com/other-controller")));

    // The route stops naming any of our Gateways: all of our entries go.
    update(
        &api,
        "httproutes",
        http_route(
            "team-a",
            "shop",
            3,
            json!([{ "name": "theirs", "group": "other.io", "kind": "Mesh" }]),
            &["shop.acme.test"],
            to_web(),
        ),
    );
    let route = wait_route(&api, "shop", "all our entries removed", |route| {
        route["status"]["parents"]
            .as_array()
            .is_some_and(|parents| parents.iter().all(|p| p["controllerName"] != CONTROLLER))
    })
    .await;
    assert_eq!(route["status"]["parents"].as_array().map(Vec::len), Some(1));
}

fn holder(api: &FakeApi) -> Option<String> {
    api.get("leases", "podgate-system", "podgate-provider-status")
        .and_then(|lease| lease["spec"]["holderIdentity"].as_str().map(str::to_owned))
}

#[tokio::test]
async fn status_only_leader_writes() {
    let api = FakeApi::start().await;
    world(&api);
    api.put("httproutes", shop(json!([parent("gw")])));
    let dir = dir("leader");
    let _a = replica(&api, &dir, "token-a", "a", Mode::Accept, quick(), eager());
    let _b = replica(&api, &dir, "token-b", "b", Mode::Accept, quick(), eager());

    wait_route(&api, "shop", "the route's status", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    let leader = holder(&api).expect("somebody holds the lease");
    let (leader_token, follower_token) = if leader == "a" {
        ("Bearer token-a", "Bearer token-b")
    } else {
        ("Bearer token-b", "Bearer token-a")
    };
    let lease = api
        .get("leases", "podgate-system", "podgate-provider-status")
        .expect("the lease");
    assert!(
        lease["spec"]["leaseDurationSeconds"].as_i64() == Some(2),
        "{lease}"
    );
    assert!(lease["spec"]["renewTime"].is_string() && lease["spec"]["acquireTime"].is_string());

    // More objects, more writes: all of them come from the leader.
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "docs",
            1,
            json!([parent("gw")]),
            &["docs.acme.test"],
            to_web(),
        ),
    );
    wait_route(&api, "docs", "the second route's status", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    wait_gateway(&api, "gw", "attachedRoutes 2", |gw| {
        listener_status(gw, "http")["attachedRoutes"] == 2
    })
    .await;
    let writes = api.writes();
    let status_writes: Vec<_> = writes
        .iter()
        .filter(|seen| seen.is_status_write())
        .collect();
    assert!(
        status_writes.len() >= 3,
        "{} status writes",
        status_writes.len()
    );
    assert!(
        status_writes
            .iter()
            .all(|seen| seen.authorization.as_deref() == Some(leader_token)),
        "a replica that is not the leader wrote status"
    );
    assert!(
        writes
            .iter()
            .filter(|seen| seen.authorization.as_deref() == Some(follower_token))
            .all(|seen| seen.plural() == "leases"),
        "the follower wrote something besides a lease create attempt"
    );
    // The leader keeps renewing, and nobody else takes the lease over.
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(holder(&api).as_deref(), Some(leader.as_str()));
}

#[tokio::test]
async fn lease_loss_stops_writes() {
    let api = FakeApi::start().await;
    world(&api);
    api.put("httproutes", shop(json!([parent("gw")])));
    let timing = Timing {
        duration: Duration::from_secs(30),
        renew_deadline: Duration::from_secs(10),
        retry: Duration::from_millis(100),
    };
    let _replica = replica(
        &api,
        &dir("loss"),
        "token",
        "a",
        Mode::Accept,
        timing,
        eager(),
    );
    wait_route(&api, "shop", "the route's status", |route| {
        condition(&parent_status(route, "gw")["conditions"], "Accepted")["observedGeneration"] == 1
    })
    .await;
    assert_eq!(holder(&api).as_deref(), Some("a"));

    // Another replica takes the lease. Writes stop within one retry period.
    api.put(
        "leases",
        json!({ "apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
                "metadata": { "namespace": "podgate-system", "name": "podgate-provider-status" },
                "spec": { "holderIdentity": "thief", "leaseDurationSeconds": 30,
                          "renewTime": "2026-11-21T10:00:00.000000Z", "leaseTransitions": 5 } }),
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    let before = api.writes().iter().filter(|s| s.is_status_write()).count();
    update(
        &api,
        "httproutes",
        http_route(
            "team-a",
            "shop",
            2,
            json!([parent("gw")]),
            &["shop.acme.test"],
            to_web(),
        ),
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let after = api.writes().iter().filter(|s| s.is_status_write()).count();
    assert_eq!(before, after, "status was written without the lease");
    let route = api.get("httproutes", "team-a", "shop").expect("the route");
    assert_eq!(
        condition(&parent_status(&route, "gw")["conditions"], "Accepted")["observedGeneration"],
        1
    );
    assert_eq!(
        holder(&api).as_deref(),
        Some("thief"),
        "the lease is not taken from a live holder"
    );

    // The thief lets go: this replica takes the lease back and catches up.
    let mut lease = api
        .get("leases", "podgate-system", "podgate-provider-status")
        .expect("the lease");
    lease["spec"]["holderIdentity"] = json!("");
    api.put("leases", lease);
    wait_route(&api, "shop", "the status catches up", |route| {
        condition(&parent_status(route, "gw")["conditions"], "Accepted")["observedGeneration"] == 2
    })
    .await;
    assert_eq!(holder(&api).as_deref(), Some("a"));
    let lease = api
        .get("leases", "podgate-system", "podgate-provider-status")
        .expect("the lease");
    assert_eq!(lease["spec"]["leaseTransitions"], 6, "a new term: {lease}");
}

#[tokio::test]
async fn lease_expires_when_the_holder_goes_silent() {
    // A lease nobody renews is taken over after the duration, measured on the taker's clock.
    let api = FakeApi::start().await;
    world(&api);
    api.put("httproutes", shop(json!([parent("gw")])));
    api.put(
        "leases",
        json!({ "apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
                "metadata": { "namespace": "podgate-system", "name": "podgate-provider-status" },
                "spec": { "holderIdentity": "crashed", "leaseDurationSeconds": 15,
                          "renewTime": "2020-01-01T00:00:00.000000Z", "leaseTransitions": 1 } }),
    );
    let started = Instant::now();
    let _replica = alone(&api, "expiry", Mode::Accept);
    wait_route(&api, "shop", "status after the takeover", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    assert!(
        started.elapsed() >= Duration::from_millis(1400),
        "taken over before the lease ran out: {:?}",
        started.elapsed()
    );
    assert_eq!(holder(&api).as_deref(), Some("a"));
}

#[tokio::test]
async fn lease_failures_do_not_stop_serving() {
    // A cluster that refuses lease access (RBAC) must not stop the source from sending states.
    let api = FakeApi::start().await;
    world(&api);
    api.put("httproutes", shop(json!([parent("gw")])));
    let config = source_config(&api, &dir("rbac"), "token", "");
    let mut source = source(&config, "a", quick(), eager());
    let (_engine, status) = FakeEngine::new(Mode::Accept);
    source.observe(status);
    let (tx, mut updates) = mpsc::channel(64);
    let run = tokio::spawn(source.run(tx));
    let state = tokio::time::timeout(DEADLINE, async {
        loop {
            match updates.recv().await.expect("the source runs").body {
                UpdateBody::State(state) if !state.apps.is_empty() => return state,
                _ => {}
            }
        }
    })
    .await
    .expect("a state with the route");
    assert_eq!(state.apps.len(), 1);
    // The API refuses everything from now on, writes included: the source keeps its state.
    api.fail(Some(Failure::Status(403)));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!run.is_finished());
    run.abort();
}

#[tokio::test]
async fn status_patches_coalesced() {
    let api = FakeApi::start().await;
    world(&api);
    api.put("httproutes", shop(json!([parent("gw")])));
    // The default writer: at most one patch per object per second.
    let _replica = replica(
        &api,
        &dir("coalesce"),
        "token",
        "a",
        Mode::Accept,
        quick(),
        WriterTuning::default(),
    );
    wait_route(&api, "shop", "the first status", |route| {
        condition(&parent_status(route, "gw")["conditions"], "Accepted")["observedGeneration"] == 1
    })
    .await;
    wait_gateway(&api, "gw", "programmed", |gw| {
        holds(
            &gw["status"]["conditions"],
            "Programmed",
            "True",
            "Programmed",
        )
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let before = status_writes(&api, "httproutes", "shop");

    // Seven changes within a second: the route's status is patched far fewer times, and the last
    // generation wins.
    for generation in 2..=8 {
        update(
            &api,
            "httproutes",
            http_route(
                "team-a",
                "shop",
                generation,
                json!([parent("gw")]),
                &["shop.acme.test"],
                to_web(),
            ),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    wait_route(&api, "shop", "the last generation", |route| {
        condition(&parent_status(route, "gw")["conditions"], "Accepted")["observedGeneration"] == 8
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let patches = status_writes(&api, "httproutes", "shop") - before;
    assert!(
        (1..=3).contains(&patches),
        "{patches} patches for seven changes within a second"
    );
}

#[tokio::test]
async fn status_is_not_written_again_when_nothing_changed() {
    let api = FakeApi::start().await;
    world(&api);
    api.put("httproutes", shop(json!([parent("gw")])));
    let _replica = alone(&api, "steady", Mode::Accept);
    wait_route(&api, "shop", "the status", |route| {
        parent_status(route, "gw")["conditions"].is_array()
    })
    .await;
    wait_gateway(&api, "gw", "programmed", |gw| {
        holds(
            &gw["status"]["conditions"],
            "Programmed",
            "True",
            "Programmed",
        )
    })
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let before = api.writes().iter().filter(|s| s.is_status_write()).count();
    // Resyncs, bookmarks and the engine's status updates change nothing in the status.
    api.bookmark("httproutes");
    api.drop_watches();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let after = api.writes().iter().filter(|s| s.is_status_write()).count();
    assert_eq!(before, after, "an unchanged status was patched again");
}
