//! Black-box tests of the Kubernetes source against a fake API server (`common/k8s.rs`): the
//! Ingress and EndpointSlice mapping, tenancy and refusals, the generic list-and-watch client,
//! and one run through the real daemon. Never a real cluster; everything that waits has a
//! deadline.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use common::k8s::{self, Failure, FakeApi, GoneAs};
use common::{DEADLINE, config as base_config};
use podgate_provider::kubernetes::KubernetesSource;
use podgate_provider::kubernetes::client::{
    ApiClient, ClientConfig, ClientError, Event, ObjectMeta, Query, Resource, Store, Tuning,
    Watcher,
};
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::{Config, Merged, Merger, UpstreamPolicy};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]
catch_all = true

[[tenant]]
id = "globex"
hosts = ["globex.test"]
"#;

struct Dir(PathBuf);

impl Dir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pgp-k8s-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create the test directory");
        Self(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tuning() -> Tuning {
    Tuning {
        watch_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(80),
        // Small pages, so every list in these tests also exercises `continue`.
        page_size: 2,
    }
}

/// The provider configuration: the two tenants, then the Kubernetes source with `source` as its
/// extra keys.
fn config(api: &FakeApi, dir: &Dir, source: &str) -> Config {
    let kubeconfig = api.kubeconfig(&dir.0, "test-token");
    base_config(
        &dir.0.join("admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\nnamespace_tenants = {{ team-a = \"acme\", team-b = \"globex\" }}\n{source}\n",
            kubeconfig.display().to_string()
        ),
    )
}

fn source(config: &Config) -> KubernetesSource {
    KubernetesSource::from_config(&config.sources[0], config)
        .expect("a valid Kubernetes source")
        .with_tuning(tuning())
        .with_settle(Duration::from_millis(20))
}

/// A running source and what it has said so far.
struct Run {
    rx: mpsc::Receiver<Update>,
    task: JoinHandle<()>,
    state: Option<State>,
    outage: Option<String>,
    /// Every outage text seen, in order.
    outages: Vec<String>,
    /// How many states arrived.
    states: usize,
}

impl Run {
    fn start(config: &Config) -> Self {
        let (tx, rx) = mpsc::channel(64);
        Self {
            rx,
            task: tokio::spawn(source(config).run(tx)),
            state: None,
            outage: None,
            outages: Vec::new(),
            states: 0,
        }
    }

    async fn until(&mut self, what: &str, done: impl Fn(Option<&State>, Option<&str>) -> bool) {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                assert_eq!(&*update.source, "k8s");
                match update.body {
                    UpdateBody::State(state) => {
                        self.state = Some(state);
                        self.outage = None;
                        self.states += 1;
                    }
                    UpdateBody::Outage(why) => {
                        self.outages.push(why.to_string());
                        self.outage = Some(why.to_string());
                    }
                }
            }
        };
        if tokio::time::timeout(DEADLINE, wait).await.is_err() {
            panic!(
                "timed out waiting for: {what}; ids: {:?}; outage: {:?}",
                self.state.as_ref().map(ids),
                self.outage
            );
        }
    }

    async fn wait(&mut self, what: &str, condition: impl Fn(&State) -> bool) -> State {
        self.until(what, |state, _| state.is_some_and(&condition))
            .await;
        self.state.clone().expect("a state")
    }

    async fn wait_ids(&mut self, expected: &[&str]) -> State {
        let expected: Vec<String> = expected.iter().map(|id| (*id).to_owned()).collect();
        self.wait(&format!("apps {expected:?}"), |state| {
            ids(state) == expected
        })
        .await
    }

    /// Waits for an outage that names `needle`, whatever the state is.
    async fn wait_outage(&mut self, needle: &str) -> String {
        self.until(&format!("an outage naming {needle}"), |_, outage| {
            outage.is_some_and(|why| why.contains(needle))
        })
        .await;
        self.outage.clone().expect("an outage")
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn ids(state: &State) -> Vec<String> {
    let mut ids: Vec<String> = state
        .apps
        .iter()
        .map(|app| app.app.id.to_string())
        .collect();
    ids.sort();
    ids
}

fn app<'a>(state: &'a State, id: &str) -> &'a podgate_provider::SourceApp {
    state
        .apps
        .iter()
        .find(|app| &*app.app.id == id)
        .unwrap_or_else(|| panic!("no app {id}: {:?}", ids(state)))
}

/// The routers as JSON, without the fields that are absent (the model serializes them as null).
fn routers(state: &State, id: &str) -> Value {
    fn strip(value: Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .filter(|(_, value)| !value.is_null())
                    .map(|(key, value)| (key, strip(value)))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(items.into_iter().map(strip).collect()),
            other => other,
        }
    }
    strip(serde_json::to_value(&app(state, id).app.routers).expect("routers serialize"))
}

fn services(state: &State, id: &str) -> Value {
    serde_json::to_value(&app(state, id).app.services).expect("services serialize")
}

/// The sorted server URLs of the service `service` of app `id`.
fn servers(state: &State, id: &str, service: &str) -> Vec<String> {
    let all = services(state, id);
    let service = all
        .as_array()
        .and_then(|all| all.iter().find(|candidate| candidate["name"] == service))
        .unwrap_or_else(|| panic!("no service {service}: {all}"));
    let mut urls: Vec<String> = service["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .map(|server| server["url"].as_str().expect("a url").to_owned())
        .collect();
    urls.sort();
    urls
}

/// A Service `name` in `namespace` that listens on `port` and whose pods listen on `container`,
/// with the given endpoints `(address, ready, terminating)`.
fn backend(
    api: &FakeApi,
    namespace: &str,
    name: &str,
    port: u16,
    container: u16,
    endpoints: &[(&str, bool, bool)],
) {
    api.put("services", k8s::service(namespace, name, &[(None, port)]));
    api.put(
        "endpointslices",
        k8s::slice(namespace, name, 0, &[(None, container)], endpoints),
    );
}

fn shop(host: &str) -> Value {
    k8s::ingress(
        "team-a",
        "shop",
        "podgate",
        json!([k8s::rule(
            Some(host),
            &[
                ("/api", "Prefix", "web", json!(80)),
                ("/exact", "Exact", "web", json!(80)),
            ]
        )]),
    )
}

fn merge(config: &Config, policy: UpstreamPolicy, state: State) -> Merged {
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("k8s".into(), state)]);
    Merger::new(config, policy).merge(&states, &BTreeSet::new())
}

fn finding_codes(merged: &Merged) -> Vec<(&'static str, String)> {
    merged
        .findings()
        .iter()
        .map(|finding| (finding.code, finding.object.to_string()))
        .collect()
}

// ---- the mapping -----------------------------------------------------------------------------

#[tokio::test]
async fn ingress_host_path_to_routers() {
    let api = FakeApi::start().await;
    let dir = Dir::new("routers");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.2", true, false), ("10.0.0.1", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.shop"]).await;

    let shop = app(&state, "team-a.shop");
    assert_eq!(&*shop.origin.object, "team-a/shop");
    assert_eq!(&*shop.origin.source, "k8s");
    assert_eq!(
        shop.origin.first_seen, 1_795_176_000,
        "the creation timestamp, in unix seconds"
    );
    assert_eq!(shop.tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(shop.tenant.label, None);
    assert_eq!(
        routers(&state, "team-a.shop"),
        json!([
            { "name": "r0p0", "match": { "all": [{ "host": "shop.acme.test" }, { "path_prefix": "/api" }] },
              "service": "web.80", "chain": [] },
            { "name": "r0p1", "match": { "all": [{ "host": "shop.acme.test" }, { "path": "/exact" }] },
              "service": "web.80", "chain": [] },
        ])
    );
    assert_eq!(
        services(&state, "team-a.shop"),
        json!([{ "name": "web.80", "type": "loadbalancer",
                 "servers": [{ "url": "http://10.0.0.1:8080" }, { "url": "http://10.0.0.2:8080" }] }])
    );
    let revisions = serde_json::to_value(&shop.app.revisions).expect("revisions");
    assert_eq!(
        revisions,
        json!([{ "id": "k8s", "state": "serving", "weight": 1, "services": [] }])
    );
    assert!(run.outage.is_none(), "{:?}", run.outage);
}

#[tokio::test]
async fn endpointslice_ready_only() {
    let api = FakeApi::start().await;
    let dir = Dir::new("ready");
    api.put("services", k8s::service("team-a", "web", &[(None, 80)]));
    let mut slice = k8s::slice(
        "team-a",
        "web",
        0,
        &[(None, 8080)],
        &[
            ("10.0.0.1", true, false),
            ("10.0.0.2", false, false),
            ("10.0.0.3", false, true),
            ("10.0.0.4", true, true),
        ],
    );
    // An endpoint with no conditions at all is ready: the API says to read nil as true.
    slice["endpoints"]
        .as_array_mut()
        .expect("endpoints")
        .push(json!({ "addresses": ["10.0.0.5"] }));
    api.put("endpointslices", slice);
    // A second slice of the same Service adds its endpoints; an IPv6 one is bracketed.
    let mut second = k8s::slice(
        "team-a",
        "web",
        1,
        &[(None, 8080)],
        &[("fd00::7", true, false)],
    );
    second["addressType"] = json!("IPv6");
    api.put("endpointslices", second);
    // A slice of another Service never leaks in.
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "other",
            0,
            &[(None, 8080)],
            &[("10.9.9.9", true, false)],
        ),
    );
    api.put("ingresses", shop("shop.acme.test"));
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.shop"]).await;
    assert_eq!(
        servers(&state, "team-a.shop", "web.80"),
        [
            "http://10.0.0.1:8080",
            "http://10.0.0.5:8080",
            "http://[fd00::7]:8080"
        ]
    );
}

#[tokio::test]
async fn named_port_resolution() {
    let api = FakeApi::start().await;
    let dir = Dir::new("ports");
    api.put(
        "services",
        k8s::service(
            "team-a",
            "web",
            &[(Some("http"), 80), (Some("metrics"), 9090)],
        ),
    );
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(Some("http"), 8080), (Some("metrics"), 9091)],
            &[("10.0.0.1", true, false)],
        ),
    );
    // During a rollout the new pods listen on another container port: slices carry their own.
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            1,
            &[(Some("http"), 8081), (Some("metrics"), 9091)],
            &[("10.0.0.2", true, false)],
        ),
    );
    api.put(
        "ingresses",
        k8s::ingress(
            "team-a",
            "ports",
            "podgate",
            json!([k8s::rule(
                Some("p.acme.test"),
                &[
                    ("/named", "Prefix", "web", json!("http")),
                    ("/number", "Prefix", "web", json!(9090)),
                ]
            )]),
        ),
    );
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.ports"]).await;
    assert_eq!(
        servers(&state, "team-a.ports", "web.http"),
        ["http://10.0.0.1:8080", "http://10.0.0.2:8081"],
        "a named port resolves through each slice's own port"
    );
    assert_eq!(
        servers(&state, "team-a.ports", "web.9090"),
        ["http://10.0.0.1:9091", "http://10.0.0.2:9091"],
        "a port number is the Service's port, resolved to the slice's port of the same name"
    );

    // A port the Service does not have rejects the Ingress.
    api.put(
        "ingresses",
        k8s::ingress(
            "team-a",
            "noport",
            "podgate",
            json!([k8s::rule(
                Some("n.acme.test"),
                &[("/", "Prefix", "web", json!("grpc"))]
            )]),
        ),
    );
    let why = run.wait_outage("team-a/noport").await;
    assert!(why.contains("has no port grpc"), "{why}");
}

#[tokio::test]
async fn ingress_prefix_semantics_match_k8s() {
    // The mapping is `Prefix` to `path_prefix` and `Exact` to `path`; whether podgate's leaf
    // then matches as Kubernetes does is proved against the real daemon.
    let api = FakeApi::start().await;
    let dir = Dir::new("prefix");
    let ports = common::free_ports(2);
    let policy = dir.0.join("policy.json");
    fs::write(&policy, common::daemon::LOOPBACK_POLICY).expect("policy");
    let daemon = common::daemon::Daemon::start(&policy, (ports[0], ports[1]), &[]).await;
    let (upstream, _task) = common::daemon::backend("from-the-backend").await;
    backend(
        &api,
        "team-a",
        "web",
        80,
        upstream.port(),
        &[("127.0.0.1", true, false)],
    );
    api.put(
        "ingresses",
        k8s::ingress(
            "team-a",
            "shop",
            "podgate",
            json!([k8s::rule(
                Some("shop.acme.test"),
                &[
                    ("/foo", "Prefix", "web", json!(80)),
                    ("/bar/", "Prefix", "web", json!(80)),
                    ("/exact", "Exact", "web", json!(80)),
                ]
            )]),
        ),
    );
    let extra = format!(
        "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 2\nupstream_policy_file = {:?}\n",
        policy.display().to_string()
    );
    let kubeconfig = api.kubeconfig(&dir.0, "test-token");
    let config = base_config(
        &daemon.admin,
        &format!(
            "{extra}{TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\nnamespace_tenants = {{ team-a = \"acme\" }}\n",
            kubeconfig.display().to_string()
        ),
    );
    let mut engine = podgate_provider::Engine::new(
        config.clone(),
        UpstreamPolicy::load(&policy).expect("policy"),
    )
    .with_tuning(common::fast_tuning());
    engine.add_source(source(&config)).expect("source");
    let status_rx = engine.status();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(async move {
        let _ = engine
            .run(async {
                let _ = stopped.await;
            })
            .await;
    });

    // The route goes live when the first prefix answers.
    let started = std::time::Instant::now();
    while get(daemon.proxy, "shop.acme.test", "/foo").await.0 != 200 {
        assert!(
            started.elapsed() < DEADLINE,
            "the route never went live; provider status: {:?}",
            *status_rx.borrow()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let host = "shop.acme.test";
    let status = |path: &'static str| async move { get(daemon.proxy, host, path).await.0 };
    assert_eq!(status("/foo/bar").await, 200, "/foo matches /foo/bar");
    assert_eq!(status("/foo/").await, 200, "/foo matches /foo/");
    assert_eq!(status("/foobar").await, 404, "/foo does not match /foobar");
    assert_eq!(status("/f").await, 404);
    assert_eq!(
        status("/bar").await,
        200,
        "a trailing slash on the prefix is ignored"
    );
    assert_eq!(status("/bar/x").await, 200);
    assert_eq!(status("/barx").await, 404);
    assert_eq!(status("/exact").await, 200);
    assert_eq!(
        status("/exact/more").await,
        404,
        "Exact matches the path and nothing under it"
    );
    assert_eq!(status("/other").await, 404);
    let (code, body) = get(daemon.proxy, host, "/foo/bar").await;
    assert_eq!((code, body.as_str()), (200, "from-the-backend"));
    let _ = stop.send(());
    let _ = tokio::time::timeout(DEADLINE, run).await;
}

/// A plain `GET path` with `Host: host`.
async fn get(addr: SocketAddr, host: &str, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("proxy");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("write");
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw)).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

#[tokio::test]
async fn ingress_tls_secret_to_certificate() {
    let api = FakeApi::start().await;
    let dir = Dir::new("tls");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    let cert = rcgen::generate_simple_self_signed(vec!["shop.acme.test".to_owned()])
        .expect("a certificate");
    let (cert_pem, key_pem) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    api.put(
        "secrets",
        k8s::secret(
            "team-a",
            "shop-tls",
            "kubernetes.io/tls",
            &cert_pem,
            &key_pem,
        ),
    );
    let mut ingress = shop("shop.acme.test");
    ingress["spec"]["tls"] = json!([{ "hosts": ["shop.acme.test"], "secretName": "shop-tls" }]);
    api.put("ingresses", ingress);
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.shop"]).await;
    assert_eq!(state.certificates.len(), 1);
    let certificate = &state.certificates[0];
    assert_eq!(&*certificate.origin.object, "team-a/shop#tls-0");
    assert_eq!(certificate.tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(certificate.certificate.hosts, ["shop.acme.test".into()]);
    assert_eq!(certificate.certificate.cert_pem, cert_pem);
    assert_eq!(certificate.certificate.key_pem, key_pem);
    // Only TLS Secrets are ever asked for; no other Secret reaches the provider.
    for seen in api
        .requests()
        .iter()
        .filter(|seen| seen.plural() == "secrets")
    {
        assert_eq!(
            seen.query.get("fieldSelector").map(String::as_str),
            Some("type=kubernetes.io/tls"),
            "{seen:?}"
        );
    }
    // The key never shows in the source's own diagnostics.
    assert!(!format!("{certificate:?}").contains(key_pem.lines().nth(1).unwrap_or("-")));

    // Replacing the Secret (a renewal) reaches the next state.
    let renewed = rcgen::generate_simple_self_signed(vec!["shop.acme.test".to_owned()])
        .expect("a certificate");
    api.put(
        "secrets",
        k8s::secret(
            "team-a",
            "shop-tls",
            "kubernetes.io/tls",
            &renewed.cert.pem(),
            &renewed.signing_key.serialize_pem(),
        ),
    );
    let pem = renewed.cert.pem();
    run.wait("the renewed certificate", |state| {
        state
            .certificates
            .first()
            .is_some_and(|c| c.certificate.cert_pem == pem)
    })
    .await;
}

#[tokio::test]
async fn ingress_tls_secret_missing_rejected() {
    let api = FakeApi::start().await;
    let dir = Dir::new("tlsmissing");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put("ingresses", shop("good.acme.test"));
    let mut missing = k8s::ingress(
        "team-a",
        "missing",
        "podgate",
        json!([k8s::rule(
            Some("m.acme.test"),
            &[("/", "Prefix", "web", json!(80))]
        )]),
    );
    missing["spec"]["tls"] = json!([{ "hosts": ["m.acme.test"], "secretName": "nope" }]);
    api.put("ingresses", missing);
    // A Secret of another type is not a certificate: it is not even listed, so it is as
    // missing as one that does not exist.
    api.put(
        "secrets",
        k8s::secret("team-a", "opaque", "Opaque", "x", "y"),
    );
    let mut wrong = k8s::ingress(
        "team-a",
        "wrongtype",
        "podgate",
        json!([k8s::rule(
            Some("w.acme.test"),
            &[("/", "Prefix", "web", json!(80))]
        )]),
    );
    wrong["spec"]["tls"] = json!([{ "hosts": ["w.acme.test"], "secretName": "opaque" }]);
    api.put("ingresses", wrong);
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.shop"]).await;
    let why = run.wait_outage("team-a/wrongtype").await;
    assert!(why.contains("Ingress team-a/missing rejected"), "{why}");
    assert!(
        why.contains("no Secret team-a/nope of type kubernetes.io/tls"),
        "{why}"
    );
    assert!(why.contains("Ingress team-a/wrongtype rejected"), "{why}");
    assert!(
        !why.contains("team-a/shop"),
        "the good Ingress is not named: {why}"
    );
    assert!(state.certificates.is_empty());
}

#[tokio::test]
async fn ingress_class_filter() {
    let api = FakeApi::start().await;
    let dir = Dir::new("class");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    let make = |name: &str, class: Option<&str>, annotation: Option<&str>| {
        let mut ingress = k8s::ingress(
            "team-a",
            name,
            "ignored",
            json!([k8s::rule(
                Some(&format!("{name}.acme.test")),
                &[("/", "Prefix", "web", json!(80))]
            )]),
        );
        match class {
            Some(class) => ingress["spec"]["ingressClassName"] = json!(class),
            None => {
                ingress["spec"]
                    .as_object_mut()
                    .expect("spec")
                    .remove("ingressClassName");
            }
        }
        if let Some(annotation) = annotation {
            ingress["metadata"]["annotations"] =
                json!({ "kubernetes.io/ingress.class": annotation });
        }
        ingress
    };
    api.put("ingresses", make("ours", Some("podgate"), None));
    api.put("ingresses", make("legacy", None, Some("podgate")));
    api.put("ingresses", make("theirs", Some("nginx"), None));
    api.put("ingresses", make("none", None, None));
    // The spec field wins over the annotation.
    api.put("ingresses", make("both", Some("nginx"), Some("podgate")));
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.legacy", "team-a.ours"]).await;
    assert!(
        run.outage.is_none(),
        "another class is not a rejection: {:?}",
        run.outage
    );
    assert_eq!(ids(&state).len(), 2);

    // A custom class is configurable.
    let other = config(&api, &dir, "ingress_class = \"nginx\"");
    let mut run = Run::start(&other);
    run.wait_ids(&["team-a.both", "team-a.theirs"]).await;
}

#[tokio::test]
async fn ingress_default_backend() {
    let api = FakeApi::start().await;
    let dir = Dir::new("default");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    let mut ingress = shop("shop.acme.test");
    ingress["spec"]["defaultBackend"] =
        json!({ "service": { "name": "web", "port": { "number": 80 } } });
    api.put("ingresses", ingress);
    // acme has catch_all = true in the configuration.
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.shop"]).await;
    let routers = routers(&state, "team-a.shop");
    let routers = routers.as_array().expect("routers");
    assert_eq!(routers.len(), 3);
    let default = routers
        .iter()
        .find(|r| r["name"] == "default")
        .expect("a default router");
    assert_eq!(default["match"], json!({ "path_prefix": "/" }), "host-less");
    assert_eq!(default["priority"], json!(i32::MIN), "the lowest priority");
    assert!(
        routers
            .iter()
            .filter(|r| r["name"] != "default")
            .all(|r| r.get("priority").is_none())
    );
    assert!(run.outage.is_none(), "{:?}", run.outage);
    let merged = merge(&config(&api, &dir, ""), UpstreamPolicy::builtin(), state);
    assert!(
        finding_codes(&merged)
            .iter()
            .all(|(code, _)| *code != "catch_all_not_allowed"),
        "{:?}",
        finding_codes(&merged)
    );
}

#[tokio::test]
async fn ingress_default_backend_needs_catch_all_allowance() {
    let api = FakeApi::start().await;
    let dir = Dir::new("defaultdenied");
    backend(
        &api,
        "team-b",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    // team-b is globex, which may not have catch-all routers.
    let mut ingress = k8s::ingress(
        "team-b",
        "site",
        "podgate",
        json!([k8s::rule(
            Some("globex.test"),
            &[("/", "Prefix", "web", json!(80))]
        )]),
    );
    ingress["spec"]["defaultBackend"] =
        json!({ "service": { "name": "web", "port": { "number": 80 } } });
    api.put("ingresses", ingress);
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-b.site"]).await;
    let names: Vec<Value> = routers(&state, "team-b.site")
        .as_array()
        .expect("routers")
        .iter()
        .map(|router| router["name"].clone())
        .collect();
    assert_eq!(
        names,
        [json!("r0p0")],
        "the host rule stays, the default backend is left out"
    );
    let why = run.wait_outage("catch_all_not_allowed").await;
    assert!(
        why.contains("Ingress team-b/site") && why.contains("router default"),
        "{why}"
    );
}

#[tokio::test]
async fn ingress_hostless_rule_needs_catch_all_allowance() {
    let api = FakeApi::start().await;
    let dir = Dir::new("hostless");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    backend(
        &api,
        "team-b",
        "web",
        80,
        8080,
        &[("10.0.0.2", true, false)],
    );
    let hostless = |namespace: &str, name: &str| {
        k8s::ingress(
            namespace,
            name,
            "podgate",
            json!([k8s::rule(None, &[("/shared", "Prefix", "web", json!(80))])]),
        )
    };
    api.put("ingresses", hostless("team-a", "open"));
    api.put("ingresses", hostless("team-b", "denied"));
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.open"]).await;
    assert_eq!(
        routers(&state, "team-a.open")[0]["match"],
        json!({ "path_prefix": "/shared" }),
        "the allowed tenant gets its host-less router"
    );
    let why = run.wait_outage("Ingress team-b/denied rejected").await;
    assert!(why.contains("catch_all_not_allowed"), "{why}");
}

#[tokio::test]
async fn ingress_backend_in_other_namespace_rejected() {
    let api = FakeApi::start().await;
    let dir = Dir::new("crossns");
    // `web` exists in team-b only.
    backend(
        &api,
        "team-b",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    for (name, service) in [("dotted", "web.team-b"), ("slashed", "team-b/web")] {
        api.put(
            "ingresses",
            k8s::ingress(
                "team-a",
                name,
                "podgate",
                json!([k8s::rule(
                    Some(&format!("{name}.acme.test")),
                    &[("/", "Prefix", service, json!(80))]
                )]),
            ),
        );
    }
    let mut run = Run::start(&config(&api, &dir, ""));
    run.wait_outage("team-a/shop").await;
    let why = run.wait_outage("team-a/slashed").await;
    assert!(
        why.contains("Service team-a/web does not exist"),
        "no fall-through to another namespace: {why}"
    );
    assert!(why.contains("Ingress team-a/dotted rejected"), "{why}");
    assert!(why.contains("never another namespace"), "{why}");
    assert!(
        run.state
            .as_ref()
            .is_some_and(|state| ids(state).is_empty()),
        "nothing is served"
    );
}

#[tokio::test]
async fn externalname_service_rejected() {
    let api = FakeApi::start().await;
    let dir = Dir::new("external");
    api.put(
        "services",
        json!({ "metadata": { "namespace": "team-a", "name": "db" },
                "spec": { "type": "ExternalName", "externalName": "db.example.com", "ports": [{ "port": 5432 }] } }),
    );
    // A Service without a selector and no slices is no better.
    api.put("services", k8s::service("team-a", "empty", &[(None, 80)]));
    let route = |name: &str, service: &str, port: u16| {
        k8s::ingress(
            "team-a",
            name,
            "podgate",
            json!([k8s::rule(
                Some(&format!("{name}.acme.test")),
                &[("/", "Prefix", service, json!(port))]
            )]),
        )
    };
    api.put("ingresses", route("ext", "db", 5432));
    api.put("ingresses", route("bare", "empty", 80));
    let mut run = Run::start(&config(&api, &dir, ""));
    let why = run.wait_outage("team-a/ext").await;
    assert!(
        why.contains("ExternalName") && why.contains("allow_external_name"),
        "{why}"
    );
    assert!(
        why.contains("Ingress team-a/bare rejected") && why.contains("no EndpointSlices"),
        "{why}"
    );
    assert!(
        run.state
            .as_ref()
            .is_some_and(|state| ids(state).is_empty())
    );

    // With the operator's consent the ExternalName becomes a server by its DNS name.
    let allowed = config(&api, &dir, "allow_external_name = true");
    let mut run = Run::start(&allowed);
    let state = run.wait_ids(&["team-a.bare", "team-a.ext"]).await;
    assert_eq!(
        servers(&state, "team-a.ext", "db.5432"),
        ["http://db.example.com:5432"]
    );
    assert!(
        servers(&state, "team-a.bare", "empty.80").is_empty(),
        "no addresses, not an error"
    );
}

#[tokio::test]
async fn hand_written_slices_are_ignored_by_default() {
    let api = FakeApi::start().await;
    let dir = Dir::new("manual");
    api.put("services", k8s::service("team-a", "web", &[(None, 80)]));
    // Anyone who may write EndpointSlices can fill one with any address.
    let mut manual = k8s::slice(
        "team-a",
        "web",
        0,
        &[(None, 8080)],
        &[("10.1.2.3", true, false)],
    );
    manual["metadata"]["labels"] = json!({ k8s::SERVICE_LABEL: "web" });
    api.put("endpointslices", manual);
    api.put("ingresses", shop("shop.acme.test"));
    let mut run = Run::start(&config(&api, &dir, ""));
    let why = run.wait_outage("team-a/shop").await;
    assert!(
        why.contains("no EndpointSlices written by the Kubernetes controller"),
        "{why}"
    );
    let mut run = Run::start(&config(&api, &dir, "allow_external_name = true"));
    let state = run.wait_ids(&["team-a.shop"]).await;
    assert_eq!(
        servers(&state, "team-a.shop", "web.80"),
        ["http://10.1.2.3:8080"]
    );
}

// ---- tenancy ---------------------------------------------------------------------------------

#[tokio::test]
async fn tenant_from_namespace() {
    let api = FakeApi::start().await;
    let dir = Dir::new("tenants");
    for namespace in ["team-a", "team-b", "team-c"] {
        backend(
            &api,
            namespace,
            "web",
            80,
            8080,
            &[("10.0.0.1", true, false)],
        );
    }
    let make = |namespace: &str, host: &str| {
        k8s::ingress(
            namespace,
            "site",
            "podgate",
            json!([k8s::rule(Some(host), &[("/", "Prefix", "web", json!(80))])]),
        )
    };
    api.put("ingresses", make("team-a", "a.acme.test"));
    api.put("ingresses", make("team-b", "globex.test"));
    api.put("ingresses", make("team-c", "c.acme.test"));
    // team-c is not mapped: it takes the configured default tenant.
    let mut run = Run::start(&config(&api, &dir, "default_tenant = \"acme\""));
    let state = run
        .wait_ids(&["team-a.site", "team-b.site", "team-c.site"])
        .await;
    let mapped = |id: &str| app(&state, id).tenant.mapped.as_deref().map(str::to_owned);
    assert_eq!(mapped("team-a.site").as_deref(), Some("acme"));
    assert_eq!(mapped("team-b.site").as_deref(), Some("globex"));
    assert_eq!(mapped("team-c.site").as_deref(), Some("acme"));

    // Without a default tenant an unmapped namespace claims nothing: the core's default tenant.
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.site", "team-b.site"]).await;
    assert!(app(&state, "team-a.site").tenant.mapped.is_some());
    let why = run.wait_outage("team-c/site").await;
    assert!(
        why.contains("foreign_host_claim"),
        "the default tenant may not take acme's hosts: {why}"
    );
}

#[tokio::test]
async fn annotation_tenant_requires_trust() {
    let api = FakeApi::start().await;
    let dir = Dir::new("annotation");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    let mut ingress = k8s::ingress(
        "team-a",
        "site",
        "podgate",
        json!([k8s::rule(
            Some("shop.acme.test"),
            &[("/", "Prefix", "web", json!(80))]
        )]),
    );
    ingress["metadata"]["annotations"] = json!({ "podgate.io/tenant": "globex" });
    api.put("ingresses", ingress);

    // globex does not trust this source: the label is ignored and the namespace's tenant stays.
    let untrusted = config(&api, &dir, "");
    let mut run = Run::start(&untrusted);
    let state = run.wait_ids(&["team-a.site"]).await;
    assert_eq!(
        app(&state, "team-a.site").tenant.label.as_deref(),
        Some("globex"),
        "the claim is passed on"
    );
    let merged = merge(&untrusted, UpstreamPolicy::builtin(), state);
    assert!(
        finding_codes(&merged)
            .iter()
            .any(|(code, _)| *code == "label_ignored"),
        "{:?}",
        finding_codes(&merged)
    );
    assert_eq!(merged.snapshot().apps[0].tenant.as_ref(), "acme");

    // A host of globex under the same untrusted label gains nothing: the label is ignored, and
    // the host is outside acme's claims.
    let mut spoof = k8s::ingress(
        "team-a",
        "spoof",
        "podgate",
        json!([k8s::rule(
            Some("globex.test"),
            &[("/", "Prefix", "web", json!(80))]
        )]),
    );
    spoof["metadata"]["annotations"] = json!({ "podgate.io/tenant": "globex" });
    api.put("ingresses", spoof);
    let why = run.wait_outage("team-a/spoof").await;
    assert!(why.contains("foreign_host_claim"), "{why}");

    // Once globex lists the source, a label naming globex makes the Ingress globex's: the host of
    // globex is accepted, and acme's host under the same label is now the foreign one.
    let trusted_text = format!(
        "{TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\nnamespace_tenants = {{ team-a = \"acme\" }}\n",
        api.kubeconfig(&dir.0, "test-token").display().to_string()
    )
    .replace("id = \"globex\"", "id = \"globex\"\nlabel_sources = [\"k8s\"]");
    let trusted_config = base_config(&dir.0.join("admin.sock"), &trusted_text);
    let mut run = Run::start(&trusted_config);
    let state = run.wait_ids(&["team-a.spoof"]).await;
    let why = run.wait_outage("team-a/site").await;
    assert!(
        why.contains("foreign_host_claim") && why.contains("tenant globex"),
        "{why}"
    );
    let merged = merge(&trusted_config, UpstreamPolicy::builtin(), state);
    let tenant_of = |id: &str| {
        merged
            .snapshot()
            .apps
            .iter()
            .find(|app| app.id.ends_with(id))
            .map(|app| app.tenant.to_string())
    };
    assert_eq!(tenant_of("spoof").as_deref(), Some("globex"));
}

#[tokio::test]
async fn ingress_host_outside_tenant_claims_rejected() {
    let api = FakeApi::start().await;
    let dir = Dir::new("outside");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    api.put("ingresses", {
        let mut stolen = shop("globex.test");
        stolen["metadata"]["name"] = json!("stolen");
        stolen
    });
    api.put("ingresses", {
        let mut elsewhere = shop("anything.example");
        elsewhere["metadata"]["name"] = json!("elsewhere");
        elsewhere
    });
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.shop"]).await;
    let why = run.wait_outage("team-a/stolen").await;
    assert!(
        why.contains("Ingress team-a/stolen rejected") && why.contains("foreign_host_claim"),
        "{why}"
    );
    assert!(why.contains("Ingress team-a/elsewhere rejected"), "{why}");
    assert_eq!(
        ids(&state),
        ["team-a.shop"],
        "only the offending Ingresses are refused"
    );
}

#[tokio::test]
async fn upstream_outside_allowlist_rejected_k8s() {
    let api = FakeApi::start().await;
    let dir = Dir::new("policy");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    let mut metadata = k8s::ingress(
        "team-a",
        "meta",
        "podgate",
        json!([k8s::rule(
            Some("meta.acme.test"),
            &[("/", "Prefix", "evil", json!(80))]
        )]),
    );
    metadata["metadata"]["name"] = json!("meta");
    backend(
        &api,
        "team-a",
        "evil",
        80,
        80,
        &[("169.254.169.254", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    api.put("ingresses", metadata);
    let config = config(&api, &dir, "");
    let mut run = Run::start(&config);
    let state = run.wait_ids(&["team-a.meta", "team-a.shop"]).await;
    // The source sends every address it finds; the policy is the merge's.
    assert_eq!(
        servers(&state, "team-a.meta", "evil.80"),
        ["http://169.254.169.254:80"]
    );
    let merged = merge(&config, UpstreamPolicy::builtin(), state.clone());
    assert_eq!(
        finding_codes(&merged),
        [("upstream_forbidden", "team-a/meta".to_owned())],
        "the cloud metadata address is refused and only its Ingress is dropped"
    );
    assert_eq!(
        merged
            .snapshot()
            .apps
            .iter()
            .map(|app| app.id.to_string())
            .collect::<Vec<_>>(),
        ["k8s-team-a.shop"]
    );
    // An allow list narrows what the pod range may be.
    let allow =
        UpstreamPolicy::parse(r#"{"default": {"allow": ["192.168.0.0/16"]}}"#).expect("policy");
    let merged = merge(&config, allow, state);
    assert!(
        merged.snapshot().apps.is_empty(),
        "10.0.0.1 is outside the allow list"
    );
}

// ---- the watch -------------------------------------------------------------------------------

#[tokio::test]
async fn endpoints_follow_watch_events() {
    let api = FakeApi::start().await;
    let dir = Dir::new("follow");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.shop"]).await;
    assert_eq!(
        servers(&state, "team-a.shop", "web.80"),
        ["http://10.0.0.1:8080"]
    );
    let states = run.states;

    // Scale up.
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(None, 8080)],
            &[
                ("10.0.0.1", true, false),
                ("10.0.0.2", true, false),
                ("10.0.0.3", false, false),
            ],
        ),
    );
    let state = run
        .wait("the scaled-up servers", |state| {
            servers(state, "team-a.shop", "web.80").len() == 2
        })
        .await;
    assert_eq!(
        servers(&state, "team-a.shop", "web.80"),
        ["http://10.0.0.1:8080", "http://10.0.0.2:8080"]
    );

    // Readiness: the third pod passes its probe.
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(None, 8080)],
            &[
                ("10.0.0.1", true, false),
                ("10.0.0.2", true, false),
                ("10.0.0.3", true, false),
            ],
        ),
    );
    run.wait("three ready servers", |state| {
        servers(state, "team-a.shop", "web.80").len() == 3
    })
    .await;

    // A change to the Ingress itself (a new path) arrives too, and a deletion removes the app.
    let mut changed = shop("shop.acme.test");
    changed["spec"]["rules"][0]["http"]["paths"]
        .as_array_mut()
        .expect("paths")
        .pop();
    api.put("ingresses", changed);
    run.wait("one router", |state| {
        routers(state, "team-a.shop")
            .as_array()
            .is_some_and(|r| r.len() == 1)
    })
    .await;
    api.remove("ingresses", "team-a", "shop");
    run.wait_ids(&[]).await;
    assert!(run.states > states + 2);
    assert!(run.outage.is_none(), "{:?}", run.outage);
}

#[tokio::test]
async fn terminating_endpoint_drops_out() {
    let api = FakeApi::start().await;
    let dir = Dir::new("terminating");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false), ("10.0.0.2", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    let mut run = Run::start(&config(&api, &dir, ""));
    run.wait("two servers", |state| {
        state
            .apps
            .first()
            .is_some_and(|_| servers(state, "team-a.shop", "web.80").len() == 2)
    })
    .await;
    // The pod starts shutting down: ready flips to false and terminating to true.
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(None, 8080)],
            &[("10.0.0.1", true, false), ("10.0.0.2", false, true)],
        ),
    );
    let state = run
        .wait("the terminating pod gone", |state| {
            servers(state, "team-a.shop", "web.80").len() == 1
        })
        .await;
    assert_eq!(
        servers(&state, "team-a.shop", "web.80"),
        ["http://10.0.0.1:8080"]
    );
    // Even an endpoint that still says ready is out the moment it says terminating.
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(None, 8080)],
            &[("10.0.0.1", true, true)],
        ),
    );
    run.wait("no servers", |state| {
        servers(state, "team-a.shop", "web.80").is_empty()
    })
    .await;
}

#[tokio::test]
async fn watch_reconnects_after_410() {
    for how in [GoneAs::Frame, GoneAs::Status] {
        let api = FakeApi::start().await;
        let dir = Dir::new(&format!("gone-{how:?}"));
        api.gone_as(how);
        backend(
            &api,
            "team-a",
            "web",
            80,
            8080,
            &[("10.0.0.1", true, false)],
        );
        api.put("ingresses", shop("shop.acme.test"));
        let mut run = Run::start(&config(&api, &dir, ""));
        run.wait_ids(&["team-a.shop"]).await;
        api.wait_requests("every kind watched", |seen| {
            seen.iter().filter(|seen| seen.is_watch()).count() >= 4
        })
        .await;
        let lists = api.count("ingresses", false);

        // The watch breaks while the world moves on, and the history it would resume from is
        // gone: the only way back is a new list.
        api.drop_watches();
        api.put("ingresses", {
            let mut second = shop("second.acme.test");
            second["metadata"]["name"] = json!("second");
            second
        });
        api.put(
            "endpointslices",
            k8s::slice(
                "team-a",
                "web",
                0,
                &[(None, 8080)],
                &[("10.0.0.7", true, false)],
            ),
        );
        api.expire_history();
        let state = run
            .wait("the changes made while disconnected", |state| {
                ids(state).len() == 2
                    && servers(state, "team-a.shop", "web.80") == ["http://10.0.0.7:8080"]
            })
            .await;
        assert_eq!(ids(&state), ["team-a.second", "team-a.shop"], "{how:?}");
        assert!(
            api.count("ingresses", false) > lists,
            "{how:?}: the Ingresses were listed again"
        );
        // A 410 is the protocol working, not an outage.
        assert!(
            !run.outages
                .iter()
                .any(|why| why.contains("410") || why.contains("gone")),
            "{how:?}: {:?}",
            run.outages
        );
        // And the new watch keeps working.
        api.put(
            "endpointslices",
            k8s::slice(
                "team-a",
                "web",
                0,
                &[(None, 8080)],
                &[("10.0.0.8", true, false)],
            ),
        );
        run.wait("events after the relist", |state| {
            servers(state, "team-a.shop", "web.80") == ["http://10.0.0.8:8080"]
        })
        .await;
    }
}

#[tokio::test]
async fn watch_resumes_from_bookmark_and_after_server_timeout() {
    let api = FakeApi::start().await;
    let dir = Dir::new("bookmark");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    let mut run = Run::start(&config(&api, &dir, ""));
    run.wait_ids(&["team-a.shop"]).await;
    api.wait_requests("every kind watched", |seen| {
        seen.iter().filter(|s| s.is_watch()).count() >= 4
    })
    .await;
    // Another kind moves the version on; the Ingress watch hears nothing but a bookmark.
    let moved = api.put(
        "secrets",
        k8s::secret("team-a", "other", "kubernetes.io/tls", "c", "k"),
    );
    api.bookmark("ingresses");
    let lists = api.count("ingresses", false);
    let watches = api.count("ingresses", true);
    // Let the bookmark arrive, then end the watch: the resume must start at the bookmark.
    tokio::time::sleep(Duration::from_millis(200)).await;
    api.drop_watches();
    api.wait_requests("the Ingress watch to resume", |seen| {
        seen.iter()
            .filter(|s| s.plural() == "ingresses" && s.is_watch())
            .count()
            > watches
    })
    .await;
    let resumed = api
        .requests()
        .into_iter()
        .rfind(|seen| seen.plural() == "ingresses" && seen.is_watch())
        .expect("a watch");
    assert_eq!(
        resumed.query.get("resourceVersion"),
        Some(&moved.to_string()),
        "{resumed:?}"
    );
    assert_eq!(
        resumed.query.get("allowWatchBookmarks").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        api.count("ingresses", false),
        lists,
        "a bookmarked resume needs no new list"
    );
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(None, 8080)],
            &[("10.0.0.5", true, false)],
        ),
    );
    run.wait("a change after the resume", |state| {
        servers(state, "team-a.shop", "web.80") == ["http://10.0.0.5:8080"]
    })
    .await;

    // A watch the server ends on its own (timeoutSeconds) resumes without a list too.
    let before = api.count("endpointslices", true);
    api.wait_requests("a watch to time out and resume", |seen| {
        seen.iter()
            .filter(|s| s.plural() == "endpointslices" && s.is_watch())
            .count()
            > before
    })
    .await;
    assert_eq!(api.count("ingresses", false), lists);
}

#[tokio::test]
async fn unknown_annotation_rejects_ingress() {
    let api = FakeApi::start().await;
    let dir = Dir::new("annotations");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put("ingresses", shop("good.acme.test"));
    let with = |name: &str, key: &str, value: &str| {
        let mut ingress = shop(&format!("{name}.acme.test"));
        ingress["metadata"]["name"] = json!(name);
        ingress["metadata"]["annotations"] = json!({ key: value });
        ingress
    };
    api.put("ingresses", with("typo", "podgate.io/tennant", "globex"));
    api.put(
        "ingresses",
        with(
            "traefik",
            "traefik.ingress.kubernetes.io/router.middlewares",
            "auth@kubernetescrd",
        ),
    );
    api.put("ingresses", with("badpri", "podgate.io/priority", "high"));
    api.put(
        "ingresses",
        with("badmw", "podgate.io/middleware.x", "not json"),
    );
    // Annotations of other controllers are none of podgate's business.
    api.put(
        "ingresses",
        with("nginx", "nginx.ingress.kubernetes.io/ssl-redirect", "true"),
    );
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.nginx", "team-a.shop"]).await;
    let why = run.wait_outage("team-a/typo").await;
    for name in ["typo", "traefik", "badpri", "badmw"] {
        assert!(
            why.contains(&format!("Ingress team-a/{name} rejected")),
            "{name}: {why}"
        );
    }
    assert!(
        why.contains("podgate.io/tennant: is not a podgate annotation"),
        "{why}"
    );
    assert!(
        why.contains("Traefik annotation podgate does not implement"),
        "{why}"
    );
    assert_eq!(ids(&state).len(), 2);
}

#[tokio::test]
async fn supported_annotations_shape_the_routers() {
    let api = FakeApi::start().await;
    let dir = Dir::new("shape");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    let mut ingress = k8s::ingress(
        "team-a",
        "shaped",
        "podgate",
        json!([k8s::rule(
            Some("shaped.acme.test"),
            &[
                ("/re/.*", "ImplementationSpecific", "web", json!(80)),
                ("/", "ImplementationSpecific", "web", json!(80))
            ]
        )]),
    );
    ingress["metadata"]["annotations"] = json!({
        "podgate.io/path-type": "regexp",
        "podgate.io/entry-points": "websecure, web",
        "podgate.io/priority": "7",
        "podgate.io/middleware.strip": r#"{"type": "strip_prefix", "prefix": "/re"}"#,
        "podgate.io/chain": "strip",
        "podgate.io/tls": "acme",
    });
    api.put("ingresses", ingress);
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["team-a.shaped"]).await;
    assert_eq!(
        routers(&state, "team-a.shaped"),
        json!([
            { "name": "r0p0", "match": { "all": [{ "host": "shaped.acme.test" }, { "path_regexp": "/re/.*" }] },
              "entry_points": ["websecure", "web"], "priority": 7, "chain": ["strip"], "service": "web.80" },
            { "name": "r0p1", "match": { "all": [{ "host": "shaped.acme.test" }, { "path_regexp": "/" }] },
              "entry_points": ["websecure", "web"], "priority": 7, "chain": ["strip"], "service": "web.80" },
        ])
    );
    let shaped = app(&state, "team-a.shaped");
    assert_eq!(
        serde_json::to_value(&shaped.app.middlewares).expect("middlewares"),
        json!([{ "name": "strip", "type": "strip_prefix", "prefix": "/re" }])
    );
    assert_eq!(
        serde_json::to_value(&shaped.app.tls).expect("tls")["mode"],
        "acme"
    );
}

#[tokio::test]
async fn apiserver_outage_keeps_last_state() {
    for failure in [Failure::Status(503), Failure::Reset] {
        let api = FakeApi::start().await;
        let dir = Dir::new(&format!("outage-{failure:?}"));
        backend(
            &api,
            "team-a",
            "web",
            80,
            8080,
            &[("10.0.0.1", true, false)],
        );
        api.put("ingresses", shop("shop.acme.test"));
        let mut run = Run::start(&config(&api, &dir, ""));
        run.wait_ids(&["team-a.shop"]).await;
        let states = run.states;

        api.fail(Some(failure));
        let why = run.wait_outage("cannot watch").await;
        assert!(
            why.contains("ingresses") || why.contains("services") || why.contains("endpointslices"),
            "{why}"
        );
        assert_eq!(
            run.states, states,
            "{failure:?}: no state is sent for an unreachable cluster"
        );
        assert_eq!(
            ids(run.state.as_ref().expect("the last state")),
            ["team-a.shop"],
            "{failure:?}: the last state stays"
        );

        // The cluster comes back with a change: the source recovers, reports no outage and
        // sends the new state.
        api.put(
            "endpointslices",
            k8s::slice(
                "team-a",
                "web",
                0,
                &[(None, 8080)],
                &[("10.0.0.9", true, false)],
            ),
        );
        api.fail(None);
        run.until("recovery", |state, outage| {
            outage.is_none()
                && state.is_some_and(|state| {
                    servers(state, "team-a.shop", "web.80") == ["http://10.0.0.9:8080"]
                })
        })
        .await;
    }
}

#[tokio::test]
async fn no_state_until_every_list_succeeded() {
    let api = FakeApi::start().await;
    let dir = Dir::new("startup");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    api.fail(Some(Failure::Status(503)));
    let mut run = Run::start(&config(&api, &dir, ""));
    run.wait_outage("cannot watch").await;
    assert!(
        run.state.is_none(),
        "a half-loaded cache must not become a state"
    );
    api.fail(None);
    run.wait_ids(&["team-a.shop"]).await;
}

// ---- configuration and the client ------------------------------------------------------------

#[tokio::test]
async fn namespaces_limit_what_is_watched() {
    let api = FakeApi::start().await;
    let dir = Dir::new("scoped");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    backend(
        &api,
        "team-b",
        "web",
        80,
        8080,
        &[("10.0.0.2", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    api.put("ingresses", {
        let mut other = k8s::ingress(
            "team-b",
            "site",
            "podgate",
            json!([k8s::rule(
                Some("globex.test"),
                &[("/", "Prefix", "web", json!(80))]
            )]),
        );
        other["metadata"]["name"] = json!("site");
        other
    });
    let mut run = Run::start(&config(&api, &dir, "namespaces = [\"team-a\", \"team-a\"]"));
    let state = run.wait_ids(&["team-a.shop"]).await;
    assert_eq!(ids(&state), ["team-a.shop"]);
    assert!(
        api.requests()
            .iter()
            .all(|seen| seen.path.contains("/namespaces/team-a/")),
        "every request is scoped to the namespace: {:?}",
        api.requests()
            .iter()
            .map(|seen| seen.path.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        api.count("ingresses", false),
        1,
        "a namespace listed twice is watched once"
    );
}

#[tokio::test]
async fn source_config_errors_name_the_key() {
    let api = FakeApi::start().await;
    let dir = Dir::new("config");
    let reject = |extra: &str| {
        let config = config(&api, &dir, extra);
        KubernetesSource::from_config(&config.sources[0], &config)
            .expect_err("an invalid source")
            .to_string()
    };
    assert!(reject("colour = \"red\"").contains("colour"));
    assert!(reject("default_tenant = \"nobody\"").contains("default_tenant"));
    let nobody = base_config(
        &dir.0.join("admin.sock"),
        &format!(
            "[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\nnamespace_tenants = {{ x = \"nobody\" }}\n",
            api.kubeconfig(&dir.0, "t").display().to_string()
        ),
    );
    let why =
        KubernetesSource::from_config(&nobody.sources[0], &nobody).expect_err("unknown tenant");
    assert!(why.to_string().contains("namespace_tenants"), "{why}");
    assert!(reject("namespaces = []").contains("namespaces"));
    assert!(reject("ingress_class = \"\"").contains("ingress_class"));
    assert!(reject("context = \"x\"").contains("context"));
    let missing = base_config(
        &dir.0.join("admin.sock"),
        "[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = \"/nonexistent/kubeconfig\"\n",
    );
    let why = KubernetesSource::from_config(&missing.sources[0], &missing).expect_err("no file");
    assert!(why.to_string().contains("/nonexistent/kubeconfig"), "{why}");
}

#[test]
fn kubeconfig_refuses_what_it_cannot_do_safely() {
    let dir = Dir::new("kubeconfig");
    let refuse = |name: &str, cluster: &str, user: &str| {
        let path = dir.0.join(name);
        fs::write(
            &path,
            format!(
                "current-context: c\ncontexts:\n- name: c\n  context: {{cluster: c, user: u}}\nclusters:\n- name: c\n  cluster:\n{cluster}\nusers:\n- name: u\n  user:\n{user}\n"
            ),
        )
        .expect("write");
        ClientConfig::from_kubeconfig(&path, None)
            .expect_err("refused")
            .to_string()
    };
    let loopback = "    server: http://127.0.0.1:8001";
    assert!(
        refuse(
            "insecure",
            "    server: https://10.0.0.1\n    insecure-skip-tls-verify: true",
            "    token: t"
        )
        .contains("insecure-skip-tls-verify")
    );
    assert!(refuse("exec", loopback, "    exec: {command: aws}").contains("exec"));
    assert!(
        refuse("plain", "    server: http://10.0.0.1:8001", "    token: t").contains("clear text")
    );
    assert!(
        refuse("noca", "    server: https://10.0.0.1", "    token: t")
            .contains("certificate authority")
    );
    assert!(
        refuse("basic", loopback, "    username: u\n    password: p")
            .contains("basic authentication")
    );
    // Plain http on loopback is `kubectl proxy`: fine.
    let ok = dir.0.join("proxy");
    fs::write(
        &ok,
        "current-context: c\ncontexts:\n- name: c\n  context: {cluster: c, user: u}\nclusters:\n- name: c\n  cluster:\n    server: http://127.0.0.1:8001\nusers:\n- name: u\n  user: {}\n",
    )
    .expect("write");
    assert!(ClientConfig::from_kubeconfig(&ok, None).is_ok());
}

#[tokio::test]
async fn client_verifies_tls_and_sends_the_token() {
    let api = FakeApi::start_tls().await;
    let dir = Dir::new("tlsclient");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put("ingresses", shop("shop.acme.test"));
    let mut run = Run::start(&config(&api, &dir, ""));
    run.wait_ids(&["team-a.shop"]).await;
    assert!(
        api.requests()
            .iter()
            .all(|seen| seen.authorization.as_deref() == Some("Bearer test-token")),
        "every request carries the token"
    );

    // A server whose certificate is not the configured authority's is not talked to at all.
    let stranger = FakeApi::start_tls().await;
    let kubeconfig = {
        let path = stranger.kubeconfig(&dir.0, "other");
        // The right address, the wrong authority.
        let text = fs::read_to_string(&path).expect("read");
        let right = api.kubeconfig(&dir.0, "other");
        let right_text = fs::read_to_string(right).expect("read");
        let ca_line = right_text
            .lines()
            .find(|l| l.contains("certificate-authority-data"))
            .expect("ca");
        let swapped: String = text
            .lines()
            .map(|line| {
                if line.contains("certificate-authority-data") {
                    ca_line
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, swapped).expect("write");
        path
    };
    let client = ApiClient::new(
        ClientConfig::from_kubeconfig(&kubeconfig, None).expect("config"),
        tuning(),
    );
    let err = client
        .list::<TestPod>(&Query::all())
        .await
        .expect_err("the certificate does not match");
    assert!(matches!(err, ClientError::Connect(_)), "{err}");
    assert!(
        stranger.requests().is_empty(),
        "no HTTP request crossed an unverified connection"
    );
}

#[tokio::test]
async fn bad_token_is_an_outage_not_a_state() {
    let api = FakeApi::start().await;
    let dir = Dir::new("token");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    let config = config(&api, &dir, "");
    // The server now wants another token than the kubeconfig holds.
    let _ = api.kubeconfig(&dir.0, "rotated");
    let mut run = Run::start(&config);
    let why = run.wait_outage("401").await;
    assert!(why.contains("Unauthorized"), "{why}");
    assert!(run.state.is_none());
    assert!(
        !why.contains("test-token"),
        "the token never appears in a message: {why}"
    );
}

// ---- the generic client, as a later source uses it -------------------------------------------

/// A kind the Kubernetes source itself does not use, to show the client is generic.
#[derive(Debug, Deserialize)]
struct TestPod {
    metadata: ObjectMeta,
    #[serde(default)]
    spec: Value,
}

impl Resource for TestPod {
    const GROUP: &'static str = "";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "pods";
    const KIND: &'static str = "Pod";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

fn pod(namespace: &str, name: &str, node: &str) -> Value {
    json!({ "metadata": { "namespace": namespace, "name": name }, "spec": { "nodeName": node } })
}

async fn next(watcher: &mut Watcher<TestPod>) -> Event<TestPod> {
    tokio::time::timeout(DEADLINE, watcher.next())
        .await
        .expect("the watcher produces an event in time")
}

#[tokio::test]
async fn watcher_is_generic_over_resource_kinds() {
    let api = FakeApi::start().await;
    let dir = Dir::new("generic");
    let client = ApiClient::new(
        ClientConfig::from_kubeconfig(&api.kubeconfig(&dir.0, "t"), None).expect("config"),
        tuning(),
    );
    for index in 0..5 {
        api.put("pods", pod("a", &format!("p{index}"), "n1"));
    }
    api.put("pods", pod("b", "other", "n1"));
    let mut watcher = Watcher::<TestPod>::new(client.clone(), Query::in_namespace("a"));
    let mut store = Store::<TestPod>::new();
    assert!(!store.is_synced());

    // The list pages (page size 2) arrive as one Reset of exactly the namespace.
    let Event::Reset(items) = next(&mut watcher).await else {
        panic!("the first event is the list");
    };
    assert_eq!(items.len(), 5);
    assert!(store.apply(Event::Reset(items)) && store.is_synced());
    assert_eq!(store.len(), 5);
    assert!(store.get("a", "p3").is_some() && store.get("b", "other").is_none());

    api.put("pods", pod("a", "p9", "n2"));
    api.put("pods", pod("b", "ignored", "n2"));
    api.put("pods", pod("a", "p1", "n3"));
    api.remove("pods", "a", "p0");
    let mut seen = Vec::new();
    while seen.len() < 3 {
        match next(&mut watcher).await {
            Event::Applied(pod) => seen.push(format!("applied {}", pod.metadata.name)),
            Event::Deleted(pod) => seen.push(format!("deleted {}", pod.metadata.name)),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(
        seen,
        ["applied p9", "applied p1", "deleted p0"],
        "namespace b stays out"
    );

    // A bookmark is not an event: the next thing the watcher yields is the next real change.
    api.bookmark("pods");
    api.put("pods", pod("a", "p5", "n1"));
    let Event::Applied(applied) = next(&mut watcher).await else {
        panic!("an applied pod");
    };
    assert_eq!(applied.metadata.name, "p5");
    assert_eq!(applied.spec["nodeName"], "n1");

    // Expired history relists: a Reset with the whole current set.
    api.drop_watches();
    api.put("pods", pod("a", "p6", "n1"));
    api.expire_history();
    let relisted = next(&mut watcher).await;
    let Event::Reset(items) = relisted else {
        panic!("a 410 ends in a new list, got {relisted:?}");
    };
    let mut names: Vec<String> = items.iter().map(|pod| pod.metadata.name.clone()).collect();
    names.sort();
    assert_eq!(names, ["p1", "p2", "p3", "p4", "p5", "p6", "p9"]);
    store.apply(Event::Reset(items));
    assert_eq!(store.len(), 7);

    // Failures come back as Outage events and the watcher keeps trying.
    api.fail(Some(Failure::Status(500)));
    let Event::Outage(why) = next(&mut watcher).await else {
        panic!("an outage");
    };
    assert!(why.contains("pods") && why.contains("500"), "{why}");
    assert!(
        !store.apply(Event::Outage(why)),
        "an outage changes nothing"
    );
    assert_eq!(store.len(), 7);
    api.fail(None);
    // The watch version is still valid, so the watcher resumes without a list and the next
    // change simply arrives.
    api.put("pods", pod("a", "p7", "n1"));
    loop {
        match next(&mut watcher).await {
            Event::Outage(_) => {}
            Event::Applied(applied) => {
                assert_eq!(applied.metadata.name, "p7");
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
