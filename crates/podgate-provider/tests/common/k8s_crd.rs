//! Harness for the tests of the podgate custom resources: a running Kubernetes source against
//! the fake API (`super::k8s`), and builders for `PodgateRoute` and `PodgateMiddleware` objects.
//! The fake serves any kind by its plural, so `podgateroutes` and `podgatemiddlewares` need
//! nothing of it.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use podgate_provider::Config;
use podgate_provider::kubernetes::KubernetesSource;
use podgate_provider::kubernetes::client::Tuning;
use podgate_provider::source::{Source, SourceApp, State, Update, UpdateBody};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::DEADLINE;
use super::k8s::FakeApi;

/// Two tenants: `acme` may have catch-all routers, `globex` may not.
pub const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]
catch_all = true

[[tenant]]
id = "globex"
hosts = ["globex.test"]
"#;

/// A directory that is removed on drop.
pub struct Dir(pub PathBuf);

impl Dir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pgp-crd-{}-{label}", std::process::id()));
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

pub fn tuning() -> Tuning {
    Tuning {
        watch_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(80),
        // Small pages, so every list in these tests also exercises `continue`.
        page_size: 2,
    }
}

/// The provider configuration: the two tenants, then a Kubernetes source that reads the custom
/// resources, with `source` as its extra keys.
pub fn config(api: &FakeApi, dir: &Dir, source: &str) -> Config {
    let kubeconfig = api.kubeconfig(&dir.0, "test-token");
    super::config(
        &dir.0.join("admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\ncrds = true\nnamespace_tenants = {{ team-a = \"acme\", team-b = \"globex\" }}\n{source}\n",
            kubeconfig.display().to_string()
        ),
    )
}

pub fn source(config: &Config) -> KubernetesSource {
    KubernetesSource::from_config(&config.sources[0], config)
        .expect("a valid Kubernetes source")
        .with_tuning(tuning())
        .with_settle(Duration::from_millis(20))
}

/// A running source and what it has said so far.
pub struct Run {
    rx: mpsc::Receiver<Update>,
    task: JoinHandle<()>,
    pub state: Option<State>,
    pub outage: Option<String>,
}

impl Run {
    pub fn start(config: &Config) -> Self {
        let (tx, rx) = mpsc::channel(64);
        Self {
            rx,
            task: tokio::spawn(source(config).run(tx)),
            state: None,
            outage: None,
        }
    }

    pub async fn until(&mut self, what: &str, done: impl Fn(Option<&State>, Option<&str>) -> bool) {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                assert_eq!(&*update.source, "k8s");
                match update.body {
                    UpdateBody::State(state) => {
                        self.state = Some(state);
                        self.outage = None;
                    }
                    UpdateBody::Outage(why) => self.outage = Some(why.to_string()),
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

    pub async fn wait(&mut self, what: &str, condition: impl Fn(&State) -> bool) -> State {
        self.until(what, |state, _| state.is_some_and(&condition))
            .await;
        self.state.clone().expect("a state")
    }

    pub async fn wait_ids(&mut self, expected: &[&str]) -> State {
        let expected: Vec<String> = expected.iter().map(|id| (*id).to_owned()).collect();
        self.wait(&format!("apps {expected:?}"), |state| {
            ids(state) == expected
        })
        .await
    }

    /// Waits for an outage that names `needle`, whatever the state is.
    pub async fn wait_outage(&mut self, needle: &str) -> String {
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

pub fn ids(state: &State) -> Vec<String> {
    let mut ids: Vec<String> = state
        .apps
        .iter()
        .map(|app| app.app.id.to_string())
        .collect();
    ids.sort();
    ids
}

pub fn app<'a>(state: &'a State, id: &str) -> &'a SourceApp {
    state
        .apps
        .iter()
        .find(|app| &*app.app.id == id)
        .unwrap_or_else(|| panic!("no app {id}: {:?}", ids(state)))
}

/// A part of an app as JSON, without the fields that are absent (the model writes them as null).
pub fn stripped(value: &impl serde::Serialize) -> Value {
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
    strip(serde_json::to_value(value).expect("serializes"))
}

/// The sorted server URLs of the service `service` of app `id`.
pub fn servers(state: &State, id: &str, service: &str) -> Vec<String> {
    let all = stripped(&app(state, id).app.services);
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

/// A `PodgateRoute` with `spec`.
pub fn route(namespace: &str, name: &str, spec: Value) -> Value {
    json!({
        "apiVersion": "podgate.io/v1alpha1",
        "kind": "PodgateRoute",
        "metadata": { "namespace": namespace, "name": name, "creationTimestamp": "2026-11-20T12:00:00Z" },
        "spec": spec,
    })
}

/// A `PodgateMiddleware` of `kind` with `config`.
pub fn middleware(namespace: &str, name: &str, kind: &str, config: Value) -> Value {
    json!({
        "apiVersion": "podgate.io/v1alpha1",
        "kind": "PodgateMiddleware",
        "metadata": { "namespace": namespace, "name": name },
        "spec": { "type": kind, "config": config },
    })
}

/// A route spec with one router for `host` to the service `web`, a load balancer on the Service
/// `web` port 80. `extra` is merged over it.
pub fn web(host: &str, extra: Value) -> Value {
    let mut spec = json!({
        "routers": [{
            "name": "web",
            "match": { "all": [{ "host": host }, { "path_prefix": "/" }] },
            "service": "web",
        }],
        "services": [{ "name": "web", "type": "loadbalancer", "serviceRef": { "name": "web", "port": 80 } }],
    });
    if let (Some(spec), Some(extra)) = (spec.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            spec.insert(key.clone(), value.clone());
        }
    }
    spec
}

/// A Service `name` in `namespace` that listens on `port` with pods on `container`, behind the
/// given endpoints `(address, ready, terminating)`.
pub fn backend(
    api: &FakeApi,
    namespace: &str,
    name: &str,
    port: u16,
    container: u16,
    endpoints: &[(&str, bool, bool)],
) {
    api.put(
        "services",
        super::k8s::service(namespace, name, &[(None, port)]),
    );
    api.put(
        "endpointslices",
        super::k8s::slice(namespace, name, 0, &[(None, container)], endpoints),
    );
}
