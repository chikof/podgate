//! Black-box tests of the Docker and Podman source against a fake daemon on a unix socket
//! (`tests/common/docker.rs`): labels, addresses, tenants, container states, events, outages and
//! how its objects fare in the merge. Everything that waits has a deadline.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use common::docker::{Ctr, FakeDocker, Flavor};
use common::{DEADLINE, config};
use podgate_provider::docker::DockerSource;
use podgate_provider::docker::labels;
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::{Config, Merged, Merger, UpstreamPolicy};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// An event must show within the source's quiet window plus scheduling slack, far below the
/// hour the tests give `resync_secs`.
const PROMPT: Duration = Duration::from_secs(4);

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
"#;

/// The configuration with one docker source named `docker` after `tenants`, and `settings` as
/// the source's own keys.
fn docker_config(socket: &Path, tenants: &str, settings: &str) -> Config {
    config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{tenants}\n[[source]]\nkind = \"docker\"\nname = \"docker\"\nsocket = {:?}\nresync_secs = 3600\n{settings}\n",
            socket.display().to_string()
        ),
    )
}

fn source_of(config: &Config) -> DockerSource {
    DockerSource::from_config(&config.sources[0]).expect("a valid docker source")
}

/// A running docker source and what it has said so far.
struct Watcher {
    rx: mpsc::Receiver<Update>,
    task: JoinHandle<()>,
    state: Option<State>,
    outage: Option<String>,
}

impl Watcher {
    fn start(config: &Config) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let source = source_of(config);
        Self {
            rx,
            task: tokio::spawn(source.run(tx)),
            state: None,
            outage: None,
        }
    }

    async fn until(&mut self, what: &str, done: impl Fn(Option<&State>, Option<&str>) -> bool) {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                assert_eq!(&*update.source, "docker");
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
                "timed out waiting for: {what}; apps: {:?}; outage: {:?}",
                self.state.as_ref().map(ids),
                self.outage
            );
        }
    }

    async fn wait_ids(&mut self, expected: &[&str]) -> State {
        let expected: Vec<String> = expected.iter().map(|id| (*id).to_owned()).collect();
        self.until(&format!("apps {expected:?}"), |state, _| {
            state.is_some_and(|state| ids(state) == expected)
        })
        .await;
        self.state.clone().expect("a state")
    }

    async fn wait_outage(&mut self, needle: &str) {
        self.until(&format!("an outage naming {needle}"), |_, outage| {
            outage.is_some_and(|why| why.contains(needle))
        })
        .await;
    }

    /// Waits for the state `ids` and for the report that names `needle`.
    async fn wait_ids_and_report(&mut self, expected: &[&str], needle: &str) -> State {
        let expected: Vec<String> = expected.iter().map(|id| (*id).to_owned()).collect();
        self.until(
            &format!("apps {expected:?} and a report naming {needle}"),
            |state, outage| {
                state.is_some_and(|state| ids(state) == expected)
                    && outage.is_some_and(|why| why.contains(needle))
            },
        )
        .await;
        self.state.clone().expect("a state")
    }

    fn report(&self) -> &str {
        self.outage.as_deref().unwrap_or_default()
    }
}

impl Drop for Watcher {
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

fn app_of<'a>(state: &'a State, id: &str) -> &'a podgate_provider::source::SourceApp {
    state
        .apps
        .iter()
        .find(|app| &*app.app.id == id)
        .unwrap_or_else(|| panic!("no app {id}: {:?}", ids(state)))
}

fn app_json(state: &State, id: &str) -> Value {
    serde_json::to_value(&app_of(state, id).app).expect("an app serializes")
}

/// The urls of the servers of the first service of a revision of `id`.
fn servers_of(state: &State, id: &str, revision: &str) -> Vec<String> {
    let app = app_json(state, id);
    let revision = app["revisions"]
        .as_array()
        .expect("revisions")
        .iter()
        .find(|rev| rev["id"] == revision)
        .unwrap_or_else(|| panic!("no revision {revision} in {app}"));
    revision["services"][0]["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .map(|server| server["url"].as_str().expect("a url").to_owned())
        .collect()
}

/// A container on the `podgate` network that serves `host` on port 8080.
fn web(name: &str, ip: &str, host: &str) -> Ctr {
    Ctr::new(name).network("podgate", ip).labels(&[
        ("podgate.enable", "true"),
        ("podgate.host", host),
        ("podgate.port", "8080"),
    ])
}

fn merge(config: &Config, policy: UpstreamPolicy, state: State) -> Merged {
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("docker".into(), state)]);
    Merger::new(config, policy).merge(&states, &BTreeSet::new())
}

fn finding_codes(merged: &Merged) -> Vec<(&'static str, String)> {
    merged
        .findings()
        .iter()
        .map(|finding| (finding.code, finding.object.to_string()))
        .collect()
}

fn merged_apps(merged: &Merged) -> Vec<(String, String)> {
    merged
        .snapshot()
        .apps
        .iter()
        .map(|app| (app.id.to_string(), app.tenant.to_string()))
        .collect()
}

// ---- labels to apps --------------------------------------------------------------------------

#[tokio::test]
async fn docker_labels_to_app() {
    let docker = FakeDocker::start();
    docker.add(
        web("shop-1", "10.4.0.5", "shop.acme.test, www.shop.acme.test")
            .label("com.docker.compose.service", "shop")
            .created_at(7),
    );
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    let state = watcher.wait_ids(&["shop"]).await;
    let app = app_of(&state, "shop");
    assert_eq!(&*app.origin.object, "shop");
    assert_eq!(
        app.origin.first_seen, 1_795_168_807,
        "the oldest container's creation time"
    );
    assert_eq!(app.tenant.mapped.as_deref(), Some("default"));
    assert_eq!(app.tenant.label, None);
    assert_eq!(
        app_json(&state, "shop"),
        json!({
            "id": "shop",
            "tenant": "default",
            "declared_by": "docker",
            "tls": { "mode": "acme", "challenge": "http-01", "client_ca_pem": null },
            "routers": [{
                "name": "default",
                "entry_points": null,
                "match": { "host": ["shop.acme.test", "www.shop.acme.test"] },
                "priority": null,
                "chain": [],
                "service": "web",
                "observability": null,
                "declared_by": null,
            }],
            "middlewares": [],
            "default_chain": [],
            "services": [],
            "transports": [],
            "revisions": [{
                "id": "default",
                "state": "serving",
                "weight": 1,
                "services": [{
                    "name": "web",
                    "type": "loadbalancer",
                    "servers": [{ "url": "http://10.4.0.5:8080" }],
                }],
            }],
            "allow_domain_fronting": false,
            "record_bodies": false,
            "scale_to_zero": null,
            "canary": null,
            "tcp": null,
            "udp": null,
        })
    );
}

#[tokio::test]
async fn docker_full_labels_to_app() {
    let docker = FakeDocker::start();
    let labels = [
        ("podgate.enable", "true"),
        ("podgate.app", "api"),
        ("podgate.port", "9000"),
        ("podgate.tls", "on_demand"),
        ("podgate.revision", "r7"),
        ("podgate.revision.state", "serving"),
        (
            "podgate.router.v1.match",
            r#"{"all": [{"host": "api.acme.test"}, {"path_prefix": "/v1"}]}"#,
        ),
        ("podgate.router.v1.priority", "10"),
        ("podgate.router.v1.entry_points", "web, websecure"),
        ("podgate.router.v1.chain", "strip,limit"),
        ("podgate.router.v1.service", "api"),
        ("podgate.middleware.strip.type", "strip_prefix"),
        (
            "podgate.middleware.strip.config",
            r#"{"prefixes": ["/v1"]}"#,
        ),
        ("podgate.middleware.limit.type", "in_flight_req"),
        ("podgate.middleware.limit.config", r#"{"amount": 5}"#),
        (
            "podgate.service.api.config",
            r#"{"algorithm": "least_conn", "health_check": {"path": "/up", "interval_secs": 5, "timeout_secs": 1}, "sticky": {"cookie": {"name": "srv"}}, "transport": "tight"}"#,
        ),
        (
            "podgate.transport.tight.config",
            r#"{"dial_timeout_secs": 3}"#,
        ),
    ];
    docker.add(
        Ctr::new("api-2")
            .network("podgate", "10.4.0.7")
            .labels(&labels)
            .created_at(2),
    );
    docker.add(
        Ctr::new("api-1")
            .network("podgate", "10.4.0.6")
            .labels(&labels)
            .created_at(1),
    );
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    let state = watcher.wait_ids(&["api"]).await;
    let mut app = app_json(&state, "api");
    assert_eq!(
        app["revisions"][0]["services"][0]["servers"],
        json!([{ "url": "http://10.4.0.6:9000" }, { "url": "http://10.4.0.7:9000" }]),
        "both containers are servers, in address order"
    );
    app["tls"] = json!({ "mode": app["tls"]["mode"] });
    assert_eq!(app["tls"], json!({ "mode": "on_demand" }));
    assert_eq!(
        app["routers"],
        json!([{
            "name": "v1",
            "entry_points": ["web", "websecure"],
            "match": { "all": [{ "host": "api.acme.test" }, { "path_prefix": "/v1" }] },
            "priority": 10,
            "chain": ["strip", "limit"],
            "service": "api",
            "observability": null,
            "declared_by": null,
        }])
    );
    assert_eq!(
        app["middlewares"],
        json!([
            { "name": "limit", "type": "in_flight_req", "amount": 5 },
            { "name": "strip", "type": "strip_prefix", "prefixes": ["/v1"] },
        ])
    );
    assert_eq!(
        app["transports"],
        json!([{ "name": "tight", "type": "servers_transport", "dial_timeout_secs": 3 }])
    );
    assert_eq!(
        app["revisions"],
        json!([{
            "id": "r7",
            "state": "serving",
            "weight": 1,
            "services": [{
                "name": "api",
                "type": "loadbalancer",
                "algorithm": "least_conn",
                "health_check": { "path": "/up", "interval_secs": 5, "timeout_secs": 1 },
                "sticky": { "cookie": { "name": "srv" } },
                "transport": "tight",
                "servers": [{ "url": "http://10.4.0.6:9000" }, { "url": "http://10.4.0.7:9000" }],
            }],
        }])
    );
}

#[test]
fn label_parser_takes_plain_pairs() {
    // The same keys a Nomad tag set or a Kubernetes annotation set carries.
    let pairs = [
        ("podgate.host", "a.test"),
        ("podgate.port", "80"),
        ("unrelated", "x"),
    ];
    let parsed = labels::parse(pairs).expect("labels");
    assert_eq!(parsed.port, Some(80));
    assert_eq!(&*parsed.revision, "default");
    assert_eq!(
        parsed.definition.routers[0].matcher,
        json!({ "host": ["a.test"] })
    );
    assert_eq!(&*parsed.services[0].name, "web");
    assert_eq!(
        labels::parse([("podgate.nope", "1")])
            .expect_err("unknown")
            .code(),
        "unknown_label"
    );
}

// ---- which containers ------------------------------------------------------------------------

#[tokio::test]
async fn exposed_by_default_false() {
    let docker = FakeDocker::start();
    docker.add(web("opted-in", "10.4.0.2", "in.acme.test"));
    docker.add(
        Ctr::new("not-asked")
            .network("podgate", "10.4.0.3")
            .labels(&[("podgate.host", "no.acme.test"), ("podgate.port", "80")]),
    );
    docker.add(
        Ctr::new("opted-out")
            .network("podgate", "10.4.0.4")
            .labels(&[
                ("podgate.enable", "false"),
                ("podgate.host", "out.acme.test"),
                ("podgate.port", "80"),
            ]),
    );
    docker.add(Ctr::new("bare").network("podgate", "10.4.0.5"));
    let mut closed = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    closed.wait_ids(&["opted-in"]).await;
    assert_eq!(closed.report(), "", "ignored containers are not reported");

    let mut open = Watcher::start(&docker_config(
        docker.path(),
        "",
        "network = \"podgate\"\nexposed_by_default = true",
    ));
    open.wait_ids_and_report(&["not-asked", "opted-in"], "container bare")
        .await;
    assert!(
        open.report().contains("no router"),
        "an exposed container with no routing is reported, not routed: {}",
        open.report()
    );
}

#[tokio::test]
async fn server_address_from_container_network() {
    let docker = FakeDocker::start();
    docker.add(web("app", "10.4.0.5", "app.acme.test").network("other", "172.20.0.9"));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    let state = watcher.wait_ids(&["app"]).await;
    assert_eq!(
        servers_of(&state, "app", "default"),
        ["http://10.4.0.5:8080"]
    );

    // With a list of networks the first one the container is on gives the address.
    let mut watcher = Watcher::start(&docker_config(
        docker.path(),
        "",
        "network = [\"other\", \"podgate\"]",
    ));
    let state = watcher.wait_ids(&["app"]).await;
    assert_eq!(
        servers_of(&state, "app", "default"),
        ["http://172.20.0.9:8080"]
    );
}

#[tokio::test]
async fn container_in_other_network_not_used() {
    let docker = FakeDocker::start();
    docker.add(web("good", "10.4.0.5", "good.acme.test"));
    docker.add(
        Ctr::new("elsewhere")
            .network("other", "172.20.0.9")
            .labels(&[
                ("podgate.enable", "true"),
                ("podgate.host", "else.acme.test"),
                ("podgate.port", "80"),
            ]),
    );
    docker.add(Ctr::new("no-address").network("podgate", "").labels(&[
        ("podgate.enable", "true"),
        ("podgate.host", "none.acme.test"),
        ("podgate.port", "80"),
    ]));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    watcher
        .wait_ids_and_report(&["good"], "container elsewhere")
        .await;
    assert!(
        watcher.report().contains("container no-address"),
        "{}",
        watcher.report()
    );
    assert!(
        watcher.report().contains("no address on podgate"),
        "{}",
        watcher.report()
    );
}

// ---- the address rule ------------------------------------------------------------------------

fn labelled(name: &str, ip: &str, extra: &[(&str, &str)]) -> Ctr {
    Ctr::new(name)
        .network("podgate", ip)
        .labels(&[
            ("podgate.enable", "true"),
            ("podgate.host", "x.acme.test"),
            ("podgate.port", "8080"),
        ])
        .labels(extra)
}

#[tokio::test]
async fn label_address_rejected() {
    let docker = FakeDocker::start();
    docker.add(web("control", "10.4.0.1", "control.acme.test"));
    let bad: [(&str, &[(&str, &str)]); 8] = [
        (
            "servers",
            &[(
                "podgate.service.web.config",
                r#"{"servers": [{"url": "http://10.9.9.9:80"}]}"#,
            )],
        ),
        (
            "router-url",
            &[
                ("podgate.router.main.match", r#"{"host": "a.test"}"#),
                ("podgate.router.main.service", "http://10.9.9.9:80"),
            ],
        ),
        ("host-ip", &[("podgate.host", "10.9.9.9")]),
        (
            "nested-url",
            &[(
                "podgate.service.web.config",
                r#"{"health_check": {"path": "/", "url": "http://10.9.9.9/up"}}"#,
            )],
        ),
        (
            "socket-addr",
            &[(
                "podgate.service.web.config",
                r#"{"sticky": {"cookie": {"name": "10.9.9.9:80"}}}"#,
            )],
        ),
        (
            "forward-auth",
            &[
                ("podgate.middleware.auth.type", "forward_auth"),
                (
                    "podgate.middleware.auth.config",
                    r#"{"address": "http://auth.internal/verify"}"#,
                ),
            ],
        ),
        ("app-name", &[("podgate.app", "10.9.9.9")]),
        (
            "container",
            &[(
                "podgate.service.web.config",
                r#"{"upstream_container": "victim-1"}"#,
            )],
        ),
    ];
    for (index, (name, labels)) in bad.iter().enumerate() {
        docker.add(labelled(name, &format!("10.4.1.{}", index + 1), labels));
    }
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    watcher
        .wait_ids_and_report(&["control"], "container servers")
        .await;
    for (name, _) in bad {
        assert!(
            watcher.report().contains(&format!("container {name} ")),
            "{name} is not reported: {}",
            watcher.report()
        );
    }
    assert_eq!(
        watcher
            .report()
            .matches("names an address, a URL or a container")
            .count(),
        8,
        "every one of them is an address rejection: {}",
        watcher.report()
    );
}

#[tokio::test]
async fn unknown_podgate_label_rejects_container() {
    let docker = FakeDocker::start();
    docker
        .add(web("control", "10.4.0.1", "control.acme.test").label("com.example.anything", "goes"));
    docker.add(labelled("typo", "10.4.0.2", &[("podgate.hosts", "a.test")]));
    docker.add(labelled(
        "deep",
        "10.4.0.3",
        &[("podgate.router.main.rule", "Host(`a.test`)")],
    ));
    docker.add(labelled(
        "extra",
        "10.4.0.4",
        &[("podgate.port.http", "80")],
    ));
    docker.add(labelled(
        "bad-json",
        "10.4.0.5",
        &[("podgate.service.web.config", "{nope")],
    ));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    watcher
        .wait_ids_and_report(&["control"], "container typo")
        .await;
    let report = watcher.report().to_owned();
    for needle in [
        "unknown label podgate.hosts",
        "unknown label podgate.router.main.rule",
        "unknown label podgate.port.http",
        "not JSON",
    ] {
        assert!(report.contains(needle), "{needle} in {report}");
    }
}

#[tokio::test]
async fn label_pointing_at_other_tenants_container_rejected() {
    let docker = FakeDocker::start();
    let settings = "network = [\"net-a\", \"net-b\"]\ntenant_from = \"network\"\nnetwork_tenants = { net-a = \"acme\", net-b = \"globex\" }";
    // The victim: a service of tenant globex, reached by name through its network.
    docker.add(Ctr::new("victim-1").network("net-b", "10.5.0.2").labels(&[
        ("podgate.enable", "true"),
        ("podgate.app", "victim"),
        ("podgate.host", "victim.globex.test"),
        ("podgate.port", "80"),
    ]));
    let attacks: [(&str, &[(&str, &str)]); 5] = [
        (
            "other-app",
            &[
                ("podgate.router.main.match", r#"{"host": "mine.acme.test"}"#),
                ("podgate.router.main.service", "victim/web"),
            ],
        ),
        (
            "other-name",
            &[
                (
                    "podgate.router.main.match",
                    r#"{"host": "mine2.acme.test"}"#,
                ),
                ("podgate.router.main.service", "victim"),
            ],
        ),
        (
            "other-container",
            &[
                (
                    "podgate.router.main.match",
                    r#"{"host": "mine3.acme.test"}"#,
                ),
                ("podgate.router.main.service", "victim-1"),
            ],
        ),
        (
            "failover",
            &[(
                "podgate.service.web.config",
                r#"{"type": "failover", "service": "web", "fallback": "victim/web"}"#,
            )],
        ),
        (
            "chain",
            &[
                (
                    "podgate.router.main.match",
                    r#"{"host": "mine5.acme.test"}"#,
                ),
                ("podgate.router.main.chain", "victim/auth"),
            ],
        ),
    ];
    for (index, (name, labels)) in attacks.iter().enumerate() {
        let mut container = Ctr::new(name)
            .network("net-a", &format!("10.4.0.{}", index + 10))
            .labels(&[("podgate.enable", "true"), ("podgate.port", "80")])
            .labels(labels);
        if !name.starts_with("other") && *name != "chain" {
            container = container.label("podgate.host", "mine4.acme.test");
        }
        docker.add(container);
    }
    let mut watcher = Watcher::start(&docker_config(docker.path(), TENANTS, settings));
    watcher
        .wait_ids_and_report(&["victim"], "container other-app")
        .await;
    for (name, _) in attacks {
        assert!(
            watcher.report().contains(&format!("container {name} ")),
            "{name} is not reported: {}",
            watcher.report()
        );
    }
    let state = watcher.state.clone().expect("a state");
    assert_eq!(
        servers_of(&state, "victim", "default"),
        ["http://10.5.0.2:80"],
        "the victim keeps only its own container"
    );
    assert_eq!(
        app_of(&state, "victim").tenant.mapped.as_deref(),
        Some("globex")
    );
}

// ---- tenants ---------------------------------------------------------------------------------

#[tokio::test]
async fn label_cannot_claim_foreign_host() {
    let docker = FakeDocker::start();
    docker.add(web("mine", "10.4.0.1", "web.acme.test"));
    docker.add(web("theirs", "10.4.0.2", "globex.test"));
    // A tenant label does not help: the source only honours it in label mode.
    docker.add(web("sneaky", "10.4.0.3", "www.globex.test").label("podgate.tenant", "globex"));
    let config = docker_config(
        docker.path(),
        TENANTS,
        "network = \"podgate\"\ntenant = \"acme\"",
    );
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["mine", "sneaky", "theirs"]).await;
    assert_eq!(
        app_of(&state, "sneaky").tenant.label,
        None,
        "fixed mode ignores the label"
    );
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [("docker-mine".to_owned(), "acme".to_owned())]
    );
    let codes: Vec<&str> = finding_codes(&merged)
        .iter()
        .map(|(code, _)| *code)
        .collect();
    assert_eq!(codes, ["foreign_host_claim", "foreign_host_claim"]);
}

#[tokio::test]
async fn tenant_from_label_requires_trust() {
    let docker = FakeDocker::start();
    docker.add(web("shop", "10.4.0.1", "shop.globex.test").label("podgate.tenant", "globex"));
    let settings = "network = \"podgate\"\ntenant_from = \"label\"";

    let untrusted = docker_config(docker.path(), TENANTS, settings);
    let mut watcher = Watcher::start(&untrusted);
    let state = watcher.wait_ids(&["shop"]).await;
    assert_eq!(
        app_of(&state, "shop").tenant.label.as_deref(),
        Some("globex")
    );
    let merged = merge(&untrusted, UpstreamPolicy::builtin(), state);
    assert!(
        merged_apps(&merged).is_empty(),
        "{:?}",
        merged_apps(&merged)
    );
    let codes: Vec<&str> = finding_codes(&merged)
        .iter()
        .map(|(code, _)| *code)
        .collect();
    assert_eq!(
        codes,
        ["label_ignored", "foreign_host_claim"],
        "the label is ignored, and the default tenant may not take globex's host"
    );

    let trusted_tenants = TENANTS.replace(
        "hosts = [\"globex.test\", \"*.globex.test\"]",
        "hosts = [\"globex.test\", \"*.globex.test\"]\nlabel_sources = [\"docker\"]",
    );
    let trusted = docker_config(docker.path(), &trusted_tenants, settings);
    let mut watcher = Watcher::start(&trusted);
    let state = watcher.wait_ids(&["shop"]).await;
    let merged = merge(&trusted, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [("docker-shop".to_owned(), "globex".to_owned())],
        "a source the tenant trusts may name it"
    );
}

#[tokio::test]
async fn tenant_from_network_mapping() {
    let docker = FakeDocker::start();
    docker.add(Ctr::new("a-web").network("net-a", "10.4.0.2").labels(&[
        ("podgate.enable", "true"),
        ("podgate.host", "web.acme.test"),
        ("podgate.port", "80"),
        // Ignored: in network mode the network decides.
        ("podgate.tenant", "globex"),
    ]));
    docker.add(Ctr::new("b-web").network("net-b", "10.5.0.2").labels(&[
        ("podgate.enable", "true"),
        ("podgate.host", "web.globex.test"),
        ("podgate.port", "80"),
    ]));
    docker.add(
        Ctr::new("b-takeover")
            .network("net-b", "10.5.0.3")
            .labels(&[
                ("podgate.enable", "true"),
                ("podgate.host", "takeover.acme.test"),
                ("podgate.port", "80"),
            ]),
    );
    docker.add(
        Ctr::new("both")
            .network("net-a", "10.4.0.9")
            .network("net-b", "10.5.0.9")
            .labels(&[
                ("podgate.enable", "true"),
                ("podgate.host", "both.acme.test"),
                ("podgate.port", "80"),
            ]),
    );
    let settings = "network = [\"net-a\", \"net-b\"]\ntenant_from = \"network\"\nnetwork_tenants = { net-a = \"acme\", net-b = \"globex\" }";
    let config = docker_config(docker.path(), TENANTS, settings);
    let mut watcher = Watcher::start(&config);
    let state = watcher
        .wait_ids_and_report(&["a-web", "b-takeover", "b-web"], "container both")
        .await;
    assert!(
        watcher.report().contains("several tenants"),
        "{}",
        watcher.report()
    );
    assert_eq!(
        app_of(&state, "a-web").tenant.mapped.as_deref(),
        Some("acme")
    );
    assert_eq!(app_of(&state, "a-web").tenant.label, None);
    assert_eq!(
        app_of(&state, "b-web").tenant.mapped.as_deref(),
        Some("globex")
    );
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [
            ("docker-a-web".to_owned(), "acme".to_owned()),
            ("docker-b-web".to_owned(), "globex".to_owned()),
        ],
        "globex's container cannot claim acme's host from its own network"
    );
    assert_eq!(
        finding_codes(&merged)
            .iter()
            .map(|(code, _)| *code)
            .collect::<Vec<_>>(),
        ["foreign_host_claim"]
    );
}

#[tokio::test]
async fn upstream_outside_allowlist_rejected_docker() {
    let docker = FakeDocker::start();
    docker.add(web("inside", "10.4.0.1", "in.acme.test"));
    docker.add(web("outside", "10.5.0.1", "out.acme.test"));
    let config = docker_config(
        docker.path(),
        TENANTS,
        "network = \"podgate\"\ntenant = \"acme\"",
    );
    let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)
        .expect("policy");
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["inside", "outside"]).await;
    let merged = merge(&config, policy, state);
    assert_eq!(
        merged_apps(&merged),
        [("docker-inside".to_owned(), "acme".to_owned())]
    );
    let forbidden: Vec<String> = finding_codes(&merged)
        .into_iter()
        .filter(|(code, _)| *code == "upstream_forbidden")
        .map(|(_, object)| object)
        .collect();
    assert_eq!(forbidden, ["outside"]);
}

// ---- states, events and revisions ------------------------------------------------------------

#[tokio::test]
async fn only_running_healthy_containers() {
    let docker = FakeDocker::start();
    docker.add(web("plain", "10.4.0.1", "plain.acme.test"));
    docker.add(web("healthy", "10.4.0.2", "healthy.acme.test").health("healthy"));
    docker.add(web("starting", "10.4.0.3", "starting.acme.test").health("starting"));
    docker.add(web("unhealthy", "10.4.0.4", "unhealthy.acme.test").health("unhealthy"));
    docker.add(web("paused", "10.4.0.5", "paused.acme.test").status("paused"));
    docker.add(web("restarting", "10.4.0.6", "restarting.acme.test").status("restarting"));
    docker.add(web("exited", "10.4.0.7", "exited.acme.test").status("exited"));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    watcher.wait_ids(&["healthy", "plain"]).await;
    assert_eq!(
        watcher.report(),
        "",
        "containers that are not up are not an error"
    );

    // A container that turns healthy joins on the health event; one that stops leaves.
    wait_for_event_stream(&docker).await;
    docker.update("starting", |container| container.health = Some("healthy"));
    docker.emit(&docker.container_event("health_status: healthy", "starting"));
    watcher.wait_ids(&["healthy", "plain", "starting"]).await;
    docker.update("plain", |container| container.status = "exited");
    docker.emit(&docker.container_event("die", "plain"));
    watcher.wait_ids(&["healthy", "starting"]).await;
}

async fn wait_for_event_stream(docker: &FakeDocker) {
    let wait = async {
        while docker.event_streams() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(DEADLINE, wait)
        .await
        .expect("the source opens the event stream");
}

#[tokio::test]
async fn events_trigger_update() {
    let docker = FakeDocker::start();
    docker.add(web("first", "10.4.0.1", "first.acme.test"));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    watcher.wait_ids(&["first"]).await;
    wait_for_event_stream(&docker).await;

    docker.add(web("second", "10.4.0.2", "second.acme.test"));
    docker.emit(&docker.container_event("start", "second"));
    tokio::time::timeout(PROMPT, watcher.wait_ids(&["first", "second"]))
        .await
        .expect("a start event shows within the debounce window, not at the next resync");

    docker.remove("first");
    docker.emit(&docker.container_event("destroy", "first"));
    tokio::time::timeout(PROMPT, watcher.wait_ids(&["second"]))
        .await
        .expect("a destroy event removes the app");

    // Events that cannot change which containers serve do not cause a list.
    let lists = docker.lists();
    docker.emit(&json!({ "Type": "network", "Action": "connect" }));
    docker.emit(&json!({ "Type": "container", "Action": "exec_start: sh" }));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        docker.lists(),
        lists,
        "unrelated events are not a reason to list"
    );
}

/// A container of app `shop` in `revision`, serving `host` on the `podgate` network.
fn shop(name: &str, ip: &str, host: &str, revision: &str, state: &str, created: u32) -> Ctr {
    web(name, ip, host)
        .labels(&[
            ("podgate.app", "shop"),
            ("podgate.revision", revision),
            ("podgate.revision.state", state),
        ])
        .created_at(created)
}

#[tokio::test]
async fn revision_labels_produce_revisions() {
    let docker = FakeDocker::start();
    docker.add(shop(
        "shop-v0",
        "10.4.0.9",
        "shop.acme.test",
        "v0",
        "draining",
        0,
    ));
    // The old revision may carry older routing; the app's comes from the newest serving one.
    docker.add(shop(
        "shop-v1-a",
        "10.4.0.1",
        "old.acme.test",
        "v1",
        "retiring",
        1,
    ));
    docker.add(shop(
        "shop-v1-b",
        "10.4.0.2",
        "old.acme.test",
        "v1",
        "retiring",
        2,
    ));
    docker.add(shop(
        "shop-v2-a",
        "10.4.0.3",
        "shop.acme.test",
        "v2",
        "serving",
        10,
    ));
    docker.add(shop(
        "shop-v2-b",
        "10.4.0.4",
        "shop.acme.test",
        "v2",
        "serving",
        11,
    ));
    // Two containers of one revision must agree.
    docker.add(shop(
        "shop-v2-odd",
        "10.4.0.5",
        "odd.acme.test",
        "v2",
        "serving",
        12,
    ));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    let state = watcher
        .wait_ids_and_report(&["shop"], "container shop-v2-odd")
        .await;
    let app = app_json(&state, "shop");
    let revisions: Vec<(String, String, usize)> = app["revisions"]
        .as_array()
        .expect("revisions")
        .iter()
        .map(|rev| {
            (
                rev["id"].as_str().expect("id").to_owned(),
                rev["state"].as_str().expect("state").to_owned(),
                rev["services"][0]["servers"]
                    .as_array()
                    .expect("servers")
                    .len(),
            )
        })
        .collect();
    assert_eq!(
        revisions,
        [
            ("v0".to_owned(), "draining".to_owned(), 1),
            ("v1".to_owned(), "retiring".to_owned(), 2),
            ("v2".to_owned(), "serving".to_owned(), 2),
        ]
    );
    assert_eq!(
        app["routers"][0]["match"],
        json!({ "host": ["shop.acme.test"] }),
        "the routing is the newest serving revision's"
    );
    assert!(
        watcher.report().contains("differ from shop-v2-a"),
        "{}",
        watcher.report()
    );
}

#[tokio::test]
async fn revision_missing_a_service_is_rejected() {
    let docker = FakeDocker::start();
    docker.add(shop(
        "shop-v1",
        "10.4.0.1",
        "shop.acme.test",
        "v1",
        "serving",
        1,
    ));
    docker.add(shop(
        "shop-v2",
        "10.4.0.2",
        "shop.acme.test",
        "v2",
        "serving",
        20,
    ));
    docker.update("shop-v2", |c| {
        c.labels.remove("podgate.host");
        c.labels.insert(
            "podgate.router.main.match".into(),
            r#"{"host": "shop.acme.test"}"#.into(),
        );
        c.labels
            .insert("podgate.router.main.service".into(), "api".into());
        c.labels
            .insert("podgate.service.api.config".into(), "{}".into());
    });
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    let state = watcher
        .wait_ids_and_report(&["shop"], "container shop-v1")
        .await;
    assert!(
        watcher.report().contains("defines no service \"api\""),
        "{}",
        watcher.report()
    );
    assert_eq!(
        app_json(&state, "shop")["revisions"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "a revision without the route cannot stand next to the one that has it"
    );
    assert_eq!(servers_of(&state, "shop", "v2"), ["http://10.4.0.2:8080"]);
}

#[tokio::test]
async fn revision_labels_rolling_deploy() {
    let docker = FakeDocker::start();
    docker.add(shop(
        "shop-v1",
        "10.4.0.1",
        "shop.acme.test",
        "v1",
        "serving",
        1,
    ));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    let state = watcher.wait_ids(&["shop"]).await;
    assert_eq!(servers_of(&state, "shop", "v1"), ["http://10.4.0.1:8080"]);
    wait_for_event_stream(&docker).await;

    docker.add(shop(
        "shop-v2",
        "10.4.0.2",
        "shop.acme.test",
        "v2",
        "serving",
        20,
    ));
    docker.emit(&docker.container_event("start", "shop-v2"));
    watcher
        .until("two serving revisions", |state, _| {
            state.is_some_and(|state| {
                app_json(state, "shop")["revisions"]
                    .as_array()
                    .is_some_and(|r| r.len() == 2)
            })
        })
        .await;
    docker.remove("shop-v1");
    docker.add(shop(
        "shop-v1",
        "10.4.0.1",
        "shop.acme.test",
        "v1",
        "retiring",
        1,
    ));
    docker.emit(&docker.container_event("start", "shop-v1"));
    watcher
        .until("v1 retiring", |state, _| {
            state.is_some_and(|state| {
                let app = app_json(state, "shop");
                app["revisions"].as_array().is_some_and(|revs| {
                    revs.iter()
                        .any(|r| r["id"] == "v1" && r["state"] == "retiring")
                })
            })
        })
        .await;
}

// ---- Podman, outages, GET only ---------------------------------------------------------------

#[tokio::test]
async fn podman_api_shape() {
    let docker = FakeDocker::start_as(Flavor::Podman);
    docker.add(web("web", "10.88.0.5", "web.acme.test").created_at(0));
    // No labels at all (Podman sends `null`), and a container with a health check.
    docker.add(Ctr::new("bare").network("podgate", "10.88.0.6"));
    docker.add(web("checked", "10.88.0.7", "checked.acme.test").health("healthy"));
    docker.add(web("waiting", "10.88.0.8", "waiting.acme.test").health("starting"));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    let state = watcher.wait_ids(&["checked", "web"]).await;
    assert_eq!(
        servers_of(&state, "web", "default"),
        ["http://10.88.0.5:8080"]
    );
    assert_eq!(
        app_of(&state, "web").origin.first_seen,
        1_795_168_800,
        "the offset timestamp is read"
    );
    wait_for_event_stream(&docker).await;
    docker.update("waiting", |container| container.health = Some("healthy"));
    docker.emit(&docker.container_event("health_status", "waiting"));
    tokio::time::timeout(PROMPT, watcher.wait_ids(&["checked", "waiting", "web"]))
        .await
        .expect("a Podman health event shows");
}

#[tokio::test]
async fn daemon_unreachable_keeps_last_state() {
    let docker = FakeDocker::start();
    docker.add(web("first", "10.4.0.1", "first.acme.test"));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    watcher.wait_ids(&["first"]).await;
    wait_for_event_stream(&docker).await;

    docker.stop();
    watcher.wait_outage("cannot connect").await;
    assert_eq!(
        ids(watcher.state.as_ref().expect("the last state stays")),
        ["first"],
        "an outage is not an empty state"
    );

    docker.add(web("second", "10.4.0.2", "second.acme.test"));
    docker.restart();
    watcher.wait_ids(&["first", "second"]).await;
    assert_eq!(watcher.report(), "", "the next state clears the outage");
}

#[tokio::test]
async fn daemon_down_at_start_sends_no_state() {
    let docker = FakeDocker::start();
    docker.add(web("first", "10.4.0.1", "first.acme.test"));
    docker.stop();
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    watcher.wait_outage("cannot connect").await;
    assert!(watcher.state.is_none(), "no state before a complete list");
    docker.restart();
    watcher.wait_ids(&["first"]).await;
}

#[tokio::test]
async fn client_only_issues_get() {
    let docker = FakeDocker::start();
    docker.set_networks(&["podgate"]);
    docker.add(web("first", "10.4.0.1", "first.acme.test"));
    let mut watcher = Watcher::start(&docker_config(docker.path(), "", "network = \"podgate\""));
    watcher.wait_ids(&["first"]).await;
    wait_for_event_stream(&docker).await;
    docker.add(web("second", "10.4.0.2", "second.acme.test"));
    docker.emit(&docker.container_event("start", "second"));
    watcher.wait_ids(&["first", "second"]).await;

    let requests = docker.requests();
    assert!(
        requests.iter().all(|(method, _)| method == "GET"),
        "{requests:?}"
    );
    let paths: BTreeSet<String> = requests
        .iter()
        .map(|(_, path)| path.split('?').next().unwrap_or_default().to_owned())
        .collect();
    let id = |name: &str| Ctr::new(name).id;
    let expected: BTreeSet<String> = [
        "/containers/json".to_owned(),
        format!("/containers/{}/json", id("first")),
        format!("/containers/{}/json", id("second")),
        "/networks".to_owned(),
        "/events".to_owned(),
    ]
    .into();
    assert_eq!(
        paths, expected,
        "the list, the inspects, the networks and the events"
    );
}

// ---- configuration ---------------------------------------------------------------------------

#[test]
fn docker_config_is_strict() {
    let parse = |text: &str| {
        let config = Config::parse(&format!(
            "admin_socket = \"/x\"\n[[source]]\nkind = \"docker\"\nname = \"d\"\n{text}"
        ))
        .expect("config");
        DockerSource::from_config(&config.sources[0])
    };
    assert!(parse("network = \"podgate\"").is_ok());
    assert!(parse("network = [\"a\", \"b\"]\nsocket = \"/run/podman/podman.sock\"").is_ok());
    assert!(parse("").is_err(), "network is required");
    assert!(parse("network = []").is_err());
    let unknown = parse("network = \"a\"\nexpose = true").expect_err("unknown key");
    assert!(unknown.reason.contains("expose"), "{unknown}");
    assert!(parse("network = \"a\"\ntenant_from = \"pod\"").is_err());
    assert!(parse("network = \"a\"\nnetwork_tenants = { a = \"x\" }").is_err());
    assert!(parse("network = \"a\"\ntenant_from = \"network\"").is_err());
    let partial = parse(
        "network = [\"a\", \"b\"]\ntenant_from = \"network\"\nnetwork_tenants = { a = \"x\" }",
    )
    .expect_err("b has no tenant");
    assert!(partial.reason.contains("network_tenants"), "{partial}");
    assert!(parse("network = \"a\"\nresync_secs = 0").is_err());
}
