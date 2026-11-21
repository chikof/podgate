//! Black-box tests of the Docker Swarm source against a fake manager on a unix socket
//! (`tests/common/swarm.rs`): labels, task and virtual-IP addresses, task states, tenants,
//! events, outages and how its objects fare in the merge. Everything that waits has a deadline.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use common::swarm::{FakeSwarm, Svc, Tsk};
use common::{DEADLINE, config};
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::swarm::SwarmSource;
use podgate_provider::{Config, Merged, Merger, UpstreamPolicy};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// An event must show within the source's quiet window plus scheduling slack, far below the hour
/// the tests give `refresh_secs`.
const PROMPT: Duration = Duration::from_secs(4);

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
"#;

/// Polling and resync so far apart that only events (or a test that asks for it) refresh.
const SLOW: &str = "refresh_secs = 3600\nresync_secs = 7200\n";

/// The configuration with one swarm source named `swarm` after `tenants`, and `settings` as the
/// source's own keys.
fn swarm_config(socket: &Path, tenants: &str, settings: &str) -> Config {
    config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{tenants}\n[[source]]\nkind = \"swarm\"\nname = \"swarm\"\nsocket = {:?}\n{settings}\n",
            socket.display().to_string()
        ),
    )
}

/// The common case: slow polling and `network = "podgate"` plus `extra` keys.
fn slow(socket: &Path, extra: &str) -> Config {
    swarm_config(socket, "", &format!("{SLOW}network = \"podgate\"\n{extra}"))
}

fn source_of(config: &Config) -> SwarmSource {
    SwarmSource::from_config(&config.sources[0]).expect("a valid swarm source")
}

/// A running swarm source and what it has said so far.
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
                assert_eq!(&*update.source, "swarm");
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

    /// Waits until the servers of `app`'s default revision are `expected`.
    async fn wait_servers(&mut self, app: &str, expected: &[&str]) -> State {
        let expected: Vec<String> = expected.iter().map(|url| (*url).to_owned()).collect();
        self.until(&format!("servers {expected:?} of {app}"), |state, _| {
            state.is_some_and(|state| {
                state.apps.iter().any(|a| &*a.app.id == app)
                    && servers_of(state, app, "default") == expected
            })
        })
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

/// The app without `tenant` and `declared_by`: placeholders that the core overwrites, and that
/// the tenant claim next to the app already covers.
fn without_placeholders(mut app: Value) -> Value {
    if let Some(object) = app.as_object_mut() {
        object.remove("tenant");
        object.remove("declared_by");
    }
    app
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

/// A service that serves `host` on port 8080.
fn web(name: &str, host: &str) -> Svc {
    Svc::new(name).labels(&[
        ("podgate.enable", "true"),
        ("podgate.host", host),
        ("podgate.port", "8080"),
    ])
}

/// The task of `service` in `slot` with `ip` on the `podgate` network and an address on the
/// engine's `ingress` network that must never be used.
fn task(service: &str, slot: u64, ip: &str) -> Tsk {
    Tsk::new(service, slot)
        .network("ingress", &format!("10.255.0.{}", slot + 100))
        .network("podgate", ip)
}

/// A service with one running task on the `podgate` network.
fn deployed(swarm: &FakeSwarm, service: Svc, ip: &str) {
    let name = service.name.clone();
    swarm.add_service(service);
    swarm.add_task(task(&name, 1, ip));
}

fn merge(config: &Config, policy: UpstreamPolicy, state: State) -> Merged {
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("swarm".into(), state)]);
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

async fn wait_for_event_stream(swarm: &FakeSwarm) {
    let wait = async {
        while swarm.event_streams() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(DEADLINE, wait)
        .await
        .expect("the source opens the event stream");
}

// ---- services to apps ------------------------------------------------------------------------

#[tokio::test]
async fn swarm_services_to_apps() {
    let swarm = FakeSwarm::start();
    swarm.add_service(
        web("shop_web", "shop.acme.test, www.shop.acme.test")
            .label("com.docker.stack.namespace", "shop")
            .created_at(7),
    );
    swarm.add_task(task("shop_web", 1, "10.4.0.5"));
    swarm.add_task(task("shop_web", 2, "10.4.0.6"));
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    let state = watcher.wait_ids(&["shop_web"]).await;
    let app = app_of(&state, "shop_web");
    assert_eq!(&*app.origin.object, "shop_web");
    assert_eq!(
        app.origin.first_seen, 1_795_168_807,
        "the service's own creation time, not when the source saw it"
    );
    assert_eq!(app.tenant.mapped.as_deref(), Some("default"));
    assert_eq!(app.tenant.label, None);
    assert_eq!(
        without_placeholders(app_json(&state, "shop_web")),
        json!({
            "id": "shop_web",
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
                    "servers": [
                        { "url": "http://10.4.0.5:8080" },
                        { "url": "http://10.4.0.6:8080" },
                    ],
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
    assert_eq!(watcher.report(), "");
}

#[tokio::test]
async fn swarm_services_of_one_app_share_it() {
    let swarm = FakeSwarm::start();
    for (name, seconds, ip) in [("shop_a", 9, "10.4.0.5"), ("shop_b", 3, "10.4.0.6")] {
        deployed(
            &swarm,
            web(name, "shop.acme.test")
                .label("podgate.app", "shop")
                .created_at(seconds),
            ip,
        );
    }
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    let state = watcher.wait_ids(&["shop"]).await;
    assert_eq!(
        servers_of(&state, "shop", "default"),
        ["http://10.4.0.5:8080", "http://10.4.0.6:8080"]
    );
    assert_eq!(
        app_of(&state, "shop").origin.first_seen,
        1_795_168_803,
        "the oldest service's creation time"
    );
}

#[tokio::test]
async fn exposed_by_default_false() {
    let swarm = FakeSwarm::start();
    deployed(
        &swarm,
        Svc::new("quiet")
            .label("podgate.host", "quiet.acme.test")
            .label("podgate.port", "80"),
        "10.4.0.1",
    );
    deployed(
        &swarm,
        web("hidden", "hidden.acme.test").label("podgate.enable", "false"),
        "10.4.0.2",
    );
    deployed(&swarm, web("shown", "shown.acme.test"), "10.4.0.3");
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    watcher.wait_ids(&["shown"]).await;
    assert_eq!(
        watcher.report(),
        "",
        "a service that is not exposed is quiet"
    );

    let swarm = FakeSwarm::start();
    deployed(
        &swarm,
        Svc::new("quiet")
            .label("podgate.host", "quiet.acme.test")
            .label("podgate.port", "80"),
        "10.4.0.1",
    );
    deployed(
        &swarm,
        web("hidden", "hidden.acme.test").label("traefik.enable", "false"),
        "10.4.0.2",
    );
    let mut watcher = Watcher::start(&slow(swarm.path(), "exposed_by_default = true"));
    watcher.wait_ids(&["quiet"]).await;
}

// ---- the address rule ------------------------------------------------------------------------

#[tokio::test]
async fn swarm_task_addresses_on_network() {
    let swarm = FakeSwarm::start();
    swarm.set_networks(&["podgate", "ingress", "other"]);
    swarm.add_service(web("shop", "shop.acme.test"));
    swarm.add_task(task("shop", 1, "10.4.0.5"));
    swarm.add_task(task("shop", 2, "10.4.0.6").network("other", "10.9.0.6"));
    // A task of another service must not leak into this one.
    swarm.add_service(web("other", "other.acme.test"));
    swarm.add_task(task("other", 1, "10.4.0.7"));
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    let state = watcher.wait_ids(&["other", "shop"]).await;
    assert_eq!(
        servers_of(&state, "shop", "default"),
        ["http://10.4.0.5:8080", "http://10.4.0.6:8080"],
        "one server per running task, on the configured network"
    );
    assert_eq!(
        servers_of(&state, "other", "default"),
        ["http://10.4.0.7:8080"]
    );
    assert_eq!(watcher.report(), "");

    // A network that is not the configured one never gives an address.
    let swarm = FakeSwarm::start();
    swarm.add_service(web("shop", "shop.acme.test"));
    swarm.add_task(Tsk::new("shop", 1).network("other", "10.9.0.5"));
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    watcher
        .wait_ids_and_report(&[], "no address on podgate")
        .await;
}

#[tokio::test]
async fn swarm_vip_mode() {
    let swarm = FakeSwarm::start();
    swarm.set_networks(&["podgate", "ingress"]);
    swarm.add_service(
        web("shop", "shop.acme.test")
            .vip("ingress", "10.255.0.9")
            .vip("podgate", "10.4.0.100"),
    );
    swarm.add_task(task("shop", 1, "10.4.0.5"));
    swarm.add_task(task("shop", 2, "10.4.0.6"));
    // dnsrr: no virtual IP, so no server in this mode.
    swarm.add_service(web("rr", "rr.acme.test"));
    swarm.add_task(task("rr", 1, "10.4.0.7"));
    // Scaled to zero: a virtual IP nobody answers on is no server.
    swarm.add_service(web("idle", "idle.acme.test").vip("podgate", "10.4.0.101"));
    let mut watcher = Watcher::start(&slow(swarm.path(), "endpoint = \"vip\""));
    let state = watcher.wait_ids_and_report(&["shop"], "service rr ").await;
    assert_eq!(
        servers_of(&state, "shop", "default"),
        ["http://10.4.0.100:8080"],
        "the virtual IP on the configured network, no task address and no other network's"
    );
    assert!(
        watcher.report().contains("no virtual IP on podgate"),
        "{}",
        watcher.report()
    );
    assert!(
        !watcher.report().contains("service idle"),
        "a service without tasks is quiet: {}",
        watcher.report()
    );

    // A proxy that hides /networks: the ids come from the tasks' attachments.
    let hidden = FakeSwarm::start();
    hidden.refuse("/networks");
    hidden.add_service(web("shop", "shop.acme.test").vip("podgate", "10.4.0.100"));
    hidden.add_task(task("shop", 1, "10.4.0.5"));
    let mut watcher = Watcher::start(&slow(hidden.path(), "endpoint = \"vip\""));
    let state = watcher.wait_ids(&["shop"]).await;
    assert_eq!(
        servers_of(&state, "shop", "default"),
        ["http://10.4.0.100:8080"]
    );
}

#[tokio::test]
async fn swarm_only_running_healthy_tasks() {
    let swarm = FakeSwarm::start();
    swarm.add_service(web("shop", "shop.acme.test"));
    for (slot, state, health, ip) in [
        (1, "running", None, "10.4.0.1"),
        (2, "running", Some("healthy"), "10.4.0.2"),
        (3, "running", Some("unhealthy"), "10.4.0.3"),
        (4, "running", Some("starting"), "10.4.0.4"),
        (5, "starting", None, "10.4.0.5"),
        (6, "preparing", None, "10.4.0.6"),
        (7, "failed", None, "10.4.0.7"),
        (8, "shutdown", None, "10.4.0.8"),
        (9, "complete", None, "10.4.0.9"),
        (10, "rejected", None, "10.4.0.10"),
    ] {
        let mut t = task("shop", slot, ip).state(state);
        if let Some(health) = health {
            t = t.health(health);
        }
        swarm.add_task(t);
    }
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    let state = watcher.wait_ids(&["shop"]).await;
    assert_eq!(
        servers_of(&state, "shop", "default"),
        ["http://10.4.0.1:8080", "http://10.4.0.2:8080"]
    );
    assert_eq!(
        watcher.report(),
        "",
        "tasks that are not up are not an error"
    );

    // A task that turns running joins on the service event; one that fails leaves.
    wait_for_event_stream(&swarm).await;
    swarm.update_task("shop", 5, |t| t.state = "running");
    swarm.emit(&swarm.service_event("update", "shop"));
    watcher
        .wait_servers(
            "shop",
            &[
                "http://10.4.0.1:8080",
                "http://10.4.0.2:8080",
                "http://10.4.0.5:8080",
            ],
        )
        .await;
    swarm.update_task("shop", 1, |t| t.state = "failed");
    swarm.emit(&swarm.service_event("update", "shop"));
    watcher
        .wait_servers("shop", &["http://10.4.0.2:8080", "http://10.4.0.5:8080"])
        .await;
}

#[tokio::test]
async fn swarm_task_without_network_address_reported() {
    let swarm = FakeSwarm::start();
    swarm.add_service(web("shop", "shop.acme.test"));
    swarm.add_task(task("shop", 1, "10.4.0.5"));
    swarm.add_task(Tsk::new("shop", 2).network("other", "10.9.0.6"));
    swarm.add_task(Tsk::new("shop", 3).network("podgate", ""));
    swarm.add_task(Tsk::new("shop", 4));
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    let state = watcher.wait_ids_and_report(&["shop"], "task shop.2").await;
    assert_eq!(
        servers_of(&state, "shop", "default"),
        ["http://10.4.0.5:8080"],
        "the other tasks are left out"
    );
    for slot in [2, 3, 4] {
        assert!(
            watcher
                .report()
                .contains(&format!("task shop.{slot}: skipped: no address on podgate")),
            "{}",
            watcher.report()
        );
    }
    assert!(
        watcher.report().contains("attached to [\"other\"]"),
        "the report names where the task is attached: {}",
        watcher.report()
    );
}

#[tokio::test]
async fn swarm_down_node_tasks_not_served() {
    let swarm = FakeSwarm::start();
    swarm.set_nodes(&[("node-1", "ready"), ("node-2", "ready")]);
    swarm.add_service(web("shop", "shop.acme.test"));
    swarm.add_task(task("shop", 1, "10.4.0.5"));
    swarm.add_task(task("shop", 2, "10.4.0.6").node("node-2"));
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    watcher
        .wait_servers("shop", &["http://10.4.0.5:8080", "http://10.4.0.6:8080"])
        .await;
    wait_for_event_stream(&swarm).await;

    // The tasks of a lost node keep the state they had until the orchestrator replaces them.
    swarm.set_nodes(&[("node-1", "ready"), ("node-2", "down")]);
    swarm.emit(&json!({ "Type": "node", "Action": "update" }));
    watcher
        .until(
            "the task of the down node is gone and reported",
            |state, outage| {
                state.is_some_and(|state| {
                    servers_of(state, "shop", "default") == ["http://10.4.0.5:8080"]
                }) && outage.is_some_and(|why| why.contains("its node node-2 is not ready"))
            },
        )
        .await;
}

#[tokio::test]
async fn swarm_refused_optional_lists_are_not_an_outage() {
    let swarm = FakeSwarm::start();
    swarm.refuse("/nodes");
    swarm.refuse("/networks");
    deployed(&swarm, web("shop", "shop.acme.test"), "10.4.0.5");
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    watcher.wait_ids(&["shop"]).await;
    assert_eq!(watcher.report(), "");

    let swarm = FakeSwarm::start();
    swarm.refuse("/tasks");
    deployed(&swarm, web("shop", "shop.acme.test"), "10.4.0.5");
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    watcher.wait_outage("403").await;
    assert!(
        watcher.state.is_none(),
        "services and tasks are required: no state without them"
    );
}

// ---- rolling updates, scaling and events -----------------------------------------------------

#[tokio::test]
async fn swarm_rolling_update_follows_tasks() {
    let swarm = FakeSwarm::start();
    swarm.add_service(web("shop", "shop.acme.test"));
    let old1 = task("shop", 1, "10.4.0.5");
    let old2 = task("shop", 2, "10.4.0.6");
    swarm.add_task(old1.clone());
    swarm.add_task(old2.clone());
    // Polling only: the update is followed without an event.
    let mut watcher = Watcher::start(&swarm_config(
        swarm.path(),
        "",
        "network = \"podgate\"\nrefresh_secs = 1\nresync_secs = 3600\n",
    ));
    watcher
        .wait_servers("shop", &["http://10.4.0.5:8080", "http://10.4.0.6:8080"])
        .await;

    // The replacement of slot 1 starts; the old task is told to stop but still runs.
    swarm.update_task("shop", 1, |t| t.desired = "shutdown");
    let new1 = task("shop", 1, "10.4.0.7").generation(1);
    swarm.add_task(new1.clone());
    watcher
        .wait_servers(
            "shop",
            &[
                "http://10.4.0.5:8080",
                "http://10.4.0.6:8080",
                "http://10.4.0.7:8080",
            ],
        )
        .await;
    // The old task of slot 1 stops: it leaves, and only then.
    swarm.remove_task(&old1);
    swarm.add_task(old1.clone().state("shutdown").desired("shutdown"));
    watcher
        .wait_servers("shop", &["http://10.4.0.6:8080", "http://10.4.0.7:8080"])
        .await;
    // Slot 2 follows.
    let new2 = task("shop", 2, "10.4.0.8").generation(1);
    swarm.add_task(new2.clone());
    swarm.remove_task(&old2);
    swarm.add_task(old2.state("complete").desired("shutdown"));
    watcher
        .wait_servers("shop", &["http://10.4.0.7:8080", "http://10.4.0.8:8080"])
        .await;
    // Scaling down to nothing drops the app, with no report.
    swarm.remove_task(&new1);
    swarm.remove_task(&new2);
    watcher.wait_ids(&[]).await;
    assert_eq!(watcher.report(), "");
}

#[tokio::test]
async fn swarm_events_trigger_refresh() {
    let swarm = FakeSwarm::start();
    deployed(&swarm, web("first", "first.acme.test"), "10.4.0.1");
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    watcher.wait_ids(&["first"]).await;
    wait_for_event_stream(&swarm).await;

    deployed(&swarm, web("second", "second.acme.test"), "10.4.0.2");
    swarm.emit(&swarm.service_event("create", "second"));
    tokio::time::timeout(PROMPT, watcher.wait_ids(&["first", "second"]))
        .await
        .expect("a create event shows within the debounce window, not at the next poll");

    swarm.remove_service("first");
    swarm.emit(&swarm.service_event("remove", "first"));
    tokio::time::timeout(PROMPT, watcher.wait_ids(&["second"]))
        .await
        .expect("a remove event removes the app");

    let settle = async {
        let mut last = swarm.lists();
        let mut since = Instant::now();
        while since.elapsed() < Duration::from_millis(150) {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let now = swarm.lists();
            if now != last {
                last = now;
                since = Instant::now();
            }
        }
    };
    tokio::time::timeout(DEADLINE, settle)
        .await
        .expect("the list count settles");
    // Events that cannot change which tasks serve do not cause a refresh.
    let lists = swarm.lists();
    swarm.emit(&json!({ "Type": "network", "Action": "connect" }));
    swarm.emit(&json!({ "Type": "container", "Action": "start" }));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        swarm.lists(),
        lists,
        "unrelated events are not a reason to refresh"
    );
}

#[tokio::test]
async fn swarm_manager_outage_keeps_last_state() {
    let swarm = FakeSwarm::start();
    deployed(&swarm, web("first", "first.acme.test"), "10.4.0.1");
    let mut watcher = Watcher::start(&swarm_config(
        swarm.path(),
        "",
        "network = \"podgate\"\nrefresh_secs = 1\nresync_secs = 3600\n",
    ));
    watcher.wait_ids(&["first"]).await;
    wait_for_event_stream(&swarm).await;

    swarm.stop();
    watcher.wait_outage("cannot connect").await;
    assert_eq!(
        ids(watcher.state.as_ref().expect("the last state stays")),
        ["first"],
        "an outage is not an empty state"
    );

    deployed(&swarm, web("second", "second.acme.test"), "10.4.0.2");
    swarm.restart();
    watcher.wait_ids(&["first", "second"]).await;
    assert_eq!(watcher.report(), "", "the next state clears the outage");

    // Down at start: no state before a complete read.
    let down = FakeSwarm::start();
    deployed(&down, web("first", "first.acme.test"), "10.4.0.1");
    down.stop();
    let mut watcher = Watcher::start(&slow(down.path(), ""));
    watcher.wait_outage("cannot connect").await;
    assert!(watcher.state.is_none());
    down.restart();
    watcher.wait_ids(&["first"]).await;
}

// ---- labels ----------------------------------------------------------------------------------

#[tokio::test]
async fn swarm_labels_from_service_not_container() {
    let swarm = FakeSwarm::start();
    // The deployer's labels are on the service; the container labels are the image author's and
    // are not read, however loud: they would reject the service if they were.
    deployed(
        &swarm,
        web("shop", "shop.acme.test")
            .container_label("podgate.hosts", "typo")
            .container_label("podgate.host", "evil.acme.test")
            .container_label(
                "podgate.service.web.config",
                r#"{"servers": [{"url": "http://10.9.9.9:80"}]}"#,
            ),
        "10.4.0.5",
    );
    // Labels on the container only: not exposed, and no report either.
    deployed(
        &swarm,
        Svc::new("image-labelled")
            .container_label("podgate.enable", "true")
            .container_label("podgate.host", "evil.acme.test")
            .container_label("podgate.port", "80"),
        "10.4.0.6",
    );
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    let state = watcher.wait_ids(&["shop"]).await;
    assert_eq!(
        app_json(&state, "shop")["routers"][0]["match"],
        json!({ "host": ["shop.acme.test"] })
    );
    assert_eq!(watcher.report(), "");

    // Even with exposed_by_default the container labels give the service no route.
    let mut watcher = Watcher::start(&slow(swarm.path(), "exposed_by_default = true"));
    watcher
        .wait_ids_and_report(&["shop"], "service image-labelled")
        .await;
    assert!(
        watcher.report().contains("no router"),
        "{}",
        watcher.report()
    );
}

/// A service on the `podgate` network that serves `x.acme.test`, plus `extra` labels.
fn labelled(swarm: &FakeSwarm, name: &str, ip: &str, extra: &[(&str, &str)]) {
    deployed(
        swarm,
        Svc::new(name)
            .labels(&[
                ("podgate.enable", "true"),
                ("podgate.host", "x.acme.test"),
                ("podgate.port", "8080"),
            ])
            .labels(extra),
        ip,
    );
}

#[tokio::test]
async fn swarm_unknown_label_rejected() {
    let swarm = FakeSwarm::start();
    deployed(&swarm, web("control", "control.acme.test"), "10.4.0.1");
    labelled(&swarm, "typo", "10.4.0.2", &[("podgate.hosts", "a.test")]);
    labelled(
        &swarm,
        "deep",
        "10.4.0.3",
        &[("podgate.router.main.rule", "Host(`a.test`)")],
    );
    labelled(&swarm, "extra", "10.4.0.4", &[("podgate.port.http", "80")]);
    labelled(
        &swarm,
        "bad-json",
        "10.4.0.5",
        &[("podgate.service.web.config", "{nope")],
    );
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    watcher
        .wait_ids_and_report(&["control"], "service typo")
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
async fn swarm_label_address_rejected() {
    let swarm = FakeSwarm::start();
    deployed(&swarm, web("control", "control.acme.test"), "10.4.0.1");
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
            "task-ref",
            &[(
                "podgate.service.web.config",
                r#"{"upstream_container": "victim_web.1"}"#,
            )],
        ),
    ];
    for (index, (name, labels)) in bad.iter().enumerate() {
        labelled(&swarm, name, &format!("10.4.1.{}", index + 1), labels);
    }
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    watcher
        .wait_ids_and_report(&["control"], "service servers")
        .await;
    for (name, _) in bad {
        assert!(
            watcher.report().contains(&format!("service {name} ")),
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
async fn swarm_label_other_apps_service_rejected() {
    let swarm = FakeSwarm::start();
    let settings = "network = [\"net-a\", \"net-b\"]\ntenant_from = \"network\"\nnetwork_tenants = { net-a = \"acme\", net-b = \"globex\" }";
    // The victim: a service of tenant globex, named by its own app id and its service name.
    swarm.add_service(Svc::new("victim_web").labels(&[
        ("podgate.enable", "true"),
        ("podgate.app", "victim"),
        ("podgate.host", "victim.globex.test"),
        ("podgate.port", "80"),
    ]));
    swarm.add_task(Tsk::new("victim_web", 1).network("net-b", "10.5.0.2"));
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
            "other-service",
            &[
                (
                    "podgate.router.main.match",
                    r#"{"host": "mine3.acme.test"}"#,
                ),
                ("podgate.router.main.service", "victim_web"),
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
        let mut service = Svc::new(name)
            .labels(&[("podgate.enable", "true"), ("podgate.port", "80")])
            .labels(labels);
        if !name.starts_with("other") && *name != "chain" {
            service = service.label("podgate.host", "mine4.acme.test");
        }
        swarm.add_service(service);
        swarm.add_task(Tsk::new(name, 1).network("net-a", &format!("10.4.0.{}", index + 10)));
    }
    let mut watcher = Watcher::start(&swarm_config(
        swarm.path(),
        TENANTS,
        &format!("{SLOW}{settings}"),
    ));
    watcher
        .wait_ids_and_report(&["victim"], "service other-app")
        .await;
    for (name, _) in attacks {
        assert!(
            watcher.report().contains(&format!("service {name} ")),
            "{name} is not reported: {}",
            watcher.report()
        );
    }
    let state = watcher.state.clone().expect("a state");
    assert_eq!(
        servers_of(&state, "victim", "default"),
        ["http://10.5.0.2:80"],
        "the victim keeps only its own task"
    );
    assert_eq!(
        app_of(&state, "victim").tenant.mapped.as_deref(),
        Some("globex")
    );
}

// ---- tenants ---------------------------------------------------------------------------------

#[tokio::test]
async fn swarm_label_cannot_claim_foreign_host() {
    let swarm = FakeSwarm::start();
    deployed(&swarm, web("mine", "web.acme.test"), "10.4.0.1");
    deployed(&swarm, web("theirs", "globex.test"), "10.4.0.2");
    // A tenant label does not help: the source only honours it in label mode.
    deployed(
        &swarm,
        web("sneaky", "www.globex.test").label("podgate.tenant", "globex"),
        "10.4.0.3",
    );
    let config = swarm_config(
        swarm.path(),
        TENANTS,
        &format!("{SLOW}network = \"podgate\"\ntenant = \"acme\""),
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
        [("swarm-mine".to_owned(), "acme".to_owned())]
    );
    let codes: Vec<&str> = finding_codes(&merged)
        .iter()
        .map(|(code, _)| *code)
        .collect();
    assert_eq!(codes, ["foreign_host_claim", "foreign_host_claim"]);
}

#[tokio::test]
async fn swarm_tenant_label_requires_trust() {
    let swarm = FakeSwarm::start();
    deployed(
        &swarm,
        web("shop", "shop.globex.test").label("podgate.tenant", "globex"),
        "10.4.0.1",
    );
    let settings = format!("{SLOW}network = \"podgate\"\ntenant_from = \"label\"");

    let untrusted = swarm_config(swarm.path(), TENANTS, &settings);
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
        "hosts = [\"globex.test\", \"*.globex.test\"]\nlabel_sources = [\"swarm\"]",
    );
    let trusted = swarm_config(swarm.path(), &trusted_tenants, &settings);
    let mut watcher = Watcher::start(&trusted);
    let state = watcher.wait_ids(&["shop"]).await;
    let merged = merge(&trusted, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [("swarm-shop".to_owned(), "globex".to_owned())],
        "a source the tenant trusts may name it"
    );
}

#[tokio::test]
async fn swarm_tenant_from_network() {
    let swarm = FakeSwarm::start();
    let on = |name: &str, host: &str, networks: &[(&str, &str)], extra: &[(&str, &str)]| {
        swarm.add_service(
            Svc::new(name)
                .labels(&[
                    ("podgate.enable", "true"),
                    ("podgate.host", host),
                    ("podgate.port", "80"),
                ])
                .labels(extra),
        );
        let mut t = Tsk::new(name, 1);
        for (network, ip) in networks {
            t = t.network(network, ip);
        }
        swarm.add_task(t);
    };
    // Ignored: in network mode the network decides.
    on(
        "a-web",
        "web.acme.test",
        &[("net-a", "10.4.0.2")],
        &[("podgate.tenant", "globex")],
    );
    on("b-web", "web.globex.test", &[("net-b", "10.5.0.2")], &[]);
    on(
        "b-takeover",
        "takeover.acme.test",
        &[("net-b", "10.5.0.3")],
        &[],
    );
    on(
        "both",
        "both.acme.test",
        &[("net-a", "10.4.0.9"), ("net-b", "10.5.0.9")],
        &[],
    );
    let settings = "network = [\"net-a\", \"net-b\"]\ntenant_from = \"network\"\nnetwork_tenants = { net-a = \"acme\", net-b = \"globex\" }";
    let config = swarm_config(swarm.path(), TENANTS, &format!("{SLOW}{settings}"));
    let mut watcher = Watcher::start(&config);
    let state = watcher
        .wait_ids_and_report(&["a-web", "b-takeover", "b-web"], "service both")
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
            ("swarm-a-web".to_owned(), "acme".to_owned()),
            ("swarm-b-web".to_owned(), "globex".to_owned()),
        ],
        "globex's service cannot claim acme's host from its own network"
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
async fn upstream_outside_allowlist_rejected_swarm() {
    let swarm = FakeSwarm::start();
    deployed(&swarm, web("inside", "in.acme.test"), "10.4.0.1");
    deployed(&swarm, web("outside", "out.acme.test"), "10.5.0.1");
    let config = swarm_config(
        swarm.path(),
        TENANTS,
        &format!("{SLOW}network = \"podgate\"\ntenant = \"acme\""),
    );
    let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)
        .expect("policy");
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["inside", "outside"]).await;
    let merged = merge(&config, policy, state);
    assert_eq!(
        merged_apps(&merged),
        [("swarm-inside".to_owned(), "acme".to_owned())]
    );
    let forbidden: Vec<String> = finding_codes(&merged)
        .into_iter()
        .filter(|(code, _)| *code == "upstream_forbidden")
        .map(|(_, object)| object)
        .collect();
    assert_eq!(forbidden, ["outside"]);
}

// ---- the client and the configuration --------------------------------------------------------

#[tokio::test]
async fn swarm_client_only_issues_get() {
    let swarm = FakeSwarm::start();
    swarm.set_networks(&["podgate"]);
    swarm.set_nodes(&[("node-1", "ready")]);
    deployed(&swarm, web("first", "first.acme.test"), "10.4.0.1");
    let mut watcher = Watcher::start(&slow(swarm.path(), ""));
    watcher.wait_ids(&["first"]).await;
    wait_for_event_stream(&swarm).await;
    deployed(&swarm, web("second", "second.acme.test"), "10.4.0.2");
    swarm.emit(&swarm.service_event("create", "second"));
    watcher.wait_ids(&["first", "second"]).await;

    let requests = swarm.requests();
    assert!(
        requests.iter().all(|(method, _)| method == "GET"),
        "{requests:?}"
    );
    let paths: BTreeSet<String> = requests
        .iter()
        .map(|(_, path)| path.split('?').next().unwrap_or_default().to_owned())
        .collect();
    let expected: BTreeSet<String> = ["/services", "/tasks", "/nodes", "/networks", "/events"]
        .map(str::to_owned)
        .into();
    assert_eq!(
        paths, expected,
        "the services, tasks, nodes and networks lists and the events"
    );
}

#[test]
fn swarm_config_is_strict() {
    let parse = |text: &str| {
        let config = Config::parse(&format!(
            "admin_socket = \"/x\"\n[[source]]\nkind = \"swarm\"\nname = \"s\"\n{text}"
        ))
        .expect("config");
        SwarmSource::from_config(&config.sources[0])
    };
    assert!(parse("network = \"podgate\"").is_ok());
    assert!(parse("network = \"podgate\"\nendpoint = \"vip\"").is_ok());
    assert!(parse("network = [\"a\", \"b\"]\nsocket = \"/run/proxy.sock\"").is_ok());
    assert!(parse("").is_err(), "network is required");
    assert!(parse("network = []").is_err());
    assert!(parse("network = \"a\"\nendpoint = \"dnsrr\"").is_err());
    let unknown = parse("network = \"a\"\nexpose = true").expect_err("unknown key");
    assert!(unknown.reason.contains("expose"), "{unknown}");
    assert!(parse("network = \"a\"\ntenant_from = \"pod\"").is_err());
    assert!(parse("network = \"a\"\nnetwork_tenants = { a = \"x\" }").is_err());
    assert!(parse("network = \"a\"\ntenant_from = \"network\"").is_err());
    assert!(parse("network = \"a\"\nrefresh_secs = 0").is_err());
    let resync = parse("network = \"a\"\nrefresh_secs = 30\nresync_secs = 10")
        .expect_err("resync before refresh");
    assert!(resync.reason.contains("resync_secs"), "{resync}");
}
