//! Black-box tests of the Consul source against a fake Consul on a loopback port
//! (`tests/common/consul.rs`): tags, addresses, health, tenants, blocking queries, outages and
//! how its objects fare in the merge. Everything that waits has a deadline.
//!
//! The token never reaching a log is checked in `consul_logs.rs`, a binary of its own.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::consul::{FakeConsul, Svc};
use common::{DEADLINE, config};
use podgate_provider::consul::ConsulSource;
use podgate_provider::quarantine;
use podgate_provider::source::{Source, SourceApp, State, Update, UpdateBody};
use podgate_provider::{Config, Merged, Merger, UpstreamPolicy};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A change must show within the source's quiet window plus scheduling slack, far below both the
/// hour the tests give `resync_secs` and the ten seconds the fake holds a blocking query.
const PROMPT: Duration = Duration::from_secs(4);

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
"#;

/// The configuration with one consul source named `consul` after `tenants`, and `settings` as
/// the source's own keys.
fn consul_config(url: &str, tenants: &str, settings: &str) -> Config {
    let wait = if settings.contains("wait_secs") {
        ""
    } else {
        "wait_secs = 5\n"
    };
    config(
        std::path::Path::new("/nonexistent/admin.sock"),
        &format!(
            "{tenants}\n[[source]]\nkind = \"consul\"\nname = \"consul\"\naddress = {url:?}\nresync_secs = 3600\n{wait}{settings}\n"
        ),
    )
}

fn source_of(config: &Config) -> ConsulSource {
    ConsulSource::from_config(&config.sources[0]).expect("a valid consul source")
}

/// A running consul source and what it has said so far.
struct Watcher {
    rx: mpsc::Receiver<Update>,
    task: JoinHandle<()>,
    state: Option<State>,
    outage: Option<String>,
    /// Every state the source sent, as app ids.
    states: Vec<Vec<String>>,
    /// Every outage text the source sent.
    outages: Vec<String>,
}

impl Watcher {
    fn start(config: &Config) -> Self {
        let (tx, rx) = mpsc::channel(256);
        let source = source_of(config);
        Self {
            rx,
            task: tokio::spawn(source.run(tx)),
            state: None,
            outage: None,
            states: Vec::new(),
            outages: Vec::new(),
        }
    }

    async fn until(&mut self, what: &str, done: impl Fn(Option<&State>, Option<&str>) -> bool) {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                assert_eq!(&*update.source, "consul");
                match update.body {
                    UpdateBody::State(state) => {
                        self.states.push(ids(&state));
                        self.state = Some(state);
                        self.outage = None;
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

    /// Waits for a state in which `check` holds, within [`PROMPT`] of now.
    async fn promptly(&mut self, what: &str, check: impl Fn(&State) -> bool) {
        let started = Instant::now();
        self.until(what, |state, _| state.is_some_and(&check)).await;
        assert!(
            started.elapsed() < PROMPT,
            "{what} took {:?}, a blocking query answers at once",
            started.elapsed()
        );
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

fn app_of<'a>(state: &'a State, id: &str) -> &'a SourceApp {
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

/// An instance of service `name` that serves `host` on port 8080.
fn web(id: &str, name: &str, ip: &str, host: &str) -> Svc {
    Svc::new(id, name, ip, 8080).tags(&["podgate.enable=true", &format!("podgate.host={host}")])
}

fn merge(config: &Config, policy: UpstreamPolicy, state: State) -> Merged {
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("consul".into(), state)]);
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

// ---- services to apps ------------------------------------------------------------------------

#[tokio::test]
async fn consul_services_to_apps() {
    let consul = FakeConsul::start().await;
    consul.register(
        web(
            "web-2",
            "web",
            "10.4.0.6",
            "shop.acme.test, www.shop.acme.test",
        )
        .tag("v2"),
    );
    consul.register(
        web(
            "web-1",
            "web",
            "10.4.0.5",
            "shop.acme.test, www.shop.acme.test",
        )
        .tag("v2"),
    );
    consul.register(Svc::new("db-1", "db", "10.4.0.9", 5432).tag("primary"));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    let state = watcher.wait_ids(&["web"]).await;
    let app = app_of(&state, "web");
    assert_eq!(&*app.origin.object, "web");
    assert_eq!(app.origin.first_seen, 0, "Consul has no creation time");
    assert_eq!(app.tenant.mapped.as_deref(), Some("default"));
    assert_eq!(app.tenant.label, None);
    let mut json = app_json(&state, "web");
    // The core sets both.
    json.as_object_mut()
        .expect("an object")
        .remove("declared_by");
    json.as_object_mut().expect("an object").remove("tenant");
    assert_eq!(
        json,
        json!({
            "id": "web",
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
                    "servers": [{ "url": "http://10.4.0.5:8080" }, { "url": "http://10.4.0.6:8080" }],
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
    assert_eq!(watcher.report(), "", "an untagged service is not reported");
}

#[tokio::test]
async fn consul_full_tags_to_app() {
    let consul = FakeConsul::start().await;
    let tags = [
        "podgate.enable=true",
        "podgate.tls=on_demand",
        "podgate.revision=r7",
        r#"podgate.router.v1.match={"all": [{"host": "api.acme.test"}, {"path_prefix": "/v1"}]}"#,
        "podgate.router.v1.priority=10",
        "podgate.router.v1.chain=strip",
        "podgate.router.v1.service=api",
        "podgate.middleware.strip.type=strip_prefix",
        r#"podgate.middleware.strip.config={"prefixes": ["/v1"]}"#,
        r#"podgate.service.api.config={"algorithm": "least_conn"}"#,
    ];
    consul.register(Svc::new("api-1", "api", "10.4.0.6", 9000).tags(&tags));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    let state = watcher.wait_ids(&["api"]).await;
    let app = app_json(&state, "api");
    assert_eq!(app["tls"]["mode"], "on_demand");
    assert_eq!(
        app["routers"][0]["match"],
        json!({ "all": [{ "host": "api.acme.test" }, { "path_prefix": "/v1" }] }),
        "the JSON of a matcher tag is read whole"
    );
    assert_eq!(app["routers"][0]["priority"], 10);
    assert_eq!(
        app["revisions"][0]["services"],
        json!([{
            "name": "api",
            "type": "loadbalancer",
            "algorithm": "least_conn",
            "servers": [{ "url": "http://10.4.0.6:9000" }],
        }])
    );
    assert_eq!(app["revisions"][0]["id"], "r7");
}

#[tokio::test]
async fn consul_only_passing_instances() {
    let consul = FakeConsul::start().await;
    consul.register(web("ok", "web", "10.4.0.1", "web.acme.test"));
    consul
        .register(web("warn", "web", "10.4.0.2", "web.acme.test").checks(&["passing", "warning"]));
    consul.register(web("crit", "web", "10.4.0.3", "web.acme.test").checks(&["critical"]));
    consul.register(web("node-down", "web", "10.4.0.4", "web.acme.test").node_check("critical"));
    // Maintenance mode is a critical check Consul adds itself.
    consul.register(
        web("maint", "web", "10.4.0.5", "web.acme.test").checks(&["passing", "critical"]),
    );
    consul.register(web("only-bad", "worse", "10.4.0.6", "worse.acme.test").checks(&["critical"]));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    let state = watcher.wait_ids(&["web"]).await;
    assert_eq!(
        servers_of(&state, "web", "default"),
        ["http://10.4.0.1:8080"]
    );
    let health = consul.health_requests("web");
    assert!(
        health
            .iter()
            .all(|request| request.query.get("passing").is_some_and(|v| v == "true")),
        "the instances are asked for with passing=true: {health:?}"
    );

    // An instance turns unhealthy, and comes back.
    consul.set_checks("ok", &["critical"]);
    watcher.wait_ids(&[]).await;
    consul.set_checks("ok", &["passing"]);
    watcher.wait_ids(&["web"]).await;

    // The server's filter is not the only one: a Consul that ignores passing=true changes nothing.
    let lax = FakeConsul::start().await;
    lax.ignore_passing_filter();
    lax.register(web("ok", "web", "10.4.0.1", "web.acme.test"));
    lax.register(web("crit", "web", "10.4.0.3", "web.acme.test").checks(&["critical"]));
    lax.register(web("node-down", "web", "10.4.0.4", "web.acme.test").node_check("critical"));
    let mut watcher = Watcher::start(&consul_config(&lax.url(), "", ""));
    let state = watcher.wait_ids(&["web"]).await;
    assert_eq!(
        servers_of(&state, "web", "default"),
        ["http://10.4.0.1:8080"]
    );
}

#[tokio::test]
async fn consul_node_address_fallback() {
    let consul = FakeConsul::start().await;
    // No Service.Address: the instance is where its node is.
    consul.register(web("web-1", "web", "", "web.acme.test").node("n1", "10.4.1.7"));
    consul.register(web("web-2", "web", "10.4.2.8", "web.acme.test").node("n2", "10.4.9.9"));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    let state = watcher.wait_ids(&["web"]).await;
    assert_eq!(
        servers_of(&state, "web", "default"),
        ["http://10.4.1.7:8080", "http://10.4.2.8:8080"],
        "the service's own address wins over its node's"
    );
}

#[tokio::test]
async fn consul_address_must_be_an_ip() {
    let consul = FakeConsul::start().await;
    consul.register(web("good", "web", "10.4.0.1", "web.acme.test"));
    consul.register(web("named", "web", "web.internal", "web.acme.test"));
    consul.register(
        Svc::new("noport", "web", "10.4.0.3", 0)
            .tags(&["podgate.enable=true", "podgate.host=web.acme.test"]),
    );
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    let state = watcher
        .wait_ids_and_report(&["web"], "instance named")
        .await;
    assert_eq!(
        servers_of(&state, "web", "default"),
        ["http://10.4.0.1:8080"]
    );
    assert!(
        watcher.report().contains("not an IP address"),
        "{}",
        watcher.report()
    );
    assert!(
        watcher.report().contains("registered no port"),
        "{}",
        watcher.report()
    );
}

#[tokio::test]
async fn consul_host_conflict_winner_survives_restart() {
    // Two services claim one host: podgate's compiler reports `host_conflict`, and the provider
    // keeps the older object. Consul has no creation time, so neither is older: which one
    // stays must not depend on which was registered, or seen, first.
    let config = |url: &str| consul_config(url, TENANTS, "tenant = \"acme\"");
    let mut losers = Vec::new();
    for order in [["alpha", "beta"], ["beta", "alpha"]] {
        let consul = FakeConsul::start().await;
        for (n, name) in order.iter().enumerate() {
            let ip = format!("10.4.0.{}", n + 1);
            consul.register(web(name, name, &ip, "shared.acme.test"));
        }
        let config = config(&consul.url());
        // A fresh source each time, like a restarted provider.
        let mut watcher = Watcher::start(&config);
        let state = watcher.wait_ids(&["alpha", "beta"]).await;
        assert!(state.apps.iter().all(|app| app.origin.first_seen == 0));
        let merged = merge(&config, UpstreamPolicy::builtin(), state);
        let named: Vec<&str> = merged
            .included()
            .iter()
            .map(|included| &*included.declared_by)
            .collect();
        let culprits = quarantine::attribute(&merged, &[common::conflict("host_conflict", &named)]);
        losers.push(
            culprits
                .iter()
                .map(|culprit| culprit.object.object.object.to_string())
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(losers[0], ["beta"], "ties fall back to the object name");
    assert_eq!(losers[0], losers[1], "the same app stays after a restart");
}

#[tokio::test]
async fn consul_revision_tags() {
    let consul = FakeConsul::start().await;
    let shop = |id: &str, ip: &str, revision: &str, state: &str| {
        web(id, "shop", ip, "shop.acme.test").tags(&[
            &format!("podgate.revision={revision}"),
            &format!("podgate.revision.state={state}"),
        ])
    };
    consul.register(shop("old", "10.4.0.1", "r1", "retiring"));
    consul.register(shop("new-a", "10.4.0.2", "r2", "serving"));
    consul.register(shop("new-b", "10.4.0.3", "r2", "serving"));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    let state = watcher.wait_ids(&["shop"]).await;
    let app = app_json(&state, "shop");
    let revisions: BTreeMap<String, (String, Vec<String>)> = app["revisions"]
        .as_array()
        .expect("revisions")
        .iter()
        .map(|revision| {
            (
                revision["id"].as_str().expect("id").to_owned(),
                (
                    revision["state"].as_str().expect("state").to_owned(),
                    servers_of(&state, "shop", revision["id"].as_str().expect("id")),
                ),
            )
        })
        .collect();
    assert_eq!(
        revisions,
        BTreeMap::from([
            (
                "r1".to_owned(),
                (
                    "retiring".to_owned(),
                    vec!["http://10.4.0.1:8080".to_owned()]
                )
            ),
            (
                "r2".to_owned(),
                (
                    "serving".to_owned(),
                    vec![
                        "http://10.4.0.2:8080".to_owned(),
                        "http://10.4.0.3:8080".to_owned()
                    ]
                )
            ),
        ])
    );
}

#[tokio::test]
async fn consul_connect_proxies_ignored() {
    let consul = FakeConsul::start().await;
    consul.register(web("web-1", "web", "10.4.0.1", "web.acme.test"));
    // A sidecar registered with its service's tags, as Consul copies them.
    consul.register(
        web(
            "web-1-sidecar",
            "web-sidecar-proxy",
            "10.4.0.1",
            "web.acme.test",
        )
        .kind("connect-proxy"),
    );
    consul.register(web("gw-1", "gateway", "10.4.0.2", "gw.acme.test").kind("ingress-gateway"));
    let mut off = Watcher::start(&consul_config(&consul.url(), "", ""));
    off.wait_ids(&["web"]).await;
    assert_eq!(off.report(), "", "a sidecar is ignored, not reported");

    let mut on = Watcher::start(&consul_config(&consul.url(), "", "connect = true"));
    on.wait_ids(&["web", "web-sidecar-proxy"]).await;
}

// ---- blocking queries ------------------------------------------------------------------------

#[tokio::test]
async fn consul_blocking_query_updates() {
    let consul = FakeConsul::start().await;
    consul.max_hold(Duration::from_secs(30));
    consul.register(web("web-1", "web", "10.4.0.1", "web.acme.test"));
    let config = consul_config(&consul.url(), "", "wait_secs = 30");
    let mut watcher = Watcher::start(&config);
    watcher.wait_ids(&["web"]).await;
    // One blocking query on the catalog, one on the service.
    consul.wait_held(2).await;
    let catalog: Vec<_> = consul
        .requests()
        .into_iter()
        .filter(|request| request.path == "/v1/catalog/services")
        .collect();
    assert_eq!(catalog[0].index(), None, "the first read is not blocking");
    let blocking = catalog.last().expect("a catalog query");
    assert!(
        blocking.index().is_some_and(|index| index > 0),
        "{blocking:?}"
    );
    assert_eq!(blocking.query.get("wait").map(String::as_str), Some("30s"));

    // A registration, a health change and a deregistration show at once: the source is not
    // polling (resync_secs is an hour).
    consul.register(web("web-2", "web", "10.4.0.2", "web.acme.test"));
    watcher
        .promptly("the second instance", |state| {
            servers_of(state, "web", "default") == ["http://10.4.0.1:8080", "http://10.4.0.2:8080"]
        })
        .await;
    consul.set_checks("web-1", &["critical"]);
    watcher
        .promptly("the unhealthy instance leaves", |state| {
            servers_of(state, "web", "default") == ["http://10.4.0.2:8080"]
        })
        .await;
    consul.register(web("api-1", "api", "10.4.0.3", "api.acme.test"));
    watcher
        .promptly("a new service", |state| ids(state) == ["api", "web"])
        .await;
    consul.deregister("web-2");
    watcher
        .promptly("the last instance leaves", |state| ids(state) == ["api"])
        .await;
    consul.deregister("api-1");
    watcher
        .promptly("no service is left", |state| ids(state).is_empty())
        .await;
    assert_eq!(
        watcher.states.iter().filter(|ids| ids.is_empty()).count(),
        1,
        "one empty state, for the real change: {:?}",
        watcher.states
    );
}

#[tokio::test]
async fn consul_client_only_issues_get() {
    let consul = FakeConsul::start().await;
    consul.register(web("web-1", "web", "10.4.0.1", "web.acme.test"));
    consul.register(web("odd", "odd name/x", "10.4.0.2", "odd.acme.test"));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    watcher
        .wait_ids_and_report(&["web"], "service odd name")
        .await;
    let requests = consul.requests();
    assert!(
        requests.iter().all(|request| request.method == "GET"),
        "{requests:?}"
    );
    let paths: BTreeSet<String> = requests.into_iter().map(|request| request.path).collect();
    assert_eq!(
        paths,
        BTreeSet::from([
            "/v1/catalog/services".to_owned(),
            "/v1/health/service/odd name/x".to_owned(),
            "/v1/health/service/web".to_owned(),
        ]),
        "the catalog and the health of each tagged service, a name percent-encoded"
    );
}

#[tokio::test]
async fn consul_reconnects() {
    let consul = FakeConsul::start().await;
    consul.max_hold(Duration::from_secs(30));
    consul.register(web("web-1", "web", "10.4.0.1", "web.acme.test"));
    // Consul answers 503 to the first requests: no state until it recovers, then the state.
    consul.fail_next(503, 3);
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", "wait_secs = 30"));
    let state = watcher.wait_ids(&["web"]).await;
    assert_eq!(
        servers_of(&state, "web", "default"),
        ["http://10.4.0.1:8080"]
    );
    assert!(
        watcher.outages.iter().any(|why| why.contains("503")),
        "the failures are reported: {:?}",
        watcher.outages
    );
    assert!(
        watcher.states.iter().all(|ids| ids == &["web"]),
        "no state before the first complete read: {:?}",
        watcher.states
    );
    consul.wait_held(2).await;

    // Every connection drops, with queries held; a change is made while Consul is down.
    consul.stop();
    watcher.wait_outage("cannot reach Consul").await;
    consul.register(web("web-2", "web", "10.4.0.2", "web.acme.test"));
    consul.restart().await;
    watcher
        .until("the change made during the outage", |state, _| {
            state.is_some_and(|state| servers_of(state, "web", "default").len() == 2)
        })
        .await;
    consul.wait_held(2).await;
    assert_eq!(watcher.report(), "", "the next state clears the outage");

    // And the new connections block again.
    consul.register(web("web-3", "web", "10.4.0.3", "web.acme.test"));
    watcher
        .promptly("a change after the reconnect", |state| {
            servers_of(state, "web", "default").len() == 3
        })
        .await;
}

#[tokio::test]
async fn consul_index_goes_backwards() {
    let consul = FakeConsul::start().await;
    consul.max_hold(Duration::from_secs(2));
    for n in 0..5 {
        consul.register(web(
            &format!("web-{n}"),
            "web",
            &format!("10.4.0.{n}"),
            "web.acme.test",
        ));
    }
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", "wait_secs = 30"));
    watcher.wait_ids(&["web"]).await;
    consul.wait_held(2).await;
    let before = consul.requests().len();

    // Consul is restored from a snapshot: its indexes are lower than the source has seen. The
    // held queries run out, and the source starts over with a read that does not block.
    consul.rewind_indexes(1);
    consul
        .wait_requests("a full read after the rewind", |requests| {
            requests[before..]
                .iter()
                .any(|request| request.path == "/v1/catalog/services" && request.index().is_none())
        })
        .await;
    consul.wait_held(2).await;
    consul.register(web("web-9", "web", "10.4.0.9", "web.acme.test"));
    watcher
        .promptly("a registration at the lower indexes", |state| {
            servers_of(state, "web", "default").contains(&"http://10.4.0.9:8080".to_owned())
        })
        .await;
}

#[tokio::test]
async fn consul_watch_caps() {
    let consul = FakeConsul::start().await;
    consul.register_all((0..600).map(|n| {
        web(
            &format!("svc-{n:03}-1"),
            &format!("svc-{n:03}"),
            "10.4.1.1",
            &format!("svc-{n:03}.acme.test"),
        )
    }));
    // "big" sorts before every svc-*: it is watched, and has more instances than are used.
    consul.register_all((0..300).map(|n| {
        web(
            &format!("big-{n:03}"),
            "big",
            &format!("10.5.{}.{}", n / 250, n % 250 + 1),
            "big.acme.test",
        )
    }));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    watcher
        .until("512 apps and both caps reported", |state, outage| {
            state.is_some_and(|state| state.apps.len() == 512)
                && outage.is_some_and(|why| {
                    why.contains("89 services are not watched") && why.contains("service big")
                })
        })
        .await;
    let state = watcher.state.clone().expect("a state");
    assert_eq!(
        servers_of(&state, "big", "default").len(),
        256,
        "instances per service are capped"
    );
    assert!(
        watcher
            .report()
            .contains("44 instances more than the cap of 256"),
        "{}",
        watcher.report()
    );
    assert!(
        watcher.report().contains("the cap is 512 per source"),
        "{}",
        watcher.report()
    );
    let watched = consul.health_paths();
    assert_eq!(
        watched.len(),
        512,
        "one blocking query per watched service, no more"
    );
    assert!(watched.contains("/v1/health/service/big"));
    assert!(
        !watched.contains("/v1/health/service/svc-599"),
        "the services past the cap, in name order, are the ones left out"
    );
}

// ---- which services --------------------------------------------------------------------------

#[tokio::test]
async fn consul_exposed_by_default_false() {
    let consul = FakeConsul::start().await;
    consul.register(web("in", "in", "10.4.0.2", "in.acme.test"));
    consul.register(
        Svc::new("not-asked", "not-asked", "10.4.0.3", 80).tags(&["podgate.host=no.acme.test"]),
    );
    consul.register(
        Svc::new("out", "out", "10.4.0.4", 80)
            .tags(&["podgate.enable=false", "podgate.host=out.acme.test"]),
    );
    consul.register(Svc::new("bare", "bare", "10.4.0.5", 80));
    let mut closed = Watcher::start(&consul_config(&consul.url(), "", ""));
    closed.wait_ids(&["in"]).await;
    assert_eq!(closed.report(), "", "ignored services are not reported");
    assert_eq!(
        consul.health_paths(),
        BTreeSet::from(["/v1/health/service/in".to_owned()]),
        "a service that did not ask is not even read"
    );

    let mut open = Watcher::start(&consul_config(
        &consul.url(),
        "",
        "exposed_by_default = true",
    ));
    open.wait_ids_and_report(&["in", "not-asked"], "service bare")
        .await;
    assert!(open.report().contains("no router"), "{}", open.report());
    assert!(
        !open.report().contains("service out"),
        "enable=false always excludes"
    );
}

#[tokio::test]
async fn consul_enable_false_on_one_instance_excludes_only_it() {
    let consul = FakeConsul::start().await;
    consul.register(web("a", "web", "10.4.0.1", "web.acme.test"));
    consul.register(web("b", "web", "10.4.0.2", "web.acme.test").tag("podgate.enable=false"));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    let state = watcher.wait_ids(&["web"]).await;
    assert_eq!(
        servers_of(&state, "web", "default"),
        ["http://10.4.0.1:8080"]
    );
}

fn labelled(id: &str, name: &str, ip: &str, extra: &[&str]) -> Svc {
    Svc::new(id, name, ip, 8080)
        .tags(&["podgate.enable=true", "podgate.host=x.acme.test"])
        .tags(extra)
}

#[tokio::test]
async fn consul_unknown_tag_rejected() {
    let consul = FakeConsul::start().await;
    consul.register(web("control", "control", "10.4.0.1", "control.acme.test").tag("v2"));
    consul.register(labelled(
        "typo",
        "typo",
        "10.4.0.2",
        &["podgate.hosts=a.test"],
    ));
    consul.register(labelled(
        "deep",
        "deep",
        "10.4.0.3",
        &["podgate.router.main.rule=Host(`a.test`)"],
    ));
    consul.register(labelled(
        "bad-json",
        "bad-json",
        "10.4.0.4",
        &["podgate.service.web.config={nope"],
    ));
    consul.register(labelled("novalue", "novalue", "10.4.0.5", &["podgate.tls"]));
    consul.register(labelled(
        "twice",
        "twice",
        "10.4.0.6",
        &["podgate.host=b.test"],
    ));
    consul.register(labelled("port", "port", "10.4.0.7", &["podgate.port=80"]));
    consul.register(labelled("app", "app", "10.4.0.8", &["podgate.app=control"]));
    consul.register(labelled(
        "address",
        "address",
        "10.4.0.9",
        &[
            "podgate.router.main.match={\"host\": \"a.test\"}",
            "podgate.router.main.service=http://10.9.9.9:80",
        ],
    ));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    watcher
        .wait_ids_and_report(&["control"], "service typo")
        .await;
    let report = watcher.report().to_owned();
    for needle in [
        "unknown label podgate.hosts",
        "unknown label podgate.router.main.rule",
        "not JSON",
        "tag \"podgate.tls\": a podgate tag is written key=value",
        "tag podgate.host: given twice",
        "port 80 (podgate.port or a traefik server.port) is not the registered port 8080",
        "podgate.app: \"control\" is not the service's name",
        "names an address",
    ] {
        assert!(report.contains(needle), "{needle} in {report}");
    }
    for service in [
        "typo", "deep", "bad-json", "novalue", "twice", "port", "app", "address",
    ] {
        assert!(
            report.contains(&format!("service {service} instance {service}")),
            "{service} in {report}"
        );
    }
}

#[tokio::test]
async fn consul_traefik_tags_translate() {
    let consul = FakeConsul::start().await;
    // Tags as a Traefik Consul Catalog user writes them: no podgate.* tag at all, and the
    // service is exposed by traefik.enable although exposed_by_default is off.
    consul.register(Svc::new("shop-1", "shop", "10.4.0.1", 8080).tags(&[
        "traefik.enable=true",
        "traefik.http.routers.shop.rule=Host(`shop.acme.test`) && PathPrefix(`/v1`)",
        "traefik.http.routers.shop.priority=5",
        "traefik.http.routers.shop.middlewares=strip",
        "traefik.http.middlewares.strip.stripprefix.prefixes=/v1",
        "traefik.http.services.shop.loadbalancer.server.port=8080",
        "v2",
    ]));
    // A tag that cannot be translated leaves out its router and is reported; the rest stays.
    consul.register(Svc::new("part-1", "part", "10.4.0.2", 8080).tags(&[
        "traefik.enable=true",
        "traefik.http.routers.good.rule=Host(`good.acme.test`)",
        "traefik.http.routers.bad.rule=Host(`bad.acme.test`)",
        "traefik.http.routers.bad.tls.options=strict",
    ]));
    // The port is the registered one: a tag that says another is a rejection, not a redirect.
    consul.register(Svc::new("port-1", "port", "10.4.0.3", 8080).tags(&[
        "traefik.enable=true",
        "traefik.http.routers.p.rule=Host(`p.acme.test`)",
        "traefik.http.services.p.loadbalancer.server.port=9000",
    ]));
    // traefik.enable=false hides, and so does it when exposed_by_default is on.
    consul.register(Svc::new("hidden-1", "hidden", "10.4.0.4", 8080).tags(&[
        "traefik.enable=false",
        "traefik.http.routers.h.rule=Host(`h.acme.test`)",
    ]));
    // A tag that names an address is as fatal as a podgate.* one.
    consul.register(Svc::new("addr-1", "addr", "10.4.0.5", 8080).tags(&[
        "traefik.enable=true",
        "traefik.http.routers.a.rule=Host(`a.acme.test`)",
        "traefik.http.services.a.loadbalancer.server.url=http://10.9.9.9:80",
    ]));
    // Both spellings on one instance.
    consul.register(Svc::new("mix-1", "mix", "10.4.0.6", 8080).tags(&[
        "traefik.enable=true",
        "traefik.http.routers.t.rule=Host(`t.acme.test`)",
        "podgate.host=m.acme.test",
    ]));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    let state = watcher
        .wait_ids_and_report(&["mix", "part", "shop"], "instance addr-1")
        .await;

    let shop = app_json(&state, "shop");
    assert_eq!(
        shop["routers"],
        json!([{
            "name": "shop",
            "entry_points": null,
            "match": { "all": [{ "host": "shop.acme.test" }, { "path_prefix": "/v1" }] },
            "priority": 5,
            "chain": ["strip"],
            "service": "shop",
            "observability": null,
            "declared_by": null,
        }])
    );
    assert_eq!(
        shop["middlewares"],
        json!([{ "name": "strip", "type": "strip_prefix", "prefixes": ["/v1"] }])
    );
    assert_eq!(
        servers_of(&state, "shop", "default"),
        ["http://10.4.0.1:8080"]
    );

    let part = app_json(&state, "part");
    let routers: Vec<&str> = part["routers"]
        .as_array()
        .expect("routers")
        .iter()
        .filter_map(|router| router["name"].as_str())
        .collect();
    assert_eq!(
        routers,
        ["good"],
        "the untranslatable router is left out, not approximated"
    );
    let mix = app_json(&state, "mix");
    let routers: BTreeSet<&str> = mix["routers"]
        .as_array()
        .expect("routers")
        .iter()
        .filter_map(|router| router["name"].as_str())
        .collect();
    assert_eq!(routers, BTreeSet::from(["default", "t"]));

    let report = watcher.report().to_owned();
    for needle in [
        "service part instance part-1",
        "traefik.http.routers.bad.tls.options",
        "service port instance port-1",
        "is not the registered port 8080",
        "service addr instance addr-1",
        "traefik.http.services.a.loadbalancer.server.url",
    ] {
        assert!(report.contains(needle), "{needle} in {report}");
    }
    assert!(
        !report.contains("service hidden"),
        "traefik.enable=false hides: {report}"
    );
    assert_eq!(
        consul.health_paths().contains("/v1/health/service/hidden"),
        false,
        "a hidden service is not even read"
    );

    // With exposed_by_default the hidden service is still hidden.
    let mut open = Watcher::start(&consul_config(
        &consul.url(),
        "",
        "exposed_by_default = true",
    ));
    open.wait_ids_and_report(&["mix", "part", "shop"], "instance addr-1")
        .await;
    assert!(
        !open.report().contains("service hidden"),
        "{}",
        open.report()
    );
}

#[tokio::test]
async fn consul_unknown_tag_rejects_only_its_instance() {
    let consul = FakeConsul::start().await;
    consul.register(web("old", "web", "10.4.0.1", "web.acme.test"));
    consul.register(web("new", "web", "10.4.0.2", "web.acme.test").tag("podgate.hostz=1"));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    let state = watcher.wait_ids_and_report(&["web"], "instance new").await;
    assert_eq!(
        servers_of(&state, "web", "default"),
        ["http://10.4.0.1:8080"],
        "a bad rollout keeps the instances that were fine"
    );
}

// ---- tenants ---------------------------------------------------------------------------------

#[tokio::test]
async fn consul_tag_cannot_claim_foreign_host() {
    let consul = FakeConsul::start().await;
    consul.register(web("mine", "mine", "10.4.0.1", "web.acme.test"));
    consul.register(web("theirs", "theirs", "10.4.0.2", "globex.test"));
    // Neither a tenant tag nor a tenant in meta helps: a fixed source ignores both.
    consul.register(
        web("sneaky", "sneaky", "10.4.0.3", "www.globex.test")
            .tag("podgate.tenant=globex")
            .meta("podgate-tenant", "globex"),
    );
    let config = consul_config(&consul.url(), TENANTS, "tenant = \"acme\"");
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["mine", "sneaky", "theirs"]).await;
    assert_eq!(
        app_of(&state, "sneaky").tenant.label,
        None,
        "fixed mode ignores them"
    );
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [("consul-mine".to_owned(), "acme".to_owned())]
    );
    let codes: Vec<&str> = finding_codes(&merged)
        .iter()
        .map(|(code, _)| *code)
        .collect();
    assert_eq!(codes, ["foreign_host_claim", "foreign_host_claim"]);
}

#[tokio::test]
async fn consul_meta_tenant_requires_trust() {
    let consul = FakeConsul::start().await;
    consul.register(
        web("shop", "shop", "10.4.0.1", "shop.globex.test").meta("podgate-tenant", "globex"),
    );
    consul.register(web("plain", "plain", "10.4.0.2", "plain.acme.test"));
    let settings = "tenant_from = \"meta\"\ntenant = \"acme\"";

    let untrusted = consul_config(&consul.url(), TENANTS, settings);
    let mut watcher = Watcher::start(&untrusted);
    let state = watcher.wait_ids(&["plain", "shop"]).await;
    assert_eq!(
        app_of(&state, "shop").tenant.label.as_deref(),
        Some("globex")
    );
    assert_eq!(
        app_of(&state, "shop").tenant.mapped.as_deref(),
        Some("acme")
    );
    assert_eq!(app_of(&state, "plain").tenant.label, None);
    let merged = merge(&untrusted, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [("consul-plain".to_owned(), "acme".to_owned())],
        "an untrusted source's meta names no tenant, and acme may not take globex's host"
    );
    let codes: Vec<&str> = finding_codes(&merged)
        .iter()
        .map(|(code, _)| *code)
        .collect();
    assert_eq!(codes, ["label_ignored", "foreign_host_claim"]);

    let trusted_tenants = TENANTS.replace(
        "hosts = [\"globex.test\", \"*.globex.test\"]",
        "hosts = [\"globex.test\", \"*.globex.test\"]\nlabel_sources = [\"consul\"]",
    );
    let trusted = consul_config(&consul.url(), &trusted_tenants, settings);
    let mut watcher = Watcher::start(&trusted);
    let state = watcher.wait_ids(&["plain", "shop"]).await;
    let merged = merge(&trusted, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [
            ("consul-plain".to_owned(), "acme".to_owned()),
            ("consul-shop".to_owned(), "globex".to_owned()),
        ],
        "a source the tenant trusts may name it"
    );

    // The key is the operator's to choose, and the tag is not a second way in.
    let custom = consul_config(
        &consul.url(),
        &trusted_tenants,
        "tenant_from = \"meta\"\nmeta_key = \"owner\"",
    );
    let mut watcher = Watcher::start(&custom);
    let state = watcher.wait_ids(&["plain", "shop"]).await;
    assert_eq!(
        app_of(&state, "shop").tenant.label,
        None,
        "podgate-tenant is not owner"
    );
}

#[tokio::test]
async fn consul_meta_tenant_must_be_a_name() {
    let consul = FakeConsul::start().await;
    consul.register(web("ok", "ok", "10.4.0.1", "ok.acme.test").meta("podgate-tenant", "acme"));
    consul.register(
        web("bad", "bad", "10.4.0.2", "bad.acme.test").meta("podgate-tenant", "a b/../c"),
    );
    let mut watcher = Watcher::start(&consul_config(
        &consul.url(),
        TENANTS,
        "tenant_from = \"meta\"",
    ));
    watcher.wait_ids_and_report(&["ok"], "instance bad").await;
    assert!(
        watcher.report().contains("meta podgate-tenant"),
        "{}",
        watcher.report()
    );
}

#[tokio::test]
async fn consul_namespace_tenant() {
    let consul = FakeConsul::start().await;
    consul.register(web("a-web", "web", "10.4.0.2", "web.acme.test").namespace("team-a"));
    consul.register(web("b-web", "web", "10.5.0.2", "web.globex.test").namespace("team-b"));
    consul
        .register(web("b-take", "takeover", "10.5.0.3", "takeover.acme.test").namespace("team-b"));
    consul.register(web("c-web", "web", "10.6.0.2", "web.acme.test").namespace("team-c"));
    // A meta tenant does not move a service out of its namespace's tenant.
    consul.register(
        web("a-meta", "meta", "10.4.0.3", "meta.acme.test")
            .namespace("team-a")
            .meta("podgate-tenant", "globex"),
    );
    let settings = "namespaces = [\"team-a\", \"team-b\"]\ntenant_from = \"namespace\"\nnamespace_tenants = { team-a = \"acme\", team-b = \"globex\" }";
    let config = consul_config(&consul.url(), TENANTS, settings);
    let mut watcher = Watcher::start(&config);
    let state = watcher
        .wait_ids(&["team-a.meta", "team-a.web", "team-b.takeover", "team-b.web"])
        .await;
    assert_eq!(
        app_of(&state, "team-a.web").tenant.mapped.as_deref(),
        Some("acme")
    );
    assert_eq!(app_of(&state, "team-a.meta").tenant.label, None);
    assert_eq!(
        app_of(&state, "team-b.web").tenant.mapped.as_deref(),
        Some("globex")
    );
    assert_eq!(&*app_of(&state, "team-b.web").origin.object, "team-b.web");
    let namespaces: BTreeSet<String> = consul
        .requests()
        .iter()
        .filter_map(|request| request.query.get("ns").cloned())
        .collect();
    assert_eq!(
        namespaces,
        BTreeSet::from(["team-a".to_owned(), "team-b".to_owned()])
    );

    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [
            ("consul-team-a.meta".to_owned(), "acme".to_owned()),
            ("consul-team-a.web".to_owned(), "acme".to_owned()),
            ("consul-team-b.web".to_owned(), "globex".to_owned()),
        ],
        "globex's namespace cannot claim acme's host"
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
async fn consul_scopes_are_passed_through() {
    let consul = FakeConsul::start().await;
    consul.register(web("web-1", "web", "10.4.0.1", "web.acme.test").partition("p1"));
    consul.register(web("web-2", "web", "10.4.0.2", "web.acme.test"));
    let settings = "datacenter = \"dc1\"\npartitions = [\"p1\"]\nstale = true";
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", settings));
    let state = watcher.wait_ids(&["p1.web"]).await;
    assert_eq!(
        servers_of(&state, "p1.web", "default"),
        ["http://10.4.0.1:8080"]
    );
    let requests = consul.requests();
    assert!(!requests.is_empty());
    for request in &requests {
        assert_eq!(
            request.query.get("dc").map(String::as_str),
            Some("dc1"),
            "{request:?}"
        );
        assert_eq!(
            request.query.get("partition").map(String::as_str),
            Some("p1"),
            "{request:?}"
        );
        assert!(
            request.raw_query.split('&').any(|flag| flag == "stale"),
            "{request:?}"
        );
    }

    let mut elsewhere = Watcher::start(&consul_config(&consul.url(), "", "datacenter = \"dc9\""));
    elsewhere.wait_outage("No path to datacenter").await;
    assert!(elsewhere.state.is_none());
}

#[tokio::test]
async fn upstream_outside_allowlist_rejected_consul() {
    let consul = FakeConsul::start().await;
    consul.register(web("inside", "inside", "10.4.0.1", "in.acme.test"));
    consul.register(web("outside", "outside", "10.5.0.1", "out.acme.test"));
    consul.register(web("loopback", "loopback", "127.0.0.1", "loop.acme.test"));
    let config = consul_config(&consul.url(), TENANTS, "tenant = \"acme\"");
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["inside", "loopback", "outside"]).await;

    let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)
        .expect("policy");
    let merged = merge(&config, policy, state.clone());
    assert_eq!(
        merged_apps(&merged),
        [("consul-inside".to_owned(), "acme".to_owned())]
    );
    let forbidden: Vec<String> = finding_codes(&merged)
        .into_iter()
        .filter(|(code, _)| *code == "upstream_forbidden")
        .map(|(_, object)| object)
        .collect();
    assert_eq!(forbidden, ["loopback", "outside"]);

    // Without a policy file the built-in deny list still stops a service that advertises the
    // machine podgate runs on.
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [
            ("consul-inside".to_owned(), "acme".to_owned()),
            ("consul-outside".to_owned(), "acme".to_owned()),
        ]
    );
    assert_eq!(finding_codes(&merged).len(), 1);
}

// ---- outages ---------------------------------------------------------------------------------

#[tokio::test]
async fn consul_outage_keeps_last_state() {
    let consul = FakeConsul::start().await;
    consul.register(web("first", "first", "10.4.0.1", "first.acme.test"));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    watcher.wait_ids(&["first"]).await;
    consul.wait_held(2).await;

    consul.stop();
    watcher.wait_outage("cannot reach Consul").await;
    assert_eq!(
        ids(watcher.state.as_ref().expect("the last state stays")),
        ["first"],
        "an outage is not an empty state"
    );
    assert!(
        watcher.states.iter().all(|ids| ids == &["first"]),
        "no state without the app was ever sent: {:?}",
        watcher.states
    );

    consul.register(web("second", "second", "10.4.0.2", "second.acme.test"));
    consul.restart().await;
    watcher.wait_ids(&["first", "second"]).await;
    assert_eq!(watcher.report(), "", "the next state clears the outage");
}

#[tokio::test]
async fn consul_down_at_start_sends_no_state() {
    let consul = FakeConsul::start().await;
    consul.register(web("first", "first", "10.4.0.1", "first.acme.test"));
    consul.stop();
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    watcher.wait_outage("cannot reach Consul").await;
    assert!(watcher.state.is_none(), "no state before a complete read");
    consul.restart().await;
    watcher.wait_ids(&["first"]).await;
}

#[tokio::test]
async fn consul_acl_change_keeps_the_last_state() {
    let consul = FakeConsul::start().await;
    consul.register(web("a", "a", "10.4.0.1", "a.acme.test"));
    consul.register(web("b", "b", "10.4.0.2", "b.acme.test"));
    let mut watcher = Watcher::start(&consul_config(&consul.url(), "", ""));
    watcher.wait_ids(&["a", "b"]).await;
    // ACLs change: the token no longer reads one service. Its apps stay as they were, and the
    // failure is named.
    consul.require_token("secret");
    watcher.wait_outage("Permission denied").await;
    assert_eq!(ids(watcher.state.as_ref().expect("a state")), ["a", "b"]);
    assert!(watcher.report().contains("403"), "{}", watcher.report());
}

// ---- configuration ---------------------------------------------------------------------------

fn token_file(name: &str, mode: u32, text: &str) -> PathBuf {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!("pgp-consul-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .expect("write the token file");
    path
}

#[test]
fn consul_config_is_strict() {
    let parse = |text: &str| {
        let config = Config::parse(&format!(
            "admin_socket = \"/x\"\n[[source]]\nkind = \"consul\"\nname = \"c\"\n{text}"
        ))
        .expect("config");
        ConsulSource::from_config(&config.sources[0])
    };
    let addr = "address = \"http://127.0.0.1:8500\"\n";
    assert!(parse(addr).is_ok());
    assert!(parse("address = \"https://consul.example:8501\"\ndatacenter = \"dc2\"\nstale = true\nconnect = true").is_ok());
    assert!(parse("").is_err(), "address is required");
    for bad in [
        "127.0.0.1:8500",
        "unix:///run/consul.sock",
        "http://x/v1/",
        "ftp://x",
    ] {
        let err = parse(&format!("address = {bad:?}")).expect_err("bad address");
        assert!(err.reason.contains("address"), "{bad}: {err}");
    }
    let unknown = parse(&format!("{addr}expose = true")).expect_err("unknown key");
    assert!(unknown.reason.contains("expose"), "{unknown}");
    assert!(parse(&format!("{addr}tenant_from = \"node\"")).is_err());
    assert!(parse(&format!("{addr}resync_secs = 0")).is_err());
    assert!(parse(&format!("{addr}wait_secs = 0")).is_err());
    assert!(parse(&format!("{addr}wait_secs = 601")).is_err());
    assert!(parse(&format!("{addr}namespaces = []")).is_err());
    assert!(parse(&format!("{addr}namespaces = [\"a\", \"a\"]")).is_err());
    assert!(parse(&format!("{addr}namespace_tenants = {{ a = \"x\" }}")).is_err());
    assert!(
        parse(&format!("{addr}meta_key = \"owner\"")).is_err(),
        "only for meta"
    );
    assert!(parse(&format!("{addr}tenant_from = \"namespace\"")).is_err());
    assert!(
        parse(&format!(
            "{addr}tenant_from = \"namespace\"\nnamespaces = [\"a\", \"b\"]\nnamespace_tenants = {{ a = \"x\" }}"
        ))
        .expect_err("b has no tenant")
        .reason
        .contains("namespace_tenants")
    );
    assert!(
        parse(&format!(
            "{addr}tenant_from = \"namespace\"\nnamespaces = [\"a\"]\nnamespace_tenants = {{ a = \"x\", z = \"y\" }}"
        ))
        .is_err(),
        "a tenant for a namespace the source does not watch"
    );
    assert!(parse(&format!(
        "{addr}tenant_from = \"namespace\"\nnamespaces = [\"a\"]\nnamespace_tenants = {{ a = \"x\" }}"
    ))
    .is_ok());

    let private = token_file("private", 0o600, "s3cret\n");
    let open = token_file("open", 0o644, "s3cret\n");
    let empty = token_file("empty", 0o600, "\n");
    assert!(
        parse(&format!(
            "{addr}token_file = {:?}",
            private.display().to_string()
        ))
        .is_ok()
    );
    let err = parse(&format!(
        "{addr}token_file = {:?}",
        open.display().to_string()
    ))
    .expect_err("readable by others");
    assert!(err.reason.contains("token_file"), "{err}");
    assert!(!err.to_string().contains("s3cret"));
    assert!(
        parse(&format!(
            "{addr}token_file = {:?}",
            empty.display().to_string()
        ))
        .is_err()
    );
    assert!(parse(&format!("{addr}token_file = \"/nonexistent/token\"")).is_err());
    for path in [private, open, empty] {
        let _ = std::fs::remove_file(path);
    }
}
