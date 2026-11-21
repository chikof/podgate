//! Black-box tests of the Nomad source against a fake Nomad API on a loopback port
//! (`tests/common/nomad.rs`): tags to apps, servers from registrations, blocking queries,
//! reconnects, tenants and trust, the upstream policy and the program that runs it. Everything
//! that waits has a deadline.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use common::nomad::{FakeNomad, Reg};
use common::{DEADLINE, config};
use podgate_provider::nomad::NomadSource;
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::{Config, Merged, Merger, UpstreamPolicy};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A change must show within the source's quiet window plus scheduling slack, far below the
/// hour the tests give `resync_secs`: only a blocking query can deliver it in time.
const PROMPT: Duration = Duration::from_secs(4);

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
"#;

/// The configuration with one nomad source named `nomad` after `tenants`, and `settings` as the
/// source's own keys.
fn nomad_config(address: &str, tenants: &str, settings: &str) -> Config {
    config(
        std::path::Path::new("/nonexistent/admin.sock"),
        &format!(
            "{tenants}\n[[source]]\nkind = \"nomad\"\nname = \"nomad\"\naddress = {address:?}\nresync_secs = 3600\n{settings}\n"
        ),
    )
}

fn source_of(config: &Config) -> NomadSource {
    NomadSource::from_config(&config.sources[0]).expect("a valid nomad source")
}

/// A running nomad source and what it has said so far.
struct Watcher {
    rx: mpsc::Receiver<Update>,
    task: JoinHandle<()>,
    state: Option<State>,
    /// How many complete states arrived.
    states: usize,
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
            states: 0,
            outage: None,
        }
    }

    async fn until(&mut self, what: &str, done: impl Fn(Option<&State>, Option<&str>) -> bool) {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                assert_eq!(&*update.source, "nomad");
                match update.body {
                    UpdateBody::State(state) => {
                        self.state = Some(state);
                        self.states += 1;
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

    /// Waits for the state `expected` and for the report that names `needle`.
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

/// An instance in the `default` namespace that serves `host`.
fn web(service: &str, ip: &str, port: u16, host: &str) -> Reg {
    in_namespace("default", service, ip, port, host)
}

fn in_namespace(namespace: &str, service: &str, ip: &str, port: u16, host: &str) -> Reg {
    Reg::new(namespace, service, ip, port)
        .tag("podgate.enable=true")
        .tag(&format!("podgate.host={host}"))
}

fn merge(config: &Config, policy: UpstreamPolicy, state: State) -> Merged {
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("nomad".into(), state)]);
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

async fn wait_blocked(nomad: &FakeNomad) {
    let wait = async {
        while nomad.blocked() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(DEADLINE, wait)
        .await
        .expect("the source holds a blocking query");
}

// ---- tags to apps -----------------------------------------------------------------------------

#[tokio::test]
async fn nomad_services_to_apps() {
    let nomad = FakeNomad::start().await;
    nomad.add(
        web(
            "shop",
            "10.4.0.5",
            8080,
            "shop.acme.test, www.shop.acme.test",
        )
        .tag("urlprefix-/shop")
        .tag("version=7")
        .created(42),
    );
    let mut watcher = Watcher::start(&nomad_config(&nomad.address(), "", ""));
    let state = watcher.wait_ids(&["default.shop"]).await;
    let app = app_of(&state, "default.shop");
    assert_eq!(&*app.origin.object, "default.shop");
    assert!(
        app.origin.first_seen > 1_700_000_000,
        "the time the source first saw the app, not a raft index: {}",
        app.origin.first_seen
    );
    assert_eq!(app.tenant.mapped.as_deref(), Some("default"));
    assert_eq!(app.tenant.label, None);
    assert_eq!(
        app_json(&state, "default.shop"),
        json!({
            "id": "default.shop",
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
    assert_eq!(watcher.report(), "");
    assert!(
        nomad
            .requests()
            .iter()
            .all(|request| request.method == "GET"),
        "the source only reads: {:?}",
        nomad.requests()
    );
}

#[tokio::test]
async fn nomad_instances_to_servers() {
    let nomad = FakeNomad::start().await;
    // Three allocations of one service, an IPv6 one among them.
    nomad.add(web("shop", "10.4.0.6", 8081, "shop.acme.test").created(2));
    nomad.add(web("shop", "10.4.0.5", 8080, "shop.acme.test").created(1));
    nomad.add(web("shop", "::1", 9000, "shop.acme.test").created(3));
    // Two services of one job that share an app by name: one app, both services' servers.
    nomad.add(web("api-a", "10.4.1.1", 7000, "api.acme.test").tag("podgate.app=api"));
    nomad.add(web("api-b", "10.4.1.2", 7001, "api.acme.test").tag("podgate.app=api"));
    // What cannot be a server: a name, a missing port, and a tag that names a port.
    nomad.add(web("named", "db.internal", 5432, "named.acme.test"));
    nomad.add(web("portless", "10.4.2.1", 0, "portless.acme.test"));
    nomad.add(web("taggedport", "10.4.3.1", 8080, "taggedport.acme.test").tag("podgate.port=22"));
    let mut watcher = Watcher::start(&nomad_config(&nomad.address(), "", ""));
    let state = watcher
        .wait_ids_and_report(&["default.api", "default.shop"], "taggedport")
        .await;
    assert_eq!(
        servers_of(&state, "default.shop", "default"),
        [
            "http://10.4.0.5:8080",
            "http://10.4.0.6:8081",
            "http://[::1]:9000"
        ],
        "the registered address and port, in address order"
    );
    assert_eq!(
        servers_of(&state, "default.api", "default"),
        ["http://10.4.1.1:7000", "http://10.4.1.2:7001"]
    );
    let report = watcher.report().to_owned();
    for needle in [
        "default/named",
        "\"db.internal\" is not an IP address",
        "default/portless",
        "the registration has no port",
        "default/taggedport",
        "podgate.port: not used with Nomad",
    ] {
        assert!(report.contains(needle), "{needle:?} missing from {report}");
    }
}

#[tokio::test]
async fn nomad_exposed_by_default_false() {
    let nomad = FakeNomad::start().await;
    nomad.add(web("tagged", "10.4.0.1", 80, "tagged.acme.test"));
    // Routing tags without `podgate.enable`, an explicit opt-out, and no tags at all.
    nomad.add(
        Reg::new("default", "implicit", "10.4.0.2", 80).tag("podgate.host=implicit.acme.test"),
    );
    nomad.add(
        Reg::new("default", "optout", "10.4.0.3", 80)
            .tags(&["podgate.enable=false", "podgate.host=optout.acme.test"]),
    );
    nomad.add(Reg::new("default", "bare", "10.4.0.4", 80));
    let mut watcher = Watcher::start(&nomad_config(&nomad.address(), "", ""));
    watcher.wait_ids(&["default.tagged"]).await;
    assert_eq!(
        watcher.report(),
        "",
        "services that are not exposed are not an error"
    );
    assert_eq!(
        nomad.instance_reads(),
        1,
        "the instances of services that are not exposed are not even read"
    );

    // With `exposed_by_default` a service without `podgate.enable` counts; the explicit
    // opt-out still wins, and one that says nothing about routing is reported.
    let mut watcher = Watcher::start(&nomad_config(
        &nomad.address(),
        "",
        "exposed_by_default = true",
    ));
    watcher
        .wait_ids_and_report(&["default.implicit", "default.tagged"], "default/bare")
        .await;
    assert!(
        watcher.report().contains("no router"),
        "{}",
        watcher.report()
    );
}

#[tokio::test]
async fn nomad_unknown_tag_rejected() {
    let nomad = FakeNomad::start().await;
    nomad.add(web("good", "10.4.0.1", 80, "good.acme.test"));
    nomad
        .add(web("misspelt", "10.4.0.2", 80, "misspelt.acme.test").tag("podgate.hots=x.acme.test"));
    nomad.add(web("unpaired", "10.4.0.3", 80, "unpaired.acme.test").tag("podgate.tls"));
    nomad.add(web("twice", "10.4.0.4", 80, "twice.acme.test").tag("podgate.host=other.acme.test"));
    nomad.add(
        web("address", "10.4.0.5", 80, "address.acme.test")
            .tag("podgate.router.x.match={\"host\":[\"x.acme.test\"]}")
            .tag("podgate.router.x.service=http://10.9.9.9:80"),
    );
    let mut watcher = Watcher::start(&nomad_config(&nomad.address(), "", ""));
    watcher
        .wait_ids_and_report(&["default.good"], "default/address")
        .await;
    let report = watcher.report().to_owned();
    for needle in [
        "default/misspelt",
        "unknown label podgate.hots",
        "default/unpaired",
        "podgate.tls: a podgate tag must be written key=value",
        "default/twice",
        "podgate.host: the tag is given more than once",
        "default/address",
        "names an address",
    ] {
        assert!(report.contains(needle), "{needle:?} missing from {report}");
    }
}

// ---- blocking queries and outages -------------------------------------------------------------

#[tokio::test]
async fn nomad_blocking_query_updates() {
    let nomad = FakeNomad::start().await;
    nomad.add(web("first", "10.4.0.1", 80, "first.acme.test"));
    let mut watcher = Watcher::start(&nomad_config(&nomad.address(), "", ""));
    watcher.wait_ids(&["default.first"]).await;
    wait_blocked(&nomad).await;

    // The source is now parked in a blocking query; a registration must wake it, long before
    // the hour of `resync_secs`.
    let started = Instant::now();
    nomad.add(web("second", "10.4.0.2", 80, "second.acme.test"));
    watcher.wait_ids(&["default.first", "default.second"]).await;
    assert!(started.elapsed() < PROMPT, "took {:?}", started.elapsed());
    wait_blocked(&nomad).await;
    let started = Instant::now();
    nomad.remove("default", "first");
    watcher.wait_ids(&["default.second"]).await;
    assert!(started.elapsed() < PROMPT, "took {:?}", started.elapsed());

    let queries = nomad.blocking_queries();
    assert_eq!(
        queries[0].param("index"),
        Some("0"),
        "the first query does not block"
    );
    assert!(
        queries
            .iter()
            .skip(1)
            .all(|query| query.param("index") != Some("0")),
        "later queries carry the index the server answered with: {queries:?}"
    );
    assert!(
        queries
            .iter()
            .all(|query| query.param("wait") == Some("60s")
                && query.param("namespace") == Some("default")),
        "{queries:?}"
    );
}

#[tokio::test]
async fn nomad_reconnects() {
    let nomad = FakeNomad::start().await;
    nomad.add(web("first", "10.4.0.1", 80, "first.acme.test"));
    let mut watcher = Watcher::start(&nomad_config(&nomad.address(), "", ""));
    watcher.wait_ids(&["default.first"]).await;
    wait_blocked(&nomad).await;

    // The server dies while the source is parked in a blocking query, and comes back with
    // another registration.
    nomad.stop();
    watcher.wait_outage("cannot reach Nomad").await;
    let before = nomad.blocking_queries().len();
    nomad.add(web("second", "10.4.0.2", 80, "second.acme.test"));
    nomad.restart().await;
    watcher.wait_ids(&["default.first", "default.second"]).await;
    wait_blocked(&nomad).await;
    assert!(
        nomad.blocking_queries().len() > before,
        "the blocking query was opened again"
    );
    assert_eq!(watcher.report(), "", "the outage is over");
}

#[tokio::test]
async fn nomad_outage_keeps_last_state() {
    let nomad = FakeNomad::start().await;
    nomad.add(web("first", "10.4.0.1", 80, "first.acme.test"));
    let mut watcher = Watcher::start(&nomad_config(&nomad.address(), "", ""));
    watcher.wait_ids(&["default.first"]).await;
    wait_blocked(&nomad).await;
    let states = watcher.states;

    nomad.stop();
    watcher.wait_outage("cannot reach Nomad").await;
    // However long it lasts, the source never sends a state that says "nothing is registered":
    // that would delete every route.
    let quiet = tokio::time::sleep(Duration::from_millis(800));
    tokio::pin!(quiet);
    loop {
        tokio::select! {
            () = &mut quiet => break,
            update = watcher.rx.recv() => {
                let update = update.expect("the source keeps running");
                assert!(
                    matches!(update.body, UpdateBody::Outage(_)),
                    "only outages while Nomad is down: {update:?}"
                );
            }
        }
    }
    assert_eq!(watcher.states, states);
    assert_eq!(
        ids(watcher.state.as_ref().expect("the last state")),
        ["default.first"]
    );

    // An answer that is an error is an outage too: the last state stays.
    nomad.restart().await;
    nomad.require_token("a-token-the-source-does-not-have");
    nomad.remove("default", "first");
    watcher.wait_outage("403").await;
    assert_eq!(watcher.states, states, "an ACL error is not an empty list");
}

// ---- tenants and trust ------------------------------------------------------------------------

const NAMESPACES: &str = r#"
namespaces = ["default", "team-a", "team-b"]
namespace_tenants = { team-a = "acme", team-b = "globex" }
"#;

#[tokio::test]
async fn nomad_namespace_tenant() {
    let nomad = FakeNomad::start().await;
    nomad.add(in_namespace(
        "team-a",
        "web",
        "10.4.0.1",
        80,
        "web.acme.test",
    ));
    nomad.add(in_namespace(
        "team-b",
        "web",
        "10.4.0.2",
        80,
        "web.globex.test",
    ));
    nomad.add(in_namespace(
        "default",
        "web",
        "10.4.0.3",
        80,
        "web.example.test",
    ));
    // A namespace the source was not told to watch is never asked about.
    nomad.add(in_namespace(
        "elsewhere",
        "web",
        "10.4.0.4",
        80,
        "web.acme.test",
    ));
    let config = nomad_config(&nomad.address(), TENANTS, NAMESPACES);
    let mut watcher = Watcher::start(&config);
    let state = watcher
        .wait_ids(&["default.web", "team-a.web", "team-b.web"])
        .await;
    let tenants: Vec<(String, Option<&str>)> = state
        .apps
        .iter()
        .map(|app| (app.app.id.to_string(), app.tenant.mapped.as_deref()))
        .collect();
    assert_eq!(
        tenants,
        [
            ("default.web".to_owned(), Some("default")),
            ("team-a.web".to_owned(), Some("acme")),
            ("team-b.web".to_owned(), Some("globex")),
        ]
    );
    assert!(
        nomad
            .requests()
            .iter()
            .all(|request| request.param("namespace") != Some("elsewhere")),
        "{:?}",
        nomad.requests()
    );
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [
            ("nomad-default.web".to_owned(), "default".to_owned()),
            ("nomad-team-a.web".to_owned(), "acme".to_owned()),
            ("nomad-team-b.web".to_owned(), "globex".to_owned()),
        ]
    );
}

#[tokio::test]
async fn nomad_tag_cannot_claim_foreign_host() {
    let nomad = FakeNomad::start().await;
    nomad.add(in_namespace(
        "team-a",
        "mine",
        "10.4.0.1",
        80,
        "web.acme.test",
    ));
    // A job in acme's namespace that claims globex's host, with and without naming globex.
    nomad.add(in_namespace(
        "team-a",
        "grab",
        "10.4.0.2",
        80,
        "www.globex.test",
    ));
    nomad.add(
        in_namespace("team-a", "sneaky", "10.4.0.3", 80, "shop.globex.test")
            .tag("podgate.tenant=globex"),
    );
    let settings = "namespaces = [\"team-a\"]\nnamespace_tenants = { team-a = \"acme\" }";
    let untrusted = nomad_config(&nomad.address(), TENANTS, settings);
    let mut watcher = Watcher::start(&untrusted);
    let state = watcher
        .wait_ids(&["team-a.grab", "team-a.mine", "team-a.sneaky"])
        .await;
    assert_eq!(
        app_of(&state, "team-a.sneaky").tenant.label.as_deref(),
        Some("globex"),
        "the source passes the tag on as a claim, and the core decides"
    );
    let merged = merge(&untrusted, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [("nomad-team-a.mine".to_owned(), "acme".to_owned())]
    );
    let codes: BTreeSet<&str> = finding_codes(&merged)
        .iter()
        .map(|(code, _)| *code)
        .collect();
    assert_eq!(
        codes,
        BTreeSet::from(["foreign_host_claim", "label_ignored"]),
        "{:?}",
        finding_codes(&merged)
    );

    // Only a tenant that lists the source in `label_sources` honours a tenant tag, and then
    // only the tenant that did.
    let trusted_tenants = TENANTS.replace(
        "hosts = [\"globex.test\", \"*.globex.test\"]",
        "hosts = [\"globex.test\", \"*.globex.test\"]\nlabel_sources = [\"nomad\"]",
    );
    let trusted = nomad_config(&nomad.address(), &trusted_tenants, settings);
    let mut watcher = Watcher::start(&trusted);
    let state = watcher
        .wait_ids(&["team-a.grab", "team-a.mine", "team-a.sneaky"])
        .await;
    let merged = merge(&trusted, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [
            ("nomad-team-a.mine".to_owned(), "acme".to_owned()),
            ("nomad-team-a.sneaky".to_owned(), "globex".to_owned()),
        ],
        "a tenant that trusts the source accepts its tag; the job without a tag stays out"
    );
    assert_eq!(
        finding_codes(&merged)
            .iter()
            .map(|(code, object)| (*code, object.as_str()))
            .collect::<Vec<_>>(),
        [("foreign_host_claim", "team-a.grab")]
    );
}

#[tokio::test]
async fn upstream_outside_allowlist_rejected_nomad() {
    let nomad = FakeNomad::start().await;
    nomad.add(web("inside", "10.4.0.1", 80, "in.acme.test"));
    // A job can advertise any address it likes: the registration says 10.5.0.1.
    nomad.add(web("outside", "10.5.0.1", 80, "out.acme.test"));
    let config = nomad_config(
        &nomad.address(),
        TENANTS,
        "namespace_tenants = { default = \"acme\" }",
    );
    let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)
        .expect("policy");
    let mut watcher = Watcher::start(&config);
    let state = watcher
        .wait_ids(&["default.inside", "default.outside"])
        .await;
    let merged = merge(&config, policy, state);
    assert_eq!(
        merged_apps(&merged),
        [("nomad-default.inside".to_owned(), "acme".to_owned())]
    );
    let forbidden: Vec<String> = finding_codes(&merged)
        .into_iter()
        .filter(|(code, _)| *code == "upstream_forbidden")
        .map(|(_, object)| object)
        .collect();
    assert_eq!(forbidden, ["default.outside"]);
}

// ---- configuration and the program ------------------------------------------------------------

#[tokio::test]
async fn nomad_config_rejects_bad_entries() {
    let token = std::env::temp_dir().join(format!("pgp-nomad-token-{}", std::process::id()));
    std::fs::write(&token, "  \n").expect("token file");
    let token_key = format!("token_file = {:?}", token.display().to_string());
    let cases: [(&str, &str); 9] = [
        (
            "address = \"http://127.0.0.1:4646\"\nfoo = 1",
            "unknown field",
        ),
        ("address = \"127.0.0.1:4646\"", "address"),
        ("address = \"ftp://127.0.0.1\"", "address"),
        ("address = \"http://tok@127.0.0.1:4646\"", "credentials"),
        ("address = \"http://127.0.0.1:4646/v1\"", "origin"),
        (
            "address = \"http://127.0.0.1:4646\"\nnamespaces = [\"a\"]\nnamespace_tenants = { b = \"x\" }",
            "namespace_tenants",
        ),
        (
            "address = \"http://127.0.0.1:4646\"\nnamespaces = [\"*\"]",
            "wildcard",
        ),
        (
            "address = \"http://127.0.0.1:4646\"\nresync_secs = 0",
            "resync_secs",
        ),
        (
            &format!("address = \"http://127.0.0.1:4646\"\n{token_key}"),
            "is empty",
        ),
    ];
    for (settings, needle) in cases {
        let config = config(
            std::path::Path::new("/x.sock"),
            &format!("[[source]]\nkind = \"nomad\"\nname = \"nomad\"\n{settings}\n"),
        );
        let err = NomadSource::from_config(&config.sources[0])
            .expect_err(settings)
            .to_string();
        assert!(err.contains(needle), "{needle:?} missing from {err}");
        assert!(err.starts_with("source nomad: "), "{err}");
    }
    let _ = std::fs::remove_file(token);
}

#[tokio::test]
async fn nomad_runs_in_the_program() {
    let nomad = FakeNomad::start().await;
    nomad.add(web("shop", "10.4.0.5", 8080, "shop.acme.test"));
    let path = std::env::temp_dir().join(format!("pgp-nomad-print-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        format!(
            "admin_socket = \"/nonexistent/admin.sock\"\n[[source]]\nkind = \"nomad\"\nname = \"nomad\"\naddress = {:?}\n",
            nomad.address()
        ),
    )
    .expect("config");
    let output = tokio::task::spawn_blocking({
        let path = path.clone();
        move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_podgate-provider"))
                .args(["print", "--config"])
                .arg(path)
                .output()
                .expect("run print")
        }
    })
    .await
    .expect("print ran");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("\"id\":\"nomad-default.shop\""), "{stdout}");
    assert!(stdout.contains("http://10.4.0.5:8080"), "{stdout}");
    let _ = std::fs::remove_file(path);
}
