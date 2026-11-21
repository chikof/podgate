//! Black-box tests of the HTTP source against a scripted endpoint on a loopback port
//! (`tests/common/http_endpoint.rs`): both formats to apps, conditional requests, polling and
//! backoff, every kind of failure keeping the last good state, the emptiness rule, the trust rules
//! of the key-value layer, header secrets, TLS client certificates and the local-address rule.
//! Everything that waits has a deadline.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::etcd::Pki;
use common::http_endpoint::{FakeHttp, Reply};
use common::{DEADLINE, config};
use podgate_model::App;
use podgate_provider::http::HttpSource;
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::traefik_file::{Syntax, convert_inline};
use podgate_provider::{Config, Merged, Merger, UpstreamPolicy};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const POLICY: &str = r#"{"tenants": {
    "acme": {"allow": ["10.4.0.0/16"]},
    "globex": {"allow": ["10.5.0.0/16"]}
}}"#;

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
catch_all = true
"#;

const INSIDE: &str = "http://10.4.0.5:8080";

fn policy() -> UpstreamPolicy {
    UpstreamPolicy::parse(POLICY).expect("a valid policy")
}

/// The configuration with one HTTP source named `web` for `tenant`. `keys` are its own keys,
/// `tables` the tables below them (`[source.headers]`, `[source.tls]`).
fn http_config(url: &str, tenant: &str, keys: &str, tables: &str) -> Config {
    config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"http\"\nname = \"web\"\nurl = {url:?}\ntenant = {tenant:?}\n{keys}\n{tables}\n"
        ),
    )
}

fn acme_config(url: &str, keys: &str) -> Config {
    http_config(url, "acme", &format!("allow_local = true\n{keys}"), "")
}

fn try_source(config: &Config) -> Result<HttpSource, String> {
    HttpSource::from_config(&config.sources[0], &policy()).map_err(|err| err.to_string())
}

/// A source that polls every 50 ms and waits at most 400 ms after failures.
fn fast(config: &Config) -> HttpSource {
    try_source(config)
        .expect("a valid HTTP source")
        .with_timing(Duration::from_millis(50), Duration::from_millis(400))
}

fn app_value(id: &str, host: &str, upstream: &str) -> Value {
    json!({
        "id": id,
        "tls": { "mode": "acme" },
        "routers": [{ "name": "main", "match": { "host": [host] }, "service": "svc" }],
        "services": [{ "name": "svc", "type": "loadbalancer", "servers": [{ "url": upstream }] }],
        "revisions": [{ "id": "r1", "state": "serving", "weight": 1 }],
    })
}

fn doc(apps: &[Value]) -> String {
    json!({ "apps": apps }).to_string()
}

fn shop() -> String {
    doc(&[app_value("shop", "shop.acme.test", INSIDE)])
}

fn ids(state: &State) -> Vec<String> {
    state
        .apps
        .iter()
        .map(|app| app.app.id.to_string())
        .collect()
}

/// A running HTTP source and what it has said so far.
struct Run {
    rx: mpsc::Receiver<Update>,
    task: JoinHandle<()>,
    state: Option<State>,
    /// The app ids of every state that arrived, in order.
    history: Vec<Vec<String>>,
    outage: Option<String>,
}

impl Drop for Run {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Run {
    fn start(source: HttpSource) -> Self {
        let (tx, rx) = mpsc::channel(64);
        Self {
            rx,
            task: tokio::spawn(source.run(tx)),
            state: None,
            history: Vec::new(),
            outage: None,
        }
    }

    fn apply(&mut self, update: Update) {
        assert_eq!(&*update.source, "web");
        match update.body {
            UpdateBody::State(state) => {
                self.history.push(ids(&state));
                self.state = Some(state);
                self.outage = None;
            }
            UpdateBody::Outage(why) => self.outage = Some(why.to_string()),
        }
    }

    /// Takes what the source has said so far, after giving it a moment to say more.
    async fn settle(&mut self) {
        tokio::time::sleep(Duration::from_millis(150)).await;
        while let Ok(update) = self.rx.try_recv() {
            self.apply(update);
        }
    }

    async fn until(&mut self, what: &str, done: impl Fn(Option<&State>, Option<&str>) -> bool) {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                self.apply(update);
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

    async fn wait_outage(&mut self, needle: &str) -> String {
        self.until(&format!("an outage naming {needle:?}"), |_, outage| {
            outage.is_some_and(|outage| outage.contains(needle))
        })
        .await;
        self.outage.clone().expect("an outage")
    }

    /// Waits for the state to come back after an outage: a state with no outage.
    async fn wait_recovered(&mut self) -> State {
        self.until("the outage to clear", |state, outage| {
            state.is_some() && outage.is_none()
        })
        .await;
        self.state.clone().expect("a state")
    }
}

fn merge(config: &Config, state: &State) -> Merged {
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("web".into(), state.clone())]);
    Merger::new(config, policy()).merge(&states, &BTreeSet::new())
}

fn findings(merged: &Merged) -> Vec<(&'static str, String)> {
    merged
        .findings()
        .iter()
        .map(|finding| (finding.code, finding.object.to_string()))
        .collect()
}

struct Dir(PathBuf);

impl Dir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pgp-http-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the test directory");
        Self(path)
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("write a test file");
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- formats ----------------------------------------------------------------------------------

#[tokio::test]
async fn http_podgate_format_to_apps() {
    let endpoint = FakeHttp::start().await;
    let certificate = json!({ "hosts": ["shop.acme.test"], "cert_pem": "CERT", "key_pem": "KEY" });
    endpoint.set(
        "/",
        Reply::json(
            json!({
                "tenants": [{ "id": "globex", "hosts": ["*"] }],
                "apps": [
                    app_value("shop", "shop.acme.test", INSIDE),
                    app_value("api", "api.acme.test", "http://10.4.0.6:8080"),
                ],
                "certificates": [certificate],
            })
            .to_string(),
        ),
    );
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    let state = run.wait_ids(&["api", "shop"]).await;
    for app in &state.apps {
        assert_eq!(app.tenant.mapped.as_deref(), Some("acme"));
        assert_eq!(app.tenant.label, None);
        assert_eq!(&*app.app.tenant, "acme");
        assert_eq!(&*app.origin.source, "web");
        assert_eq!(&*app.origin.object, &*app.app.id);
        // An HTTP body has no creation time per object, and the fetch time is not one.
        assert_eq!(app.origin.first_seen, 0);
    }
    assert_eq!(state.certificates.len(), 1);
    assert_eq!(&*state.certificates[0].origin.object, "certificate-0");
    assert_eq!(state.certificates[0].tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(state.certificates[0].certificate.cert_pem, "CERT");

    // The same document as YAML, by its content type, is the same state; quoted wildcards are
    // not aliases.
    let yaml = "apps:\n  - id: api\n    tls: {mode: acme}\n    routers: [{name: main, match: {host: ['*.acme.test']}, service: svc}]\n    services: [{name: svc, type: loadbalancer, servers: [{url: 'http://10.4.0.6:8080'}]}]\n    revisions: [{id: r1, state: serving, weight: 1}]\n";
    endpoint.set("/", Reply::yaml(yaml));
    let state = run.wait_ids(&["api"]).await;
    assert_eq!(&*state.apps[0].app.tenant, "acme");
}

#[tokio::test]
async fn http_traefik_format_to_apps() {
    let text = json!({
        "http": {
            "routers": { "shop": { "rule": "Host(`shop.acme.test`)", "service": "web" } },
            "services": { "web": { "loadBalancer": { "servers": [{ "url": INSIDE }] } } },
            "middlewares": { "m": { "plugin": { "x": {} } } },
        }
    })
    .to_string();
    let endpoint = FakeHttp::start().await;
    endpoint.set("/", Reply::json(text.clone()));
    let config = acme_config(&endpoint.url("/"), "format = \"traefik\"");
    let mut run = Run::start(fast(&config));
    let state = run.wait_ids(&["traefik"]).await;

    // The app is what the merged Traefik translator makes of the text, with the source's tenant.
    let converted = convert_inline("traefik", &text, Syntax::Yaml).expect("converts");
    let Value::Object(mut expected) = converted.app else {
        panic!("an app object");
    };
    expected.insert("tenant".into(), json!("acme"));
    expected.insert("declared_by".into(), json!("http"));
    let expected: App = serde_json::from_value(Value::Object(expected)).expect("an app");
    assert_eq!(state.apps[0].app, expected);
    assert_eq!(state.apps[0].tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(state.apps[0].origin.first_seen, 0);
    assert!(!state.apps[0].app.routers.is_empty());

    // What the translator leaves out is reported, with its path, and the rest stays.
    let outage = run.wait_outage("http.middlewares.m.plugin").await;
    assert!(outage.contains("rejected"), "{outage}");

    // A YAML answer is the same document.
    endpoint.set("/", Reply::yaml(text));
    run.until("nothing changes", |state, _| state.is_some())
        .await;
}

// ---- conditional requests, polling, backoff ----------------------------------------------------

#[tokio::test]
async fn http_conditional_get_304() {
    let endpoint = FakeHttp::start().await;
    endpoint.set(
        "/",
        Reply::json(shop())
            .etag("\"v1\"")
            .last_modified("Wed, 21 Oct 2026 07:28:00 GMT"),
    );
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["shop"]).await;
    endpoint
        .wait_requests("three polls", |seen| seen.len() >= 3)
        .await;

    let seen = endpoint.requests();
    assert_eq!(seen[0].headers.get("if-none-match"), None);
    assert_eq!(seen[0].headers.get("if-modified-since"), None);
    assert_eq!(
        seen[0].headers.get("accept").map(String::as_str),
        Some("application/json, application/yaml;q=0.9")
    );
    for later in &seen[1..] {
        assert_eq!(
            later.headers.get("if-none-match").map(String::as_str),
            Some("\"v1\"")
        );
        assert_eq!(
            later.headers.get("if-modified-since").map(String::as_str),
            Some("Wed, 21 Oct 2026 07:28:00 GMT")
        );
    }
    run.settle().await;
    // The 304s keep the state and say nothing: exactly one state so far.
    assert_eq!(run.history, [["shop"]]);
    assert_eq!(run.outage, None);

    // A new version is fetched and replaces the state.
    endpoint.set(
        "/",
        Reply::json(doc(&[app_value("blog", "blog.acme.test", INSIDE)])).etag("\"v2\""),
    );
    run.wait_ids(&["blog"]).await;
    endpoint
        .wait_requests("a request with the new validator", |seen| {
            seen.iter()
                .any(|seen| seen.headers.get("if-none-match").map(String::as_str) == Some("\"v2\""))
        })
        .await;
}

#[tokio::test]
async fn http_poll_interval() {
    let endpoint = FakeHttp::start().await;
    endpoint.set("/", Reply::json(shop()).etag("\"v1\""));
    let config = acme_config(&endpoint.url("/"), "");
    let source = try_source(&config)
        .expect("a valid source")
        .with_timing(Duration::from_millis(150), Duration::from_secs(5));
    let mut run = Run::start(source);
    run.wait_ids(&["shop"]).await;
    endpoint
        .wait_requests("five polls", |seen| seen.len() >= 5)
        .await;
    let times: Vec<_> = endpoint.requests().iter().map(|seen| seen.at).collect();
    for pair in times.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(gap >= Duration::from_millis(140), "polled after {gap:?}");
        assert!(gap < Duration::from_secs(2), "polled after {gap:?}");
    }

    // The configured interval has a floor of 5 seconds, a default of 30, and bounded other limits.
    for (keys, needle) in [
        ("poll_secs = 4", "poll_secs"),
        ("timeout_secs = 0", "timeout_secs"),
        ("max_bytes = 16777217", "max_bytes"),
        ("max_bytes = 0", "max_bytes"),
    ] {
        let why = try_source(&acme_config(&endpoint.url("/"), keys)).expect_err(keys);
        assert!(why.contains(needle), "{keys}: {why}");
    }
    for keys in ["poll_secs = 5", "max_bytes = 16777216", ""] {
        try_source(&acme_config(&endpoint.url("/"), keys)).expect(keys);
    }
}

#[tokio::test]
async fn http_failure_backoff() {
    let endpoint = FakeHttp::start().await;
    endpoint.set("/", Reply::status(500));
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    run.wait_outage("answered 500").await;
    endpoint
        .wait_requests("six attempts", |seen| seen.len() >= 6)
        .await;
    let times: Vec<_> = endpoint.requests().iter().map(|seen| seen.at).collect();
    let gaps: Vec<Duration> = times.windows(2).map(|pair| pair[1] - pair[0]).collect();
    // 50, 100, 200, 400 ms and then the 400 ms cap, each up to a quarter longer.
    for (gap, floor) in gaps.iter().zip([50, 100, 200, 400, 400]) {
        assert!(
            *gap >= Duration::from_millis(floor - 10),
            "waited {gap:?} before an attempt that should wait {floor} ms; gaps {gaps:?}"
        );
        assert!(
            *gap < Duration::from_millis(floor * 5 / 4 + 250),
            "waited {gap:?} for {floor} ms; gaps {gaps:?}"
        );
    }
    assert!(gaps[3] > gaps[0] * 3, "the wait grew: {gaps:?}");

    // Success returns to the poll interval.
    endpoint.set("/", Reply::json(shop()));
    run.wait_ids(&["shop"]).await;
    let before = endpoint.requests().len();
    tokio::time::sleep(Duration::from_millis(900)).await;
    let after = endpoint.requests().len();
    assert!(after - before >= 5, "{} polls in 900 ms", after - before);
}

// ---- failures ---------------------------------------------------------------------------------

#[tokio::test]
async fn http_failure_keeps_last_state() {
    let endpoint = FakeHttp::start().await;
    endpoint.set("/", Reply::json(shop()));
    let config = acme_config(&endpoint.url("/"), "timeout_secs = 1");
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["shop"]).await;

    for (what, reply, needle) in [
        ("an error status", Reply::status(500), "answered 500"),
        (
            "bad JSON",
            Reply::json("{\"apps\": [oops"),
            "not valid JSON",
        ),
        (
            "a timeout",
            Reply::json(shop()).delay(Duration::from_secs(4)),
            "within 1 s",
        ),
        ("a dropped connection", Reply::dropped(), "failed"),
        ("a missing page", Reply::status(404), "answered 404"),
    ] {
        endpoint.set("/", reply);
        let outage = run.wait_outage(needle).await;
        assert!(!outage.is_empty(), "{what}");
        // The last good state is still there: the source never said an empty one.
        assert_eq!(
            run.state.as_ref().map(ids),
            Some(vec!["shop".to_owned()]),
            "{what}"
        );
        endpoint.set("/", Reply::json(shop()));
        run.wait_recovered().await;
    }
    assert!(
        run.history.iter().all(|apps| apps == &["shop"]),
        "a state other than the good one was sent: {:?}",
        run.history
    );
}

#[tokio::test]
async fn http_oversize_rejected() {
    let endpoint = FakeHttp::start().await;
    endpoint.set("/", Reply::json(shop()));
    let config = acme_config(&endpoint.url("/"), "max_bytes = 2048");
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["shop"]).await;

    // Over the limit by its declared length.
    let big = doc(&[
        app_value("big", "big.acme.test", INSIDE),
        json!({ "id": "pad", "pad": "x".repeat(4096) }),
    ]);
    endpoint.set("/", Reply::json(big));
    let outage = run.wait_outage("max_bytes").await;
    assert!(outage.contains("2048"), "{outage}");

    // Over the limit while streaming, with no length to go by: the read stops at the limit.
    endpoint.set("/", Reply::json(shop()));
    run.wait_recovered().await;
    endpoint.set("/", Reply::json("").endless(64 * 1024 * 1024));
    run.wait_outage("max_bytes").await;
    assert_eq!(run.state.as_ref().map(ids), Some(vec!["shop".to_owned()]));
}

#[tokio::test]
async fn http_wrong_content_type_rejected() {
    let endpoint = FakeHttp::start().await;
    endpoint.set("/", Reply::json(shop()));
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["shop"]).await;

    let other = doc(&[app_value("other", "other.acme.test", INSIDE)]);
    for (reply, needle) in [
        (
            Reply::json(other.clone()).content_type("text/html"),
            "text/html",
        ),
        (
            Reply::json(other.clone()).content_type("text/plain"),
            "text/plain",
        ),
        (
            Reply::json(other.clone()).header("content-type", ""),
            "Content-Type",
        ),
        (
            Reply::json(other.clone()).content_type("application/json; charset=latin1"),
            "charset",
        ),
        (
            Reply::json(other.clone()).header("content-encoding", "gzip"),
            "encoded",
        ),
    ] {
        endpoint.set("/", reply);
        run.wait_outage(needle).await;
        assert_eq!(run.state.as_ref().map(ids), Some(vec!["shop".to_owned()]));
    }

    // JSON and YAML types, with parameters and structured suffixes, are accepted.
    for content_type in [
        "application/json; charset=utf-8",
        "Application/JSON",
        "application/vnd.podgate+json",
        "application/x-yaml",
    ] {
        endpoint.set("/", Reply::json(other.clone()).content_type(content_type));
        run.wait_ids(&["other"]).await;
        endpoint.set("/", Reply::json(shop()));
        run.wait_ids(&["shop"]).await;
    }
}

#[tokio::test]
async fn http_yaml_aliases_refused() {
    let endpoint = FakeHttp::start().await;
    endpoint.set("/", Reply::json(shop()));
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["shop"]).await;
    endpoint.set(
        "/",
        Reply::yaml("apps: [&a {id: x}, *a]\ncopies: [*a, *a]\n"),
    );
    let outage = run.wait_outage("aliases").await;
    assert!(outage.contains("YAML"), "{outage}");
    assert_eq!(run.state.as_ref().map(ids), Some(vec!["shop".to_owned()]));
}

// ---- redirects --------------------------------------------------------------------------------

#[tokio::test]
async fn http_cross_host_redirect_refused() {
    let endpoint = FakeHttp::start().await;
    let elsewhere = FakeHttp::start().await;
    endpoint.set("/", Reply::json(shop()));
    endpoint.set("/start", Reply::json(shop()));
    let config = acme_config(&endpoint.url("/start"), "");
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["shop"]).await;

    // Another port, another host name for the same address, and another scheme: three origins.
    let port = endpoint.port();
    for location in [
        elsewhere.url("/stolen"),
        format!("http://localhost:{port}/stolen"),
        format!("https://127.0.0.1:{port}/stolen"),
    ] {
        endpoint.set("/start", Reply::redirect(302, &location));
        let outage = run.wait_outage("another origin").await;
        assert!(!outage.contains(&location), "{outage}");
        assert_eq!(run.state.as_ref().map(ids), Some(vec!["shop".to_owned()]));
        endpoint.set("/start", Reply::json(shop()));
        run.wait_recovered().await;
    }
    assert_eq!(elsewhere.requests().len(), 0, "the redirect was followed");
    assert_eq!(endpoint.count("/stolen"), 0);
}

#[tokio::test]
async fn http_same_origin_redirect_followed() {
    let endpoint = FakeHttp::start().await;
    let port = endpoint.port();
    endpoint.set("/r1", Reply::redirect(301, "/r2"));
    endpoint.set(
        "/r2",
        Reply::redirect(307, &format!("http://127.0.0.1:{port}/r3")),
    );
    endpoint.set("/r3", Reply::redirect(302, "/final"));
    endpoint.set("/r4", Reply::redirect(302, "/r1"));
    endpoint.set("/final", Reply::json(shop()));

    // Three redirects are followed.
    let config = acme_config(&endpoint.url("/r1"), "");
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["shop"]).await;
    drop(run);

    // A fourth is not.
    let config = acme_config(&endpoint.url("/r4"), "");
    let mut run = Run::start(fast(&config));
    let outage = run.wait_outage("more than 3 redirects").await;
    assert!(run.state.is_none(), "{outage}");
}

// ---- the emptiness rule -----------------------------------------------------------------------

#[tokio::test]
async fn http_empty_document_rules() {
    let endpoint = FakeHttp::start().await;
    endpoint.set("/", Reply::json(shop()));
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["shop"]).await;

    // Nothing that is not a valid document with an `apps` key replaces the state.
    for (body, needle) in [
        ("", "the answer is empty"),
        ("   \n", "the answer is empty"),
        ("{}", "no `apps` key"),
        ("null", "object"),
        ("[]", "object"),
        ("{\"certificates\": []}", "no `apps` key"),
        ("{\"apps\": {}}", "`apps` must be a list"),
        ("{\"apps\": [], \"junk\": 1}", "unknown top-level key"),
    ] {
        endpoint.set("/", Reply::json(body));
        run.wait_outage(needle).await;
        assert_eq!(
            run.state.as_ref().map(ids),
            Some(vec!["shop".to_owned()]),
            "{body:?} replaced the state"
        );
        endpoint.set("/", Reply::json(shop()));
        run.wait_recovered().await;
    }
    assert!(
        run.history.iter().all(|apps| apps == &["shop"]),
        "{:?}",
        run.history
    );

    // A deliberate empty configuration is a valid document, and it does replace the state.
    endpoint.set("/", Reply::json("{\"apps\": []}"));
    run.until("an empty state", |state, outage| {
        state.is_some_and(|state| state.apps.is_empty()) && outage.is_none()
    })
    .await;
    drop(run);

    // The same rule for a Traefik document: one that names no section is not a deletion.
    let config = acme_config(&endpoint.url("/"), "format = \"traefik\"");
    let traefik = json!({
        "http": {
            "routers": { "shop": { "rule": "Host(`shop.acme.test`)", "service": "web" } },
            "services": { "web": { "loadBalancer": { "servers": [{ "url": INSIDE }] } } },
        }
    })
    .to_string();
    endpoint.set("/", Reply::json(traefik.clone()));
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["traefik"]).await;
    for body in ["", "{}", "null", "{\"unrelated\": true}"] {
        endpoint.set("/", Reply::json(body));
        run.wait_outage("answer").await;
        assert_eq!(
            run.state.as_ref().map(ids),
            Some(vec!["traefik".to_owned()]),
            "{body:?}"
        );
        endpoint.set("/", Reply::json(traefik.clone()));
        run.wait_recovered().await;
    }

    // A section that is there is a document, even an empty one.
    endpoint.set("/", Reply::yaml("http: {}\n"));
    run.until("an app with no routers", |state, outage| {
        outage.is_none()
            && state.is_some_and(|state| state.apps.iter().all(|app| app.app.routers.is_empty()))
    })
    .await;
}

// ---- trust ------------------------------------------------------------------------------------

#[tokio::test]
async fn http_tenant_from_config_only() {
    let endpoint = FakeHttp::start().await;
    let mut named = app_value("named", "named.acme.test", INSIDE);
    named["tenant"] = json!("globex");
    let mut own = app_value("own", "own.acme.test", INSIDE);
    own["tenant"] = json!("acme");
    let mut by = app_value("by", "by.acme.test", INSIDE);
    by["declared_by"] = json!("file/globex:x");
    endpoint.set(
        "/",
        Reply::json(doc(&[
            named,
            own,
            by,
            app_value("plain", "plain.acme.test", INSIDE),
        ])),
    );
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    // A document that names a tenant, even the source's own, is left out and reported; the
    // others stay, all with the tenant of the configuration and no label claim.
    let state = run.wait_ids(&["by", "plain"]).await;
    let outage = run.wait_outage("tenant").await;
    assert!(outage.contains("named"), "{outage}");
    for app in &state.apps {
        assert_eq!(app.tenant.mapped.as_deref(), Some("acme"));
        assert_eq!(app.tenant.label, None);
        assert_eq!(&*app.app.tenant, "acme");
    }
    drop(run);

    // Another source of the same endpoint, mapped to globex, gets globex apps and no acme ones.
    let config = http_config(&endpoint.url("/"), "globex", "allow_local = true", "");
    let mut run = Run::start(fast(&config));
    let state = run.wait_ids(&["by", "plain"]).await;
    assert!(state.apps.iter().all(|app| &*app.app.tenant == "globex"));
}

#[test]
fn http_source_requires_tenant_allowlist() {
    let config = http_config("https://config.internal/p.json", "initech", "", "");
    let why = try_source(&config).expect_err("no allow list for initech");
    assert!(why.contains("kv_source_requires_tenant_allowlist"), "{why}");
    assert!(why.contains("initech"), "{why}");

    // The `default` entry is shared by every tenant and does not count.
    let shared =
        UpstreamPolicy::parse(r#"{"default": {"allow": ["10.0.0.0/8"]}}"#).expect("a valid policy");
    let why = HttpSource::from_config(&config.sources[0], &shared)
        .expect_err("a shared list is not the tenant's own")
        .to_string();
    assert!(why.contains("kv_source_requires_tenant_allowlist"), "{why}");

    // An unknown key is an error, so a misspelt `tenant` cannot move the apps.
    let config = config_with_extra_key("owner = \"globex\"");
    let why = try_source(&config).expect_err("an unknown key");
    assert!(why.contains("owner"), "{why}");
    // The tenant is required: there is no default tenant to fall back to.
    let config = config_without_tenant();
    let why = try_source(&config).expect_err("no tenant");
    assert!(why.contains("tenant"), "{why}");

    let config = http_config("https://config.internal/p.json", "acme", "", "");
    try_source(&config).expect("a tenant with an allow list starts");
}

fn config_with_extra_key(extra: &str) -> Config {
    http_config("https://config.internal/p.json", "acme", extra, "")
}

fn config_without_tenant() -> Config {
    config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"http\"\nname = \"web\"\nurl = \"https://config.internal/p.json\"\n"
        ),
    )
}

#[tokio::test]
async fn upstream_outside_allowlist_rejected_http() {
    let endpoint = FakeHttp::start().await;
    endpoint.set(
        "/",
        Reply::json(doc(&[
            app_value("inside", "shop.acme.test", INSIDE),
            app_value("outside", "api.acme.test", "http://10.9.0.5:8080"),
            // 10.5.0.0/16 is globex's range: acme may not point a server at its containers.
            app_value("theirs", "blog.acme.test", "http://10.5.0.7:8080"),
        ])),
    );
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    let state = run.wait_ids(&["inside", "outside", "theirs"]).await;
    let merged = merge(&config, &state);
    assert_eq!(
        findings(&merged),
        [
            ("upstream_forbidden", "outside".to_owned()),
            ("upstream_forbidden", "theirs".to_owned()),
        ]
    );
    let kept: Vec<&str> = merged.snapshot().apps.iter().map(|app| &*app.id).collect();
    assert_eq!(kept, ["web-inside"]);

    // The same for a Traefik document: its explicit server URLs go through the same check.
    let traefik = json!({
        "http": {
            "routers": { "shop": { "rule": "Host(`shop.acme.test`)", "service": "web" } },
            "services": { "web": { "loadBalancer": { "servers": [{ "url": "http://10.9.0.5:8080" }] } } },
        }
    });
    endpoint.set("/", Reply::json(traefik.to_string()));
    let config = acme_config(&endpoint.url("/"), "format = \"traefik\"");
    let mut run = Run::start(fast(&config));
    let state = run.wait_ids(&["traefik"]).await;
    let merged = merge(&config, &state);
    assert_eq!(
        findings(&merged),
        [("upstream_forbidden", "traefik".to_owned())]
    );
    assert!(merged.snapshot().apps.is_empty());
}

#[tokio::test]
async fn http_foreign_host_rejected() {
    let endpoint = FakeHttp::start().await;
    endpoint.set(
        "/",
        Reply::json(doc(&[
            app_value("mine", "shop.acme.test", INSIDE),
            app_value("theirs", "globex.test", INSIDE),
        ])),
    );
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    let state = run.wait_ids(&["mine", "theirs"]).await;
    let merged = merge(&config, &state);
    assert_eq!(
        findings(&merged),
        [("foreign_host_claim", "theirs".to_owned())]
    );
    let kept: Vec<&str> = merged.snapshot().apps.iter().map(|app| &*app.id).collect();
    assert_eq!(kept, ["web-mine"]);
}

#[tokio::test]
async fn http_catch_all_needs_allowance() {
    let endpoint = FakeHttp::start().await;
    let mut hostless = app_value("any", "unused.test", INSIDE);
    hostless["routers"][0]["match"] = json!({ "path_prefix": "/" });
    endpoint.set("/", Reply::json(doc(&[hostless])));
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    let state = run.wait_ids(&["any"]).await;
    let merged = merge(&config, &state);
    assert_eq!(
        findings(&merged),
        [("catch_all_not_allowed", "any".to_owned())]
    );
    assert!(merged.snapshot().apps.is_empty());
    drop(run);

    // globex has `catch_all = true` in the configuration.
    let mut hostless = app_value("any", "unused.test", "http://10.5.0.5:8080");
    hostless["routers"][0]["match"] = json!({ "path_prefix": "/" });
    endpoint.set("/", Reply::json(doc(&[hostless])));
    let config = http_config(&endpoint.url("/"), "globex", "allow_local = true", "");
    let mut run = Run::start(fast(&config));
    let state = run.wait_ids(&["any"]).await;
    let merged = merge(&config, &state);
    assert_eq!(findings(&merged), []);
    let kept: Vec<&str> = merged.snapshot().apps.iter().map(|app| &*app.id).collect();
    assert_eq!(kept, ["web-any"]);
}

#[tokio::test]
async fn http_unknown_fields_reject_the_object() {
    let endpoint = FakeHttp::start().await;
    let mut typo = app_value("typo", "typo.acme.test", INSIDE);
    typo["tls"] = json!({ "mode": "acme", "client_ca": "PEM" });
    endpoint.set(
        "/",
        Reply::json(doc(&[typo, app_value("ok", "ok.acme.test", INSIDE)])),
    );
    let config = acme_config(&endpoint.url("/"), "");
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["ok"]).await;
    let outage = run.wait_outage("unknown field").await;
    assert!(outage.contains("tls.client_ca"), "{outage}");
    assert!(!outage.contains("PEM"), "{outage}");
}

// ---- Traefik documents never read this machine's files -----------------------------------------

#[tokio::test]
async fn http_traefik_file_reference_refused() {
    let dir = Dir::new("file-reference");
    let marker = "MARKER-4f1d-never-read";
    let begin = ["-----", "BEGIN PRIVATE KEY", "-----"].concat();
    let secret = dir.write("secret.key", &format!("{begin}\n{marker}\n"));
    let missing = dir.0.join("no-such-file.pem");
    let inline = rcgen::generate_simple_self_signed(vec!["inline.acme.test".to_owned()])
        .expect("certificate");
    let (cert_pem, key_pem) = (inline.cert.pem(), inline.signing_key.serialize_pem());

    let document = |path: &Path| {
        json!({
            "http": {
                "routers": { "shop": { "rule": "Host(`shop.acme.test`)", "service": "web" } },
                "services": { "web": { "loadBalancer": { "servers": [{ "url": INSIDE }] } } },
                "middlewares": { "auth": { "basicAuth": { "usersFile": path } } },
            },
            "tls": { "certificates": [
                { "certFile": path, "keyFile": path },
                { "certFile": cert_pem, "keyFile": key_pem },
            ] },
        })
        .to_string()
    };
    let mut outages = Vec::new();
    let mut states = Vec::new();
    for path in [&secret, &missing] {
        let endpoint = FakeHttp::start().await;
        endpoint.set("/", Reply::json(document(path)));
        let config = acme_config(&endpoint.url("/"), "format = \"traefik\"");
        let mut run = Run::start(fast(&config));
        let state = run.wait_ids(&["traefik"]).await;
        let outage = run.wait_outage("file_reference_not_allowed").await;
        // The certificate of the inline PEM is kept, and the ones that named a file are not.
        assert_eq!(state.certificates.len(), 1, "{state:?}");
        assert_eq!(state.certificates[0].certificate.cert_pem, cert_pem);
        outages.push(outage);
        states.push(format!("{state:?}"));
    }
    // The same refusal whether the path holds a key or nothing, and it names no path.
    assert_eq!(outages[0], outages[1]);
    for text in outages.iter().chain(&states) {
        assert!(!text.contains(marker), "{text}");
        assert!(!text.contains(&dir.0.display().to_string()), "{text}");
    }
}

// ---- secrets, TLS, local addresses ------------------------------------------------------------

#[tokio::test]
async fn http_header_secret_from_file() {
    let dir = Dir::new("header-secret");
    let token = dir.write("token", "Bearer s3cr3t-token-5a9c\n");
    let endpoint = FakeHttp::start().await;
    endpoint.set("/", Reply::json(shop()));
    let config = http_config(
        &endpoint.url("/"),
        "acme",
        "allow_local = true",
        &format!(
            "[source.headers]\nAuthorization = \"file:{}\"\nX-Environment = \"production\"\n",
            token.display()
        ),
    );
    let source = fast(&config);
    // Nothing of the values shows in the debug output.
    let shown = format!("{source:?}");
    assert!(!shown.contains("s3cr3t"), "{shown}");
    assert!(!shown.contains("production"), "{shown}");
    assert!(shown.contains("authorization"), "{shown}");
    let mut run = Run::start(source);
    run.wait_ids(&["shop"]).await;
    let seen = &endpoint.requests()[0];
    // Read from the file with its newline removed, and sent as is.
    assert_eq!(
        seen.headers.get("authorization").map(String::as_str),
        Some("Bearer s3cr3t-token-5a9c")
    );
    assert_eq!(
        seen.headers.get("x-environment").map(String::as_str),
        Some("production")
    );

    // A missing file is a startup error that names the file and never a value.
    let why = try_source(&http_config(
        &endpoint.url("/"),
        "acme",
        "allow_local = true",
        "[source.headers]\nAuthorization = \"file:/nonexistent/token\"\n",
    ))
    .expect_err("a missing token file");
    assert!(why.contains("/nonexistent/token"), "{why}");
    // An empty file, a reserved header and a bad name are refused as well.
    let empty = dir.write("empty", "\n");
    for (headers, needle) in [
        (
            format!("Authorization = \"file:{}\"", empty.display()),
            "empty",
        ),
        ("Host = \"evil.test\"".to_owned(), "headers.Host"),
        ("If-None-Match = \"x\"".to_owned(), "headers.If-None-Match"),
        ("\"bad name\" = \"x\"".to_owned(), "not a header name"),
    ] {
        let why = try_source(&http_config(
            &endpoint.url("/"),
            "acme",
            "allow_local = true",
            &format!("[source.headers]\n{headers}\n"),
        ))
        .expect_err(&headers);
        assert!(why.contains(needle), "{headers}: {why}");
    }
    // Credentials never travel in clear over the network.
    let why = try_source(&http_config(
        "http://config.internal/p.json",
        "acme",
        "",
        "[source.headers]\nAuthorization = \"Bearer x\"\n",
    ))
    .expect_err("headers over http");
    assert!(why.contains("https://"), "{why}");
    assert!(!why.contains("Bearer"), "{why}");
}

#[tokio::test]
async fn http_tls_client_cert() {
    let dir = Dir::new("tls");
    let pki = Pki::new();
    let endpoint = FakeHttp::start_tls(&pki, true).await;
    endpoint.set("/", Reply::json(shop()));
    let (cert, key) = pki.client_files(&dir.0, "podgate");
    let ca = pki.ca_file(&dir.0);
    let tls = |ca: Option<&Path>, client: Option<(&Path, &Path)>| {
        let mut text = String::from("[source.tls]\n");
        if let Some(ca) = ca {
            text.push_str(&format!("ca_file = {:?}\n", ca.display().to_string()));
        }
        if let Some((cert, key)) = client {
            text.push_str(&format!(
                "cert_file = {:?}\nkey_file = {:?}\n",
                cert.display().to_string(),
                key.display().to_string()
            ));
        }
        text
    };

    // With the CA and a client certificate, the endpoint answers and saw the certificate.
    let config = http_config(
        &endpoint.url("/"),
        "acme",
        "allow_local = true",
        &tls(Some(&ca), Some((&cert, &key))),
    );
    let mut run = Run::start(fast(&config));
    run.wait_ids(&["shop"]).await;
    assert!(endpoint.requests().iter().all(|seen| seen.client_cert));
    drop(run);

    // Without the client certificate the endpoint refuses and nothing is read.
    let before = endpoint.requests().len();
    let config = http_config(
        &endpoint.url("/"),
        "acme",
        "allow_local = true",
        &tls(Some(&ca), None),
    );
    let mut run = Run::start(fast(&config));
    run.until("an outage", |_, outage| outage.is_some()).await;
    assert!(run.state.is_none());
    assert_eq!(endpoint.requests().len(), before);
    drop(run);

    // Without the CA the platform's roots do not trust the endpoint's certificate.
    let config = http_config(
        &endpoint.url("/"),
        "acme",
        "allow_local = true",
        &tls(None, Some((&cert, &key))),
    );
    let mut run = Run::start(fast(&config));
    run.until("an outage", |_, outage| outage.is_some()).await;
    assert!(run.state.is_none());

    // A certificate without its key, a file without a certificate and a TLS table on a plain
    // URL are start errors.
    for (tables, needle) in [
        (
            format!(
                "[source.tls]\ncert_file = {:?}\n",
                cert.display().to_string()
            ),
            "go together",
        ),
        (
            format!(
                "[source.tls]\nca_file = {:?}\n",
                cert.display()
                    .to_string()
                    .replace("podgate.pem", "none.pem")
            ),
            "ca_file",
        ),
    ] {
        let why = try_source(&http_config(
            &endpoint.url("/"),
            "acme",
            "allow_local = true",
            &tables,
        ))
        .expect_err(needle);
        assert!(why.contains(needle), "{why}");
    }
    let plain = FakeHttp::start().await;
    let why = try_source(&http_config(
        &plain.url("/"),
        "acme",
        "allow_local = true",
        &tls(Some(&ca), None),
    ))
    .expect_err("tls on http");
    assert!(why.contains("https://"), "{why}");
}

#[test]
fn http_local_url_refused_without_allow_local() {
    for url in [
        "http://127.0.0.1:8080/p.json",
        "http://127.1.2.3/p.json",
        "http://localhost/p.json",
        "http://api.localhost/p.json",
        "http://[::1]:9/p.json",
        "http://[::ffff:127.0.0.1]/p.json",
        "http://169.254.169.254/latest/meta-data",
        "http://[fe80::1]/p.json",
        "http://0.0.0.0/p.json",
        "https://127.0.0.1/p.json",
    ] {
        let why = try_source(&http_config(url, "acme", "", "")).expect_err(url);
        assert!(why.contains("allow_local"), "{url}: {why}");
        // The error never quotes the URL: a token may sit in its query.
        assert!(!why.contains("169.254"), "{url}: {why}");
        try_source(&http_config(url, "acme", "allow_local = true", "")).expect(url);
    }
    // Addresses that are only private are fine: the config server may be on the cluster network.
    for url in ["http://10.0.0.5/p.json", "https://config.internal/p.json"] {
        try_source(&http_config(url, "acme", "", "")).expect(url);
    }
    // Other schemes, credentials and a missing host are refused.
    for url in [
        "ftp://config.internal/p.json",
        "https://user:pass@config.internal/p.json",
        "file:///etc/podgate.json",
        "/p.json",
    ] {
        let why = try_source(&http_config(url, "acme", "allow_local = true", "")).expect_err(url);
        assert!(!why.contains("pass"), "{url}: {why}");
    }
}
