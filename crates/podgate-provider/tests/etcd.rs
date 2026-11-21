//! Black-box tests of the etcd source against a fake etcd JSON gateway on a loopback port
//! (`tests/common/etcd.rs`): layouts to apps, the watch and its repairs, outages, authentication,
//! TLS client certificates and the promise that the client only reads. Everything that waits has
//! a deadline.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::etcd::{FakeEtcd, Pki};
use common::{DEADLINE, config};
use podgate_provider::etcd::EtcdSource;
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::{Config, UpstreamPolicy};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A change must show within the source's quiet window plus scheduling slack, far below the hour
/// the tests give `resync_secs`: only the watch can deliver it in time.
const PROMPT: Duration = Duration::from_secs(4);

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
"#;

fn policy() -> UpstreamPolicy {
    UpstreamPolicy::parse(POLICY).expect("a valid policy")
}

/// The configuration with one etcd source named `etcd`: `keys` are its own keys, `tables` the
/// tables below them (`[source.tls]`), and one `podgate-json` prefix for acme follows.
fn etcd_config(endpoint: &str, keys: &str, tables: &str) -> Config {
    config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"etcd\"\nname = \"etcd\"\nendpoints = [{endpoint:?}]\nresync_secs = 3600\n{keys}\n{tables}\n[[source.prefix]]\nprefix = \"podgate/acme\"\ntenant = \"acme\"\nlayout = \"podgate-json\"\n"
        ),
    )
}

fn source_of(config: &Config) -> EtcdSource {
    EtcdSource::from_config(&config.sources[0], &policy()).expect("a valid etcd source")
}

fn doc(host: &str, upstream: &str) -> String {
    json!({
        "tls": { "mode": "acme" },
        "routers": [{ "name": "main", "match": { "host": [host] }, "service": "svc" }],
        "services": [{ "name": "svc", "type": "loadbalancer", "servers": [{ "url": upstream }] }],
        "revisions": [{ "id": "r1", "state": "serving", "weight": 1 }],
    })
    .to_string()
}

/// A running etcd source and what it has said so far.
struct Watcher {
    rx: mpsc::Receiver<Update>,
    task: JoinHandle<()>,
    state: Option<State>,
    /// The app ids of every state that arrived, in order.
    history: Vec<Vec<String>>,
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
            history: Vec::new(),
            outage: None,
        }
    }

    async fn until(&mut self, what: &str, done: impl Fn(Option<&State>, Option<&str>) -> bool) {
        self.until_within(DEADLINE, what, done).await;
    }

    async fn until_within(
        &mut self,
        within: Duration,
        what: &str,
        done: impl Fn(Option<&State>, Option<&str>) -> bool,
    ) {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                assert_eq!(&*update.source, "etcd");
                match update.body {
                    UpdateBody::State(state) => {
                        self.history.push(ids(&state));
                        self.state = Some(state);
                        self.outage = None;
                    }
                    UpdateBody::Outage(why) => self.outage = Some(why.to_string()),
                }
            }
        };
        if tokio::time::timeout(within, wait).await.is_err() {
            panic!(
                "timed out waiting for: {what}; apps: {:?}; outage: {:?}",
                self.state.as_ref().map(ids),
                self.outage
            );
        }
    }

    async fn wait_ids(&mut self, expected: &[&str]) -> State {
        self.wait_ids_within(DEADLINE, expected).await
    }

    async fn wait_ids_within(&mut self, within: Duration, expected: &[&str]) -> State {
        let expected: Vec<String> = expected.iter().map(|id| (*id).to_owned()).collect();
        self.until_within(within, &format!("apps {expected:?}"), |state, _| {
            state.is_some_and(|state| ids(state) == expected)
        })
        .await;
        self.state.clone().expect("a state")
    }

    async fn wait_outage(&mut self, needle: &str) -> String {
        self.until(&format!("an outage naming {needle}"), |_, outage| {
            outage.is_some_and(|why| why.contains(needle))
        })
        .await;
        self.outage.clone().expect("an outage")
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

fn servers_of(state: &State, id: &str) -> Vec<String> {
    let app = state
        .apps
        .iter()
        .find(|app| &*app.app.id == id)
        .unwrap_or_else(|| panic!("no app {id}: {:?}", ids(state)));
    let value = serde_json::to_value(&app.app).expect("an app serializes");
    value["services"][0]["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .filter_map(|server| server["url"].as_str().map(str::to_owned))
        .collect()
}

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgp-etcd-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

// ---- layouts -----------------------------------------------------------------------------------

#[tokio::test]
async fn etcd_json_layout_to_apps() {
    let etcd = FakeEtcd::start().await;
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    etcd.put(
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    etcd.put(
        "podgate/acme/certificates/shop",
        &json!({ "hosts": ["shop.acme.test"], "cert_pem": "CERT", "key_pem": "KEY" }).to_string(),
    );
    // Neighbours that must not be read: another tenant's prefix, and a prefix that only shares
    // letters with this one.
    etcd.put(
        "podgate/globex/apps/site",
        &doc("globex.test", "http://10.5.0.5:8080"),
    );
    etcd.put(
        "podgate/acme2/apps/site",
        &doc("x.acme.test", "http://10.4.0.9:8080"),
    );

    let mut watcher = Watcher::start(&etcd_config(&etcd.url(), "", ""));
    let state = watcher.wait_ids(&["api", "site"]).await;
    assert_eq!(servers_of(&state, "site"), ["http://10.4.0.5:8080"]);
    assert_eq!(servers_of(&state, "api"), ["http://10.4.0.6:8080"]);
    for app in &state.apps {
        assert_eq!(app.tenant.mapped.as_deref(), Some("acme"));
        assert_eq!(app.tenant.label, None);
        assert_eq!(&*app.origin.source, "etcd");
        assert_eq!(app.origin.first_seen, 0);
    }
    assert_eq!(state.certificates.len(), 1);
    assert_eq!(state.certificates[0].tenant.mapped.as_deref(), Some("acme"));

    // The read asked for the prefix with its slash, and for nothing but that range.
    let ranges: Vec<_> = etcd
        .requests()
        .into_iter()
        .filter(|seen| seen.path == "/v3/kv/range")
        .collect();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].body["key"], STANDARD.encode("podgate/acme/"));
    assert_eq!(
        ranges[0].body["range_end"],
        STANDARD.encode("podgate/acme0")
    );
}

#[tokio::test]
async fn etcd_traefik_tree_to_app() {
    let etcd = FakeEtcd::start().await;
    etcd.put("traefik/http/routers/site/rule", "Host(`shop.acme.test`)");
    etcd.put("traefik/http/routers/site/service", "web");
    etcd.put(
        "traefik/http/services/web/loadbalancer/servers/0/url",
        "http://10.4.0.5:8080",
    );
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"etcd\"\nname = \"etcd\"\nendpoints = [{:?}]\nresync_secs = 3600\n[[source.prefix]]\nprefix = \"traefik\"\ntenant = \"acme\"\nlayout = \"traefik-kv\"\n",
            etcd.url()
        ),
    );
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["acme"]).await;
    let app = serde_json::to_value(&state.apps[0].app).expect("app");
    assert_eq!(
        app["revisions"][0]["services"][0]["servers"],
        json!([{ "url": "http://10.4.0.5:8080" }])
    );
    // The tree changes, and the change arrives through the watch.
    etcd.put(
        "traefik/http/services/web/loadbalancer/servers/1/url",
        "http://10.4.0.6:8080",
    );
    watcher
        .until_within(PROMPT, "the second server", |state, _| {
            state.is_some_and(|state| {
                serde_json::to_value(&state.apps[0].app).is_ok_and(|app| {
                    app["revisions"][0]["services"][0]["servers"]
                        .as_array()
                        .map(Vec::len)
                        == Some(2)
                })
            })
        })
        .await;
}

// ---- the watch ---------------------------------------------------------------------------------

#[tokio::test]
async fn etcd_watch_updates() {
    let etcd = FakeEtcd::start().await;
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let mut watcher = Watcher::start(&etcd_config(&etcd.url(), "", ""));
    watcher.wait_ids(&["site"]).await;
    etcd.wait_requests("the watch", |seen| {
        seen.iter().any(|seen| seen.path == "/v3/watch")
    })
    .await;

    // The watch starts right after the revision of the read.
    let range = etcd
        .requests()
        .into_iter()
        .find(|seen| seen.path == "/v3/kv/range")
        .expect("a range request");
    let watch = etcd
        .requests()
        .into_iter()
        .find(|seen| seen.path == "/v3/watch")
        .expect("a watch request");
    assert_eq!(
        watch.body["create_request"]["start_revision"],
        json!(10 + 1 + 1),
        "the fake started at revision 10 and wrote once: the read saw 11, the watch asks for 12 ({range:?})"
    );
    assert_eq!(
        watch.body["create_request"]["key"],
        STANDARD.encode("podgate/acme/")
    );

    // A new app, a changed app and a removed app each show up promptly, with `resync_secs` at an
    // hour and no second range request.
    etcd.put(
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    watcher.wait_ids_within(PROMPT, &["api", "site"]).await;
    etcd.put(
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.7:8080"),
    );
    watcher
        .until_within(PROMPT, "the changed server", |state, _| {
            state.is_some_and(|state| {
                ids(state) == ["api", "site"]
                    && servers_of(state, "api") == ["http://10.4.0.7:8080"]
            })
        })
        .await;
    etcd.delete("podgate/acme/apps/site");
    watcher.wait_ids_within(PROMPT, &["api"]).await;
    assert_eq!(
        etcd.count("/v3/kv/range"),
        1,
        "every change came through the watch"
    );
    // A key that belongs to nobody changes nothing.
    etcd.put(
        "podgate/globex/apps/site",
        &doc("globex.test", "http://10.5.0.5:8080"),
    );
    etcd.put(
        "podgate/acme/apps/last",
        &doc("last.acme.test", "http://10.4.0.8:8080"),
    );
    watcher.wait_ids_within(PROMPT, &["api", "last"]).await;
}

#[tokio::test]
async fn etcd_compaction_triggers_resync() {
    let etcd = FakeEtcd::start().await;
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let mut watcher = Watcher::start(&etcd_config(&etcd.url(), "", ""));
    watcher.wait_ids(&["site"]).await;
    etcd.wait_requests("the watch", |seen| {
        seen.iter().any(|seen| seen.path == "/v3/watch")
    })
    .await;
    assert_eq!(etcd.count("/v3/kv/range"), 1);

    // The stream breaks, the changes made meanwhile are in the history etcd then compacts: the
    // source must read the prefix again, twice (once after the break, once after the
    // compaction error), and end up with everything.
    etcd.compact_at_next_watch();
    etcd.break_watches();
    etcd.put(
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    etcd.put(
        "podgate/acme/apps/more",
        &doc("more.acme.test", "http://10.4.0.7:8080"),
    );
    watcher
        .wait_ids_within(PROMPT, &["api", "more", "site"])
        .await;
    etcd.wait_requests("a range after the compaction error", |seen| {
        seen.iter()
            .filter(|seen| seen.path == "/v3/kv/range")
            .count()
            >= 3
    })
    .await;
    etcd.wait_requests("a watch after it", |seen| {
        seen.iter().filter(|seen| seen.path == "/v3/watch").count() >= 3
    })
    .await;

    // And the new watch works.
    etcd.put(
        "podgate/acme/apps/after",
        &doc("after.acme.test", "http://10.4.0.8:8080"),
    );
    watcher
        .wait_ids_within(PROMPT, &["after", "api", "more", "site"])
        .await;
}

#[tokio::test]
async fn etcd_resync_reads_again_when_the_watch_is_quiet() {
    let etcd = FakeEtcd::start().await;
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"etcd\"\nname = \"etcd\"\nendpoints = [{:?}]\nresync_secs = 1\n[[source.prefix]]\nprefix = \"podgate/acme\"\ntenant = \"acme\"\nlayout = \"podgate-json\"\n",
            etcd.url()
        ),
    );
    let mut watcher = Watcher::start(&config);
    watcher.wait_ids(&["site"]).await;
    etcd.wait_requests("a second full read", |seen| {
        seen.iter()
            .filter(|seen| seen.path == "/v3/kv/range")
            .count()
            >= 2
    })
    .await;
}

#[tokio::test]
async fn etcd_polling_without_a_watch() {
    let etcd = FakeEtcd::start().await;
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"etcd\"\nname = \"etcd\"\nendpoints = [{:?}]\nwatch = false\nresync_secs = 1\n[[source.prefix]]\nprefix = \"podgate/acme\"\ntenant = \"acme\"\nlayout = \"podgate-json\"\n",
            etcd.url()
        ),
    );
    let mut watcher = Watcher::start(&config);
    watcher.wait_ids(&["site"]).await;
    etcd.put(
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    watcher.wait_ids(&["api", "site"]).await;
    assert_eq!(etcd.count("/v3/watch"), 0, "watch = false opens no watch");
}

#[tokio::test]
async fn etcd_outage_keeps_last_state() {
    let etcd = FakeEtcd::start().await;
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let mut watcher = Watcher::start(&etcd_config(&etcd.url(), "", ""));
    watcher.wait_ids(&["site"]).await;

    etcd.stop();
    let why = watcher.wait_outage("cannot reach etcd").await;
    assert!(
        why.contains("podgate/acme/"),
        "the outage names the prefix: {why}"
    );
    assert!(
        watcher
            .history
            .iter()
            .all(|ids| ids == &["site".to_owned()]),
        "an outage never sends a state without the apps: {:?}",
        watcher.history
    );
    assert_eq!(
        ids(watcher.state.as_ref().expect("the last state")),
        ["site"]
    );

    // etcd comes back with a different content: the outage ends with a new state.
    etcd.put(
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    etcd.delete("podgate/acme/apps/site");
    etcd.restart().await;
    watcher.wait_ids(&["api"]).await;
    assert!(watcher.outage.is_none(), "{:?}", watcher.outage);

    // An error answer is an outage too, and the state stays.
    etcd.fail_next(503, 1000);
    etcd.break_watches();
    watcher.wait_outage("503").await;
    assert_eq!(ids(watcher.state.as_ref().expect("a state")), ["api"]);
}

#[tokio::test]
async fn etcd_endpoints_fail_over() {
    let down = FakeEtcd::start().await;
    let up = FakeEtcd::start().await;
    up.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let first = down.url();
    down.stop();
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"etcd\"\nname = \"etcd\"\nendpoints = [{first:?}, {:?}]\nresync_secs = 3600\n[[source.prefix]]\nprefix = \"podgate/acme\"\ntenant = \"acme\"\nlayout = \"podgate-json\"\n",
            up.url()
        ),
    );
    let mut watcher = Watcher::start(&config);
    watcher.wait_ids(&["site"]).await;
}

// ---- authentication ------------------------------------------------------------------------------

fn password_file(name: &str, password: &str) -> PathBuf {
    let path = dir(name).join("password");
    std::fs::write(&path, format!("{password}\n")).expect("write the password");
    path
}

#[tokio::test]
async fn etcd_auth_token_renewed() {
    let etcd = FakeEtcd::start().await;
    etcd.require_auth("podgate", "hunter2-correct-horse");
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let file = password_file("renew", "hunter2-correct-horse");
    let keys = format!(
        "username = \"podgate\"\npassword_file = {:?}",
        file.display().to_string()
    );
    let mut watcher = Watcher::start(&etcd_config(&etcd.url(), &keys, ""));
    watcher.wait_ids(&["site"]).await;
    assert_eq!(
        etcd.count("/v3/auth/authenticate"),
        1,
        "one token for the read and the watch"
    );
    let first = etcd
        .requests()
        .into_iter()
        .find(|seen| seen.path == "/v3/kv/range")
        .and_then(|seen| seen.authorization)
        .expect("the read carries a token");
    let authenticate = etcd
        .requests()
        .into_iter()
        .find(|seen| seen.path == "/v3/auth/authenticate")
        .expect("an authenticate call");
    assert_eq!(authenticate.body["name"], "podgate");
    assert_eq!(authenticate.body["password"], "hunter2-correct-horse");
    assert_eq!(
        authenticate.authorization, None,
        "no token to ask for a token"
    );

    // The token expires. The next call is refused with 401, the source asks for a new token and
    // repeats the call, and the new watch works with it.
    etcd.expire_tokens();
    etcd.break_watches();
    etcd.put(
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    watcher.wait_ids(&["api", "site"]).await;
    assert_eq!(etcd.count("/v3/auth/authenticate"), 2);
    let last = etcd
        .requests()
        .into_iter()
        .rfind(|seen| seen.path == "/v3/watch")
        .and_then(|seen| seen.authorization)
        .expect("the watch carries a token");
    assert_ne!(first, last, "the watch uses the renewed token");
    etcd.put(
        "podgate/acme/apps/third",
        &doc("third.acme.test", "http://10.4.0.7:8080"),
    );
    watcher
        .wait_ids_within(PROMPT, &["api", "site", "third"])
        .await;
}

#[tokio::test]
async fn etcd_wrong_password_is_an_outage_not_a_leak() {
    let etcd = FakeEtcd::start().await;
    etcd.require_auth("podgate", "the-right-password");
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let file = password_file("wrong", "the-wrong-password");
    let keys = format!(
        "username = \"podgate\"\npassword_file = {:?}",
        file.display().to_string()
    );
    let mut watcher = Watcher::start(&etcd_config(&etcd.url(), &keys, ""));
    let why = watcher.wait_outage("authentication failed").await;
    assert!(!why.contains("the-wrong-password"), "{why}");
    assert!(watcher.state.is_none());
    assert_eq!(
        etcd.count("/v3/kv/range"),
        0,
        "nothing is read without a token"
    );
}

// ---- TLS -----------------------------------------------------------------------------------------

#[tokio::test]
async fn etcd_tls_client_cert() {
    let pki = Pki::new();
    let etcd = FakeEtcd::start_tls(&pki, true).await;
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let tmp = dir("tls");
    let ca = pki.ca_file(&tmp);
    let (cert, key) = pki.client_files(&tmp, "podgate");
    let tables = format!(
        "[source.tls]\nca_file = {:?}\ncert_file = {:?}\nkey_file = {:?}\n",
        ca.display().to_string(),
        cert.display().to_string(),
        key.display().to_string()
    );

    // With the client certificate the source reads, and every request carried it.
    let mut watcher = Watcher::start(&etcd_config(&etcd.url(), "", &tables));
    watcher.wait_ids(&["site"]).await;
    etcd.wait_requests("the watch", |seen| {
        seen.iter().any(|seen| seen.path == "/v3/watch")
    })
    .await;
    assert!(
        etcd.requests().iter().all(|seen| seen.client_cert),
        "{:?}",
        etcd.requests()
    );
    drop(watcher);

    // Without it the handshake is refused: an outage, and etcd sees no request at all.
    let before = etcd.requests().len();
    let only_ca = format!("[source.tls]\nca_file = {:?}\n", ca.display().to_string());
    let mut bare = Watcher::start(&etcd_config(&etcd.url(), "", &only_ca));
    bare.wait_outage("cannot reach etcd").await;
    assert!(bare.state.is_none());
    assert_eq!(
        etcd.requests().len(),
        before,
        "no request got through the handshake"
    );
    drop(bare);

    // A server certificate of another CA is not trusted.
    let other = Pki::new();
    let other_dir = dir("tls-other");
    let other_ca = other.ca_file(&other_dir);
    let wrong = format!(
        "[source.tls]\nca_file = {:?}\ncert_file = {:?}\nkey_file = {:?}\n",
        other_ca.display().to_string(),
        cert.display().to_string(),
        key.display().to_string()
    );
    let mut distrusting = Watcher::start(&etcd_config(&etcd.url(), "", &wrong));
    distrusting.wait_outage("cannot reach etcd").await;
    assert!(distrusting.state.is_none());
    assert_eq!(etcd.requests().len(), before);
}

// ---- configuration ---------------------------------------------------------------------------------

#[test]
fn etcd_config_errors_name_the_key() {
    let cases: [(&str, &str, &str); 8] = [
        (
            "endpoints = [\"http://10.0.0.1:2379\"]",
            "",
            "must be https:// unless the server is on this machine",
        ),
        (
            "endpoints = [\"https://etcd:2379/v3\"]",
            "",
            "without a path",
        ),
        (
            "endpoints = [\"https://u:p@etcd:2379\"]",
            "",
            "must not carry credentials",
        ),
        (
            "endpoints = [\"https://etcd:2379\"]\nusername = \"u\"",
            "",
            "give both or neither",
        ),
        (
            "endpoints = [\"https://etcd:2379\"]\npassword = \"x\"",
            "",
            "unknown field `password`",
        ),
        (
            "endpoints = [\"https://etcd:2379\"]\nresync_secs = 0",
            "",
            "resync_secs: must be at least 1",
        ),
        (
            "endpoints = [\"https://etcd:2379\"]",
            "[source.tls]\ncert_file = \"/nonexistent/cert.pem\"\n",
            "cert_file and key_file go together",
        ),
        ("endpoints = []", "", "at least one is required"),
    ];
    for (keys, tables, needle) in cases {
        let config = config(
            Path::new("/nonexistent/admin.sock"),
            &format!(
                "{TENANTS}\n[[source]]\nkind = \"etcd\"\nname = \"etcd\"\n{keys}\n{tables}\n[[source.prefix]]\nprefix = \"podgate/acme\"\ntenant = \"acme\"\nlayout = \"podgate-json\"\n"
            ),
        );
        let err = EtcdSource::from_config(&config.sources[0], &policy())
            .expect_err(keys)
            .to_string();
        assert!(err.contains(needle), "{keys}: {err}");
        assert!(err.starts_with("source etcd: "), "{err}");
    }
    // Loopback needs no TLS, and a missing password file is named.
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"etcd\"\nname = \"etcd\"\nendpoints = [\"http://127.0.0.1:2379\", \"http://[::1]:2379\", \"http://localhost:2379\"]\n[[source.prefix]]\nprefix = \"podgate/acme\"\ntenant = \"acme\"\nlayout = \"podgate-json\"\n"
        ),
    );
    EtcdSource::from_config(&config.sources[0], &policy()).expect("loopback endpoints");
    let config = config_with_password("/nonexistent/password");
    let err = EtcdSource::from_config(&config.sources[0], &policy())
        .expect_err("no password file")
        .to_string();
    assert!(
        err.contains("password_file: cannot read /nonexistent/password"),
        "{err}"
    );
}

fn config_with_password(path: &str) -> Config {
    config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"etcd\"\nname = \"etcd\"\nendpoints = [\"https://etcd:2379\"]\nusername = \"u\"\npassword_file = {path:?}\n[[source.prefix]]\nprefix = \"podgate/acme\"\ntenant = \"acme\"\nlayout = \"podgate-json\"\n"
        ),
    )
}

// ---- read-only -----------------------------------------------------------------------------------

/// A request the source never makes, sent by hand to see that the fake notices it.
async fn raw_post(etcd: &FakeEtcd, path: &str) {
    let address = etcd.url().trim_start_matches("http://").to_owned();
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer).await;
}

#[tokio::test]
async fn etcd_client_only_reads() {
    let etcd = FakeEtcd::start().await;
    etcd.require_auth("podgate", "pw-for-reading");
    etcd.put(
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let file = password_file("reads", "pw-for-reading");
    let keys = format!(
        "username = \"podgate\"\npassword_file = {:?}",
        file.display().to_string()
    );
    let mut watcher = Watcher::start(&etcd_config(&etcd.url(), &keys, ""));
    watcher.wait_ids(&["site"]).await;

    // Everything the source does: changes, a broken watch, a compaction, an expired token, an
    // outage and the recovery.
    etcd.put(
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    watcher.wait_ids_within(PROMPT, &["api", "site"]).await;
    etcd.expire_tokens();
    etcd.compact_at_next_watch();
    etcd.break_watches();
    etcd.delete("podgate/acme/apps/site");
    watcher.wait_ids(&["api"]).await;
    etcd.stop();
    watcher.wait_outage("cannot reach etcd").await;
    etcd.restart().await;
    watcher
        .until("recovery", |_, outage| outage.is_none())
        .await;

    let paths: std::collections::BTreeSet<String> =
        etcd.requests().into_iter().map(|seen| seen.path).collect();
    assert_eq!(
        paths,
        ["/v3/auth/authenticate", "/v3/kv/range", "/v3/watch"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "the source calls range, watch and authenticate and nothing else"
    );
    assert_eq!(etcd.writes(), Vec::<String>::new());

    // The fake does notice a write when one is made, so the empty list above means something.
    raw_post(&etcd, "/v3/kv/put").await;
    raw_post(&etcd, "/v3/kv/deleterange").await;
    assert_eq!(etcd.writes(), ["/v3/kv/put", "/v3/kv/deleterange"]);
}

#[test]
fn etcd_source_refused_without_tenant_allowlist() {
    let config = etcd_config("https://etcd:2379", "", "");
    let err = EtcdSource::from_config(&config.sources[0], &UpstreamPolicy::builtin())
        .expect_err("a tenant without an allow list")
        .to_string();
    assert!(err.contains("kv_source_requires_tenant_allowlist"), "{err}");
    assert!(err.contains("tenants.acme.allow"), "{err}");
}
