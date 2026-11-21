//! Black-box tests of the file source: formats, directories, change detection, broken files,
//! and how its objects fare in the merge (tenants, hosts, upstream policy) and in the engine.
//! Everything that waits has a deadline.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use common::{DEADLINE, FakeAdmin, app_ids, config, fast_tuning};
use podgate_provider::file::FileSource;
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::{Config, Engine, Merged, Merger, UpstreamPolicy};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const POLL_MS: u64 = 25;

/// A change must show within a poll plus scheduling slack, far below the default `poll_ms`.
const PROMPT: Duration = Duration::from_millis(1500);

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test"]
"#;

struct Dir(PathBuf);

impl Dir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pgp-file-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create the test directory");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, text: &str) {
        fs::write(self.path(name), text).expect("write a test file");
    }

    fn remove(&self, name: &str) {
        fs::remove_file(self.path(name)).expect("remove a test file");
    }

    /// Writes the file as it was an hour ago, so a poll trusts its stamp.
    fn write_aged(&self, name: &str, text: &str) {
        self.write(name, text);
        age(&self.path(name));
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn aged() -> SystemTime {
    SystemTime::now() - Duration::from_secs(3600)
}

fn age(path: &Path) {
    set_modified(path, aged());
}

fn set_modified(path: &Path, when: SystemTime) {
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(when))
        .expect("set the modification time");
}

fn app_json(id: &str, host: &str, upstream: &str) -> Value {
    json!({
        "id": id,
        "tls": { "mode": "acme" },
        "routers": [{ "name": "main", "match": { "host": [host] }, "service": "svc" }],
        "services": [{ "name": "svc", "type": "loadbalancer", "servers": [{ "url": upstream }] }],
        "revisions": [{ "id": "r1", "state": "serving", "weight": 1 }],
    })
}

fn file_json(apps: &[Value]) -> String {
    json!({ "apps": apps }).to_string()
}

fn one_app(id: &str, host: &str, upstream: &str) -> String {
    file_json(&[app_json(id, host, upstream)])
}

/// The source's configuration for `path`, after `extra` (tenants and other tables).
fn file_config(path: &Path, tenant: &str, extra: &str) -> Config {
    config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{extra}\n[[source]]\nkind = \"file\"\nname = \"files\"\npath = {:?}\npoll_ms = {POLL_MS}\ntenant = {tenant:?}\n",
            path.display().to_string()
        ),
    )
}

fn file_source(config: &Config) -> FileSource {
    FileSource::from_config(&config.sources[0]).expect("a valid file source")
}

/// A running file source and what it has said so far.
struct Watcher {
    rx: mpsc::Receiver<Update>,
    task: JoinHandle<()>,
    state: Option<State>,
    outage: Option<String>,
}

impl Watcher {
    fn start(config: &Config) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let source = file_source(config);
        Self {
            rx,
            task: tokio::spawn(source.run(tx)),
            state: None,
            outage: None,
        }
    }

    /// Takes updates until `done` holds for the latest state and outage.
    async fn until(&mut self, what: &str, done: impl Fn(Option<&State>, Option<&str>) -> bool) {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                assert_eq!(&*update.source, "files");
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
                "timed out waiting for: {what}; state: {:?}; outage: {:?}",
                self.state.as_ref().map(ids),
                self.outage
            );
        }
    }

    async fn wait(
        &mut self,
        what: &str,
        condition: impl Fn(&State, Option<&str>) -> bool,
    ) -> State {
        self.until(what, |state, outage| {
            state.is_some_and(|state| condition(state, outage))
        })
        .await;
        self.state.clone().expect("the condition needed a state")
    }

    async fn wait_ids(&mut self, expected: &[&str]) -> State {
        let expected: Vec<String> = expected.iter().map(|id| (*id).to_owned()).collect();
        self.wait(&format!("apps {expected:?}"), |state, _| {
            ids(state) == expected
        })
        .await
    }

    async fn wait_outage(&mut self, needle: &str) {
        self.until(&format!("an outage naming {needle}"), |_, outage| {
            outage.is_some_and(|why| why.contains(needle))
        })
        .await;
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

fn upstream_of(state: &State, id: &str) -> String {
    let app = state
        .apps
        .iter()
        .find(|app| &*app.app.id == id)
        .unwrap_or_else(|| panic!("no app {id}: {:?}", ids(state)));
    let services = &app.app.services;
    serde_json::to_value(services).expect("services serialize")[0]["servers"][0]["url"]
        .as_str()
        .expect("a server url")
        .to_owned()
}

fn merge(config: &Config, policy: UpstreamPolicy, state: State) -> Merged {
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("files".into(), state)]);
    Merger::new(config, policy).merge(&states, &BTreeSet::new())
}

fn finding_codes(merged: &Merged) -> Vec<(&'static str, String)> {
    merged
        .findings()
        .iter()
        .map(|finding| (finding.code, finding.object.to_string()))
        .collect()
}

fn merged_ids(merged: &Merged) -> Vec<String> {
    merged
        .snapshot()
        .apps
        .iter()
        .map(|app| app.id.to_string())
        .collect()
}

const YAML: &str = r#"
apps:
  - id: web
    tls: {mode: acme}
    routers:
      - name: main
        match: {host: [web.test]}
        service: svc
    services:
      - name: svc
        type: loadbalancer
        servers:
          - url: http://10.0.0.1:80
    revisions:
      - {id: r1, state: serving, weight: 1}
"#;

const TOML: &str = r#"
[[apps]]
id = "web"
tls = { mode = "acme" }

[[apps.routers]]
name = "main"
service = "svc"
[apps.routers.match]
host = ["web.test"]

[[apps.services]]
name = "svc"
type = "loadbalancer"
[[apps.services.servers]]
url = "http://10.0.0.1:80"

[[apps.revisions]]
id = "r1"
state = "serving"
weight = 1
"#;

// ---- formats ---------------------------------------------------------------------------------

#[tokio::test]
async fn file_formats_equivalent() {
    let dir = Dir::new("formats");
    dir.write("web.yaml", YAML);
    dir.write("web.toml", TOML);
    dir.write(
        "web.json",
        &one_app("web", "web.test", "http://10.0.0.1:80"),
    );
    let mut apps = Vec::new();
    for name in ["web.yaml", "web.toml", "web.json"] {
        let path = dir.path(name);
        let mut watcher = Watcher::start(&file_config(&path, "default", ""));
        let state = watcher.wait_ids(&["web"]).await;
        let app = state.apps[0].clone();
        assert_eq!(
            &*app.origin.object,
            format!("{}#web", path.display()),
            "the object names the file and the app"
        );
        assert_eq!(app.tenant.mapped.as_deref(), Some("default"));
        assert_eq!(app.tenant.label, None);
        apps.push(app.app);
    }
    assert_eq!(apps[0], apps[1], "yaml and toml give the same app");
    assert_eq!(apps[0], apps[2], "yaml and json give the same app");
}

#[tokio::test]
async fn file_formats_extension_is_case_insensitive_and_yml_counts() {
    let dir = Dir::new("extensions");
    dir.write("a.YML", YAML);
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    watcher.wait_ids(&["web"]).await;
}

// ---- directories -----------------------------------------------------------------------------

#[tokio::test]
async fn file_directory_merge() {
    let dir = Dir::new("merge");
    dir.write("a.yaml", &YAML.replace("web", "a"));
    dir.write("b.toml", &TOML.replace("web", "b"));
    dir.write("c.json", &one_app("c", "c.test", "http://10.0.0.3:80"));
    dir.write("notes.txt", "not a podgate file");
    dir.write(
        ".hidden.json",
        &one_app("hidden", "h.test", "http://10.0.0.4:80"),
    );
    dir.write(
        "backup.json.bak",
        &one_app("bak", "k.test", "http://10.0.0.5:80"),
    );
    fs::create_dir(dir.path("nested.json")).expect("a directory with a file name");
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    let state = watcher.wait_ids(&["a", "b", "c"]).await;
    let objects: Vec<String> = state
        .apps
        .iter()
        .map(|app| app.origin.object.to_string())
        .collect();
    assert_eq!(
        objects,
        [
            format!("{}#a", dir.path("a.yaml").display()),
            format!("{}#b", dir.path("b.toml").display()),
            format!("{}#c", dir.path("c.json").display()),
        ],
        "apps come in file name order"
    );
}

#[tokio::test]
async fn file_removed_removes_apps() {
    let dir = Dir::new("removed");
    dir.write("a.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    dir.write("b.json", &one_app("b", "b.test", "http://10.0.0.2:80"));
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    watcher.wait_ids(&["a", "b"]).await;
    dir.remove("b.json");
    watcher.wait_ids(&["a"]).await;
    dir.write("b.json", &one_app("b", "b.test", "http://10.0.0.2:80"));
    watcher.wait_ids(&["a", "b"]).await;
}

#[tokio::test]
async fn file_missing_path_is_an_outage_and_keeps_the_apps() {
    let dir = Dir::new("missing-path");
    let file = dir.path("only.json");
    dir.write("only.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    let mut watcher = Watcher::start(&file_config(&file, "default", ""));
    watcher.wait_ids(&["a"]).await;
    dir.remove("only.json");
    watcher.wait_outage("only.json").await;
    assert_eq!(ids(watcher.state.as_ref().expect("a state")), ["a"]);
    dir.write("only.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    watcher
        .wait("the file is back", |state, outage| {
            outage.is_none() && ids(state) == ["a"]
        })
        .await;
}

// ---- change detection ------------------------------------------------------------------------

#[tokio::test]
async fn file_edit_triggers_push() {
    let dir = Dir::new("edit");
    dir.write_aged("a.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    watcher.wait_ids(&["a"]).await;

    // A longer file written through the normal path.
    let start = Instant::now();
    dir.write("a.json", &one_app("a", "a.test", "http://10.0.0.1:8080"));
    let state = watcher
        .wait("the new upstream", |state, _| {
            ids(state) == ["a"] && upstream_of(state, "a") == "http://10.0.0.1:8080"
        })
        .await;
    assert!(start.elapsed() < PROMPT, "took {:?}", start.elapsed());
    assert_eq!(ids(&state), ["a"]);

    // The same length, written in place, with the old modification time restored: only the
    // change time and the content give it away.
    let old = aged();
    set_modified(&dir.path("a.json"), old);
    tokio::time::sleep(Duration::from_millis(POLL_MS * 4)).await;
    let same_length = one_app("a", "a.test", "http://10.0.0.9:8080");
    assert_eq!(
        same_length.len(),
        one_app("a", "a.test", "http://10.0.0.1:8080").len()
    );
    let mut file = OpenOptions::new()
        .write(true)
        .open(dir.path("a.json"))
        .expect("open for an in-place write");
    file.write_all(same_length.as_bytes())
        .expect("write in place");
    file.set_modified(old)
        .expect("restore the modification time");
    drop(file);
    watcher
        .wait("the in-place write", |state, _| {
            upstream_of(state, "a") == "http://10.0.0.9:8080"
        })
        .await;
}

#[tokio::test]
async fn file_atomic_replace_detected() {
    let dir = Dir::new("replace");
    dir.write_aged("a.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    watcher.wait_ids(&["a"]).await;

    // An editor's write-then-rename: same length, same modification time, another inode.
    let replacement = one_app("a", "a.test", "http://10.0.0.2:80");
    assert_eq!(
        replacement.len(),
        one_app("a", "a.test", "http://10.0.0.1:80").len()
    );
    let temporary = dir.path("a.json.tmp");
    fs::write(&temporary, &replacement).expect("write the replacement");
    set_modified(
        &temporary,
        fs::metadata(dir.path("a.json"))
            .and_then(|m| m.modified())
            .expect("mtime"),
    );
    let start = Instant::now();
    fs::rename(&temporary, dir.path("a.json")).expect("rename over the file");
    watcher
        .wait("the replacement", |state, _| {
            upstream_of(state, "a") == "http://10.0.0.2:80"
        })
        .await;
    assert!(start.elapsed() < PROMPT, "took {:?}", start.elapsed());
}

#[tokio::test]
async fn file_touch_without_change_sends_nothing() {
    let dir = Dir::new("touch");
    dir.write_aged("a.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    watcher.wait_ids(&["a"]).await;
    set_modified(&dir.path("a.json"), SystemTime::now());
    tokio::time::sleep(Duration::from_millis(POLL_MS * 8)).await;
    assert!(watcher.rx.try_recv().is_err(), "a touch is not a change");
}

// ---- broken files ----------------------------------------------------------------------------

#[tokio::test]
async fn file_parse_error_keeps_last_good() {
    let dir = Dir::new("broken");
    dir.write("a.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    dir.write("b.yaml", &YAML.replace("web", "b"));
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    watcher.wait_ids(&["a", "b"]).await;

    dir.write("a.json", "{ \"apps\": [ ");
    watcher.wait_outage("a.json").await;
    let state = watcher.state.clone().expect("a state");
    assert_eq!(
        ids(&state),
        ["a", "b"],
        "the broken file keeps its last good content"
    );
    assert_eq!(upstream_of(&state, "a"), "http://10.0.0.1:80");

    // The other file carries on while the first stays broken.
    dir.write(
        "b.yaml",
        &YAML.replace("web", "b").replace("10.0.0.1", "10.0.0.7"),
    );
    let state = watcher
        .wait("b's edit with a still broken", |state, outage| {
            outage.is_some_and(|why| why.contains("a.json"))
                && upstream_of(state, "b") == "http://10.0.0.7:80"
        })
        .await;
    assert_eq!(upstream_of(&state, "a"), "http://10.0.0.1:80");

    // Fixing it clears the report.
    dir.write("a.json", &one_app("a", "a.test", "http://10.0.0.3:80"));
    watcher
        .wait("a fixed", |state, outage| {
            outage.is_none() && upstream_of(state, "a") == "http://10.0.0.3:80"
        })
        .await;
}

#[tokio::test]
async fn file_unknown_field_is_a_parse_error() {
    let dir = Dir::new("unknown");
    dir.write("a.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    watcher.wait_ids(&["a"]).await;
    dir.write("a.json", &json!({ "apps": [], "tenant": "x" }).to_string());
    watcher.wait_outage("unknown field").await;
    assert_eq!(ids(watcher.state.as_ref().expect("a state")), ["a"]);
}

#[tokio::test]
async fn file_broken_at_start_waits_for_a_fix() {
    let dir = Dir::new("start-broken");
    dir.write("a.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    dir.write("b.toml", "apps = [");
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    watcher.wait_outage("b.toml").await;
    assert!(
        watcher.state.is_none(),
        "no partial state before every file parsed once"
    );
    dir.write("b.toml", &TOML.replace("web", "b"));
    watcher.wait_ids(&["a", "b"]).await;
}

// ---- tenants, hosts, policy ------------------------------------------------------------------

#[tokio::test]
async fn file_tenants_ignored() {
    let dir = Dir::new("tenants");
    let body = json!({
        "tenants": [{ "id": "evil", "weight": 99, "budget": { "max_inflight": 1000000, "max_buffer_bytes": 1 } }],
        "apps": [app_json("ok", "web.acme.test", "http://10.0.0.1:80")],
    });
    dir.write("a.json", &body.to_string());
    let config = file_config(&dir.0, "acme", TENANTS);
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["ok"]).await;
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    let tenants: Vec<&str> = merged.snapshot().tenants.iter().map(|t| &*t.id).collect();
    assert_eq!(
        tenants,
        ["acme", "default", "globex"],
        "no tenant came from the file"
    );
    let tenant = merged.snapshot().apps[0].tenant.to_string();
    assert_eq!(tenant, "acme", "the app has the source's tenant");

    // An app naming a tenant that is not configured is dropped, never defaulted.
    let mut named = app_json("named", "web.acme.test", "http://10.0.0.2:80");
    named["tenant"] = json!("evil");
    dir.write("a.json", &file_json(&[named]));
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["named"]).await;
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert!(merged_ids(&merged).is_empty(), "{:?}", merged_ids(&merged));
    assert_eq!(
        finding_codes(&merged),
        [(
            "unknown_tenant",
            format!("{}#named", dir.path("a.json").display())
        )]
    );
}

#[tokio::test]
async fn file_foreign_host_rejected() {
    let dir = Dir::new("foreign");
    dir.write(
        "a.json",
        &file_json(&[
            app_json("mine", "web.acme.test", "http://10.0.0.1:80"),
            app_json("theirs", "globex.test", "http://10.0.0.2:80"),
            app_json("wild", "other.example", "http://10.0.0.3:80"),
        ]),
    );
    let config = file_config(&dir.0, "acme", TENANTS);
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["mine", "theirs", "wild"]).await;
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert_eq!(merged_ids(&merged), ["files-mine"]);
    let codes: Vec<&str> = finding_codes(&merged)
        .iter()
        .map(|(code, _)| *code)
        .collect();
    assert_eq!(codes, ["foreign_host_claim", "foreign_host_claim"]);
}

#[tokio::test]
async fn upstream_outside_allowlist_rejected_file() {
    let dir = Dir::new("policy");
    dir.write(
        "a.json",
        &file_json(&[
            app_json("inside", "in.acme.test", "http://10.4.0.1:80"),
            app_json("outside", "out.acme.test", "http://10.5.0.1:80"),
            app_json("loopback", "lo.acme.test", "http://127.0.0.1:80"),
        ]),
    );
    let config = file_config(&dir.0, "acme", TENANTS);
    let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)
        .expect("policy");
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["inside", "loopback", "outside"]).await;
    let merged = merge(&config, policy, state);
    assert_eq!(merged_ids(&merged), ["files-inside"]);
    let forbidden: Vec<String> = finding_codes(&merged)
        .into_iter()
        .filter(|(code, _)| *code == "upstream_forbidden")
        .map(|(_, object)| object)
        .collect();
    assert_eq!(
        forbidden,
        [
            format!("{}#loopback", dir.path("a.json").display()),
            format!("{}#outside", dir.path("a.json").display()),
        ]
    );
}

// ---- configuration ---------------------------------------------------------------------------

#[test]
fn file_config_is_strict() {
    let source = |keys: &str| {
        let config = config(
            Path::new("/x"),
            &format!("[[source]]\nkind = \"file\"\nname = \"files\"\n{keys}"),
        );
        FileSource::from_config(&config.sources[0])
    };
    assert!(source("path = \"/x\"").is_ok());
    for (keys, needle) in [
        ("", "path"),
        ("path = \"\"", "path"),
        ("path = \"/x\"\npoll_ms = 1", "poll_ms"),
        ("path = \"/x\"\nwatch = true", "watch"),
        ("path = \"/x\"\ntenant = \"\"", "tenant"),
    ] {
        let err = source(keys).expect_err(keys);
        assert!(err.to_string().contains(needle), "{keys}: {err}");
    }
}

// ---- through the engine ----------------------------------------------------------------------

#[tokio::test]
async fn file_source_through_engine() {
    let dir = Dir::new("engine");
    dir.write("a.json", &one_app("a", "a.test", "http://10.0.0.1:80"));
    dir.write("b.json", &one_app("b", "b.test", "http://10.0.0.2:80"));
    let admin = FakeAdmin::start();
    let config = {
        let text = format!(
            "admin_socket = {:?}\n[[source]]\nkind = \"file\"\nname = \"files\"\npath = {:?}\npoll_ms = {POLL_MS}\n",
            admin.path.display().to_string(),
            dir.0.display().to_string()
        );
        Config::parse(&text).expect("config")
    };
    let mut engine =
        Engine::new(config.clone(), UpstreamPolicy::builtin()).with_tuning(fast_tuning());
    engine.add_source(file_source(&config)).expect("registered");
    let mut status = engine.status();
    let (stop, stopped) = oneshot::channel::<()>();
    let run = tokio::spawn(async move {
        engine
            .run(async {
                let _ = stopped.await;
            })
            .await
    });

    let puts = admin.wait_puts("both apps", |puts| !puts.is_empty()).await;
    assert_eq!(app_ids(&puts[0].body), ["files-a", "files-b"]);
    assert_eq!(
        puts[0].body["apps"][0]["declared_by"],
        format!("file/files:{}#a", dir.path("a.json").display())
    );

    dir.write("b.json", "not json");
    tokio::time::timeout(DEADLINE, async {
        loop {
            let reported = status
                .borrow_and_update()
                .outages
                .get("files")
                .is_some_and(|why| why.contains("b.json"));
            if reported {
                return;
            }
            status.changed().await.expect("the engine runs");
        }
    })
    .await
    .expect("the broken file is reported");

    dir.write("a.json", &one_app("a", "a.test", "http://10.0.0.9:80"));
    let puts = admin.wait_puts("a's edit", |puts| puts.len() >= 2).await;
    assert_eq!(
        app_ids(&puts[1].body),
        ["files-a", "files-b"],
        "b keeps its last good content"
    );
    assert_eq!(
        puts[1].body["apps"][1]["services"][0]["servers"][0]["url"],
        "http://10.0.0.2:80"
    );

    let _ = stop.send(());
    tokio::time::timeout(DEADLINE, run)
        .await
        .expect("the engine stops")
        .expect("no panic")
        .expect("a clean end");
}

#[tokio::test]
async fn file_example_is_valid() {
    let dir = Dir::new("example");
    dir.write(
        "podgate-file.example.yaml",
        include_str!("../../../deploy/podgate-file.example.yaml"),
    );
    let mut watcher = Watcher::start(&file_config(&dir.0, "default", ""));
    let state = watcher.wait_ids(&["shop"]).await;
    assert_eq!(upstream_of(&state, "shop"), "http://10.4.0.10:8080");
}
