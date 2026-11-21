//! Black-box tests of the Redis source against a real `valkey-server` (`tests/common/valkey.rs`,
//! the daemon's harness): layouts to apps, pub/sub, keyspace notifications and the poll, outages
//! and reconnects, the commands that reach the store, authentication, an ACL user, TLS and `db`,
//! and the rules of the key-value layer. Everything that waits has a deadline.

mod common;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::valkey::{TlsFiles, Valkey, scratch};
use common::{DEADLINE, config};
use podgate_provider::redis::RedisSource;
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::{Config, UpstreamPolicy};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// A change must show within the source's quiet window plus scheduling slack, far below the hour
/// the tests give `refresh_secs`: only a notification can deliver it in time.
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

const ACME_PREFIX: &str = "\n[[source.prefix]]\nprefix = \"podgate/acme\"\ntenant = \"acme\"\nlayout = \"podgate-json\"\n";

fn policy() -> UpstreamPolicy {
    UpstreamPolicy::parse(POLICY).expect("a valid policy")
}

/// The configuration with one Redis source named `redis`: `keys` are its own keys, `tables` the
/// tables below them (`[source.tls]`), and one `podgate-json` prefix for acme follows.
fn redis_config(url: &str, keys: &str, tables: &str) -> Config {
    let refresh = if keys.contains("refresh_secs") {
        ""
    } else {
        "refresh_secs = 3600\n"
    };
    config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"redis\"\nname = \"redis\"\nurl = {url:?}\n{refresh}{keys}\n{tables}{ACME_PREFIX}"
        ),
    )
}

fn source_of(config: &Config) -> RedisSource {
    RedisSource::from_config(&config.sources[0], &policy()).expect("a valid redis source")
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

fn set(valkey: &Valkey, key: &str, value: &str) {
    assert_eq!(valkey.cli(&["SET", key, value]), "OK");
}

fn publish(valkey: &Valkey, channel: &str) {
    valkey.cli(&["PUBLISH", channel, "changed"]);
}

/// Sends `commands` in one pipeline on a plain connection and waits for every reply, for the tests
/// that need thousands of keys.
async fn pipeline(valkey: &Valkey, commands: &[Vec<Vec<u8>>]) {
    let mut out = Vec::new();
    for command in commands {
        out.extend_from_slice(format!("*{}\r\n", command.len()).as_bytes());
        for arg in command {
            out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
            out.extend_from_slice(arg);
            out.extend_from_slice(b"\r\n");
        }
    }
    let mut stream = TcpStream::connect(valkey.addr()).await.expect("connect");
    stream.write_all(&out).await.expect("write the pipeline");
    // Every reply is `+OK\r\n` (SET) or `:n\r\n` (DEL): count the line ends.
    let mut lines = 0;
    let mut chunk = vec![0_u8; 8192];
    while lines < commands.len() {
        let read = stream.read(&mut chunk).await.expect("read replies");
        assert!(read > 0, "the server closed the connection");
        lines += chunk[..read].iter().filter(|byte| **byte == b'\n').count();
    }
}

fn set_command(key: &str, value: &[u8]) -> Vec<Vec<u8>> {
    vec![b"SET".to_vec(), key.as_bytes().to_vec(), value.to_vec()]
}

/// Waits until `channel` has `count` subscribers.
async fn wait_subscribers(valkey: &Valkey, channel: &str, count: usize) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let seen = valkey.cli(&["PUBSUB", "NUMSUB", channel]);
        if seen.lines().nth(1) == Some(count.to_string().as_str()) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{channel} has no {count} subscribers: {seen}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A running Redis source and what it has said so far.
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

    /// Reads updates until `done` accepts what is known, or `within` has passed.
    async fn poll(
        &mut self,
        within: Duration,
        done: impl Fn(Option<&State>, Option<&str>) -> bool,
    ) -> bool {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                assert_eq!(&*update.source, "redis");
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
        tokio::time::timeout(within, wait).await.is_ok()
    }

    async fn until_within(
        &mut self,
        within: Duration,
        what: &str,
        done: impl Fn(Option<&State>, Option<&str>) -> bool,
    ) {
        assert!(
            self.poll(within, done).await,
            "timed out waiting for: {what}; apps: {:?}; outage: {:?}",
            self.state.as_ref().map(ids),
            self.outage
        );
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
        self.until_within(
            DEADLINE,
            &format!("an outage naming {needle}"),
            |_, outage| outage.is_some_and(|why| why.contains(needle)),
        )
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

/// A TCP forwarder in front of the store that records every command the client sends.
struct Recorder {
    port: u16,
    seen: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
    task: JoinHandle<()>,
}

/// The first command of `buf` and its length, or `None` while it is incomplete.
fn parse_command(buf: &[u8]) -> Option<(Vec<Vec<u8>>, usize)> {
    fn line<'a>(buf: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
        let end = buf[*at..].windows(2).position(|pair| pair == b"\r\n")?;
        let found = &buf[*at..*at + end];
        *at += end + 2;
        Some(found)
    }
    fn number(text: &[u8], mark: &[u8]) -> Option<usize> {
        std::str::from_utf8(text.strip_prefix(mark)?)
            .ok()?
            .parse()
            .ok()
    }
    let mut at = 0;
    let count = number(line(buf, &mut at)?, b"*")?;
    let mut args = Vec::new();
    for _ in 0..count {
        let len = number(line(buf, &mut at)?, b"$")?;
        if buf.len() < at + len + 2 {
            return None;
        }
        args.push(buf[at..at + len].to_vec());
        at += len + 2;
    }
    Some((args, at))
}

impl Recorder {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let record = Arc::clone(&record);
                tokio::spawn(async move {
                    let Ok(mut upstream) = TcpStream::connect(target).await else {
                        return;
                    };
                    let (mut from_client, mut to_client) = client.split();
                    let (mut from_store, mut to_store) = upstream.split();
                    let up = async {
                        let mut buf = Vec::new();
                        let mut chunk = vec![0_u8; 8192];
                        loop {
                            let read = from_client.read(&mut chunk).await?;
                            if read == 0 {
                                return Ok::<(), std::io::Error>(());
                            }
                            to_store.write_all(&chunk[..read]).await?;
                            buf.extend_from_slice(&chunk[..read]);
                            while let Some((command, used)) = parse_command(&buf) {
                                record.lock().expect("lock").push(command);
                                buf.drain(..used);
                            }
                        }
                    };
                    let down = tokio::io::copy(&mut from_store, &mut to_client);
                    tokio::select! {
                        _ = up => {}
                        _ = down => {}
                    }
                });
            }
        });
        Self { port, seen, task }
    }

    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}", self.port)
    }

    fn commands(&self) -> Vec<Vec<Vec<u8>>> {
        self.seen.lock().expect("lock").clone()
    }

    fn names(&self) -> BTreeSet<String> {
        self.commands()
            .iter()
            .filter_map(|command| command.first())
            .map(|name| String::from_utf8_lossy(name).to_uppercase())
            .collect()
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn password_file(dir: &Path, name: &str, password: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{password}\n")).expect("password file");
    path
}

// ---- layouts -----------------------------------------------------------------------------------

#[tokio::test]
async fn redis_json_layout_to_apps() {
    let valkey = Valkey::start().await;
    set(
        &valkey,
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    set(
        &valkey,
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    set(
        &valkey,
        "podgate/acme/certificates/shop",
        &json!({ "hosts": ["shop.acme.test"], "cert_pem": "CERT", "key_pem": "KEY" }).to_string(),
    );
    // Neighbours that must not be read: another tenant's prefix, and a prefix that only shares
    // letters with this one.
    set(
        &valkey,
        "podgate/globex/apps/site",
        &doc("globex.test", "http://10.5.0.5:8080"),
    );
    set(
        &valkey,
        "podgate/acme2/apps/site",
        &doc("x.acme.test", "http://10.4.0.9:8080"),
    );

    let mut watcher = Watcher::start(&redis_config(&valkey.url(), "", ""));
    let state = watcher.wait_ids(&["api", "site"]).await;
    assert_eq!(servers_of(&state, "site"), ["http://10.4.0.5:8080"]);
    assert_eq!(servers_of(&state, "api"), ["http://10.4.0.6:8080"]);
    for app in &state.apps {
        assert_eq!(app.tenant.mapped.as_deref(), Some("acme"));
        assert_eq!(app.tenant.label, None);
        assert_eq!(&*app.origin.source, "redis");
        assert_eq!(app.origin.first_seen, 0, "a key has no creation time");
    }
    assert_eq!(state.certificates.len(), 1);
    assert_eq!(state.certificates[0].tenant.mapped.as_deref(), Some("acme"));
}

#[tokio::test]
async fn redis_traefik_tree_to_app() {
    let valkey = Valkey::start().await;
    set(
        &valkey,
        "traefik/http/routers/site/rule",
        "Host(`shop.acme.test`)",
    );
    set(&valkey, "traefik/http/routers/site/service", "web");
    set(
        &valkey,
        "traefik/http/services/web/loadbalancer/servers/0/url",
        "http://10.4.0.5:8080",
    );
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"redis\"\nname = \"redis\"\nurl = {:?}\nrefresh_secs = 3600\n[[source.prefix]]\nprefix = \"traefik\"\ntenant = \"acme\"\nlayout = \"traefik-kv\"\n",
            valkey.url()
        ),
    );
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["acme"]).await;
    let app = serde_json::to_value(&state.apps[0].app).expect("app");
    assert_eq!(
        app["revisions"][0]["services"][0]["servers"],
        json!([{ "url": "http://10.4.0.5:8080" }])
    );
    // The tree changes, and the change arrives through the notification channel.
    wait_subscribers(&valkey, "podgate:changed", 1).await;
    set(
        &valkey,
        "traefik/http/services/web/loadbalancer/servers/1/url",
        "http://10.4.0.6:8080",
    );
    publish(&valkey, "podgate:changed");
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

// ---- changes -----------------------------------------------------------------------------------

#[tokio::test]
async fn redis_pubsub_triggers_refresh() {
    let valkey = Valkey::start().await;
    set(
        &valkey,
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let mut watcher = Watcher::start(&redis_config(&valkey.url(), "", ""));
    watcher.wait_ids(&["site"]).await;
    wait_subscribers(&valkey, "podgate:changed", 1).await;

    // A new app, a changed app and a removed app each show up promptly with `refresh_secs` at an
    // hour, once the writer publishes.
    set(
        &valkey,
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    publish(&valkey, "podgate:changed");
    watcher.wait_ids_within(PROMPT, &["api", "site"]).await;
    set(
        &valkey,
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.7:8080"),
    );
    publish(&valkey, "podgate:changed");
    watcher
        .until_within(PROMPT, "the changed server", |state, _| {
            state.is_some_and(|state| {
                state.apps.iter().any(|app| &*app.app.id == "api")
                    && servers_of(state, "api") == ["http://10.4.0.7:8080"]
            })
        })
        .await;
    valkey.cli(&["DEL", "podgate/acme/apps/site"]);
    publish(&valkey, "podgate:changed");
    watcher.wait_ids_within(PROMPT, &["api"]).await;

    // Without a message nothing changes before the poll.
    set(
        &valkey,
        "podgate/acme/apps/web",
        &doc("web.acme.test", "http://10.4.0.8:8080"),
    );
    assert!(
        !watcher
            .poll(Duration::from_millis(800), |state, _| state
                .is_some_and(|state| ids(state) == ["api", "web"]))
            .await,
        "a key written without a message waits for the poll"
    );

    // The channel is configurable, and only it is followed.
    let mut custom = Watcher::start(&redis_config(
        &valkey.url(),
        "notify_channel = \"paas:reload\"",
        "",
    ));
    custom.wait_ids(&["api", "web"]).await;
    wait_subscribers(&valkey, "paas:reload", 1).await;
    // The subscription's own wake-up (it may have missed messages) settles before the test writes.
    custom.poll(Duration::from_millis(500), |_, _| false).await;
    set(
        &valkey,
        "podgate/acme/apps/extra",
        &doc("extra.acme.test", "http://10.4.0.9:8080"),
    );
    publish(&valkey, "podgate:changed");
    assert!(
        !custom
            .poll(Duration::from_millis(800), |state, _| state
                .is_some_and(|state| ids(state).len() == 3))
            .await,
        "a message on another channel is not a notification"
    );
    publish(&valkey, "paas:reload");
    custom
        .wait_ids_within(PROMPT, &["api", "extra", "web"])
        .await;
}

#[tokio::test]
async fn redis_keyspace_notifications_trigger_refresh() {
    let valkey = Valkey::start().await;
    // The operator's decision on their own store; the provider never issues CONFIG SET.
    assert_eq!(
        valkey.cli(&["CONFIG", "SET", "notify-keyspace-events", "Kg$"]),
        "OK"
    );
    set(
        &valkey,
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let mut watcher = Watcher::start(&redis_config(
        &valkey.url(),
        "keyspace_notifications = true",
        "",
    ));
    watcher.wait_ids(&["site"]).await;
    wait_subscribers(&valkey, "podgate:changed", 1).await;
    let patterns = valkey.cli(&["PUBSUB", "NUMPAT"]);
    assert_eq!(patterns, "1", "one pattern, for the one prefix");

    // No message is published: the keyspace event alone is enough.
    set(
        &valkey,
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    watcher.wait_ids_within(PROMPT, &["api", "site"]).await;
    valkey.cli(&["DEL", "podgate/acme/apps/site"]);
    watcher.wait_ids_within(PROMPT, &["api"]).await;
}

#[tokio::test]
async fn redis_poll_fallback() {
    let valkey = Valkey::start().await;
    set(
        &valkey,
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"redis\"\nname = \"redis\"\nurl = {:?}\nrefresh_secs = 5\n{ACME_PREFIX}",
            valkey.url()
        ),
    );
    let mut watcher = Watcher::start(&config);
    watcher.wait_ids(&["site"]).await;

    // Nobody publishes and no keyspace event is enabled: the poll finds the change.
    set(
        &valkey,
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    let started = Instant::now();
    watcher
        .wait_ids_within(Duration::from_secs(12), &["api", "site"])
        .await;
    assert!(
        started.elapsed() < Duration::from_secs(9),
        "the poll runs every refresh_secs: {:?}",
        started.elapsed()
    );

    // The poll keeps finding changes: a removal too.
    valkey.cli(&["DEL", "podgate/acme/apps/site"]);
    watcher
        .wait_ids_within(Duration::from_secs(12), &["api"])
        .await;
}

#[tokio::test]
async fn redis_reconnects() {
    let mut valkey = Valkey::start().await;
    set(
        &valkey,
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let mut watcher = Watcher::start(&redis_config(&valkey.url(), "", ""));
    watcher.wait_ids(&["site"]).await;
    wait_subscribers(&valkey, "podgate:changed", 1).await;

    valkey.stop();
    watcher.wait_outage("cannot reach the store").await;

    // The store comes back, empty, and the writer fills it again. The read connection reconnects
    // on its own; the subscription's reconnect wakes the source too, because it may have missed
    // messages while it was down.
    valkey.restart().await;
    set(
        &valkey,
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    publish(&valkey, "podgate:changed");
    watcher.wait_ids(&["api"]).await;
    assert!(watcher.outage.is_none(), "{:?}", watcher.outage);

    // The subscription is back as well: a message is enough again, with the poll an hour away.
    wait_subscribers(&valkey, "podgate:changed", 1).await;
    set(
        &valkey,
        "podgate/acme/apps/web",
        &doc("web.acme.test", "http://10.4.0.7:8080"),
    );
    publish(&valkey, "podgate:changed");
    watcher.wait_ids_within(PROMPT, &["api", "web"]).await;
}

#[tokio::test]
async fn redis_outage_keeps_last_state() {
    let mut valkey = Valkey::start().await;
    set(
        &valkey,
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let mut watcher = Watcher::start(&redis_config(&valkey.url(), "", ""));
    watcher.wait_ids(&["site"]).await;

    valkey.stop();
    let why = watcher.wait_outage("cannot reach the store").await;
    assert!(
        why.contains(&valkey.addr().to_string()),
        "the outage names the store: {why}"
    );
    // The source keeps trying meanwhile; the state stays and no state without apps is sent.
    watcher
        .poll(Duration::from_millis(1500), |_, _| false)
        .await;
    assert!(
        watcher
            .history
            .iter()
            .all(|ids| ids == &["site".to_owned()]),
        "an outage never sends a state without the apps: {:?}",
        watcher.history
    );
    assert_eq!(
        watcher.state.as_ref().map(ids),
        Some(vec!["site".to_owned()])
    );

    // The store comes back with different content: the outage ends with a new state.
    valkey.restart().await;
    set(
        &valkey,
        "podgate/acme/apps/api",
        &doc("api.acme.test", "http://10.4.0.6:8080"),
    );
    publish(&valkey, "podgate:changed");
    watcher.wait_ids(&["api"]).await;
    assert!(watcher.outage.is_none(), "{:?}", watcher.outage);
}

// ---- the commands ------------------------------------------------------------------------------

#[tokio::test]
async fn redis_uses_scan_not_keys() {
    let valkey = Valkey::start().await;
    let recorder = Recorder::start(valkey.addr()).await;
    // 300 apps and as many keys of another prefix: more keys than one `SCAN` page looks at, so
    // the cursor has to be followed, and the match filters on the server.
    let mut commands = Vec::new();
    let mut own = BTreeSet::new();
    for n in 0..300 {
        let key = format!("podgate/acme/apps/a{n:03}");
        let host = format!("a{n:03}.acme.test");
        commands.push(set_command(
            &key,
            doc(&host, "http://10.4.0.5:8080").as_bytes(),
        ));
        commands.push(set_command(
            &format!("podgate/globex/apps/g{n:03}"),
            doc(&format!("g{n:03}.globex.test"), "http://10.5.0.5:8080").as_bytes(),
        ));
        own.insert(key);
    }
    pipeline(&valkey, &commands).await;

    let mut watcher = Watcher::start(&redis_config(&recorder.url(), "", ""));
    watcher
        .until_within(DEADLINE, "the apps of acme", |state, _| state.is_some())
        .await;
    assert_eq!(
        watcher.state.as_ref().map(|state| state.apps.len()),
        Some(256),
        "the key-value layer's cap of apps per prefix"
    );

    let commands = recorder.commands();
    fn name(command: &[Vec<u8>]) -> String {
        String::from_utf8_lossy(&command[0]).to_uppercase()
    }
    assert!(
        commands.iter().all(|command| name(command) != "KEYS"),
        "KEYS is never sent"
    );
    let scans: Vec<_> = commands
        .iter()
        .filter(|command| name(command) == "SCAN")
        .collect();
    assert!(scans.len() > 1, "the cursor is followed: {}", scans.len());
    for scan in &scans {
        assert_eq!(scan[2], b"MATCH");
        assert_eq!(scan[3], b"podgate/acme/*", "the prefix, with its slash");
    }
    let asked: BTreeSet<String> = commands
        .iter()
        .filter(|command| name(command) == "MGET")
        .flat_map(|command| command[1..].iter())
        .map(|key| String::from_utf8_lossy(key).into_owned())
        .collect();
    assert_eq!(
        asked, own,
        "MGET asks for the keys of the prefix and no others"
    );
}

#[tokio::test]
async fn redis_only_allowed_commands() {
    let valkey = Valkey::start_with(Some("pw-for-the-commands"), None).await;
    let dir = scratch("redis-commands");
    set(
        &valkey,
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    assert_eq!(valkey.cli(&["MOVE", "podgate/acme/apps/site", "1"]), "1");
    let recorder = Recorder::start(valkey.addr()).await;
    let password = password_file(&dir, "password", "pw-for-the-commands");
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"redis\"\nname = \"redis\"\nurl = {:?}\npassword_file = {:?}\ndb = 1\nkeyspace_notifications = true\nrefresh_secs = 5\n{ACME_PREFIX}",
            recorder.url(),
            password.display().to_string()
        ),
    );
    let mut watcher = Watcher::start(&config);
    watcher.wait_ids(&["site"]).await;

    // The heartbeat of the subscription comes every refresh_secs.
    let deadline = Instant::now() + DEADLINE;
    while !recorder.names().contains("PING") {
        assert!(Instant::now() < deadline, "no PING: {:?}", recorder.names());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let names: Vec<String> = recorder.names().into_iter().collect();
    assert_eq!(
        names,
        [
            "AUTH",
            "MGET",
            "PING",
            "PSUBSCRIBE",
            "SCAN",
            "SELECT",
            "SUBSCRIBE"
        ],
        "exactly the listed commands, and each of them is used"
    );
    let select = recorder
        .commands()
        .into_iter()
        .find(|command| command[0].eq_ignore_ascii_case(b"SELECT"))
        .expect("a SELECT");
    assert_eq!(select[1], b"1");
    let pattern = recorder
        .commands()
        .into_iter()
        .find(|command| command[0].eq_ignore_ascii_case(b"PSUBSCRIBE"))
        .expect("a PSUBSCRIBE");
    assert_eq!(
        pattern[1], b"__keyspace@1__:podgate/acme/*",
        "the keyspace channel of the configured db"
    );
    let _ = std::fs::remove_dir_all(dir);
}

// ---- authentication, ACL, TLS, db ---------------------------------------------------------------

#[tokio::test]
async fn redis_auth_and_tls() {
    let dir = scratch("redis-auth");
    let pki = TlsFiles::new(&dir, "pki-a");
    let other_pki = TlsFiles::new(&dir, "pki-b");
    let valkey = Valkey::start_with(Some("admin-password"), Some(pki.clone())).await;
    set(
        &valkey,
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    // The keys live in database 1.
    assert_eq!(valkey.cli(&["MOVE", "podgate/acme/apps/site", "1"]), "1");
    // The read-only user of the documentation: the listed commands (and SELECT for `db`), the
    // prefix's keys and the notification channel, nothing else.
    assert_eq!(
        valkey.cli(&[
            "ACL",
            "SETUSER",
            "podgate",
            "on",
            ">user-password",
            "resetkeys",
            "~podgate/acme/*",
            "resetchannels",
            "&podgate:changed",
            "-@all",
            "+scan",
            "+mget",
            "+get",
            "+subscribe",
            "+psubscribe",
            "+ping",
            "+select",
        ]),
        "OK"
    );
    let good = password_file(&dir, "good", "user-password");
    let wrong = password_file(&dir, "wrong", "not-the-password");
    let url = valkey.url();
    assert!(url.starts_with("rediss://"), "{url}");
    let tls = |pki: &TlsFiles| {
        format!(
            "[source.tls]\nca_file = {:?}\ncert_file = {:?}\nkey_file = {:?}\n",
            pki.ca.display().to_string(),
            pki.cert.display().to_string(),
            pki.key.display().to_string()
        )
    };
    let keys = |password: &Path, db: u32| {
        format!(
            "username = \"podgate\"\npassword_file = {:?}\ndb = {db}",
            password.display().to_string()
        )
    };

    // The right user, CA and database: the app arrives over TLS with the restricted user.
    let mut watcher = Watcher::start(&redis_config(&url, &keys(&good, 1), &tls(&pki)));
    watcher.wait_ids(&["site"]).await;
    // The notification channel is allowed to that user too.
    wait_subscribers(&valkey, "podgate:changed", 1).await;

    // Database 0 holds nothing.
    let mut empty = Watcher::start(&redis_config(&url, &keys(&good, 0), &tls(&pki)));
    empty.wait_ids(&[]).await;

    // Another password is refused, and the outage says so without quoting anything.
    let mut refused = Watcher::start(&redis_config(&url, &keys(&wrong, 1), &tls(&pki)));
    let why = refused.wait_outage("refused the credentials").await;
    assert!(!why.contains("not-the-password"), "{why}");

    // A server certificate from another CA is not trusted.
    let mut untrusted = Watcher::start(&redis_config(&url, &keys(&good, 1), &tls(&other_pki)));
    untrusted.wait_outage("TLS").await;
    assert!(untrusted.state.is_none());

    // A connection that never asked for TLS cannot talk to a TLS port: plain text is refused
    // before it starts.
    let plain = url.replacen("rediss://", "redis://", 1);
    let mut plain_text = Watcher::start(&redis_config(&plain, &keys(&good, 1), ""));
    plain_text.wait_outage("cannot reach the store").await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn redis_password_without_a_user() {
    let dir = scratch("redis-password");
    let valkey = Valkey::start_with(Some("only-a-password"), None).await;
    set(
        &valkey,
        "podgate/acme/apps/site",
        &doc("shop.acme.test", "http://10.4.0.5:8080"),
    );
    let good = password_file(&dir, "good", "only-a-password");
    let mut watcher = Watcher::start(&redis_config(
        &valkey.url(),
        &format!("password_file = {:?}", good.display().to_string()),
        "",
    ));
    watcher.wait_ids(&["site"]).await;

    // Without a password the server refuses every command, and that is an outage, not an empty
    // state.
    let mut anonymous = Watcher::start(&redis_config(&valkey.url(), "", ""));
    anonymous.wait_outage("NOAUTH").await;
    assert!(anonymous.state.is_none());
    let _ = std::fs::remove_dir_all(dir);
}

// ---- the rules of the key-value layer ------------------------------------------------------------

#[tokio::test]
async fn redis_tenant_only_from_prefix() {
    let valkey = Valkey::start().await;
    let mut naming = doc("shop.acme.test", "http://10.4.0.5:8080");
    let mut value: serde_json::Value = serde_json::from_str(&naming).expect("json");
    value["tenant"] = json!("globex");
    naming = value.to_string();
    value["tenant"] = json!("acme");
    let naming_own = value.to_string();
    set(&valkey, "podgate/acme/apps/naming", &naming);
    set(&valkey, "podgate/acme/apps/naming-own", &naming_own);
    set(
        &valkey,
        "podgate/acme/apps/fine",
        &doc("www.acme.test", "http://10.4.0.5:8080"),
    );
    // Keys that are outside the prefix, or inside it with a shape that is no app or certificate.
    set(
        &valkey,
        "podgate/acme2/apps/other",
        &doc("x.acme.test", "http://10.4.0.5:8080"),
    );
    set(
        &valkey,
        "podgate/globex/apps/site",
        &doc("globex.test", "http://10.5.0.5:8080"),
    );
    set(
        &valkey,
        "podgate/acme/junk",
        &doc("junk.acme.test", "http://10.4.0.5:8080"),
    );

    let mut watcher = Watcher::start(&redis_config(&valkey.url(), "", ""));
    let state = watcher.wait_ids(&["fine"]).await;
    assert_eq!(state.apps[0].tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(state.apps[0].tenant.label, None);
    let report = watcher.wait_outage("podgate/acme/apps/naming-own").await;
    assert!(report.contains("podgate/acme/apps/naming"), "{report}");
    assert!(
        report.contains("the tenant comes only from the prefix mapping"),
        "{report}"
    );
    assert!(report.contains("podgate/acme/junk"), "{report}");
    assert!(
        !report.contains("podgate/acme2/apps/other"),
        "a key the prefix does not match is never even read: {report}"
    );
}

#[test]
fn redis_source_requires_tenant_allowlist() {
    let config = redis_config("redis://127.0.0.1:6379", "", "");
    let err = RedisSource::from_config(&config.sources[0], &UpstreamPolicy::builtin())
        .expect_err("a tenant without an allow list")
        .to_string();
    assert!(err.contains("kv_source_requires_tenant_allowlist"), "{err}");
    assert!(err.contains("tenants.acme.allow"), "{err}");
}

#[tokio::test]
async fn redis_document_limits() {
    let valkey = Valkey::start().await;
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"redis\"\nname = \"redis\"\nurl = {:?}\nrefresh_secs = 3600\n{ACME_PREFIX}\n[[source.prefix]]\nprefix = \"podgate/globex\"\ntenant = \"globex\"\nlayout = \"podgate-json\"\n",
            valkey.url()
        ),
    );
    // A value past 256 KiB, next to a fine app.
    let mut commands = vec![set_command(
        "podgate/acme/apps/site",
        doc("shop.acme.test", "http://10.4.0.5:8080").as_bytes(),
    )];
    commands.push(set_command(
        "podgate/acme/apps/big",
        &vec![b'x'; 256 * 1024 + 1],
    ));
    // A value of exactly 256 KiB is read (and is no valid document: it is reported by the layer).
    commands.push(set_command(
        "podgate/acme/apps/exact",
        &vec![b'x'; 256 * 1024],
    ));
    // A prefix with more keys than the provider reads.
    for n in 0..4100 {
        commands.push(set_command(&format!("podgate/globex/apps/k{n}"), b"{}"));
    }
    pipeline(&valkey, &commands).await;

    let mut watcher = Watcher::start(&config);
    let report = watcher
        .wait_outage("the prefix holds more than 4096 keys")
        .await;
    assert!(report.contains("podgate/globex/"), "{report}");
    let state = watcher.state.clone().expect("acme is served meanwhile");
    assert_eq!(ids(&state), ["site"], "the other prefix is not held back");
    let oversize: Vec<&str> = report
        .split("; ")
        .filter(|line| line.contains("larger than 262144 bytes"))
        .collect();
    assert_eq!(oversize.len(), 1, "{report}");
    assert!(oversize[0].contains("podgate/acme/apps/big"), "{report}");
    assert!(
        report.contains("podgate/acme/apps/exact"),
        "a value of exactly 256 KiB is read, and the layer rejects it as a document: {report}"
    );

    // The flood ends: the outage ends with it, and the oversized value stays reported.
    let deletes: Vec<Vec<Vec<u8>>> = (0..4100)
        .map(|n| {
            vec![
                b"DEL".to_vec(),
                format!("podgate/globex/apps/k{n}").into_bytes(),
            ]
        })
        .collect();
    pipeline(&valkey, &deletes).await;
    wait_subscribers(&valkey, "podgate:changed", 1).await;
    publish(&valkey, "podgate:changed");
    watcher
        .until_within(PROMPT, "the globex prefix readable again", |_, outage| {
            outage.is_some_and(|why| !why.contains("podgate/globex/"))
        })
        .await;
    drop(valkey);
}

#[test]
fn redis_config_errors_name_the_key() {
    let probe = |keys: &str, tables: &str, url: &str| -> String {
        let config = redis_config(url, keys, tables);
        RedisSource::from_config(&config.sources[0], &policy())
            .expect_err("an invalid redis source")
            .to_string()
    };
    let plain = "redis://127.0.0.1:6379";
    assert!(probe("bogus = 1", "", plain).contains("bogus"));
    assert!(probe("", "", "http://127.0.0.1:6379").contains("redis:// or rediss://"));
    assert!(probe("", "", "redis://user:pw@127.0.0.1").contains("must not carry credentials"));
    assert!(probe("", "", "redis://127.0.0.1/3").contains("`db`"));
    assert!(probe("", "", "redis://redis.internal:6379").contains("rediss://"));
    assert!(probe("username = \"u\"", "", plain).contains("username: needs password_file"));
    assert!(probe("password_file = \"/nonexistent/pw\"", "", plain).contains("password_file"));
    assert!(probe("notify_channel = \"\"", "", plain).contains("notify_channel"));
    assert!(probe("refresh_secs = 4", "", plain).contains("refresh_secs: must be at least 5"));
    assert!(probe("", "[source.tls]\nca_file = \"/x\"\n", plain).contains("needs a rediss:// url"));
    assert!(
        probe(
            "",
            "[source.tls]\nca_file = \"/nonexistent/ca.pem\"\n",
            "rediss://redis.internal"
        )
        .contains("tls.ca_file")
    );
}
