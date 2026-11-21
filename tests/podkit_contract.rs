//! The podkit integration contract: `docs/podkit-integration.md` is tested, not just
//! written.
//!
//! The document's fenced JSON blocks carry a label after `json`:
//!
//! - `fixture:<name>` is byte for byte `tests/fixtures/podkit/<name>.json`, which the real
//!   binary accepts (`podkit_fixtures_compile`) and serves as the document says
//!   (`podkit_rolling_deploy_sequence`, `podkit_acme_walkthrough`).
//! - `reply:<name>` is a response the real daemon gives, compared as JSON.
//! - `shape:<name>` is an event or answer whose values vary; its top-level keys are compared.
//! - `snippet:<name>` is merged into a fixture and validated by the daemon.
//! - `policy:upstream` is the upstream policy file the daemon is started with.
//!
//! Every test starts the real binary the way the document tells podkit's agent to
//! (`ENTRY_POINTS=web=:80/http,websecure=:443/https`) on free loopback ports. `pebble` is a
//! prerequisite of the ACME test, which fails without it.

mod common;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::pebble::{Pebble, Pki, Validation};
use common::{Podgate, TestCert, Upstream};
use rcgen::KeyPair;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;

const AGENT: &str = "podkit-agent";
const PLATFORM_HOST: &str = "shop.apps.example.com";
const CUSTOM_HOST: &str = "shop.acme-corp.dev";
/// Where the fixtures put the containers of `d-1001` and `d-1002`.
const OLD_CONTAINER: &str = "10.89.0.21:3000";
const NEW_CONTAINER: &str = "10.89.0.22:3000";
/// The names of the entry points the document tells podkit to start podgate with.
const ENTRY_POINTS: [(&str, &str); 2] = [("web", "http"), ("websecure", "https")];

/// Longest to wait for one step that depends on another process.
const STEP: Duration = Duration::from_secs(45);

/// Held while a test starts its processes, so the tests of one `cargo test` process (threads)
/// do not race each other for ports. Starting is serialized; running is not.
static STARTUP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ---- the document and the fixtures -------------------------------------------------------

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> String {
    let path = root()
        .join("tests/fixtures/podkit")
        .join(format!("{name}.json"));
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn fixture_json(name: &str) -> Value {
    serde_json::from_str(&fixture(name)).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
}

/// The fixture with its container addresses replaced by real local upstreams.
fn fixture_on(name: &str, old: Option<SocketAddr>, new: Option<SocketAddr>) -> Value {
    let mut text = fixture(name);
    if let Some(old) = old {
        text = text.replace(OLD_CONTAINER, &old.to_string());
    }
    if let Some(new) = new {
        text = text.replace(NEW_CONTAINER, &new.to_string());
    }
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
}

/// Every labelled fenced block of the document: `(label, body)`. The opening fence is three
/// backticks, a language, a space and the label.
fn doc_blocks() -> Vec<(String, String)> {
    let doc = std::fs::read_to_string(root().join("docs/podkit-integration.md"))
        .expect("docs/podkit-integration.md exists");
    let mut blocks = Vec::new();
    let mut open: Option<(String, String)> = None;
    for line in doc.lines() {
        match &mut open {
            None => {
                if let Some((_, label)) = line.strip_prefix("```").and_then(|f| f.split_once(' ')) {
                    open = Some((label.trim().to_owned(), String::new()));
                }
            }
            Some((_, body)) if line != "```" => {
                body.push_str(line);
                body.push('\n');
            }
            Some(_) => blocks.extend(open.take()),
        }
    }
    assert!(
        open.is_none(),
        "a fenced block of the document is not closed"
    );
    blocks
}

fn doc_block(label: &str) -> String {
    let mut found = doc_blocks().into_iter().filter(|(name, _)| name == label);
    let (_, body) = found
        .next()
        .unwrap_or_else(|| panic!("the document has no block labelled {label}"));
    assert!(found.next().is_none(), "two blocks labelled {label}");
    body
}

fn doc_json(label: &str) -> Value {
    serde_json::from_str(&doc_block(label))
        .unwrap_or_else(|err| panic!("block {label} is not JSON: {err}"))
}

fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {value}"))
        .keys()
        .cloned()
        .collect()
}

/// `value` has the top-level keys of the document's `shape:<label>` block.
fn assert_shape(label: &str, value: &Value) {
    assert_eq!(
        keys(&doc_json(&format!("shape:{label}"))),
        keys(value),
        "the document's shape:{label} differs from what podgate sent: {value}"
    );
}

// ---- talking to the daemon ---------------------------------------------------------------

#[derive(Debug)]
struct Reply {
    status: u16,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|err| panic!("not JSON ({err}): {:?}", self.body))
    }
}

/// One request on the admin socket with the headers the agent sends.
async fn admin(
    podgate: &Podgate,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut stream = UnixStream::connect(&podgate.admin_socket)
        .await
        .expect("connect to the admin socket");
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{extra}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    timeout(Duration::from_secs(15), async {
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("no header end: {text:?}"));
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("bad status line: {head:?}"));
        Reply {
            status,
            body: body.to_owned(),
        }
    })
    .await
    .expect("response in time")
}

/// A push as the agent sends it: `PUT /v1/snapshot` with `podgate-writer: podkit-agent`.
async fn push(podgate: &Podgate, snapshot: &Value) -> Reply {
    push_as(podgate, Some(AGENT), false, snapshot).await
}

async fn push_as(
    podgate: &Podgate,
    writer: Option<&str>,
    takeover: bool,
    snapshot: &Value,
) -> Reply {
    let headers: Vec<(&str, &str)> = writer
        .map(|name| ("podgate-writer", name))
        .into_iter()
        .collect();
    let target = if takeover {
        "/v1/snapshot?takeover=true"
    } else {
        "/v1/snapshot"
    };
    admin(podgate, "PUT", target, &headers, &snapshot.to_string()).await
}

async fn validate(podgate: &Podgate, snapshot: &Value) -> Reply {
    admin(
        podgate,
        "POST",
        "/v1/snapshot/validate",
        &[],
        &snapshot.to_string(),
    )
    .await
}

async fn get(podgate: &Podgate, target: &str) -> Reply {
    admin(podgate, "GET", target, &[], "").await
}

/// The first `web` request to `host`: status and body.
async fn web(podgate: &Podgate, host: &str, path: &str) -> (u16, String) {
    let response = podgate.get(host, path).await;
    (response.status, response.body)
}

/// The agent's poller: events after `after`, long polling in short turns until one of `kind`
/// arrives or `deadline` passes. Returns the matching event and the last `seq` seen.
async fn wait_event(
    podgate: &Podgate,
    after: &mut u64,
    kind: &str,
    deadline: Duration,
) -> Option<Value> {
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        let reply = get(podgate, &format!("/v1/events?after={after}&timeout_secs=1")).await;
        // 408: the long poll outlived the admin request timeout and consumed nothing. Poll again.
        if reply.status == 408 {
            continue;
        }
        assert_eq!(reply.status, 200, "{reply:?}");
        let body = reply.json();
        for event in body["events"].as_array().cloned().unwrap_or_default() {
            *after = event["seq"].as_u64().expect("seq");
            if event["kind"] == kind {
                return Some(event);
            }
        }
    }
    None
}

/// podgate as the document starts it: the two entry points, plus `extra_env`.
async fn start_podkit(extra_env: &[(&str, &str)]) -> Podgate {
    let _startup = STARTUP.lock().await;
    Podgate::start_with_entry_points(&ENTRY_POINTS, extra_env).await
}

// ---- tests -------------------------------------------------------------------------------

#[test]
fn podkit_doc_examples_match_fixtures() {
    let blocks = doc_blocks();
    for name in ["steady", "rolling", "retired", "acme"] {
        let label = format!("fixture:{name}");
        let mut found = blocks.iter().filter(|(found, _)| *found == label);
        let (_, body) = found
            .next()
            .unwrap_or_else(|| panic!("the document has no {label} block"));
        assert!(found.next().is_none(), "two {label} blocks");
        assert_eq!(
            body.trim_end(),
            fixture(name).trim_end(),
            "the document's {label} block differs from tests/fixtures/podkit/{name}.json"
        );
    }
    for (label, body) in &blocks {
        let known = label.starts_with("fixture:")
            || ["env:", "reply:", "shape:", "snippet:", "policy:"]
                .iter()
                .any(|prefix| label.starts_with(prefix));
        assert!(known, "unknown block label {label}");
        assert!(
            label.starts_with("env:") || serde_json::from_str::<Value>(body).is_ok(),
            "block {label} is not valid JSON"
        );
    }
}

#[tokio::test]
async fn podkit_fixtures_compile() {
    let policy_dir = std::env::temp_dir().join(format!("podkit-policy-{}", std::process::id()));
    std::fs::create_dir_all(&policy_dir).expect("policy dir");
    let policy_file = policy_dir.join("upstream-policy.json");
    std::fs::write(&policy_file, doc_block("policy:upstream")).expect("write the policy");
    let podgate = start_podkit(&[("UPSTREAM_POLICY_FILE", &policy_file.to_string_lossy())]).await;

    // Every fixture validates as written, whatever the live version, with no side effect.
    for name in ["steady", "rolling", "retired", "acme"] {
        let reply = validate(&podgate, &fixture_json(name)).await;
        assert_eq!(reply.status, 200, "validate {name}: {reply:?}");
        assert_eq!(
            reply.json(),
            json!({"valid": true, "warnings": []}),
            "{name}"
        );
    }
    let before = get(&podgate, "/v1/snapshot/version").await.json();
    assert_eq!(before["version"], 0, "validate applies nothing: {before}");

    // The agent's counter is its own: the first push of a process can be any version.
    for name in ["steady", "rolling", "retired", "acme"] {
        let snapshot = fixture_json(name);
        let reply = push(&podgate, &snapshot).await;
        assert_eq!(reply.status, 200, "push {name}: {reply:?}");
        assert_eq!(
            reply.json(),
            json!({"version": snapshot["version"]}),
            "{name}"
        );
    }
    let live = get(&podgate, "/v1/snapshot/version").await;
    let live = live.json();
    assert_shape("version", &live);
    assert_eq!(
        (live["version"].clone(), live["writer"].clone()),
        (json!(44), json!(AGENT))
    );

    // The optional variations of the document are accepted when merged into the fixture.
    let mut variation = fixture_json("rolling");
    variation["version"] = json!(45);
    let canary = doc_json("snippet:canary");
    variation["apps"][0]["canary"] = canary["canary"].clone();
    for revision in variation["apps"][0]["revisions"]
        .as_array_mut()
        .expect("revisions")
    {
        revision["state"] = json!("serving");
        revision["weight"] = json!(if revision["id"] == "d-1001" { 100 } else { 0 });
    }
    variation["skew_secret"] = doc_json("snippet:skew")["skew_secret"].clone();
    let reply = validate(&podgate, &variation).await;
    assert_eq!(reply.status, 200, "canary and skew snippets: {reply:?}");

    // The upstream policy of the document refuses the agent's own address and the metadata
    // range, and the compiler says so in the `422` the agent must read.
    let mut forbidden = fixture_json("retired");
    forbidden["version"] = json!(45);
    let with_server = |url: &str| {
        let mut snapshot = forbidden.clone();
        snapshot["apps"][0]["revisions"][0]["services"][0]["servers"] = json!([{ "url": url }]);
        snapshot
    };
    let reply = push(&podgate, &with_server("http://10.89.0.1:3000")).await;
    assert_eq!(reply.status, 422, "{reply:?}");
    assert_eq!(reply.json(), doc_json("reply:upstream_forbidden"));
    let reply = push(&podgate, &with_server("http://169.254.169.254:80")).await;
    assert_eq!(reply.status, 422, "{reply:?}");
    assert_eq!(
        reply.json()["conflicts"][0]["code"],
        "upstream_forbidden",
        "{reply:?}"
    );
    let reply = push(&podgate, &with_server("http://10.89.0.99:3000")).await;
    assert_eq!(
        reply.status, 200,
        "an address of the podkit network is allowed: {reply:?}"
    );
    drop(std::fs::remove_dir_all(&policy_dir));
}

/// A backend that answers `/` at once with `body` and holds every request for `/slow` until the
/// test releases it: the in-flight request of a rolling deploy.
struct Container {
    addr: SocketAddr,
    /// One message per `/slow` request that reached the backend.
    started: mpsc::UnboundedReceiver<()>,
    gate: Arc<Semaphore>,
}

impl Container {
    async fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind container");
        let addr = listener.local_addr().expect("container addr");
        let (started_tx, started) = mpsc::unbounded_channel();
        let gate = Arc::new(Semaphore::new(0));
        tokio::spawn({
            let gate = Arc::clone(&gate);
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(serve(stream, body, started_tx.clone(), Arc::clone(&gate)));
                }
            }
        });
        Self {
            addr,
            started,
            gate,
        }
    }

    async fn slow_request_arrived(&mut self) {
        timeout(Duration::from_secs(5), self.started.recv())
            .await
            .expect("the slow request reaches the container")
            .expect("container alive");
    }

    fn release(&self) {
        self.gate.add_permits(1);
    }
}

async fn serve(
    mut stream: TcpStream,
    body: &'static str,
    started: mpsc::UnboundedSender<()>,
    gate: Arc<Semaphore>,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
    let body = if seen.starts_with(b"GET /slow ") {
        if started.send(()).is_err() {
            return;
        }
        gate.acquire().await.expect("gate open").forget();
        "slow-done"
    } else {
        body
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    drop(stream.write_all(response.as_bytes()).await);
}

#[tokio::test]
async fn podkit_rolling_deploy_sequence() {
    let podgate = Arc::new(start_podkit(&[]).await);
    let mut old = Container::start("old").await;
    let new = Container::start("new").await;
    let (old_addr, new_addr) = (old.addr, new.addr);
    let on = |name: &str| fixture_on(name, Some(old_addr), Some(new_addr));

    // steady: the application serves from its one deployment.
    let reply = push(&podgate, &on("steady")).await;
    assert_eq!(reply.status, 200, "{reply:?}");
    assert_eq!(web(&podgate, PLATFORM_HOST, "/").await, (200, "old".into()));
    let unknown = web(&podgate, "nobody.example.com", "/").await;
    assert_eq!(unknown, (404, r#"{"error":"not found"}"#.into()));

    // A request is in flight on the old deployment, and traffic keeps flowing for the whole
    // sequence: not one request may fail.
    let in_flight = tokio::spawn({
        let podgate = Arc::clone(&podgate);
        async move { web(&podgate, PLATFORM_HOST, "/slow").await }
    });
    old.slow_request_arrived().await;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let traffic = tokio::spawn({
        let (podgate, stop) = (Arc::clone(&podgate), Arc::clone(&stop));
        async move {
            let mut seen = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                seen.push(web(&podgate, PLATFORM_HOST, "/").await);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            seen
        }
    });

    // rolling: the new deployment serves, the old one drains.
    let mut after = 0;
    let reply = push(&podgate, &on("rolling")).await;
    assert_eq!(reply.status, 200, "{reply:?}");
    assert_eq!(
        web(&podgate, PLATFORM_HOST, "/").await,
        (200, "new".into()),
        "a draining revision gets no new request"
    );
    let early = wait_event(
        &podgate,
        &mut after,
        "revision_drained",
        Duration::from_secs(2),
    )
    .await;
    assert!(
        early.is_none(),
        "drained while a request is in flight: {early:?}"
    );

    // The in-flight request finishes on the old deployment, then podgate says it is drained.
    old.release();
    let finished = in_flight.await.expect("in-flight request");
    assert_eq!(
        finished,
        (200, "slow-done".into()),
        "the in-flight request completes"
    );
    let drained = wait_event(&podgate, &mut after, "revision_drained", STEP)
        .await
        .expect("revision_drained arrives once the request ended");
    assert_eq!(drained["app"], "app-42");
    assert_eq!(drained["revision"], "d-1001");
    assert_shape("revision_drained", &drained);

    // The agent retires the old container, then pushes the snapshot without it.
    let reply = push(&podgate, &on("retired")).await;
    assert_eq!(reply.status, 200, "{reply:?}");
    stop.store(true, Ordering::Relaxed);
    let seen = traffic.await.expect("traffic task");
    assert!(
        seen.len() > 5,
        "traffic ran during the sequence: {}",
        seen.len()
    );
    let failed: Vec<_> = seen.iter().filter(|(status, _)| *status != 200).collect();
    assert!(
        failed.is_empty(),
        "requests failed during the rolling deploy: {failed:?}"
    );
    let first_new = seen
        .iter()
        .position(|(_, body)| body == "new")
        .expect("traffic reached the new deployment");
    assert!(
        seen[first_new..].iter().all(|(_, body)| body == "new"),
        "no request went back to the old deployment"
    );

    // retired: the old revision is gone from the live table, and drained exactly once.
    let explain = get(
        &podgate,
        &format!("/v1/explain?url=http://{PLATFORM_HOST}/&method=GET"),
    )
    .await
    .json();
    let revisions: Vec<&Value> = explain["revisions"]
        .as_array()
        .expect("revisions")
        .iter()
        .map(|revision| &revision["id"])
        .collect();
    assert_eq!(revisions, [&json!("d-1002")], "{explain}");
    let again = wait_event(
        &podgate,
        &mut after,
        "revision_drained",
        Duration::from_secs(2),
    )
    .await;
    assert!(again.is_none(), "one drain per draining period: {again:?}");
}

#[tokio::test]
async fn podkit_writer_rules() {
    let podgate = start_podkit(&[]).await;
    let upstream = Upstream::start("upstream").await;
    let steady = fixture_on("steady", Some(upstream.addr), None);
    let at = |version: u64| {
        let mut snapshot = steady.clone();
        snapshot["version"] = json!(version);
        snapshot
    };

    // Before the first snapshot: ready, nothing routed, nobody owns the node.
    assert_eq!(get(&podgate, "/readyz").await.status, 200);
    assert_eq!(
        web(&podgate, PLATFORM_HOST, "/").await,
        (404, r#"{"error":"not found"}"#.into()),
        "traffic before the first snapshot"
    );
    let version = get(&podgate, "/v1/snapshot/version").await.json();
    assert_eq!(
        (version["version"].clone(), version["writer"].clone()),
        (json!(0), Value::Null)
    );

    // The agent's first push pins it.
    let reply = push(&podgate, &at(41)).await;
    assert_eq!(reply.status, 200, "{reply:?}");
    let version = get(&podgate, "/v1/snapshot/version").await.json();
    assert_eq!(version["writer"], AGENT);

    // A second writer, and a writer with no name, are refused and change nothing. This is the
    // exact answer the document quotes.
    let refused = push_as(&podgate, Some("podgate-provider"), false, &at(42)).await;
    assert_eq!(refused.status, 409, "{refused:?}");
    assert_eq!(refused.json(), doc_json("reply:writer_owned"));
    let unnamed = push_as(&podgate, None, false, &at(42)).await;
    assert_eq!(unnamed.status, 409, "{unnamed:?}");
    assert_eq!(unnamed.json(), doc_json("reply:writer_owned"));
    let plan = admin(
        &podgate,
        "POST",
        "/v1/snapshot/plan",
        &[("podgate-writer", "podgate-provider")],
        &at(42).to_string(),
    )
    .await;
    assert_eq!(plan.status, 409, "a plan is checked like a push: {plan:?}");
    let live = get(&podgate, "/v1/snapshot/version").await.json();
    assert_eq!(
        (live["version"].clone(), live["writer"].clone()),
        (json!(41), json!(AGENT))
    );

    // The owner is refused when its version is not newer: also a 409, with no `writer`.
    let stale = push(&podgate, &at(41)).await;
    assert_eq!(stale.status, 409, "{stale:?}");
    assert_eq!(stale.json(), doc_json("reply:stale_version"));

    // A snapshot the compiler refuses: 422 with the conflicts, and the live one keeps serving.
    let mut clash = at(42);
    let mut twin = clash["apps"][0].clone();
    twin["id"] = json!("app-43");
    twin["routers"] = json!([clash["apps"][0]["routers"][0].clone()]);
    clash["apps"].as_array_mut().expect("apps").push(twin);
    let rejected = push(&podgate, &clash).await;
    assert_eq!(rejected.status, 422, "{rejected:?}");
    assert_eq!(rejected.json(), doc_json("reply:rejected"));
    assert_eq!(
        web(&podgate, PLATFORM_HOST, "/").await.0,
        200,
        "a rejected push changes nothing"
    );

    // A takeover needs a name.
    let unnamed = push_as(&podgate, None, true, &at(42)).await;
    assert_eq!(unnamed.status, 400, "{unnamed:?}");

    // A human takes over: the pin moves, the feed says so, and the agent is now the stranger.
    let taken = push_as(&podgate, Some("operator-chiko"), true, &at(42)).await;
    assert_eq!(taken.status, 200, "{taken:?}");
    let version = get(&podgate, "/v1/snapshot/version").await.json();
    assert_eq!(version["writer"], "operator-chiko");
    let mut after = 0;
    let changed = wait_event(
        &podgate,
        &mut after,
        "writer_changed",
        Duration::from_secs(5),
    )
    .await
    .expect("writer_changed arrives");
    assert_eq!(changed["from"], AGENT);
    assert_eq!(changed["to"], "operator-chiko");
    assert_shape("writer_changed", &changed);
    let agent = push(&podgate, &at(43)).await;
    assert_eq!(agent.status, 409, "{agent:?}");
    assert_eq!(
        agent.json(),
        json!({"error": "snapshot is owned by writer operator-chiko", "writer": "operator-chiko"})
    );

    // The agent takes the node back the same way.
    let back = push_as(&podgate, Some(AGENT), true, &at(43)).await;
    assert_eq!(back.status, 200, "{back:?}");
    let version = get(&podgate, "/v1/snapshot/version").await.json();
    assert_eq!(version["writer"], AGENT);
}

#[tokio::test]
async fn podkit_rolling_deploy_reverts() {
    // The new container is broken: podgate undoes the push, which is what an agent that is
    // still waiting for `revision_drained` must notice.
    let podgate = start_podkit(&[]).await;
    let old = Upstream::start("old").await;
    let broken = common::refused();
    let reply = push(&podgate, &fixture_on("steady", Some(old.addr), None)).await;
    assert_eq!(reply.status, 200, "{reply:?}");
    let reply = push(
        &podgate,
        &fixture_on("rolling", Some(old.addr), Some(broken.addr)),
    )
    .await;
    assert_eq!(reply.status, 200, "{reply:?}");
    for _ in 0..30 {
        assert_eq!(web(&podgate, PLATFORM_HOST, "/").await.0, 502);
    }
    let mut after = 0;
    let reverted = wait_event(
        &podgate,
        &mut after,
        "config_reverted",
        Duration::from_secs(10),
    )
    .await
    .expect("config_reverted arrives");
    assert_eq!(reverted["from_version"], 42);
    assert_eq!(reverted["to_version"], 41);
    assert_shape("config_reverted", &reverted);
    assert_eq!(
        web(&podgate, PLATFORM_HOST, "/").await,
        (200, "old".into()),
        "the old revision serves again"
    );
    // The live version stays at the reverted one: the next push must be newer than 42.
    let stale = push(
        &podgate,
        &fixture_on("rolling", Some(old.addr), Some(broken.addr)),
    )
    .await;
    assert_eq!(stale.status, 409, "{stale:?}");
    let mut next = fixture_on("steady", Some(old.addr), None);
    next["version"] = json!(43);
    assert_eq!(push(&podgate, &next).await.status, 200);
}

#[test]
fn podkit_documented_environment() {
    let env: Vec<(String, String)> = doc_block("env:podgate")
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    let lookup = |extra: &'static [(&'static str, &'static str)]| {
        let env = env.clone();
        move |name: &str| {
            extra
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
                .or_else(|| {
                    env.iter()
                        .find(|(key, _)| key == name)
                        .map(|(_, value)| value.clone())
                })
        }
    };

    let config = podgate::config::Config::from_lookup(lookup(&[])).expect("the documented env");
    let listeners: Vec<(&str, String, podgate::entry::Protocol)> = config
        .entry_points
        .iter()
        .map(|point| (&*point.name, point.addr.to_string(), point.protocol))
        .collect();
    assert_eq!(
        listeners,
        [
            (
                "web",
                "0.0.0.0:8080".to_owned(),
                podgate::entry::Protocol::Http
            ),
            (
                "websecure",
                "0.0.0.0:8443".to_owned(),
                podgate::entry::Protocol::Https
            ),
        ]
    );
    assert_eq!(config.node_name.as_deref(), Some("srv-1"));

    // The image sets `PROXY_ADDR`, which `ENTRY_POINTS` refuses to share a process with.
    let clash = podgate::config::Config::from_lookup(lookup(&[("PROXY_ADDR", "0.0.0.0:8080")]));
    let message = clash.expect_err("ENTRY_POINTS with PROXY_ADDR").to_string();
    assert!(message.contains("PROXY_ADDR"), "{message}");

    // The shorthand names the same two entry points.
    let shorthand = podgate::config::Config::from_lookup(|name| match name {
        "PROXY_ADDR" => Some("0.0.0.0:8080".to_owned()),
        "PROXY_TLS_ADDR" => Some("0.0.0.0:8443".to_owned()),
        _ => None,
    })
    .expect("the shorthand");
    assert_eq!(shorthand.entry_points, config.entry_points);
}

// ---- ACME against pebble -----------------------------------------------------------------

/// The agent's side of the ACME exchange: everything it keeps for podgate.
struct Agent {
    snapshot: Value,
    challenges: Vec<Value>,
    certificates: Vec<Value>,
    after: u64,
}

impl Agent {
    /// The next push: the fixture's state plus what the agent stored, one version up.
    fn next(&mut self) -> &Value {
        let version = self.snapshot["version"].as_u64().expect("version") + 1;
        self.snapshot["version"] = json!(version);
        self.snapshot["acme"]["challenges"] = Value::Array(self.challenges.clone());
        self.snapshot["certificates"] = Value::Array(self.certificates.clone());
        &self.snapshot
    }
}

#[tokio::test]
async fn podkit_acme_walkthrough() {
    static DIRS: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "podkit-acme-{}-{}",
        std::process::id(),
        DIRS.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let pki = Pki::new(&dir);
    let ca_file = pki.ca_pem.to_string_lossy().into_owned();
    // The node is named as the fixture names the issuer: `NODE_NAME=srv-1`.
    let env = [("NODE_NAME", "srv-1"), ("ACME_CA_FILE", ca_file.as_str())];
    let issuer = start_podkit(&env).await;
    let validation = Validation {
        http: Some(issuer.proxy_addr.port()),
        tls: None,
    };
    let pebble = Pebble::start(pki, validation).await;
    let container = Container::start("app body").await;

    // The fixture, with pebble as the CA, the account key podkit generated once, and a local
    // container where the fixture has the container address.
    let key = KeyPair::generate().expect("account key").serialize_pem();
    let mut snapshot = fixture_on("acme", None, Some(container.addr));
    snapshot["acme"]["directory_url"] = json!(pebble.directory);
    snapshot["acme"]["account_key_pem"] = json!(key);
    let mut agent = Agent {
        snapshot,
        challenges: Vec::new(),
        certificates: Vec::new(),
        after: 0,
    };

    // 1. The agent pushes the fixture: the issuer starts an order.
    let first = agent.snapshot.clone();
    let reply = push(&issuer, &first).await;
    assert_eq!(reply.status, 200, "{reply:?}");

    // 2 and 3. Every `acme_challenge` is answered with a push that carries it.
    // 4. `certificate_issued` ends the order; the agent stores it.
    let deadline = Instant::now() + STEP;
    let issued = loop {
        assert!(
            Instant::now() < deadline,
            "no certificate_issued within {STEP:?}; pebble said:\n{}",
            pebble.pki.read("pebble.log")
        );
        let reply = get(
            &issuer,
            &format!("/v1/events?after={}&timeout_secs=1", agent.after),
        )
        .await;
        if reply.status == 408 {
            continue;
        }
        assert_eq!(reply.status, 200, "{reply:?}");
        let mut pushed_challenge = false;
        let mut issued = None;
        for event in reply.json()["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            agent.after = event["seq"].as_u64().expect("seq");
            match event["kind"].as_str() {
                Some("acme_challenge") => {
                    assert_shape("acme_challenge", &event);
                    assert_eq!(event["type"], "http-01", "{event}");
                    agent.challenges.push(json!({
                        "token": event["token"], "key_authorization": event["key_authorization"],
                    }));
                    pushed_challenge = true;
                }
                Some("certificate_issued") => issued = Some(event),
                _ => {}
            }
        }
        if pushed_challenge {
            let next = agent.next().clone();
            let reply = push(&issuer, &next).await;
            assert_eq!(reply.status, 200, "{reply:?}");
        }
        if let Some(issued) = issued {
            break issued;
        }
    };
    assert_shape("certificate_issued", &issued);
    let mut hosts: Vec<&str> = issued["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    hosts.sort_unstable();
    assert_eq!(hosts, [CUSTOM_HOST, PLATFORM_HOST], "{issued}");
    assert!(!agent.challenges.is_empty());

    // 5. The agent stores the certificate and pushes it; the challenges are done with.
    agent.certificates.push(json!({
        "hosts": issued["hosts"], "cert_pem": issued["cert_pem"], "key_pem": issued["key_pem"],
    }));
    agent.challenges.clear();
    let stored = agent.next().clone();
    let reply = push(&issuer, &stored).await;
    assert_eq!(reply.status, 200, "{reply:?}");
    let root = TestCert {
        cert_pem: String::new(),
        key_pem: String::new(),
        der: pebble.root().await,
    };
    let served = issuer.https_get(CUSTOM_HOST, CUSTOM_HOST, "/", &root).await;
    assert_eq!(
        (served.status, served.body.as_str()),
        (200, "app body"),
        "{served:?}"
    );

    // 6. A fresh podgate (a restart, or a new node) gets the stored certificate in its first
    // snapshot. Until then it is ready, and it routes nothing.
    let fresh = start_podkit(&env).await;
    assert_eq!(get(&fresh, "/readyz").await.status, 200);
    assert_eq!(web(&fresh, PLATFORM_HOST, "/").await.0, 404);
    let replay = agent.next().clone();
    let reply = push(&fresh, &replay).await;
    assert_eq!(reply.status, 200, "{reply:?}");
    let served = fresh.https_get(CUSTOM_HOST, CUSTOM_HOST, "/", &root).await;
    assert_eq!(
        (served.status, served.body.as_str()),
        (200, "app body"),
        "{served:?}"
    );
    let mut after = 0;
    let ordered = wait_event(&fresh, &mut after, "acme_challenge", Duration::from_secs(4)).await;
    assert!(
        ordered.is_none(),
        "a host with a certificate is not ordered again: {ordered:?}"
    );
    drop(std::fs::remove_dir_all(&dir));
}
