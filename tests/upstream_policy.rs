//! The upstream address policy end to end: the compiler refuses literal addresses outside it,
//! the connect path refuses the rest, a bad policy file stops startup, and no snapshot can loosen
//! it. The pure rules (CIDR matching, normalization, the file format) are unit-tested in
//! `src/service/upstream_policy.rs`.

mod common;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, Response, Upstream, app, serving, snapshot};
use pingora::ErrorType::HTTPStatus;
use podgate::route::Selected;
use podgate::service::upstream_policy::UpstreamPolicy;
use podgate::{EventFeed, Gateway, Inflight, RoutingTable, TableHandle};
use podgate_model::Snapshot;
use serde_json::{Value, json};

/// A policy file in its own temp directory, removed on drop.
struct PolicyFile {
    dir: PathBuf,
    path: PathBuf,
}

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-policy-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("policy.json");
        std::fs::write(&path, contents).expect("write policy file");
        Self { dir, path }
    }

    fn path(&self) -> &str {
        self.path.to_str().expect("utf-8 path")
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        // Best effort: a leftover temp directory is harmless.
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

/// Starts podgate with `policy` as its `UPSTREAM_POLICY_FILE`.
async fn start_with(policy: &PolicyFile) -> Podgate {
    Podgate::start_with_env(&[("UPSTREAM_POLICY_FILE", policy.path())]).await
}

/// A snapshot with tenants `t1` and `t2` and one app per `(tenant, server address)`, named
/// `a0`, `a1`, ... and answering for `a0.test`, `a1.test`, ...
fn snapshot_of(version: u64, servers: &[(&str, &str)]) -> Value {
    let apps: Vec<Value> = servers
        .iter()
        .enumerate()
        .map(|(at, (tenant, server))| {
            let host = format!("a{at}.test");
            let mut value = app(
                &format!("a{at}"),
                &[&host],
                &[json!({
                    "id": "r1", "state": "serving", "weight": 100,
                    "services": [{ "name": "web", "type": "loadbalancer",
                                   "servers": [{ "url": format!("http://{server}") }] }],
                })],
            );
            value["tenant"] = json!(tenant);
            value
        })
        .collect();
    let mut pushed = snapshot(version, &apps);
    pushed["tenants"].as_array_mut().expect("tenants").push(json!({
        "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 },
    }));
    pushed
}

/// The `conflicts` entries of a `422`.
fn conflicts(response: &Response) -> Vec<Value> {
    assert_eq!(response.status, 422, "{response:?}");
    let body = response.json();
    assert_eq!(body["error"], "snapshot rejected", "{body}");
    body["conflicts"].as_array().expect("conflicts").clone()
}

/// Asserts `server` is refused with `upstream_forbidden` for tenant `t1`.
async fn assert_forbidden(podgate: &Podgate, version: u64, server: &str) {
    let response = podgate
        .push_snapshot(&snapshot_of(version, &[("t1", server)]))
        .await;
    let entries = conflicts(&response);
    assert_eq!(entries.len(), 1, "{server}: {entries:?}");
    assert_eq!(entries[0]["code"], "upstream_forbidden", "{server}");
}

#[tokio::test]
async fn upstream_outside_allowlist_rejected() {
    let policy = PolicyFile::write(r#"{"default": {"allow": ["10.0.0.0/8"]}}"#);
    let podgate = start_with(&policy).await;

    let rejected = podgate
        .push_snapshot(&snapshot_of(1, &[("t1", "192.168.1.1:80")]))
        .await;
    let entries = conflicts(&rejected);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let entry = &entries[0];
    assert_eq!(entry["code"], "upstream_forbidden");
    assert_eq!(entry["app"], "a0");
    assert_eq!(entry["declared_by"], "tests/a0");
    assert_eq!(entry["at"], "revision r1 service web");
    assert_eq!(entry["service"], "web");
    assert_eq!(entry["server"], "http://192.168.1.1:80");
    assert_eq!(entry["rule"], "not in the allow list of the default entry");
    let message = entry["message"].as_str().expect("message");
    assert!(
        message.contains("a0") && message.contains("web") && message.contains("192.168.1.1"),
        "{message}"
    );

    let accepted = podgate
        .push_snapshot(&snapshot_of(1, &[("t1", "10.1.2.3:80")]))
        .await;
    assert_eq!(accepted.status, 200, "{accepted:?}");
}

#[tokio::test]
async fn loopback_denied_by_default() {
    let policy = PolicyFile::write("{}");
    let podgate = start_with(&policy).await;
    for (version, server) in (1..).zip([
        "127.0.0.1:80",
        "127.8.9.10:80",
        "[::1]:80",
        "0.0.0.0:80",
        "[::]:80",
        "224.0.0.1:80",
        "[ff02::1]:80",
    ]) {
        assert_forbidden(&podgate, version, server).await;
    }
    let accepted = podgate
        .push_snapshot(&snapshot_of(1, &[("t1", "10.0.0.1:80")]))
        .await;
    assert_eq!(accepted.status, 200, "{accepted:?}");
}

#[tokio::test]
async fn link_local_metadata_denied() {
    let policy = PolicyFile::write("{}");
    let podgate = start_with(&policy).await;
    for (version, server) in (1..).zip([
        "169.254.169.254:80",
        "169.254.1.1:80",
        "[fe80::1]:80",
        "[fd00:ec2::254]:80",
    ]) {
        assert_forbidden(&podgate, version, server).await;
    }
}

#[tokio::test]
async fn v4_mapped_v6_denied() {
    let policy = PolicyFile::write("{}");
    let podgate = start_with(&policy).await;
    for (version, server) in (1..).zip([
        "[::ffff:127.0.0.1]:80",
        "[::ffff:169.254.169.254]:80",
        "[::127.0.0.1]:80",
    ]) {
        assert_forbidden(&podgate, version, server).await;
    }
}

#[tokio::test]
async fn deny_beats_allow() {
    let policy = PolicyFile::write(
        r#"{"deny": ["10.9.0.0/16"], "default": {"allow": ["10.0.0.0/8"]},
            "tenants": {"t1": {"allow": ["10.9.0.0/16", "10.1.0.0/16"]}}}"#,
    );
    let podgate = start_with(&policy).await;
    assert_forbidden(&podgate, 1, "10.9.0.1:80").await;
    let accepted = podgate
        .push_snapshot(&snapshot_of(2, &[("t1", "10.1.0.1:80")]))
        .await;
    assert_eq!(accepted.status, 200, "{accepted:?}");
}

#[tokio::test]
async fn tenant_without_entry_uses_default() {
    let policy = PolicyFile::write(
        r#"{"default": {"allow": ["10.0.0.0/8"]},
            "tenants": {"t1": {"allow": ["192.168.0.0/16"]}}}"#,
    );
    let podgate = start_with(&policy).await;

    let rejected = podgate
        .push_snapshot(&snapshot_of(
            1,
            &[
                ("t1", "10.0.0.1:80"),
                ("t2", "192.168.0.1:80"),
                ("t1", "192.168.0.1:80"),
                ("t2", "10.0.0.1:80"),
            ],
        ))
        .await;
    let entries = conflicts(&rejected);
    let refused: Vec<(&str, &str)> = entries
        .iter()
        .map(|entry| {
            (
                entry["app"].as_str().expect("app"),
                entry["rule"].as_str().expect("rule"),
            )
        })
        .collect();
    assert_eq!(
        refused,
        [
            ("a0", "not in the allow list of tenant t1"),
            ("a1", "not in the allow list of the default entry"),
        ],
        "{entries:?}"
    );

    let accepted = podgate
        .push_snapshot(&snapshot_of(
            2,
            &[("t1", "192.168.0.1:80"), ("t2", "10.0.0.1:80")],
        ))
        .await;
    assert_eq!(accepted.status, 200, "{accepted:?}");
}

#[tokio::test]
async fn snapshot_cannot_loosen_policy() {
    let policy = PolicyFile::write(r#"{"default": {"allow": ["10.0.0.0/8"]}}"#);
    let podgate = start_with(&policy).await;
    let loosen = json!({
        "default": { "allow": ["0.0.0.0/0", "::/0"] }, "deny": [],
        "allow": ["0.0.0.0/0"], "upstream_policy": { "deny": [] },
    });

    // Fields no type reads are ignored, so the address is still outside the operator's list.
    let mut pushed = snapshot_of(1, &[("t1", "192.168.1.1:80")]);
    for pointer in ["", "/tenants/0", "/apps/0", "/apps/0/revisions/0"] {
        let target = pushed.pointer_mut(pointer).expect("level exists");
        for (key, value) in loosen.as_object().expect("object") {
            target[key.as_str()] = value.clone();
        }
    }
    let entries = conflicts(&podgate.push_snapshot(&pushed).await);
    assert_eq!(entries[0]["code"], "upstream_forbidden", "{entries:?}");

    // The service and its servers refuse unknown settings outright.
    for (level, setting) in [("service", "allow"), ("server", "allow")] {
        let mut pushed = snapshot_of(2, &[("t1", "192.168.1.1:80")]);
        let service = &mut pushed["apps"][0]["revisions"][0]["services"][0];
        match level {
            "service" => service[setting] = json!(["0.0.0.0/0"]),
            _ => service["servers"][0][setting] = json!(["0.0.0.0/0"]),
        }
        let response = podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 422, "{level}: {response:?}");
    }

    // Loopback stays denied for the default entry's tenants however the snapshot is written.
    let mut pushed = snapshot_of(3, &[("t1", "127.0.0.1:80")]);
    pushed["upstream_policy"] = loosen;
    let entries = conflicts(&podgate.push_snapshot(&pushed).await);
    assert_eq!(entries[0]["code"], "upstream_forbidden", "{entries:?}");
}

/// A gateway that enforces `policy`, and a table compiled by a process that did not see the
/// address: the compiler's context allows everything, like a resolver handing back an address
/// the snapshot never named.
fn unseen_address(policy: UpstreamPolicy, address: &str) -> (Gateway, RoutingTable, Selected) {
    let snapshot: Snapshot =
        serde_json::from_value(snapshot_of(1, &[("t1", "10.0.0.1:80")])).expect("valid snapshot");
    let table = RoutingTable::compile(&snapshot).expect("compiles");
    let gateway = Gateway::new(
        TableHandle::new(),
        Inflight::new(EventFeed::new()),
        Duration::from_secs(5),
    )
    .with_upstream_policy(policy);
    let selected = Selected {
        app: 0,
        router: 0,
        revision: 0,
        upstream: address.parse().expect("address"),
        pinned: false,
    };
    (gateway, table, selected)
}

#[test]
fn connect_time_check_blocks() {
    let policy =
        UpstreamPolicy::parse(r#"{"default": {"allow": ["10.0.0.0/8"]}}"#).expect("policy parses");
    for refused in [
        "127.0.0.1:80",
        "169.254.169.254:80",
        "192.168.1.1:80",
        "[::ffff:127.0.0.1]:80",
    ] {
        let (gateway, table, selected) = unseen_address(policy.clone(), refused);
        let err = gateway
            .check_upstream(&table, &selected)
            .expect_err("the connect path refuses it");
        assert_eq!(err.etype(), &HTTPStatus(502), "{refused}: {err}");
    }
    let (gateway, table, selected) = unseen_address(policy, "10.9.8.7:80");
    gateway
        .check_upstream(&table, &selected)
        .expect("an address inside the allow list connects");
}

#[test]
fn upstream_refused_metric() {
    let policy = UpstreamPolicy::builtin();
    let (gateway, table, selected) = unseen_address(policy.clone(), "127.0.0.1:80");
    for _ in 0..3 {
        gateway
            .check_upstream(&table, &selected)
            .expect_err("loopback is refused");
    }
    let text = policy.render();
    assert!(
        text.contains("# TYPE podgate_upstream_refused_total counter\n"),
        "{text}"
    );
    assert!(
        text.contains("podgate_upstream_refused_total{tenant=\"t1\"} 3\n"),
        "{text}"
    );
}

#[tokio::test]
async fn upstream_refused_metric_is_exposed_on_the_admin_api() {
    let podgate = Podgate::start().await;
    let metrics = podgate.admin_get("/metrics").await;
    assert_eq!(metrics.status, 200, "{metrics:?}");
    assert!(
        metrics
            .body
            .contains("# TYPE podgate_upstream_refused_total counter\n"),
        "{}",
        metrics.body
    );
}

#[tokio::test]
async fn allowed_upstreams_still_proxy() {
    let upstream = Upstream::start("hello").await;
    let podgate = Podgate::start().await;
    let pushed = snapshot(
        1,
        &[app("a0", &["a0.test"], &[serving("r1", upstream.addr)])],
    );
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    let response = podgate.get("a0.test", "/").await;
    assert_eq!((response.status, response.body.as_str()), (200, "hello"));
}

/// Runs podgate with `UPSTREAM_POLICY_FILE=value` and returns its exit status and stderr. It
/// must exit by itself: a process that started serving is killed and the test fails.
fn start_with_policy_file(value: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("podgate-bad-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let mut child = Command::new(env!("CARGO_BIN_EXE_podgate"))
        .env("PROXY_ADDR", "127.0.0.1:0")
        .env("ADMIN_SOCKET", dir.join("admin.sock"))
        .env("UPSTREAM_POLICY_FILE", value)
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn podgate");
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll podgate") {
            break Some(status);
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if status.is_none() {
        drop(child.kill());
    }
    let output = child.wait_with_output().expect("collect output");
    drop(std::fs::remove_dir_all(&dir));
    (
        status.is_some_and(|status| !status.success()),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn policy_file_invalid_stops_startup() {
    for (contents, entry) in [
        (r#"{"deny": ["10.0.0.0/8", "nope"]}"#, "deny[1]"),
        (
            r#"{"default": {"allow": ["10.0.0.1/8"]}}"#,
            "default.allow[0]",
        ),
        (
            r#"{"tenants": {"acme": {"allow": ["::/129"]}}}"#,
            "tenants.acme.allow[0]",
        ),
        (r#"{"deny_extra": ["x/8"]}"#, "deny_extra[0]"),
        (r#"{"unknown": 1}"#, "unknown"),
        ("not json", "file"),
    ] {
        let file = PolicyFile::write(contents);
        let (failed, stderr) = start_with_policy_file(file.path());
        assert!(failed, "{contents}: podgate did not stop:\n{stderr}");
        assert!(
            stderr.contains("UPSTREAM_POLICY_FILE") && stderr.contains(entry),
            "{contents}: expected the variable and {entry:?} in:\n{stderr}"
        );
    }
    let (failed, stderr) = start_with_policy_file("/nonexistent/podgate-policy.json");
    assert!(failed, "a missing file must stop startup:\n{stderr}");
    assert!(
        stderr.contains("UPSTREAM_POLICY_FILE")
            && stderr.contains("/nonexistent/podgate-policy.json"),
        "{stderr}"
    );
}
