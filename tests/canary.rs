//! A canary revision gains traffic only while it stays healthy, and the control plane hears about
//! a regression. Intervals are one second: the shortest the snapshot allows.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::time::Duration;

use common::{Podgate, Response, Upstream, app, revision, serving, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};

/// A backend whose status can be changed while it runs; the body stays the same.
struct Switch {
    addr: SocketAddr,
    status: Arc<AtomicU16>,
}

impl Switch {
    async fn start(body: &'static str, status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let addr = listener.local_addr().expect("backend addr");
        let status = Arc::new(AtomicU16::new(status));
        let shared = Arc::clone(&status);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(answer(stream, body, Arc::clone(&shared)));
            }
        });
        Self { addr, status }
    }

    fn set(&self, status: u16) {
        self.status.store(status, Ordering::Relaxed);
    }
}

/// Answers each request on `stream` (keep-alive) until the peer closes.
async fn answer(mut stream: TcpStream, body: &'static str, status: Arc<AtomicU16>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            seen.drain(..end + 4);
            let response = format!(
                "HTTP/1.1 {} Status\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                status.load(Ordering::Relaxed),
                body.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// Steady background traffic to `a.test`, counting which revision answered by body.
struct Load {
    stop: Arc<AtomicBool>,
    canary_hits: Arc<AtomicU64>,
    tasks: Vec<JoinHandle<()>>,
}

impl Load {
    fn start(podgate: &Arc<Podgate>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let canary_hits = Arc::new(AtomicU64::new(0));
        let tasks = (0..4)
            .map(|_| {
                let (podgate, stop, hits) = (
                    Arc::clone(podgate),
                    Arc::clone(&stop),
                    Arc::clone(&canary_hits),
                );
                tokio::spawn(async move {
                    while !stop.load(Ordering::Relaxed) {
                        if podgate.get("a.test", "/").await.body == "canary" {
                            hits.fetch_add(1, Ordering::Relaxed);
                        }
                        sleep(Duration::from_millis(5)).await;
                    }
                })
            })
            .collect();
        Self {
            stop,
            canary_hits,
            tasks,
        }
    }

    async fn stop(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        for task in self.tasks {
            task.await.expect("load worker");
        }
        self.canary_hits.load(Ordering::Relaxed)
    }
}

/// App `a` with a `base` revision and a `canary` revision, under the given canary policy.
fn canary_app(base: SocketAddr, canary: SocketAddr, step: u32, max_permille: u32) -> Value {
    let mut app = app(
        "a",
        &["a.test"],
        &[
            serving("base", base),
            revision("canary", canary, 1, "serving"),
        ],
    );
    app["canary"] = json!({
        "revision": "canary",
        "step_percent": step,
        "interval_secs": 1,
        "max_error_permille": max_permille,
    });
    app
}

async fn explain(podgate: &Podgate) -> Value {
    let response = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(response.status, 200, "{response:?}");
    response.json()
}

fn share(explained: &Value) -> u64 {
    explained["canary"]["share_percent"]
        .as_u64()
        .expect("canary share")
}

fn weights(explained: &Value) -> Vec<u64> {
    explained["revisions"]
        .as_array()
        .expect("revisions")
        .iter()
        .map(|revision| revision["effective_weight"].as_u64().expect("weight"))
        .collect()
}

async fn events_of(podgate: &Podgate, kind: &str) -> Vec<Value> {
    let events = podgate.admin_get("/v1/events?after=0").await.json();
    events["events"]
        .as_array()
        .expect("events list")
        .iter()
        .filter(|event| event["kind"] == kind)
        .cloned()
        .collect()
}

/// Polls `explain` until `done` accepts it; panics after `secs`.
async fn wait_until(podgate: &Podgate, secs: u64, done: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let explained = explain(podgate).await;
        if done(&explained) {
            return explained;
        }
        assert!(Instant::now() < deadline, "timed out: {explained}");
        sleep(Duration::from_millis(100)).await;
    }
}

/// Sends `n` requests one after the other and counts those the canary answered.
async fn canary_answers(podgate: &Podgate, n: u32) -> u32 {
    let mut hits = 0;
    for _ in 0..n {
        hits += u32::from(podgate.get("a.test", "/").await.body == "canary");
    }
    hits
}

#[tokio::test]
async fn canary_ramps() {
    let podgate = Arc::new(Podgate::start().await);
    let base = Upstream::start("base").await;
    let canary = Upstream::start("canary").await;
    let pushed = snapshot(1, &[canary_app(base.addr, canary.addr, 20, 500)]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    // The canary starts at one step; the configured weights are untouched.
    let first = explain(&podgate).await;
    assert_eq!(share(&first), 20);
    assert_eq!(weights(&first), [8000, 2000]);
    assert_eq!(first["revisions"][0]["weight"], 100);
    assert_eq!(first["revisions"][1]["weight"], 1);

    // Healthy traffic: the share rises by exactly one step per judgment, up to promotion.
    let load = Load::start(&podgate);
    let mut seen = vec![20];
    let deadline = Instant::now() + Duration::from_secs(30);
    while seen.last() != Some(&100) {
        assert!(Instant::now() < deadline, "no promotion, saw {seen:?}");
        let now = share(&explain(&podgate).await);
        if seen.last() != Some(&now) {
            seen.push(now);
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(seen, [20, 40, 60, 80, 100]);
    let during = load.stop().await;
    assert!(during > 0, "the canary served traffic while ramping");

    // Promoted: the base revision gets nothing, and routing follows.
    let promoted = explain(&podgate).await;
    assert_eq!(weights(&promoted), [0, 10_000]);
    assert_eq!(canary_answers(&podgate, 20).await, 20);
    assert!(events_of(&podgate, "canary_regressed").await.is_empty());

    // The observed split follows the share: 30% of 400 sessions, not just what explain says.
    let mut slow = canary_app(base.addr, canary.addr, 30, 500);
    slow["canary"]["interval_secs"] = json!(3600);
    assert_eq!(
        podgate.push_snapshot(&snapshot(2, &[slow])).await.status,
        200
    );
    assert_eq!(weights(&explain(&podgate).await), [7000, 3000]);
    let on_canary = canary_answers(&podgate, 400).await;
    assert!(
        (110..=130).contains(&on_canary),
        "30% of 400 requests is 120, the canary got {on_canary}"
    );
}

#[tokio::test]
async fn canary_regresses() {
    let podgate = Arc::new(Podgate::start().await);
    let base = Upstream::start("base").await;
    let canary = Switch::start("canary", 500).await;
    // The first snapshot gives auto-revert something to go back to.
    let before = snapshot(1, &[app("a", &["a.test"], &[serving("base", base.addr)])]);
    assert_eq!(podgate.push_snapshot(&before).await.status, 200);
    let pushed = snapshot(2, &[canary_app(base.addr, canary.addr, 50, 100)]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let load = Load::start(&podgate);
    let regressed = wait_until(&podgate, 20, |explained| {
        explained["canary"]["regressed"] == true
    })
    .await;
    assert_eq!(share(&regressed), 0);
    assert_eq!(weights(&regressed), [10_000, 0]);

    // It stays out, and the event is not repeated.
    sleep(Duration::from_secs(3)).await;
    load.stop().await;
    let events = events_of(&podgate, "canary_regressed").await;
    assert_eq!(events.len(), 1, "exactly one event: {events:?}");
    assert_eq!(events[0]["app"], "a");
    assert_eq!(events[0]["revision"], "canary");
    assert_eq!(events[0]["error_permille"], 1000);
    for _ in 0..30 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!((response.status, response.body.as_str()), (200, "base"));
    }

    // The canary's own 5xx never counted toward auto-revert of the push that introduced it.
    assert!(events_of(&podgate, "config_reverted").await.is_empty());
    assert_eq!(explain(&podgate).await["version"], 2);
}

#[tokio::test]
async fn canary_explain() {
    let podgate = Podgate::start().await;
    let base = Upstream::start("base").await;
    let canary = Upstream::start("canary").await;
    let old = revision("old", base.addr, 50, "draining");
    let mut with_canary = canary_app(base.addr, canary.addr, 25, 20);
    with_canary["canary"]["interval_secs"] = json!(3600);
    with_canary["revisions"]
        .as_array_mut()
        .expect("revisions")
        .push(old);
    let plain = app("b", &["b.test"], &[serving("r1", base.addr)]);
    let pushed = snapshot(1, &[with_canary, plain]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let explained = explain(&podgate).await;
    assert_eq!(
        explained["canary"],
        json!({
            "revision": "canary", "share_percent": 25, "regressed": false,
            "step_percent": 25, "interval_secs": 3600, "max_error_permille": 20,
        })
    );
    let revisions = explained["revisions"].as_array().expect("revisions");
    let shown: Vec<(&str, u64, u64)> = revisions
        .iter()
        .map(|revision| {
            (
                revision["id"].as_str().expect("id"),
                revision["weight"].as_u64().expect("weight"),
                revision["effective_weight"].as_u64().expect("effective"),
            )
        })
        .collect();
    assert_eq!(
        shown,
        [("base", 100, 7500), ("canary", 1, 2500), ("old", 50, 0)]
    );

    // An app without a canary shows none, and keeps its configured weights.
    let other = podgate.admin_get("/v1/explain?url=http://b.test/").await;
    assert_eq!(other.status, 200);
    assert!(other.json().get("canary").is_none());
    assert_eq!(weights(&other.json()), [100]);
}

type Edit = fn(&mut Value);

/// The `code`s of a `422` body's conflict list.
fn codes(response: &Response) -> Vec<String> {
    assert_eq!(response.status, 422, "{response:?}");
    response.json()["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|conflict| conflict["code"].as_str().expect("code").to_owned())
        .collect()
}

#[tokio::test]
async fn canary_compile_rejects_unsound_policies() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("x").await;
    let push = |edit: Edit| {
        let mut app = canary_app(up.addr, up.addr, 10, 50);
        edit(&mut app);
        snapshot(1, &[app])
    };

    let cases: [(&str, Edit, &str); 6] = [
        (
            "unknown revision",
            |app| app["canary"]["revision"] = json!("nope"),
            "canary_revision_missing",
        ),
        (
            "not serving",
            |app| app["revisions"][1]["state"] = json!("retiring"),
            "canary_revision_not_serving",
        ),
        (
            "step zero",
            |app| app["canary"]["step_percent"] = json!(0),
            "canary_step_invalid",
        ),
        (
            "step over 100",
            |app| app["canary"]["step_percent"] = json!(101),
            "canary_step_invalid",
        ),
        (
            "interval zero",
            |app| app["canary"]["interval_secs"] = json!(0),
            "canary_interval_invalid",
        ),
        (
            "no baseline",
            |app| app["revisions"][0]["state"] = json!("draining"),
            "canary_no_baseline",
        ),
    ];
    for (name, edit, code) in cases {
        let response = podgate.push_snapshot(&push(edit)).await;
        assert_eq!(codes(&response), [code], "{name}");
    }
    // Nothing was applied: no table is live.
    assert_eq!(podgate.get("a.test", "/").await.status, 404);
}

#[tokio::test]
async fn canary_reset_on_snapshot() {
    let podgate = Arc::new(Podgate::start().await);
    let base = Upstream::start("base").await;
    let canary = Switch::start("canary", 500).await;
    let pushed = snapshot(1, &[canary_app(base.addr, canary.addr, 25, 100)]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let load = Load::start(&podgate);
    wait_until(&podgate, 20, |explained| {
        explained["canary"]["regressed"] == true
    })
    .await;
    load.stop().await;
    assert_eq!(events_of(&podgate, "canary_regressed").await.len(), 1);

    // The same policy in a newer snapshot starts over from one step, with a healthy canary.
    canary.set(200);
    let again = snapshot(2, &[canary_app(base.addr, canary.addr, 25, 100)]);
    assert_eq!(podgate.push_snapshot(&again).await.status, 200);
    let reset = explain(&podgate).await;
    assert_eq!(reset["canary"]["regressed"], false);
    assert_eq!(share(&reset), 25);
    assert_eq!(weights(&reset), [7500, 2500]);

    // It serves and ramps again, and does not regress on what it did before.
    let load = Load::start(&podgate);
    wait_until(&podgate, 20, |explained| share(explained) >= 50).await;
    let served = load.stop().await;
    assert!(served > 0, "the reset canary got traffic");
    assert_eq!(events_of(&podgate, "canary_regressed").await.len(), 1);
}

#[tokio::test]
async fn canary_regressed_unpins_sessions() {
    let podgate = Arc::new(Podgate::start().await);
    let base = Upstream::start("base").await;
    let canary = Switch::start("canary", 200).await;
    let mut pushed = snapshot(1, &[canary_app(base.addr, canary.addr, 10, 100)]);
    pushed["skew_secret"] = json!("a-secret-of-at-least-16-bytes");
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    // A session that first landed on the canary stays there while it is healthy.
    let mut cookie = None;
    for _ in 0..500 {
        let response = podgate.get("a.test", "/").await;
        if response.body == "canary" {
            let header = response.header("set-cookie").expect("session cookie");
            cookie = Some(header.split(';').next().expect("cookie pair").to_owned());
            break;
        }
    }
    let cookie = cookie.expect("a request reached the canary");
    for _ in 0..5 {
        let response = podgate
            .get_with_headers("a.test", "/", &[("Cookie", &cookie)])
            .await;
        assert_eq!(response.body, "canary");
        assert!(response.header("set-cookie").is_none(), "already pinned");
    }

    // The canary starts failing and is pulled back.
    canary.set(500);
    let load = Load::start(&podgate);
    wait_until(&podgate, 20, |explained| {
        explained["canary"]["regressed"] == true
    })
    .await;
    load.stop().await;
    canary.set(200);

    // Its sessions no longer stay: they get the weighted pick and a fresh cookie.
    for _ in 0..5 {
        let response = podgate
            .get_with_headers("a.test", "/", &[("Cookie", &cookie)])
            .await;
        assert_eq!((response.status, response.body.as_str()), (200, "base"));
        let fresh = response.header("set-cookie").expect("fresh cookie");
        assert!(
            !fresh.starts_with(&cookie),
            "the old pin must not be renewed: {fresh}"
        );
    }
}
