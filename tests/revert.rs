//! End to end: a snapshot that makes the apps it changed fail is reverted, and says so.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{Podgate, Upstream, app, serving, snapshot};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep};

/// An address nothing listens on: connecting is refused, so the proxy answers `502`.
fn dead_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind a free port")
        .local_addr()
        .expect("local addr")
}

async fn reverted_events(podgate: &Podgate) -> Vec<Value> {
    let events = podgate.admin_get("/v1/events?after=0").await.json();
    events["events"]
        .as_array()
        .expect("events list")
        .iter()
        .filter(|event| event["kind"] == "config_reverted")
        .cloned()
        .collect()
}

async fn wait_for_revert(podgate: &Podgate) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let found = reverted_events(podgate).await;
        if !found.is_empty() || Instant::now() > deadline {
            return found;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn with_window(mut snapshot: Value, secs: u64) -> Value {
    snapshot["revert_window_secs"] = json!(secs);
    snapshot
}

#[tokio::test]
async fn auto_revert_on_5xx() {
    let podgate = Podgate::start().await;
    let good = Upstream::start("good").await;
    let healthy = snapshot(1, &[app("a", &["a.test"], &[serving("r1", good.addr)])]);
    assert_eq!(podgate.push_snapshot(&healthy).await.status, 200);

    let broken = with_window(
        snapshot(2, &[app("a", &["a.test"], &[serving("r2", dead_addr())])]),
        20,
    );
    assert_eq!(podgate.push_snapshot(&broken).await.status, 200);
    for _ in 0..30 {
        assert_eq!(podgate.get("a.test", "/").await.status, 502);
    }

    let reverted = wait_for_revert(&podgate).await;
    assert_eq!(
        reverted.len(),
        1,
        "exactly one config_reverted event: {reverted:?}"
    );
    assert_eq!(reverted[0]["from_version"], 2);
    assert_eq!(reverted[0]["to_version"], 1);

    // The previous snapshot serves again.
    let served = podgate.get("a.test", "/").await;
    assert_eq!((served.status, served.body.as_str()), (200, "good"));

    // The live version stays at the reverted one: pushing it again is refused, a newer one works.
    assert_eq!(podgate.push_snapshot(&broken).await.status, 409);
    let fixed = snapshot(3, &[app("a", &["a.test"], &[serving("r3", good.addr)])]);
    assert_eq!(podgate.push_snapshot(&fixed).await.status, 200);
}

#[tokio::test]
async fn auto_revert_ignores_unchanged_apps() {
    let podgate = Podgate::start().await;
    let good = Upstream::start("good").await;
    let broken_b = app("b", &["b.test"], &[serving("r1", dead_addr())]);
    let a = app("a", &["a.test"], &[serving("r1", good.addr)]);
    let before = snapshot(1, &[a.clone(), broken_b.clone()]);
    assert_eq!(podgate.push_snapshot(&before).await.status, 200);

    // The new snapshot adds app c and leaves a and b exactly as they were; b is failing anyway.
    let c = app("c", &["c.test"], &[serving("r1", good.addr)]);
    let after = with_window(snapshot(2, &[a, broken_b, c]), 3);
    assert_eq!(podgate.push_snapshot(&after).await.status, 200);
    for _ in 0..30 {
        assert_eq!(podgate.get("b.test", "/").await.status, 502);
        assert_eq!(podgate.get("c.test", "/").await.status, 200);
    }

    sleep(Duration::from_secs(5)).await;
    assert!(reverted_events(&podgate).await.is_empty());
    assert_eq!(podgate.get("c.test", "/").await.body, "good");
}

/// An app `id` with `scale_to_zero` and one serving revision on `upstreams` (empty: asleep).
fn sleepy(id: &str, host: &str, upstreams: &[SocketAddr], wake_timeout_secs: u64) -> Value {
    let revision = json!({
        "id": "r1",
        "upstreams": upstreams.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "weight": 100,
        "state": "serving",
    });
    let mut app = app(id, &[host], &[revision]);
    app["scale_to_zero"] = json!({ "idle_secs": 3600, "wake_timeout_secs": wake_timeout_secs });
    app
}

#[tokio::test]
async fn auto_revert_ignores_tenant_overload() {
    let podgate = Podgate::start().await;
    let good = Upstream::start("good").await;
    let before = snapshot(1, &[app("a", &["a.test"], &[serving("r1", good.addr)])]);
    assert_eq!(podgate.push_snapshot(&before).await.status, 200);

    // The change gives the tenant no in-flight slots at all: every request is a capacity 503.
    let mut after = with_window(
        snapshot(2, &[app("a", &["a.test"], &[serving("r2", good.addr)])]),
        3,
    );
    after["tenants"][0]["budget"]["max_inflight"] = json!(0);
    assert_eq!(podgate.push_snapshot(&after).await.status, 200);
    for _ in 0..30 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!(response.status, 503);
        assert_eq!(response.header("retry-after"), Some("1"));
    }

    sleep(Duration::from_secs(5)).await;
    assert!(reverted_events(&podgate).await.is_empty());
}

#[tokio::test]
async fn auto_revert_ignores_wake_timeouts() {
    let podgate = Arc::new(Podgate::start().await);
    let good = Upstream::start("good").await;
    let before = snapshot(1, &[sleepy("s", "s.test", &[good.addr], 1)]);
    assert_eq!(podgate.push_snapshot(&before).await.status, 200);

    // The change puts the app to sleep and nothing wakes it: each request times out after 1 s.
    let after = with_window(snapshot(2, &[sleepy("s", "s.test", &[], 1)]), 4);
    assert_eq!(podgate.push_snapshot(&after).await.status, 200);
    let requests: Vec<_> = (0..25)
        .map(|_| {
            let podgate = Arc::clone(&podgate);
            tokio::spawn(async move { podgate.get("s.test", "/").await })
        })
        .collect();
    for request in requests {
        let response = request.await.expect("request task");
        assert_eq!(response.status, 503);
        assert_eq!(response.header("retry-after"), Some("5"));
    }

    sleep(Duration::from_secs(5)).await;
    assert!(reverted_events(&podgate).await.is_empty());
}

#[tokio::test]
async fn auto_revert_releases_held_request() {
    let podgate = Arc::new(Podgate::start().await);
    let good = Upstream::start("good").await;
    let before = snapshot(
        1,
        &[
            sleepy("s", "s.test", &[good.addr], 30),
            app("b", &["b.test"], &[serving("r1", good.addr)]),
        ],
    );
    assert_eq!(podgate.push_snapshot(&before).await.status, 200);

    // The change puts `s` to sleep and breaks `b`. A request for `s` is held waiting for a wake.
    let after = with_window(
        snapshot(
            2,
            &[
                sleepy("s", "s.test", &[], 30),
                app("b", &["b.test"], &[serving("r1", dead_addr())]),
            ],
        ),
        20,
    );
    assert_eq!(podgate.push_snapshot(&after).await.status, 200);
    let held = {
        let podgate = Arc::clone(&podgate);
        tokio::spawn(async move { podgate.get("s.test", "/").await })
    };
    sleep(Duration::from_millis(300)).await;
    assert!(!held.is_finished(), "the request waits for a wake");

    // 5xx from the sibling breach the threshold; the revert brings `s`'s upstream back.
    for _ in 0..30 {
        assert_eq!(podgate.get("b.test", "/").await.status, 502);
    }
    let released = tokio::time::timeout(Duration::from_secs(10), held)
        .await
        .expect("the revert releases the held request")
        .expect("request task");
    assert_eq!((released.status, released.body.as_str()), (200, "good"));
    assert_eq!(reverted_events(&podgate).await.len(), 1);
}
