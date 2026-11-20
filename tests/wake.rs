//! End to end: scale to zero. Requests for an app with no upstream are held and one wake is
//! requested; a snapshot with an upstream releases them; a wake that never comes ends in `503`;
//! an app with no traffic is reported idle.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Podgate, Response, Upstream, app, snapshot};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio::time::sleep;

/// An app of tenant `t1` with the given `scale_to_zero` policy, one serving revision, and
/// `upstreams` (empty: the app is asleep).
fn sleepy(host: &str, upstreams: &[SocketAddr], idle_secs: u64, wake_timeout_secs: u64) -> Value {
    let revision = json!({
        "id": "r1",
        "upstreams": upstreams.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "weight": 100,
        "state": "serving",
    });
    let mut app = app("a", &[host], &[revision]);
    app["scale_to_zero"] =
        json!({ "idle_secs": idle_secs, "wake_timeout_secs": wake_timeout_secs });
    app
}

fn request(podgate: &Arc<Podgate>, host: &'static str) -> JoinHandle<Response> {
    let podgate = Arc::clone(podgate);
    tokio::spawn(async move { podgate.get(host, "/").await })
}

async fn events(podgate: &Podgate, after: u64, timeout_secs: u64) -> Value {
    let response = podgate
        .admin_get(&format!(
            "/v1/events?after={after}&timeout_secs={timeout_secs}"
        ))
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    response.json()["events"].clone()
}

fn wake_requested(seq: u64, app: &str) -> Value {
    json!({"seq": seq, "kind": "wake_requested", "app": app})
}

fn app_idle(seq: u64, app: &str) -> Value {
    json!({"seq": seq, "kind": "app_idle", "app": app})
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let pushed = podgate.push_snapshot(snapshot).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
}

#[tokio::test]
async fn wake_single_event() {
    let podgate = Arc::new(Podgate::start().await);
    push(&podgate, &snapshot(1, &[sleepy("a.test", &[], 3600, 20)])).await;

    let held: Vec<_> = (0..5).map(|_| request(&podgate, "a.test")).collect();
    sleep(Duration::from_millis(700)).await;
    assert_eq!(
        events(&podgate, 0, 4).await,
        json!([wake_requested(1, "a")]),
        "five held requests, one wake request"
    );
    assert!(
        held.iter().all(|request| !request.is_finished()),
        "the requests are held, not answered"
    );

    let upstream = Upstream::start("awake").await;
    push(
        &podgate,
        &snapshot(2, &[sleepy("a.test", &[upstream.addr], 3600, 20)]),
    )
    .await;
    for request in held {
        let response = request.await.expect("request task");
        assert_eq!((response.status, response.body.as_str()), (200, "awake"));
    }
    assert_eq!(
        events(&podgate, 1, 1).await,
        json!([]),
        "waking adds no event"
    );

    push(&podgate, &snapshot(3, &[sleepy("a.test", &[], 3600, 1)])).await;
    let second = request(&podgate, "a.test");
    assert_eq!(
        events(&podgate, 1, 4).await,
        json!([wake_requested(2, "a")]),
        "a later sleep is a new wake cycle"
    );
    assert_eq!(second.await.expect("request task").status, 503);
}

#[tokio::test]
async fn wake_releases_held() {
    let podgate = Arc::new(Podgate::start().await);
    push(&podgate, &snapshot(1, &[sleepy("a.test", &[], 3600, 20)])).await;

    let started = Instant::now();
    let held = request(&podgate, "a.test");
    sleep(Duration::from_millis(500)).await;
    assert!(!held.is_finished(), "held while the app sleeps");

    let upstream = Upstream::start("awake").await;
    push(
        &podgate,
        &snapshot(2, &[sleepy("a.test", &[upstream.addr], 3600, 20)]),
    )
    .await;
    let response = held.await.expect("request task");
    assert_eq!((response.status, response.body.as_str()), (200, "awake"));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "released by the snapshot, not by the timeout"
    );
}

#[tokio::test]
async fn wake_timeout_503() {
    let podgate = Podgate::start().await;
    push(&podgate, &snapshot(1, &[sleepy("a.test", &[], 3600, 1)])).await;

    let started = Instant::now();
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 503, "{response:?}");
    assert_eq!(response.header("retry-after"), Some("5"));
    assert_eq!(
        response.json(),
        json!({"error": "app did not wake in time"})
    );
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "waited for wake_timeout_secs: {:?}",
        started.elapsed()
    );

    let again = podgate.get("a.test", "/").await;
    assert_eq!(again.status, 503);
    assert_eq!(
        events(&podgate, 0, 0).await,
        json!([wake_requested(1, "a"), wake_requested(2, "a")]),
        "a timed-out cycle is over; the retry asks again"
    );
}

#[tokio::test]
async fn app_without_scale_to_zero_still_answers_503_at_once() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let mut plain = sleepy("a.test", &[upstream.addr], 1, 1);
    plain["revisions"][0]["weight"] = json!(0);
    plain
        .as_object_mut()
        .expect("object")
        .remove("scale_to_zero");
    push(&podgate, &snapshot(1, &[plain])).await;

    let started = Instant::now();
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 503, "{response:?}");
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(events(&podgate, 0, 0).await, json!([]));
}

#[tokio::test]
async fn app_idle_event() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    push(
        &podgate,
        &snapshot(1, &[sleepy("a.test", &[upstream.addr], 1, 5)]),
    )
    .await;

    let explained = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(
        explained.json()["middleware"],
        json!([
            "acme_http01",
            "route",
            "wake_hold",
            "inflight_admit",
            "tenant_admit",
            "failure_capture"
        ])
    );
    let served = podgate.get("a.test", "/").await;
    assert_eq!(served.status, 200, "{served:?}");
    let requested = Instant::now();
    assert_eq!(events(&podgate, 0, 4).await, json!([app_idle(1, "a")]));
    assert!(
        requested.elapsed() >= Duration::from_millis(900),
        "idle only after idle_secs of silence: {:?}",
        requested.elapsed()
    );
    assert_eq!(
        events(&podgate, 1, 2).await,
        json!([]),
        "reported once per idle period"
    );

    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_eq!(
        events(&podgate, 1, 4).await,
        json!([app_idle(2, "a")]),
        "a request starts a new idle period"
    );
}

#[tokio::test]
async fn wake_held_requests_count_against_max_inflight() {
    let podgate = Arc::new(Podgate::start().await);
    let mut sleeping = snapshot(1, &[sleepy("a.test", &[], 3600, 20)]);
    sleeping["tenants"][0]["budget"]["max_inflight"] = json!(2);
    push(&podgate, &sleeping).await;

    let held = [request(&podgate, "a.test"), request(&podgate, "a.test")];
    sleep(Duration::from_millis(500)).await;
    let refused = podgate.get("a.test", "/").await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(
        refused.json(),
        json!({"error": "tenant is over its in-flight limit"})
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metrics.contains("podgate_tenant_inflight{tenant=\"t1\"} 2"),
        "{metrics}"
    );

    let upstream = Upstream::start("awake").await;
    let mut awake = snapshot(2, &[sleepy("a.test", &[upstream.addr], 3600, 20)]);
    awake["tenants"][0]["budget"]["max_inflight"] = json!(2);
    push(&podgate, &awake).await;
    for request in held {
        let response = request.await.expect("request task");
        assert_eq!((response.status, response.body.as_str()), (200, "awake"));
    }
    // The held requests kept their slots through the release; nothing leaked.
    sleep(Duration::from_millis(200)).await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
}
