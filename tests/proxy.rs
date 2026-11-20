//! End to end: the real binary, snapshots pushed over its admin socket, requests through its
//! proxy listeners.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{Podgate, TestCert, Upstream, app, revision, serving, simple_snapshot, snapshot};
use serde_json::json;

#[tokio::test]
async fn routes_by_host() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("hello from a").await;
    let pushed = podgate
        .push_snapshot(&simple_snapshot(1, &[("a.test", upstream.addr)]))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    assert_eq!(pushed.json(), json!({"version": 1}));

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hello from a");
}

#[tokio::test]
async fn host_matching_ignores_case_and_port() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("a").await;
    podgate
        .push_snapshot(&simple_snapshot(1, &[("a.test", upstream.addr)]))
        .await;

    let response = podgate.get("A.Test:8080", "/").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "a");
}

#[tokio::test]
async fn unknown_host_is_json_404() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("a").await;
    podgate
        .push_snapshot(&simple_snapshot(1, &[("a.test", upstream.addr)]))
        .await;

    let response = podgate.get("nope.test", "/").await;
    assert_eq!(response.status, 404);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.body, r#"{"error":"not found"}"#);
}

#[tokio::test]
async fn nothing_routes_before_the_first_snapshot() {
    let podgate = Podgate::start().await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 404);
    assert_eq!(response.body, r#"{"error":"not found"}"#);
}

#[tokio::test]
async fn stale_snapshot_is_refused_and_the_table_unchanged() {
    let podgate = Podgate::start().await;
    let first = Upstream::start("first").await;
    let second = Upstream::start("second").await;
    let newer = podgate
        .push_snapshot(&simple_snapshot(2, &[("a.test", first.addr)]))
        .await;
    assert_eq!(newer.status, 200);

    for stale_version in [1, 2] {
        let stale = podgate
            .push_snapshot(&simple_snapshot(stale_version, &[("a.test", second.addr)]))
            .await;
        assert_eq!(stale.status, 409, "version {stale_version}: {stale:?}");
        assert!(stale.json()["error"].is_string());
    }
    assert_eq!(podgate.get("a.test", "/").await.body, "first");
}

#[tokio::test]
async fn a_newer_snapshot_replaces_the_routes() {
    let podgate = Podgate::start().await;
    let a = Upstream::start("a").await;
    let b = Upstream::start("b").await;
    podgate
        .push_snapshot(&simple_snapshot(1, &[("a.test", a.addr)]))
        .await;
    assert_eq!(podgate.get("a.test", "/").await.body, "a");

    podgate
        .push_snapshot(&simple_snapshot(2, &[("b.test", b.addr)]))
        .await;
    assert_eq!(podgate.get("b.test", "/").await.body, "b");
    assert_eq!(podgate.get("a.test", "/").await.status, 404);
}

#[tokio::test]
async fn malformed_json_is_400_and_a_rejected_snapshot_is_422() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("kept").await;
    podgate
        .push_snapshot(&simple_snapshot(1, &[("a.test", upstream.addr)]))
        .await;

    let malformed = podgate.push_snapshot_raw("{not json").await;
    assert_eq!(malformed.status, 400);
    assert!(malformed.json()["error"].is_string());

    let duplicate = snapshot(
        2,
        &[
            app("one", &["dup.test"], &[serving("r1", upstream.addr)]),
            app("two", &["dup.test"], &[serving("r1", upstream.addr)]),
        ],
    );
    let rejected = podgate.push_snapshot(&duplicate).await;
    assert_eq!(rejected.status, 422);
    assert_eq!(rejected.json()["error"], "snapshot rejected");
    assert!(
        rejected.json()["conflicts"][0]
            .as_str()
            .is_some_and(|c| c.contains("dup.test"))
    );

    assert_eq!(podgate.get("a.test", "/").await.body, "kept");
}

#[tokio::test]
async fn only_serving_revisions_take_new_requests() {
    let podgate = Podgate::start().await;
    let old = Upstream::start("old").await;
    let retiring = Upstream::start("retiring").await;
    let new = Upstream::start("new").await;
    let revisions = [
        revision("r1", old.addr, 100, "draining"),
        revision("r2", retiring.addr, 100, "retiring"),
        revision("r3", new.addr, 1, "serving"),
    ];
    let pushed = podgate
        .push_snapshot(&snapshot(1, &[app("a", &["a.test"], &revisions)]))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");

    for _ in 0..5 {
        assert_eq!(podgate.get("a.test", "/").await.body, "new");
    }
}

#[tokio::test]
async fn an_app_with_no_serving_revision_is_503() {
    let podgate = Podgate::start().await;
    let old = Upstream::start("old").await;
    let revisions = [revision("r1", old.addr, 100, "draining")];
    podgate
        .push_snapshot(&snapshot(1, &[app("a", &["a.test"], &revisions)]))
        .await;

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 503);
    assert_eq!(response.body, r#"{"error":"no upstream available"}"#);
}

#[tokio::test]
async fn admin_socket_serves_health_and_readiness() {
    let podgate = Podgate::start().await;

    let ready = podgate.admin_get("/readyz").await;
    assert_eq!(ready.status, 200);
    assert_eq!(ready.json(), json!({"status": "ready"}));
    let live = podgate.admin_get("/healthz").await;
    assert_eq!(live.status, 200);
    assert_eq!(live.json(), json!({"status": "ok"}));

    let unknown = podgate.admin_get("/nope").await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.json(), json!({"error": "not found"}));
}

#[tokio::test]
async fn admin_socket_is_private_to_its_owner() {
    let podgate = Podgate::start().await;
    let mode = std::fs::metadata(&podgate.admin_socket)
        .expect("socket exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn https_routes_by_host_with_the_certificate_chosen_by_sni() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("secure a").await;
    let cert = TestCert::new(&["a.test"]);
    let mut pushed = simple_snapshot(1, &[("a.test", upstream.addr)]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let response = podgate.https_get("a.test", "a.test", "/", &cert).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "secure a");

    assert!(
        podgate.https_handshake_fails("other.test", &cert).await,
        "a name without a certificate must not complete a handshake"
    );
}

#[tokio::test]
async fn an_unusable_certificate_rejects_the_snapshot() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("a").await;
    let mut pushed = simple_snapshot(1, &[("a.test", upstream.addr)]);
    pushed["certificates"] =
        json!([{ "hosts": ["a.test"], "cert_pem": "nope", "key_pem": "nope" }]);

    let rejected = podgate.push_snapshot(&pushed).await;
    assert_eq!(rejected.status, 422, "{rejected:?}");
    assert_eq!(podgate.get("a.test", "/").await.status, 404);
}
