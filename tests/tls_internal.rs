//! `tls.mode = "internal"`: the daemon serves the certificates the snapshot carries
//! and orders nothing. The certificates come from the provider's internal CA
//! (`docs/ref/internal-ca.md`); here a self-signed one stands in.

mod common;

use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use serde_json::{Value, json};

fn internal_app(upstream: &Upstream) -> Value {
    let mut internal = app("a", &["a.internal"], &[serving("r1", upstream.addr)]);
    internal["tls"] = json!({ "mode": "internal" });
    internal
}

#[tokio::test]
async fn internal_mode_serves_the_snapshots_certificate() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("internal body").await;
    let cert = TestCert::new(&["a.internal"]);
    let mut pushed = snapshot(1, &[internal_app(&upstream)]);
    pushed["certificates"] = json!([cert.entry(&["a.internal"])]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");

    let served = podgate
        .https_get("a.internal", "a.internal", "/", &cert)
        .await;
    assert_eq!(served.status, 200, "{served:?}");
    assert_eq!(served.body, "internal body");
    let events = podgate.admin_get("/v1/events?after=0").await.json();
    let ordered = events["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| {
            event["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("acme_") || kind.starts_with("certificate_"))
        })
        .count();
    assert_eq!(ordered, 0, "an internal app orders nothing: {events}");
}

#[tokio::test]
async fn internal_mode_without_a_certificate_fails_the_handshake() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("never").await;
    let other = TestCert::new(&["other.internal"]);
    let mut pushed = snapshot(1, &[internal_app(&upstream)]);
    pushed["certificates"] = json!([other.entry(&["other.internal"])]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert!(
        podgate.https_handshake_fails("a.internal", &other).await,
        "no certificate for the host, and nothing is ordered to make one"
    );
}

#[tokio::test]
async fn internal_mode_refuses_an_acme_challenge() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("never").await;
    let mut internal = internal_app(&upstream);
    internal["tls"] = json!({ "mode": "internal", "challenge": "dns-01" });
    let response = podgate.push_snapshot(&snapshot(1, &[internal])).await;
    assert_eq!(response.status, 422, "{response:?}");
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "dns01_needs_acme_mode"
    );
}
