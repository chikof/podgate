//! End to end: snapshots whose declarations conflict on security are refused as a whole with a
//! `422` that names every conflict, and the previous snapshot keeps serving.

mod common;

use common::{Podgate, Upstream, app, serving, snapshot};
use serde_json::{Value, json};

/// An app of `tenant`, claiming `hosts`, requiring client certificates signed by `ca` if given.
fn app_of(id: &str, tenant: &str, hosts: &[&str], ca: Option<&str>, upstream: &Upstream) -> Value {
    let mut value = app(id, hosts, &[serving("r1", upstream.addr)]);
    value["tenant"] = json!(tenant);
    if let Some(ca) = ca {
        value["tls"]["client_ca_pem"] = json!(ca);
    }
    value
}

/// `snapshot(version, apps)` with a second tenant `t2` declared.
fn two_tenants(version: u64, apps: &[Value]) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["tenants"].as_array_mut().expect("tenants").push(json!({
        "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 },
    }));
    pushed
}

#[tokio::test]
async fn host_conflict() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let rejected = podgate
        .push_snapshot(&two_tenants(
            1,
            &[
                app_of("one", "t1", &["dup.test", "*.w.test"], None, &upstream),
                app_of("two", "t2", &["DUP.test", "*.w.test"], None, &upstream),
            ],
        ))
        .await;

    assert_eq!(rejected.status, 422, "{rejected:?}");
    let body = rejected.json();
    assert_eq!(body["error"], "snapshot rejected");
    let conflicts = body["conflicts"].as_array().expect("conflicts list");
    assert_eq!(conflicts.len(), 2, "{body}");
    assert_eq!(conflicts[0]["code"], "host_conflict");
    assert_eq!(conflicts[0]["host"], "dup.test");
    assert_eq!(conflicts[1]["code"], "host_conflict");
    assert_eq!(conflicts[1]["host"], "*.w.test");
}

#[tokio::test]
async fn tls_policy_conflict() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let rejected = podgate
        .push_snapshot(&snapshot(
            1,
            &[
                app_of("wild", "t1", &["*.a.test"], Some("CA"), &upstream),
                app_of("exact", "t1", &["x.a.test"], None, &upstream),
                app_of("same", "t1", &["y.a.test"], Some("CA"), &upstream),
            ],
        ))
        .await;

    assert_eq!(rejected.status, 422, "{rejected:?}");
    let conflicts = rejected.json()["conflicts"].clone();
    assert_eq!(conflicts.as_array().map(Vec::len), Some(1), "{conflicts}");
    assert_eq!(conflicts[0]["code"], "tls_policy_conflict");
    assert_eq!(conflicts[0]["host"], "x.a.test");
    assert_eq!(conflicts[0]["wildcard"], "*.a.test");
}

#[tokio::test]
async fn cross_tenant_wildcard() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let rejected = podgate
        .push_snapshot(&two_tenants(
            1,
            &[
                app_of("wild", "t1", &["*.a.test"], None, &upstream),
                app_of("intruder", "t2", &["x.a.test"], None, &upstream),
            ],
        ))
        .await;

    assert_eq!(rejected.status, 422, "{rejected:?}");
    let conflicts = rejected.json()["conflicts"].clone();
    assert_eq!(conflicts.as_array().map(Vec::len), Some(1), "{conflicts}");
    assert_eq!(conflicts[0]["code"], "cross_tenant_wildcard");
    assert_eq!(conflicts[0]["host"], "x.a.test");
    assert_eq!(conflicts[0]["wildcard"], "*.a.test");
    assert_eq!(conflicts[0]["tenants"], json!(["t2", "t1"]));
}

#[tokio::test]
async fn conflict_names_sources() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let rejected = podgate
        .push_snapshot(&snapshot(
            1,
            &[
                app_of("one", "t1", &["dup.test"], None, &upstream),
                app_of("two", "t1", &["dup.test"], None, &upstream),
            ],
        ))
        .await;

    assert_eq!(rejected.status, 422, "{rejected:?}");
    let conflict = &rejected.json()["conflicts"][0];
    assert_eq!(
        *conflict,
        json!({
            "code": "host_conflict",
            "message": "host dup.test is claimed by app one (tests/one) and app two (tests/two)",
            "host": "dup.test",
            "apps": ["one", "two"],
            "declared_by": ["tests/one", "tests/two"],
        })
    );
}

#[tokio::test]
async fn rejected_keeps_previous() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("kept").await;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[app_of("a", "t1", &["a.test"], None, &upstream)],
        ))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");

    let rejected = podgate
        .push_snapshot(&snapshot(
            2,
            &[
                app_of("a", "t1", &["a.test", "dup.test"], None, &upstream),
                app_of("b", "t1", &["dup.test"], None, &upstream),
            ],
        ))
        .await;
    assert_eq!(rejected.status, 422, "{rejected:?}");

    assert_eq!(podgate.get("a.test", "/").await.body, "kept");
    assert_eq!(podgate.get("dup.test", "/").await.status, 404);
    let retry = podgate
        .push_snapshot(&snapshot(
            2,
            &[app_of("a", "t1", &["a.test", "b.test"], None, &upstream)],
        ))
        .await;
    assert_eq!(
        retry.status, 200,
        "a rejected version is not consumed: {retry:?}"
    );
}
