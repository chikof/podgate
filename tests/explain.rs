//! `GET /v1/explain` answers from the live routing table.

mod common;

use common::{Podgate, Upstream, app, revision, serving, simple_snapshot, snapshot};
use serde_json::json;

#[tokio::test]
async fn explain_known_host() {
    let podgate = Podgate::start().await;
    let (old, new) = (Upstream::start("old").await, Upstream::start("new").await);
    let a = app(
        "a",
        &["a.test"],
        &[
            revision("r1", old.addr, 30, "draining"),
            revision("r2", new.addr, 70, "serving"),
        ],
    );
    assert_eq!(podgate.push_snapshot(&snapshot(4, &[a])).await.status, 200);

    let plain = podgate
        .admin_get("/v1/explain?url=http://A.test:8080/x%3Fy=1&method=POST")
        .await;
    assert_eq!(plain.status, 200, "{plain:?}");
    assert_eq!(
        plain.json(),
        json!({
            "version": 4, "host": "a.test", "method": "POST",
            "app": "a", "tenant": "t1", "declared_by": "tests/a",
            "matched": {"pattern": "a.test", "kind": "exact"},
            "revisions": [
                {"id": "r1", "state": "draining", "weight": 30, "effective_weight": 0, "upstreams": [old.addr.to_string()]},
                {"id": "r2", "state": "serving", "weight": 70, "effective_weight": 70, "upstreams": [new.addr.to_string()]},
            ],
            "middleware": ["acme_http01", "route", "inflight_admit", "tenant_admit", "failure_capture"],
        })
    );

    let tls = podgate.admin_get("/v1/explain?url=https://a.test/").await;
    assert_eq!(
        tls.json()["middleware"],
        json!([
            "sni_check",
            "route",
            "inflight_admit",
            "tenant_admit",
            "failure_capture"
        ])
    );
    assert_eq!(tls.json()["method"], "GET");

    assert_eq!(podgate.get("a.test", "/").await.body, "new");
}

#[tokio::test]
async fn explain_unknown_host() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("w").await;
    let pushed = snapshot(
        1,
        &[app("w", &["*.w.test"], &[serving("r1", upstream.addr)])],
    );
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let wildcard_hit = podgate.admin_get("/v1/explain?url=http://x.w.test/").await;
    assert_eq!(wildcard_hit.status, 200, "{wildcard_hit:?}");
    assert_eq!(
        wildcard_hit.json()["matched"],
        json!({"pattern": "*.w.test", "kind": "wildcard"})
    );

    for (url, nearest) in [
        ("http://w.test/", json!("*.w.test")),
        ("http://p.q.w.test/", json!("*.w.test")),
        ("http://nope.test/", json!(null)),
    ] {
        let miss = podgate.admin_get(&format!("/v1/explain?url={url}")).await;
        assert_eq!(miss.status, 404, "{url}: {miss:?}");
        assert_eq!(
            miss.json(),
            json!({"error": "not found", "nearest_wildcard": nearest}),
            "{url}"
        );
    }

    for bad in [
        "/v1/explain",
        "/v1/explain?url=a.test",
        "/v1/explain?url=ftp://a.test/",
        "/v1/explain?url=http://a.test/&method=not%20a%20method",
    ] {
        let response = podgate.admin_get(bad).await;
        assert_eq!(response.status, 400, "{bad}: {response:?}");
        assert!(response.json()["error"].is_string(), "{bad}");
    }
}

#[tokio::test]
async fn explain_follows_swap() {
    let podgate = Podgate::start().await;
    let (first, second) = (
        Upstream::start("first").await,
        Upstream::start("second").await,
    );
    assert_eq!(
        podgate
            .push_snapshot(&simple_snapshot(1, &[("a.test", first.addr)]))
            .await
            .status,
        200
    );
    let before = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(before.json()["version"], 1);
    assert_eq!(before.json()["revisions"][0]["effective_weight"], 100);
    assert_eq!(
        podgate
            .admin_get("/v1/explain?url=http://b.test/")
            .await
            .status,
        404
    );

    let a = app(
        "a",
        &["a.test"],
        &[revision("r1", first.addr, 100, "draining")],
    );
    let b = app("b", &["b.test"], &[serving("r1", second.addr)]);
    assert_eq!(
        podgate.push_snapshot(&snapshot(2, &[a, b])).await.status,
        200
    );

    let after = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(after.json()["version"], 2);
    assert_eq!(after.json()["revisions"][0]["state"], "draining");
    assert_eq!(after.json()["revisions"][0]["effective_weight"], 0);
    assert_eq!(podgate.get("a.test", "/").await.status, 503);

    let now_known = podgate.admin_get("/v1/explain?url=http://b.test/").await;
    assert_eq!(now_known.status, 200);
    assert_eq!(now_known.json()["app"], "b");
    assert_eq!(podgate.get("b.test", "/").await.body, "second");
}
