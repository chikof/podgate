//! `GET /v1/catalog` through the real binary: every API the live table serves, with
//! its version and lifecycle, read from the table, bounded, paged by a key, and never showing
//! what an OpenAPI document holds. Also the plan's posture entry for reopening an API.

mod common;

use std::net::SocketAddr;

use common::{Podgate, Upstream, app, router, serving, snapshot};
use serde_json::{Value, json};

fn two_tenants(version: u64, apps: &[Value]) -> Value {
    json!({
        "version": version,
        "tenants": [
            { "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
            { "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
        ],
        "apps": apps,
    })
}

fn under(host: &str, name: &str, prefix: &str) -> Value {
    router(
        name,
        json!({"all": [{"host": host}, {"path_prefix": prefix}]}),
        "web",
    )
}

/// Tenant `t1`'s app `pets` with two versions of one API, the second described by an OpenAPI
/// document that holds a planted string.
fn pets(upstream: SocketAddr, first: &str) -> Value {
    let mut app = app("pets", &["a.test"], &[serving("r1", upstream)]);
    app["routers"] = json!([under("a.test", "v1", "/v1"), under("a.test", "v2", "/v2")]);
    app["middlewares"] = json!([{
        "name": "spec", "type": "openapi",
        "document": {
            "openapi": "3.1.0",
            "info": {"title": "Pets", "version": "1.0.0"},
            "paths": {
                "/planted/pets": {"get": {"description": "planted-secret-doc"}},
                "/planted/pets/{id}": {"get": {"description": "planted-secret-doc"}},
            },
        },
    }]);
    let mut old = json!({
        "id": "pets", "version": "1", "lifecycle": first, "routers": ["v1"],
    });
    if first == "deprecated" {
        old["sunset"] = json!("2027-03-01");
        old["successor"] = json!({"id": "pets", "version": "2"});
    }
    app["apis"] = json!([
        old,
        {
            "id": "pets", "version": "2", "lifecycle": "stable", "routers": ["v2"],
            "title": "Pets 2", "published": true, "openapi": "spec",
        },
    ]);
    app
}

/// Tenant `t2`'s app `shop`: a retired and a preview version, dated.
fn shop(upstream: SocketAddr) -> Value {
    let mut app = app("shop", &["b.test"], &[serving("r1", upstream)]);
    app["tenant"] = json!("t2");
    app["routers"] = json!([
        under("b.test", "old", "/old"),
        under("b.test", "new", "/new")
    ]);
    app["apis"] = json!([
        {"id": "shop", "version": "2026-01-01", "lifecycle": "retired", "routers": ["old"]},
        {"id": "shop", "version": "2026-05-01", "lifecycle": "preview", "routers": ["new"],
         "description": "The shop API."},
    ]);
    app
}

async fn catalog(podgate: &Podgate, query: &str) -> Value {
    let answer = podgate.admin_get(&format!("/v1/catalog{query}")).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(answer.header("content-type"), Some("application/json"));
    answer.json()
}

fn keys(document: &Value) -> Vec<String> {
    document["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            format!(
                "{}/{}/{}",
                item["tenant"].as_str().expect("tenant"),
                item["id"].as_str().expect("id"),
                item["version"].as_str().expect("version")
            )
        })
        .collect()
}

const ALL: [&str; 4] = [
    "t1/pets/1",
    "t1/pets/2",
    "t2/shop/2026-01-01",
    "t2/shop/2026-05-01",
];

async fn serve() -> (Podgate, Upstream) {
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    let pushed = podgate
        .push_snapshot(&two_tenants(
            1,
            &[pets(upstream.addr, "deprecated"), shop(upstream.addr)],
        ))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    (podgate, upstream)
}

#[tokio::test]
async fn catalog_lists_all_entries() {
    let (podgate, _upstream) = serve().await;
    let document = catalog(&podgate, "").await;
    assert_eq!(document["version"], 1);
    assert_eq!(document["total"], 4);
    assert_eq!(keys(&document), ALL);
    assert!(document.get("truncated").is_none(), "{document}");
    let items = document["items"].as_array().expect("items");
    assert_eq!(
        items[0],
        json!({
            "tenant": "t1", "app": "pets", "declared_by": "tests/pets",
            "id": "pets", "version": "1", "lifecycle": "deprecated",
            "sunset": "2027-03-01", "successor": {"id": "pets", "version": "2"},
            "routers": ["v1"], "hosts": ["a.test"], "published": false,
        })
    );
    assert_eq!(
        items[1],
        json!({
            "tenant": "t1", "app": "pets", "declared_by": "tests/pets",
            "id": "pets", "version": "2", "title": "Pets 2", "lifecycle": "stable",
            "routers": ["v2"], "hosts": ["a.test"], "published": true,
            "openapi": {
                "name": "spec", "title": "Pets", "version": "1.0.0",
                "dialect": "3.1", "operations": 2,
            },
        })
    );
    assert_eq!(items[2]["lifecycle"], "retired");
    assert_eq!(items[3]["description"], "The shop API.");
    assert_eq!(items[3]["hosts"], json!(["b.test"]));
}

#[tokio::test]
async fn catalog_filters_and_pages() {
    let (podgate, _upstream) = serve().await;
    assert_eq!(keys(&catalog(&podgate, "?tenant=t2").await), &ALL[2..]);
    assert_eq!(keys(&catalog(&podgate, "?app=pets").await), &ALL[..2]);
    let retired = catalog(&podgate, "?lifecycle=retired").await;
    assert_eq!(retired["total"], 1);
    assert_eq!(keys(&retired), [ALL[2]]);
    assert_eq!(catalog(&podgate, "?tenant=nobody").await["total"], 0);
    for bad in [
        "?lifecycle=old",
        "?limit=0",
        "?after=t1/pets",
        "?after=",
        "?limit=many",
    ] {
        let answer = podgate.admin_get(&format!("/v1/catalog{bad}")).await;
        assert_eq!(answer.status, 400, "{bad}: {answer:?}");
        assert!(answer.json()["error"].is_string(), "{bad}: {answer:?}");
    }

    let mut seen = Vec::new();
    let mut after = String::new();
    loop {
        let page = catalog(&podgate, &format!("?limit=3{after}")).await;
        assert_eq!(page["total"], 4, "total ignores the cursor");
        seen.extend(keys(&page));
        match page["next"].as_str() {
            Some(next) => {
                assert_eq!(page["truncated"], true);
                after = format!("&after={next}");
            }
            None => break,
        }
    }
    assert_eq!(seen, ALL, "every entry once, in key order");
}

#[tokio::test]
async fn catalog_follows_live_table() {
    let (podgate, upstream) = serve().await;
    let before = catalog(&podgate, "").await;
    assert_eq!(before["items"][0]["lifecycle"], "deprecated");

    let pushed = podgate
        .push_snapshot(&two_tenants(2, &[pets(upstream.addr, "retired")]))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    let after = catalog(&podgate, "").await;
    assert_eq!(after["version"], 2);
    assert_eq!(after["total"], 2);
    assert_eq!(keys(&after), &ALL[..2]);
    assert_eq!(after["items"][0]["lifecycle"], "retired");
    assert!(after["items"][0].get("successor").is_none(), "{after}");
}

#[tokio::test]
async fn catalog_unchanged_after_rejection() {
    let (podgate, upstream) = serve().await;
    let before = catalog(&podgate, "").await;

    let mut twice = pets(upstream.addr, "deprecated");
    twice["apis"][1]["version"] = json!("1");
    let rejected = podgate
        .push_snapshot(&two_tenants(2, &[twice, shop(upstream.addr)]))
        .await;
    assert_eq!(rejected.status, 422, "{rejected:?}");
    let conflicts = rejected.json()["conflicts"].clone();
    assert_eq!(conflicts[0]["code"], "duplicate_api_version", "{conflicts}");
    assert_eq!(conflicts[0]["app"], "pets");
    assert_eq!(conflicts[0]["declared_by"], "tests/pets");

    assert_eq!(catalog(&podgate, "").await, before);
}

#[tokio::test]
async fn catalog_reopening_is_a_posture_change() {
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    let live = two_tenants(1, &[pets(upstream.addr, "retired")]);
    assert_eq!(podgate.push_snapshot(&live).await.status, 200);

    let postures = |plan: &Value| -> Vec<(String, String, String)> {
        plan["posture_changes"]
            .as_array()
            .expect("posture_changes")
            .iter()
            .map(|change| {
                let text = |key: &str| change[key].as_str().expect(key).to_owned();
                (text("host"), text("app"), text("kind"))
            })
            .collect()
    };
    let reopened = vec![(
        "a.test".to_owned(),
        "pets".to_owned(),
        "api_reopened".to_owned(),
    )];

    let stable = two_tenants(2, &[pets(upstream.addr, "stable")]);
    let plan = podgate.admin_post("/v1/snapshot/plan", &stable).await;
    assert_eq!(plan.status, 200, "{plan:?}");
    assert_eq!(postures(&plan.json()), reopened, "retired to stable");

    let mut gone = pets(upstream.addr, "stable");
    gone["apis"] = json!([]);
    let plan = podgate
        .admin_post("/v1/snapshot/plan", &two_tenants(2, &[gone]))
        .await;
    assert_eq!(postures(&plan.json()), reopened, "the entry is removed");

    let dated = pets(upstream.addr, "deprecated");
    let plan = podgate
        .admin_post("/v1/snapshot/plan", &two_tenants(2, &[dated]))
        .await;
    assert_eq!(postures(&plan.json()), reopened, "retired to deprecated");

    let still = two_tenants(2, &[pets(upstream.addr, "retired")]);
    let plan = podgate.admin_post("/v1/snapshot/plan", &still).await;
    assert!(postures(&plan.json()).is_empty(), "retired stays retired");

    // Closing an API is not a relaxation.
    assert_eq!(
        podgate
            .push_snapshot(&two_tenants(3, &[pets(upstream.addr, "stable")]))
            .await
            .status,
        200
    );
    let closed = two_tenants(4, &[pets(upstream.addr, "retired")]);
    let plan = podgate.admin_post("/v1/snapshot/plan", &closed).await;
    assert!(postures(&plan.json()).is_empty(), "stable to retired");
}

#[tokio::test]
async fn catalog_shows_no_document() {
    let (podgate, _upstream) = serve().await;
    let answer = podgate.admin_get("/v1/catalog").await;
    assert_eq!(answer.status, 200);
    assert!(
        !answer.body.contains("planted"),
        "the OpenAPI document is never shown: {}",
        answer.body
    );
}

#[tokio::test]
async fn catalog_get_only() {
    let (podgate, _upstream) = serve().await;
    let answer = podgate.admin_post("/v1/catalog", &json!({})).await;
    assert_eq!(answer.status, 405, "{answer:?}");
    assert_eq!(answer.header("allow"), Some("GET"));
    assert_eq!(answer.json(), json!({"error": "method not allowed"}));
}

#[tokio::test]
async fn catalog_is_empty_without_apis() {
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    let plain = snapshot(1, &[app("a", &["a.test"], &[serving("r1", upstream.addr)])]);
    assert_eq!(podgate.push_snapshot(&plain).await.status, 200);
    let document = catalog(&podgate, "").await;
    assert_eq!(document["total"], 0);
    assert_eq!(document["items"], json!([]));
}
