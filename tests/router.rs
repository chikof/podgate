//! The v2 model end to end: routers with priority and path matchers, the middleware chain,
//! compile-time rejection of unknown kinds and bad matchers, tenant isolation of routers, and
//! path normalization.

mod common;

use common::{Podgate, Upstream, app, middleware, router, service, serving, snapshot};
use serde_json::{Value, json};

/// Two tenants `t1` and `t2`, each with generous budgets.
fn two_tenants(version: u64, apps: &[Value]) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["tenants"].as_array_mut().expect("tenants").push(json!({
        "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 },
    }));
    pushed
}

fn conflict_codes(body: &Value) -> Vec<String> {
    body["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code").to_owned())
        .collect()
}

#[tokio::test]
async fn paths_and_priority_pick_the_router_and_its_service() {
    let podgate = Podgate::start().await;
    let (api, web) = (Upstream::start("api").await, Upstream::start("web").await);
    let mut shop = app("shop", &["shop.test"], &[serving("r1", web.addr)]);
    shop["revisions"][0]["services"]
        .as_array_mut()
        .expect("services")
        .push(service("api", &[api.addr]));
    shop["routers"] = json!([
        router("site", json!({ "host": "shop.test" }), "web"),
        router(
            "api",
            json!({ "all": [{ "host": "shop.test" }, { "path_prefix": "/api" }] }),
            "api"
        ),
    ]);
    assert_eq!(
        podgate.push_snapshot(&snapshot(1, &[shop])).await.status,
        200
    );

    assert_eq!(podgate.get("shop.test", "/").await.body, "web");
    assert_eq!(podgate.get("shop.test", "/api/users").await.body, "api");
    assert_eq!(podgate.get("shop.test", "/apix").await.body, "web");
    // The path that was matched is the path that was served: `.` and `//` collapse first.
    assert_eq!(
        podgate.get("shop.test", "/x/../api//users").await.body,
        "api"
    );
}

#[tokio::test]
async fn unsafe_paths_are_refused_before_routing() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let pushed = snapshot(1, &[app("a", &["a.test"], &[serving("r1", up.addr)])]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    for path in ["/a%2fb", "/%2e%2e/x", "/a%00"] {
        assert_eq!(podgate.get("a.test", path).await.status, 400, "{path}");
    }
}

#[tokio::test]
async fn v2_rejects_unknown_middleware() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let with = |kind: &str| {
        let mut app = app("a", &["a.test"], &[serving("r1", up.addr)]);
        app["middlewares"] = json!([middleware("m", kind, json!({}))]);
        app["default_chain"] = json!(["m"]);
        snapshot(1, &[app])
    };
    let unknown = podgate.push_snapshot(&with("no_such_kind")).await;
    assert_eq!(unknown.status, 422, "{}", unknown.body);
    assert_eq!(conflict_codes(&unknown.json()), ["unknown_middleware"]);
    let unbuilt = podgate.push_snapshot(&with("rate_limit")).await;
    assert_eq!(unbuilt.status, 422, "{}", unbuilt.body);
    assert_eq!(conflict_codes(&unbuilt.json()), ["middleware_not_built"]);

    let mut dangling = app("a", &["a.test"], &[serving("r1", up.addr)]);
    dangling["default_chain"] = json!(["missing"]);
    let refused = podgate.push_snapshot(&snapshot(1, &[dangling])).await;
    assert_eq!(conflict_codes(&refused.json()), ["unknown_middleware_ref"]);
    assert_eq!(
        podgate.get("a.test", "/").await.status,
        404,
        "nothing was applied"
    );
}

#[tokio::test]
async fn v2_rejects_bad_matcher() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    for (matcher, code) in [
        (json!({ "host": "a.test", "path": "/x" }), "invalid_matcher"),
        (json!({ "nonsense": "x" }), "invalid_matcher"),
        (json!({ "path_regexp": "(" }), "invalid_matcher"),
        (json!({ "host": "a b" }), "invalid_host"),
    ] {
        let mut bad = app("a", &["a.test"], &[serving("r1", up.addr)]);
        bad["routers"][0]["match"] = matcher.clone();
        let refused = podgate.push_snapshot(&snapshot(1, &[bad])).await;
        assert_eq!(refused.status, 422, "{matcher}: {}", refused.body);
        assert_eq!(conflict_codes(&refused.json()), [code], "{matcher}");
    }
}

/// Priority never orders routers across tenants: tenant B's catch-all regexp at the highest
/// priority still loses a host tenant A claims, on every path.
#[tokio::test]
async fn cross_tenant_regexp_capture() {
    let podgate = Podgate::start_with_env(&[("CATCH_ALL_TENANTS", "t2")]).await;
    let (a_up, b_up) = (Upstream::start("a").await, Upstream::start("b").await);
    let mut a = app("a", &["a.test"], &[serving("r1", a_up.addr)]);
    a["routers"] = json!([router(
        "api",
        json!({ "all": [{ "host": "a.test" }, { "path_prefix": "/api" }] }),
        "web"
    )]);
    let mut b = app("b", &["unused.test"], &[serving("r1", b_up.addr)]);
    b["tenant"] = json!("t2");
    b["routers"] = json!([{
        "name": "catch-all", "match": { "host_regexp": ".*" }, "service": "web",
        "priority": i32::MAX,
    }]);
    let pushed = two_tenants(1, &[a, b]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);

    assert_eq!(podgate.get("a.test", "/api/x").await.body, "a");
    // A has no router for this path, and B's catch-all may not take a host A claims.
    assert_eq!(podgate.get("a.test", "/other").await.status, 404);
    assert_eq!(podgate.get("a.test", "/").await.status, 404);
    // The operator's setting lets B declare a catch-all; it still takes nothing A claims.
}

#[tokio::test]
async fn fallback_routers_of_two_tenants_are_refused() {
    let podgate = Podgate::start_with_env(&[("CATCH_ALL_TENANTS", "t1,t2")]).await;
    let up = Upstream::start("up").await;
    let catch_all = |id: &str, tenant: &str| {
        let mut app = app(id, &["unused.test"], &[serving("r1", up.addr)]);
        app["tenant"] = json!(tenant);
        app["routers"] = json!([router("all", json!({ "host_regexp": ".*" }), "web")]);
        app
    };
    let refused = podgate
        .push_snapshot(&two_tenants(
            1,
            &[catch_all("a", "t1"), catch_all("b", "t2")],
        ))
        .await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(conflict_codes(&refused.json()), ["cross_tenant_catch_all"]);
}

#[tokio::test]
async fn a_chain_answers_before_the_backend_is_chosen() {
    // `wasm` is the one built middleware: a filter that answers makes the request end in the
    // chain, even for an app with no serving revision.
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let mut sleeping = app(
        "a",
        &["a.test"],
        &[common::revision("r1", up.addr, 100, "draining")],
    );
    sleeping["default_chain"] = json!([]);
    assert_eq!(
        podgate
            .push_snapshot(&snapshot(1, &[sleeping]))
            .await
            .status,
        200
    );
    assert_eq!(podgate.get("a.test", "/").await.status, 503);
}

/// The default entry points: no policy restricts them, so a catch-all on them is refused.
fn catch_all_app(id: &str, tenant: &str, up: &Upstream, matcher: Value) -> Value {
    let mut app = app(id, &["unused.test"], &[serving("r1", up.addr)]);
    app["tenant"] = json!(tenant);
    app["routers"] = json!([router("all", matcher, "web")]);
    app
}

/// A tenant cannot take the hosts nobody claims right now (a redeploy gap, a deleted app, a
/// lookalike domain): a `.*` or host-free router on a shared entry point is refused, and on an
/// entry point whose policy names the tenant alone it is accepted.
#[tokio::test]
async fn catch_all_cannot_take_unclaimed_host() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("b").await;
    for matcher in [
        json!({ "host_regexp": ".*" }),
        json!({ "path_prefix": "/" }),
        json!({ "any": [{ "host": "x.test" }, { "host_regexp": ".*" }] }),
    ] {
        let refused = podgate
            .push_snapshot(&two_tenants(
                1,
                &[catch_all_app("b", "t2", &up, matcher.clone())],
            ))
            .await;
        assert_eq!(refused.status, 422, "{matcher}: {}", refused.body);
        assert_eq!(
            conflict_codes(&refused.json()),
            ["catch_all_not_allowed"],
            "{matcher}"
        );
    }
    assert_eq!(podgate.get("elsewhere.test", "/").await.status, 404);

    // On an entry point that admits tenant `t2` alone, the same router is accepted.
    let mut exclusive = catch_all_app("b", "t2", &up, json!({ "host_regexp": ".*" }));
    exclusive["routers"][0]["entry_points"] = json!(["web"]);
    let mut pushed = two_tenants(2, &[exclusive]);
    pushed["entry_points"] = json!([{ "name": "web", "tenants": ["t2"] }]);
    let accepted = podgate.push_snapshot(&pushed).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(podgate.get("elsewhere.test", "/").await.body, "b");
}

/// A `host_regexp` next to a literal host the tenant claims is not a catch-all: it narrows that
/// claim, so it compiles without any operator setting.
#[tokio::test]
async fn anchored_regexp_under_own_suffix_accepted() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("preview").await;
    let mut acme = app("acme", &["unused.test"], &[serving("r1", up.addr)]);
    acme["routers"] = json!([router(
        "preview",
        json!({ "all": [
            { "host": "*.preview.acme.test" },
            { "host_regexp": "^pr-[0-9]+\\.preview\\.acme\\.test$" },
        ] }),
        "web"
    )]);
    let response = podgate.push_snapshot(&snapshot(1, &[acme])).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        podgate.get("pr-42.preview.acme.test", "/").await.body,
        "preview"
    );
    assert_eq!(podgate.get("main.preview.acme.test", "/").await.status, 404);
    assert_eq!(podgate.get("pr-42.other.acme.test", "/").await.status, 404);
}

/// The operator, never a snapshot, can allow a tenant a catch-all (`CATCH_ALL_TENANTS`).
#[tokio::test]
async fn operator_allowed_catch_all() {
    let podgate = Podgate::start_with_env(&[("CATCH_ALL_TENANTS", "t2")]).await;
    let (a_up, b_up) = (Upstream::start("a").await, Upstream::start("b").await);
    let a = app("a", &["a.test"], &[serving("r1", a_up.addr)]);
    let b = catch_all_app("b", "t2", &b_up, json!({ "host_regexp": ".*" }));
    let accepted = podgate.push_snapshot(&two_tenants(1, &[a, b])).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(podgate.get("a.test", "/").await.body, "a");
    assert_eq!(podgate.get("elsewhere.test", "/").await.body, "b");

    // Another tenant is still refused.
    let c = catch_all_app("c", "t1", &b_up, json!({ "path_prefix": "/" }));
    let refused = podgate.push_snapshot(&two_tenants(2, &[c])).await;
    assert_eq!(conflict_codes(&refused.json()), ["catch_all_not_allowed"]);
}

/// A regexp only narrows a literal claim: an alternation naming another host cannot widen the
/// router to it, whether that host is claimed by another tenant or by nobody.
#[tokio::test]
async fn regexp_alternation_cannot_widen_claim() {
    let podgate = Podgate::start().await;
    let (a_up, b_up) = (Upstream::start("a").await, Upstream::start("b").await);
    let mut a = app("a", &["unused.test"], &[serving("r1", a_up.addr)]);
    a["routers"] = json!([router(
        "narrow",
        json!({ "all": [
            { "host": "*.a.test" },
            { "host_regexp": "^(other-tenant\\.test|x\\.a\\.test)$" },
        ] }),
        "web"
    )]);
    // Unclaimed first: `other-tenant.test` belongs to nobody.
    let pushed = two_tenants(1, std::slice::from_ref(&a));
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    assert_eq!(podgate.get("x.a.test", "/").await.body, "a");
    assert_eq!(podgate.get("other-tenant.test", "/").await.status, 404);
    assert_eq!(podgate.get("y.a.test", "/").await.status, 404);

    // Now tenant B claims it.
    let mut b = app("b", &["other-tenant.test"], &[serving("r1", b_up.addr)]);
    b["tenant"] = json!("t2");
    let pushed = two_tenants(2, &[a, b]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    assert_eq!(podgate.get("other-tenant.test", "/").await.body, "b");
    assert_eq!(podgate.get("x.a.test", "/").await.body, "a");
}
