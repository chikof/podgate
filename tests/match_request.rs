//! The `header`, `header_regexp`, `query` and `query_regexp` matcher leaves through
//! the real binary: routing by header and decoded query, no peeking at what a middleware adds
//! after routing, the catch-all rule, compile-time rejections, and explain's near misses.

mod common;

use common::{Podgate, Upstream, app, middleware, router, service, serving, snapshot, with_chain};
use serde_json::{Value, json};

/// App `a` on `a.test` with one service per `(name, body)`, starting with `web`, and the routers
/// given. Returns the app and keeps the upstreams alive through `ups`.
async fn split_app(routers: Value, ups: &mut Vec<Upstream>, bodies: &[&'static str]) -> Value {
    let web = Upstream::start("web").await;
    let mut a = app("a", &["a.test"], &[serving("r1", web.addr)]);
    ups.push(web);
    for body in bodies {
        let up = Upstream::start(body).await;
        a["revisions"][0]["services"]
            .as_array_mut()
            .expect("services")
            .push(service(body, &[up.addr]));
        ups.push(up);
    }
    a["routers"] = routers;
    a
}

fn host_and(leaf: &Value) -> Value {
    json!({ "all": [{ "host": "a.test" }, leaf] })
}

/// A router with an explicit priority, since several constraints of one kind overlap.
fn ranked(name: &str, priority: i32, matcher: Value, service: &str) -> Value {
    let mut ranked = router(name, matcher, service);
    ranked["priority"] = json!(priority);
    ranked
}

#[tokio::test]
async fn header_routes_by_value_regexp_and_presence() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let routers = json!([
        router("site", json!({ "host": "a.test" }), "web"),
        ranked(
            "canary",
            3,
            host_and(&json!({ "header": { "name": "X-Env", "value": "canary" } })),
            "canary"
        ),
        ranked(
            "mobile",
            2,
            host_and(&json!({ "header_regexp": { "name": "user-agent", "regex": "^Mobile/" } })),
            "mobile"
        ),
        ranked(
            "beta",
            1,
            host_and(&json!({ "header": { "name": "x-beta" } })),
            "beta"
        ),
    ]);
    let a = split_app(routers, &mut ups, &["canary", "mobile", "beta"]).await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    assert_eq!(podgate.get("a.test", "/").await.body, "web");
    assert_eq!(with(&podgate, &[("x-env", "canary")]).await, "canary");
    assert_eq!(
        with(&podgate, &[("X-ENV", "canary")]).await,
        "canary",
        "name case"
    );
    assert_eq!(
        with(&podgate, &[("x-env", "Canary")]).await,
        "web",
        "value case"
    );
    assert_eq!(
        with(&podgate, &[("x-env", "prod"), ("x-env", "canary")]).await,
        "canary"
    );
    assert_eq!(
        with(&podgate, &[("user-agent", "Mobile/1.0")]).await,
        "mobile"
    );
    assert_eq!(with(&podgate, &[("user-agent", "Desktop")]).await, "web");
    assert_eq!(with(&podgate, &[("x-beta", "")]).await, "beta", "presence");
}

#[tokio::test]
async fn query_routes_by_decoded_parameter() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let routers = json!([
        router("site", json!({ "host": "a.test" }), "web"),
        ranked(
            "debug",
            2,
            host_and(&json!({ "query": { "name": "debug", "value": "1" } })),
            "debug"
        ),
        ranked(
            "search",
            1,
            host_and(&json!({ "query_regexp": { "name": "q", "regex": "^hello world$" } })),
            "search"
        ),
    ]);
    let a = split_app(routers, &mut ups, &["debug", "search"]).await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    assert_eq!(podgate.get("a.test", "/").await.body, "web");
    assert_eq!(podgate.get("a.test", "/x?debug=1").await.body, "debug");
    assert_eq!(
        podgate.get("a.test", "/x?a=b&debug=0&debug=1").await.body,
        "debug"
    );
    assert_eq!(podgate.get("a.test", "/x?debug=10").await.body, "web");
    assert_eq!(
        podgate.get("a.test", "/x?%64ebug=1").await.body,
        "debug",
        "name decoded"
    );
    assert_eq!(
        podgate.get("a.test", "/?q=hello+world").await.body,
        "search"
    );
    assert_eq!(
        podgate.get("a.test", "/?q=hello%20world").await.body,
        "search"
    );
    assert_eq!(podgate.get("a.test", "/?q=hello%zzworld").await.body, "web");
}

#[tokio::test]
async fn constraints_beat_none_and_disjoint_values_are_not_ambiguous() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let routers = json!([
        router("site", json!({ "host": "a.test" }), "web"),
        router(
            "a",
            host_and(&json!({ "header": { "name": "x-env", "value": "a" } })),
            "alpha"
        ),
        router(
            "b",
            host_and(&json!({ "header": { "name": "x-env", "value": "b" } })),
            "bee"
        ),
    ]);
    let a = split_app(routers, &mut ups, &["alpha", "bee"]).await;
    // `a` and `b` have the same priority and specificity but cannot both match.
    let pushed = podgate
        .push_snapshot(&snapshot(1, std::slice::from_ref(&a)))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    for (value, body) in [("a", "alpha"), ("b", "bee"), ("c", "web")] {
        let got = podgate
            .get_with_headers("a.test", "/", &[("x-env", value)])
            .await;
        assert_eq!(got.body, body, "x-env: {value}");
    }

    // A header and a query constraint can match one request: ambiguous at equal priority.
    let mut overlapping = a;
    overlapping["routers"]
        .as_array_mut()
        .expect("routers")
        .push(router(
            "debug",
            host_and(&json!({ "query": { "name": "debug", "value": "1" } })),
            "web",
        ));
    let refused = podgate.push_snapshot(&snapshot(2, &[overlapping])).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(refused.json()["conflicts"][0]["code"], "route_ambiguity");
}

#[tokio::test]
async fn matcher_sees_original_request() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let routers = json!([
        router("site", json!({ "host": "a.test" }), "web"),
        router(
            "added",
            host_and(&json!({ "header": { "name": "x-added", "value": "1" } })),
            "added"
        ),
    ]);
    let a = split_app(routers, &mut ups, &["added"]).await;
    let a = with_chain(
        a,
        &[middleware(
            "adds",
            "headers",
            json!({ "request": { "set": { "x-added": "1" } } }),
        )],
    );
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    // The middleware sets `x-added` on every request, after the route was chosen.
    assert_eq!(podgate.get("a.test", "/").await.body, "web");
    // A client that sends it itself is routed by it.
    assert_eq!(
        podgate
            .get_with_headers("a.test", "/", &[("x-added", "1")])
            .await
            .body,
        "added"
    );
}

#[tokio::test]
async fn request_leaves_alone_need_exclusive_entry_point() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("b").await;
    for leaf in [
        json!({ "header": { "name": "x-env" } }),
        json!({ "header_regexp": { "name": "x-env", "regex": "." } }),
        json!({ "query": { "name": "debug" } }),
        json!({ "query_regexp": { "name": "debug", "regex": "." } }),
    ] {
        let mut shared = app("a", &["unused.test"], &[serving("r1", up.addr)]);
        shared["routers"] = json!([router("only", leaf.clone(), "web")]);
        let refused = podgate.push_snapshot(&snapshot(1, &[shared])).await;
        assert_eq!(refused.status, 422, "{leaf}: {}", refused.body);
        assert_eq!(
            refused.json()["conflicts"][0]["code"],
            "catch_all_not_allowed",
            "{leaf}"
        );
    }
}

#[tokio::test]
async fn bad_leaves_are_refused_at_compile() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("b").await;
    for leaf in [
        json!({ "header": "x-env" }),
        json!({ "header": { "name": "bad name" } }),
        json!({ "header": { "name": "x", "regex": "a" } }),
        json!({ "header_regexp": { "name": "x" } }),
        json!({ "header_regexp": { "name": "x", "regex": "(" } }),
        json!({ "header_regexp": { "name": "x", "regex": "(a{1000}){1000}" } }),
        json!({ "query": { "name": "" } }),
        json!({ "query_regexp": { "name": "q", "regex": "(a{1000}){1000}" } }),
    ] {
        let mut bad = app("a", &["a.test"], &[serving("r1", up.addr)]);
        bad["routers"] = json!([router("r", host_and(&leaf), "web")]);
        let refused = podgate.push_snapshot(&snapshot(1, &[bad])).await;
        assert_eq!(refused.status, 422, "{leaf}: {}", refused.body);
        assert_eq!(
            refused.json()["conflicts"][0]["code"],
            "invalid_matcher",
            "{leaf}"
        );
    }
}

#[tokio::test]
async fn explain_names_failing_header_leaf() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let routers = json!([
        router("site", json!({ "host": "a.test" }), "web"),
        ranked(
            "canary",
            2,
            host_and(&json!({ "header": { "name": "x-env", "value": "canary" } })),
            "canary"
        ),
        router(
            "elsewhere",
            json!({ "all": [{ "host": "b.test" }, { "header": { "name": "x-env" } }] }),
            "canary"
        ),
        ranked(
            "search",
            1,
            host_and(&json!({ "all": [
                { "query_regexp": { "name": "q", "regex": "^[a-z]+$" } },
                { "method": ["POST"] },
            ] })),
            "canary"
        ),
    ]);
    let a = split_app(routers, &mut ups, &["canary"]).await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let answer = podgate
        .admin_get("/v1/explain?url=http://a.test/?q=Hello")
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let body = answer.json();
    assert_eq!(body["matched"]["router"], "site");
    assert_eq!(
        body["near_misses"],
        json!([
            { "app": "a", "router": "canary", "failed": ["header x-env = \"canary\""] },
            { "app": "a", "router": "search", "failed": ["query_regexp \"q\" ~ \"^[a-z]+$\"", "method"] },
        ])
    );
}

#[tokio::test]
async fn explain_miss_lists_near_misses() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let routers = json!([router(
        "canary",
        host_and(&json!({ "query": { "name": "debug", "value": "1" } })),
        "web"
    )]);
    let a = split_app(routers, &mut ups, &[]).await;
    assert_eq!(podgate.push_snapshot(&snapshot(1, &[a])).await.status, 200);

    let miss = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(miss.status, 404, "{miss:?}");
    assert_eq!(
        miss.json()["near_misses"],
        json!([{ "app": "a", "router": "canary", "failed": ["query \"debug\" = \"1\""] }])
    );
    let hit = podgate
        .admin_get("/v1/explain?url=http://a.test/?debug=1")
        .await;
    assert_eq!(hit.status, 200, "{hit:?}");
    assert!(hit.json().get("near_misses").is_none());
    let other_host = podgate.admin_get("/v1/explain?url=http://b.test/").await;
    assert_eq!(other_host.status, 404);
    assert!(
        other_host.json().get("near_misses").is_none(),
        "a host miss is not a near miss"
    );
}

/// The body of `GET a.test/` with `headers`.
async fn with(podgate: &Podgate, headers: &[(&str, &str)]) -> String {
    podgate.get_with_headers("a.test", "/", headers).await.body
}
