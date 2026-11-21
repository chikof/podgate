//! The `cel` matcher leaf through the real binary: the environment, compile-time
//! rejections, the static cost limit, bounded evaluation, errors that are non-matches and are
//! counted, the claim and catch-all rules, and explain.

mod common;

use std::time::{Duration, Instant};

use common::{Podgate, TestCert, Upstream, app, router, service, serving, snapshot};
use serde_json::{Value, json};

/// App `a` on `a.test` whose router `site` answers with `web` and whose router `cel` (priority
/// 1, `host a.test` and the leaf `cel`) answers with `hit`.
async fn cel_app(cel: Value, ups: &mut Vec<Upstream>) -> Value {
    let web = Upstream::start("web").await;
    let hit = Upstream::start("hit").await;
    let mut a = app("a", &["a.test"], &[serving("r1", web.addr)]);
    a["revisions"][0]["services"]
        .as_array_mut()
        .expect("services")
        .push(service("hit", &[hit.addr]));
    a["routers"] = json!([
        router("site", json!({ "host": "a.test" }), "web"),
        {
            "name": "cel", "priority": 1, "service": "hit",
            "match": { "all": [{ "host": "a.test" }, { "cel": cel }] },
        },
    ]);
    ups.extend([web, hit]);
    a
}

async fn started(cel: impl Into<Value>) -> (Podgate, Vec<Upstream>) {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let cel = cel.into();
    let a = cel_app(cel.clone(), &mut ups).await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 200, "{cel}: {}", pushed.body);
    (podgate, ups)
}

/// Pushes a snapshot with the leaf `cel` and returns the refusal's first conflict.
async fn refused(cel: Value) -> Value {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let a = cel_app(cel.clone(), &mut ups).await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 422, "{cel}: {}", pushed.body);
    let conflict = pushed.json()["conflicts"][0].clone();
    assert_eq!(conflict["code"], "invalid_matcher", "{cel}: {conflict}");
    conflict
}

fn message(conflict: &Value) -> &str {
    conflict["message"].as_str().expect("message")
}

#[tokio::test]
async fn cel_matches_method_and_headers() {
    let (podgate, _ups) = started(
        "request.method == 'POST' && request.headers['x-env'] == 'canary' \
         && ('x-beta' in request.headers || request.headers['user-agent'].startsWith('curl/'))",
    )
    .await;
    macro_rules! post {
        ($($header:expr),*) => {
            podgate
                .request("POST", "a.test", "/", &[$($header),*])
                .await
                .body
        };
    }
    assert_eq!(
        post!(("x-env", "canary"), ("user-agent", "curl/8.4")),
        "hit"
    );
    assert_eq!(
        post!(("X-Env", "canary"), ("x-beta", "1")),
        "hit",
        "header names are case-insensitive on the wire and lower-case in the map"
    );
    assert_eq!(post!(("x-env", "canary"), ("user-agent", "wget")), "web");
    assert_eq!(post!(("x-env", "prod"), ("x-beta", "1")), "web");
    assert_eq!(
        post!(("x-beta", "1")),
        "web",
        "a missing header is a non-match"
    );
    assert_eq!(
        podgate
            .get_with_headers("a.test", "/", &[("x-env", "canary"), ("x-beta", "1")])
            .await
            .body,
        "web",
        "a GET is not a POST"
    );
}

#[tokio::test]
async fn cel_matches_query_and_path() {
    let (podgate, _ups) = started(json!({
        "expression": "request.path.startsWith('/api/') && request.query['v'] == '2' \
            && !request.path.contains('/admin') && request.host == 'a.test' \
            && request.path.matches('^/api/[a-z0-9/]+$')",
        "max_cost": 300,
    }))
    .await;
    for (target, body) in [
        ("/api/users?v=2", "hit"),
        ("/api/users/1?x=y&v=2&v=3", "hit"),
        ("/api/users?%76=2", "hit"),
        ("/api/users?v=3", "web"),
        ("/api/users", "web"),
        ("/api/admin/users?v=2", "web"),
        ("/api/Users?v=2", "web"),
        ("/other?v=2", "web"),
    ] {
        assert_eq!(podgate.get("a.test", target).await.body, body, "{target}");
    }
}

#[tokio::test]
async fn cel_matches_client_ip_cidr() {
    let (podgate, _ups) = started("ip(request.client_ip).in_cidr('127.0.0.0/8')").await;
    assert_eq!(
        podgate.get("a.test", "/").await.body,
        "hit",
        "the test client is 127.0.0.1"
    );
    // A forged header from a peer that is not trusted does not move the client.
    let forged = podgate
        .get_with_headers("a.test", "/", &[("x-forwarded-for", "203.0.113.9")])
        .await;
    assert_eq!(forged.body, "hit");

    let other = Podgate::start().await;
    let mut ups = Vec::new();
    let a = cel_app(
        json!("ip(request.client_ip).in_cidr('10.0.0.0/8') || request.client_ip == '::1'"),
        &mut ups,
    )
    .await;
    assert_eq!(other.push_snapshot(&snapshot(1, &[a])).await.status, 200);
    assert_eq!(other.get("a.test", "/").await.body, "web");
}

#[tokio::test]
async fn cel_matches_tls_sni() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let a = cel_app(
        json!(
            "request.scheme == 'https' && tls.sni == 'a.test' && tls.version.startsWith('TLS') \
             && size(tls.version) > 3"
        ),
        &mut ups,
    )
    .await;
    let cert = TestCert::new(&["a.test"]);
    let mut pushed = snapshot(1, &[a]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    let accepted = podgate.push_snapshot(&pushed).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    let secure = podgate.https_get("a.test", "a.test", "/", &cert).await;
    assert_eq!(secure.body, "hit", "{secure:?}");
    assert_eq!(
        podgate.get("a.test", "/").await.body,
        "web",
        "plain HTTP has no SNI and is not https"
    );
}

#[tokio::test]
async fn cel_matches_entry_point() {
    let podgate =
        Podgate::start_with_entry_points(&[("public", "http"), ("internal", "http")], &[]).await;
    let mut ups = Vec::new();
    let a = cel_app(json!("entry_point == 'internal'"), &mut ups).await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(podgate.get_on("internal", "a.test", "/").await.body, "hit");
    assert_eq!(podgate.get_on("public", "a.test", "/").await.body, "web");
}

#[tokio::test]
async fn cel_syntax_error_rejected() {
    for (expression, at) in [
        ("request.method ==", "column 18"),
        ("request.method == 'GET' &&& true", "column"),
        ("(request.method == 'GET'", "column"),
        ("request.method == 'GET", "unterminated"),
        ("1.5 > 1", "floating point"),
        ("", "empty"),
    ] {
        let conflict = refused(json!(expression)).await;
        assert!(
            message(&conflict).contains("cel:"),
            "{expression}: {conflict}"
        );
        if !expression.is_empty() {
            assert!(message(&conflict).contains(at), "{expression}: {conflict}");
        }
    }
}

#[tokio::test]
async fn cel_type_error_rejected() {
    for expression in [
        "request.method == 1",
        "request.method",
        "request.headers == request.query",
        "size(1) > 0",
        "request.path + 1 == 'a'",
        "request.client_ip.in_cidr('10.0.0.0/8')",
        "ip(request.client_ip).in_cidr('10.0.0.0/99')",
    ] {
        let conflict = refused(json!(expression)).await;
        assert!(
            message(&conflict).contains("column"),
            "{expression}: the position is named: {conflict}"
        );
    }
    let conflict = refused(json!("request.method == 1")).await;
    assert!(message(&conflict).contains("type error"), "{conflict}");
}

#[tokio::test]
async fn cel_unknown_identifier_rejected() {
    for (expression, name) in [
        ("remote_addr == '1.2.3.4'", "remote_addr"),
        ("request.body == 'x'", "request.body"),
        ("frobnicate(request.path)", "frobnicate"),
        ("request.path.reverse() == 'x'", "reverse"),
    ] {
        let conflict = refused(json!(expression)).await;
        assert!(
            message(&conflict).contains("undeclared reference")
                && message(&conflict).contains(name),
            "{expression}: {conflict}"
        );
    }
}

#[tokio::test]
async fn cel_oversized_expression_rejected() {
    let at_limit = format!("request.path == '{}'", "a".repeat(2048 - 18));
    assert_eq!(at_limit.len(), 2048);
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let a = cel_app(json!(at_limit), &mut ups).await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let over = format!("request.path == '{}'", "a".repeat(2048 - 17));
    let conflict = refused(json!(over)).await;
    assert!(message(&conflict).contains("2049 bytes"), "{conflict}");
}

#[tokio::test]
async fn cel_cost_limit_rejects() {
    let scan = "request.headers['user-agent'].contains('a')";
    let four = [scan; 4].join(" || ");
    let conflict = refused(json!(four)).await;
    assert!(
        message(&conflict).contains("cel_cost_exceeded"),
        "{conflict}"
    );

    // `max_cost` raises the limit, up to 1000.
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let a = cel_app(json!({ "expression": four, "max_cost": 400 }), &mut ups).await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let forty = [scan; 40].join(" || ");
    let conflict = refused(json!({ "expression": forty, "max_cost": 1000 })).await;
    assert!(
        message(&conflict).contains("cel_cost_exceeded"),
        "{conflict}"
    );
    let conflict = refused(json!({ "expression": "true", "max_cost": 1001 })).await;
    assert!(message(&conflict).contains("max_cost"), "{conflict}");
}

#[tokio::test]
async fn cel_comprehension_rejected() {
    for expression in [
        "['a', 'b'].all(x, x != request.method)",
        "['a'].exists(x, x == request.method)",
        "['a'].exists_one(x, x == request.method)",
        "['a'].map(x, x) == ['a']",
        "['a'].filter(x, x == request.method) == []",
    ] {
        let conflict = refused(json!(expression)).await;
        assert!(
            message(&conflict).contains("cel_comprehension"),
            "{expression}: {conflict}"
        );
    }
}

#[tokio::test]
async fn cel_non_literal_regex_rejected() {
    for expression in [
        "request.path.matches(request.headers['x-re'])",
        "matches(request.path, request.host)",
        "request.path.matches('(' + 'a')",
    ] {
        let conflict = refused(json!(expression)).await;
        assert!(
            message(&conflict).contains("string literal"),
            "{expression}: {conflict}"
        );
    }
    let conflict = refused(json!("request.path.matches('(a{1000}){1000}')")).await;
    assert!(message(&conflict).contains("cel"), "{conflict}");
}

#[tokio::test]
async fn cel_no_time_or_io_functions() {
    for expression in [
        "now() > 0",
        "timestamp('2024-01-01T00:00:00Z') < timestamp('2025-01-01T00:00:00Z')",
        "duration('1h') == duration('60m')",
        "request.headers['x'] == string(now)",
        "env('HOME') == '/root'",
        "http.get('http://127.0.0.1/') == 'x'",
        "dns('a.test') == '1.2.3.4'",
        "file('/etc/passwd').contains('root')",
        "rand() > 1",
        "request.path.getHours() > 1",
    ] {
        let conflict = refused(json!(expression)).await;
        assert!(
            message(&conflict).contains("undeclared reference"),
            "{expression}: {conflict}"
        );
    }
}

/// The number the metric `podgate_cel_errors_total` has for app `a`, 0 when it has no series.
async fn errors(podgate: &Podgate) -> u64 {
    let metrics = podgate.admin_get("/metrics").await.body;
    metrics
        .lines()
        .find_map(|line| line.strip_prefix("podgate_cel_errors_total{app=\"a\"} "))
        .map_or(0, |count| count.trim().parse().expect("a counter"))
}

#[tokio::test]
async fn cel_error_is_non_match_not_5xx() {
    // `request.headers['x-gone']` fails when the header is absent: never a 5xx.
    let (podgate, _ups) = started("request.headers['x-gone'] == 'a'").await;
    for _ in 0..3 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(response.body, "web");
    }
    let present = podgate
        .get_with_headers("a.test", "/", &[("x-gone", "a")])
        .await;
    assert_eq!((present.status, present.body.as_str()), (200, "hit"));
    // An address that is not one, a client that has none, and an input that is too long.
    let (podgate, _ups) =
        started("ip(request.host).in_cidr('10.0.0.0/8') || request.query['q'].startsWith('x')")
            .await;
    let response = podgate.get("a.test", "/?q=xyz").await;
    assert_eq!((response.status, response.body.as_str()), (200, "hit"));
    let long = format!("/?q={}", "a".repeat(9000));
    let response = podgate.get("a.test", &long).await;
    assert_eq!((response.status, response.body.as_str()), (200, "web"));
}

#[tokio::test]
async fn cel_error_counted() {
    let (podgate, _ups) = started("request.headers['x-gone'] == 'a'").await;
    assert_eq!(
        errors(&podgate).await,
        0,
        "a series exists from the first push"
    );
    assert!(
        podgate
            .admin_get("/metrics")
            .await
            .body
            .contains("# TYPE podgate_cel_errors_total counter\n")
    );
    for _ in 0..3 {
        assert_eq!(podgate.get("a.test", "/").await.body, "web");
    }
    assert_eq!(errors(&podgate).await, 3);
    // A matching request is not an error.
    let hit = podgate
        .get_with_headers("a.test", "/", &[("x-gone", "a")])
        .await;
    assert_eq!(hit.body, "hit");
    assert_eq!(errors(&podgate).await, 3);

    // The count survives a push: it is the process's, not the table's.
    let mut ups = Vec::new();
    let a = cel_app(json!("request.headers['x-gone'] == 'b'"), &mut ups).await;
    assert_eq!(podgate.push_snapshot(&snapshot(2, &[a])).await.status, 200);
    assert_eq!(podgate.get("a.test", "/").await.body, "web");
    assert_eq!(errors(&podgate).await, 4);
}

#[tokio::test]
async fn cel_evaluation_bounded_under_hostile_request() {
    let (podgate, _ups) =
        started("request.headers['x-0'].contains('zzz') || request.path.matches('^/a+$')").await;
    let started_at = Instant::now();
    // 100 headers of 8 KiB, with the request's own `host`: more than the 100 the map offers.
    let value = "a".repeat(8192);
    let names: Vec<String> = (0..100).map(|n| format!("x-{n}")).collect();
    let headers: Vec<(&str, &str)> = names.iter().map(|name| (name.as_str(), &*value)).collect();
    let crowded = podgate.get_with_headers("a.test", "/", &headers).await;
    assert_eq!(
        (crowded.status, crowded.body.as_str()),
        (200, "web"),
        "{crowded:?}"
    );
    assert_eq!(
        errors(&podgate).await,
        1,
        "too many headers is an error, counted"
    );

    // 90 headers: readable, each header value is scanned within its bound.
    let few: Vec<(&str, &str)> = headers[..90].to_vec();
    let sparse = podgate.get_with_headers("a.test", "/", &few).await;
    assert_eq!(sparse.body, "web", "{sparse:?}");

    // A long path is matched in linear time and a path over 8 KiB is an error, not a hang.
    let path = format!("/{}", "a".repeat(8000));
    assert_eq!(podgate.get("a.test", &path).await.body, "hit");
    let too_long = format!("/{}", "a".repeat(9000));
    let response = podgate.get("a.test", &too_long).await;
    assert_eq!(response.body, "web", "{response:?}");
    assert!(
        started_at.elapsed() < Duration::from_secs(20),
        "evaluation took {:?}",
        started_at.elapsed()
    );
}

#[tokio::test]
async fn cel_claims_no_host() {
    // The cel leaf next to a host does not widen it: another host never reaches the router.
    let (podgate, _ups) = started("true").await;
    assert_eq!(podgate.get("a.test", "/").await.body, "hit");
    let other = podgate.get("b.test", "/").await;
    assert_eq!(
        (other.status, other.body.as_str()),
        (404, r#"{"error":"not found"}"#)
    );

    // A tenant cannot take a host another tenant owns through a cel leaf: host_conflict does not
    // see the expression, the host claim is the `host` leaf's.
    let web = Upstream::start("t2").await;
    let mut thief = app("thief", &["a.test"], &[serving("r1", web.addr)]);
    thief["tenant"] = json!("t2");
    thief["routers"] = json!([{
        "name": "x", "service": "web",
        "match": { "all": [{ "host": "a.test" }, { "cel": "true" }] },
    }]);
    let mut pushed = snapshot(2, &[thief]);
    pushed["tenants"] = json!([
        { "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
        { "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
    ]);
    let mut owner_ups = Vec::new();
    let owner = cel_app(json!("true"), &mut owner_ups).await;
    pushed["apps"] = json!([owner, pushed["apps"][0].clone()]);
    let refused = podgate.push_snapshot(&pushed).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(refused.json()["conflicts"][0]["code"], "host_conflict");
}

#[tokio::test]
async fn cel_alone_is_catch_all_not_allowed() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("web").await;
    let mut only = app("a", &["unused.test"], &[serving("r1", up.addr)]);
    only["routers"] = json!([router(
        "only",
        json!({ "cel": "request.method == 'GET'" }),
        "web"
    )]);
    let refused = podgate.push_snapshot(&snapshot(1, &[only.clone()])).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(
        refused.json()["conflicts"][0]["code"],
        "catch_all_not_allowed"
    );

    // Under `not` and `any` the leaf still does not name a host.
    only["routers"] = json!([router(
        "only",
        json!({ "any": [{ "cel": "true" }, { "not": { "cel": "false" } }] }),
        "web"
    )]);
    let refused = podgate.push_snapshot(&snapshot(2, &[only.clone()])).await;
    assert_eq!(
        refused.json()["conflicts"][0]["code"],
        "catch_all_not_allowed"
    );

    // The operator can allow the tenant a catch-all.
    let allowed = Podgate::start_with_env(&[("CATCH_ALL_TENANTS", "t1")]).await;
    only["routers"] = json!([router(
        "only",
        json!({ "cel": "request.host == 'z.test'" }),
        "web"
    )]);
    let pushed = allowed.push_snapshot(&snapshot(1, &[only])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(allowed.get("z.test", "/").await.body, "web");
    assert_eq!(allowed.get("y.test", "/").await.status, 404);
}

#[tokio::test]
async fn cel_routers_ambiguous_without_priority() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let mut a = cel_app(json!("request.method == 'GET'"), &mut ups).await;
    let both = |priority: Option<i32>| {
        let mut second = json!({
            "name": "second", "service": "web",
            "match": { "all": [{ "host": "a.test" }, { "cel": "request.method == 'POST'" }] },
        });
        if let Some(priority) = priority {
            second["priority"] = json!(priority);
        }
        second
    };
    // Same priority and the same specificity, and the expressions are never provably disjoint,
    // even though one wants GET and the other POST.
    a["routers"][0] = json!({
        "name": "first", "service": "hit", "priority": 1,
        "match": { "all": [{ "host": "a.test" }, { "cel": "request.method == 'GET'" }] },
    });
    a["routers"][1] = both(Some(1));
    let refused = podgate.push_snapshot(&snapshot(1, &[a.clone()])).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(refused.json()["conflicts"][0]["code"], "route_ambiguity");

    // Different priorities order them.
    a["routers"][1] = both(Some(2));
    let accepted = podgate.push_snapshot(&snapshot(2, &[a])).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
}

#[tokio::test]
async fn explain_shows_cel_expression_and_near_miss() {
    let expression = "request.method == 'POST' && request.headers['x-env'] == 'canary'";
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let a = cel_app(json!(expression), &mut ups).await;
    assert_eq!(podgate.push_snapshot(&snapshot(1, &[a])).await.status, 200);

    let answer = podgate.admin_get("/v1/explain?url=http://a.test/x").await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let body = answer.json();
    assert_eq!(body["matched"]["router"], "site");
    assert_eq!(
        body["near_misses"],
        json!([{ "app": "a", "router": "cel", "failed": [format!("cel {expression}")] }])
    );

    let post = podgate
        .admin_get("/v1/explain?url=http://a.test/x&method=POST")
        .await;
    assert_eq!(
        post.json()["near_misses"][0]["failed"],
        json!([format!("cel {expression}")]),
        "explain sends no header, so the second half fails (an error is a non-match)"
    );
}
