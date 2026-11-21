//! Traefik rule strings in the snapshot through the real binary: the rule compiles to
//! the same routing as the equivalent tree, the exclusivity and error codes, the tenant and
//! catch-all rules, the default priority, TCP routers, explain and the plan diff.

mod common;

use std::time::Duration;

use common::{Podgate, Upstream, app, router, service, serving, snapshot};
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

fn with_tenant_2(mut pushed: Value) -> Value {
    pushed["tenants"].as_array_mut().expect("tenants").push(json!({
        "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 },
    }));
    pushed
}

fn by_rule(name: &str, rule: &str, service: &str) -> Value {
    json!({ "name": name, "rule": rule, "service": service })
}

/// App `id` of `tenant` with the services `web` and `hit` on the given servers and the routers
/// `routers`.
fn app_on(
    id: &str,
    tenant: &str,
    routers: Value,
    web: std::net::SocketAddr,
    hit: std::net::SocketAddr,
) -> Value {
    let mut app = app(id, &["unused.test"], &[serving("r1", web)]);
    app["tenant"] = json!(tenant);
    app["revisions"][0]["services"]
        .as_array_mut()
        .expect("services")
        .push(service("hit", &[hit]));
    app["routers"] = routers;
    app
}

/// [`app_on`] on two fresh upstreams that answer `web` and `hit`, kept alive in `ups`.
async fn two_service_app(id: &str, tenant: &str, routers: Value, ups: &mut Vec<Upstream>) -> Value {
    let web = Upstream::start("web").await;
    let hit = Upstream::start("hit").await;
    let app = app_on(id, tenant, routers, web.addr, hit.addr);
    ups.extend([web, hit]);
    app
}

/// The first conflict of a refused push: its code and the whole entry.
async fn refused(podgate: &Podgate, pushed: &Value) -> Value {
    let response = podgate.push_snapshot(pushed).await;
    assert_eq!(response.status, 422, "{}", response.body);
    response.json()["conflicts"][0].clone()
}

fn codes(body: &Value) -> Vec<String> {
    body["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code").to_owned())
        .collect()
}

/// What the router that answers `a.test` for `method`, `path` and `headers` serves.
async fn answer(podgate: &Podgate, host: &str, method: &str, path: &str, x_env: &str) -> String {
    let headers: Vec<(&str, &str)> = if x_env.is_empty() {
        Vec::new()
    } else {
        vec![("x-env", x_env)]
    };
    podgate.request(method, host, path, &headers).await.body
}

#[tokio::test]
async fn rule_routes_like_the_equivalent_tree_through_the_daemon() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let cases = [
        (
            "Host(`a.test`) && PathPrefix(`/api`) && !Method(`DELETE`)",
            json!({"all": [{"host": "a.test"}, {"path_prefix": "/api"}, {"not": {"method": "DELETE"}}]}),
        ),
        (
            "(Host(`a.test`) || Host(`b.test`)) && Header(`X-Env`, `canary`)",
            json!({"all": [{"host": ["a.test", "b.test"]}, {"header": {"name": "x-env", "value": "canary"}}]}),
        ),
        (
            "Host(`*.a.test`) && PathRegexp(`^/api/v[0-9]+$`) && HeaderRegexp(`x-env`, `^ca`)",
            json!({"all": [{"host": "*.a.test"}, {"path_regexp": "^/api/v[0-9]+$"},
                {"header_regexp": {"name": "x-env", "regex": "^ca"}}]}),
        ),
    ];
    let mut version = 0;
    for (rule, tree) in cases {
        let routers_tree = json!([
            router("site", json!({"host": ["a.test", "b.test", "x.a.test"]}), "web"),
            {"name": "hit", "match": tree, "priority": rule.len(), "service": "hit"},
        ]);
        let routers_rule = json!([
            router(
                "site",
                json!({"host": ["a.test", "b.test", "x.a.test"]}),
                "web"
            ),
            by_rule("hit", rule, "hit"),
        ]);
        let mut seen: [Vec<String>; 2] = [Vec::new(), Vec::new()];
        for (slot, routers) in [routers_tree, routers_rule].into_iter().enumerate() {
            let app = two_service_app("a", "t1", routers, &mut ups).await;
            version += 1;
            let pushed = podgate.push_snapshot(&snapshot(version, &[app])).await;
            assert_eq!(pushed.status, 200, "{rule}: {}", pushed.body);
            for host in ["a.test", "b.test", "x.a.test"] {
                for method in ["GET", "DELETE"] {
                    for path in ["/", "/api", "/api/v2", "/api/x"] {
                        for x_env in ["", "canary", "prod"] {
                            seen[slot].push(answer(&podgate, host, method, path, x_env).await);
                        }
                    }
                }
            }
        }
        assert_eq!(seen[0], seen[1], "{rule}: the rule routes like its tree");
        assert!(
            seen[0].iter().any(|body| body == "hit") && seen[0].iter().any(|body| body == "web"),
            "{rule}: the table reaches both routers"
        );
    }
}

#[tokio::test]
async fn rule_and_match_exclusive() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    for (routers, what) in [
        (
            json!([{"name": "r", "match": {"host": "a.test"}, "rule": "Host(`a.test`)", "service": "web"}]),
            "both",
        ),
        (json!([{"name": "r", "service": "web"}]), "neither"),
        (
            json!([{"name": "r", "match": null, "service": "web"}]),
            "a null match",
        ),
    ] {
        let app = two_service_app("a", "t1", routers, &mut ups).await;
        let conflict = refused(&podgate, &snapshot(1, &[app])).await;
        assert_eq!(conflict["code"], "invalid_router", "{what}: {conflict}");
        assert_eq!(conflict["at"], "router r", "{what}");
    }
    let tcp_both = json!({
        "name": "t", "entry_points": ["web"], "service": "s",
        "match": {"client_ip": ["127.0.0.0/8"]}, "rule": "ClientIP(`127.0.0.0/8`)",
    });
    let mut app = two_service_app(
        "a",
        "t1",
        json!([router("r", json!({"host": "a.test"}), "web")]),
        &mut ups,
    )
    .await;
    app["tcp"] = json!({"routers": [tcp_both], "services": []});
    let conflict = refused(&podgate, &snapshot(1, &[app])).await;
    assert_eq!(conflict["code"], "invalid_router", "{conflict}");
    assert_eq!(conflict["at"], "tcp router t");
}

#[tokio::test]
async fn rule_unsupported_function_rejected() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    for (rule, position) in [
        ("Host(`a.test`) && Headers(`x`, `y`)", 18),
        ("Host(`a.test`) && Nope(`x`)", 18),
        ("HostRegexp(`{sub:[a-z]+}.a.test`)", 0),
        ("HostHeader(`a.test`)", 0),
        ("Host(`a.test`) && Query(`debug`)", 18),
    ] {
        let app = two_service_app("a", "t1", json!([by_rule("r", rule, "web")]), &mut ups).await;
        let conflict = refused(&podgate, &snapshot(1, &[app])).await;
        assert_eq!(conflict["code"], "unsupported_rule", "{rule}: {conflict}");
        assert_eq!(conflict["at"], "router r", "{rule}");
        assert_eq!(conflict["position"], position, "{rule}: {conflict}");
        assert_eq!(conflict["app"], "a");
        assert!(
            conflict["message"]
                .as_str()
                .expect("message")
                .contains("rule: "),
            "{conflict}"
        );
    }
}

#[tokio::test]
async fn rule_bad_regexp_rejected() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    // A pattern the regex crate rejects, and one it compiles that is over the matcher size limit
    // (`(a{200}){200}`: the regex crate's own 10 MiB limit would take it).
    for rule in [
        "Host(`a.test`) && PathRegexp(`^/a(`)",
        "Host(`a.test`) && HeaderRegexp(`x-env`, `(?=a)`)",
        "Host(`a.test`) && PathRegexp(`(a{200}){200}`)",
        "Host(`a.test`) && HeaderRegexp(`x-env`, `(a{200}){200}`)",
    ] {
        let app = two_service_app("a", "t1", json!([by_rule("r", rule, "web")]), &mut ups).await;
        let conflict = refused(&podgate, &snapshot(1, &[app])).await;
        assert_eq!(conflict["code"], "invalid_rule", "{rule}: {conflict}");
        assert!(
            conflict["position"].as_u64().is_some(),
            "{rule}: {conflict}"
        );
    }
}

#[tokio::test]
async fn rule_too_long_rejected() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let padded = |len: usize| {
        let rule = "Host(`a.test`)";
        format!("{rule}{}", " ".repeat(len - rule.len()))
    };
    let app = two_service_app(
        "a",
        "t1",
        json!([by_rule("r", &padded(2049), "web")]),
        &mut ups,
    )
    .await;
    let conflict = refused(&podgate, &snapshot(1, &[app])).await;
    assert_eq!(conflict["code"], "invalid_rule", "{conflict}");
    assert!(
        conflict["message"]
            .as_str()
            .expect("message")
            .contains("2049"),
        "{conflict}"
    );
    // Exactly 2 KiB is accepted, and its length is its priority.
    let app = two_service_app(
        "a",
        "t1",
        json!([by_rule("r", &padded(2048), "web")]),
        &mut ups,
    )
    .await;
    let pushed = podgate.push_snapshot(&snapshot(2, &[app])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let explained = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(explained.json()["matched"]["priority"], 2048);
}

#[tokio::test]
async fn rule_wrong_dialect_rejected() {
    let podgate = Podgate::start_with_entry_points(&[("web", "http"), ("pg", "tcp")], &[]).await;
    let mut ups = Vec::new();
    let app = two_service_app(
        "a",
        "t1",
        json!([by_rule("r", "HostSNI(`a.test`)", "web")]),
        &mut ups,
    )
    .await;
    let conflict = refused(&podgate, &snapshot(1, &[app])).await;
    assert_eq!(conflict["code"], "invalid_rule", "{conflict}");
    assert_eq!(conflict["at"], "router r");

    let mut app = two_service_app(
        "a",
        "t1",
        json!([router("r", json!({"host": "a.test"}), "web")]),
        &mut ups,
    )
    .await;
    app["tcp"] = json!({
        "routers": [{"name": "t", "entry_points": ["pg"], "service": "s", "rule": "Host(`a.test`)"}],
        "services": [{"name": "s", "type": "loadbalancer", "servers": [{"address": "127.0.0.1:9"}]}],
    });
    let mut pushed = snapshot(2, &[app]);
    pushed["entry_points"] = json!([{"name": "pg", "tenants": ["t1"]}]);
    let conflict = refused(&podgate, &pushed).await;
    assert_eq!(conflict["code"], "invalid_rule", "{conflict}");
    assert_eq!(conflict["at"], "tcp router t");
}

/// A tenant with only `HostRegexp` would match every host nobody claims.
#[tokio::test]
async fn rule_hostregexp_alone_catch_all_refused() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    for rule in [
        "HostRegexp(`.*`)",
        "HostRegexp(`^.*\\.a\\.test$`)",
        "HostRegexp(`^a\\.test$`) || PathPrefix(`/`)",
        "Host(`a.test`) || HostRegexp(`.*`)",
        "PathPrefix(`/api`)",
    ] {
        let app = two_service_app("b", "t2", json!([by_rule("r", rule, "web")]), &mut ups).await;
        let conflict = refused(&podgate, &with_tenant_2(snapshot(1, &[app]))).await;
        assert_eq!(
            conflict["code"], "catch_all_not_allowed",
            "{rule}: {conflict}"
        );
        assert_eq!(conflict["at"], "router r", "{rule}");
    }
    // The same tree is refused the same way.
    let app = two_service_app(
        "b",
        "t2",
        json!([router("r", json!({"host_regexp": ".*"}), "web")]),
        &mut ups,
    )
    .await;
    let conflict = refused(&podgate, &with_tenant_2(snapshot(1, &[app]))).await;
    assert_eq!(conflict["code"], "catch_all_not_allowed");
    // On an entry point that admits the tenant alone, the rule is accepted.
    let mut exclusive = two_service_app(
        "b",
        "t2",
        json!([by_rule("r", "HostRegexp(`.*`)", "web")]),
        &mut ups,
    )
    .await;
    exclusive["routers"][0]["entry_points"] = json!(["web"]);
    let mut pushed = with_tenant_2(snapshot(2, &[exclusive]));
    pushed["entry_points"] = json!([{"name": "web", "tenants": ["t2"]}]);
    let accepted = podgate.push_snapshot(&pushed).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(podgate.get("elsewhere.test", "/").await.body, "web");
}

#[tokio::test]
async fn rule_hostregexp_narrowing_accepted() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let app = two_service_app(
        "acme",
        "t1",
        json!([by_rule(
            "preview",
            "Host(`*.preview.acme.test`) && HostRegexp(`^pr-[0-9]+\\.preview\\.acme\\.test$`)",
            "hit"
        )]),
        &mut ups,
    )
    .await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[app])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(
        podgate.get("pr-42.preview.acme.test", "/").await.body,
        "hit"
    );
    assert_eq!(podgate.get("main.preview.acme.test", "/").await.status, 404);
    assert_eq!(podgate.get("pr-42.other.acme.test", "/").await.status, 404);

    // An alternation in the regexp cannot widen the claim to a host nobody claims.
    let app = two_service_app(
        "acme",
        "t1",
        json!([by_rule(
            "preview",
            "Host(`*.a.test`) && HostRegexp(`^(other\\.test|x\\.a\\.test)$`)",
            "hit"
        )]),
        &mut ups,
    )
    .await;
    assert_eq!(
        podgate.push_snapshot(&snapshot(2, &[app])).await.status,
        200
    );
    assert_eq!(podgate.get("x.a.test", "/").await.body, "hit");
    assert_eq!(podgate.get("other.test", "/").await.status, 404);
}

#[tokio::test]
async fn rule_foreign_host_conflicts() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let a = two_service_app(
        "a",
        "t1",
        json!([router(
            "r",
            json!({"host": ["a.test", "*.wild.test"]}),
            "web"
        )]),
        &mut ups,
    )
    .await;
    let b = two_service_app(
        "b",
        "t2",
        json!([by_rule("r", "Host(`a.test`)", "web")]),
        &mut ups,
    )
    .await;
    let conflict = refused(&podgate, &with_tenant_2(snapshot(1, &[a.clone(), b]))).await;
    assert_eq!(conflict["code"], "host_conflict", "{conflict}");

    let b = two_service_app(
        "b",
        "t2",
        json!([by_rule("r", "Host(`x.wild.test`) && Method(`GET`)", "web")]),
        &mut ups,
    )
    .await;
    let pushed = podgate
        .push_snapshot(&with_tenant_2(snapshot(2, &[a.clone(), b])))
        .await;
    assert_eq!(pushed.status, 422, "{}", pushed.body);
    assert_eq!(codes(&pushed.json()), ["cross_tenant_wildcard"]);

    // A disjunction cannot smuggle another tenant's host in either.
    let b = two_service_app(
        "b",
        "t2",
        json!([by_rule("r", "Host(`b.test`) || Host(`a.test`)", "web")]),
        &mut ups,
    )
    .await;
    let pushed = podgate
        .push_snapshot(&with_tenant_2(snapshot(3, &[a, b])))
        .await;
    assert_eq!(codes(&pushed.json()), ["host_conflict"]);
}

#[tokio::test]
async fn rule_default_priority_is_length() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    // The tree router is more specific on the path, the rule router has a priority: the rule
    // router's 14 beats the tree's default 0.
    let routers = json!([
        router(
            "tree",
            json!({"all": [{"host": "a.test"}, {"path": "/exact"}]}),
            "web"
        ),
        by_rule("short", "Host(`a.test`)", "hit"),
    ]);
    let app = two_service_app("a", "t1", routers, &mut ups).await;
    assert_eq!(
        podgate.push_snapshot(&snapshot(1, &[app])).await.status,
        200
    );
    assert_eq!(podgate.get("a.test", "/exact").await.body, "hit");
    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/exact")
        .await
        .json();
    assert_eq!(explained["matched"]["priority"], 14);
    assert_eq!(explained["matched"]["router"], "short");

    // Between two rules the longer one wins, as in Traefik.
    let routers = json!([
        by_rule("short", "Host(`a.test`)", "web"),
        by_rule("long", "Host(`a.test`) && PathPrefix(`/`)", "hit"),
    ]);
    let app = two_service_app("a", "t1", routers, &mut ups).await;
    assert_eq!(
        podgate.push_snapshot(&snapshot(2, &[app])).await.status,
        200
    );
    assert_eq!(podgate.get("a.test", "/anything").await.body, "hit");
    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/anything")
        .await
        .json();
    assert_eq!(explained["matched"]["priority"], 33);

    // A router with a match keeps the platform default of 0.
    let app = two_service_app(
        "a",
        "t1",
        json!([router("tree", json!({"host": "a.test"}), "web")]),
        &mut ups,
    )
    .await;
    assert_eq!(
        podgate.push_snapshot(&snapshot(3, &[app])).await.status,
        200
    );
    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/")
        .await
        .json();
    assert_eq!(explained["matched"]["priority"], 0);
}

#[tokio::test]
async fn rule_explicit_priority_wins() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let mut long = by_rule("long", "Host(`a.test`) && PathPrefix(`/`)", "hit");
    long["priority"] = json!(1);
    let mut short = by_rule("short", "Host(`a.test`)", "web");
    short["priority"] = json!(100);
    let app = two_service_app("a", "t1", json!([long, short]), &mut ups).await;
    assert_eq!(
        podgate.push_snapshot(&snapshot(1, &[app])).await.status,
        200
    );
    assert_eq!(podgate.get("a.test", "/x").await.body, "web");
    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/x")
        .await
        .json();
    assert_eq!(explained["matched"]["priority"], 100);
    assert_eq!(explained["considered"], json!(["short", "long"]));
}

#[tokio::test]
async fn rule_priority_does_not_cross_tenants() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let a = two_service_app(
        "a",
        "t1",
        json!([by_rule("r", "Host(`a.test`)", "web")]),
        &mut ups,
    )
    .await;
    // The longest rule there is cannot take `a.test` from tenant t1.
    let padding = " ".repeat(1900);
    let greedy = format!("Host(`a.test`){padding}");
    let b = two_service_app("b", "t2", json!([by_rule("r", &greedy, "hit")]), &mut ups).await;
    let conflict = refused(&podgate, &with_tenant_2(snapshot(1, &[a.clone(), b]))).await;
    assert_eq!(conflict["code"], "host_conflict", "{conflict}");

    // Each tenant's own host goes to it whatever the length of the other's rules.
    let b = two_service_app(
        "b",
        "t2",
        json!([by_rule("r", &format!("Host(`b.test`){padding}"), "hit")]),
        &mut ups,
    )
    .await;
    let pushed = podgate
        .push_snapshot(&with_tenant_2(snapshot(2, &[a, b])))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(podgate.get("a.test", "/").await.body, "web");
    assert_eq!(podgate.get("b.test", "/").await.body, "hit");
    assert_eq!(podgate.get("c.test", "/").await.status, 404);
}

/// A TCP server that sends `tag\n` and closes.
async fn greeter(tag: &'static str) -> std::net::SocketAddr {
    use tokio::io::AsyncWriteExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(format!("{tag}\n").as_bytes()).await;
        }
    });
    addr
}

fn tcp_app(server: std::net::SocketAddr, router: &Value) -> Value {
    let mut app = app("t", &["t.test"], &[]);
    app["routers"] = json!([]);
    let mut config = json!({"name": "r", "entry_points": ["pg"], "service": "svc"});
    config
        .as_object_mut()
        .expect("object")
        .extend(router.as_object().expect("router").clone());
    app["tcp"] = json!({
        "routers": [config],
        "services": [{"name": "svc", "type": "loadbalancer", "servers": [{"address": server.to_string()}]}],
    });
    app
}

fn reserved(version: u64, app: Value) -> Value {
    let mut pushed = snapshot(version, &[app]);
    pushed["entry_points"] = json!([{"name": "pg", "tenants": ["t1"]}]);
    pushed
}

/// What a connection to the `pg` entry point reads before it ends.
async fn read_all(podgate: &Podgate) -> String {
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(podgate.entry_addr("pg")),
    )
    .await
    .expect("connect in time")
    .expect("connect");
    let mut text = String::new();
    let _ = timeout(Duration::from_secs(5), stream.read_to_string(&mut text)).await;
    text
}

#[tokio::test]
async fn rule_tcp_dialect() {
    let podgate = Podgate::start_with_entry_points(&[("web", "http"), ("pg", "tcp")], &[]).await;
    let server = greeter("A").await;

    // `ClientIP` is in both dialects; the test client is 127.0.0.1.
    for (version, rule, served) in [
        (1, "ClientIP(`127.0.0.0/8`)", "A\n"),
        (2, "ClientIP(`10.0.0.0/8`)", ""),
        (3, "!ClientIP(`10.0.0.0/8`)", "A\n"),
        (4, "HostSNI(`*`)", "A\n"),
        (5, "HostSNI(`*`) && ClientIP(`127.0.0.1`)", "A\n"),
    ] {
        let pushed = podgate
            .push_snapshot(&reserved(version, tcp_app(server, &json!({"rule": rule}))))
            .await;
        assert_eq!(pushed.status, 200, "{rule}: {}", pushed.body);
        assert_eq!(read_all(&podgate).await, served, "{rule}");
    }

    // The L4 functions that read the ClientHello need `tls`, exactly like the tree leaves.
    let reading = json!({"rule": "HostSNI(`a.test`) && ALPN(`h2`)"});
    let conflict = refused(&podgate, &reserved(6, tcp_app(server, &reading))).await;
    assert_eq!(conflict["code"], "invalid_router", "{conflict}");
    let passthrough =
        json!({"rule": "HostSNI(`a.test`) && ALPN(`h2`)", "tls": {"passthrough": true}});
    let pushed = podgate
        .push_snapshot(&reserved(7, tcp_app(server, &passthrough)))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let regexp = json!({"rule": "HostSNIRegexp(`^.*\\.a\\.test$`)", "tls": {"passthrough": true}});
    let pushed = podgate
        .push_snapshot(&reserved(8, tcp_app(server, &regexp)))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    // A rule that is not supported is refused with its position.
    let bad =
        json!({"rule": "HostSNI(`a.test`) && Headers(`x`, `y`)", "tls": {"passthrough": true}});
    let conflict = refused(&podgate, &reserved(9, tcp_app(server, &bad))).await;
    assert_eq!(conflict["code"], "unsupported_rule", "{conflict}");
    assert_eq!(conflict["at"], "tcp router r");
    assert_eq!(conflict["position"], 21);
}

#[tokio::test]
async fn explain_shows_rule_and_tree() {
    let podgate = Podgate::start().await;
    let mut ups = Vec::new();
    let rule = "Host(`a.test`) && !PathPrefix(`/admin`)";
    let routers = json!([by_rule("site", rule, "web")]);
    let app = two_service_app("a", "t1", routers, &mut ups).await;
    assert_eq!(
        podgate.push_snapshot(&snapshot(1, &[app])).await.status,
        200
    );
    let explained = podgate.admin_get("/v1/explain?url=http://a.test/x").await;
    assert_eq!(explained.status, 200, "{}", explained.body);
    let matched = explained.json()["matched"].clone();
    assert_eq!(
        matched,
        json!({
            "router": "site", "priority": rule.len(), "pattern": "a.test", "kind": "exact",
            "rule": rule,
            "match": {"all": [{"host": "a.test"}, {"not": {"path_prefix": "/admin"}}]},
        })
    );
    let denied = podgate
        .admin_get("/v1/explain?url=http://a.test/admin/x")
        .await;
    assert_eq!(denied.status, 404, "{}", denied.body);

    // A router with a `match` shows neither field.
    let app = two_service_app(
        "a",
        "t1",
        json!([router("site", json!({"host": "a.test"}), "web")]),
        &mut ups,
    )
    .await;
    assert_eq!(
        podgate.push_snapshot(&snapshot(2, &[app])).await.status,
        200
    );
    let matched = podgate
        .admin_get("/v1/explain?url=http://a.test/x")
        .await
        .json()["matched"]
        .clone();
    assert!(
        matched.get("rule").is_none() && matched.get("match").is_none(),
        "{matched}"
    );
}

#[tokio::test]
async fn plan_ignores_equivalent_rule_rewrite() {
    let podgate = Podgate::start().await;
    let (web, hit) = (Upstream::start("web").await, Upstream::start("hit").await);
    let candidate = |rule: &str, priority: Option<i32>| {
        let mut declared = by_rule("site", rule, "web");
        if let Some(priority) = priority {
            declared["priority"] = json!(priority);
        }
        app_on("a", "t1", json!([declared]), web.addr, hit.addr)
    };
    let plan = |version: u64, app: Value| {
        let podgate = &podgate;
        async move {
            let response = podgate
                .admin_post("/v1/snapshot/plan", &snapshot(version, &[app]))
                .await;
            assert_eq!(response.status, 200, "{}", response.body);
            response.json()
        }
    };
    let live = candidate("Host(`a.test`) && Method(`GET`, `POST`)", Some(10));
    assert_eq!(
        podgate.push_snapshot(&snapshot(1, &[live])).await.status,
        200
    );

    // Spacing, the order of the arguments and of the operands, redundant parentheses: the same
    // meaning, so nothing changed.
    for rule in [
        "Host( `a.test` )   &&   Method(`GET`,`POST`)",
        "Host(`a.test`) && Method(`POST`, `GET`)",
        "Method(`GET`, `POST`) && Host(`a.test`)",
        "(Method(`POST`, `GET`)) && (Host(`a.test`))",
    ] {
        let planned = plan(2, candidate(rule, Some(10))).await;
        assert_eq!(
            [&planned["added"], &planned["removed"], &planned["changed"]],
            [&json!([]), &json!([]), &json!([])],
            "{rule}: {planned}"
        );
    }

    // A different meaning is a change, and so is a different priority.
    for (rule, priority) in [
        ("Host(`a.test`) && Method(`GET`)", 10),
        ("Host(`a.test`) && Method(`GET`, `POST`)", 11),
    ] {
        let planned = plan(2, candidate(rule, Some(priority))).await;
        assert_eq!(
            planned["changed"],
            json!(["a.test"]),
            "{rule}/{priority}: {planned}"
        );
    }

    // Without a priority the rule's length is one, so a spacing-only rewrite that changes the
    // length changes the order the router takes: it is a change.
    let pushed = podgate
        .push_snapshot(&snapshot(2, &[candidate("Host(`a.test`)", None)]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let planned = plan(3, candidate("Host(`a.test` )", None)).await;
    assert_eq!(planned["changed"], json!(["a.test"]), "{planned}");
    let planned = plan(3, candidate("Host(`a.test`)", None)).await;
    assert_eq!(planned["changed"], json!([]), "{planned}");
}
