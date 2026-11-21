//! Named entry points: `ENTRY_POINTS` listeners, routers scoped to them, per-tenant
//! access, explain, and the startup errors.

mod common;

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use serde_json::{Value, json};

const LISTENERS: [(&str, &str); 3] = [
    ("public", "http"),
    ("internal", "http"),
    ("secure", "https"),
];

/// `snapshot` with a second tenant, `t2`.
fn two_tenants(version: u64, apps: &[Value]) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["tenants"]
        .as_array_mut()
        .expect("tenants")
        .push(json!({
            "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 },
        }));
    pushed
}

/// `app` with its only router listening on `names`.
fn on(mut app: Value, names: &[&str]) -> Value {
    app["routers"][0]["entry_points"] = json!(names);
    app
}

fn codes(body: &Value) -> Vec<String> {
    body["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code").to_owned())
        .collect()
}

/// An app of tenant `tenant` whose only router matches every host.
fn catch_all(id: &str, tenant: &str, up: &Upstream, names: &[&str]) -> Value {
    let mut catch_all = app(id, &["unused.test"], &[serving("r1", up.addr)]);
    catch_all["tenant"] = json!(tenant);
    catch_all["routers"] = json!([common::router("all", json!({ "host_regexp": ".*" }), "web")]);
    on(catch_all, names)
}

#[tokio::test]
async fn entry_point_scopes_routers() {
    let podgate = Podgate::start_with_entry_points(&LISTENERS, &[]).await;
    let (p, i, s) = (
        Upstream::start("p").await,
        Upstream::start("i").await,
        Upstream::start("s").await,
    );
    let cert = TestCert::new(&["s.test"]);
    let mut pushed = snapshot(
        1,
        &[
            on(app("p", &["p.test"], &[serving("r1", p.addr)]), &["public"]),
            on(
                app("i", &["i.test"], &[serving("r1", i.addr)]),
                &["internal"],
            ),
            on(app("s", &["s.test"], &[serving("r1", s.addr)]), &["secure"]),
        ],
    );
    pushed["certificates"] = json!([cert.entry(&["s.test"])]);
    let accepted = podgate.push_snapshot(&pushed).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);

    assert_eq!(podgate.get_on("internal", "i.test", "/").await.body, "i");
    assert_eq!(podgate.get_on("public", "p.test", "/").await.body, "p");
    for (entry, host) in [
        ("public", "i.test"),
        ("public", "s.test"),
        ("internal", "p.test"),
        ("internal", "s.test"),
    ] {
        let response = podgate.get_on(entry, host, "/").await;
        assert_eq!(response.status, 404, "{host} on {entry}: {response:?}");
    }
    let secure = podgate.https_get("s.test", "s.test", "/", &cert).await;
    assert_eq!((secure.status, secure.body.as_str()), (200, "s"));
    let wrong = podgate.https_get("s.test", "i.test", "/", &cert).await;
    assert_eq!(wrong.status, 421, "{wrong:?}");
}

#[tokio::test]
async fn router_without_entry_points_is_everywhere() {
    let podgate = Podgate::start_with_entry_points(&LISTENERS, &[]).await;
    let up = Upstream::start("all").await;
    let cert = TestCert::new(&["all.test"]);
    let mut pushed = snapshot(1, &[app("all", &["all.test"], &[serving("r1", up.addr)])]);
    pushed["certificates"] = json!([cert.entry(&["all.test"])]);
    let accepted = podgate.push_snapshot(&pushed).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);

    for entry in ["public", "internal"] {
        let response = podgate.get_on(entry, "all.test", "/").await;
        assert_eq!(response.body, "all", "{entry}");
    }
    let secure = podgate.https_get("all.test", "all.test", "/", &cert).await;
    assert_eq!(secure.body, "all");
}

/// Runs the binary with `env` and returns its exit code and stderr; it must stop on its own.
fn startup_failure(env: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_podgate"));
    command
        .env_remove("PROXY_ADDR")
        .env_remove("PROXY_TLS_ADDR")
        .env_remove("ENTRY_POINTS")
        .env("RUST_LOG", "warn")
        .envs(env.iter().copied());
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run podgate");
    // A listener that starts instead of failing would run for ever, so a missing refusal is a
    // failed test, not a hung one.
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for podgate") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("podgate with {env:?} did not stop on its own within 20 seconds");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    (status.code(), stderr)
}

#[test]
fn entry_points_conflict_with_proxy_addr() {
    for shorthand in ["PROXY_ADDR", "PROXY_TLS_ADDR"] {
        let (code, stderr) = startup_failure(&[
            ("ENTRY_POINTS", "web=127.0.0.1:18080/http"),
            (shorthand, "127.0.0.1:18081"),
        ]);
        assert_eq!(code, Some(1), "{shorthand}: {stderr}");
        assert!(
            stderr.contains("ENTRY_POINTS") && stderr.contains(shorthand),
            "{shorthand}: {stderr}"
        );
    }
}

#[test]
fn entry_points_invalid_values() {
    for bad in [
        "web=nope/http",
        "web=127.0.0.1:18080/ftp",
        "web=127.0.0.1:18080",
        "a=127.0.0.1:18080/http,a=127.0.0.1:18081/http",
        "web=127.0.0.1:18080/http;tls",
    ] {
        let (code, stderr) = startup_failure(&[("ENTRY_POINTS", bad)]);
        assert_eq!(code, Some(1), "{bad}: {stderr}");
        assert!(
            stderr.contains("invalid ENTRY_POINTS") && stderr.contains("entry \""),
            "{bad}: {stderr}"
        );
    }

    // The parser accepts tcp and udp. Starting a tcp entry point waits for the spec that builds
    // it, and a udp one cannot take the PROXY protocol; the error names the entry point.
    for (value, name) in [
        ("web=127.0.0.1:18080/http,db=127.0.0.1:15432/tcp", "db"),
        ("dns=127.0.0.1:15353/udp;proxy_protocol", "dns"),
    ] {
        let (code, stderr) = startup_failure(&[
            ("ENTRY_POINTS", value),
            ("ADMIN_SOCKET", "/tmp/podgate-entry-points-unused.sock"),
        ]);
        assert_eq!(code, Some(1), "{value}: {stderr}");
        assert!(
            stderr.contains(&format!("entry point {name}")),
            "{value}: {stderr}"
        );
    }
}

#[tokio::test]
async fn unknown_entry_point_rejected() {
    let podgate = Podgate::start_with_entry_points(&LISTENERS, &[]).await;
    let up = Upstream::start("a").await;
    // `web` is the default name; this node bound others, so a snapshot written for the default
    // fails closed.
    let refused = podgate
        .push_snapshot(&snapshot(
            1,
            &[on(
                app("a", &["a.test"], &[serving("r1", up.addr)]),
                &["web"],
            )],
        ))
        .await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(codes(&refused.json()), ["unknown_entry_point"]);

    let mut policy = snapshot(2, &[app("a", &["a.test"], &[serving("r1", up.addr)])]);
    policy["entry_points"] = json!([{ "name": "websecure", "tenants": ["t1"] }]);
    let refused = podgate.push_snapshot(&policy).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(codes(&refused.json()), ["unknown_entry_point"]);

    assert_eq!(podgate.get_on("public", "a.test", "/").await.status, 404);
}

#[tokio::test]
async fn exclusive_entry_point_allows_catch_all() {
    let podgate = Podgate::start_with_entry_points(&LISTENERS, &[]).await;
    let up = Upstream::start("fallback").await;
    let mut pushed = two_tenants(1, &[catch_all("fb", "t1", &up, &["internal"])]);
    pushed["entry_points"] = json!([{ "name": "internal", "tenants": ["t1"] }]);
    let accepted = podgate.push_snapshot(&pushed).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);

    let any = podgate.get_on("internal", "never-claimed.test", "/").await;
    assert_eq!(any.body, "fallback");
    assert_eq!(
        podgate
            .get_on("public", "never-claimed.test", "/")
            .await
            .status,
        404
    );
}

#[tokio::test]
async fn shared_entry_point_refuses_catch_all() {
    let podgate = Podgate::start_with_entry_points(&LISTENERS, &[]).await;
    let up = Upstream::start("fallback").await;
    // `public` has no policy, and `internal` names two tenants: neither is exclusive to t1.
    let mut shared = two_tenants(1, &[catch_all("fb", "t1", &up, &["internal"])]);
    shared["entry_points"] = json!([{ "name": "internal", "tenants": ["t1", "t2"] }]);
    for pushed in [
        two_tenants(1, &[catch_all("fb", "t1", &up, &["public"])]),
        shared,
    ] {
        let refused = podgate.push_snapshot(&pushed).await;
        assert_eq!(refused.status, 422, "{}", refused.body);
        assert_eq!(codes(&refused.json()), ["catch_all_not_allowed"]);
    }
}

#[tokio::test]
async fn entry_point_forbidden_for_other_tenant() {
    let podgate = Podgate::start_with_entry_points(&LISTENERS, &[]).await;
    let (a, b) = (Upstream::start("a").await, Upstream::start("b").await);
    let mut intruder = app("b", &["b.test"], &[serving("r1", b.addr)]);
    intruder["tenant"] = json!("t2");
    let mut pushed = two_tenants(
        1,
        &[
            on(
                app("a", &["a.test"], &[serving("r1", a.addr)]),
                &["internal"],
            ),
            on(intruder, &["internal"]),
        ],
    );
    pushed["entry_points"] = json!([{ "name": "internal", "tenants": ["t1"] }]);
    let refused = podgate.push_snapshot(&pushed).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(codes(&refused.json()), ["entry_point_forbidden"]);

    // Without the intruder the snapshot is accepted, and a router that lists no entry point
    // skips the entry point that does not admit its tenant.
    let mut open = app("b", &["b.test"], &[serving("r1", b.addr)]);
    open["tenant"] = json!("t2");
    let mut allowed = two_tenants(
        2,
        &[
            on(
                app("a", &["a.test"], &[serving("r1", a.addr)]),
                &["internal"],
            ),
            open,
        ],
    );
    allowed["entry_points"] = json!([{ "name": "internal", "tenants": ["t1"] }]);
    let accepted = podgate.push_snapshot(&allowed).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(podgate.get_on("internal", "a.test", "/").await.body, "a");
    assert_eq!(podgate.get_on("internal", "b.test", "/").await.status, 404);
    assert_eq!(podgate.get_on("public", "b.test", "/").await.body, "b");
}

#[tokio::test]
async fn explain_filters_by_entry_point() {
    let podgate = Podgate::start_with_entry_points(&LISTENERS, &[]).await;
    let up = Upstream::start("i").await;
    let accepted = podgate
        .push_snapshot(&snapshot(
            1,
            &[
                on(
                    app("i", &["i.test"], &[serving("r1", up.addr)]),
                    &["internal"],
                ),
                app("all", &["all.test"], &[serving("r1", up.addr)]),
            ],
        ))
        .await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);

    // No entry point asked: the entry points of the URL's scheme are tried in order.
    let found = podgate.admin_get("/v1/explain?url=http://i.test/").await;
    assert_eq!(found.status, 200, "{found:?}");
    assert_eq!(found.json()["entry_point"], "internal");
    assert_eq!(found.json()["reachable_on"], json!(["internal"]));

    let named = podgate
        .admin_get("/v1/explain?url=http://i.test/&entry_point=internal")
        .await;
    assert_eq!(named.status, 200, "{named:?}");

    let elsewhere = podgate
        .admin_get("/v1/explain?url=http://i.test/&entry_point=public")
        .await;
    assert_eq!(elsewhere.status, 404, "{elsewhere:?}");
    assert_eq!(
        elsewhere.json(),
        json!({"error": "not found", "nearest_wildcard": null, "routed_on": ["internal"]})
    );

    let everywhere = podgate.admin_get("/v1/explain?url=http://all.test/").await;
    assert_eq!(everywhere.json()["entry_point"], "public");
    assert_eq!(
        everywhere.json()["reachable_on"],
        json!(["public", "internal", "secure"])
    );

    let unbound = podgate
        .admin_get("/v1/explain?url=http://i.test/&entry_point=web")
        .await;
    assert_eq!(unbound.status, 400, "{unbound:?}");
    assert!(
        unbound.json()["error"]
            .as_str()
            .is_some_and(|e| e.contains("web"))
    );
}

#[tokio::test]
async fn router_reachable_nowhere_rejected() {
    let podgate = Podgate::start_with_entry_points(&LISTENERS, &[]).await;
    let up = Upstream::start("b").await;
    let mut tenant_b = app("b", &["b.test"], &[serving("r1", up.addr)]);
    tenant_b["tenant"] = json!("t2");
    // Every http and https entry point admits t1 alone, so a t2 router that lists none would
    // serve nothing.
    let mut pushed = two_tenants(1, &[tenant_b.clone()]);
    pushed["entry_points"] = json!(
        LISTENERS
            .iter()
            .map(|(name, _)| json!({ "name": name, "tenants": ["t1"] }))
            .collect::<Vec<_>>()
    );
    let refused = podgate.push_snapshot(&pushed).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(codes(&refused.json()), ["no_reachable_entry_point"]);
    let message = refused.json()["conflicts"][0]["message"].to_string();
    assert!(
        message.contains("router default") && message.contains("t2"),
        "{message}"
    );

    // Naming the entry points explicitly is `entry_point_forbidden` instead.
    pushed["apps"] = json!([on(tenant_b, &["public", "internal"])]);
    let refused = podgate.push_snapshot(&pushed).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(
        codes(&refused.json()),
        ["entry_point_forbidden", "entry_point_forbidden"]
    );
}
