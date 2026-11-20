//! `GET /v1/overview` through the real binary: what is configured and how it is
//! doing, read from the live table and the runtime registries, with no secret and no way to
//! change anything.

mod common;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{
    Podgate, TestCa, TestCert, Upstream, app, revision, revision_on, router, serving, snapshot,
    with_middleware,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::Notify;
use tokio::time::{Instant, sleep};

/// A backend that answers every request with `status` after `delay`, and signals `entered` when
/// a request reaches it.
struct Backend {
    addr: SocketAddr,
    entered: Arc<Notify>,
}

impl Backend {
    async fn start(status: u16, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let entered = Arc::new(Notify::new());
        let signal = Arc::clone(&entered);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let signal = Arc::clone(&signal);
                tokio::spawn(async move {
                    let mut seen = Vec::new();
                    let mut chunk = [0_u8; 1024];
                    loop {
                        while let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                            seen.drain(..end + 4);
                            signal.notify_one();
                            sleep(delay).await;
                            let reply =
                                format!("HTTP/1.1 {status} X\r\nContent-Length: 2\r\n\r\nok");
                            if stream.write_all(reply.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => seen.extend_from_slice(&chunk[..read]),
                        }
                    }
                });
            }
        });
        Self { addr, entered }
    }
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let pushed = podgate.push_snapshot(snapshot).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
}

async fn overview(podgate: &Podgate, query: &str) -> Value {
    let answer = podgate.admin_get(&format!("/v1/overview{query}")).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(answer.header("content-type"), Some("application/json"));
    answer.json()
}

fn items<'a>(document: &'a Value, section: &str) -> &'a [Value] {
    document[section]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("no {section} items in {document}"))
}

fn ids(document: &Value) -> Vec<&str> {
    items(document, "apps")
        .iter()
        .map(|item| item["id"].as_str().expect("id"))
        .collect()
}

fn app_of<'a>(document: &'a Value, id: &str) -> &'a Value {
    items(document, "apps")
        .iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("no app {id} in {document}"))
}

/// `a.test` with two routers and a `headers` middleware in the default chain.
fn rich_app(addr: SocketAddr) -> Value {
    let mut rich = with_middleware(
        app("a", &["a.test"], &[serving("r1", addr)]),
        "h",
        "headers",
        json!({"response": {"set": {"x-served-by": "podgate"}}}),
    );
    rich["routers"] = json!([
        router(
            "api",
            json!({"all": [{"host": "a.test"}, {"path_prefix": "/api"}]}),
            "web"
        ),
        router("site", json!({"host": ["a.test", "*.a.test"]}), "web"),
    ]);
    rich["routers"][0]["priority"] = json!(5);
    rich
}

#[tokio::test]
async fn overview_lists_apps_routers_services() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let cert = TestCert::new(&["a.test"]);
    let mut pushed = snapshot(
        7,
        &[rich_app(upstream.addr), {
            let mut other = app("b", &["b.test"], &[serving("r1", upstream.addr)]);
            other["tenant"] = json!("t2");
            other
        }],
    );
    pushed["tenants"].as_array_mut().expect("tenants").push(
        json!({"id": "t2", "weight": 3, "budget": {"max_inflight": 5, "max_buffer_bytes": 4096}}),
    );
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    push(&podgate, &pushed).await;

    let document = overview(&podgate, "").await;

    let summary = &document["summary"];
    assert_eq!(summary["version"], 7);
    assert!(
        summary["applied_at"]
            .as_u64()
            .is_some_and(|at| at > 1_700_000_000)
    );
    assert!(summary["boot_id"].as_str().is_some_and(|id| !id.is_empty()));
    assert_eq!(
        (
            summary["tenants"].clone(),
            summary["apps"].clone(),
            summary["routers"].clone()
        ),
        (json!(2), json!(2), json!(3))
    );
    assert_eq!(summary["services"], 2);
    assert_eq!(
        summary["servers"],
        json!({"healthy": 2, "unhealthy": 0, "ejected": 0})
    );

    let tenants = items(&document, "tenants");
    assert_eq!(document["tenants"]["total"], 2);
    assert_eq!(tenants[0]["id"], "t1");
    assert_eq!(tenants[0]["apps"], 1);
    assert_eq!(tenants[1]["weight"], 3);
    assert_eq!(
        tenants[1]["budget"],
        json!({"max_inflight": 5, "max_buffer_bytes": 4096})
    );
    assert_eq!(tenants[1]["inflight"], 0);

    assert_eq!(ids(&document), ["a", "b"]);
    let a = app_of(&document, "a");
    assert_eq!(
        (a["tenant"].clone(), a["declared_by"].clone()),
        (json!("t1"), json!("tests/a"))
    );
    assert_eq!(
        a["tls"],
        json!({"mode": "acme", "challenge": "http-01", "client_auth": false, "pass_client_cert": false})
    );
    assert_eq!(a["hosts"], json!(["a.test", "*.a.test"]));
    assert_eq!(
        a["routers"][0],
        json!({"name": "api", "declared_by": "tests/a",
               "match": {"all": [{"host": "a.test"}, {"path_prefix": "/api"}]},
               "priority": 5, "chain": ["h"], "service": "web"})
    );
    assert_eq!(a["routers"][1]["name"], "site");
    assert_eq!(
        a["revisions"][0],
        json!({"id": "r1", "state": "serving", "weight": 100, "effective_weight": 100,
               "inflight": 0, "recent": {"window_secs": 300, "requests": 0, "errors_5xx": 0}})
    );
    assert_eq!(
        a["services"],
        json!([{"name": "web", "revision": "r1", "type": "loadbalancer",
                "algorithm": "round_robin",
                "servers": [{"url": format!("http://{}", upstream.addr), "weight": 1,
                             "available": true, "active": 0}]}])
    );
    assert_eq!(a["middlewares"].as_array().map(Vec::len), Some(1));
    assert_eq!(a["middlewares"][0]["name"], "h");
    assert_eq!(a["middlewares"][0]["type"], "headers");
    assert_eq!(
        a["middlewares"][0]["config"]["response"]["set"],
        json!(["x-served-by"])
    );

    let entries = document["entry_points"].as_array().expect("entry points");
    assert_eq!(entries[0]["name"], "web");
    assert_eq!(entries[0]["protocol"], "http");
    assert_eq!(entries[0]["address"], podgate.proxy_addr.to_string());
    assert_eq!(entries[0]["forwarded_headers"], "nobody");
    assert_eq!(entries[1]["name"], "websecure");
    assert_eq!(entries[1]["protocol"], "https");

    let certificates = items(&document, "certificates");
    assert_eq!(certificates.len(), 1);
    assert_eq!(certificates[0]["hosts"], json!(["a.test"]));
    assert_eq!(certificates[0]["source"], "snapshot");
    assert!(
        certificates[0]["not_after"]
            .as_i64()
            .is_some_and(|at| at > 1_700_000_000)
    );
    assert!(certificates[0]["issuer"].is_string());
    assert!(certificates[0].get("cert_pem").is_none() && certificates[0].get("key_pem").is_none());
}

#[tokio::test]
async fn overview_matches_explain() {
    let podgate = Podgate::start().await;
    let (old, new) = (Upstream::start("o").await, Upstream::start("n").await);
    let mut a = app(
        "a",
        &["a.test"],
        &[
            revision("r1", old.addr, 30, "retiring"),
            revision("r2", new.addr, 70, "serving"),
        ],
    );
    a["routers"][0]["priority"] = json!(3);
    push(&podgate, &snapshot(4, &[a])).await;

    let explained = podgate
        .admin_get("/v1/explain?url=http://a.test/x")
        .await
        .json();
    let document = overview(&podgate, "?section=summary,apps").await;
    let shown = app_of(&document, "a");

    assert_eq!(shown["tenant"], explained["tenant"]);
    assert_eq!(shown["declared_by"], explained["declared_by"]);
    let router = &shown["routers"][0];
    assert_eq!(router["name"], explained["matched"]["router"]);
    assert_eq!(router["priority"], explained["matched"]["priority"]);
    assert_eq!(router["service"], explained["service"]);
    assert_eq!(document["summary"]["version"], explained["version"]);
    for (mine, theirs) in shown["revisions"]
        .as_array()
        .expect("revisions")
        .iter()
        .zip(explained["revisions"].as_array().expect("revisions"))
    {
        for field in ["id", "state", "weight", "effective_weight"] {
            assert_eq!(mine[field], theirs[field], "revision field {field}");
        }
    }
    let urls = |servers: &Value| -> Vec<String> {
        servers
            .as_array()
            .expect("servers")
            .iter()
            .map(|server| server["url"].as_str().expect("url").to_owned())
            .collect()
    };
    let service = &shown["services"][1];
    assert_eq!(service["revision"], "r2");
    assert_eq!(
        urls(&service["servers"]),
        urls(&explained["revisions"][1]["servers"])
    );
}

#[tokio::test]
async fn overview_includes_runtime_state() {
    let podgate = Podgate::start().await;
    let failing = Backend::start(502, Duration::ZERO).await;
    let fine = Backend::start(200, Duration::ZERO).await;
    let slow = Backend::start(200, Duration::from_secs(30)).await;
    let dead = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        probe.local_addr().expect("addr")
    };

    // `a` ejects its failing server, `b` health checks a dead one, `c` has a request in flight
    // and a circuit breaker, `d` a canary.
    let mut a = app(
        "a",
        &["a.test"],
        &[revision_on(
            "r1",
            &[failing.addr, fine.addr],
            100,
            "serving",
        )],
    );
    a["revisions"][0]["services"][0]["passive"] =
        json!({"consecutive_failures": 2, "ejection_secs": 60, "max_ejection_percent": 50});
    let mut b = app(
        "b",
        &["b.test"],
        &[revision_on("r1", &[dead], 100, "serving")],
    );
    b["revisions"][0]["services"][0]["health_check"] =
        json!({"path": "/healthz", "interval_secs": 1, "timeout_secs": 1});
    let c = with_middleware(
        app("c", &["c.test"], &[serving("r1", slow.addr)]),
        "cb",
        "circuit_breaker",
        json!({"trip_when": {"network_error_ratio": 0.5}}),
    );
    let mut d = app(
        "d",
        &["d.test"],
        &[
            revision("r1", slow.addr, 100, "serving"),
            revision("r2", slow.addr, 1, "serving"),
        ],
    );
    d["canary"] = json!({"revision": "r2", "step_percent": 10, "interval_secs": 3600, "max_error_permille": 500});
    push(&podgate, &snapshot(1, &[a, b, c, d])).await;

    // Round robin sends every other request to the failing server; two failures eject it.
    for _ in 0..6 {
        podgate.get("a.test", "/").await;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let document = overview(&podgate, "").await;
        let unhealthy = app_of(&document, "b")["services"][0]["servers"][0]["healthy"] == false;
        if unhealthy || Instant::now() > deadline {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    let held = {
        let podgate_addr = podgate.proxy_addr;
        tokio::spawn(async move {
            let mut stream = TcpStream::connect(podgate_addr).await.expect("connect");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: c.test\r\nConnection: close\r\n\r\n")
                .await
                .expect("send");
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).await.expect("read");
        })
    };
    slow.entered.notified().await;
    let document = overview(&podgate, "").await;

    let service = &app_of(&document, "a")["services"][0];
    assert_eq!(service["outlier_detection"], true);
    let ejected: Vec<&Value> = service["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .filter(|server| server.get("ejected_for_ms").is_some())
        .collect();
    assert_eq!(ejected.len(), 1, "{service}");
    assert!(
        ejected[0]["ejected_for_ms"]
            .as_u64()
            .is_some_and(|ms| ms > 0)
    );
    assert_eq!(ejected[0]["available"], false);
    assert_eq!(ejected[0]["url"], format!("http://{}", failing.addr));
    assert_eq!(app_of(&document, "a")["recent"]["errors_5xx"], 2);

    let probed = &app_of(&document, "b")["services"][0];
    assert_eq!(probed["health_check"], true);
    assert_eq!(probed["servers"][0]["healthy"], false, "{probed}");
    assert_eq!(probed["servers"][0]["available"], false);

    let busy = app_of(&document, "c");
    assert_eq!(busy["revisions"][0]["inflight"], 1);
    assert_eq!(busy["services"][0]["servers"][0]["active"], 1);
    assert_eq!(busy["middlewares"][0]["config"]["phase"], "closed");
    assert_eq!(items(&document, "tenants")[0]["inflight"], 1);

    let canary = &app_of(&document, "d")["canary"];
    assert_eq!(canary["revision"], "r2");
    assert_eq!(canary["regressed"], false);

    let summary = &document["summary"]["servers"];
    assert_eq!(summary["ejected"], 1);
    assert!(
        summary["unhealthy"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );

    held.abort();
}

#[tokio::test]
async fn overview_without_optional_features() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    push(
        &podgate,
        &snapshot(1, &[app("a", &["a.test"], &[serving("r1", upstream.addr)])]),
    )
    .await;

    let document = overview(&podgate, "").await;
    let text = document.to_string();
    for absent in [
        "\"healthy\":true",
        "\"healthy\":false",
        "ejected_for_ms",
        "\"canary\"",
        "health_check",
        "outlier_detection",
        "scale_to_zero",
        "\"writer\"",
        "\"truncated\"",
    ] {
        assert!(
            !text.contains(absent),
            "{absent} appears without its feature: {text}"
        );
    }
    assert_eq!(app_of(&document, "a")["middlewares"], json!([]));
    assert!(
        document["certificates"]["items"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
}

#[tokio::test]
async fn overview_redacts_secrets() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let ca = TestCa::new("secret-ca");
    let cert = TestCert::new(&["a.test"]);
    let password = "sentinel-password-hunter2";
    let hash = bcrypt::hash(password, 10).expect("bcrypt hash");
    let wasm = STANDARD.encode(
        wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "proxy_abi_version_0_2_1"))
              (func (export "proxy_on_memory_allocate") (param i32) (result i32) (i32.const 0))
              (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32) (i32.const 0)))"#,
        )
        .expect("valid WAT"),
    );

    let mut a = app("a", &["a.test"], &[serving("r1", upstream.addr)]);
    a["tls"]["client_ca_pem"] = json!(ca.pem);
    a["routers"] = json!([router(
        "keyed",
        json!({"all": [{"host": "a.test"}, {"header": {"name": "x-api-key", "value": "sentinel-matcher-key"}}]}),
        "web"
    )]);
    let a = with_middleware(
        a,
        "auth",
        "basic_auth",
        json!({"users": [format!("alice:{hash}")]}),
    );
    let a = with_middleware(
        a,
        "filter",
        "wasm",
        json!({"wasm_base64": wasm, "fuel": 1000, "max_memory_bytes": 65536}),
    );
    let a = with_middleware(
        a,
        "h",
        "headers",
        json!({"request": {"set": {"x-upstream-auth": "sentinel-header-value"}}}),
    );
    let mut pushed = snapshot(1, &[a]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    pushed["skew_secret"] = json!("sentinel-skew-secret-0123456789");
    pushed["acme"] = json!({
        "issuer_node": "some-other-node",
        "directory_url": "https://acme.invalid/directory",
        "account_key_pem": "sentinel-account-key",
        "challenges": [{"token": "tok-1", "key_authorization": "sentinel-key-authorization"}],
    });
    push(&podgate, &pushed).await;

    let body = podgate.admin_get("/v1/overview?limit=500").await.body;
    assert!(
        body.contains("\"basic_auth\""),
        "the middleware is listed: {body}"
    );
    let body_line = |pem: &str| pem.lines().nth(1).expect("a PEM body line").to_owned();
    for secret in [
        hash.as_str(),
        password,
        "sentinel-skew-secret-0123456789",
        "sentinel-account-key",
        "sentinel-key-authorization",
        "sentinel-matcher-key",
        "sentinel-header-value",
        wasm.as_str(),
        &wasm[..24],
        &body_line(&ca.pem),
        &body_line(&cert.key_pem),
        &body_line(&cert.cert_pem),
        "BEGIN",
        "client_ca_pem",
        "key_pem",
        "skew_secret",
    ] {
        assert!(
            !body.contains(secret),
            "{secret:?} is in the overview: {body}"
        );
    }
    let document: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(app_of(&document, "a")["tls"]["client_auth"], true);
    assert_eq!(
        app_of(&document, "a")["routers"][0]["match"]["all"][1],
        json!({"header": {"name": "x-api-key", "value": "[redacted]"}})
    );
    assert_eq!(
        app_of(&document, "a")["middlewares"][1]["config"],
        json!({"fuel": 1000, "max_memory_bytes": 65536})
    );
}

/// Apps `a0` to `a{count-1}`, each with one serving revision.
fn many_apps(count: usize, upstream: SocketAddr) -> Vec<Value> {
    (0..count)
        .map(|index| {
            let id = format!("a{index:03}");
            app(&id, &[&format!("{id}.test")], &[serving("r1", upstream)])
        })
        .collect()
}

#[tokio::test]
async fn overview_paginates() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    push(&podgate, &snapshot(1, &many_apps(7, upstream.addr))).await;

    let mut seen = Vec::new();
    let mut after = String::new();
    let mut pages = 0;
    loop {
        let document = overview(&podgate, &format!("?section=apps&limit=3{after}")).await;
        assert_eq!(document["apps"]["total"], 7);
        assert!(document.get("summary").is_none() && document.get("tenants").is_none());
        let page = ids(&document);
        assert!(page.len() <= 3);
        seen.extend(page.iter().map(|id| (*id).to_owned()));
        pages += 1;
        match document["apps"]["next"].as_str() {
            Some(next) => after = format!("&after={next}"),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    let expected: Vec<String> = (0..7).map(|index| format!("a{index:03}")).collect();
    assert_eq!(seen, expected);

    let default = overview(&podgate, "?section=apps").await;
    assert_eq!(ids(&default).len(), 7, "the default limit shows all 7");
    assert!(default["apps"].get("next").is_none());
    let bad = podgate.admin_get("/v1/overview?limit=0").await;
    assert_eq!(bad.status, 400);
    assert_eq!(bad.json(), json!({"error": "limit must be at least 1"}));
    assert_eq!(
        podgate
            .admin_get("/v1/overview?section=apps,nope")
            .await
            .status,
        400
    );
}

#[tokio::test]
async fn overview_filters_by_tenant_and_app() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let mut apps = many_apps(4, upstream.addr);
    for other in &mut apps[2..] {
        other["tenant"] = json!("t2");
    }
    let mut pushed = snapshot(1, &apps);
    pushed["tenants"].as_array_mut().expect("tenants").push(
        json!({"id": "t2", "weight": 1, "budget": {"max_inflight": 9, "max_buffer_bytes": 1}}),
    );
    push(&podgate, &pushed).await;

    let t2 = overview(&podgate, "?tenant=t2").await;
    assert_eq!(ids(&t2), ["a002", "a003"]);
    assert_eq!(t2["apps"]["total"], 2);
    assert_eq!(items(&t2, "tenants").len(), 1);
    assert_eq!(items(&t2, "tenants")[0]["id"], "t2");

    let one = overview(&podgate, "?app=a001&section=apps").await;
    assert_eq!(ids(&one), ["a001"]);

    let neither = overview(&podgate, "?tenant=t1&app=a003&section=apps").await;
    assert!(ids(&neither).is_empty());
    assert_eq!(neither["apps"]["total"], 0);

    let unknown = overview(&podgate, "?tenant=nobody").await;
    assert!(ids(&unknown).is_empty());
    assert!(items(&unknown, "tenants").is_empty());
    assert_eq!(
        unknown["summary"]["apps"], 4,
        "the summary counts the whole node"
    );
}

#[tokio::test]
async fn overview_size_bounded() {
    let podgate = Podgate::start().await;
    // 450 apps of 256 servers each: about 6 MiB of overview, more than one response may hold.
    let apps: Vec<Value> = (0..450)
        .map(|index| {
            let addrs: Vec<SocketAddr> = (0..256)
                .map(|server| SocketAddr::from(([127, 0, 0, 1], 10_000 + server)))
                .collect();
            let id = format!("a{index:03}");
            app(
                &id,
                &[&format!("{id}.test")],
                &[revision_on("r1", &addrs, 100, "serving")],
            )
        })
        .collect();
    push(&podgate, &snapshot(1, &apps)).await;

    let mut seen = HashSet::new();
    let mut after = String::new();
    let mut pages = 0;
    loop {
        let answer = podgate
            .admin_get(&format!("/v1/overview?section=apps&limit=500{after}"))
            .await;
        assert_eq!(answer.status, 200);
        assert!(
            answer.body.len() <= 4 * 1024 * 1024,
            "a response of {} bytes is over the cap",
            answer.body.len()
        );
        let document = answer.json();
        assert_eq!(document["apps"]["total"], 450);
        for id in ids(&document) {
            assert!(seen.insert(id.to_owned()), "{id} listed twice");
        }
        pages += 1;
        match document["apps"]["next"].as_str() {
            Some(next) => {
                assert_eq!(document["apps"]["truncated"], true);
                after = format!("&after={next}");
            }
            None => break,
        }
    }
    assert!(pages >= 2, "the cap made the listing take {pages} page");
    assert_eq!(seen.len(), 450);
}

#[tokio::test]
async fn overview_follows_swap_and_revert() {
    let podgate = Podgate::start().await;
    let good = Upstream::start("good").await;
    let dead = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        probe.local_addr().expect("addr")
    };
    push(
        &podgate,
        &snapshot(1, &[app("a", &["a.test"], &[serving("r1", good.addr)])]),
    )
    .await;
    let first = overview(&podgate, "").await;
    assert_eq!(first["summary"]["version"], 1);
    assert_eq!(app_of(&first, "a")["revisions"][0]["id"], "r1");

    let mut broken = snapshot(
        2,
        &[
            app("a", &["a.test"], &[serving("r2", dead)]),
            app("extra", &["extra.test"], &[serving("r1", good.addr)]),
        ],
    );
    broken["revert_window_secs"] = json!(20);
    push(&podgate, &broken).await;
    let swapped = overview(&podgate, "").await;
    assert_eq!(swapped["summary"]["version"], 2);
    assert_eq!(ids(&swapped), ["a", "extra"]);
    assert_eq!(app_of(&swapped, "a")["revisions"][0]["id"], "r2");
    assert_eq!(
        app_of(&swapped, "a")["services"][0]["servers"][0]["url"],
        format!("http://{dead}")
    );

    for _ in 0..30 {
        assert_eq!(podgate.get("a.test", "/").await.status, 502);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let reverted = loop {
        let document = overview(&podgate, "").await;
        if ids(&document) == ["a"] || Instant::now() > deadline {
            break document;
        }
        sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(
        ids(&reverted),
        ["a"],
        "the revert restored the first snapshot"
    );
    assert_eq!(app_of(&reverted, "a")["revisions"][0]["id"], "r1");
    assert_eq!(
        reverted["summary"]["version"], 2,
        "the live version never goes down"
    );
}

/// Sends `method path` on the admin socket and returns the status line, the headers and the body.
async fn raw(podgate: &Podgate, method: &str, path: &str) -> (u16, String, String) {
    let mut stream = UnixStream::connect(&podgate.admin_socket)
        .await
        .expect("connect to the admin socket");
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send");
    let mut text = String::new();
    stream.read_to_string(&mut text).await.expect("read");
    let (head, body) = text.split_once("\r\n\r\n").expect("a response");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status");
    (status, head.to_ascii_lowercase(), body.to_owned())
}

#[tokio::test]
async fn overview_rejects_other_methods() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    push(
        &podgate,
        &snapshot(1, &[app("a", &["a.test"], &[serving("r1", upstream.addr)])]),
    )
    .await;
    let before = overview(&podgate, "").await;

    for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
        let (status, head, body) = raw(&podgate, method, "/v1/overview").await;
        assert_eq!(status, 405, "{method}: {head}");
        assert!(head.contains("allow: get"), "{method}: {head}");
        if method != "HEAD" {
            assert_eq!(body, r#"{"error":"method not allowed"}"#, "{method}");
        }
    }
    let (status, _, body) = raw(&podgate, "GET", "/v1/overview").await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("JSON")["summary"]["version"],
        before["summary"]["version"]
    );
    assert_eq!(overview(&podgate, "").await, before, "nothing changed");
}

#[tokio::test]
async fn overview_never_includes_events() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    push(
        &podgate,
        &snapshot(1, &[app("a", &["a.test"], &[serving("r1", upstream.addr)])]),
    )
    .await;
    // A drained revision is an event on the feed.
    let mut draining = snapshot(
        2,
        &[app(
            "a",
            &["a.test"],
            &[
                revision("r1", upstream.addr, 100, "draining"),
                revision("r2", upstream.addr, 100, "serving"),
            ],
        )],
    );
    draining["revert_window_secs"] = json!(0);
    push(&podgate, &draining).await;
    let feed = podgate
        .admin_get("/v1/events?after=0&timeout_secs=1")
        .await
        .json();
    assert!(
        feed["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty()),
        "the feed has an event: {feed}"
    );

    let text = overview(&podgate, "").await.to_string();
    for word in [
        "revision_drained",
        "\"events\"",
        "\"seq\"",
        "certificate_issued",
    ] {
        assert!(!text.contains(word), "{word} is in the overview: {text}");
    }
    let asked = podgate.admin_get("/v1/overview?section=events").await;
    assert_eq!(asked.status, 400);
}
