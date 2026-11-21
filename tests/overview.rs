//! `GET /v1/overview` through the real binary: what is configured and how it is
//! doing, read from the live table and the runtime registries, with no secret and no way to
//! change anything.

mod common;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
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
        json!({"mode": "acme", "challenge": "http-01", "client_auth": false})
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
    let refused = common::refused();

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
        &[revision_on("r1", &[refused.addr], 100, "serving")],
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

/// The first planted secret (or private marker) that `body` shows.
fn leaked<'a>(body: &str, plants: &'a [String]) -> Option<&'a str> {
    plants
        .iter()
        .map(String::as_str)
        .chain(["BEGIN", "client_ca_pem"])
        .find(|secret| body.contains(secret))
}

/// A string no overview may ever show: unique, so one `contains` finds it.
fn plant(what: &str) -> String {
    format!("PLANT-{what}-7f3a9c")
}

/// A line of a PEM's base64 body.
fn pem_body(pem: &str) -> String {
    pem.lines().nth(1).expect("a PEM body line").to_owned()
}

/// One middleware of every built kind, with a planted secret wherever the kind takes one. A kind
/// that is built and missing here fails the guard, so no kind reaches the overview unchecked.
fn every_kind(plants: &mut Vec<String>) -> Vec<(&'static str, Value)> {
    let module = wat::parse_str(format!(
        r#"(module
          (memory (export "memory") 1)
          (data (i32.const 0) "{}")
          (func (export "proxy_abi_version_0_2_1"))
          (func (export "proxy_on_memory_allocate") (param i32) (result i32) (i32.const 0))
          (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32) (i32.const 0)))"#,
        plant("wasm-bytes")
    ))
    .expect("valid WAT");
    let wasm = STANDARD.encode(module);
    plants.extend([wasm.clone(), wasm[40..72].to_owned()]);

    let password = plant("basic-password");
    let hash = bcrypt::hash(&password, 10).expect("bcrypt hash");
    plants.extend([password, hash.clone()]);
    let ha1 = "7f3a9c0de1b2a45f6c8d90e1a2b3c4d5".to_owned();
    plants.push(ha1.clone());
    let (request_value, response_value) = (
        plant("request-header-value"),
        plant("response-header-value"),
    );
    plants.extend([request_value.clone(), response_value.clone()]);
    let (page_key, respond_header, respond_body) = (
        plant("errors-page-key"),
        plant("respond-header-value"),
        plant("respond-body"),
    );
    plants.extend([
        page_key.clone(),
        respond_header.clone(),
        respond_body.clone(),
    ]);
    let auth_key = plant("forward-auth-key");
    plants.push(auth_key.clone());
    plants.extend([plant("store-password"), plant("store-host")]);
    let (jwt_secret, jwt_query) = (
        plant("jwt-hmac-secret-padded-to-32-bytes"),
        plant("jwks-uri-key"),
    );
    plants.extend([
        jwt_secret.clone(),
        jwt_query.clone(),
        URL_SAFE_NO_PAD.encode(&jwt_secret),
    ]);
    let oidc_secret = plant("oidc-client-secret");
    plants.push(oidc_secret.clone());

    let kinds = vec![
        (
            "wasm",
            json!({"wasm_base64": wasm, "fuel": 1000, "max_memory_bytes": 65536}),
        ),
        ("add_prefix", json!({"prefix": "/api"})),
        ("strip_prefix", json!({"prefixes": ["/api"]})),
        ("strip_prefix_regex", json!({"regexes": ["^/t-[a-z]+"]})),
        ("replace_path", json!({"path": "/new"})),
        (
            "replace_path_regex",
            json!({"regex": "^/old/(.*)", "replacement": "/new/$1"}),
        ),
        ("redirect_scheme", json!({"scheme": "https"})),
        (
            "redirect_regex",
            json!({"regex": "^http://([^/]+)/old/(.*)$", "replacement": "https://$1/new/$2"}),
        ),
        (
            "headers",
            json!({"request": {"set": {"x-up": request_value}},
                   "response": {"set": {"x-down": response_value}}}),
        ),
        ("content_type", json!({})),
        ("basic_auth", json!({"users": [format!("alice:{hash}")]})),
        (
            "digest_auth",
            json!({"users": [format!("alice:podgate:{ha1}")], "realm": "podgate"}),
        ),
        (
            "cache",
            json!({"default_ttl_secs": 30, "tag_header": "Cache-Tag"}),
        ),
        (
            "circuit_breaker",
            json!({"trip_when": {"network_error_ratio": 0.3}}),
        ),
        ("buffering", json!({"max_request_body_bytes": 1024})),
        ("retry", json!({"attempts": 3})),
        (
            "pass_tls_client_cert",
            json!({"pem": true, "info": {"subject": {"common_name": true}}}),
        ),
        ("compress", json!({})),
        (
            "grpc_web",
            json!({"allow_origins": ["https://app.example.com"]}),
        ),
        ("ip_allow_list", json!({"source_range": ["203.0.113.0/24"]})),
        (
            "rate_limit",
            json!({"average": 10, "burst": 20, "source": {"ip": {}}, "max_sources": 64}),
        ),
        (
            "in_flight_req",
            json!({"amount": 5, "source": {"header": "x-api-key"}, "max_sources": 64}),
        ),
        (
            "errors",
            json!({"status": ["500-599"], "service": "pinned", "query": format!("/{{status}}.html?key={page_key}")}),
        ),
        (
            "forward_auth",
            json!({"address": format!("http://10.0.0.9:9091/verify?key={auth_key}"), "response_headers": ["x-user"]}),
        ),
        (
            "jwt_auth",
            json!({"algorithms": ["HS256", "ES256"],
                   "keys": {"keys": [{"kty": "oct", "kid": "shared", "k": URL_SAFE_NO_PAD.encode(&jwt_secret)}]},
                   "jwks_uri": format!("https://10.0.0.8:8443/jwks?key={jwt_query}"),
                   "issuer": "https://idp.test", "forward_claims": {"sub": "x-user-sub"}}),
        ),
        (
            "oidc",
            json!({"issuer": "https://idp.test", "client_id": "podgate", "client_secret": oidc_secret,
                   "forward_claims": {"sub": "x-user-sub"}}),
        ),
        (
            "respond",
            json!({"status": 403, "headers": {"x-closed-by": respond_header}, "body": respond_body}),
        ),
    ];
    let mut declared: Vec<&str> = kinds.iter().map(|(kind, _)| *kind).collect();
    let mut built: Vec<&str> = podgate::middleware::Stage::BUILT.to_vec();
    declared.sort_unstable();
    built.sort_unstable();
    assert_eq!(
        declared, built,
        "a middleware kind was built or removed: add or drop its fixture in `every_kind`, with a \
         planted secret in every field that holds one"
    );
    kinds
}

/// The operator's `RATE_LIMIT_STORES_FILE` for the planted snapshot: a store whose address and
/// password are the process's secrets, which no overview may show. Returns its path.
fn planted_stores() -> String {
    let dir = std::env::temp_dir().join(format!("podgate-overview-stores-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the stores directory");
    let password = dir.join("password");
    std::fs::write(&password, plant("store-password")).expect("write the password file");
    let file = dir.join("stores.json");
    // A password is only allowed over loopback or TLS, so the planted host is a second store.
    let stores = json!({
        "main": {"url": "redis://127.0.0.1:6379", "password_file": password, "tenants": ["t1"]},
        "remote": {
            "url": format!("redis://{}:6379", plant("store-host")), "tenants": ["t1"],
        },
    });
    std::fs::write(&file, stores.to_string()).expect("write the stores file");
    file.to_string_lossy().into_owned()
}

/// A snapshot of one app that holds a planted secret in everything that can hold one: every
/// built middleware kind, the four matcher leaves that carry a client's value, the sticky cookie,
/// a transport's client key, the client CA, a certificate and its key, the skew secret and the
/// ACME account key. Returns it with every planted string.
fn planted(upstream: SocketAddr) -> (Value, Vec<String>) {
    let mut plants = Vec::new();
    let kinds = every_kind(&mut plants);
    let (ca, cert, client) = (
        TestCa::new("planted-ca"),
        TestCert::new(&["a.test"]),
        TestCert::new(&["client.test"]),
    );
    plants.extend([
        pem_body(&ca.pem),
        pem_body(&cert.key_pem),
        pem_body(&cert.cert_pem),
        pem_body(&client.key_pem),
    ]);
    let matchers = [
        ("header-value", "header", "value"),
        ("header-regex", "header_regexp", "regex"),
        ("query-value", "query", "value"),
        ("query-regex", "query_regexp", "regex"),
    ];
    let mut leaves = vec![json!({"host": "a.test"})];
    for (index, (what, leaf, field)) in matchers.into_iter().enumerate() {
        let value = plant(&format!("matcher-{what}"));
        plants.push(value.clone());
        leaves.push(json!({ leaf: {"name": format!("x-{index}"), field: value}}));
    }
    let sticky = plant("sticky-cookie");
    plants.push(sticky.clone());
    let skew = plant("skew-secret-0123456789");
    let account = plant("account-key");
    let key_authorization = plant("key-authorization");
    plants.extend([skew.clone(), account.clone(), key_authorization.clone()]);

    let mut a = app("a", &["a.test"], &[serving("r1", upstream)]);
    a["tls"]["client_ca_pem"] = json!(ca.pem);
    a["routers"] = json!([
        router("a", json!({"all": leaves}), "web"),
        router("p", json!({"host": "p.test"}), "pinned"),
        router("s", json!({"host": "s.test"}), "secure"),
    ]);
    a["services"] = json!([
        {"name": "pinned", "type": "loadbalancer", "servers": [{"url": format!("http://{upstream}")}],
         "sticky": {"cookie": {"name": sticky}}},
        {"name": "secure", "type": "loadbalancer", "transport": "internal",
         "servers": [{"url": "https://127.0.0.1:9"}]},
    ]);
    a["transports"] = json!([{
        "name": "internal", "type": "servers_transport", "ca_pem": cert.cert_pem,
        "client_cert": {"cert_pem": client.cert_pem, "key_pem": client.key_pem},
    }]);
    a["middlewares"] = kinds
        .iter()
        .map(|(kind, config)| {
            let mut declared = json!({"name": kind, "type": kind});
            declared
                .as_object_mut()
                .expect("object")
                .extend(config.as_object().expect("object").clone());
            declared
        })
        .collect();
    a["middlewares"].as_array_mut().expect("array").push(json!({
        "name": "rate_limit_cluster", "type": "rate_limit", "average": 10, "burst": 20,
        "source": {"ip": {}}, "max_sources": 64, "scope": "cluster", "store": "main",
        "on_store_error": "allow", "local_fallback": {"average": 2, "burst": 4},
    }));
    let mut pushed = snapshot(1, &[a]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    pushed["skew_secret"] = json!(skew);
    pushed["acme"] = json!({
        "issuer_node": "some-other-node",
        "directory_url": "https://acme.invalid/directory",
        "account_key_pem": account,
        "challenges": [{"token": "tok-1", "key_authorization": key_authorization}],
    });
    (pushed, plants)
}

#[tokio::test]
async fn overview_redacts_secrets() {
    let stores = planted_stores();
    let podgate = Podgate::start_with_env(&[("RATE_LIMIT_STORES_FILE", &stores)]).await;
    let upstream = Upstream::start("x").await;
    let (pushed, plants) = planted(upstream.addr);
    push(&podgate, &pushed).await;

    // Every section in one answer, and the apps again page by page.
    let mut bodies = vec![podgate.admin_get("/v1/overview?limit=500").await.body];
    let mut after = String::new();
    loop {
        let page = overview(&podgate, &format!("?section=apps&limit=1{after}")).await;
        bodies.push(page.to_string());
        match page["apps"]["next"].as_str() {
            Some(next) => after = format!("&after={next}"),
            None => break,
        }
    }
    for body in &bodies {
        assert_eq!(
            leaked(body, &plants),
            None,
            "a secret is in the overview: {body}"
        );
    }

    // The planted snapshot is really in the view: only the secrets are missing.
    let document: Value = serde_json::from_str(&bodies[0]).expect("JSON");
    let a = app_of(&document, "a");
    assert_eq!(a["tls"]["client_auth"], true);

    assert_eq!(
        a["routers"][0]["match"]["all"][1],
        json!({"header": {"name": "x-0", "value": "[value]"}})
    );
    assert_eq!(
        a["routers"][0]["match"]["all"][4],
        json!({"query_regexp": {"name": "x-3", "regex": "[value]"}})
    );
    assert_eq!(a["services"].as_array().map(Vec::len), Some(3));
    assert_eq!(items(&document, "certificates").len(), 1);
}

/// Field names that hold a setting and never a credential, though they contain a word the guard
/// looks for: `jwt_auth` shows its configuration under the names the operator wrote, and these are
/// the ones with "token" in them. Only these exact names pass; the secret itself, an `oct` key or
/// the query of a `jwks_uri`, is never shown whatever its field is called, which
/// `overview_redacts_secrets` checks by value.
const NOT_SECRET_NAMES: [&str; 3] = ["max_token_age_secs", "token_sources", "remove_token"];

/// Whether a field name looks like it holds a secret.
fn names_a_secret(name: &str) -> bool {
    !NOT_SECRET_NAMES.contains(&name)
        && ["password", "secret", "key_pem", "token", "hash"]
            .iter()
            .any(|word| name.contains(word))
}

#[test]
fn the_name_guard_only_lets_the_listed_names_through() {
    for secret in [
        "token",
        "access_token",
        "api_token_hash",
        "password",
        "client_secret",
        "key_pem",
        "max_token_age",
        "token_sources_extra",
        "remove_token_value",
    ] {
        assert!(names_a_secret(secret), "{secret}");
    }
    for plain in NOT_SECRET_NAMES
        .iter()
        .copied()
        .chain(["algorithms", "keys", "issuer"])
    {
        assert!(!names_a_secret(plain), "{plain}");
    }
}

#[test]
fn a_listed_name_holding_a_planted_secret_is_still_caught() {
    let plants = vec![plant("jwt-leak")];
    let leaking =
        json!({"max_token_age_secs": plants[0], "token_sources": [], "remove_token": true});
    assert_eq!(
        leaked(&leaking.to_string(), &plants),
        Some(plants[0].as_str())
    );
    let clean =
        json!({"max_token_age_secs": 60, "token_sources": [{"query": "t"}], "remove_token": true});
    assert_eq!(leaked(&clean.to_string(), &plants), None);
}

#[tokio::test]
async fn every_describe_is_secret_free() {
    let stores = planted_stores();
    let podgate = Podgate::start_with_env(&[("RATE_LIMIT_STORES_FILE", &stores)]).await;
    let upstream = Upstream::start("x").await;
    let (pushed, _) = planted(upstream.addr);
    push(&podgate, &pushed).await;

    // Secondary to the value check above: no `describe()` names a field like a secret.
    fn names(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    found.push(key.to_ascii_lowercase());
                    names(child, found);
                }
            }
            Value::Array(list) => list.iter().for_each(|child| names(child, found)),
            _ => {}
        }
    }
    let document = overview(&podgate, "?section=apps").await;
    for middleware in app_of(&document, "a")["middlewares"]
        .as_array()
        .expect("middlewares")
    {
        let mut found = Vec::new();
        names(&middleware["config"], &mut found);
        for name in found {
            assert!(
                !names_a_secret(&name),
                "{} describes itself with the field {name:?}, which names a secret",
                middleware["type"]
            );
        }
    }
}

#[tokio::test]
async fn overview_shows_the_metrics_listener() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = probe.local_addr().expect("addr").to_string();
    drop(probe);
    let podgate = Podgate::start_with_env(&[("METRICS_ADDR", &addr)]).await;
    let shown = overview(&podgate, "?section=summary").await;
    assert_eq!(shown["summary"]["metrics_addr"], addr);

    let plain = Podgate::start().await;
    let shown = overview(&plain, "?section=summary").await;
    assert!(shown["summary"].get("metrics_addr").is_none());
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
    let refused = common::refused();
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
            app("a", &["a.test"], &[serving("r2", refused.addr)]),
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
        format!("http://{}", refused.addr)
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
