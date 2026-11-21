//! Cluster-scope `rate_limit` through the real binary and a real `valkey-server`: one
//! limit across nodes, keys that isolate tenants and configurations and never hold a client's
//! address, a chosen behaviour when the store fails, and a store that exists only in the
//! operator's process configuration.

// The builders take the JSON they are given, as the ones in `common` do.
#![allow(clippy::needless_pass_by_value)]

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::valkey::{self, TlsFiles, Valkey};
use common::{Podgate, Response, Upstream, app, middleware, serving, snapshot, with_chain};
use podgate::ratelimit_store::{Gcra, OPEN_FOR, StoreError, Stores};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time::sleep;

/// App `a` on `a.test` with one rate limit called `limit` in its chain.
fn limited(upstream: SocketAddr, config: Value) -> Value {
    with_chain(
        app("a", &["a.test"], &[serving("r1", upstream)]),
        &[middleware("limit", "rate_limit", config)],
    )
}

/// A cluster limit on store `main`, counted per `x-client`: one token every hour, so nothing
/// refills during a test.
fn limit(burst: u32, failure: Value) -> Value {
    let mut config = json!({
        "average": 1, "period_secs": 3600, "burst": burst,
        "source": {"header": "x-client"}, "scope": "cluster", "store": "main",
    });
    let object = config.as_object_mut().expect("object");
    object.extend(failure.as_object().expect("object").clone());
    config
}

fn deny() -> Value {
    json!({"on_store_error": "deny"})
}

fn allow(average: u32, burst: u32) -> Value {
    json!({"on_store_error": "allow", "local_fallback": {"average": average, "burst": burst}})
}

/// A node whose `RATE_LIMIT_STORES_FILE` is `stores`.
async fn node(stores: &Path) -> Podgate {
    Podgate::start_with_env(&[(
        "RATE_LIMIT_STORES_FILE",
        stores.to_str().expect("utf-8 path"),
    )])
    .await
}

async fn push(podgate: &Podgate, pushed: &Value) {
    let response = podgate.push_snapshot(pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

async fn hit(podgate: &Podgate, host: &str, who: &str) -> Response {
    podgate
        .get_with_headers(host, "/", &[("x-client", who)])
        .await
}

/// The stores file naming `store` as `main` for tenant `t1`.
fn one_store(dir: &Path, store: Value) -> std::path::PathBuf {
    valkey::stores_file(dir, &json!({ "main": store }))
}

/// The code of the first rejection of a refused push.
fn rejection_code(response: &Response) -> String {
    assert_eq!(response.status, 422, "{}", response.body);
    response.json()["conflicts"][0]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// The value of the metric line that starts with `series`.
fn metric(text: &str, series: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(series)?.trim().parse().ok())
}

/// A TCP server that accepts connections and counts them. With `reply_after` it answers every
/// read with an error line after that delay; without it never answers: a store that hangs.
struct Stub {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

impl Stub {
    async fn start(reply_after: Option<Duration>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the stub");
        let addr = listener.local_addr().expect("stub address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                if let Some(delay) = reply_after {
                                    sleep(delay).await;
                                    if stream.write_all(b"-ERR slow\r\n").await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });
        Self { addr, accepted }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn cluster_limit_shared_across_nodes() {
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("shared");
    let stores = one_store(&dir, valkey::entry(valkey.addr()));
    let (first, second) = (node(&stores).await, node(&stores).await);
    let pushed = snapshot(1, &[limited(upstream.addr, limit(10, deny()))]);
    push(&first, &pushed).await;
    push(&second, &pushed).await;

    let (mut admitted, mut refused) = (0, 0);
    for round in 0..30 {
        let node = if round % 2 == 0 { &first } else { &second };
        let response = hit(node, "a.test", "client-1").await;
        match response.status {
            200 => admitted += 1,
            429 => {
                refused += 1;
                assert!(response.header("retry-after").is_some(), "{response:?}");
            }
            other => panic!("unexpected status {other}: {response:?}"),
        }
    }
    // Each node alone would admit its own burst of 10, 20 in all.
    assert_eq!(
        admitted, 10,
        "the sum across both nodes stays within the burst"
    );
    assert_eq!(refused, 20);
    let other = hit(&first, "a.test", "client-2").await;
    assert_eq!(other.status, 200, "another source has its own bucket");
}

#[tokio::test]
async fn cluster_keys_isolated_by_tenant_and_config() {
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("isolated");
    let mut entry = valkey::entry(valkey.addr());
    entry["tenants"] = json!(["t1", "t2"]);
    let podgate = node(&one_store(&dir, entry)).await;
    let build = |version: u64, burst: u32| {
        let first = limited(upstream.addr, limit(burst, deny()));
        let mut second = with_chain(
            app("b", &["b.test"], &[serving("r1", upstream.addr)]),
            &[middleware("limit", "rate_limit", limit(1, deny()))],
        );
        second["tenant"] = json!("t2");
        // One app with two limiters of its own: the middleware name is part of the key.
        let third = with_chain(
            app("c", &["c.test"], &[serving("r1", upstream.addr)]),
            &[
                middleware("m1", "rate_limit", limit(5, deny())),
                middleware("m2", "rate_limit", limit(5, deny())),
            ],
        );
        let mut pushed = snapshot(version, &[first, second, third]);
        pushed["tenants"] = json!([
            {"id": "t1", "weight": 1, "budget": {"max_inflight": 100, "max_buffer_bytes": 1_048_576}},
            {"id": "t2", "weight": 1, "budget": {"max_inflight": 100, "max_buffer_bytes": 1_048_576}},
        ]);
        pushed
    };
    push(&podgate, &build(1, 1)).await;

    assert_eq!(hit(&podgate, "a.test", "same").await.status, 200);
    assert_eq!(hit(&podgate, "a.test", "same").await.status, 429);
    assert_eq!(
        hit(&podgate, "b.test", "same").await.status,
        200,
        "the same source in another tenant has its own bucket"
    );
    assert_eq!(hit(&podgate, "c.test", "same").await.status, 200);
    assert_eq!(valkey.keys("podgate:rl:t1:a:limit:*").len(), 1);
    assert_eq!(valkey.keys("podgate:rl:t2:b:limit:*").len(), 1);
    assert_eq!(valkey.keys("podgate:rl:t1:c:m1:*").len(), 1);
    assert_eq!(valkey.keys("podgate:rl:t1:c:m2:*").len(), 1);
    assert_eq!(valkey.keys("podgate:rl:*").len(), 4);

    // A changed declaration is a new bucket: its first request passes though the old one is spent.
    push(&podgate, &build(2, 2)).await;
    assert_eq!(hit(&podgate, "a.test", "same").await.status, 200);
    let keys = valkey.keys("podgate:rl:t1:a:limit:*");
    assert_eq!(keys.len(), 2, "{keys:?}");
    let fingerprints: Vec<&str> = keys
        .iter()
        .map(|key| key.split(':').nth(5).expect("fingerprint"))
        .collect();
    assert_ne!(fingerprints[0], fingerprints[1]);
}

#[tokio::test]
async fn cluster_source_hashed_in_key() {
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("hashed");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    let by_ip = with_chain(
        app("b", &["b.test"], &[serving("r1", upstream.addr)]),
        &[middleware("limit", "rate_limit", {
            let mut config = limit(5, deny());
            config["source"] = json!({"ip": {}});
            config
        })],
    );
    push(
        &podgate,
        &snapshot(1, &[limited(upstream.addr, limit(5, deny())), by_ip]),
    )
    .await;
    let api_key = "sk-live-planted-api-key-81c4";
    assert_eq!(hit(&podgate, "a.test", api_key).await.status, 200);
    assert_eq!(hit(&podgate, "b.test", "anything").await.status, 200);

    let keys = valkey.keys("podgate:rl:*");
    assert_eq!(keys.len(), 2, "{keys:?}");
    for key in &keys {
        assert!(!key.contains(api_key), "{key}");
        assert!(!key.contains("127.0.0.1"), "{key}");
        let source = key.rsplit(':').next().expect("source part");
        assert_eq!(source.len(), 32, "16 bytes of SHA-256 as hex: {key}");
        assert!(source.bytes().all(|byte| byte.is_ascii_hexdigit()), "{key}");
    }
    let (a_key, b_key) = (
        valkey.keys("podgate:rl:t1:a:*"),
        valkey.keys("podgate:rl:t1:b:*"),
    );
    assert_ne!(a_key[0].rsplit(':').next(), b_key[0].rsplit(':').next());
}

/// Requests to `a.test` as one source, `count` times, each status in order.
async fn statuses(podgate: &Podgate, count: usize) -> Vec<u16> {
    let mut seen = Vec::new();
    for _ in 0..count {
        seen.push(hit(podgate, "a.test", "client").await.status);
    }
    seen
}

#[tokio::test]
async fn store_killed_mid_run_allow_uses_local_fallback() {
    let mut valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("allow");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    push(
        &podgate,
        &snapshot(1, &[limited(upstream.addr, limit(100, allow(1, 3)))]),
    )
    .await;
    assert_eq!(
        statuses(&podgate, 2).await,
        [200, 200],
        "the store counts these"
    );

    valkey.stop();
    let during = statuses(&podgate, 10).await;
    assert_eq!(
        during,
        [200, 200, 200, 429, 429, 429, 429, 429, 429, 429],
        "served up to the local fallback's burst of 3, then limited"
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(&metrics, r#"podgate_ratelimit_store_up{store="main"}"#),
        Some(0)
    );
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_ratelimit_store_errors_total{store="main",mode="allow"}"#
        ),
        Some(10)
    );
}

#[tokio::test]
async fn store_killed_mid_run_deny_returns_503() {
    let mut valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("deny");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    push(
        &podgate,
        &snapshot(1, &[limited(upstream.addr, limit(100, deny()))]),
    )
    .await;
    assert_eq!(hit(&podgate, "a.test", "client").await.status, 200);

    valkey.stop();
    for _ in 0..8 {
        let response = hit(&podgate, "a.test", "client").await;
        assert_eq!(response.status, 503, "{response:?}");
        assert_eq!(response.header("retry-after"), Some("1"));
        assert_eq!(
            response.json(),
            json!({"error": "rate limiter unavailable"})
        );
    }
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_ratelimit_store_errors_total{store="main",mode="deny"}"#
        ),
        Some(8)
    );
}

#[tokio::test]
async fn store_recovery_restores_cluster_limit() {
    let mut valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("recovery");
    let stores = one_store(&dir, valkey::entry(valkey.addr()));
    let (first, second) = (node(&stores).await, node(&stores).await);
    let pushed = snapshot(1, &[limited(upstream.addr, limit(10, deny()))]);
    push(&first, &pushed).await;
    push(&second, &pushed).await;
    assert_eq!(hit(&first, "a.test", "client").await.status, 200);

    // Five errors open the circuit.
    valkey.stop();
    for _ in 0..5 {
        assert_eq!(hit(&first, "a.test", "client").await.status, 503);
    }
    valkey.restart().await;

    // Open for OPEN_FOR, then one request probes the returned store. Each poll is its own
    // source: the node's local pre-filter counts every request of one source.
    let deadline = Instant::now() + OPEN_FOR + Duration::from_secs(10);
    let mut poll = 0;
    loop {
        poll += 1;
        let response = hit(&first, "a.test", &format!("probe-{poll}")).await;
        if response.status == 200 {
            break;
        }
        assert_eq!(response.status, 503, "{response:?}");
        assert!(
            Instant::now() < deadline,
            "the store never came back into use"
        );
        sleep(Duration::from_millis(250)).await;
    }

    // The restarted store is empty. This node takes one token of the shared burst of 10, the
    // other node, which never saw an outage, the other nine, and the store refuses its tenth.
    assert_eq!(hit(&first, "a.test", "client").await.status, 200);
    for taken in 0..8 {
        assert_eq!(
            hit(&second, "a.test", "client").await.status,
            200,
            "token {taken} of the second node"
        );
    }
    assert_eq!(hit(&second, "a.test", "client").await.status, 200);
    let spent = hit(&second, "a.test", "client").await;
    assert_eq!(spent.status, 429, "{spent:?}");
    let retry: u32 = spent
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("seconds");
    assert!(
        retry > 1,
        "the store's verdict, not the outage's: {spent:?}"
    );
    let metrics = first.admin_get("/metrics").await.body;
    assert_eq!(
        metric(&metrics, r#"podgate_ratelimit_store_up{store="main"}"#),
        Some(1)
    );
}

#[tokio::test]
async fn dead_store_circuit_opens() {
    let stub = Stub::start(None).await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("circuit");
    let podgate = node(&one_store(&dir, valkey::entry(stub.addr))).await;
    push(
        &podgate,
        &snapshot(1, &[limited(upstream.addr, limit(100, deny()))]),
    )
    .await;

    // Five errors, each a timeout of the store's 100 ms, open the circuit.
    let started = Instant::now();
    for _ in 0..5 {
        assert_eq!(hit(&podgate, "a.test", "client").await.status, 503);
    }
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "each waited for the store"
    );
    assert_eq!(stub.accepted(), 5);

    // Open: 50 more requests cost nothing, and the store hears nothing.
    let started = Instant::now();
    for _ in 0..50 {
        assert_eq!(hit(&podgate, "a.test", "client").await.status, 503);
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "one timeout per period, not one per request: {:?}",
        started.elapsed()
    );
    assert_eq!(stub.accepted(), 5);
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(&metrics, r#"podgate_ratelimit_store_up{store="main"}"#),
        Some(0)
    );

    // After the period exactly one request probes the store; its failure reopens the circuit.
    sleep(OPEN_FOR + Duration::from_millis(300)).await;
    for _ in 0..20 {
        assert_eq!(hit(&podgate, "a.test", "client").await.status, 503);
    }
    assert_eq!(stub.accepted(), 6, "one probe");
}

#[tokio::test(flavor = "multi_thread")]
async fn store_inflight_calls_capped() {
    let stub = Stub::start(None).await;
    let dir = valkey::scratch("inflight");
    let mut entry = valkey::entry(stub.addr);
    entry["timeout_ms"] = json!(200);
    let stores = Stores::load(&one_store(&dir, entry)).expect("stores");
    let store = Arc::clone(stores.get("main").expect("main"));
    let rate = Gcra {
        interval_us: 1_000_000,
        burst_us: 1_000_000,
    };

    let mut calls = JoinSet::new();
    for _ in 0..300 {
        let store = Arc::clone(&store);
        calls.spawn(async move { store.gcra("t1", "k", rate, None).await });
    }
    let (mut saturated, mut timed_out, mut other) = (0, 0, 0);
    while let Some(done) = calls.join_next().await {
        match done.expect("task") {
            Err(StoreError::Saturated) => saturated += 1,
            Err(StoreError::Timeout) => timed_out += 1,
            _ => other += 1,
        }
    }
    assert_eq!(
        (saturated, timed_out, other),
        (44, 256, 0),
        "256 calls in flight, the rest an error at once"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn store_inflight_share_is_per_tenant() {
    let stub = Stub::start(None).await;
    let dir = valkey::scratch("share");
    let mut entry = valkey::entry(stub.addr);
    entry["timeout_ms"] = json!(200);
    entry["tenants"] = json!(["t1", "t2"]);
    let stores = Stores::load(&one_store(&dir, entry)).expect("stores");
    let store = Arc::clone(stores.get("main").expect("main"));
    let rate = Gcra {
        interval_us: 1_000_000,
        burst_us: 1_000_000,
    };

    let mut flood = JoinSet::new();
    for _ in 0..200 {
        let store = Arc::clone(&store);
        flood.spawn(async move { store.gcra("t1", "k", rate, None).await });
    }
    sleep(Duration::from_millis(30)).await;
    let neighbour = store.gcra("t2", "k", rate, None).await;
    assert!(
        matches!(neighbour, Err(StoreError::Timeout)),
        "another tenant still gets a slot: {neighbour:?}"
    );
    let stranger = store.gcra("t3", "k", rate, None).await;
    assert!(
        matches!(stranger, Err(StoreError::Forbidden)),
        "{stranger:?}"
    );
    let mut saturated = 0;
    while let Some(done) = flood.join_next().await {
        if matches!(done.expect("task"), Err(StoreError::Saturated)) {
            saturated += 1;
        }
    }
    assert_eq!(saturated, 200 - 128, "a tenant holds half of the 256 slots");
}

#[tokio::test]
async fn slow_store_times_out_as_error() {
    let stub = Stub::start(Some(Duration::from_millis(600))).await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("slow");
    let podgate = node(&one_store(&dir, valkey::entry(stub.addr))).await;
    let mut config = limit(100, deny());
    config["store_timeout_ms"] = json!(50);
    push(&podgate, &snapshot(1, &[limited(upstream.addr, config)])).await;

    let started = Instant::now();
    let response = hit(&podgate, "a.test", "client").await;
    assert_eq!(response.status, 503, "{response:?}");
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "the request did not wait for the slow store: {:?}",
        started.elapsed()
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_ratelimit_store_errors_total{store="main",mode="deny"}"#
        ),
        Some(1)
    );
}

#[tokio::test]
async fn cluster_config_requires_failure_mode() {
    let refused = common::refused();
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("config");
    let podgate = node(&one_store(&dir, valkey::entry(refused.addr))).await;
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut config = limit(5, deny());
        edit(&mut config);
        snapshot(1, &[limited(upstream.addr, config)])
    };
    let wrong: Vec<(&str, Value)> = vec![
        (
            "no on_store_error",
            with(&|config| {
                config
                    .as_object_mut()
                    .expect("object")
                    .remove("on_store_error");
            }),
        ),
        (
            "allow without local_fallback",
            with(&|config| config["on_store_error"] = json!("allow")),
        ),
        (
            "deny with local_fallback",
            with(&|config| config["local_fallback"] = json!({"average": 1, "burst": 1})),
        ),
        (
            "unknown mode",
            with(&|config| config["on_store_error"] = json!("shrug")),
        ),
        (
            "no store",
            with(&|config| {
                config.as_object_mut().expect("object").remove("store");
            }),
        ),
        (
            "a cluster field on a node-scope limit",
            with(&|config| config["scope"] = json!("node")),
        ),
        (
            "unknown scope",
            with(&|config| config["scope"] = json!("region")),
        ),
        (
            "timeout over the cap",
            with(&|config| config["store_timeout_ms"] = json!(201)),
        ),
        (
            "timeout of zero",
            with(&|config| config["store_timeout_ms"] = json!(0)),
        ),
        (
            "empty fallback rate",
            with(&|config| {
                config["on_store_error"] = json!("allow");
                config["local_fallback"] = json!({"average": 0, "burst": 1});
            }),
        ),
        (
            "empty fallback burst",
            with(&|config| {
                config["on_store_error"] = json!("allow");
                config["local_fallback"] = json!({"average": 1, "burst": 0});
            }),
        ),
    ];
    for (what, pushed) in &wrong {
        let response = podgate.push_snapshot(pushed).await;
        assert_eq!(
            rejection_code(&response),
            "invalid_middleware",
            "{what}: {}",
            response.body
        );
    }
    let message = podgate.push_snapshot(&wrong[0].1).await.json()["conflicts"][0]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(message.contains("on_store_error"), "{message}");

    let good = with(&|config| {
        config["on_store_error"] = json!("allow");
        config["local_fallback"] = json!({"average": 1, "burst": 2});
    });
    push(&podgate, &good).await;
}

#[tokio::test]
async fn cluster_unknown_store_rejected() {
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    let mut config = limit(5, deny());
    config["store"] = json!("main");
    let response = podgate
        .push_snapshot(&snapshot(1, &[limited(upstream.addr, config)]))
        .await;
    assert_eq!(
        rejection_code(&response),
        "invalid_middleware",
        "a process with no RATE_LIMIT_STORES_FILE has no store: {}",
        response.body
    );

    let refused = common::refused();
    let dir = valkey::scratch("unknown");
    let podgate = node(&one_store(&dir, valkey::entry(refused.addr))).await;
    let mut config = limit(5, deny());
    config["store"] = json!("nope");
    let response = podgate
        .push_snapshot(&snapshot(1, &[limited(upstream.addr, config)]))
        .await;
    assert_eq!(
        rejection_code(&response),
        "invalid_middleware",
        "{}",
        response.body
    );
}

#[tokio::test]
async fn cluster_store_forbidden_for_tenant() {
    let refused = common::refused();
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("forbidden");
    let mut entry = valkey::entry(refused.addr);
    entry["tenants"] = json!(["someone-else"]);
    let podgate = node(&one_store(&dir, entry)).await;

    let try_store = |name: &str| {
        let mut config = limit(5, deny());
        config["store"] = json!(name);
        snapshot(1, &[limited(upstream.addr, config)])
    };
    let forbidden = podgate.push_snapshot(&try_store("main")).await;
    assert_eq!(
        rejection_code(&forbidden),
        "invalid_middleware",
        "{}",
        forbidden.body
    );
    let unknown = podgate.push_snapshot(&try_store("other")).await;
    assert_eq!(
        rejection_code(&unknown),
        "invalid_middleware",
        "{}",
        unknown.body
    );
    let message = |response: &Response, name: &str| {
        response.json()["conflicts"][0]["message"]
            .as_str()
            .unwrap_or_default()
            .replace(name, "NAME")
    };
    assert_eq!(
        message(&forbidden, "main"),
        message(&unknown, "other"),
        "a store that exists and one the tenant may not use read the same"
    );
}

#[tokio::test]
async fn store_address_only_from_process_config() {
    let upstream = Upstream::start("ok").await;
    let watcher = Stub::start(None).await;
    let url = format!("redis://{}", watcher.addr);
    let podgate = Podgate::start().await;

    // The snapshot cannot carry an address, whatever the field is called.
    for field in [
        "url",
        "address",
        "host",
        "endpoints",
        "password",
        "password_file",
    ] {
        let mut config = limit(5, deny());
        config[field] = json!(url);
        let response = podgate
            .push_snapshot(&snapshot(1, &[limited(upstream.addr, config)]))
            .await;
        assert_eq!(
            rejection_code(&response),
            "invalid_middleware",
            "{field}: {}",
            response.body
        );
    }
    // And a store name that is an address is only a name nobody configured.
    let mut config = limit(5, deny());
    config["store"] = json!(url);
    let response = podgate
        .push_snapshot(&snapshot(1, &[limited(upstream.addr, config)]))
        .await;
    assert_eq!(
        rejection_code(&response),
        "invalid_middleware",
        "{}",
        response.body
    );
    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        watcher.accepted(),
        0,
        "podgate never dialled an address from a snapshot"
    );

    // The file itself refuses a credential inside the URL.
    let dir = valkey::scratch("address");
    let file = one_store(
        &dir,
        json!({"url": "redis://user:secret@127.0.0.1:1", "tenants": ["t1"]}),
    );
    let err = Stores::load(&file).expect_err("credentials in a url");
    assert!(!err.to_string().contains("secret"), "{err}");
}

#[tokio::test]
async fn store_password_never_logged() {
    let right = "planted-correct-horse-9f3a";
    let wrong = "planted-wrong-battery-2b7c";
    let valkey = Valkey::start_with(Some(right), None).await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("password");
    let write = |name: &str, content: &str| {
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write a password file");
        path
    };
    let mut good = valkey::entry(valkey.addr());
    good["password_file"] = json!(write("right.pw", &format!("{right}\n")));
    let mut bad = valkey::entry(valkey.addr());
    bad["password_file"] = json!(write("wrong.pw", wrong));
    let stores = valkey::stores_file(&dir, &json!({"main": good, "bad": bad}));

    let podgate = Podgate::start_logged(&[
        (
            "RATE_LIMIT_STORES_FILE",
            stores.to_str().expect("utf-8 path"),
        ),
        ("RUST_LOG", "debug"),
    ])
    .await;
    let mut other = limit(5, deny());
    other["store"] = json!("bad");
    let second = with_chain(
        app("b", &["b.test"], &[serving("r1", upstream.addr)]),
        &[middleware("limit", "rate_limit", other)],
    );
    push(
        &podgate,
        &snapshot(1, &[limited(upstream.addr, limit(5, deny())), second]),
    )
    .await;
    assert_eq!(
        hit(&podgate, "a.test", "client").await.status,
        200,
        "the right password was sent"
    );
    let refused = hit(&podgate, "b.test", "client").await;
    assert_eq!(
        refused.status, 503,
        "the wrong password is an error: {refused:?}"
    );

    let explain = podgate
        .admin_get("/v1/explain?url=http://a.test/")
        .await
        .body;
    let overview = podgate.admin_get("/v1/overview?limit=500").await.body;
    let metrics = podgate.admin_get("/metrics").await.body;
    let in_process = format!("{:?}", Stores::load(&stores).expect("stores"));
    for (what, text) in [
        ("the log", podgate.log()),
        ("explain", explain),
        ("overview", overview),
        ("metrics", metrics),
        ("Debug", in_process),
    ] {
        for secret in [right, wrong] {
            assert!(!text.contains(secret), "{what} shows a password: {text}");
        }
    }
    let log = podgate.log();
    assert!(
        log.contains("WRONGPASS") || log.contains("rate limit store"),
        "the failure itself is logged, without the password: {log}"
    );
}

#[tokio::test]
async fn rediss_store_is_verified_against_the_ca_file() {
    let dir = valkey::scratch("tls");
    let trusted = TlsFiles::new(&dir, "trusted");
    let stranger = TlsFiles::new(&dir, "stranger");
    let valkey = Valkey::start_with(None, Some(trusted.clone())).await;
    let upstream = Upstream::start("ok").await;
    let pushed = snapshot(1, &[limited(upstream.addr, limit(5, deny()))]);

    let mut entry = valkey::entry(valkey.addr());
    entry["url"] = json!(valkey.url());
    entry["tls_ca_file"] = json!(trusted.ca);
    entry["timeout_ms"] = json!(200);
    let sub = dir.join("good");
    let podgate = node(&one_store(&sub, entry.clone())).await;
    push(&podgate, &pushed).await;
    assert_eq!(hit(&podgate, "a.test", "client").await.status, 200);
    assert_eq!(
        valkey.keys("podgate:rl:*").len(),
        1,
        "the store was reached over TLS"
    );

    entry["tls_ca_file"] = json!(stranger.ca);
    let sub = dir.join("stranger");
    let podgate = node(&one_store(&sub, entry.clone())).await;
    push(&podgate, &pushed).await;
    assert_eq!(
        hit(&podgate, "a.test", "client").await.status,
        503,
        "a store whose certificate is not from the named CA is an error"
    );

    entry.as_object_mut().expect("object").remove("tls_ca_file");
    let err = Stores::load(&one_store(&dir.join("nocafile"), entry)).expect_err("no CA");
    assert!(err.to_string().contains("tls_ca_file"), "{err}");
}

#[tokio::test]
async fn explain_shows_scope_store_and_failure_mode() {
    let refused = common::refused();
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("explain");
    let podgate = node(&one_store(&dir, valkey::entry(refused.addr))).await;
    push(
        &podgate,
        &snapshot(1, &[limited(upstream.addr, limit(10, allow(2, 4)))]),
    )
    .await;
    let explain = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(explain.status, 200, "{}", explain.body);
    let shown = explain.json().to_string();
    for part in [
        r#""scope":"cluster""#,
        r#""store":"main""#,
        r#""on_store_error":"allow""#,
        r#""local_fallback":{"average":2,"burst":4}"#,
    ] {
        assert!(shown.contains(part), "{part} is missing from {shown}");
    }
}

#[tokio::test]
async fn plan_lists_cluster_posture_changes() {
    let refused = common::refused();
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("posture");
    let podgate = node(&one_store(&dir, valkey::entry(refused.addr))).await;
    let node_scope = || json!({"average": 1, "period_secs": 3600, "burst": 10, "source": {"header": "x-client"}});
    let kinds = |response: &Response| -> Vec<String> {
        assert_eq!(response.status, 200, "{}", response.body);
        let mut kinds: Vec<String> = response.json()["posture_changes"]
            .as_array()
            .expect("posture_changes")
            .iter()
            .map(|change| change["kind"].as_str().expect("kind").to_owned())
            .collect();
        kinds.sort();
        kinds
    };
    let plan = |config: Value| {
        let podgate = &podgate;
        let pushed = snapshot(2, &[limited(upstream.addr, config)]);
        async move { podgate.admin_post("/v1/snapshot/plan", &pushed).await }
    };

    push(
        &podgate,
        &snapshot(1, &[limited(upstream.addr, limit(10, deny()))]),
    )
    .await;
    assert_eq!(
        kinds(&plan(limit(10, allow(1, 5))).await),
        ["rate_limit_cluster_fail_open"],
        "deny to allow"
    );
    assert_eq!(kinds(&plan(node_scope()).await), ["rate_limit_scope_node"]);
    assert!(kinds(&plan(limit(5, deny())).await).is_empty(), "stricter");

    push(
        &podgate,
        &snapshot(2, &[limited(upstream.addr, node_scope())]),
    )
    .await;
    let pushed = |config: Value| snapshot(3, &[limited(upstream.addr, config)]);
    let to_allow = podgate
        .admin_post("/v1/snapshot/plan", &pushed(limit(10, allow(1, 5))))
        .await;
    assert_eq!(
        kinds(&to_allow),
        ["rate_limit_cluster_fail_open"],
        "node to cluster allow"
    );
    let to_deny = podgate
        .admin_post("/v1/snapshot/plan", &pushed(limit(10, deny())))
        .await;
    assert!(kinds(&to_deny).is_empty(), "node to cluster deny");

    push(
        &podgate,
        &snapshot(3, &[limited(upstream.addr, limit(10, allow(1, 5)))]),
    )
    .await;
    let looser = podgate
        .admin_post(
            "/v1/snapshot/plan",
            &snapshot(4, &[limited(upstream.addr, limit(10, allow(1, 6)))]),
        )
        .await;
    assert_eq!(
        kinds(&looser),
        ["rate_limit_loosened"],
        "a bigger fallback burst"
    );
    let to_deny = podgate
        .admin_post(
            "/v1/snapshot/plan",
            &snapshot(4, &[limited(upstream.addr, limit(10, deny()))]),
        )
        .await;
    assert!(kinds(&to_deny).is_empty(), "allow to deny");
}

/// Runs `oha` against the proxy for `secs` seconds at `connections` and returns
/// `(requests per second, p50, p95, p99 in milliseconds, requests that were not 200)`.
fn oha(proxy: SocketAddr, secs: u32, connections: u32) -> (f64, f64, f64, f64, u64) {
    let output = std::process::Command::new("oha")
        .args(["-z", &format!("{secs}s"), "-c", &connections.to_string()])
        .args(["--no-tui", "--output-format", "json"])
        .args(["-H", "Host: a.test", "-H", "x-client: bench"])
        .arg(format!("http://{proxy}/"))
        .output()
        .expect("run oha: it must be on PATH (devenv shell)");
    let report: Value = serde_json::from_slice(&output.stdout).expect("oha JSON");
    let millis = |percentile: &str| {
        report["latencyPercentiles"][percentile]
            .as_f64()
            .expect("percentile")
            * 1000.0
    };
    let failed: u64 = report["statusCodeDistribution"]
        .as_object()
        .expect("status codes")
        .iter()
        .filter(|(status, _)| *status != "200")
        .map(|(_, count)| count.as_u64().unwrap_or(0))
        .sum();
    (
        report["summary"]["requestsPerSec"].as_f64().expect("rps"),
        millis("p50"),
        millis("p95"),
        millis("p99"),
        failed,
    )
}

/// The latency a cluster-scope limit adds over the same limit at node scope, against a local
/// `valkey-server`. A measurement, not a check: it prints the numbers recorded in change 0094.
/// `cargo nextest run --release --run-ignored only cluster_limit_latency --no-capture`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, not a check: run it with --release and --run-ignored only"]
async fn cluster_limit_latency() {
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("latency");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    // A limit nothing reaches: the measurement is the cost of counting, not of refusing.
    let open =
        json!({"average": 10_000_000, "burst": 10_000_000, "source": {"header": "x-client"}});
    let mut cluster = open.clone();
    cluster.as_object_mut().expect("object").extend(
        [
            ("scope".to_owned(), json!("cluster")),
            ("store".to_owned(), json!("main")),
            ("on_store_error".to_owned(), json!("deny")),
        ]
        .into_iter(),
    );
    for (version, (label, config)) in [("node", open), ("cluster", cluster)]
        .into_iter()
        .enumerate()
    {
        push(
            &podgate,
            &snapshot(version as u64 + 1, &[limited(upstream.addr, config)]),
        )
        .await;
        let proxy = podgate.proxy_addr;
        for connections in [1, 32] {
            let (rps, p50, p95, p99, failed) =
                tokio::task::spawn_blocking(move || oha(proxy, 8, connections))
                    .await
                    .expect("oha task");
            println!(
                "cluster limit latency: {label:7} c={connections:<2} {rps:8.0} req/s  p50 {p50:6.2} ms  p95 {p95:6.2} ms  p99 {p99:6.2} ms  non-200 {failed}"
            );
            assert_eq!(failed, 0);
        }
    }
}
