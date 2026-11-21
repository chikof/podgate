//! The `rate_limit` and `in_flight_req` middlewares through the real binary: the
//! source is the resolved client or a named header, per-source state is bounded and charged to
//! the tenant, a refusal reaches no upstream and takes no tenant slot, and a slot returns when a
//! request ends however it ends.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, Response, app, middleware, serving, snapshot, with_chain};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A backend that counts requests and answers `ok`; a request for `/slow` waits `slow` first.
struct Backend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Backend {
    async fn start(slow: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let addr = listener.local_addr().expect("backend addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(connection(stream, slow, Arc::clone(&counted)));
            }
        });
        Self { addr, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn connection(mut stream: TcpStream, slow: Duration, hits: Arc<AtomicUsize>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            hits.fetch_add(1, Ordering::SeqCst);
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            seen.drain(..end + 4);
            if head.to_ascii_lowercase().contains("upgrade: websocket") {
                echo_upgraded(stream).await;
                return;
            }
            if head.starts_with("GET /slow") {
                tokio::time::sleep(slow).await;
            }
            let response =
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// Answers `101` and then echoes every byte until the peer closes: a WebSocket upstream that
/// needs no framing.
async fn echo_upgraded(mut stream: TcpStream) {
    let reply =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    if stream.write_all(reply.as_bytes()).await.is_err() {
        return;
    }
    let mut buffer = [0_u8; 1024];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                if stream.write_all(&buffer[..read]).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// App `a` on `a.test` and `b.test` with one middleware `kind` called `limit` in its chain.
fn limited(upstream: SocketAddr, kind: &str, config: Value) -> Value {
    with_chain(
        app("a", &["a.test", "b.test"], &[serving("r1", upstream)]),
        &[middleware("limit", kind, config)],
    )
}

fn rate(burst: u32, source: Value) -> Value {
    let mut config = json!({ "average": 1, "period_secs": 3600, "burst": burst });
    config["source"] = source;
    config
}

async fn serve(app: Value, backend_tenant_budget: Option<u64>) -> Podgate {
    let podgate = Podgate::start().await;
    let mut pushed = snapshot(1, &[app]);
    if let Some(bytes) = backend_tenant_budget {
        pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(bytes);
    }
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    podgate
}

async fn keyed(podgate: &Podgate, host: &str, key: &str) -> Response {
    podgate
        .get_with_headers(host, "/", &[("X-Api-Key", key)])
        .await
}

fn assert_limited(response: &Response) {
    assert_eq!(response.status, 429, "{response:?}");
    assert_eq!(response.body, r#"{"error":"rate limit exceeded"}"#);
    assert_eq!(response.header("content-type"), Some("application/json"));
    let wait: u64 = response
        .header("retry-after")
        .expect("retry-after")
        .parse()
        .expect("whole seconds");
    assert!((1..=3600).contains(&wait), "retry-after {wait}");
}

/// The value of the sample of `/metrics` that starts with `series`.
async fn metric(podgate: &Podgate, series: &str) -> u64 {
    let text = podgate.admin_get("/metrics").await.body;
    text.lines()
        .find(|line| line.starts_with(series))
        .unwrap_or_else(|| panic!("no series {series} in\n{text}"))
        .rsplit(' ')
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("series {series} has no number"))
}

#[tokio::test]
async fn rate_limit_429_after_burst() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        limited(backend.addr, "rate_limit", rate(3, json!({ "ip": {} }))),
        None,
    )
    .await;
    for taken in 0..3 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!(response.status, 200, "request {taken}: {response:?}");
    }
    assert_limited(&podgate.get("a.test", "/").await);
    assert_limited(&podgate.get("a.test", "/").await);
    assert_eq!(backend.hits(), 3, "a refusal reaches no upstream");
}

#[tokio::test]
async fn rate_limit_per_source_isolated() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        limited(
            backend.addr,
            "rate_limit",
            rate(1, json!({ "header": "x-api-key" })),
        ),
        None,
    )
    .await;
    assert_eq!(keyed(&podgate, "a.test", "alice").await.status, 200);
    assert_limited(&keyed(&podgate, "a.test", "alice").await);
    assert_eq!(
        keyed(&podgate, "a.test", "bob").await.status,
        200,
        "another source has its own bucket"
    );
    assert_limited(&keyed(&podgate, "a.test", "bob").await);
}

#[tokio::test]
async fn rate_limit_host_source_is_per_host() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        limited(backend.addr, "rate_limit", rate(1, json!({ "host": true }))),
        None,
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_limited(&podgate.get("a.test", "/").await);
    assert_eq!(podgate.get("b.test", "/").await.status, 200);
    assert_limited(&podgate.get("b.test", "/").await);
}

#[tokio::test]
async fn rate_limit_absent_source_value_shares_bucket() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        limited(
            backend.addr,
            "rate_limit",
            rate(1, json!({ "header": "x-api-key" })),
        ),
        None,
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_limited(&podgate.get("a.test", "/").await);
    assert_limited(&keyed(&podgate, "a.test", "-").await);
    assert_eq!(
        keyed(&podgate, "a.test", "carol").await.status,
        200,
        "a client that names itself has its own bucket"
    );
}

#[tokio::test]
async fn rate_limit_ignores_forged_forwarded_for() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        limited(backend.addr, "rate_limit", rate(1, json!({ "ip": {} }))),
        None,
    )
    .await;
    let via = |chain: &'static str| {
        let podgate = &podgate;
        async move {
            podgate
                .get_with_headers("a.test", "/", &[("X-Forwarded-For", chain)])
                .await
        }
    };
    assert_eq!(via("203.0.113.1").await.status, 200);
    assert_limited(&via("203.0.113.2").await);
    assert_limited(&via("198.51.100.9").await);
}

#[tokio::test]
async fn rate_limit_reads_the_chain_a_trusted_proxy_sent() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    let mut pushed = snapshot(
        1,
        &[limited(
            backend.addr,
            "rate_limit",
            rate(1, json!({ "ip": {} })),
        )],
    );
    pushed["entry_points"] =
        json!([{"name": "web", "forwarded_headers": {"trusted_ips": ["127.0.0.0/8"]}}]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let via = |chain: &'static str| {
        let podgate = &podgate;
        async move {
            podgate
                .get_with_headers("a.test", "/", &[("X-Forwarded-For", chain)])
                .await
        }
    };
    assert_eq!(via("203.0.113.1").await.status, 200);
    assert_limited(&via("203.0.113.1").await);
    assert_eq!(
        via("203.0.113.2").await.status,
        200,
        "the trusted proxy's client is the source"
    );
}

#[tokio::test]
async fn rate_limit_flood_of_sources_is_limited_as_one() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        limited(
            backend.addr,
            "rate_limit",
            json!({
                "average": 1, "period_secs": 3600, "burst": 1,
                "source": { "header": "x-api-key" }, "max_sources": 8,
            }),
        ),
        None,
    )
    .await;
    let mut passed = 0;
    for source in 0..40 {
        if keyed(&podgate, "a.test", &format!("source-{source}"))
            .await
            .status
            == 200
        {
            passed += 1;
        }
    }
    assert_eq!(
        passed, 9,
        "eight sources got an entry, and all the others together got one token"
    );
    let overflow = metric(
        &podgate,
        r#"podgate_limiter_overflow_total{app="a",middleware="limit",type="rate_limit"}"#,
    )
    .await;
    assert_eq!(overflow, 32);
    assert_limited(&keyed(&podgate, "a.test", "source-0").await);
}

#[tokio::test]
async fn rate_limit_memory_charged_to_tenant() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        limited(
            backend.addr,
            "rate_limit",
            rate(1, json!({ "header": "x-api-key" })),
        ),
        None,
    )
    .await;
    let buffered = r#"podgate_tenant_buffer_bytes{tenant="t1"}"#;
    let table = r#"podgate_limiter_table_bytes{app="a",middleware="limit",type="rate_limit"}"#;
    assert_eq!(
        metric(&podgate, table).await,
        0,
        "nothing is charged before a request"
    );
    let text = podgate.admin_get("/metrics").await.body;
    assert!(
        !text.contains(&format!("{buffered} ")) || text.contains(&format!("{buffered} 0\n")),
        "the tenant holds nothing before a request"
    );
    assert_eq!(keyed(&podgate, "a.test", "a").await.status, 200);
    let charged = metric(&podgate, buffered).await;
    assert!(
        (10_000 * 16..10_000 * 24).contains(&charged),
        "10,000 sources of 16 bytes and their locks: {charged}"
    );
    assert_eq!(metric(&podgate, table).await, charged);
    for source in 0..200 {
        keyed(&podgate, "a.test", &format!("s{source}")).await;
    }
    assert_eq!(
        metric(&podgate, buffered).await,
        charged,
        "a flood of sources does not grow the charge"
    );
}

#[tokio::test]
async fn rate_limit_table_over_budget_rejected() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    let sources = |max_sources: u32| {
        json!({
            "average": 1, "burst": 1, "source": { "ip": {} }, "max_sources": max_sources,
        })
    };
    let push = |version: u64, app: Value, budget: u64| {
        let podgate = &podgate;
        async move {
            let mut pushed = snapshot(version, &[app]);
            pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(budget);
            podgate.push_snapshot(&pushed).await
        }
    };

    let alone = push(
        1,
        limited(backend.addr, "rate_limit", sources(100_000)),
        100_000,
    )
    .await;
    assert_eq!(alone.status, 422, "{}", alone.body);
    let conflict = alone.json()["conflicts"][0].clone();
    assert_eq!(conflict["code"], "invalid_middleware", "{conflict}");
    assert_eq!(conflict["max_buffer_bytes"], 100_000);

    let two = with_chain(
        app("a", &["a.test"], &[serving("r1", backend.addr)]),
        &[
            middleware("one", "rate_limit", sources(10_000)),
            middleware(
                "two",
                "in_flight_req",
                json!({"amount": 1, "source": {"ip": {}}, "max_sources": 10_000}),
            ),
        ],
    );
    let together = push(2, two.clone(), 300_000).await;
    assert_eq!(together.status, 422, "{}", together.body);
    let conflicts = together.json()["conflicts"].clone();
    assert_eq!(conflicts.as_array().map(Vec::len), Some(1), "{conflicts}");
    assert_eq!(conflicts[0]["at"], "middleware two");

    let fits = push(3, two, 400_000).await;
    assert_eq!(fits.status, 200, "{}", fits.body);
}

#[tokio::test]
async fn rate_limit_state_survives_unrelated_push() {
    let backend = Backend::start(Duration::ZERO).await;
    let other = Backend::start(Duration::ZERO).await;
    let mine = limited(backend.addr, "rate_limit", rate(2, json!({ "ip": {} })));
    let podgate = Podgate::start().await;
    let theirs = |host: &str| app("other", &[host], &[serving("r1", other.addr)]);
    let first = podgate
        .push_snapshot(&snapshot(1, &[mine.clone(), theirs("o1.test")]))
        .await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_limited(&podgate.get("a.test", "/").await);

    let unrelated = podgate
        .push_snapshot(&snapshot(2, &[mine.clone(), theirs("o2.test")]))
        .await;
    assert_eq!(unrelated.status, 200, "{}", unrelated.body);
    assert_limited(&podgate.get("a.test", "/").await);
}

#[tokio::test]
async fn rate_limit_changed_config_resets() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        limited(backend.addr, "rate_limit", rate(1, json!({ "ip": {} }))),
        None,
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_limited(&podgate.get("a.test", "/").await);

    let changed = podgate
        .push_snapshot(&snapshot(
            2,
            &[limited(
                backend.addr,
                "rate_limit",
                rate(2, json!({ "ip": {} })),
            )],
        ))
        .await;
    assert_eq!(changed.status, 200, "{}", changed.body);
    assert_eq!(
        podgate.get("a.test", "/").await.status,
        200,
        "a fresh bucket"
    );
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_limited(&podgate.get("a.test", "/").await);
}

#[tokio::test]
async fn rate_limit_before_admission() {
    let slow = Backend::start(Duration::from_millis(1500)).await;
    let fast = Backend::start(Duration::ZERO).await;
    let open = app("open", &["open.test"], &[serving("r1", slow.addr)]);
    let closed = with_chain(
        app("closed", &["closed.test"], &[serving("r1", fast.addr)]),
        &[middleware(
            "limit",
            "rate_limit",
            rate(1, json!({ "header": "x-api-key" })),
        )],
    );
    let mut pushed = snapshot(1, &[open, closed]);
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(1);
    let podgate = Podgate::start().await;
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(keyed(&podgate, "closed.test", "k").await.status, 200);

    let inflight = r#"podgate_tenant_inflight{tenant="t1"}"#;
    let rejected = r#"podgate_tenant_inflight_rejected_total{tenant="t1"}"#;
    let (held, ()) = tokio::join!(
        async {
            podgate
                .get_with_headers("open.test", "/slow", &[("X-Api-Key", "x")])
                .await
        },
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(metric(&podgate, inflight).await, 1, "the slow request");
            for _ in 0..20 {
                assert_limited(&keyed(&podgate, "closed.test", "k").await);
            }
            assert_eq!(
                metric(&podgate, inflight).await,
                1,
                "a flood of refusals took no slot"
            );
            assert_eq!(metric(&podgate, rejected).await, 0);
        }
    );
    assert_eq!(held.status, 200, "{held:?}");
    assert_eq!(fast.hits(), 1, "a refusal reaches no upstream");
}

#[tokio::test]
async fn in_flight_req_caps_per_source() {
    let backend = Backend::start(Duration::from_millis(800)).await;
    let podgate = serve(
        limited(
            backend.addr,
            "in_flight_req",
            json!({ "amount": 1, "source": { "header": "x-api-key" } }),
        ),
        None,
    )
    .await;
    let slow = |key: &'static str| {
        let podgate = &podgate;
        async move {
            podgate
                .get_with_headers("a.test", "/slow", &[("X-Api-Key", key)])
                .await
        }
    };
    let (first, (second, other)) = tokio::join!(slow("alice"), async {
        tokio::time::sleep(Duration::from_millis(250)).await;
        tokio::join!(keyed(&podgate, "a.test", "alice"), slow("bob"),)
    });
    assert_eq!(first.status, 200, "{first:?}");
    assert_eq!(second.status, 429, "{second:?}");
    assert_eq!(second.body, r#"{"error":"too many requests in flight"}"#);
    assert_eq!(second.header("retry-after"), Some("1"));
    assert_eq!(
        other.status, 200,
        "another source has its own count: {other:?}"
    );
    assert_eq!(
        keyed(&podgate, "a.test", "alice").await.status,
        200,
        "the slot came back when the request completed"
    );
}

async fn until_served(podgate: &Podgate, key: &str, within: Duration) -> Response {
    let deadline = Instant::now() + within;
    loop {
        let response = keyed(podgate, "a.test", key).await;
        if response.status != 429 || Instant::now() >= deadline {
            return response;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn in_flight_req_releases_on_abort() {
    let backend = Backend::start(Duration::from_secs(30)).await;
    let podgate = serve(
        limited(
            backend.addr,
            "in_flight_req",
            json!({ "amount": 1, "source": { "header": "x-api-key" } }),
        ),
        None,
    )
    .await;
    let mut client = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    client
        .write_all(b"GET /slow HTTP/1.1\r\nHost: a.test\r\nX-Api-Key: quitter\r\n\r\n")
        .await
        .expect("send");
    let deadline = Instant::now() + Duration::from_secs(5);
    while backend.hits() == 0 {
        assert!(
            Instant::now() < deadline,
            "the request never reached the backend"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let held = keyed(&podgate, "a.test", "quitter").await;
    assert_eq!(
        held.status, 429,
        "the aborted-to-be request holds the slot: {held:?}"
    );
    drop(client);
    let served = until_served(&podgate, "quitter", Duration::from_secs(5)).await;
    assert_eq!(
        served.status, 200,
        "the slot of the aborted request came back: {served:?}"
    );
}

#[tokio::test]
async fn in_flight_req_releases_on_upstream_error() {
    let dead = common::refused();
    let podgate = serve(
        limited(
            dead.addr,
            "in_flight_req",
            json!({ "amount": 1, "source": { "ip": {} } }),
        ),
        None,
    )
    .await;
    for attempt in 0..3 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!(
            response.status, 502,
            "attempt {attempt} reached the dead upstream, so the slot came back: {response:?}"
        );
    }
}

#[tokio::test]
async fn limits_invalid_config_rejected() {
    let backend = Backend::start(Duration::ZERO).await;
    let cases = [
        (
            "rate_limit",
            json!({"average": 0, "burst": 1, "source": {"ip": {}}}),
        ),
        (
            "rate_limit",
            json!({"average": 1, "burst": 0, "source": {"ip": {}}}),
        ),
        (
            "rate_limit",
            json!({"average": 1, "burst": 1, "source": {"ip": {}}, "max_sources": 0}),
        ),
        (
            "rate_limit",
            json!({"average": 1, "burst": 1, "source": {"ip": {}}, "max_sources": 1_000_001}),
        ),
        (
            "rate_limit",
            json!({"average": 1, "burst": 1, "period_secs": 0, "source": {"ip": {}}}),
        ),
        (
            "rate_limit",
            json!({"average": 1, "burst": 1, "source": {"header": "not a header"}}),
        ),
        (
            "rate_limit",
            json!({"average": 1, "burst": 1, "source": {"ip": {}}, "sourceCriterion": {}}),
        ),
        ("rate_limit", json!({"average": 1, "burst": 1})),
        ("in_flight_req", json!({"amount": 0, "source": {"ip": {}}})),
        (
            "in_flight_req",
            json!({"amount": 1, "source": {"ip": {}}, "max_sources": 0}),
        ),
        (
            "in_flight_req",
            json!({"amount": 1, "source": {"ip": {}}, "max_sources": 1_000_001}),
        ),
        (
            "in_flight_req",
            json!({"amount": 1, "source": {"host": false}}),
        ),
        (
            "in_flight_req",
            json!({"amount": 1, "source": {"cookie": "a"}}),
        ),
        (
            "rate_limit",
            json!({"average": 1, "burst": 1, "source": {"ip": {"ipv6_subnet_bits": 0}}}),
        ),
        (
            "rate_limit",
            json!({"average": 1, "burst": 1, "source": {"ip": {"ipv6_subnet_bits": 129}}}),
        ),
        (
            "in_flight_req",
            json!({"amount": 1, "source": {"ip": {"ipv6_subnet": 64}}}),
        ),
    ];
    for (kind, config) in cases {
        let podgate = Podgate::start().await;
        let response = podgate
            .push_snapshot(&snapshot(1, &[limited(backend.addr, kind, config.clone())]))
            .await;
        assert_eq!(response.status, 422, "{kind} {config}: {}", response.body);
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_middleware",
            "{kind} {config}"
        );
    }
}

#[tokio::test]
async fn plan_lists_limit_changes() {
    let backend = Backend::start(Duration::ZERO).await;
    let both = |average: u32, burst: u32, amount: u32, source: Value| {
        with_chain(
            app("a", &["a.test"], &[serving("r1", backend.addr)]),
            &[
                middleware(
                    "rate",
                    "rate_limit",
                    json!({"average": average, "burst": burst, "source": source}),
                ),
                middleware(
                    "cap",
                    "in_flight_req",
                    json!({"amount": amount, "source": source}),
                ),
            ],
        )
    };
    let podgate = serve(both(10, 5, 5, json!({"ip": {}})), None).await;
    let kinds = |plan: &Response| -> Vec<String> {
        let mut kinds: Vec<String> = plan.json()["posture_changes"]
            .as_array()
            .expect("posture_changes")
            .iter()
            .map(|change| change["kind"].as_str().expect("kind").to_owned())
            .collect();
        kinds.sort();
        kinds
    };
    let plan = |apps: &[Value]| {
        let podgate = &podgate;
        let pushed = snapshot(2, apps);
        async move {
            let response = podgate.admin_post("/v1/snapshot/plan", &pushed).await;
            assert_eq!(response.status, 200, "{}", response.body);
            response
        }
    };

    let removed = plan(&[app("a", &["a.test"], &[serving("r1", backend.addr)])]).await;
    assert_eq!(
        kinds(&removed),
        ["in_flight_req_removed", "rate_limit_removed"]
    );
    let looser = plan(&[both(20, 5, 6, json!({"ip": {}}))]).await;
    assert_eq!(
        kinds(&looser),
        ["in_flight_req_loosened", "rate_limit_loosened"]
    );
    let burstier = plan(&[both(10, 6, 5, json!({"ip": {}}))]).await;
    assert_eq!(kinds(&burstier), ["rate_limit_loosened"]);
    let elsewhere = plan(&[both(10, 5, 5, json!({"header": "x-api-key"}))]).await;
    assert_eq!(
        kinds(&elsewhere),
        ["in_flight_req_source_changed", "rate_limit_source_changed"]
    );
    let stricter = plan(&[both(5, 2, 2, json!({"ip": {}}))]).await;
    assert!(kinds(&stricter).is_empty(), "{}", stricter.body);
    let same = plan(&[both(10, 5, 5, json!({"ip": {}}))]).await;
    assert!(kinds(&same).is_empty(), "{}", same.body);
}

/// A request whose trusted proxy (the test client) says the client is `chain`.
async fn forwarded(podgate: &Podgate, chain: &str) -> Response {
    podgate
        .get_with_headers("a.test", "/", &[("X-Forwarded-For", chain)])
        .await
}

async fn trusting_proxy(backend: &Backend, source: Value) -> Podgate {
    let podgate = Podgate::start().await;
    let mut pushed = snapshot(1, &[limited(backend.addr, "rate_limit", rate(1, source))]);
    pushed["entry_points"] =
        json!([{"name": "web", "forwarded_headers": {"trusted_ips": ["127.0.0.0/8"]}}]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    podgate
}

#[tokio::test]
async fn rate_limit_ipv6_keyed_by_subnet() {
    let backend = Backend::start(Duration::ZERO).await;

    let by_default = trusting_proxy(&backend, json!({ "ip": {} })).await;
    assert_eq!(forwarded(&by_default, "2001:db8:1:2::1").await.status, 200);
    assert_limited(&forwarded(&by_default, "2001:db8:1:2:ffff:ffff:ffff:ffff").await);
    assert_eq!(
        forwarded(&by_default, "2001:db8:1:3::1").await.status,
        200,
        "another /64 is another source"
    );
    assert_eq!(forwarded(&by_default, "203.0.113.1").await.status, 200);
    assert_eq!(
        forwarded(&by_default, "203.0.113.2").await.status,
        200,
        "IPv4 addresses are never merged"
    );

    let wide = trusting_proxy(&backend, json!({ "ip": { "ipv6_subnet_bits": 32 } })).await;
    assert_eq!(forwarded(&wide, "2001:db8:1::1").await.status, 200);
    assert_limited(&forwarded(&wide, "2001:db8:ffff::1").await);

    let exact = trusting_proxy(&backend, json!({ "ip": { "ipv6_subnet_bits": 128 } })).await;
    assert_eq!(forwarded(&exact, "2001:db8:1:2::1").await.status, 200);
    assert_eq!(
        forwarded(&exact, "2001:db8:1:2::2").await.status,
        200,
        "a full-length prefix counts every address"
    );
}

#[tokio::test]
async fn in_flight_req_held_for_websocket_lifetime() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        limited(
            backend.addr,
            "in_flight_req",
            json!({ "amount": 1, "source": { "header": "x-api-key" } }),
        ),
        None,
    )
    .await;
    let mut socket = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    socket
        .write_all(
            b"GET /chat HTTP/1.1\r\nHost: a.test\r\nX-Api-Key: ws\r\nConnection: Upgrade\r\n\
              Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .expect("send the upgrade");
    let mut head = Vec::new();
    let mut chunk = [0_u8; 512];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut chunk))
            .await
            .expect("the upgrade answers")
            .expect("read");
        assert_ne!(read, 0, "closed before the 101: {head:?}");
        head.extend_from_slice(&chunk[..read]);
    }
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    socket
        .write_all(b"ping")
        .await
        .expect("send through the tunnel");
    let mut echoed = [0_u8; 4];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut echoed))
        .await
        .expect("the echo arrives")
        .expect("read");
    assert_eq!(&echoed, b"ping");

    let during = keyed(&podgate, "a.test", "ws").await;
    assert_eq!(
        during.status, 429,
        "the open connection holds the slot: {during:?}"
    );
    assert_eq!(keyed(&podgate, "a.test", "other").await.status, 200);

    drop(socket);
    let after = until_served(&podgate, "ws", Duration::from_secs(5)).await;
    assert_eq!(
        after.status, 200,
        "closing the connection returned the slot: {after:?}"
    );
}
