//! Cluster-scope `in_flight_req` through the real binary and a real `valkey-server`:
//! one cap across nodes, slots that come back when a request ends however it ends and when a
//! node dies without saying so (leases), a chosen behaviour when the store fails, keys that
//! isolate tenants, apps, middlewares and configurations, and a set that never outgrows `amount`.

// The builders take the JSON they are given, as the ones in `common` do.
#![allow(clippy::needless_pass_by_value)]

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::valkey::{self, Valkey};
use common::{Podgate, Response, app, middleware, serving, snapshot, with_chain};
use podgate::ratelimit_store::OPEN_FOR;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

/// Longest a test waits for something that must happen.
const WAIT: Duration = Duration::from_secs(10);

/// What a client waits for one response; a held request outlives the others.
const IO: Duration = Duration::from_secs(40);

/// Where the store keeps the slots of every cluster `in_flight_req`.
const KEYS: &str = "podgate:ifr:*";

/// A backend that counts the requests it receives and answers `ok`: `/slow` after `slow`,
/// `/hold` once the test adds a permit to `release`, anything else at once.
struct Backend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    release: Arc<Semaphore>,
}

impl Backend {
    async fn start(slow: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let addr = listener.local_addr().expect("backend addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let (counted, gate) = (Arc::clone(&hits), Arc::clone(&release));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(stream, slow, Arc::clone(&counted), Arc::clone(&gate)));
            }
        });
        Self {
            addr,
            hits,
            release,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// Lets `count` held requests answer.
    fn release(&self, count: usize) {
        self.release.add_permits(count);
    }

    async fn wait_hits(&self, count: usize) {
        let deadline = Instant::now() + WAIT;
        while self.hits() < count {
            assert!(
                Instant::now() < deadline,
                "the backend saw {} requests, not {count}",
                self.hits()
            );
            sleep(Duration::from_millis(20)).await;
        }
    }
}

async fn serve(
    mut stream: TcpStream,
    slow: Duration,
    hits: Arc<AtomicUsize>,
    gate: Arc<Semaphore>,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
    hits.fetch_add(1, Ordering::SeqCst);
    let head = String::from_utf8_lossy(&seen);
    if head.starts_with("GET /slow") {
        sleep(slow).await;
    } else if head.starts_with("GET /hold") {
        match gate.acquire().await {
            Ok(permit) => permit.forget(),
            Err(_) => return,
        }
    }
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    drop(stream.write_all(response.as_bytes()).await);
}

/// App `a` on `a.test` with one `in_flight_req` called `cap` in its chain.
fn capped(upstream: SocketAddr, config: Value) -> Value {
    with_chain(
        app("a", &["a.test"], &[serving("r1", upstream)]),
        &[middleware("cap", "in_flight_req", config)],
    )
}

/// A cluster cap on store `main`, counted per `x-client`.
fn cap(amount: u32, extra: Value) -> Value {
    let mut config = json!({
        "amount": amount, "source": {"header": "x-client"}, "scope": "cluster", "store": "main",
    });
    let object = config.as_object_mut().expect("object");
    object.extend(extra.as_object().expect("object").clone());
    config
}

fn deny() -> Value {
    json!({"on_store_error": "deny"})
}

fn allow(amount: u32) -> Value {
    json!({"on_store_error": "allow", "local_fallback": {"amount": amount}})
}

/// The stores file naming `store` as `main` for tenant `t1`.
fn one_store(dir: &Path, store: Value) -> std::path::PathBuf {
    valkey::stores_file(dir, &json!({ "main": store }))
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

async fn hit(podgate: &Podgate, path: &str, who: &str) -> Response {
    podgate
        .get_with_headers("a.test", path, &[("x-client", who)])
        .await
}

/// Sends `GET path` as `who` to `proxy` for `host` and returns the connection without reading.
async fn open(proxy: SocketAddr, host: &str, path: &str, who: &str) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.expect("connect");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nx-client: {who}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send the request");
    stream
}

/// The status of the response on `stream`.
async fn status(mut stream: TcpStream) -> u16 {
    let mut raw = Vec::new();
    timeout(IO, stream.read_to_end(&mut raw))
        .await
        .expect("a response in time")
        .expect("read the response");
    String::from_utf8_lossy(&raw)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status in {:?}", String::from_utf8_lossy(&raw)))
}

/// Slots every key of the store holds, added up.
fn held_slots(valkey: &Valkey) -> usize {
    valkey
        .keys(KEYS)
        .iter()
        .map(|key| valkey.cli(&["ZCARD", key]).parse::<usize>().unwrap_or(0))
        .sum()
}

/// Waits until the store holds `count` slots in all.
async fn wait_slots(valkey: &Valkey, count: usize) {
    let deadline = Instant::now() + WAIT;
    while held_slots(valkey) != count {
        assert!(
            Instant::now() < deadline,
            "the store holds {} slots, not {count}: {:?}",
            held_slots(valkey),
            valkey.keys(KEYS)
        );
        sleep(Duration::from_millis(25)).await;
    }
}

/// Requests `/` as `who` until the answer is not `429`, within `within`.
async fn until_served(podgate: &Podgate, who: &str, within: Duration) -> Response {
    let deadline = Instant::now() + within;
    loop {
        let response = hit(podgate, "/", who).await;
        if response.status != 429 || Instant::now() >= deadline {
            return response;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn assert_over_cap(response: &Response) {
    assert_eq!(response.status, 429, "{response:?}");
    assert_eq!(response.body, r#"{"error":"too many requests in flight"}"#);
    assert_eq!(response.header("retry-after"), Some("1"));
}

/// The value of the metric line that starts with `series`.
fn metric(text: &str, series: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(series)?.trim().parse().ok())
}

async fn metrics(podgate: &Podgate) -> String {
    podgate.admin_get("/metrics").await.body
}

/// The code of the first rejection of a refused push.
fn rejection_code(response: &Response) -> String {
    assert_eq!(response.status, 422, "{}", response.body);
    response.json()["conflicts"][0]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn cluster_inflight_shared_across_nodes() {
    let valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-shared");
    let stores = one_store(&dir, valkey::entry(valkey.addr()));
    let (first, second) = (node(&stores).await, node(&stores).await);
    let pushed = snapshot(1, &[capped(backend.addr, cap(3, deny()))]);
    push(&first, &pushed).await;
    push(&second, &pushed).await;

    // Two on one node, one on the other: three in all, each node alone is under its cap.
    let held = vec![
        open(first.proxy_addr, "a.test", "/hold", "client").await,
        open(first.proxy_addr, "a.test", "/hold", "client").await,
        open(second.proxy_addr, "a.test", "/hold", "client").await,
    ];
    backend.wait_hits(3).await;
    wait_slots(&valkey, 3).await;
    for node in [&first, &second] {
        assert_over_cap(&hit(node, "/", "client").await);
    }
    assert_eq!(
        hit(&first, "/", "other").await.status,
        200,
        "another source has its own slots"
    );
    assert_eq!(backend.hits(), 4, "a refusal reaches no upstream");

    backend.release(3);
    for stream in held {
        assert_eq!(status(stream).await, 200);
    }
    let served = until_served(&second, "client", WAIT).await;
    assert_eq!(served.status, 200, "the slots came back: {served:?}");
    wait_slots(&valkey, 0).await;
}

#[tokio::test]
async fn cluster_inflight_released_on_complete_and_abort() {
    let valkey = Valkey::start().await;
    let backend = Backend::start(Duration::from_millis(800)).await;
    let dir = valkey::scratch("ifr-release");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    push(
        &podgate,
        &snapshot(1, &[capped(backend.addr, cap(1, deny()))]),
    )
    .await;

    // Completion.
    let (slow, ()) = tokio::join!(hit(&podgate, "/slow", "client"), async {
        sleep(Duration::from_millis(300)).await;
        assert_eq!(held_slots(&valkey), 1, "the request holds its slot");
        assert_over_cap(&hit(&podgate, "/", "client").await);
    });
    assert_eq!(slow.status, 200, "{slow:?}");
    wait_slots(&valkey, 0).await;
    assert_eq!(hit(&podgate, "/", "client").await.status, 200);

    // The client goes away while the upstream is still working.
    let seen = backend.hits();
    let client = open(podgate.proxy_addr, "a.test", "/hold", "client").await;
    backend.wait_hits(seen + 1).await;
    wait_slots(&valkey, 1).await;
    assert_over_cap(&hit(&podgate, "/", "client").await);
    drop(client);
    wait_slots(&valkey, 0).await;
    let served = until_served(&podgate, "client", WAIT).await;
    assert_eq!(served.status, 200, "{served:?}");
}

#[tokio::test]
async fn cluster_inflight_lease_renewed_for_long_request() {
    let valkey = Valkey::start().await;
    let backend = Backend::start(Duration::from_secs(14)).await;
    let dir = valkey::scratch("ifr-renew");
    let stores = one_store(&dir, valkey::entry(valkey.addr()));
    // The harness's upstream read timeout is 5 seconds; this request takes 14.
    let podgate = Podgate::start_with_env(&[
        (
            "RATE_LIMIT_STORES_FILE",
            stores.to_str().expect("utf-8 path"),
        ),
        ("REQUEST_TIMEOUT_SECS", "30"),
    ])
    .await;
    push(
        &podgate,
        &snapshot(
            1,
            &[capped(
                backend.addr,
                cap(1, json!({"on_store_error": "deny", "lease_secs": 10})),
            )],
        ),
    )
    .await;

    let started = Instant::now();
    let long = open(podgate.proxy_addr, "a.test", "/slow", "client").await;
    backend.wait_hits(1).await;
    wait_slots(&valkey, 1).await;

    // Past the first lease, which ended 10 seconds after the request started.
    sleep(Duration::from_secs(12).saturating_sub(started.elapsed())).await;
    assert_eq!(held_slots(&valkey), 1, "the lease was extended");
    assert_over_cap(&hit(&podgate, "/", "client").await);
    let renewals = metric(
        &metrics(&podgate).await,
        "podgate_inflight_lease_renewals_total",
    );
    assert!(renewals >= Some(1), "{renewals:?}");

    assert_eq!(status(long).await, 200);
    wait_slots(&valkey, 0).await;
    assert_eq!(hit(&podgate, "/", "client").await.status, 200);
}

#[tokio::test]
async fn cluster_inflight_crashed_node_leases_expire() {
    let valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-crash");
    let stores = one_store(&dir, valkey::entry(valkey.addr()));
    let (doomed, survivor) = (node(&stores).await, node(&stores).await);
    let pushed = snapshot(
        1,
        &[capped(
            backend.addr,
            cap(2, json!({"on_store_error": "deny", "lease_secs": 10})),
        )],
    );
    push(&doomed, &pushed).await;
    push(&survivor, &pushed).await;

    let held = [
        open(doomed.proxy_addr, "a.test", "/hold", "client").await,
        open(doomed.proxy_addr, "a.test", "/hold", "client").await,
    ];
    backend.wait_hits(2).await;
    wait_slots(&valkey, 2).await;
    assert_over_cap(&hit(&survivor, "/", "client").await);

    // SIGKILL: the node says goodbye to nobody.
    let killed = Instant::now();
    drop(doomed);
    assert_eq!(held_slots(&valkey), 2, "nothing released the slots");
    sleep(Duration::from_secs(2)).await;
    assert_over_cap(&hit(&survivor, "/", "client").await);

    let served = until_served(&survivor, "client", Duration::from_secs(20)).await;
    assert_eq!(served.status, 200, "the leases ran out: {served:?}");
    let freed_after = killed.elapsed();
    assert!(
        freed_after >= Duration::from_secs(4),
        "freed by the lease, not by a release: after {freed_after:?}"
    );
    assert!(freed_after <= Duration::from_secs(15), "{freed_after:?}");
    drop(held);
}

#[tokio::test]
async fn inflight_store_killed_allow_uses_local_fallback() {
    let mut valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-allow");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    push(
        &podgate,
        &snapshot(1, &[capped(backend.addr, cap(100, allow(2)))]),
    )
    .await;
    let first = open(podgate.proxy_addr, "a.test", "/hold", "client").await;
    backend.wait_hits(1).await;
    wait_slots(&valkey, 1).await;

    valkey.stop();
    // The node's own count includes the request the store knew about: one more fits the
    // fallback of 2, the next does not.
    let second = open(podgate.proxy_addr, "a.test", "/hold", "client").await;
    backend.wait_hits(2).await;
    assert_over_cap(&hit(&podgate, "/", "client").await);
    assert_eq!(
        hit(&podgate, "/", "other").await.status,
        200,
        "another source has its own fallback count"
    );
    let text = metrics(&podgate).await;
    assert_eq!(
        metric(&text, r#"podgate_inflight_store_up{store="main"}"#),
        Some(0)
    );
    assert_eq!(
        metric(
            &text,
            r#"podgate_inflight_store_errors_total{store="main",mode="allow"}"#
        ),
        Some(3),
        "the three requests that met the dead store"
    );

    backend.release(2);
    assert_eq!(status(first).await, 200);
    assert_eq!(status(second).await, 200);
    let served = until_served(&podgate, "client", WAIT).await;
    assert_eq!(
        served.status, 200,
        "the node's own count came back: {served:?}"
    );
}

#[tokio::test]
async fn inflight_store_killed_deny_503() {
    let mut valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-deny");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    push(
        &podgate,
        &snapshot(1, &[capped(backend.addr, cap(100, deny()))]),
    )
    .await;
    assert_eq!(hit(&podgate, "/", "client").await.status, 200);

    valkey.stop();
    for _ in 0..8 {
        let response = hit(&podgate, "/", "client").await;
        assert_eq!(response.status, 503, "{response:?}");
        assert_eq!(response.header("retry-after"), Some("1"));
        assert_eq!(
            response.json(),
            json!({"error": "rate limiter unavailable"})
        );
    }
    assert_eq!(backend.hits(), 1, "a refusal reaches no upstream");
    let text = metrics(&podgate).await;
    assert_eq!(
        metric(
            &text,
            r#"podgate_inflight_store_errors_total{store="main",mode="deny"}"#
        ),
        Some(8)
    );
    assert_eq!(
        metric(&text, r#"podgate_inflight_store_up{store="main"}"#),
        Some(0)
    );
}

#[tokio::test]
async fn inflight_store_recovery() {
    let mut valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-recovery");
    let stores = one_store(&dir, valkey::entry(valkey.addr()));
    let (first, second) = (node(&stores).await, node(&stores).await);
    let pushed = snapshot(1, &[capped(backend.addr, cap(1, deny()))]);
    push(&first, &pushed).await;
    push(&second, &pushed).await;
    assert_eq!(hit(&first, "/", "client").await.status, 200);

    // Five errors open the circuit.
    valkey.stop();
    for _ in 0..5 {
        assert_eq!(hit(&first, "/", "client").await.status, 503);
    }
    valkey.restart().await;

    // Open for OPEN_FOR, then one request probes the returned store.
    let deadline = Instant::now() + OPEN_FOR + WAIT;
    let mut polls = 0;
    loop {
        polls += 1;
        let response = hit(&first, "/", &format!("probe-{polls}")).await;
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

    // The cluster cap works again, across both nodes: a slot taken on one is felt by the other.
    let seen = backend.hits();
    let held = open(first.proxy_addr, "a.test", "/hold", "client").await;
    backend.wait_hits(seen + 1).await;
    wait_slots(&valkey, 1).await;
    assert_over_cap(&hit(&second, "/", "client").await);
    assert_eq!(
        metric(
            &metrics(&first).await,
            r#"podgate_inflight_store_up{store="main"}"#
        ),
        Some(1)
    );
    backend.release(1);
    assert_eq!(status(held).await, 200);
    let served = until_served(&second, "client", WAIT).await;
    assert_eq!(served.status, 200, "{served:?}");
}

#[tokio::test]
async fn cluster_inflight_keys_isolated() {
    let valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-isolated");
    let mut entry = valkey::entry(valkey.addr());
    entry["tenants"] = json!(["t1", "t2"]);
    let podgate = node(&one_store(&dir, entry)).await;
    let build = |version: u64, amount: u32| {
        let first = with_chain(
            app("a", &["a.test"], &[serving("r1", backend.addr)]),
            &[middleware("cap", "in_flight_req", cap(amount, deny()))],
        );
        let mut second = with_chain(
            app("b", &["b.test"], &[serving("r1", backend.addr)]),
            &[middleware("cap", "in_flight_req", cap(1, deny()))],
        );
        second["tenant"] = json!("t2");
        // One app with two caps of its own: the middleware name is part of the key.
        let third = with_chain(
            app("c", &["c.test"], &[serving("r1", backend.addr)]),
            &[
                middleware("m1", "in_flight_req", cap(1, deny())),
                middleware("m2", "in_flight_req", cap(1, deny())),
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

    let proxy = podgate.proxy_addr;
    let held = [
        open(proxy, "a.test", "/hold", "same").await,
        open(proxy, "b.test", "/hold", "same").await,
        open(proxy, "c.test", "/hold", "same").await,
    ];
    backend.wait_hits(3).await;
    wait_slots(&valkey, 4).await;
    assert_eq!(valkey.keys("podgate:ifr:t1:a:cap:*").len(), 1);
    assert_eq!(valkey.keys("podgate:ifr:t2:b:cap:*").len(), 1);
    assert_eq!(valkey.keys("podgate:ifr:t1:c:m1:*").len(), 1);
    assert_eq!(valkey.keys("podgate:ifr:t1:c:m2:*").len(), 1);
    assert_eq!(valkey.keys(KEYS).len(), 4);
    for host in ["a.test", "b.test", "c.test"] {
        let response = podgate
            .get_with_headers(host, "/", &[("x-client", "same")])
            .await;
        assert_over_cap(&response);
    }

    // A changed declaration counts apart: its first request passes though the old key is full.
    push(&podgate, &build(2, 2)).await;
    let again = open(proxy, "a.test", "/hold", "same").await;
    backend.wait_hits(4).await;
    let keys = valkey.keys("podgate:ifr:t1:a:cap:*");
    assert_eq!(keys.len(), 2, "{keys:?}");
    let fingerprints: Vec<&str> = keys
        .iter()
        .map(|key| key.split(':').nth(5).expect("fingerprint"))
        .collect();
    assert_ne!(fingerprints[0], fingerprints[1]);

    backend.release(4);
    for stream in held.into_iter().chain([again]) {
        assert_eq!(status(stream).await, 200);
    }
}

#[tokio::test]
async fn cluster_inflight_set_bounded() {
    const AMOUNT: usize = 5;
    const REQUESTS: usize = 60;
    let valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-bounded");
    let stores = one_store(&dir, valkey::entry(valkey.addr()));
    let (first, second) = (node(&stores).await, node(&stores).await);
    let pushed = snapshot(1, &[capped(backend.addr, cap(5, deny()))]);
    push(&first, &pushed).await;
    push(&second, &pushed).await;

    let mut requests = JoinSet::new();
    for number in 0..REQUESTS {
        let proxy = if number % 2 == 0 {
            first.proxy_addr
        } else {
            second.proxy_addr
        };
        requests.spawn(async move { status(open(proxy, "a.test", "/hold", "client").await).await });
    }
    let mut refused = 0;
    let deadline = Instant::now() + WAIT;
    while refused < REQUESTS - AMOUNT {
        assert!(Instant::now() < deadline, "{refused} refused so far");
        assert!(
            held_slots(&valkey) <= AMOUNT,
            "the set outgrew amount: {}",
            held_slots(&valkey)
        );
        if let Ok(Some(done)) = timeout(Duration::from_millis(20), requests.join_next()).await {
            assert_eq!(done.expect("request task"), 429);
            refused += 1;
        }
    }
    backend.wait_hits(AMOUNT).await;
    assert_eq!(held_slots(&valkey), AMOUNT);
    assert_eq!(backend.hits(), AMOUNT, "only amount requests got through");
    let keys = valkey.keys(KEYS);
    assert_eq!(keys.len(), 1, "{keys:?}");
    let ttl: i64 = valkey.cli(&["PTTL", &keys[0]]).parse().expect("a ttl");
    assert!(
        (1..=60_000).contains(&ttl),
        "the key expires with its leases: {ttl}"
    );

    backend.release(AMOUNT);
    while let Some(done) = requests.join_next().await {
        assert_eq!(done.expect("request task"), 200);
    }
    wait_slots(&valkey, 0).await;
    assert!(valkey.keys(KEYS).is_empty(), "an empty set leaves no key");
}

#[tokio::test]
async fn cluster_inflight_config_rejected() {
    let valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-config");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut config = cap(5, deny());
        edit(&mut config);
        snapshot(1, &[capped(backend.addr, config)])
    };
    let without = |field: &'static str| {
        with(&move |config| {
            config.as_object_mut().expect("object").remove(field);
        })
    };
    let wrong: Vec<(&str, Value)> = vec![
        ("no on_store_error", without("on_store_error")),
        ("no store", without("store")),
        (
            "allow without local_fallback",
            with(&|config| config["on_store_error"] = json!("allow")),
        ),
        (
            "deny with local_fallback",
            with(&|config| config["local_fallback"] = json!({"amount": 1})),
        ),
        (
            "empty local_fallback",
            with(&|config| {
                *config = cap(5, json!({"on_store_error": "allow", "local_fallback": {}}));
            }),
        ),
        (
            "local_fallback of zero",
            with(&|config| *config = cap(5, allow(0))),
        ),
        (
            "unknown field in local_fallback",
            with(&|config| {
                *config = cap(
                    5,
                    json!({"on_store_error": "allow", "local_fallback": {"amount": 1, "burst": 1}}),
                );
            }),
        ),
        (
            "unknown store",
            with(&|config| config["store"] = json!("nope")),
        ),
        (
            "store that is an address",
            with(&|config| config["store"] = json!("redis://127.0.0.1:6379")),
        ),
        (
            "an address field",
            with(&|config| config["url"] = json!("redis://127.0.0.1:6379")),
        ),
        (
            "amount above 10,000",
            with(&|config| config["amount"] = json!(10_001)),
        ),
        (
            "lease below 10 seconds",
            with(&|config| config["lease_secs"] = json!(9)),
        ),
        (
            "lease above an hour",
            with(&|config| config["lease_secs"] = json!(3601)),
        ),
        (
            "cluster fields on a node limit",
            with(&|config| config["scope"] = json!("node")),
        ),
        (
            "failure mode without a scope",
            snapshot(
                1,
                &[capped(
                    backend.addr,
                    json!({"amount": 5, "source": {"ip": {}}, "on_store_error": "deny"}),
                )],
            ),
        ),
        (
            "an unknown scope",
            with(&|config| config["scope"] = json!("region")),
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

    // The bounds themselves are fine.
    let good: Vec<Value> = vec![
        with(&|config| config["amount"] = json!(10_000)),
        with(&|config| config["lease_secs"] = json!(10)),
        with(&|config| config["lease_secs"] = json!(3600)),
        with(&|config| *config = cap(5, allow(1))),
    ];
    for (number, pushed) in good.iter().enumerate() {
        let mut pushed = pushed.clone();
        pushed["version"] = json!(10 + number);
        push(&podgate, &pushed).await;
    }
    // A node-scope cap keeps working without a store and above the cluster ceiling.
    let node_scope = snapshot(
        100,
        &[capped(
            backend.addr,
            json!({"amount": 50_000, "source": {"ip": {}}}),
        )],
    );
    push(&podgate, &node_scope).await;

    // A process with no store at all, and a store the tenant is not listed for, give the same
    // refusal as an unknown name.
    let bare = Podgate::start().await;
    let response = bare
        .push_snapshot(&snapshot(1, &[capped(backend.addr, cap(5, deny()))]))
        .await;
    assert_eq!(rejection_code(&response), "invalid_middleware");
    let refused = common::refused();
    let mut entry = valkey::entry(refused.addr);
    entry["tenants"] = json!(["someone-else"]);
    let strangers = node(&one_store(&valkey::scratch("ifr-forbidden"), entry)).await;
    let forbidden = strangers
        .push_snapshot(&snapshot(1, &[capped(backend.addr, cap(5, deny()))]))
        .await;
    assert_eq!(rejection_code(&forbidden), "invalid_middleware");
    let mut unknown_cap = cap(5, deny());
    unknown_cap["store"] = json!("other");
    let unknown = strangers
        .push_snapshot(&snapshot(1, &[capped(backend.addr, unknown_cap)]))
        .await;
    assert_eq!(rejection_code(&unknown), "invalid_middleware");
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
async fn cluster_inflight_before_admission() {
    let mut valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-admission");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    let mut pushed = snapshot(1, &[capped(backend.addr, cap(1, deny()))]);
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(1);
    push(&podgate, &pushed).await;

    let inflight = r#"podgate_tenant_inflight{tenant="t1"}"#;
    let rejected = r#"podgate_tenant_inflight_rejected_total{tenant="t1"}"#;
    let held = open(podgate.proxy_addr, "a.test", "/hold", "client").await;
    backend.wait_hits(1).await;
    wait_slots(&valkey, 1).await;
    assert_eq!(
        metric(&metrics(&podgate).await, inflight),
        Some(1),
        "the held request"
    );

    for _ in 0..20 {
        assert_over_cap(&hit(&podgate, "/", "client").await);
    }
    let text = metrics(&podgate).await;
    assert_eq!(
        metric(&text, inflight),
        Some(1),
        "a flood of refusals took no tenant slot"
    );
    assert_eq!(metric(&text, rejected), Some(0));

    // The same for the refusal of a dead store.
    valkey.stop();
    for _ in 0..5 {
        assert_eq!(hit(&podgate, "/", "client").await.status, 503);
    }
    let text = metrics(&podgate).await;
    assert_eq!(metric(&text, inflight), Some(1));
    assert_eq!(metric(&text, rejected), Some(0));
    assert_eq!(backend.hits(), 1, "a refusal reaches no upstream");

    backend.release(1);
    assert_eq!(status(held).await, 200);
}

#[tokio::test]
async fn cluster_inflight_plan_lists_scope_changes() {
    let valkey = Valkey::start().await;
    let backend = Backend::start(Duration::ZERO).await;
    let dir = valkey::scratch("ifr-plan");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    let node_scope = json!({"amount": 5, "source": {"header": "x-client"}});
    push(
        &podgate,
        &snapshot(1, &[capped(backend.addr, node_scope.clone())]),
    )
    .await;
    let kinds = |plan: &Response| -> Vec<String> {
        plan.json()["posture_changes"]
            .as_array()
            .expect("posture_changes")
            .iter()
            .map(|change| change["kind"].as_str().expect("kind").to_owned())
            .collect()
    };
    let plan = |version: u64, config: Value| {
        let podgate = &podgate;
        let pushed = snapshot(version, &[capped(backend.addr, config)]);
        async move {
            let response = podgate.admin_post("/v1/snapshot/plan", &pushed).await;
            assert_eq!(response.status, 200, "{}", response.body);
            kinds(&response)
        }
    };

    assert!(
        plan(2, cap(5, deny())).await.is_empty(),
        "counting across nodes is stricter"
    );
    assert_eq!(
        plan(2, cap(5, allow(2))).await,
        ["in_flight_req_cluster_fail_open"]
    );
    push(
        &podgate,
        &snapshot(2, &[capped(backend.addr, cap(5, allow(2)))]),
    )
    .await;
    assert!(plan(3, cap(5, allow(2))).await.is_empty());
    assert_eq!(
        plan(3, cap(5, allow(3))).await,
        ["in_flight_req_loosened"],
        "a higher local fallback lets a node alone hold more"
    );
    assert!(plan(3, cap(5, allow(1))).await.is_empty());
    assert!(plan(3, cap(5, deny())).await.is_empty());
    assert_eq!(plan(3, node_scope).await, ["in_flight_req_scope_node"]);
}
