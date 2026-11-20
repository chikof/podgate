//! The `ip_allow_list` middleware through the real binary: the client address it
//! checks is the entry point's resolved one, forged forwarding headers do not move it, and a
//! refusal reaches no upstream and takes no tenant slot.
//!
//! The test client connects from `127.0.0.1`, so `trusted_ips: ["127.0.0.0/8"]` makes it a
//! trusted proxy whose `X-Forwarded-For` is read, and no policy makes it an ordinary client.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{Podgate, Response, app, middleware, serving, snapshot, with_chain};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A backend that counts requests and answers `ok` after `delay`.
struct Backend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Backend {
    async fn start(delay: Duration) -> Self {
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
                tokio::spawn(connection(stream, delay, Arc::clone(&counted)));
            }
        });
        Self { addr, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn connection(mut stream: TcpStream, delay: Duration, hits: Arc<AtomicUsize>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            hits.fetch_add(1, Ordering::SeqCst);
            seen.drain(..end + 4);
            tokio::time::sleep(delay).await;
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

/// App `a.test` with one `ip_allow_list` middleware `config` in its chain.
fn guarded(upstream: SocketAddr, config: Value) -> Value {
    with_chain(
        app("a", &["a.test"], &[serving("r1", upstream)]),
        &[middleware("allow", "ip_allow_list", config)],
    )
}

fn with_policy(mut snapshot: Value, trusted_ips: &[&str]) -> Value {
    snapshot["entry_points"] =
        json!([{"name": "web", "forwarded_headers": {"trusted_ips": trusted_ips}}]);
    snapshot
}

/// podgate with the guarded app pushed; `trusted` makes the test client a trusted proxy.
async fn serve(config: Value, trusted: bool, backend: &Backend) -> Podgate {
    let podgate = Podgate::start().await;
    let mut pushed = snapshot(1, &[guarded(backend.addr, config)]);
    if trusted {
        pushed = with_policy(pushed, &["127.0.0.0/8"]);
    }
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    podgate
}

async fn get_via(podgate: &Podgate, forwarded_for: &str) -> Response {
    podgate
        .get_with_headers("a.test", "/", &[("X-Forwarded-For", forwarded_for)])
        .await
}

fn assert_forbidden(response: &Response) {
    assert_eq!(response.status, 403, "{response:?}");
    assert_eq!(response.body, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn ip_allow_passes_listed() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "source_range": ["127.0.0.0/8", "2001:db8::/32"] }),
        false,
        &backend,
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "ok");
    assert_eq!(backend.hits(), 1);
}

#[tokio::test]
async fn ip_allow_denies_unlisted() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "source_range": ["203.0.113.0/24", "2001:db8::/32"] }),
        false,
        &backend,
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_forbidden(&response);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert!(
        !response.body.contains("203.0.113") && !response.body.contains("2001"),
        "the refusal names no range: {}",
        response.body
    );
    assert_eq!(backend.hits(), 0, "a refusal reaches no upstream");
}

#[tokio::test]
async fn ip_allow_xff_depth() {
    let backend = Backend::start(Duration::ZERO).await;
    let chain = "203.0.113.9, 198.51.100.7";
    let by_default = serve(
        json!({ "source_range": ["203.0.113.0/24"] }),
        true,
        &backend,
    )
    .await;
    assert_forbidden(&get_via(&by_default, chain).await);
    assert_eq!(get_via(&by_default, "203.0.113.9").await.status, 200);

    let second = serve(
        json!({ "source_range": ["203.0.113.0/24"], "ip_strategy": { "depth": 2 } }),
        true,
        &backend,
    )
    .await;
    assert_eq!(get_via(&second, chain).await.status, 200);
    assert_forbidden(&get_via(&second, "198.51.100.7, 203.0.113.9").await);
    assert_eq!(
        get_via(&second, "203.0.113.9").await.status,
        403,
        "a chain shorter than depth falls back to the connection's peer"
    );
}

#[tokio::test]
async fn ip_allow_excluded() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({
            "source_range": ["203.0.113.0/24"],
            "ip_strategy": { "excluded": ["198.51.100.0/24", "192.0.2.1"] },
        }),
        true,
        &backend,
    )
    .await;
    let response = get_via(&podgate, "203.0.113.9, 198.51.100.7, 192.0.2.1").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_forbidden(&get_via(&podgate, "203.0.113.9, 198.51.100.7, 192.0.2.2").await);
}

#[tokio::test]
async fn ip_allow_spoofed_xff_ignored() {
    let backend = Backend::start(Duration::ZERO).await;
    for strategy in [
        json!({}),
        json!({ "depth": 1 }),
        json!({ "excluded": ["10.0.0.0/8"] }),
    ] {
        let podgate = serve(
            json!({ "source_range": ["203.0.113.0/24"], "ip_strategy": strategy }),
            false,
            &backend,
        )
        .await;
        for (name, value) in [
            ("X-Forwarded-For", "203.0.113.9"),
            ("X-Real-IP", "203.0.113.9"),
            ("Forwarded", "for=203.0.113.9"),
        ] {
            let response = podgate
                .get_with_headers("a.test", "/", &[(name, value)])
                .await;
            assert_forbidden(&response);
        }
    }
    assert_eq!(backend.hits(), 0);

    let only_local = serve(json!({ "source_range": ["127.0.0.1"] }), false, &backend).await;
    let response = get_via(&only_local, "203.0.113.9").await;
    assert_eq!(
        response.status, 200,
        "the connection's own address decides, whatever the header says"
    );
}

#[tokio::test]
async fn ip_allow_ipv6() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "source_range": ["2001:db8::/32", "fd00::7"] }),
        true,
        &backend,
    )
    .await;
    for inside in ["2001:db8::5", "[2001:db8:ffff::1]:4711", "fd00::7"] {
        let response = get_via(&podgate, inside).await;
        assert_eq!(response.status, 200, "{inside}: {response:?}");
    }
    for outside in ["2001:db9::1", "fd00::8", "::1"] {
        assert_forbidden(&get_via(&podgate, outside).await);
    }
}

#[tokio::test]
async fn ip_allow_v4_mapped() {
    let backend = Backend::start(Duration::ZERO).await;
    let v4 = serve(
        json!({ "source_range": ["203.0.113.0/24"] }),
        true,
        &backend,
    )
    .await;
    assert_eq!(get_via(&v4, "::ffff:203.0.113.9").await.status, 200);
    assert_forbidden(&get_via(&v4, "::ffff:198.51.100.7").await);

    let mapped = serve(
        json!({ "source_range": ["::ffff:203.0.113.0/120"] }),
        true,
        &backend,
    )
    .await;
    assert_eq!(get_via(&mapped, "203.0.113.9").await.status, 200);
    assert_eq!(get_via(&mapped, "::ffff:203.0.113.9").await.status, 200);
    assert_forbidden(&get_via(&mapped, "::ffff:198.51.100.7").await);
}

#[tokio::test]
async fn ip_allow_ipv6_subnet() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({
            "source_range": ["2001:db8:1::/64", "203.0.113.9"],
            "ip_strategy": { "ipv6_subnet_bits": 64 },
        }),
        true,
        &backend,
    )
    .await;
    assert_eq!(get_via(&podgate, "2001:db8:1::dead:beef").await.status, 200);
    assert_forbidden(&get_via(&podgate, "2001:db8:2::1").await);
    assert_eq!(
        get_via(&podgate, "203.0.113.9").await.status,
        200,
        "IPv4 clients are not masked"
    );

    let narrow = serve(
        json!({ "source_range": ["2001:db8:1::1"], "ip_strategy": { "ipv6_subnet_bits": 64 } }),
        true,
        &backend,
    )
    .await;
    assert_forbidden(&get_via(&narrow, "2001:db8:1::1").await);
}

async fn rejected(config: Value) -> Value {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    let response = podgate
        .push_snapshot(&snapshot(1, &[guarded(backend.addr, config)]))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    response.json()["conflicts"][0].clone()
}

#[tokio::test]
async fn ip_allow_empty_rejected() {
    for config in [json!({ "source_range": [] }), json!({})] {
        let conflict = rejected(config.clone()).await;
        assert_eq!(
            conflict["code"], "invalid_middleware",
            "{config}: {conflict}"
        );
    }
}

#[tokio::test]
async fn ip_allow_bad_cidr_rejected() {
    for config in [
        json!({ "source_range": ["10.0.0.0/33"] }),
        json!({ "source_range": ["not-an-address"] }),
        json!({ "source_range": ["10.0.0.0/8"], "ip_strategy": { "excluded": ["x/8"] } }),
        json!({ "source_range": ["10.0.0.0/8"], "ip_strategy": { "ipv6_subnet_bits": 200 } }),
    ] {
        let conflict = rejected(config.clone()).await;
        assert_eq!(
            conflict["code"], "invalid_middleware",
            "{config}: {conflict}"
        );
    }
}

#[tokio::test]
async fn ip_allow_before_admission() {
    let slow = Backend::start(Duration::from_millis(600)).await;
    let guarded_backend = Backend::start(Duration::ZERO).await;
    let open = app("open", &["open.test"], &[serving("r1", slow.addr)]);
    let closed = with_chain(
        app(
            "closed",
            &["closed.test"],
            &[serving("r1", guarded_backend.addr)],
        ),
        &[middleware(
            "allow",
            "ip_allow_list",
            json!({ "source_range": ["203.0.113.0/24"] }),
        )],
    );
    let mut pushed = snapshot(1, &[open, closed]);
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(1);
    let podgate = Podgate::start().await;
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);

    let (held, (full, denied)) = tokio::join!(podgate.get("open.test", "/"), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        (
            podgate.get("open.test", "/").await,
            podgate.get("closed.test", "/").await,
        )
    });
    assert_eq!(held.status, 200, "{held:?}");
    assert_eq!(
        full.status, 503,
        "the tenant's one slot was taken: {full:?}"
    );
    assert_forbidden(&denied);
    assert_eq!(guarded_backend.hits(), 0, "a refusal reaches no upstream");
}

#[tokio::test]
async fn plan_lists_ip_allow_list_changes() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "source_range": ["203.0.113.0/24"] }),
        false,
        &backend,
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
    assert_eq!(kinds(&removed), ["ip_allow_list_removed"]);

    let widened = plan(&[guarded(
        backend.addr,
        json!({ "source_range": ["203.0.113.0/24", "198.51.100.0/24"] }),
    )])
    .await;
    assert_eq!(kinds(&widened), ["ip_allow_list_widened"]);

    let wider_block = plan(&[guarded(
        backend.addr,
        json!({ "source_range": ["203.0.0.0/16"] }),
    )])
    .await;
    assert_eq!(kinds(&wider_block), ["ip_allow_list_widened"]);

    let strategy = plan(&[guarded(
        backend.addr,
        json!({ "source_range": ["203.0.113.0/24"], "ip_strategy": { "depth": 2 } }),
    )])
    .await;
    assert_eq!(kinds(&strategy), ["ip_allow_list_strategy_changed"]);

    let narrowed = plan(&[guarded(
        backend.addr,
        json!({ "source_range": ["203.0.113.128/25"] }),
    )])
    .await;
    assert!(kinds(&narrowed).is_empty(), "{}", narrowed.body);

    let same = plan(&[guarded(
        backend.addr,
        json!({ "source_range": ["203.0.113.0/25", "203.0.113.128/25"] }),
    )])
    .await;
    assert!(kinds(&same).is_empty(), "{}", same.body);
}
