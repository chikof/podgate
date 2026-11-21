//! TCP routers and services through the real binary: byte flow, half-close, balancing
//! and failover, the router rules, the tenant charge, the idle timeout and shutdown.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::dns::Dns;
use common::{Podgate, app, refused, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep, timeout};

const ENTRY_POINTS: [(&str, &str); 2] = [("web", "http"), ("pg", "tcp")];
const WAIT: Duration = Duration::from_secs(5);

/// A TCP server on a loopback port: how many connections it accepted, and where it listens.
struct Server {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

impl Server {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// Starts a server on `listener` that runs `handle` for each connection.
fn spawn_server<F, Fut>(listener: TcpListener, handle: F) -> Server
where
    F: Fn(TcpStream, usize) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let addr = listener.local_addr().expect("server addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let nth = count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(handle(stream, nth));
        }
    });
    Server { addr, accepted }
}

async fn serve<F, Fut>(handle: F) -> Server
where
    F: Fn(TcpStream, usize) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    spawn_server(
        TcpListener::bind("127.0.0.1:0").await.expect("bind server"),
        handle,
    )
}

/// A server that greets with `tag\n` and then echoes until the client closes.
async fn greeter(tag: &'static str) -> Server {
    serve(move |mut stream, _| async move {
        if stream
            .write_all(format!("{tag}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
        let mut buf = [0_u8; 4096];
        while let Ok(read) = stream.read(&mut buf).await {
            if read == 0 || stream.write_all(&buf[..read]).await.is_err() {
                return;
            }
        }
    })
    .await
}

fn servers_of(addrs: &[SocketAddr]) -> Vec<Value> {
    addrs
        .iter()
        .map(|addr| json!({ "address": addr.to_string() }))
        .collect()
}

/// An app of tenant `t1` with one TCP router `r` and one service `svc`; `router` and `service`
/// add fields to them.
fn tcp_app(servers: &[Value], router: &Value, service: &Value) -> Value {
    let mut app = app("t", &["t.test"], &[]);
    app["routers"] = json!([]);
    let mut router_config = json!({ "name": "r", "entry_points": ["pg"], "service": "svc" });
    let mut service_config = json!({ "name": "svc", "type": "loadbalancer", "servers": servers });
    for (config, extra) in [(&mut router_config, router), (&mut service_config, service)] {
        if let (Some(config), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
            config.extend(extra.clone());
        }
    }
    app["tcp"] = json!({ "routers": [router_config], "services": [service_config] });
    app
}

/// A snapshot of tenant `t1` that reserves the `pg` entry point to it.
fn reserved(version: u64, apps: &[Value]) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["entry_points"] = json!([{ "name": "pg", "tenants": ["t1"] }]);
    pushed
}

fn budget(mut pushed: Value, max_inflight: u32, max_buffer_bytes: u64) -> Value {
    pushed["tenants"][0]["budget"] =
        json!({ "max_inflight": max_inflight, "max_buffer_bytes": max_buffer_bytes });
    pushed
}

async fn start() -> Podgate {
    Podgate::start_with_entry_points(&ENTRY_POINTS, &[]).await
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

async fn connect(podgate: &Podgate) -> TcpStream {
    timeout(WAIT, TcpStream::connect(podgate.entry_addr("pg")))
        .await
        .expect("connect in time")
        .expect("connect to the tcp entry point")
}

/// The first line the server behind a fresh connection sends.
async fn greeting(stream: &mut TcpStream) -> String {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match timeout(WAIT, stream.read(&mut byte)).await {
            Ok(Ok(1)) if byte[0] == b'\n' => break,
            Ok(Ok(1)) => line.push(byte[0]),
            other => panic!(
                "no greeting, got {other:?} after {:?}",
                String::from_utf8_lossy(&line)
            ),
        }
    }
    String::from_utf8_lossy(&line).into_owned()
}

/// Whether the connection ends without a byte: podgate closed it, as it does a refusal.
async fn closed_without_data(stream: &mut TcpStream) -> bool {
    let mut buf = [0_u8; 16];
    matches!(
        timeout(WAIT, stream.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// The value of the sample `series` (a name with its labels) in the metrics of `podgate`.
async fn metric(podgate: &Podgate, series: &str) -> u64 {
    let body = podgate.admin_get("/metrics").await.body;
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("no sample {series} in:\n{body}"))
}

/// Waits until `series` satisfies `wanted`, up to ten seconds, and returns its last value.
async fn wait_for(podgate: &Podgate, series: &str, wanted: impl Fn(u64) -> bool) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let value = metric(podgate, series).await;
        if wanted(value) || Instant::now() > deadline {
            return value;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// The tags of `count` connections, one after the other, each closed after its greeting.
async fn tags(podgate: &Podgate, count: usize) -> Vec<String> {
    let mut seen = Vec::new();
    for _ in 0..count {
        let mut stream = connect(podgate).await;
        seen.push(greeting(&mut stream).await);
    }
    seen
}

fn count_of(seen: &[String], tag: &str) -> usize {
    seen.iter().filter(|seen| *seen == tag).count()
}

fn conflict_codes(body: &Value) -> Vec<String> {
    body["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code").to_owned())
        .collect()
}

/// The peak resident set of process `pid`, in kilobytes.
fn peak_rss_kb(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .expect("read process status")
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .trim()
                .strip_suffix("kB")?
                .trim()
                .parse()
                .ok()
        })
        .expect("VmHWM")
}

#[tokio::test]
async fn tcp_proxies_bytes_both_ways() {
    let podgate = start().await;
    let up = greeter("A").await;
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}))],
        ),
    )
    .await;
    let mut stream = connect(&podgate).await;
    assert_eq!(greeting(&mut stream).await, "A");
    stream.write_all(b"ping").await.expect("write");
    let mut echoed = [0_u8; 4];
    timeout(WAIT, stream.read_exact(&mut echoed))
        .await
        .expect("echo in time")
        .expect("echo");
    assert_eq!(&echoed, b"ping");
    assert_eq!(
        metric(&podgate, "podgate_tcp_bytes_total{direction=\"in\"}").await,
        4
    );
    assert_eq!(
        metric(&podgate, "podgate_tcp_bytes_total{direction=\"out\"}").await,
        6
    );
}

#[tokio::test]
async fn tcp_half_close_propagates() {
    let podgate = start().await;
    // The server closes its write half first, and goes on reading until the client closes.
    let (told, heard) = oneshot::channel::<Vec<u8>>();
    let told = Arc::new(std::sync::Mutex::new(Some(told)));
    let up = serve(move |mut stream, _| {
        let told = Arc::clone(&told);
        async move {
            stream.write_all(b"bye").await.expect("write");
            stream.shutdown().await.expect("shutdown write half");
            let mut rest = Vec::new();
            stream
                .read_to_end(&mut rest)
                .await
                .expect("read to the client's FIN");
            if let Some(told) = told.lock().expect("lock").take() {
                told.send(rest).expect("report");
            }
        }
    })
    .await;
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}))],
        ),
    )
    .await;
    let mut stream = connect(&podgate).await;
    let mut said = Vec::new();
    // `read_to_end` returns only on the server's FIN: it crossed podgate while the client's
    // direction was still open.
    timeout(WAIT, stream.read_to_end(&mut said))
        .await
        .expect("the server's FIN reaches the client")
        .expect("read");
    assert_eq!(said, b"bye");
    stream
        .write_all(b"tail")
        .await
        .expect("write after the server closed");
    stream.shutdown().await.expect("client FIN");
    let rest = timeout(WAIT, heard)
        .await
        .expect("the client's FIN reaches the server")
        .expect("report");
    assert_eq!(rest, b"tail");
}

#[tokio::test]
async fn tcp_large_transfer() {
    const TOTAL: u64 = 100 * 1024 * 1024;
    let podgate = start().await;
    let up = serve(|mut stream, _| async move {
        let mut buf = vec![0_u8; 64 * 1024];
        let mut total = 0_u64;
        while let Ok(read) = stream.read(&mut buf).await {
            if read == 0 {
                break;
            }
            total += read as u64;
        }
        drop(stream.write_all(total.to_string().as_bytes()).await);
    })
    .await;
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}))],
        ),
    )
    .await;
    let before = peak_rss_kb(podgate.pid());
    let mut stream = connect(&podgate).await;
    let (mut read_half, mut write_half) = stream.split();
    let send = async {
        let chunk = vec![0xab_u8; 64 * 1024];
        let mut sent = 0_u64;
        while sent < TOTAL {
            write_half.write_all(&chunk).await.expect("write");
            sent += chunk.len() as u64;
        }
        write_half.shutdown().await.expect("shutdown");
    };
    let receive = async {
        let mut said = String::new();
        read_half
            .read_to_string(&mut said)
            .await
            .expect("read the total");
        said
    };
    let (_, said) = timeout(Duration::from_secs(60), async {
        tokio::join!(send, receive)
    })
    .await
    .expect("100 MiB moves in a minute");
    assert_eq!(said, TOTAL.to_string());
    // The copy holds two 16 KiB buffers: moving 100 MiB must not grow the process by anything
    // like the size of the transfer.
    let grown = peak_rss_kb(podgate.pid()).saturating_sub(before);
    assert!(
        grown < 20 * 1024,
        "the process grew by {grown} kB while it copied 100 MiB"
    );
}

#[tokio::test]
async fn tcp_round_robin_two_servers() {
    let podgate = start().await;
    let (a, b) = (greeter("A").await, greeter("B").await);
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[a.addr, b.addr]),
                &json!({}),
                &json!({}),
            )],
        ),
    )
    .await;
    let seen = tags(&podgate, 6).await;
    assert_eq!(
        (count_of(&seen, "A"), count_of(&seen, "B")),
        (3, 3),
        "{seen:?}"
    );
}

#[tokio::test]
async fn tcp_weighted_round_robin_follows_weights() {
    let podgate = start().await;
    let (a, b) = (greeter("A").await, greeter("B").await);
    let servers = vec![
        json!({ "address": a.addr.to_string(), "weight": 3 }),
        json!({ "address": b.addr.to_string(), "weight": 1 }),
    ];
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers,
                &json!({}),
                &json!({ "algorithm": "weighted_round_robin" }),
            )],
        ),
    )
    .await;
    let seen = tags(&podgate, 8).await;
    assert_eq!(
        (count_of(&seen, "A"), count_of(&seen, "B")),
        (6, 2),
        "{seen:?}"
    );
}

#[tokio::test]
async fn tcp_connect_failure_tries_next_server() {
    let podgate = start().await;
    let (dead, live) = (refused(), greeter("A").await);
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[dead.addr, live.addr]),
                &json!({}),
                &json!({}),
            )],
        ),
    )
    .await;
    let seen = tags(&podgate, 4).await;
    assert_eq!(count_of(&seen, "A"), 4, "{seen:?}");
    assert!(metric(&podgate, "podgate_tcp_connect_failures_total").await >= 1);
}

#[tokio::test]
async fn tcp_connect_failure_on_every_server_closes_the_connection() {
    let podgate = start().await;
    let (one, two) = (refused(), refused());
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[one.addr, two.addr]),
                &json!({}),
                &json!({}),
            )],
        ),
    )
    .await;
    let mut stream = connect(&podgate).await;
    assert!(closed_without_data(&mut stream).await);
    assert_eq!(
        metric(&podgate, "podgate_l4_refused_total{reason=\"no_server\"}").await,
        1
    );
    assert_eq!(
        metric(&podgate, "podgate_tcp_connect_failures_total").await,
        2
    );
}

#[tokio::test]
async fn tcp_no_retry_after_data() {
    let podgate = start().await;
    // Both servers take the connection, read what the client sent and close without an answer.
    let (a, b) = (
        serve(|mut stream, _| async move {
            let mut buf = [0_u8; 16];
            drop(stream.read(&mut buf).await);
        })
        .await,
        serve(|mut stream, _| async move {
            let mut buf = [0_u8; 16];
            drop(stream.read(&mut buf).await);
        })
        .await,
    );
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[a.addr, b.addr]),
                &json!({}),
                &json!({}),
            )],
        ),
    )
    .await;
    for _ in 0..2 {
        let mut stream = connect(&podgate).await;
        stream.write_all(b"query").await.expect("write");
        assert!(closed_without_data(&mut stream).await);
    }
    // One connection each: the one that was closed after data was not tried on the other server.
    assert_eq!((a.accepted(), b.accepted()), (1, 1));
}

#[tokio::test]
async fn tcp_router_client_ip_match() {
    let podgate = start().await;
    let (a, b) = (greeter("A").await, greeter("B").await);
    let mut app = tcp_app(
        &servers_of(&[a.addr]),
        &json!({ "match": { "client_ip": ["10.0.0.0/8"] } }),
        &json!({}),
    );
    // The test's client is 127.0.0.1: no router matches, and a non-matching peer is closed.
    push(&podgate, &reserved(1, &[app.clone()])).await;
    let mut stream = connect(&podgate).await;
    assert!(closed_without_data(&mut stream).await);
    assert_eq!(
        metric(&podgate, "podgate_l4_refused_total{reason=\"no_route\"}").await,
        1
    );
    // A router that matches the client takes it.
    app["tcp"]["routers"][0]["match"] = json!({ "client_ip": ["127.0.0.0/8"] });
    push(&podgate, &reserved(2, &[app.clone()])).await;
    assert_eq!(tags(&podgate, 1).await, ["A"]);
    // A catch-all takes what the router with a match does not.
    app["tcp"]["routers"][0]["match"] = json!({ "client_ip": ["10.0.0.0/8"] });
    app["tcp"]["routers"]
        .as_array_mut()
        .expect("routers")
        .push(json!({ "name": "fallback", "entry_points": ["pg"], "service": "other" }));
    app["tcp"]["services"]
        .as_array_mut()
        .expect("services")
        .push(json!({ "name": "other", "type": "loadbalancer", "servers": servers_of(&[b.addr]) }));
    push(&podgate, &reserved(3, &[app.clone()])).await;
    assert_eq!(tags(&podgate, 1).await, ["B"]);
    // And a router with a match wins over the catch-all for the client it matches.
    app["tcp"]["routers"][0]["match"] = json!({ "not": { "client_ip": ["10.0.0.0/8"] } });
    push(&podgate, &reserved(4, &[app])).await;
    assert_eq!(tags(&podgate, 1).await, ["A"]);
}

#[tokio::test]
async fn tcp_two_catch_all_routers_ambiguous() {
    let podgate = start().await;
    let (a, b) = (greeter("A").await, greeter("B").await);
    let mut first = tcp_app(&servers_of(&[a.addr]), &json!({}), &json!({}));
    first["id"] = json!("one");
    let mut second = tcp_app(&servers_of(&[b.addr]), &json!({ "name": "r2" }), &json!({}));
    second["id"] = json!("two");
    second["declared_by"] = json!("tests/two");
    let response = podgate
        .push_snapshot(&reserved(1, &[first.clone(), second]))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(conflict_codes(&response.json()), ["route_ambiguity"]);
    assert_eq!(
        response.json()["conflicts"][0]["apps"],
        json!(["one", "two"])
    );
    // Two routers of one app that cannot be told apart are the same.
    first["tcp"]["routers"]
        .as_array_mut()
        .expect("routers")
        .push(json!({ "name": "r2", "entry_points": ["pg"], "service": "svc" }));
    let response = podgate.push_snapshot(&reserved(2, &[first])).await;
    assert_eq!(conflict_codes(&response.json()), ["route_ambiguity"]);
}

#[tokio::test]
async fn tcp_connection_charges_tenant_inflight() {
    let podgate = start().await;
    let up = greeter("A").await;
    let pushed = budget(
        reserved(
            1,
            &[tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}))],
        ),
        1,
        1_048_576,
    );
    push(&podgate, &pushed).await;
    let mut first = connect(&podgate).await;
    assert_eq!(greeting(&mut first).await, "A");
    assert_eq!(
        metric(&podgate, "podgate_tenant_inflight{tenant=\"t1\"}").await,
        1
    );
    assert_eq!(
        metric(&podgate, "podgate_tenant_buffer_bytes{tenant=\"t1\"}").await,
        32_768
    );
    // The tenant is at `max_inflight`: the second connection is closed at once.
    let mut second = connect(&podgate).await;
    assert!(closed_without_data(&mut second).await);
    assert_eq!(
        metric(
            &podgate,
            "podgate_l4_refused_total{reason=\"over_inflight\"}"
        )
        .await,
        1
    );
    drop(first);
    assert_eq!(
        wait_for(
            &podgate,
            "podgate_tenant_inflight{tenant=\"t1\"}",
            |now| now == 0
        )
        .await,
        0
    );
    assert_eq!(
        wait_for(
            &podgate,
            "podgate_tenant_buffer_bytes{tenant=\"t1\"}",
            |now| now == 0
        )
        .await,
        0
    );
    assert_eq!(tags(&podgate, 1).await, ["A"]);
}

#[tokio::test]
async fn tcp_connection_over_budget_refused() {
    let podgate = start().await;
    let up = greeter("A").await;
    // Room for one connection's two 16 KiB buffers and not for a second pair.
    let pushed = budget(
        reserved(
            1,
            &[tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}))],
        ),
        100,
        40_000,
    );
    push(&podgate, &pushed).await;
    let mut first = connect(&podgate).await;
    assert_eq!(greeting(&mut first).await, "A");
    let mut second = connect(&podgate).await;
    assert!(closed_without_data(&mut second).await);
    assert_eq!(
        metric(&podgate, "podgate_l4_refused_total{reason=\"over_budget\"}").await,
        1
    );
    // The refused connection took no slot and no buffer with it.
    assert_eq!(
        metric(&podgate, "podgate_tenant_inflight{tenant=\"t1\"}").await,
        1
    );
    assert_eq!(
        metric(&podgate, "podgate_tenant_buffer_bytes{tenant=\"t1\"}").await,
        32_768
    );
}

#[tokio::test]
async fn tcp_idle_timeout_closes() {
    let podgate = start().await;
    let up = greeter("A").await;
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(
                &servers_of(&[up.addr]),
                &json!({}),
                &json!({ "idle_timeout_secs": 1 }),
            )],
        ),
    )
    .await;
    // Traffic in either direction keeps a connection alive.
    let mut busy = connect(&podgate).await;
    assert_eq!(greeting(&mut busy).await, "A");
    for _ in 0..5 {
        sleep(Duration::from_millis(400)).await;
        busy.write_all(b"x").await.expect("write");
        let mut echoed = [0_u8; 1];
        timeout(WAIT, busy.read_exact(&mut echoed))
            .await
            .expect("in time")
            .expect("echo");
    }
    // Silence for the timeout closes it.
    let started = Instant::now();
    let mut idle = connect(&podgate).await;
    assert_eq!(greeting(&mut idle).await, "A");
    let mut buf = [0_u8; 1];
    let ended = timeout(Duration::from_secs(4), idle.read(&mut buf))
        .await
        .expect("the idle connection is closed in time");
    assert!(matches!(ended, Ok(0) | Err(_)), "{ended:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "closed after {:?}",
        started.elapsed()
    );
    // The busy connection went quiet too, once the loop ended.
    let closed = wait_for(&podgate, "podgate_tcp_closed_total{reason=\"idle\"}", |n| {
        n >= 1
    })
    .await;
    assert!(
        (1..=2).contains(&closed),
        "{closed} connections closed as idle"
    );
}

#[tokio::test]
async fn tcp_removed_router_drains() {
    let podgate = start().await;
    let up = greeter("A").await;
    let pushed = reserved(
        1,
        &[tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}))],
    );
    push(&podgate, &pushed).await;
    let mut live = connect(&podgate).await;
    assert_eq!(greeting(&mut live).await, "A");
    // The next snapshot has no TCP router.
    let mut gone = tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}));
    gone["tcp"] = Value::Null;
    push(&podgate, &reserved(2, &[gone])).await;
    let mut turned_away = connect(&podgate).await;
    assert!(closed_without_data(&mut turned_away).await);
    // The connection that was open finishes its conversation.
    live.write_all(b"still here").await.expect("write");
    let mut echoed = [0_u8; 10];
    timeout(WAIT, live.read_exact(&mut echoed))
        .await
        .expect("in time")
        .expect("echo");
    assert_eq!(&echoed, b"still here");
    live.shutdown().await.expect("close");
    let mut rest = Vec::new();
    timeout(WAIT, live.read_to_end(&mut rest))
        .await
        .expect("in time")
        .expect("read");
    assert!(rest.is_empty());
}

#[tokio::test]
async fn tcp_entry_point_forbidden_for_other_tenant() {
    let podgate = start().await;
    let up = greeter("A").await;
    let mut other = tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}));
    other["tenant"] = json!("t2");
    let mut pushed = reserved(1, &[other]);
    pushed["tenants"]
        .as_array_mut()
        .expect("tenants")
        .push(json!({ "id": "t2", "weight": 1, "budget": { "max_inflight": 10, "max_buffer_bytes": 1_048_576 } }));
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "entry_point_forbidden"
    );
    // An entry point with no policy is not reserved to anyone either.
    let mut open = snapshot(
        2,
        &[tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}))],
    );
    open["entry_points"] = json!([]);
    let response = podgate.push_snapshot(&open).await;
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "entry_point_forbidden"
    );
}

#[tokio::test]
async fn tcp_dial_obeys_upstream_policy() {
    let dir = std::env::temp_dir().join(format!("podgate-tcp-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("policy dir");
    let file = dir.join("policy.json");
    std::fs::write(&file, r#"{"deny": ["127.0.0.2/32"]}"#).expect("write policy");
    let path = file.to_str().expect("utf-8 path").to_owned();
    let podgate =
        Podgate::start_with_entry_points(&ENTRY_POINTS, &[("UPSTREAM_POLICY_FILE", path.as_str())])
            .await;
    let denied: SocketAddr = "127.0.0.2:5432".parse().expect("addr");
    let response = podgate
        .push_snapshot(&reserved(
            1,
            &[tcp_app(&servers_of(&[denied]), &json!({}), &json!({}))],
        ))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "upstream_forbidden"
    );
    assert_eq!(response.json()["conflicts"][0]["rule"], "deny 127.0.0.2/32");
    std::fs::remove_dir_all(&dir).expect("remove policy dir");
}

/// Servers that listen on the same free port on `127.0.0.1` and `127.0.0.2`, greeting with the
/// given tags.
async fn on_two_addresses(tags: [&'static str; 2]) -> (u16, [Server; 2]) {
    for _ in 0..50 {
        let Ok(first) = TcpListener::bind("127.0.0.1:0").await else {
            continue;
        };
        let port = first.local_addr().expect("addr").port();
        let Ok(second) = TcpListener::bind(format!("127.0.0.2:{port}")).await else {
            continue;
        };
        let greet = |tag: &'static str| {
            move |mut stream: TcpStream, _| async move {
                drop(stream.write_all(format!("{tag}\n").as_bytes()).await);
                let mut buf = [0_u8; 16];
                drop(stream.read(&mut buf).await);
            }
        };
        return (
            port,
            [
                spawn_server(first, greet(tags[0])),
                spawn_server(second, greet(tags[1])),
            ],
        );
    }
    panic!("no port was free on both loopback addresses");
}

#[tokio::test]
async fn tcp_named_server_resolves_and_obeys_policy() {
    let dns = Dns::start().await;
    dns.set("db.internal", &["127.0.0.1", "127.0.0.2"], 30);
    let (port, _servers) = on_two_addresses(["ONE", "TWO"]).await;
    let env = [
        ("DNS_SERVERS", dns.servers()),
        ("DNS_MIN_TTL_SECS", "1".to_owned()),
        ("DNS_TIMEOUT_MS", "1000".to_owned()),
    ];
    let env: Vec<(&str, &str)> = env
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    let podgate = Podgate::start_with_entry_points(&ENTRY_POINTS, &env).await;
    let named = json!({ "address": format!("db.internal:{port}") });
    push(
        &podgate,
        &reserved(1, &[tcp_app(&[named], &json!({}), &json!({}))]),
    )
    .await;
    // The name expands into both addresses, and the connections alternate between them.
    let deadline = Instant::now() + Duration::from_secs(10);
    let seen = loop {
        let mut seen = Vec::new();
        for _ in 0..4 {
            let mut stream = connect(&podgate).await;
            let mut line = [0_u8; 4];
            let read = timeout(WAIT, stream.read(&mut line))
                .await
                .expect("in time")
                .unwrap_or(0);
            seen.push(String::from_utf8_lossy(&line[..read]).trim().to_owned());
        }
        if (count_of(&seen, "ONE"), count_of(&seen, "TWO")) == (2, 2) || Instant::now() > deadline {
            break seen;
        }
        sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        (count_of(&seen, "ONE"), count_of(&seen, "TWO")),
        (2, 2),
        "{seen:?}"
    );
    let overview = podgate.admin_get("/v1/overview?section=apps").await.json();
    let service = &overview["apps"]["items"][0]["tcp"]["services"][0];
    assert_eq!(service["names"], json!(["db.internal"]));
    assert_eq!(
        service["servers"].as_array().map(Vec::len),
        Some(2),
        "{service}"
    );
}

#[tokio::test]
async fn tcp_named_server_answering_a_denied_address_is_never_dialled() {
    let dir = std::env::temp_dir().join(format!("podgate-tcp-dns-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("policy dir");
    let file = dir.join("policy.json");
    std::fs::write(&file, r#"{"deny": ["127.0.0.2/32"]}"#).expect("write policy");
    let path = file.to_str().expect("utf-8 path").to_owned();
    let dns = Dns::start().await;
    dns.set("db.internal", &["127.0.0.1", "127.0.0.2"], 30);
    let (port, servers) = on_two_addresses(["ONE", "TWO"]).await;
    let env = [
        ("DNS_SERVERS", dns.servers()),
        ("DNS_MIN_TTL_SECS", "1".to_owned()),
        ("UPSTREAM_POLICY_FILE", path.clone()),
    ];
    let env: Vec<(&str, &str)> = env
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    let podgate = Podgate::start_with_entry_points(&ENTRY_POINTS, &env).await;
    let named = json!({ "address": format!("db.internal:{port}") });
    push(
        &podgate,
        &reserved(1, &[tcp_app(&[named], &json!({}), &json!({}))]),
    )
    .await;
    wait_for(&podgate, "podgate_tcp_connections_total", |_| true).await;
    sleep(Duration::from_secs(2)).await;
    let mut seen = Vec::new();
    for _ in 0..4 {
        let mut stream = connect(&podgate).await;
        let mut line = [0_u8; 4];
        let read = timeout(WAIT, stream.read(&mut line))
            .await
            .expect("in time")
            .unwrap_or(0);
        seen.push(String::from_utf8_lossy(&line[..read]).trim().to_owned());
    }
    assert_eq!(count_of(&seen, "ONE"), 4, "{seen:?}");
    assert_eq!(servers[1].accepted(), 0, "the denied address was dialled");
    std::fs::remove_dir_all(&dir).expect("remove policy dir");
}

#[tokio::test]
async fn tcp_proxy_protocol_sets_the_client_address() {
    let podgate =
        Podgate::start_with_entry_points(&[("web", "http"), ("pg", "tcp;proxy_protocol")], &[])
            .await;
    let up = greeter("A").await;
    let mut pushed = reserved(
        1,
        &[tcp_app(
            &servers_of(&[up.addr]),
            &json!({ "match": { "client_ip": ["10.9.8.0/24"] } }),
            &json!({}),
        )],
    );
    pushed["entry_points"] = json!([{ "name": "pg", "tenants": ["t1"], "proxy_protocol": { "trusted_ips": ["127.0.0.1"] } }]);
    push(&podgate, &pushed).await;
    // The address in the header is the client the router matches.
    let mut behind = connect(&podgate).await;
    behind
        .write_all(b"PROXY TCP4 10.9.8.7 127.0.0.1 40000 5432\r\n")
        .await
        .expect("write the header");
    assert_eq!(greeting(&mut behind).await, "A");
    let mut elsewhere = connect(&podgate).await;
    elsewhere
        .write_all(b"PROXY TCP4 10.1.1.1 127.0.0.1 40000 5432\r\n")
        .await
        .expect("write the header");
    assert!(closed_without_data(&mut elsewhere).await);
    // A connection that sends no header is not served.
    let mut bare = connect(&podgate).await;
    bare.write_all(b"hello\r\n").await.expect("write");
    assert!(closed_without_data(&mut bare).await);
}

#[tokio::test]
async fn tcp_graceful_shutdown_lets_a_connection_finish() {
    let podgate = start().await;
    let up = greeter("A").await;
    push(
        &podgate,
        &reserved(
            1,
            &[tcp_app(&servers_of(&[up.addr]), &json!({}), &json!({}))],
        ),
    )
    .await;
    let mut live = connect(&podgate).await;
    assert_eq!(greeting(&mut live).await, "A");
    let status = std::process::Command::new("kill")
        .args(["-TERM", &podgate.pid().to_string()])
        .status()
        .expect("run kill");
    assert!(status.success());
    // The grace period is `REQUEST_TIMEOUT_SECS` (5 s in the harness): the conversation goes on...
    sleep(Duration::from_secs(1)).await;
    live.write_all(b"late")
        .await
        .expect("write during the grace period");
    let mut echoed = [0_u8; 4];
    timeout(WAIT, live.read_exact(&mut echoed))
        .await
        .expect("in time")
        .expect("echo");
    assert_eq!(&echoed, b"late");
    // ...and is closed when it ends.
    let mut rest = Vec::new();
    let ended = timeout(Duration::from_secs(10), live.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the connection outlived the grace period");
}
