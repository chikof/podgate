//! The load balancing algorithms of a `loadbalancer` service, through the real proxy: smooth
//! weighted round robin, least connections, power of two choices on latency, and the refusal of
//! unknown algorithm names.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, app, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// A backend that answers every request with its name after `delay`, and counts them.
struct Backend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Backend {
    async fn start(name: &'static str, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, name, delay, Arc::clone(&counter)));
            }
        });
        Self { addr, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

async fn serve(mut stream: TcpStream, name: &'static str, delay: Duration, hits: Arc<AtomicUsize>) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{name}",
        name.len()
    );
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            seen.drain(..end + 4);
            hits.fetch_add(1, Ordering::Relaxed);
            sleep(delay).await;
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

/// A snapshot with app `a` (`a.test`) whose one revision's `web` service balances `servers`
/// (address and weight) by `algorithm`, and an unrelated app `b` declared by `bump`. Only
/// `weighted_round_robin` is given the weights.
fn balanced(version: u64, algorithm: &str, servers: &[(SocketAddr, u32)], bump: &str) -> Value {
    let servers: Vec<Value> = servers
        .iter()
        .map(|(addr, weight)| {
            let mut server = json!({ "url": format!("http://{addr}") });
            if algorithm == "weighted_round_robin" {
                server["weight"] = json!(weight);
            }
            server
        })
        .collect();
    let revision = json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
        { "name": "web", "type": "loadbalancer", "algorithm": algorithm, "servers": servers }] });
    let mut other = app("b", &["b.test"], &[]);
    other["declared_by"] = json!(bump);
    other["revisions"] = json!([{ "id": "r1", "state": "serving", "weight": 1, "services": [
        { "name": "web", "type": "loadbalancer", "servers": [{ "url": "http://127.0.0.1:9" }] }] }]);
    snapshot(version, &[app("a", &["a.test"], &[revision]), other])
}

fn conflict_codes(body: &Value) -> Vec<String> {
    body["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code").to_owned())
        .collect()
}

#[tokio::test]
async fn wrr_interleaves_smoothly_and_skips_weight_zero() {
    let podgate = Podgate::start().await;
    let (a, b, c, never) = (
        Backend::start("a", Duration::ZERO).await,
        Backend::start("b", Duration::ZERO).await,
        Backend::start("c", Duration::ZERO).await,
        Backend::start("never", Duration::ZERO).await,
    );
    let pushed = podgate
        .push_snapshot(&balanced(
            1,
            "weighted_round_robin",
            &[(a.addr, 5), (b.addr, 1), (c.addr, 1), (never.addr, 0)],
            "x",
        ))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let mut bodies = Vec::new();
    for _ in 0..14 {
        bodies.push(podgate.get("a.test", "/").await.body);
    }
    // Smooth: the single b and c slots sit between runs of a, not after all five of them.
    assert_eq!(
        bodies,
        [
            "a", "a", "b", "a", "c", "a", "a", "a", "a", "b", "a", "c", "a", "a"
        ]
    );
    assert_eq!(never.hits(), 0, "weight 0 receives nothing");
}

#[tokio::test]
async fn least_conn_routes_around_a_slow_server() {
    let podgate = Podgate::start().await;
    let slow = Backend::start("slow", Duration::from_millis(400)).await;
    let fast = Backend::start("fast", Duration::ZERO).await;
    let pushed = podgate
        .push_snapshot(&balanced(
            1,
            "least_conn",
            &[(slow.addr, 1), (fast.addr, 1)],
            "x",
        ))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let podgate = Arc::new(podgate);

    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let podgate = Arc::clone(&podgate);
        requests.spawn(async move { podgate.get("a.test", "/").await.status });
        sleep(Duration::from_millis(10)).await;
    }
    while let Some(status) = requests.join_next().await {
        assert_eq!(status.expect("request task"), 200);
    }
    assert!(slow.hits() <= 2, "slow server took {}", slow.hits());
    assert!(fast.hits() >= 18, "fast server took {}", fast.hits());
}

#[tokio::test]
async fn least_conn_remembers_its_requests_across_an_unrelated_push() {
    let podgate = Podgate::start().await;
    let slow = Backend::start("slow", Duration::from_millis(600)).await;
    let fast = Backend::start("fast", Duration::ZERO).await;
    let servers = [(slow.addr, 1), (fast.addr, 1)];
    let pushed = podgate
        .push_snapshot(&balanced(1, "least_conn", &servers, "before"))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let podgate = Arc::new(podgate);

    // The first request of a fresh counter goes to the first server, the slow one, and stays.
    let held = {
        let podgate = Arc::clone(&podgate);
        tokio::spawn(async move { podgate.get("a.test", "/").await.body })
    };
    sleep(Duration::from_millis(150)).await;
    assert_eq!(slow.hits(), 1);

    let pushed = podgate
        .push_snapshot(&balanced(2, "least_conn", &servers, "after"))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    for _ in 0..5 {
        assert_eq!(podgate.get("a.test", "/").await.body, "fast");
    }
    assert_eq!(held.await.expect("held request"), "slow");
}

#[tokio::test]
async fn p2c_ewma_prefers_fast_server_end_to_end() {
    let podgate = Podgate::start().await;
    let slow = Backend::start("slow", Duration::from_millis(200)).await;
    let fast = Backend::start("fast", Duration::from_millis(20)).await;
    let pushed = podgate
        .push_snapshot(&balanced(
            1,
            "p2c_ewma",
            &[(slow.addr, 1), (fast.addr, 1)],
            "x",
        ))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let podgate = Arc::new(podgate);

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let podgate = Arc::clone(&podgate);
        clients.spawn(async move {
            while Instant::now() < deadline {
                assert_eq!(podgate.get("a.test", "/").await.status, 200);
            }
        });
    }
    while let Some(done) = clients.join_next().await {
        done.expect("client task");
    }
    assert!(slow.hits() > 0, "the slow server is probed at the start");
    assert!(
        fast.hits() >= 4 * slow.hits(),
        "fast {} against slow {}",
        fast.hits(),
        slow.hits()
    );
}

#[tokio::test]
async fn unknown_algorithm_rejected() {
    let podgate = Podgate::start().await;
    let backend = Backend::start("a", Duration::ZERO).await;
    let servers = [(backend.addr, 1)];

    let unknown = podgate
        .push_snapshot(&balanced(1, "fastest", &servers, "x"))
        .await;
    assert_eq!(unknown.status, 422, "{}", unknown.body);
    assert_eq!(conflict_codes(&unknown.json())[0], "invalid_service");

    // A weight where weights are not used is refused too, never ignored.
    let mut weighted = balanced(1, "least_conn", &servers, "x");
    weighted["apps"][0]["revisions"][0]["services"][0]["servers"][0]["weight"] = json!(3);
    let refused = podgate.push_snapshot(&weighted).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(conflict_codes(&refused.json())[0], "invalid_service");
}
