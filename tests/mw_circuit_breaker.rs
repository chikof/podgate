//! The `circuit_breaker` middleware end to end: it opens on failures, answers
//! without contacting the upstream, keeps its state across unrelated pushes, resets on a changed
//! configuration and reports opening and closing through the event feed. The trigger arithmetic
//! and the recovery ramp run on an injected clock in the unit tests of
//! `src/middleware/circuit_breaker.rs`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, Response, Upstream, app, middleware, serving, snapshot, with_chain};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// A backend whose status the test sets, and which counts the requests that reach it.
struct Flaky {
    addr: SocketAddr,
    hits: Arc<AtomicU32>,
    status: Arc<AtomicU16>,
}

impl Flaky {
    async fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind flaky");
        let addr = listener.local_addr().expect("flaky addr");
        let hits = Arc::new(AtomicU32::new(0));
        let status = Arc::new(AtomicU16::new(status));
        tokio::spawn({
            let (hits, status) = (Arc::clone(&hits), Arc::clone(&status));
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(flaky_connection(
                        stream,
                        Arc::clone(&hits),
                        Arc::clone(&status),
                    ));
                }
            }
        });
        Self { addr, hits, status }
    }

    fn hits(&self) -> u32 {
        self.hits.load(Ordering::SeqCst)
    }

    fn answer_with(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
    }
}

async fn flaky_connection(mut stream: TcpStream, hits: Arc<AtomicU32>, status: Arc<AtomicU16>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            seen.drain(..end + 4);
            hits.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "HTTP/1.1 {} Upstream\r\nContent-Length: 8\r\n\r\nupstream",
                status.load(Ordering::SeqCst)
            );
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

/// Opens after a quarter of at least 5 responses in the window are 5xx; stays open for a minute.
fn trips_on_5xx() -> Value {
    json!({
        "trip_when": { "response_code_ratio": { "from": 500, "to": 600, "ratio": 0.25 } },
        "check_period_ms": 10,
        "min_requests": 5,
        "fallback_secs": 60,
    })
}

fn pushed(version: u64, config: &Value, upstream: SocketAddr) -> Value {
    let guarded = with_chain(
        app("a.test", &["a.test"], &[serving("r1", upstream)]),
        &[middleware("cb", "circuit_breaker", config.clone())],
    );
    snapshot(version, &[guarded])
}

async fn serve(config: &Value, upstream: SocketAddr) -> Podgate {
    let podgate = Podgate::start().await;
    let response = podgate.push_snapshot(&pushed(1, config, upstream)).await;
    assert_eq!(response.status, 200, "{}", response.body);
    podgate
}

fn is_circuit_answer(response: &Response) -> bool {
    response.status == 503 && response.body.contains("circuit breaker open")
}

/// Sends requests until the circuit answers one, and returns that answer.
async fn until_open(podgate: &Podgate) -> Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = podgate.get("a.test", "/").await;
        if is_circuit_answer(&response) {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "the circuit never opened: {response:?}"
        );
        sleep(Duration::from_millis(5)).await;
    }
}

async fn events_of(podgate: &Podgate, kind: &str) -> Vec<Value> {
    let events = podgate.admin_get("/v1/events?after=0").await.json();
    events["events"]
        .as_array()
        .expect("events list")
        .iter()
        .filter(|event| event["kind"] == kind)
        .cloned()
        .collect()
}

#[tokio::test]
async fn circuit_trips_on_5xx_ratio() {
    let upstream = Flaky::start(500).await;
    let podgate = serve(&trips_on_5xx(), upstream.addr).await;

    let first = podgate.get("a.test", "/").await;
    assert_eq!((first.status, first.body.as_str()), (500, "upstream"));

    let open = until_open(&podgate).await;
    assert_eq!(open.status, 503);
    assert_eq!(open.json(), json!({ "error": "circuit breaker open" }));
    let retry_after: u64 = open
        .header("retry-after")
        .expect("a Retry-After header")
        .parse()
        .expect("whole seconds");
    assert!((1..=60).contains(&retry_after), "{retry_after}");
}

#[tokio::test]
async fn circuit_open_does_not_hit_upstream() {
    let upstream = Flaky::start(500).await;
    let podgate = serve(&trips_on_5xx(), upstream.addr).await;
    until_open(&podgate).await;

    let before = upstream.hits();
    for _ in 0..20 {
        assert!(is_circuit_answer(&podgate.get("a.test", "/").await));
    }
    assert_eq!(
        upstream.hits(),
        before,
        "an open circuit reached the upstream"
    );
}

#[tokio::test]
async fn circuit_opens_on_unreachable_upstream() {
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        listener.local_addr().expect("addr")
    };
    let config = json!({
        "trip_when": { "network_error_ratio": 0.5 },
        "check_period_ms": 10,
        "min_requests": 5,
        "fallback_secs": 60,
    });
    let podgate = serve(&config, dead).await;
    let first = podgate.get("a.test", "/").await;
    assert_eq!(first.status, 502, "{first:?}");
    until_open(&podgate).await;
}

#[tokio::test]
async fn circuit_state_survives_unrelated_push() {
    let upstream = Flaky::start(500).await;
    let podgate = serve(&trips_on_5xx(), upstream.addr).await;
    until_open(&podgate).await;

    let other = Upstream::start("other").await;
    let mut next = pushed(2, &trips_on_5xx(), upstream.addr);
    next["apps"].as_array_mut().expect("apps").push(app(
        "b.test",
        &["b.test"],
        &[serving("r1", other.addr)],
    ));
    let response = podgate.push_snapshot(&next).await;
    assert_eq!(response.status, 200, "{}", response.body);

    let before = upstream.hits();
    assert!(is_circuit_answer(&podgate.get("a.test", "/").await));
    assert_eq!(upstream.hits(), before);
    assert_eq!(podgate.get("b.test", "/").await.body, "other");
}

#[tokio::test]
async fn circuit_state_resets_on_change() {
    let upstream = Flaky::start(500).await;
    let podgate = serve(&trips_on_5xx(), upstream.addr).await;
    until_open(&podgate).await;

    let mut changed = trips_on_5xx();
    changed["min_requests"] = json!(6);
    let response = podgate
        .push_snapshot(&pushed(2, &changed, upstream.addr))
        .await;
    assert_eq!(response.status, 200, "{}", response.body);

    let after = podgate.get("a.test", "/").await;
    assert_eq!((after.status, after.body.as_str()), (500, "upstream"));
}

#[tokio::test]
async fn circuit_events_emitted_once() {
    let upstream = Flaky::start(500).await;
    let config = json!({
        "trip_when": { "response_code_ratio": { "from": 500, "to": 600, "ratio": 0.25 } },
        "check_period_ms": 10,
        "min_requests": 5,
        "fallback_secs": 1,
        "recovery_secs": 1,
    });
    let podgate = serve(&config, upstream.addr).await;
    until_open(&podgate).await;
    assert_eq!(
        events_of(&podgate, "circuit_opened").await,
        [json!({ "seq": 1, "kind": "circuit_opened", "app": "a.test", "middleware": "cb" })]
    );
    assert!(events_of(&podgate, "circuit_closed").await.is_empty());

    // The backend is fine again. Traffic returns over a second, and the first request after that
    // closes the circuit.
    upstream.answer_with(200);
    let deadline = Instant::now() + Duration::from_secs(15);
    while events_of(&podgate, "circuit_closed").await.is_empty() {
        assert!(Instant::now() < deadline, "the circuit never closed");
        podgate.get("a.test", "/").await;
        sleep(Duration::from_millis(50)).await;
    }
    for _ in 0..20 {
        assert_eq!(podgate.get("a.test", "/").await.body, "upstream");
    }
    assert_eq!(events_of(&podgate, "circuit_opened").await.len(), 1);
    let closed = events_of(&podgate, "circuit_closed").await;
    assert_eq!(closed.len(), 1, "{closed:?}");
    assert_eq!(closed[0]["app"], "a.test");
    assert_eq!(closed[0]["middleware"], "cb");
}

#[tokio::test]
async fn circuit_invalid_config_rejected() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    for (config, what) in [
        (json!({ "trip_when": {} }), "no trigger"),
        (
            json!({ "trip_when": { "network_error_ratio": 1.5 } }),
            "ratio over 1",
        ),
        (
            json!({ "trip_when": { "response_code_ratio": { "from": 500, "to": 600, "ratio": -0.1 } } }),
            "negative ratio",
        ),
        (
            json!({ "trip_when": { "latency_quantile_ms": { "quantile": 101.0, "ms": 100 } } }),
            "quantile over 100",
        ),
        (
            json!({ "trip_when": { "network_error_ratio": 0.3 }, "expression": "NetworkErrorRatio() > 0.30" }),
            "an unknown field, such as Traefik's expression",
        ),
    ] {
        let response = podgate.push_snapshot(&pushed(1, &config, up.addr)).await;
        assert_eq!(response.status, 422, "{what}: {}", response.body);
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_middleware",
            "{what}"
        );
    }
}
