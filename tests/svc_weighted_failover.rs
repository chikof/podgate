//! The `weighted` and `failover` services through the real proxy. The pick rules on
//! a controlled clock, the graph checks and the retry rules are unit tests in
//! `src/service/graph.rs`; this file covers what only a running proxy shows: the split over
//! HTTP, failover driven by real health checks, a sleeping app, retries across children, the
//! sticky cookie of a parent, and explain.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, Response, Upstream, app, middleware, refused, snapshot, with_chain};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;

const SECRET: &str = "a-secret-of-at-least-16-bytes";

/// A backend that answers every request, health probes included, with a status the test can
/// change and a fixed body.
struct Backend {
    addr: SocketAddr,
    status: Arc<AtomicU16>,
    hits: Arc<AtomicUsize>,
}

impl Backend {
    async fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let status = Arc::new(AtomicU16::new(200));
        let hits = Arc::new(AtomicUsize::new(0));
        let (seen_status, seen_hits) = (Arc::clone(&status), Arc::clone(&hits));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(
                    stream,
                    body,
                    Arc::clone(&seen_status),
                    Arc::clone(&seen_hits),
                ));
            }
        });
        Self { addr, status, hits }
    }

    fn set_status(&self, status: u16) {
        self.status.store(status, Ordering::Relaxed);
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

async fn serve(
    mut stream: TcpStream,
    body: &'static str,
    status: Arc<AtomicU16>,
    hits: Arc<AtomicUsize>,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            seen.drain(..end + 4);
            if !head.contains("/healthz") {
                hits.fetch_add(1, Ordering::Relaxed);
            }
            let response = format!(
                "HTTP/1.1 {} Test\r\nContent-Length: {}\r\n\r\n{body}",
                status.load(Ordering::Relaxed),
                body.len()
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

fn lb(name: &str, addrs: &[SocketAddr]) -> Value {
    let servers: Vec<Value> = addrs
        .iter()
        .map(|addr| json!({ "url": format!("http://{addr}") }))
        .collect();
    json!({ "name": name, "type": "loadbalancer", "servers": servers })
}

fn probed(mut service: Value) -> Value {
    service["health_check"] = json!({ "path": "/healthz", "interval_secs": 1, "timeout_secs": 1 });
    service
}

fn weighted(name: &str, children: &[(&str, u16)]) -> Value {
    let services: Vec<Value> = children
        .iter()
        .map(|(service, weight)| json!({ "service": service, "weight": weight }))
        .collect();
    json!({ "name": name, "type": "weighted", "services": services })
}

fn failover(name: &str, primary: &str, fallback: &str, hold_secs: u64) -> Value {
    json!({ "name": name, "type": "failover", "service": primary, "fallback": fallback,
            "fallback_hold_secs": hold_secs })
}

/// App `a` (`a.test`) whose router uses service `top`, with one serving revision `r1` holding
/// `services`.
fn graph_app(services: &[Value]) -> Value {
    let mut graph = app(
        "a",
        &["a.test"],
        &[json!({ "id": "r1", "state": "serving", "weight": 100, "services": services })],
    );
    graph["routers"][0]["service"] = json!("top");
    graph
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let pushed = podgate.push_snapshot(snapshot).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
}

/// Sends `count` requests and counts the bodies.
async fn bodies(podgate: &Podgate, count: usize) -> BTreeMap<String, usize> {
    let mut seen = BTreeMap::new();
    for _ in 0..count {
        let response = podgate.get("a.test", "/").await;
        assert_eq!(response.status, 200, "{response:?}");
        *seen.entry(response.body).or_default() += 1;
    }
    seen
}

/// Polls until `check` holds, for at most `seconds`.
async fn eventually(what: &str, seconds: u64, mut check: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while !check().await {
        assert!(Instant::now() < deadline, "gave up waiting for {what}");
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn weighted_split_over_http() {
    let podgate = Podgate::start().await;
    let (heavy, light) = (Backend::start("heavy").await, Backend::start("light").await);
    push(
        &podgate,
        &snapshot(
            1,
            &[graph_app(&[
                weighted("top", &[("heavy", 3), ("light", 1)]),
                lb("heavy", &[heavy.addr]),
                lb("light", &[light.addr]),
            ])],
        ),
    )
    .await;
    let seen = bodies(&podgate, 400).await;
    assert_eq!(seen["heavy"] + seen["light"], 400, "{seen:?}");
    assert!(
        (290..=310).contains(&seen["heavy"]),
        "3 of 4 of 400: {seen:?}"
    );
}

#[tokio::test]
async fn failover_end_to_end() {
    let podgate = Podgate::start().await;
    let (primary, fallback) = (
        Backend::start("primary").await,
        Backend::start("fallback").await,
    );
    push(
        &podgate,
        &snapshot(
            1,
            &[graph_app(&[
                failover("top", "p", "f", 1),
                probed(lb("p", &[primary.addr])),
                lb("f", &[fallback.addr]),
            ])],
        ),
    )
    .await;
    assert_eq!(
        bodies(&podgate, 5).await,
        BTreeMap::from([("primary".to_owned(), 5)])
    );

    // The probe fails: the fallback takes over, without any request having failed.
    primary.set_status(503);
    eventually("the fallback to take over", 10, async || {
        podgate.get("a.test", "/").await.body == "fallback"
    })
    .await;
    assert_eq!(
        bodies(&podgate, 5).await,
        BTreeMap::from([("fallback".to_owned(), 5)])
    );

    // The primary is back: the fallback serves for `fallback_hold_secs` more, then it returns.
    primary.set_status(200);
    eventually("the primary to take over again", 10, async || {
        podgate.get("a.test", "/").await.body == "primary"
    })
    .await;
    assert_eq!(
        bodies(&podgate, 5).await,
        BTreeMap::from([("primary".to_owned(), 5)])
    );
}

/// A sleeping `scale_to_zero` app: `failover` whose primary has no server.
fn sleepy(primary: &[SocketAddr], fallback: SocketAddr) -> Value {
    let mut sleepy = graph_app(&[
        failover("top", "p", "f", 10),
        lb("p", primary),
        lb("f", &[fallback]),
    ]);
    sleepy["scale_to_zero"] = json!({ "idle_secs": 3600, "wake_timeout_secs": 20 });
    sleepy
}

#[tokio::test]
async fn failover_does_not_hide_sleeping_app_end_to_end() {
    let podgate = Arc::new(Podgate::start().await);
    let (primary, fallback) = (
        Upstream::start("primary").await,
        Upstream::start("fallback").await,
    );
    push(&podgate, &snapshot(1, &[sleepy(&[], fallback.addr)])).await;

    let held: JoinHandle<Response> = {
        let podgate = Arc::clone(&podgate);
        tokio::spawn(async move { podgate.get("a.test", "/").await })
    };
    sleep(Duration::from_millis(700)).await;
    assert!(
        !held.is_finished(),
        "held for the wake, not answered by the fallback"
    );
    let events = podgate.admin_get("/v1/events?after=0&timeout_secs=4").await;
    assert_eq!(
        events.json()["events"],
        json!([{ "seq": 1, "kind": "wake_requested", "app": "a" }])
    );

    push(
        &podgate,
        &snapshot(2, &[sleepy(&[primary.addr], fallback.addr)]),
    )
    .await;
    let response = held.await.expect("request task");
    assert_eq!((response.status, response.body.as_str()), (200, "primary"));
}

/// A `retry` middleware that retries at once.
fn with_retry(app: Value) -> Value {
    with_chain(
        app,
        &[middleware(
            "r",
            "retry",
            json!({ "attempts": 3, "initial_interval_ms": 0 }),
        )],
    )
}

#[tokio::test]
async fn retry_across_weighted_children_end_to_end() {
    let podgate = Podgate::start().await;
    let (dead, live) = (refused(), Backend::start("live").await);
    push(
        &podgate,
        &snapshot(
            1,
            &[with_retry(graph_app(&[
                weighted("top", &[("dead", 1), ("live", 1)]),
                lb("dead", &[dead.addr]),
                lb("live", &[live.addr]),
            ]))],
        ),
    )
    .await;
    // Half the requests are sent to the child whose only server refuses: the retry moves to the
    // other child, which no balancer inside one service could do.
    assert_eq!(
        bodies(&podgate, 20).await,
        BTreeMap::from([("live".to_owned(), 20)])
    );
    assert_eq!(live.hits(), 20);
}

#[tokio::test]
async fn retry_under_failover_reaches_fallback_end_to_end() {
    let podgate = Podgate::start().await;
    let (dead, fallback) = (refused(), Backend::start("fallback").await);
    push(
        &podgate,
        &snapshot(
            1,
            &[with_retry(graph_app(&[
                failover("top", "p", "f", 10),
                lb("p", &[dead.addr]),
                lb("f", &[fallback.addr]),
            ]))],
        ),
    )
    .await;
    // No health check marks the primary down: the first attempt dials it, and the retry goes on
    // to the fallback.
    assert_eq!(
        bodies(&podgate, 5).await,
        BTreeMap::from([("fallback".to_owned(), 5)])
    );
    // The retries did not start a hold: nothing else changed about the primary.
    assert_eq!(fallback.hits(), 5);
}

fn set_cookie<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .filter(|(header, _)| header == "set-cookie")
        .map(|(_, value)| value.as_str())
        .find(|value| value.starts_with(&format!("{name}=")))
}

fn cookie_pair(response: &Response, name: &str) -> String {
    let header = set_cookie(response, name).unwrap_or_else(|| panic!("no {name}: {response:?}"));
    header.split(';').next().expect("pair").to_owned()
}

#[tokio::test]
async fn weighted_sticky_pins_child() {
    let podgate = Podgate::start().await;
    let (one, two) = (Backend::start("one").await, Backend::start("two").await);
    let mut split = weighted("top", &[("one", 1), ("two", 1)]);
    split["sticky"] = json!({ "cookie": {} });
    let mut pushed = snapshot(
        1,
        &[graph_app(&[
            split,
            lb("one", &[one.addr]),
            lb("two", &[two.addr]),
        ])],
    );
    pushed["skew_secret"] = json!(SECRET);
    push(&podgate, &pushed).await;

    // Without the cookie both children answer, and every answer pins the client.
    let mut pins: BTreeMap<String, String> = BTreeMap::new();
    for _ in 0..6 {
        let response = podgate.get("a.test", "/").await;
        let header = set_cookie(&response, "__podgate_svc")
            .expect("a pin")
            .to_owned();
        assert!(
            header.contains("HttpOnly") && header.contains("SameSite=Lax"),
            "{header}"
        );
        pins.insert(
            response.body.clone(),
            cookie_pair(&response, "__podgate_svc"),
        );
    }
    assert_eq!(pins.len(), 2, "both children were chosen: {pins:?}");

    // With a pin the client stays on its child, and gets no new cookie.
    for (body, pin) in &pins {
        for _ in 0..10 {
            let response = podgate
                .get_with_headers("a.test", "/", &[("cookie", pin.as_str())])
                .await;
            assert_eq!(&response.body, body);
            assert!(
                set_cookie(&response, "__podgate_svc").is_none(),
                "{response:?}"
            );
        }
    }

    let forged = "__podgate_svc=AAAAAAAAAAAAAAAAAAAAAA";
    let response = podgate
        .get_with_headers("a.test", "/", &[("cookie", forged)])
        .await;
    assert_eq!(response.status, 200);
    assert!(
        set_cookie(&response, "__podgate_svc").is_some(),
        "a forged pin pins nothing"
    );
}

#[tokio::test]
async fn weighted_sticky_and_child_sticky_use_two_cookies() {
    let podgate = Podgate::start().await;
    let backends = [
        Backend::start("one").await,
        Backend::start("two").await,
        Backend::start("three").await,
    ];
    let mut split = weighted("top", &[("one", 1)]);
    split["sticky"] = json!({ "cookie": {} });
    let mut child = lb(
        "one",
        &[backends[0].addr, backends[1].addr, backends[2].addr],
    );
    child["sticky"] = json!({ "cookie": {} });
    let mut pushed = snapshot(1, &[graph_app(&[split.clone(), child.clone()])]);
    pushed["skew_secret"] = json!(SECRET);
    push(&podgate, &pushed).await;
    let response = podgate.get("a.test", "/").await;
    let (parent_pin, server_pin) = (
        cookie_pair(&response, "__podgate_svc"),
        cookie_pair(&response, "__podgate_srv"),
    );
    assert_ne!(parent_pin, server_pin);
    let cookie = format!("{parent_pin}; {server_pin}");
    for _ in 0..10 {
        let again = podgate
            .get_with_headers("a.test", "/", &[("cookie", cookie.as_str())])
            .await;
        assert_eq!(again.body, response.body);
        assert!(
            set_cookie(&again, "__podgate_svc").is_none()
                && set_cookie(&again, "__podgate_srv").is_none(),
            "{again:?}"
        );
    }

    // One cookie name on one path would let the two overwrite each other.
    split["sticky"] = json!({ "cookie": { "name": "__podgate_srv" } });
    let mut clash = snapshot(2, &[graph_app(&[split, child])]);
    clash["skew_secret"] = json!(SECRET);
    let refused = podgate.push_snapshot(&clash).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert!(refused.body.contains("invalid_service"), "{}", refused.body);
}

#[tokio::test]
async fn explain_shows_service_graph() {
    let podgate = Podgate::start().await;
    let (v1, v2) = (Backend::start("v1").await, Backend::start("v2").await);
    let dead = refused();
    push(
        &podgate,
        &snapshot(
            1,
            &[graph_app(&[
                weighted("top", &[("safe", 9), ("web-v1", 1), ("asleep", 5)]),
                failover("safe", "web-v2", "web-v1", 10),
                lb("web-v1", &[v1.addr]),
                lb("web-v2", &[v2.addr, dead.addr]),
                lb("asleep", &[]),
            ])],
        ),
    )
    .await;
    let answer = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let explained = answer.json();
    assert_eq!(explained["service"], "top");
    let graph = &explained["revisions"][0]["graph"];
    assert_eq!(graph["path"], "top -> safe -> web-v2", "{graph}");
    let root = &graph["root"];
    assert_eq!(
        (root["service"].as_str(), root["kind"].as_str()),
        (Some("top"), Some("weighted"))
    );
    let children = root["children"].as_array().expect("children");
    let summary: Vec<(&str, u64, u64, &str, bool)> = children
        .iter()
        .map(|child| {
            (
                child["service"].as_str().expect("service"),
                child["weight"].as_u64().expect("weight"),
                child["effective_weight"].as_u64().expect("effective"),
                child["state"].as_str().expect("state"),
                child["on_path"].as_bool().expect("on_path"),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("safe", 9, 9, "ready", true),
            ("web-v1", 1, 1, "ready", false),
            ("asleep", 5, 0, "asleep", false),
        ],
        "an asleep child has weight 0 in effect"
    );
    let safe = children[0]["children"]
        .as_array()
        .expect("failover children");
    assert_eq!(safe[0]["role"], "primary");
    assert_eq!(safe[0]["service"], "web-v2");
    assert_eq!(safe[1]["role"], "fallback");
    assert_eq!(safe[1]["service"], "web-v1");
    assert_eq!(safe[1]["on_path"], false);

    // A plain service has no graph.
    push(
        &podgate,
        &snapshot(2, &[graph_app(&[lb("top", &[v1.addr])])]),
    )
    .await;
    let plain = podgate
        .admin_get("/v1/explain?url=http://a.test/")
        .await
        .json();
    assert!(plain["revisions"][0].get("graph").is_none(), "{plain}");
}

#[tokio::test]
async fn unknown_graph_fields_are_refused_not_ignored() {
    let podgate = Podgate::start().await;
    let backend = Backend::start("x").await;
    let mut split = weighted("top", &[("web", 1)]);
    split["servers"] = json!([]);
    let reply = podgate
        .push_snapshot(&snapshot(
            1,
            &[graph_app(&[split, lb("web", &[backend.addr])])],
        ))
        .await;
    assert_eq!(reply.status, 422, "{}", reply.body);
    assert!(reply.body.contains("invalid_service"), "{}", reply.body);
}

#[tokio::test]
async fn weighted_sticky_cookie_not_set_on_shared_cacheable_response() {
    let podgate = Podgate::start().await;
    let (one, two) = (Backend::start("one").await, Backend::start("two").await);
    let mut split = weighted("top", &[("one", 1), ("two", 1)]);
    split["sticky"] = json!({ "cookie": {} });
    let services = [split, lb("one", &[one.addr]), lb("two", &[two.addr])];
    let with_control = |version: u64, control: &str| {
        let header = middleware(
            "cc",
            "headers",
            json!({ "response": { "set": { "cache-control": control } } }),
        );
        let mut pushed = snapshot(version, &[with_chain(graph_app(&services), &[header])]);
        pushed["skew_secret"] = json!(SECRET);
        pushed
    };

    push(&podgate, &with_control(1, "max-age=60")).await;
    for _ in 0..4 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!(response.status, 200);
        assert!(
            set_cookie(&response, "__podgate_svc").is_none(),
            "a shared cache must not store a pin: {response:?}"
        );
    }

    push(&podgate, &with_control(2, "private, max-age=60")).await;
    let response = podgate.get("a.test", "/").await;
    assert!(
        set_cookie(&response, "__podgate_svc").is_some(),
        "{response:?}"
    );
}
