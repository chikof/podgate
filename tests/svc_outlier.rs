//! Passive outlier ejection (`passive` on a `loadbalancer`), through the real proxy. The state
//! machine on a controlled clock is tested in `src/service/outlier.rs`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{Podgate, app, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// What a backend answers to its n-th request (from `1`): a status and how long it takes.
type Script = Arc<dyn Fn(usize) -> (u16, Duration) + Send + Sync>;

struct Backend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Backend {
    async fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, Arc::clone(&script), Arc::clone(&counter)));
            }
        });
        Self { addr, hits }
    }

    async fn always(status: u16) -> Self {
        Self::start(Arc::new(move |_| (status, Duration::ZERO))).await
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn serve(mut stream: TcpStream, script: Script, hits: Arc<AtomicUsize>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            seen.drain(..end + 4);
            let (status, delay) = script(hits.fetch_add(1, Ordering::Relaxed) + 1);
            sleep(delay).await;
            let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: 2\r\n\r\nok");
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

/// The settings of `passive` most tests use: `failures` in a row ejects for `secs` seconds,
/// at most `percent` of the servers.
fn passive(failures: u32, secs: u32, percent: u8) -> Value {
    json!({ "consecutive_failures": failures, "ejection_secs": secs, "max_ejection_percent": percent })
}

/// App `a` (`a.test`) whose `web` service balances `servers` round robin with `passive`, and an
/// unrelated app `b` declared by `bump`. The tenant allows `max_inflight` requests.
fn guarded(
    version: u64,
    servers: &[&Backend],
    passive: &Value,
    bump: &str,
    max_inflight: u64,
) -> Value {
    let urls: Vec<Value> = servers
        .iter()
        .map(|backend| json!({ "url": backend.url() }))
        .collect();
    let revision = json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
        { "name": "web", "type": "loadbalancer", "servers": urls, "passive": passive }] });
    let mut other = app("b", &["b.test"], &[]);
    other["declared_by"] = json!(bump);
    other["revisions"] = json!([{ "id": "r1", "state": "serving", "weight": 1, "services": [
        { "name": "web", "type": "loadbalancer", "servers": [{ "url": "http://127.0.0.1:9" }] }] }]);
    let mut pushed = snapshot(version, &[app("a", &["a.test"], &[revision]), other]);
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(max_inflight);
    pushed
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let pushed = podgate.push_snapshot(snapshot).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
}

/// The servers of app `a` as `explain` shows them, in declaration order.
async fn explained(podgate: &Podgate) -> Vec<Value> {
    let answer = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(answer.status, 200, "{answer:?}");
    answer.json()["revisions"][0]["servers"]
        .as_array()
        .expect("servers")
        .clone()
}

async fn statuses(podgate: &Podgate, count: usize) -> Vec<u16> {
    let mut seen = Vec::new();
    for _ in 0..count {
        seen.push(podgate.get("a.test", "/").await.status);
    }
    seen
}

/// A failing and a healthy backend behind `passive(2, 1, 50)`, with the failing one ejected.
async fn ejected_pair(podgate: &Podgate) -> (Backend, Backend) {
    let (bad, good) = (Backend::always(502).await, Backend::always(200).await);
    push(
        podgate,
        &guarded(1, &[&bad, &good], &passive(2, 1, 50), "x", 100),
    )
    .await;
    let seen = statuses(podgate, 10).await;
    assert_eq!(
        seen.iter().filter(|status| **status == 502).count(),
        2,
        "{seen:?}"
    );
    (bad, good)
}

#[tokio::test]
async fn outlier_ejects_after_consecutive_failures() {
    let podgate = Podgate::start().await;
    let (bad, good) = ejected_pair(&podgate).await;
    assert_eq!(bad.hits(), 2, "no traffic after the second failure");
    assert_eq!(good.hits(), 8);
    let servers = explained(&podgate).await;
    assert_eq!(servers[0]["available"], false);
    assert_eq!(servers[1]["available"], true);
}

#[tokio::test]
async fn outlier_returns_after_ejection() {
    let podgate = Podgate::start().await;
    let (bad, _good) = ejected_pair(&podgate).await;
    sleep(Duration::from_millis(1200)).await;
    assert_eq!(explained(&podgate).await[0]["available"], true);
    let seen = statuses(&podgate, 6).await;
    assert!(
        bad.hits() > 2,
        "the server is tried again after its ejection"
    );
    assert!(seen.contains(&502), "{seen:?}");
}

#[tokio::test]
async fn outlier_success_resets_counter() {
    let podgate = Podgate::start().await;
    let flaky = Backend::start(Arc::new(|hit| {
        (if hit % 2 == 1 { 502 } else { 200 }, Duration::ZERO)
    }))
    .await;
    let good = Backend::always(200).await;
    push(
        &podgate,
        &guarded(1, &[&flaky, &good], &passive(2, 30, 100), "x", 100),
    )
    .await;
    let seen = statuses(&podgate, 12).await;
    assert_eq!(
        seen.iter().filter(|status| **status == 502).count(),
        3,
        "{seen:?}"
    );
    assert_eq!(flaky.hits(), 6, "failures never come twice in a row");
    assert_eq!(explained(&podgate).await[0]["available"], true);
}

#[tokio::test]
async fn outlier_max_ejection_percent() {
    let podgate = Podgate::start().await;
    let backends = [
        Backend::always(502).await,
        Backend::always(502).await,
        Backend::always(502).await,
        Backend::always(502).await,
    ];
    let refs: Vec<&Backend> = backends.iter().collect();
    push(&podgate, &guarded(1, &refs, &passive(1, 60, 50), "x", 100)).await;
    statuses(&podgate, 40).await;
    let mut hits: Vec<usize> = backends.iter().map(Backend::hits).collect();
    hits.sort_unstable();
    assert_eq!(hits[..2], [1, 1], "50% of four servers is two ejections");
    assert_eq!(hits.iter().sum::<usize>(), 40);
    let ejected = explained(&podgate)
        .await
        .iter()
        .filter(|server| server["available"] == false)
        .count();
    assert_eq!(ejected, 2);
}

#[tokio::test]
async fn outlier_never_ejects_last_server() {
    let podgate = Podgate::start().await;
    let backends = [
        Backend::always(502).await,
        Backend::always(502).await,
        Backend::always(502).await,
    ];
    let refs: Vec<&Backend> = backends.iter().collect();
    push(&podgate, &guarded(1, &refs, &passive(1, 60, 100), "x", 100)).await;
    let seen = statuses(&podgate, 30).await;
    assert!(
        seen.iter().all(|status| *status == 502),
        "the service degrades and never goes dark: {seen:?}"
    );
    let mut hits: Vec<usize> = backends.iter().map(Backend::hits).collect();
    hits.sort_unstable();
    assert_eq!(hits, [1, 1, 28]);
}

#[tokio::test]
async fn outlier_ignores_capacity_and_client_abort() {
    let podgate = Arc::new(Podgate::start().await);

    // A tenant at its limit answers 503 itself: that says nothing about the servers.
    let (slow_a, slow_b) = (
        Backend::start(Arc::new(|_| (200, Duration::from_millis(400)))).await,
        Backend::start(Arc::new(|_| (200, Duration::from_millis(400)))).await,
    );
    push(
        &podgate,
        &guarded(1, &[&slow_a, &slow_b], &passive(1, 60, 100), "x", 1),
    )
    .await;
    let holder = {
        let podgate = Arc::clone(&podgate);
        tokio::spawn(async move { podgate.get("a.test", "/").await.status })
    };
    sleep(Duration::from_millis(100)).await;
    for _ in 0..4 {
        let refused = podgate.get("a.test", "/").await;
        assert_eq!(refused.status, 503, "{}", refused.body);
    }
    assert_eq!(holder.await.expect("holder"), 200);
    assert!(
        explained(&podgate)
            .await
            .iter()
            .all(|s| s["available"] == true)
    );

    // A client that leaves before a failing server answers is not that server's failure.
    let failing = Backend::start(Arc::new(|_| (502, Duration::from_millis(300)))).await;
    let good = Backend::always(200).await;
    push(
        &podgate,
        &guarded(2, &[&failing, &good], &passive(1, 60, 100), "x", 100),
    )
    .await;
    for _ in 0..4 {
        let mut stream = TcpStream::connect(podgate.proxy_addr)
            .await
            .expect("connect");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .expect("send");
        sleep(Duration::from_millis(60)).await;
    }
    sleep(Duration::from_millis(500)).await;
    assert!(
        failing.hits() >= 1,
        "the aborted requests reached the failing server"
    );
    assert!(
        explained(&podgate)
            .await
            .iter()
            .all(|s| s["available"] == true),
        "no abort counted"
    );
}

#[tokio::test]
async fn outlier_state_survives_unrelated_push() {
    let podgate = Podgate::start().await;
    let (bad, _good) = ejected_pair(&podgate).await;
    push(
        &podgate,
        &guarded(
            2,
            &[&bad, &_good],
            &passive(2, 1, 50),
            "changed elsewhere",
            100,
        ),
    )
    .await;
    assert_eq!(explained(&podgate).await[0]["available"], false);
}

#[tokio::test]
async fn outlier_state_resets_on_change() {
    let podgate = Podgate::start().await;
    let (bad, good) = ejected_pair(&podgate).await;
    push(
        &podgate,
        &guarded(2, &[&bad, &good], &passive(3, 1, 50), "x", 100),
    )
    .await;
    assert_eq!(explained(&podgate).await[0]["available"], true);
}

#[tokio::test]
async fn explain_shows_ejected_server() {
    let podgate = Podgate::start().await;
    let (bad, good) = ejected_pair(&podgate).await;
    let servers = explained(&podgate).await;
    assert_eq!(servers[0]["url"], bad.url());
    assert_eq!(servers[0]["available"], false);
    let left = servers[0]["ejected_for_ms"]
        .as_u64()
        .expect("ejected_for_ms");
    assert!((1..=1000).contains(&left), "{left}");
    assert_eq!(servers[1]["url"], good.url());
    assert!(servers[1].get("ejected_for_ms").is_none());
}

#[tokio::test]
async fn outlier_metric() {
    let podgate = Podgate::start().await;
    let series =
        "podgate_outlier_ejected_servers{tenant=\"t1\",app=\"a\",revision=\"r1\",service=\"web\"}";
    let (_bad, _good) = ejected_pair(&podgate).await;
    let text = podgate.admin_get("/metrics").await.body;
    assert!(text.contains(&format!("{series} 1\n")), "{text}");
    sleep(Duration::from_millis(1100)).await;
    let text = podgate.admin_get("/metrics").await.body;
    assert!(text.contains(&format!("{series} 0\n")), "{text}");
}
