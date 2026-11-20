//! End to end: the event feed and the drain handshake through the real binary.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Podgate, Upstream, app, revision, serving, simple_snapshot, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;

/// A backend that holds every request until the test releases it.
struct HoldUpstream {
    addr: SocketAddr,
    /// One message per request that reached the backend.
    started: mpsc::UnboundedReceiver<()>,
    gate: Arc<Semaphore>,
}

impl HoldUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let addr = listener.local_addr().expect("upstream addr");
        let (started_tx, started) = mpsc::unbounded_channel();
        let gate = Arc::new(Semaphore::new(0));
        tokio::spawn({
            let gate = Arc::clone(&gate);
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(hold_one(stream, started_tx.clone(), Arc::clone(&gate)));
                }
            }
        });
        Self {
            addr,
            started,
            gate,
        }
    }

    async fn request_arrived(&mut self) {
        timeout(Duration::from_secs(5), self.started.recv())
            .await
            .expect("the request reaches the upstream")
            .expect("upstream alive");
    }

    fn release_one(&self) {
        self.gate.add_permits(1);
    }
}

async fn hold_one(mut stream: TcpStream, started: mpsc::UnboundedSender<()>, gate: Arc<Semaphore>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
    if started.send(()).is_err() {
        return;
    }
    gate.acquire().await.expect("gate open").forget();
    drop(
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone")
            .await,
    );
}

async fn events(podgate: &Podgate, after: u64, timeout_secs: u64) -> Value {
    let response = podgate
        .admin_get(&format!(
            "/v1/events?after={after}&timeout_secs={timeout_secs}"
        ))
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    response.json()
}

fn drained(seq: u64, app: &str, revision: &str) -> Value {
    json!({"seq": seq, "kind": "revision_drained", "app": app, "revision": revision})
}

#[tokio::test]
async fn drain_waits_for_inflight() {
    let podgate = Arc::new(Podgate::start().await);
    let mut slow = HoldUpstream::start().await;
    let fresh = Upstream::start("fresh").await;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[app("a", &["a.test"], &[serving("r1", slow.addr)])],
        ))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");

    let in_flight = tokio::spawn({
        let podgate = Arc::clone(&podgate);
        async move { podgate.get("a.test", "/").await }
    });
    slow.request_arrived().await;

    let pushed = podgate
        .push_snapshot(&snapshot(
            2,
            &[app(
                "a",
                &["a.test"],
                &[
                    revision("r1", slow.addr, 100, "draining"),
                    serving("r2", fresh.addr),
                ],
            )],
        ))
        .await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    assert_eq!(
        podgate.get("a.test", "/").await.body,
        "fresh",
        "new requests leave the draining revision"
    );

    let before = events(&podgate, 0, 1).await;
    assert_eq!(before["events"], json!([]), "no drain while a request runs");

    slow.release_one();
    let response = in_flight.await.expect("request task");
    assert_eq!((response.status, response.body.as_str()), (200, "done"));

    let after = events(&podgate, 0, 4).await;
    assert_eq!(after["events"], json!([drained(1, "a", "r1")]));
    let later = events(&podgate, 1, 1).await;
    assert_eq!(later["events"], json!([]), "exactly one drain event");
}

#[tokio::test]
async fn drain_of_an_idle_revision_is_reported_once() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let draining = |version| {
        snapshot(
            version,
            &[app(
                "a",
                &["a.test"],
                &[
                    revision("r1", upstream.addr, 100, "draining"),
                    serving("r2", upstream.addr),
                ],
            )],
        )
    };
    podgate
        .push_snapshot(&snapshot(
            1,
            &[app(
                "a",
                &["a.test"],
                &[serving("r1", upstream.addr), serving("r2", upstream.addr)],
            )],
        ))
        .await;
    podgate.push_snapshot(&draining(2)).await;
    podgate.push_snapshot(&draining(3)).await;

    let seen = events(&podgate, 0, 0).await;
    assert_eq!(seen["events"], json!([drained(1, "a", "r1")]));
}

#[tokio::test]
async fn events_long_poll_timeout() {
    let podgate = Podgate::start().await;
    let started = Instant::now();
    let seen = events(&podgate, 0, 1).await;
    let waited = started.elapsed();
    assert_eq!(seen["events"], json!([]));
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_secs(4),
        "waited {waited:?}"
    );
}

#[tokio::test]
async fn events_long_poll_wakes_on_a_new_event() {
    let podgate = Arc::new(Podgate::start().await);
    let upstream = Upstream::start("x").await;
    let poll = tokio::spawn({
        let podgate = Arc::clone(&podgate);
        async move { events(&podgate, 0, 4).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let drained_at_once = snapshot(
        1,
        &[app(
            "a",
            &["a.test"],
            &[revision("r1", upstream.addr, 100, "draining")],
        )],
    );
    podgate.push_snapshot(&drained_at_once).await;

    let started = Instant::now();
    let seen = poll.await.expect("poll task");
    assert_eq!(seen["events"], json!([drained(1, "a", "r1")]));
    assert!(started.elapsed() < Duration::from_secs(2), "poll woke late");
}

#[tokio::test]
async fn events_resume_after() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    podgate
        .push_snapshot(&simple_snapshot(1, &[("a.test", upstream.addr)]))
        .await;
    let both = snapshot(
        2,
        &[
            app(
                "a",
                &["a.test"],
                &[revision("r1", upstream.addr, 100, "draining")],
            ),
            app(
                "b",
                &["b.test"],
                &[revision("r1", upstream.addr, 100, "draining")],
            ),
        ],
    );
    podgate.push_snapshot(&both).await;

    let all = events(&podgate, 0, 0).await;
    let list = all["events"].as_array().expect("list");
    assert_eq!(list.len(), 2, "{all}");
    assert_eq!((list[0]["seq"].clone(), list[1]["seq"].clone()), (json!(1), json!(2)));

    let rest = events(&podgate, 1, 0).await;
    assert_eq!(rest["events"], json!([list[1]]), "no duplicate of seq 1");
    let none = events(&podgate, 2, 0).await;
    assert_eq!(none["events"], json!([]));
}

#[tokio::test]
async fn events_boot_id() {
    let podgate = Podgate::start().await;
    let other = Podgate::start().await;
    let first = events(&podgate, 0, 0).await;
    let second = events(&podgate, 0, 0).await;
    let boot_id = first["boot_id"].as_str().expect("boot_id is a string");
    assert_eq!(boot_id.len(), 32);
    assert_eq!(second["boot_id"], first["boot_id"]);
    assert_ne!(events(&other, 0, 0).await["boot_id"], first["boot_id"]);
}

#[tokio::test]
async fn events_rejects_malformed_queries_as_json() {
    let podgate = Podgate::start().await;
    let response = podgate.admin_get("/v1/events?after=abc").await;
    assert_eq!(response.status, 400);
    assert!(response.json()["error"].is_string());
}
