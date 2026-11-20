//! Upstream connections are never shared across tenants, apps or revisions, and NTLM or
//! Negotiate connections never cross downstream connections.
//!
//! The test upstream numbers every connection it accepts and answers each request with
//! `x-conn: <number>`, so a test sees which upstream connection served which request.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{Podgate, app, revision, serving};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

/// Time for Pingora to move a finished upstream connection into its pool.
const POOL_SETTLE: Duration = Duration::from_millis(150);

/// A backend that tags every response with the number of the connection it arrived on.
async fn conn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let mut accepted = 0_u64;
        while let Ok((stream, _)) = listener.accept().await {
            accepted += 1;
            tokio::spawn(serve_numbered(stream, accepted));
        }
    });
    addr
}

async fn serve_numbered(mut stream: TcpStream, number: u64) {
    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nx-conn: {number}\r\n\r\nok");
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            seen.drain(..end + 4);
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

/// A downstream HTTP/1.1 keepalive connection to the proxy.
struct Client {
    stream: TcpStream,
}

impl Client {
    async fn connect(podgate: &Podgate) -> Self {
        let stream = TcpStream::connect(podgate.proxy_addr)
            .await
            .expect("connect to the proxy");
        Self { stream }
    }

    /// Sends `GET /` for `host` with the optional `Authorization` value and returns the number of
    /// the upstream connection that served it. The downstream connection stays open.
    async fn get(&mut self, host: &str, authorization: Option<&str>) -> u64 {
        let auth = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n{auth}\r\n");
        timeout(Duration::from_secs(10), async {
            self.stream
                .write_all(request.as_bytes())
                .await
                .expect("send request");
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 1024];
            // The response is a head plus a 2-byte body.
            loop {
                if let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n")
                    && raw.len() >= end + 4 + 2
                {
                    break;
                }
                let read = self.stream.read(&mut chunk).await.expect("read response");
                assert!(read > 0, "proxy closed the connection: {raw:?}");
                raw.extend_from_slice(&chunk[..read]);
            }
            let text = String::from_utf8_lossy(&raw).into_owned();
            assert!(text.starts_with("HTTP/1.1 200"), "{text}");
            text.lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("x-conn:")
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| panic!("no x-conn header: {text}"))
                .trim()
                .parse()
                .expect("x-conn is a number")
        })
        .await
        .expect("response in time")
    }
}

/// The upstream connection number for one request on a fresh downstream connection.
async fn conn_of(podgate: &Podgate, host: &str, authorization: Option<&str>) -> u64 {
    Client::connect(podgate)
        .await
        .get(host, authorization)
        .await
}

fn tenant(id: &str) -> Value {
    json!({ "id": id, "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } })
}

fn app_of(tenant: &str, id: &str, host: &str, revisions: &[Value]) -> Value {
    let mut app = app(id, &[host], revisions);
    app["tenant"] = Value::from(tenant);
    app
}

fn snapshot(version: u64, apps: &[Value]) -> Value {
    json!({ "version": version, "tenants": [tenant("t1"), tenant("t2")], "apps": apps })
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{response:?}");
}

/// `a.test` (tenant `t1`) and `b.test` (tenant `t2` or `t1`) behind one upstream address.
async fn two_apps(second_tenant: &str) -> Podgate {
    let podgate = Podgate::start().await;
    let upstream = conn_upstream().await;
    let apps = [
        app_of("t1", "a", "a.test", &[serving("r1", upstream)]),
        app_of(second_tenant, "b", "b.test", &[serving("r1", upstream)]),
    ];
    push(&podgate, &snapshot(1, &apps)).await;
    podgate
}

/// Requests for `a.test`, then `b.test`, then `a.test` again: the repeat must reuse the first
/// connection (so the pool is really in play) and `b.test` must not touch it.
async fn assert_isolated(podgate: &Podgate) {
    let first = conn_of(podgate, "a.test", None).await;
    sleep(POOL_SETTLE).await;
    assert_eq!(
        conn_of(podgate, "a.test", None).await,
        first,
        "the same identity reuses its idle connection"
    );
    sleep(POOL_SETTLE).await;
    let other = conn_of(podgate, "b.test", None).await;
    assert_ne!(other, first, "another identity opens its own connection");
    sleep(POOL_SETTLE).await;
    assert_eq!(conn_of(podgate, "b.test", None).await, other);
    assert_eq!(conn_of(podgate, "a.test", None).await, first);
}

#[tokio::test]
async fn pool_isolated_per_tenant() {
    assert_isolated(&two_apps("t2").await).await;
}

#[tokio::test]
async fn pool_isolated_per_app() {
    assert_isolated(&two_apps("t1").await).await;
}

#[tokio::test]
async fn pool_isolated_per_revision() {
    let podgate = Podgate::start().await;
    let upstream = conn_upstream().await;
    push(
        &podgate,
        &snapshot(
            1,
            &[app_of("t1", "a", "a.test", &[serving("r1", upstream)])],
        ),
    )
    .await;
    let first = conn_of(&podgate, "a.test", None).await;
    sleep(POOL_SETTLE).await;
    assert_eq!(conn_of(&podgate, "a.test", None).await, first);

    let second = [
        revision("r1", upstream, 100, "retiring"),
        serving("r2", upstream),
    ];
    push(
        &podgate,
        &snapshot(2, &[app_of("t1", "a", "a.test", &second)]),
    )
    .await;
    sleep(POOL_SETTLE).await;
    let rolled = conn_of(&podgate, "a.test", None).await;
    assert_ne!(
        rolled, first,
        "a new revision never takes the old one's connection"
    );
    sleep(POOL_SETTLE).await;
    assert_eq!(conn_of(&podgate, "a.test", None).await, rolled);
}

/// An authenticated downstream connection `A` and a bystander `B`, for `scheme`.
async fn assert_pinned(scheme: &str) {
    let podgate = two_apps("t1").await;
    // A connection in the shared pool, which the pinned request must not take.
    let shared = conn_of(&podgate, "a.test", None).await;
    sleep(POOL_SETTLE).await;

    let credentials = format!("{scheme} TlRMTVNTUAAB");
    let mut owner = Client::connect(&podgate).await;
    let pinned = owner.get("a.test", Some(&credentials)).await;
    assert_ne!(
        pinned, shared,
        "the pinned request does not draw from the shared pool"
    );
    assert_eq!(
        owner.get("a.test", None).await,
        pinned,
        "later requests on the same downstream connection stay on the authenticated connection"
    );
    assert_eq!(owner.get("a.test", Some(&credentials)).await, pinned);

    sleep(POOL_SETTLE).await;
    let mut other = Client::connect(&podgate).await;
    let plain = other.get("a.test", None).await;
    assert_ne!(
        plain, pinned,
        "an unauthenticated client never gets the pinned connection"
    );
    let rival = other.get("a.test", Some(&credentials)).await;
    assert_ne!(
        rival, pinned,
        "another client with NTLM gets its own connection"
    );
    assert_ne!(rival, plain);

    drop(owner);
    sleep(POOL_SETTLE).await;
    let newcomer = conn_of(&podgate, "a.test", Some(&credentials)).await;
    assert_ne!(
        newcomer, pinned,
        "a closed downstream connection leaves its pin unreachable"
    );
    assert_ne!(conn_of(&podgate, "a.test", None).await, pinned);
}

#[tokio::test]
async fn pool_ntlm_pinned() {
    assert_pinned("NTLM").await;
}

#[tokio::test]
async fn pool_negotiate_pinned() {
    assert_pinned("negotiate").await;
}
