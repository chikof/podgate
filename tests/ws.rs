//! WebSockets through the real binary: the upgrade over HTTP and TLS, frames of
//! every size, idle behaviour under the entry point's and the transport's timeouts, the
//! middlewares of the route, tenant and revision accounting, snapshot swaps, shutdown, and
//! WebSockets over HTTP/2. The client and the echo upstream speak raw frames
//! (`tests/common/ws.rs`).

mod common;

#[path = "fixtures/jwt/signer.rs"]
mod signer;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::ws::{self, Echo, Frame, Opened, Tunnel};
use common::{
    Podgate, TestCert, app, middleware, refused, revision, router, service, serving, snapshot,
    with_buffering, with_chain, with_forward_auth, with_jwt_auth, with_middleware,
};
use serde_json::{Value, json};
use signer::{Signer, now};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

type Plain = Tunnel<TcpStream>;

/// App `a` on `a.test` whose only revision is served by `upstream`.
fn ws_app(upstream: SocketAddr) -> Value {
    app("a", &["a.test"], &[serving("r1", upstream)])
}

/// Pushes `pushed` and expects it to be applied.
async fn push(podgate: &Podgate, pushed: &Value) {
    let response = podgate.push_snapshot(pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// A podgate serving [`ws_app`] over `echo`.
async fn serve(echo: &Echo) -> Podgate {
    let podgate = Podgate::start().await;
    push(&podgate, &snapshot(1, &[ws_app(echo.addr)])).await;
    podgate
}

/// An upgrade of `path` on `a.test` over plain HTTP.
async fn upgrade(podgate: &Podgate, path: &str, extra: &[(&str, &str)]) -> Opened<TcpStream> {
    let stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect to the proxy");
    ws::open(stream, "a.test", path, extra).await
}

/// An open tunnel to `/` on `a.test`.
async fn tunnel(podgate: &Podgate) -> Plain {
    upgrade(podgate, "/", &[]).await.tunnel()
}

fn text(payload: &str) -> Frame {
    Frame {
        fin: true,
        opcode: ws::TEXT,
        masked: false,
        payload: payload.as_bytes().to_vec(),
    }
}

#[tokio::test]
async fn ws_echo_plain() {
    let echo = Echo::start().await;
    let podgate = serve(&echo).await;
    let mut tunnel = upgrade(
        &podgate,
        "/chat",
        &[
            ("Sec-WebSocket-Protocol", "chat, superchat"),
            ("Sec-WebSocket-Extensions", "permessage-deflate"),
            ("Origin", "http://a.test"),
        ],
    )
    .await
    .tunnel();

    let head = &tunnel.head;
    assert_eq!(
        head.header("sec-websocket-accept"),
        Some(ws::accept_key(ws::KEY).as_str())
    );
    assert_eq!(head.header("sec-websocket-protocol"), Some("chat"));
    assert_eq!(head.header("x-upstream"), Some("echo"));
    assert!(
        head.header("upgrade")
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket")),
        "{head:?}"
    );
    assert!(
        head.header("connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("upgrade")),
        "{head:?}"
    );

    tunnel.send(ws::TEXT, b"hello").await;
    assert_eq!(tunnel.recv().await, text("hello"));

    let heads = echo.upgrade_heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
    for kept in [
        "get /chat http/1.1",
        "sec-websocket-key: dghlihnhbxbszsbub25jzq==",
        "sec-websocket-version: 13",
        "sec-websocket-protocol: chat, superchat",
        "origin: http://a.test",
        "sec-websocket-extensions: permessage-deflate",
        "upgrade: websocket",
        "connection: upgrade",
    ] {
        assert!(
            heads[0].contains(kept),
            "{kept:?} missing from {}",
            heads[0]
        );
    }
    assert_eq!(echo.frames(), [(ws::TEXT, true)]);
}

#[tokio::test]
async fn ws_echo_tls() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    let cert = TestCert::new(&["a.test"]);
    let mut pushed = snapshot(1, &[ws_app(echo.addr)]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    push(&podgate, &pushed).await;

    let stream = podgate.ws_tls("a.test", &cert).await;
    let mut tunnel = ws::open(stream, "a.test", "/secure", &[]).await.tunnel();
    assert_eq!(
        tunnel.head.header("sec-websocket-accept"),
        Some(ws::accept_key(ws::KEY).as_str())
    );
    tunnel.send(ws::TEXT, b"over tls").await;
    assert_eq!(tunnel.recv().await, text("over tls"));
    let heads = echo.upgrade_heads();
    assert!(
        heads[0].contains("x-forwarded-proto: https"),
        "the upstream is told the client used TLS: {}",
        heads[0]
    );
}

#[tokio::test]
async fn ws_large_message() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    // A 1 KiB buffer budget: a tunnel that buffered messages would not fit one.
    let mut pushed = snapshot(1, &[ws_app(echo.addr)]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(1024);
    push(&podgate, &pushed).await;

    let mut tunnel = tunnel(&podgate).await;
    let payload: Vec<u8> = (0..1_048_576_u32).map(|n| (n % 251) as u8).collect();
    let echoed = tunnel.round_trip(ws::BINARY, &payload).await;
    assert_eq!(echoed.opcode, ws::BINARY);
    assert!(echoed.fin);
    assert_eq!(echoed.payload.len(), payload.len());
    assert!(echoed.payload == payload, "the echoed megabyte differs");

    // The same megabyte as 64 KiB fragments, each masked with its own pass over the key.
    let mut wire = Vec::new();
    let chunks: Vec<&[u8]> = payload.chunks(64 * 1024).collect();
    for (index, chunk) in chunks.iter().enumerate() {
        let opcode = if index == 0 {
            ws::BINARY
        } else {
            ws::CONTINUATION
        };
        wire.extend(ws::encode(
            index + 1 == chunks.len(),
            opcode,
            chunk,
            Some([1, 2, 3, 4]),
        ));
    }
    tunnel.send_raw(&wire).await;
    let mut received = Vec::new();
    for _ in 0..chunks.len() {
        received.extend(tunnel.recv().await.payload);
    }
    assert!(received == payload, "the fragmented megabyte differs");
}

#[tokio::test]
async fn ws_ping_pong() {
    let echo = Echo::start().await;
    let podgate = serve(&echo).await;
    let mut tunnel = tunnel(&podgate).await;

    tunnel.send(ws::PING, b"are you there").await;
    let pong = tunnel.recv().await;
    assert_eq!(
        (pong.opcode, pong.payload.as_slice()),
        (ws::PONG, &b"are you there"[..])
    );

    // An unmasked client frame is not the proxy's to judge: the bytes arrive as sent.
    tunnel.send_unmasked(ws::TEXT, b"no mask").await;
    assert_eq!(tunnel.recv().await, text("no mask"));
    let long = vec![b'x'; 125];
    tunnel.send(ws::PING, &long).await;
    assert_eq!(tunnel.recv().await.payload, long);
    assert_eq!(
        echo.frames(),
        [(ws::PING, true), (ws::TEXT, false), (ws::PING, true)]
    );

    tunnel.send(ws::CLOSE, &[0x03, 0xe8]).await;
    assert_eq!(tunnel.recv().await.opcode, ws::CLOSE);
    assert!(tunnel.closes_within(Duration::from_secs(5)).await.is_some());
}

/// Waits up to five seconds for `condition`, polling every 50 ms.
async fn eventually(what: &str, condition: impl AsyncFn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        sleep(Duration::from_millis(50)).await;
    }
}

/// `app` with the middlewares `declared` (name, kind, config) in its default chain.
fn chained<'a>(declared: &'a [(&'a str, &'a str, Value)]) -> impl FnOnce(Value) -> Value + 'a {
    move |app| {
        let middlewares: Vec<Value> = declared
            .iter()
            .map(|(name, kind, config)| middleware(name, kind, config.clone()))
            .collect();
        with_chain(app, &middlewares)
    }
}

/// A podgate serving `app` as the only app of version 1.
async fn serve_app(app: Value) -> Podgate {
    let podgate = Podgate::start().await;
    push(&podgate, &snapshot(1, &[app])).await;
    podgate
}

#[tokio::test]
async fn ws_idle_timeout_closes() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    let mut a = ws_app(echo.addr);
    a["transports"] = json!([{ "name": "t", "type": "servers_transport",
                                "tunnel_idle_timeout_secs": 2, "idle_timeout_secs": 1 }]);
    a["revisions"][0]["services"][0]["transport"] = json!("t");
    let mut pushed = snapshot(1, &[a]);
    // None of these govern a tunnel: `idle_secs` is the keep-alive wait between requests,
    // `write_secs` bounds a stalled write, the transport's `idle_timeout_secs` is for pooled
    // connections.
    pushed["entry_points"] =
        json!([{ "name": "web", "timeouts": { "idle_secs": 1, "write_secs": 1 } }]);
    push(&podgate, &pushed).await;

    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"hi").await;
    assert_eq!(tunnel.recv().await, text("hi"));
    let lived = tunnel
        .closes_within(Duration::from_secs(8))
        .await
        .expect("an idle tunnel is closed at the transport's read timeout");
    assert!(
        (Duration::from_millis(1800)..Duration::from_secs(4)).contains(&lived),
        "closed after the 2 s read timeout, not at idle_secs, not at the default: {lived:?}"
    );
    assert!(
        tunnel.discarded.is_empty() && tunnel.trailing().is_empty(),
        "the proxy wrote nothing into the tunnel when it timed out: {:?} {:?}",
        tunnel.discarded,
        tunnel.trailing()
    );
    assert!(
        echo.wait_open(0, Duration::from_secs(3)).await,
        "the upstream side closed too"
    );
}

#[tokio::test]
async fn ws_active_tunnel_survives_idle_timeout() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    let mut a = ws_app(echo.addr);
    a["transports"] =
        json!([{ "name": "t", "type": "servers_transport", "tunnel_idle_timeout_secs": 2 }]);
    a["revisions"][0]["services"][0]["transport"] = json!("t");
    push(&podgate, &snapshot(1, &[a])).await;

    let mut tunnel = tunnel(&podgate).await;
    let started = Instant::now();
    let mut rounds = 0;
    while started.elapsed() < Duration::from_secs(5) {
        tunnel.send(ws::PING, b"keep").await;
        assert_eq!(tunnel.recv().await.opcode, ws::PONG, "round {rounds}");
        rounds += 1;
        sleep(Duration::from_millis(500)).await;
    }
    assert!(rounds >= 8, "{rounds} rounds");
    assert_eq!(
        echo.open_tunnels(),
        1,
        "twice the read timeout later the tunnel is still open"
    );
    tunnel.send(ws::TEXT, b"still here").await;
    assert_eq!(tunnel.recv().await, text("still here"));
}

#[tokio::test]
async fn ws_upstream_close_ends_tunnel() {
    let echo = Echo::start().await;
    let podgate = serve(&echo).await;

    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"close").await;
    let frame = tunnel.recv().await;
    assert_eq!(
        (frame.opcode, frame.payload.as_slice()),
        (ws::CLOSE, &[0x03, 0xe8][..])
    );
    assert!(tunnel.closes_within(Duration::from_secs(5)).await.is_some());

    let mut abrupt = self::tunnel(&podgate).await;
    abrupt.send(ws::TEXT, b"drop").await;
    assert!(
        abrupt.closes_within(Duration::from_secs(5)).await.is_some(),
        "a dropped upstream ends the tunnel"
    );
    assert!(echo.wait_open(0, Duration::from_secs(3)).await);

    // A client that hangs up ends the upstream side.
    let hangup = self::tunnel(&podgate).await;
    assert!(echo.wait_open(1, Duration::from_secs(3)).await);
    drop(hangup);
    assert!(
        echo.wait_open(0, Duration::from_secs(5)).await,
        "the client's hang-up reaches the upstream"
    );
}

#[tokio::test]
async fn ws_basic_auth_refuses_upgrade() {
    let echo = Echo::start().await;
    let users = json!({ "users": [format!("alice:{}", bcrypt::hash("s3cret", 4).expect("hash"))] });
    let podgate = serve_app(chained(&[("auth", "basic_auth", users)])(ws_app(echo.addr))).await;

    let refused = upgrade(&podgate, "/", &[]).await.refused();
    assert_eq!(refused.status, 401, "{refused:?}");
    assert!(refused.header("www-authenticate").is_some(), "{refused:?}");
    let wrong = format!("Basic {}", STANDARD.encode("alice:wrong"));
    let wrong = upgrade(&podgate, "/", &[("Authorization", &wrong)])
        .await
        .refused();
    assert_eq!(wrong.status, 401);
    assert_eq!(
        echo.connections(),
        0,
        "a refused upgrade never reaches the upstream"
    );

    let right = format!("Basic {}", STANDARD.encode("alice:s3cret"));
    let mut tunnel = upgrade(&podgate, "/", &[("Authorization", &right)])
        .await
        .tunnel();
    tunnel.send(ws::TEXT, b"in").await;
    assert_eq!(tunnel.recv().await, text("in"));
}

/// A `forward_auth` service: `200` for `Authorization: Bearer ok`, `401` for everything else.
async fn gate() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the auth service");
    let addr = listener.local_addr().expect("auth address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 2048];
                while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
                let head = String::from_utf8_lossy(&seen).to_ascii_lowercase();
                let reply = if head.contains("authorization: bearer ok") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied"
                };
                drop(stream.write_all(reply.as_bytes()).await);
            });
        }
    });
    addr
}

#[tokio::test]
async fn ws_forward_auth_refuses_upgrade() {
    let echo = Echo::start().await;
    let auth = gate().await;
    let podgate = serve_app(with_forward_auth(ws_app(echo.addr), auth, &Value::Null)).await;

    let refused = upgrade(&podgate, "/", &[]).await.refused();
    assert_eq!(
        (refused.status, refused.body.as_str()),
        (401, "denied"),
        "{refused:?}"
    );
    assert_eq!(echo.connections(), 0);

    let mut tunnel = upgrade(&podgate, "/", &[("Authorization", "Bearer ok")])
        .await
        .tunnel();
    tunnel.send(ws::TEXT, b"allowed").await;
    assert_eq!(tunnel.recv().await, text("allowed"));
}

#[tokio::test]
async fn ws_jwt_auth_refuses_upgrade() {
    let echo = Echo::start().await;
    let key = Signer::ed25519("k");
    let config = json!({ "keys": { "keys": [key.jwk()] }, "algorithms": ["EdDSA"] });
    let podgate = serve_app(with_jwt_auth(ws_app(echo.addr), config)).await;

    let refused = upgrade(&podgate, "/", &[]).await.refused();
    assert_eq!(refused.status, 401, "{refused:?}");
    let forged = Signer::ed25519("k").sign("EdDSA", &json!({}), &json!({ "sub": "ann", "exp": 1 }));
    let expired = upgrade(
        &podgate,
        "/",
        &[("Authorization", &format!("Bearer {forged}"))],
    )
    .await
    .refused();
    assert_eq!(expired.status, 401, "{expired:?}");
    assert_eq!(echo.connections(), 0);

    let token = key.sign(
        "EdDSA",
        &json!({}),
        &json!({ "sub": "ann", "exp": now() + 600 }),
    );
    let mut tunnel = upgrade(
        &podgate,
        "/",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await
    .tunnel();
    tunnel.send(ws::TEXT, b"signed").await;
    assert_eq!(tunnel.recv().await, text("signed"));
}

#[tokio::test]
async fn ws_rate_limit_counts_upgrade() {
    let echo = Echo::start().await;
    let limit = json!({ "average": 1, "period_secs": 3600, "burst": 1, "source": { "ip": {} } });
    let podgate = serve_app(chained(&[("limit", "rate_limit", limit)])(ws_app(
        echo.addr,
    )))
    .await;

    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"one").await;
    assert_eq!(tunnel.recv().await, text("one"));
    let second = upgrade(&podgate, "/", &[]).await.refused();
    assert_eq!(second.status, 429, "the upgrade used the burst: {second:?}");
    assert!(second.header("retry-after").is_some());
    assert_eq!(
        podgate.get("a.test", "/").await.status,
        429,
        "and so did the plain request"
    );
    assert_eq!(echo.upgrade_heads().len(), 1);
}

#[tokio::test]
async fn ws_in_flight_held_for_life() {
    let echo = Echo::start().await;
    let limit = json!({ "amount": 1, "source": { "header": "x-api-key" } });
    let podgate = serve_app(chained(&[("limit", "in_flight_req", limit)])(ws_app(
        echo.addr,
    )))
    .await;

    let mut tunnel = upgrade(&podgate, "/", &[("X-Api-Key", "ws")])
        .await
        .tunnel();
    tunnel.send(ws::PING, b"x").await;
    assert_eq!(tunnel.recv().await.opcode, ws::PONG);
    sleep(Duration::from_millis(1500)).await;
    let during = upgrade(&podgate, "/", &[("X-Api-Key", "ws")])
        .await
        .refused();
    assert_eq!(
        during.status, 429,
        "the open tunnel holds the slot: {during:?}"
    );
    let other = upgrade(&podgate, "/", &[("X-Api-Key", "other")])
        .await
        .tunnel();
    drop(other);

    drop(tunnel);
    eventually("the slot to come back", async || {
        matches!(
            upgrade(&podgate, "/", &[("X-Api-Key", "ws")]).await,
            Opened::Tunnel(_)
        )
    })
    .await;
}

#[tokio::test]
async fn ws_headers_on_101() {
    let echo = Echo::start().await;
    let headers = json!({ "response": { "set": { "x-from-podgate": "yes" } } });
    let podgate = serve_app(chained(&[("h", "headers", headers)])(ws_app(echo.addr))).await;

    let mut tunnel = tunnel(&podgate).await;
    assert_eq!(
        tunnel.head.header("x-from-podgate"),
        Some("yes"),
        "{:?}",
        tunnel.head
    );
    assert_eq!(tunnel.head.header("x-upstream"), Some("echo"));
    assert!(tunnel.head.header("sec-websocket-accept").is_some());
    tunnel.send(ws::TEXT, b"ok").await;
    assert_eq!(tunnel.recv().await, text("ok"));
}

#[tokio::test]
async fn ws_path_rewrite() {
    let echo = Echo::start().await;
    let strip = json!({ "prefixes": ["/api"] });
    let podgate = serve_app(chained(&[("strip", "strip_prefix", strip)])(ws_app(
        echo.addr,
    )))
    .await;

    let mut tunnel = upgrade(&podgate, "/api/chat?room=1", &[]).await.tunnel();
    tunnel.send(ws::TEXT, b"x").await;
    assert_eq!(tunnel.recv().await, text("x"));
    let heads = echo.upgrade_heads();
    assert!(
        heads[0].starts_with("get /chat?room=1 http/1.1"),
        "{}",
        heads[0]
    );
}

#[tokio::test]
async fn ws_not_buffered_or_compressed() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    let a = with_buffering(
        ws_app(echo.addr),
        json!({ "max_request_body_bytes": 1, "buffer_request": true,
                "max_response_body_bytes": 1, "buffer_response": true }),
    );
    let a = with_middleware(
        a,
        "z",
        "compress",
        json!({ "algorithms": ["gzip"], "min_bytes": 1 }),
    );
    push(&podgate, &snapshot(1, &[a])).await;

    let mut tunnel = upgrade(&podgate, "/", &[("Accept-Encoding", "gzip")])
        .await
        .tunnel();
    assert!(
        tunnel.head.header("content-encoding").is_none(),
        "{:?}",
        tunnel.head
    );
    let payload = vec![b'a'; 64 * 1024];
    let echoed = tunnel.round_trip(ws::BINARY, &payload).await;
    assert!(
        echoed.payload == payload,
        "frames over every cap went through as they were"
    );
    tunnel.send(ws::TEXT, &payload).await;
    let back = tunnel.recv().await;
    assert!(
        back.opcode == ws::TEXT && back.payload == payload,
        "and a compressible text frame was not encoded"
    );
}

#[tokio::test]
async fn ws_retry_not_after_101() {
    let echo = Echo::start().await;
    let dead = refused();
    let retry = json!({ "attempts": 3, "initial_interval_ms": 1 });
    let mut a = chained(&[("retry", "retry", retry)])(ws_app(echo.addr));
    a["revisions"][0]["services"] = json!([service("web", &[echo.addr])]);
    let podgate = serve_app(a).await;

    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"drop").await;
    assert!(tunnel.closes_within(Duration::from_secs(5)).await.is_some());
    sleep(Duration::from_millis(500)).await;
    assert_eq!(
        echo.upgrade_heads().len(),
        1,
        "a tunnel that broke after the 101 is not opened again"
    );
    assert_eq!(echo.connections(), 1);

    // Before the 101 a failed connect is retried: the upgrade moves on to the live server.
    let mut b = chained(&[(
        "retry",
        "retry",
        json!({ "attempts": 3, "initial_interval_ms": 1 }),
    )])(ws_app(echo.addr));
    b["revisions"][0]["services"] = json!([service("web", &[dead.addr, echo.addr])]);
    push(&podgate, &snapshot(2, &[b])).await;
    for round in 0..6 {
        let mut tunnel = upgrade(&podgate, "/", &[]).await.tunnel();
        tunnel.send(ws::TEXT, b"hop").await;
        assert_eq!(tunnel.recv().await, text("hop"), "round {round}");
    }
}

#[tokio::test]
async fn ws_upgrade_bypasses_cache() {
    let echo = Echo::start().await;
    let podgate = serve_app(chained(&[(
        "c",
        "cache",
        json!({ "default_ttl_secs": 60 }),
    )])(ws_app(echo.addr)))
    .await;

    assert_eq!(podgate.get("a.test", "/x").await.body, "plain");
    assert_eq!(podgate.get("a.test", "/x").await.body, "plain");
    assert_eq!(
        echo.heads().len(),
        1,
        "the second plain request was a cache hit"
    );

    let mut tunnel = upgrade(&podgate, "/x", &[]).await.tunnel();
    tunnel.send(ws::TEXT, b"live").await;
    assert_eq!(tunnel.recv().await, text("live"));
    assert_eq!(
        echo.upgrade_heads().len(),
        1,
        "the upgrade reached the upstream"
    );
}

#[tokio::test]
async fn ws_upgrade_not_mirrored() {
    let main = Echo::start().await;
    let shadow = Echo::start().await;
    let mirrored = |config: Value| {
        let mut declared = json!({ "name": "m", "type": "mirroring", "service": "web",
                                   "mirrors": [{ "service": "shadow", "percent": 100.0 }] });
        declared
            .as_object_mut()
            .expect("object")
            .extend(config.as_object().expect("fields").clone());
        let services = vec![
            service("web", &[main.addr]),
            service("shadow", &[shadow.addr]),
            declared,
        ];
        let revision =
            json!({ "id": "r1", "state": "serving", "weight": 100, "services": services });
        let mut a = app("a", &["a.test"], &[revision]);
        a["routers"] = json!([router("default", json!({ "host": ["a.test"] }), "m")]);
        a
    };
    let podgate = Podgate::start().await;

    // With the body mirrored an upgrade is dropped whole.
    push(
        &podgate,
        &snapshot(
            1,
            &[mirrored(
                json!({ "mirror_body": true, "max_body_size": 4096 }),
            )],
        ),
    )
    .await;
    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"one").await;
    assert_eq!(tunnel.recv().await, text("one"));
    sleep(Duration::from_millis(500)).await;
    assert_eq!(shadow.connections(), 0, "no copy of the upgrade was sent");
    drop(tunnel);

    // Without it the copy is a plain request: no `Upgrade`, so the shadow cannot upgrade it.
    push(&podgate, &snapshot(2, &[mirrored(json!({}))])).await;
    let mut tunnel = self::tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"two").await;
    assert_eq!(tunnel.recv().await, text("two"));
    eventually("the bodiless copy", async || shadow.heads().len() == 1).await;
    let copy = &shadow.heads()[0];
    assert!(
        !copy.contains("upgrade:") && copy.contains("connection: close"),
        "{copy}"
    );
    assert!(copy.contains("x-podgate-mirrored: 1"), "{copy}");
    assert_eq!(shadow.open_tunnels(), 0);
}

#[tokio::test]
async fn ws_counts_against_tenant_inflight() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    let mut pushed = snapshot(1, &[ws_app(echo.addr)]);
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(1);
    push(&podgate, &pushed).await;

    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::PING, b"x").await;
    assert_eq!(tunnel.recv().await.opcode, ws::PONG);
    sleep(Duration::from_millis(1200)).await;
    let refused = podgate.get("a.test", "/").await;
    assert_eq!(
        refused.status, 503,
        "the open tunnel is the tenant's one in-flight request: {refused:?}"
    );
    assert_eq!(refused.header("retry-after"), Some("1"));
    let second = upgrade(&podgate, "/", &[]).await.refused();
    assert_eq!(second.status, 503, "{second:?}");

    drop(tunnel);
    eventually("the tunnel's slot to come back", async || {
        podgate.get("a.test", "/").await.status == 200
    })
    .await;
}

#[tokio::test]
async fn ws_delays_revision_drained() {
    let old = Echo::start().await;
    let new = Echo::start().await;
    let podgate = Podgate::start().await;
    push(&podgate, &snapshot(1, &[ws_app(old.addr)])).await;
    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"before").await;
    assert_eq!(tunnel.recv().await, text("before"));

    let draining = app(
        "a",
        &["a.test"],
        &[
            revision("r1", old.addr, 100, "draining"),
            serving("r2", new.addr),
        ],
    );
    push(&podgate, &snapshot(2, &[draining])).await;
    let mut fresh = self::tunnel(&podgate).await;
    fresh.send(ws::TEXT, b"new").await;
    assert_eq!(fresh.recv().await, text("new"));
    assert_eq!(
        new.upgrade_heads().len(),
        1,
        "a new tunnel leaves the draining revision"
    );
    assert_eq!(old.upgrade_heads().len(), 1);

    let early = podgate
        .admin_get("/v1/events?after=0&timeout_secs=1")
        .await
        .json();
    assert_eq!(
        early["events"],
        json!([]),
        "r1 is not drained while its tunnel is open: {early}"
    );
    tunnel.send(ws::TEXT, b"during").await;
    assert_eq!(
        tunnel.recv().await,
        text("during"),
        "the draining revision keeps serving its tunnel"
    );

    tunnel.send(ws::CLOSE, &[0x03, 0xe8]).await;
    assert_eq!(tunnel.recv().await.opcode, ws::CLOSE);
    drop(tunnel);
    let drained = podgate
        .admin_get("/v1/events?after=0&timeout_secs=5")
        .await
        .json();
    let events: Vec<&Value> = drained["events"]
        .as_array()
        .expect("events")
        .iter()
        .collect();
    assert_eq!(events.len(), 1, "{drained}");
    assert_eq!(
        (
            events[0]["kind"].as_str(),
            events[0]["app"].as_str(),
            events[0]["revision"].as_str()
        ),
        (Some("revision_drained"), Some("a"), Some("r1"))
    );
    drop(fresh);
}

#[tokio::test]
async fn ws_survives_snapshot_swap() {
    let old = Echo::start().await;
    let new = Echo::start().await;
    let podgate = Podgate::start().await;
    push(&podgate, &snapshot(1, &[ws_app(old.addr)])).await;
    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"v1").await;
    assert_eq!(tunnel.recv().await, text("v1"));

    let swapped = app(
        "a",
        &["a.test"],
        &[
            revision("r1", old.addr, 100, "draining"),
            serving("r2", new.addr),
        ],
    );
    push(&podgate, &snapshot(2, &[swapped])).await;
    tunnel.send(ws::TEXT, b"v2").await;
    assert_eq!(tunnel.recv().await, text("v2"));

    // The revision the tunnel runs on is gone from the table altogether.
    push(
        &podgate,
        &snapshot(3, &[app("a", &["a.test"], &[serving("r2", new.addr)])]),
    )
    .await;
    tunnel.send(ws::TEXT, b"v3").await;
    assert_eq!(tunnel.recv().await, text("v3"));
    assert_eq!(old.open_tunnels(), 1);

    // Even the app is gone: the tunnel is not the table's to end.
    push(
        &podgate,
        &snapshot(4, &[app("b", &["b.test"], &[serving("r1", new.addr)])]),
    )
    .await;
    tunnel.send(ws::PING, b"v4").await;
    assert_eq!(tunnel.recv().await.opcode, ws::PONG);
    assert_eq!(podgate.get("a.test", "/").await.status, 404);
}

#[tokio::test]
async fn ws_graceful_shutdown_grace() {
    let echo = Echo::start().await;
    let mut podgate = Podgate::start_with_env(&[("REQUEST_TIMEOUT_SECS", "4")]).await;
    push(&podgate, &snapshot(1, &[ws_app(echo.addr)])).await;
    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"before").await;
    assert_eq!(tunnel.recv().await, text("before"));

    let signalled = Instant::now();
    podgate.sigterm();
    eventually("readiness to turn 503", async || {
        podgate.admin_get("/readyz").await.status == 503
    })
    .await;
    tunnel.send(ws::TEXT, b"during grace").await;
    assert_eq!(
        tunnel.recv().await,
        text("during grace"),
        "the tunnel works during the grace period"
    );

    let (status, _) = podgate
        .wait_exit(Duration::from_secs(10))
        .await
        .expect("the process exits once the grace period is over");
    let waited = signalled.elapsed();
    assert!(
        waited >= Duration::from_secs(1) && waited < Duration::from_secs(7),
        "exited {waited:?} after SIGTERM, status {status}"
    );
    assert!(
        tunnel.closes_within(Duration::from_secs(3)).await.is_some(),
        "the exit ended the tunnel"
    );
}

/// A TLS client config that offers only `h2` and trusts `cert`.
fn h2_config(cert: &TestCert) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der.clone()).expect("trust the certificate");
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// RFC 8441 needs the server to send `SETTINGS_ENABLE_CONNECT_PROTOCOL`. Pingora 0.9.1 builds its
/// HTTP/2 server from `default_h2_options` (`pingora-core/src/protocols/http/v2/server.rs:69-74`),
/// which never calls `h2::server::Builder::enable_connect_protocol`, so the setting is not sent,
/// and `h2` 0.4.20 answers a `:protocol` request on a connection without it with a stream
/// `PROTOCOL_ERROR` (`h2/src/proto/streams/recv.rs:244-250`). WebSockets over HTTP/2 are
/// therefore refused, and a client falls back to HTTP/1.1 (see `ws_echo_tls`). If a Pingora
/// update turns the setting on, this test fails at the first assertion: replace it with a tunnel
/// test over HTTP/2.
#[tokio::test]
async fn ws_over_h2_supported_or_refused() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    let cert = TestCert::new(&["a.test"]);
    let mut pushed = snapshot(1, &[ws_app(echo.addr)]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    push(&podgate, &pushed).await;

    let name = rustls::pki_types::ServerName::try_from("a.test".to_owned()).expect("name");
    let tcp = TcpStream::connect(podgate.tls_addr).await.expect("connect");
    let tls = tokio_rustls::TlsConnector::from(h2_config(&cert))
        .connect(name, tcp)
        .await
        .expect("handshake");
    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(connection);

    // A plain request first: the server's settings are in by the time it is answered.
    let get = http::Request::get("https://a.test/")
        .body(())
        .expect("request");
    let (response, _) = client.send_request(get, true).expect("send");
    assert_eq!(response.await.expect("response").status().as_u16(), 200);
    assert!(
        !client.is_extended_connect_protocol_enabled(),
        "podgate does not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL"
    );

    // A client that ignores the missing setting gets its stream reset, not a hang or a tunnel.
    let mut connect = http::Request::builder()
        .method("CONNECT")
        .uri("https://a.test/chat")
        .header("sec-websocket-version", "13")
        .body(())
        .expect("request");
    connect
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("websocket"));
    let (response, _stream) = client.send_request(connect, false).expect("send");
    let refused = timeout(Duration::from_secs(5), response)
        .await
        .expect("an answer in time")
        .expect_err("extended CONNECT is refused");
    assert_eq!(
        refused.reason(),
        Some(h2::Reason::PROTOCOL_ERROR),
        "{refused}"
    );

    // The connection and the proxy are fine, and nothing reached the upstream.
    let get = http::Request::get("https://a.test/")
        .body(())
        .expect("request");
    let (response, _) = client
        .send_request(get, true)
        .expect("send after the reset");
    assert_eq!(response.await.expect("response").status().as_u16(), 200);
    assert!(echo.upgrade_heads().is_empty());
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
}

#[tokio::test]
async fn ws_entry_read_timeout_closes_idle_tunnel() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    let mut pushed = snapshot(1, &[ws_app(echo.addr)]);
    // `write_secs` bounds a stalled write, not a quiet tunnel; `read_secs` is the wait for the
    // client's next bytes.
    pushed["entry_points"] =
        json!([{ "name": "web", "timeouts": { "read_secs": 2, "write_secs": 1 } }]);
    push(&podgate, &pushed).await;

    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"hi").await;
    assert_eq!(tunnel.recv().await, text("hi"));
    let lived = tunnel
        .closes_within(Duration::from_secs(4))
        .await
        .expect("a tunnel the client leaves quiet is closed at read_secs");
    assert!(
        (Duration::from_millis(1800)..Duration::from_millis(3500)).contains(&lived),
        "{lived:?}"
    );
}

/// A podgate whose only app reaches `echo` through a transport with tunnel idle timeout `secs`,
/// and whose entry point `web` has the policy `entry` when given.
async fn with_tunnel_idle(echo: &Echo, secs: u64, entry: Option<Value>) -> Podgate {
    let podgate = Podgate::start().await;
    let mut a = ws_app(echo.addr);
    a["transports"] =
        json!([{ "name": "t", "type": "servers_transport", "tunnel_idle_timeout_secs": secs }]);
    a["revisions"][0]["services"][0]["transport"] = json!("t");
    let mut pushed = snapshot(1, &[a]);
    if let Some(policy) = entry {
        pushed["entry_points"] = json!([policy]);
    }
    push(&podgate, &pushed).await;
    podgate
}

#[tokio::test]
async fn ws_one_way_client_traffic_keeps_tunnel_alive() {
    let echo = Echo::start().await;
    let podgate = with_tunnel_idle(&echo, 2, None).await;

    // Unsolicited pongs are a one-way heartbeat: the upstream never answers them. The idle
    // timers restart on any traffic, so the quiet upstream side does not end the tunnel.
    let mut tunnel = tunnel(&podgate).await;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        tunnel.send(ws::PONG, b"").await;
        assert!(
            tunnel
                .closes_within(Duration::from_millis(400))
                .await
                .is_none(),
            "closed after {:?} of one-way traffic",
            started.elapsed()
        );
    }
    tunnel.send(ws::TEXT, b"alive").await;
    assert_eq!(tunnel.recv().await, text("alive"));
    let quiet = tunnel
        .closes_within(Duration::from_secs(6))
        .await
        .expect("then it goes quiet and is closed");
    assert!(
        (Duration::from_millis(1800)..Duration::from_secs(4)).contains(&quiet),
        "{quiet:?}"
    );
}

#[tokio::test]
async fn ws_server_push_keeps_tunnel_alive() {
    let echo = Echo::start().await;
    let entry = json!({ "name": "web", "timeouts": { "read_secs": 2 } });
    let podgate = with_tunnel_idle(&echo, 2, Some(entry)).await;

    // The client says nothing after the first frame while the upstream pushes for 6 s.
    let mut tunnel = tunnel(&podgate).await;
    tunnel.send(ws::TEXT, b"tick").await;
    let started = Instant::now();
    let mut ticks = 0;
    while started.elapsed() < Duration::from_secs(5) {
        assert_eq!(tunnel.recv().await, text("tick"), "after {ticks} ticks");
        ticks += 1;
    }
    assert!(ticks >= 10, "{ticks} ticks");
}
