//! gRPC through podgate end to end: unary and the three streaming kinds over `h2c://`
//! and TLS `h2` upstreams, trailers, deadlines and cancellation, what podgate answers when it
//! fails a call itself, and how the middlewares treat a stream.
//!
//! The upstream and the client are the frame-level peers of `common::grpc` (the `h2` crate, no
//! `tonic`). The client reaches podgate over TLS with ALPN `h2`, the way a gRPC client library
//! does, unless a test is about the cleartext entry point.

mod common;

use std::time::{Duration, Instant};

use common::grpc::{Ca, Client, MESSAGE, Server, code_for_http, path, stream_request};
use common::{Podgate, TestCert, app, refused, snapshot};
use serde_json::{Value, json};
use tokio::time::timeout;

/// The host every test app answers for; the certificate and the SNI carry it.
const HOST: &str = "g.test";

/// How the upstream is reached.
#[derive(Clone, Copy, Debug)]
enum Kind {
    H2c,
    Tls,
}

const KINDS: [Kind; 2] = [Kind::H2c, Kind::Tls];

/// A service `web` over `servers`; `transport` is declared as `t` and named by the service.
fn app_over(servers: &[String], transport: Option<Value>) -> Value {
    let servers: Vec<Value> = servers.iter().map(|url| json!({ "url": url })).collect();
    let mut service = json!({ "name": "web", "type": "loadbalancer", "servers": servers });
    if transport.is_some() {
        service["transport"] = json!("t");
    }
    let mut declared = app(
        "g",
        &[HOST],
        &[json!({ "id": "r1", "state": "serving", "weight": 100, "services": [service] })],
    );
    if let Some(Value::Object(mut fields)) = transport {
        fields.insert("name".into(), json!("t"));
        fields.insert("type".into(), json!("servers_transport"));
        declared["transports"] = json!([fields]);
    }
    declared
}

/// A snapshot of `version` with `app` and a certificate for [`HOST`].
fn pushed(version: u64, app: Value, cert: &TestCert) -> Value {
    let mut pushed = snapshot(version, &[app]);
    pushed["certificates"] = json!([cert.entry(&[HOST])]);
    pushed
}

/// A running podgate with one app, `g.test`, and the certificate its clients trust.
struct Rig {
    podgate: Podgate,
    cert: TestCert,
}

impl Rig {
    async fn start(app: Value) -> Self {
        Self::start_env(app, &[]).await
    }

    async fn start_env(app: Value, env: &[(&str, &str)]) -> Self {
        let podgate = Podgate::start_with_env(env).await;
        let cert = TestCert::new(&[HOST]);
        let reply = podgate.push_snapshot(&pushed(1, app, &cert)).await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        Self { podgate, cert }
    }

    /// A client over TLS with ALPN `h2`.
    async fn client(&self) -> Client {
        let client = Client::tls(self.podgate.tls_addr, HOST, &self.cert.der).await;
        assert_eq!(client.alpn(), Some(b"h2".as_slice()), "ALPN selected h2");
        client
    }
}

/// An upstream of `kind` and the transport that reaches it.
async fn backend(kind: Kind) -> (Server, Option<Value>) {
    match kind {
        Kind::H2c => (Server::h2c().await, None),
        Kind::Tls => {
            let ca = Ca::new();
            let server = Server::tls(&ca).await;
            (server, Some(json!({ "ca_pem": ca.pem })))
        }
    }
}

/// A rig over one upstream of `kind`; `tweak` edits the app before it is pushed.
async fn rig_over(kind: Kind, tweak: impl FnOnce(Value) -> Value) -> (Rig, Server) {
    let (server, transport) = backend(kind).await;
    let rig = Rig::start(tweak(app_over(&[server.url()], transport))).await;
    (rig, server)
}

fn payload_of(len: usize, fill: u8) -> Vec<u8> {
    vec![fill; len]
}

/// `grpc-timeout`, `te` and the other request headers a gRPC server needs reach the upstream.
fn assert_grpc_request(server: &Server, path: &str) {
    let seen = server
        .calls()
        .into_iter()
        .find(|seen| seen.path == path)
        .unwrap_or_else(|| panic!("the upstream saw no call to {path}"));
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.header("content-type"), Some("application/grpc"));
    assert_eq!(seen.header("te"), Some("trailers"));
}

// ---------------------------------------------------------------------------------------
// Unary and streaming, over both upstream kinds
// ---------------------------------------------------------------------------------------

async fn unary_over(kind: Kind) {
    let (rig, server) = rig_over(kind, |app| app).await;
    let client = rig.client().await;
    let outcome = client.unary(path::UNARY, b"hello", &[]).await;
    assert_eq!(outcome.status, 200, "{kind:?}: {outcome:?}");
    assert_eq!(outcome.header("content-type"), Some("application/grpc"));
    assert_eq!(outcome.payloads(), [b"echo:hello".as_slice()], "{kind:?}");
    assert_eq!(outcome.grpc_status(), Some(0), "{kind:?}");
    assert_grpc_request(&server, path::UNARY);
}

#[tokio::test]
async fn grpc_unary_h2c() {
    Box::pin(unary_over(Kind::H2c)).await;
}

#[tokio::test]
async fn grpc_unary_tls_h2() {
    Box::pin(unary_over(Kind::Tls)).await;
}

#[tokio::test]
async fn grpc_client_streaming() {
    for kind in KINDS {
        let (rig, server) = rig_over(kind, |app| app).await;
        let client = rig.client().await;
        let mut call = client.start(path::CLIENT_STREAM, &[]).await;
        let sizes = [1_usize, 100, MESSAGE, 3 * MESSAGE + 7, 0];
        for (index, size) in sizes.into_iter().enumerate() {
            call.send(&payload_of(size, u8::try_from(index).unwrap_or(0)))
                .await;
        }
        call.finish();
        let outcome = call.collect().await;
        let total: usize = sizes.iter().sum();
        assert_eq!(
            outcome.payloads(),
            [format!("{} {total}", sizes.len()).as_bytes()],
            "{kind:?}"
        );
        assert_eq!(outcome.grpc_status(), Some(0), "{kind:?}");
        assert_grpc_request(&server, path::CLIENT_STREAM);
    }
}

#[tokio::test]
async fn grpc_server_streaming() {
    for kind in KINDS {
        let (rig, server) = rig_over(kind, |app| app).await;
        let client = rig.client().await;
        let mut call = client.start(path::SERVER_STREAM, &[]).await;
        call.send(&stream_request(300, 1000)).await;
        call.finish();
        let outcome = call.collect().await;
        assert_eq!(outcome.messages.len(), 300, "{kind:?}");
        for (index, (flag, payload)) in outcome.messages.iter().enumerate() {
            assert_eq!(*flag, 0);
            assert_eq!(payload.len(), 1000);
            assert_eq!(payload[0], u8::try_from(index % 251).unwrap_or(0));
        }
        assert_eq!(outcome.grpc_status(), Some(0), "{kind:?}");

        // Each message is delivered as the upstream sends it, not when the stream ends: the
        // second one does not arrive before the upstream lets it.
        let mut paced = client.start(path::PACED, &[]).await;
        paced.send(b"go").await;
        paced.finish();
        assert_eq!(paced.message().await.expect("first").1, b"msg1");
        assert!(
            timeout(Duration::from_millis(300), paced.message())
                .await
                .is_err(),
            "{kind:?}: the second message came before the upstream sent it"
        );
        for expected in [b"msg2", b"msg3"] {
            server.release(1);
            assert_eq!(paced.message().await.expect("next").1, expected);
        }
        assert!(paced.message().await.is_none());
        let outcome = paced.collect().await;
        assert_eq!(outcome.grpc_status(), Some(0), "{kind:?}");
    }
}

#[tokio::test]
async fn grpc_bidi_streaming() {
    for kind in KINDS {
        let (rig, server) = rig_over(kind, |app| app).await;
        let client = rig.client().await;
        let mut call = client.start(path::BIDI, &[]).await;
        // Each message comes back before the next one is sent: the request is not held until it
        // ends, and the response is not held until the request does.
        for round in 0..20_u8 {
            let size = if round % 5 == 0 { 3 * MESSAGE } else { 17 };
            let sent = payload_of(size, round);
            call.send(&sent).await;
            let (flag, echoed) = call.message().await.expect("the echo");
            assert_eq!((flag, echoed), (0, sent), "{kind:?} round {round}");
        }
        call.finish();
        let outcome = call.collect().await;
        assert!(outcome.messages.is_empty(), "nothing is left to read");
        assert_eq!(outcome.grpc_status(), Some(0), "{kind:?}");
        assert_grpc_request(&server, path::BIDI);
    }
}

#[tokio::test]
async fn grpc_large_messages() {
    const BIG: usize = 5 * 1024 * 1024 + 17;
    for kind in KINDS {
        let (rig, _server) = rig_over(kind, |app| app).await;
        let client = rig.client().await;

        let sent = payload_of(BIG, 0x5a);
        let outcome = client.unary(path::UNARY, &sent, &[]).await;
        assert_eq!(outcome.messages.len(), 1, "{kind:?}");
        let echoed = &outcome.messages[0].1;
        assert_eq!(echoed.len(), 5 + BIG, "{kind:?}");
        assert!(echoed.starts_with(b"echo:") && echoed[5..].iter().all(|byte| *byte == 0x5a));
        assert_eq!(outcome.grpc_status(), Some(0));

        let mut call = client.start(path::SERVER_STREAM, &[]).await;
        let big = u32::try_from(BIG).expect("fits");
        call.send(&stream_request(2, big)).await;
        call.finish();
        let outcome = call.collect().await;
        let lengths: Vec<usize> = outcome.messages.iter().map(|(_, m)| m.len()).collect();
        assert_eq!(lengths, [BIG, BIG], "{kind:?}");
        assert_eq!(outcome.grpc_status(), Some(0));

        let mut call = client.start(path::CLIENT_STREAM, &[]).await;
        call.send(&payload_of(BIG, 1)).await;
        call.send(&payload_of(MESSAGE, 2)).await;
        call.finish();
        let outcome = call.collect().await;
        assert_eq!(
            outcome.payloads(),
            [format!("2 {}", BIG + MESSAGE).as_bytes()],
            "{kind:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// Trailers
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_trailers_reach_client() {
    for kind in KINDS {
        let (rig, _server) = rig_over(kind, |app| app).await;
        let client = rig.client().await;

        let outcome = client.unary(path::UNARY, b"x", &[]).await;
        assert_eq!(outcome.header("x-custom-header"), Some("kept"), "{kind:?}");
        let trailers = outcome.trailers.as_ref().expect("trailers");
        assert_eq!(trailers.get("grpc-status").expect("status"), "0");
        assert_eq!(trailers.get("grpc-message").expect("message"), "fine");
        assert_eq!(trailers.get("x-custom-trailer").expect("custom"), "kept");

        // A failure after data: the code and message are in the trailers and the data arrived.
        let outcome = client.unary(path::FAIL_AFTER_DATA, b"x", &[]).await;
        assert_eq!(outcome.payloads(), [b"partial".as_slice()], "{kind:?}");
        let trailers = outcome.trailers.as_ref().expect("trailers");
        assert_eq!(trailers.get("grpc-status").expect("status"), "3");
        assert_eq!(trailers.get("grpc-message").expect("message"), "bad thing");
        assert_eq!(trailers.get("x-meta").expect("meta"), "kept");
    }
}

#[tokio::test]
async fn grpc_trailers_only_error() {
    for kind in KINDS {
        let (rig, _server) = rig_over(kind, |app| app).await;
        let client = rig.client().await;
        let outcome = client.unary(path::FAIL, b"x", &[]).await;
        assert_eq!(outcome.status, 200, "{kind:?}");
        assert!(outcome.messages.is_empty(), "no body");
        assert!(outcome.trailers.is_none(), "the status is in the head");
        assert_eq!(outcome.grpc_status(), Some(5), "{kind:?}");
        assert_eq!(outcome.header("grpc-message"), Some("no such thing"));
        assert_eq!(outcome.header("x-meta"), Some("kept"));
        assert_eq!(outcome.header("content-type"), Some("application/grpc"));

        // A method the upstream does not know: its own UNIMPLEMENTED is passed through.
        let outcome = client.unary("/test.Echo/Missing", b"x", &[]).await;
        assert_eq!(outcome.grpc_status(), Some(12), "{kind:?}");
    }
}

// ---------------------------------------------------------------------------------------
// Deadlines and cancellation
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_timeout_propagated() {
    let (rig, server) = rig_over(Kind::H2c, |app| app).await;
    let client = rig.client().await;
    let headers = [
        ("grpc-timeout", "1500m"),
        ("grpc-encoding", "identity"),
        ("grpc-accept-encoding", "identity,gzip"),
        ("x-user-header", "v"),
    ];
    let outcome = client.unary(path::UNARY, b"x", &headers).await;
    assert_eq!(outcome.grpc_status(), Some(0));
    let seen = &server.calls()[0];
    assert_eq!(seen.header("grpc-timeout"), Some("1500m"));
    assert_eq!(seen.header("grpc-encoding"), Some("identity"));
    assert_eq!(seen.header("grpc-accept-encoding"), Some("identity,gzip"));
    assert_eq!(seen.header("x-user-header"), Some("v"));

    // podgate does not enforce the deadline itself (as Traefik and Caddy do not): the client
    // does, by resetting the stream, and the reset reaches the upstream.
    let mut call = client.start(path::HANG, &[("grpc-timeout", "300m")]).await;
    call.send(b"x").await;
    server.wait_calls(path::HANG, 1).await;
    assert!(
        timeout(Duration::from_millis(300), call.try_head())
            .await
            .is_err(),
        "no answer inside the deadline"
    );
    assert!(
        !server.ends().iter().any(|end| end.starts_with("reset")),
        "podgate did not cancel the call on its own: {:?}",
        server.ends()
    );
    let since = Instant::now();
    call.reset();
    server
        .wait_end("reset:", since, Duration::from_secs(1))
        .await;
}

#[tokio::test]
async fn grpc_client_reset_cancels_upstream() {
    for kind in KINDS {
        for method in [path::HANG, path::HANG_AFTER_HEAD] {
            let (rig, server) = rig_over(kind, |app| app).await;
            let client = rig.client().await;
            let mut call = client.start(method, &[("grpc-timeout", "30S")]).await;
            call.send(b"request").await;
            server.wait_calls(method, 1).await;
            if method == path::HANG_AFTER_HEAD {
                assert_eq!(call.message().await.expect("first").1, b"first");
            }
            let since = Instant::now();
            call.reset();
            let after = server
                .wait_end("reset:", since, Duration::from_secs(1))
                .await;
            assert!(
                after < Duration::from_secs(1),
                "{kind:?} {method}: the reset reached the upstream after {after:?}"
            );
        }
    }
}

#[tokio::test]
async fn grpc_upstream_read_timeout_gateway_timeout() {
    let server = Server::h2c().await;
    let app = app_over(&[server.url()], Some(json!({ "read_timeout_secs": 1 })));
    let rig = Rig::start(app).await;
    let client = rig.client().await;
    let started = Instant::now();
    let raw = client.unary_raw(path::HANG, b"x", &[]).await;
    assert_eq!(raw.status, 504, "{raw:?}");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(code_for_http(raw.status), 14, "UNAVAILABLE");
    assert_eq!(raw.header("grpc-status"), None);
    assert!(
        raw.body.is_empty(),
        "Pingora's own error answer has no body: {raw:?}"
    );
    server
        .wait_end("reset:", started, Duration::from_secs(3))
        .await;

    // The connection is still good for the next call.
    let outcome = client.unary(path::UNARY, b"again", &[]).await;
    assert_eq!(outcome.grpc_status(), Some(0));
}

// ---------------------------------------------------------------------------------------
// Downstream HTTP/2
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_downstream_h2_over_tls() {
    let (rig, server) = rig_over(Kind::H2c, |app| app).await;
    let client = rig.client().await;
    // Several calls share the one connection and finish in any order.
    let mut paced = Vec::new();
    for _ in 0..3 {
        let mut call = client.start(path::PACED, &[]).await;
        call.send(b"go").await;
        call.finish();
        assert_eq!(call.message().await.expect("first").1, b"msg1");
        paced.push(call);
    }
    server.release(6);
    for mut call in paced.into_iter().rev() {
        let outcome = call.collect().await;
        assert_eq!(outcome.payloads(), [b"msg2".as_slice(), b"msg3"]);
        assert_eq!(outcome.grpc_status(), Some(0));
    }
    assert_eq!(
        server.connections(),
        1,
        "one upstream connection carried all three"
    );
}

// ---------------------------------------------------------------------------------------
// podgate's own answers
// ---------------------------------------------------------------------------------------

/// What every answer podgate gives a gRPC call itself looks like: a plain HTTP response that
/// ends cleanly, with no `grpc-status`, whose HTTP status a gRPC client maps to `code`. A
/// refusal of podgate's own (`json`) says why in `{"error": ...}`; a failure on the way to the
/// upstream is Pingora's empty answer.
fn assert_http_answer(raw: &common::grpc::Raw, status: u16, code: u32, json: bool) {
    assert_eq!(raw.status, status, "{raw:?}");
    assert_eq!(code_for_http(raw.status), code, "{raw:?}");
    assert_eq!(raw.header("grpc-status"), None, "{raw:?}");
    assert!(raw.trailers.is_none(), "{raw:?}");
    if json {
        assert_eq!(
            raw.header("content-type"),
            Some("application/json"),
            "{raw:?}"
        );
        assert!(
            raw.json()["error"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "{raw:?}"
        );
    } else {
        assert!(raw.body.is_empty(), "{raw:?}");
    }
}

#[tokio::test]
async fn grpc_unknown_host_unimplemented() {
    let (rig, server) = rig_over(Kind::H2c, |app| app).await;
    // A certificate that covers any `*.z.test`, so a client can name a host the app does not.
    let wide = TestCert::new(&[HOST, "*.z.test"]);
    let mut pushed = pushed(2, app_over(&[server.url()], None), &wide);
    pushed["certificates"] = json!([wide.entry(&[HOST, "*.z.test"])]);
    assert_eq!(rig.podgate.push_snapshot(&pushed).await.status, 200);
    let client = Client::tls(rig.podgate.tls_addr, "nope.z.test", &wide.der).await;
    let raw = client.unary_raw(path::UNARY, b"x", &[]).await;
    assert_http_answer(&raw, 404, 12, true);
    assert_eq!(server.calls().len(), 0, "nothing reached the upstream");
}

#[tokio::test]
async fn grpc_no_upstream_unavailable() {
    let rig = Rig::start(app_over(&[], None)).await;
    let client = rig.client().await;
    let raw = client.unary_raw(path::UNARY, b"x", &[]).await;
    assert_http_answer(&raw, 503, 14, true);
}

#[tokio::test]
async fn grpc_upstream_refused_unavailable() {
    let dead = refused();
    let rig = Rig::start(app_over(&[format!("h2c://{}", dead.addr)], None)).await;
    let client = rig.client().await;
    let raw = client.unary_raw(path::UNARY, b"x", &[]).await;
    assert_http_answer(&raw, 502, 14, false);
    // The stream failed, not the connection: the next call on it is answered the same way.
    let raw = client.unary_raw(path::UNARY, b"x", &[]).await;
    assert_http_answer(&raw, 502, 14, false);
}

#[tokio::test]
async fn grpc_rate_limited_unavailable() {
    let (rig, _server) = rig_over(Kind::H2c, |app| {
        common::with_middleware(
            app,
            "rl",
            "rate_limit",
            json!({ "average": 1, "period_secs": 3600, "burst": 1, "source": { "ip": {} } }),
        )
    })
    .await;
    let client = rig.client().await;
    let outcome = client.unary(path::UNARY, b"x", &[]).await;
    assert_eq!(
        outcome.grpc_status(),
        Some(0),
        "the first call is inside the burst"
    );
    let raw = client.unary_raw(path::UNARY, b"x", &[]).await;
    assert_http_answer(&raw, 429, 14, true);
    assert!(
        raw.header("retry-after")
            .is_some_and(|secs| secs.parse::<u64>().is_ok_and(|s| s >= 1)),
        "{raw:?}"
    );
}

// ---------------------------------------------------------------------------------------
// Entry point settings
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_entry_point_stream_limit() {
    let (rig, server) = rig_over(Kind::H2c, |app| app).await;
    let mut limited = pushed(2, app_over(&[server.url()], None), &rig.cert);
    limited["entry_points"] =
        json!([{ "name": "websecure", "http2": { "max_concurrent_streams": 2 } }]);
    assert_eq!(rig.podgate.push_snapshot(&limited).await.status, 200);

    let client = rig.client().await;
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut call = client.start(path::HOLD, &[]).await;
        call.send(b"x").await;
        call.finish();
        assert_eq!(call.message().await.expect("first").1, b"first");
        held.push(call);
    }
    // The client queues a third stream until a slot frees: the upstream does not see it.
    let mut third = client.start(path::UNARY, &[]).await;
    assert!(
        timeout(
            Duration::from_millis(400),
            server.wait_calls(path::UNARY, 1)
        )
        .await
        .is_err(),
        "a third stream does not open while two are in flight: the limit is the entry point's"
    );
    server.release(2);
    for mut call in held {
        assert_eq!(call.collect().await.grpc_status(), Some(0));
    }
    // Both slots are free again; the stream that was waiting for one goes through.
    third.send(b"x").await;
    third.finish();
    assert_eq!(third.collect().await.grpc_status(), Some(0));
}

// ---------------------------------------------------------------------------------------
// Middlewares leave a stream alone
// ---------------------------------------------------------------------------------------

/// The chains a stream goes through: none (the platform's own compression applies), and each
/// stage that would encode or hold an ordinary exchange, alone and together.
const CHAINS: [&str; 2] = ["none", "compress"];

fn holding_chain(mut app: Value, chain: &str) -> Value {
    let compress = json!({ "min_bytes": 1 });
    let request = json!({ "max_request_body_bytes": 65536, "buffer_request": true });
    let response = json!({ "max_response_body_bytes": 1_048_576, "buffer_response": true });
    if matches!(chain, "compress" | "all") {
        app = common::with_middleware(app, "z", "compress", compress);
    }
    let buffering = match chain {
        "buffer_request" => Some(request),
        "buffer_response" => Some(response),
        "all" => Some(json!({
            "max_request_body_bytes": 65536,
            "buffer_request": true,
            "max_response_body_bytes": 1_048_576,
            "buffer_response": true,
        })),
        _ => None,
    };
    match buffering {
        Some(config) => common::with_middleware(app, "b", "buffering", config),
        None => app,
    }
}

/// One chain's worth of [`grpc_not_compressed_or_buffered`].
async fn stream_through(chain: &'static str) {
    let (rig, server) = rig_over(Kind::H2c, |app| holding_chain(app, chain)).await;
    let client = rig.client().await;
    let accept = [("accept-encoding", "gzip, br, zstd")];

    // The bodies are compressible, and the client accepts every encoding.
    let mut call = client.start(path::SERVER_STREAM, &accept).await;
    call.send(&stream_request(4, 100_000)).await;
    call.finish();
    let outcome = call.collect().await;
    assert_eq!(outcome.header("content-encoding"), None, "chain: {chain}");
    assert_eq!(outcome.header("content-length"), None, "chain: {chain}");
    let lengths: Vec<usize> = outcome.messages.iter().map(|(_, m)| m.len()).collect();
    assert_eq!(lengths, [100_000; 4], "chain: {chain}");

    // A message the upstream marked compressed goes through untouched, with its header.
    let outcome = client.unary(path::COMPRESSED, b"x", &accept).await;
    assert_eq!(
        outcome.header("grpc-encoding"),
        Some("gzip"),
        "chain: {chain}"
    );
    assert_eq!(outcome.messages, [(1, b"not really gzip".to_vec())]);

    // The response is not held: a message arrives while the upstream still waits.
    let mut paced = client.start(path::PACED, &accept).await;
    paced.send(b"go").await;
    paced.finish();
    assert_eq!(
        paced.message().await.expect("first").1,
        b"msg1",
        "chain: {chain}"
    );
    server.release(2);
    assert_eq!(
        paced.collect().await.grpc_status(),
        Some(0),
        "chain: {chain}"
    );

    // The request is not held: the echo comes back before the request ends.
    let mut bidi = client.start(path::BIDI, &accept).await;
    for round in 0..5_u8 {
        bidi.send(&payload_of(1000, round)).await;
        assert_eq!(
            bidi.message().await.expect("echo").1,
            payload_of(1000, round),
            "chain: {chain}"
        );
    }
    bidi.finish();
    assert_eq!(
        bidi.collect().await.grpc_status(),
        Some(0),
        "chain: {chain}"
    );
}

#[tokio::test]
async fn grpc_not_compressed_or_buffered() {
    let runs: Vec<_> = CHAINS
        .into_iter()
        .map(|chain| (chain, tokio::spawn(stream_through(chain))))
        .collect();
    let mut broken = Vec::new();
    for (chain, run) in runs {
        if run.await.is_err() {
            broken.push(chain);
        }
    }
    assert!(broken.is_empty(), "a stream broke on the chains {broken:?}");
}

#[tokio::test]
async fn grpc_no_retry_after_start() {
    let (first, second) = (Server::h2c().await, Server::h2c().await);
    let app = common::with_middleware(
        app_over(&[first.url(), second.url()], None),
        "r",
        "retry",
        json!({ "attempts": 3, "initial_interval_ms": 0, "methods": ["POST"] }),
    );
    let rig = Rig::start(app).await;
    let client = rig.client().await;
    let calls = || first.calls().len() + second.calls().len();

    // The stream broke after the response started: the client sees the head and the data, then
    // the failure, and no other server was asked.
    let mut call = client.start(path::RESET_AFTER_HEAD, &[]).await;
    call.send(b"x").await;
    call.finish();
    assert_eq!(call.head().await.status, 200);
    assert_eq!(call.message().await.expect("first").1, b"first");
    assert!(
        call.try_collect().await.is_err(),
        "the reset reaches the client"
    );
    assert_eq!(
        calls(),
        1,
        "a call whose response started is never repeated"
    );

    // The upstream refused the stream before it answered. The request body was streamed to it,
    // so it cannot be sent again, and a POST is not replayed whatever `methods` says.
    let before = calls();
    let mut call = client.start(path::RESET_BEFORE_HEAD, &[]).await;
    call.send(b"x").await;
    call.finish();
    let raw = call.raw().await;
    assert_eq!(calls() - before, 1, "{raw:?}");
    assert_eq!(code_for_http(raw.status), 14, "{raw:?}");
}

#[tokio::test]
async fn grpc_retry_connect_error() {
    let dead = refused();
    let live = Server::h2c().await;
    let app = common::with_middleware(
        app_over(&[format!("h2c://{}", dead.addr), live.url()], None),
        "r",
        "retry",
        json!({ "attempts": 3, "initial_interval_ms": 0 }),
    );
    let rig = Rig::start(app).await;
    let client = rig.client().await;
    // Nothing was sent to a server that refused the connection, so any call can go to the next.
    for round in 0..4 {
        let outcome = client.unary(path::UNARY, b"x", &[]).await;
        assert_eq!(outcome.grpc_status(), Some(0), "call {round}: {outcome:?}");
    }
    assert_eq!(live.calls().len(), 4);
}

#[tokio::test]
async fn grpc_in_flight_held_for_stream() {
    let (rig, server) = rig_over(Kind::H2c, |app| {
        common::with_middleware(
            app,
            "cap",
            "in_flight_req",
            json!({ "amount": 1, "source": { "ip": {} } }),
        )
    })
    .await;
    let client = rig.client().await;

    let mut held = client.start(path::HOLD, &[]).await;
    held.send(b"x").await;
    held.finish();
    assert_eq!(held.message().await.expect("first").1, b"first");

    // The first call's response has started, and its slot is still taken.
    let raw = client.unary_raw(path::UNARY, b"x", &[]).await;
    assert_http_answer(&raw, 429, 14, true);
    assert_eq!(raw.header("retry-after"), Some("1"));
    assert_eq!(
        server.calls_to(path::UNARY),
        0,
        "the refused call reached no upstream"
    );

    // It ended, and the slot came back.
    server.release(1);
    assert_eq!(held.collect().await.grpc_status(), Some(0));
    let outcome = client.unary(path::UNARY, b"x", &[]).await;
    assert_eq!(outcome.grpc_status(), Some(0), "{outcome:?}");
}

#[tokio::test]
async fn grpc_cache_bypassed() {
    let (rig, server) = rig_over(Kind::H2c, |app| {
        common::with_middleware(app, "c", "cache", json!({ "default_ttl_secs": 60 }))
    })
    .await;
    let client = rig.client().await;
    // A gRPC call is a POST, which the cache never serves; the response is fresh for a minute.
    for _ in 0..3 {
        let outcome = client.unary(path::CACHEABLE, b"x", &[]).await;
        assert_eq!(outcome.grpc_status(), Some(0));
        assert_eq!(outcome.header("age"), None);
    }
    assert_eq!(server.calls_to(path::CACHEABLE), 3);

    // The same exchange as a GET (not gRPC, which is always POST, but a client library or an
    // attacker can send it) is not stored either: a stream is never held for a cache.
    for _ in 0..3 {
        let mut call = client
            .start_request("GET", "application/grpc", path::CACHEABLE, &[])
            .await;
        call.finish();
        assert_eq!(call.collect().await.grpc_status(), Some(0));
    }
    assert_eq!(server.calls_to(path::CACHEABLE), 6, "{:?}", server.calls());
}

// ---------------------------------------------------------------------------------------
// Mirroring
// ---------------------------------------------------------------------------------------

/// A plain HTTP/1.1 shadow: reads each request head, notes it, answers `200` and closes.
struct Shadow {
    addr: std::net::SocketAddr,
    heads: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Shadow {
    async fn start() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the shadow");
        let addr = listener.local_addr().expect("addr");
        let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = std::sync::Arc::clone(&heads);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = std::sync::Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => head.extend_from_slice(&chunk[..read]),
                        }
                    }
                    seen.lock()
                        .expect("heads")
                        .push(String::from_utf8_lossy(&head).into_owned());
                    drop(
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await,
                    );
                });
            }
        });
        Self { addr, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("heads").clone()
    }
}

/// `g.test` answered by `server`, with every call copied to `shadow`; `mirroring` holds the
/// fields of the mirroring service besides its `service` and `mirrors`.
fn mirrored(server: &Server, shadow: &Shadow, mirroring: &Value) -> Value {
    let mut service = json!({
        "name": "m", "type": "mirroring", "service": "web",
        "mirrors": [{ "service": "shadow", "percent": 100 }],
    });
    if let (Some(service), Some(extra)) = (service.as_object_mut(), mirroring.as_object()) {
        service.extend(extra.clone());
    }
    let mut declared = app_over(&[server.url()], None);
    declared["revisions"][0]["services"] = json!([
        { "name": "web", "type": "loadbalancer", "servers": [{ "url": server.url() }] },
        { "name": "shadow", "type": "loadbalancer", "servers": [{ "url": format!("http://{}", shadow.addr) }] },
        service,
    ]);
    declared["routers"] = json!([common::router("default", json!({ "host": [HOST] }), "m")]);
    declared
}

/// The value of metric series `series` (name and labels as rendered), 0 when it has no sample.
async fn metric(podgate: &Podgate, series: &str) -> f64 {
    podgate
        .admin_get("/metrics")
        .await
        .body
        .lines()
        .find_map(|line| line.strip_prefix(series)?.trim().parse().ok())
        .unwrap_or(0.0)
}

async fn wait_metric_at_least(podgate: &Podgate, series: &str, wanted: f64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while metric(podgate, series).await < wanted {
        assert!(Instant::now() < deadline, "{series} never reached {wanted}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn grpc_mirroring_bounded() {
    let (server, shadow) = (Server::h2c().await, Shadow::start().await);
    let app = mirrored(
        &server,
        &shadow,
        &json!({ "mirror_body": true, "max_body_size": 65536 }),
    );
    let rig = Rig::start(app).await;
    let client = rig.client().await;

    // A unary call is copied, as a plain HTTP/1.1 request with its head.
    let outcome = client.unary(path::UNARY, b"hello", &[]).await;
    assert_eq!(outcome.payloads(), [b"echo:hello".as_slice()]);
    let deadline = Instant::now() + Duration::from_secs(10);
    while shadow.heads().is_empty() {
        assert!(Instant::now() < deadline, "the shadow saw no copy");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let head = shadow.heads().remove(0).to_ascii_lowercase();
    assert!(
        head.starts_with(&format!(
            "post {} http/1.1",
            path::UNARY.to_ascii_lowercase()
        )),
        "{head}"
    );
    assert!(head.contains("x-podgate-mirrored: 1"), "{head}");
    assert!(
        !head.contains("\r\nte:"),
        "a hop-by-hop header is not copied: {head}"
    );

    // A stream that outgrows `max_body_size` is not copied, and the real call is untouched.
    let mut call = client.start(path::BIDI, &[]).await;
    for round in 0..8_u8 {
        let sent = payload_of(MESSAGE, round);
        call.send(&sent).await;
        assert_eq!(call.message().await.expect("echo").1, sent);
    }
    call.finish();
    assert_eq!(call.collect().await.grpc_status(), Some(0));
    wait_metric_at_least(
        &rig.podgate,
        "podgate_mirror_dropped_total{reason=\"body_too_large\"}",
        1.0,
    )
    .await;

    // A stream the client abandons before it ends is not copied either.
    let before = shadow.heads().len();
    let mut call = client.start(path::BIDI, &[]).await;
    call.send(b"small").await;
    assert_eq!(call.message().await.expect("echo").1, b"small");
    call.reset();
    wait_metric_at_least(
        &rig.podgate,
        "podgate_mirror_dropped_total{reason=\"incomplete\"}",
        1.0,
    )
    .await;
    assert_eq!(
        shadow.heads().len(),
        before,
        "no copy of a stream that never ended"
    );
}

// ---------------------------------------------------------------------------------------
// gRPC-Web
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_web_through_route() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let (rig, server) = rig_over(Kind::H2c, |app| {
        common::with_middleware(app, "web", "grpc_web", json!({}))
    })
    .await;
    let client = rig.client().await;

    // Binary: the trailers come back as a last frame with the high flag bit.
    let mut call = client
        .start_with(
            "application/grpc-web+proto",
            path::UNARY,
            &[("x-grpc-web", "1")],
        )
        .await;
    call.send(b"hello").await;
    call.finish();
    let outcome = call.collect().await;
    assert_eq!(outcome.status, 200);
    assert_eq!(
        outcome.header("content-type"),
        Some("application/grpc-web+proto")
    );
    assert_eq!(outcome.messages[0], (0, b"echo:hello".to_vec()));
    let (flag, trailers) = outcome.messages.last().expect("a trailer frame");
    assert_eq!(*flag, 0x80);
    let text = String::from_utf8(trailers.clone())
        .expect("text")
        .to_ascii_lowercase();
    assert!(
        text.contains("grpc-status: 0") && text.contains("x-custom-trailer: kept"),
        "{text}"
    );
    let seen = &server.calls()[0];
    assert_eq!(
        seen.header("content-type"),
        Some("application/grpc"),
        "the upstream speaks gRPC"
    );

    // Text: base64 both ways, the same frames inside.
    let mut call = client
        .start_with("application/grpc-web-text+proto", path::UNARY, &[])
        .await;
    call.try_send(bytes::Bytes::from(
        STANDARD.encode(common::grpc::frame(b"text")),
    ))
    .await
    .expect("the request goes out");
    call.finish();
    let raw = call.raw().await;
    assert_eq!(
        raw.header("content-type"),
        Some("application/grpc-web-text")
    );
    let decoded = STANDARD
        .decode(String::from_utf8(raw.body).expect("text").trim())
        .expect("base64");
    let mut frames = common::grpc::Messages::default();
    frames.push(&decoded);
    assert_eq!(
        frames.next().expect("a message"),
        (0, b"echo:text".to_vec())
    );
    assert_eq!(frames.next().expect("trailers").0, 0x80);

    // A server stream reaches the browser a message at a time.
    let mut call = client
        .start_with("application/grpc-web+proto", path::PACED, &[])
        .await;
    call.send(b"go").await;
    call.finish();
    assert_eq!(call.message().await.expect("first").1, b"msg1");
    assert!(
        timeout(Duration::from_millis(300), call.message())
            .await
            .is_err()
    );
    server.release(2);
    let outcome = call.collect().await;
    assert_eq!(
        outcome.messages.len(),
        3,
        "two messages and the trailer frame"
    );
}

#[tokio::test]
async fn grpc_http2_false_refused() {
    let ca = Ca::new();
    let server = Server::tls(&ca).await;
    let transport = json!({ "ca_pem": ca.pem, "http2": false });
    let app = common::with_middleware(
        app_over(&[server.url()], Some(transport)),
        "web",
        "grpc_web",
        json!({}),
    );
    let rig = Rig::start(app_over(&[server.url()], None)).await;
    let reply = rig.podgate.push_snapshot(&pushed(2, app, &rig.cert)).await;
    assert_eq!(reply.status, 422, "{}", reply.body);
    assert_eq!(reply.json()["conflicts"][0]["code"], "invalid_middleware");
}

// ---------------------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------------------

/// The peak resident size of `pid`, in KiB.
fn peak_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .expect("the process")
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmHWM")
}

/// Streams `count` messages of [`MESSAGE`] bytes downstream, reading slowly at first so the
/// proxy has a reason to hold bytes back.
async fn download(client: &Client, count: u32) {
    let mut call = client.start(path::SERVER_STREAM, &[]).await;
    let size = u32::try_from(MESSAGE).expect("fits");
    call.send(&stream_request(count, size)).await;
    call.finish();
    let mut seen = 0_u32;
    while let Some((flag, payload)) = call.message().await {
        assert_eq!((flag, payload.len()), (0, MESSAGE));
        assert_eq!(payload[0], u8::try_from(seen % 251).unwrap_or(0));
        seen += 1;
        if seen < 200 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    assert_eq!(seen, count);
}

async fn upload(client: &Client, count: u32) {
    let mut call = client.start(path::CLIENT_STREAM, &[]).await;
    let message = payload_of(MESSAGE, 7);
    for _ in 0..count {
        call.send(&message).await;
    }
    call.finish();
    let outcome = call.collect().await;
    assert_eq!(
        outcome.payloads(),
        [format!("{count} {}", u64::from(count) * MESSAGE as u64).as_bytes()]
    );
}

async fn ping_pong(client: &Client, count: u32) {
    let mut call = client.start(path::BIDI, &[]).await;
    let message = payload_of(MESSAGE, 9);
    for _ in 0..count {
        call.send(&message).await;
        assert_eq!(call.message().await.expect("echo").1.len(), MESSAGE);
    }
    call.finish();
    assert_eq!(call.collect().await.grpc_status(), Some(0));
}

#[tokio::test]
async fn grpc_stream_memory_bounded() {
    // 100 MiB take longer than the default wait for a response head, which a client-streaming
    // call spends uploading.
    let (server, _) = backend(Kind::H2c).await;
    let rig = Rig::start_env(
        app_over(&[server.url()], None),
        &[("REQUEST_TIMEOUT_SECS", "300")],
    )
    .await;
    let client = rig.client().await;
    // Everything the proxy sets up once is in the baseline.
    download(&client, 64).await;
    upload(&client, 64).await;
    ping_pong(&client, 64).await;
    let before = peak_kib(rig.podgate.pid());

    // 100 MiB each way: 1600 messages of 64 KiB.
    download(&client, 1600).await;
    upload(&client, 1600).await;
    ping_pong(&client, 1600).await;
    let grown = peak_kib(rig.podgate.pid()).saturating_sub(before);
    assert!(
        grown < 48 * 1024,
        "the proxy's peak size grew by {grown} KiB streaming 100 MiB down, up and both"
    );
}

#[tokio::test]
async fn grpc_idle_stream_cut_by_read_timeout() {
    // The transport's read timeout is the longest a stream may be silent, and a server stream
    // that pauses longer is cut. The cut reaches the upstream as a reset, and the client gets
    // no `grpc-status` at all.
    let server = Server::h2c().await;
    let transport = json!({ "read_timeout_secs": 1 });
    let rig = Rig::start(app_over(&[server.url()], Some(transport))).await;
    let client = rig.client().await;
    let mut call = client.start(path::HANG_AFTER_HEAD, &[]).await;
    call.send(b"go").await;
    call.finish();
    assert_eq!(call.message().await.expect("first").1, b"first");
    let started = Instant::now();
    let cut = call.try_collect().await;
    assert!(
        cut.as_ref()
            .map_or(true, |outcome| outcome.grpc_status().is_none()),
        "the client was told the call ended fine: {cut:?}"
    );
    server
        .wait_end("reset:", started, Duration::from_secs(3))
        .await;

    // A pause inside the timeout is not a problem.
    let server = Server::h2c().await;
    let transport = json!({ "read_timeout_secs": 5 });
    let rig = Rig::start(app_over(&[server.url()], Some(transport))).await;
    let client = rig.client().await;
    let mut call = client.start(path::PACED, &[]).await;
    call.send(b"go").await;
    call.finish();
    assert_eq!(call.message().await.expect("first").1, b"msg1");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    server.release(2);
    let outcome = call.collect().await;
    assert_eq!(outcome.payloads(), [b"msg2".as_slice(), b"msg3"]);
    assert_eq!(outcome.grpc_status(), Some(0));
}
