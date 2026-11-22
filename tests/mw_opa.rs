//! The `opa` middleware: an Open Policy Agent decides, a deny is `403`, and every way
//! the call can fail closes the door with `503`. The pure rules (address, limits, the answer
//! reader, the input) are unit-tested in `src/middleware/opa.rs` and `opa/verdict.rs`.

mod common;

#[path = "fixtures/jwt/signer.rs"]
mod signer;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Podgate, Response, app, refused, serving, snapshot, with_jwt_auth, with_middleware};
use serde_json::{Value, json};
use signer::{Signer, now, unsigned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// What a test server answers with.
enum Reply {
    /// These bytes, then the connection closes.
    Raw(Vec<u8>),
    /// These bytes after a pause.
    Delay(Duration, Vec<u8>),
}

fn raw(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn json_reply(body: &str) -> Reply {
    Reply::Raw(raw(200, body))
}

/// What a test server saw: the request head and its JSON body (`null` when it had none).
struct Call {
    head: String,
    body: Value,
}

type Handler = dyn Fn(&Call) -> Reply + Send + Sync;

/// A server that records each request and answers by `handler`.
struct Server {
    addr: SocketAddr,
    calls: Arc<Mutex<Vec<Call>>>,
    peak: Arc<AtomicUsize>,
}

impl Server {
    async fn start(handler: impl Fn(&Call) -> Reply + Send + Sync + 'static) -> Self {
        Self::start_on("127.0.0.1", handler).await
    }

    async fn start_on(ip: &str, handler: impl Fn(&Call) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind(format!("{ip}:0")).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let handler: Arc<Handler> = Arc::new(handler);
        let shared = (Arc::clone(&calls), live, Arc::clone(&peak));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (calls, live, peak) = shared.clone();
                tokio::spawn(serve(stream, Arc::clone(&handler), calls, live, peak));
            }
        });
        Self { addr, calls, peak }
    }

    fn requests(&self) -> usize {
        self.calls.lock().expect("calls").len()
    }

    /// The `input` of the `index`-th call.
    fn input(&self, index: usize) -> Value {
        self.calls.lock().expect("calls")[index].body["input"].clone()
    }

    fn head(&self, index: usize) -> String {
        self.calls.lock().expect("calls")[index].head.clone()
    }

    fn peak_concurrency(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

async fn serve(
    mut stream: TcpStream,
    handler: Arc<Handler>,
    calls: Arc<Mutex<Vec<Call>>>,
    live: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end + 4]).into_owned();
            let length: usize = header_of(&head, "content-length")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            while seen.len() < end + 4 + length {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => seen.extend_from_slice(&chunk[..read]),
                }
            }
            let body =
                serde_json::from_slice(&seen[end + 4..end + 4 + length]).unwrap_or(Value::Null);
            let call = Call { head, body };
            peak.fetch_max(live.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            let bytes = match handler(&call) {
                Reply::Raw(bytes) => bytes,
                Reply::Delay(pause, bytes) => {
                    sleep(pause).await;
                    bytes
                }
            };
            calls.lock().expect("calls").push(call);
            drop(stream.write_all(&bytes).await);
            live.fetch_sub(1, Ordering::SeqCst);
            drop(stream.shutdown().await);
            return;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// The value of header `name` in a request head.
fn header_of<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(": ")?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

/// How many headers named `name` a request head has.
fn count_of(head: &str, name: &str) -> usize {
    head.lines()
        .skip(1)
        .filter(|line| {
            line.split_once(": ")
                .is_some_and(|(key, _)| key.eq_ignore_ascii_case(name))
        })
        .count()
}

/// The app's upstream: answers `200` with the request head it got as the body, so a test sees
/// exactly what reached it.
async fn echo() -> Server {
    Server::start(|call| Reply::Raw(raw_text(&call.head))).await
}

fn raw_text(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 X\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A policy server that answers by the `path` of the `input` it was asked about.
async fn policy(answer: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Server {
    Server::start(move |call| answer(call.body["input"]["path"].as_str().unwrap_or_default())).await
}

/// A policy server that allows everything.
async fn allow_all() -> Server {
    policy(|_| json_reply(r#"{"result": true}"#)).await
}

fn config(opa: SocketAddr, extra: &Value) -> Value {
    let mut config = json!({ "address": format!("http://{opa}/v1/data/podgate/allow") });
    if let (Some(config), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
        config.extend(extra.clone());
    }
    config
}

fn site(id: &str, host: &str, upstream: SocketAddr, opa: SocketAddr, extra: &Value) -> Value {
    with_middleware(
        app(id, &[host], &[serving("r1", upstream)]),
        "policy",
        "opa",
        config(opa, extra),
    )
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{response:?}");
}

fn assert_closed(response: &Response) {
    assert_eq!(response.status, 503, "{response:?}");
    assert_eq!(response.body, r#"{"error":"authorizer unavailable"}"#);
}

#[tokio::test]
async fn opa_allow_reaches_upstream() {
    let podgate = Podgate::start().await;
    let (up, opa) = (echo().await, allow_all().await);
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, opa.addr, &Value::Null)]),
    )
    .await;

    let answer = podgate.get("a.test", "/ok").await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert!(
        answer.body.starts_with("GET /ok HTTP/1.1"),
        "{}",
        answer.body
    );
    assert_eq!(up.requests(), 1);
    assert_eq!(opa.requests(), 1);
    let head = opa.head(0);
    assert!(
        head.starts_with("POST /v1/data/podgate/allow HTTP/1.1\r\n"),
        "{head}"
    );
    assert_eq!(
        header_of(&head, "host"),
        Some(opa.addr.to_string().as_str()),
        "{head}"
    );
    assert_eq!(header_of(&head, "content-type"), Some("application/json"));
}

#[tokio::test]
async fn opa_input_shape() {
    let podgate = Podgate::start().await;
    let (up, opa) = (echo().await, allow_all().await);
    let listed = json!({"request_headers": ["X-Api-Key", "authorization", "x-absent"]});
    let apps = [
        site("a", "a.test", up.addr, opa.addr, &listed),
        site(
            "b",
            "b.test",
            up.addr,
            opa.addr,
            &json!({"include_query": true}),
        ),
        site("c", "c.test", up.addr, opa.addr, &Value::Null),
    ];
    push(&podgate, &snapshot(1, &apps)).await;
    let sent = [
        ("X-Api-Key", "k1"),
        ("x-api-key", "k2"),
        ("X-Other", "no"),
        ("Authorization", "Bearer zzz"),
        ("Cookie", "s=1"),
    ];

    let answer = podgate
        .request("POST", "a.test", "/orders?id=7", &sent)
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    // Exactly the documented keys; a repeated header is one list, never a scalar that changes
    // type; the query, the cookie and unlisted headers are not sent.
    assert_eq!(
        opa.input(0),
        json!({
            "method": "POST", "path": "/orders", "host": "a.test",
            "source_ip": "127.0.0.1", "tenant": "t1", "app": "a",
            "headers": {"x-api-key": ["k1", "k2"], "authorization": ["Bearer zzz"]},
        })
    );

    podgate
        .request("GET", "b.test", "/p?id=7&x=%20", &sent)
        .await;
    assert_eq!(
        opa.input(1),
        json!({
            "method": "GET", "path": "/p", "query": "id=7&x=%20", "host": "b.test",
            "source_ip": "127.0.0.1", "tenant": "t1", "app": "b", "headers": {},
        })
    );

    // `authorization` is never sent unless listed, and no query without `include_query`.
    podgate.request("GET", "c.test", "/p?id=7", &sent).await;
    assert_eq!(
        opa.input(2),
        json!({
            "method": "GET", "path": "/p", "host": "c.test",
            "source_ip": "127.0.0.1", "tenant": "t1", "app": "c", "headers": {},
        })
    );
    assert!(
        !opa.head(2).to_ascii_lowercase().contains("bearer zzz"),
        "the call carries the input only"
    );
}

#[tokio::test]
async fn opa_deny_is_403() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let opa = policy(|path| match path {
        "/false" => json_reply(r#"{"result": false}"#),
        _ => json_reply(r#"{"result": {"allow": false}}"#),
    })
    .await;
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, opa.addr, &Value::Null)]),
    )
    .await;

    for path in ["/false", "/object"] {
        let denied = podgate.get("a.test", path).await;
        assert_eq!(denied.status, 403, "{path}: {denied:?}");
        assert_eq!(denied.body, r#"{"error":"forbidden"}"#);
        assert_eq!(denied.header("content-type"), Some("application/json"));
        assert_eq!(denied.header("cache-control"), Some("no-store"));
    }
    assert_eq!(
        up.requests(),
        0,
        "a denied request never reaches the upstream"
    );
    assert_eq!(opa.requests(), 2);
}

#[tokio::test]
async fn opa_undefined_result_denies() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let opa = policy(|path| match path {
        "/empty" => json_reply("{}"),
        _ => json_reply(r#"{"decision_id": "x"}"#),
    })
    .await;
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, opa.addr, &Value::Null)]),
    )
    .await;

    for path in ["/empty", "/decision"] {
        let denied = podgate.get("a.test", path).await;
        assert_eq!(denied.status, 403, "{path}: {denied:?}");
        assert_eq!(denied.body, r#"{"error":"forbidden"}"#);
    }
    assert_eq!(up.requests(), 0);
}

#[tokio::test]
async fn opa_object_result_status_and_headers() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let opa = policy(|path| match path {
        "/deny" => json_reply(
            r#"{"result": {"allow": false, "status": 401, "headers": {"WWW-Authenticate": "Bearer realm=\"x\"", "content-type": "text/plain"}}}"#,
        ),
        "/allow" => json_reply(r#"{"result": {"allow": true, "headers": {"X-User": "ann"}}}"#),
        "/foreign" => json_reply(r#"{"result": {"allow": true, "headers": {"x-other": "1"}}}"#),
        _ => json_reply(r#"{"result": true}"#),
    })
    .await;
    let extra = json!({"response_headers": ["x-user", "www-authenticate", "content-type"]});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, opa.addr, &extra)]),
    )
    .await;
    let forged = [("X-User", "admin"), ("x-user", "root"), ("X-Kept", "yes")];

    let denied = podgate.get_with_headers("a.test", "/deny", &forged).await;
    assert_eq!(denied.status, 401, "{denied:?}");
    assert_eq!(denied.body, r#"{"error":"unauthorized"}"#);
    assert_eq!(
        denied.header("www-authenticate"),
        Some("Bearer realm=\"x\"")
    );
    assert_eq!(
        denied.header("content-type"),
        Some("application/json"),
        "podgate's own body headers win over the policy's"
    );

    // An allow puts the policy's value in, and only it: the client's copies are gone.
    let allowed = podgate.get_with_headers("a.test", "/allow", &forged).await;
    assert_eq!(allowed.status, 200, "{allowed:?}");
    assert_eq!(count_of(&allowed.body, "x-user"), 1, "{}", allowed.body);
    assert_eq!(header_of(&allowed.body, "x-user"), Some("ann"));
    assert_eq!(header_of(&allowed.body, "x-kept"), Some("yes"));

    // A policy that leaves the header out cannot let a forged one through.
    let quiet = podgate.get_with_headers("a.test", "/quiet", &forged).await;
    assert_eq!(quiet.status, 200, "{quiet:?}");
    assert_eq!(count_of(&quiet.body, "x-user"), 0, "{}", quiet.body);
    assert!(!quiet.body.contains("admin") && !quiet.body.contains("root"));

    // A header the app did not let the policy set is a failure, not an ignored field.
    let foreign = podgate.get("a.test", "/foreign").await;
    assert_closed(&foreign);
    assert_eq!(up.requests(), 2, "only the two allowed requests arrived");
}

#[tokio::test]
async fn opa_down_fails_closed() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let dead = refused();
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, dead.addr, &Value::Null)]),
    )
    .await;

    assert_closed(&podgate.get("a.test", "/ok").await);
    assert_eq!(up.requests(), 0);
}

#[tokio::test]
async fn opa_timeout_fails_closed() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let slow =
        Server::start(|_| Reply::Delay(Duration::from_secs(4), raw(200, r#"{"result": true}"#)))
            .await;
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                slow.addr,
                &json!({"timeout_secs": 1}),
            )],
        ),
    )
    .await;

    let started = std::time::Instant::now();
    assert_closed(&podgate.get("a.test", "/ok").await);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(up.requests(), 0);
}

#[tokio::test]
async fn opa_malformed_result_fails_closed() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let long = format!(r#"{{"result": true, "pad": "{}"}}"#, "a".repeat(2000));
    let opa = policy(move |path| match path.trim_start_matches('/') {
        "truncated" => json_reply(r#"{"result": tr"#),
        "string" => json_reply(r#"{"result": "true"}"#),
        "number" => json_reply(r#"{"result": 1}"#),
        "null" => json_reply(r#"{"result": null}"#),
        "array" => json_reply(r#"{"result": [true]}"#),
        "no-allow" => json_reply(r#"{"result": {"status": 401}}"#),
        "status-200" => json_reply(r#"{"result": {"allow": false, "status": 200}}"#),
        "status-text" => json_reply(r#"{"result": {"allow": false, "status": "401"}}"#),
        "not-object" => json_reply("true"),
        "http-500" => Reply::Raw(raw(500, r#"{"result": true}"#)),
        "http-404" => Reply::Raw(raw(404, r#"{"result": true}"#)),
        "http-204" => Reply::Raw(raw(204, "")),
        "over-cap" => json_reply(&long),
        "garbage" => Reply::Raw(b"not http at all".to_vec()),
        _ => json_reply(r#"{"result": true}"#),
    })
    .await;
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                opa.addr,
                &json!({"max_response_bytes": 1024}),
            )],
        ),
    )
    .await;

    for path in [
        "truncated",
        "string",
        "number",
        "null",
        "array",
        "no-allow",
        "status-200",
        "status-text",
        "not-object",
        "http-500",
        "http-404",
        "http-204",
        "over-cap",
        "garbage",
    ] {
        let answer = podgate.get("a.test", &format!("/{path}")).await;
        assert_closed(&answer);
    }
    assert_eq!(up.requests(), 0, "no malformed answer opened the door");
    // The same server, answering a clean verdict, still works.
    assert_eq!(podgate.get("a.test", "/fine").await.status, 200);
    assert_eq!(up.requests(), 1);
}

#[tokio::test]
async fn opa_no_capacity_fails_closed() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let slow = Server::start(|_| {
        Reply::Delay(Duration::from_millis(800), raw(200, r#"{"result": true}"#))
    })
    .await;
    push(
        &podgate,
        &snapshot(
            1,
            &[site(
                "a",
                "a.test",
                up.addr,
                slow.addr,
                &json!({"max_concurrent": 1}),
            )],
        ),
    )
    .await;

    let (first, second) = tokio::join!(podgate.get("a.test", "/1"), async {
        sleep(Duration::from_millis(250)).await;
        podgate.get("a.test", "/2").await
    });
    assert_eq!(first.status, 200, "{first:?}");
    assert_closed(&second);
    assert_eq!(second.header("retry-after"), Some("1"));
    assert_eq!(slow.peak_concurrency(), 1);
    assert_eq!(
        up.requests(),
        1,
        "only the admitted request reached the upstream"
    );
    // The permit came back.
    assert_eq!(podgate.get("a.test", "/3").await.status, 200);

    // A tenant budget with room for exactly one call: the second call finds none.
    let tight = Podgate::start().await;
    let up = echo().await;
    let mut snap = snapshot(
        1,
        &[site(
            "a",
            "a.test",
            up.addr,
            slow.addr,
            &json!({"max_response_bytes": 1024}),
        )],
    );
    // 32 KiB request, 8 KiB head and 8 KiB of read buffers, plus the 1 KiB answer cap.
    snap["tenants"][0]["budget"]["max_buffer_bytes"] = json!(49152 + 1024);
    push(&tight, &snap).await;
    let (first, second) = tokio::join!(tight.get("a.test", "/1"), async {
        sleep(Duration::from_millis(250)).await;
        tight.get("a.test", "/2").await
    });
    assert_eq!(first.status, 200, "{first:?}");
    assert_closed(&second);
    assert_eq!(second.header("retry-after"), Some("1"));
    assert_eq!(up.requests(), 1);
    assert_eq!(tight.get("a.test", "/3").await.status, 200);
}

const SECRET: &[u8] = b"an hmac secret of more than thirty-two bytes";

fn hs256() -> (Signer, Value) {
    let signer = Signer::hmac("k", SECRET);
    let config = json!({
        "keys": {"keys": [signer.jwk()]},
        "algorithms": ["HS256"],
        "forward_claims": {"sub": "X-User"},
    });
    (signer, config)
}

fn token(signer: &Signer, extra: &Value) -> String {
    let mut claims = json!({"sub": "ann", "exp": now() + 600});
    if let (Some(claims), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
        claims.extend(extra.clone());
    }
    signer.sign("HS256", &json!({}), &claims)
}

#[tokio::test]
async fn opa_input_claims_from_verified_token() {
    let podgate = Podgate::start().await;
    let (up, opa) = (echo().await, allow_all().await);
    let (signer, jwt) = hs256();
    let guarded = with_middleware(
        with_jwt_auth(app("a", &["a.test"], &[serving("r1", up.addr)]), jwt),
        "policy",
        "opa",
        config(opa.addr, &Value::Null),
    );
    push(&podgate, &snapshot(1, &[guarded])).await;

    let jwt_claims = |token: &str| -> Value {
        let payload = token.split('.').nth(1).expect("payload");
        let bytes = base64_url(payload);
        serde_json::from_slice(&bytes).expect("claims json")
    };
    let good = token(
        &signer,
        &json!({"role": "admin", "groups": ["a", "b"], "tier": 3}),
    );
    let answer = podgate
        .get_with_headers(
            "a.test",
            "/ok",
            &[("Authorization", &format!("Bearer {good}"))],
        )
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(opa.requests(), 1);
    assert_eq!(opa.input(0)["claims"], jwt_claims(&good));
    assert_eq!(opa.input(0)["claims"]["role"], "admin");

    // A token that does not verify never reaches the policy.
    let forged = Signer::hmac("k", b"another secret of more than 32 bytes!!").sign(
        "HS256",
        &json!({}),
        &json!({"sub": "mallory", "exp": now() + 600}),
    );
    let refused = podgate
        .get_with_headers(
            "a.test",
            "/ok",
            &[("Authorization", &format!("Bearer {forged}"))],
        )
        .await;
    assert_eq!(refused.status, 401, "{refused:?}");
    assert_eq!(opa.requests(), 1);
}

/// Decodes a base64url segment of a test token.
fn base64_url(segment: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("base64url")
}

#[tokio::test]
async fn opa_client_cannot_forge_claims() {
    let podgate = Podgate::start().await;
    let (up, opa) = (echo().await, allow_all().await);
    let (signer, jwt) = hs256();
    let listed = json!({"request_headers": ["x-user", "x-claims"]});
    let bare = site("bare", "bare.test", up.addr, opa.addr, &listed);
    let verified = with_middleware(
        with_jwt_auth(app("jwt", &["jwt.test"], &[serving("r1", up.addr)]), jwt),
        "policy",
        "opa",
        config(opa.addr, &listed),
    );
    push(&podgate, &snapshot(1, &[bare, verified])).await;
    let made_up = unsigned("none", &json!({"sub": "root", "role": "admin"}));
    let forgeries = [
        ("X-Claims", r#"{"sub":"root","role":"admin"}"#),
        ("X-User", "root"),
        ("X-Jwt-Claims", r#"{"role":"admin"}"#),
    ];

    // No `jwt_auth` stage: nothing is a claim, whatever the client writes.
    let mut sent = forgeries.to_vec();
    let bearer = format!("Bearer {made_up}");
    sent.push(("Authorization", &bearer));
    let answer = podgate.get_with_headers("bare.test", "/ok", &sent).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let input = opa.input(0);
    assert!(input.get("claims").is_none(), "{input}");
    assert_eq!(
        input["headers"],
        json!({"x-user": ["root"], "x-claims": [r#"{"sub":"root","role":"admin"}"#]}),
        "what the client wrote is the client's, under headers"
    );

    // With `jwt_auth`, the claims are the token's; its `forward_claims` header replaces the
    // client's copy, and the forged `X-Claims` stays a header.
    let good = token(&signer, &json!({"role": "user"}));
    let mut sent = forgeries.to_vec();
    let bearer = format!("Bearer {good}");
    sent.push(("Authorization", &bearer));
    let answer = podgate.get_with_headers("jwt.test", "/ok", &sent).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let input = opa.input(1);
    assert_eq!(input["claims"]["sub"], "ann", "{input}");
    assert_eq!(input["claims"]["role"], "user", "{input}");
    assert_eq!(input["headers"]["x-user"], json!(["ann"]), "{input}");
    assert_eq!(
        input["headers"]["x-claims"],
        json!([r#"{"sub":"root","role":"admin"}"#])
    );
}

struct PolicyFile(PathBuf);

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-opa-policy-{}-{}.json",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("write the policy file");
        Self(path)
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        // Best effort: a leftover temp file is harmless.
        drop(std::fs::remove_file(&self.0));
    }
}

#[tokio::test]
async fn opa_address_policy_enforced() {
    // Each tenant may dial its own loopback address and no other.
    let policy_file = PolicyFile::write(
        r#"{"deny": ["0.0.0.0/8"], "tenants": {
            "t1": {"allow": ["127.0.0.1/32"]}, "t2": {"allow": ["127.0.0.2/32"]}}}"#,
    );
    let podgate = Podgate::start_with_env(&[(
        "UPSTREAM_POLICY_FILE",
        policy_file.0.to_str().expect("utf-8"),
    )])
    .await;
    let (up1, opa1) = (echo().await, allow_all().await);
    let up2 = Server::start_on("127.0.0.2", |call| Reply::Raw(raw_text(&call.head))).await;
    let opa2 = Server::start_on("127.0.0.2", |_| json_reply(r#"{"result": true}"#)).await;
    let mut c = site("c", "c.test", up2.addr, opa2.addr, &Value::Null);
    c["tenant"] = json!("t2");
    let mut d = site("d", "d.test", up2.addr, opa1.addr, &Value::Null);
    d["tenant"] = json!("t2");
    let apps = [
        site("a", "a.test", up1.addr, opa1.addr, &Value::Null),
        site("b", "b.test", up1.addr, opa2.addr, &Value::Null),
        c,
        d,
    ];
    let mut snap = snapshot(1, &apps);
    let tenant = snap["tenants"][0].clone();
    let mut second = tenant.clone();
    second["id"] = json!("t2");
    snap["tenants"] = json!([tenant, second]);
    // The address is only judged where it is dialled, on the exact IP: the snapshot compiles.
    push(&podgate, &snap).await;

    assert_eq!(podgate.get("a.test", "/ok").await.status, 200);
    assert_closed(&podgate.get("b.test", "/ok").await);
    assert_eq!(podgate.get("c.test", "/ok").await.status, 200);
    assert_closed(&podgate.get("d.test", "/ok").await);
    assert_eq!(opa2.requests(), 1, "t2's authorizer was asked by t2 only");
    assert_eq!(opa1.requests(), 1, "t1's authorizer was asked by t1 only");
    assert_eq!(up1.requests(), 1);
    assert_eq!(up2.requests(), 1);
    let metrics = podgate.admin_get("/metrics").await.body;
    for tenant in ["t1", "t2"] {
        let wanted = format!("podgate_upstream_refused_total{{tenant=\"{tenant}\"}} 1");
        assert!(
            metrics.lines().any(|line| line.starts_with(&wanted)),
            "{wanted} in {metrics}"
        );
    }
}

#[tokio::test]
async fn opa_removal_is_a_posture_change() {
    let podgate = Podgate::start().await;
    let (up, opa) = (echo().await, allow_all().await);
    let other = allow_all().await;
    let base = json!({"request_headers": ["x-a", "x-b"], "include_query": true});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, opa.addr, &base)]),
    )
    .await;

    let kinds = |plan: &Response| -> Vec<String> {
        assert_eq!(plan.status, 200, "{}", plan.body);
        plan.json()["posture_changes"]
            .as_array()
            .expect("list")
            .iter()
            .map(|change| change["kind"].as_str().expect("kind").to_owned())
            .collect()
    };
    let plan = |app: Value| {
        let podgate = &podgate;
        async move {
            kinds(
                &podgate
                    .admin_post("/v1/snapshot/plan", &snapshot(2, &[app]))
                    .await,
            )
        }
    };

    let removed = app("a", &["a.test"], &[serving("r1", up.addr)]);
    assert_eq!(plan(removed).await, ["opa_removed"]);

    let other_path = with_middleware(
        app("a", &["a.test"], &[serving("r1", up.addr)]),
        "policy",
        "opa",
        json!({"address": format!("http://{}/v1/data/podgate/other", opa.addr),
               "request_headers": ["x-a", "x-b"], "include_query": true}),
    );
    assert_eq!(plan(other_path).await, ["opa_policy_changed"]);

    let other_server = site("a", "a.test", up.addr, other.addr, &base);
    assert_eq!(plan(other_server).await, ["opa_policy_changed"]);

    let fewer = site(
        "a",
        "a.test",
        up.addr,
        opa.addr,
        &json!({"request_headers": ["x-a"], "include_query": true}),
    );
    assert_eq!(plan(fewer).await, ["opa_input_reduced"]);

    let no_query = site(
        "a",
        "a.test",
        up.addr,
        opa.addr,
        &json!({"request_headers": ["x-a", "x-b"]}),
    );
    assert_eq!(plan(no_query).await, ["opa_input_reduced"]);

    // Sending more to the policy lists nothing.
    let more = site(
        "a",
        "a.test",
        up.addr,
        opa.addr,
        &json!({"request_headers": ["x-a", "x-b", "x-c"], "include_query": true,
                "response_headers": ["x-user"]}),
    );
    assert_eq!(plan(more).await, Vec::<String>::new());
    // Nothing was applied.
    assert_eq!(podgate.get("a.test", "/ok").await.status, 200);
}

#[tokio::test]
async fn opa_invalid_address_is_rejected_by_the_snapshot() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let bad = with_middleware(
        app("a", &["a.test"], &[serving("r1", up.addr)]),
        "policy",
        "opa",
        json!({"address": "http://127.0.0.1:8181/v1/policies/a"}),
    );
    let response = podgate.push_snapshot(&snapshot(1, &[bad])).await;
    assert_eq!(response.status, 422, "{response:?}");
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "invalid_middleware"
    );
}
