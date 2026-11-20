//! The `digest_auth` middleware through the real binary: the digest is computed here
//! with an independent implementation of RFC 7616, so a mistake in the middleware's own formula
//! cannot hide.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, Response, Upstream, app, middleware, serving, snapshot};
use md5::Md5;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const REALM: &str = "podgate";

fn hex_hash(algorithm: &str, text: &str) -> String {
    let bytes = match algorithm {
        "SHA-256" => Sha256::digest(text.as_bytes()).to_vec(),
        _ => Md5::digest(text.as_bytes()).to_vec(),
    };
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ha1(algorithm: &str, user: &str, password: &str) -> String {
    hex_hash(algorithm, &format!("{user}:{REALM}:{password}"))
}

/// A backend that answers with the head of the request it got as the body and counts requests.
struct Echo {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Echo {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(echo_connection(stream, Arc::clone(&counter)));
            }
        });
        Self { addr, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

async fn echo_connection(mut stream: TcpStream, hits: Arc<AtomicUsize>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
            seen.drain(..end + 4);
            hits.fetch_add(1, Ordering::Relaxed);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{head}",
                head.len()
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

/// The request header `name` the upstream saw.
fn seen(response: &Response, name: &str) -> Vec<String> {
    let prefix = format!("{name}:");
    response
        .body
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(|value| value.trim().to_owned())
        .collect()
}

/// What a `401` asked for.
struct Challenge {
    nonce: String,
    algorithms: Vec<String>,
    stale: bool,
}

fn challenge(response: &Response) -> Challenge {
    assert_eq!(response.status, 401, "{response:?}");
    assert_eq!(response.body, r#"{"error":"unauthorized"}"#);
    let values: Vec<&str> = response
        .headers
        .iter()
        .filter(|(name, _)| name == "www-authenticate")
        .map(|(_, value)| value.as_str())
        .collect();
    assert!(!values.is_empty(), "no challenge: {response:?}");
    let param = |value: &str, name: &str| {
        let after = value.split(&format!("{name}=")).nth(1).expect(name);
        after
            .trim_start_matches('"')
            .split(['"', ','])
            .next()
            .expect("value")
            .to_owned()
    };
    for value in &values {
        assert!(value.starts_with("Digest "), "{value}");
        assert_eq!(param(value, "realm"), REALM);
        assert_eq!(param(value, "qop"), "auth");
    }
    Challenge {
        nonce: param(values[0], "nonce"),
        algorithms: values
            .iter()
            .map(|value| param(value, "algorithm"))
            .collect(),
        stale: values[0].contains("stale=true"),
    }
}

/// The `Authorization` value of a client answering `nonce`.
fn authorization(
    algorithm: &str,
    (user, password): (&str, &str),
    nonce: &str,
    count: u32,
    uri: &str,
) -> String {
    let nc = format!("{count:08x}");
    let cnonce = "6b8b4567327b23c6";
    let ha2 = hex_hash(algorithm, &format!("GET:{uri}"));
    let digest = hex_hash(
        algorithm,
        &format!(
            "{}:{nonce}:{nc}:{cnonce}:auth:{ha2}",
            ha1(algorithm, user, password)
        ),
    );
    format!(
        "Digest username=\"{user}\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"{uri}\", \
         algorithm={algorithm}, qop=auth, nc={nc}, cnonce=\"{cnonce}\", response=\"{digest}\", \
         opaque=\"ignored\""
    )
}

fn users() -> Value {
    json!([
        format!("alice:{REALM}:{}", ha1("SHA-256", "alice", "wonderland")),
        format!("bob:{REALM}:{}", ha1("MD5", "bob", "builder")),
    ])
}

fn guarded(host: &str, upstream: SocketAddr, config: Value) -> Value {
    let mut app = app(host, &[host], &[serving("r1", upstream)]);
    let mut config = config;
    if config.get("users").is_none() {
        config["users"] = users();
    }
    app["middlewares"] = json!([middleware("auth", "digest_auth", config)]);
    app["default_chain"] = json!(["auth"]);
    app
}

async fn serve(config: Value, echo: &Echo) -> Podgate {
    let podgate = Podgate::start().await;
    let response = podgate
        .push_snapshot(&snapshot(1, &[guarded("a.test", echo.addr, config)]))
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    podgate
}

async fn fresh(podgate: &Podgate, path: &str) -> Challenge {
    challenge(&podgate.get("a.test", path).await)
}

async fn rejection(config: Value) -> Value {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let response = podgate
        .push_snapshot(&snapshot(1, &[guarded("a.test", up.addr, config)]))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    response.json()["conflicts"][0].clone()
}

#[tokio::test]
async fn digest_auth_challenge_and_both_algorithms_accepted() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;
    assert_eq!(first.algorithms, ["SHA-256", "MD5"]);
    assert!(!first.stale);
    assert_eq!(echo.hits(), 0, "a challenge never reaches the backend");

    let alice = authorization(
        "SHA-256",
        ("alice", "wonderland"),
        &first.nonce,
        1,
        "/x?q=1",
    );
    let response = podgate
        .get_with_headers("a.test", "/x?q=1", &[("Authorization", &alice)])
        .await;
    assert_eq!(response.status, 200, "{response:?}");

    let second = fresh(&podgate, "/y").await;
    let bob = authorization("MD5", ("bob", "builder"), &second.nonce, 1, "/y");
    let response = podgate
        .get_with_headers("a.test", "/y", &[("Authorization", &bob)])
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(echo.hits(), 2);
}

#[tokio::test]
async fn digest_auth_wrong_response_401() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;
    let wrong = authorization("SHA-256", ("alice", "nope"), &first.nonce, 1, "/x");
    let response = podgate
        .get_with_headers("a.test", "/x", &[("Authorization", &wrong)])
        .await;
    let next = challenge(&response);
    assert_ne!(next.nonce, first.nonce, "a refusal carries a fresh nonce");
    assert!(!next.stale);
    let basic = podgate
        .get_with_headers("a.test", "/x", &[("Authorization", "Basic YWxpY2U6eA==")])
        .await;
    challenge(&basic);
    assert_eq!(echo.hits(), 0);
}

#[tokio::test]
async fn digest_auth_unknown_user_401() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;
    let stranger = authorization("SHA-256", ("mallory", "wonderland"), &first.nonce, 1, "/x");
    let response = podgate
        .get_with_headers("a.test", "/x", &[("Authorization", &stranger)])
        .await;
    challenge(&response);
    assert_eq!(echo.hits(), 0);
}

#[tokio::test]
async fn digest_auth_wrong_realm_401() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;
    let right = authorization("SHA-256", ("alice", "wonderland"), &first.nonce, 1, "/x");
    let wrong = right.replace(&format!("realm=\"{REALM}\""), "realm=\"elsewhere\"");
    let response = podgate
        .get_with_headers("a.test", "/x", &[("Authorization", &wrong)])
        .await;
    challenge(&response);
    assert_eq!(echo.hits(), 0);
}

#[tokio::test]
async fn digest_auth_uri_mismatch_401() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;
    let signed_for_other = authorization(
        "SHA-256",
        ("alice", "wonderland"),
        &first.nonce,
        1,
        "/other",
    );
    let response = podgate
        .get_with_headers("a.test", "/x", &[("Authorization", &signed_for_other)])
        .await;
    challenge(&response);
    assert_eq!(echo.hits(), 0);
}

#[tokio::test]
async fn digest_auth_replayed_nc_refused_over_http() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;
    let one = authorization("SHA-256", ("alice", "wonderland"), &first.nonce, 1, "/x");
    let two = authorization("SHA-256", ("alice", "wonderland"), &first.nonce, 2, "/x");
    let send = |value: String| {
        let podgate = &podgate;
        async move {
            podgate
                .get_with_headers("a.test", "/x", &[("Authorization", &value)])
                .await
        }
    };
    assert_eq!(send(one.clone()).await.status, 200);
    let replay = send(one).await;
    challenge(&replay);
    assert_eq!(send(two.clone()).await.status, 200);
    challenge(&send(two).await);
    assert_eq!(echo.hits(), 2);
}

#[tokio::test]
async fn digest_auth_user_header() {
    let echo = Echo::start().await;
    let podgate = serve(json!({ "header_field": "x-user" }), &echo).await;
    let first = fresh(&podgate, "/x").await;
    let auth = authorization("SHA-256", ("alice", "wonderland"), &first.nonce, 1, "/x");
    let response = podgate
        .get_with_headers(
            "a.test",
            "/x",
            &[("Authorization", &auth), ("X-User", "root")],
        )
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(
        seen(&response, "x-user"),
        ["alice"],
        "the client's value is replaced"
    );
    assert!(
        seen(&response, "authorization").is_empty(),
        "the credentials stop at the proxy by default: {response:?}"
    );

    let keep = serve(
        json!({ "header_field": "x-user", "remove_header": false }),
        &echo,
    )
    .await;
    let first = fresh(&keep, "/x").await;
    let auth = authorization("SHA-256", ("alice", "wonderland"), &first.nonce, 1, "/x");
    let response = keep
        .get_with_headers("a.test", "/x", &[("Authorization", &auth)])
        .await;
    assert_eq!(seen(&response, "authorization").len(), 1, "{response:?}");
}

#[tokio::test]
async fn digest_auth_invalid_users_rejected_at_compile() {
    let good = ha1("SHA-256", "a", "pw");
    let auth_int =
        rejection(json!({ "users": [format!("a:{REALM}:{good}")], "qop": "auth-int" })).await;
    assert_eq!(auth_int["code"], "invalid_middleware", "{auth_int}");
    let short = rejection(json!({ "users": [format!("a:{REALM}:{}", &good[..40])] })).await;
    assert_eq!(short["code"], "invalid_middleware", "{short}");
    assert!(!short.to_string().contains(&good[..40]), "{short}");
    let realm = rejection(json!({ "users": [format!("a:elsewhere:{good}")] })).await;
    assert_eq!(realm["code"], "invalid_middleware", "{realm}");
}

#[tokio::test]
async fn digest_auth_secrets_redacted_in_explain() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let explain = podgate.admin_get("/v1/explain?url=http://a.test/x").await;
    assert_eq!(explain.status, 200, "{explain:?}");
    assert!(explain.body.contains("digest_auth"), "{}", explain.body);
    for secret in [
        ha1("SHA-256", "alice", "wonderland"),
        ha1("MD5", "bob", "builder"),
    ] {
        assert!(!explain.body.contains(&secret), "{}", explain.body);
    }
}

#[tokio::test]
async fn digest_auth_repeated_failures_are_delayed() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;
    let wrong = authorization("SHA-256", ("alice", "nope"), &first.nonce, 1, "/x");
    let mut slowest = Duration::ZERO;
    let mut fastest_after = Duration::MAX;
    for attempt in 0..8 {
        let started = Instant::now();
        let response = podgate
            .get_with_headers("a.test", "/x", &[("Authorization", &wrong)])
            .await;
        challenge(&response);
        let took = started.elapsed();
        slowest = slowest.max(took);
        if attempt >= 6 {
            fastest_after = fastest_after.min(took);
        }
    }
    assert!(
        fastest_after >= Duration::from_millis(900),
        "attempts past the fifth failure wait: {fastest_after:?}"
    );
    assert!(slowest < Duration::from_secs(5), "{slowest:?}");
}

#[tokio::test]
async fn plan_lists_digest_auth_removal() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let live = snapshot(1, &[guarded("a.test", up.addr, json!({}))]);
    assert_eq!(podgate.push_snapshot(&live).await.status, 200);

    let kinds = |plan: Response| -> Vec<String> {
        assert_eq!(plan.status, 200, "{}", plan.body);
        plan.json()["posture_changes"]
            .as_array()
            .expect("posture_changes")
            .iter()
            .map(|change| {
                assert_eq!(change["host"], "a.test");
                change["kind"].as_str().expect("kind").to_owned()
            })
            .collect()
    };
    let removed = podgate
        .admin_post(
            "/v1/snapshot/plan",
            &snapshot(2, &[app("a.test", &["a.test"], &[serving("r1", up.addr)])]),
        )
        .await;
    assert_eq!(kinds(removed), ["digest_auth_removed"]);

    let fewer = json!([format!(
        "alice:{REALM}:{}",
        ha1("SHA-256", "alice", "wonderland")
    )]);
    let fewer = podgate
        .admin_post(
            "/v1/snapshot/plan",
            &snapshot(2, &[guarded("a.test", up.addr, json!({ "users": fewer }))]),
        )
        .await;
    assert_eq!(kinds(fewer), ["digest_auth_users_removed"]);
}

/// Pushes `apps` as `version` and expects it to be accepted.
async fn push(podgate: &Podgate, version: u64, apps: &[Value]) {
    let response = podgate.push_snapshot(&snapshot(version, apps)).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// An app that has nothing to do with the guarded one.
fn unrelated(up: SocketAddr) -> Value {
    app("other", &["other.test"], &[serving("r1", up)])
}

#[tokio::test]
async fn digest_nonce_valid_across_unrelated_push() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;

    push(
        &podgate,
        2,
        &[
            guarded("a.test", echo.addr, json!({})),
            unrelated(echo.addr),
        ],
    )
    .await;
    let auth = authorization("SHA-256", ("alice", "wonderland"), &first.nonce, 1, "/x");
    let response = podgate
        .get_with_headers("a.test", "/x", &[("Authorization", &auth)])
        .await;
    assert_eq!(
        response.status, 200,
        "an unrelated push keeps the nonce: {response:?}"
    );

    let again = podgate
        .get_with_headers("a.test", "/x", &[("Authorization", &auth)])
        .await;
    challenge(&again);

    // A change to the middleware's own configuration starts it fresh.
    let second = fresh(&podgate, "/x").await;
    push(
        &podgate,
        3,
        &[guarded(
            "a.test",
            echo.addr,
            json!({ "header_field": "x-user" }),
        )],
    )
    .await;
    let auth = authorization("SHA-256", ("alice", "wonderland"), &second.nonce, 1, "/x");
    let response = podgate
        .get_with_headers("a.test", "/x", &[("Authorization", &auth)])
        .await;
    challenge(&response);
}

#[tokio::test]
async fn digest_replayed_nc_stays_refused_across_unrelated_push() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;
    let auth = authorization("SHA-256", ("alice", "wonderland"), &first.nonce, 1, "/x");
    let send = || async {
        podgate
            .get_with_headers("a.test", "/x", &[("Authorization", &auth)])
            .await
    };
    assert_eq!(send().await.status, 200);

    push(
        &podgate,
        2,
        &[
            guarded("a.test", echo.addr, json!({})),
            unrelated(echo.addr),
        ],
    )
    .await;
    challenge(&send().await);
    assert_eq!(echo.hits(), 1);
}

#[tokio::test]
async fn digest_auth_throttle_survives_unrelated_push() {
    let echo = Echo::start().await;
    let podgate = serve(json!({}), &echo).await;
    let first = fresh(&podgate, "/x").await;
    let wrong = authorization("SHA-256", ("alice", "nope"), &first.nonce, 1, "/x");
    for _ in 0..5 {
        challenge(
            &podgate
                .get_with_headers("a.test", "/x", &[("Authorization", &wrong)])
                .await,
        );
    }

    push(
        &podgate,
        2,
        &[
            guarded("a.test", echo.addr, json!({})),
            unrelated(echo.addr),
        ],
    )
    .await;
    let started = Instant::now();
    challenge(
        &podgate
            .get_with_headers("a.test", "/x", &[("Authorization", &wrong)])
            .await,
    );
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "a push is not a free reset of the throttle: {:?}",
        started.elapsed()
    );
}

/// A snapshot whose tenant may buffer only `bytes`.
async fn serve_with_budget(bytes: u64, echo: &Echo) -> Podgate {
    let podgate = Podgate::start().await;
    let mut pushed = snapshot(1, &[guarded("a.test", echo.addr, json!({}))]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(bytes);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    podgate
}

#[tokio::test]
async fn digest_auth_replay_budget_transient_is_busy() {
    let echo = Echo::start().await;
    // Room for exactly one replay entry: the second nonce does not fit right now.
    let podgate = serve_with_budget(128, &echo).await;
    let first = fresh(&podgate, "/x").await;
    let second = fresh(&podgate, "/x").await;
    let send = |nonce: &str| {
        let value = authorization("SHA-256", ("alice", "wonderland"), nonce, 1, "/x");
        let podgate = &podgate;
        async move {
            podgate
                .get_with_headers("a.test", "/x", &[("Authorization", &value)])
                .await
        }
    };
    assert_eq!(send(&first.nonce).await.status, 200);
    let busy = send(&second.nonce).await;
    assert_eq!(busy.status, 503, "{busy:?}");
    assert_eq!(busy.header("retry-after"), Some("1"));
    assert_eq!(
        busy.json()["error"],
        "password verification is busy",
        "{busy:?}"
    );
    assert_eq!(echo.hits(), 1);
}

#[tokio::test]
async fn digest_auth_replay_budget_never_fits_is_over_budget() {
    let echo = Echo::start().await;
    let podgate = serve_with_budget(100, &echo).await;
    let first = fresh(&podgate, "/x").await;
    let auth = authorization("SHA-256", ("alice", "wonderland"), &first.nonce, 1, "/x");
    let refused = podgate
        .get_with_headers("a.test", "/x", &[("Authorization", &auth)])
        .await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(
        refused.json()["error"],
        "password verification memory is over the tenant's budget",
        "{refused:?}"
    );
    assert_eq!(echo.hits(), 0);
}
