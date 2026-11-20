//! The `basic_auth` middleware: bcrypt and argon2 credentials, the entries and
//! costs refused at compile, the headers it sets and strips, and the bounds on password
//! hashing, through the real binary.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Podgate, Response, app, middleware, serving, snapshot, with_chain};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CHALLENGE: &str = r#"Basic realm="podgate", charset="UTF-8""#;

/// A backend that counts requests and answers with the lowercased head it got as the body,
/// after `delay`.
struct Backend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Backend {
    async fn start(delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let addr = listener.local_addr().expect("backend addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(connection(stream, delay, Arc::clone(&counted)));
            }
        });
        Self { addr, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn connection(mut stream: TcpStream, delay: Duration, hits: Arc<AtomicUsize>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            hits.fetch_add(1, Ordering::SeqCst);
            let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
            seen.drain(..end + 4);
            tokio::time::sleep(delay).await;
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

/// The values of request header `name` the backend saw.
fn seen(response: &Response, name: &str) -> Vec<String> {
    let prefix = format!("{name}:");
    response
        .body
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(|value| value.trim().to_owned())
        .collect()
}

fn bcrypt_hash(password: &str) -> String {
    bcrypt::hash(password, 4).expect("bcrypt hash")
}

fn argon2_hash(password: &str, memory_kib: u32) -> String {
    let params = Params::new(memory_kib, 1, 1, None).expect("argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_with_salt(password.as_bytes(), b"saltsaltsalt")
        .expect("argon2 hash")
        .to_string()
}

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

/// App `a.test` of tenant `t1` with one `basic_auth` middleware `config` in its chain.
fn protected(upstream: SocketAddr, config: Value) -> Value {
    with_chain(
        app("a", &["a.test"], &[serving("r1", upstream)]),
        &[middleware("auth", "basic_auth", config)],
    )
}

async fn serve(config: Value, backend: &Backend) -> Podgate {
    let podgate = Podgate::start().await;
    let pushed = podgate
        .push_snapshot(&snapshot(1, &[protected(backend.addr, config)]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    podgate
}

async fn get_as(podgate: &Podgate, authorization: &str) -> Response {
    podgate
        .get_with_headers("a.test", "/", &[("Authorization", authorization)])
        .await
}

fn assert_challenge(response: &Response) {
    assert_eq!(response.status, 401, "{response:?}");
    assert_eq!(
        response.header("www-authenticate"),
        Some(CHALLENGE),
        "{response:?}"
    );
    assert_eq!(response.json()["error"], "unauthorized");
}

#[tokio::test]
async fn basic_auth_accepts_bcrypt() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))] }),
        &backend,
    )
    .await;
    let response = get_as(&podgate, &basic("alice", "s3cret")).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(backend.hits(), 1);
}

#[tokio::test]
async fn basic_auth_accepts_argon2() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "users": [format!("bob:{}", argon2_hash("hunter2", 64))] }),
        &backend,
    )
    .await;
    let response = get_as(&podgate, &basic("bob", "hunter2")).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_challenge(&get_as(&podgate, &basic("bob", "hunter3")).await);
}

#[tokio::test]
async fn basic_auth_wrong_password_401() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))], "realm": "podgate" }),
        &backend,
    )
    .await;
    assert_challenge(&get_as(&podgate, &basic("alice", "nope")).await);
    assert_eq!(backend.hits(), 0);
}

#[tokio::test]
async fn basic_auth_unknown_user_401() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))] }),
        &backend,
    )
    .await;
    assert_challenge(&get_as(&podgate, &basic("mallory", "s3cret")).await);
    assert_eq!(backend.hits(), 0);
}

#[tokio::test]
async fn basic_auth_malformed_header_401() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))] }),
        &backend,
    )
    .await;
    assert_challenge(&podgate.get("a.test", "/").await);
    for value in [
        "Bearer abc".to_owned(),
        "Basic".to_owned(),
        "Basic !!!not-base64".to_owned(),
        format!("Basic {}", STANDARD.encode("nocolon")),
    ] {
        assert_challenge(&get_as(&podgate, &value).await);
    }
    let twice = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("Authorization", &basic("alice", "s3cret")),
                ("Authorization", &basic("alice", "s3cret")),
            ],
        )
        .await;
    assert_challenge(&twice);
    assert_eq!(backend.hits(), 0);
}

#[tokio::test]
async fn basic_auth_weak_hash_rejected() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    for entry in [
        "alice:$apr1$salt$hashhashhashhashhashhash".to_owned(),
        "alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=".to_owned(),
        "alice:rl3bvrRxVqPIA".to_owned(),
        "alice:s3cret".to_owned(),
    ] {
        let response = podgate
            .push_snapshot(&snapshot(
                1,
                &[protected(backend.addr, json!({ "users": [entry] }))],
            ))
            .await;
        assert_eq!(response.status, 422, "{entry}: {}", response.body);
        let conflict = &response.json()["conflicts"][0];
        assert_eq!(conflict["code"], "invalid_middleware", "{conflict}");
        assert!(!response.body.contains("hashhash"), "{}", response.body);
    }
}

#[tokio::test]
async fn basic_auth_cost_cap_rejected() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    let digest = "A".repeat(43);
    for entry in [
        format!("alice:$2b$15${}", "A".repeat(53)),
        format!("alice:$argon2id$v=19$m=65537,t=1,p=1$c2FsdHNhbHRzYWx0${digest}"),
        format!("alice:$argon2id$v=19$m=1024,t=5,p=1$c2FsdHNhbHRzYWx0${digest}"),
        format!("alice:$argon2id$v=19$m=1024,t=1,p=5$c2FsdHNhbHRzYWx0${digest}"),
    ] {
        let response = podgate
            .push_snapshot(&snapshot(
                1,
                &[protected(backend.addr, json!({ "users": [entry] }))],
            ))
            .await;
        assert_eq!(response.status, 422, "{entry}: {}", response.body);
        let conflict = &response.json()["conflicts"][0];
        assert_eq!(conflict["code"], "invalid_middleware", "{conflict}");
        assert!(
            conflict["message"]
                .as_str()
                .is_some_and(|m| m.contains("above the limit")),
            "{conflict}"
        );
    }
    let at_the_cap = format!("alice:$2b$14${}", "A".repeat(53));
    let accepted = podgate
        .push_snapshot(&snapshot(
            1,
            &[protected(backend.addr, json!({ "users": [at_the_cap] }))],
        ))
        .await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
}

#[tokio::test]
async fn basic_auth_user_header_set() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))], "header_field": "X-User" }),
        &backend,
    )
    .await;
    let response = get_as(&podgate, &basic("alice", "s3cret")).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(seen(&response, "x-user"), ["alice"], "{}", response.body);
    assert_eq!(
        seen(&response, "authorization"),
        [basic("alice", "s3cret").to_ascii_lowercase()],
        "Authorization goes to the upstream unless `remove_header` says otherwise"
    );
}

#[tokio::test]
async fn basic_auth_removes_authorization() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))], "remove_header": true }),
        &backend,
    )
    .await;
    let response = get_as(&podgate, &basic("alice", "s3cret")).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert!(
        seen(&response, "authorization").is_empty(),
        "{}",
        response.body
    );
}

#[tokio::test]
async fn basic_auth_client_user_header_overwritten() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = serve(
        json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))], "header_field": "x-user" }),
        &backend,
    )
    .await;
    let response = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("X-User", "root"),
                ("x-user", "admin"),
                ("Authorization", &basic("alice", "s3cret")),
            ],
        )
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(seen(&response, "x-user"), ["alice"], "{}", response.body);
}

#[tokio::test]
async fn basic_auth_header_field_that_frames_messages_rejected() {
    let backend = Backend::start(Duration::ZERO).await;
    let podgate = Podgate::start().await;
    for field in [
        "host",
        "content-length",
        "authorization",
        "proxy-authorization",
    ] {
        let config = json!({
            "users": [format!("alice:{}", bcrypt_hash("s3cret"))], "header_field": field
        });
        let response = podgate
            .push_snapshot(&snapshot(1, &[protected(backend.addr, config)]))
            .await;
        assert_eq!(response.status, 422, "{field}: {}", response.body);
    }
}

/// A snapshot of two tenants, each with its own protected app: `a.test` of `t1` and `b.test` of
/// `t2`, both with `config`, and each tenant's budget as `budget`.
fn two_tenants(backend: SocketAddr, config: &Value, budget: &Value) -> Value {
    let mut first = protected(backend, config.clone());
    first["tenant"] = json!("t1");
    let mut second = with_chain(
        app("b", &["b.test"], &[serving("r1", backend)]),
        &[middleware("auth", "basic_auth", config.clone())],
    );
    second["tenant"] = json!("t2");
    let mut pushed = snapshot(1, &[first, second]);
    pushed["tenants"] = json!([
        { "id": "t1", "weight": 1, "budget": budget },
        { "id": "t2", "weight": 1, "budget": budget },
    ]);
    pushed
}

#[tokio::test]
async fn basic_auth_flood_is_bounded() {
    let backend = Backend::start(Duration::ZERO).await;
    // Two workers: a tenant may hold one, so the other tenant always finds one free.
    let podgate = Podgate::start_with_env(&[("BASIC_AUTH_MAX_CONCURRENT", "2")]).await;
    let slow_hash = bcrypt::hash("s3cret", 8).expect("bcrypt hash");
    let config = json!({ "users": [format!("alice:{slow_hash}")] });
    let budget = json!({ "max_inflight": 1000, "max_buffer_bytes": 1_048_576 });
    let pushed = podgate
        .push_snapshot(&two_tenants(backend.addr, &config, &budget))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let flood = Arc::new(podgate);
    let mut floods = Vec::new();
    for round in 0..64 {
        let flood = Arc::clone(&flood);
        floods.push(tokio::spawn(async move {
            flood
                .get_with_headers(
                    "a.test",
                    "/",
                    &[("Authorization", &basic("alice", &format!("guess-{round}")))],
                )
                .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    let started = Instant::now();
    let other = flood
        .get_with_headers(
            "b.test",
            "/",
            &[("Authorization", &basic("alice", "s3cret"))],
        )
        .await;
    let waited = started.elapsed();
    assert_eq!(
        other.status, 200,
        "another tenant is served during the flood: {other:?}"
    );
    assert!(
        waited < Duration::from_millis(900),
        "the other tenant waited {waited:?}"
    );

    let mut refused = 0;
    for task in floods {
        let response = task.await.expect("flood request");
        match response.status {
            401 => {}
            503 => {
                refused += 1;
                assert_eq!(response.header("retry-after"), Some("1"), "{response:?}");
            }
            other => panic!("unexpected status {other}: {response:?}"),
        }
    }
    assert!(
        refused > 0,
        "a flood of 64 over one share must be refused in part"
    );
    assert_eq!(
        backend.hits(),
        1,
        "only the legitimate request reached the backend"
    );
}

#[tokio::test]
async fn basic_auth_argon2_memory_charged() {
    let backend = Backend::start(Duration::ZERO).await;
    let config = json!({ "users": [format!("bob:{}", argon2_hash("hunter2", 4096))] });
    let podgate = Podgate::start().await;
    let small = json!({ "max_inflight": 10, "max_buffer_bytes": 1_048_576 });
    let pushed = podgate
        .push_snapshot(&two_tenants(backend.addr, &config, &small))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    // 4096 KiB of argon2 memory does not fit a 1 MiB buffer budget.
    let refused = get_as(&podgate, &basic("bob", "hunter2")).await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert_eq!(refused.header("retry-after"), Some("1"));

    let large = json!({ "max_inflight": 10, "max_buffer_bytes": 8 * 1024 * 1024 });
    let mut again = two_tenants(backend.addr, &config, &large);
    again["version"] = json!(2);
    let pushed = podgate.push_snapshot(&again).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let served = get_as(&podgate, &basic("bob", "hunter2")).await;
    assert_eq!(served.status, 200, "{served:?}");
    let metrics = podgate.admin_get("/metrics").await;
    assert!(
        metrics
            .body
            .contains("podgate_tenant_buffer_bytes_peak{tenant=\"t1\"} 4194304"),
        "{}",
        metrics.body
    );
}

#[tokio::test]
async fn basic_auth_before_admission() {
    let backend = Backend::start(Duration::from_millis(600)).await;
    let podgate = Podgate::start().await;
    let config = json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))] });
    let budget = json!({ "max_inflight": 1, "max_buffer_bytes": 1_048_576 });
    let pushed = podgate
        .push_snapshot(&two_tenants(backend.addr, &config, &budget))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let podgate = Arc::new(podgate);
    let slow = {
        let podgate = Arc::clone(&podgate);
        tokio::spawn(async move { get_as(&podgate, &basic("alice", "s3cret")).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The tenant's only slot is taken by the slow request; an unauthenticated one is answered
    // before admission, so it is `401` and not `503`, and never reaches the backend.
    let unauthenticated = podgate.get("a.test", "/").await;
    assert_challenge(&unauthenticated);
    assert_challenge(&get_as(&podgate, &basic("alice", "wrong")).await);
    assert_eq!(slow.await.expect("slow request").status, 200);
    assert_eq!(backend.hits(), 1);
}

#[tokio::test]
async fn basic_auth_secrets_redacted() {
    let backend = Backend::start(Duration::ZERO).await;
    let hash = bcrypt_hash("s3cret");
    let podgate = serve(json!({ "users": [format!("alice:{hash}")] }), &backend).await;
    let explain = podgate
        .admin_get("/v1/explain?url=http://a.test/&method=GET")
        .await;
    assert_eq!(explain.status, 200, "{}", explain.body);
    assert!(explain.body.contains("basic_auth"), "{}", explain.body);
    assert!(!explain.body.contains(&hash[7..]), "{}", explain.body);

    // A failed request is recorded with its headers: the credentials must not be in it.
    let upstream = {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind failing backend");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 2048];
                    let _ = stream.read(&mut buffer).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        addr
    };
    let mut failing = protected(upstream, json!({ "users": [format!("alice:{hash}")] }));
    failing["id"] = json!("failing");
    let pushed = podgate.push_snapshot(&snapshot(2, &[failing])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let credentials = basic("alice", "s3cret");
    let response = get_as(&podgate, &credentials).await;
    assert_eq!(response.status, 500, "{response:?}");
    let recorded = podgate.admin_get("/v1/apps/failing/failures").await;
    assert_eq!(recorded.status, 200, "{}", recorded.body);
    assert!(recorded.body.contains("[redacted]"), "{}", recorded.body);
    assert!(!recorded.body.contains(&credentials), "{}", recorded.body);
    assert!(
        !recorded.body.contains(&STANDARD.encode("alice:s3cret")),
        "{}",
        recorded.body
    );
    assert!(!recorded.body.contains(&hash[7..]), "{}", recorded.body);
}

#[tokio::test]
async fn plan_lists_basic_auth_removal() {
    let backend = Backend::start(Duration::ZERO).await;
    let hash = bcrypt_hash("s3cret");
    let podgate = serve(json!({ "users": [format!("alice:{hash}")] }), &backend).await;

    let without = app("a", &["a.test"], &[serving("r1", backend.addr)]);
    let removed = podgate
        .admin_post("/v1/snapshot/plan", &snapshot(2, &[without]))
        .await;
    assert_eq!(removed.status, 200, "{}", removed.body);
    let kinds: Vec<String> = removed.json()["posture_changes"]
        .as_array()
        .expect("posture_changes")
        .iter()
        .map(|change| change["kind"].as_str().expect("kind").to_owned())
        .collect();
    assert_eq!(kinds, ["basic_auth_removed"]);

    let fewer = protected(
        backend.addr,
        json!({ "users": [format!("bob:{}", bcrypt_hash("other"))] }),
    );
    let dropped = podgate
        .admin_post("/v1/snapshot/plan", &snapshot(2, &[fewer]))
        .await;
    assert_eq!(dropped.status, 200, "{}", dropped.body);
    assert_eq!(
        dropped.json()["posture_changes"][0]["kind"],
        "basic_auth_users_removed"
    );

    let same = protected(
        backend.addr,
        json!({ "users": [format!("alice:{hash}")], "realm": "x" }),
    );
    let kept = podgate
        .admin_post("/v1/snapshot/plan", &snapshot(2, &[same]))
        .await;
    assert_eq!(kept.json()["posture_changes"], json!([]), "{}", kept.body);
}

/// How long one request with a wrong password takes.
async fn timed_failure(podgate: &Podgate) -> Duration {
    let started = Instant::now();
    let response = get_as(podgate, &basic("alice", "wrong")).await;
    assert_eq!(response.status, 401, "{response:?}");
    started.elapsed()
}

#[tokio::test]
async fn basic_auth_throttle_survives_unrelated_push() {
    let backend = Backend::start(Duration::ZERO).await;
    let hash = bcrypt_hash("s3cret");
    let podgate = Podgate::start().await;
    let other = |revision: &str| app("b", &["b.test"], &[serving(revision, backend.addr)]);
    let guarded = |realm: &str| {
        protected(
            backend.addr,
            json!({ "users": [format!("alice:{hash}")], "realm": realm }),
        )
    };
    let pushed = podgate
        .push_snapshot(&snapshot(1, &[guarded("one"), other("r1")]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    for _ in 0..5 {
        assert!(timed_failure(&podgate).await < Duration::from_millis(900));
    }
    assert!(
        timed_failure(&podgate).await >= Duration::from_millis(900),
        "the sixth failure in a minute is delayed"
    );

    // A push that changes another app keeps the count.
    let pushed = podgate
        .push_snapshot(&snapshot(2, &[guarded("one"), other("r2")]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert!(
        timed_failure(&podgate).await >= Duration::from_millis(900),
        "an unrelated push must not reset the throttle"
    );

    // A push that changes the middleware itself starts it fresh.
    let pushed = podgate
        .push_snapshot(&snapshot(3, &[guarded("two"), other("r2")]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert!(
        timed_failure(&podgate).await < Duration::from_millis(900),
        "a changed middleware starts with a clean count"
    );
}
