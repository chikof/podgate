//! The `jwt_auth` middleware end to end: which tokens get through, what the client
//! and the upstream see, the JWKS fetch under the upstream address policy, and the posture a
//! plan reports. The pure rules (algorithm and key matrix, claims, the key cache) are
//! unit-tested in `src/middleware/jwt_auth/`; the same test names appear there.

mod common;

#[path = "fixtures/jwt/signer.rs"]
mod signer;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    Podgate, Response, TestCert, app, refused, router, service, serving, snapshot, with_jwt_auth,
    with_middleware,
};
use serde_json::{Value, json};
use signer::{Signer, forge_hmac, now, unsigned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

const CHALLENGE: &str = r#"Bearer realm="podgate", error="invalid_token""#;

/// What a test server answers with.
enum Reply {
    Raw(Vec<u8>),
    Delay(Duration, Vec<u8>),
}

fn raw(status: u16, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    out.into_bytes()
}

fn http(status: u16, headers: &[(&str, &str)], body: &str) -> Reply {
    Reply::Raw(raw(status, headers, body))
}

type Handler = dyn Fn(&str) -> Reply + Send + Sync;

/// A server that records each request head and answers by `handler`.
struct Server {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Server {
    async fn start(handler: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let recorded = Arc::clone(&heads);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, Arc::clone(&handler), Arc::clone(&recorded)));
            }
        });
        Self { addr, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("heads").clone()
    }

    fn requests(&self) -> usize {
        self.heads().len()
    }
}

async fn serve(mut stream: TcpStream, handler: Arc<Handler>, heads: Arc<Mutex<Vec<String>>>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end + 4]).into_owned();
            heads.lock().expect("heads").push(head.clone());
            let bytes = match handler(&head) {
                Reply::Raw(bytes) => bytes,
                Reply::Delay(pause, bytes) => {
                    sleep(pause).await;
                    bytes
                }
            };
            drop(stream.write_all(&bytes).await);
            drop(stream.shutdown().await);
            return;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

fn header_of<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(": ")?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

/// The app's upstream: answers `200` with the request head it got as the body.
async fn echo() -> Server {
    Server::start(|head| http(200, &[], head)).await
}

/// A JWKS endpoint whose answer a test changes through the returned handle.
async fn jwks_endpoint(first: &[&Signer]) -> (Server, Arc<Mutex<(u16, String)>>) {
    let state = Arc::new(Mutex::new((200, jwks_of(first))));
    let shared = Arc::clone(&state);
    let server = Server::start(move |_| {
        let (status, body) = shared.lock().expect("jwks").clone();
        http(status, &[("Content-Type", "application/json")], &body)
    })
    .await;
    (server, state)
}

fn jwks_of(signers: &[&Signer]) -> String {
    json!({"keys": signers.iter().map(|signer| signer.jwk()).collect::<Vec<_>>()}).to_string()
}

fn claims(extra: &Value) -> Value {
    let mut all = json!({"sub": "ann", "exp": now() + 600});
    if let (Some(all), Some(extra)) = (all.as_object_mut(), extra.as_object()) {
        all.extend(extra.clone());
    }
    all
}

fn site(host: &str, upstream: SocketAddr, config: &Value) -> Value {
    with_jwt_auth(
        app("a", &[host], &[serving("r1", upstream)]),
        config.clone(),
    )
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{response:?}");
}

fn rejection(response: &Response) -> Value {
    assert_eq!(response.status, 422, "{response:?}");
    response.json()["conflicts"][0].clone()
}

async fn bearer(podgate: &Podgate, host: &str, token: &str) -> Response {
    podgate
        .get_with_headers(host, "/", &[("Authorization", &format!("Bearer {token}"))])
        .await
}

fn assert_unauthorized(response: &Response) {
    assert_eq!(response.status, 401, "{response:?}");
    assert_eq!(response.header("www-authenticate"), Some(CHALLENGE));
    assert_eq!(response.body, r#"{"error":"unauthorized"}"#);
}

fn keys_config(signers: &[&Signer], algorithms: &[&str]) -> Value {
    json!({"keys": {"keys": signers.iter().map(|s| s.jwk()).collect::<Vec<_>>()},
           "algorithms": algorithms})
}

fn with(config: &Value, extra: &Value) -> Value {
    let mut all = config.clone();
    if let (Some(all), Some(extra)) = (all.as_object_mut(), extra.as_object()) {
        all.extend(extra.clone());
    }
    all
}

#[tokio::test]
async fn jwt_rs256_accepted_over_http() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let (rs, ps, es, ed) = (
        Signer::rsa_a("rs"),
        Signer::rsa_b("ps"),
        Signer::es256("es"),
        Signer::ed25519("ed"),
    );
    let config = keys_config(&[&rs, &ps, &es, &ed], &["RS256", "PS256", "ES256", "EdDSA"]);
    push(&podgate, &snapshot(1, &[site("a.test", up.addr, &config)])).await;

    for (signer, alg) in [
        (&rs, "RS256"),
        (&ps, "PS256"),
        (&es, "ES256"),
        (&ed, "EdDSA"),
    ] {
        let token = signer.sign(alg, &json!({}), &claims(&json!({})));
        let answer = bearer(&podgate, "a.test", &token).await;
        assert_eq!(answer.status, 200, "{alg}: {answer:?}");
    }
    assert_eq!(up.requests(), 4);

    // A signature by another key under the same kid, a key of another type under the kid.
    let impostor = Signer::rsa_b("rs").sign("RS256", &json!({}), &claims(&json!({})));
    assert_unauthorized(&bearer(&podgate, "a.test", &impostor).await);
    let wrong_type = es.sign_with_kid("ES256", Some("rs"), &json!({}), &claims(&json!({})));
    assert_unauthorized(&bearer(&podgate, "a.test", &wrong_type).await);
    let unknown_kid = es.sign_with_kid("ES256", Some("nobody"), &json!({}), &claims(&json!({})));
    assert_unauthorized(&bearer(&podgate, "a.test", &unknown_kid).await);
    assert_unauthorized(&podgate.get("a.test", "/").await);
    assert_unauthorized(&bearer(&podgate, "a.test", "not-a-token").await);
    assert_eq!(up.requests(), 4, "no refused request reached the upstream");
}

#[tokio::test]
async fn jwt_alg_none_rejected_over_http() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let (rsa, secret) = (Signer::rsa_a("rs"), Signer::hmac("shared", &[9; 48]));
    let config = keys_config(&[&rsa, &secret], &["RS256", "HS256"]);
    push(&podgate, &snapshot(1, &[site("a.test", up.addr, &config)])).await;

    let good = rsa.sign("RS256", &json!({}), &claims(&json!({})));
    assert_eq!(bearer(&podgate, "a.test", &good).await.status, 200);

    let jwk = rsa.jwk();
    let attacks = [
        unsigned("none", &claims(&json!({}))),
        unsigned("None", &claims(&json!({}))),
        unsigned("RS256", &claims(&json!({}))),
        // Not listed.
        rsa.sign("PS256", &json!({}), &claims(&json!({}))),
        rsa.sign("RS384", &json!({}), &claims(&json!({}))),
        // The classic confusion: HS256 with the RSA public key as the secret.
        forge_hmac("HS256", &rsa.public_der(), Some("rs"), &claims(&json!({}))),
        forge_hmac(
            "HS256",
            jwk.to_string().as_bytes(),
            None,
            &claims(&json!({})),
        ),
    ];
    for token in &attacks {
        assert_unauthorized(&bearer(&podgate, "a.test", token).await);
    }
    assert_eq!(up.requests(), 1);
}

#[tokio::test]
async fn jwt_expired_401_over_http() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let key = Signer::es256("k");
    let config = with(
        &keys_config(&[&key], &["ES256"]),
        &json!({"issuer": "https://idp.test", "audiences": ["api", "web"],
                "required_claims": {"role": ["admin", "ops"]}}),
    );
    push(&podgate, &snapshot(1, &[site("a.test", up.addr, &config)])).await;

    let good = json!({"iss": "https://idp.test", "aud": "web", "role": "ops"});
    let token = |extra: &Value| key.sign("ES256", &json!({}), &claims(&with(&good, extra)));
    assert_eq!(
        bearer(&podgate, "a.test", &token(&json!({}))).await.status,
        200
    );
    // Inside the 30 seconds of leeway.
    let recent = token(&json!({"exp": now() - 10}));
    assert_eq!(bearer(&podgate, "a.test", &recent).await.status, 200);

    for bad in [
        json!({"exp": now() - 120}),
        json!({"nbf": now() + 120}),
        json!({"iat": now() + 120}),
        json!({"iss": "https://evil.test"}),
        json!({"aud": "other"}),
        json!({"exp": "soon"}),
    ] {
        assert_unauthorized(&bearer(&podgate, "a.test", &token(&bad)).await);
    }
    let no_exp = key.sign(
        "ES256",
        &json!({}),
        &json!({"iss": "https://idp.test", "aud": "web", "role": "ops"}),
    );
    assert_unauthorized(&bearer(&podgate, "a.test", &no_exp).await);

    // A real credential that may not do this is a 403.
    let forbidden = bearer(&podgate, "a.test", &token(&json!({"role": "dev"}))).await;
    assert_eq!(forbidden.status, 403, "{forbidden:?}");
    assert_eq!(forbidden.body, r#"{"error":"forbidden"}"#);
    let missing = bearer(&podgate, "a.test", &token(&json!({"role": null}))).await;
    assert_eq!(missing.status, 403, "{missing:?}");
    // Even a crit header on an otherwise good token.
    let crit = key.sign("ES256", &json!({"crit": ["exp"]}), &claims(&good));
    assert_unauthorized(&bearer(&podgate, "a.test", &crit).await);
}

#[tokio::test]
async fn jwt_oversized_token_rejected_over_http() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let key = Signer::es256("k");
    push(
        &podgate,
        &snapshot(
            1,
            &[site("a.test", up.addr, &keys_config(&[&key], &["ES256"]))],
        ),
    )
    .await;
    let big = key.sign(
        "ES256",
        &json!({}),
        &claims(&json!({"pad": "a".repeat(9000)})),
    );
    assert!(big.len() > 8 * 1024);
    assert_unauthorized(&bearer(&podgate, "a.test", &big).await);
    assert_eq!(up.requests(), 0);
}

#[tokio::test]
async fn jwt_forward_claims_overwrite_client_headers() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let key = Signer::es256("k");
    let config = with(
        &keys_config(&[&key], &["ES256"]),
        &json!({"forward_claims": {"sub": "X-User", "role": "X-Role", "groups": "X-Groups",
                                   "nested": "X-Nested"}}),
    );
    push(&podgate, &snapshot(1, &[site("a.test", up.addr, &config)])).await;

    let token = key.sign(
        "ES256",
        &json!({}),
        &claims(&json!({"groups": ["a", "b"], "nested": {"x": 1}})),
    );
    let answer = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("Authorization", &format!("Bearer {token}")),
                ("X-User", "root"),
                ("X-Role", "admin"),
                ("X-Nested", "forged"),
                ("X-Groups", "forged"),
            ],
        )
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(header_of(&answer.body, "x-user"), Some("ann"));
    assert_eq!(header_of(&answer.body, "x-groups"), Some("a, b"));
    // The claim the token lacks, and the one that cannot be a header, leave nothing of the client's.
    assert_eq!(header_of(&answer.body, "x-role"), None, "{}", answer.body);
    assert_eq!(header_of(&answer.body, "x-nested"), None, "{}", answer.body);

    // A refused request reaches nobody, whatever it carries.
    let refused = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[("Authorization", "Bearer nope"), ("X-User", "root")],
        )
        .await;
    assert_unauthorized(&refused);
    assert_eq!(up.requests(), 1);
}

#[tokio::test]
async fn jwt_remove_token() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let key = Signer::es256("k");
    let sources = json!({"token_sources": [
        {"header": "authorization", "scheme": "Bearer"},
        {"cookie": "session"},
        {"query": "access_token"},
    ]});
    let kept = with(&keys_config(&[&key], &["ES256"]), &sources);
    let removed = with(&kept, &json!({"remove_token": true}));
    let mut b = site("b.test", up.addr, &kept);
    b["id"] = json!("b");
    push(
        &podgate,
        &snapshot(1, &[site("a.test", up.addr, &removed), b]),
    )
    .await;
    let token = key.sign("ES256", &json!({}), &claims(&json!({})));

    // Header.
    let answer = bearer(&podgate, "a.test", &token).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(
        header_of(&answer.body, "authorization"),
        None,
        "{}",
        answer.body
    );
    // Cookie: the others stay.
    let answer = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[("Cookie", &format!("theme=dark; session={token}; lang=en"))],
        )
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(
        header_of(&answer.body, "cookie"),
        Some("theme=dark; lang=en")
    );
    let only = podgate
        .get_with_headers("a.test", "/", &[("Cookie", &format!("session={token}"))])
        .await;
    assert_eq!(only.status, 200, "{only:?}");
    assert_eq!(header_of(&only.body, "cookie"), None, "{}", only.body);
    // Query: the others stay, in order.
    let answer = podgate
        .get("a.test", &format!("/p?x=1&access_token={token}&y=2"))
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert!(
        answer.body.starts_with("GET /p?x=1&y=2 HTTP/1.1"),
        "{}",
        answer.body
    );
    let answer = podgate
        .get("a.test", &format!("/p?access_token={token}"))
        .await;
    assert!(
        answer.body.starts_with("GET /p HTTP/1.1"),
        "{}",
        answer.body
    );

    // Without the setting the credential goes on.
    let answer = bearer(&podgate, "b.test", &token).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(
        header_of(&answer.body, "authorization"),
        Some(format!("Bearer {token}").as_str())
    );
    // The same token twice (header and cookie) is not guessed at.
    let twice = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("Authorization", &format!("Bearer {token}")),
                ("Authorization", &format!("Bearer {token}")),
            ],
        )
        .await;
    assert_unauthorized(&twice);
}

#[tokio::test]
async fn jwt_before_admission() {
    let podgate = Podgate::start().await;
    let up = Server::start(|head| {
        if head.starts_with("GET /slow ") {
            Reply::Delay(Duration::from_millis(900), raw(200, &[], "slow"))
        } else {
            http(200, &[], "fast")
        }
    })
    .await;
    let key = Signer::es256("k");
    let mut pushed = snapshot(
        1,
        &[site("a.test", up.addr, &keys_config(&[&key], &["ES256"]))],
    );
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(1);
    push(&podgate, &pushed).await;
    let token = key.sign("ES256", &json!({}), &claims(&json!({})));
    let header = format!("Bearer {token}");

    let authorization = [("Authorization", header.as_str())];
    let (held, others) = tokio::join!(
        podgate.get_with_headers("a.test", "/slow", &authorization),
        async {
            sleep(Duration::from_millis(300)).await;
            let anonymous = podgate.get("a.test", "/other").await;
            let forged = bearer(&podgate, "a.test", "x.y.z").await;
            // The slot is taken: a valid request is turned away for capacity...
            let valid = podgate
                .get_with_headers("a.test", "/other", &authorization)
                .await;
            (anonymous, forged, valid)
        }
    );
    assert_eq!(held.status, 200, "{held:?}");
    // ...and a refused one is answered by the middleware, untouched by the tenant's limit.
    assert_unauthorized(&others.0);
    assert_unauthorized(&others.1);
    assert_eq!(others.2.status, 503, "{:?}", others.2);
    assert_eq!(others.2.header("retry-after"), Some("1"));
}

#[tokio::test]
async fn jwt_verified_request_bypasses_cache() {
    let podgate = Podgate::start().await;
    // The page depends on who is asking and says it may be shared.
    let up = Server::start(|head| {
        let user = header_of(head, "x-user").unwrap_or("anonymous");
        http(
            200,
            &[("Cache-Control", "public, max-age=60")],
            &format!("page for {user}"),
        )
    })
    .await;
    let key = Signer::es256("k");
    let base = with(
        &keys_config(&[&key], &["ES256"]),
        &json!({"remove_token": true, "forward_claims": {"sub": "X-User"}}),
    );
    let cached = |id: &str, host: &str, extra: &Value| {
        let guarded = with_jwt_auth(
            app(id, &[host], &[serving("r1", up.addr)]),
            with(&base, extra),
        );
        with_middleware(guarded, "c", "cache", json!({}))
    };
    push(
        &podgate,
        &snapshot(
            1,
            &[
                cached("h", "h.test", &json!({})),
                cached("q", "q.test", &json!({"token_sources": [{"query": "t"}]})),
                cached(
                    "k",
                    "k.test",
                    &json!({"token_sources": [{"cookie": "jwt"}]}),
                ),
            ],
        ),
    )
    .await;
    let token = |sub: &str| key.sign("ES256", &json!({}), &claims(&json!({"sub": sub})));

    let mut expected_upstream = 0;
    for (host, how) in [
        ("h.test", "header"),
        ("q.test", "query"),
        ("k.test", "cookie"),
    ] {
        let ask = |sub: &str| {
            let token = token(sub);
            let podgate = &podgate;
            async move {
                match how {
                    "header" => {
                        podgate
                            .get_with_headers(
                                host,
                                "/page",
                                &[("Authorization", &format!("Bearer {token}"))],
                            )
                            .await
                    }
                    "query" => podgate.get(host, &format!("/page?t={token}")).await,
                    _ => {
                        podgate
                            .get_with_headers(host, "/page", &[("Cookie", &format!("jwt={token}"))])
                            .await
                    }
                }
            }
        };
        let first = ask("a").await;
        assert_eq!(
            (first.status, first.body.as_str()),
            (200, "page for a"),
            "{how}: {first:?}"
        );
        assert_eq!(
            first.header("cache-status"),
            Some("podgate; bypass"),
            "{how}: {first:?}"
        );
        let second = ask("b").await;
        assert_eq!(
            (second.status, second.body.as_str()),
            (200, "page for b"),
            "{how}: {second:?}"
        );
        assert_eq!(
            second.header("cache-status"),
            Some("podgate; bypass"),
            "{how}: {second:?}"
        );
        expected_upstream += 2;
        assert_eq!(
            up.requests(),
            expected_upstream,
            "{how}: both requests reached the upstream"
        );
    }
}

#[tokio::test]
async fn jwt_invalid_config_rejected_by_snapshot() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let key = Signer::es256("k");
    let good = keys_config(&[&key], &["ES256"]);
    let rsa = Signer::rsa_a("r").jwk();
    let mut weak = rsa.clone();
    weak["n"] = json!("AQAB");
    let mut private = key.jwk();
    private["d"] = json!("AQAB");
    let cases: Vec<(Value, &str)> = vec![
        (json!({"keys": good["keys"]}), "no algorithms"),
        (with(&good, &json!({"algorithms": []})), "empty algorithms"),
        (with(&good, &json!({"algorithms": ["none"]})), "none"),
        (
            with(&good, &json!({"algorithms": ["ES256", "HS256"]})),
            "hs without an oct key",
        ),
        (
            with(
                &good,
                &json!({"algorithms": ["RS256", "RS384", "RS512", "PS256", "PS384"]}),
            ),
            "five rsa algorithms",
        ),
        (json!({"algorithms": ["ES256"]}), "no keys and no jwks_uri"),
        (with(&good, &json!({"jwks_uri": "not a url"})), "bad url"),
        (
            with(&good, &json!({"jwks_uri": "https://-bad-.example/jwks"})),
            "a bad host name",
        ),
        (
            with(&good, &json!({"jwks_uri": "h2c://10.0.0.5/jwks"})),
            "h2c",
        ),
        (with(&good, &json!({"leeway_secs": 301})), "leeway"),
        (with(&good, &json!({"unknown_field": 1})), "unknown field"),
        (
            with(
                &good,
                &json!({"token_sources": [{"header": "x", "cookie": "y"}]}),
            ),
            "two kinds",
        ),
        (
            with(&good, &json!({"forward_claims": {"sub": "Authorization"}})),
            "claim into authorization",
        ),
        (
            with(&good, &json!({"transport": "nope"})),
            "transport without jwks_uri",
        ),
        (
            json!({"algorithms": ["RS256"], "keys": {"keys": [weak]}}),
            "weak rsa key",
        ),
        (
            json!({"algorithms": ["ES256"], "keys": {"keys": [private]}}),
            "private key",
        ),
    ];
    for (n, (config, what)) in cases.iter().enumerate() {
        let pushed = push_status(&podgate, 10 + n as u64, &site("a.test", up.addr, config)).await;
        assert_eq!(
            rejection(&pushed)["code"],
            "invalid_middleware",
            "{what}: {}",
            pushed.body
        );
    }
    // An undeclared transport is its own code.
    let pushed = push_status(
        &podgate,
        100,
        &site(
            "a.test",
            up.addr,
            &with(
                &good,
                &json!({"jwks_uri": "http://10.0.0.5/jwks", "transport": "nope"}),
            ),
        ),
    )
    .await;
    assert_eq!(rejection(&pushed)["code"], "unknown_transport");
    push(&podgate, &snapshot(200, &[site("a.test", up.addr, &good)])).await;
}

async fn push_status(podgate: &Podgate, version: u64, app: &Value) -> Response {
    podgate
        .push_snapshot(&snapshot(version, std::slice::from_ref(app)))
        .await
}

#[tokio::test]
async fn plan_lists_jwt_auth_changes() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let (a, b) = (Signer::es256("a"), Signer::es256("b"));
    let base = with(
        &keys_config(&[&a], &["ES256"]),
        &json!({"issuer": "https://idp.test", "audiences": ["api"], "leeway_secs": 30,
                "max_token_age_secs": 60, "required_claims": {"role": ["admin"]}}),
    );
    push(&podgate, &snapshot(1, &[site("a.test", up.addr, &base)])).await;

    let kinds = |plan: &Response| -> Vec<String> {
        assert_eq!(plan.status, 200, "{}", plan.body);
        plan.json()["posture_changes"]
            .as_array()
            .expect("list")
            .iter()
            .map(|change| change["kind"].as_str().expect("kind").to_owned())
            .collect()
    };
    let plan = |config: &Value| {
        let pushed = snapshot(2, &[site("a.test", up.addr, config)]);
        let podgate = &podgate;
        async move { kinds(&podgate.admin_post("/v1/snapshot/plan", &pushed).await) }
    };
    let removed = snapshot(2, &[app("a", &["a.test"], &[serving("r1", up.addr)])]);
    assert_eq!(
        kinds(&podgate.admin_post("/v1/snapshot/plan", &removed).await),
        ["jwt_auth_removed"]
    );
    for (change, kind) in [
        (
            json!({"algorithms": ["ES256", "ES384"]}),
            "jwt_auth_algorithm_added",
        ),
        (
            json!({"required_claims": {}}),
            "jwt_auth_required_claims_loosened",
        ),
        (
            json!({"required_claims": {"role": ["admin", "ops"]}}),
            "jwt_auth_required_claims_loosened",
        ),
        (json!({"leeway_secs": 31}), "jwt_auth_leeway_increased"),
        (json!({"issuer": null}), "jwt_auth_issuer_loosened"),
        (
            json!({"issuer": "https://other.test"}),
            "jwt_auth_issuer_loosened",
        ),
        (json!({"audiences": []}), "jwt_auth_audience_loosened"),
        (
            json!({"audiences": ["api", "web"]}),
            "jwt_auth_audience_loosened",
        ),
        (
            json!({"max_token_age_secs": null}),
            "jwt_auth_max_token_age_loosened",
        ),
        (
            json!({"max_token_age_secs": 61}),
            "jwt_auth_max_token_age_loosened",
        ),
        (
            json!({"keys": {"keys": [a.jwk(), b.jwk()]}}),
            "jwt_auth_key_added",
        ),
        (
            json!({"jwks_uri": "https://10.0.0.5/jwks"}),
            "jwt_auth_key_added",
        ),
        (
            json!({"token_sources": [{"header": "authorization"}, {"query": "t"}]}),
            "jwt_auth_token_source_added",
        ),
    ] {
        let mut config = base.clone();
        for (field, value) in change.as_object().expect("object") {
            if value.is_null() {
                config.as_object_mut().expect("object").remove(field);
            } else {
                config[field] = value.clone();
            }
        }
        assert_eq!(plan(&config).await, [kind], "{change}");
    }
    // Tightening is not listed.
    let tighter = with(
        &base,
        &json!({"leeway_secs": 5, "max_token_age_secs": 30, "audiences": ["api"],
                "required_claims": {"role": ["admin"], "tier": 1}}),
    );
    assert_eq!(plan(&tighter).await, Vec::<String>::new());
    // Nothing was applied.
    assert_eq!(
        podgate.admin_get("/v1/snapshot/version").await.json()["version"],
        1
    );
}

#[tokio::test]
async fn jwks_fetch_serves_keys_and_kid_miss_refresh_rate_limited_over_http() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let (a, b, c) = (Signer::es256("a"), Signer::es256("b"), Signer::es256("c"));
    let (jwks, answer) = jwks_endpoint(&[&a]).await;
    let config = json!({"jwks_uri": format!("http://{}/jwks", jwks.addr), "algorithms": ["ES256"]});
    push(&podgate, &snapshot(1, &[site("a.test", up.addr, &config)])).await;
    let token = |signer: &Signer| signer.sign("ES256", &json!({}), &claims(&json!({})));

    // One fetch serves every request while the set is fresh.
    for _ in 0..3 {
        assert_eq!(bearer(&podgate, "a.test", &token(&a)).await.status, 200);
    }
    assert_eq!(jwks.requests(), 1);
    let head = &jwks.heads()[0];
    assert!(head.starts_with("GET /jwks HTTP/1.1"), "{head}");

    // The endpoint rotated: a token with the new kid refreshes the set once.
    *answer.lock().expect("jwks") = (200, jwks_of(&[&a, &b]));
    assert_eq!(bearer(&podgate, "a.test", &token(&b)).await.status, 200);
    assert_eq!(jwks.requests(), 2);
    // An unknown kid right after does not fetch again.
    assert_unauthorized(&bearer(&podgate, "a.test", &token(&c)).await);
    assert_unauthorized(&bearer(&podgate, "a.test", &token(&c)).await);
    assert_eq!(jwks.requests(), 2, "kid misses are rate limited");
    assert_eq!(bearer(&podgate, "a.test", &token(&a)).await.status, 200);
}

#[tokio::test]
async fn jwks_stale_on_error_keeps_serving() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let (a, other) = (Signer::es256("a"), Signer::es256("zzz"));
    let (jwks, answer) = jwks_endpoint(&[&a]).await;
    let config = json!({"jwks_uri": format!("http://{}/jwks", jwks.addr), "algorithms": ["ES256"]});
    push(&podgate, &snapshot(1, &[site("a.test", up.addr, &config)])).await;
    let token = |signer: &Signer| signer.sign("ES256", &json!({}), &claims(&json!({})));
    assert_eq!(bearer(&podgate, "a.test", &token(&a)).await.status, 200);

    // The endpoint breaks. The refresh a new kid asks for fails, and the old keys stay.
    *answer.lock().expect("jwks") = (500, "down".to_owned());
    assert_unauthorized(&bearer(&podgate, "a.test", &token(&other)).await);
    assert_eq!(jwks.requests(), 2);
    assert_eq!(bearer(&podgate, "a.test", &token(&a)).await.status, 200);
    // A set of nothing usable is a failure too: the keys stay.
    *answer.lock().expect("jwks") = (200, r#"{"keys": []}"#.to_owned());
    assert_eq!(bearer(&podgate, "a.test", &token(&a)).await.status, 200);
}

#[tokio::test]
async fn jwks_unreachable_no_cache_503_over_http() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let dead = refused();
    let key = Signer::es256("k");
    let config = json!({"jwks_uri": format!("http://{}/jwks", dead.addr), "algorithms": ["ES256"]});
    push(&podgate, &snapshot(1, &[site("a.test", up.addr, &config)])).await;
    let token = key.sign("ES256", &json!({}), &claims(&json!({})));
    for _ in 0..2 {
        let answer = bearer(&podgate, "a.test", &token).await;
        assert_eq!(answer.status, 503, "{answer:?}");
        assert_eq!(answer.body, r#"{"error":"authentication unavailable"}"#);
    }
    // No token is still a 401: there is nothing to check keys for.
    assert_unauthorized(&podgate.get("a.test", "/").await);
    assert_eq!(up.requests(), 0);
}

/// A TLS server that answers every request with `body`, on a certificate for `cert`.
async fn tls_jwks(cert: &TestCert, body: String) -> SocketAddr {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .expect("chain");
    let key = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).expect("key");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, body) = (acceptor.clone(), body.clone());
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&chunk[..read]),
                    }
                }
                drop(stream.write_all(&raw(200, &[], &body)).await);
                drop(stream.shutdown().await);
            });
        }
    });
    addr
}

#[tokio::test]
async fn jwks_uses_transport_tls() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let key = Signer::es256("k");
    let cert = TestCert::new(&["127.0.0.1", "jwks.internal"]);
    let addr = tls_jwks(&cert, jwks_of(&[&key])).await;
    let transports = json!([{
        "name": "t", "type": "servers_transport", "server_name": "jwks.internal",
        "ca_pem": cert.cert_pem,
    }]);
    let with_transport = |id: &str, host: &str, transport: bool| {
        let mut config =
            json!({"jwks_uri": format!("https://{addr}/jwks"), "algorithms": ["ES256"]});
        if transport {
            config["transport"] = json!("t");
        }
        let mut app = app(id, &[host], &[serving("r1", up.addr)]);
        app["transports"] = transports.clone();
        with_jwt_auth(app, config)
    };
    push(
        &podgate,
        &snapshot(
            1,
            &[
                with_transport("a", "a.test", true),
                with_transport("b", "b.test", false),
            ],
        ),
    )
    .await;
    let token = key.sign("ES256", &json!({}), &claims(&json!({})));

    // The private CA and the server name of the named transport.
    assert_eq!(bearer(&podgate, "a.test", &token).await.status, 200);
    // No transport: only the platform roots are trusted, the handshake fails, no keys: closed.
    let closed = bearer(&podgate, "b.test", &token).await;
    assert_eq!(closed.status, 503, "{closed:?}");

    // A transport on a plain address is refused: a setting is never silently unused.
    let mut plain = with_transport("c", "c.test", true);
    plain["middlewares"][0]["jwks_uri"] = json!(format!("http://{addr}/jwks"));
    let refused = podgate.push_snapshot(&snapshot(2, &[plain])).await;
    assert_eq!(rejection(&refused)["code"], "invalid_middleware");
}

#[tokio::test]
async fn jwks_named_uri_dials_checked_ip() {
    let dns = common::dns::Dns::start().await;
    let policy = PolicyFile::write(r#"{"deny": ["10.9.0.0/16"]}"#);
    let podgate = Podgate::start_with_env(&[
        ("DNS_SERVERS", &dns.servers()),
        ("DNS_TIMEOUT_MS", "1000"),
        ("UPSTREAM_POLICY_FILE", policy.path.to_str().expect("utf-8")),
    ])
    .await;
    let up = echo().await;
    let key = Signer::es256("k");
    let (jwks, _) = jwks_endpoint(&[&key]).await;
    let port = jwks.addr.port();
    dns.set("jwks.internal", &["127.0.0.1"], 30);
    dns.set("rebind.internal", &["10.9.0.1"], 30);
    let named = |id: &str, host: &str, name: &str| {
        with_jwt_auth(
            app(id, &[host], &[serving("r1", up.addr)]),
            json!({"jwks_uri": format!("http://{name}:{port}/jwks"), "algorithms": ["ES256"]}),
        )
    };
    let apps = [
        named("a", "a.test", "jwks.internal"),
        named("b", "b.test", "rebind.internal"),
        named("c", "c.test", "missing.internal"),
    ];
    push(&podgate, &snapshot(1, &apps)).await;
    let token = key.sign("ES256", &json!({}), &claims(&json!({})));

    // Resolved once for the fetch, dialled at the permitted address, the name is the Host.
    assert_eq!(bearer(&podgate, "a.test", &token).await.status, 200);
    assert_eq!(
        header_of(&jwks.heads()[0], "host"),
        Some(format!("jwks.internal:{port}").as_str())
    );
    assert_eq!(dns.queries_for("jwks.internal"), 2);
    // The keys are cached: no second fetch, no second resolution.
    assert_eq!(bearer(&podgate, "a.test", &token).await.status, 200);
    assert_eq!(jwks.requests(), 1);
    assert_eq!(dns.queries_for("jwks.internal"), 2);

    // A name that answers a denied address, or none, gives no keys: closed.
    for host in ["b.test", "c.test"] {
        let closed = bearer(&podgate, host, &token).await;
        assert_eq!(closed.status, 503, "{host}: {closed:?}");
    }
    assert_eq!(jwks.requests(), 1, "nothing was dialled for them");
}

/// A policy file in its own temp directory, removed on drop.
struct PolicyFile {
    dir: PathBuf,
    path: PathBuf,
}

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-jwt-policy-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("policy.json");
        std::fs::write(&path, contents).expect("write policy file");
        Self { dir, path }
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

#[tokio::test]
async fn jwks_loopback_refused_at_compile() {
    // `{}` is the built-in policy: loopback, link-local and the metadata address are denied.
    let policy = PolicyFile::write("{}");
    let podgate =
        Podgate::start_with_env(&[("UPSTREAM_POLICY_FILE", policy.path.to_str().expect("utf-8"))])
            .await;
    let up = echo().await;
    let key = Signer::es256("k");
    for (n, uri) in [
        "http://127.0.0.1:9/jwks",
        "https://[::1]/jwks",
        "http://169.254.169.254/jwks",
        "https://0.0.0.0/jwks",
    ]
    .into_iter()
    .enumerate()
    {
        let config = with(&keys_config(&[&key], &["ES256"]), &json!({"jwks_uri": uri}));
        let pushed = push_status(&podgate, 1 + n as u64, &site("a.test", up.addr, &config)).await;
        let entry = rejection(&pushed);
        assert_eq!(
            entry["code"], "upstream_forbidden",
            "{uri}: {}",
            pushed.body
        );
        assert_eq!(entry["app"], "a");
    }
    assert_eq!(
        podgate.admin_get("/v1/snapshot/version").await.json()["version"],
        0
    );
}

#[tokio::test]
async fn jwks_outside_allowlist_refused_at_compile() {
    let policy =
        PolicyFile::write(r#"{"deny": [], "tenants": {"t1": {"allow": ["10.4.0.0/16"]}}}"#);
    let podgate =
        Podgate::start_with_env(&[("UPSTREAM_POLICY_FILE", policy.path.to_str().expect("utf-8"))])
            .await;
    let up = echo().await;
    let key = Signer::es256("k");
    let compile = |uri: &str| {
        let config = with(&keys_config(&[&key], &["ES256"]), &json!({"jwks_uri": uri}));
        site("a.test", up.addr, &config)
    };
    // Plain http inside the tenant's list is fine at compile time, https too.
    // The server of the app itself is on loopback, outside the list: only the JWKS is judged here
    // because the revision's server would also be refused; use a revision inside the list.
    let inside = {
        let mut app = compile("http://10.4.0.5/jwks");
        app["revisions"][0]["services"][0]["servers"][0]["url"] = json!("http://10.4.0.9:80");
        app
    };
    let ok = push_status(&podgate, 1, &inside).await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    let mut outside = compile("https://10.9.0.5/jwks");
    outside["revisions"][0]["services"][0]["servers"][0]["url"] = json!("http://10.4.0.9:80");
    let refused = push_status(&podgate, 2, &outside).await;
    let entry = rejection(&refused);
    assert_eq!(entry["code"], "upstream_forbidden", "{}", refused.body);
    assert!(
        entry["message"]
            .as_str()
            .expect("message")
            .contains("jwks_uri"),
        "{entry}"
    );
}

#[tokio::test]
async fn jwks_uris_per_tenant_are_bounded() {
    let podgate = Podgate::start().await;
    let up = echo().await;
    let key = Signer::es256("k");
    let app_with = |n: usize| {
        let config = with(
            &keys_config(&[&key], &["ES256"]),
            &json!({"jwks_uri": format!("http://10.0.0.{}/jwks", n + 1)}),
        );
        let mut app = site(&format!("a{n}.test"), up.addr, &config);
        app["id"] = json!(format!("a{n}"));
        app
    };
    let eight: Vec<Value> = (0..8).map(app_with).collect();
    push(&podgate, &snapshot(1, &eight)).await;
    let nine: Vec<Value> = (0..9).map(app_with).collect();
    let refused = podgate.push_snapshot(&snapshot(2, &nine)).await;
    assert_eq!(
        rejection(&refused)["code"],
        "invalid_middleware",
        "{}",
        refused.body
    );
}

#[tokio::test]
async fn jwt_failures_reach_the_access_log_and_the_metrics() {
    let dir = PolicyFile::write("{}");
    let log_path = dir.dir.join("access.log");
    let podgate =
        Podgate::start_with_env(&[("ACCESS_LOG_FILE", log_path.to_str().expect("utf-8 path"))])
            .await;
    let up = echo().await;
    let key = Signer::es256("k");
    let mut pushed = snapshot(
        1,
        &[site("a.test", up.addr, &keys_config(&[&key], &["ES256"]))],
    );
    pushed["observability"] = json!({"access_log": true});
    push(&podgate, &pushed).await;
    let secret = key.sign("ES256", &json!({}), &claims(&json!({"exp": now() - 600})));
    assert_unauthorized(&bearer(&podgate, "a.test", &secret).await);
    let good = key.sign("ES256", &json!({}), &claims(&json!({})));
    assert_eq!(bearer(&podgate, "a.test", &good).await.status, 200);

    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metrics.contains(
            "podgate_jwt_auth_rejected_total{app=\"a\",middleware=\"jwt\",reason=\"jwt_expired\"} 1"
        ),
        "{metrics}"
    );
    assert!(
        metrics.contains("podgate_jwt_auth_verified_total{app=\"a\",middleware=\"jwt\"} 1"),
        "{metrics}"
    );
    // The access log names the reason and never holds the token.
    let mut log = String::new();
    for _ in 0..100 {
        log = std::fs::read_to_string(&log_path).unwrap_or_default();
        if log.lines().count() >= 2 {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(log.contains("jwt_expired"), "{log}");
    assert!(
        !log.contains(&secret) && !log.contains(&good),
        "the token is in the log"
    );
    assert!(
        !log.contains(&secret[..40]),
        "part of the token is in the log"
    );
}

#[tokio::test]
async fn mirror_drops_jwt_claims() {
    let podgate = Podgate::start().await;
    let (main, shadow) = (echo().await, echo().await);
    let key = Signer::es256("k");
    let site = |forward_credentials: bool| {
        let mirror = json!({
            "name": "m", "type": "mirroring", "service": "web",
            "mirrors": [{"service": "shadow", "percent": 100.0}],
            "forward_credentials": forward_credentials,
        });
        let revision = json!({"id": "r1", "state": "serving", "weight": 100,
            "services": [service("web", &[main.addr]), service("shadow", &[shadow.addr]), mirror]});
        let mut app = app("a", &["a.test"], &[revision]);
        app["routers"] = json!([router("default", json!({"host": ["a.test"]}), "m")]);
        // The token travels in a header of its own, which is not removed.
        with_jwt_auth(
            app,
            with(
                &keys_config(&[&key], &["ES256"]),
                &json!({"token_sources": [{"header": "x-api-token"}],
                        "forward_claims": {"sub": "X-User"}}),
            ),
        )
    };
    push(&podgate, &snapshot(1, &[site(false)])).await;
    let token = key.sign("ES256", &json!({}), &claims(&json!({})));
    let sent = [("X-Api-Token", token.as_str()), ("X-User", "forged")];
    let ask = || podgate.get_with_headers("a.test", "/", &sent);

    let answer = ask().await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(header_of(&answer.body, "x-user"), Some("ann"));
    assert_eq!(header_of(&answer.body, "x-api-token"), Some(token.as_str()));
    wait_for_requests(&shadow, 1).await;
    let copy = shadow.heads()[0].clone();
    assert!(
        header_of(&copy, "x-user").is_none() && header_of(&copy, "x-api-token").is_none(),
        "the identity and the token are credentials: {copy}"
    );

    // Meant to carry credentials: the copy gets both.
    push(&podgate, &snapshot(2, &[site(true)])).await;
    assert_eq!(ask().await.status, 200);
    wait_for_requests(&shadow, 2).await;
    let copy = shadow.heads()[1].clone();
    assert_eq!(header_of(&copy, "x-user"), Some("ann"), "{copy}");
    assert_eq!(
        header_of(&copy, "x-api-token"),
        Some(token.as_str()),
        "{copy}"
    );
}

async fn wait_for_requests(server: &Server, count: usize) {
    for _ in 0..100 {
        if server.requests() >= count {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "the mirror got {} requests, wanted {count}",
        server.requests()
    );
}

/// The app `a.test` whose router mirrors to a shadow server, behind `jwt_auth` with `config`.
fn mirrored_site(
    main: SocketAddr,
    shadow: SocketAddr,
    forward_credentials: bool,
    config: Value,
) -> Value {
    let mirror = json!({
        "name": "m", "type": "mirroring", "service": "web",
        "mirrors": [{"service": "shadow", "percent": 100.0}],
        "forward_credentials": forward_credentials,
    });
    let revision = json!({"id": "r1", "state": "serving", "weight": 100,
        "services": [service("web", &[main]), service("shadow", &[shadow]), mirror]});
    let mut app = app("a", &["a.test"], &[revision]);
    app["routers"] = json!([router("default", json!({"host": ["a.test"]}), "m")]);
    with_jwt_auth(app, config)
}

#[tokio::test]
async fn mirror_drops_jwt_query_token() {
    let podgate = Podgate::start().await;
    let (main, shadow) = (echo().await, echo().await);
    let key = Signer::es256("k");
    let config = with(
        &keys_config(&[&key], &["ES256"]),
        &json!({"token_sources": [{"query": "t"}]}),
    );
    push(
        &podgate,
        &snapshot(
            1,
            &[mirrored_site(main.addr, shadow.addr, false, config.clone())],
        ),
    )
    .await;
    let token = key.sign("ES256", &json!({}), &claims(&json!({})));
    let path = format!("/p?x=1&t={token}&y=2");

    let answer = podgate.get("a.test", &path).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert!(
        answer.body.starts_with(&format!("GET {path} HTTP/1.1")),
        "the main service gets the request as it was: {}",
        answer.body
    );
    wait_for_requests(&shadow, 1).await;
    let copy = shadow.heads()[0].clone();
    assert!(copy.starts_with("GET /p?x=1&y=2 HTTP/1.1"), "{copy}");
    assert!(!copy.contains(&token), "{copy}");

    // Meant to carry credentials: the copy keeps the URL as it is.
    push(
        &podgate,
        &snapshot(2, &[mirrored_site(main.addr, shadow.addr, true, config)]),
    )
    .await;
    assert_eq!(podgate.get("a.test", &path).await.status, 200);
    wait_for_requests(&shadow, 2).await;
    assert!(
        shadow.heads()[1].starts_with(&format!("GET {path} HTTP/1.1")),
        "{}",
        shadow.heads()[1]
    );
}
