//! The `oidc` middleware end to end against a fake identity provider: the login
//! redirect and its cookie, the callback and what it checks, the session cookie, the reserved
//! paths, the calls to the provider under the upstream address policy and the resolver, and what
//! never reaches a log. The pure rules (cookie sealing, the flow, the discovery document, the
//! configuration) are unit-tested in `src/middleware/oidc/` and `src/middleware/oidc.rs`; the
//! same test names appear there.
//!
//! The test is the browser: it follows the redirect by hand, answers for the provider through
//! [`Idp::grant`] and carries the cookies itself.

mod common;

#[path = "fixtures/jwt/signer.rs"]
mod signer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::dns::Dns;
use common::{
    Podgate, Response, app, router, service, serving, snapshot, with_middleware, with_oidc,
};
use serde_json::{Value, json};
use signer::{Signer, now, unsigned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::sleep;

const CLIENT: &str = "app1";
const SKEW: &str = "0123456789abcdef0123456789abcdef";
const FLOW_COOKIE: &str = "__Secure-podgate_oidc_flow";
const SESSION_COOKIE: &str = "__Host-podgate_oidc";
const CALLBACK: &str = "/_podgate/oidc/callback";
const HTML: [(&str, &str); 1] = [("Accept", "text/html")];

// ---------------------------------------------------------------------------------------------
// The fake identity provider
// ---------------------------------------------------------------------------------------------

/// What the token endpoint answers for a code.
enum Grant {
    /// An ID token signed with the provider's key over these claims.
    Claims(Value),
    /// This text as the ID token.
    Token(String),
}

/// One request the provider got.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    head: String,
    body: String,
}

struct IdpState {
    /// The issuer and the prefix of every endpoint.
    base: String,
    /// The `issuer` the discovery document says.
    doc_issuer: Mutex<String>,
    /// The `token_endpoint` the discovery document says, when it is not `<base>/token`.
    token_endpoint: Mutex<Option<String>>,
    key: Signer,
    grants: Mutex<HashMap<String, Grant>>,
    seen: Mutex<Vec<Seen>>,
    /// Every endpoint answers `503`.
    down: AtomicBool,
    /// How long the token endpoint takes.
    token_delay_ms: AtomicU64,
    live: AtomicUsize,
    peak: AtomicUsize,
}

struct Idp {
    base: String,
    addr: SocketAddr,
    state: Arc<IdpState>,
}

fn http(status: u16, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
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

/// Reads one request: its head, and its body as far as `Content-Length` says.
async fn read_request(stream: &mut TcpStream) -> Option<Seen> {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    let end = loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&seen[..end]).into_owned();
    let length: usize = header_of(&head, "content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    while seen.len() < end + length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
    let body = String::from_utf8_lossy(&seen[end..end + length]).into_owned();
    let mut first = head.split(' ');
    let (method, path) = (
        first.next().unwrap_or_default().to_owned(),
        first.next().unwrap_or_default().to_owned(),
    );
    Some(Seen {
        method,
        path,
        head,
        body,
    })
}

fn header_of<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(": ")?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

async fn idp_serve(mut stream: TcpStream, state: Arc<IdpState>) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    state.seen.lock().expect("seen").push(request.clone());
    let answer = if state.down.load(Ordering::SeqCst) {
        http(503, &[], "down")
    } else {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/.well-known/openid-configuration") => {
                let base = &state.base;
                let token = state
                    .token_endpoint
                    .lock()
                    .expect("token")
                    .clone()
                    .unwrap_or_else(|| format!("{base}/token"));
                let doc = json!({
                    "issuer": *state.doc_issuer.lock().expect("issuer"),
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": token,
                    "jwks_uri": format!("{base}/jwks"),
                    "code_challenge_methods_supported": ["S256"],
                });
                http(
                    200,
                    &[("Content-Type", "application/json")],
                    &doc.to_string(),
                )
            }
            ("GET", "/jwks") => {
                let keys = json!({"keys": [state.key.jwk()]});
                http(
                    200,
                    &[("Content-Type", "application/json")],
                    &keys.to_string(),
                )
            }
            ("POST", "/token") => token(&state, &request).await,
            _ => http(404, &[], "not found"),
        }
    };
    drop(stream.write_all(&answer).await);
    drop(stream.shutdown().await);
}

async fn token(state: &IdpState, request: &Seen) -> Vec<u8> {
    let live = state.live.fetch_add(1, Ordering::SeqCst) + 1;
    state.peak.fetch_max(live, Ordering::SeqCst);
    sleep(Duration::from_millis(
        state.token_delay_ms.load(Ordering::SeqCst),
    ))
    .await;
    let form: HashMap<String, String> = form_urlencoded::parse(request.body.as_bytes())
        .into_owned()
        .collect();
    let code = form.get("code").cloned().unwrap_or_default();
    let answer = match state.grants.lock().expect("grants").get(&code) {
        Some(Grant::Claims(claims)) => {
            let id_token = state.key.sign("ES256", &json!({}), claims);
            http(
                200,
                &[("Content-Type", "application/json")],
                &json!({"id_token": id_token, "access_token": "PLANT-access-token", "token_type": "Bearer"})
                    .to_string(),
            )
        }
        Some(Grant::Token(id_token)) => http(
            200,
            &[("Content-Type", "application/json")],
            &json!({"id_token": id_token}).to_string(),
        ),
        None => http(400, &[], r#"{"error":"invalid_grant"}"#),
    };
    state.live.fetch_sub(1, Ordering::SeqCst);
    answer
}

impl Idp {
    /// A provider whose URLs name `host` (an IP literal, or a name a test DNS answers).
    async fn start_at(host: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let base = format!("http://{host}:{}", addr.port());
        let state = Arc::new(IdpState {
            base: base.clone(),
            doc_issuer: Mutex::new(base.clone()),
            token_endpoint: Mutex::new(None),
            key: Signer::es256("idp-key"),
            grants: Mutex::new(HashMap::new()),
            seen: Mutex::new(Vec::new()),
            down: AtomicBool::new(false),
            token_delay_ms: AtomicU64::new(0),
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        });
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(idp_serve(stream, Arc::clone(&shared)));
            }
        });
        Self { base, addr, state }
    }

    async fn start() -> Self {
        Self::start_at("127.0.0.1").await
    }

    /// The claims of an ID token for `nonce`; `extra` overrides.
    fn claims(&self, nonce: &str, extra: &Value) -> Value {
        let mut all = json!({
            "iss": self.base, "aud": CLIENT, "sub": "ann", "nonce": nonce,
            "exp": now() + 600, "iat": now(),
        });
        if let (Some(all), Some(extra)) = (all.as_object_mut(), extra.as_object()) {
            all.extend(extra.clone());
        }
        all
    }

    fn grant(&self, code: &str, claims: Value) {
        self.state
            .grants
            .lock()
            .expect("grants")
            .insert(code.to_owned(), Grant::Claims(claims));
    }

    /// Everything the provider was asked, in order.
    fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().expect("seen").clone()
    }

    fn asked(&self, method: &str, path: &str) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|seen| seen.method == method && seen.path == path)
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------
// The upstream
// ---------------------------------------------------------------------------------------------

/// The app's upstream: answers with the head of the request it got, so a test sees exactly what
/// reached it. A path `/slow` takes 900 ms, `/boom` is a `500`.
struct Up {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Up {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&heads);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    recorded.lock().expect("heads").push(request.head.clone());
                    if request.path == "/slow" {
                        sleep(Duration::from_millis(900)).await;
                    }
                    let answer = if request.path == "/boom" {
                        http(500, &[], "boom")
                    } else {
                        http(200, &[], &request.head)
                    };
                    drop(stream.write_all(&answer).await);
                    drop(stream.shutdown().await);
                });
            }
        });
        Self { addr, heads }
    }

    fn requests(&self) -> usize {
        self.heads.lock().expect("heads").len()
    }
}

// ---------------------------------------------------------------------------------------------
// The browser
// ---------------------------------------------------------------------------------------------

fn with(config: &Value, extra: &Value) -> Value {
    let mut all = config.clone();
    if let (Some(all), Some(extra)) = (all.as_object_mut(), extra.as_object()) {
        all.extend(extra.clone());
    }
    all
}

/// The configuration of the middleware at `idp`.
fn config(idp: &Idp, extra: &Value) -> Value {
    with(
        &json!({"issuer": idp.base, "client_id": CLIENT, "allowed_algorithms": ["ES256"]}),
        extra,
    )
}

fn site(id: &str, host: &str, up: &Up, config: &Value) -> Value {
    with_oidc(app(id, &[host], &[serving("r1", up.addr)]), config.clone())
}

/// A snapshot of `apps` that has the `skew_secret` an `oidc` middleware needs.
fn pushed(version: u64, apps: &[Value]) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["skew_secret"] = json!(SKEW);
    // The test browser speaks plain HTTP: say that TLS ends in front of the entry point.
    pushed["entry_points"] =
        json!([{"name": "web", "forwarded_headers": {"trusted_ips": ["127.0.0.0/8"]}}]);
    pushed
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{response:?}");
}

/// The test browser talks plain http to an entry point that trusts the loopback proxy, which says
/// it terminated TLS: the flow runs only over https.
const TLS: (&str, &str) = ("X-Forwarded-Proto", "https");

async fn h(podgate: &Podgate, host: &str, path: &str, headers: &[(&str, &str)]) -> Response {
    let mut all = headers.to_vec();
    all.push(TLS);
    Podgate::get_with_headers(podgate, host, path, &all).await
}

async fn h0(podgate: &Podgate, host: &str, path: &str) -> Response {
    h(podgate, host, path, &[]).await
}

async fn hr(
    podgate: &Podgate,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Response {
    let mut all = headers.to_vec();
    all.push(TLS);
    Podgate::request(podgate, method, host, path, &all).await
}

#[tokio::test]
async fn oidc_plain_request_without_trusted_https_refused() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;
    for path in ["/", "/_podgate/oidc/callback?code=x&state=y"] {
        let plain = Podgate::get_with_headers(&podgate, "a.test", path, &HTML).await;
        assert_eq!(
            (plain.status, plain.body.as_str()),
            (400, r#"{"error":"oidc requires https"}"#),
            "{plain:?}"
        );
        assert!(set_cookies(&plain).is_empty() && plain.header("location").is_none());
    }
    assert!(idp.seen().is_empty() && up.requests() == 0);
}

fn rejection(response: &Response) -> Value {
    assert_eq!(response.status, 422, "{response:?}");
    response.json()["conflicts"][0].clone()
}

fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .map(|(_, value)| value.clone())
        .collect()
}

/// The `name=value` a browser sends back for `set_cookie`.
fn pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap_or_default().to_owned()
}

fn cookie_named(response: &Response, name: &str) -> Option<String> {
    set_cookies(response)
        .into_iter()
        .find(|cookie| cookie.starts_with(&format!("{name}=")))
}

fn query_of(url: &str) -> HashMap<String, String> {
    let query = url.split_once('?').map_or("", |(_, query)| query);
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

/// A login that has been sent to the provider.
struct Login {
    location: String,
    state: String,
    nonce: String,
    challenge: String,
    flow_cookie: String,
}

/// Asks for `path` as a browser does, expects the redirect to the provider and reads it.
async fn begin(podgate: &Podgate, host: &str, path: &str) -> Login {
    let response = h(podgate, host, path, &HTML).await;
    assert_eq!(response.status, 302, "{response:?}");
    let location = response.header("location").expect("location").to_owned();
    let query = query_of(&location);
    Login {
        state: query["state"].clone(),
        nonce: query["nonce"].clone(),
        challenge: query["code_challenge"].clone(),
        flow_cookie: cookie_named(&response, FLOW_COOKIE).expect("a flow cookie"),
        location,
    }
}

/// The browser comes back to the callback with `code` and the flow cookie.
async fn callback(podgate: &Podgate, host: &str, login: &Login, code: &str) -> Response {
    let target = format!("{CALLBACK}?code={code}&state={}", login.state);
    let cookie = pair(&login.flow_cookie);
    h(podgate, host, &target, &[("Cookie", cookie.as_str())]).await
}

/// A complete login of `ann`: the `name=value` of the session cookie it earned.
async fn sign_in(podgate: &Podgate, idp: &Idp, host: &str, extra: &Value) -> String {
    static CODES: AtomicU32 = AtomicU32::new(0);
    let login = begin(podgate, host, "/start?x=1").await;
    let code = format!("code-{}", CODES.fetch_add(1, Ordering::SeqCst));
    idp.grant(&code, idp.claims(&login.nonce, extra));
    let done = callback(podgate, host, &login, &code).await;
    assert_eq!(done.status, 302, "{done:?}");
    pair(&cookie_named(&done, SESSION_COOKIE).expect("a session cookie"))
}

async fn with_session(podgate: &Podgate, host: &str, path: &str, cookie: &str) -> Response {
    h(
        podgate,
        host,
        path,
        &[("Cookie", cookie), ("Accept", "text/html")],
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// The login
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn oidc_login_redirect_has_pkce_state_nonce() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;

    let first = begin(&podgate, "a.test", "/page?x=1").await;
    let query = query_of(&first.location);
    assert!(
        first
            .location
            .starts_with(&format!("{}/authorize?", idp.base)),
        "{}",
        first.location
    );
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], CLIENT);
    assert_eq!(query["redirect_uri"], format!("https://a.test{CALLBACK}"));
    assert_eq!(query["scope"], "openid");
    assert_eq!(query["code_challenge_method"], "S256");
    // 128 random bits of state and nonce, 256 of verifier whose S256 is the challenge.
    assert_eq!(first.state.len(), 22, "{}", first.state);
    assert_eq!(first.nonce.len(), 22);
    assert_eq!(first.challenge.len(), 43);
    assert_eq!(
        up.requests(),
        0,
        "an anonymous visitor never reaches the app"
    );

    let second = begin(&podgate, "a.test", "/page?x=1").await;
    assert_ne!(first.state, second.state);
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.challenge, second.challenge);
    assert_eq!(
        idp.asked("GET", "/.well-known/openid-configuration").len(),
        1,
        "the document is cached"
    );
    let response = h(&podgate, "a.test", "/", &HTML).await;
    assert_eq!(response.header("cache-control"), Some("no-store"));
}

#[tokio::test]
async fn oidc_flow_cookie_attributes() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;
    let response = h(&podgate, "a.test", "/", &HTML).await;
    let cookie = cookie_named(&response, FLOW_COOKIE).expect("flow cookie");
    assert!(
        cookie.ends_with(&format!(
            "; Path={CALLBACK}; Max-Age=300; HttpOnly; Secure; SameSite=Lax"
        )),
        "{cookie}"
    );
    // Sealed: neither the state nor the verifier is readable in it.
    let login = begin(&podgate, "a.test", "/").await;
    let value = pair(&login.flow_cookie)
        .split_once('=')
        .expect("pair")
        .1
        .to_owned();
    let bytes = URL_SAFE_NO_PAD.decode(&value).expect("base64url");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !value.contains(&login.state) && !text.contains(&login.state),
        "{value}"
    );
    assert!(!text.contains("verifier") && !text.contains(&login.nonce));

    // A configured callback path is the cookie's path.
    let custom = config(&idp, &json!({"redirect_path": "/auth/back"}));
    push(&podgate, &pushed(2, &[site("a", "a.test", &up, &custom)])).await;
    let response = h(&podgate, "a.test", "/", &HTML).await;
    let cookie = cookie_named(&response, FLOW_COOKIE).expect("flow cookie");
    assert!(cookie.contains("; Path=/auth/back; "), "{cookie}");
    assert_eq!(
        query_of(response.header("location").expect("location"))["redirect_uri"],
        "https://a.test/auth/back"
    );
}

#[tokio::test]
async fn oidc_callback_sets_session() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let secret = "s3cret/with space&odd";
    let confidential = config(&idp, &json!({"client_secret": secret}));
    push(
        &podgate,
        &pushed(
            1,
            &[
                site("a", "a.test", &up, &confidential),
                site("b", "b.test", &up, &config(&idp, &json!({}))),
            ],
        ),
    )
    .await;

    let login = begin(&podgate, "a.test", "/start?x=1&y=2").await;
    idp.grant("c1", idp.claims(&login.nonce, &json!({})));
    let done = callback(&podgate, "a.test", &login, "c1").await;
    assert_eq!(done.status, 302, "{done:?}");
    assert_eq!(done.header("location"), Some("/start?x=1&y=2"));
    assert_eq!(done.header("cache-control"), Some("no-store"));
    let session = cookie_named(&done, SESSION_COOKIE).expect("a session cookie");
    assert!(session.contains("; Path=/; Max-Age="), "{session}");
    assert!(
        session.ends_with("; HttpOnly; Secure; SameSite=Lax"),
        "{session}"
    );
    assert!(!session.contains("Domain"), "{session}");
    let max_age: u64 = session
        .split("Max-Age=")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .and_then(|digits| digits.parse().ok())
        .expect("max age");
    assert!(
        (590..=600).contains(&max_age),
        "the ID token ends first: {max_age}"
    );
    let cleared = cookie_named(&done, FLOW_COOKIE).expect("the flow cookie is cleared");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");

    // The code was redeemed with the verifier of the login, the redirect URI and the secret.
    let redeemed = &idp.asked("POST", "/token")[0];
    let form: HashMap<String, String> = form_urlencoded::parse(redeemed.body.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "c1");
    assert_eq!(form["redirect_uri"], format!("https://a.test{CALLBACK}"));
    let challenge = ring::digest::digest(&ring::digest::SHA256, form["code_verifier"].as_bytes());
    assert_eq!(URL_SAFE_NO_PAD.encode(challenge), login.challenge, "PKCE");
    let basic = STANDARD.encode("app1:s3cret%2Fwith+space%26odd");
    assert_eq!(
        header_of(&redeemed.head, "authorization"),
        Some(format!("Basic {basic}").as_str())
    );
    assert!(!form.contains_key("client_id") && !redeemed.body.contains("s3cret"));

    // A public client sends its id in the body and no secret at all.
    let login = begin(&podgate, "b.test", "/").await;
    idp.grant("c2", idp.claims(&login.nonce, &json!({})));
    assert_eq!(callback(&podgate, "b.test", &login, "c2").await.status, 302);
    let public = idp.asked("POST", "/token");
    assert!(
        header_of(&public[1].head, "authorization").is_none(),
        "{}",
        public[1].head
    );
    assert!(
        public[1].body.contains("client_id=app1"),
        "{}",
        public[1].body
    );

    // The session lets the browser through.
    let cookie = pair(&session);
    let page = with_session(&podgate, "a.test", "/start", &cookie).await;
    assert_eq!(page.status, 200, "{page:?}");
    assert_eq!(up.requests(), 1);
}

#[tokio::test]
async fn oidc_state_mismatch_refused() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;
    let login = begin(&podgate, "a.test", "/").await;
    idp.grant("c1", idp.claims(&login.nonce, &json!({})));
    let cookie = pair(&login.flow_cookie);

    let other = format!("{CALLBACK}?code=c1&state=somethingelse");
    let wrong = h(&podgate, "a.test", &other, &[("Cookie", &cookie)]).await;
    assert_eq!(
        (wrong.status, wrong.body.as_str()),
        (400, r#"{"error":"bad request"}"#)
    );
    let none = format!("{CALLBACK}?code=c1&state={}", login.state);
    let no_cookie = h0(&podgate, "a.test", &none).await;
    assert_eq!(no_cookie.status, 400, "{no_cookie:?}");
    let no_state = h(
        &podgate,
        "a.test",
        &format!("{CALLBACK}?code=c1"),
        &[("Cookie", &cookie)],
    )
    .await;
    assert_eq!(no_state.status, 400);
    let twice = format!("{CALLBACK}?code=c1&state={0}&state={0}", login.state);
    let repeated = h(&podgate, "a.test", &twice, &[("Cookie", &cookie)]).await;
    assert_eq!(repeated.status, 400);
    let tampered = format!("{}x", cookie);
    let altered = h(&podgate, "a.test", &none, &[("Cookie", tampered.as_str())]).await;
    assert_eq!(altered.status, 400);
    for refused in [&wrong, &no_cookie, &no_state, &repeated, &altered] {
        assert!(cookie_named(refused, SESSION_COOKIE).is_none());
    }
    assert!(
        idp.asked("POST", "/token").is_empty(),
        "no code was redeemed"
    );

    // The state belongs to a login of this app: the right one works.
    assert_eq!(callback(&podgate, "a.test", &login, "c1").await.status, 302);
}

#[tokio::test]
async fn oidc_nonce_mismatch_refused() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;
    let login = begin(&podgate, "a.test", "/").await;
    for (code, claims) in [
        ("wrong", idp.claims("another-nonce", &json!({}))),
        ("missing", {
            let mut claims = idp.claims(&login.nonce, &json!({}));
            claims.as_object_mut().expect("claims").remove("nonce");
            claims
        }),
    ] {
        idp.grant(code, claims);
        let refused = callback(&podgate, "a.test", &login, code).await;
        assert_eq!(
            (refused.status, refused.body.as_str()),
            (401, r#"{"error":"unauthorized"}"#),
            "{code}"
        );
        assert!(cookie_named(&refused, SESSION_COOKIE).is_none());
    }
}

#[tokio::test]
async fn oidc_bad_id_token_refused() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let config = config(
        &idp,
        &json!({"required_claims": {"role": ["admin"]}, "allow_subjects": ["ann", "bob"]}),
    );
    push(&podgate, &pushed(1, &[site("a", "a.test", &up, &config)])).await;
    let login = begin(&podgate, "a.test", "/").await;
    let nonce = login.nonce.as_str();
    let good = |extra: &Value| idp.claims(nonce, &with(&json!({"role": "admin"}), extra));

    let forged = Signer::es256("idp-key");
    let other_alg = idp
        .state
        .key
        .sign("ES256", &json!({"alg": "none"}), &good(&json!({})));
    let cases: Vec<(&str, u16, Grant)> = vec![
        (
            "expired",
            401,
            Grant::Claims(good(&json!({"exp": now() - 600}))),
        ),
        (
            "audience",
            401,
            Grant::Claims(good(&json!({"aud": "another-app"}))),
        ),
        (
            "no exp",
            401,
            Grant::Claims({
                let mut claims = good(&json!({}));
                claims.as_object_mut().expect("claims").remove("exp");
                claims
            }),
        ),
        (
            "no sub",
            401,
            Grant::Claims({
                let mut claims = good(&json!({}));
                claims.as_object_mut().expect("claims").remove("sub");
                claims
            }),
        ),
        (
            "a key the provider does not publish",
            401,
            Grant::Token(forged.sign("ES256", &json!({}), &good(&json!({})))),
        ),
        (
            "alg none",
            401,
            Grant::Token(unsigned("none", &good(&json!({})))),
        ),
        (
            "an algorithm not allowed",
            401,
            Grant::Token(Signer::rsa_a("idp-key").sign("RS256", &json!({}), &good(&json!({})))),
        ),
        ("a header that says none", 401, Grant::Token(other_alg)),
        ("not a token", 401, Grant::Token("abc".to_owned())),
        (
            "several audiences without azp",
            401,
            Grant::Claims(good(&json!({"aud": [CLIENT, "other"]}))),
        ),
        (
            "required claim",
            403,
            Grant::Claims(idp.claims(nonce, &json!({"role": "viewer"}))),
        ),
        (
            "no required claim",
            403,
            Grant::Claims(idp.claims(nonce, &json!({}))),
        ),
        (
            "subject not admitted",
            403,
            Grant::Claims(good(&json!({"sub": "mallory"}))),
        ),
    ];
    for (n, (what, status, grant)) in cases.into_iter().enumerate() {
        let code = format!("bad-{n}");
        idp.state
            .grants
            .lock()
            .expect("grants")
            .insert(code.clone(), grant);
        let refused = callback(&podgate, "a.test", &login, &code).await;
        assert_eq!(refused.status, status, "{what}: {refused:?}");
        assert!(cookie_named(&refused, SESSION_COOKIE).is_none(), "{what}");
        assert!(
            !refused.body.contains("jwt") && !refused.body.contains("signature"),
            "{what}"
        );
    }
    // A code the provider does not know is refused, as is a provider that says so.
    let unknown = callback(&podgate, "a.test", &login, "never-granted").await;
    assert_eq!(unknown.status, 401, "{unknown:?}");
    // An azp that names the client makes a token for several audiences valid.
    idp.grant(
        "azp",
        good(&json!({"aud": [CLIENT, "other"], "azp": CLIENT})),
    );
    assert_eq!(
        callback(&podgate, "a.test", &login, "azp").await.status,
        302
    );
    // And so does a good token: nothing above was a matter of the setup.
    idp.grant("ok", good(&json!({})));
    assert_eq!(callback(&podgate, "a.test", &login, "ok").await.status, 302);
}

#[tokio::test]
async fn oidc_issuer_mismatch_refused() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;
    // The document names another issuer: it is not used, and nobody is sent anywhere.
    *idp.state.doc_issuer.lock().expect("issuer") = "https://evil.test".to_owned();
    let refused = h(&podgate, "a.test", "/", &HTML).await;
    assert_eq!(
        (refused.status, refused.body.as_str()),
        (503, r#"{"error":"authentication unavailable"}"#)
    );
    assert!(refused.header("location").is_none());
    *idp.state.doc_issuer.lock().expect("issuer") = idp.base.clone();

    // An ID token of another issuer is refused (a changed declaration starts a fresh fetch).
    let again = config(&idp, &json!({"scopes": ["openid", "email"]}));
    push(&podgate, &pushed(2, &[site("a", "a.test", &up, &again)])).await;
    let login = begin(&podgate, "a.test", "/").await;
    idp.grant(
        "c1",
        idp.claims(&login.nonce, &json!({"iss": "https://evil.test"})),
    );
    let wrong = callback(&podgate, "a.test", &login, "c1").await;
    assert_eq!(wrong.status, 401, "{wrong:?}");
    idp.grant("c2", idp.claims(&login.nonce, &json!({})));
    assert_eq!(callback(&podgate, "a.test", &login, "c2").await.status, 302);
}

#[tokio::test]
async fn oidc_redirect_target_relative_only() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;
    for (n, path) in [
        "/page?next=//evil.test/x",
        "//evil.test/path",
        "///evil.test",
        "/%2F%2Fevil.test",
        "/a//b",
    ]
    .into_iter()
    .enumerate()
    {
        let response = h(&podgate, "a.test", path, &HTML).await;
        if response.status == 400 {
            // A request target the proxy itself refuses never starts a login.
            continue;
        }
        assert_eq!(response.status, 302, "{path}: {response:?}");
        let query = query_of(response.header("location").expect("location"));
        let login = Login {
            state: query["state"].clone(),
            nonce: query["nonce"].clone(),
            challenge: query["code_challenge"].clone(),
            flow_cookie: cookie_named(&response, FLOW_COOKIE).expect("a flow cookie"),
            location: String::new(),
        };
        let code = format!("c{n}");
        idp.grant(&code, idp.claims(&login.nonce, &json!({})));
        let done = callback(&podgate, "a.test", &login, &code).await;
        assert_eq!(done.status, 302, "{path}: {done:?}");
        let location = done.header("location").expect("location");
        assert!(
            location.starts_with('/')
                && !location.starts_with("//")
                && !location.starts_with("/\\"),
            "{path} went to {location}"
        );
    }
    // A target that was a relative path is kept exactly.
    let login = begin(&podgate, "a.test", "/deep/page?x=1&y=%20").await;
    idp.grant("last", idp.claims(&login.nonce, &json!({})));
    let done = callback(&podgate, "a.test", &login, "last").await;
    assert_eq!(done.header("location"), Some("/deep/page?x=1&y=%20"));
}

// ---------------------------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn oidc_session_passes_with_claims() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let config = config(
        &idp,
        &json!({"forward_claims": {"email": "X-Email", "sub": "X-User", "groups": "X-Groups"},
                "required_claims": {"email_verified": true}}),
    );
    push(&podgate, &pushed(1, &[site("a", "a.test", &up, &config)])).await;
    let session = sign_in(
        &podgate,
        &idp,
        "a.test",
        &json!({"email": "ann@example.test", "email_verified": true, "groups": ["dev", "ops"]}),
    )
    .await;

    let cookie = format!("theme=dark; {session}; other=1");
    let page = h(
        &podgate,
        "a.test",
        "/dash",
        &[
            ("Cookie", cookie.as_str()),
            ("X-Email", "forged@evil.test"),
            ("X-Groups", "root"),
            ("Accept", "text/html"),
        ],
    )
    .await;
    assert_eq!(page.status, 200, "{page:?}");
    assert_eq!(
        header_of(&page.body, "x-email"),
        Some("ann@example.test"),
        "{}",
        page.body
    );
    assert_eq!(header_of(&page.body, "x-user"), Some("ann"));
    assert_eq!(header_of(&page.body, "x-groups"), Some("dev, ops"));
    // The session cookie stays with podgate; the app's own cookies pass.
    let upstream_cookie = header_of(&page.body, "cookie").expect("the other cookies");
    assert!(
        !upstream_cookie.contains("podgate_oidc"),
        "{upstream_cookie}"
    );
    assert!(upstream_cookie.contains("theme=dark") && upstream_cookie.contains("other=1"));

    // A visitor with no session cannot present an identity.
    let anonymous = h(
        &podgate,
        "a.test",
        "/dash",
        &[("X-User", "admin"), ("Accept", "text/html")],
    )
    .await;
    assert_eq!(anonymous.status, 302);
    assert_eq!(up.requests(), 1);

    // A claim the provider did not send is not forged into existence.
    let session = sign_in(&podgate, &idp, "a.test", &json!({"email_verified": true})).await;
    let bare = with_session(&podgate, "a.test", "/", &session).await;
    assert_eq!(bare.status, 200);
    assert!(header_of(&bare.body, "x-email").is_none(), "{}", bare.body);
}

#[tokio::test]
async fn oidc_session_tampered_refused() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;
    let session = sign_in(&podgate, &idp, "a.test", &json!({})).await;
    assert_eq!(
        with_session(&podgate, "a.test", "/", &session).await.status,
        200
    );

    let (name, value) = session.split_once('=').expect("pair");
    let mut flipped = value.as_bytes().to_vec();
    let at = flipped.len() / 2;
    flipped[at] = if flipped[at] == b'A' { b'B' } else { b'A' };
    let cases = [
        format!("{name}={}", String::from_utf8(flipped).expect("ascii")),
        format!("{name}={value}x"),
        format!("{name}={}", &value[..value.len() - 4]),
        format!("{name}="),
        format!("{name}=not-a-session"),
        format!("{name}={}", STANDARD.encode(r#"{"sub":"admin"}"#)),
    ];
    for tampered in &cases {
        let refused = with_session(&podgate, "a.test", "/", tampered).await;
        assert_eq!(refused.status, 302, "{tampered}: {refused:?}");
        assert!(
            refused
                .header("location")
                .expect("location")
                .starts_with(&idp.base)
        );
    }
    assert_eq!(up.requests(), 1, "only the genuine cookie reached the app");
}

#[tokio::test]
async fn oidc_session_expires() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let short = config(&idp, &json!({"session": {"max_age_secs": 3}}));
    push(
        &podgate,
        &pushed(
            1,
            &[
                site("a", "a.test", &up, &config(&idp, &json!({}))),
                site("b", "b.test", &up, &short),
            ],
        ),
    )
    .await;
    // The cookie lives as long as the ID token...
    let by_token = sign_in(&podgate, &idp, "a.test", &json!({"exp": now() + 3})).await;
    // ...or as long as the configuration allows, whichever is shorter.
    let by_setting = sign_in(&podgate, &idp, "b.test", &json!({})).await;
    assert_eq!(
        with_session(&podgate, "a.test", "/", &by_token)
            .await
            .status,
        200
    );
    assert_eq!(
        with_session(&podgate, "b.test", "/", &by_setting)
            .await
            .status,
        200
    );
    sleep(Duration::from_millis(3200)).await;
    let ended = with_session(&podgate, "a.test", "/", &by_token).await;
    assert_eq!(ended.status, 302, "{ended:?}");
    let ended = with_session(&podgate, "b.test", "/", &by_setting).await;
    assert_eq!(ended.status, 302, "{ended:?}");
}

#[tokio::test]
async fn oidc_cookie_not_valid_on_other_app() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let one = config(&idp, &json!({}));
    let mut wildcard = site("a", "a.test", &up, &one);
    wildcard["routers"][0]["match"] = json!({"host": ["a.test", "c.test"]});
    push(
        &podgate,
        &pushed(1, &[wildcard, site("b", "b.test", &up, &one)]),
    )
    .await;
    let session = sign_in(&podgate, &idp, "a.test", &json!({})).await;
    assert_eq!(
        with_session(&podgate, "a.test", "/", &session).await.status,
        200
    );
    // The same configuration, the same cookie name, another app: another key.
    let other = with_session(&podgate, "b.test", "/", &session).await;
    assert_eq!(other.status, 302, "{other:?}");
    // Another host of the same app: the cookie is bound to the host it was issued for.
    let host = with_session(&podgate, "c.test", "/", &session).await;
    assert_eq!(host.status, 302, "{host:?}");
    assert_eq!(up.requests(), 1);
}

#[tokio::test]
async fn oidc_logout_clears_cookie() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let config = config(&idp, &json!({"logout_path": "/logout"}));
    push(&podgate, &pushed(1, &[site("a", "a.test", &up, &config)])).await;
    let session = sign_in(&podgate, &idp, "a.test", &json!({})).await;

    for (method, status) in [("GET", 302), ("POST", 303)] {
        let out = hr(
            &podgate,
            method,
            "a.test",
            "/logout",
            &[("Cookie", session.as_str())],
        )
        .await;
        assert_eq!(out.status, status, "{out:?}");
        assert_eq!(out.header("location"), Some("/"));
        let cleared = cookie_named(&out, SESSION_COOKIE).expect("the session cookie is cleared");
        assert_eq!(
            cleared,
            format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
        );
    }
    assert_eq!(up.requests(), 0, "logout is answered by the middleware");
    // The browser drops the cookie: the next visit starts a login.
    let again = h(&podgate, "a.test", "/", &HTML).await;
    assert_eq!(again.status, 302);
}

#[tokio::test]
async fn oidc_xhr_gets_401() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;
    let json_accept = [("Accept", "application/json")];
    let xhr = [
        ("Accept", "text/html"),
        ("X-Requested-With", "XMLHttpRequest"),
    ];
    let cases = [
        h(&podgate, "a.test", "/api", &json_accept).await,
        h(&podgate, "a.test", "/api", &xhr).await,
        h(&podgate, "a.test", "/api", &[("Accept", "*/*")]).await,
        h0(&podgate, "a.test", "/api").await,
        hr(&podgate, "POST", "a.test", "/api", &HTML).await,
        hr(&podgate, "DELETE", "a.test", "/api", &HTML).await,
    ];
    for response in &cases {
        assert_eq!(response.status, 401, "{response:?}");
        assert_eq!(response.header("www-authenticate"), Some("Bearer"));
        assert_eq!(response.body, r#"{"error":"unauthorized"}"#);
        assert!(response.header("location").is_none());
    }
    // A request that cannot follow a redirect never starts a login.
    assert!(idp.seen().is_empty(), "no provider traffic for a script");
    assert_eq!(h(&podgate, "a.test", "/", &HTML).await.status, 302);
    assert_eq!(up.requests(), 0);
}

#[tokio::test]
async fn oidc_callback_path_reserved() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let config = config(
        &idp,
        &json!({"redirect_path": "/auth/back", "logout_path": "/auth/out"}),
    );
    push(&podgate, &pushed(1, &[site("a", "a.test", &up, &config)])).await;
    let session = {
        let login = begin(&podgate, "a.test", "/").await;
        idp.grant("c1", idp.claims(&login.nonce, &json!({})));
        let target = format!("/auth/back?code=c1&state={}", login.state);
        let cookie = pair(&login.flow_cookie);
        let done = h(&podgate, "a.test", &target, &[("Cookie", cookie.as_str())]).await;
        assert_eq!(done.status, 302, "{done:?}");
        pair(&cookie_named(&done, SESSION_COOKIE).expect("session"))
    };
    // Neither the callback nor the logout path reaches the app, with a session or without.
    for path in ["/auth/back", "/auth/back?code=x&state=y", "/auth/out"] {
        for cookie in [None, Some(session.as_str())] {
            let headers: Vec<(&str, &str)> = cookie.map(|c| ("Cookie", c)).into_iter().collect();
            let answer = h(&podgate, "a.test", path, &headers).await;
            assert!(
                matches!(answer.status, 302 | 303 | 400),
                "{path}: {answer:?}"
            );
        }
    }
    assert_eq!(up.requests(), 0);
    // The default callback path is an ordinary path of the app once it is not the setting.
    assert_eq!(
        with_session(&podgate, "a.test", CALLBACK, &session)
            .await
            .status,
        200
    );
    assert_eq!(up.requests(), 1);
}

// ---------------------------------------------------------------------------------------------
// The provider: policy, outage, bounds
// ---------------------------------------------------------------------------------------------

/// A policy file in its own temp directory, removed on drop.
struct PolicyFile {
    dir: PathBuf,
    path: PathBuf,
}

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-oidc-policy-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("policy.json");
        std::fs::write(&path, contents).expect("write policy file");
        Self { dir, path }
    }

    fn env(&self) -> (&'static str, &str) {
        ("UPSTREAM_POLICY_FILE", self.path.to_str().expect("utf-8"))
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

#[tokio::test]
async fn oidc_discovery_through_policy() {
    // The built-in policy refuses loopback: a literal issuer is refused when it is declared.
    let strict = PolicyFile::write("{}");
    let podgate = Podgate::start_with_env(&[strict.env()]).await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let refused = podgate
        .push_snapshot(&pushed(
            1,
            &[site("a", "a.test", &up, &config(&idp, &json!({})))],
        ))
        .await;
    let entry = rejection(&refused);
    assert_eq!(entry["code"], "upstream_forbidden", "{refused:?}");
    assert!(idp.seen().is_empty());

    // A name is judged where it is dialled: on every answer. The provider's own document can
    // send the token call to a denied address too.
    let dns = Dns::start().await;
    let policy = PolicyFile::write(r#"{"deny": ["10.9.0.0/16"]}"#);
    let podgate = Podgate::start_with_env(&[
        ("DNS_SERVERS", &dns.servers()),
        ("DNS_TIMEOUT_MS", "1000"),
        policy.env(),
    ])
    .await;
    dns.set("denied.internal", &["10.9.0.1"], 30);
    dns.set("idp.internal", &["127.0.0.1"], 30);
    let named = Idp::start_at("idp.internal").await;
    let denied_issuer = format!("http://denied.internal:{}", named.addr.port());
    let lead = site(
        "a",
        "a.test",
        &up,
        &json!({"issuer": denied_issuer, "client_id": CLIENT, "allowed_algorithms": ["ES256"]}),
    );
    let token_denied = site("b", "b.test", &up, &config(&named, &json!({})));
    push(&podgate, &pushed(1, &[lead, token_denied])).await;
    let unreachable = h(&podgate, "a.test", "/", &HTML).await;
    assert_eq!(unreachable.status, 503, "{unreachable:?}");
    assert!(
        named.seen().is_empty(),
        "the denied address was never dialled"
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metrics
            .lines()
            .any(|line| line.starts_with("podgate_upstream_refused_total{tenant=\"t1\"} ")),
        "{metrics}"
    );

    *named.state.token_endpoint.lock().expect("token") = Some("http://10.9.0.2:9/token".to_owned());
    let login = begin(&podgate, "b.test", "/").await;
    named.grant("c1", named.claims(&login.nonce, &json!({})));
    let refused = callback(&podgate, "b.test", &login, "c1").await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert!(named.asked("POST", "/token").is_empty());
}

#[tokio::test]
async fn oidc_provider_outage_keeps_sessions() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let config = config(&idp, &json!({"forward_claims": {"sub": "X-User"}}));
    push(
        &podgate,
        &pushed(
            1,
            &[
                site("a", "a.test", &up, &config),
                site("b", "b.test", &up, &config),
            ],
        ),
    )
    .await;
    let session = sign_in(&podgate, &idp, "a.test", &json!({})).await;
    let pending = begin(&podgate, "a.test", "/later").await;
    idp.grant("late", idp.claims(&pending.nonce, &json!({})));

    idp.state.down.store(true, Ordering::SeqCst);
    // The signed-in visitor does not notice: the cookie is the whole session.
    for _ in 0..3 {
        let page = with_session(&podgate, "a.test", "/page", &session).await;
        assert_eq!(page.status, 200, "{page:?}");
        assert_eq!(header_of(&page.body, "x-user"), Some("ann"));
    }
    // A login that has to ask the provider for its document cannot start...
    let cold = h(&podgate, "b.test", "/", &HTML).await;
    assert_eq!(
        (cold.status, cold.body.as_str()),
        (503, r#"{"error":"authentication unavailable"}"#),
        "{cold:?}"
    );
    // ...and one that has to redeem its code cannot finish.
    let late = callback(&podgate, "a.test", &pending, "late").await;
    assert_eq!(late.status, 503, "{late:?}");
    assert!(cookie_named(&late, SESSION_COOKIE).is_none());

    // The provider comes back: the same flow cookie now completes.
    idp.state.down.store(false, Ordering::SeqCst);
    assert_eq!(
        callback(&podgate, "a.test", &pending, "late").await.status,
        302
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metrics.contains("podgate_oidc_refused_total{app=\"b\",middleware=\"login\",reason=\"provider_unavailable\"} 1"),
        "{metrics}"
    );
}

#[tokio::test]
async fn oidc_token_endpoint_concurrency_capped() {
    let podgate = Arc::new(Podgate::start().await);
    let (idp, up) = (Idp::start().await, Up::start().await);
    push(&podgate, &{
        let mut big = pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]);
        big["tenants"][0]["budget"]["max_buffer_bytes"] = json!(256 * 1024 * 1024);
        big
    })
    .await;
    // Forty browsers are on their way back from the provider, which is slow to redeem a code.
    let mut logins = Vec::new();
    for n in 0..40 {
        let login = begin(&podgate, "a.test", "/").await;
        idp.grant(&format!("c{n}"), idp.claims(&login.nonce, &json!({})));
        logins.push(login);
    }
    idp.state.token_delay_ms.store(1500, Ordering::SeqCst);
    let mut set = JoinSet::new();
    for (n, login) in logins.into_iter().enumerate() {
        let podgate = Arc::clone(&podgate);
        set.spawn(async move { callback(&podgate, "a.test", &login, &format!("c{n}")).await });
    }
    let mut statuses = Vec::new();
    while let Some(done) = set.join_next().await {
        let response = done.expect("a callback");
        if response.status == 503 {
            assert_eq!(response.header("retry-after"), Some("1"), "{response:?}");
        }
        statuses.push(response.status);
    }
    let busy = statuses.iter().filter(|status| **status == 503).count();
    let signed_in = statuses.iter().filter(|status| **status == 302).count();
    assert_eq!(busy + signed_in, 40, "{statuses:?}");
    assert!(
        busy >= 1,
        "past 32 calls the callback answers 503: {statuses:?}"
    );
    assert!(
        idp.state.peak.load(Ordering::SeqCst) <= 32,
        "peak {}",
        idp.state.peak.load(Ordering::SeqCst)
    );
    assert!(signed_in >= 20, "the rest are served: {statuses:?}");
}

// ---------------------------------------------------------------------------------------------
// Secrets, admission, configuration
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn oidc_client_secret_redacted() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let secret = "PLANT-oidc-client-secret-7f3a9c";
    let config = config(
        &idp,
        &json!({"client_secret": secret, "forward_claims": {"sub": "X-User"}}),
    );
    push(&podgate, &pushed(1, &[site("a", "a.test", &up, &config)])).await;
    let explain = podgate.admin_get("/v1/explain?url=https://a.test/").await;
    assert_eq!(explain.status, 200, "{explain:?}");
    assert!(
        explain.body.contains("client_secret_basic"),
        "{}",
        explain.body
    );
    for (what, shown) in [
        ("explain", explain.body),
        ("overview", podgate.admin_get("/v1/overview").await.body),
        (
            "plan",
            podgate
                .admin_post(
                    "/v1/snapshot/plan",
                    &pushed(2, &[site("a", "a.test", &up, &config)]),
                )
                .await
                .body,
        ),
        ("metrics", podgate.admin_get("/metrics").await.body),
    ] {
        assert!(!shown.contains(secret), "{what}: {shown}");
    }
    // A login that uses the secret leaves it out of every answer.
    let login = begin(&podgate, "a.test", "/").await;
    idp.grant("c1", idp.claims(&login.nonce, &json!({})));
    let done = callback(&podgate, "a.test", &login, "c1").await;
    assert_eq!(done.status, 302);
    assert!(!format!("{done:?}").contains(secret));
    assert!(
        !idp.asked("POST", "/token")[0].body.contains(secret),
        "only the header carries it"
    );
}

#[tokio::test]
async fn oidc_refused_on_plain_entry_point() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let guarded = site("a", "a.test", &up, &config(&idp, &json!({})));
    let mut plain = snapshot(1, std::slice::from_ref(&guarded));
    plain["skew_secret"] = json!(SKEW);
    let refused = podgate.push_snapshot(&plain).await;
    let entry = rejection(&refused);
    assert_eq!(entry["code"], "invalid_middleware", "{refused:?}");
    assert_eq!(entry["entry_point"], "web", "{entry}");
}

#[tokio::test]
async fn oidc_allowed_when_plain_entry_point_redirects() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let guarded = site("a", "a.test", &up, &config(&idp, &json!({})));
    // The router is on every entry point; `web` redirects to `websecure` before routing, so no
    // cookie is ever issued over plain http there.
    let mut redirected = snapshot(1, &[guarded]);
    redirected["skew_secret"] = json!(SKEW);
    redirected["entry_points"] = json!([{"name": "web", "redirect": {"to": "websecure"}}]);
    push(&podgate, &redirected).await;
}

#[tokio::test]
async fn oidc_requires_skew_secret() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let without = snapshot(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]);
    let refused = podgate.push_snapshot(&without).await;
    let entry = rejection(&refused);
    assert_eq!(entry["code"], "invalid_middleware", "{refused:?}");
    assert!(
        entry["message"]
            .as_str()
            .is_some_and(|m| m.contains("skew_secret")),
        "{entry}"
    );
    assert_eq!(
        podgate.admin_get("/v1/snapshot/version").await.json()["version"],
        0
    );
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;
}

#[tokio::test]
async fn oidc_before_admission() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let mut snap = pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]);
    snap["tenants"][0]["budget"]["max_inflight"] = json!(1);
    push(&podgate, &snap).await;
    let session = sign_in(&podgate, &idp, "a.test", &json!({})).await;

    let (held, others) = tokio::join!(with_session(&podgate, "a.test", "/slow", &session), async {
        sleep(Duration::from_millis(300)).await;
        // The tenant's only slot is taken: nobody who has no session needs one.
        let browser = h(&podgate, "a.test", "/other", &HTML).await;
        let script = h(&podgate, "a.test", "/other", &[]).await;
        let signed_in = with_session(&podgate, "a.test", "/other", &session).await;
        (browser, script, signed_in)
    });
    assert_eq!(held.status, 200, "{held:?}");
    assert_eq!(others.0.status, 302, "{:?}", others.0);
    assert_eq!(others.1.status, 401, "{:?}", others.1);
    assert_eq!(others.2.status, 503, "{:?}", others.2);
    assert_eq!(others.2.header("retry-after"), Some("1"));
}

#[tokio::test]
async fn oidc_session_request_bypasses_cache() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let guarded = site(
        "a",
        "a.test",
        &up,
        &config(&idp, &json!({"forward_claims": {"sub": "X-User"}})),
    );
    let app = with_middleware(guarded, "c", "cache", json!({}));
    push(&podgate, &pushed(1, &[app])).await;
    let session = sign_in(&podgate, &idp, "a.test", &json!({})).await;
    for _ in 0..2 {
        let page = with_session(&podgate, "a.test", "/page", &session).await;
        assert_eq!(page.status, 200, "{page:?}");
        assert_eq!(
            page.header("cache-status"),
            Some("podgate; bypass"),
            "{page:?}"
        );
    }
    assert_eq!(up.requests(), 2);
}

#[tokio::test]
async fn oidc_invalid_config_rejected_by_snapshot() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let good = config(&idp, &json!({}));
    for (what, bad) in [
        ("unknown field", with(&good, &json!({"nope": 1}))),
        ("no openid", with(&good, &json!({"scopes": ["email"]}))),
        (
            "hmac",
            with(&good, &json!({"allowed_algorithms": ["HS256"]})),
        ),
        (
            "relative issuer",
            with(&good, &json!({"issuer": "idp.test"})),
        ),
        (
            "long session",
            with(&good, &json!({"session": {"max_age_secs": 8 * 24 * 3600}})),
        ),
        (
            "callback is the logout",
            with(&good, &json!({"logout_path": CALLBACK})),
        ),
        (
            "undeclared transport",
            with(&good, &json!({"transport": "nope"})),
        ),
    ] {
        let refused = podgate
            .push_snapshot(&pushed(1, &[site("a", "a.test", &up, &bad)]))
            .await;
        let entry = rejection(&refused);
        assert!(
            matches!(
                entry["code"].as_str(),
                Some("invalid_middleware" | "unknown_transport")
            ),
            "{what}: {refused:?}"
        );
    }
    // Five issuers are more than a tenant may trust.
    let apps: Vec<Value> = (0..5)
        .map(|n| {
            let issuer = json!({"issuer": format!("http://127.0.0.1:{}", 9000 + n)});
            site(
                &format!("a{n}"),
                &format!("a{n}.test"),
                &up,
                &with(&good, &issuer),
            )
        })
        .collect();
    let refused = podgate.push_snapshot(&pushed(1, &apps)).await;
    let entry = rejection(&refused);
    assert!(
        entry["message"]
            .as_str()
            .is_some_and(|m| m.contains("distinct issuers")),
        "{entry}"
    );
    // A budget that cannot hold one call to the provider is refused with the bytes it needs.
    let mut small = pushed(1, &[site("a", "a.test", &up, &good)]);
    small["tenants"][0]["budget"]["max_buffer_bytes"] = json!(1024);
    let refused = podgate.push_snapshot(&small).await;
    let entry = rejection(&refused);
    assert_eq!(entry["code"], "invalid_middleware");
    assert!(
        entry["needed_bytes"]
            .as_u64()
            .is_some_and(|needed| needed > 1024),
        "{entry}"
    );
}

#[tokio::test]
async fn plan_lists_oidc_changes() {
    let podgate = Podgate::start().await;
    let (idp, up) = (Idp::start().await, Up::start().await);
    let strict = config(
        &idp,
        &json!({"session": {"max_age_secs": 600}, "required_claims": {"role": ["admin"]},
                "allow_subjects": ["ann"]}),
    );
    push(&podgate, &pushed(1, &[site("a", "a.test", &up, &strict)])).await;
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
        let body = pushed(2, &[site("a", "a.test", &up, config)]);
        let podgate = &podgate;
        async move { kinds(&podgate.admin_post("/v1/snapshot/plan", &body).await) }
    };
    let removed = pushed(2, &[app("a", &["a.test"], &[serving("r1", up.addr)])]);
    assert_eq!(
        kinds(&podgate.admin_post("/v1/snapshot/plan", &removed).await),
        ["oidc_removed"]
    );
    assert!(plan(&strict).await.is_empty());
    for (change, kind) in [
        (
            json!({"session": {"max_age_secs": 601}}),
            "oidc_session_longer",
        ),
        (
            json!({"required_claims": {}}),
            "oidc_required_claims_loosened",
        ),
        (
            json!({"required_claims": {"role": ["admin", "ops"]}}),
            "oidc_required_claims_loosened",
        ),
        (json!({"allow_subjects": null}), "oidc_subjects_loosened"),
        (
            json!({"allow_subjects": ["ann", "bob"]}),
            "oidc_subjects_loosened",
        ),
        (
            json!({"allowed_algorithms": ["ES256", "ES384"]}),
            "oidc_algorithm_added",
        ),
        (json!({"client_id": "another"}), "oidc_provider_changed"),
    ] {
        assert_eq!(plan(&with(&strict, &change)).await, [kind], "{change}");
    }
    // Tightening is not a relaxation.
    let tighter = with(
        &strict,
        &json!({"session": {"max_age_secs": 60}, "allow_subjects": ["ann"]}),
    );
    assert!(plan(&tighter).await.is_empty());
}

// ---------------------------------------------------------------------------------------------
// What never reaches a log, a record or a mirror
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn oidc_cookie_and_code_never_reach_logs_records_or_mirrors() {
    let log_dir = PolicyFile::write("{}");
    let log_path = log_dir.dir.join("access.log");
    let podgate =
        Podgate::start_with_env(&[("ACCESS_LOG_FILE", log_path.to_str().expect("utf-8"))]).await;
    let (idp, up, shadow) = (Idp::start().await, Up::start().await, Up::start().await);
    let secret = "PLANT-log-client-secret-1c9";
    let config = config(
        &idp,
        &json!({"client_secret": secret, "forward_claims": {"sub": "X-User"}}),
    );
    let mirror = json!({
        "name": "m", "type": "mirroring", "service": "web",
        "mirrors": [{"service": "shadow", "percent": 100.0}], "forward_credentials": false,
    });
    let revision = json!({"id": "r1", "state": "serving", "weight": 100,
        "services": [service("web", &[up.addr]), service("shadow", &[shadow.addr]), mirror]});
    let mut guarded = with_oidc(app("a", &["a.test"], &[revision]), config);
    guarded["routers"] = json!([router("default", json!({"host": ["a.test"]}), "m")]);
    let mut snap = pushed(1, &[guarded]);
    snap["observability"] = json!({"access_log": {
        "fields": {"names": {"query": "keep"}}, "headers": {"default": "keep"},
    }});
    push(&podgate, &snap).await;

    let login = begin(&podgate, "a.test", "/").await;
    let code = "PLANT-authorization-code-5e2";
    idp.grant(code, idp.claims(&login.nonce, &json!({})));
    let done = callback(&podgate, "a.test", &login, code).await;
    assert_eq!(done.status, 302, "{done:?}");
    let session = pair(&cookie_named(&done, SESSION_COOKIE).expect("session"));
    let value = session.split_once('=').expect("pair").1.to_owned();
    // A page that fails: the record of the failed request is the other place a cookie could go.
    let failed = with_session(&podgate, "a.test", "/boom", &session).await;
    assert_eq!(failed.status, 500, "{failed:?}");
    let ok = with_session(&podgate, "a.test", "/fine", &session).await;
    assert_eq!(ok.status, 200);

    let mut log = String::new();
    for _ in 0..100 {
        log = std::fs::read_to_string(&log_path).unwrap_or_default();
        if log.lines().count() >= 3 {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(log.lines().count() >= 3, "{log}");
    assert!(
        log.contains("code=[redacted]") && log.contains("state=[redacted]"),
        "{log}"
    );
    for plant in [code, value.as_str(), secret] {
        assert!(!log.contains(plant), "{plant} is in the access log: {log}");
    }
    let records = podgate.admin_get("/v1/apps/a/failures").await;
    assert_eq!(records.status, 200, "{records:?}");
    assert!(
        !records.body.contains(&value) && !records.body.contains(secret),
        "{}",
        records.body
    );
    // The copy the mirror got is a request with no credentials at all.
    for _ in 0..100 {
        if shadow.requests() >= 2 {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    for copy in shadow.heads.lock().expect("heads").iter() {
        assert!(
            !copy.contains(&value) && !copy.contains("podgate_oidc"),
            "{copy}"
        );
        assert!(
            header_of(copy, "x-user").is_none(),
            "the identity is a credential: {copy}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn oidc_named_issuer_through_dns() {
    let dns = Dns::start().await;
    let podgate =
        Podgate::start_with_env(&[("DNS_SERVERS", &dns.servers()), ("DNS_TIMEOUT_MS", "1000")])
            .await;
    dns.set("idp.internal", &["127.0.0.1"], 30);
    let (idp, up) = (Idp::start_at("idp.internal").await, Up::start().await);
    assert!(idp.base.starts_with("http://idp.internal:"));
    push(
        &podgate,
        &pushed(1, &[site("a", "a.test", &up, &config(&idp, &json!({})))]),
    )
    .await;

    // Discovery, the keys and the token endpoint are all dialled through the resolver, at the
    // address the policy let through, with the name as Host.
    let session = sign_in(&podgate, &idp, "a.test", &json!({})).await;
    assert_eq!(
        with_session(&podgate, "a.test", "/", &session).await.status,
        200
    );
    let port = idp.addr.port();
    for (method, path) in [
        ("GET", "/.well-known/openid-configuration"),
        ("GET", "/jwks"),
        ("POST", "/token"),
    ] {
        let seen = idp.asked(method, path);
        assert_eq!(seen.len(), 1, "{method} {path}");
        assert_eq!(
            header_of(&seen[0].head, "host"),
            Some(format!("idp.internal:{port}").as_str())
        );
    }
    assert!(
        dns.queries_for("idp.internal") >= 6,
        "one A and one AAAA per call"
    );
    // The authorization endpoint is for the browser: it names the provider, not an address.
    let login = begin(&podgate, "a.test", "/").await;
    assert!(
        login
            .location
            .starts_with(&format!("http://idp.internal:{port}/authorize?"))
    );
}
