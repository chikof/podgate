//! A session stays on the revision that served its first request.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    Podgate, Response, TestCert, Upstream, app, middleware, revision, snapshot, with_chain,
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SECRET: &str = "a-secret-of-at-least-16-bytes";
const COOKIE: &str = "__podgate_rev";

/// Two upstreams that answer `one` and `two`.
struct Rollout {
    podgate: Podgate,
    one: Upstream,
    two: Upstream,
}

impl Rollout {
    async fn start() -> Self {
        Self {
            podgate: Podgate::start().await,
            one: Upstream::start("one").await,
            two: Upstream::start("two").await,
        }
    }

    /// Pushes app `a` (`a.test`) with the given `(revision, state)` pairs, all weight 1: `r1`
    /// is served by `one`, `r2` by `two`. Signed with `secret`.
    async fn push(&self, version: u64, secret: Option<&str>, revisions: &[(&str, &str)]) {
        let revisions: Vec<Value> = revisions
            .iter()
            .map(|(id, state)| {
                let upstream = if *id == "r1" { &self.one } else { &self.two };
                revision(id, upstream.addr, 1, state)
            })
            .collect();
        let mut pushed = snapshot(version, &[app("a", &["a.test"], &revisions)]);
        if let Some(secret) = secret {
            pushed["skew_secret"] = Value::from(secret);
        }
        let response = self.podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 200, "{response:?}");
    }

    async fn get(&self, cookie: Option<&str>) -> Response {
        let cookie = cookie.map(|value| format!("{COOKIE}={value}"));
        let headers: Vec<(&str, &str)> = cookie.iter().map(|c| ("Cookie", c.as_str())).collect();
        self.podgate.get_with_headers("a.test", "/", &headers).await
    }
}

/// The `Set-Cookie` header split into the cookie value and its attributes.
fn issued(response: &Response) -> Option<(String, String)> {
    let header = response.header("set-cookie")?;
    let (pair, attributes) = header.split_once(';').unwrap_or((header, ""));
    let value = pair.strip_prefix(&format!("{COOKIE}="))?;
    Some((value.to_owned(), attributes.to_owned()))
}

fn cookie_of(response: &Response) -> String {
    issued(response)
        .unwrap_or_else(|| panic!("no {COOKIE} cookie in {response:?}"))
        .0
}

/// Checks the layout the docs promise: `base64url(len(app) || app || revision || mac)` and
/// returns `(app, revision)`. The MAC is recomputed here with the secret.
fn open(value: &str, secret: &str) -> (String, String) {
    let bytes = URL_SAFE_NO_PAD.decode(value).expect("base64url value");
    let (payload, tag) = bytes.split_at(bytes.len() - 32);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("key");
    mac.update(payload);
    mac.verify_slice(tag).expect("HMAC-SHA256 over the payload");
    let app_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
    let app = String::from_utf8(payload[2..2 + app_len].to_vec()).expect("app id");
    let revision = String::from_utf8(payload[2 + app_len..].to_vec()).expect("revision id");
    (app, revision)
}

#[tokio::test]
async fn skew_cookie_set() {
    let rollout = Rollout::start().await;
    rollout.push(1, Some(SECRET), &[("r1", "serving")]).await;

    let response = rollout.get(None).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "one");
    let (value, attributes) = issued(&response).expect("first response sets the cookie");
    assert_eq!(open(&value, SECRET), ("a".to_owned(), "r1".to_owned()));
    assert_eq!(attributes, " Path=/; HttpOnly; SameSite=Lax");

    let pinned = rollout.get(Some(&value)).await;
    assert_eq!(pinned.body, "one");
    assert_eq!(
        pinned.header("set-cookie"),
        None,
        "a request already pinned to the served revision is not re-pinned: {pinned:?}"
    );
}

#[tokio::test]
async fn skew_cookie_secure_on_tls() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("one").await;
    let cert = TestCert::new(&["a.test"]);
    let mut pushed = snapshot(
        1,
        &[app(
            "a",
            &["a.test"],
            &[revision("r1", upstream.addr, 100, "serving")],
        )],
    );
    pushed["skew_secret"] = json!(SECRET);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let response = podgate.https_get("a.test", "a.test", "/", &cert).await;
    let (_, attributes) = issued(&response).expect("cookie over TLS");
    assert_eq!(attributes, " Path=/; HttpOnly; SameSite=Lax; Secure");
}

#[tokio::test]
async fn skew_off_without_a_secret() {
    let rollout = Rollout::start().await;
    rollout.push(1, None, &[("r1", "serving")]).await;

    let response = rollout.get(None).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.header("set-cookie"), None, "{response:?}");
}

#[tokio::test]
async fn skew_pinned() {
    let rollout = Rollout::start().await;
    rollout.push(1, Some(SECRET), &[("r1", "serving")]).await;
    let cookie = cookie_of(&rollout.get(None).await);

    // r2 joins and takes half of the new sessions; the r1 session stays on r1.
    rollout
        .push(2, Some(SECRET), &[("r1", "serving"), ("r2", "serving")])
        .await;
    for _ in 0..20 {
        let response = rollout.get(Some(&cookie)).await;
        assert_eq!(response.body, "one", "{response:?}");
        assert_eq!(response.header("set-cookie"), None, "{response:?}");
    }
    let unpinned: Vec<String> = {
        let mut bodies = Vec::new();
        for _ in 0..20 {
            bodies.push(rollout.get(None).await.body);
        }
        bodies
    };
    assert!(unpinned.iter().any(|body| body == "two"), "{unpinned:?}");

    // r1 retires: no new sessions, but the pinned one is still served by it.
    rollout
        .push(3, Some(SECRET), &[("r1", "retiring"), ("r2", "serving")])
        .await;
    for _ in 0..5 {
        let response = rollout.get(Some(&cookie)).await;
        assert_eq!(response.body, "one", "{response:?}");
        assert_eq!(response.header("set-cookie"), None, "{response:?}");
    }
    for _ in 0..5 {
        let response = rollout.get(None).await;
        assert_eq!(response.body, "two", "{response:?}");
        assert_eq!(open(&cookie_of(&response), SECRET).1, "r2");
    }
}

#[tokio::test]
async fn skew_fallback() {
    let rollout = Rollout::start().await;
    rollout
        .push(1, Some(SECRET), &[("r1", "serving"), ("r2", "serving")])
        .await;
    let mut cookie = None;
    for _ in 0..10 {
        let response = rollout.get(None).await;
        if response.body == "one" {
            cookie = Some(cookie_of(&response));
            break;
        }
    }
    let cookie = cookie.expect("a session lands on r1");

    rollout
        .push(2, Some(SECRET), &[("r1", "draining"), ("r2", "serving")])
        .await;
    let drained = rollout.get(Some(&cookie)).await;
    assert_eq!(drained.body, "two", "{drained:?}");
    assert_eq!(open(&cookie_of(&drained), SECRET).1, "r2");

    // The revision disappears from the snapshot altogether.
    rollout.push(3, Some(SECRET), &[("r2", "serving")]).await;
    let removed = rollout.get(Some(&cookie)).await;
    assert_eq!(removed.body, "two", "{removed:?}");
    assert_eq!(open(&cookie_of(&removed), SECRET).1, "r2");
}

#[tokio::test]
async fn skew_tampered() {
    let rollout = Rollout::start().await;
    rollout
        .push(1, Some(SECRET), &[("r1", "serving"), ("r2", "retiring")])
        .await;
    let cookie = cookie_of(&rollout.get(None).await);
    assert_eq!(open(&cookie, SECRET).1, "r1");

    let mut bytes = URL_SAFE_NO_PAD.decode(&cookie).expect("base64url");
    // Same signature, different revision: the MAC no longer matches.
    let revision_at = bytes.len() - 32 - 1;
    bytes[revision_at] = b'2';
    let forged = URL_SAFE_NO_PAD.encode(&bytes);
    let mut flipped = URL_SAFE_NO_PAD.decode(&cookie).expect("base64url");
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let flipped = URL_SAFE_NO_PAD.encode(&flipped);

    for bad in [forged.as_str(), flipped.as_str(), "garbage", ""] {
        let response = rollout.get(Some(bad)).await;
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(
            response.body, "one",
            "a tampered cookie must not pin to the retiring r2: {response:?}"
        );
        assert_eq!(open(&cookie_of(&response), SECRET).1, "r1", "{response:?}");
    }
}

#[tokio::test]
async fn skew_other_app_cookie_ignored() {
    let podgate = Podgate::start().await;
    let (a, b) = (
        Upstream::start("a-body").await,
        Upstream::start("b-body").await,
    );
    let mut pushed = snapshot(
        1,
        &[
            app("a", &["a.test"], &[revision("r2", a.addr, 100, "serving")]),
            app("b", &["b.test"], &[revision("r2", b.addr, 100, "serving")]),
        ],
    );
    pushed["skew_secret"] = json!(SECRET);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let b_cookie = cookie_of(&podgate.get("b.test", "/").await);
    let response = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[("Cookie", &format!("{COOKIE}={b_cookie}"))],
        )
        .await;
    assert_eq!(response.body, "a-body", "{response:?}");
    assert_eq!(
        open(&cookie_of(&response), SECRET).0,
        "a",
        "the cookie of another app is replaced: {response:?}"
    );
}

#[tokio::test]
async fn skew_short_secret_rejected() {
    let rollout = Rollout::start().await;
    rollout.push(1, Some(SECRET), &[("r1", "serving")]).await;

    let mut pushed = snapshot(
        2,
        &[app(
            "a",
            &["a.test"],
            &[revision("r2", rollout.two.addr, 1, "serving")],
        )],
    );
    pushed["skew_secret"] = json!("too short");
    let response = rollout.podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 422, "{response:?}");
    let body = response.json();
    assert_eq!(body["error"], "snapshot rejected");
    assert_eq!(body["conflicts"][0]["code"], "invalid_skew_secret");
    assert_eq!(
        body["conflicts"][0]["message"],
        "skew_secret must be at least 16 bytes"
    );
    assert!(!response.body.contains("too short"), "{response:?}");

    let live = rollout.get(None).await;
    assert_eq!(
        live.body, "one",
        "the previous snapshot keeps serving: {live:?}"
    );
}

/// An upstream that answers every request `ok` with the raw `headers` lines (`\r\n`-joined by
/// the caller) added to the response.
async fn upstream_with(headers: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    while let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                        seen.drain(..end + 4);
                        let response =
                            format!("HTTP/1.1 200 OK\r\n{headers}\r\nContent-Length: 2\r\n\r\nok");
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
            });
        }
    });
    addr
}

/// Pushes app `a` with one serving revision on an upstream that sends `headers`, and returns
/// the first response for `a.test`.
async fn first_response(headers: &'static str, chain: &[Value]) -> Response {
    let podgate = Podgate::start().await;
    let addr = upstream_with(headers).await;
    let mut pushed = snapshot(
        1,
        &[with_chain(
            app("a", &["a.test"], &[revision("r1", addr, 1, "serving")]),
            chain,
        )],
    );
    pushed["skew_secret"] = json!(SECRET);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    response
}

#[tokio::test]
async fn skew_cookie_not_set_on_public_response() {
    for control in [
        "Cache-Control: max-age=60, Public",
        "Cache-Control: max-age=5\r\nCache-Control: PUBLIC",
    ] {
        let response = first_response(control, &[]).await;
        assert_eq!(
            response.header("set-cookie"),
            None,
            "{control}: {response:?}"
        );
    }
}

#[tokio::test]
async fn skew_cookie_not_set_on_s_maxage_response() {
    let response = first_response("Cache-Control: S-MaxAge=60", &[]).await;
    assert_eq!(response.header("set-cookie"), None, "{response:?}");
}

#[tokio::test]
async fn skew_cookie_not_set_on_max_age_response() {
    for control in [
        "Cache-Control: max-age=60",
        "Expires: Thu, 01 Jan 2099 00:00:00 GMT",
    ] {
        let response = first_response(control, &[]).await;
        assert_eq!(
            response.header("set-cookie"),
            None,
            "{control}: {response:?}"
        );
    }
}

#[tokio::test]
async fn skew_cookie_set_on_private_public_mix() {
    for control in [
        "Cache-Control: public, private",
        "Cache-Control: public\r\nCache-Control: no-store",
        "Cache-Control: s-maxage=60, private",
        "Cache-Control: private, max-age=60",
        "Cache-Control: no-cache",
    ] {
        let response = first_response(control, &[]).await;
        assert!(issued(&response).is_some(), "{control}: {response:?}");
    }
}

#[tokio::test]
async fn skew_cookie_not_set_when_the_chain_makes_it_public() {
    let headers = middleware(
        "cc",
        "headers",
        json!({ "response": { "set": { "cache-control": "public, max-age=60" } } }),
    );
    let response = first_response("X-Plain: 1", &[headers]).await;
    assert_eq!(response.header("set-cookie"), None, "{response:?}");
}
