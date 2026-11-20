//! Sticky cookie on a `loadbalancer`: the first response pins a client to one
//! server, the cookie reveals no address and cannot be forged, and an unusable pin falls back to
//! the balancer.

mod common;

use std::net::SocketAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Podgate, Response, TestCert, Upstream, app, router, snapshot};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SECRET: &str = "a-secret-of-at-least-16-bytes";
const NAME: &str = "__podgate_srv";

/// A service `name` balancing `servers` round robin, with `sticky` set.
fn sticky_service(name: &str, servers: &[SocketAddr], sticky: &Value) -> Value {
    let servers: Vec<Value> = servers
        .iter()
        .map(|addr| json!({ "url": format!("http://{addr}") }))
        .collect();
    json!({ "name": name, "type": "loadbalancer", "servers": servers, "sticky": sticky })
}

fn serving(id: &str, services: &[Value]) -> Value {
    json!({ "id": id, "state": "serving", "weight": 100, "services": services })
}

/// App `a` (`a.test`) with one sticky `web` service over `servers`.
fn sticky_app(servers: &[SocketAddr], sticky: &Value) -> Value {
    app(
        "a",
        &["a.test"],
        &[serving("r1", &[sticky_service("web", servers, sticky)])],
    )
}

fn pushed(version: u64, apps: &[Value]) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["skew_secret"] = json!(SECRET);
    pushed
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// The values of every `Set-Cookie` header of `response`.
fn set_cookies(response: &Response) -> Vec<&str> {
    response
        .headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .map(|(_, value)| value.as_str())
        .collect()
}

/// The `Set-Cookie` header of cookie `name`, whole.
fn header_of<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
    set_cookies(response)
        .into_iter()
        .find(|header| header.starts_with(&format!("{name}=")))
}

/// The value of cookie `name` that `response` sets.
fn cookie_of(response: &Response, name: &str) -> String {
    let header = header_of(response, name)
        .unwrap_or_else(|| panic!("no {name} cookie in {:?}", set_cookies(response)));
    let (pair, _) = header.split_once(';').unwrap_or((header, ""));
    pair[name.len() + 1..].to_owned()
}

async fn get(podgate: &Podgate, host: &str, path: &str, cookie: &str) -> Response {
    podgate
        .get_with_headers(host, path, &[("Cookie", cookie)])
        .await
}

async fn three_servers() -> [Upstream; 3] {
    [
        Upstream::start("one").await,
        Upstream::start("two").await,
        Upstream::start("three").await,
    ]
}

fn addrs(upstreams: &[Upstream]) -> Vec<SocketAddr> {
    upstreams.iter().map(|upstream| upstream.addr).collect()
}

#[tokio::test]
async fn sticky_pins_to_one_server() {
    let podgate = Podgate::start().await;
    let servers = three_servers().await;
    push(
        &podgate,
        &pushed(1, &[sticky_app(&addrs(&servers), &json!({ "cookie": {} }))]),
    )
    .await;

    let first = podgate.get("a.test", "/").await;
    let cookie = format!("{NAME}={}", cookie_of(&first, NAME));
    for _ in 0..9 {
        let again = get(&podgate, "a.test", "/", &format!("x=1; {cookie}; y=2")).await;
        assert_eq!(again.body, first.body);
        assert!(
            header_of(&again, NAME).is_none(),
            "a pinned client is not given the cookie again: {:?}",
            set_cookies(&again)
        );
    }
    let mut bodies: Vec<String> = Vec::new();
    for _ in 0..6 {
        bodies.push(podgate.get("a.test", "/").await.body);
    }
    bodies.sort();
    bodies.dedup();
    assert!(bodies.len() > 1, "clients without the cookie still balance");
}

#[tokio::test]
async fn sticky_tampered_cookie_ignored() {
    let podgate = Podgate::start().await;
    let servers = three_servers().await;
    push(
        &podgate,
        &pushed(1, &[sticky_app(&addrs(&servers), &json!({ "cookie": {} }))]),
    )
    .await;

    let genuine = cookie_of(&podgate.get("a.test", "/").await, NAME);
    let mut flipped = genuine.clone().into_bytes();
    flipped[0] = if flipped[0] == b'A' { b'B' } else { b'A' };
    let flipped = String::from_utf8(flipped).expect("ascii");
    let other_length = format!("{genuine}A");
    for bad in [
        flipped.as_str(),
        other_length.as_str(),
        "",
        "!!!!",
        "127.0.0.1:1",
    ] {
        let mut bodies = Vec::new();
        for _ in 0..6 {
            let response = get(&podgate, "a.test", "/", &format!("{NAME}={bad}")).await;
            assert!(
                header_of(&response, NAME).is_some(),
                "a refused cookie is replaced: {bad:?}"
            );
            bodies.push(response.body);
        }
        bodies.sort();
        bodies.dedup();
        assert!(bodies.len() > 1, "{bad:?} must not pin: {bodies:?}");
    }
}

#[tokio::test]
async fn sticky_cookie_is_per_app_and_service() {
    let podgate = Podgate::start().await;
    let servers = three_servers().await;
    let cookie = json!({ "cookie": {} });
    let mut other = app(
        "b",
        &["b.test"],
        &[serving(
            "r1",
            &[sticky_service("web", &addrs(&servers), &cookie)],
        )],
    );
    other["declared_by"] = json!("tests/b");
    let mut same_app = sticky_app(&addrs(&servers), &cookie);
    same_app["routers"] = json!([
        router(
            "api",
            json!({ "all": [{ "host": "a.test" }, { "path_prefix": "/api" }] }),
            "api"
        ),
        router("default", json!({ "host": ["a.test"] }), "web"),
    ]);
    same_app["revisions"][0]["services"]
        .as_array_mut()
        .expect("services")
        .push(sticky_service("api", &addrs(&servers), &cookie));
    push(&podgate, &pushed(1, &[same_app, other])).await;

    let from_web = cookie_of(&podgate.get("a.test", "/").await, NAME);
    let header = format!("{NAME}={from_web}");
    for (host, path) in [("b.test", "/"), ("a.test", "/api")] {
        let mut bodies = Vec::new();
        for _ in 0..6 {
            let response = get(&podgate, host, path, &header).await;
            assert_ne!(
                cookie_of(&response, NAME),
                from_web,
                "{host}{path} signs its own cookie"
            );
            bodies.push(response.body);
        }
        bodies.sort();
        bodies.dedup();
        assert!(
            bodies.len() > 1,
            "{host}{path} must not be pinned: {bodies:?}"
        );
    }
    let again = get(&podgate, "a.test", "/", &header).await;
    assert!(
        header_of(&again, NAME).is_none(),
        "its own service still pins"
    );
}

#[tokio::test]
async fn sticky_falls_back_and_repins() {
    let podgate = Podgate::start().await;
    let servers = three_servers().await;
    push(
        &podgate,
        &pushed(1, &[sticky_app(&addrs(&servers), &json!({ "cookie": {} }))]),
    )
    .await;
    let first = podgate.get("a.test", "/").await;
    let old = cookie_of(&first, NAME);
    let pinned = ["one", "two", "three"]
        .iter()
        .position(|name| *name == first.body)
        .expect("a known server");

    // The pinned server leaves the service.
    let remaining: Vec<SocketAddr> = addrs(&servers)
        .into_iter()
        .enumerate()
        .filter(|(index, _)| *index != pinned)
        .map(|(_, addr)| addr)
        .collect();
    push(
        &podgate,
        &pushed(2, &[sticky_app(&remaining, &json!({ "cookie": {} }))]),
    )
    .await;

    let header = format!("{NAME}={old}");
    let moved = get(&podgate, "a.test", "/", &header).await;
    assert_eq!(moved.status, 200, "first {first:?}, moved {moved:?}");
    assert_ne!(
        moved.body, first.body,
        "the removed server is not used: first {first:?}, moved {moved:?}"
    );
    let fresh = cookie_of(&moved, NAME);
    assert_ne!(fresh, old, "the client is pinned again: {moved:?}");
    let fresh_header = format!("{NAME}={fresh}");
    for _ in 0..5 {
        let again = get(&podgate, "a.test", "/", &fresh_header).await;
        assert_eq!(again.body, moved.body, "moved {moved:?}, again {again:?}");
        assert!(
            header_of(&again, NAME).is_none(),
            "moved {moved:?}, again {again:?}"
        );
    }
    // The old cookie is still refused, not remembered.
    let stale = get(&podgate, "a.test", "/", &header).await;
    assert!(header_of(&stale, NAME).is_some(), "{stale:?}");
}

#[tokio::test]
async fn sticky_cookie_attributes() {
    let podgate = Podgate::start().await;
    let server = Upstream::start("one").await;
    let cert = TestCert::new(&["a.test"]);
    let mut plain = pushed(1, &[sticky_app(&[server.addr], &json!({ "cookie": {} }))]);
    plain["certificates"] = json!([cert.entry(&["a.test"])]);
    push(&podgate, &plain).await;

    let response = podgate.get("a.test", "/").await;
    let header = header_of(&response, NAME).expect("cookie");
    assert!(
        header.ends_with("; Path=/; HttpOnly; SameSite=Lax"),
        "{header}"
    );
    let over_tls = podgate.https_get("a.test", "a.test", "/", &cert).await;
    let header = header_of(&over_tls, NAME).expect("cookie over TLS");
    assert!(
        header.ends_with("; Path=/; HttpOnly; SameSite=Lax; Secure"),
        "{header}"
    );

    let custom = json!({ "cookie": {
        "name": "pin", "secure": true, "http_only": false, "same_site": "strict",
        "max_age_secs": 600, "path": "/shop",
    } });
    let mut next = pushed(2, &[sticky_app(&[server.addr], &custom)]);
    next["certificates"] = json!([cert.entry(&["a.test"])]);
    push(&podgate, &next).await;
    let response = podgate.get("a.test", "/").await;
    let header = header_of(&response, "pin").expect("named cookie");
    assert!(
        header.ends_with("; Path=/shop; SameSite=Strict; Max-Age=600; Secure"),
        "{header}"
    );
    assert!(header_of(&response, NAME).is_none());
}

#[tokio::test]
async fn sticky_requires_skew_secret() {
    let podgate = Podgate::start().await;
    let server = Upstream::start("one").await;
    let without = snapshot(1, &[sticky_app(&[server.addr], &json!({ "cookie": {} }))]);
    let response = podgate.push_snapshot(&without).await;
    assert_eq!(response.status, 422, "{}", response.body);
    let body = response.json();
    assert_eq!(body["conflicts"][0]["code"], "invalid_service", "{body}");
    assert!(
        body["conflicts"][0]["message"]
            .as_str()
            .is_some_and(|message| message.contains("skew_secret")),
        "{body}"
    );

    for bad in [
        json!({}),
        json!({ "cookie": { "name": "__podgate_rev" } }),
        json!({ "cookie": { "same_site": "none" } }),
        json!({ "cookie": { "max_age_secs": 0 } }),
    ] {
        let response = podgate
            .push_snapshot(&pushed(2, &[sticky_app(&[server.addr], &bad)]))
            .await;
        assert_eq!(response.status, 422, "{bad}: {}", response.body);
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_service",
            "{bad}"
        );
    }
}

/// An upstream that answers `GET` with `body` and the given `Cache-Control`.
async fn caching_upstream(cache_control: &'static str) -> SocketAddr {
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
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nCache-Control: {cache_control}\r\n\
                             Content-Length: 2\r\n\r\nok"
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
            });
        }
    });
    addr
}

#[tokio::test]
async fn sticky_not_set_on_public_responses() {
    let podgate = Podgate::start().await;
    let public = caching_upstream("max-age=60, Public").await;
    let private = caching_upstream("private").await;
    let sticky = json!({ "cookie": {} });
    push(
        &podgate,
        &pushed(
            1,
            &[
                sticky_app(&[public], &sticky),
                app(
                    "b",
                    &["b.test"],
                    &[serving("r1", &[sticky_service("web", &[private], &sticky)])],
                ),
            ],
        ),
    )
    .await;

    let shared = podgate.get("a.test", "/").await;
    assert_eq!(shared.status, 200);
    assert!(
        header_of(&shared, NAME).is_none(),
        "a shared cache must not store a pin: {:?}",
        set_cookies(&shared)
    );
    let personal = podgate.get("b.test", "/").await;
    assert!(header_of(&personal, NAME).is_some(), "{personal:?}");
}

#[tokio::test]
async fn sticky_cookie_hides_address() {
    let podgate = Podgate::start().await;
    let servers = three_servers().await;
    let addrs = addrs(&servers);
    push(
        &podgate,
        &pushed(1, &[sticky_app(&addrs, &json!({ "cookie": {} }))]),
    )
    .await;

    let response = podgate.get("a.test", "/").await;
    let value = cookie_of(&response, NAME);
    assert_eq!(value.len(), 22, "{value}");
    let bytes = URL_SAFE_NO_PAD.decode(&value).expect("base64url");
    assert_eq!(bytes.len(), 16);
    for addr in &addrs {
        let url = format!("http://{addr}");
        assert!(
            !value.contains(&addr.port().to_string()) && !value.contains(&addr.ip().to_string()),
            "{value} names {addr}"
        );
        assert!(
            !bytes
                .windows(4)
                .any(|window| url.as_bytes().windows(4).any(|part| part == window)),
            "{value} carries bytes of {url}"
        );
    }

    // The documented derivation: HMAC-SHA256(skew_secret, label || len(app) || app ||
    // len(service) || service || url), first 16 bytes.
    let served = ["one", "two", "three"]
        .iter()
        .position(|name| *name == response.body)
        .expect("a known server");
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("key");
    mac.update(b"podgate/sticky/v1");
    mac.update(&1_u16.to_be_bytes());
    mac.update(b"a");
    mac.update(&3_u16.to_be_bytes());
    mac.update(b"web");
    mac.update(format!("http://{}", addrs[served]).as_bytes());
    assert_eq!(bytes, mac.finalize().into_bytes()[..16]);
}

#[tokio::test]
async fn sticky_composes_with_revision_pinning() {
    let podgate = Podgate::start().await;
    let (r1a, r1b, r2a, r2b) = (
        Upstream::start("r1a").await,
        Upstream::start("r1b").await,
        Upstream::start("r2a").await,
        Upstream::start("r2b").await,
    );
    let sticky = json!({ "cookie": {} });
    let revisions = [
        serving(
            "r1",
            &[sticky_service("web", &[r1a.addr, r1b.addr], &sticky)],
        ),
        serving(
            "r2",
            &[sticky_service("web", &[r2a.addr, r2b.addr], &sticky)],
        ),
    ];
    push(&podgate, &pushed(1, &[app("a", &["a.test"], &revisions)])).await;

    let first = podgate.get("a.test", "/").await;
    let revision = cookie_of(&first, "__podgate_rev");
    let server = cookie_of(&first, NAME);
    let header = format!("__podgate_rev={revision}; {NAME}={server}");
    for _ in 0..8 {
        let again = get(&podgate, "a.test", "/", &header).await;
        assert_eq!(again.body, first.body, "both pins hold");
        assert!(
            set_cookies(&again).is_empty(),
            "a fully pinned client is given nothing: {:?}",
            set_cookies(&again)
        );
    }
    // Only the revision pin: the server is chosen inside that revision and pinned.
    let only_revision = get(
        &podgate,
        "a.test",
        "/",
        &format!("__podgate_rev={revision}"),
    )
    .await;
    assert_eq!(&only_revision.body[..2], &first.body[..2]);
    assert!(header_of(&only_revision, NAME).is_some());
    assert!(header_of(&only_revision, "__podgate_rev").is_none());
}
