//! The forwarding headers an upstream receives: the default set, what a client or a
//! trusted proxy sent before, the opt-outs, and how they combine with the `headers` middleware.
//!
//! The upstreams here echo the request headers exactly as they arrived on the wire, which is how
//! a test sees what survived. The test client connects from `127.0.0.1`, so
//! `trusted_ips: ["127.0.0.0/8"]` makes it a trusted proxy and the default (no policy) makes it
//! an ordinary client.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{Podgate, TestCert, app, middleware, serving, snapshot};
use http::Request;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

/// A backend that answers with every request header it saw, as `name: value` lines in wire order
/// and wire case. A request with `Upgrade: websocket` gets `101`, and then the same lines
/// through the tunnel before the connection closes.
struct Echo {
    addr: SocketAddr,
}

impl Echo {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(echo(stream));
            }
        });
        Self { addr }
    }
}

async fn echo(mut stream: TcpStream) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            seen.drain(..end + 4);
            let mut body = String::new();
            for line in head.split("\r\n").skip(1) {
                body.push_str(line);
                body.push('\n');
            }
            let upgrade = head.to_ascii_lowercase().contains("upgrade: websocket");
            let response = if upgrade {
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\n\r\n{body}"
                )
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
            };
            if stream.write_all(response.as_bytes()).await.is_err() || upgrade {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// The values of every echoed request header called `name` (case-insensitive), one per line.
fn seen(body: &str, name: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
        .collect()
}

/// The one value of echoed header `name`; panics when it was sent zero or several times.
fn one(body: &str, name: &str) -> String {
    let mut values = seen(body, name);
    assert_eq!(values.len(), 1, "{name} must be sent exactly once: {body}");
    values.remove(0)
}

/// The echoed header names (wire case, sorted: the wire order of different names is not part of
/// the contract) that carry forwarding information.
fn forwarding_names(body: &str) -> Vec<String> {
    let mut names: Vec<String> = body
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, _)| key)
        .filter(|key| {
            let lower = key.to_ascii_lowercase();
            lower.starts_with("x-forwarded-") || lower == "x-real-ip" || lower == "forwarded"
        })
        .map(str::to_owned)
        .collect();
    names.sort();
    names
}

fn sorted<const N: usize>(names: [&str; N]) -> Vec<String> {
    let mut names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    names.sort();
    names
}

/// App `a` on `a.test` in front of `echo`, with the `forwarded` object `forwarded` when given.
fn echo_app(echo: &Echo, forwarded: Option<Value>) -> Value {
    let mut app = app("a", &["a.test"], &[serving("r1", echo.addr)]);
    if let Some(forwarded) = forwarded {
        app["forwarded"] = forwarded;
    }
    app
}

/// A snapshot of `apps` whose `web` entry point trusts `trusted_ips`, when given.
fn pushed(apps: &[Value], trusted_ips: Option<&[&str]>) -> Value {
    let mut snapshot = snapshot(1, apps);
    if let Some(trusted) = trusted_ips {
        snapshot["entry_points"] =
            json!([{"name": "web", "forwarded_headers": {"trusted_ips": trusted}}]);
    }
    snapshot
}

async fn serve(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// One app `a` with `forwarded`, behind a podgate that trusts `trusted_ips`.
async fn setup(forwarded: Option<Value>, trusted_ips: Option<&[&str]>) -> (Podgate, Echo) {
    let podgate = Podgate::start().await;
    let echo = Echo::start().await;
    serve(
        &podgate,
        &pushed(&[echo_app(&echo, forwarded)], trusted_ips),
    )
    .await;
    (podgate, echo)
}

const FORGED: [(&str, &str); 7] = [
    ("X-Forwarded-For", "1.2.3.4"),
    ("X-Forwarded-Proto", "https"),
    ("X-Forwarded-Host", "evil.test"),
    ("X-Forwarded-Port", "9999"),
    ("X-Forwarded-Server", "evil"),
    ("X-Real-IP", "9.9.9.9"),
    ("Forwarded", "for=8.8.8.8;proto=https"),
];

#[tokio::test]
async fn forwarded_default_set_plain() {
    let (podgate, _echo) = setup(None, None).await;
    let host = format!("A.Test:{}", podgate.proxy_addr.port());

    let response = podgate.get(&host, "/").await;

    assert_eq!(response.status, 200, "{response:?}");
    let body = &response.body;
    assert_eq!(one(body, "x-forwarded-for"), "127.0.0.1");
    assert_eq!(one(body, "x-forwarded-proto"), "http");
    assert_eq!(
        one(body, "x-forwarded-host"),
        host.to_ascii_lowercase(),
        "the Host the client sent, lowercase, port kept"
    );
    assert_eq!(
        one(body, "x-forwarded-port"),
        podgate.proxy_addr.port().to_string()
    );
    assert_eq!(one(body, "x-real-ip"), "127.0.0.1");
    assert_eq!(
        forwarding_names(body),
        sorted([
            "X-Forwarded-For",
            "X-Forwarded-Proto",
            "X-Forwarded-Host",
            "X-Forwarded-Port",
            "X-Real-IP"
        ]),
        "exactly the default set, and no Forwarded or X-Forwarded-Server: {body}"
    );
}

#[tokio::test]
async fn forwarded_default_set_tls() {
    let podgate = Podgate::start().await;
    let echo = Echo::start().await;
    let cert = TestCert::new(&["a.test"]);
    let mut snapshot = pushed(&[echo_app(&echo, None)], None);
    snapshot["certificates"] = json!([cert.entry(&["a.test"])]);
    serve(&podgate, &snapshot).await;
    let host = format!("a.test:{}", podgate.tls_addr.port());

    let response = podgate.https_get("a.test", &host, "/", &cert).await;

    assert_eq!(response.status, 200, "{response:?}");
    let body = &response.body;
    assert_eq!(one(body, "x-forwarded-proto"), "https");
    assert_eq!(one(body, "x-forwarded-for"), "127.0.0.1");
    assert_eq!(one(body, "x-forwarded-host"), host);
    assert_eq!(
        one(body, "x-forwarded-port"),
        podgate.tls_addr.port().to_string()
    );
    assert_eq!(one(body, "x-real-ip"), "127.0.0.1");
}

#[tokio::test]
async fn forwarded_untrusted_inbound_replaced() {
    let (podgate, _echo) = setup(None, None).await;

    let response = podgate.get_with_headers("a.test", "/", &FORGED).await;

    assert_eq!(response.status, 200, "{response:?}");
    let body = &response.body;
    assert_eq!(one(body, "x-forwarded-for"), "127.0.0.1");
    assert_eq!(one(body, "x-forwarded-proto"), "http");
    assert_eq!(one(body, "x-forwarded-host"), "a.test");
    assert_ne!(one(body, "x-forwarded-port"), "9999");
    assert_eq!(one(body, "x-real-ip"), "127.0.0.1");
    assert!(
        seen(body, "forwarded").is_empty() && seen(body, "x-forwarded-server").is_empty(),
        "forged Forwarded and X-Forwarded-Server must not reach the upstream: {body}"
    );
    for forged in ["1.2.3.4", "evil", "9.9.9.9", "8.8.8.8"] {
        assert!(!body.contains(forged), "{forged} leaked: {body}");
    }
}

#[tokio::test]
async fn forwarded_trusted_chain_extended() {
    let (podgate, _echo) = setup(None, Some(&["127.0.0.0/8", "10.0.0.0/8"])).await;

    let response = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("X-Forwarded-For", "203.0.113.7, 10.0.0.2"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "Shop.Example:8443"),
                ("X-Forwarded-Port", "8443"),
                ("X-Forwarded-Prefix", "/app"),
            ],
        )
        .await;

    assert_eq!(response.status, 200, "{response:?}");
    let body = &response.body;
    assert_eq!(
        one(body, "x-forwarded-for"),
        "203.0.113.7, 10.0.0.2, 127.0.0.1",
        "the peer is appended to the chain, never replaces it"
    );
    assert_eq!(one(body, "x-forwarded-proto"), "https");
    assert_eq!(one(body, "x-forwarded-host"), "shop.example:8443");
    assert_eq!(one(body, "x-forwarded-port"), "8443");
    assert_eq!(
        one(body, "x-real-ip"),
        "203.0.113.7",
        "the client is the first address from the right that is not trusted"
    );
    assert_eq!(
        one(body, "x-forwarded-prefix"),
        "/app",
        "headers of other features are never touched"
    );
}

#[tokio::test]
async fn forwarded_trusted_chain_ignores_garbage_entries() {
    let (podgate, _echo) = setup(None, Some(&["127.0.0.0/8"])).await;

    let response = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                (
                    "X-Forwarded-For",
                    "203.0.113.7, <script>, unknown, 2001:DB8::1",
                ),
                ("X-Forwarded-Host", "bad host\\x00,ok.test"),
            ],
        )
        .await;

    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(
        one(&response.body, "x-forwarded-for"),
        "203.0.113.7, 2001:db8::1, 127.0.0.1",
        "only parsed addresses are written, so no byte a client chose is copied"
    );
    assert_eq!(one(&response.body, "x-forwarded-host"), "ok.test");
}

/// A TLS request with `:scheme http` over HTTP/2: the proto must come from the connection.
async fn h2_get(podgate: &Podgate, cert: &TestCert, scheme: &str) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert.der.clone())
        .expect("trust the test certificate");
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let name = rustls::pki_types::ServerName::try_from("a.test".to_owned()).expect("server name");
    let tcp = TcpStream::connect(podgate.tls_addr).await.expect("connect");
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .expect("handshake");
    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(connection);
    let request = Request::get(format!("{scheme}://a.test/"))
        .header("x-forwarded-proto", "http")
        .body(())
        .expect("request");
    let (response, _) = client.send_request(request, true).expect("send request");
    let response = response.await.expect("response");
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut text = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        body.flow_control()
            .release_capacity(chunk.len())
            .expect("release capacity");
        text.extend_from_slice(&chunk);
    }
    String::from_utf8(text).expect("utf-8 body")
}

#[tokio::test]
async fn forwarded_proto_from_connection_state() {
    let podgate = Podgate::start().await;
    let echo = Echo::start().await;
    let cert = TestCert::new(&["a.test"]);
    let mut snapshot = pushed(&[echo_app(&echo, None)], None);
    snapshot["certificates"] = json!([cert.entry(&["a.test"])]);
    serve(&podgate, &snapshot).await;

    let tls_says_http = Box::pin(h2_get(&podgate, &cert, "http")).await;
    assert_eq!(
        one(&tls_says_http, "x-forwarded-proto"),
        "https",
        ":scheme http on a TLS connection is still https, and the client's own header lost"
    );
    let tls_says_https = Box::pin(h2_get(&podgate, &cert, "https")).await;
    assert_eq!(one(&tls_says_https, "x-forwarded-proto"), "https");

    let plain_claims_https = podgate
        .get_with_headers("a.test", "/", &[("X-Forwarded-Proto", "https")])
        .await;
    assert_eq!(
        one(&plain_claims_https.body, "x-forwarded-proto"),
        "http",
        "an untrusted peer cannot claim TLS"
    );
}

#[tokio::test]
async fn forwarded_replace_not_duplicate() {
    let (podgate, _echo) = setup(None, Some(&["127.0.0.0/8"])).await;

    let response = podgate
        .request(
            "GET",
            "a.test",
            "/",
            &[
                ("X-Forwarded-For", "203.0.113.7"),
                ("X-Forwarded-For", "198.51.100.9"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Proto", "http"),
                ("X-Forwarded-Host", "one.test"),
                ("X-Forwarded-Host", "two.test"),
                ("X-Forwarded-Port", "443"),
                ("X-Forwarded-Port", "444"),
                ("X-Real-IP", "198.51.100.9"),
                ("X-Real-IP", "203.0.113.7"),
            ],
        )
        .await;

    assert_eq!(response.status, 200, "{response:?}");
    for name in [
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-real-ip",
    ] {
        let _ = one(&response.body, name);
    }
    assert_eq!(
        one(&response.body, "x-forwarded-for"),
        "203.0.113.7, 198.51.100.9, 127.0.0.1"
    );
    assert_eq!(
        one(&response.body, "x-forwarded-host"),
        "two.test",
        "the nearest trusted proxy's value, the last one"
    );
}

#[tokio::test]
async fn forwarded_chain_bounded() {
    let (podgate, _echo) = setup(None, Some(&["127.0.0.0/8"])).await;
    let chain: Vec<String> = (1..=64)
        .map(|n| format!("2001:db8:1234:5678:9abc:def0:1234:{n:x}"))
        .collect();

    let response = podgate
        .get_with_headers("a.test", "/", &[("X-Forwarded-For", &chain.join(", "))])
        .await;

    assert_eq!(response.status, 200, "{response:?}");
    let value = one(&response.body, "x-forwarded-for");
    assert!(value.len() <= 1024, "{} bytes", value.len());
    assert!(
        value.ends_with(&format!("{}, 127.0.0.1", chain[63])),
        "the newest entries stay: {value}"
    );
    assert!(
        !value.contains(&chain[0]),
        "the oldest entries are dropped: {value}"
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    let dropped: u64 = metrics
        .lines()
        .find_map(|line| line.strip_prefix("podgate_forwarded_chain_truncated_total "))
        .and_then(|count| count.trim().parse().ok())
        .expect("the truncation counter is exposed");
    assert!(dropped > 0, "dropped entries are counted: {metrics}");
}

#[tokio::test]
async fn forwarded_on_upgrade() {
    let (podgate, _echo) = setup(None, None).await;
    let mut socket = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    socket
        .write_all(
            b"GET /chat HTTP/1.1\r\nHost: a.test\r\nX-Forwarded-For: 1.2.3.4\r\n\
              Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .expect("send the upgrade");
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut raw))
        .await
        .expect("the tunnel closes")
        .expect("read");
    let text = String::from_utf8_lossy(&raw);

    assert!(text.starts_with("HTTP/1.1 101"), "{text}");
    let (_, body) = text.split_once("\r\n\r\n").expect("a response head");
    assert_eq!(one(body, "x-forwarded-for"), "127.0.0.1");
    assert_eq!(one(body, "x-forwarded-proto"), "http");
    assert_eq!(one(body, "x-forwarded-host"), "a.test");
    assert_eq!(one(body, "x-real-ip"), "127.0.0.1");
}

#[tokio::test]
async fn forwarded_headers_middleware_overrides() {
    let podgate = Podgate::start().await;
    let echo = Echo::start().await;
    let mut app = echo_app(&echo, None);
    app["middlewares"] = json!([middleware(
        "h",
        "headers",
        json!({"request": {
            "set": {"x-forwarded-proto": "https", "x-forwarded-host": "public.example"},
            "remove": ["x-real-ip"],
        }}),
    )]);
    app["default_chain"] = json!(["h"]);
    serve(&podgate, &pushed(&[app], None)).await;

    let response = podgate.get("a.test", "/").await;

    assert_eq!(response.status, 200, "{response:?}");
    let body = &response.body;
    assert_eq!(one(body, "x-forwarded-proto"), "https", "explicit override");
    assert_eq!(one(body, "x-forwarded-host"), "public.example");
    assert!(
        seen(body, "x-real-ip").is_empty(),
        "explicit removal: {body}"
    );
    assert_eq!(
        one(body, "x-forwarded-for"),
        "127.0.0.1",
        "what the middleware leaves alone stays"
    );
}

#[tokio::test]
async fn forwarded_opt_outs() {
    let (podgate, _echo) = setup(Some(json!({"x_forwarded": false})), None).await;
    let response = podgate.get_with_headers("a.test", "/", &FORGED).await;
    assert_eq!(
        forwarding_names(&response.body),
        ["X-Real-IP"],
        "x_forwarded: false leaves only X-Real-IP: {}",
        response.body
    );

    let (podgate, _echo) = setup(Some(json!({"real_ip": false})), None).await;
    let response = podgate.get_with_headers("a.test", "/", &FORGED).await;
    assert_eq!(
        forwarding_names(&response.body),
        sorted([
            "X-Forwarded-For",
            "X-Forwarded-Proto",
            "X-Forwarded-Host",
            "X-Forwarded-Port"
        ]),
        "real_ip: false drops X-Real-IP: {}",
        response.body
    );

    let (podgate, _echo) = setup(
        Some(json!({"x_forwarded": false, "real_ip": false})),
        Some(&["127.0.0.0/8"]),
    )
    .await;
    let response = podgate
        .get_with_headers("a.test", "/", &[("X-Forwarded-For", "203.0.113.7")])
        .await;
    assert_eq!(
        one(&response.body, "x-forwarded-for"),
        "203.0.113.7",
        "an opt-out stops podgate writing: a trusted proxy's own header passes through"
    );
    assert!(seen(&response.body, "x-real-ip").is_empty());

    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    let rejected = podgate
        .push_snapshot(&pushed(
            &[echo_app(
                &echo,
                Some(json!({"real_ip": false, "realip": true})),
            )],
            None,
        ))
        .await;
    assert!(
        rejected.status == 400 || rejected.status == 422,
        "a misspelt option must be refused, not ignored: {rejected:?}"
    );
}

#[tokio::test]
async fn forwarded_rfc7239() {
    let (podgate, _echo) = setup(Some(json!({"rfc7239": true})), None).await;
    let host = format!("a.test:{}", podgate.proxy_addr.port());

    let response = podgate
        .get_with_headers(&host, "/", &[("Forwarded", "for=8.8.8.8;proto=https")])
        .await;

    assert_eq!(
        one(&response.body, "forwarded"),
        format!("for=127.0.0.1;proto=http;host=\"{host}\""),
        "an untrusted peer's Forwarded is replaced: {}",
        response.body
    );
    assert_eq!(one(&response.body, "x-forwarded-for"), "127.0.0.1");

    let (podgate, _echo) = setup(Some(json!({"rfc7239": true})), Some(&["127.0.0.0/8"])).await;
    let response = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("X-Forwarded-For", "203.0.113.7"),
                ("X-Forwarded-Proto", "https"),
            ],
        )
        .await;
    assert_eq!(
        one(&response.body, "forwarded"),
        "for=203.0.113.7, for=127.0.0.1;proto=https;host=\"a.test\"",
        "a trusted chain is extended: {}",
        response.body
    );
}

#[tokio::test]
async fn forwarded_server_header_opt_in() {
    let podgate = Podgate::start_with_env(&[("NODE_NAME", "node-a")]).await;
    let echo = Echo::start().await;
    let mut named = app("named", &["named.test"], &[serving("r1", echo.addr)]);
    named["forwarded"] = json!({"server": true});
    let plain = app("plain", &["plain.test"], &[serving("r1", echo.addr)]);
    serve(&podgate, &pushed(&[named, plain], None)).await;

    let opted_in = podgate
        .get_with_headers("named.test", "/", &[("X-Forwarded-Server", "evil")])
        .await;
    assert_eq!(one(&opted_in.body, "x-forwarded-server"), "node-a");
    assert_eq!(
        forwarding_names(&opted_in.body),
        sorted([
            "X-Forwarded-For",
            "X-Forwarded-Proto",
            "X-Forwarded-Host",
            "X-Forwarded-Port",
            "X-Real-IP",
            "X-Forwarded-Server"
        ])
    );

    let default = podgate
        .get_with_headers("plain.test", "/", &[("X-Forwarded-Server", "evil")])
        .await;
    assert!(
        seen(&default.body, "x-forwarded-server").is_empty(),
        "the node name is not disclosed unless the app asks: {}",
        default.body
    );
}

#[tokio::test]
async fn forwarded_connection_nomination_is_refused() {
    let (podgate, _echo) = setup(None, None).await;

    let response = podgate
        .get_with_headers("a.test", "/", &[("Connection", "close, X-Real-IP")])
        .await;

    assert_eq!(
        response.status, 400,
        "a Connection header must not make the next hop drop X-Real-IP: {response:?}"
    );
}

#[tokio::test]
async fn explain_shows_forwarded_set() {
    let (podgate, _echo) = setup(Some(json!({"rfc7239": true, "real_ip": false})), None).await;

    let explained = podgate.admin_get("/v1/explain?url=http://a.test/").await;

    assert_eq!(explained.status, 200, "{explained:?}");
    let stage = explained.json()["pipeline"]
        .as_array()
        .and_then(|stages| stages.iter().find(|s| s["stage"] == "forwarded_headers"))
        .cloned()
        .expect("a forwarded_headers stage");
    assert_eq!(
        stage["headers"],
        json!([
            "X-Forwarded-For",
            "X-Forwarded-Proto",
            "X-Forwarded-Host",
            "X-Forwarded-Port",
            "Forwarded"
        ])
    );
}

/// The headers of one recording in `tests/fixtures/forwarded/recorded.json`, lowercase names.
fn recorded(proxy: &Value, case: &str) -> Vec<(String, String)> {
    proxy[case]
        .as_array()
        .unwrap_or_else(|| panic!("recording {case}"))
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().expect("name").to_ascii_lowercase(),
                pair[1].as_str().expect("value").to_owned(),
            )
        })
        .collect()
}

fn forwarding(headers: &[(String, String)]) -> Vec<&(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| {
            name.starts_with("x-forwarded-") || name == "x-real-ip" || name == "forwarded"
        })
        .collect()
}

#[tokio::test]
async fn forwarded_matches_recorded_proxies() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/forwarded/recorded.json"))
        .expect("the recording is JSON");
    let (caddy, traefik) = (&fixture["caddy"], &fixture["traefik"]);
    let (podgate, _echo) = setup(None, None).await;
    let host = format!("a.test:{}", podgate.proxy_addr.port());
    let response = podgate.get(&host, "/").await;
    let ours: Vec<(String, String)> = response
        .body
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let our_names: Vec<&str> = forwarding(&ours)
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();

    for case in ["plain", "tls"] {
        for proxy in [caddy, traefik] {
            let theirs = recorded(proxy, case);
            for (name, value) in forwarding(&theirs) {
                if name == "x-forwarded-server" {
                    continue;
                }
                assert!(
                    our_names.contains(&name.as_str()),
                    "podgate lacks {name}, which {} sends ({case}): {our_names:?}",
                    proxy["version"]
                );
                if name == "x-forwarded-for" || name == "x-real-ip" {
                    assert_eq!(value, "127.0.0.1", "a loopback client in the recording");
                }
            }
        }
    }
    let traefik_plain = recorded(traefik, "plain");
    let mut traefik_set: Vec<&str> = forwarding(&traefik_plain)
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| *name != "x-forwarded-server")
        .collect();
    traefik_set.sort_unstable();
    let mut ours_sorted = our_names.clone();
    ours_sorted.sort_unstable();
    assert_eq!(
        ours_sorted, traefik_set,
        "podgate's default set is Traefik's minus X-Forwarded-Server"
    );

    let sent_host = recorded(traefik, "plain")
        .into_iter()
        .find(|(name, _)| name == "host")
        .map(|(_, value)| value)
        .expect("the recording has the Host the client sent");
    let echoed = recorded(traefik, "plain")
        .into_iter()
        .find(|(name, _)| name == "x-forwarded-host")
        .map(|(_, value)| value);
    assert_eq!(
        echoed.as_deref(),
        Some(sent_host.as_str()),
        "both proxies copy the Host with its port"
    );
    let ours_host = ours
        .iter()
        .find(|(name, _)| name == "x-forwarded-host")
        .map(|(_, value)| value.as_str());
    assert_eq!(ours_host, Some(host.as_str()), "so does podgate");
    for (name, value) in recorded(caddy, "forged_plain")
        .into_iter()
        .chain(recorded(traefik, "forged_plain"))
    {
        if name == "x-forwarded-for" {
            assert_eq!(
                value, "127.0.0.1",
                "both replace a forged chain from an untrusted peer"
            );
        }
    }
}
