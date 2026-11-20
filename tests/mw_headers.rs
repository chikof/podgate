//! The `headers` and `content_type` middlewares: header edits, security headers,
//! CORS, and the headers a tenant may never touch.

mod common;

use std::net::SocketAddr;

use common::{Podgate, Response, TestCert, Upstream, app, middleware, serving, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A backend that answers with the head of the request it got as the body, plus `extra` response
/// headers, and a `Content-Type` unless `content_type` is false.
struct Echo {
    addr: SocketAddr,
}

impl Echo {
    async fn start(extra: &'static [(&'static str, &'static str)], content_type: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(echo_connection(stream, extra, content_type));
            }
        });
        Self { addr }
    }
}

async fn echo_connection(
    mut stream: TcpStream,
    extra: &'static [(&'static str, &'static str)],
    content_type: bool,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
            seen.drain(..end + 4);
            let mut response = String::from("HTTP/1.1 200 OK\r\n");
            if content_type {
                response.push_str("Content-Type: text/plain\r\n");
            }
            for (name, value) in extra {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str(&format!("Content-Length: {}\r\n\r\n{head}", head.len()));
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

/// The values of request header `name` the upstream saw.
fn seen(response: &Response, name: &str) -> Vec<String> {
    let prefix = format!("{name}:");
    response
        .body
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(|value| value.trim().to_owned())
        .collect()
}

/// All values of response header `name`.
fn all(response: &Response, name: &str) -> Vec<String> {
    response
        .headers
        .iter()
        .filter(|(header, _)| header == name)
        .map(|(_, value)| value.clone())
        .collect()
}

/// An app on `host` in front of `upstream`, with one `headers` middleware `config` in its chain.
fn chained(host: &str, upstream: SocketAddr, kind: &str, config: Value) -> Value {
    let mut app = app(host, &[host], &[serving("r1", upstream)]);
    app["middlewares"] = json!([middleware("m", kind, config)]);
    app["default_chain"] = json!(["m"]);
    app
}

async fn serve(config: Value, echo: &Echo) -> Podgate {
    let podgate = Podgate::start().await;
    let pushed = snapshot(1, &[chained("a.test", echo.addr, "headers", config)]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    podgate
}

async fn rejection(config: Value, kind: &str) -> Value {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let response = podgate
        .push_snapshot(&snapshot(1, &[chained("a.test", up.addr, kind, config)]))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    response.json()["conflicts"][0].clone()
}

#[tokio::test]
async fn headers_request_set_remove() {
    let echo = Echo::start(&[], true).await;
    let podgate = serve(
        json!({ "request": { "set": { "X-Tenant": "acme" }, "remove": ["x-debug"] } }),
        &echo,
    )
    .await;
    let response = podgate
        .get_with_headers("a.test", "/", &[("X-Debug", "1"), ("X-Keep", "yes")])
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(seen(&response, "x-tenant"), ["acme"]);
    assert!(seen(&response, "x-debug").is_empty(), "{}", response.body);
    assert_eq!(seen(&response, "x-keep"), ["yes"]);
}

#[tokio::test]
async fn headers_response_set_remove() {
    let echo = Echo::start(&[("X-Internal", "secret")], true).await;
    let podgate = serve(
        json!({ "response": { "set": { "x-served-by": "podgate" }, "remove": ["X-Internal"] } }),
        &echo,
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(all(&response, "x-served-by"), ["podgate"]);
    assert!(all(&response, "x-internal").is_empty(), "{response:?}");
}

#[tokio::test]
async fn headers_overwrite_client_values() {
    let echo = Echo::start(&[("X-Served-By", "upstream")], true).await;
    let podgate = serve(
        json!({
            "request": { "set": { "x-tenant": "acme" } },
            "response": { "set": { "x-served-by": "podgate" } }
        }),
        &echo,
    )
    .await;
    let response = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[("X-Tenant", "evil"), ("x-tenant", "worse")],
        )
        .await;
    assert_eq!(seen(&response, "x-tenant"), ["acme"], "{}", response.body);
    assert_eq!(all(&response, "x-served-by"), ["podgate"]);
}

const SECURITY: fn() -> Value = || {
    json!({ "response": { "security": {
        "hsts": { "max_age_secs": 100, "include_subdomains": true, "preload": true },
        "csp": "default-src 'self'",
        "csp_report_only": "default-src 'none'",
        "frame_options": "DENY",
        "content_type_nosniff": true,
        "referrer_policy": "no-referrer",
        "permissions_policy": "camera=()",
        "cross_origin_opener_policy": "same-origin",
        "cross_origin_resource_policy": "same-site"
    } } })
};

#[tokio::test]
async fn headers_security_set() {
    let echo = Echo::start(&[("X-Frame-Options", "ALLOWALL")], true).await;
    let podgate = serve(SECURITY(), &echo).await;
    let response = podgate.get("a.test", "/").await;
    for (name, value) in [
        ("content-security-policy", "default-src 'self'"),
        ("content-security-policy-report-only", "default-src 'none'"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("permissions-policy", "camera=()"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-site"),
    ] {
        assert_eq!(all(&response, name), [value], "{name}: {response:?}");
    }
}

#[tokio::test]
async fn hsts_only_over_tls() {
    let podgate = Podgate::start().await;
    let echo = Echo::start(&[], true).await;
    let cert = TestCert::new(&["a.test"]);
    let mut pushed = snapshot(1, &[chained("a.test", echo.addr, "headers", SECURITY())]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let plain = podgate.get("a.test", "/").await;
    assert_eq!(plain.status, 200, "{plain:?}");
    assert!(all(&plain, "strict-transport-security").is_empty());
    assert_eq!(all(&plain, "x-frame-options"), ["DENY"]);

    let tls = podgate.https_get("a.test", "a.test", "/", &cert).await;
    assert_eq!(tls.status, 200, "{tls:?}");
    assert_eq!(
        all(&tls, "strict-transport-security"),
        ["max-age=100; includeSubDomains; preload"]
    );
}

fn cors_config() -> Value {
    json!({ "cors": {
        "allow_origins": ["https://app.test"],
        "allow_origin_regexes": ["https://[a-z0-9]+\\.preview\\.test"],
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["content-type", "x-token"],
        "expose_headers": ["x-request-id"],
        "allow_credentials": true,
        "max_age_secs": 600
    } })
}

#[tokio::test]
async fn cors_preflight_allowed() {
    let echo = Echo::start(&[], true).await;
    let podgate = serve(cors_config(), &echo).await;
    for origin in ["https://app.test", "https://pr7.preview.test"] {
        let response = podgate
            .request(
                "OPTIONS",
                "a.test",
                "/",
                &[
                    ("Origin", origin),
                    ("Access-Control-Request-Method", "POST"),
                    ("Access-Control-Request-Headers", "x-other"),
                ],
            )
            .await;
        assert_eq!(response.status, 204, "{response:?}");
        assert_eq!(all(&response, "access-control-allow-origin"), [origin]);
        assert_eq!(
            all(&response, "access-control-allow-methods"),
            ["GET, POST"]
        );
        assert_eq!(
            all(&response, "access-control-allow-headers"),
            ["content-type, x-token"],
            "the request's headers are never reflected"
        );
        assert_eq!(all(&response, "access-control-max-age"), ["600"]);
        assert_eq!(all(&response, "access-control-allow-credentials"), ["true"]);
        assert_eq!(all(&response, "vary"), ["Origin"]);
        assert!(response.body.is_empty(), "{response:?}");
    }
    let actual = podgate
        .get_with_headers("a.test", "/", &[("Origin", "https://app.test")])
        .await;
    assert_eq!(actual.status, 200, "{actual:?}");
    assert_eq!(
        all(&actual, "access-control-allow-origin"),
        ["https://app.test"]
    );
    assert_eq!(all(&actual, "access-control-allow-credentials"), ["true"]);
    assert_eq!(
        all(&actual, "access-control-expose-headers"),
        ["x-request-id"]
    );
}

#[tokio::test]
async fn cors_disallowed_origin_gets_nothing() {
    let echo = Echo::start(&[], true).await;
    let podgate = serve(cors_config(), &echo).await;
    for origin in [
        "https://evil.test",
        "https://app.test.evil.test",
        "http://app.test",
        "https://app.test:8443",
        "https://x.preview.test.evil.test",
        "null",
    ] {
        let response = podgate
            .get_with_headers("a.test", "/", &[("Origin", origin)])
            .await;
        assert_eq!(response.status, 200, "{origin}: {response:?}");
        let cors: Vec<_> = response
            .headers
            .iter()
            .filter(|(name, _)| name.starts_with("access-control-"))
            .collect();
        assert!(cors.is_empty(), "{origin}: {cors:?}");

        let preflight = podgate
            .request(
                "OPTIONS",
                "a.test",
                "/",
                &[("Origin", origin), ("Access-Control-Request-Method", "GET")],
            )
            .await;
        assert_eq!(
            preflight.status, 200,
            "a preflight from {origin} is not answered by the middleware: {preflight:?}"
        );
        assert!(all(&preflight, "access-control-allow-origin").is_empty());
    }
}

#[tokio::test]
async fn cors_never_reflects_origin() {
    let echo = Echo::start(&[], true).await;
    let podgate = serve(
        json!({ "cors": { "allow_origins": ["*"], "allow_methods": ["GET"] } }),
        &echo,
    )
    .await;
    let response = podgate
        .get_with_headers("a.test", "/", &[("Origin", "https://anything.test")])
        .await;
    assert_eq!(all(&response, "access-control-allow-origin"), ["*"]);
    assert!(
        all(&response, "vary").is_empty(),
        "the answer does not depend on the origin: {response:?}"
    );
    let preflight = podgate
        .request(
            "OPTIONS",
            "a.test",
            "/",
            &[
                ("Origin", "https://anything.test"),
                ("Access-Control-Request-Method", "GET"),
            ],
        )
        .await;
    assert_eq!(preflight.status, 204);
    assert_eq!(all(&preflight, "access-control-allow-origin"), ["*"]);

    let second = Echo::start(&[], true).await;
    let listed = serve(cors_config(), &second).await;
    let two_origins = listed
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("Origin", "https://app.test"),
                ("Origin", "https://evil.test"),
            ],
        )
        .await;
    assert!(
        all(&two_origins, "access-control-allow-origin").is_empty(),
        "two Origin headers are no origin: {two_origins:?}"
    );
}

#[tokio::test]
async fn cors_adds_vary() {
    let echo = Echo::start(&[("Vary", "Accept-Encoding")], true).await;
    let podgate = serve(cors_config(), &echo).await;
    let allowed = podgate
        .get_with_headers("a.test", "/", &[("Origin", "https://app.test")])
        .await;
    assert_eq!(all(&allowed, "vary"), ["Accept-Encoding", "Origin"]);
    let other = podgate
        .get_with_headers("a.test", "/", &[("Origin", "https://evil.test")])
        .await;
    assert_eq!(
        all(&other, "vary"),
        ["Accept-Encoding", "Origin"],
        "a cache must not serve one origin's answer to another"
    );

    let quiet = Echo::start(&[], true).await;
    let mut config = cors_config();
    config["cors"]["add_vary"] = json!(false);
    let podgate = serve(config, &quiet).await;
    let response = podgate
        .get_with_headers("a.test", "/", &[("Origin", "https://app.test")])
        .await;
    assert!(all(&response, "vary").is_empty(), "{response:?}");
}

#[tokio::test]
async fn cors_credentials_with_wildcard_rejected() {
    let conflict = rejection(
        json!({ "cors": { "allow_origins": ["*"], "allow_credentials": true } }),
        "headers",
    )
    .await;
    assert_eq!(conflict["code"], "invalid_middleware", "{conflict}");
    let bad_origin = rejection(
        json!({ "cors": { "allow_origins": ["https://a.test/path"] } }),
        "headers",
    )
    .await;
    assert_eq!(bad_origin["code"], "invalid_middleware", "{bad_origin}");
}

#[tokio::test]
async fn headers_framing_headers_rejected() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    for name in [
        "Host",
        "Content-Length",
        "transfer-encoding",
        "Connection",
        "Upgrade",
        "TE",
        "Trailer",
        "Proxy-Authorization",
        "Proxy-Connection",
        ":authority",
        ":path",
    ] {
        for config in [
            json!({ "request": { "set": { name: "x" } } }),
            json!({ "response": { "set": { name: "x" } } }),
            json!({ "request": { "remove": [name] } }),
            json!({ "response": { "remove": [name] } }),
        ] {
            let response = podgate
                .push_snapshot(&snapshot(
                    1,
                    &[chained("a.test", up.addr, "headers", config.clone())],
                ))
                .await;
            assert_eq!(response.status, 422, "{name} {config}: {}", response.body);
            assert_eq!(
                response.json()["conflicts"][0]["code"],
                "invalid_middleware",
                "{name} {config}"
            );
        }
    }
}

#[tokio::test]
async fn headers_invalid_value_rejected() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    for (name, value) in [
        ("x-a", "ok\r\nset-cookie: pwned=1"),
        ("x-a", "line\nbreak"),
        ("x-a", "nul\u{0}byte"),
        ("x-a", ""),
        ("bad name", "x"),
        ("x-a:b", "x"),
    ] {
        let response = podgate
            .push_snapshot(&snapshot(
                1,
                &[chained(
                    "a.test",
                    up.addr,
                    "headers",
                    json!({ "response": { "set": { name: value } } }),
                )],
            ))
            .await;
        assert_eq!(response.status, 422, "{name:?}: {}", response.body);
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_middleware",
            "{name:?}"
        );
    }
}

#[tokio::test]
async fn content_type_auto_detect_unsupported() {
    let conflict = rejection(json!({ "auto_detect": true }), "content_type").await;
    assert_eq!(conflict["code"], "unsupported_setting", "{conflict}");
    let unknown = rejection(json!({ "detect": true }), "content_type").await;
    assert_eq!(unknown["code"], "invalid_middleware", "{unknown}");
}

#[tokio::test]
async fn content_type_missing_stays_missing() {
    let echo = Echo::start(&[], false).await;
    let podgate = Podgate::start().await;
    let pushed = snapshot(
        1,
        &[chained(
            "a.test",
            echo.addr,
            "content_type",
            json!({ "auto_detect": false }),
        )],
    );
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert!(all(&response, "content-type").is_empty(), "{response:?}");
}

#[tokio::test]
async fn plan_lists_headers_posture() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let strong = json!({
        "response": { "security": {
            "hsts": { "max_age_secs": 31_536_000 },
            "csp": "default-src 'self'",
            "frame_options": "DENY",
            "content_type_nosniff": true } },
        "cors": { "allow_origins": ["https://a.test"] }
    });
    let live = snapshot(1, &[chained("a.test", up.addr, "headers", strong.clone())]);
    assert_eq!(podgate.push_snapshot(&live).await.status, 200);

    let weaker = json!({
        "response": { "security": { "hsts": { "max_age_secs": 60 }, "csp": "default-src *" } },
        "cors": { "allow_origins": ["https://a.test", "https://b.test"] }
    });
    let plan = podgate
        .admin_post(
            "/v1/snapshot/plan",
            &snapshot(2, &[chained("a.test", up.addr, "headers", weaker)]),
        )
        .await;
    assert_eq!(plan.status, 200, "{}", plan.body);
    let kinds: Vec<_> = plan.json()["posture_changes"]
        .as_array()
        .expect("posture_changes")
        .iter()
        .map(|change| {
            assert_eq!(change["host"], "a.test");
            change["kind"].as_str().expect("kind").to_owned()
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "hsts_weakened",
            "csp_changed",
            "frame_options_removed",
            "nosniff_removed",
            "cors_widened"
        ]
    );

    let gone = podgate
        .admin_post(
            "/v1/snapshot/plan",
            &snapshot(2, &[app("a.test", &["a.test"], &[serving("r1", up.addr)])]),
        )
        .await;
    assert_eq!(gone.status, 200, "{}", gone.body);
    let removed: Vec<_> = gone.json()["posture_changes"]
        .as_array()
        .expect("posture_changes")
        .iter()
        .map(|change| change["kind"].as_str().expect("kind").to_owned())
        .collect();
    assert_eq!(
        removed,
        [
            "hsts_removed",
            "csp_removed",
            "frame_options_removed",
            "nosniff_removed"
        ],
        "dropping the middleware drops the protection; narrowing CORS is not a relaxation"
    );
}
