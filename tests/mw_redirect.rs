//! The `redirect_scheme` and `redirect_regex` middlewares.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Podgate, Response, TestCert, Upstream, app, serving, snapshot, with_middleware};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// `a.test` with one middleware in its chain, pushed to a fresh proxy.
async fn start(kind: &str, config: Value) -> (Podgate, Upstream) {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("upstream body").await;
    push(&podgate, &upstream, kind, config).await;
    (podgate, upstream)
}

async fn push(podgate: &Podgate, upstream: &Upstream, kind: &str, config: Value) {
    let a = with_middleware(
        app("a", &["a.test"], &[serving("r1", upstream.addr)]),
        "m",
        kind,
        config,
    );
    let pushed = podgate.push_snapshot(&snapshot(1, &[a])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
}

fn assert_redirect(response: &Response, status: u16, location: &str) {
    assert_eq!(response.status, status, "{response:?}");
    assert_eq!(response.header("location"), Some(location), "{response:?}");
    assert_eq!(response.header("content-length"), Some("0"), "{response:?}");
    assert_eq!(response.body, "", "{response:?}");
}

/// A backend that counts the connections it accepts and answers `200`.
async fn counting_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nup",
                    )
                    .await;
            });
        }
    });
    (addr, accepted)
}

#[tokio::test]
async fn redirect_scheme_http_to_https() {
    let (podgate, _upstream) = start("redirect_scheme", json!({"scheme": "https"})).await;

    let response = podgate.get("A.test", "/x/y?q=1&r=%20s").await;
    assert_redirect(&response, 302, "https://a.test/x/y?q=1&r=%20s");

    let with_port = podgate.get("a.test:8080", "/").await;
    assert_redirect(&with_port, 302, "https://a.test/");

    let normalized = podgate.get("a.test", "/a/./b//c").await;
    assert_redirect(&normalized, 302, "https://a.test/a/b/c");
}

#[tokio::test]
async fn redirect_scheme_port() {
    let (podgate, _upstream) =
        start("redirect_scheme", json!({"scheme": "https", "port": 8443})).await;
    let response = podgate.get("a.test:8080", "/x?q=1").await;
    assert_redirect(&response, 302, "https://a.test:8443/x?q=1");

    let default_port = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    push(
        &default_port,
        &upstream,
        "redirect_scheme",
        json!({"scheme": "https", "port": 443}),
    )
    .await;
    let response = default_port.get("a.test", "/").await;
    assert_redirect(&response, 302, "https://a.test/");
}

#[tokio::test]
async fn redirect_scheme_no_loop() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("body a").await;
    let cert = TestCert::new(&["a.test", "b.test"]);
    let plain = with_middleware(
        app("a", &["a.test"], &[serving("r1", up.addr)]),
        "m",
        "redirect_scheme",
        json!({"scheme": "https"}),
    );
    let with_port = with_middleware(
        app("b", &["b.test"], &[serving("r1", up.addr)]),
        "m",
        "redirect_scheme",
        json!({"scheme": "https", "port": 8443}),
    );
    let mut pushed = snapshot(1, &[plain, with_port]);
    pushed["certificates"] = json!([cert.entry(&["a.test", "b.test"])]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let served = podgate.https_get("a.test", "a.test", "/", &cert).await;
    assert_eq!((served.status, served.body.as_str()), (200, "body a"));
    let port_mapped = podgate.https_get("a.test", "a.test:8443", "/", &cert).await;
    assert_eq!(port_mapped.status, 200, "{port_mapped:?}");

    let on_the_target_port = podgate.https_get("b.test", "b.test:8443", "/", &cert).await;
    assert_eq!(on_the_target_port.status, 200, "{on_the_target_port:?}");
    let on_another_port = podgate.https_get("b.test", "b.test", "/p", &cert).await;
    assert_redirect(&on_another_port, 302, "https://b.test:8443/p");

    let plain_http = podgate.get("a.test", "/").await;
    assert_redirect(&plain_http, 302, "https://a.test/");
}

#[tokio::test]
async fn redirect_regex_captures() {
    let (podgate, _upstream) = start(
        "redirect_regex",
        json!({
            "regex": "^http://([^/]+)/old/(.*)$",
            "replacement": "https://$1/new/$2",
        }),
    )
    .await;
    let response = podgate.get("a.test", "/old/x/y?q=1").await;
    assert_redirect(&response, 302, "https://a.test/new/x/y?q=1");

    let (podgate, _upstream) = start(
        "redirect_regex",
        json!({
            "regex": "^http://a\\.test/moved/(?P<rest>.*)$",
            "replacement": "https://b.example/${rest}",
        }),
    )
    .await;
    let response = podgate.get("a.test", "/moved/page?x=1").await;
    assert_redirect(&response, 302, "https://b.example/page?x=1");
}

#[tokio::test]
async fn redirect_regex_no_match_passes_through() {
    let (podgate, _upstream) = start(
        "redirect_regex",
        json!({"regex": "^http://[^/]+/old/(.*)$", "replacement": "https://a.test/$1"}),
    )
    .await;
    let response = podgate.get("a.test", "/other").await;
    assert_eq!(
        (response.status, response.body.as_str()),
        (200, "upstream body")
    );

    let identity = Podgate::start().await;
    let upstream = Upstream::start("kept").await;
    push(
        &identity,
        &upstream,
        "redirect_regex",
        json!({"regex": "^http://", "replacement": "http://"}),
    )
    .await;
    let response = identity.get("a.test", "/same").await;
    assert_eq!((response.status, response.body.as_str()), (200, "kept"));
}

#[tokio::test]
async fn redirect_permanent_status() {
    let cases = [
        ("redirect_scheme", json!({"scheme": "https"}), 302),
        (
            "redirect_scheme",
            json!({"scheme": "https", "permanent": true}),
            301,
        ),
        (
            "redirect_scheme",
            json!({"scheme": "https", "permanent": false}),
            302,
        ),
        (
            "redirect_regex",
            json!({"regex": "^http://", "replacement": "https://"}),
            302,
        ),
        (
            "redirect_regex",
            json!({"regex": "^http://", "replacement": "https://", "permanent": true}),
            301,
        ),
    ];
    for (kind, config, status) in cases {
        let (podgate, _upstream) = start(kind, config.clone()).await;
        let response = podgate.get("a.test", "/p").await;
        assert_redirect(&response, status, "https://a.test/p");
    }
}

#[tokio::test]
async fn redirect_location_no_header_injection() {
    let scheme = json!({"scheme": "https"});
    let regex = json!({"regex": "^http://[^/]+(.*)$", "replacement": "https://a.test$1"});
    let hostile = [
        "/a%0d%0aSet-Cookie:%20pwned=1",
        "/a%0D%0A",
        "/a?x=%0d%0aSet-Cookie:%20pwned=1",
        "/a?x=%0A",
        "/a%7f",
        "/a?x=%1b",
        "/a?x=%00",
    ];
    for (kind, config) in [("redirect_scheme", scheme), ("redirect_regex", regex)] {
        let (podgate, _upstream) = start(kind, config).await;
        for target in hostile {
            let response = podgate.get("a.test", target).await;
            assert_eq!(response.status, 400, "{kind} {target}: {response:?}");
            assert_eq!(response.header("location"), None, "{kind} {target}");
            assert_eq!(response.header("set-cookie"), None, "{kind} {target}");
            assert!(!response.body.contains("pwned"), "{kind} {target}");
        }
        let fine = podgate.get("a.test", "/a%20b?x=%7E").await;
        assert_redirect(&fine, 302, "https://a.test/a%20b?x=%7E");
    }
}

#[tokio::test]
async fn redirect_ignores_untrusted_forwarded_proto() {
    let (podgate, _upstream) = start("redirect_scheme", json!({"scheme": "https"})).await;
    let forged = [
        ("x-forwarded-proto", "https"),
        ("x-forwarded-scheme", "https"),
        ("forwarded", "proto=https"),
        ("x-forwarded-host", "evil.test"),
        ("x-forwarded-port", "443"),
    ];
    let response = podgate.get_with_headers("a.test", "/x", &forged).await;
    assert_redirect(&response, 302, "https://a.test/x");

    let (podgate, _upstream) = start(
        "redirect_regex",
        json!({"regex": "^https://", "replacement": "http://"}),
    )
    .await;
    let response = podgate
        .get_with_headers("a.test", "/x", &[("x-forwarded-proto", "https")])
        .await;
    assert_eq!(
        (response.status, response.body.as_str()),
        (200, "upstream body"),
        "the regex saw http, so it did not match: {response:?}"
    );
}

#[tokio::test]
async fn redirect_never_contacts_upstream() {
    let podgate = Podgate::start().await;
    let (addr, accepted) = counting_upstream().await;
    let to_https = with_middleware(
        app("a", &["a.test"], &[serving("r1", addr)]),
        "m",
        "redirect_scheme",
        json!({"scheme": "https"}),
    );
    let moved = with_middleware(
        app("b", &["b.test"], &[serving("r1", addr)]),
        "m",
        "redirect_regex",
        json!({"regex": "^http://b\\.test/old", "replacement": "https://b.test/new"}),
    );
    let pushed = podgate
        .push_snapshot(&snapshot(1, &[to_https, moved]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    assert_eq!(podgate.get("a.test", "/").await.status, 302);
    assert_eq!(podgate.get("a.test", "/a%0d%0ab").await.status, 400);
    assert_eq!(podgate.get("b.test", "/old").await.status, 302);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "no upstream connection for a redirected or refused request"
    );

    let served = podgate.get("b.test", "/other").await;
    assert_eq!(served.status, 200, "{served:?}");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "the counter sees a request that passes"
    );
}

#[tokio::test]
async fn redirect_regex_invalid_rejected() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    let bad = [
        ("redirect_regex", json!({"regex": "(", "replacement": "x"})),
        (
            "redirect_regex",
            json!({"regex": "^(a)", "replacement": "$2"}),
        ),
        (
            "redirect_regex",
            json!({"regex": "^(a)", "replacement": "${nope}"}),
        ),
        (
            "redirect_regex",
            json!({"regex": "^(a)", "replacement": "$"}),
        ),
        (
            "redirect_regex",
            json!({"regex": "^(a)", "replacement": "/a\r\nSet-Cookie: x"}),
        ),
        (
            "redirect_regex",
            json!({"regex": "^(a)", "replacement": "/a%0d%0a"}),
        ),
        (
            "redirect_regex",
            json!({"regex": "^(a)", "replacement": ""}),
        ),
        ("redirect_regex", json!({"regex": "^a"})),
        (
            "redirect_regex",
            json!({"regex": "^a", "replacement": "b", "typo": true}),
        ),
        ("redirect_scheme", json!({"scheme": "ftp"})),
        ("redirect_scheme", json!({"scheme": "https", "port": 0})),
        ("redirect_scheme", json!({})),
        (
            "redirect_scheme",
            json!({"scheme": "https", "permanent": "yes"}),
        ),
    ];
    for (version, (kind, config)) in bad.iter().enumerate() {
        let a = with_middleware(
            app("a", &["a.test"], &[serving("r1", upstream.addr)]),
            "m",
            kind,
            config.clone(),
        );
        let refused = podgate
            .push_snapshot(&snapshot(version as u64 + 1, &[a]))
            .await;
        assert_eq!(refused.status, 422, "{kind} {config}: {}", refused.body);
        let body = refused.json();
        assert_eq!(
            body["conflicts"].as_array().map(Vec::len),
            Some(1),
            "{kind} {config}: {body}"
        );
        assert_eq!(
            body["conflicts"][0]["code"], "invalid_middleware",
            "{kind} {config}"
        );
    }
    assert_eq!(
        podgate.get("a.test", "/").await.status,
        404,
        "nothing was applied"
    );
}

#[tokio::test]
async fn redirect_scheme_explain_and_plan_posture() {
    let (podgate, upstream) = start(
        "redirect_scheme",
        json!({"scheme": "https", "permanent": true}),
    )
    .await;
    let explained = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(
        explained.json()["pipeline"][4],
        json!({"stage": "chain", "middleware": "m", "type": "redirect_scheme",
               "scheme": "https", "port": null, "permanent": true})
    );

    let without = snapshot(2, &[app("a", &["a.test"], &[serving("r1", upstream.addr)])]);
    let plan = podgate.admin_post("/v1/snapshot/plan", &without).await;
    assert_eq!(plan.status, 200, "{}", plan.body);
    assert_eq!(
        plan.json()["posture_changes"],
        json!([{"host": "a.test", "app": "a", "kind": "https_redirect_removed"}])
    );
}
