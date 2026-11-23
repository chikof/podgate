//! The API lifecycle through the real binary: what the routers of a `draft`,
//! `deprecated` or `retired` API answer, and that a tenant's own middlewares cannot weaken it.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Podgate, Response, Upstream, app, router, serving, snapshot, with_middleware};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SUNSET: &str = "Mon, 01 Mar 2027 00:00:00 GMT";
const SUCCESSOR_LINK: &str = "</v2>; rel=\"successor-version\"";

/// An app on `a.test` with three routers, `v1`, `v2` and `rest`, each under its own path.
fn pets(upstream: SocketAddr, apis: &Value) -> Value {
    let mut app = app("pets", &["a.test"], &[serving("r1", upstream)]);
    let under = |name: &str| {
        router(
            name,
            json!({"all": [{"host": "a.test"}, {"path_prefix": format!("/{name}")}]}),
            "web",
        )
    };
    app["routers"] = json!([under("v1"), under("v2"), under("rest")]);
    app["apis"] = apis.clone();
    app
}

fn api(version: &str, lifecycle: &str, router: &str, extra: &Value) -> Value {
    let mut api = json!({
        "id": "pets", "version": version, "lifecycle": lifecycle, "routers": [router],
    });
    if let (Some(object), Some(extra)) = (api.as_object_mut(), extra.as_object()) {
        object.extend(extra.clone());
    }
    api
}

async fn serve(app: Value) -> Podgate {
    let podgate = Podgate::start().await;
    let pushed = podgate.push_snapshot(&snapshot(1, &[app])).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    podgate
}

/// Every value of the header `name`, in order.
fn values<'a>(response: &'a Response, name: &str) -> Vec<&'a str> {
    response
        .headers
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .collect()
}

/// A deprecated `pets@1` on `v1` with its successor `pets@2` on `v2`.
fn deprecated_v1() -> Value {
    json!([
        api(
            "1",
            "deprecated",
            "v1",
            &json!({
                "sunset": "2027-03-01", "successor": {"id": "pets", "version": "2"},
            })
        ),
        api("2", "stable", "v2", &json!({})),
    ])
}

#[tokio::test]
async fn lifecycle_draft_404() {
    let upstream = Upstream::start("pets").await;
    let podgate = serve(pets(
        upstream.addr,
        &json!([api("1", "draft", "v1", &json!({}))]),
    ))
    .await;
    let draft = podgate.get("a.test", "/v1/x").await;
    assert_eq!(draft.status, 404, "{draft:?}");
    assert_eq!(draft.json(), json!({"error": "not found"}));
    let served = podgate.get("a.test", "/v2/x").await;
    assert_eq!(
        served.status, 200,
        "an unnamed router is not a draft: {served:?}"
    );
}

#[tokio::test]
async fn lifecycle_deprecated_headers() {
    let upstream = Upstream::start("pets").await;
    let podgate = serve(pets(upstream.addr, &deprecated_v1())).await;
    let old = podgate.get("a.test", "/v1/x").await;
    assert_eq!(old.status, 200, "a deprecated API still serves: {old:?}");
    assert_eq!(old.body, "pets");
    assert_eq!(values(&old, "deprecation"), ["true"]);
    assert_eq!(values(&old, "sunset"), [SUNSET]);
    assert_eq!(values(&old, "link"), [SUCCESSOR_LINK]);
    let current = podgate.get("a.test", "/v2/x").await;
    assert_eq!(current.status, 200);
    for name in ["deprecation", "sunset", "link"] {
        assert!(
            values(&current, name).is_empty(),
            "{name} on the successor: {current:?}"
        );
    }
}

#[tokio::test]
async fn lifecycle_deprecated_without_a_successor_path_has_no_link() {
    let upstream = Upstream::start("pets").await;
    let apis = json!([api(
        "1",
        "deprecated",
        "v1",
        &json!({"sunset": "2027-03-01"})
    )]);
    let podgate = serve(pets(upstream.addr, &apis)).await;
    let old = podgate.get("a.test", "/v1/x").await;
    assert_eq!(old.status, 200);
    assert_eq!(values(&old, "sunset"), [SUNSET]);
    assert!(values(&old, "link").is_empty(), "{old:?}");
}

#[tokio::test]
async fn lifecycle_retired_410() {
    let upstream = Upstream::start("pets").await;
    let apis = json!([api("1", "retired", "v1", &json!({"sunset": "2026-01-01"}))]);
    let podgate = serve(pets(upstream.addr, &apis)).await;
    let gone = podgate.get("a.test", "/v1/x").await;
    assert_eq!(gone.status, 410, "{gone:?}");
    assert_eq!(gone.header("content-type"), Some("application/json"));
    assert_eq!(gone.json(), json!({"error": "api retired"}));
    let post = podgate
        .request("POST", "a.test", "/v1/x", &[("content-length", "0")])
        .await;
    assert_eq!(post.status, 410, "{post:?}");
    assert_eq!(podgate.get("a.test", "/v2/x").await.status, 200);
}

#[tokio::test]
async fn lifecycle_stable_untouched() {
    let upstream = Upstream::start("pets").await;
    let apis = json!([
        api("1", "stable", "v1", &json!({"published": true})),
        api("2", "preview", "v2", &json!({})),
    ]);
    let podgate = serve(pets(upstream.addr, &apis)).await;
    for path in ["/v1/x", "/v2/x"] {
        let served = podgate.get("a.test", path).await;
        assert_eq!(served.status, 200, "{path}: {served:?}");
        assert_eq!(served.body, "pets");
        for name in ["deprecation", "sunset", "link"] {
            assert!(
                values(&served, name).is_empty(),
                "{path} {name}: {served:?}"
            );
        }
    }
    let overview = podgate.admin_get("/v1/overview?section=apps").await.json();
    let chain = &overview["apps"]["items"][0]["routers"];
    assert!(
        !chain.to_string().contains("lifecycle"),
        "a stable or preview API adds nothing to a chain: {chain}"
    );
}

#[tokio::test]
async fn lifecycle_headers_survive_header_middleware() {
    let upstream = Upstream::start("pets").await;
    // The remover is first in the chain, so its response hook runs after the setter's.
    let app = with_middleware(
        pets(upstream.addr, &deprecated_v1()),
        "remover",
        "headers",
        json!({"response": {"remove": ["deprecation", "sunset"]}}),
    );
    let app = with_middleware(
        app,
        "setter",
        "headers",
        json!({"response": {"set": {
            "deprecation": "false", "sunset": "never",
            "link": "<https://evil.test/v9>; rel=\"successor-version\"",
        }}}),
    );
    let podgate = serve(app).await;
    let old = podgate.get("a.test", "/v1/x").await;
    assert_eq!(old.status, 200, "{old:?}");
    assert_eq!(values(&old, "deprecation"), ["true"], "{old:?}");
    assert_eq!(values(&old, "sunset"), [SUNSET], "{old:?}");
    let links = values(&old, "link");
    assert_eq!(
        links.iter().filter(|link| **link == SUCCESSOR_LINK).count(),
        1,
        "{old:?}"
    );
}

#[tokio::test]
async fn lifecycle_a_tenant_cannot_declare_the_guard() {
    let upstream = Upstream::start("pets").await;
    let app = with_middleware(
        pets(upstream.addr, &json!([])),
        "mine",
        "lifecycle",
        json!({}),
    );
    let podgate = Podgate::start().await;
    let rejected = podgate.push_snapshot(&snapshot(1, &[app])).await;
    assert_eq!(rejected.status, 422, "{rejected:?}");
    assert_eq!(
        rejected.json()["conflicts"][0]["code"],
        "unknown_middleware"
    );
}

#[tokio::test]
async fn lifecycle_only_named_routers() {
    let upstream = Upstream::start("pets").await;
    let apis = json!([api("1", "retired", "v1", &json!({}))]);
    let podgate = serve(pets(upstream.addr, &apis)).await;
    assert_eq!(podgate.get("a.test", "/v1/x").await.status, 410);
    for path in ["/v2/x", "/rest/x"] {
        let served = podgate.get("a.test", path).await;
        assert_eq!(served.status, 200, "{path}: {served:?}");
        assert_eq!(served.body, "pets");
    }
}

/// An upstream that counts requests and answers with a cacheable page and a `Link` of its own.
async fn cacheable(hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    while let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                        seen.drain(..end + 4);
                        hits.fetch_add(1, Ordering::SeqCst);
                        let reply = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                            Cache-Control: max-age=60\r\n\
                            Link: <https://a.test/v1/x?page=2>; rel=\"next\"\r\n\
                            Content-Length: 4\r\n\r\npets";
                        if stream.write_all(reply.as_bytes()).await.is_err() {
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
async fn lifecycle_cache_hit_keeps_headers() {
    let hits = Arc::new(AtomicUsize::new(0));
    let addr = cacheable(Arc::clone(&hits)).await;
    let app = with_middleware(pets(addr, &deprecated_v1()), "c", "cache", json!({}));
    let podgate = serve(app).await;
    let first = podgate.get("a.test", "/v1/x").await;
    let second = podgate.get("a.test", "/v1/x").await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the second request is a cache hit"
    );
    for (name, response) in [("miss", &first), ("hit", &second)] {
        assert_eq!(response.status, 200, "{name}: {response:?}");
        assert_eq!(
            values(response, "deprecation"),
            ["true"],
            "{name}: {response:?}"
        );
        assert_eq!(values(response, "sunset"), [SUNSET], "{name}: {response:?}");
        let links = values(response, "link");
        assert_eq!(
            links.len(),
            2,
            "the upstream's next and the successor, once each: {name}: {response:?}"
        );
        assert!(links.contains(&SUCCESSOR_LINK), "{name}: {response:?}");
    }
}
