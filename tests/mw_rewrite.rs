//! The path rewrite middlewares: `add_prefix`, `strip_prefix`, `strip_prefix_regex`,
//! `replace_path` and `replace_path_regex` through the real binary, against an upstream that
//! echoes the request head it received.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{
    Podgate, Response, Upstream, app, middleware, router, service, serving, snapshot, with_chain,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A backend that answers with the head of the request it got, and counts the requests.
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
        self.hits.load(Ordering::SeqCst)
    }
}

async fn echo_connection(mut stream: TcpStream, hits: Arc<AtomicUsize>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            seen.drain(..end + 4);
            hits.fetch_add(1, Ordering::SeqCst);
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

/// The request target the upstream saw.
fn target(response: &Response) -> &str {
    response
        .body
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap_or_else(|| panic!("no request line in {response:?}"))
}

/// The values of request header `name` the upstream saw.
fn seen(response: &Response, name: &str) -> Vec<String> {
    response
        .body
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
        .collect()
}

fn rewrite(name: &str, kind: &str, config: Value) -> Value {
    middleware(name, kind, config)
}

/// An app on `a.test` in front of `echo` whose chain is `chain`.
fn chained(echo: &Echo, chain: &[Value]) -> Value {
    with_chain(app("a", &["a.test"], &[serving("r1", echo.addr)]), chain)
}

async fn serve(echo: &Echo, chain: &[Value]) -> Podgate {
    let podgate = Podgate::start().await;
    push(&podgate, 1, &chained(echo, chain)).await;
    podgate
}

async fn push(podgate: &Podgate, version: u64, app: &Value) {
    let response = podgate
        .push_snapshot(&snapshot(version, std::slice::from_ref(app)))
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// The `(code, message)` of the one problem a snapshot with this chain is rejected for.
async fn rejection(chain: &[Value]) -> (String, String) {
    let up = Upstream::start("up").await;
    let podgate = Podgate::start().await;
    let up = common::serving("r1", up.addr);
    let response = podgate
        .push_snapshot(&snapshot(
            1,
            &[with_chain(app("a", &["a.test"], &[up]), chain)],
        ))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    let problem = response.json()["conflicts"][0].clone();
    (
        problem["code"].as_str().expect("code").to_owned(),
        problem["message"].as_str().unwrap_or_default().to_owned(),
    )
}

#[tokio::test]
async fn rewrite_each_type_end_to_end() {
    let echo = Echo::start().await;
    for (chain, path, expected) in [
        (
            rewrite("m", "add_prefix", json!({ "prefix": "/api" })),
            "/users?x=1&y=%2F",
            "/api/users?x=1&y=%2F",
        ),
        (
            rewrite("m", "strip_prefix", json!({ "prefixes": ["/api"] })),
            "/api/users?x=1",
            "/users?x=1",
        ),
        (
            rewrite(
                "m",
                "strip_prefix_regex",
                json!({ "regexes": ["^/t-[a-z]+"] }),
            ),
            "/t-acme/users",
            "/users",
        ),
        (
            rewrite("m", "replace_path", json!({ "path": "/index.html" })),
            "/anything/at/all?v=2",
            "/index.html?v=2",
        ),
        (
            rewrite(
                "m",
                "replace_path_regex",
                json!({ "regex": "^/old/(.*)", "replacement": "/new/$1" }),
            ),
            "/old/a/b?q=1",
            "/new/a/b?q=1",
        ),
    ] {
        let podgate = serve(&echo, std::slice::from_ref(&chain)).await;
        let response = podgate.get("a.test", path).await;
        assert_eq!(response.status, 200, "{chain}: {response:?}");
        assert_eq!(target(&response), expected, "{chain} for {path}");
    }
}

#[tokio::test]
async fn rewrite_sets_forwarded_prefix_header() {
    let echo = Echo::start().await;
    let podgate = serve(
        &echo,
        &[
            rewrite("strip", "strip_prefix", json!({ "prefixes": ["/api"] })),
            rewrite(
                "replace",
                "replace_path_regex",
                json!({ "regex": "^/(old)/.*", "replacement": "/$1" }),
            ),
        ],
    )
    .await;

    let stripped = podgate.get("a.test", "/api/users").await;
    assert_eq!(target(&stripped), "/users");
    assert_eq!(seen(&stripped, "x-forwarded-prefix"), ["/api"]);
    assert!(
        seen(&stripped, "x-replaced-path").is_empty(),
        "{stripped:?}"
    );

    let untouched = podgate.get("a.test", "/apix/users").await;
    assert_eq!(target(&untouched), "/apix/users");
    assert!(
        seen(&untouched, "x-forwarded-prefix").is_empty(),
        "{untouched:?}"
    );

    let replaced = podgate.get("a.test", "/old/thing?q=1").await;
    assert_eq!(target(&replaced), "/old?q=1");
    assert_eq!(seen(&replaced, "x-replaced-path"), ["/old/thing"]);

    let regex = serve(
        &echo,
        &[rewrite(
            "m",
            "strip_prefix_regex",
            json!({ "regexes": ["^/t-[a-z]+"] }),
        )],
    )
    .await;
    let response = regex.get("a.test", "/t-acme/users").await;
    assert_eq!(seen(&response, "x-forwarded-prefix"), ["/t-acme"]);

    let fixed = serve(
        &echo,
        &[rewrite("m", "replace_path", json!({ "path": "/new" }))],
    )
    .await;
    let response = fixed.get("a.test", "/old?q=1").await;
    assert_eq!(seen(&response, "x-replaced-path"), ["/old"]);
}

#[tokio::test]
async fn rewrite_removes_client_supplied_headers() {
    let echo = Echo::start().await;
    let podgate = serve(
        &echo,
        &[
            rewrite("strip", "strip_prefix", json!({ "prefixes": ["/api"] })),
            rewrite(
                "replace",
                "replace_path_regex",
                json!({ "regex": "^/old", "replacement": "/new" }),
            ),
        ],
    )
    .await;
    let forged = [
        ("X-Forwarded-Prefix", "/forged"),
        ("x-replaced-path", "/forged"),
        ("X-Replaced-Path", "/forged-again"),
    ];

    // Neither rewrite applies: the client's copies are gone anyway.
    let response = podgate.get_with_headers("a.test", "/plain", &forged).await;
    assert_eq!(target(&response), "/plain");
    assert!(
        seen(&response, "x-forwarded-prefix").is_empty(),
        "{response:?}"
    );
    assert!(
        seen(&response, "x-replaced-path").is_empty(),
        "{response:?}"
    );

    // Both apply: the upstream sees exactly what podgate wrote, once each.
    let response = podgate
        .get_with_headers("a.test", "/api/old/x", &forged)
        .await;
    assert_eq!(target(&response), "/new/x");
    assert_eq!(seen(&response, "x-forwarded-prefix"), ["/api"]);
    assert_eq!(seen(&response, "x-replaced-path"), ["/api/old/x"]);
}

#[tokio::test]
async fn rewrite_cannot_produce_authority_form() {
    let echo = Echo::start().await;
    let podgate = serve(
        &echo,
        &[rewrite(
            "m",
            "replace_path_regex",
            json!({ "regex": "^/go/(.*)", "replacement": "//$1" }),
        )],
    )
    .await;
    let response = podgate.get("a.test", "/go/evil.test/x?q=1").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(target(&response), "/evil.test/x?q=1");
    for (kind, config, path, expected) in [
        (
            "replace_path",
            json!({ "path": "//evil.test/x" }),
            "/a",
            "/evil.test/x",
        ),
        (
            "add_prefix",
            json!({ "prefix": "//" }),
            "/evil.test/x",
            "/evil.test/x",
        ),
        (
            "replace_path_regex",
            json!({ "regex": "^/a$", "replacement": "///evil.test" }),
            "/a",
            "/evil.test",
        ),
    ] {
        let podgate = serve(&echo, &[rewrite("m", kind, config)]).await;
        let response = podgate.get("a.test", path).await;
        assert_eq!(response.status, 200, "{kind}: {response:?}");
        assert_eq!(target(&response), expected, "{kind}");
    }
}

#[tokio::test]
async fn rewrite_dot_segments_renormalized() {
    let echo = Echo::start().await;
    for (replacement, path, expected) in [
        ("/base/../$1/./x", "/go/a", "/a/x"),
        ("/files/$1/../..", "/go/a", "/"),
        ("/a/$1", "/go/b/", "/a/b/"),
        ("/../../$1", "/go/a", "/a"),
    ] {
        let podgate = serve(
            &echo,
            &[rewrite(
                "m",
                "replace_path_regex",
                json!({ "regex": "^/go/(.*)", "replacement": replacement }),
            )],
        )
        .await;
        let response = podgate.get("a.test", path).await;
        assert_eq!(response.status, 200, "{replacement}: {response:?}");
        assert_eq!(target(&response), expected, "{replacement} for {path}");
    }
    let podgate = serve(
        &echo,
        &[rewrite(
            "m",
            "add_prefix",
            json!({ "prefix": "/a/b/../c/./" }),
        )],
    )
    .await;
    assert_eq!(target(&podgate.get("a.test", "/d").await), "/a/c/d");
}

#[tokio::test]
async fn rewrite_invalid_result_500() {
    let echo = Echo::start().await;
    let podgate = Podgate::start().await;
    for (version, replacement) in [
        (1, "/x%2F$1"),
        (2, "/x%2f$1"),
        (3, "/x%5C$1"),
        (4, "/x%00$1"),
        (5, "/%2e%2e/$1"),
        (6, "/x%zz$1"),
    ] {
        let chain = [rewrite(
            "m",
            "replace_path_regex",
            json!({ "regex": "^/go/(.*)", "replacement": replacement }),
        )];
        push(&podgate, version, &chained(&echo, &chain)).await;
        let before = echo.hits();
        let response = podgate.get("a.test", "/go/a").await;
        assert_eq!(response.status, 500, "{replacement}: {response:?}");
        assert_eq!(echo.hits(), before, "{replacement} reached the upstream");
        assert!(!response.body.contains("%2F"), "{response:?}");
    }
}

#[tokio::test]
async fn rewrite_chain_order() {
    let echo = Echo::start().await;
    let add = rewrite("add", "add_prefix", json!({ "prefix": "/b" }));
    let swap = rewrite(
        "swap",
        "replace_path_regex",
        json!({ "regex": "^/b/(.*)", "replacement": "/c/$1" }),
    );

    let podgate = serve(&echo, &[add.clone(), swap.clone()]).await;
    assert_eq!(target(&podgate.get("a.test", "/x").await), "/c/x");
    let podgate = serve(&echo, &[swap, add]).await;
    assert_eq!(target(&podgate.get("a.test", "/x").await), "/b/x");

    let podgate = serve(
        &echo,
        &[
            rewrite("one", "strip_prefix", json!({ "prefixes": ["/a"] })),
            rewrite("two", "strip_prefix", json!({ "prefixes": ["/b"] })),
        ],
    )
    .await;
    let response = podgate.get("a.test", "/a/b/x").await;
    assert_eq!(target(&response), "/x");
    assert_eq!(seen(&response, "x-forwarded-prefix"), ["/a/b"]);

    let podgate = serve(
        &echo,
        &[
            rewrite("one", "replace_path", json!({ "path": "/one" })),
            rewrite("two", "replace_path", json!({ "path": "/two" })),
        ],
    )
    .await;
    let response = podgate.get("a.test", "/start").await;
    assert_eq!(target(&response), "/two");
    assert_eq!(seen(&response, "x-replaced-path"), ["/start"]);
}

#[tokio::test]
async fn rewrite_does_not_change_route() {
    let podgate = Podgate::start().await;
    let (public, admin, web) = (
        Upstream::start("public").await,
        Upstream::start("admin").await,
        Echo::start().await,
    );
    let mut shop = app("shop", &["shop.test"], &[serving("r1", web.addr)]);
    shop["revisions"][0]["services"]
        .as_array_mut()
        .expect("services")
        .extend([
            service("public", &[public.addr]),
            service("admin", &[admin.addr]),
        ]);
    let mut to_admin = router(
        "pub",
        json!({ "all": [{ "host": "shop.test" }, { "path_prefix": "/pub" }] }),
        "public",
    );
    to_admin["chain"] = json!(["into-admin"]);
    shop["routers"] = json!([
        router("web", json!({ "host": "shop.test" }), "web"),
        router(
            "admin",
            json!({ "all": [{ "host": "shop.test" }, { "path_prefix": "/admin" }] }),
            "admin"
        ),
        to_admin,
    ]);
    shop["middlewares"] = json!([rewrite(
        "into-admin",
        "replace_path",
        json!({ "path": "/admin/secret" })
    )]);
    push(&podgate, 1, &shop).await;

    // The rewritten path would match the admin router, but routing saw `/pub`.
    assert_eq!(podgate.get("shop.test", "/pub/x").await.body, "public");
    assert_eq!(podgate.get("shop.test", "/admin/x").await.body, "admin");
    // A request that really is for `/admin` is not affected by the rewrite on `/pub`.
    assert_eq!(target(&podgate.get("shop.test", "/other").await), "/other");
}

#[tokio::test]
async fn rewrite_bad_regex_rejected() {
    for chain in [
        rewrite("m", "strip_prefix_regex", json!({ "regexes": ["("] })),
        rewrite("m", "strip_prefix_regex", json!({ "regexes": [""] })),
        rewrite("m", "strip_prefix_regex", json!({ "regexes": [] })),
        rewrite(
            "m",
            "replace_path_regex",
            json!({ "regex": "(", "replacement": "/x" }),
        ),
        rewrite(
            "m",
            "replace_path_regex",
            json!({ "regex": "", "replacement": "/x" }),
        ),
        rewrite("m", "replace_path_regex", json!({ "regex": "a" })),
        rewrite(
            "m",
            "replace_path_regex",
            json!({ "regex": "a", "replacement": "/x?y=1" }),
        ),
        rewrite(
            "m",
            "replace_path_regex",
            json!({ "regex": "a", "replacement": "/x", "extra": 1 }),
        ),
        rewrite("m", "add_prefix", json!({ "prefix": "api" })),
        rewrite("m", "add_prefix", json!({ "prefix": "/a%2Fb" })),
        rewrite("m", "strip_prefix", json!({ "prefixes": ["/"] })),
        rewrite("m", "strip_prefix", json!({ "prefixes": [] })),
        rewrite("m", "replace_path", json!({ "path": "/a#b" })),
        rewrite("m", "replace_path", json!({ "path": "" })),
    ] {
        let (code, message) = rejection(std::slice::from_ref(&chain)).await;
        assert_eq!(code, "invalid_middleware", "{chain}: {message}");
    }
}

#[tokio::test]
async fn rewrite_missing_group_rejected() {
    for replacement in ["/$2", "/${nope}", "/$1a", "/${}", "/$name"] {
        let chain = rewrite(
            "m",
            "replace_path_regex",
            json!({ "regex": "^/(a)", "replacement": replacement }),
        );
        let (code, message) = rejection(&[chain]).await;
        assert_eq!(code, "invalid_middleware", "{replacement}: {message}");
        assert!(message.contains("does not define"), "{message}");
    }
    // Groups that exist are accepted, numbered or named.
    let echo = Echo::start().await;
    let chain = rewrite(
        "m",
        "replace_path_regex",
        json!({ "regex": "^/(?<first>a)/(b)", "replacement": "/${first}/$2/$0/$$" }),
    );
    let podgate = serve(&echo, &[chain]).await;
    let response = podgate.get("a.test", "/a/b").await;
    assert_eq!(target(&response), "/a/b/a/b/$");
}

#[tokio::test]
async fn explain_shows_rewrite() {
    let echo = Echo::start().await;
    let podgate = serve(
        &echo,
        &[
            rewrite("add", "add_prefix", json!({ "prefix": "/api" })),
            rewrite("strip", "strip_prefix", json!({ "prefixes": ["/v1"] })),
            rewrite(
                "strip-re",
                "strip_prefix_regex",
                json!({ "regexes": ["^/t-[a-z]+"] }),
            ),
            rewrite("fixed", "replace_path", json!({ "path": "/index.html" })),
            rewrite(
                "re",
                "replace_path_regex",
                json!({ "regex": "^/old/(.*)", "replacement": "/new/$1" }),
            ),
        ],
    )
    .await;
    let explained = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(explained.status, 200, "{}", explained.body);
    let chain: Vec<Value> = explained.json()["pipeline"]
        .as_array()
        .expect("pipeline")
        .iter()
        .filter(|stage| stage["stage"] == "chain")
        .cloned()
        .collect();
    assert_eq!(
        chain,
        [
            json!({ "stage": "chain", "middleware": "add", "type": "add_prefix", "prefix": "/api" }),
            json!({ "stage": "chain", "middleware": "strip", "type": "strip_prefix", "prefixes": ["/v1"] }),
            json!({ "stage": "chain", "middleware": "strip-re", "type": "strip_prefix_regex", "regexes": ["^/t-[a-z]+"] }),
            json!({ "stage": "chain", "middleware": "fixed", "type": "replace_path", "path": "/index.html" }),
            json!({ "stage": "chain", "middleware": "re", "type": "replace_path_regex", "regex": "^/old/(.*)", "replacement": "/new/$1" }),
        ]
    );
}

#[tokio::test]
async fn removing_a_rewrite_shows_in_the_plan_as_a_changed_app() {
    let echo = Echo::start().await;
    let podgate = serve(
        &echo,
        &[rewrite("m", "add_prefix", json!({ "prefix": "/api" }))],
    )
    .await;
    let without = snapshot(2, &[chained(&echo, &[])]);
    let planned = podgate.admin_post("/v1/snapshot/plan", &without).await;
    assert_eq!(planned.status, 200, "{}", planned.body);
    assert_eq!(
        planned.json()["changed"],
        json!(["a.test"]),
        "{}",
        planned.body
    );
}
