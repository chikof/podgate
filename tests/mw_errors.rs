//! The `errors` and `respond` middlewares: error pages served by another service of
//! the app, and fixed responses. The pure rules (template, status ranges, the HTTP/1.1 reader of
//! the page fetch) are unit-tested in `src/middleware/errors.rs` and its `fetch.rs`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    Podgate, Response, app, refused, router, service, serving, snapshot, with_middleware,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// What a test server answers with.
enum Reply {
    /// These bytes, then the connection closes.
    Raw(Vec<u8>),
    /// These bytes after a pause.
    Delay(Duration, Vec<u8>),
}

/// `HTTP/1.1 <status>` with `Connection: close`, the headers and a `Content-Length` body.
fn http(status: u16, headers: &[(&str, &str)], body: &str) -> Reply {
    Reply::Raw(raw(status, headers, body))
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

type Handler = dyn Fn(&str) -> Reply + Send + Sync;

/// A server that records each request head and answers by `handler`, which gets the head.
struct Server {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
    peak: Arc<AtomicUsize>,
}

impl Server {
    async fn start(handler: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let handler: Arc<Handler> = Arc::new(handler);
        let shared = (Arc::clone(&heads), live, Arc::clone(&peak));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (heads, live, peak) = shared.clone();
                tokio::spawn(serve(stream, Arc::clone(&handler), heads, live, peak));
            }
        });
        Self { addr, heads, peak }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("heads").clone()
    }

    fn requests(&self) -> usize {
        self.heads().len()
    }

    fn peak_concurrency(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

async fn serve(
    mut stream: TcpStream,
    handler: Arc<Handler>,
    heads: Arc<Mutex<Vec<String>>>,
    live: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end + 4]).into_owned();
            heads.lock().expect("heads").push(head.clone());
            peak.fetch_max(live.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            let bytes = match handler(&head) {
                Reply::Raw(bytes) => bytes,
                Reply::Delay(pause, bytes) => {
                    sleep(pause).await;
                    bytes
                }
            };
            drop(stream.write_all(&bytes).await);
            live.fetch_sub(1, Ordering::SeqCst);
            drop(stream.shutdown().await);
            return;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

fn path_of(head: &str) -> &str {
    head.split(' ').nth(1).unwrap_or_default()
}

fn host_of(head: &str) -> &str {
    head.lines()
        .find_map(|line| line.strip_prefix("Host: "))
        .unwrap_or_default()
}

/// The app's upstream: `/boom...` is a `503` with a cookie, `/gone...` a `404`, anything else `200`.
async fn upstream() -> Server {
    Server::start(|head| match path_of(head) {
        path if path.starts_with("/boom") => http(
            503,
            &[("Set-Cookie", "sid=secret"), ("X-Origin", "app")],
            "upstream down",
        ),
        path if path.starts_with("/gone") => http(404, &[("X-Origin", "app")], "nope"),
        _ => http(200, &[], "fine"),
    })
    .await
}

/// A page server that answers `<h1>page for <path></h1>` as HTML.
async fn pages() -> Server {
    Server::start(|head| {
        http(
            200,
            &[("Content-Type", "text/html")],
            &format!("<h1>page for {}</h1>", path_of(head)),
        )
    })
    .await
}

/// An app answering `host`, proxying to `upstream`, with a service `pages` at `pages` and an
/// `errors` middleware `e` configured by `errors`.
fn site(id: &str, host: &str, upstream: SocketAddr, pages: SocketAddr, errors: Value) -> Value {
    let mut app = app(id, &[host], &[serving("r1", upstream)]);
    app["services"] = json!([service("pages", &[pages])]);
    with_middleware(app, "e", "errors", errors)
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{response:?}");
}

fn rejection(response: &Response) -> Value {
    assert_eq!(response.status, 422, "{response:?}");
    response.json()["conflicts"][0].clone()
}

#[tokio::test]
async fn errors_replaces_matching_status() {
    let podgate = Podgate::start().await;
    let (up, pages) = (upstream().await, pages().await);
    let config = json!({"status": ["500-599"], "service": "pages"});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, pages.addr, config)]),
    )
    .await;

    let replaced = podgate.get("a.test", "/boom").await;
    assert_eq!(replaced.status, 503);
    assert_eq!(replaced.body, "<h1>page for /503.html</h1>");
    assert_eq!(replaced.header("content-type"), Some("text/html"));
    assert_eq!(
        replaced.header("content-length"),
        Some(replaced.body.len().to_string().as_str())
    );
    assert_eq!(replaced.header("set-cookie"), None, "{replaced:?}");
    assert_eq!(replaced.header("x-origin"), None, "{replaced:?}");
    assert_eq!(pages.heads().len(), 1);
}

#[tokio::test]
async fn errors_leaves_other_statuses() {
    let podgate = Podgate::start().await;
    let (up, pages) = (upstream().await, pages().await);
    let config = json!({"status": ["500-599"], "service": "pages"});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, pages.addr, config)]),
    )
    .await;

    let fine = podgate.get("a.test", "/ok").await;
    assert_eq!((fine.status, fine.body.as_str()), (200, "fine"));
    let missing = podgate.get("a.test", "/gone").await;
    assert_eq!((missing.status, missing.body.as_str()), (404, "nope"));
    assert_eq!(missing.header("x-origin"), Some("app"));
    assert_eq!(
        pages.requests(),
        0,
        "no page for a status that is not listed"
    );

    // The same response is replaced once its status is listed.
    let config = json!({"status": [404], "service": "pages"});
    push(
        &podgate,
        &snapshot(2, &[site("a", "a.test", up.addr, pages.addr, config)]),
    )
    .await;
    assert_eq!(
        podgate.get("a.test", "/gone").await.body,
        "<h1>page for /404.html</h1>"
    );
    assert_eq!(podgate.get("a.test", "/boom").await.body, "upstream down");
}

#[tokio::test]
async fn errors_covers_gateway_errors() {
    let podgate = Podgate::start().await;
    let dead = refused();
    let dead_addr = dead.addr;
    let pages = pages().await;
    let config = json!({"status": ["502"], "service": "pages"});
    let covered = site("a", "a.test", dead_addr, pages.addr, config);
    let bare = app("b", &["b.test"], &[serving("r1", dead_addr)]);
    push(&podgate, &snapshot(1, &[covered, bare])).await;

    let gateway = podgate.get("a.test", "/").await;
    assert_eq!(gateway.status, 502);
    assert_eq!(gateway.body, "<h1>page for /502.html</h1>");
    assert_eq!(gateway.header("content-type"), Some("text/html"));
    // Without the middleware the same failure keeps Pingora's own answer.
    let plain = podgate.get("b.test", "/").await;
    assert_eq!(plain.status, 502);
    assert!(!plain.body.contains("page for"), "{plain:?}");
    assert_eq!(pages.requests(), 1);
    drop(dead);
}

#[tokio::test]
async fn errors_ignores_earlier_middleware_answers() {
    let podgate = Podgate::start().await;
    let (up, pages) = (upstream().await, pages().await);
    let listed = json!({"status": ["400-599"], "service": "pages"});
    let mut denied = site(
        "a",
        "a.test",
        up.addr,
        pages.addr,
        json!({"status": ["400-599"], "service": "pages"}),
    );
    denied = with_middleware(
        denied,
        "deny",
        "ip_allow_list",
        json!({"source_range": ["203.0.113.0/24"]}),
    );
    // `deny` runs after `e` in the chain, so put it first.
    denied["default_chain"] = json!(["deny", "e"]);
    let mut closed = site("b", "b.test", up.addr, pages.addr, listed);
    closed = with_middleware(
        closed,
        "closed",
        "respond",
        json!({"status": 503, "body": "closed on purpose"}),
    );
    closed["default_chain"] = json!(["closed", "e"]);
    push(&podgate, &snapshot(1, &[denied, closed])).await;

    let refused = podgate.get("a.test", "/ok").await;
    assert_eq!(refused.status, 403, "{refused:?}");
    assert!(refused.body.contains("error"), "{refused:?}");
    let answered = podgate.get("b.test", "/ok").await;
    assert_eq!(
        (answered.status, answered.body.as_str()),
        (503, "closed on purpose")
    );
    assert_eq!(
        pages.requests(),
        0,
        "an answer of an earlier middleware is never replaced"
    );
}

#[tokio::test]
async fn errors_request_has_no_client_data() {
    let podgate = Podgate::start().await;
    let (up, pages) = (upstream().await, pages().await);
    let config = json!({"status": ["503"], "service": "pages"});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, pages.addr, config)]),
    )
    .await;

    let sent = podgate
        .get_with_headers(
            "a.test",
            "/boom?token=abc",
            &[
                ("Authorization", "Bearer s3cret"),
                ("Cookie", "sid=1"),
                ("X-Custom", "v"),
                ("Accept", "text/html"),
            ],
        )
        .await;
    assert_eq!(sent.status, 503);
    podgate.get("a.test", "/boom").await;
    assert_eq!(
        pages.heads(),
        vec![
            "GET /503.html HTTP/1.1\r\nHost: a.test\r\nAccept: text/html\r\n\r\n".to_owned(),
            "GET /503.html HTTP/1.1\r\nHost: a.test\r\nAccept: */*\r\n\r\n".to_owned(),
        ]
    );
}

#[tokio::test]
async fn errors_path_is_template_only() {
    let podgate = Podgate::start().await;
    let (up, pages) = (upstream().await, pages().await);
    let config = json!({"status": ["404", "503"], "service": "pages", "query": "/p/{status}/i.html?lang=en"});
    push(
        &podgate,
        &snapshot(1, &[site("a", "a.test", up.addr, pages.addr, config)]),
    )
    .await;

    podgate
        .get("a.test", "/boom/{status}?x={status}&y=../../etc")
        .await;
    podgate.get("a.test", "/gone?y=..%2f503&z={status}").await;
    let paths: Vec<String> = pages
        .heads()
        .iter()
        .map(|head| path_of(head).to_owned())
        .collect();
    assert_eq!(paths, ["/p/503/i.html?lang=en", "/p/404/i.html?lang=en"]);
}

#[tokio::test]
async fn errors_failure_keeps_original() {
    let podgate = Podgate::start().await;
    let up = upstream().await;
    let failing = Server::start(|_| http(500, &[], "page broke")).await;
    let slow =
        Server::start(|_| Reply::Delay(Duration::from_secs(6), raw(200, &[], "too late"))).await;
    let dead = refused();
    let dead_addr = dead.addr;
    let config = |secs: u64| json!({"status": ["503"], "service": "pages", "timeout_secs": secs});
    let apps = [
        site("a", "a.test", up.addr, failing.addr, config(3)),
        site("b", "b.test", up.addr, slow.addr, config(1)),
        site("c", "c.test", up.addr, dead_addr, config(3)),
    ];
    push(&podgate, &snapshot(1, &apps)).await;

    for host in ["a.test", "c.test"] {
        let kept = podgate.get(host, "/boom").await;
        assert_eq!(
            (kept.status, kept.body.as_str()),
            (503, "upstream down"),
            "{host}"
        );
        assert_eq!(
            kept.header("set-cookie"),
            Some("sid=secret"),
            "{host}: the original is untouched"
        );
    }
    let started = Instant::now();
    let kept = podgate.get("b.test", "/boom").await;
    assert_eq!((kept.status, kept.body.as_str()), (503, "upstream down"));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the fetch is bounded by timeout_secs: {:?}",
        started.elapsed()
    );
    assert_eq!(failing.requests(), 1);
    drop(dead);
}

#[tokio::test]
async fn errors_no_recursion() {
    let podgate = Podgate::start().await;
    // One server is both the app and its page service, and everything it says is a 500.
    let broken = Server::start(|_| http(500, &[], "broken")).await;
    let mut app = app("a", &["a.test"], &[serving("r1", broken.addr)]);
    app = with_middleware(
        app,
        "e",
        "errors",
        json!({"status": ["500"], "service": "web"}),
    );
    push(&podgate, &snapshot(1, &[app])).await;

    let answer = podgate.get("a.test", "/").await;
    assert_eq!((answer.status, answer.body.as_str()), (500, "broken"));
    assert_eq!(
        broken.requests(),
        2,
        "one request and one page fetch, and the failing page does not fetch again: {:?}",
        broken.heads()
    );
    assert_eq!(path_of(&broken.heads()[1]), "/500.html");
}

#[tokio::test]
async fn errors_body_cap() {
    let podgate = Podgate::start().await;
    let up = upstream().await;
    let page = "x".repeat(2000);
    let pages = Server::start(move |head| match host_of(head) {
        "chunked.test" => Reply::Raw(
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                1000,
                &page[..1000],
                1000,
                &page[..1000]
            )
            .into_bytes(),
        ),
        "close.test" => Reply::Raw(format!("HTTP/1.1 200 OK\r\n\r\n{page}").into_bytes()),
        _ => http(200, &[], &page),
    })
    .await;
    let capped = |id: &str, host: &str, cap: u64| {
        let config = json!({"status": ["503"], "service": "pages", "max_body_bytes": cap});
        site(id, host, up.addr, pages.addr, config)
    };
    let apps = [
        capped("a", "length.test", 1000),
        capped("b", "chunked.test", 1000),
        capped("c", "close.test", 1000),
        capped("d", "roomy.test", 4000),
    ];
    push(&podgate, &snapshot(1, &apps)).await;

    for host in ["length.test", "chunked.test", "close.test"] {
        let kept = podgate.get(host, "/boom").await;
        assert_eq!(
            (kept.status, kept.body.as_str()),
            (503, "upstream down"),
            "{host}"
        );
    }
    let roomy = podgate.get("roomy.test", "/boom").await;
    assert_eq!((roomy.status, roomy.body.len()), (503, 2000));
    assert_eq!(roomy.body, "x".repeat(2000));
}

/// A policy file in its own temp directory.
struct PolicyFile(PathBuf);

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-errors-policy-{}-{}.json",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("write the policy file");
        Self(path)
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        // Best effort: a leftover temp file is harmless.
        drop(std::fs::remove_file(&self.0));
    }
}

#[tokio::test]
async fn errors_obeys_upstream_policy() {
    let policy = PolicyFile::write(r#"{"deny": ["10.9.0.0/16"]}"#);
    let podgate =
        Podgate::start_with_env(&[("UPSTREAM_POLICY_FILE", policy.0.to_str().expect("utf-8"))])
            .await;
    let up = upstream().await;
    let config = json!({"status": ["503"], "service": "pages"});
    let forbidden: SocketAddr = "10.9.0.1:80".parse().expect("addr");
    let refused = podgate
        .push_snapshot(&snapshot(
            1,
            &[site("a", "a.test", up.addr, forbidden, config.clone())],
        ))
        .await;
    let entry = rejection(&refused);
    assert_eq!(entry["code"], "upstream_forbidden", "{entry}");
    assert_eq!(entry["service"], "pages", "{entry}");

    // The connect-time check on the exact address is unit-tested in `src/middleware/errors/fetch.rs`
    // (`the_policy_decides_before_anything_is_dialled`): the compiler never sees an address the
    // snapshot did not write.
    let pages = pages().await;
    push(
        &podgate,
        &snapshot(2, &[site("a", "a.test", up.addr, pages.addr, config)]),
    )
    .await;
    assert_eq!(
        podgate.get("a.test", "/boom").await.body,
        "<h1>page for /503.html</h1>"
    );
}

/// The value of the metric line that starts with `prefix`.
fn metric(text: &str, prefix: &str) -> u64 {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .and_then(|rest| rest.trim().parse().ok())
        .unwrap_or_else(|| panic!("no metric {prefix} in {text}"))
}

#[tokio::test]
async fn errors_body_charged_to_tenant() {
    let podgate = Podgate::start().await;
    let up = upstream().await;
    let slow_pages = Server::start(|head| {
        let body = format!("<p>{}</p>", path_of(head));
        match host_of(head) {
            "slow.test" => Reply::Delay(Duration::from_millis(600), raw(200, &[], &body)),
            _ => http(200, &[], &body),
        }
    })
    .await;
    // The tenant may hold 100 KiB. A page costs its cap plus 16 KiB for the head and buffers.
    let with = |id: &str, host: &str, cap: Option<u64>| {
        let mut config = json!({"status": ["503"], "service": "pages"});
        if let Some(cap) = cap {
            config["max_body_bytes"] = json!(cap);
        }
        site(id, host, up.addr, slow_pages.addr, config)
    };
    let mut pushed = snapshot(
        1,
        &[
            with("b", "small.test", Some(8192)),
            with("c", "slow.test", Some(40_000)),
        ],
    );
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(100 * 1024);
    push(&podgate, &pushed).await;

    // 8 KiB plus the allowance is charged while the page is held.
    let small = podgate.get("small.test", "/boom").await;
    assert_eq!(small.body, "<p>/503.html</p>");
    let peak = metric(
        &podgate.admin_get("/metrics").await.body,
        "podgate_tenant_buffer_bytes_peak{tenant=\"t1\"} ",
    );
    assert_eq!(
        peak,
        8192 + 16 * 1024,
        "the page is charged as cap plus allowance"
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let now = metric(
            &podgate.admin_get("/metrics").await.body,
            "podgate_tenant_buffer_bytes{tenant=\"t1\"} ",
        );
        if now == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the charge was never released: {now}"
        );
        sleep(Duration::from_millis(50)).await;
    }

    // Room for one such page at a time: concurrent failures share it, the rest keep their original.
    let answers = tokio::join!(
        podgate.get("slow.test", "/boom"),
        podgate.get("slow.test", "/boom"),
        podgate.get("slow.test", "/boom"),
        podgate.get("slow.test", "/boom"),
    );
    let bodies = [
        answers.0.body,
        answers.1.body,
        answers.2.body,
        answers.3.body,
    ];
    let pages = bodies
        .iter()
        .filter(|body| *body == "<p>/503.html</p>")
        .count();
    let originals = bodies
        .iter()
        .filter(|body| *body == "upstream down")
        .count();
    assert_eq!(pages + originals, 4, "{bodies:?}");
    assert!(pages >= 1 && originals >= 1, "{bodies:?}");
    assert_eq!(
        slow_pages.peak_concurrency(),
        1,
        "the budget admits one fetch at a time"
    );
}

#[tokio::test]
async fn errors_unknown_service_rejected() {
    let podgate = Podgate::start().await;
    let (up, pages) = (upstream().await, pages().await);
    for (service, version) in [("nope", 1), ("pages@r9", 2), ("web@r1", 3)] {
        let mut a = site(
            "a",
            "a.test",
            up.addr,
            pages.addr,
            json!({"status": ["503"], "service": service}),
        );
        // `web` is the revision's own service, so only the first two names are unknown.
        let response = podgate.push_snapshot(&snapshot(version, &[a.take()])).await;
        if service == "web@r1" {
            assert_eq!(response.status, 200, "{response:?}");
        } else {
            let entry = rejection(&response);
            assert_eq!(entry["code"], "unknown_service", "{service}: {entry}");
            assert_eq!(entry["app"], "a");
        }
    }
}

#[tokio::test]
async fn errors_invalid_status_rejected() {
    let podgate = Podgate::start().await;
    let (up, pages) = (upstream().await, pages().await);
    for (status, version) in [
        (json!(["200"]), 1),
        (json!(["300-399"]), 2),
        (json!(["400-600"]), 3),
        (json!([]), 4),
        (json!(["599-500"]), 5),
    ] {
        let config = json!({"status": status, "service": "pages"});
        let response = podgate
            .push_snapshot(&snapshot(
                version,
                &[site("a", "a.test", up.addr, pages.addr, config)],
            ))
            .await;
        let entry = rejection(&response);
        assert_eq!(entry["code"], "invalid_middleware", "{status}: {entry}");
    }
}

/// An app with the `respond` middleware `closed`, in its chain.
fn closing(upstream: SocketAddr, config: Value) -> Value {
    with_middleware(
        app("a", &["a.test"], &[serving("r1", upstream)]),
        "closed",
        "respond",
        config,
    )
}

#[tokio::test]
async fn respond_static_answer() {
    let podgate = Podgate::start().await;
    let up = upstream().await;
    let config = json!({
        "status": 418,
        "headers": {"X-Closed": "yes", "content-type": "text/plain; charset=utf-8"},
        "body": "closed\nfor now",
    });
    push(&podgate, &snapshot(1, &[closing(up.addr, config)])).await;

    let answer = podgate.get("a.test", "/anything").await;
    assert_eq!(answer.status, 418);
    assert_eq!(answer.body, "closed\nfor now");
    assert_eq!(answer.header("x-closed"), Some("yes"));
    assert_eq!(
        answer.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(answer.header("content-length"), Some("14"));

    let head = podgate.request("HEAD", "a.test", "/anything", &[]).await;
    assert_eq!((head.status, head.body.as_str()), (418, ""));
    assert_eq!(head.header("content-length"), Some("14"));

    // No body, no content type; a body without one is plain text.
    push(
        &podgate,
        &snapshot(2, &[closing(up.addr, json!({"status": 204}))]),
    )
    .await;
    let empty = podgate.get("a.test", "/").await;
    assert_eq!((empty.status, empty.body.as_str()), (204, ""));
    assert_eq!(empty.header("content-type"), None);
    push(
        &podgate,
        &snapshot(3, &[closing(up.addr, json!({"status": 200, "body": "hi"}))]),
    )
    .await;
    let plain = podgate.get("a.test", "/").await;
    assert_eq!(
        plain.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
}

#[tokio::test]
async fn respond_never_contacts_upstream() {
    let podgate = Podgate::start().await;
    let up = upstream().await;
    // A closed route: everything outside /public answers 403, nothing reaches the upstream.
    let mut app = closing(up.addr, json!({"status": 403, "body": "closed"}));
    let open = router(
        "open",
        json!({"all": [{"host": "a.test"}, {"path_prefix": "/public"}]}),
        "web",
    );
    let mut closed = router(
        "closed",
        json!({"all": [{"host": "a.test"}, {"not": {"path_prefix": "/public"}}]}),
        "web",
    );
    closed["chain"] = json!(["closed"]);
    app["routers"] = json!([open, closed]);
    app["default_chain"] = json!([]);
    push(&podgate, &snapshot(1, &[app])).await;

    for path in ["/", "/private", "/admin/x", "/publi"] {
        let answer = podgate.get("a.test", path).await;
        assert_eq!(
            (answer.status, answer.body.as_str()),
            (403, "closed"),
            "{path}"
        );
    }
    assert_eq!(up.requests(), 0, "respond is terminal: no upstream request");
    let open = podgate.get("a.test", "/public/x").await;
    assert_eq!((open.status, open.body.as_str()), (200, "fine"));
    assert_eq!(up.requests(), 1);
}

#[tokio::test]
async fn respond_invalid_rejected() {
    let podgate = Podgate::start().await;
    let up = upstream().await;
    let bad = [
        json!({"status": 200, "headers": {"x-a": "ok\r\nSet-Cookie: pwn=1"}}),
        json!({"status": 200, "headers": {"x-a\r\ninjected": "v"}}),
        json!({"status": 200, "headers": {"content-length": "4"}}),
        json!({"status": 200, "headers": {"transfer-encoding": "chunked"}}),
        json!({"status": 200, "body": "x".repeat(64 * 1024 + 1)}),
        json!({"status": 101}),
        json!({"status": 100}),
        json!({"status": 600}),
        json!({"status": 204, "body": "x"}),
        json!({"body": "no status"}),
    ];
    for (version, config) in (1..).zip(bad) {
        let response = podgate
            .push_snapshot(&snapshot(version, &[closing(up.addr, config.clone())]))
            .await;
        let entry = rejection(&response);
        assert!(
            ["invalid_middleware"].contains(&entry["code"].as_str().unwrap_or_default()),
            "{config}: {entry}"
        );
    }
    // The largest body and a header with every allowed character still compile.
    let limit =
        json!({"status": 200, "headers": {"x-ok": "a b\tc;q=1"}, "body": "x".repeat(64 * 1024)});
    push(&podgate, &snapshot(99, &[closing(up.addr, limit)])).await;
}

/// A certificate authority and what it issues, for a page server that speaks TLS.
struct Pki {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().expect("CA key"),
        )
        .expect("CA");
        Self { issuer }
    }

    /// A certificate for `names` signed by this CA: its PEM and its key's PEM.
    fn issue(&self, names: &[&str]) -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("key");
        let params = rcgen::CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("params");
        let cert = params.signed_by(&key, &self.issuer).expect("sign");
        (cert.pem(), key.serialize_pem())
    }
}

/// A TLS page server that insists on a client certificate from `pki` and says in its page which
/// server name and client certificate it saw.
async fn tls_pages(pki: &Pki, server: (String, String)) -> SocketAddr {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pki.issuer.pem().as_bytes()).expect("CA DER"))
        .expect("trust the CA");
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()
    .expect("client verifier");
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(server.0.as_bytes())
        .collect::<Result<_, _>>()
        .expect("chain");
    let key = PrivateKeyDer::from_pem_slice(server.1.as_bytes()).expect("key");
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let (_, connection) = stream.get_ref();
                let page = format!(
                    "tls page sni={} client={}",
                    connection.server_name().unwrap_or("none"),
                    connection
                        .peer_certificates()
                        .is_some_and(|chain| !chain.is_empty())
                );
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
                drop(stream.write_all(&raw(200, &[], &page)).await);
                drop(stream.shutdown().await);
            });
        }
    });
    addr
}

#[tokio::test]
async fn errors_page_over_tls_uses_the_transport() {
    let podgate = Podgate::start().await;
    let up = upstream().await;
    let pki = Pki::new();
    let addr = tls_pages(&pki, pki.issue(&["127.0.0.1", "pages.internal"])).await;
    let client = pki.issue(&[]);
    let services = json!([{
        "name": "pages", "type": "loadbalancer", "servers": [{"url": format!("https://{addr}")}],
        "transport": "t",
    }, {
        "name": "plain", "type": "loadbalancer", "servers": [{"url": format!("https://{addr}")}],
    }]);
    let transports = json!([{
        "name": "t", "type": "servers_transport", "server_name": "pages.internal",
        "ca_pem": pki.issuer.pem(),
        "client_cert": {"cert_pem": client.0, "key_pem": client.1},
    }]);
    let with = |id: &str, host: &str, service: &str| {
        let mut app = app(id, &[host], &[serving("r1", up.addr)]);
        app["services"] = services.clone();
        app["transports"] = transports.clone();
        with_middleware(
            app,
            "e",
            "errors",
            json!({"status": ["503"], "service": service}),
        )
    };
    push(
        &podgate,
        &snapshot(
            1,
            &[with("a", "a.test", "pages"), with("b", "b.test", "plain")],
        ),
    )
    .await;

    // The private CA, the server name and the client certificate of the service's transport.
    let page = podgate.get("a.test", "/boom").await;
    assert_eq!(page.status, 503);
    assert_eq!(page.body, "tls page sni=pages.internal client=true");
    // A service with no transport trusts only the platform roots: the handshake fails and the
    // original response stays.
    let kept = podgate.get("b.test", "/boom").await;
    assert_eq!((kept.status, kept.body.as_str()), (503, "upstream down"));
}

#[tokio::test]
async fn errors_cap_over_tenant_budget_rejected() {
    let podgate = Podgate::start().await;
    let (up, pages) = (upstream().await, pages().await);
    let site_with = |extra: Value| {
        let mut config = json!({"status": ["503"], "service": "pages"});
        config.as_object_mut().expect("object").extend(extra.as_object().expect("object").clone());
        site("a", "a.test", up.addr, pages.addr, config)
    };
    let with_budget = |version: u64, bytes: u64, app: Value| {
        let mut pushed = snapshot(version, &[app]);
        pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(bytes);
        pushed
    };

    // The default cap (256 KiB) plus the 16 KiB allowance never fits 100 KiB: refused, with the
    // numbers, instead of silently never serving a page.
    let refused = podgate
        .push_snapshot(&with_budget(1, 100 * 1024, site_with(json!({}))))
        .await;
    let entry = rejection(&refused);
    assert_eq!(entry["code"], "invalid_middleware", "{entry}");
    assert_eq!(entry["app"], "a");
    assert_eq!(entry["needed_bytes"], 256 * 1024 + 16 * 1024, "{entry}");
    assert_eq!(entry["max_buffer_bytes"], 100 * 1024, "{entry}");
    assert_eq!(entry["tenant"], "t1", "{entry}");
    let message = entry["message"].as_str().expect("message");
    assert!(message.contains("t1") && message.contains("102400"), "{message}");

    // Exactly the budget fits; a budget that is merely busy later keeps the original response.
    let needed = 8192 + 16 * 1024;
    push(
        &podgate,
        &with_budget(2, needed, site_with(json!({"max_body_bytes": 8192}))),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/boom").await.body, "<h1>page for /503.html</h1>");
    let refused = podgate
        .push_snapshot(&with_budget(3, needed - 1, site_with(json!({"max_body_bytes": 8192}))))
        .await;
    assert_eq!(rejection(&refused)["code"], "invalid_middleware");
}
