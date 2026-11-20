//! The `cache` middleware, end to end on the real binary: hits, freshness, what is
//! never stored, `Vary`, revalidation, collapsed misses, the tenant's budget, isolation between
//! tenants and apps, and the purge API.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use common::{Podgate, app, serving, snapshot, with_middleware};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// What the test upstream answers.
#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
    chunked: bool,
}

impl Reply {
    fn ok(body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: body.as_bytes().to_vec(),
            delay: Duration::ZERO,
            chunked: false,
        }
    }

    fn bytes(len: usize) -> Self {
        Self::ok(&"x".repeat(len))
    }

    fn with(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    fn delayed(mut self, ms: u64) -> Self {
        self.delay = Duration::from_millis(ms);
        self
    }

    fn chunked(mut self) -> Self {
        self.chunked = true;
        self
    }

    fn fresh(self, secs: u64) -> Self {
        self.with("Cache-Control", &format!("max-age={secs}"))
    }
}

/// One request the upstream saw.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

type Handler = Arc<dyn Fn(&Seen, usize) -> Reply + Send + Sync>;

/// An upstream that answers through a handler `(request, index of this request overall)` and
/// records every request.
struct Backend {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Backend {
    async fn start(handler: impl Fn(&Seen, usize) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler: Handler = Arc::new(handler);
        let (log, counter) = (Arc::clone(&seen), Arc::new(AtomicUsize::new(0)));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(
                    stream,
                    Arc::clone(&handler),
                    Arc::clone(&log),
                    Arc::clone(&counter),
                ));
            }
        });
        Self { addr, seen }
    }

    fn count(&self) -> usize {
        self.seen.lock().expect("log").len()
    }

    fn count_path(&self, path: &str) -> usize {
        self.seen().iter().filter(|seen| seen.path == path).count()
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("log").clone()
    }
}

async fn serve(
    mut stream: TcpStream,
    handler: Handler,
    log: Arc<Mutex<Vec<Seen>>>,
    counter: Arc<AtomicUsize>,
) {
    let mut buffered = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        while let Some(end) = find(&buffered, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffered[..end]).into_owned();
            buffered.drain(..end + 4);
            let mut lines = head.split("\r\n");
            let mut words = lines.next().unwrap_or("").split_whitespace();
            let method = words.next().unwrap_or("").to_owned();
            let path = words.next().unwrap_or("/").to_owned();
            let headers = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
                .collect();
            let seen = Seen {
                method,
                path,
                headers,
            };
            let index = counter.fetch_add(1, Ordering::SeqCst);
            log.lock().expect("log").push(seen.clone());
            let reply = handler(&seen, index);
            sleep(reply.delay).await;
            if stream
                .write_all(&wire(&reply, seen.method == "HEAD"))
                .await
                .is_err()
            {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => buffered.extend_from_slice(&chunk[..read]),
        }
    }
}

fn wire(reply: &Reply, head_only: bool) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {} X\r\n", reply.status);
    for (name, value) in &reply.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    let bodiless = matches!(reply.status, 204 | 304);
    if reply.chunked {
        out.push_str("Transfer-Encoding: chunked\r\n");
    } else if !bodiless {
        out.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    if head_only || bodiless {
        return bytes;
    }
    if reply.chunked {
        for chunk in reply.body.chunks(1000) {
            bytes.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            bytes.extend_from_slice(chunk);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"0\r\n\r\n");
    } else {
        bytes.extend_from_slice(&reply.body);
    }
    bytes
}

/// A response as received, chunked framing undone.
#[derive(Debug)]
struct Got {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Got {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The `Cache-Status` result: `hit`, `miss`, `stale`, `bypass` or `revalidated`.
    fn result(&self) -> &str {
        self.header("cache-status")
            .and_then(|value| value.strip_prefix("podgate; "))
            .unwrap_or("none")
    }
}

fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let line_end = find(raw, b"\r\n").expect("chunk size line");
        let size = usize::from_str_radix(
            std::str::from_utf8(&raw[..line_end]).expect("ascii size"),
            16,
        )
        .expect("hex chunk size");
        raw = &raw[line_end + 2..];
        if size == 0 {
            return body;
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

async fn send(
    proxy: SocketAddr,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Got {
    timeout(Duration::from_secs(20), async {
        let mut stream = TcpStream::connect(proxy).await.expect("connect");
        let extra: String = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect();
        let request =
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let split = find(&raw, b"\r\n\r\n").expect("header end");
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status line");
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let mut body = raw[split + 4..].to_vec();
        if headers
            .iter()
            .any(|(name, value)| name == "transfer-encoding" && value == "chunked")
        {
            body = dechunk(&body);
        }
        Got {
            status,
            headers,
            body,
        }
    })
    .await
    .expect("response in time")
}

/// `GET path` on `a.test`.
async fn get(podgate: &Podgate, path: &str) -> Got {
    send(podgate.proxy_addr, "GET", "a.test", path, &[]).await
}

async fn get_with(podgate: &Podgate, path: &str, headers: &[(&str, &str)]) -> Got {
    send(podgate.proxy_addr, "GET", "a.test", path, headers).await
}

/// Starts `podgate` with app `a.test` (tenant `t1`, 1 MiB budget) on `upstream`, with a `cache`
/// middleware configured by `config`.
async fn serve_cache(upstream: SocketAddr, config: Value) -> Podgate {
    serve_cache_with(upstream, config, &[]).await
}

async fn serve_cache_with(upstream: SocketAddr, config: Value, env: &[(&str, &str)]) -> Podgate {
    let podgate = Podgate::start_with_env(env).await;
    let app = with_middleware(
        app("a", &["a.test"], &[serving("r1", upstream)]),
        "c",
        "cache",
        config,
    );
    let pushed = podgate.push_snapshot(&snapshot(1, &[app])).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    podgate
}

/// A snapshot with tenants `t1` and `t2` (1 MiB each).
fn two_tenants(version: u64, apps: &[Value]) -> Value {
    json!({
        "version": version,
        "tenants": [
            { "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
            { "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
        ],
        "apps": apps,
    })
}

/// An app of `tenant` with a `cache` middleware.
fn cached_app(tenant: &str, id: &str, host: &str, upstream: SocketAddr, config: Value) -> Value {
    let mut app = with_middleware(
        app(id, &[host], &[serving("r1", upstream)]),
        "c",
        "cache",
        config,
    );
    app["tenant"] = json!(tenant);
    app
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// The value of the series `selector` (name and labels, as exposed) in `/metrics`.
async fn metric(podgate: &Podgate, selector: &str) -> Option<u64> {
    let body = podgate.admin_get("/metrics").await.body;
    body.lines()
        .find_map(|line| line.strip_prefix(selector)?.trim().parse().ok())
}

fn http_date(offset_secs: u64) -> String {
    httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(offset_secs))
}

#[tokio::test]
async fn cache_hit_serves_without_upstream() {
    let backend = Backend::start(|_, n| Reply::ok(&format!("page {n}")).fresh(60)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    let first = get(&podgate, "/page").await;
    let second = get(&podgate, "/page").await;
    assert_eq!((first.status, first.text().as_str()), (200, "page 0"));
    assert_eq!((second.status, second.text().as_str()), (200, "page 0"));
    assert_eq!(backend.count(), 1, "the hit never reached the upstream");
    let other = get(&podgate, "/other").await;
    assert_eq!(other.text(), "page 1", "another URL is another entry");
}

#[tokio::test]
async fn cache_status_and_age_headers() {
    let backend = Backend::start(|_, _| Reply::ok("page").fresh(60)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    let miss = get(&podgate, "/page").await;
    assert_eq!(miss.result(), "miss");
    assert_eq!(
        miss.header("age"),
        None,
        "a response from the upstream has no Age"
    );
    sleep(Duration::from_millis(1200)).await;
    let hit = get(&podgate, "/page").await;
    assert_eq!(hit.result(), "hit");
    let age: u64 = hit
        .header("age")
        .expect("Age on a hit")
        .parse()
        .expect("seconds");
    assert!((1..=3).contains(&age), "age {age}");
    assert_eq!(hit.header("content-length"), Some("4"));
    assert_eq!(hit.header("content-type"), Some("text/plain"));
    assert_eq!(hit.header("cache-control"), Some("max-age=60"));
}

#[tokio::test]
async fn cache_respects_s_maxage_max_age_expires() {
    let backend = Backend::start(|seen, _| match seen.path.as_str() {
        "/s" => Reply::ok("s").with("Cache-Control", "max-age=0, s-maxage=60"),
        "/m" => Reply::ok("m").with("Cache-Control", "max-age=60"),
        "/e" => Reply::ok("e").with("Expires", &http_date(60)),
        "/past" => Reply::ok("past").with("Expires", &http_date(0)),
        "/bad" => Reply::ok("bad").with("Expires", "0"),
        _ => Reply::ok("none"),
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    for path in ["/s", "/m", "/e"] {
        assert_eq!(get(&podgate, path).await.result(), "miss", "{path}");
        assert_eq!(get(&podgate, path).await.result(), "hit", "{path}");
        assert_eq!(backend.count_path(path), 1, "{path} is fresh");
    }
    for path in ["/past", "/bad", "/none"] {
        get(&podgate, path).await;
        get(&podgate, path).await;
        assert_eq!(
            backend.count_path(path),
            2,
            "{path} has no freshness to keep"
        );
    }
}

#[tokio::test]
async fn cache_default_ttl_is_opt_in() {
    let backend = Backend::start(|_, _| Reply::ok("none")).await;
    let podgate = serve_cache(backend.addr, json!({ "default_ttl_secs": 30 })).await;
    get(&podgate, "/x").await;
    assert_eq!(get(&podgate, "/x").await.result(), "hit");
    assert_eq!(backend.count(), 1);
}

#[tokio::test]
async fn cache_expires_on_time() {
    let backend = Backend::start(|_, n| Reply::ok(&format!("v{n}")).fresh(1)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    assert_eq!(get(&podgate, "/t").await.text(), "v0");
    assert_eq!(get(&podgate, "/t").await.text(), "v0");
    sleep(Duration::from_millis(1300)).await;
    let renewed = get(&podgate, "/t").await;
    assert_eq!((renewed.text().as_str(), renewed.result()), ("v1", "miss"));
    assert_eq!(get(&podgate, "/t").await.text(), "v1");
}

#[tokio::test]
async fn cache_stale_while_revalidate() {
    let backend = Backend::start(|_, n| {
        let reply = Reply::ok(&format!("v{n}"))
            .with("Cache-Control", "max-age=1, stale-while-revalidate=30");
        if n == 0 { reply } else { reply.delayed(400) }
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    assert_eq!(get(&podgate, "/s").await.text(), "v0");
    sleep(Duration::from_millis(1300)).await;
    let started = Instant::now();
    let stale = get(&podgate, "/s").await;
    assert_eq!((stale.text().as_str(), stale.result()), ("v0", "stale"));
    assert!(
        started.elapsed() < Duration::from_millis(350),
        "the stale response did not wait for the 400 ms refresh: {:?}",
        started.elapsed()
    );
    wait_until("the background refresh to reach the upstream", || {
        backend.count() == 2
    })
    .await;
    let mut refreshed = None;
    for _ in 0..40 {
        let got = get(&podgate, "/s").await;
        if got.text() == "v1" {
            refreshed = Some(got);
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    let refreshed = refreshed.expect("the refresh replaced the entry");
    assert_eq!(refreshed.result(), "hit");
    assert_eq!(
        backend.count(),
        2,
        "one refresh, however many requests found it stale"
    );
}

#[tokio::test]
async fn cache_stale_if_error() {
    let backend = Backend::start(|_, n| {
        if n == 0 {
            Reply::ok("good").with("Cache-Control", "max-age=1, stale-if-error=30")
        } else {
            Reply::ok("boom").status(500)
        }
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    assert_eq!(get(&podgate, "/e").await.text(), "good");
    sleep(Duration::from_millis(1300)).await;
    let stale = get(&podgate, "/e").await;
    assert_eq!(
        (stale.status, stale.text().as_str(), stale.result()),
        (200, "good", "stale"),
        "the upstream's 500 is replaced by the stale entry"
    );
    assert_eq!(backend.count(), 2, "the upstream was asked");
}

#[tokio::test]
async fn cache_stale_if_error_is_bounded() {
    let backend = Backend::start(|_, n| {
        if n == 0 {
            Reply::ok("good").with("Cache-Control", "max-age=1, stale-if-error=1")
        } else {
            Reply::ok("boom").status(500)
        }
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/e").await;
    sleep(Duration::from_millis(2300)).await;
    let past = get(&podgate, "/e").await;
    assert_eq!(
        past.status, 500,
        "past its stale-if-error window the error is the answer"
    );
}

#[tokio::test]
async fn cache_no_store_private_not_stored() {
    let backend = Backend::start(|seen, _| match seen.path.as_str() {
        "/no-store" => Reply::ok("a").with("Cache-Control", "no-store, max-age=60"),
        _ => Reply::ok("b").with("Cache-Control", "private, max-age=60"),
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    for path in ["/no-store", "/private"] {
        assert_eq!(get(&podgate, path).await.result(), "miss", "{path}");
        assert_eq!(get(&podgate, path).await.result(), "miss", "{path}");
        assert_eq!(backend.count_path(path), 2, "{path} is never stored");
    }
    assert_eq!(
        metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}")
            .await
            .unwrap_or(0),
        0
    );
}

#[tokio::test]
async fn cache_set_cookie_not_stored() {
    let backend =
        Backend::start(|_, _| Reply::ok("page").fresh(60).with("Set-Cookie", "sid=1")).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/c").await;
    let again = get(&podgate, "/c").await;
    assert_eq!(again.result(), "miss");
    assert_eq!(backend.count(), 2);
    drop(podgate);

    let podgate = serve_cache(backend.addr, json!({ "cache_set_cookie": true })).await;
    let first = get(&podgate, "/c2").await;
    assert_eq!(
        first.header("set-cookie"),
        Some("sid=1"),
        "the cookie reaches the client that caused the miss"
    );
    let hit = get(&podgate, "/c2").await;
    assert_eq!(hit.result(), "hit");
    assert_eq!(
        hit.header("set-cookie"),
        None,
        "the stored copy has no cookie"
    );
}

#[tokio::test]
async fn cache_vary_star_uncacheable() {
    let backend = Backend::start(|_, _| Reply::ok("page").fresh(60).with("Vary", "*")).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/v").await;
    assert_eq!(get(&podgate, "/v").await.result(), "miss");
    assert_eq!(backend.count(), 2);
}

#[tokio::test]
async fn cache_authorization_bypass() {
    let backend = Backend::start(|_, n| {
        Reply::ok(&format!("v{n}"))
            .fresh(60)
            .with("Cache-Control", "public, max-age=60")
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    assert_eq!(get(&podgate, "/a").await.text(), "v0");
    assert_eq!(get(&podgate, "/a").await.result(), "hit");
    let authorized = get_with(&podgate, "/a", &[("Authorization", "Bearer x")]).await;
    assert_eq!(
        (authorized.result(), authorized.text().as_str()),
        ("bypass", "v1"),
        "a request with credentials is never answered from the cache"
    );
    get_with(&podgate, "/auth-only", &[("Authorization", "Bearer x")]).await;
    assert_eq!(
        get(&podgate, "/auth-only").await.result(),
        "miss",
        "and its response was not stored"
    );
}

#[tokio::test]
async fn cache_request_cookie_bypass() {
    let backend = Backend::start(|_, n| Reply::ok(&format!("v{n}")).fresh(60)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/k").await;
    let with_cookie = get_with(&podgate, "/k", &[("Cookie", "sid=1")]).await;
    assert_eq!(
        (with_cookie.result(), with_cookie.text().as_str()),
        ("bypass", "v1")
    );
    drop(podgate);

    let podgate = serve_cache(backend.addr, json!({ "ignore_request_cookies": true })).await;
    get_with(&podgate, "/k2", &[("Cookie", "sid=1")]).await;
    let hit = get_with(&podgate, "/k2", &[("Cookie", "sid=2")]).await;
    assert_eq!(
        hit.result(),
        "hit",
        "the cookie is ignored when the declaration says so"
    );
}

#[tokio::test]
async fn cache_range_bypass() {
    let backend = Backend::start(|_, _| Reply::ok("0123456789").fresh(60)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/r").await;
    let ranged = get_with(&podgate, "/r", &[("Range", "bytes=0-3")]).await;
    assert_eq!(ranged.result(), "bypass");
    assert_eq!(backend.count(), 2, "the range request went to the upstream");
    let upstream_saw = backend.seen().pop().expect("seen");
    assert_eq!(upstream_saw.header("range"), Some("bytes=0-3"));
    assert_eq!(
        get(&podgate, "/r").await.result(),
        "hit",
        "the whole entry is still there"
    );
}

#[tokio::test]
async fn cache_over_object_cap_not_stored() {
    let backend = Backend::start(|seen, _| match seen.path.as_str() {
        "/declared" => Reply::bytes(5000).fresh(60),
        _ => Reply::bytes(5000).fresh(60).chunked(),
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({ "max_object_bytes": 1000 })).await;
    for path in ["/declared", "/chunked"] {
        let first = get(&podgate, path).await;
        assert_eq!(
            first.body.len(),
            5000,
            "{path} still reaches the client whole"
        );
        get(&podgate, path).await;
        assert_eq!(backend.count_path(path), 2, "{path} is over the object cap");
    }
    assert_eq!(
        metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}")
            .await
            .unwrap_or(0),
        0,
        "an abandoned copy leaves nothing charged"
    );
    assert_eq!(
        metric(&podgate, "podgate_tenant_buffer_bytes{tenant=\"t1\"}")
            .await
            .unwrap_or(0),
        0
    );
}

#[tokio::test]
async fn cache_vary_accept_encoding() {
    let backend = Backend::start(|seen, _| {
        let coding = seen.header("accept-encoding").unwrap_or("none").to_owned();
        Reply::ok(&format!("for {coding}"))
            .fresh(60)
            .with("Vary", "Accept-Encoding")
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    let gzip = [("Accept-Encoding", "gzip")];
    assert_eq!(get_with(&podgate, "/v", &gzip).await.text(), "for gzip");
    let again = get_with(&podgate, "/v", &gzip).await;
    assert_eq!((again.text().as_str(), again.result()), ("for gzip", "hit"));
    let plain = get(&podgate, "/v").await;
    assert_eq!(
        (plain.text().as_str(), plain.result()),
        ("for none", "miss")
    );
    let reordered = get_with(&podgate, "/v", &[("Accept-Encoding", "GZIP;q=1.0")]).await;
    assert_eq!(
        reordered.result(),
        "hit",
        "equivalent Accept-Encoding values are one variant"
    );
    let other = get_with(&podgate, "/v", &[("Accept-Encoding", "br, gzip")]).await;
    assert_eq!(
        other.result(),
        "miss",
        "a different set of codings is another variant"
    );
    assert_eq!(backend.count(), 3);
}

#[tokio::test]
async fn cache_vary_other_header_selects_variants() {
    let backend = Backend::start(|seen, _| {
        let lang = seen.header("accept-language").unwrap_or("none").to_owned();
        Reply::ok(&format!("lang {lang}"))
            .fresh(60)
            .with("Vary", "Accept-Language")
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    assert_eq!(
        get_with(&podgate, "/l", &[("Accept-Language", "en")])
            .await
            .text(),
        "lang en"
    );
    assert_eq!(
        get_with(&podgate, "/l", &[("Accept-Language", "fr")])
            .await
            .text(),
        "lang fr"
    );
    assert_eq!(
        get_with(&podgate, "/l", &[("Accept-Language", "en")])
            .await
            .result(),
        "hit"
    );
    assert_eq!(backend.count(), 2);
}

#[tokio::test]
async fn cache_no_cache_revalidates() {
    let backend = Backend::start(|seen, _| {
        let base = Reply::ok("page")
            .with("Cache-Control", "no-cache")
            .with("ETag", "\"v1\"");
        if seen.header("if-none-match") == Some("\"v1\"") {
            Reply {
                status: 304,
                body: Vec::new(),
                ..base
            }
        } else {
            base
        }
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    let first = get(&podgate, "/n").await;
    assert_eq!(
        (first.status, first.text().as_str(), first.result()),
        (200, "page", "miss")
    );
    let second = get(&podgate, "/n").await;
    assert_eq!(
        (second.status, second.text().as_str(), second.result()),
        (200, "page", "revalidated"),
        "the origin's 304 is answered with the stored page; upstream saw {:?}",
        backend.seen()
    );
    let seen = backend.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[1].header("if-none-match"),
        Some("\"v1\""),
        "a conditional request"
    );
    let third = get(&podgate, "/n").await;
    assert_eq!(third.result(), "revalidated", "and so before every use");
    assert_eq!(backend.count(), 3);
}

#[tokio::test]
async fn cache_head_served_from_get() {
    let backend = Backend::start(|_, _| Reply::ok("0123456789").fresh(60)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/h").await;
    let head = send(podgate.proxy_addr, "HEAD", "a.test", "/h", &[]).await;
    assert_eq!((head.status, head.result()), (200, "hit"));
    assert_eq!(head.header("content-length"), Some("10"));
    assert!(head.body.is_empty());
    assert_eq!(
        backend.count(),
        1,
        "the HEAD was answered from the GET entry"
    );
    let cold = send(podgate.proxy_addr, "HEAD", "a.test", "/never", &[]).await;
    assert_eq!(cold.result(), "miss");
    assert_eq!(
        get(&podgate, "/never").await.result(),
        "miss",
        "a HEAD stores nothing"
    );
}

#[tokio::test]
async fn cache_if_none_match_gets_304() {
    let backend = Backend::start(|_, _| Reply::ok("page").fresh(60).with("ETag", "\"abc\"")).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/i").await;
    let matched = get_with(&podgate, "/i", &[("If-None-Match", "W/\"abc\", \"zzz\"")]).await;
    assert_eq!((matched.status, matched.result()), (304, "hit"));
    assert!(matched.body.is_empty());
    assert_eq!(matched.header("etag"), Some("\"abc\""));
    let other = get_with(&podgate, "/i", &[("If-None-Match", "\"zzz\"")]).await;
    assert_eq!((other.status, other.text().as_str()), (200, "page"));
    assert_eq!(backend.count(), 1);
}

#[tokio::test]
async fn cache_stampede_collapsed() {
    let backend = Backend::start(|_, n| Reply::ok(&format!("v{n}")).fresh(60).delayed(500)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    let proxy = podgate.proxy_addr;
    let requests: Vec<_> = (0..20)
        .map(|_| tokio::spawn(async move { send(proxy, "GET", "a.test", "/hot", &[]).await }))
        .collect();
    let mut bodies = Vec::new();
    for request in requests {
        bodies.push(request.await.expect("task").text());
    }
    assert_eq!(
        backend.count(),
        1,
        "twenty concurrent misses made one upstream request"
    );
    assert!(bodies.iter().all(|body| body == "v0"), "{bodies:?}");
    let collapsed = metric(&podgate, "podgate_cache_collapsed_total ")
        .await
        .unwrap_or(0);
    assert!(collapsed >= 10, "waiters are counted: {collapsed}");
}

#[tokio::test]
async fn cache_waiters_bounded() {
    let backend = Backend::start(|_, n| Reply::ok(&format!("v{n}")).fresh(60).delayed(1500)).await;
    let podgate = serve_cache(backend.addr, json!({ "collapse_timeout_ms": 8000 })).await;
    let proxy = podgate.proxy_addr;
    let requests: Vec<_> = (0..100)
        .map(|_| tokio::spawn(async move { send(proxy, "GET", "a.test", "/hot", &[]).await }))
        .collect();
    for request in requests {
        assert_eq!(request.await.expect("task").status, 200);
    }
    let upstream = backend.count();
    // One leader, at most 64 waiters; the rest go to the upstream alone.
    assert!(
        upstream >= 2,
        "requests past the waiter cap reached the upstream: {upstream}"
    );
    assert!(
        upstream <= 1 + (100 - 64),
        "at most 64 requests waited: {upstream}"
    );
}

#[tokio::test]
async fn cache_waiter_gives_up_after_the_timeout() {
    let backend = Backend::start(|_, n| Reply::ok(&format!("v{n}")).fresh(60).delayed(1500)).await;
    let podgate = serve_cache(backend.addr, json!({ "collapse_timeout_ms": 200 })).await;
    let proxy = podgate.proxy_addr;
    let leader = tokio::spawn(async move { send(proxy, "GET", "a.test", "/slow", &[]).await });
    sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let follower = send(proxy, "GET", "a.test", "/slow", &[]).await;
    assert_eq!(follower.status, 200);
    assert!(
        started.elapsed() >= Duration::from_millis(1400),
        "it then asked the slow upstream itself"
    );
    leader.await.expect("leader");
    assert_eq!(
        backend.count(),
        2,
        "the follower did not wait for the leader past its timeout"
    );
}

#[tokio::test]
async fn cache_bytes_charged_to_tenant_budget() {
    let backend = Backend::start(|_, _| Reply::bytes(10_000).fresh(60)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/big").await;
    let cached = metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}")
        .await
        .expect("series");
    let charged = metric(&podgate, "podgate_tenant_buffer_bytes{tenant=\"t1\"}")
        .await
        .expect("series");
    assert!(
        cached > 10_000 && cached < 12_000,
        "body plus head plus overhead: {cached}"
    );
    assert_eq!(
        charged, cached,
        "every cached byte is on the tenant's budget, nothing else is"
    );
    get(&podgate, "/big2").await;
    let two = metric(&podgate, "podgate_tenant_buffer_bytes{tenant=\"t1\"}")
        .await
        .expect("series");
    assert_eq!(two, 2 * cached);
}

#[tokio::test]
async fn cache_tenant_cap_holds() {
    let backend = Backend::start(|_, _| Reply::bytes(30_000).fresh(60)).await;
    let podgate = serve_cache(
        backend.addr,
        json!({ "max_bytes": 100_000, "max_object_bytes": 40_000 }),
    )
    .await;
    for n in 0..12 {
        get(&podgate, &format!("/p{n}")).await;
        let held = metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}")
            .await
            .expect("series");
        assert!(
            held <= 100_000,
            "after {} responses the cache holds {held}",
            n + 1
        );
    }
    let evicted = metric(&podgate, "podgate_cache_evictions_total{tenant=\"t1\"}")
        .await
        .expect("series");
    assert!(
        evicted >= 8,
        "the tenant's own entries made room: {evicted}"
    );
    let budget = metric(&podgate, "podgate_tenant_buffer_bytes{tenant=\"t1\"}")
        .await
        .expect("series");
    assert!(budget <= 100_000, "{budget}");
    // The most recent entries are the ones that stayed.
    assert_eq!(get(&podgate, "/p11").await.result(), "hit");
    assert_eq!(get(&podgate, "/p0").await.result(), "miss");
}

#[tokio::test]
async fn cache_tenant_cap_holds_with_concurrent_copies() {
    let backend = Backend::start(|_, _| Reply::bytes(30_000).fresh(60).delayed(300)).await;
    let podgate = serve_cache(
        backend.addr,
        json!({ "max_bytes": 100_000, "max_object_bytes": 40_000 }),
    )
    .await;
    let proxy = podgate.proxy_addr;
    let requests: Vec<_> = (0..20)
        .map(|n| {
            tokio::spawn(async move { send(proxy, "GET", "a.test", &format!("/c{n}"), &[]).await })
        })
        .collect();
    for request in requests {
        assert_eq!(
            request.await.expect("task").body.len(),
            30_000,
            "every client gets its whole response"
        );
    }
    let held = metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}")
        .await
        .expect("series");
    assert!(held <= 100_000, "{held}");
    let peak = metric(&podgate, "podgate_tenant_buffer_bytes_peak{tenant=\"t1\"}")
        .await
        .expect("series");
    assert!(
        peak <= 100_000,
        "copies in progress count against the cap, so the tenant's buffer never passed it: {peak}"
    );
}

#[tokio::test]
async fn cache_default_cap_is_a_quarter_of_the_budget() {
    let backend = Backend::start(|_, _| Reply::bytes(100_000).fresh(60)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    for n in 0..8 {
        get(&podgate, &format!("/q{n}")).await;
    }
    let held = metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}")
        .await
        .expect("series");
    assert!(held <= 262_144, "a quarter of 1 MiB: {held}");
    assert!(held >= 200_000, "and it does use it: {held}");
}

#[tokio::test]
async fn cache_eviction_stays_within_tenant() {
    let one = Backend::start(|_, n| {
        Reply::bytes(30_000)
            .with("Cache-Control", "max-age=60")
            .with("X-Seq", &n.to_string())
    })
    .await;
    let two = Backend::start(|_, n| {
        Reply::bytes(30_000)
            .with("Cache-Control", "max-age=60")
            .with("X-Seq", &n.to_string())
    })
    .await;
    let podgate = Podgate::start().await;
    let config = json!({ "max_bytes": 100_000, "max_object_bytes": 40_000 });
    let apps = [
        cached_app("t1", "a", "a.test", one.addr, config.clone()),
        cached_app("t2", "b", "b.test", two.addr, config),
    ];
    assert_eq!(
        podgate.push_snapshot(&two_tenants(1, &apps)).await.status,
        200
    );
    let proxy = podgate.proxy_addr;
    send(proxy, "GET", "b.test", "/keep", &[]).await;
    let before = metric(&podgate, "podgate_cache_bytes{tenant=\"t2\"}")
        .await
        .expect("series");
    for n in 0..12 {
        send(proxy, "GET", "a.test", &format!("/flood{n}"), &[]).await;
    }
    assert!(
        metric(&podgate, "podgate_cache_evictions_total{tenant=\"t1\"}")
            .await
            .expect("series")
            >= 8,
        "tenant t1 evicted its own entries"
    );
    assert_eq!(
        metric(&podgate, "podgate_cache_evictions_total{tenant=\"t2\"}").await,
        Some(0),
        "t1's flood evicted nothing of t2's"
    );
    assert_eq!(
        metric(&podgate, "podgate_cache_bytes{tenant=\"t2\"}").await,
        Some(before)
    );
    let kept = send(proxy, "GET", "b.test", "/keep", &[]).await;
    assert_eq!(kept.result(), "hit");
    assert_eq!(two.count(), 1);
}

#[tokio::test]
async fn cache_purge_releases_charge() {
    let backend = Backend::start(|_, _| Reply::bytes(20_000).fresh(60)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    for n in 0..3 {
        get(&podgate, &format!("/x{n}")).await;
    }
    assert!(
        metric(&podgate, "podgate_tenant_buffer_bytes{tenant=\"t1\"}")
            .await
            .expect("series")
            > 60_000
    );
    let purged = podgate
        .admin_post("/v1/cache/purge", &json!({ "app": "a", "all": true }))
        .await;
    assert_eq!(
        (purged.status, purged.json()["purged"].clone()),
        (200, json!(3))
    );
    assert_eq!(
        metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}").await,
        Some(0)
    );
    assert_eq!(
        metric(&podgate, "podgate_tenant_buffer_bytes{tenant=\"t1\"}").await,
        Some(0),
        "the bytes are back on the budget"
    );
}

#[tokio::test]
async fn cache_key_includes_app() {
    let one = Backend::start(|_, _| Reply::ok("from one").fresh(3600)).await;
    let two = Backend::start(|_, _| Reply::ok("from two").fresh(3600)).await;
    let podgate = Podgate::start().await;
    let first = [cached_app("t1", "one", "h.test", one.addr, json!({}))];
    assert_eq!(
        podgate.push_snapshot(&two_tenants(1, &first)).await.status,
        200
    );
    let proxy = podgate.proxy_addr;
    assert_eq!(
        send(proxy, "GET", "h.test", "/", &[]).await.text(),
        "from one"
    );
    assert_eq!(send(proxy, "GET", "h.test", "/", &[]).await.result(), "hit");
    // The host moves to another app of the same tenant.
    let second = [cached_app("t1", "two", "h.test", two.addr, json!({}))];
    assert_eq!(
        podgate.push_snapshot(&two_tenants(2, &second)).await.status,
        200
    );
    let moved = send(proxy, "GET", "h.test", "/", &[]).await;
    assert_eq!(
        (moved.text().as_str(), moved.result()),
        ("from two", "miss"),
        "the old app's entry is not the new app's"
    );
    assert_eq!(one.count(), 1);
}

#[tokio::test]
async fn cache_never_crosses_tenants() {
    let one = Backend::start(|_, _| Reply::ok("tenant one").fresh(3600)).await;
    let two = Backend::start(|_, _| Reply::ok("tenant two").fresh(3600)).await;
    let podgate = Podgate::start().await;
    let apps = [
        cached_app("t1", "a", "a.test", one.addr, json!({})),
        cached_app("t2", "b", "b.test", two.addr, json!({})),
    ];
    assert_eq!(
        podgate.push_snapshot(&two_tenants(1, &apps)).await.status,
        200
    );
    let proxy = podgate.proxy_addr;
    for _ in 0..2 {
        assert_eq!(
            send(proxy, "GET", "a.test", "/same", &[]).await.text(),
            "tenant one"
        );
        assert_eq!(
            send(proxy, "GET", "b.test", "/same", &[]).await.text(),
            "tenant two"
        );
    }
    assert_eq!((one.count(), two.count()), (1, 1));
    assert!(
        metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}")
            .await
            .expect("series")
            > 0
    );
    assert!(
        metric(&podgate, "podgate_cache_bytes{tenant=\"t2\"}")
            .await
            .expect("series")
            > 0
    );
}

#[tokio::test]
async fn cache_host_moved_between_tenants_no_stale_entries() {
    let one = Backend::start(|_, _| Reply::ok("old tenant").fresh(3600)).await;
    let two = Backend::start(|_, _| Reply::ok("new tenant").fresh(3600)).await;
    let podgate = Podgate::start().await;
    let first = [cached_app("t1", "a", "h.test", one.addr, json!({}))];
    assert_eq!(
        podgate.push_snapshot(&two_tenants(1, &first)).await.status,
        200
    );
    let proxy = podgate.proxy_addr;
    assert_eq!(
        send(proxy, "GET", "h.test", "/p", &[]).await.text(),
        "old tenant"
    );
    assert_eq!(
        send(proxy, "GET", "h.test", "/p", &[]).await.result(),
        "hit"
    );
    // The same host and path, now another tenant's.
    let second = [cached_app("t2", "a", "h.test", two.addr, json!({}))];
    assert_eq!(
        podgate.push_snapshot(&two_tenants(2, &second)).await.status,
        200
    );
    let moved = send(proxy, "GET", "h.test", "/p", &[]).await;
    assert_eq!(
        (moved.text().as_str(), moved.result()),
        ("new tenant", "miss")
    );
    assert_eq!(
        metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}")
            .await
            .unwrap_or(0),
        0,
        "the old tenant's entries were dropped with the move"
    );
    // And back: nothing of the second stay is served to the first.
    let third = [cached_app("t1", "a", "h.test", one.addr, json!({}))];
    assert_eq!(
        podgate.push_snapshot(&two_tenants(3, &third)).await.status,
        200
    );
    let back = send(proxy, "GET", "h.test", "/p", &[]).await;
    assert_eq!(
        (back.text().as_str(), back.result()),
        ("old tenant", "miss")
    );
    assert_eq!(one.count(), 2);
}

#[tokio::test]
async fn cache_key_includes_revision() {
    let old = Backend::start(|_, _| Reply::ok("release one").fresh(3600)).await;
    let new = Backend::start(|_, _| Reply::ok("release two").fresh(3600)).await;
    for (shared, expected) in [(false, "release two"), (true, "release one")] {
        let podgate = Podgate::start().await;
        let mut first = with_middleware(
            app("a", &["a.test"], &[serving("r1", old.addr)]),
            "c",
            "cache",
            json!({ "share_across_revisions": shared }),
        );
        assert_eq!(
            podgate
                .push_snapshot(&snapshot(1, &[first.clone()]))
                .await
                .status,
            200
        );
        assert_eq!(get(&podgate, "/rev").await.text(), "release one");
        // A rollout: release two serves, release one only keeps its pinned sessions.
        first["revisions"] = json!([
            common::revision("r1", old.addr, 0, "retiring"),
            common::revision("r2", new.addr, 100, "serving"),
        ]);
        assert_eq!(
            podgate.push_snapshot(&snapshot(2, &[first])).await.status,
            200
        );
        let got = get(&podgate, "/rev").await;
        assert_eq!(
            got.text(),
            expected,
            "share_across_revisions={shared}: a rollout never serves one release's page to another"
        );
    }
}

#[tokio::test]
async fn cache_purge_by_url_prefix_tag_all() {
    let backend = Backend::start(|seen, _| {
        let tags = match seen.path.as_str() {
            "/a/1" => "news home",
            "/a/2" => "news",
            _ => "other",
        };
        Reply::ok("page").fresh(3600).with("Cache-Tag", tags)
    })
    .await;
    let podgate = serve_cache(backend.addr, json!({ "tag_header": "Cache-Tag" })).await;
    let first = get(&podgate, "/a/1").await;
    assert_eq!(
        first.header("cache-tag"),
        None,
        "the tags never reach the client"
    );
    get(&podgate, "/a/2").await;
    get(&podgate, "/b/1").await;
    assert_eq!(get(&podgate, "/a/1").await.header("cache-tag"), None);
    let purge = |selector: Value| {
        let podgate = &podgate;
        async move {
            let mut body = json!({ "app": "a" });
            body.as_object_mut()
                .expect("object")
                .extend(selector.as_object().expect("object").clone());
            let response = podgate.admin_post("/v1/cache/purge", &body).await;
            assert_eq!(response.status, 200, "{}", response.body);
            response.json()["purged"].as_u64().expect("count")
        }
    };
    assert_eq!(purge(json!({ "url": "/a/1" })).await, 1);
    assert_eq!(get(&podgate, "/a/1").await.result(), "miss");
    assert_eq!(
        purge(json!({ "url": "http://a.test/a/./2" })).await,
        1,
        "URLs are normalized"
    );
    assert_eq!(
        purge(json!({ "url": "/a/2" })).await,
        0,
        "and a purged one is gone"
    );
    get(&podgate, "/a/2").await;
    assert_eq!(purge(json!({ "prefix": "/a/" })).await, 2);
    assert_eq!(
        get(&podgate, "/b/1").await.result(),
        "hit",
        "the prefix did not reach /b/1"
    );
    get(&podgate, "/a/1").await;
    get(&podgate, "/a/2").await;
    assert_eq!(purge(json!({ "tag": "news" })).await, 2);
    assert_eq!(purge(json!({ "tag": "other" })).await, 1);
    assert_eq!(purge(json!({ "tag": "other" })).await, 0);
    get(&podgate, "/a/1").await;
    get(&podgate, "/b/1").await;
    assert_eq!(purge(json!({ "all": true })).await, 2);
    assert_eq!(get(&podgate, "/a/1").await.result(), "miss");
}

#[tokio::test]
async fn cache_purge_scoped_to_app() {
    let backend = Backend::start(|_, _| Reply::ok("page").fresh(3600)).await;
    let other = Backend::start(|_, _| Reply::ok("other").fresh(3600)).await;
    let podgate = Podgate::start().await;
    let apps = [
        cached_app("t1", "a", "a.test", backend.addr, json!({})),
        cached_app("t1", "b", "b.test", backend.addr, json!({})),
        cached_app("t2", "c", "c.test", other.addr, json!({})),
    ];
    assert_eq!(
        podgate.push_snapshot(&two_tenants(1, &apps)).await.status,
        200
    );
    let proxy = podgate.proxy_addr;
    for host in ["a.test", "b.test", "c.test"] {
        send(proxy, "GET", host, "/p", &[]).await;
    }
    let purged = podgate
        .admin_post("/v1/cache/purge", &json!({ "app": "a", "prefix": "/" }))
        .await;
    assert_eq!(purged.json()["purged"], json!(1));
    assert_eq!(
        send(proxy, "GET", "a.test", "/p", &[]).await.result(),
        "miss"
    );
    assert_eq!(
        send(proxy, "GET", "b.test", "/p", &[]).await.result(),
        "hit",
        "another app of the tenant"
    );
    assert_eq!(
        send(proxy, "GET", "c.test", "/p", &[]).await.result(),
        "hit",
        "another tenant"
    );
    // The same URL under another host of the app is its own entry; `url` with a host is exact.
    let by_host = podgate
        .admin_post(
            "/v1/cache/purge",
            &json!({ "app": "b", "url": "http://elsewhere.test/p" }),
        )
        .await;
    assert_eq!(by_host.json()["purged"], json!(0));
    assert_eq!(
        send(proxy, "GET", "b.test", "/p", &[]).await.result(),
        "hit"
    );
}

#[tokio::test]
async fn cache_purge_unknown_app_404() {
    let backend = Backend::start(|_, _| Reply::ok("page").fresh(3600)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    let unknown = podgate
        .admin_post("/v1/cache/purge", &json!({ "app": "nope", "all": true }))
        .await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.json(), json!({ "error": "not found" }));
    for bad in [
        json!({ "app": "a" }),
        json!({ "app": "a", "all": true, "tag": "x" }),
        json!({ "app": "a", "url": "relative" }),
        json!({ "app": "a", "tag": "" }),
        json!({ "app": "a", "mystery": 1 }),
    ] {
        let response = podgate.admin_post("/v1/cache/purge", &bad).await;
        assert_eq!(response.status, 400, "{bad}: {}", response.body);
    }
}

#[tokio::test]
async fn cache_purge_is_admin_only() {
    let backend = Backend::start(|_, _| Reply::ok("page").fresh(3600)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/p").await;
    // The purge path on the proxy port is just a path of the app: it reaches the app's upstream
    // as any POST, and purges nothing.
    let posted = send(
        podgate.proxy_addr,
        "POST",
        "a.test",
        "/v1/cache/purge",
        &[("Content-Length", "0")],
    )
    .await;
    assert_eq!(posted.result(), "bypass");
    assert_eq!(get(&podgate, "/p").await.result(), "hit");
    let seen = backend.seen();
    assert_eq!(
        seen.iter()
            .filter(|s| s.method == "POST" && s.path == "/v1/cache/purge")
            .count(),
        1
    );
}

#[tokio::test]
async fn cache_client_no_cache_ignored_by_default() {
    let backend = Backend::start(|_, n| Reply::ok(&format!("v{n}")).fresh(60)).await;
    let podgate = serve_cache(backend.addr, json!({})).await;
    get(&podgate, "/c").await;
    for header in [
        ("Cache-Control", "no-cache"),
        ("Cache-Control", "max-age=0"),
        ("Pragma", "no-cache"),
    ] {
        let got = get_with(&podgate, "/c", &[header]).await;
        assert_eq!(
            (got.result(), got.text().as_str()),
            ("hit", "v0"),
            "{header:?}"
        );
    }
    assert_eq!(backend.count(), 1);
}

#[tokio::test]
async fn cache_respects_request_cache_control_when_set() {
    let backend = Backend::start(|_, n| Reply::ok(&format!("v{n}")).fresh(60)).await;
    let podgate = serve_cache(
        backend.addr,
        json!({ "respect_request_cache_control": true }),
    )
    .await;
    get(&podgate, "/c").await;
    let forced = get_with(&podgate, "/c", &[("Cache-Control", "no-cache")]).await;
    assert_eq!((forced.result(), forced.text().as_str()), ("miss", "v1"));
    let after = get(&podgate, "/c").await;
    assert_eq!(
        (after.result(), after.text().as_str()),
        ("hit", "v1"),
        "and it refreshed the entry"
    );
    let no_store = get_with(&podgate, "/c", &[("Cache-Control", "no-store")]).await;
    assert_eq!(no_store.result(), "bypass");
}

#[tokio::test]
async fn cache_max_bytes_over_operator_cap_rejected() {
    let backend = Backend::start(|_, _| Reply::ok("x")).await;
    let podgate = Podgate::start().await;
    let declare = |max: u64| {
        with_middleware(
            app("a", &["a.test"], &[serving("r1", backend.addr)]),
            "c",
            "cache",
            json!({ "max_bytes": max }),
        )
    };
    // 1 MiB budget, default operator share 50 percent: 524288 is the most.
    let over = podgate
        .push_snapshot(&snapshot(1, &[declare(524_289)]))
        .await;
    assert_eq!(over.status, 422, "{}", over.body);
    assert_eq!(
        over.json()["conflicts"][0]["code"],
        "cache_max_bytes_over_cap"
    );
    let at = podgate
        .push_snapshot(&snapshot(1, &[declare(524_288)]))
        .await;
    assert_eq!(at.status, 200, "{}", at.body);
    drop(podgate);

    let podgate = Podgate::start_with_env(&[("CACHE_TENANT_MAX_PERCENT", "10")]).await;
    let over = podgate
        .push_snapshot(&snapshot(1, &[declare(150_000)]))
        .await;
    assert_eq!(over.status, 422, "{}", over.body);
    assert_eq!(
        over.json()["conflicts"][0]["code"],
        "cache_max_bytes_over_cap"
    );
    let at = podgate
        .push_snapshot(&snapshot(1, &[declare(104_857)]))
        .await;
    assert_eq!(at.status, 200, "{}", at.body);
}

#[tokio::test]
async fn cache_invalid_declarations_are_rejected() {
    let backend = Backend::start(|_, _| Reply::ok("x")).await;
    let podgate = Podgate::start().await;
    for (version, config) in [
        (1, json!({ "statuses": [] })),
        (2, json!({ "statuses": [500] })),
        (3, json!({ "statuses": [206] })),
        (
            4,
            json!({ "max_object_bytes": 300_000, "max_bytes": 200_000 }),
        ),
        (5, json!({ "collapse_timeout_ms": 20_000 })),
        (6, json!({ "max_bytes": 0 })),
        (7, json!({ "tag_header": "not a header" })),
        (8, json!({ "unknown_field": true })),
    ] {
        let declared = with_middleware(
            app("a", &["a.test"], &[serving("r1", backend.addr)]),
            "c",
            "cache",
            config.clone(),
        );
        let response = podgate.push_snapshot(&snapshot(version, &[declared])).await;
        assert_eq!(response.status, 422, "{config}: {}", response.body);
    }
}

#[tokio::test]
async fn cache_stores_the_encoded_bytes_compression_produced() {
    let backend = Backend::start(|_, _| Reply::bytes(20_000).fresh(60)).await;
    let podgate = Podgate::start().await;
    let declared = common::with_chain(
        app("a", &["a.test"], &[serving("r1", backend.addr)]),
        &[
            common::middleware("z", "compress", json!({ "algorithms": ["gzip"] })),
            common::middleware("c", "cache", json!({})),
        ],
    );
    assert_eq!(
        podgate
            .push_snapshot(&snapshot(1, &[declared]))
            .await
            .status,
        200
    );
    let gzip = [("Accept-Encoding", "gzip")];
    let first = get_with(&podgate, "/z", &gzip).await;
    assert_eq!(first.header("content-encoding"), Some("gzip"));
    assert_eq!(first.result(), "miss");
    let second = get_with(&podgate, "/z", &gzip).await;
    assert_eq!(second.result(), "hit");
    assert_eq!(second.header("content-encoding"), Some("gzip"));
    assert_eq!(
        second.body, first.body,
        "the stored bytes are the encoded ones, served as they are"
    );
    assert!(second.body.len() < 2_000, "{}", second.body.len());
    assert_eq!(second.header("vary"), Some("accept-encoding"));
    let plain = get(&podgate, "/z").await;
    assert_eq!(
        plain.result(),
        "miss",
        "a client that accepts no coding is another variant"
    );
    assert_eq!(plain.header("content-encoding"), None);
    assert_eq!(plain.body.len(), 20_000);
    assert_eq!(backend.count(), 2);
}

#[tokio::test]
async fn cache_hit_skips_backend_admission() {
    // The tenant may have one request in flight, and a slow one is on its way: a hit is still
    // answered, because it takes no slot.
    let backend = Backend::start(|seen, _| {
        let reply = Reply::ok("page").fresh(60);
        if seen.path == "/slow" {
            reply.delayed(1500)
        } else {
            reply
        }
    })
    .await;
    let podgate = Podgate::start().await;
    let declared = with_middleware(
        app("a", &["a.test"], &[serving("r1", backend.addr)]),
        "c",
        "cache",
        json!({}),
    );
    let mut pushed = snapshot(1, &[declared]);
    pushed["tenants"][0]["budget"]["max_inflight"] = json!(1);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    get(&podgate, "/fast").await;
    let proxy = podgate.proxy_addr;
    let slow = tokio::spawn(async move { send(proxy, "GET", "a.test", "/slow", &[]).await });
    sleep(Duration::from_millis(300)).await;
    let hit = get(&podgate, "/fast").await;
    assert_eq!((hit.status, hit.result()), (200, "hit"));
    let refused = get(&podgate, "/uncached").await;
    assert_eq!(refused.status, 503, "a miss does need the slot");
    assert_eq!(slow.await.expect("slow").status, 200);
}

#[tokio::test]
async fn cache_hit_never_skips_access_control() {
    let backend = Backend::start(|_, _| Reply::ok("secret page").fresh(3600)).await;
    let podgate = Podgate::start().await;
    let guarded = |range: &str| {
        common::with_chain(
            app("a", &["a.test"], &[serving("r1", backend.addr)]),
            &[
                common::middleware("allow", "ip_allow_list", json!({ "source_range": [range] })),
                common::middleware("c", "cache", json!({})),
            ],
        )
    };
    // The client (loopback) is allowed: the entry is filled and served as a hit.
    assert_eq!(
        podgate
            .push_snapshot(&snapshot(1, &[guarded("127.0.0.0/8")]))
            .await
            .status,
        200
    );
    assert_eq!(get(&podgate, "/p").await.result(), "miss");
    assert_eq!(get(&podgate, "/p").await.result(), "hit");
    // The same app, the same cached URL, but the client is no longer in the allow list: the
    // entry is still there, and the stage before the cache still answers first.
    assert_eq!(
        podgate
            .push_snapshot(&snapshot(2, &[guarded("203.0.113.0/24")]))
            .await
            .status,
        200
    );
    let denied = get(&podgate, "/p").await;
    assert_eq!(denied.status, 403, "{denied:?}");
    assert_eq!(denied.header("cache-status"), None);
    assert!(!denied.text().contains("secret"));
    assert_eq!(backend.count(), 1, "nothing reached the upstream either");
    // Access control is checked per request, not per entry: allowed again, the hit is served.
    assert_eq!(
        podgate
            .push_snapshot(&snapshot(3, &[guarded("127.0.0.0/8")]))
            .await
            .status,
        200
    );
    assert_eq!(get(&podgate, "/p").await.result(), "hit");
}

#[tokio::test]
async fn cache_hit_never_skips_an_earlier_request_hook() {
    let backend = Backend::start(|_, _| Reply::ok("page").fresh(3600)).await;
    let podgate = Podgate::start().await;
    let declared = common::with_chain(
        app("a", &["a.test"], &[serving("r1", backend.addr)]),
        &[
            common::middleware("https", "redirect_scheme", json!({ "scheme": "https" })),
            common::middleware("c", "cache", json!({})),
        ],
    );
    assert_eq!(
        podgate
            .push_snapshot(&snapshot(1, &[declared]))
            .await
            .status,
        200
    );
    for _ in 0..2 {
        let got = get(&podgate, "/p").await;
        assert!(matches!(got.status, 301 | 302 | 307 | 308), "{got:?}");
        assert_eq!(
            got.header("cache-status"),
            None,
            "the redirect answered before the cache"
        );
    }
    assert_eq!(backend.count(), 0);
    assert_eq!(
        metric(&podgate, "podgate_cache_bytes{tenant=\"t1\"}")
            .await
            .unwrap_or(0),
        0
    );
}

/// `[headers, cache]` over `upstream`: the stage before the cache must still run on a hit.
fn headers_then_cache(upstream: SocketAddr, headers: Value) -> Value {
    common::with_chain(
        app("a", &["a.test"], &[serving("r1", upstream)]),
        &[
            common::middleware("h", "headers", headers),
            common::middleware("c", "cache", json!({})),
        ],
    )
}

#[tokio::test]
async fn cache_hit_runs_earlier_security_headers() {
    let backend = Backend::start(|_, _| Reply::ok("page").fresh(3600)).await;
    let podgate = Podgate::start().await;
    let cert = common::TestCert::new(&["a.test"]);
    let declared = headers_then_cache(
        backend.addr,
        json!({ "response": { "security": {
            "hsts": { "max_age_secs": 31_536_000 },
            "csp": "default-src 'self'",
            "frame_options": "DENY",
            "content_type_nosniff": true,
        } } }),
    );
    let mut pushed = snapshot(1, &[declared]);
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    // Plain HTTP: no HSTS, everything else on the miss and on the hit.
    for expected in ["miss", "hit"] {
        let got = get(&podgate, "/p").await;
        assert_eq!(got.result(), expected);
        assert_eq!(
            got.header("content-security-policy"),
            Some("default-src 'self'"),
            "{expected}: {got:?}"
        );
        assert_eq!(got.header("x-frame-options"), Some("DENY"), "{expected}");
        assert_eq!(
            got.header("x-content-type-options"),
            Some("nosniff"),
            "{expected}"
        );
        assert_eq!(got.header("strict-transport-security"), None, "{expected}");
    }
    // TLS: HSTS as well, on the miss and on the hit.
    for expected in ["miss", "hit"] {
        let got = podgate.https_get("a.test", "a.test", "/p", &cert).await;
        assert_eq!(
            got.header("cache-status"),
            Some(format!("podgate; {expected}").as_str())
        );
        assert_eq!(
            got.header("strict-transport-security"),
            Some("max-age=31536000"),
            "{expected}: {got:?}"
        );
        assert_eq!(got.header("x-frame-options"), Some("DENY"), "{expected}");
    }
    assert_eq!(
        backend.count(),
        2,
        "one fetch per scheme, the rest are hits"
    );
}

#[tokio::test]
async fn cache_hit_cors_follows_each_origin() {
    let backend = Backend::start(|_, _| Reply::ok("page").fresh(3600)).await;
    let podgate = Podgate::start().await;
    let declared = headers_then_cache(
        backend.addr,
        json!({ "cors": { "allow_origins": ["https://a.example", "https://b.example"] } }),
    );
    assert_eq!(
        podgate
            .push_snapshot(&snapshot(1, &[declared]))
            .await
            .status,
        200
    );
    let fetch = |origin: Option<&'static str>| {
        let podgate = &podgate;
        async move {
            match origin {
                Some(origin) => get_with(podgate, "/p", &[("Origin", origin)]).await,
                None => get(podgate, "/p").await,
            }
        }
    };
    let first = fetch(Some("https://a.example")).await;
    assert_eq!(first.result(), "miss");
    assert_eq!(
        first.header("access-control-allow-origin"),
        Some("https://a.example")
    );
    // Hits: each request gets its own answer, never the one that filled the entry.
    let second = fetch(Some("https://b.example")).await;
    assert_eq!(second.result(), "hit");
    assert_eq!(
        second.header("access-control-allow-origin"),
        Some("https://b.example")
    );
    let again = fetch(Some("https://a.example")).await;
    assert_eq!(
        again.header("access-control-allow-origin"),
        Some("https://a.example")
    );
    for none in [None, Some("https://evil.example")] {
        let got = fetch(none).await;
        assert_eq!(got.result(), "hit");
        assert_eq!(
            got.header("access-control-allow-origin"),
            None,
            "the stored head has no CORS header, so a hit for {none:?} carries none: {got:?}"
        );
        assert!(
            got.header("vary")
                .is_some_and(|vary| vary.to_ascii_lowercase().contains("origin"))
        );
    }
    assert_eq!(backend.count(), 1);
}

#[tokio::test]
async fn cache_chain_order_that_would_skip_a_stage_is_refused() {
    let backend = Backend::start(|_, _| Reply::ok("x")).await;
    let podgate = Podgate::start().await;
    let cors = json!({ "cors": { "allow_origins": ["https://a.example"] } });
    let limit = json!({ "max_response_body_bytes": 1_000_000, "buffer_response": true });
    let chain = |first: Value, second: Value| {
        common::with_chain(
            app("a", &["a.test"], &[serving("r1", backend.addr)]),
            &[first, second],
        )
    };
    let headers = || common::middleware("h", "headers", cors.clone());
    let buffering = || common::middleware("b", "buffering", limit.clone());
    let cache = || common::middleware("c", "cache", json!({}));
    for (version, declared, names) in [
        (1, chain(cache(), headers()), "h"),
        (2, chain(buffering(), cache()), "b"),
    ] {
        let response = podgate.push_snapshot(&snapshot(version, &[declared])).await;
        assert_eq!(response.status, 422, "{}", response.body);
        let rejection = &response.json()["conflicts"][0];
        assert_eq!(rejection["code"], "invalid_middleware", "{rejection}");
        assert!(
            rejection["message"]
                .as_str()
                .is_some_and(|m| m.contains(&format!("middleware {names} "))),
            "names the stage: {rejection}"
        );
    }
    // The other orders compile.
    for (version, declared) in [
        (3, chain(headers(), cache())),
        (4, chain(cache(), buffering())),
    ] {
        let response = podgate.push_snapshot(&snapshot(version, &[declared])).await;
        assert_eq!(response.status, 200, "{}", response.body);
    }
}

/// An app with the upstream `upstream`, an error page service `pages` on `pages`, and the chain
/// `middlewares`.
fn paged_app(upstream: SocketAddr, pages: SocketAddr, middlewares: &[Value]) -> Value {
    let mut declared = common::with_chain(
        app("a", &["a.test"], &[serving("r1", upstream)]),
        middlewares,
    );
    declared["services"] = json!([common::service("pages", &[pages])]);
    declared
}

fn errors_stage() -> Value {
    common::middleware(
        "e",
        "errors",
        json!({ "status": ["404"], "service": "pages" }),
    )
}

fn cache_stage() -> Value {
    common::middleware("c", "cache", json!({}))
}

#[tokio::test]
async fn cache_hit_runs_earlier_error_page() {
    let backend = Backend::start(|seen, _| match seen.path.as_str() {
        "/gone" => Reply::ok("nope").status(404).fresh(3600),
        _ => Reply::ok("fine").fresh(3600),
    })
    .await;
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let down = Arc::clone(&failing);
    let pages = Backend::start(move |_, _| {
        if down.load(Ordering::SeqCst) {
            Reply::ok("down").status(500)
        } else {
            Reply::ok("<h1>page</h1>").with("Content-Type", "text/html")
        }
    })
    .await;
    // Either order of the two stages: the page is the answer, on a miss and where an entry could
    // be served.
    for (round, chain) in [
        [errors_stage(), cache_stage()],
        [cache_stage(), errors_stage()],
    ]
    .into_iter()
    .enumerate()
    {
        let podgate = Podgate::start().await;
        let first = round as u64 * 10;
        // The app caches without an error page: a 404 is stored and served as a hit.
        let plain = paged_app(backend.addr, pages.addr, &[cache_stage()]);
        assert_eq!(
            podgate
                .push_snapshot(&snapshot(first + 1, &[plain]))
                .await
                .status,
            200
        );
        let before = backend.count_path("/gone");
        assert_eq!(get(&podgate, "/gone").await.text(), "nope");
        assert_eq!(get(&podgate, "/gone").await.result(), "hit");
        // The error page is configured: the stored 404 is not served, the page is.
        let paged = paged_app(backend.addr, pages.addr, &chain);
        assert_eq!(
            podgate
                .push_snapshot(&snapshot(first + 2, &[paged]))
                .await
                .status,
            200
        );
        for _ in 0..2 {
            let got = get(&podgate, "/gone").await;
            assert_eq!(
                (got.status, got.text().as_str()),
                (404, "<h1>page</h1>"),
                "round {round}"
            );
            assert_ne!(got.result(), "hit", "the page is never a cache hit");
        }
        assert_eq!(
            backend.count_path("/gone") - before,
            3,
            "the 404 was fetched each time, never stored again"
        );
        // A page that cannot be fetched leaves the 404 standing, and it is not stored either:
        // when the page server is back, the next request gets the page.
        failing.store(true, Ordering::SeqCst);
        let raw = get(&podgate, "/gone").await;
        assert_eq!(
            (raw.status, raw.text().as_str()),
            (404, "nope"),
            "round {round}"
        );
        failing.store(false, Ordering::SeqCst);
        assert_eq!(
            get(&podgate, "/gone").await.text(),
            "<h1>page</h1>",
            "round {round}"
        );
        // Statuses the stage does not page are cached as usual.
        assert_eq!(get(&podgate, "/ok").await.result(), "miss");
        assert_eq!(get(&podgate, "/ok").await.result(), "hit");
        // A HEAD is never paged: it is answered with what the upstream sent.
        let head = send(podgate.proxy_addr, "HEAD", "a.test", "/gone", &[]).await;
        assert_eq!(head.status, 404, "round {round}");
    }
}
