//! The read-only dashboard on `DASHBOARD_ADDR`, through the real binary: what it
//! serves, what it refuses, who may reach it, and that its two APIs answer exactly what the
//! admin endpoints answer.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use common::{Podgate, Upstream, app, router, serving, snapshot};
use podgate::Config;
use podgate::dashboard::{ASSETS, CONTENT_SECURITY_POLICY_VALUE};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

/// The `Content-Security-Policy` the spec asks for, written out so a change to the constant
/// fails here.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// What the dashboard answered.
#[derive(Debug)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("not JSON ({err}): {}", self.text()))
    }
}

async fn raw(addr: SocketAddr, request: &str) -> Option<Reply> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    // The server may answer and close before it has read a body it refuses, so a failed write
    // is not a failed exchange.
    drop(stream.write_all(request.as_bytes()).await);
    let mut bytes = Vec::new();
    let mut chunk = vec![0_u8; 4096];
    loop {
        match timeout(Duration::from_secs(10), stream.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) => break,
            Ok(Ok(read)) => bytes.extend_from_slice(&chunk[..read]),
            Err(_) => return None,
        }
    }
    let split = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&bytes[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    Some(Reply {
        status,
        headers,
        body: bytes[split + 4..].to_vec(),
    })
}

/// One request with `Connection: close`. `extra` are more header lines, each ending in CRLF.
fn request(method: &str, target: &str, host: &str, extra: &str, body: &str) -> String {
    format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn get(addr: SocketAddr, target: &str) -> Reply {
    send(addr, "GET", target, "").await
}

async fn send(addr: SocketAddr, method: &str, target: &str, body: &str) -> Reply {
    let host = addr.to_string();
    raw(addr, &request(method, target, &host, "", body))
        .await
        .unwrap_or_else(|| panic!("no answer to {method} {target}"))
}

async fn post_json(addr: SocketAddr, target: &str, body: &str) -> Reply {
    let host = addr.to_string();
    raw(
        addr,
        &request(
            "POST",
            target,
            &host,
            "Content-Type: application/json\r\n",
            body,
        ),
    )
    .await
    .expect("answer")
}

fn free_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], common::free_ports(1)[0]))
}

async fn reachable(addr: SocketAddr) {
    for _ in 0..100 {
        if raw(addr, &request("GET", "/", &addr.to_string(), "", ""))
            .await
            .is_some()
        {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing listens on {addr}");
}

async fn start(extra: &[(&str, &str)]) -> (Podgate, SocketAddr) {
    let addr = free_addr();
    let address = addr.to_string();
    let mut env = vec![("DASHBOARD_ADDR", address.as_str())];
    env.extend_from_slice(extra);
    let podgate = Podgate::start_with_env(&env).await;
    reachable(addr).await;
    (podgate, addr)
}

/// A dashboard that asks for `alice:s3cret`, with its htpasswd file in a temp dir that lives as
/// long as the returned path's parent.
fn htpasswd() -> (PathBuf, String) {
    let dir = std::env::temp_dir().join(format!(
        "podgate-dashboard-{}-{}",
        std::process::id(),
        common::free_ports(1)[0]
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("htpasswd");
    let hash = bcrypt::hash("s3cret", 4).expect("hash");
    std::fs::write(&path, format!("# the operators\nalice:{hash}\n")).expect("write htpasswd");
    (path.clone(), path.to_string_lossy().into_owned())
}

fn basic(user: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Authorization: Basic {}\r\n",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

async fn with_snapshot(podgate: &Podgate) -> Upstream {
    let backend = Upstream::start("hello").await;
    let mut a = app("a", &["a.test"], &[serving("r1", backend.addr)]);
    a["routers"] = json!([
        {
            "name": "api",
            "match": { "all": [{ "host": "a.test" }, { "path_prefix": "/api" }] },
            "priority": 10,
            "service": "web"
        },
        router("default", json!({ "host": ["a.test", "*.wild.test"] }), "web"),
    ]);
    let pushed = podgate
        .push_snapshot(&snapshot(
            7,
            &[a, app("b", &["b.test"], &[serving("r1", backend.addr)])],
        ))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    backend
}

#[tokio::test]
async fn dashboard_off_by_default() {
    assert_eq!(
        Config::from_lookup(|_| None)
            .expect("config")
            .dashboard_addr,
        None
    );
    let podgate = Podgate::start_logged(&[("RUST_LOG", "info")]).await;
    let log = podgate.log();
    assert!(
        log.contains("admin API ready") && !log.contains("dashboard"),
        "no dashboard without DASHBOARD_ADDR: {log}"
    );
}

#[tokio::test]
async fn dashboard_serves_assets_and_apis() {
    let (podgate, addr) = start(&[]).await;
    let _backend = with_snapshot(&podgate).await;

    for asset in ASSETS {
        let path = asset.path;
        let reply = get(addr, path).await;
        assert_eq!(reply.status, 200, "{path}");
        assert_eq!(
            reply.header("content-type"),
            Some(asset.content_type),
            "{path}"
        );
        assert_eq!(reply.body, asset.bytes, "{path}");
    }

    let overview = get(addr, "/api/overview").await;
    assert_eq!(overview.status, 200);
    assert_eq!(overview.header("content-type"), Some("application/json"));
    let document = overview.json();
    assert_eq!(document["summary"]["version"], 7);
    assert_eq!(document["apps"]["total"], 2);

    let explain = get(addr, "/api/explain?url=http%3A%2F%2Fa.test%2Fapi%2Fx").await;
    assert_eq!(explain.status, 200, "{}", explain.text());
    assert_eq!(explain.json()["app"], "a");
    let posted = post_json(addr, "/api/explain", r#"{"url": "http://a.test/api/x"}"#).await;
    assert_eq!(posted.status, 200, "{}", posted.text());
    assert_eq!(posted.json(), explain.json());
}

#[tokio::test]
async fn dashboard_never_serves_events() {
    let (podgate, addr) = start(&[]).await;
    let _backend = with_snapshot(&podgate).await;
    for path in [
        "/v1/events",
        "/v1/events?after=0&timeout_secs=1",
        "/v1/snapshot",
        "/v1/snapshot/version",
        "/v1/snapshot/plan",
        "/v1/snapshot/validate",
        "/v1/overview",
        "/v1/explain?url=http%3A%2F%2Fa.test%2F",
        "/v1/apps/a/failures",
        "/v1/apps/a/failures/1/replay",
        "/v1/cache/purge",
        "/v1/schema",
        "/metrics",
        "/healthz",
        "/readyz",
        "/api/events",
        "/api/snapshot",
        "/api/failures",
        "/api/plan",
    ] {
        for method in ["GET", "POST", "PUT"] {
            let reply = send(addr, method, path, "").await;
            assert_eq!(reply.status, 404, "{method} {path}: {}", reply.text());
            assert_eq!(
                reply.json(),
                json!({ "error": "not found" }),
                "{method} {path}"
            );
        }
    }
}

#[tokio::test]
async fn dashboard_only_read_routes() {
    let (podgate, addr) = start(&[]).await;
    let _backend = with_snapshot(&podgate).await;
    for path in [
        "/",
        "/app.js",
        "/style.css",
        "/favicon.svg",
        "/api/overview",
        "/api/overview?section=summary",
        "/api/explain?url=http%3A%2F%2Fa.test%2F",
    ] {
        assert_eq!(get(addr, path).await.status, 200, "GET {path}");
    }
    for path in [
        "/index.html",
        "/api",
        "/api/",
        "/api/overview/",
        "/api/explain/",
        "/app.js/",
        "/dashboard/app.js",
        "/%2e%2e/Cargo.toml",
        "/../Cargo.toml",
        "/a.test",
        "//",
    ] {
        assert_eq!(get(addr, path).await.status, 404, "GET {path}");
    }
}

#[tokio::test]
async fn dashboard_rejects_non_get() {
    let (podgate, addr) = start(&[]).await;
    let _backend = with_snapshot(&podgate).await;
    for path in [
        "/",
        "/app.js",
        "/style.css",
        "/favicon.svg",
        "/api/overview",
    ] {
        for method in ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let reply = send(addr, method, path, "").await;
            assert_eq!(reply.status, 405, "{method} {path}");
            assert_eq!(reply.header("allow"), Some("GET"), "{method} {path}");
        }
    }
    for method in ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
        let reply = send(addr, method, "/api/explain", "").await;
        assert_eq!(reply.status, 405, "{method} /api/explain");
        assert_eq!(reply.header("allow"), Some("GET, POST"));
    }
    // The one POST reads: it explains and changes nothing.
    let before = get(addr, "/api/overview").await.json();
    let posted = post_json(addr, "/api/explain", r#"{"url": "http://a.test/"}"#).await;
    assert_eq!(posted.status, 200);
    assert_eq!(get(addr, "/api/overview").await.json(), before);
    assert_eq!(
        podgate.admin_get("/v1/snapshot/version").await.json()["version"],
        7
    );
}

#[tokio::test]
async fn dashboard_non_loopback_requires_auth() {
    // The settings alone refuse it, whichever way they are built.
    let lookup = |auth: bool| {
        move |name: &str| match name {
            "DASHBOARD_ADDR" => Some("0.0.0.0:9200".to_owned()),
            "DASHBOARD_AUTH_FILE" if auth => Some("/etc/podgate/dashboard.htpasswd".to_owned()),
            _ => None,
        }
    };
    let refused = Config::from_lookup(lookup(false)).expect_err("needs auth");
    let message = refused.to_string();
    assert!(
        message.contains("DASHBOARD_ADDR") && message.contains("DASHBOARD_AUTH_FILE"),
        "{message}"
    );
    assert!(Config::from_lookup(lookup(true)).is_ok());
    let built = Config {
        dashboard_addr: Some(SocketAddr::from(([10, 0, 0, 5], 9200))),
        ..Config::default()
    };
    let refused = built.dashboard_auth().expect_err("needs auth");
    assert!(
        refused.to_string().contains("DASHBOARD_AUTH_FILE"),
        "{refused}"
    );
    for addr in ["127.0.0.1:9200", "[::1]:9200", "127.9.9.9:80"] {
        let loopback =
            Config::from_lookup(|name| (name == "DASHBOARD_ADDR").then(|| addr.to_owned()));
        assert!(
            loopback
                .expect("loopback needs no file")
                .dashboard_auth()
                .is_ok(),
            "{addr}"
        );
    }
    let orphan = Config::from_lookup(|name| {
        (name == "DASHBOARD_AUTH_FILE").then(|| "/etc/podgate/dashboard.htpasswd".to_owned())
    })
    .expect_err("a password file without a dashboard");
    assert_eq!(orphan.var, "DASHBOARD_AUTH_FILE");

    // And so does the binary, before it serves anything.
    let dir = std::env::temp_dir().join(format!("podgate-dashboard-start-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let run = |env: &[(&str, String)]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_podgate"));
        command
            .env(
                "PROXY_ADDR",
                format!("127.0.0.1:{}", common::free_ports(1)[0]),
            )
            .env("ADMIN_SOCKET", dir.join("admin.sock"))
            .env("RUST_LOG", "warn")
            .stdin(std::process::Stdio::null());
        for (name, value) in env {
            command.env(name, value);
        }
        let output = command.output().expect("run podgate");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let (ok, stderr) = run(&[("DASHBOARD_ADDR", "0.0.0.0:9200".into())]);
    assert!(!ok, "started without credentials");
    assert!(
        stderr.contains("DASHBOARD_ADDR") && stderr.contains("DASHBOARD_AUTH_FILE"),
        "{stderr}"
    );
    let (_, file) = htpasswd();
    let weak = dir.join("weak");
    std::fs::write(&weak, "alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n").expect("write");
    let (ok, stderr) = run(&[
        ("DASHBOARD_ADDR", "127.0.0.1:9200".into()),
        ("DASHBOARD_AUTH_FILE", weak.to_string_lossy().into_owned()),
    ]);
    assert!(!ok, "started with a weak hash");
    assert!(
        stderr.contains("DASHBOARD_AUTH_FILE") && !stderr.contains("W6ph5Mm5Pz8G"),
        "{stderr}"
    );
    let (ok, stderr) = run(&[
        ("DASHBOARD_ADDR", "127.0.0.1:9200".into()),
        (
            "DASHBOARD_AUTH_FILE",
            dir.join("missing").to_string_lossy().into_owned(),
        ),
    ]);
    assert!(!ok && stderr.contains("DASHBOARD_AUTH_FILE"), "{stderr}");
    drop(std::fs::remove_dir_all(&dir));

    // With a file it serves, over a wildcard address, and warns that it is plain HTTP.
    let addr = free_addr();
    let wildcard = format!("0.0.0.0:{}", addr.port());
    let podgate = Podgate::start_logged(&[
        ("DASHBOARD_ADDR", wildcard.as_str()),
        ("DASHBOARD_AUTH_FILE", file.as_str()),
    ])
    .await;
    reachable(addr).await;
    let denied = get(addr, "/").await;
    assert_eq!(denied.status, 401);
    let log = podgate.log();
    assert!(log.contains("plain HTTP") && log.contains("Basic"), "{log}");
}

#[tokio::test]
async fn dashboard_basic_auth_and_throttle() {
    let (_, file) = htpasswd();
    let (podgate, addr) = start(&[("DASHBOARD_AUTH_FILE", file.as_str())]).await;
    let _backend = with_snapshot(&podgate).await;
    let host = addr.to_string();
    let call = |path: &'static str, extra: String| {
        let host = host.clone();
        async move {
            raw(addr, &request("GET", path, &host, &extra, ""))
                .await
                .expect("answer")
        }
    };

    for path in [
        "/",
        "/app.js",
        "/api/overview",
        "/api/explain?url=http%3A%2F%2Fa.test%2F",
        "/nothing",
    ] {
        let reply = call(path, String::new()).await;
        assert_eq!(
            reply.status, 401,
            "{path}: nothing is routed before the credentials"
        );
        assert_eq!(
            reply.header("www-authenticate"),
            Some("Basic realm=\"podgate dashboard\", charset=\"UTF-8\"")
        );
        assert_eq!(reply.json(), json!({ "error": "unauthorized" }));
    }
    let good = call("/api/overview", basic("alice", "s3cret")).await;
    assert_eq!(good.status, 200, "{}", good.text());
    assert_eq!(good.json()["summary"]["version"], 7);
    assert_eq!(call("/", basic("alice", "s3cret")).await.status, 200);
    assert_eq!(call("/nothing", basic("alice", "s3cret")).await.status, 404);
    for bad in [
        basic("alice", "wrong"),
        basic("mallory", "s3cret"),
        "Authorization: Bearer abc\r\n".to_owned(),
        "Authorization: Basic !!!\r\n".to_owned(),
        format!("{}{}", basic("alice", "s3cret"), basic("alice", "s3cret")),
    ] {
        assert_eq!(call("/", bad.clone()).await.status, 401, "{bad:?}");
    }

    // A source that fails five times in a minute waits for each further attempt. The attempts
    // above already count; the wait is paid before the verdict, right or wrong.
    for _ in 0..6 {
        call("/", basic("alice", "wrong")).await;
    }
    let started = Instant::now();
    let delayed = call("/", basic("alice", "wrong")).await;
    assert_eq!(delayed.status, 401);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "a throttled attempt took {:?}",
        started.elapsed()
    );
    // A credential that was verified and cached is not charged the wait, and nothing ever
    // reveals the hash.
    let again = call("/api/overview", basic("alice", "s3cret")).await;
    assert_eq!(again.status, 200);
    assert!(!again.text().contains("$2b$"));
}

#[tokio::test]
async fn dashboard_security_headers() {
    assert_eq!(CONTENT_SECURITY_POLICY_VALUE, CSP);
    let (_, file) = htpasswd();
    let (podgate, addr) = start(&[("DASHBOARD_AUTH_FILE", file.as_str())]).await;
    let _backend = with_snapshot(&podgate).await;
    let host = addr.to_string();
    let credentials = basic("alice", "s3cret");
    let call = |method: &'static str, path: &'static str, host: String, extra: String| async move {
        raw(addr, &request(method, path, &host, &extra, ""))
            .await
            .expect("answer")
    };
    for (what, reply) in [
        (
            "/",
            call("GET", "/", host.clone(), credentials.clone()).await,
        ),
        (
            "/app.js",
            call("GET", "/app.js", host.clone(), credentials.clone()).await,
        ),
        (
            "/style.css",
            call("GET", "/style.css", host.clone(), credentials.clone()).await,
        ),
        (
            "/api/overview",
            call("GET", "/api/overview", host.clone(), credentials.clone()).await,
        ),
        (
            "404",
            call("GET", "/nope", host.clone(), credentials.clone()).await,
        ),
        (
            "405",
            call("POST", "/", host.clone(), credentials.clone()).await,
        ),
        ("401", call("GET", "/", host.clone(), String::new()).await),
        (
            "421",
            call("GET", "/", "evil.test".into(), credentials.clone()).await,
        ),
    ] {
        assert_eq!(reply.header("content-security-policy"), Some(CSP), "{what}");
        assert_eq!(
            reply.header("x-content-type-options"),
            Some("nosniff"),
            "{what}"
        );
        assert_eq!(
            reply.header("referrer-policy"),
            Some("no-referrer"),
            "{what}"
        );
        assert_eq!(
            reply.header("set-cookie"),
            None,
            "{what}: the dashboard sets no cookie"
        );
        if what != "/" && what != "/app.js" && what != "/style.css" {
            assert_eq!(reply.header("cache-control"), Some("no-store"), "{what}");
        }
    }
}

#[tokio::test]
async fn dashboard_host_check() {
    let (_podgate, addr) = start(&[("DASHBOARD_HOSTS", "dash.example")]).await;
    let status = |host: &str| {
        let request = request("GET", "/api/overview?section=summary", host, "", "");
        let host = host.to_owned();
        async move {
            raw(addr, &request)
                .await
                .unwrap_or_else(|| panic!("no answer for Host {host:?}"))
                .status
        }
    };
    let port = addr.port();
    for ok in [
        format!("127.0.0.1:{port}"),
        "127.0.0.1".to_owned(),
        format!("localhost:{port}"),
        "LOCALHOST".to_owned(),
        "dash.example".to_owned(),
        format!("Dash.Example:{port}"),
    ] {
        assert_eq!(status(&ok).await, 200, "{ok}");
    }
    for refused in [
        "evil.test".to_owned(),
        format!("evil.test:{port}"),
        "127.0.0.1.evil.test".to_owned(),
        "127.0.0.2".to_owned(),
        "[::1]".to_owned(),
        "localhost.evil.test".to_owned(),
        "u@127.0.0.1".to_owned(),
        "dash.example.evil.test".to_owned(),
    ] {
        assert_eq!(status(&refused).await, 421, "{refused}");
    }
    let reply = raw(addr, &request("GET", "/", "evil.test", "", ""))
        .await
        .expect("answer");
    assert_eq!(reply.json(), json!({ "error": "misdirected request" }));
    // HTTP/1.0 without a Host names nobody, so it is refused too.
    let bare = raw(addr, "GET / HTTP/1.0\r\n\r\n").await.expect("answer");
    assert_eq!(bare.status, 421);
    // The check comes before the credentials: no hashing for a wrong host.
    let (_, file) = htpasswd();
    let (_guarded_podgate, guarded) = start(&[("DASHBOARD_AUTH_FILE", file.as_str())]).await;
    let refused = raw(guarded, &request("GET", "/", "evil.test", "", ""))
        .await
        .expect("answer");
    assert_eq!(refused.status, 421);
    // Without DASHBOARD_HOSTS only the address and localhost pass.
    let (_plain_podgate, plain) = start(&[]).await;
    let refused = raw(plain, &request("GET", "/", "dash.example", "", ""))
        .await
        .expect("answer");
    assert_eq!(refused.status, 421);
}

/// The tags of `html` as `(name, attributes)`, enough of a tokenizer for files we write
/// ourselves: it skips comments and reads quoted and bare attribute values.
fn tags(html: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut found = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        if let Some(comment) = rest.strip_prefix("!--") {
            rest = comment.split_once("-->").map_or("", |(_, after)| after);
            continue;
        }
        let Some(end) = rest.find('>') else { break };
        let inside = &rest[..end];
        rest = &rest[end + 1..];
        if inside.starts_with('!') || inside.starts_with('/') {
            continue;
        }
        let mut words = inside.trim_end_matches('/').trim().chars().peekable();
        let mut name = String::new();
        while let Some(c) = words.next_if(|c| !c.is_whitespace()) {
            name.push(c);
        }
        let mut attributes = Vec::new();
        loop {
            while words.next_if(|c| c.is_whitespace()).is_some() {}
            let mut key = String::new();
            while let Some(c) = words.next_if(|c| !c.is_whitespace() && *c != '=') {
                key.push(c);
            }
            if key.is_empty() {
                break;
            }
            let mut value = String::new();
            if words.next_if_eq(&'=').is_some() {
                match words.peek().copied() {
                    Some(quote @ ('"' | '\'')) => {
                        words.next();
                        while let Some(c) = words.next_if(|c| *c != quote) {
                            value.push(c);
                        }
                        words.next();
                    }
                    _ => {
                        while let Some(c) = words.next_if(|c| !c.is_whitespace()) {
                            value.push(c);
                        }
                    }
                }
            }
            attributes.push((key.to_ascii_lowercase(), value));
        }
        found.push((name.to_ascii_lowercase(), attributes));
    }
    found
}

fn embedded(file: &str) -> String {
    let asset = ASSETS
        .iter()
        .find(|asset| asset.file == file)
        .expect("asset");
    String::from_utf8(asset.bytes.to_vec()).expect("utf-8")
}

#[test]
fn dashboard_no_inline_script() {
    let html = embedded("index.html");
    let found = tags(&html);
    assert!(
        found.iter().any(|(name, _)| name == "script"),
        "the page has a script"
    );
    for (name, attributes) in &found {
        if name == "script" {
            assert!(
                attributes
                    .iter()
                    .any(|(key, value)| key == "src" && value.starts_with('/')),
                "an inline <script>: {attributes:?}"
            );
        }
        assert_ne!(name, "style", "an inline <style>");
        for (key, value) in attributes {
            assert!(
                !key.starts_with("on"),
                "event handler attribute {key} on <{name}>"
            );
            assert_ne!(key, "style", "style attribute on <{name}>");
            assert!(
                !value
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("javascript:"),
                "javascript: URL on <{name}>"
            );
        }
    }
    // The tokenizer sees what it should: it finds the inline script a bad page would carry.
    let bad = tags(r#"<p onclick="x()" style="a:b"><script>alert(1)</script><script src="/a.js">"#);
    assert_eq!(bad.len(), 3);
    assert!(bad[0].1.iter().any(|(key, _)| key == "onclick"));
    assert!(bad[1].1.is_empty() && bad[2].1[0].0 == "src");

    let script = embedded("app.js");
    for banned in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "setAttribute(\"style\"",
        "cssText",
        "srcdoc",
        "createContextualFragment",
        "DOMParser",
    ] {
        assert!(!script.contains(banned), "app.js uses {banned}");
    }
    let css = embedded("style.css");
    assert!(
        !css.contains("@import") && !css.contains("url("),
        "style.css loads nothing"
    );
}

#[test]
fn dashboard_no_external_references() {
    for asset in ASSETS {
        let text = embedded(asset.file);
        // The SVG namespace is an identifier, not a request.
        let text = text.replace("http://www.w3.org/2000/svg", "");
        for banned in [
            "http://", "https://", "ws://", "wss://", "@import", "//cdn", "<iframe", "<object",
            "<embed",
        ] {
            assert!(!text.contains(banned), "{} contains {banned}", asset.file);
        }
    }
    for (name, attributes) in tags(&embedded("index.html")) {
        for (key, value) in attributes {
            if matches!(key.as_str(), "src" | "href" | "action" | "data" | "poster") {
                let local_page = value.starts_with('#');
                assert!(
                    local_page || (value.starts_with('/') && !value.starts_with("//")),
                    "<{name} {key}={value:?}> leaves the origin"
                );
            }
        }
    }
    let script = embedded("app.js");
    for line in script
        .lines()
        .filter(|line| line.contains("fetch(") || line.contains("getJson("))
    {
        for quoted in line.split(['"', '`']).skip(1).step_by(2) {
            if quoted.contains('/') {
                assert!(quoted.starts_with("/api/"), "app.js reaches {quoted:?}");
            }
        }
    }
}

#[test]
fn dashboard_assets_embedded_match_files() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("dashboard");
    let mut on_disk: Vec<String> = std::fs::read_dir(&root)
        .expect("dashboard/")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    on_disk.sort();
    let mut embedded_names: Vec<&str> = ASSETS.iter().map(|asset| asset.file).collect();
    embedded_names.sort_unstable();
    assert_eq!(
        on_disk, embedded_names,
        "every file of dashboard/ is embedded, and only those"
    );
    for asset in ASSETS {
        let file = std::fs::read(root.join(asset.file)).expect("read the asset file");
        assert_eq!(
            file, asset.bytes,
            "{} differs from the embedded copy",
            asset.file
        );
        assert!(!file.is_empty(), "{}", asset.file);
    }
}

#[tokio::test]
async fn dashboard_overview_equals_admin() {
    let (podgate, addr) = start(&[]).await;
    let _backend = with_snapshot(&podgate).await;
    for query in [
        "",
        "?section=summary",
        "?section=apps&limit=1",
        "?section=apps&limit=1&after=a",
        "?tenant=t1",
        "?tenant=nobody",
        "?app=b&section=apps",
        "?section=certificates,tenants,entry_points",
        "?limit=0",
        "?section=events",
        "?limit=many",
    ] {
        let admin = podgate.admin_get(&format!("/v1/overview{query}")).await;
        let dashboard = get(addr, &format!("/api/overview{query}")).await;
        assert_eq!(dashboard.status, admin.status, "{query}");
        assert_eq!(dashboard.text(), admin.body, "{query}");
    }
}

/// An explain question: URL, method, entry point and client address.
type Case<'a> = (&'a str, Option<&'a str>, Option<&'a str>, Option<&'a str>);

#[tokio::test]
async fn dashboard_explain_equals_admin() {
    let (podgate, addr) = start(&[]).await;
    let _backend = with_snapshot(&podgate).await;
    let cases: [Case; 9] = [
        ("http://a.test/api/x?q=1", None, None, None),
        ("http://a.test/other", Some("POST"), None, None),
        ("https://a.test/", None, None, None),
        ("http://x.wild.test/", None, None, None),
        ("http://nobody.test/", None, None, None),
        ("http://a.test/", None, Some("nope"), None),
        ("http://a.test/", None, None, Some("10.0.0.1")),
        ("not a url", None, None, None),
        ("http://a.test/", Some("bad method"), None, None),
    ];
    for (url, method, entry_point, client_ip) in cases {
        let mut pairs = vec![("url", url)];
        pairs.extend(method.map(|m| ("method", m)));
        pairs.extend(entry_point.map(|e| ("entry_point", e)));
        pairs.extend(client_ip.map(|c| ("client_ip", c)));
        let query: Vec<String> = pairs
            .iter()
            .map(|(key, value)| {
                format!(
                    "{key}={}",
                    form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
                )
            })
            .collect();
        let query = query.join("&");
        let admin = podgate.admin_get(&format!("/v1/explain?{query}")).await;
        let by_query = get(addr, &format!("/api/explain?{query}")).await;
        assert_eq!(by_query.status, admin.status, "{url}");
        assert_eq!(by_query.text(), admin.body, "{url}");
        let body: serde_json::Map<String, Value> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), json!(value)))
            .collect();
        let by_body = post_json(addr, "/api/explain", &Value::Object(body).to_string()).await;
        assert_eq!(by_body.status, admin.status, "{url}");
        assert_eq!(by_body.text(), admin.body, "{url}");
    }

    // The body is bounded, JSON only, and takes the admin parameters and nothing else.
    let fields = |body: &str| {
        let body = body.to_owned();
        async move { post_json(addr, "/api/explain", &body).await }
    };
    assert_eq!(
        fields(r#"{"url": "http://a.test/", "headers": {"x": "y"}}"#)
            .await
            .status,
        400
    );
    assert_eq!(fields(r#"{"method": "GET"}"#).await.status, 400);
    assert_eq!(fields("[1, 2]").await.status, 400);
    assert_eq!(fields("{").await.status, 400);
    assert_eq!(fields("").await.status, 400);
    let large = format!(r#"{{"url": "http://a.test/{}"}}"#, "a".repeat(17 * 1024));
    let refused = fields(&large).await;
    assert_eq!(refused.status, 413, "{}", refused.text());
    assert_eq!(refused.json(), json!({ "error": "request body too large" }));
    let just_fits = format!(r#"{{"url": "http://a.test/{}"}}"#, "a".repeat(15 * 1024));
    assert_eq!(fields(&just_fits).await.status, 200);
}

#[tokio::test]
async fn dashboard_explain_requires_json_content_type() {
    let (podgate, addr) = start(&[]).await;
    let _backend = with_snapshot(&podgate).await;
    let host = addr.to_string();
    let body = r#"{"url": "http://a.test/"}"#;
    let post = |extra: String| {
        let request = request("POST", "/api/explain", &host, &extra, body);
        async move { raw(addr, &request).await.expect("answer") }
    };
    // What a page on another site can send without a preflight, and near misses.
    for content_type in [
        "text/plain",
        "text/plain;charset=UTF-8",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
        "application/jsonx",
        "application/json-seq",
        "application/vnd.api+json",
        "text/json",
        "json",
        "",
    ] {
        let reply = post(format!("Content-Type: {content_type}\r\n")).await;
        assert_eq!(reply.status, 415, "{content_type:?}");
        assert_eq!(
            reply.json(),
            json!({ "error": "content-type must be application/json" }),
            "{content_type:?}"
        );
    }
    let none = post(String::new()).await;
    assert_eq!(none.status, 415, "no Content-Type");
    let twice =
        post("Content-Type: application/json\r\nContent-Type: text/plain\r\n".to_owned()).await;
    assert_eq!(twice.status, 415, "two Content-Type headers");
    for content_type in [
        "application/json",
        "application/json; charset=utf-8",
        "application/json;charset=utf-8",
        "Application/JSON",
    ] {
        let reply = post(format!("Content-Type: {content_type}\r\n")).await;
        assert_eq!(reply.status, 200, "{content_type:?}: {}", reply.text());
    }
}
