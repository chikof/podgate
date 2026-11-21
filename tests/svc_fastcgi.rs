//! End to end: the `fastcgi` service on the real binary. The upstreams and code roots come from
//! the operator's `FASTCGI_FILE`; the application is a test FastCGI server (`common::fcgi`) that
//! records what it receives, except in `fastcgi_real_php_fpm_smoke`, which runs a real `php-fpm`.

mod common;

use std::net::SocketAddr;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::fcgi::{Fcgi, Reply, Request};
use common::{Podgate, app};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const SECRET: &str = "TOPSECRET";

fn temp_base(name: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let base = std::env::temp_dir().join(format!(
        "podgate-fcgi-{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&base).expect("create the temp tree");
    base
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("create parents");
    std::fs::write(path, content).expect("write a file");
}

/// `<base>/root` is the code root of tenant `t1`, `<base>/theirs` the root of tenant `t2`;
/// `<base>/secret.php` and `<base>/outside` are beside the root and must never run.
fn populate(base: &Path) {
    let root = base.join("root");
    write(&base.join("secret.php"), "<?php echo 'TOPSECRET';");
    write(&base.join("outside/inner.php"), "<?php echo 'TOPSECRET';");
    write(&root.join("index.php"), "<?php echo 'index';");
    write(&root.join("hello.php"), "<?php echo 'hello';");
    write(&root.join("page.phtml"), "<?php echo 'phtml';");
    write(&root.join("sub/index.php"), "<?php echo 'sub';");
    write(&root.join("note.txt"), "plain text");
    write(&root.join("uploads/evil.jpg"), "<?php echo 'EVIL';");
    write(&root.join(".env"), "SECRET=1");
    write(&base.join("theirs/theirs.php"), "<?php echo 'theirs';");
    symlink("../secret.php", root.join("up.php")).expect("relative escape");
    symlink("../outside", root.join("dirlink")).expect("directory escape");
    symlink(base.join("secret.php"), root.join("abs.php")).expect("absolute escape");
    symlink("hello.php", root.join("alias.php")).expect("link inside");
    symlink("note.txt", root.join("text.php")).expect("link to a file that may not run");
}

/// What a client got.
#[derive(Debug)]
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn decode_chunked(mut rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(end) = rest.windows(2).position(|pair| pair == b"\r\n") else {
            return out;
        };
        let size = usize::from_str_radix(
            std::str::from_utf8(&rest[..end])
                .expect("a chunk size")
                .split(';')
                .next()
                .expect("a size")
                .trim(),
            16,
        )
        .expect("a hex chunk size");
        rest = &rest[end + 2..];
        if size == 0 {
            return out;
        }
        if rest.len() < size {
            out.extend_from_slice(rest);
            return out;
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
}

fn parse_answer(raw: &[u8]) -> Answer {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header end in {:?}", String::from_utf8_lossy(raw)));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("bad status line in {head:?}"));
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let rest = &raw[split + 4..];
    let chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.contains("chunked"));
    Answer {
        status,
        headers,
        body: if chunked {
            decode_chunked(rest)
        } else {
            rest.to_vec()
        },
    }
}

/// Sends the raw request and reads until the connection closes. A reset after the response has
/// arrived (the proxy answered without reading a large body) does not lose the response.
async fn exchange(addr: SocketAddr, request: &[u8]) -> Answer {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let outcome = timeout(Duration::from_secs(20), async {
        // The proxy may answer and close before it has read the whole request.
        drop(stream.write_all(request).await);
        let mut raw = Vec::new();
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(count) => raw.extend_from_slice(&buffer[..count]),
            }
        }
        raw
    })
    .await
    .expect("a response in time");
    parse_answer(&outcome)
}

fn head(method: &str, path: &str, host: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.into_bytes()
}

fn with_length(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut out = head(method, path, host, headers);
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

fn chunked(method: &str, path: &str, host: &str, chunks: &[&[u8]]) -> Vec<u8> {
    let mut out = head(method, path, host, &[("Transfer-Encoding", "chunked")]);
    out.extend_from_slice(b"\r\n");
    for chunk in chunks {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// A temporary tree, two test applications (one per tenant) and a running `podgate`.
struct Site {
    base: PathBuf,
    podgate: Podgate,
    fcgi: Fcgi,
    theirs: Fcgi,
}

impl Site {
    async fn start(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Self {
        Self::start_with(handler, json!({})).await
    }

    /// `entry` is merged into the `FASTCGI_FILE` entry of tenant `t1`'s upstream `php`.
    async fn start_with(
        handler: impl Fn(&Request) -> Reply + Send + Sync + 'static,
        entry: Value,
    ) -> Self {
        let base = temp_base("site");
        populate(&base);
        let fcgi = Fcgi::start(handler).await;
        let theirs = Fcgi::start(|_| Reply::text("THEIRS")).await;
        Self::finish(base, fcgi, theirs, entry).await
    }

    async fn finish(base: PathBuf, fcgi: Fcgi, theirs: Fcgi, entry: Value) -> Self {
        let mut php = json!({ "address": fcgi.address, "root": base.join("root") });
        php.as_object_mut()
            .expect("object")
            .extend(entry.as_object().expect("an object").clone());
        let file = base.join("fastcgi.json");
        let declared = json!({
            "t1": { "php": php },
            "t2": { "theirs": { "address": theirs.address, "root": base.join("theirs") } },
        });
        std::fs::write(&file, declared.to_string()).expect("write FASTCGI_FILE");
        let file = file.to_string_lossy().into_owned();
        let podgate = Podgate::start_with_env(&[("FASTCGI_FILE", file.as_str())]).await;
        Self {
            base,
            podgate,
            fcgi,
            theirs,
        }
    }

    /// The `SCRIPT_FILENAME` of a script under the code root.
    fn script(&self, name: &str) -> String {
        std::fs::canonicalize(self.base.join("root"))
            .expect("canonical root")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    /// Pushes app `a` (tenant `t1`, host `a.test`) whose service `web` is `fastcgi` with `config`.
    async fn serve(&self, config: Value) -> common::Response {
        self.podgate
            .push_snapshot(&snapshot(&[fastcgi_app(
                "a", "t1", "a.test", "php", config,
            )]))
            .await
    }

    async fn serve_ok(&self, config: Value) {
        let pushed = self.serve(config).await;
        assert_eq!(pushed.status, 200, "snapshot refused: {}", pushed.body);
    }

    async fn get(&self, path: &str) -> Answer {
        exchange(
            self.podgate.proxy_addr,
            &with_length("GET", path, "a.test", &[], b""),
        )
        .await
    }

    async fn get_with(&self, path: &str, headers: &[(&str, &str)]) -> Answer {
        exchange(
            self.podgate.proxy_addr,
            &with_length("GET", path, "a.test", headers, b""),
        )
        .await
    }

    async fn post(&self, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Answer {
        exchange(
            self.podgate.proxy_addr,
            &with_length("POST", path, "a.test", headers, body),
        )
        .await
    }

    async fn post_chunked(&self, path: &str, chunks: &[&[u8]]) -> Answer {
        exchange(
            self.podgate.proxy_addr,
            &chunked("POST", path, "a.test", chunks),
        )
        .await
    }
}

impl Drop for Site {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.base));
    }
}

fn next_version() -> u64 {
    static VERSION: AtomicU64 = AtomicU64::new(1);
    VERSION.fetch_add(1, Ordering::Relaxed)
}

fn snapshot(apps: &[Value]) -> Value {
    json!({
        "version": next_version(),
        "tenants": [
            { "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
            { "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
        ],
        "apps": apps,
    })
}

/// An app `id` of `tenant` answering `host` with a serving revision whose service `web` is
/// `fastcgi` on `upstream`, with `config` next to it.
fn fastcgi_app(id: &str, tenant: &str, host: &str, upstream: &str, config: Value) -> Value {
    let Value::Object(fields) = config else {
        panic!("config is an object");
    };
    let mut service = json!({ "name": "web", "type": "fastcgi", "upstream": upstream });
    service.as_object_mut().expect("object").extend(fields);
    let revision = json!({
        "id": "r1", "state": "serving", "weight": 100, "services": [service]
    });
    let mut app = app(id, &[host], &[revision]);
    app["tenant"] = json!(tenant);
    app
}

/// Only `{path}` is tried: a request that names no allowed file is a `404`, not the front
/// controller.
fn direct() -> Value {
    json!({ "try_files": ["{path}"] })
}

fn ran(fcgi: &Fcgi) -> Vec<String> {
    fcgi.requests()
        .iter()
        .map(|request| {
            request
                .param("SCRIPT_FILENAME")
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// The codes of a `422`, without `unknown_service`: a service that did not compile leaves its
/// router with nothing to point at, which the compiler reports next to the cause.
fn conflict_codes(response: &common::Response) -> Vec<String> {
    response.json()["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|conflict| conflict["code"].as_str().expect("code").to_owned())
        .filter(|code| code != "unknown_service")
        .collect()
}

async fn eventually(what: &str, mut done: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        sleep(Duration::from_millis(50)).await;
    }
}

/// The `podgate_tenant_buffer_bytes` metric of `tenant`; 0 when it has no line.
async fn buffered(podgate: &Podgate, tenant: &str, name: &str) -> u64 {
    let metrics = podgate.admin_get("/metrics").await.body;
    let prefix = format!("{name}{{tenant=\"{tenant}\"}} ");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.trim().parse().expect("a number"))
}

// -- running scripts -------------------------------------------------------------------------

#[tokio::test]
async fn fastcgi_runs_script_and_returns_output() {
    let site = Site::start(|_| Reply::text("hello from php")).await;
    site.serve_ok(json!({})).await;
    let response = site.get("/hello.php?a=1&b=two").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "hello from php");
    assert_eq!(response.header("content-type"), Some("text/plain"));
    let requests = site.fcgi.requests();
    let request = requests.first().expect("the application saw one request");
    for (name, value) in [
        ("REQUEST_METHOD", "GET"),
        ("SCRIPT_NAME", "/hello.php"),
        ("QUERY_STRING", "a=1&b=two"),
        ("REQUEST_URI", "/hello.php?a=1&b=two"),
        ("SERVER_NAME", "a.test"),
        ("REMOTE_ADDR", "127.0.0.1"),
        ("GATEWAY_INTERFACE", "CGI/1.1"),
    ] {
        assert_eq!(request.param(name), Some(value), "{name}");
    }
    assert_eq!(
        request.param("SCRIPT_FILENAME"),
        Some(site.script("hello.php").as_str())
    );
    assert_eq!(request.param("PATH_INFO"), None);
    assert_eq!(request.param("HTTPS"), None, "the request is plain HTTP");
    assert_eq!(request.param("HTTP_HOST"), Some("a.test"));
    // A directory runs its index; the front controller catches what is not a file.
    assert_eq!(site.get("/").await.status, 200);
    assert_eq!(site.get("/sub/").await.status, 200);
    assert_eq!(
        site.get("/no/such/route").await.status,
        200,
        "the default try_files ends in the index script"
    );
    let seen = ran(&site.fcgi);
    assert_eq!(seen[1], site.script("index.php"));
    assert_eq!(seen[2], site.script("sub/index.php"));
    assert_eq!(seen[3], site.script("index.php"));
}

#[tokio::test]
async fn fastcgi_runs_script_over_unix_socket() {
    let base = temp_base("unix");
    populate(&base);
    let socket = base.join("php.sock");
    let fcgi = Fcgi::start_unix(&socket, |_| Reply::text("over a unix socket")).await;
    let theirs = Fcgi::start(|_| Reply::text("THEIRS")).await;
    let site = Site::finish(base, fcgi, theirs, json!({})).await;
    site.serve_ok(json!({})).await;
    let response = site.get("/hello.php").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "over a unix socket");
}

#[tokio::test]
async fn fastcgi_status_and_headers() {
    let site = Site::start(|request| match request.param("SCRIPT_NAME") {
        Some("/hello.php") => Reply::cgi(
            "Status: 404 Not Found\r\nX-Custom: yes\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Type: text/html\r\n",
            b"<p>gone</p>",
        )
        .with_stderr("PHP Warning: something"),
        Some("/page.phtml") => Reply::cgi("Location: /elsewhere\r\n", b""),
        _ => Reply::cgi("", b"bare body"),
    })
    .await;
    site.serve_ok(json!({ "extensions": [".php", ".phtml"] }))
        .await;
    let response = site.get("/hello.php").await;
    assert_eq!(response.status, 404);
    assert_eq!(response.text(), "<p>gone</p>");
    assert_eq!(response.header("x-custom"), Some("yes"));
    assert_eq!(response.header("content-type"), Some("text/html"));
    assert_eq!(response.all("set-cookie"), ["a=1", "b=2"]);
    assert_eq!(
        response.header("status"),
        None,
        "Status is not a response header"
    );
    let redirect = site.get("/page.phtml").await;
    assert_eq!(
        redirect.status, 302,
        "a Location and no Status is a redirect"
    );
    assert_eq!(redirect.header("location"), Some("/elsewhere"));
    let plain = site.get("/index.php").await;
    assert_eq!(plain.status, 200, "a missing Status is 200");
    assert_eq!(plain.text(), "bare body");
    let head = exchange(
        site.podgate.proxy_addr,
        &with_length("HEAD", "/hello.php", "a.test", &[], b""),
    )
    .await;
    assert_eq!(head.status, 404);
    assert_eq!(head.header("x-custom"), Some("yes"));
    assert!(head.body.is_empty(), "a HEAD answer has no body");
}

#[tokio::test]
async fn fastcgi_large_output_streams() {
    let body = "x".repeat(300_000);
    let expected = body.clone();
    let site = Site::start(move |_| Reply::text(&body)).await;
    site.serve_ok(json!({})).await;
    let response = site.get("/hello.php").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), expected);
}

#[tokio::test]
async fn fastcgi_explain_shows_upstream_and_index() {
    let site = Site::start(|_| Reply::text("ok")).await;
    site.serve_ok(json!({ "index": "home.php" })).await;
    let explained = site
        .podgate
        .admin_get("/v1/explain?url=http%3A%2F%2Fa.test%2Fhello.php&method=GET")
        .await;
    assert_eq!(explained.status, 200, "{}", explained.body);
    assert_eq!(
        explained.json()["revisions"][0]["fastcgi"],
        json!({ "upstream": "php", "index": "home.php" })
    );
}

// -- a real PHP-FPM ----------------------------------------------------------------------------

/// Makes the child receive SIGTERM when this process dies, however it dies: a test binary that
/// is killed (SIGKILL, a timeout, the OOM killer) never runs `Drop`, and php-fpm would live on
/// with its workers. The master stops its workers on SIGTERM.
#[allow(unsafe_code)] // `pre_exec` is unsafe; the closure makes one prctl call, see SAFETY.
fn die_with_parent(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs between fork and exec and calls only `prctl`, a plain
    // async-signal-safe syscall wrapper: no allocation, no locks, no access to shared state.
    unsafe {
        command.pre_exec(|| {
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::TERM))
                .map_err(std::io::Error::from)
        });
    }
}

/// A `php-fpm` serving `<dir>/www` on a unix socket. Missing `php-fpm` fails the test (it is on
/// PATH in `devenv shell`); nothing is skipped. Killed on drop.
struct PhpFpm {
    child: Child,
    socket: PathBuf,
}

impl PhpFpm {
    async fn start(dir: &Path) -> Self {
        let socket = dir.join("fpm.sock");
        let config = dir.join("php-fpm.conf");
        std::fs::write(
            &config,
            format!(
                "[global]\ndaemonize = no\nerror_log = /dev/stderr\n\
                 [www]\nlisten = {}\npm = static\npm.max_children = 2\nclear_env = no\n\
                 catch_workers_output = yes\n\
                 php_admin_value[cgi.fix_pathinfo] = 0\n\
                 php_admin_value[display_errors] = stderr\n",
                socket.display()
            ),
        )
        .expect("write php-fpm.conf");
        let mut command = Command::new("php-fpm");
        command
            .arg("--nodaemonize")
            .arg("-n")
            .arg("-R")
            .arg("--fpm-config")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        die_with_parent(&mut command);
        let child = command
            .spawn()
            .expect("php-fpm must be on PATH (it is in `devenv shell`)");
        let deadline = Instant::now() + Duration::from_secs(15);
        while tokio::net::UnixStream::connect(&socket).await.is_err() {
            assert!(Instant::now() < deadline, "php-fpm did not listen");
            sleep(Duration::from_millis(50)).await;
        }
        Self { child, socket }
    }
}

impl Drop for PhpFpm {
    /// SIGTERM, not a kill: the master stops its workers on SIGTERM, and a workers left behind
    /// would hold on to every file descriptor the test run inherited (the cargo lock included).
    fn drop(&mut self) {
        drop(
            Command::new("kill")
                .arg(self.child.id().to_string())
                .status(),
        );
        drop(self.child.wait());
    }
}

#[tokio::test]
async fn fastcgi_real_php_fpm_smoke() {
    let base = temp_base("php");
    let root = base.join("www");
    write(
        &root.join("index.php"),
        "<?php\nheader('X-Php: yes');\nheader('Content-Type: application/json');\n\
         echo json_encode([\n\
           'get' => $_GET, 'post' => $_POST, 'cookie' => $_COOKIE,\n\
           'method' => $_SERVER['REQUEST_METHOD'],\n\
           'script' => $_SERVER['SCRIPT_NAME'],\n\
           'path_info' => $_SERVER['PATH_INFO'] ?? null,\n\
           'ua' => $_SERVER['HTTP_USER_AGENT'] ?? null,\n\
         ]);\n",
    );
    write(
        &root.join("status.php"),
        "<?php http_response_code(418); echo 'teapot';",
    );
    write(&root.join("uploads/evil.jpg"), "<?php echo 'EVIL';");
    let fpm = PhpFpm::start(&base).await;
    let file = base.join("fastcgi.json");
    std::fs::write(
        &file,
        json!({ "t1": { "php": {
            "address": format!("unix:{}", fpm.socket.display()),
            "root": root,
            "max_connections": 2,
        }}})
        .to_string(),
    )
    .expect("write FASTCGI_FILE");
    let podgate = Podgate::start_with_env(&[("FASTCGI_FILE", &file.to_string_lossy())]).await;
    let pushed = podgate
        .push_snapshot(&snapshot(&[fastcgi_app(
            "a",
            "t1",
            "a.test",
            "php",
            json!({}),
        )]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let get = exchange(
        podgate.proxy_addr,
        &with_length(
            "GET",
            "/index.php/extra?q=1&list=a",
            "a.test",
            &[("Cookie", "sid=abc; theme=dark"), ("User-Agent", "smoke")],
            b"",
        ),
    )
    .await;
    assert_eq!(get.status, 200, "{}", get.text());
    assert_eq!(get.header("x-php"), Some("yes"));
    let seen: Value = serde_json::from_str(&get.text()).expect("PHP answered JSON");
    assert_eq!(seen["get"], json!({ "q": "1", "list": "a" }));
    assert_eq!(seen["cookie"], json!({ "sid": "abc", "theme": "dark" }));
    assert_eq!(seen["method"], "GET");
    assert_eq!(seen["script"], "/index.php");
    assert_eq!(seen["path_info"], "/extra");
    assert_eq!(seen["ua"], "smoke");

    let post = exchange(
        podgate.proxy_addr,
        &with_length(
            "POST",
            "/index.php?from=query",
            "a.test",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            b"name=Ada+Lovelace&langs%5B%5D=en&langs%5B%5D=fr",
        ),
    )
    .await;
    assert_eq!(post.status, 200, "{}", post.text());
    let seen: Value = serde_json::from_str(&post.text()).expect("PHP answered JSON");
    assert_eq!(
        seen["post"],
        json!({ "name": "Ada Lovelace", "langs": ["en", "fr"] })
    );
    assert_eq!(seen["get"], json!({ "from": "query" }));
    assert_eq!(seen["method"], "POST");

    let status = exchange(
        podgate.proxy_addr,
        &with_length("GET", "/status.php", "a.test", &[], b""),
    )
    .await;
    assert_eq!(status.status, 418);
    assert_eq!(status.text(), "teapot");

    let attack = exchange(
        podgate.proxy_addr,
        &with_length("GET", "/uploads/evil.jpg/x.php", "a.test", &[], b""),
    )
    .await;
    assert!(!attack.text().contains("EVIL"), "{}", attack.text());
    let plain = exchange(
        podgate.proxy_addr,
        &with_length("GET", "/uploads/evil.jpg", "a.test", &[], b""),
    )
    .await;
    assert!(!plain.text().contains("EVIL"), "{}", plain.text());
    drop(std::fs::remove_dir_all(&base));
}

// -- the script comes only from the operator's root ------------------------------------------

#[tokio::test]
async fn fastcgi_traversal_refused() {
    let site = Site::start(|_| Reply::text("RAN")).await;
    site.serve_ok(direct()).await;
    for path in [
        "/../secret.php",
        "/%2e%2e/secret.php",
        "/%2E%2E%2Fsecret.php",
        "/sub/../../secret.php",
        "/..%2f..%2fsecret.php",
        "/sub/%252e%252e/secret.php",
        "/%5c..%5csecret.php",
        "/hello.php%00.txt",
        "/.env",
        "/.git/config",
    ] {
        let response = site.get(path).await;
        assert!(
            matches!(response.status, 400 | 404),
            "{path}: {} {}",
            response.status,
            response.text()
        );
        assert!(!response.text().contains(SECRET), "{path}");
        assert!(!response.text().contains("RAN"), "{path}");
    }
    assert_eq!(ran(&site.fcgi), Vec::<String>::new(), "no script ever ran");
    assert_eq!(
        site.get("/hello.php").await.text(),
        "RAN",
        "the root itself works"
    );
}

#[tokio::test]
async fn fastcgi_symlink_escape_refused() {
    let site = Site::start(|_| Reply::text("RAN")).await;
    site.serve_ok(direct()).await;
    for path in ["/up.php", "/abs.php", "/dirlink/inner.php", "/text.php"] {
        let response = site.get(path).await;
        assert_eq!(response.status, 404, "{path}: {}", response.text());
    }
    assert_eq!(ran(&site.fcgi), Vec::<String>::new(), "no script ever ran");
    let inside = site.get("/alias.php").await;
    assert_eq!(
        inside.status, 200,
        "a symlink to an allowed file inside the root runs"
    );
    assert_eq!(
        ran(&site.fcgi),
        [site.script("hello.php")],
        "and the application gets the real file"
    );
}

#[tokio::test]
async fn fastcgi_other_tenant_upstream_rejected() {
    let site = Site::start(|_| Reply::text("MINE")).await;
    let pushed = site
        .podgate
        .push_snapshot(&snapshot(&[fastcgi_app(
            "a",
            "t1",
            "a.test",
            "theirs",
            json!({}),
        )]))
        .await;
    assert_eq!(pushed.status, 422, "{}", pushed.body);
    assert!(
        conflict_codes(&pushed).contains(&"unknown_fastcgi_upstream".to_owned()),
        "{}",
        pushed.body
    );
    // Each tenant reaches its own pool and code only.
    let pushed = site
        .podgate
        .push_snapshot(&snapshot(&[
            fastcgi_app("a", "t1", "a.test", "php", json!({})),
            fastcgi_app("b", "t2", "b.test", "theirs", json!({})),
        ]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(site.get("/hello.php").await.text(), "MINE");
    let theirs = exchange(
        site.podgate.proxy_addr,
        &with_length("GET", "/theirs.php", "b.test", &[], b""),
    )
    .await;
    assert_eq!(theirs.text(), "THEIRS");
    let mine = site.fcgi.requests();
    assert_eq!(
        mine.len(),
        1,
        "the other tenant's request never reached this pool"
    );
    let theirs = site.theirs.requests();
    assert_eq!(theirs.len(), 1);
    assert!(
        theirs[0]
            .param("SCRIPT_FILENAME")
            .is_some_and(|path| path.ends_with("/theirs/theirs.php")),
        "{:?}",
        theirs[0].param("SCRIPT_FILENAME")
    );
    // Tenant t2 cannot run tenant t1's script, and the other way round.
    let cross = exchange(
        site.podgate.proxy_addr,
        &with_length("GET", "/hello.php", "b.test", &[], b""),
    )
    .await;
    assert_ne!(
        cross.status,
        200,
        "t2's root has no hello.php: {}",
        cross.text()
    );
    assert_eq!(site.theirs.requests().len(), 1);
}

#[tokio::test]
async fn fastcgi_snapshot_cannot_supply_address() {
    let site = Site::start(|_| Reply::text("MINE")).await;
    let attacker = Fcgi::start(|_| Reply::text("ATTACKER")).await;
    for (extra, why) in [
        (json!({ "address": attacker.address }), "address"),
        (json!({ "root": "/etc" }), "root"),
        (json!({ "socket": "unix:/tmp/x.sock" }), "socket"),
        (
            json!({ "servers": [{ "url": format!("http://{}", attacker.address) }] }),
            "servers",
        ),
        (json!({ "max_connections": 9999 }), "max_connections"),
    ] {
        let pushed = site.serve(extra).await;
        assert_eq!(pushed.status, 422, "{why}: {}", pushed.body);
        assert!(
            conflict_codes(&pushed).contains(&"invalid_service".to_owned()),
            "{why}: {}",
            pushed.body
        );
    }
    for name in [
        attacker.address.as_str(),
        "unix:/tmp/x.sock",
        "/etc",
        "other",
        "",
    ] {
        let pushed = site
            .podgate
            .push_snapshot(&snapshot(&[fastcgi_app(
                "a",
                "t1",
                "a.test",
                name,
                json!({}),
            )]))
            .await;
        assert_eq!(pushed.status, 422, "{name:?}: {}", pushed.body);
        assert!(
            conflict_codes(&pushed).contains(&"unknown_fastcgi_upstream".to_owned()),
            "{name:?}: {}",
            pushed.body
        );
    }
    assert!(
        attacker.requests().is_empty(),
        "nothing was ever sent to the attacker"
    );
}

// -- only .php files run -----------------------------------------------------------------------

#[tokio::test]
async fn fastcgi_only_php_files_run() {
    let site = Site::start(|_| Reply::text("RAN")).await;
    site.serve_ok(direct()).await;
    for path in ["/note.txt", "/uploads/evil.jpg", "/index.html", "/uploads/"] {
        assert_eq!(site.get(path).await.status, 404, "{path}");
    }
    assert_eq!(
        ran(&site.fcgi),
        Vec::<String>::new(),
        "no file but a .php one runs"
    );
    // With a front controller the same requests reach the index script, never the file.
    site.serve_ok(json!({})).await;
    assert_eq!(site.get("/uploads/evil.jpg").await.status, 200);
    assert_eq!(site.get("/note.txt").await.status, 200);
    assert_eq!(
        ran(&site.fcgi),
        [site.script("index.php"), site.script("index.php")]
    );
    // An extra extension is the operator-visible service setting, and it is the only way.
    assert_eq!(site.get("/page.phtml").await.status, 200);
    assert_eq!(
        ran(&site.fcgi).last().expect("ran"),
        &site.script("index.php")
    );
    let pushed = site
        .podgate
        .push_snapshot(&snapshot(&[fastcgi_app(
            "a",
            "t1",
            "a.test",
            "php",
            json!({ "try_files": ["{path}"], "extensions": [".php", ".phtml"] }),
        )]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(site.get("/page.phtml").await.status, 200);
    assert_eq!(
        ran(&site.fcgi).last().expect("ran"),
        &site.script("page.phtml")
    );
    // `deny` keeps whole directories from running.
    let pushed = site
        .podgate
        .push_snapshot(&snapshot(&[fastcgi_app(
            "a",
            "t1",
            "a.test",
            "php",
            json!({ "try_files": ["{path}"], "deny": ["sub"] }),
        )]))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let before = site.fcgi.requests().len();
    assert_eq!(site.get("/sub/index.php").await.status, 404);
    assert_eq!(site.get("/sub/").await.status, 404);
    assert_eq!(site.fcgi.requests().len(), before);
}

#[tokio::test]
async fn fastcgi_path_info_attack_refused() {
    let site = Site::start(|_| Reply::text("RAN")).await;
    site.serve_ok(direct()).await;
    for path in [
        "/uploads/evil.jpg/x.php",
        "/uploads/evil.jpg/x.php/more",
        "/uploads/evil.jpg/.php",
        "/note.txt/x.php",
        "/uploads/evil.jpg%2fx.php",
    ] {
        let response = site.get(path).await;
        assert!(
            matches!(response.status, 400 | 404),
            "{path}: {}",
            response.status
        );
    }
    assert_eq!(
        ran(&site.fcgi),
        Vec::<String>::new(),
        "evil.jpg was never executed"
    );
    // With the front controller the index script runs, and the request path stays in
    // REQUEST_URI for the application to route on, with nothing guessed from the file system.
    site.serve_ok(json!({})).await;
    let response = site.get("/uploads/evil.jpg/x.php").await;
    assert_eq!(response.status, 200);
    let requests = site.fcgi.requests();
    let request = requests.first().expect("one request");
    assert_eq!(
        request.param("SCRIPT_FILENAME"),
        Some(site.script("index.php").as_str())
    );
    assert_eq!(request.param("SCRIPT_NAME"), Some("/index.php"));
    assert_eq!(request.param("PATH_INFO"), None);
    assert_eq!(
        request.param("REQUEST_URI"),
        Some("/uploads/evil.jpg/x.php")
    );
    assert!(
        !ran(&site.fcgi).iter().any(|path| path.contains("evil.jpg")),
        "{:?}",
        ran(&site.fcgi)
    );
}

#[tokio::test]
async fn fastcgi_path_info_split() {
    let site = Site::start(|_| Reply::text("ok")).await;
    site.serve_ok(direct()).await;
    let response = site.get("/hello.php/a/b%20c?x=1").await;
    assert_eq!(response.status, 200);
    let requests = site.fcgi.requests();
    let request = requests.first().expect("one request");
    assert_eq!(request.param("SCRIPT_NAME"), Some("/hello.php"));
    assert_eq!(
        request.param("SCRIPT_FILENAME"),
        Some(site.script("hello.php").as_str())
    );
    assert_eq!(request.param("PATH_INFO"), Some("/a/b c"));
    assert_eq!(
        request.param("PATH_TRANSLATED"),
        None,
        "PHP-FPM with cgi.fix_pathinfo = 0 would take it for the script"
    );
    assert_eq!(request.param("DOCUMENT_URI"), Some("/hello.php/a/b c"));
    assert_eq!(request.param("REQUEST_URI"), Some("/hello.php/a/b%20c?x=1"));
    assert_eq!(request.param("QUERY_STRING"), Some("x=1"));
    // A trailing slash after the script is a PATH_INFO of `/`.
    assert_eq!(site.get("/hello.php/").await.status, 200);
    assert_eq!(site.fcgi.requests()[1].param("PATH_INFO"), Some("/"));
    // Without the split the script must be the whole path.
    site.serve_ok(json!({ "try_files": ["{path}"], "split_path_info": false }))
        .await;
    let before = site.fcgi.requests().len();
    assert_eq!(site.get("/hello.php/a/b").await.status, 404);
    assert_eq!(site.fcgi.requests().len(), before);
    assert_eq!(site.get("/hello.php").await.status, 200);
}

// -- parameters ----------------------------------------------------------------------------------

#[tokio::test]
async fn fastcgi_httpoxy_proxy_header_dropped() {
    let site = Site::start(|_| Reply::text("ok")).await;
    site.serve_ok(json!({})).await;
    let response = site
        .get_with(
            "/hello.php",
            &[("Proxy", "http://evil.example:8080"), ("X-Keep", "kept")],
        )
        .await;
    assert_eq!(response.status, 200);
    let requests = site.fcgi.requests();
    let request = requests.first().expect("one request");
    assert!(
        !request
            .params
            .iter()
            .any(|(name, value)| name == "HTTP_PROXY" || value.contains("evil.example")),
        "{:?}",
        request.params
    );
    assert_eq!(request.param("HTTP_X_KEEP"), Some("kept"));
}

#[tokio::test]
async fn fastcgi_header_collision_dropped() {
    let site = Site::start(|_| Reply::text("ok")).await;
    site.serve_ok(json!({})).await;
    let response = site
        .get_with(
            "/hello.php",
            &[
                ("X_Foo", "from-underscore"),
                ("X-Foo", "from-hyphen"),
                ("X_Only", "underscore alone"),
                ("X-Keep", "kept"),
            ],
        )
        .await;
    assert_eq!(response.status, 200);
    let requests = site.fcgi.requests();
    let request = requests.first().expect("one request");
    let names = request.http_names();
    assert!(
        !names.contains(&"HTTP_X_FOO"),
        "neither spelling passes: {names:?}"
    );
    assert!(
        !names.contains(&"HTTP_X_ONLY"),
        "an underscore name never passes: {names:?}"
    );
    assert_eq!(request.param("HTTP_X_KEEP"), Some("kept"));
    assert!(
        !request
            .params
            .iter()
            .any(|(_, value)| value.contains("from-")),
        "no value of a dropped header leaks: {:?}",
        request.params
    );
}

#[tokio::test]
async fn fastcgi_env_names_validated() {
    let site = Site::start(|_| Reply::text("ok")).await;
    for bad in [
        "lower",
        "1STARTS_WITH_DIGIT",
        "HTTP_PROXY",
        "HTTP_HOST",
        "SCRIPT_FILENAME",
        "PATH_INFO",
        "REQUEST_URI",
        "SERVER_NAME",
        "REMOTE_ADDR",
        "CONTENT_TYPE",
        "PHP_VALUE",
        "PHP_ADMIN_VALUE",
        "PHP_INI_SCAN_DIR",
        "PHPRC",
        "DOCUMENT_ROOT",
        "QUERY_STRING",
        "LD_PRELOAD",
        "WITH-DASH",
    ] {
        let pushed = site.serve(json!({ "env": { bad: "x" } })).await;
        assert_eq!(pushed.status, 422, "{bad}: {}", pushed.body);
        assert!(
            conflict_codes(&pushed).contains(&"invalid_service".to_owned()),
            "{bad}: {}",
            pushed.body
        );
    }
    let long = "A".repeat(65);
    let pushed = site.serve(json!({ "env": { long: "x" } })).await;
    assert_eq!(pushed.status, 422, "{}", pushed.body);
    let pushed = site.serve(json!({ "env": { "OK": "a\u{1}b" } })).await;
    assert_eq!(pushed.status, 422, "{}", pushed.body);
    site.serve_ok(json!({ "env": { "APP_ENV": "production", "DB_HOST": "db.internal" } }))
        .await;
    assert_eq!(site.get("/hello.php").await.status, 200);
    let requests = site.fcgi.requests();
    let request = requests.first().expect("one request");
    assert_eq!(request.param("APP_ENV"), Some("production"));
    assert_eq!(request.param("DB_HOST"), Some("db.internal"));
}

#[tokio::test]
async fn fastcgi_request_headers_over_the_cap_are_431() {
    let site = Site::start(|_| Reply::text("ok")).await;
    site.serve_ok(json!({})).await;
    let big = "a".repeat(8000);
    let headers: Vec<(String, String)> = (0..10)
        .map(|n| (format!("X-Big-{n}"), big.clone()))
        .collect();
    let borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let response = site.get_with("/hello.php", &borrowed).await;
    assert_eq!(response.status, 431, "{}", response.text());
    assert!(site.fcgi.requests().is_empty());
}

// -- bodies -------------------------------------------------------------------------------------

#[tokio::test]
async fn fastcgi_body_streamed() {
    let site = Site::start(|request| Reply::text(&format!("got {}", request.stdin.len()))).await;
    site.serve_ok(json!({ "max_request_body_bytes": 8 << 20 }))
        .await;
    let body = vec![b'z'; 4 << 20];
    let response = site
        .post(
            "/hello.php",
            &[("Content-Type", "application/octet-stream")],
            &body,
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.text());
    assert_eq!(response.text(), format!("got {}", body.len()));
    let requests = site.fcgi.requests();
    let request = requests.first().expect("one request");
    assert_eq!(request.param("CONTENT_LENGTH"), Some("4194304"));
    assert_eq!(
        request.param("CONTENT_TYPE"),
        Some("application/octet-stream")
    );
    assert_eq!(request.param("REQUEST_METHOD"), Some("POST"));
    assert!(
        request.stdin == body,
        "the application received the exact bytes"
    );
    // A body of 4 MiB passed through a 1 MiB budget: it was streamed, not held.
    let peak = buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes_peak").await;
    assert!(peak <= 128 * 1024, "peak buffer {peak}");
    eventually("the charge to end", async || {
        buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await == 0
    })
    .await;
    // No body, no CONTENT_LENGTH other than 0.
    assert_eq!(site.get("/hello.php").await.status, 200);
    assert_eq!(site.fcgi.requests()[1].param("CONTENT_LENGTH"), Some("0"));
}

#[tokio::test]
async fn fastcgi_chunked_body_buffered_and_charged() {
    let site = Site::start(|request| {
        Reply::text(&format!("got {}", request.stdin.len())).after(Duration::from_millis(600))
    })
    .await;
    site.serve_ok(json!({})).await;
    let chunk = vec![b'c'; 100_000];
    let addr = site.podgate.proxy_addr;
    let request = chunked("POST", "/hello.php", "a.test", &[&chunk, &chunk, &chunk]);
    let sending = tokio::spawn(async move { exchange(addr, &request).await });
    // While the application works, the held body is charged on top of the request's buffers.
    let mut highest = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !sending.is_finished() {
        highest = highest.max(buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await);
        sleep(Duration::from_millis(50)).await;
    }
    let response = sending.await.expect("joins");
    assert_eq!(response.status, 200, "{}", response.text());
    assert_eq!(response.text(), "got 300000");
    assert!(
        highest >= 300_000 + 128 * 1024,
        "the whole body and the request's buffers were charged: {highest}"
    );
    let requests = site.fcgi.requests();
    let request = requests.first().expect("one request");
    assert_eq!(request.param("CONTENT_LENGTH"), Some("300000"));
    assert_eq!(request.stdin.len(), 300_000);
    eventually("the charge to end", async || {
        buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await == 0
    })
    .await;
    // A tenant whose budget cannot take the body gets a capacity answer, not an allocation.
    let tiny = json!({
        "version": next_version(),
        "tenants": [{ "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 256 * 1024 } }],
        "apps": [fastcgi_app("a", "t1", "a.test", "php", json!({}))],
    });
    assert_eq!(site.podgate.push_snapshot(&tiny).await.status, 200);
    let response = site
        .post_chunked("/hello.php", &[&chunk, &chunk, &chunk])
        .await;
    assert_eq!(response.status, 503, "{}", response.text());
    assert_eq!(response.header("retry-after"), Some("1"));
    assert_eq!(
        site.fcgi.requests().len(),
        1,
        "the application never saw it"
    );
    let known = site.post("/hello.php", &[], b"small").await;
    assert_eq!(
        known.status, 200,
        "a streamed body needs no more than the reservation"
    );
}

#[tokio::test]
async fn fastcgi_body_over_cap_413() {
    let site = Site::start(|request| Reply::text(&format!("got {}", request.stdin.len()))).await;
    site.serve_ok(json!({ "max_request_body_bytes": 1000 }))
        .await;
    let at_limit = site.post("/hello.php", &[], &[b'a'; 1000]).await;
    assert_eq!(at_limit.status, 200);
    assert_eq!(at_limit.text(), "got 1000");
    let over = site.post("/hello.php", &[], &[b'a'; 1001]).await;
    assert_eq!(over.status, 413, "{}", over.text());
    let over_chunked = site
        .post_chunked("/hello.php", &[&[b'a'; 600], &[b'a'; 600]])
        .await;
    assert_eq!(over_chunked.status, 413, "{}", over_chunked.text());
    let chunked_ok = site
        .post_chunked("/hello.php", &[&[b'a'; 600], &[b'a'; 400]])
        .await;
    assert_eq!(chunked_ok.status, 200);
    assert_eq!(chunked_ok.text(), "got 1000");
    assert_eq!(
        site.fcgi.requests().len(),
        2,
        "the refused bodies never reached the application"
    );
    let bad_length = exchange(
        site.podgate.proxy_addr,
        b"POST /hello.php HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\nContent-Length: abc\r\n\r\n",
    )
    .await;
    assert!(
        matches!(bad_length.status, 400 | 413),
        "{}",
        bad_length.status
    );
}

// -- the application's answer --------------------------------------------------------------------

#[tokio::test]
async fn fastcgi_invalid_response_header_502() {
    let site = Site::start(|request| match request.param("QUERY_STRING") {
        Some("no_colon") => Reply::raw(b"this is not a header\r\n\r\nbody"),
        Some("bad_name") => Reply::raw(b"Bad Name: x\r\n\r\nbody"),
        Some("folded") => Reply::raw(b"X-A: 1\r\n continued\r\n\r\nbody"),
        Some("control") => Reply::raw(b"X-A: a\x01b\r\n\r\nbody"),
        Some("bad_status") => Reply::raw(b"Status: 99x\r\n\r\nbody"),
        Some("informational") => Reply::raw(b"Status: 100 Continue\r\n\r\nbody"),
        Some("empty") => Reply::raw(b""),
        Some("headless") => Reply::raw(b"X-A: 1\r\n"),
        Some("dropped") => Reply {
            stdout: b"Content-Type: text/plain\r\n\r\npartial".to_vec(),
            drop_connection: true,
            ..Reply::default()
        },
        _ => Reply::text("fine"),
    })
    .await;
    site.serve_ok(json!({})).await;
    for case in [
        "no_colon",
        "bad_name",
        "folded",
        "control",
        "bad_status",
        "informational",
        "empty",
        "headless",
    ] {
        let response = site.get(&format!("/hello.php?{case}")).await;
        assert_eq!(
            response.status,
            502,
            "{case}: {} {}",
            response.status,
            response.text()
        );
        assert!(
            !response.text().contains("body"),
            "{case}: the body of an invalid answer is not sent"
        );
    }
    let response = site.get("/hello.php?ok").await;
    assert_eq!(
        response.status, 200,
        "an invalid answer leaves the pool usable"
    );
    assert_eq!(response.text(), "fine");
}

#[tokio::test]
async fn fastcgi_response_headers_capped() {
    let site = Site::start(|request| {
        let size: usize = request
            .param("QUERY_STRING")
            .and_then(|query| query.parse().ok())
            .unwrap_or(0);
        let value = "v".repeat(size);
        Reply::cgi(&format!("X-Big: {value}\r\n"), b"body")
    })
    .await;
    site.serve_ok(json!({})).await;
    let ok = site.get("/hello.php?30000").await;
    assert_eq!(ok.status, 200);
    assert_eq!(ok.header("x-big").map(str::len), Some(30000));
    let over = site.get("/hello.php?70000").await;
    assert_eq!(over.status, 502, "{}", over.status);
    // Many small headers hit the count cap, not memory.
    let many: String = (0..300).map(|n| format!("X-N-{n}: v\r\n")).collect();
    let flood = Site::start(move |_| Reply::cgi(&many, b"body")).await;
    flood.serve_ok(json!({})).await;
    assert_eq!(flood.get("/hello.php").await.status, 502);
}

#[tokio::test]
async fn fastcgi_x_accel_ignored() {
    let site = Site::start(|_| {
        Reply::cgi(
            "X-Accel-Redirect: /note.txt\r\nX-Accel-Buffering: no\r\nX-Sendfile: /etc/passwd\r\nX-Kept: yes\r\n",
            b"the script's own body",
        )
    })
    .await;
    site.serve_ok(json!({})).await;
    let response = site.get("/hello.php").await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.text(),
        "the script's own body",
        "the file named by the header is never served"
    );
    assert_eq!(response.header("x-kept"), Some("yes"));
    assert!(
        !response
            .headers
            .iter()
            .any(|(name, _)| name.starts_with("x-accel") || name == "x-sendfile"),
        "{:?}",
        response.headers
    );
}

// -- the pool -----------------------------------------------------------------------------------

#[tokio::test]
async fn fastcgi_pool_bounded() {
    let site = Site::start_with(
        |_| Reply::text("ok").after(Duration::from_millis(300)),
        json!({ "max_connections": 2 }),
    )
    .await;
    site.serve_ok(json!({})).await;
    let addr = site.podgate.proxy_addr;
    let requests: Vec<_> = (0..6)
        .map(|_| {
            tokio::spawn(async move {
                exchange(addr, &with_length("GET", "/hello.php", "a.test", &[], b"")).await
            })
        })
        .collect();
    for request in requests {
        let response = request.await.expect("joins");
        assert_eq!(response.status, 200, "{}", response.text());
    }
    assert_eq!(site.fcgi.requests().len(), 6);
    assert!(
        site.fcgi.peak_open() <= 2,
        "peak open connections {}",
        site.fcgi.peak_open()
    );
    assert!(site.fcgi.peak_in_flight() <= 2);
    assert!(
        site.fcgi.accepted() <= 2,
        "idle connections were reused: {}",
        site.fcgi.accepted()
    );
}

#[tokio::test]
async fn fastcgi_pool_wait_503() {
    let site = Site::start_with(
        |_| Reply::text("ok").after(Duration::from_secs(3)),
        json!({ "max_connections": 1 }),
    )
    .await;
    site.serve_ok(json!({})).await;
    let addr = site.podgate.proxy_addr;
    let first = tokio::spawn(async move {
        exchange(addr, &with_length("GET", "/hello.php", "a.test", &[], b"")).await
    });
    eventually("the first request to reach the application", async || {
        !site.fcgi.requests().is_empty()
    })
    .await;
    let started = Instant::now();
    let second = site.get("/hello.php").await;
    let waited = started.elapsed();
    assert_eq!(second.status, 503, "{}", second.text());
    assert_eq!(second.header("retry-after"), Some("1"));
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_millis(2500),
        "waited {waited:?}"
    );
    assert_eq!(site.fcgi.requests().len(), 1);
    assert_eq!(
        first.await.expect("joins").status,
        200,
        "the request in flight is not harmed"
    );
}

#[tokio::test]
async fn fastcgi_dead_upstream_502() {
    // A refused TCP address: every request is a 502, and none hangs.
    let dead = common::refused();
    let base = temp_base("dead");
    populate(&base);
    let live = Fcgi::start(|_| Reply::text("live")).await;
    let theirs = Fcgi::start(|_| Reply::text("THEIRS")).await;
    let site = Site::finish(
        base,
        live,
        theirs,
        json!({ "address": dead.addr.to_string() }),
    )
    .await;
    site.serve_ok(json!({})).await;
    let started = Instant::now();
    let response = site.get("/hello.php").await;
    assert_eq!(response.status, 502, "{}", response.text());
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(site.fcgi.requests().is_empty());
    drop(dead);

    // A unix application that goes away and comes back: 502 while it is gone, then service again
    // without a new snapshot or a restart.
    let base = temp_base("restart");
    populate(&base);
    let socket = base.join("php.sock");
    let app = Fcgi::start_unix(&socket, |_| Reply::text("first life")).await;
    let theirs = Fcgi::start(|_| Reply::text("THEIRS")).await;
    let site = Site::finish(base, app, theirs, json!({})).await;
    site.serve_ok(json!({})).await;
    assert_eq!(site.get("/hello.php").await.text(), "first life");
    let podgate_addr = site.podgate.proxy_addr;
    let mut site = site;
    drop(std::mem::replace(
        &mut site.fcgi,
        Fcgi::start(|_| Reply::text("unused")).await,
    ));
    sleep(Duration::from_millis(100)).await;
    let gone = exchange(
        podgate_addr,
        &with_length("GET", "/hello.php", "a.test", &[], b""),
    )
    .await;
    assert_eq!(gone.status, 502, "{}", gone.text());
    drop(std::fs::remove_file(&socket));
    site.fcgi = Fcgi::start_unix(&socket, |_| Reply::text("second life")).await;
    let again = exchange(
        podgate_addr,
        &with_length("GET", "/hello.php", "a.test", &[], b""),
    )
    .await;
    assert_eq!(again.status, 200, "{}", again.text());
    assert_eq!(again.text(), "second life");
}

#[tokio::test]
async fn fastcgi_closed_idle_connection_is_replaced() {
    // Every answer is followed by a close although the client asked to keep the connection,
    // like a PHP-FPM worker that reached `pm.max_requests`. The next request finds its idle
    // connection dead (noticed before use, or on use and retried once) and still succeeds.
    let site = Site::start(|_| Reply::text("ok").then_close()).await;
    site.serve_ok(json!({})).await;
    for round in 0..4 {
        let response = site.get("/hello.php").await;
        assert_eq!(response.status, 200, "round {round}: {}", response.text());
        assert_eq!(response.text(), "ok");
    }
    assert_eq!(
        site.fcgi.requests().len(),
        4,
        "one run per request, none repeated"
    );
}

#[tokio::test]
async fn fastcgi_control_character_header_refused() {
    let site = Site::start(|_| Reply::text("ok")).await;
    site.serve_ok(json!({})).await;
    let response = exchange(
        site.podgate.proxy_addr,
        b"GET /hello.php HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\nX-Bad: a\x01b\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 400, "{}", response.text());
    assert!(
        site.fcgi.requests().is_empty(),
        "the application never saw it"
    );
}

#[tokio::test]
async fn fastcgi_slow_application_is_504() {
    let site = Site::start_with(
        |_| Reply::text("late").after(Duration::from_secs(4)),
        json!({ "read_timeout_secs": 1 }),
    )
    .await;
    site.serve_ok(json!({})).await;
    let started = Instant::now();
    let response = site.get("/hello.php").await;
    assert_eq!(response.status, 504, "{}", response.text());
    assert!(started.elapsed() < Duration::from_secs(3));
}

// -- startup ------------------------------------------------------------------------------------

#[test]
fn fastcgi_file_invalid_stops_startup() {
    let base = temp_base("startup");
    let file = base.join("fastcgi.json");
    let code = base.join("code");
    std::fs::create_dir_all(&code).expect("code dir");
    let missing = base.join("missing");
    for (content, expected) in [
        ("not json".to_owned(), "expected"),
        (
            json!({ "t1": { "php": { "address": "unix:/x", "root": "relative" } } }).to_string(),
            "not an absolute path",
        ),
        (
            json!({ "t1": { "php": { "address": "nonsense", "root": code } } }).to_string(),
            "neither unix:/path nor host:port",
        ),
        (
            json!({ "t1": { "php": { "address": "unix:/x", "root": missing } } }).to_string(),
            "not a usable directory",
        ),
        (
            json!({ "t1": { "php": { "address": "unix:/x", "root": code, "max_connections": 0 } } }).to_string(),
            "max_connections",
        ),
        (
            json!({ "t1": { "php": { "address": "unix:/x", "root": code, "bogus": 1 } } }).to_string(),
            "bogus",
        ),
        (
            json!({ "": { "php": { "address": "unix:/x", "root": code } } }).to_string(),
            "tenant id is empty",
        ),
    ] {
        std::fs::write(&file, &content).expect("write the file");
        let admin = base.join("admin.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_podgate"))
            .env("FASTCGI_FILE", &file)
            .env("ADMIN_SOCKET", &admin)
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn podgate");
        let output = child.wait_with_output().expect("podgate exits");
        assert!(!output.status.success(), "{content}: startup must fail");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("FASTCGI_FILE"), "{content}: {stderr}");
        assert!(stderr.contains(expected), "{content}: {stderr}");
        assert!(stderr.contains("fastcgi.json"), "the file is named: {stderr}");
        assert!(!admin.exists(), "nothing was bound");
    }
    std::fs::write(
        &file,
        json!({ "tenant-x": { "bad-entry": { "address": "unix:/x", "root": "relative" } } })
            .to_string(),
    )
    .expect("write");
    let output = Command::new(env!("CARGO_BIN_EXE_podgate"))
        .env("FASTCGI_FILE", &file)
        .env("ADMIN_SOCKET", base.join("admin.sock"))
        .stdin(Stdio::null())
        .output()
        .expect("run podgate");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tenant-x") && stderr.contains("bad-entry"),
        "the entry is named: {stderr}"
    );
    drop(std::fs::remove_dir_all(&base));
}
