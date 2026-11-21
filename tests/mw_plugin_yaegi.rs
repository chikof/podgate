//! Traefik Go plugins through the Yaegi host: `plugins/yaegi-host`, a Go program that
//! interprets a vendored Traefik middleware plugin and speaks the plugin protocol of change 0099.
//!
//! Every test drives a real `podgate` whose `PLUGINS_FILE` declares the host as a managed plugin,
//! loading one of the example plugins in `plugins/yaegi-host/testdata/`. The host is built by
//! `scripts/build-yaegi-host.sh`, which the first test of each process runs: it needs `go` on
//! `PATH` (the devenv shell has it) and fails the test with the script's output when it cannot
//! build. The Go side has its own tests in the module (`go test ./...`).

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use common::plugin::{PidGuard, pids};
use common::{Podgate, Response, app, middleware, serving};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

/// The built host: `<target dir>/yaegi-host/yaegi-host`, made by the build script once per test
/// process (`go build` reuses its cache, so this costs a fraction of a second after the first).
static HOST_BINARY: LazyLock<PathBuf> = LazyLock::new(|| {
    let exe = std::env::current_exe().expect("the test binary's path");
    let target = exe
        .ancestors()
        .nth(3)
        .expect("target/<profile>/deps/<test binary>");
    let out = target.join("yaegi-host").join("yaegi-host");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/build-yaegi-host.sh");
    let built = Command::new(&script)
        .env("YAEGI_HOST_OUT", &out)
        .output()
        .unwrap_or_else(|err| panic!("cannot run {}: {err}", script.display()));
    assert!(
        built.status.success(),
        "{} failed (the Yaegi host needs `go`: run inside `devenv shell`):\n{}{}",
        script.display(),
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr),
    );
    out
});

fn host_binary() -> &'static Path {
    &HOST_BINARY
}

fn testdata(plugin: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("plugins/yaegi-host/testdata")
        .join(plugin)
}

/// A directory that goes away with the test.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-yaegi-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create the test directory");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// An upstream that answers every request with its own request head, lower-cased, counting them.
struct Up {
    addr: SocketAddr,
    hits: Arc<std::sync::atomic::AtomicUsize>,
}

async fn up() -> Up {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counted = Arc::clone(&counted);
            tokio::spawn(async move {
                let mut seen: Vec<u8> = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
                counted.fetch_add(1, Ordering::SeqCst);
                let text = String::from_utf8_lossy(&seen).to_ascii_lowercase();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
                drop(stream.write_all(response.as_bytes()).await);
            });
        }
    });
    Up { addr, hits }
}

impl Up {
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// A `PLUGINS_FILE` in `dir` declaring the host as the managed plugin `p`, loading the example
/// plugin `plugin` for `tenants`. The command writes its pid to a file first, so a test can tell
/// whether the host was ever started again.
fn host_entry(dir: &Dir, plugin: &str, tenants: &[&str]) -> (Value, PidGuard) {
    let pid_file = dir.join("pids");
    let entry = json!({
        "socket": dir.join("p.sock"), "tenants": tenants, "managed": true,
        "command": "/bin/sh",
        "args": [
            "-c", "echo $$ >> \"$0\"; exec \"$@\"", pid_file,
            host_binary(), "--plugin", testdata(plugin), "--name", plugin,
        ],
    });
    (entry, PidGuard(pid_file))
}

fn plugins_file(dir: &Dir, entry: &Value) -> String {
    let file = dir.join("plugins.json");
    std::fs::write(&file, json!({"p": entry}).to_string()).expect("write PLUGINS_FILE");
    file.to_str().expect("utf-8 path").to_owned()
}

/// Starts podgate with the host loading `plugin` for tenants `t1` and `t2`.
async fn start(dir: &Dir, plugin: &str) -> (Podgate, PidGuard) {
    let (entry, guard) = host_entry(dir, plugin, &["t1", "t2"]);
    let plugins = plugins_file(dir, &entry);
    let podgate = Podgate::start_logged(&[("PLUGINS_FILE", &plugins), ("RUST_LOG", "info")]).await;
    (podgate, guard)
}

const ONE_MIB: u64 = 1 << 20;

/// A snapshot of tenants `t1` and `t2` and `apps`.
fn snap(version: u64, apps: &[Value]) -> Value {
    let tenants: Vec<Value> = ["t1", "t2"]
        .iter()
        .map(|id| {
            json!({"id": id, "weight": 1, "budget": {"max_inflight": 1000, "max_buffer_bytes": ONE_MIB}})
        })
        .collect();
    json!({"version": version, "tenants": tenants, "apps": apps})
}

/// An app on `host` of `tenant` whose chain is one `plugin` middleware with `options`
/// (`config`, `timeout_ms`, `on_plugin_error`, ...).
fn site(id: &str, host: &str, tenant: &str, upstream: SocketAddr, options: &Value) -> Value {
    let mut app = app(id, &[host], &[serving("r1", upstream)]);
    app["tenant"] = json!(tenant);
    let mut declared = json!({"plugin": "p", "timeout_ms": 1000});
    if let (Some(object), Some(extra)) = (declared.as_object_mut(), options.as_object()) {
        object.extend(extra.clone());
    }
    app["middlewares"] = json!([middleware("p", "plugin", declared)]);
    app["default_chain"] = json!(["p"]);
    app
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{response:?}");
}

fn assert_closed(response: &Response) {
    assert_eq!(response.status, 503, "{response:?}");
    assert_eq!(response.body, r#"{"error":"plugin unavailable"}"#);
}

/// Waits until podgate's log, which carries the host's output, has `needle`.
async fn logged(podgate: &Podgate, needle: &str) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let log = podgate.log();
        if log.contains(needle) {
            return;
        }
        assert!(
            Instant::now() < until,
            "{needle:?} never appeared in the log:\n{log}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

/// The value of header `name` in the request head an upstream echoed.
fn echoed(response: &Response, name: &str) -> Option<String> {
    let prefix = format!("{name}: ");
    response
        .body
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
}

fn started_hosts(guard: &PidGuard) -> usize {
    pids(&guard.0).len()
}

// A plugin can edit the request and answer it.

#[tokio::test]
async fn yaegi_plugin_adds_header() {
    let dir = Dir::new("adds");
    let upstream = up().await;
    let (podgate, guard) = start(&dir, "headeradder").await;
    let config = json!({"config": {"header": "x-hello", "value": "world"}});
    push(
        &podgate,
        &snap(1, &[site("a", "a.test", "t1", upstream.addr, &config)]),
    )
    .await;
    let response = podgate
        .get_with_headers("a.test", "/p?q=1", &[("X-Keep", "k")])
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(echoed(&response, "x-hello").as_deref(), Some("world"));
    assert_eq!(echoed(&response, "x-keep").as_deref(), Some("k"));
    assert!(
        response.body.starts_with("get /p?q=1 http/1.1"),
        "{}",
        response.body
    );
    // `rw.Header().Set(..)` before `next` becomes a header of the response the client gets.
    assert_eq!(response.header("x-plugin-name"), Some("headeradder"));
    assert_eq!(started_hosts(&guard), 1, "one start of the host");
}

#[tokio::test]
async fn yaegi_plugin_responds_without_next() {
    let dir = Dir::new("responds");
    let upstream = up().await;
    let (podgate, _guard) = start(&dir, "blocker").await;
    let config = json!({"config": {"status": 451}});
    push(
        &podgate,
        &snap(1, &[site("a", "a.test", "t1", upstream.addr, &config)]),
    )
    .await;
    let blocked = podgate
        .get_with_headers("a.test", "/", &[("X-Block", "yes")])
        .await;
    assert_eq!(blocked.status, 451, "{blocked:?}");
    assert_eq!(blocked.body, "blocked by plugin\n");
    assert_eq!(blocked.header("x-blocked-by"), Some("blocker"));
    assert_eq!(blocked.header("content-type"), Some("text/plain"));
    assert_eq!(upstream.hits(), 0, "the upstream never saw the request");
    let allowed = podgate.get("a.test", "/").await;
    assert_eq!(allowed.status, 200, "{allowed:?}");
    assert_eq!(upstream.hits(), 1);
}

// Config.

#[tokio::test]
async fn yaegi_config_decoded() {
    let dir = Dir::new("config");
    let upstream = up().await;
    let (podgate, _guard) = start(&dir, "configcheck").await;
    let config = json!({"config": {
        "NAME": "n", "count": 3, "enabled": true, "tags": ["a", "b"], "labels": {"k": "v"},
        "nested": {"depth": 2, "label": "x"}, "ptr": {"depth": 5, "Label": "p"}, "plain": "pl",
    }});
    push(
        &podgate,
        &snap(
            1,
            &[
                site("a", "a.test", "t1", upstream.addr, &config),
                site("b", "b.test", "t1", upstream.addr, &json!({})),
            ],
        ),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(
        echoed(&response, "x-cfg").as_deref(),
        Some(
            "name=n count=3 enabled=true tags=a+b labels=1 nested=2/x ptr=5/p secret=kept plain=pl"
        ),
        "keys match by tag or by name, whatever the case"
    );
    // No config at all leaves what CreateConfig returned.
    let defaults = podgate.get("b.test", "/").await;
    assert!(
        echoed(&defaults, "x-cfg").is_some_and(|cfg| cfg.starts_with("name=default count=1 ")),
        "{defaults:?}"
    );
}

#[tokio::test]
async fn yaegi_unknown_config_field_rejected() {
    let dir = Dir::new("unknown-field");
    let upstream = up().await;
    let (podgate, _guard) = start(&dir, "configcheck").await;
    let typo = json!({"config": {"nme": "x"}});
    let open = json!({"config": {"nme": "x"}, "on_plugin_error": "fail_open"});
    let nested = json!({"config": {"nested": {"depht": 1}}});
    push(
        &podgate,
        &snap(
            1,
            &[
                site("a", "a.test", "t1", upstream.addr, &typo),
                site("b", "b.test", "t1", upstream.addr, &open),
                site("c", "c.test", "t1", upstream.addr, &nested),
                site("ok", "ok.test", "t1", upstream.addr, &json!({})),
            ],
        ),
    )
    .await;
    // A misspelled option never runs the plugin with its default: the call fails.
    assert_closed(&podgate.get("a.test", "/").await);
    logged(&podgate, r#"unknown config field "nme""#).await;
    // `on_plugin_error` decides what a failed call does, as for any plugin.
    let continued = podgate.get("b.test", "/").await;
    assert_eq!(continued.status, 200, "{continued:?}");
    assert_eq!(echoed(&continued, "x-cfg"), None, "the plugin did not run");
    assert_eq!(podgate.get("ok.test", "/").await.status, 200);
    assert_closed(&podgate.get("c.test", "/").await);
    logged(&podgate, r#"unknown config field "depht" in nested"#).await;
}

// What the protocol cannot carry.

/// Apps of tenant `t1` on `<mode>.test`, closed, and `open-<mode>.test`, `fail_open`, for the
/// mutator plugin in each of `modes`, and `ok.test` for a mutator that does nothing.
fn mutator_apps(upstream: SocketAddr, modes: &[&str]) -> Vec<Value> {
    let mut apps = vec![site(
        "ok",
        "ok.test",
        "t1",
        upstream,
        &json!({"config": {"mode": "none"}}),
    )];
    for mode in modes {
        let config = json!({"mode": mode});
        apps.push(site(
            &format!("closed-{mode}"),
            &format!("closed-{mode}.test"),
            "t1",
            upstream,
            &json!({"config": config}),
        ));
        apps.push(site(
            &format!("open-{mode}"),
            &format!("open-{mode}.test"),
            "t1",
            upstream,
            &json!({"config": config, "on_plugin_error": "fail_open"}),
        ));
    }
    apps
}

/// The call of `mode` fails with `plugin_unsupported_mutation` and the middleware decides:
/// `fail_closed` answers 503, `fail_open` sends the request on unchanged.
async fn assert_refused(podgate: &Podgate, mode: &str, fragment: &str) {
    let closed = podgate.get(&format!("closed-{mode}.test"), "/p?q=1").await;
    assert_closed(&closed);
    logged(podgate, &format!("plugin_unsupported_mutation: {fragment}")).await;
    let open = podgate.get(&format!("open-{mode}.test"), "/p?q=1").await;
    assert_eq!(open.status, 200, "{open:?}");
    assert!(
        open.body.starts_with("get /p?q=1 http/1.1"),
        "the request went on as it was: {}",
        open.body
    );
    assert!(!open.body.contains("rewritten") && !open.body.contains("other.test"));
    // A call that works in between: consecutive failures open the plugin's circuit.
    assert_eq!(podgate.get("ok.test", "/").await.status, 200);
}

#[tokio::test]
async fn yaegi_path_rewrite_refused() {
    let dir = Dir::new("path");
    let upstream = up().await;
    let (podgate, _guard) = start(&dir, "mutator").await;
    push(
        &podgate,
        &snap(1, &mutator_apps(upstream.addr, &["path", "query", "clone"])),
    )
    .await;
    for mode in ["path", "query", "clone"] {
        assert_refused(&podgate, mode, "the URL path or query was changed").await;
    }
}

#[tokio::test]
async fn yaegi_host_change_refused() {
    let dir = Dir::new("host");
    let upstream = up().await;
    let (podgate, _guard) = start(&dir, "mutator").await;
    push(
        &podgate,
        &snap(
            1,
            &mutator_apps(upstream.addr, &["host", "header-host", "method"]),
        ),
    )
    .await;
    assert_refused(&podgate, "host", "the host was changed").await;
    assert_refused(&podgate, "header-host", "the header host frames").await;
    assert_refused(&podgate, "method", "the method was changed").await;
}

#[tokio::test]
async fn yaegi_body_change_refused() {
    let dir = Dir::new("body");
    let upstream = up().await;
    let (podgate, _guard) = start(&dir, "mutator").await;
    push(
        &podgate,
        &snap(
            1,
            &mutator_apps(upstream.addr, &["body-replace", "body-read"]),
        ),
    )
    .await;
    for mode in ["body-replace", "body-read"] {
        assert_refused(&podgate, mode, "the request body was read or replaced").await;
    }
}

#[tokio::test]
async fn yaegi_response_wrapping_has_no_effect() {
    let dir = Dir::new("wrap");
    let upstream = up().await;
    let (podgate, _guard) = start(&dir, "mutator").await;
    push(&podgate, &snap(1, &mutator_apps(upstream.addr, &["wrap"]))).await;
    for _ in 0..2 {
        let response = podgate.get("closed-wrap.test", "/").await;
        assert_eq!(response.status, 200, "{response:?}");
    }
    logged(&podgate, "passes its own ResponseWriter to next").await;
    let log = podgate.log();
    assert_eq!(
        log.matches("passes its own ResponseWriter to next").count(),
        1,
        "said once per instance:\n{log}"
    );
}

// A plugin that goes wrong.

#[tokio::test]
async fn yaegi_panic_recovered() {
    let dir = Dir::new("panic");
    let upstream = up().await;
    let (podgate, guard) = start(&dir, "chaos").await;
    let open = json!({"on_plugin_error": "fail_open"});
    push(
        &podgate,
        &snap(
            1,
            &[
                site("a", "a.test", "t1", upstream.addr, &json!({})),
                site("b", "b.test", "t1", upstream.addr, &open),
            ],
        ),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_closed(
        &podgate
            .get_with_headers("a.test", "/", &[("X-Panic", "1")])
            .await,
    );
    logged(&podgate, "plugin went wrong on purpose").await;
    let continued = podgate
        .get_with_headers("b.test", "/", &[("X-Panic", "1")])
        .await;
    assert_eq!(continued.status, 200, "fail_open goes on: {continued:?}");
    // The host survives: same process, serving the next request.
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_eq!(started_hosts(&guard), 1, "the host was never restarted");
}

#[tokio::test]
async fn yaegi_infinite_loop_hits_deadline() {
    let dir = Dir::new("loop");
    let upstream = up().await;
    let (podgate, guard) = start(&dir, "chaos").await;
    let options = json!({"timeout_ms": 300});
    push(
        &podgate,
        &snap(1, &[site("a", "a.test", "t1", upstream.addr, &options)]),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    let started = Instant::now();
    assert_closed(
        &podgate
            .get_with_headers("a.test", "/", &[("X-Loop", "1")])
            .await,
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "answered after {:?}",
        started.elapsed()
    );
    // The host stops running the loop and serves on, in the same process.
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_eq!(started_hosts(&guard), 1, "the host was never restarted");
}

// Refusal at load.

/// Runs the host on its own and returns whether it exited with an error, its stderr, and whether
/// it created its socket.
fn run_host(dir: &Dir, plugin: &str) -> (bool, String, bool) {
    let socket = dir.join(&format!("{plugin}.sock"));
    let mut child = Command::new(host_binary())
        .arg("--plugin")
        .arg(testdata(plugin))
        .arg("--socket")
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the host");
    let until = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the host") {
            break Some(status);
        }
        if Instant::now() > until {
            // Our own child, stopped by handle.
            drop(child.kill());
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(child.wait());
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        std::io::Read::read_to_string(&mut pipe, &mut stderr).expect("read stderr");
    }
    (
        status.is_some_and(|status| !status.success()),
        stderr,
        socket.exists(),
    )
}

#[test]
fn yaegi_forbidden_imports_refused() {
    let dir = Dir::new("forbidden");
    for (plugin, reason) in [
        (
            "forbidden_unsafe",
            r#"import "unsafe" is refused: it gives unsafe memory access"#,
        ),
        (
            "forbidden_osexec",
            r#"import "os/exec" is refused: it gives starting processes"#,
        ),
        (
            "forbidden_net",
            r#"import "net" is refused: it gives network access"#,
        ),
        (
            "forbidden_cgo",
            r#"import "C" is refused: it gives cgo (native code)"#,
        ),
        (
            "forbidden_syscall",
            r#"import "syscall" is refused: it gives system calls"#,
        ),
        ("forbidden_reflect", r#"import "reflect" is refused"#),
        // The refusal covers the packages the plugin vendors, not only its own files.
        ("vendored_bad", r#"import "os/exec" is refused"#),
    ] {
        let (failed, stderr, listening) = run_host(&dir, plugin);
        assert!(
            failed,
            "{plugin}: the host did not refuse the plugin:\n{stderr}"
        );
        assert!(
            stderr.contains(reason),
            "{plugin}: expected {reason:?} in:\n{stderr}"
        );
        assert!(
            !listening,
            "{plugin}: the host listens although it refused the plugin"
        );
    }
    // A plugin that is fine starts, so the refusals above are not a broken host.
    let socket = dir.join("fine.sock");
    let mut child = Command::new(host_binary())
        .arg("--plugin")
        .arg(testdata("vendored"))
        .arg("--socket")
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the host");
    let until = Instant::now() + Duration::from_secs(10);
    while !socket.exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    let listening = socket.exists();
    drop(child.kill());
    drop(child.wait());
    assert!(
        listening,
        "the host did not start for a plugin with a vendored package"
    );
}

#[test]
fn yaegi_refused_plugin_stops_podgate_startup() {
    let dir = Dir::new("refused-startup");
    let (entry, _guard) = host_entry(&dir, "forbidden_osexec", &["t1"]);
    let plugins = plugins_file(&dir, &entry);
    let admin = dir.join("admin.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_podgate"))
        .env_remove("ENTRY_POINTS")
        .env("PROXY_ADDR", "127.0.0.1:0")
        .env("ADMIN_SOCKET", &admin)
        .env("RUST_LOG", "info")
        .env("PLUGINS_FILE", &plugins)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn podgate");
    let until = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll podgate") {
            break Some(status);
        }
        if Instant::now() > until {
            drop(child.kill());
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(child.wait());
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        std::io::Read::read_to_string(&mut pipe, &mut stderr).expect("read stderr");
    }
    assert!(
        status.is_some_and(|status| !status.success()),
        "podgate started with a plugin the host refuses:\n{stderr}"
    );
    assert!(stderr.contains(r#"cannot start plugin "p""#), "{stderr}");
}

// Instances.

#[tokio::test]
async fn yaegi_instances_per_tenant_and_config() {
    let dir = Dir::new("instances");
    let upstream = up().await;
    let (podgate, guard) = start(&dir, "headeradder").await;
    let same = json!({"config": {"value": "one"}});
    let other = json!({"config": {"value": "two"}});
    push(
        &podgate,
        &snap(
            1,
            &[
                site("a", "a.test", "t1", upstream.addr, &same),
                site("a2", "a2.test", "t1", upstream.addr, &same),
                site("b", "b.test", "t2", upstream.addr, &same),
                site("c", "c.test", "t1", upstream.addr, &other),
            ],
        ),
    )
    .await;
    let id = async |host: &str| {
        let response = podgate.get(host, "/").await;
        assert_eq!(response.status, 200, "{response:?}");
        (
            echoed(&response, "x-instance").expect("an instance id"),
            echoed(&response, "x-served").expect("a served count"),
        )
    };
    let (first, served_first) = id("a.test").await;
    let (again, served_again) = id("a.test").await;
    assert_eq!(first, again, "one tenant and one config share an instance");
    assert_eq!((served_first.as_str(), served_again.as_str()), ("1", "2"));
    // The same tenant and the same config in another app: still that instance.
    assert_eq!(id("a2.test").await.0, first);
    let (other_tenant, served) = id("b.test").await;
    assert_ne!(other_tenant, first, "tenants never share an instance");
    assert_eq!(served, "1");
    assert_ne!(
        id("c.test").await.0,
        first,
        "another config is another instance"
    );
    assert_eq!(started_hosts(&guard), 1);
}

#[tokio::test]
async fn yaegi_instance_cache_bounded() {
    // The host keeps 64 instances (docs/ref/plugin-yaegi.md); the least recently used is dropped.
    const LIMIT: usize = 64;
    let dir = Dir::new("cache");
    let upstream = up().await;
    let (podgate, _guard) = start(&dir, "headeradder").await;
    let apps: Vec<Value> = (0..=LIMIT)
        .map(|i| {
            site(
                &format!("app{i}"),
                &format!("app{i}.test"),
                "t1",
                upstream.addr,
                &json!({"config": {"value": i.to_string()}}),
            )
        })
        .collect();
    push(&podgate, &snap(1, &apps)).await;
    let id = async |i: usize| {
        let response = podgate.get(&format!("app{i}.test"), "/").await;
        assert_eq!(response.status, 200, "{response:?}");
        echoed(&response, "x-instance").expect("an instance id")
    };
    let first = id(0).await;
    assert_eq!(id(0).await, first, "an instance lives while it is in use");
    for i in 1..=LIMIT {
        id(i).await;
    }
    // 65 configs went through a cache of 64: the first, least recently used, is gone.
    assert_ne!(id(0).await, first, "the oldest instance was evicted");
    let newest = id(LIMIT).await;
    assert_eq!(id(LIMIT).await, newest, "a recent instance is kept");
}
