//! The `plugin` middleware: out-of-process plugins over a unix socket, with deadlines,
//! caps, circuits, budgets and a supervisor. The pure rules (configuration, header selection,
//! decision validation, posture, limits, `PLUGINS_FILE`) are unit-tested next to the code in
//! `src/middleware/plugin*`.
//!
//! Plugins here are the in-process servers of `tests/common/plugin.rs` unless a test is about a
//! process: those run the `echo_plugin` example, either started by the test (unmanaged) or by
//! the `podgate` under test (managed). Every process a test starts is stopped by its pid.

mod common;

use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::plugin::{
    Describe, Handler, PidGuard, Process, Reply, Server, echo, echo_plugin_path, pids,
};
use common::{Podgate, Response, app, middleware, serving};
use podgate::middleware::plugin::wire::{Action, Decision, Header, Phase, Response as Answer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// A directory that goes away with the test.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-plugin-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create the test directory");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn text(&self, name: &str) -> String {
        self.join(name).to_str().expect("utf-8 path").to_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// An upstream that answers every request with its own request head and body, counting them.
struct Up {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

async fn serve_echo(mut stream: TcpStream, hits: Arc<AtomicUsize>) {
    let mut seen: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") else {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => {
                    seen.extend_from_slice(&chunk[..read]);
                    continue;
                }
            }
        };
        let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        while seen.len() < end + 4 + length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => seen.extend_from_slice(&chunk[..read]),
            }
        }
        let body = String::from_utf8_lossy(&seen[end + 4..end + 4 + length]).into_owned();
        seen.drain(..end + 4 + length);
        hits.fetch_add(1, Ordering::SeqCst);
        let text = format!("{head}\n--body--\n{body}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Up: 1\r\nSet-Cookie: a=b\r\nContent-Length: {}\r\n\r\n{text}",
            text.len()
        );
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

async fn up() -> Up {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(serve_echo(stream, Arc::clone(&counted)));
        }
    });
    Up { addr, hits }
}

/// A `PLUGINS_FILE` in `dir` with one unmanaged plugin `p` on `socket` for `tenants`.
fn file(dir: &Dir, entries: &Value) -> String {
    std::fs::write(dir.join("plugins.json"), entries.to_string()).expect("write PLUGINS_FILE");
    dir.text("plugins.json")
}

fn unmanaged(socket: &Path, tenants: &[&str], extra: &Value) -> Value {
    let mut entry = json!({"socket": socket, "managed": false, "tenants": tenants});
    if let (Some(object), Some(extra)) = (entry.as_object_mut(), extra.as_object()) {
        object.extend(extra.clone());
    }
    entry
}

/// A snapshot of tenants `(id, weight, max_buffer_bytes)` and `apps`.
fn snap(version: u64, tenants: &[(&str, u32, u64)], apps: &[Value]) -> Value {
    let tenants: Vec<Value> = tenants
        .iter()
        .map(|(id, weight, bytes)| {
            json!({"id": id, "weight": weight, "budget": {"max_inflight": 1000, "max_buffer_bytes": bytes}})
        })
        .collect();
    json!({"version": version, "tenants": tenants, "apps": apps})
}

const ONE_MIB: u64 = 1 << 20;

/// An app on `host` of `tenant` whose chain is one `plugin` middleware `p` with `config`.
fn site(id: &str, host: &str, tenant: &str, upstream: SocketAddr, config: &Value) -> Value {
    let mut app = app(id, &[host], &[serving("r1", upstream)]);
    app["tenant"] = json!(tenant);
    let mut options = json!({"plugin": "p"});
    if let (Some(object), Some(extra)) = (options.as_object_mut(), config.as_object()) {
        object.extend(extra.clone());
    }
    app["middlewares"] = json!([middleware("p", "plugin", options)]);
    app["default_chain"] = json!(["p"]);
    app
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{response:?}");
}

fn rejection(response: &Response) -> Value {
    assert_eq!(response.status, 422, "{response:?}");
    response.json()["conflicts"][0].clone()
}

fn assert_closed(response: &Response) {
    assert_eq!(response.status, 503, "{response:?}");
    assert_eq!(response.body, r#"{"error":"plugin unavailable"}"#);
}

fn decide(decision: Decision) -> Handler {
    Arc::new(move |_| Reply::Decision(decision.clone()))
}

fn header(name: &str, value: &str) -> Header {
    Header {
        name: name.to_owned(),
        value: value.as_bytes().to_vec(),
    }
}

async fn started(dir: &Dir, server_name: &str, handler: Handler) -> (Server, String) {
    let server = Server::start(&dir.join("p.sock"), server_name, Describe::all(), handler).await;
    let plugins = file(
        dir,
        &json!({"p": unmanaged(&dir.join("p.sock"), &["t1"], &json!({}))}),
    );
    (server, plugins)
}

async fn metric(podgate: &Podgate, series: &str) -> String {
    let metrics = podgate.admin_get("/metrics").await.body;
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(series).map(|rest| rest.trim().to_owned()))
        .unwrap_or_else(|| panic!("no series {series} in:\n{metrics}"))
}

// A plugin can change what the upstream receives, what the client receives, and answer.

#[tokio::test]
async fn plugin_edits_request_headers() {
    let dir = Dir::new("edit");
    let upstream = up().await;
    let handler = decide(Decision {
        set_request_headers: vec![header("x-injected", "yes"), header("x-over", "new")],
        remove_request_headers: vec!["x-secret".into()],
        ..Decision::default()
    });
    let (server, plugins) = started(&dir, "edit", handler).await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &json!({}))],
        ),
    )
    .await;
    let response = podgate
        .get_with_headers(
            "a.test",
            "/",
            &[("X-Secret", "s"), ("X-Over", "old"), ("X-Keep", "k")],
        )
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    assert!(
        response.body.contains("x-injected: yes"),
        "{}",
        response.body
    );
    assert!(response.body.contains("x-over: new"), "{}", response.body);
    assert!(!response.body.contains("x-over: old"), "{}", response.body);
    assert!(!response.body.contains("x-secret"), "{}", response.body);
    assert!(response.body.contains("x-keep: k"), "{}", response.body);
    assert_eq!(server.calls().len(), 1);
}

#[tokio::test]
async fn plugin_adds_response_headers() {
    let dir = Dir::new("respheaders");
    let upstream = up().await;
    let handler = decide(Decision {
        add_response_headers: vec![header("x-added", "1"), header("x-added", "2")],
        ..Decision::default()
    });
    let (_server, plugins) = started(&dir, "resp", handler).await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &json!({}))],
        ),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    let added: Vec<&str> = response
        .headers
        .iter()
        .filter(|(name, _)| name == "x-added")
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(added, ["1", "2"], "{response:?}");
    assert_eq!(response.header("x-up"), Some("1"));
}

#[tokio::test]
async fn plugin_response_phase_adds_headers() {
    let dir = Dir::new("phase");
    let upstream = up().await;
    let (server, plugins) = started(
        &dir,
        "phase",
        Arc::new(|call| {
            if call.phase == Phase::ResponseHeaders as i32 {
                Reply::Decision(Decision {
                    add_response_headers: vec![header("x-seen-status", &call.status.to_string())],
                    ..Decision::default()
                })
            } else {
                Reply::Decision(Decision::default())
            }
        }),
    )
    .await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let config = json!({"phases": ["request_headers", "response_headers"]});
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &config)],
        ),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(
        response.header("x-seen-status"),
        Some("200"),
        "{response:?}"
    );
    let calls = server.calls();
    assert_eq!(calls.len(), 2, "one per phase");
    let last = &calls[1];
    assert_eq!(last.phase, Phase::ResponseHeaders as i32);
    let names: Vec<&str> = last
        .response_headers
        .iter()
        .map(|h| h.name.as_str())
        .collect();
    assert!(names.contains(&"x-up"), "{names:?}");
    assert!(
        !names.contains(&"set-cookie"),
        "set-cookie is withheld: {names:?}"
    );
}

#[tokio::test]
async fn plugin_answers_request() {
    let dir = Dir::new("answer");
    let upstream = up().await;
    let handler = decide(Decision {
        action: Action::Respond as i32,
        response: Some(Answer {
            status: 418,
            headers: vec![
                header("x-plugin", "1"),
                header("content-type", "text/plain"),
            ],
            body: b"teapot".to_vec(),
        }),
        ..Decision::default()
    });
    let (_server, plugins) = started(&dir, "answer", handler).await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &json!({}))],
        ),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(
        (response.status, response.body.as_str()),
        (418, "teapot"),
        "{response:?}"
    );
    assert_eq!(response.header("x-plugin"), Some("1"));
    assert_eq!(
        upstream.hits.load(Ordering::SeqCst),
        0,
        "the request never reached the upstream"
    );
}

#[tokio::test]
async fn plugin_request_body_phase() {
    let dir = Dir::new("body");
    let upstream = up().await;
    let (server, plugins) = started(
        &dir,
        "body",
        Arc::new(|_| Reply::Decision(Decision::default())),
    )
    .await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let config = json!({"phases": ["request_body"], "body": {"max_bytes": 1024}});
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &config)],
        ),
    )
    .await;
    let post = |body: String| {
        let addr = podgate.proxy_addr;
        async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            let request = format!(
                "POST /up HTTP/1.1\r\nHost: a.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(request.as_bytes()).await.expect("send");
            let mut raw = String::new();
            stream.read_to_string(&mut raw).await.expect("read");
            raw
        }
    };
    let raw = post("hello body".to_owned()).await;
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    assert!(
        raw.ends_with("--body--\nhello body"),
        "the upstream got the body too: {raw}"
    );
    let calls = server.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].phase, Phase::RequestBody as i32);
    assert_eq!(calls[0].body, b"hello body");
    let raw = post("x".repeat(2000)).await;
    assert!(
        raw.starts_with("HTTP/1.1 413"),
        "{}",
        &raw[..raw.len().min(200)]
    );
    assert_eq!(server.calls().len(), 1, "an oversized body is never sent");
}

// What the plugin is told.

#[tokio::test]
async fn plugin_sends_only_declared_headers() {
    let dir = Dir::new("declared");
    let upstream = up().await;
    let (server, plugins) = started(
        &dir,
        "declared",
        Arc::new(|_| Reply::Decision(Decision::default())),
    )
    .await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let config = json!({"request_headers": ["x-keep"], "config": {"k": 1}});
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &config)],
        ),
    )
    .await;
    let response = podgate
        .get_with_headers(
            "a.test",
            "/path?q=1",
            &[("X-Keep", "1"), ("X-Drop", "2"), ("User-Agent", "u")],
        )
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    let calls = server.calls();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    let names: Vec<&str> = call.headers.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, ["x-keep"]);
    assert_eq!(call.headers[0].value, b"1");
    assert_eq!(
        (
            call.method.as_str(),
            call.target.as_str(),
            call.host.as_str(),
            call.scheme.as_str()
        ),
        ("GET", "/path?q=1", "a.test", "http")
    );
    assert_eq!(
        (
            call.tenant.as_str(),
            call.app.as_str(),
            call.router.as_str(),
            call.middleware.as_str()
        ),
        ("t1", "a", "default", "p")
    );
    assert_eq!(call.client_addr, "127.0.0.1");
    assert_eq!(call.config, br#"{"k":1}"#);
    assert!(call.body.is_empty());
    assert_eq!(call.phase, Phase::RequestHeaders as i32);
}

#[tokio::test]
async fn plugin_withholds_credentials_by_default() {
    let dir = Dir::new("creds");
    let upstream = up().await;
    let (server, plugins) = started(
        &dir,
        "creds",
        Arc::new(|_| Reply::Decision(Decision::default())),
    )
    .await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let named = json!({"request_headers": ["authorization", "cookie"]});
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[
                site("a", "a.test", "t1", upstream.addr, &json!({})),
                site("b", "b.test", "t1", upstream.addr, &named),
            ],
        ),
    )
    .await;
    let credentials = [
        ("Authorization", "Bearer secret"),
        ("Proxy-Authorization", "Basic c2VjcmV0"),
        ("Cookie", "session=secret"),
        ("X-Plain", "1"),
    ];
    assert_eq!(
        podgate
            .get_with_headers("a.test", "/", &credentials)
            .await
            .status,
        200
    );
    assert_eq!(
        podgate
            .get_with_headers("b.test", "/", &credentials)
            .await
            .status,
        200
    );
    let calls = server.calls();
    let names = |app: &str| -> Vec<String> {
        calls
            .iter()
            .find(|call| call.app == app)
            .expect("a call")
            .headers
            .iter()
            .map(|h| h.name.clone())
            .collect()
    };
    let (a, b) = (names("a"), names("b"));
    assert!(a.contains(&"x-plain".to_owned()), "{a:?}");
    for secret in ["authorization", "proxy-authorization", "cookie"] {
        assert!(
            !a.iter().any(|name| name == secret),
            "{secret} is withheld unless named: {a:?}"
        );
    }
    assert!(
        b.contains(&"authorization".to_owned()) && b.contains(&"cookie".to_owned()),
        "named, they are sent: {b:?}"
    );
    assert!(
        !b.iter()
            .any(|name| name == "proxy-authorization" || name == "x-plain"),
        "only those named: {b:?}"
    );
}

// What a snapshot may name.

#[tokio::test]
async fn plugin_snapshot_cannot_choose_socket() {
    let dir = Dir::new("socket");
    let upstream = up().await;
    let (server, plugins) = started(
        &dir,
        "ok",
        Arc::new(|_| Reply::Decision(Decision::default())),
    )
    .await;
    let evil = Server::passive(&dir.join("evil.sock"), "evil").await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    for (key, value) in [
        ("socket", json!(dir.text("evil.sock"))),
        ("command", json!("/bin/sh")),
        ("args", json!(["-c", "true"])),
        ("address", json!("127.0.0.1:1")),
        ("managed", json!(true)),
        ("tenants", json!(["t1"])),
    ] {
        let mut options = json!({});
        options[key] = value;
        let response = podgate
            .push_snapshot(&snap(
                1,
                &[("t1", 1, ONE_MIB)],
                &[site("a", "a.test", "t1", upstream.addr, &options)],
            ))
            .await;
        assert_eq!(
            rejection(&response)["code"],
            "invalid_middleware",
            "{key}: {response:?}"
        );
    }
    assert_eq!(
        evil.describes() + evil.calls().len(),
        0,
        "nothing was ever sent to the socket"
    );
    drop(server);
}

#[tokio::test]
async fn unknown_plugin_rejected() {
    let dir = Dir::new("unknown");
    let upstream = up().await;
    let (_server, plugins) = started(
        &dir,
        "p",
        Arc::new(|_| Reply::Decision(Decision::default())),
    )
    .await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let response = podgate
        .push_snapshot(&snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site(
                "a",
                "a.test",
                "t1",
                upstream.addr,
                &json!({"plugin": "nope"}),
            )],
        ))
        .await;
    let entry = rejection(&response);
    assert_eq!(entry["code"], "unknown_plugin", "{response:?}");
    assert_eq!(entry["app"], "a");
    assert!(entry["at"].as_str().expect("at").contains("middleware p"));
    // Without PLUGINS_FILE no plugin exists at all.
    let bare = Podgate::start().await;
    let response = bare
        .push_snapshot(&snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &json!({}))],
        ))
        .await;
    assert_eq!(
        rejection(&response)["code"],
        "unknown_plugin",
        "{response:?}"
    );
}

#[tokio::test]
async fn plugin_forbidden_for_unlisted_tenant() {
    let dir = Dir::new("forbidden");
    let upstream = up().await;
    let (_server, plugins) = started(
        &dir,
        "p",
        Arc::new(|_| Reply::Decision(Decision::default())),
    )
    .await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let tenants = [("t1", 1, ONE_MIB), ("t2", 1, ONE_MIB)];
    let response = podgate
        .push_snapshot(&snap(
            1,
            &tenants,
            &[site("b", "b.test", "t2", upstream.addr, &json!({}))],
        ))
        .await;
    let entry = rejection(&response);
    assert_eq!(entry["code"], "plugin_forbidden", "{response:?}");
    assert_eq!(entry["app"], "b");
    // The listed tenant is let in, in the same snapshot.
    push(
        &podgate,
        &snap(
            1,
            &tenants,
            &[site("a", "a.test", "t1", upstream.addr, &json!({}))],
        ),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
}

// What a plugin may answer.

#[tokio::test]
async fn plugin_framing_header_mutation_refused() {
    let upstream = up().await;
    for (what, decision) in [
        (
            "set content-length",
            Decision {
                set_request_headers: vec![header("content-length", "5")],
                ..Decision::default()
            },
        ),
        (
            "set host",
            Decision {
                set_request_headers: vec![header("host", "evil.test")],
                ..Decision::default()
            },
        ),
        (
            "set transfer-encoding",
            Decision {
                set_request_headers: vec![header("transfer-encoding", "chunked")],
                ..Decision::default()
            },
        ),
        (
            "set connection",
            Decision {
                set_request_headers: vec![header("connection", "upgrade")],
                ..Decision::default()
            },
        ),
        (
            "remove host",
            Decision {
                remove_request_headers: vec!["host".into()],
                ..Decision::default()
            },
        ),
        (
            "add proxy header",
            Decision {
                add_response_headers: vec![header("proxy-authenticate", "x")],
                ..Decision::default()
            },
        ),
        (
            "response content-length",
            Decision {
                add_response_headers: vec![header("content-length", "0")],
                ..Decision::default()
            },
        ),
    ] {
        let dir = Dir::new("framing");
        let (_server, plugins) = started(&dir, "framing", decide(decision)).await;
        let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
        push(
            &podgate,
            &snap(
                1,
                &[("t1", 1, ONE_MIB)],
                &[site("a", "a.test", "t1", upstream.addr, &json!({}))],
            ),
        )
        .await;
        let before = upstream.hits.load(Ordering::SeqCst);
        assert_closed(&podgate.get("a.test", "/").await);
        assert_eq!(
            upstream.hits.load(Ordering::SeqCst),
            before,
            "{what}: the request went on"
        );
        let invalid = metric(
            &podgate,
            r#"podgate_plugin_calls_total{plugin="p",outcome="invalid"}"#,
        )
        .await;
        assert_eq!(invalid, "1", "{what}");
    }
}

#[tokio::test]
async fn plugin_oversized_decision_refused() {
    let dir = Dir::new("oversized");
    let upstream = up().await;
    let (_server, plugins) = started(&dir, "big", Arc::new(|_| Reply::Big(70_000))).await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &json!({}))],
        ),
    )
    .await;
    assert_closed(&podgate.get("a.test", "/").await);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    let invalid = metric(
        &podgate,
        r#"podgate_plugin_calls_total{plugin="p",outcome="invalid"}"#,
    )
    .await;
    assert_eq!(invalid, "1");
    // The cap is 64 KiB: a decision just under it is taken.
    let dir = Dir::new("undersized");
    let (_server, plugins) = started(&dir, "big", Arc::new(|_| Reply::Big(60_000))).await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &json!({}))],
        ),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(
        response.status,
        200,
        "{}",
        &response.body[..response.body.len().min(200)]
    );
    assert_eq!(response.header("x-big").map(str::len), Some(60_000));
}

// Slow, dead and crashing plugins, and what each route chose to do about it.

fn slow(delay_ms: u64) -> Handler {
    Arc::new(move |_| {
        Reply::After(
            Duration::from_millis(delay_ms),
            Box::new(Reply::Decision(Decision {
                set_request_headers: vec![header("x-plugin", "ran")],
                ..Decision::default()
            })),
        )
    })
}

#[tokio::test]
async fn plugin_timeout_fail_closed() {
    let dir = Dir::new("timeout-closed");
    let upstream = up().await;
    let (_server, plugins) = started(&dir, "slow", slow(2000)).await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site(
                "a",
                "a.test",
                "t1",
                upstream.addr,
                &json!({"timeout_ms": 100}),
            )],
        ),
    )
    .await;
    let began = Instant::now();
    assert_closed(&podgate.get("a.test", "/").await);
    let took = began.elapsed();
    assert!(
        took >= Duration::from_millis(90) && took < Duration::from_millis(1500),
        "{took:?}"
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        metric(
            &podgate,
            r#"podgate_plugin_calls_total{plugin="p",outcome="timeout"}"#
        )
        .await,
        "1"
    );
}

#[tokio::test]
async fn plugin_timeout_fail_open() {
    let dir = Dir::new("timeout-open");
    let upstream = up().await;
    let (_server, plugins) = started(&dir, "slow", slow(2000)).await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let config = json!({"timeout_ms": 100, "on_plugin_error": "fail_open"});
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site("a", "a.test", "t1", upstream.addr, &config)],
        ),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert!(
        !response.body.contains("x-plugin"),
        "the plugin's change was not applied"
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        metric(
            &podgate,
            r#"podgate_plugin_calls_total{plugin="p",outcome="failed_open"}"#
        )
        .await,
        "1"
    );
}

#[tokio::test]
async fn plugin_dead_circuit_opens() {
    let dir = Dir::new("circuit");
    let upstream = up().await;
    let (server, plugins) = started(
        &dir,
        "dead",
        Arc::new(|_| Reply::Decision(Decision::default())),
    )
    .await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let config = json!({"on_plugin_error": "fail_open"});
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[
                site("a", "a.test", "t1", upstream.addr, &json!({})),
                site("b", "b.test", "t1", upstream.addr, &config),
            ],
        ),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_eq!(
        metric(&podgate, r#"podgate_plugin_up{plugin="p"}"#).await,
        "1"
    );
    server.kill();
    // Five failed calls open the circuit; fail_open requests still go through.
    for _ in 0..5 {
        assert_eq!(podgate.get("b.test", "/").await.status, 200);
    }
    assert_eq!(
        metric(&podgate, r#"podgate_plugin_up{plugin="p"}"#).await,
        "0"
    );
    assert_eq!(
        metric(
            &podgate,
            r#"podgate_plugin_calls_total{plugin="p",outcome="transport"}"#
        )
        .await,
        "5"
    );
    assert_closed(&podgate.get("a.test", "/").await);
    assert_eq!(
        metric(
            &podgate,
            r#"podgate_plugin_calls_total{plugin="p",outcome="unavailable"}"#
        )
        .await,
        "1",
        "the sixth call was not made"
    );
    // The plugin comes back at once; the circuit still holds off for its period...
    let revived = Server::passive(&dir.join("p.sock"), "dead").await;
    assert_closed(&podgate.get("a.test", "/").await);
    assert!(
        revived.calls().is_empty(),
        "no call was made while the circuit was open"
    );
    // ...then one probe closes it.
    sleep(Duration::from_millis(5300)).await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_eq!(revived.calls().len(), 1);
    assert_eq!(
        metric(&podgate, r#"podgate_plugin_up{plugin="p"}"#).await,
        "1"
    );
}

#[tokio::test]
async fn plugin_crash_mid_run_both_modes() {
    let dir = Dir::new("crash");
    let upstream = up().await;
    let mut process = Process::start(&dir.join("p.sock")).await;
    let plugins = file(
        &dir,
        &json!({"p": unmanaged(&dir.join("p.sock"), &["t1"], &json!({}))}),
    );
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let slow_config = json!({"config": {"sleep_ms": 3000}, "timeout_ms": 1000});
    let open_config =
        json!({"config": {"sleep_ms": 3000}, "timeout_ms": 1000, "on_plugin_error": "fail_open"});
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[
                site("a", "a.test", "t1", upstream.addr, &json!({"config": {}})),
                site("closed", "closed.test", "t1", upstream.addr, &slow_config),
                site("open", "open.test", "t1", upstream.addr, &open_config),
            ],
        ),
    )
    .await;
    assert_eq!(
        podgate.get("a.test", "/").await.status,
        200,
        "the plugin works"
    );
    // Both routes have a call in flight when the plugin dies.
    let closed = podgate.get("closed.test", "/");
    let open = podgate.get("open.test", "/");
    let crash = async {
        sleep(Duration::from_millis(300)).await;
        process.crash();
    };
    let began = Instant::now();
    let (closed, open, ()) = tokio::join!(closed, open, crash);
    assert!(
        began.elapsed() < Duration::from_millis(2500),
        "the call did not wait for its deadline"
    );
    assert_closed(&closed);
    assert_eq!(open.status, 200, "{open:?}");
    // And after it: the same, with nothing to connect to.
    assert_closed(&podgate.get("closed.test", "/").await);
    assert_eq!(podgate.get("open.test", "/").await.status, 200);
}

// Calls in flight.

#[tokio::test]
async fn plugin_concurrency_capped() {
    let dir = Dir::new("capped");
    let upstream = up().await;
    let server = Server::start(&dir.join("p.sock"), "slow", Describe::all(), slow(500)).await;
    let plugins = file(
        &dir,
        &json!({"p": unmanaged(&dir.join("p.sock"), &["t1"], &json!({"max_concurrent": 2}))}),
    );
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site(
                "a",
                "a.test",
                "t1",
                upstream.addr,
                &json!({"timeout_ms": 1000}),
            )],
        ),
    )
    .await;
    let responses = futures_all((0..4).map(|_| podgate.get("a.test", "/"))).await;
    let mut statuses: Vec<u16> = responses.iter().map(|r| r.status).collect();
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 200, 503, 503], "{responses:?}");
    let refused = responses
        .iter()
        .find(|r| r.status == 503)
        .expect("a refusal");
    assert_eq!(refused.body, r#"{"error":"plugin unavailable"}"#);
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(server.peak(), 2, "the plugin never had more than two calls");
    assert_eq!(
        metric(
            &podgate,
            r#"podgate_plugin_calls_total{plugin="p",outcome="busy"}"#
        )
        .await,
        "2"
    );
    // Room is free again once the calls are over; a busy plugin is not a failed one.
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_eq!(
        metric(&podgate, r#"podgate_plugin_up{plugin="p"}"#).await,
        "1"
    );
}

/// Runs the futures at once and returns their outputs in order.
async fn futures_all<F: Future>(futures: impl Iterator<Item = F>) -> Vec<F::Output> {
    let mut set = Vec::new();
    for future in futures {
        set.push(Box::pin(future));
    }
    let mut out: Vec<Option<F::Output>> = set.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (slot, future) in out.iter_mut().zip(set.iter_mut()) {
            if slot.is_none() {
                match future.as_mut().poll(cx) {
                    std::task::Poll::Ready(value) => *slot = Some(value),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter()
        .map(|slot| slot.expect("finished"))
        .collect()
}

#[tokio::test]
async fn plugin_tenant_share_enforced() {
    let dir = Dir::new("share");
    let upstream = up().await;
    let server = Server::start(&dir.join("p.sock"), "slow", Describe::all(), slow(600)).await;
    let plugins = file(
        &dir,
        &json!({"p": unmanaged(&dir.join("p.sock"), &["t1", "t2"], &json!({"max_concurrent": 4}))}),
    );
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let config = json!({"timeout_ms": 1000});
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB), ("t2", 1, ONE_MIB)],
            &[
                site("a", "a.test", "t1", upstream.addr, &config),
                site("b", "b.test", "t2", upstream.addr, &config),
            ],
        ),
    )
    .await;
    // Tenant t1 floods: it may hold its half of the four places, and no more.
    let flood = futures_all((0..4).map(|_| podgate.get("a.test", "/")));
    let polite = async {
        sleep(Duration::from_millis(150)).await;
        futures_all((0..2).map(|_| podgate.get("b.test", "/"))).await
    };
    let (flood, polite) = tokio::join!(flood, polite);
    let mut flood: Vec<u16> = flood.iter().map(|r| r.status).collect();
    flood.sort_unstable();
    assert_eq!(flood, [200, 200, 503, 503], "t1 is held to its share");
    assert!(
        polite.iter().all(|r| r.status == 200),
        "t2 still has its places: {polite:?}"
    );
    assert_eq!(server.peak(), 4);
}

#[tokio::test]
async fn plugin_buffers_charged_to_tenant() {
    let dir = Dir::new("budget");
    let upstream = up().await;
    let (server, plugins) = started(
        &dir,
        "big",
        Arc::new(|call| {
            if call.config.starts_with(b"{\"big\"") {
                Reply::Big(40_000)
            } else {
                Reply::Decision(Decision::default())
            }
        }),
    )
    .await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let tenants = [("t1", 1, 64 * 1024)];
    push(
        &podgate,
        &snap(
            1,
            &tenants,
            &[
                site("a", "a.test", "t1", upstream.addr, &json!({})),
                site(
                    "big",
                    "big.test",
                    "t1",
                    upstream.addr,
                    &json!({"config": {"big": true}}),
                ),
            ],
        ),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    assert_eq!(
        metric(&podgate, r#"podgate_tenant_buffer_bytes{tenant="t1"}"#).await,
        "0",
        "the charge ends with the call"
    );
    // The answer would weigh twice its 40 KB: the tenant cannot pay, so it is refused.
    let refused = podgate.get("big.test", "/").await;
    assert_eq!(
        refused.status,
        503,
        "{}",
        &refused.body[..refused.body.len().min(200)]
    );
    assert_eq!(refused.body, r#"{"error":"plugin unavailable"}"#);
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(
        metric(
            &podgate,
            r#"podgate_plugin_calls_total{plugin="p",outcome="over_budget"}"#
        )
        .await,
        "1"
    );
    assert_eq!(
        metric(&podgate, r#"podgate_plugin_up{plugin="p"}"#).await,
        "1",
        "not the plugin's fault"
    );
    assert_eq!(
        metric(&podgate, r#"podgate_tenant_buffer_bytes{tenant="t1"}"#).await,
        "0"
    );
    // A request whose own headers cost more than the budget never reaches the plugin.
    let calls = server.calls().len();
    let pad = "p".repeat(40_000);
    let response = podgate
        .get_with_headers("a.test", "/", &[("X-Pad", &pad)])
        .await;
    assert_eq!(
        response.status,
        503,
        "{}",
        &response.body[..response.body.len().min(200)]
    );
    assert_eq!(
        server.calls().len(),
        calls,
        "refused before the call was built"
    );
    // A tenant over its budget is refused even when the route fails open.
    let open = json!({"on_plugin_error": "fail_open", "config": {"big": true}});
    push(
        &podgate,
        &snap(
            2,
            &tenants,
            &[site("big", "big.test", "t1", upstream.addr, &open)],
        ),
    )
    .await;
    assert_eq!(podgate.get("big.test", "/").await.status, 503);
    // A budget that cannot hold one call is a deploy error.
    let tiny = [("t1", 1, 4096)];
    let response = podgate
        .push_snapshot(&snap(
            3,
            &tiny,
            &[site("a", "a.test", "t1", upstream.addr, &json!({}))],
        ))
        .await;
    assert_eq!(
        rejection(&response)["code"],
        "invalid_middleware",
        "{response:?}"
    );
}

// A plugin that podgate runs.

fn kill_pid(pid: u32) {
    drop(
        Command::new("kill")
            .args(["-9", &pid.to_string()])
            .stderr(Stdio::null())
            .status(),
    );
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// A managed `echo_plugin`: the entry, and the file its process ids are written to.
fn managed(dir: &Dir, extra: &Value) -> (Value, PidGuard) {
    let pid_file = dir.join("pids");
    let mut entry = json!({
        "socket": dir.join("p.sock"), "tenants": ["t1"], "managed": true,
        "command": echo_plugin_path(),
        "env": {"PLUGIN_PID_FILE": pid_file},
    });
    if let (Some(object), Some(extra)) = (entry.as_object_mut(), extra.as_object()) {
        object.extend(extra.clone());
    }
    (entry, PidGuard(pid_file))
}

async fn wait_pids(file: &Path, count: usize, within: Duration) -> Vec<u32> {
    let until = Instant::now() + within;
    loop {
        let listed = pids(file);
        if listed.len() >= count {
            return listed;
        }
        assert!(
            Instant::now() < until,
            "{count} plugin starts expected, saw {listed:?}"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn plugin_managed_start_restart_backoff() {
    let dir = Dir::new("managed");
    let upstream = up().await;
    let (entry, guard) = managed(&dir, &json!({}));
    let plugins = file(&dir, &json!({"p": entry}));
    // Startup waits for the plugin: a returned `start` means it answered `Describe`.
    let podgate =
        Podgate::start_with_env(&[("PLUGINS_FILE", &plugins), ("RUST_LOG", "warn")]).await;
    let first = wait_pids(&guard.0, 1, Duration::from_secs(1)).await;
    assert_eq!(first.len(), 1);
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[site(
                "a",
                "a.test",
                "t1",
                upstream.addr,
                &json!({"config": {"set": {"x-plugin": "ran"}}, "timeout_ms": 500}),
            )],
        ),
    )
    .await;
    let response = podgate.get("a.test", "/").await;
    assert!(response.body.contains("x-plugin: ran"), "{response:?}");
    assert_eq!(
        metric(&podgate, r#"podgate_plugin_restarts_total{plugin="p"}"#).await,
        "0"
    );
    // First crash: back after one second, not at once.
    let crashed = Instant::now();
    kill_pid(first[0]);
    let two = wait_pids(&guard.0, 2, Duration::from_secs(5)).await;
    let first_gap = crashed.elapsed();
    assert!(
        first_gap >= Duration::from_millis(900),
        "restarted after {first_gap:?}"
    );
    assert_ne!(two[1], first[0]);
    // Second crash soon after: the wait doubles.
    sleep(Duration::from_millis(1500)).await;
    let crashed = Instant::now();
    kill_pid(two[1]);
    wait_pids(&guard.0, 3, Duration::from_secs(6)).await;
    let second_gap = crashed.elapsed();
    assert!(
        second_gap >= Duration::from_millis(1900),
        "restarted after {second_gap:?}"
    );
    // And the proxy serves through the new process once it is up.
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let response = podgate.get("a.test", "/").await;
        if response.status == 200 {
            assert!(response.body.contains("x-plugin: ran"));
            break;
        }
        assert_eq!(response.status, 503, "{response:?}");
        assert!(Instant::now() < until, "the plugin never came back");
        sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        metric(&podgate, r#"podgate_plugin_restarts_total{plugin="p"}"#).await,
        "2"
    );
}

#[tokio::test]
async fn plugin_shutdown_stops_process() {
    let dir = Dir::new("shutdown");
    let (entry, guard) = managed(&dir, &json!({}));
    let plugins = file(&dir, &json!({"p": entry}));
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let listed = wait_pids(&guard.0, 1, Duration::from_secs(1)).await;
    let pid = listed[0];
    assert!(alive(pid));
    drop(
        Command::new("kill")
            .args(["-TERM", &podgate.pid().to_string()])
            .status(),
    );
    let until = Instant::now() + Duration::from_secs(10);
    while alive(pid) {
        assert!(
            Instant::now() < until,
            "the plugin outlived podgate's shutdown"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

/// A cgroup v2 directory this test may create cgroups in, with the three controllers on.
struct Cgroup(PathBuf);

impl Cgroup {
    /// The first ancestor of this process's cgroup that lets it create a child with `memory`,
    /// `pids` and `cpu`. `None` on a machine that delegates none.
    fn delegated(tag: &str) -> Option<Self> {
        let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let relative = own
            .lines()
            .find_map(|line| line.strip_prefix("0::"))?
            .to_owned();
        let mut at = PathBuf::from("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
        loop {
            let child = at.join(format!("podgate-test-{tag}-{}", std::process::id()));
            if std::fs::create_dir(&child).is_ok() {
                let enabled =
                    std::fs::write(child.join("cgroup.subtree_control"), "+memory +pids +cpu");
                let has = std::fs::read_to_string(child.join("cgroup.subtree_control")).is_ok_and(
                    |text| {
                        ["memory", "pids", "cpu"]
                            .iter()
                            .all(|c| text.split_whitespace().any(|w| w == *c))
                    },
                );
                if enabled.is_ok() && has {
                    return Some(Self(child));
                }
                drop(std::fs::remove_dir(&child));
            }
            if !at.pop() || at == Path::new("/sys/fs") {
                return None;
            }
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // Whatever is left in it dies with it.
        if let Ok(children) = std::fs::read_dir(&self.0) {
            for child in children.flatten().filter(|c| c.path().is_dir()) {
                drop(std::fs::write(child.path().join("cgroup.kill"), "1"));
                for _ in 0..50 {
                    if std::fs::remove_dir(child.path()).is_ok() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        drop(std::fs::write(self.0.join("cgroup.kill"), "1"));
        drop(std::fs::remove_dir(&self.0));
    }
}

#[tokio::test]
async fn plugin_cgroup_limits_written() {
    let Some(root) = Cgroup::delegated("limits") else {
        eprintln!("skipped: no delegated cgroup v2 with memory, pids and cpu on this machine");
        return;
    };
    let dir = Dir::new("cgroup");
    let limits =
        json!({"limits": {"memory_max_bytes": 134_217_728, "pids_max": 64, "cpu_percent": 50}});
    let (entry, guard) = managed(&dir, &limits);
    let plugins = file(&dir, &json!({"p": entry}));
    let _podgate = Podgate::start_with_env(&[
        ("PLUGINS_FILE", &plugins),
        ("PLUGINS_CGROUP_ROOT", root.0.to_str().expect("utf-8")),
    ])
    .await;
    let listed = wait_pids(&guard.0, 1, Duration::from_secs(1)).await;
    let cgroup = root.0.join("p");
    let read = |file: &str| {
        std::fs::read_to_string(cgroup.join(file))
            .expect(file)
            .trim()
            .to_owned()
    };
    assert_eq!(read("memory.max"), "134217728");
    assert_eq!(read("pids.max"), "64");
    assert_eq!(read("cpu.max"), "50000 100000");
    let procs: Vec<u32> = read("cgroup.procs")
        .lines()
        .filter_map(|l| l.parse().ok())
        .collect();
    assert_eq!(procs, [listed[0]], "the plugin is in its cgroup");
}

#[tokio::test]
async fn plugin_memory_limit_kills_plugin_only() {
    let Some(root) = Cgroup::delegated("memory") else {
        eprintln!("skipped: no delegated cgroup v2 with memory, pids and cpu on this machine");
        return;
    };
    let dir = Dir::new("oom");
    let upstream = up().await;
    let (entry, guard) = managed(&dir, &json!({"limits": {"memory_max_bytes": 67_108_864}}));
    let plugins = file(&dir, &json!({"p": entry}));
    let podgate = Podgate::start_with_env(&[
        ("PLUGINS_FILE", &plugins),
        ("PLUGINS_CGROUP_ROOT", root.0.to_str().expect("utf-8")),
    ])
    .await;
    let hungry = json!({"config": {"alloc_mb": 400}, "timeout_ms": 1000});
    push(
        &podgate,
        &snap(
            1,
            &[("t1", 1, ONE_MIB)],
            &[
                site("a", "a.test", "t1", upstream.addr, &json!({})),
                site("hungry", "hungry.test", "t1", upstream.addr, &hungry),
            ],
        ),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    let first = wait_pids(&guard.0, 1, Duration::from_secs(1)).await[0];
    assert_closed(&podgate.get("hungry.test", "/").await);
    // The plugin was killed by the kernel, and only it: podgate answers and the plugin returns.
    let until = Instant::now() + Duration::from_secs(5);
    while alive(first) {
        assert!(Instant::now() < until, "the plugin was not killed");
        sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(podgate.admin_get("/readyz").await.status, 200);
    wait_pids(&guard.0, 2, Duration::from_secs(5)).await;
    let until = Instant::now() + Duration::from_secs(6);
    loop {
        let response = podgate.get("a.test", "/").await;
        if response.status == 200 {
            break;
        }
        assert!(
            Instant::now() < until,
            "the plugin never came back: {response:?}"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

// Startup.

/// Runs `podgate` with `env`; it must stop by itself. Returns whether it failed, and stderr.
fn startup_failure(dir: &Path, env: &[(&str, &str)]) -> (bool, String) {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let admin = dir.join(format!(
        "admin-{}.sock",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_podgate"))
        .env_remove("ENTRY_POINTS")
        .env("PROXY_ADDR", "127.0.0.1:0")
        .env("ADMIN_SOCKET", &admin)
        .env("RUST_LOG", "warn")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn podgate");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll podgate") {
            break Some(status);
        }
        if Instant::now() > deadline {
            drop(child.kill());
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        drop(pipe.read_to_string(&mut stderr));
    }
    drop(child.wait());
    (status.is_some_and(|status| !status.success()), stderr)
}

#[test]
fn plugin_file_invalid_stops_startup() {
    let dir = Dir::new("invalid");
    let socket = dir.text("p.sock");
    for (contents, wanted) in [
        ("not json".to_owned(), "PLUGINS_FILE"),
        (json!({"p": {"socket": socket, "tenants": [], "bogus": 1}}).to_string(), "bogus"),
        (json!({"Bad Name": {"socket": socket, "managed": false}}).to_string(), "Bad Name"),
        (json!({"p": {"socket": "relative.sock", "managed": false}}).to_string(), "absolute"),
        (json!({"p": {"socket": socket}}).to_string(), "needs a `command`"),
        (json!({"p": {"socket": socket, "managed": false, "command": "/bin/true"}}).to_string(), "managed plugin"),
        (json!({"p": {"socket": socket, "command": "/bin/true", "user": "no-such-user-podgate"}}).to_string(), "no-such-user-podgate"),
    ] {
        std::fs::write(dir.join("bad.json"), &contents).expect("write");
        let (failed, stderr) = startup_failure(&dir.0, &[("PLUGINS_FILE", &dir.text("bad.json"))]);
        assert!(failed, "{contents}: podgate did not stop:\n{stderr}");
        assert!(
            stderr.contains("PLUGINS_FILE") && stderr.contains(wanted),
            "{contents}: expected PLUGINS_FILE and {wanted:?} in:\n{stderr}"
        );
    }
    let (failed, stderr) =
        startup_failure(&dir.0, &[("PLUGINS_FILE", "/nonexistent/plugins.json")]);
    assert!(
        failed && stderr.contains("/nonexistent/plugins.json"),
        "{stderr}"
    );
    let (failed, stderr) = startup_failure(&dir.0, &[("PLUGINS_CGROUP_ROOT", "/sys/fs/cgroup/x")]);
    assert!(failed && stderr.contains("PLUGINS_CGROUP_ROOT"), "{stderr}");
}

#[test]
fn plugin_limits_without_cgroup_root_stops_startup() {
    let dir = Dir::new("nolimits");
    let entry = json!({"hungry": {
        "socket": dir.text("h.sock"), "command": "/bin/true", "tenants": ["t1"],
        "limits": {"memory_max_bytes": 67_108_864},
    }});
    std::fs::write(dir.join("plugins.json"), entry.to_string()).expect("write");
    let (failed, stderr) = startup_failure(&dir.0, &[("PLUGINS_FILE", &dir.text("plugins.json"))]);
    assert!(
        failed,
        "podgate started with a limit it cannot apply:\n{stderr}"
    );
    assert!(
        stderr.contains("hungry") && stderr.contains("PLUGINS_CGROUP_ROOT"),
        "the plugin and the variable are named:\n{stderr}"
    );
}

#[tokio::test]
async fn plugin_describe_required() {
    let dir = Dir::new("describe");
    let make = |name: &str| -> Value {
        let path = dir.join(&format!("{name}.sock"));
        json!({name: {"socket": path, "managed": false, "tenants": ["t1"]}})
    };
    let idle: Handler = Arc::new(|_| Reply::Decision(Decision::default()));
    let unimplemented = Server::start(
        &dir.join("noop.sock"),
        "noop",
        Describe::Status(12),
        Arc::clone(&idle),
    )
    .await;
    let future = Server::start(
        &dir.join("future.sock"),
        "future",
        Describe::Version(2),
        idle,
    )
    .await;
    let run = |entries: Value, wanted: &'static str| {
        let (dir_path, file_path) = (dir.0.clone(), {
            std::fs::write(dir.join(&format!("{wanted}.json")), entries.to_string())
                .expect("write");
            dir.text(&format!("{wanted}.json"))
        });
        tokio::task::spawn_blocking(move || {
            startup_failure(&dir_path, &[("PLUGINS_FILE", &file_path)])
        })
    };
    // A plugin that answers an error, one that speaks another version, one that never listens
    // and a managed one that starts and never describes itself.
    let never_listens = make("silent");
    let mut stuck = json!({"stuck": {
        "socket": dir.join("stuck.sock"), "tenants": ["t1"], "managed": true,
        "command": "/bin/sh", "args": ["-c", "exec sleep 60"],
    }});
    stuck["stuck"]["env"] = json!({"PATH": std::env::var("PATH").unwrap_or_default()});
    let (noop, version, silent, stuck_run) = tokio::join!(
        run(make("noop"), "noop"),
        run(make("future"), "future"),
        run(never_listens, "silent"),
        run(stuck, "stuck"),
    );
    for (outcome, plugin, why) in [
        (noop, "noop", "UNIMPLEMENTED"),
        (version, "future", "protocol version 2"),
        (silent, "silent", "did not answer Describe"),
        (stuck_run, "stuck", "did not answer Describe"),
    ] {
        let (failed, stderr) = outcome.expect("the run finished");
        assert!(failed, "{plugin}: podgate did not stop:\n{stderr}");
        assert!(
            stderr.contains(&format!("\"{plugin}\"")) && stderr.contains(why),
            "{plugin}: expected the plugin and {why:?} in:\n{stderr}"
        );
    }
    drop((unimplemented, future));
    // The same plugins, answering, start.
    let (_server, plugins) = started(&Dir::new("describe-ok"), "ok", Arc::new(echo)).await;
    drop(plugins);
}

#[tokio::test]
async fn plan_lists_plugin_changes() {
    let dir = Dir::new("plan");
    let upstream = up().await;
    let (_server, plugins) = started(
        &dir,
        "plan",
        Arc::new(|_| Reply::Decision(Decision::default())),
    )
    .await;
    let podgate = Podgate::start_with_env(&[("PLUGINS_FILE", &plugins)]).await;
    let tenants = [("t1", 1, ONE_MIB)];
    let guarded = |version: u64, config: &Value| {
        snap(
            version,
            &tenants,
            &[site("a", "a.test", "t1", upstream.addr, config)],
        )
    };
    push(
        &podgate,
        &guarded(
            1,
            &json!({"phases": ["request_headers", "response_headers"]}),
        ),
    )
    .await;
    let plan = |snapshot: Value| {
        let podgate = &podgate;
        async move {
            let plan = podgate.admin_post("/v1/snapshot/plan", &snapshot).await;
            assert_eq!(plan.status, 200, "{}", plan.body);
            plan.json()["posture_changes"].clone()
        }
    };
    assert_eq!(
        plan(guarded(2, &json!({"phases": ["request_headers", "response_headers"], "on_plugin_error": "fail_open"}))).await,
        json!([{"host": "a.test", "app": "a", "kind": "plugin_fail_open"}])
    );
    let removed = snap(
        2,
        &tenants,
        &[app("a", &["a.test"], &[serving("r1", upstream.addr)])],
    );
    assert_eq!(
        plan(removed).await,
        json!([{"host": "a.test", "app": "a", "kind": "plugin_removed"}])
    );
    assert_eq!(
        plan(guarded(2, &json!({}))).await,
        json!([{"host": "a.test", "app": "a", "kind": "plugin_phases_removed"}])
    );
    // Closing, or changing what only tightens, is no relaxation; nothing was applied.
    assert_eq!(
        plan(guarded(
            2,
            &json!({"phases": ["request_headers", "response_headers"], "timeout_ms": 200})
        ))
        .await,
        json!([])
    );
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
}
