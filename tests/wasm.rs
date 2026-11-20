//! Black-box tests for WASM request filters: real binary, filters written in WAT,
//! snapshots pushed over the admin socket.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Podgate, Response, Upstream, app, serving, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Imports and exports every filter shares; `body` is the text of `proxy_on_request_headers`.
/// Data: `x-filter` at 0, `wasm` at 16, `x-replace` at 32, `new` at 48, `x-remove` at 64,
/// `x-method` at 80, `:method` at 96, `denied` at 112. The bump allocator starts at 1024.
fn filter_module(imports: &str, memory: &str, body: &str) -> String {
    format!(
        r#"(module
  (import "env" "proxy_add_header_map_value" (func $add (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_replace_header_map_value" (func $replace (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_remove_header_map_value" (func $remove (param i32 i32 i32) (result i32)))
  (import "env" "proxy_get_header_map_value" (func $get (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_send_local_response" (func $send (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  {imports}
  (memory (export "memory") {memory})
  (data (i32.const 0) "x-filter")
  (data (i32.const 16) "wasm")
  (data (i32.const 32) "x-replace")
  (data (i32.const 48) "new")
  (data (i32.const 64) "x-remove")
  (data (i32.const 80) "x-method")
  (data (i32.const 96) ":method")
  (data (i32.const 112) "denied")
  (global $heap (mut i32) (i32.const 1024))
  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get 0)))
    (local.get $p))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    {body}))"#
    )
}

/// Adds `x-filter`, replaces `x-replace`, removes `x-remove` and copies `:method` into
/// `x-method`, which exercises writes and the allocate-and-return read path.
const EDIT_HEADERS: &str = r#"
    (drop (call $add (i32.const 0) (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 4)))
    (drop (call $replace (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 48) (i32.const 3)))
    (drop (call $remove (i32.const 0) (i32.const 64) (i32.const 8)))
    (if (i32.eqz (call $get (i32.const 0) (i32.const 96) (i32.const 7) (i32.const 128) (i32.const 132)))
      (then (drop (call $add (i32.const 0) (i32.const 80) (i32.const 8)
        (i32.load (i32.const 128)) (i32.load (i32.const 132))))))
    (i32.const 0)"#;

fn wat_filter(wat: &str, fuel: u64, max_memory_bytes: u64) -> Value {
    let wasm = wat::parse_str(wat).expect("valid WAT");
    json!({ "wasm_base64": STANDARD.encode(wasm), "fuel": fuel, "max_memory_bytes": max_memory_bytes })
}

/// An app on `host` with `filters` in front of `upstream`.
fn filtered(id: &str, host: &str, upstream: SocketAddr, filters: &[Value]) -> Value {
    let mut app = app(id, &[host], &[serving("r1", upstream)]);
    app["filters"] = json!(filters);
    app
}

/// A backend that answers with the values of the four headers the filters touch.
async fn echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
                let text = String::from_utf8_lossy(&seen).to_ascii_lowercase();
                let header = |name: &str| {
                    text.lines()
                        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
                        .unwrap_or("-")
                        .trim()
                        .to_owned()
                };
                let body = format!(
                    "{}|{}|{}|{}",
                    header("x-filter"),
                    header("x-replace"),
                    header("x-remove"),
                    header("x-method")
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                // The proxy may already have gone; nothing to do about a failed write.
                drop(stream.write_all(response.as_bytes()).await);
            });
        }
    });
    addr
}

/// `GET /` through the proxy with `Host: host` and extra headers, answered once.
async fn get_with(podgate: &Podgate, host: &str, extra: &[(&str, &str)]) -> (u16, String) {
    let mut request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in extra {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect to the proxy");
    timeout(Duration::from_secs(10), async {
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("bad response: {text:?}"));
        let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        (status, body.to_owned())
    })
    .await
    .expect("response in time")
}

async fn push(podgate: &Podgate, version: u64, apps: &[Value]) -> Response {
    podgate.push_snapshot(&snapshot(version, apps)).await
}

#[tokio::test]
async fn wasm_filter_runs() {
    let podgate = Podgate::start().await;
    let upstream = echo_upstream().await;
    let wat = filter_module("", "1", EDIT_HEADERS);
    let pushed = push(
        &podgate,
        1,
        &[filtered(
            "a",
            "a.test",
            upstream,
            &[wat_filter(&wat, 1_000_000, 4 * 65_536)],
        )],
    )
    .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let (status, body) = get_with(
        &podgate,
        "a.test",
        &[("x-replace", "old"), ("x-remove", "gone")],
    )
    .await;
    assert_eq!((status, body.as_str()), (200, "wasm|new|-|get"));

    let explained = podgate.admin_get("/v1/explain?url=http://a.test/").await;
    assert_eq!(
        explained.json()["middleware"],
        json!([
            "acme_http01",
            "route",
            "inflight_admit",
            "tenant_admit",
            "failure_capture",
            "wasm_filters"
        ])
    );
}

#[tokio::test]
async fn wasm_fuel_exhausted() {
    let podgate = Podgate::start().await;
    let slow = Upstream::start("slow-ok").await;
    let plain = Upstream::start("plain-ok").await;
    let looping = filter_module("", "1", "(loop $again (br $again)) (i32.const 0)");
    let pushed = push(
        &podgate,
        1,
        &[
            filtered(
                "loop",
                "loop.test",
                slow.addr,
                &[wat_filter(&looping, 100_000, 65_536)],
            ),
            app("plain", &["plain.test"], &[serving("r1", plain.addr)]),
        ],
    )
    .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let (looped, normal) = tokio::join!(
        get_with(&podgate, "loop.test", &[]),
        get_with(&podgate, "plain.test", &[]),
    );
    assert_eq!(looped.0, 500, "{}", looped.1);
    assert_eq!(
        serde_json::from_str::<Value>(&looped.1).expect("JSON body"),
        json!({"error": "internal error"})
    );
    assert_eq!((normal.0, normal.1.as_str()), (200, "plain-ok"));

    let (again, _) = get_with(&podgate, "loop.test", &[]).await;
    assert_eq!(again, 500, "the proxy keeps stopping the loop");
    let (still, _) = get_with(&podgate, "plain.test", &[]).await;
    assert_eq!(still, 200);
}

#[tokio::test]
async fn wasm_memory_limit() {
    let podgate = Podgate::start().await;
    let upstream = echo_upstream().await;
    // One page of memory; the filter grows it by one page and ignores the result.
    let grow = filter_module("", "1", "(drop (memory.grow (i32.const 1))) (i32.const 0)");

    let capped = push(
        &podgate,
        1,
        &[filtered(
            "a",
            "a.test",
            upstream,
            &[wat_filter(&grow, 1_000_000, 65_536)],
        )],
    )
    .await;
    assert_eq!(capped.status, 200, "{}", capped.body);
    let (status, _) = get_with(&podgate, "a.test", &[]).await;
    assert_eq!(
        status, 500,
        "growing past max_memory_bytes stops the filter"
    );

    let roomy = push(
        &podgate,
        2,
        &[filtered(
            "a",
            "a.test",
            upstream,
            &[wat_filter(&grow, 1_000_000, 2 * 65_536)],
        )],
    )
    .await;
    assert_eq!(roomy.status, 200, "{}", roomy.body);
    let (status, _) = get_with(&podgate, "a.test", &[]).await;
    assert_eq!(status, 200, "the same filter within its limit runs");

    // A module that starts out larger than its limit is refused at snapshot compile.
    let big = filter_module("", "4", "(i32.const 0)");
    let refused = push(
        &podgate,
        3,
        &[filtered(
            "a",
            "a.test",
            upstream,
            &[wat_filter(&big, 1_000_000, 65_536)],
        )],
    )
    .await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(refused.json()["conflicts"][0]["code"], "wasm_invalid");
}

#[tokio::test]
async fn wasm_forbidden_import() {
    let podgate = Podgate::start().await;
    let upstream = echo_upstream().await;
    let good = filter_module("", "1", EDIT_HEADERS);
    let pushed = push(
        &podgate,
        1,
        &[filtered(
            "a",
            "a.test",
            upstream,
            &[wat_filter(&good, 1_000_000, 65_536)],
        )],
    )
    .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    // Filesystem and socket WASI functions, another `fd_*` function and an unknown `env`
    // function: each is refused, all are reported at once.
    let imports = [
        r#"(import "wasi_snapshot_preview1" "path_open" (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))"#,
        r#"(import "wasi_snapshot_preview1" "sock_accept" (func (param i32 i32 i32) (result i32)))"#,
        r#"(import "wasi_snapshot_preview1" "fd_read" (func (param i32 i32 i32 i32) (result i32)))"#,
        r#"(import "env" "proxy_http_call" (func (param i32) (result i32)))"#,
    ];
    let filters: Vec<Value> = imports
        .iter()
        .map(|import| {
            let wat = filter_module(import, "1", "(i32.const 0)");
            wat_filter(&wat, 1_000_000, 65_536)
        })
        .collect();
    let refused = push(&podgate, 2, &[filtered("a", "a.test", upstream, &filters)]).await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    let body = refused.json();
    assert_eq!(body["error"], "snapshot rejected");
    let found: Vec<_> = body["conflicts"]
        .as_array()
        .expect("list")
        .iter()
        .map(|entry| {
            assert_eq!(entry["code"], "wasm_forbidden_import");
            assert_eq!(entry["app"], "a");
            assert_eq!(entry["declared_by"], "tests/a");
            (entry["module"].clone(), entry["name"].clone())
        })
        .collect();
    assert_eq!(
        found,
        [
            (json!("wasi_snapshot_preview1"), json!("path_open")),
            (json!("wasi_snapshot_preview1"), json!("sock_accept")),
            (json!("wasi_snapshot_preview1"), json!("fd_read")),
            (json!("env"), json!("proxy_http_call")),
        ]
    );

    let (status, body) = get_with(&podgate, "a.test", &[]).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "wasm|new|-|get"),
        "v1 keeps serving"
    );
}

#[tokio::test]
async fn wasm_invalid_module() {
    let podgate = Podgate::start().await;
    let upstream = echo_upstream().await;
    let not_wasm =
        json!({"wasm_base64": STANDARD.encode(b"not wasm"), "fuel": 1, "max_memory_bytes": 1});
    let not_base64 = json!({"wasm_base64": "***", "fuel": 1, "max_memory_bytes": 1});
    let no_exports = wat_filter("(module)", 1_000, 65_536);
    let no_fuel = wat_filter(&filter_module("", "1", "(i32.const 0)"), 0, 65_536);
    let refused = push(
        &podgate,
        1,
        &[filtered(
            "a",
            "a.test",
            upstream,
            &[not_wasm, not_base64, no_exports, no_fuel],
        )],
    )
    .await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    let conflicts = refused.json()["conflicts"].clone();
    let codes: Vec<_> = conflicts
        .as_array()
        .expect("list")
        .iter()
        .map(|entry| (entry["code"].clone(), entry["filter"].clone()))
        .collect();
    assert_eq!(
        codes,
        [
            (json!("wasm_invalid"), json!(0)),
            (json!("wasm_invalid"), json!(1)),
            (json!("wasm_invalid"), json!(2)),
            (json!("wasm_invalid"), json!(3)),
        ]
    );
}

#[tokio::test]
async fn wasm_local_response() {
    let podgate = Podgate::start().await;
    let upstream = echo_upstream().await;
    let deny = filter_module(
        "",
        "1",
        "(drop (call $send (i32.const 403) (i32.const 0) (i32.const 0) (i32.const 112) (i32.const 6) (i32.const 0) (i32.const 0) (i32.const -1))) (i32.const 1)",
    );
    let pushed = push(
        &podgate,
        1,
        &[filtered(
            "a",
            "a.test",
            upstream,
            &[wat_filter(&deny, 1_000_000, 65_536)],
        )],
    )
    .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let (status, body) = get_with(&podgate, "a.test", &[]).await;
    assert_eq!((status, body.as_str()), (403, "denied"));
}

#[tokio::test]
async fn wasm_wasip1_filter_loads() {
    let podgate = Podgate::start().await;
    let upstream = echo_upstream().await;
    // clock_time_get and fd_write, as wasm32-wasip1 modules import them. The filter checks
    // every result before it adds `x-filter`: the clock works, fd 1 and fd 2 accept a write
    // (fd 2 a 1 MiB one, which the host logs at most 4 KiB of), and fd 3 is EBADF (8).
    let wasip1 = filter_module(
        r#"(import "wasi_snapshot_preview1" "clock_time_get" (func $clock (param i32 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))"#,
        "17",
        r#"
    (i32.store (i32.const 256) (i32.const 0))
    (i32.store (i32.const 260) (i32.const 8))
    (i32.store (i32.const 272) (i32.const 1024))
    (i32.store (i32.const 276) (i32.const 1048576))
    (if (i32.and
          (i32.and
            (i32.eqz (call $clock (i32.const 0) (i64.const 0) (i32.const 200)))
            (i32.eqz (call $write (i32.const 1) (i32.const 256) (i32.const 1) (i32.const 264))))
          (i32.and
            (i32.eqz (call $write (i32.const 2) (i32.const 272) (i32.const 1) (i32.const 268)))
            (i32.and
              (i32.eq (i32.load (i32.const 268)) (i32.const 1048576))
              (i32.eq (call $write (i32.const 3) (i32.const 256) (i32.const 1) (i32.const 264))
                      (i32.const 8)))))
      (then (drop (call $add (i32.const 0) (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 4)))))
    (i32.const 0)"#,
    );
    // The filter's 17 pages are charged to the tenant, more than the default 1 MiB.
    let mut snapshot = snapshot(
        1,
        &[filtered(
            "a",
            "a.test",
            upstream,
            &[wat_filter(&wasip1, 10_000_000, 17 * 65_536)],
        )],
    );
    snapshot["tenants"][0]["budget"]["max_buffer_bytes"] = json!(2 * 1_048_576);
    let pushed = podgate.push_snapshot(&snapshot).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let (status, body) = get_with(&podgate, "a.test", &[]).await;
    assert_eq!((status, body.as_str()), (200, "wasm|-|-|-"));
}

#[tokio::test]
async fn wasm_wasip1_proc_exit_is_500() {
    let podgate = Podgate::start().await;
    let upstream = echo_upstream().await;
    let exits = filter_module(
        r#"(import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))"#,
        "1",
        "(call $exit (i32.const 1)) (i32.const 0)",
    );
    let pushed = push(
        &podgate,
        1,
        &[filtered(
            "a",
            "a.test",
            upstream,
            &[wat_filter(&exits, 1_000_000, 65_536)],
        )],
    )
    .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let (status, _) = get_with(&podgate, "a.test", &[]).await;
    assert_eq!(status, 500);
}
