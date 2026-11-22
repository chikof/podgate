//! End to end: requests are admitted through a per-backend limiter, visible on `GET /metrics`.
//! The weighted order and the limit's behaviour are unit tests in `src/fairq.rs`; the load test is
//! `scripts/load-fairness.sh`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Podgate, Response, Upstream, app, serving, simple_snapshot, snapshot};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn backend_metrics_report_the_limit() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("hello").await;
    let pushed = podgate
        .push_snapshot(&simple_snapshot(1, &[("a.test", upstream.addr)]))
        .await;
    assert_eq!(pushed.status, 200);

    for _ in 0..5 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!((response.status, response.body.as_str()), (200, "hello"));
    }

    let metrics = podgate.admin_get("/metrics").await.body;
    let backend = upstream.addr;
    assert!(
        metrics.contains(&format!(
            "podgate_backend_limit{{backend=\"{backend}\"}} 32\n"
        )),
        "{metrics}"
    );
    assert!(
        metrics.contains(&format!(
            "podgate_backend_inflight{{backend=\"{backend}\"}} 0\n"
        )),
        "every slot came back: {metrics}"
    );
    assert!(
        metrics.contains(&format!(
            "podgate_backend_waited_total{{backend=\"{backend}\"}} 0\n"
        )),
        "{metrics}"
    );
}

/// An upstream that answers every request with `200 ok` after `delay`.
async fn slow_upstream(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    while let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                        seen.drain(..end + 4);
                        tokio::time::sleep(delay).await;
                        let reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
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

/// A settings file that is removed when the test ends.
struct LimiterFile(PathBuf);

impl LimiterFile {
    fn write(name: &str, contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "podgate-limiter-{}-{name}.json",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write the settings file");
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().expect("utf-8 path")
    }
}

impl Drop for LimiterFile {
    fn drop(&mut self) {
        drop(std::fs::remove_file(&self.0));
    }
}

/// Sends `count` requests for `a.test` at once and returns the responses.
async fn burst(podgate: &Arc<Podgate>, count: usize) -> Vec<Response> {
    let requests: Vec<_> = (0..count)
        .map(|_| {
            let podgate = Arc::clone(podgate);
            tokio::spawn(async move { podgate.get("a.test", "/").await })
        })
        .collect();
    let mut responses = Vec::new();
    for request in requests {
        responses.push(request.await.expect("request task"));
    }
    responses
}

fn one_app(addr: SocketAddr) -> serde_json::Value {
    snapshot(1, &[app("a", &["a.test"], &[serving("r1", addr)])])
}

#[tokio::test]
async fn backend_limiter_file_turns_the_limiter_off() {
    let upstream = slow_upstream(Duration::from_millis(300)).await;
    let waited = |metrics: &str| {
        let line = format!("podgate_backend_waited_total{{backend=\"{upstream}\"}} ");
        metrics
            .lines()
            .find_map(|row| row.strip_prefix(&line))
            .and_then(|value| value.parse::<u64>().ok())
            .expect("a waited_total row")
    };

    let limited = Arc::new(Podgate::start().await);
    assert_eq!(limited.push_snapshot(&one_app(upstream)).await.status, 200);
    let responses = burst(&limited, 64).await;
    assert!(responses.iter().all(|response| response.status == 200));
    let metrics = limited.admin_get("/metrics").await.body;
    assert!(
        waited(&metrics) > 0,
        "64 at once pass the initial limit of 32, so some queue: {metrics}"
    );

    let file = LimiterFile::write("off", r#"{"default": {"enabled": false}}"#);
    let free = Arc::new(Podgate::start_with_env(&[("BACKEND_LIMITER_FILE", file.path())]).await);
    assert_eq!(free.push_snapshot(&one_app(upstream)).await.status, 200);
    let responses = burst(&free, 64).await;
    assert!(responses.iter().all(|response| response.status == 200));
    let metrics = free.admin_get("/metrics").await.body;
    assert_eq!(waited(&metrics), 0, "{metrics}");
    assert!(
        metrics.contains(&format!(
            "podgate_backend_limit{{backend=\"{upstream}\"}} 4294967295\n"
        )),
        "the series is still rendered: {metrics}"
    );
    assert!(
        metrics.contains(&format!(
            "podgate_backend_refused_total{{backend=\"{upstream}\"}} 0\n"
        )),
        "{metrics}"
    );
}

#[tokio::test]
async fn a_disabled_backend_limiter_leaves_the_tenant_cap() {
    let upstream = slow_upstream(Duration::from_millis(1500)).await;
    let file = LimiterFile::write("cap", r#"{"default": {"enabled": false}}"#);
    let podgate = Arc::new(Podgate::start_with_env(&[("BACKEND_LIMITER_FILE", file.path())]).await);
    let mut snapshot = one_app(upstream);
    snapshot["tenants"][0]["budget"] =
        serde_json::json!({ "max_inflight": 2, "max_buffer_bytes": 1_048_576 });
    assert_eq!(podgate.push_snapshot(&snapshot).await.status, 200);

    let held = tokio::spawn({
        let podgate = Arc::clone(&podgate);
        async move { burst(&podgate, 2).await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let refused = podgate.get("a.test", "/").await;
    assert_eq!(refused.status, 503);
    assert_eq!(
        refused.body,
        r#"{"error":"tenant is over its in-flight limit"}"#
    );
    for response in held.await.expect("held requests") {
        assert_eq!(response.status, 200);
    }
}

#[tokio::test]
async fn queue_wait_and_size_come_from_the_file() {
    let upstream = slow_upstream(Duration::from_millis(2000)).await;
    let file = LimiterFile::write(
        "queue",
        r#"{"default": {"initial_limit": 1, "min_limit": 1, "max_limit": 1, "queue_wait_ms": 200}}"#,
    );
    let podgate = Arc::new(Podgate::start_with_env(&[("BACKEND_LIMITER_FILE", file.path())]).await);
    assert_eq!(podgate.push_snapshot(&one_app(upstream)).await.status, 200);

    let first = tokio::spawn({
        let podgate = Arc::clone(&podgate);
        async move { podgate.get("a.test", "/").await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let started = Instant::now();
    let waiting = podgate.get("a.test", "/").await;
    assert_eq!(waiting.status, 503, "{waiting:?}");
    assert_eq!(waiting.body, r#"{"error":"backend is saturated"}"#);
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "gave up after 200 ms, not the 5 s default: {:?}",
        started.elapsed()
    );
    assert_eq!(first.await.expect("first request").status, 200);
}

/// Runs podgate with `BACKEND_LIMITER_FILE=path` and returns whether it exited by itself with a
/// failure, and its stderr. A process that started serving is killed and counts as not stopped.
fn start_with_limiter_file(path: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("podgate-bad-limiter-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let mut child = Command::new(env!("CARGO_BIN_EXE_podgate"))
        .env("PROXY_ADDR", "127.0.0.1:0")
        .env("ADMIN_SOCKET", dir.join("admin.sock"))
        .env("BACKEND_LIMITER_FILE", path)
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn podgate");
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll podgate") {
            break Some(status);
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if status.is_none() {
        drop(child.kill());
    }
    let output = child.wait_with_output().expect("collect output");
    drop(std::fs::remove_dir_all(&dir));
    (
        status.is_some_and(|status| !status.success()),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_bad_limiter_file_stops_startup_naming_the_field() {
    for (contents, field) in [
        (r#"{"default": {"max_limit": -1}}"#, "default.max_limit"),
        (
            r#"{"backends": {"10.0.0.0/8": {"min_limit": 9, "max_limit": 3}}}"#,
            r#"backends["10.0.0.0/8"].min_limit"#,
        ),
        (r#"{"backends": {"nope": {}}}"#, r#"backends["nope"]"#),
    ] {
        let file = LimiterFile::write("bad", contents);
        let (failed, stderr) = start_with_limiter_file(file.path());
        assert!(failed, "{contents}: podgate did not stop:\n{stderr}");
        assert!(
            stderr.contains("BACKEND_LIMITER_FILE") && stderr.contains(field),
            "{contents}: expected the variable and {field:?} in:\n{stderr}"
        );
    }
}
