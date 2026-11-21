//! The structured access log: fields, actions, filters, sampling, per-router
//! switches, hostile input, a sink that never delays requests, the file sink and its rotation,
//! and the Common Log Format.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use serde_json::{Value, json};
use tokio::time::sleep;

/// A directory of its own for the log files of one test, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-access-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create the log directory");
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// The finished lines of `path`, or none when it does not exist yet. A line podgate is still
/// writing has no newline yet and is left out.
fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| {
            let done = text.rsplit_once('\n').map_or("", |(done, _)| done);
            done.lines().map(str::to_owned).collect()
        })
        .unwrap_or_default()
}

/// Waits until `path` holds at least `count` lines and returns them.
async fn wait_for(path: &Path, count: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let found = lines(path);
        if found.len() >= count || Instant::now() > deadline {
            assert!(
                found.len() >= count,
                "{} has {} lines, wanted {count}: {found:?}",
                path.display(),
                found.len()
            );
            return found;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn parse(line: &str) -> Value {
    serde_json::from_str(line).unwrap_or_else(|err| panic!("not one JSON object ({err}): {line}"))
}

/// Podgate logging to a file in `dir`, one app `a.test` answering "hello", and the access log
/// setting `access_log`. Returns the log path.
async fn start(dir: &Dir, access_log: Value, extra: Value) -> (Podgate, Upstream, PathBuf) {
    let log = dir.file("access.log");
    let podgate =
        Podgate::start_with_env(&[("ACCESS_LOG_FILE", log.to_str().expect("utf-8 path"))]).await;
    let upstream = Upstream::start("hello").await;
    let mut pushed = snapshot(
        1,
        &[app("a.test", &["a.test"], &[serving("r1", upstream.addr)])],
    );
    pushed["observability"] = json!({ "access_log": access_log });
    if let Some(extra) = extra.as_object() {
        for (key, value) in extra {
            pushed[key] = value.clone();
        }
    }
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
    (podgate, upstream, log)
}

#[tokio::test]
async fn access_log_default_fields() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(&dir, json!({}), json!({})).await;
    let response = podgate
        .get_with_headers(
            "a.test",
            "/p?secret=1&token=abc",
            &[
                ("Authorization", "Bearer hunter2"),
                ("Cookie", "session=hunter2"),
                ("User-Agent", "probe/1"),
                ("Referer", "http://r.test/"),
            ],
        )
        .await;
    assert_eq!(response.status, 200, "{response:?}");

    let text = wait_for(&log, 1).await.remove(0);
    let line = parse(&text);
    let object = line.as_object().expect("an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut wanted = vec![
        "time",
        "request_id",
        "entry_point",
        "tenant",
        "app",
        "router",
        "service",
        "revision",
        "server",
        "method",
        "host",
        "path",
        "proto",
        "status",
        "bytes_in",
        "bytes_out",
        "duration_ms",
        "upstream_duration_ms",
        "client_ip",
        "tls_version",
        "sni",
        "retry_attempts",
        "origin",
        "reason",
    ];
    wanted.sort_unstable();
    assert_eq!(
        keys, wanted,
        "the default fields, no query, headers, user agent or referer: {text}"
    );
    for secret in ["hunter2", "secret=1", "token", "probe/1", "r.test"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    assert_eq!(line["path"], "/p");
}

#[tokio::test]
async fn access_log_values_correct() {
    let dir = Dir::new();
    let (podgate, upstream, log) = start(&dir, json!({}), json!({})).await;
    assert_eq!(podgate.get("a.test", "/x/y").await.status, 200);
    assert_eq!(podgate.get("nobody.test", "/").await.status, 404);

    let found = wait_for(&log, 2).await;
    let served = parse(&found[0]);
    let time = served["time"].as_str().expect("time");
    assert!(
        time.len() == 24 && time.ends_with('Z') && time.as_bytes().get(10) == Some(&b'T'),
        "RFC 3339 UTC with milliseconds: {time}"
    );
    assert_eq!(served["request_id"].as_str().map(str::len), Some(20));
    assert_eq!(served["entry_point"], "web");
    assert_eq!(served["tenant"], "t1");
    assert_eq!(served["app"], "a.test");
    assert_eq!(served["router"], "default");
    assert_eq!(served["service"], "web");
    assert_eq!(served["revision"], "r1");
    assert_eq!(served["server"], upstream.addr.to_string());
    assert_eq!(served["method"], "GET");
    assert_eq!(served["host"], "a.test");
    assert_eq!(served["path"], "/x/y");
    assert_eq!(served["proto"], "HTTP/1.1");
    assert_eq!(served["status"], 200);
    assert_eq!(served["bytes_in"], 0);
    assert_eq!(served["bytes_out"], 5, "hello");
    assert!(served["duration_ms"].as_f64().is_some_and(|ms| ms >= 0.0));
    assert!(
        served["upstream_duration_ms"]
            .as_f64()
            .is_some_and(|ms| ms >= 0.0)
    );
    assert!(served["upstream_duration_ms"].as_f64() <= served["duration_ms"].as_f64());
    assert_eq!(served["client_ip"], "127.0.0.1");
    assert_eq!(served["tls_version"], Value::Null);
    assert_eq!(served["sni"], Value::Null);
    assert_eq!(served["retry_attempts"], 0);
    assert_eq!(served["origin"], "upstream");
    assert_eq!(served["reason"], Value::Null);

    let missed = parse(&found[1]);
    assert_eq!(missed["status"], 404);
    assert_eq!(missed["host"], "nobody.test");
    for absent in ["tenant", "app", "router", "service", "revision", "server"] {
        assert_eq!(
            missed[absent],
            Value::Null,
            "{absent} of an unrouted request"
        );
    }
    assert_eq!(missed["upstream_duration_ms"], Value::Null);
    assert_eq!(missed["origin"], "podgate");
    assert_eq!(missed["reason"], "no_route");
}

#[tokio::test]
async fn access_log_tls_fields() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(&dir, json!({}), json!({})).await;
    let cert = TestCert::new(&["a.test"]);
    let mut pushed = snapshot(
        2,
        &[app(
            "a.test",
            &["a.test"],
            &[serving("r1", Upstream::start("tls").await.addr)],
        )],
    );
    pushed["observability"] = json!({ "access_log": {} });
    pushed["certificates"] = json!([cert.entry(&["a.test"])]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    let response = podgate.https_get("a.test", "a.test", "/", &cert).await;
    assert_eq!(response.status, 200, "{response:?}");
    let line = parse(&wait_for(&log, 1).await[0]);
    assert_eq!(line["entry_point"], "websecure");
    assert_eq!(line["sni"], "a.test");
    assert!(
        line["tls_version"]
            .as_str()
            .is_some_and(|version| version.starts_with("TLS")),
        "{line}"
    );
}

#[tokio::test]
async fn access_log_field_actions() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(
        &dir,
        json!({ "fields": {
            "names": {
                "method": "drop",
                "path": "redact",
                "query": "keep",
                "user_agent": "keep",
                "referer": "drop",
                "status": "keep"
            },
            "query_redact": ["token"]
        }}),
        json!({}),
    )
    .await;
    podgate
        .get_with_headers(
            "a.test",
            "/p?a=1&token=abc",
            &[("User-Agent", "probe/1"), ("Referer", "http://r.test/")],
        )
        .await;
    let line = parse(&wait_for(&log, 1).await[0]);
    assert!(line.get("method").is_none(), "dropped: {line}");
    assert!(line.get("referer").is_none());
    assert_eq!(line["path"], "[redacted]");
    assert_eq!(line["query"], "a=1&token=[redacted]");
    assert_eq!(line["user_agent"], "probe/1");
    assert_eq!(line["status"], 200);
    assert_eq!(line["app"], "a.test", "the rest of the default set stays");
}

#[tokio::test]
async fn access_log_default_drop_keeps_only_named_fields() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(
        &dir,
        json!({ "fields": { "default": "drop", "names": { "status": "keep", "app": "keep" }}}),
        json!({}),
    )
    .await;
    podgate.get("a.test", "/").await;
    let line = parse(&wait_for(&log, 1).await[0]);
    assert_eq!(line, json!({ "app": "a.test", "status": 200 }));
}

#[tokio::test]
async fn access_log_header_defaults() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(
        &dir,
        json!({ "headers": { "default": "keep", "names": { "x-trace": "keep", "accept": "drop" }}}),
        json!({}),
    )
    .await;
    podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("Authorization", "Bearer hunter2"),
                ("Proxy-Authorization", "Basic hunter2"),
                ("Cookie", "session=hunter2"),
                ("X-Trace", "t-1"),
                ("Accept", "text/html"),
                ("X-Other", "o-1"),
            ],
        )
        .await;
    let text = wait_for(&log, 1).await.remove(0);
    assert!(!text.contains("hunter2"), "a credential leaked: {text}");
    let line = parse(&text);
    let headers = &line["request_headers"];
    assert_eq!(headers["authorization"], "[redacted]");
    assert_eq!(headers["proxy-authorization"], "[redacted]");
    assert_eq!(headers["cookie"], "[redacted]");
    assert_eq!(headers["x-trace"], "t-1");
    assert_eq!(headers["x-other"], "o-1");
    assert!(
        headers.get("accept").is_none(),
        "dropped by name: {headers}"
    );
    assert_eq!(line["response_headers"]["content-type"], "text/plain");

    // With the default header action, nothing is logged at all.
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(&dir, json!({}), json!({})).await;
    podgate
        .get_with_headers("a.test", "/", &[("Authorization", "Bearer hunter2")])
        .await;
    let text = wait_for(&log, 1).await.remove(0);
    assert!(
        !text.contains("hunter2") && !text.contains("headers"),
        "{text}"
    );

    // Naming a credential header `keep` is the one way to log it.
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(
        &dir,
        json!({ "headers": { "names": { "authorization": "keep" }}}),
        json!({}),
    )
    .await;
    podgate
        .get_with_headers("a.test", "/", &[("Authorization", "Bearer hunter2")])
        .await;
    let line = parse(&wait_for(&log, 1).await[0]);
    assert_eq!(line["request_headers"]["authorization"], "Bearer hunter2");
}

#[tokio::test]
async fn access_log_ip_mask() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(
        &dir,
        json!({ "fields": { "names": { "client_ip": { "action": "mask", "ipv4_bits": 8 }}}}),
        json!({}),
    )
    .await;
    podgate.get("a.test", "/").await;
    let line = parse(&wait_for(&log, 1).await[0]);
    assert_eq!(line["client_ip"], "127.0.0.0");
}

#[tokio::test]
async fn access_log_filters() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(
        &dir,
        json!({ "filters": { "status_codes": ["400-599"] }}),
        json!({}),
    )
    .await;
    assert_eq!(podgate.get("a.test", "/ok").await.status, 200);
    assert_eq!(podgate.get("nobody.test", "/missing").await.status, 404);
    let found = wait_for(&log, 1).await;
    sleep(Duration::from_millis(300)).await;
    let found_later = lines(&log);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found_later.len(),
        1,
        "the 200 was filtered out: {found_later:?}"
    );
    assert_eq!(parse(&found[0])["status"], 404);

    let dir = Dir::new();
    let (podgate, _upstream, log) = start(
        &dir,
        json!({ "filters": { "min_duration_ms": 60000 }}),
        json!({}),
    )
    .await;
    podgate.get("a.test", "/").await;
    sleep(Duration::from_millis(500)).await;
    assert!(
        lines(&log).is_empty(),
        "a fast request is below the minimum"
    );
}

#[tokio::test]
async fn access_log_sampling_deterministic() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(
        &dir,
        json!({ "sampling_percent": 50 }),
        json!({ "entry_points": [
            { "name": "web", "forwarded_headers": { "trusted_ips": ["127.0.0.1"] }}
        ]}),
    )
    .await;
    let send = |round: usize| {
        let podgate = &podgate;
        async move {
            for n in 0..40 {
                let id = format!("req-{n}");
                let response = podgate
                    .get_with_headers("a.test", "/", &[("X-Request-Id", &id)])
                    .await;
                assert_eq!(response.status, 200, "round {round}");
            }
        }
    };
    send(1).await;
    sleep(Duration::from_millis(500)).await;
    let first: Vec<String> = lines(&log)
        .iter()
        .map(|line| parse(line)["request_id"].as_str().expect("id").to_owned())
        .collect();
    send(2).await;
    sleep(Duration::from_millis(500)).await;
    let both: Vec<String> = lines(&log)
        .iter()
        .map(|line| parse(line)["request_id"].as_str().expect("id").to_owned())
        .collect();
    assert!(
        !first.is_empty() && first.len() < 40,
        "about half of 40 were logged, got {}",
        first.len()
    );
    assert_eq!(both.len(), first.len() * 2, "the same ids are logged again");
    let mut doubled: Vec<String> = first.iter().chain(&first).cloned().collect();
    let mut seen = both.clone();
    doubled.sort_unstable();
    seen.sort_unstable();
    assert_eq!(
        seen, doubled,
        "the second round logged exactly the first round's ids"
    );
}

#[tokio::test]
async fn access_log_ignores_the_request_id_of_an_untrusted_client() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(&dir, json!({}), json!({})).await;
    podgate
        .get_with_headers("a.test", "/", &[("X-Request-Id", "chosen-by-client")])
        .await;
    let line = parse(&wait_for(&log, 1).await[0]);
    assert_ne!(line["request_id"], "chosen-by-client");
}

#[tokio::test]
async fn access_log_per_router_off() {
    let dir = Dir::new();
    let log = dir.file("access.log");
    let podgate =
        Podgate::start_with_env(&[("ACCESS_LOG_FILE", log.to_str().expect("utf-8 path"))]).await;
    let upstream = Upstream::start("hello").await;
    let mut quiet = app("a.test", &["a.test"], &[serving("r1", upstream.addr)]);
    quiet["routers"] = json!([
        {
            "name": "quiet",
            "match": { "all": [{ "host": "a.test" }, { "path_prefix": "/quiet" }] },
            "service": "web",
            "observability": { "access_log": false }
        },
        {
            "name": "loud",
            "match": { "all": [{ "host": "a.test" }, { "path_prefix": "/loud" }] },
            "service": "web"
        }
    ]);
    let mut pushed = snapshot(1, &[quiet]);
    pushed["observability"] = json!({ "access_log": {} });
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    assert_eq!(podgate.get("a.test", "/quiet").await.status, 200);
    assert_eq!(podgate.get("a.test", "/loud").await.status, 200);
    let found = wait_for(&log, 1).await;
    sleep(Duration::from_millis(300)).await;
    let found_later = lines(&log);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found_later.len(),
        1,
        "the quiet router logged: {found_later:?}"
    );
    assert_eq!(parse(&found[0])["router"], "loud");

    // A router can turn the log on in a snapshot that sets no policy.
    let mut on = app("a.test", &["a.test"], &[serving("r1", upstream.addr)]);
    on["routers"][0]["observability"] = json!({ "access_log": true });
    assert_eq!(podgate.push_snapshot(&snapshot(2, &[on])).await.status, 200);
    podgate.get("a.test", "/third").await;
    let found = wait_for(&log, 2).await;
    assert_eq!(parse(&found[1])["path"], "/third");
}

#[tokio::test]
async fn access_log_without_a_policy_logs_nothing() {
    let dir = Dir::new();
    let log = dir.file("access.log");
    let podgate =
        Podgate::start_with_env(&[("ACCESS_LOG_FILE", log.to_str().expect("utf-8 path"))]).await;
    let upstream = Upstream::start("hello").await;
    let pushed = snapshot(
        1,
        &[app("a.test", &["a.test"], &[serving("r1", upstream.addr)])],
    );
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    podgate.get("a.test", "/").await;
    sleep(Duration::from_millis(500)).await;
    assert!(lines(&log).is_empty());
}

#[tokio::test]
async fn access_log_invalid_settings_are_refused() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("hello").await;
    for bad in [
        json!({ "format": "xml" }),
        json!({ "fields": { "names": { "nope": "keep" }}}),
        json!({ "filters": { "status_codes": ["700"] }}),
        json!({ "sampling_percent": 150 }),
        json!({ "nonsense": true }),
    ] {
        let mut pushed = snapshot(
            1,
            &[app("a.test", &["a.test"], &[serving("r1", upstream.addr)])],
        );
        pushed["observability"] = json!({ "access_log": bad });
        let response = podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 422, "{bad}: {response:?}");
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_access_log",
            "{bad}"
        );
    }
    let mut pushed = snapshot(
        1,
        &[app("a.test", &["a.test"], &[serving("r1", upstream.addr)])],
    );
    pushed["observability"] = json!({ "metrics": { "enabled": true }});
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "observability_not_built"
    );
}

#[tokio::test]
async fn access_log_escapes_control_chars() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(&dir, json!({}), json!({})).await;
    // Raw control bytes cannot ride an HTTP/1.1 head, so the hostile text is what survives
    // parsing: quotes, braces, backslashes and encoded line breaks aimed at the line.
    let hostile = "/%0D%0A%22%7D,%22status%22:200%22x";
    let response = podgate.get("a.test", hostile).await;
    assert_eq!(response.status, 200, "{response:?}");
    podgate.get("a.test", "/after").await;
    let found = wait_for(&log, 2).await;
    assert_eq!(found.len(), 2, "one line per request: {found:?}");
    let line = parse(&found[0]);
    assert_eq!(line["path"], hostile);
    assert_eq!(line["status"], 200);
    assert_eq!(parse(&found[1])["path"], "/after");
}

#[tokio::test]
async fn access_log_truncates_long_fields() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(&dir, json!({}), json!({})).await;
    let long = format!("/{}", "a".repeat(30_000));
    let response = podgate.get("a.test", &long).await;
    assert_eq!(response.status, 200, "{:?}", response.status);
    let line = parse(&wait_for(&log, 1).await[0]);
    assert_eq!(line["path"].as_str().map(str::len), Some(2048));
    assert_eq!(line["truncated"], json!(["path"]));
}

#[tokio::test]
async fn access_log_never_blocks_requests() {
    let dir = Dir::new();
    let fifo = dir.file("sink");
    let made = Command::new("mkfifo").arg(&fifo).status().expect("mkfifo");
    assert!(made.success());
    // Nobody reads the pipe, so the writer is stuck on its first write for the whole test.
    let podgate = Arc::new(
        Podgate::start_with_env(&[("ACCESS_LOG_FILE", fifo.to_str().expect("utf-8 path"))]).await,
    );
    let upstream = Upstream::start("hello").await;
    let mut pushed = snapshot(
        1,
        &[app("a.test", &["a.test"], &[serving("r1", upstream.addr)])],
    );
    pushed["observability"] = json!({ "access_log": {} });
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let started = Instant::now();
    let total = 8_400;
    let mut sent = 0;
    while sent < total {
        let batch = 100.min(total - sent);
        let statuses = statuses(&podgate, batch).await;
        assert!(statuses.iter().all(|status| *status == 200), "{statuses:?}");
        sent += batch;
    }
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{total} requests took {:?}",
        started.elapsed()
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    let dropped: u64 = metrics
        .lines()
        .find_map(|line| line.strip_prefix("podgate_access_log_dropped_total "))
        .and_then(|value| value.trim().parse().ok())
        .expect("the drop counter is in /metrics");
    assert!(
        dropped >= 100,
        "{total} lines into an 8192 queue behind a stuck sink must drop, dropped {dropped}"
    );
}

/// `count` concurrent requests to `a.test`; their statuses.
async fn statuses(podgate: &Arc<Podgate>, count: usize) -> Vec<u16> {
    let mut tasks = Vec::with_capacity(count);
    for _ in 0..count {
        let podgate = Arc::clone(podgate);
        tasks.push(tokio::spawn(async move {
            podgate.get("a.test", "/").await.status
        }));
    }
    let mut statuses = Vec::with_capacity(count);
    for task in tasks {
        statuses.push(task.await.expect("request task"));
    }
    statuses
}

#[tokio::test]
async fn access_log_file_sink() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(&dir, json!({}), json!({})).await;
    std::fs::write(&log, "an earlier line\n").expect("seed the file");
    podgate.get("a.test", "/one").await;
    let found = wait_for(&log, 2).await;
    assert_eq!(
        found[0], "an earlier line",
        "the file is appended to, not truncated"
    );
    assert_eq!(parse(&found[1])["path"], "/one");
    podgate.get("a.test", "/two").await;
    let found = wait_for(&log, 3).await;
    assert_eq!(parse(&found[2])["path"], "/two");
}

#[tokio::test]
async fn access_log_file_rotation() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(&dir, json!({}), json!({})).await;
    podgate.get("a.test", "/before").await;
    wait_for(&log, 1).await;

    let rotated = dir.file("access.log.1");
    std::fs::rename(&log, &rotated).expect("rotate");
    // The sink compares inodes once a second.
    sleep(Duration::from_millis(1300)).await;
    podgate.get("a.test", "/after").await;
    let fresh = wait_for(&log, 1).await;
    assert_eq!(parse(&fresh[0])["path"], "/after");
    let old = lines(&rotated);
    assert_eq!(old.len(), 1, "{old:?}");
    assert_eq!(parse(&old[0])["path"], "/before");
}

#[tokio::test]
async fn access_log_common_format() {
    let dir = Dir::new();
    let (podgate, _upstream, log) = start(&dir, json!({ "format": "common" }), json!({})).await;
    podgate.get("a.test", "/p?q=1").await;
    let line = wait_for(&log, 1).await.remove(0);
    let (head, rest) = line.split_once(" [").expect("a time in brackets");
    assert_eq!(head, "127.0.0.1 - -");
    let (time, rest) = rest.split_once("] ").expect("end of the time");
    let shape: Vec<char> = time
        .chars()
        .map(|ch| if ch.is_ascii_digit() { '9' } else { ch })
        .collect();
    let shape: String = shape.into_iter().collect();
    assert!(
        shape.starts_with("99/") && shape.ends_with("9999:99:99:99 +9999") && time.len() == 26,
        "dd/Mon/yyyy:hh:mm:ss +0000, got {time}"
    );
    assert_eq!(rest, "\"GET /p HTTP/1.1\" 200 5", "no query, status, bytes");
}
