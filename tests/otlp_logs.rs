//! Access logs over OTLP through the real binary, against the fake collector of
//! `tests/common/otlp.rs`. The records are the JSON line's, so the tests compare them with the
//! line a file sink wrote for the same request; the transport (retries, TLS, headers) is the
//! shared exporter's and is tested for spans in `tests/tracing*.rs`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::otlp::{Collector, Received, Reply, Tls, Wire};
use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use podgate::observe::access_log::proto::{ExportLogsServiceRequest, LogRecord};
use podgate::observe::otlp::common::any_value::Value as Any;
use podgate::observe::tracing::proto::ExportTraceServiceRequest;
use serde_json::{Value, json};
use tokio::task::JoinSet;
use tokio::time::sleep;

const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT: &str = "00f067aa0ba902b7";

const LOGS_HTTP: &str = "/v1/logs";
const LOGS_GRPC: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

fn env_of(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn pairs(env: &[(String, String)]) -> Vec<(&str, &str)> {
    env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// A directory of its own for the files of one test, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("podgate-otlp-logs-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create the directory");
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

/// The environment of a node that sends its access log to `collector`.
fn logs_env(collector: &Collector) -> Vec<(String, String)> {
    let mut env = collector.env();
    env.extend(env_of(&[
        ("OTEL_LOGS_EXPORTER", "otlp"),
        ("OTEL_EXPORTER_OTLP_TIMEOUT", "1000"),
    ]));
    env
}

/// One app `a.test` answering "hello", with `observability` as the snapshot's.
async fn push(podgate: &Podgate, upstream: &Upstream, version: u64, observability: Value) {
    push_with(podgate, upstream, version, observability, None).await;
}

/// [`push`], and the router's own `observability` switches when `router` is given.
async fn push_with(
    podgate: &Podgate,
    upstream: &Upstream,
    version: u64,
    observability: Value,
    router: Option<Value>,
) {
    let mut one = app("a.test", &["a.test"], &[serving("r1", upstream.addr)]);
    if let Some(router) = router {
        one["routers"][0]["observability"] = router;
    }
    let mut pushed = snapshot(version, &[one]);
    pushed["observability"] = observability;
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
}

async fn start(env: &[(String, String)], access_log: Value) -> (Podgate, Upstream) {
    let podgate = Podgate::start_with_env(&pairs(env)).await;
    let upstream = Upstream::start("hello").await;
    push(&podgate, &upstream, 1, json!({ "access_log": access_log })).await;
    (podgate, upstream)
}

// ---------------------------------------------------------------------------------------
// Reading what the collector got
// ---------------------------------------------------------------------------------------

fn is_logs(call: &Received) -> bool {
    call.path == LOGS_HTTP || call.path == LOGS_GRPC
}

/// Every log record the collector accepted so far, oldest first.
fn records(collector: &Collector) -> Vec<LogRecord> {
    collector
        .received()
        .iter()
        .filter(|call| is_logs(call) && call.accepted)
        .flat_map(|call| {
            call.decode::<ExportLogsServiceRequest>()
                .resource_logs
                .into_iter()
                .flat_map(|resource| resource.scope_logs)
                .flat_map(|scope| scope.log_records)
        })
        .collect()
}

/// Waits for `count` records and returns them all.
async fn wait_records(collector: &Collector, count: usize) -> Vec<LogRecord> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let found = records(collector);
        if found.len() >= count {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "wanted {count} log records, the collector got {}",
            found.len()
        );
        sleep(Duration::from_millis(100)).await;
    }
}

/// The record of the request for `path`.
fn record_for<'a>(records: &'a [LogRecord], path: &str) -> &'a LogRecord {
    records
        .iter()
        .find(|record| attr(record, "url.path") == Some(Any::String(path.to_owned())))
        .unwrap_or_else(|| panic!("no record for {path}: {records:#?}"))
}

fn attr(record: &LogRecord, key: &str) -> Option<Any> {
    record
        .attributes
        .iter()
        .find(|pair| pair.key == key)
        .and_then(|pair| pair.value.as_ref()?.value.clone())
}

fn text(record: &LogRecord, key: &str) -> Option<String> {
    match attr(record, key)? {
        Any::String(text) => Some(text),
        other => panic!("{key} is not a string: {other:?}"),
    }
}

fn list_of_one(record: &LogRecord, key: &str) -> Option<String> {
    let Any::Array(array) = attr(record, key)? else {
        panic!("{key} is not a list");
    };
    match array.values.first()?.value.clone()? {
        Any::String(text) => Some(text),
        other => panic!("{key} holds {other:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn metric_value(metrics: &str, name: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(name)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("{name} is not in /metrics:\n{metrics}"))
}

async fn wait_metric(podgate: &Podgate, name: &str, at_least: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let metrics = podgate.admin_get("/metrics").await.body;
        let value = metric_value(&metrics, name);
        if value >= at_least {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "{name} is {value}, wanted {at_least}"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

/// The finished lines of `path`.
fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------
// The record is the line
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn otlp_logs_off_by_default() {
    let collector = Collector::http().await;
    // The collector is configured (for spans, say) but the log exporter is not asked for.
    let (podgate, _upstream) = start(&collector.env(), json!({})).await;
    assert_eq!(podgate.get("a.test", "/").await.status, 200);
    sleep(Duration::from_millis(3500)).await;
    assert_eq!(collector.requests(), 0, "nothing was sent");
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        !metrics.contains("podgate_access_log_otlp_"),
        "no exporter, no series:\n{metrics}"
    );
    assert!(metrics.contains("podgate_access_log_dropped_total"));
}

#[tokio::test]
async fn otlp_logs_bad_settings_stop_startup() {
    let cases: [&[(&str, &str)]; 4] = [
        &[
            ("OTEL_LOGS_EXPORTER", "console"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
        ],
        &[
            ("OTEL_LOGS_EXPORTER", "otlp,none"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
        ],
        &[("OTEL_LOGS_EXPORTER", "otlp")],
        &[
            ("OTEL_LOGS_EXPORTER", " "),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
        ],
    ];
    for vars in cases {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_podgate"));
        command.env(
            "ADMIN_SOCKET",
            std::env::temp_dir().join("podgate-otlp-logs-bad.sock"),
        );
        for (var, value) in vars {
            command.env(var, value);
        }
        let output = command.output().expect("run podgate");
        assert!(!output.status.success(), "{vars:?} must stop startup");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("OTEL_LOGS_EXPORTER"),
            "the error names OTEL_LOGS_EXPORTER for {vars:?}: {stderr}"
        );
    }
}

#[tokio::test]
async fn otlp_logs_match_json_line_http() {
    let dir = Dir::new("match");
    let file = dir.file("access.log");
    let collector = Collector::http().await;
    let mut env = logs_env(&collector);
    env.extend(env_of(&[
        ("ACCESS_LOG_FILE", file.to_str().expect("utf-8 path")),
        ("OTEL_EXPORTER_OTLP_HEADERS", "x-api-key=s3cret"),
        ("OTEL_SERVICE_NAME", "edge"),
    ]));
    let (podgate, _upstream) = start(&env, json!({})).await;

    let response = podgate.get("a.test", "/p").await;
    assert_eq!((response.status, response.body.as_str()), (200, "hello"));

    let found = wait_records(&collector, 1).await;
    assert_eq!(found.len(), 1, "one request, one record");
    let record = &found[0];
    let line: Value = serde_json::from_str(&lines(&file)[0]).expect("the JSON line");

    let call = collector
        .received()
        .into_iter()
        .find(is_logs)
        .expect("a logs call");
    assert_eq!(call.path, LOGS_HTTP);
    assert_eq!(call.header("content-type"), Some("application/x-protobuf"));
    assert_eq!(call.header("x-api-key"), Some("s3cret"));
    let request = call.decode::<ExportLogsServiceRequest>();
    let resource = request.resource_logs[0]
        .resource
        .as_ref()
        .expect("resource");
    assert_eq!(resource.attributes[0].key, "service.name");
    assert_eq!(
        resource.attributes[0]
            .value
            .as_ref()
            .and_then(|v| v.value.clone()),
        Some(Any::String("edge".to_owned()))
    );

    for (attribute, field) in [
        ("http.request.method", "method"),
        ("url.path", "path"),
        ("podgate.tenant", "tenant"),
        ("podgate.app", "app"),
        ("podgate.router", "router"),
        ("podgate.service", "service"),
        ("podgate.revision", "revision"),
        ("podgate.upstream.address", "server"),
        ("server.address", "host"),
        ("podgate.request.id", "request_id"),
        ("podgate.entry_point", "entry_point"),
        ("client.address", "client_ip"),
        ("podgate.origin", "origin"),
    ] {
        assert_eq!(
            text(record, attribute).as_deref(),
            line[field].as_str(),
            "{attribute} is the line's {field}"
        );
    }
    assert_eq!(
        attr(record, "http.response.status_code"),
        Some(Any::Int(line["status"].as_i64().expect("status")))
    );
    assert_eq!(
        attr(record, "http.response.body.size"),
        Some(Any::Int(line["bytes_out"].as_i64().expect("bytes")))
    );
    for (attribute, field) in [
        ("podgate.duration_ms", "duration_ms"),
        ("podgate.upstream.duration_ms", "upstream_duration_ms"),
    ] {
        let Some(Any::Double(milliseconds)) = attr(record, attribute) else {
            panic!("{attribute} is a double");
        };
        let wanted = line[field].as_f64().expect(field);
        assert!(
            (milliseconds - wanted).abs() < 1e-6,
            "{attribute} {milliseconds} is the line's {wanted}"
        );
    }
    assert_eq!(
        text(record, "network.protocol.version").as_deref(),
        Some("1.1")
    );
    assert_eq!(record.severity_number, 9);
    assert_eq!(record.event_name, "podgate.access_log");
    assert!(
        record.trace_id.is_empty() && record.span_id.is_empty(),
        "no tracing here"
    );
    assert!(record.time_unix_nano > 0);

    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric_value(&metrics, "podgate_access_log_otlp_exported_total "),
        1
    );
    assert_eq!(
        metric_value(&metrics, "podgate_access_log_otlp_dropped_total "),
        0
    );
    assert_eq!(metric_value(&metrics, "podgate_access_log_lines_total "), 1);
}

#[tokio::test]
async fn otlp_logs_carry_trace_ids() {
    let collector = Collector::http().await;
    let (podgate, upstream) = start(&logs_env(&collector), json!({})).await;
    push(
        &podgate,
        &upstream,
        2,
        json!({ "access_log": {}, "tracing": { "sample_percent": 100 } }),
    )
    .await;

    let traceparent = format!("00-{TRACE}-{PARENT}-01");
    podgate
        .get_with_headers("a.test", "/traced", &[("traceparent", &traceparent)])
        .await;
    let found = wait_records(&collector, 1).await;
    let traced = record_for(&found, "/traced");
    assert_eq!(
        hex(&traced.trace_id),
        TRACE,
        "the incoming trace is continued"
    );
    assert_eq!(traced.span_id.len(), 8);
    assert_eq!(traced.flags, 1, "sampled");

    // The record's span id is the proxy's server span, which the collector also received.
    let deadline = Instant::now() + Duration::from_secs(20);
    let server_span = loop {
        let spans: Vec<_> = collector
            .received()
            .iter()
            .filter(|call| call.path == "/v1/traces")
            .flat_map(|call| {
                call.decode::<ExportTraceServiceRequest>()
                    .resource_spans
                    .into_iter()
                    .flat_map(|resource| resource.scope_spans)
                    .flat_map(|scope| scope.spans)
            })
            .filter(|span| span.kind == 2)
            .collect();
        if let Some(span) = spans.into_iter().next() {
            break span;
        }
        assert!(Instant::now() < deadline, "the server span never arrived");
        sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(server_span.span_id, traced.span_id);
    assert_eq!(server_span.trace_id, traced.trace_id);

    // Traced but not sampled: the ids are there, the sampled flag is not.
    push(
        &podgate,
        &upstream,
        3,
        json!({ "access_log": {}, "tracing": { "sample_percent": 0 } }),
    )
    .await;
    podgate.get("a.test", "/unsampled").await;
    let found = wait_records(&collector, 2).await;
    let unsampled = record_for(&found, "/unsampled");
    assert_eq!(unsampled.trace_id.len(), 16);
    assert_eq!(unsampled.span_id.len(), 8);
    assert_eq!(unsampled.flags, 0);

    // A router that is not traced has no ids.
    push_with(
        &podgate,
        &upstream,
        4,
        json!({ "access_log": {}, "tracing": {} }),
        Some(json!({ "tracing": false })),
    )
    .await;
    podgate.get("a.test", "/untraced").await;
    let found = wait_records(&collector, 3).await;
    let untraced = record_for(&found, "/untraced");
    assert!(untraced.trace_id.is_empty() && untraced.span_id.is_empty());
    assert_eq!(untraced.flags, 0);
}

#[tokio::test]
async fn otlp_logs_follow_the_policy() {
    let collector = Collector::http().await;
    let (podgate, upstream) = start(&logs_env(&collector), json!({})).await;
    let headers = [
        ("Authorization", "Bearer hunter2"),
        ("Cookie", "session=hunter2"),
        ("X-Keep", "visible"),
        ("User-Agent", "probe/1"),
    ];
    let secret_in = |collector: &Collector| {
        collector
            .received()
            .iter()
            .filter(|call| is_logs(call))
            .any(|call| call.body.windows(7).any(|window| window == b"hunter2"))
    };

    // The default policy drops every header and the optional fields.
    podgate
        .get_with_headers("a.test", "/default?token=tok3n", &headers)
        .await;
    let found = wait_records(&collector, 1).await;
    let record = record_for(&found, "/default");
    assert!(
        record
            .attributes
            .iter()
            .all(|pair| !pair.key.contains("header"))
    );
    assert_eq!(attr(record, "url.query"), None);
    assert_eq!(attr(record, "user_agent.original"), None);
    assert!(!secret_in(&collector));

    // Fields: dropped, redacted, masked and optional ones kept; headers kept, credentials still
    // redacted.
    let policy = json!({
        "fields": {
            "names": {
                "tenant": "drop",
                "app": "redact",
                "client_ip": { "action": "mask", "ipv4_bits": 16 },
                "query": "keep",
                "user_agent": "keep",
            },
            "query_redact": ["token"],
        },
        "headers": { "default": "keep" },
    });
    push(&podgate, &upstream, 2, json!({ "access_log": policy })).await;
    podgate
        .get_with_headers("a.test", "/policy?token=tok3n&x=1", &headers)
        .await;
    let found = wait_records(&collector, 2).await;
    let record = record_for(&found, "/policy");
    assert_eq!(
        attr(record, "podgate.tenant"),
        None,
        "a dropped field is absent"
    );
    assert_eq!(text(record, "podgate.app").as_deref(), Some("[redacted]"));
    assert_eq!(text(record, "client.address").as_deref(), Some("127.0.0.0"));
    assert_eq!(
        text(record, "user_agent.original").as_deref(),
        Some("probe/1")
    );
    let query = text(record, "url.query").expect("the query is kept");
    assert!(
        query.contains("token=[redacted]") && query.contains("x=1"),
        "{query}"
    );
    assert_eq!(
        list_of_one(record, "http.request.header.authorization").as_deref(),
        Some("[redacted]")
    );
    assert_eq!(
        list_of_one(record, "http.request.header.cookie").as_deref(),
        Some("[redacted]")
    );
    assert_eq!(
        list_of_one(record, "http.request.header.x-keep").as_deref(),
        Some("visible")
    );
    assert!(
        record
            .attributes
            .iter()
            .any(|pair| pair.key.starts_with("http.response.header.")),
        "response headers are kept too"
    );
    assert!(
        !secret_in(&collector),
        "a credential header never leaves unless kept by name"
    );

    // Named `keep`, a credential header is written, and only that one.
    let policy = json!({ "headers": { "default": "drop", "names": { "authorization": "keep" } } });
    push(&podgate, &upstream, 3, json!({ "access_log": policy })).await;
    podgate.get_with_headers("a.test", "/named", &headers).await;
    let found = wait_records(&collector, 3).await;
    let record = record_for(&found, "/named");
    assert_eq!(
        list_of_one(record, "http.request.header.authorization").as_deref(),
        Some("Bearer hunter2")
    );
    assert_eq!(attr(record, "http.request.header.cookie"), None);

    // The line format is the file sink's business: the record is the same under `common`.
    push(
        &podgate,
        &upstream,
        4,
        json!({ "access_log": { "format": "common" } }),
    )
    .await;
    podgate.get("a.test", "/common").await;
    let found = wait_records(&collector, 4).await;
    let record = record_for(&found, "/common");
    assert_eq!(text(record, "http.request.method").as_deref(), Some("GET"));
    assert_eq!(text(record, "podgate.tenant").as_deref(), Some("t1"));
}

#[tokio::test]
async fn otlp_logs_snapshot_cannot_set_destination() {
    let collector = Collector::http().await;
    let (podgate, upstream) = start(&logs_env(&collector), json!({})).await;
    for bad in [
        json!({ "otlp": true }),
        json!({ "endpoint": "http://127.0.0.1:1" }),
        json!({ "otlp": { "endpoint": "http://127.0.0.1:1", "headers": { "x": "y" } } }),
        json!({ "headers_out": { "x": "y" } }),
    ] {
        let mut pushed = snapshot(
            9,
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
    podgate.get("a.test", "/").await;
    let found = wait_records(&collector, 1).await;
    assert!(
        collector
            .received()
            .iter()
            .all(|call| call.path == LOGS_HTTP),
        "nothing went anywhere but the operator's collector: {found:?}"
    );
}

// ---------------------------------------------------------------------------------------
// gRPC
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn otlp_logs_grpc() {
    let collector = Collector::grpc().await;
    let mut env = logs_env(&collector);
    env.extend(env_of(&[(
        "OTEL_EXPORTER_OTLP_HEADERS",
        "x-api-key=s3cret",
    )]));
    let (podgate, _upstream) = start(&env, json!({})).await;

    podgate
        .get_with_headers("a.test", "/p", &[("User-Agent", "probe/1")])
        .await;
    let found = wait_records(&collector, 1).await;
    let record = &found[0];
    let call = collector
        .received()
        .into_iter()
        .find(is_logs)
        .expect("a logs call");
    assert_eq!(call.path, LOGS_GRPC);
    assert_eq!(
        call.header("x-api-key"),
        Some("s3cret"),
        "headers are metadata"
    );
    assert_eq!(text(record, "http.request.method").as_deref(), Some("GET"));
    assert_eq!(text(record, "url.path").as_deref(), Some("/p"));
    assert_eq!(text(record, "podgate.app").as_deref(), Some("a.test"));
    assert_eq!(
        attr(record, "http.response.status_code"),
        Some(Any::Int(200))
    );
    wait_metric(&podgate, "podgate_access_log_otlp_exported_total ", 1).await;
}

#[tokio::test]
async fn otlp_logs_grpc_tls() {
    let server_cert = TestCert::new(&["localhost"]);
    let client_cert = TestCert::new(&["podgate-client"]);
    let collector =
        Collector::start(Wire::Grpc, &[], Tls::Mutual(&server_cert, &client_cert)).await;
    let dir = Dir::new("tls");
    let (ca, cert, key) = (
        dir.file("ca.pem"),
        dir.file("client.pem"),
        dir.file("client.key"),
    );
    std::fs::write(&ca, &server_cert.cert_pem).expect("write the CA");
    std::fs::write(&cert, &client_cert.cert_pem).expect("write the client certificate");
    std::fs::write(&key, &client_cert.key_pem).expect("write the client key");
    let path = |path: &Path| path.display().to_string();

    // Without a client certificate the handshake is refused and the records are lost.
    let mut anonymous = logs_env(&collector);
    anonymous.extend(env_of(&[("OTEL_EXPORTER_OTLP_CERTIFICATE", &path(&ca))]));
    let (podgate, _upstream) = start(&anonymous, json!({})).await;
    podgate.get("a.test", "/").await;
    wait_metric(&podgate, "podgate_access_log_otlp_dropped_total ", 1).await;
    assert!(collector.handshake_failures() >= 1);
    assert_eq!(
        collector.requests(),
        0,
        "nothing got through without the certificate"
    );
    drop(podgate);

    // With it the records arrive over mutual TLS.
    let mut mutual = anonymous.clone();
    mutual.extend(env_of(&[
        ("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", &path(&cert)),
        ("OTEL_EXPORTER_OTLP_CLIENT_KEY", &path(&key)),
    ]));
    let (podgate, _upstream) = start(&mutual, json!({})).await;
    podgate.get("a.test", "/secure").await;
    let found = wait_records(&collector, 1).await;
    assert_eq!(text(&found[0], "url.path").as_deref(), Some("/secure"));
}

// ---------------------------------------------------------------------------------------
// A collector that is down, slow or refusing
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn otlp_logs_retry_then_succeed() {
    let collector = Collector::start(
        Wire::Http,
        &[Reply::Status {
            code: 14,
            retry_after: None,
        }],
        Tls::None,
    )
    .await;
    let (podgate, _upstream) = start(&logs_env(&collector), json!({})).await;
    podgate.get("a.test", "/").await;
    let found = wait_records(&collector, 1).await;
    assert_eq!(found.len(), 1, "the retried batch is delivered once");
    let calls: Vec<_> = collector.received().into_iter().filter(is_logs).collect();
    assert!(
        calls.len() >= 2 && !calls[0].accepted,
        "the first try was refused"
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric_value(&metrics, "podgate_access_log_otlp_dropped_total "),
        0
    );
}

/// The 99th percentile of 400 sequential requests, spread over about two seconds so that the
/// exporter has a batch to send inside it.
async fn p99(podgate: &Podgate) -> Duration {
    let mut times = Vec::new();
    for _ in 0..400 {
        let started = Instant::now();
        assert_eq!(podgate.get("a.test", "/").await.status, 200);
        times.push(started.elapsed());
        sleep(Duration::from_millis(5)).await;
    }
    times.sort();
    times[times.len() * 99 / 100]
}

#[tokio::test]
async fn otlp_logs_collector_down_does_not_slow_requests() {
    let dir = Dir::new("down");
    let log = |name: &str| dir.file(name).to_str().expect("utf-8 path").to_owned();
    let idle_file = log("idle.log");
    let (idle, _upstream) = start(&env_of(&[("ACCESS_LOG_FILE", &idle_file)]), json!({})).await;
    let baseline = p99(&idle).await;
    drop(idle);
    let limit = baseline * 3 + Duration::from_millis(40);

    let unavailable = Collector::start(Wire::Grpc, &[], Tls::None).await;
    unavailable.set_fallback(Reply::Status {
        code: 14,
        retry_after: Some(Duration::from_secs(2)),
    });
    let hung = Collector::http().await;
    hung.set_fallback(Reply::Blackhole);
    let refused = common::refused();
    let down_env = env_of(&[
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            &format!("http://{}", refused.addr),
        ),
        ("OTEL_LOGS_EXPORTER", "otlp"),
        ("OTEL_EXPORTER_OTLP_TIMEOUT", "500"),
    ]);
    for (name, what, mut env) in [
        ("refused.log", "refusing connections", down_env),
        (
            "unavailable.log",
            "answering UNAVAILABLE",
            logs_env(&unavailable),
        ),
        ("hung.log", "never answering", logs_env(&hung)),
    ] {
        let file = log(name);
        env.push(("ACCESS_LOG_FILE".to_owned(), file.clone()));
        let (podgate, _upstream) = start(&env, json!({})).await;
        let slowest = p99(&podgate).await;
        assert!(
            slowest <= limit,
            "a collector {what} slowed p99 to {slowest:?} (exporter off: {baseline:?})"
        );
        wait_metric(&podgate, "podgate_access_log_otlp_dropped_total ", 1).await;
        drop(podgate);
        assert!(
            lines(Path::new(&file)).len() >= 400,
            "the file sink kept writing while the collector was {what}"
        );
    }
    assert!(unavailable.requests() >= 1, "the exporter did try");
    assert!(hung.requests() >= 1, "the exporter did try");
}

#[tokio::test]
async fn otlp_logs_queue_bounded() {
    let collector = Collector::http().await;
    collector.set_fallback(Reply::Blackhole);
    let mut env = logs_env(&collector);
    // The first batch is taken after two seconds and held for the whole test.
    env.push(("OTEL_EXPORTER_OTLP_TIMEOUT".to_owned(), "10000".to_owned()));
    let (podgate, _upstream) = start(&env, json!({})).await;
    let podgate = Arc::new(podgate);

    let mut workers = JoinSet::new();
    for _ in 0..16 {
        let podgate = Arc::clone(&podgate);
        workers.spawn(async move {
            for _ in 0..600 {
                assert_eq!(podgate.get("a.test", "/").await.status, 200);
            }
        });
    }
    while let Some(done) = workers.join_next().await {
        done.expect("a worker finished");
    }

    let metrics = podgate.admin_get("/metrics").await.body;
    let dropped = metric_value(&metrics, "podgate_access_log_otlp_dropped_total ");
    let queued = metric_value(&metrics, "podgate_access_log_otlp_queue_records ");
    assert!(
        dropped >= 500,
        "9600 records into an 8192 queue: dropped {dropped}"
    );
    assert!(queued <= 8192, "the queue holds {queued}");
    assert!(
        collector.received().iter().all(|call| !call.accepted),
        "the hung collector accepted nothing"
    );
}
