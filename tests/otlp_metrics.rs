//! Metrics over OTLP through the real binary, against the fake collector of
//! `tests/common/otlp.rs`. The exporter converts what `GET /metrics` renders, so the tests
//! compare every exported sample with a scrape taken at the same moment; the transport (retries,
//! TLS, headers) is the span exporter's and is tested in `tests/tracing*.rs`.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use common::otlp::{Collector, Received, Reply, Tls, Wire};
use common::{Podgate, TestCert, Upstream, app, router, serving, snapshot};
use podgate::observe::metrics::proto::{
    ExportMetricsServiceRequest, Metric, metric, number_data_point,
};
use podgate::observe::otlp::common::{KeyValue, any_value};
use serde_json::{Value, json};
use tokio::time::sleep;

/// Series that move on their own between two instants on a quiet proxy: none are known. A series
/// added here must not be a `podgate_router_*`, `podgate_service_*` or `podgate_entry_point_*`
/// one (checked by `moving_series_are_not_the_request_series`).
const MOVING: [&str; 0] = [];

fn env_of(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn pairs(env: &[(String, String)]) -> Vec<(&str, &str)> {
    env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// The environment of a node that exports its metrics every `interval_ms` to `collector`.
fn metrics_env(collector: &Collector, interval_ms: u64) -> Vec<(String, String)> {
    let mut env = collector.env();
    env.extend(env_of(&[
        ("OTEL_METRICS_EXPORTER", "otlp"),
        ("OTEL_METRIC_EXPORT_INTERVAL", &interval_ms.to_string()),
        ("OTEL_EXPORTER_OTLP_TIMEOUT", "1000"),
    ]));
    env
}

async fn start(env: &[(String, String)]) -> (Podgate, Upstream) {
    let podgate = Podgate::start_with_env(&pairs(env)).await;
    let upstream = Upstream::start("hello").await;
    let pushed = snapshot(
        1,
        &[app("a.test", &["a.test"], &[serving("r1", upstream.addr)])],
    );
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
    (podgate, upstream)
}

// ---------------------------------------------------------------------------------------
// Comparing an export with a scrape
// ---------------------------------------------------------------------------------------

/// `name{k="v",...}` with the labels sorted: the identity of one sample.
fn identity(name: &str, labels: &[(String, String)]) -> String {
    let mut labels = labels.to_vec();
    labels.sort();
    let inner: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v:?}")).collect();
    format!("{name}{{{}}}", inner.join(","))
}

fn attributes(attributes: &[KeyValue]) -> Vec<(String, String)> {
    attributes
        .iter()
        .map(|pair| {
            let Some(any_value::Value::String(text)) =
                pair.value.as_ref().and_then(|v| v.value.clone())
            else {
                panic!("label {} is not a string", pair.key);
            };
            (pair.key.clone(), text)
        })
        .collect()
}

/// The samples an export holds, as a scrape would print them, and each metric's type.
fn flatten(
    request: &ExportMetricsServiceRequest,
) -> (BTreeMap<String, f64>, BTreeMap<String, &'static str>) {
    let mut samples = BTreeMap::new();
    let mut types = BTreeMap::new();
    let metrics: Vec<&Metric> = request
        .resource_metrics
        .iter()
        .flat_map(|resource| &resource.scope_metrics)
        .flat_map(|scope| &scope.metrics)
        .collect();
    for one in metrics {
        let name = one.name.as_str();
        match one.data.as_ref().expect("a metric has data") {
            metric::Data::Sum(sum) => {
                assert!(
                    sum.is_monotonic && sum.aggregation_temporality == 2,
                    "{name}"
                );
                types.insert(name.to_owned(), "counter");
                for point in &sum.data_points {
                    samples.insert(
                        identity(name, &attributes(&point.attributes)),
                        number(point.value),
                    );
                }
            }
            metric::Data::Gauge(gauge) => {
                types.insert(name.to_owned(), "gauge");
                for point in &gauge.data_points {
                    samples.insert(
                        identity(name, &attributes(&point.attributes)),
                        number(point.value),
                    );
                }
            }
            metric::Data::Histogram(histogram) => {
                assert_eq!(histogram.aggregation_temporality, 2, "{name}");
                types.insert(name.to_owned(), "histogram");
                for point in &histogram.data_points {
                    let labels = attributes(&point.attributes);
                    assert_eq!(point.bucket_counts.len(), point.explicit_bounds.len() + 1);
                    let mut cumulative = 0;
                    for (index, count) in point.bucket_counts.iter().enumerate() {
                        cumulative += count;
                        let le = point
                            .explicit_bounds
                            .get(index)
                            .map_or_else(|| "+Inf".to_owned(), |bound| format!("{bound}"));
                        let mut with_le = labels.clone();
                        with_le.push(("le".to_owned(), le));
                        samples.insert(
                            identity(&format!("{name}_bucket"), &with_le),
                            cumulative as f64,
                        );
                    }
                    samples.insert(
                        identity(&format!("{name}_sum"), &labels),
                        point.sum.expect("a sum"),
                    );
                    samples.insert(
                        identity(&format!("{name}_count"), &labels),
                        point.count as f64,
                    );
                    assert_eq!(
                        point.count, cumulative,
                        "{name}: the count is the buckets' sum"
                    );
                }
            }
        }
    }
    (samples, types)
}

fn number(value: Option<number_data_point::Value>) -> f64 {
    match value.expect("a data point has a value") {
        number_data_point::Value::AsInt(int) => int as f64,
        number_data_point::Value::AsDouble(double) => double,
    }
}

/// The name, labels and value of one exposition sample line.
fn sample(line: &str) -> (String, Vec<(String, String)>, f64) {
    let name_end = line.find(['{', ' ']).expect("a sample has a value");
    let name = line[..name_end].to_owned();
    let mut labels = Vec::new();
    let mut rest = &line[name_end..];
    if let Some(inner) = rest.strip_prefix('{') {
        let mut chars = inner.char_indices();
        let mut key = String::new();
        let mut value = String::new();
        let mut in_value = false;
        let mut end = 0;
        while let Some((at, c)) = chars.next() {
            if in_value {
                match c {
                    '"' => {
                        labels.push((std::mem::take(&mut key), std::mem::take(&mut value)));
                        in_value = false;
                    }
                    '\\' => match chars.next().expect("an escape").1 {
                        'n' => value.push('\n'),
                        other => value.push(other),
                    },
                    other => value.push(other),
                }
            } else {
                match c {
                    '=' => {}
                    '"' => in_value = true,
                    ',' => {}
                    '}' => {
                        end = at + 1;
                        break;
                    }
                    other => key.push(other),
                }
            }
        }
        rest = &inner[end..];
    }
    (name, labels, rest.trim().parse().expect("a number"))
}

/// The samples of a scrape and each family's type, for the families that have a sample.
fn scraped(text: &str) -> (BTreeMap<String, f64>, BTreeMap<String, String>) {
    let mut declared = BTreeMap::new();
    let mut samples = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').expect("a type");
            declared.insert(name.to_owned(), kind.to_owned());
        } else if !line.starts_with('#') && !line.trim().is_empty() {
            let (name, labels, value) = sample(line);
            samples.insert(identity(&name, &labels), value);
        }
    }
    let family_of = |identity: &str| -> String {
        let name = identity.split('{').next().unwrap_or_default();
        for suffix in ["_bucket", "_sum", "_count"] {
            if let Some(base) = name.strip_suffix(suffix)
                && declared.get(base).is_some_and(|kind| kind == "histogram")
            {
                return base.to_owned();
            }
        }
        name.to_owned()
    };
    let used: BTreeSet<String> = samples.keys().map(|key| family_of(key)).collect();
    declared.retain(|name, _| used.contains(name));
    (samples, declared)
}

/// What differs between an export and a scrape; empty when they are the same.
fn difference(export: &Received, scrape: &str) -> Vec<String> {
    let request: ExportMetricsServiceRequest = export.decode();
    let (exported, exported_types) = flatten(&request);
    let (scraped_samples, scraped_types) = scraped(scrape);
    let skip = |key: &str| MOVING.iter().any(|name| key.starts_with(name));
    let mut out = Vec::new();
    for (key, value) in &scraped_samples {
        if skip(key) {
            continue;
        }
        match exported.get(key) {
            None => out.push(format!("not exported: {key} {value}")),
            Some(got) if (got - value).abs() > f64::EPSILON * value.abs().max(1.0) => {
                out.push(format!("{key}: exported {got}, scraped {value}"));
            }
            Some(_) => {}
        }
    }
    for key in exported.keys().filter(|key| !skip(key)) {
        if !scraped_samples.contains_key(key) {
            out.push(format!("exported but not scraped: {key}"));
        }
    }
    for (name, kind) in &exported_types {
        if scraped_types.get(name).map(String::as_str) != Some(kind) {
            out.push(format!(
                "{name}: exported as {kind}, scraped as {:?}",
                scraped_types.get(name)
            ));
        }
    }
    for name in scraped_types.keys() {
        if !exported_types.contains_key(name) && !skip(name) {
            out.push(format!("family not exported: {name}"));
        }
    }
    out
}

/// Some traffic, then: an export that was in flight before a scrape, or the one after it, equals
/// the scrape. The proxy is quiet, so both do, unless something moves on its own.
async fn assert_export_equals_scrape(podgate: &Podgate, collector: &Collector) {
    for _ in 0..5 {
        assert_eq!(podgate.get("a.test", "/").await.status, 200);
    }
    assert_eq!(podgate.get("nobody.test", "/").await.status, 404);
    collector.wait_requests(2).await;
    let before = collector.requests();
    let scrape = podgate.admin_get("/metrics").await.body;
    collector.wait_requests(before + 1).await;
    let received = collector.received();
    let candidates = [&received[before - 1], &received[before]];
    let diffs: Vec<Vec<String>> = candidates
        .iter()
        .map(|export| difference(export, &scrape))
        .collect();
    assert!(
        diffs.iter().any(Vec::is_empty),
        "no export equals the scrape; against the earlier: {:#?}\nagainst the later: {:#?}",
        diffs[0],
        diffs[1]
    );
    let request: ExportMetricsServiceRequest = candidates[0].decode();
    let resource = request.resource_metrics.first().expect("one resource");
    assert_eq!(
        resource.resource.as_ref().expect("resource").attributes,
        vec![KeyValue::text("service.name", "podgate")]
    );
    assert_eq!(
        resource
            .scope_metrics
            .first()
            .expect("scope")
            .scope
            .as_ref()
            .expect("scope")
            .name,
        "podgate"
    );
    let (exported, _) = flatten(&request);
    assert!(
        exported
            .keys()
            .any(|key| key.starts_with("podgate_router_requests_total")),
        "the request series are exported: {exported:#?}"
    );
}

// ---------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn otlp_metrics_match_prometheus_http() {
    let collector = Collector::http().await;
    let (podgate, _upstream) = start(&metrics_env(&collector, 300)).await;
    assert_export_equals_scrape(&podgate, &collector).await;
    let first = &collector.received()[0];
    assert_eq!(first.path, "/v1/metrics");
    assert_eq!(first.header("content-type"), Some("application/x-protobuf"));
}

#[tokio::test]
async fn otlp_metrics_match_prometheus_grpc() {
    let collector = Collector::grpc().await;
    let mut env = metrics_env(&collector, 300);
    env.extend(env_of(&[
        ("OTEL_EXPORTER_OTLP_HEADERS", "x-api-key=k-123"),
        ("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip"),
    ]));
    let (podgate, _upstream) = start(&env).await;
    assert_export_equals_scrape(&podgate, &collector).await;
    let first = &collector.received()[0];
    assert_eq!(
        first.path,
        "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
    );
    assert_eq!(
        first.header("x-api-key"),
        Some("k-123"),
        "headers go as metadata"
    );
    assert!(first.compressed, "gzip was asked for");
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "podgate-otlp-metrics-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create the directory");
    dir
}

#[tokio::test]
async fn otlp_metrics_grpc_tls() {
    let server_cert = TestCert::new(&["localhost"]);
    let client_cert = TestCert::new(&["podgate-client"]);
    let collector =
        Collector::start(Wire::Grpc, &[], Tls::Mutual(&server_cert, &client_cert)).await;
    let dir = temp_dir("tls");
    let ca = dir.join("ca.pem");
    let cert = dir.join("client.pem");
    let key = dir.join("client.key");
    std::fs::write(&ca, &server_cert.cert_pem).expect("write the CA");
    std::fs::write(&cert, &client_cert.cert_pem).expect("write the client certificate");
    std::fs::write(&key, &client_cert.key_pem).expect("write the client key");
    let (ca_path, cert_path, key_path) = (
        ca.display().to_string(),
        cert.display().to_string(),
        key.display().to_string(),
    );

    // Without a client certificate the collector refuses the handshake and the interval fails.
    let mut anonymous = metrics_env(&collector, 200);
    anonymous.extend(env_of(&[("OTEL_EXPORTER_OTLP_CERTIFICATE", &ca_path)]));
    let (podgate, _upstream) = start(&anonymous).await;
    wait_metric(&podgate, "podgate_otlp_metrics_failed_total", 1).await;
    assert!(collector.handshake_failures() >= 1);
    assert_eq!(
        collector.requests(),
        0,
        "nothing got through without the certificate"
    );
    drop(podgate);

    // With it, the metrics arrive over mutual TLS.
    let mut mutual = anonymous.clone();
    mutual.extend(env_of(&[
        ("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", &cert_path),
        ("OTEL_EXPORTER_OTLP_CLIENT_KEY", &key_path),
    ]));
    let (podgate, _upstream) = start(&mutual).await;
    assert_export_equals_scrape(&podgate, &collector).await;
    assert!(collector.received().iter().all(|call| call.accepted));
    drop(std::fs::remove_dir_all(&dir));
}

// ---------------------------------------------------------------------------------------
// A collector that is down, slow or refusing
// ---------------------------------------------------------------------------------------

fn metric_value(metrics: &str, name: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(name)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("{name} is not in /metrics:\n{metrics}"))
}

async fn wait_metric(podgate: &Podgate, name: &str, at_least: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(20);
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

/// The 99th percentile of 400 sequential requests, spread over about two seconds so that several
/// export intervals fall inside it.
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
async fn otlp_metrics_collector_down_does_not_slow_requests() {
    let (idle, _upstream) = start(&[]).await;
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
        ("OTEL_METRICS_EXPORTER", "otlp"),
        ("OTEL_METRIC_EXPORT_INTERVAL", "100"),
        ("OTEL_EXPORTER_OTLP_TIMEOUT", "500"),
    ]);
    for (what, env) in [
        ("refusing connections", down_env),
        ("answering UNAVAILABLE", metrics_env(&unavailable, 100)),
        ("never answering", metrics_env(&hung, 100)),
    ] {
        let (podgate, _upstream) = start(&env).await;
        let slowest = p99(&podgate).await;
        assert!(
            slowest <= limit,
            "a collector {what} slowed p99 to {slowest:?} (exporter off: {baseline:?})"
        );
        wait_metric(&podgate, "podgate_otlp_metrics_failed_total", 1).await;
    }
    assert!(unavailable.requests() >= 1, "the exporter did try");
    assert!(hung.requests() >= 1, "the exporter did try");
}

#[tokio::test]
async fn otlp_metrics_recover() {
    let collector = Collector::http().await;
    collector.set_fallback(Reply::Status {
        code: 14,
        retry_after: None,
    });
    let (podgate, _upstream) = start(&metrics_env(&collector, 200)).await;
    for _ in 0..3 {
        assert_eq!(podgate.get("a.test", "/").await.status, 200);
    }
    let failed = wait_metric(&podgate, "podgate_otlp_metrics_failed_total", 2).await;
    assert!(collector.received().iter().all(|call| !call.accepted));

    collector.set_fallback(Reply::Ok);
    let deadline = Instant::now() + Duration::from_secs(20);
    let accepted = loop {
        if let Some(call) = collector.received().into_iter().find(|call| call.accepted) {
            break call;
        }
        assert!(
            Instant::now() < deadline,
            "no interval succeeded after the collector came back"
        );
        sleep(Duration::from_millis(50)).await;
    };
    // The failed intervals lost nothing: the first success carries every request so far.
    let request: ExportMetricsServiceRequest = accepted.decode();
    let (samples, _) = flatten(&request);
    let counted: f64 = samples
        .iter()
        .filter(|(key, _)| key.starts_with("podgate_router_requests_total"))
        .map(|(_, value)| value)
        .sum();
    assert_eq!(counted, 3.0, "{samples:#?}");

    // The counter stops rising once exports succeed again.
    let settled = metric_value(
        &podgate.admin_get("/metrics").await.body,
        "podgate_otlp_metrics_failed_total",
    );
    assert!(settled >= failed);
    sleep(Duration::from_millis(800)).await;
    assert_eq!(
        metric_value(
            &podgate.admin_get("/metrics").await.body,
            "podgate_otlp_metrics_failed_total"
        ),
        settled
    );
}

// ---------------------------------------------------------------------------------------
// The series cap
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn otlp_metrics_respect_series_cap() {
    let collector = Collector::http().await;
    let mut env = metrics_env(&collector, 300);
    env.extend(env_of(&[("METRICS_SERIES_PER_TENANT", "5")]));
    let podgate = Podgate::start_with_env(&pairs(&env)).await;
    let upstream = Upstream::start("hello").await;
    let routers: Vec<Value> = (0..50)
        .map(|index| {
            router(
                &format!("r{index}"),
                json!({ "host": format!("r{index}.a.test") }),
                "web",
            )
        })
        .collect();
    let mut declared = app("a.test", &["a.test"], &[serving("r1", upstream.addr)]);
    declared["routers"] = Value::Array(routers);
    let response = podgate.push_snapshot(&snapshot(1, &[declared])).await;
    assert_eq!(response.status, 200, "{response:?}");
    for index in 0..50 {
        assert_eq!(
            podgate.get(&format!("r{index}.a.test"), "/").await.status,
            200
        );
    }
    collector.wait_requests(2).await;
    let before = collector.requests();
    let scrape = podgate.admin_get("/metrics").await.body;
    collector.wait_requests(before + 1).await;
    let exported = collector
        .received()
        .into_iter()
        .next_back()
        .expect("an export");
    let request: ExportMetricsServiceRequest = exported.decode();
    let (samples, _) = flatten(&request);

    let routers_of = |keys: Vec<&String>| -> BTreeSet<String> {
        keys.into_iter()
            .filter(|key| key.starts_with("podgate_router_requests_total{"))
            .filter_map(|key| {
                let (_, rest) = key.split_once("router=\"")?;
                Some(rest.split('"').next()?.to_owned())
            })
            .collect()
    };
    let exported_routers = routers_of(samples.keys().collect());
    let (scraped_samples, _) = scraped(&scrape);
    let scraped_routers = routers_of(scraped_samples.keys().collect());
    assert_eq!(
        exported_routers, scraped_routers,
        "the export names the routers the scrape does"
    );
    assert!(
        exported_routers.len() <= 5 + 1,
        "50 routers, a cap of 5: {exported_routers:?}"
    );
    assert!(
        exported_routers.contains("other"),
        "the rest collapse into other"
    );
    let series = |keys: Vec<&String>| {
        keys.iter()
            .filter(|key| key.starts_with("podgate_router_"))
            .count()
    };
    assert_eq!(
        series(samples.keys().collect()),
        series(scraped_samples.keys().collect())
    );
    assert!(
        samples
            .get("podgate_metrics_collapsed_total{tenant=\"t1\"}")
            .is_some_and(|collapsed| *collapsed >= 45.0),
        "the collapse is counted: {samples:#?}"
    );
}

// ---------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn otlp_metrics_off_by_default() {
    let collector = Collector::http().await;
    // A collector for spans and an interval, but no exporter: nothing is pushed, nothing connects.
    let mut env = collector.env();
    env.extend(env_of(&[("OTEL_METRIC_EXPORT_INTERVAL", "100")]));
    let (podgate, _upstream) = start(&env).await;
    for _ in 0..3 {
        assert_eq!(podgate.get("a.test", "/").await.status, 200);
    }
    sleep(Duration::from_millis(700)).await;
    assert_eq!(collector.requests(), 0, "nothing was pushed");
    assert_eq!(collector.connections(), 0, "nothing connected");
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric_value(&metrics, "podgate_otlp_metrics_failed_total"),
        0
    );
}

#[tokio::test]
async fn otlp_metrics_bad_settings_stop_startup() {
    let cases: [(&[(&str, &str)], &str); 7] = [
        (
            &[("OTEL_METRICS_EXPORTER", "prometheus")],
            "OTEL_METRICS_EXPORTER",
        ),
        (
            &[("OTEL_METRICS_EXPORTER", "otlp")],
            "OTEL_METRICS_EXPORTER",
        ),
        (
            &[("OTEL_METRIC_EXPORT_INTERVAL", "0")],
            "OTEL_METRIC_EXPORT_INTERVAL",
        ),
        (
            &[("OTEL_METRIC_EXPORT_INTERVAL", "abc")],
            "OTEL_METRIC_EXPORT_INTERVAL",
        ),
        (
            &[("OTEL_METRIC_EXPORT_INTERVAL", "99")],
            "OTEL_METRIC_EXPORT_INTERVAL",
        ),
        (
            &[("OTEL_METRIC_EXPORT_INTERVAL", "3600001")],
            "OTEL_METRIC_EXPORT_INTERVAL",
        ),
        (
            &[
                ("OTEL_METRICS_EXPORTER", "otlp"),
                ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"),
            ],
            "OTEL_EXPORTER_OTLP_PROTOCOL",
        ),
    ];
    for (vars, named) in cases {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_podgate"));
        command.env(
            "ADMIN_SOCKET",
            std::env::temp_dir().join("podgate-otlp-metrics-bad.sock"),
        );
        for (var, value) in vars {
            command.env(var, value);
        }
        let output = command.output().expect("run podgate");
        assert!(!output.status.success(), "{vars:?} must stop startup");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(named),
            "the error names {named} for {vars:?}: {stderr}"
        );
    }
}

#[test]
fn moving_series_are_not_the_request_series() {
    for name in MOVING {
        assert!(
            ![
                "podgate_router_",
                "podgate_service_",
                "podgate_entry_point_"
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix)),
            "{name} is a request series, which must match exactly"
        );
    }
}
