//! The span exporter's settings and its [`Feed`]: how the tracer's queue plugs into the shared
//! OTLP transport (`src/observe/otlp/`).
//!
//! The service never runs on the request path. A batch is 512 spans or whatever has queued in
//! two seconds; an export gives up after `OTEL_EXPORTER_OTLP_TIMEOUT` (3 seconds) and is retried
//! twice with backoff, then its spans are dropped and counted. Meanwhile the queue keeps its
//! bound, so a collector that is down or slow costs spans and nothing else. The collector
//! settings, the two wires and the loop are the transport's; this file adds
//! `OTEL_MAX_SPANS_PER_SEC` and the queue.

use std::num::NonZeroU32;

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

use super::otlp;
use super::span::Span;
use super::tracer::{BATCH_SPANS, DEFAULT_MAX_SPANS_PER_SEC, Tracer};
use crate::config::ConfigError;
use crate::observe::otlp::collector::{Collector, Signal, bad, present};
use crate::observe::otlp::{BatchExporter, Feed, Transport};

/// The most spans a second `OTEL_MAX_SPANS_PER_SEC` may allow.
const MAX_SPANS_PER_SEC_LIMIT: u32 = 1_000_000;

/// The operator's tracing settings, from the environment (never from a snapshot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportConfig {
    /// Where the collector is and how to reach it: the `OTEL_EXPORTER_OTLP_*` variables and
    /// `OTEL_SERVICE_NAME`, shared with every other signal. No endpoint: spans are not recorded,
    /// requests are still sampled and propagated.
    pub collector: Collector,
    /// `OTEL_MAX_SPANS_PER_SEC`: spans a second this node lets be traced, whoever asks.
    pub max_spans_per_sec: NonZeroU32,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            collector: Collector::default(),
            max_spans_per_sec: NonZeroU32::new(DEFAULT_MAX_SPANS_PER_SEC)
                .unwrap_or(NonZeroU32::MIN),
        }
    }
}

impl ExportConfig {
    /// Reads the `OTEL_*` variables through `lookup`.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] naming the variable whose value is not usable. Header values are never
    /// quoted in it.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut config = Self {
            collector: Collector::from_lookup(&lookup)?,
            ..Self::default()
        };
        if let Some(raw) = present(&lookup, "OTEL_MAX_SPANS_PER_SEC")? {
            let rate: NonZeroU32 = raw.parse().map_err(|err| {
                bad(
                    "OTEL_MAX_SPANS_PER_SEC",
                    format!(
                        "{raw:?} is not a whole number in 1..={MAX_SPANS_PER_SEC_LIMIT} ({err})"
                    ),
                )
            })?;
            if rate.get() > MAX_SPANS_PER_SEC_LIMIT {
                return Err(bad(
                    "OTEL_MAX_SPANS_PER_SEC",
                    format!("{rate} is outside 1..={MAX_SPANS_PER_SEC_LIMIT}"),
                ));
            }
            config.max_spans_per_sec = rate;
        }
        Ok(config)
    }

    /// The tracer this configuration asks for: it records spans only when there is a collector.
    #[must_use]
    pub fn tracer(&self) -> Tracer {
        Tracer::new(
            self.max_spans_per_sec.get(),
            self.collector.endpoint.is_some(),
        )
    }
}

/// The tracer's span queue as a [`Feed`].
#[derive(Debug)]
struct TraceFeed {
    tracer: Tracer,
    service_name: Box<str>,
}

#[async_trait]
impl Feed for TraceFeed {
    type Item = Span;
    const NOUN: &'static str = "spans";
    const BATCH: usize = BATCH_SPANS;

    fn take(&self, max: usize) -> Vec<Span> {
        self.tracer.take(max)
    }

    async fn ready(&self) {
        self.tracer.batch_ready().await;
    }

    fn encode(&self, items: &[Span]) -> Vec<u8> {
        otlp::encode(&self.service_name, items)
    }

    fn exported(&self, count: usize) {
        self.tracer.exported(count);
    }

    fn lost(&self, count: usize) {
        self.tracer.lost(count);
    }
}

/// Sends the tracer's queue to the collector. Register it with the server as a background
/// service.
#[derive(Debug)]
pub struct TraceService(BatchExporter<TraceFeed>);

impl TraceService {
    /// The exporter for `config`, draining `tracer`; `None` when the node has no collector.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] when the root certificates or the client certificate cannot be loaded.
    pub fn new(tracer: &Tracer, config: &ExportConfig) -> Result<Option<Self>, ConfigError> {
        let Some(transport) = Transport::new(&config.collector, Signal::Traces)? else {
            return Ok(None);
        };
        let feed = TraceFeed {
            tracer: tracer.clone(),
            service_name: config.collector.service_name.clone(),
        };
        Ok(Some(Self(BatchExporter::new(feed, transport))))
    }
}

#[async_trait]
impl BackgroundService for TraceService {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.0.start(shutdown).await;
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::observe::otlp::{Protocol, batch::split};

    fn encode(spans: &[Span]) -> Vec<u8> {
        otlp::encode("edge", spans)
    }

    fn config(vars: &[(&str, &str)]) -> Result<ExportConfig, ConfigError> {
        ExportConfig::from_lookup(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn otel_defaults_have_no_collector() {
        let parsed = config(&[]).expect("defaults");
        assert_eq!(parsed, ExportConfig::default());
        assert!(parsed.collector.endpoint.is_none());
        assert_eq!(parsed.collector.protocol, Protocol::Http);
        assert_eq!(parsed.collector.timeout, Duration::from_secs(3));
        assert_eq!(&*parsed.collector.service_name, "podgate");
        assert_eq!(parsed.max_spans_per_sec.get(), 1000);
    }

    #[test]
    fn otel_endpoint_gets_the_traces_path() {
        for (endpoint, wanted) in [
            ("http://collector:4318", "http://collector:4318/v1/traces"),
            ("http://collector:4318/", "http://collector:4318/v1/traces"),
            ("https://c.test/otlp/", "https://c.test/otlp/v1/traces"),
        ] {
            let parsed = config(&[("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)]).expect(endpoint);
            assert_eq!(
                parsed
                    .collector
                    .url(Signal::Traces)
                    .expect("url")
                    .to_string(),
                wanted
            );
        }
    }

    #[test]
    fn otel_reads_every_variable() {
        let parsed = config(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "x-api-key=s3cret, other=1"),
            ("OTEL_EXPORTER_OTLP_CERTIFICATE", "/etc/otel-ca.pem"),
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
            ("OTEL_SERVICE_NAME", "edge"),
            ("OTEL_MAX_SPANS_PER_SEC", "50"),
        ])
        .expect("parses");
        assert_eq!(parsed.collector.headers.len(), 2);
        assert!(
            !format!("{parsed:?}").contains("s3cret"),
            "header values never print"
        );
        assert_eq!(
            parsed.collector.ca_file,
            Some(PathBuf::from("/etc/otel-ca.pem"))
        );
        assert_eq!(parsed.collector.timeout, Duration::from_millis(2500));
        assert_eq!(&*parsed.collector.service_name, "edge");
        assert_eq!(parsed.max_spans_per_sec.get(), 50);
    }

    #[test]
    fn otel_grpc_reads_its_variables() {
        let parsed = config(&[
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.test:4317"),
            ("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "/etc/c.pem"),
            ("OTEL_EXPORTER_OTLP_CLIENT_KEY", "/etc/k.pem"),
            ("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip"),
        ])
        .expect("parses");
        assert_eq!(parsed.collector.protocol, Protocol::Grpc);
        assert_eq!(
            parsed
                .collector
                .url(Signal::Traces)
                .expect("url")
                .to_string(),
            "https://collector.test:4317/"
        );
        assert!(parsed.collector.gzip);
        assert_eq!(
            parsed.collector.client_key,
            Some(PathBuf::from("/etc/k.pem"))
        );
    }

    #[test]
    fn otel_grpc_plaintext_remote_needs_insecure() {
        let var = "OTEL_EXPORTER_OTLP_ENDPOINT";
        for local in [
            "http://127.0.0.1:4317",
            "http://localhost:4317",
            "http://[::1]:4317",
        ] {
            config(&[("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"), (var, local)]).expect(local);
        }
        let remote = [
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
            (var, "http://collector.test:4317"),
        ];
        assert_eq!(config(&remote).expect_err("refused").var, var);
        let mut allowed = remote.to_vec();
        allowed.push(("OTEL_EXPORTER_OTLP_INSECURE", "true"));
        assert!(
            config(&allowed)
                .expect("operator decision")
                .collector
                .insecure
        );
        config(&[
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
            (var, "https://collector.test:4317"),
        ])
        .expect("tls is always fine");
    }

    #[tokio::test]
    async fn otel_exporter_debug_never_prints_header_values() {
        for protocol in ["http/protobuf", "grpc"] {
            let parsed = config(&[
                ("OTEL_EXPORTER_OTLP_PROTOCOL", protocol),
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
                ("OTEL_EXPORTER_OTLP_HEADERS", "x-api-key=s3cret-key"),
            ])
            .expect("parses");
            let tracer = parsed.tracer();
            let service = TraceService::new(&tracer, &parsed)
                .expect("builds")
                .expect("there is a collector");
            for shown in [
                format!("{service:?}"),
                format!("{service:#?}"),
                format!("{parsed:?}"),
            ] {
                assert!(!shown.contains("s3cret"), "{shown}");
            }
        }
    }

    #[test]
    fn otel_errors_name_the_variable_and_never_quote_header_values() {
        for (var, value) in [
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4318"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "ftp://collector"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://user:pw@collector"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector/?a=b"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", " "),
            ("OTEL_EXPORTER_OTLP_HEADERS", "novalue"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "bad name=v"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"),
            ("OTEL_EXPORTER_OTLP_COMPRESSION", "zstd"),
            ("OTEL_EXPORTER_OTLP_INSECURE", "maybe"),
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "0"),
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "10001"),
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "3s"),
            ("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "/c.pem"),
            ("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip"),
            ("OTEL_SERVICE_NAME", " "),
            ("OTEL_MAX_SPANS_PER_SEC", "0"),
            ("OTEL_MAX_SPANS_PER_SEC", "1000001"),
            ("OTEL_MAX_SPANS_PER_SEC", "many"),
        ] {
            let err = config(&[(var, value)]).expect_err("value must be rejected");
            assert!(err.var.starts_with("OTEL_"), "{var}={value}: {err}");
            assert!(!err.to_string().contains("pw@"), "{err}");
        }
        let err = config(&[("OTEL_EXPORTER_OTLP_HEADERS", "k=bad\nvalue")]).expect_err("refused");
        assert!(!err.to_string().contains("bad"), "{err}");
        let err = config(&[
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "content-type=x"),
        ])
        .expect_err("a header gRPC owns");
        assert_eq!(err.var, "OTEL_EXPORTER_OTLP_HEADERS");
        let err = config(&[
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "http://127.0.0.1:4317/v1/traces",
            ),
        ])
        .expect_err("a path on a gRPC endpoint");
        assert_eq!(err.var, "OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    fn span(id: u8, name_len: usize) -> Span {
        use super::super::context::{SpanId, TraceId};
        use super::super::span::Kind;
        Span {
            trace_id: TraceId([1; 16]),
            span_id: SpanId([id; 8]),
            parent: None,
            trace_state: None,
            name: "n".repeat(name_len).into(),
            kind: Kind::Server,
            start_unix_nanos: 1,
            end_unix_nanos: 2,
            attributes: Vec::new(),
            error: false,
        }
    }

    /// The span ids of an encoded request, in order.
    fn ids(body: &[u8]) -> Vec<u8> {
        use prost::Message;
        otlp::ExportTraceServiceRequest::decode(body)
            .expect("decodes")
            .resource_spans
            .iter()
            .flat_map(|resource| &resource.scope_spans)
            .flat_map(|scope| &scope.spans)
            .map(|span| span.span_id[0])
            .collect()
    }

    #[test]
    fn request_split_halves_a_batch_just_over_the_limit() {
        let batch: Vec<Span> = (1..=8).map(|id| span(id, 100)).collect();
        let whole = otlp::encode("edge", &batch).len();

        let (requests, oversized) = split(batch.clone(), whole, encode);
        assert_eq!(oversized, 0);
        assert_eq!(requests.len(), 1, "a batch at the limit is one request");
        assert_eq!(requests[0].0, 8);
        assert_eq!(ids(&requests[0].1), (1..=8).collect::<Vec<u8>>());

        let (requests, oversized) = split(batch, whole - 1, encode);
        assert_eq!(oversized, 0);
        assert_eq!(requests.len(), 2, "one byte over splits it once");
        let mut all = Vec::new();
        for (count, body) in &requests {
            assert!(body.len() < whole, "each half is under the limit");
            let sent = ids(body);
            assert_eq!(sent.len(), *count);
            all.extend(sent);
        }
        assert_eq!(
            all,
            (1..=8).collect::<Vec<u8>>(),
            "every span, in order, once"
        );
        assert_eq!((requests[0].0, requests[1].0), (4, 4));
    }

    #[test]
    fn request_split_keeps_halving_until_every_request_fits() {
        let batch: Vec<Span> = (1..=16).map(|id| span(id, 100)).collect();
        let one = otlp::encode("edge", &batch[..1]).len();
        let (requests, oversized) = split(batch, one + 10, encode);
        assert_eq!(oversized, 0);
        assert_eq!(requests.len(), 16, "only single spans fit");
        assert!(
            requests
                .iter()
                .all(|(count, body)| *count == 1 && body.len() <= one + 10)
        );
        let all: Vec<u8> = requests.iter().flat_map(|(_, body)| ids(body)).collect();
        assert_eq!(all, (1..=16).collect::<Vec<u8>>());
    }

    #[test]
    fn request_split_drops_and_counts_a_span_over_the_limit() {
        let small = otlp::encode("edge", &[span(1, 10)]).len();
        let limit = small + 20;
        let (requests, oversized) =
            split(vec![span(1, 10), span(2, 1000), span(3, 10)], limit, encode);
        assert_eq!(oversized, 1, "the big span alone exceeds the limit");
        let all: Vec<u8> = requests.iter().flat_map(|(_, body)| ids(body)).collect();
        assert_eq!(all, vec![1, 3], "the others are still sent");

        let (requests, oversized) = split(vec![span(2, 1000)], limit, encode);
        assert!(requests.is_empty());
        assert_eq!(oversized, 1);
    }
}
