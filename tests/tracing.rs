//! OpenTelemetry tracing: trace context to the upstream, spans exported to an
//! OTLP/HTTP collector, sampling and its rate cap, and a collector that is down or slow. The
//! collector here is a local server that decodes what the exporter POSTs.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use common::{Podgate, TestCert, app, serving, snapshot};
use podgate::observe::tracing::proto::{ExportTraceServiceRequest, OtlpSpan, any_value};
use prost::Message;
use rustls_pki_types::pem::PemObject;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::sleep;

/// The exporter sends what it has every two seconds; a test that expects no span waits longer.
const SETTLE: Duration = Duration::from_millis(3200);

const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT: &str = "00f067aa0ba902b7";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Answer 200.
    Ok,
    /// Take the connection and never answer.
    Blackhole,
}

#[derive(Debug)]
struct Received {
    path: String,
    headers: Vec<(String, String)>,
    accepted: bool,
    request: ExportTraceServiceRequest,
}

/// A fake OTLP/HTTP collector.
struct Collector {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
}

struct CollectorState {
    mode: Mode,
    fail_first: usize,
    seen: AtomicUsize,
    received: Arc<Mutex<Vec<Received>>>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn read_more<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> bool {
    matches!(stream.read_buf(buf).await, Ok(read) if read > 0)
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, state: Arc<CollectorState>) {
    if state.mode == Mode::Blackhole {
        std::future::pending::<()>().await;
    }
    let mut buf = Vec::new();
    loop {
        let head_end = loop {
            if let Some(at) = find(&buf, b"\r\n\r\n") {
                break at + 4;
            }
            if !read_more(&mut stream, &mut buf).await {
                return;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let path = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_owned();
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let length: usize = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);
        while buf.len() < head_end + length {
            if !read_more(&mut stream, &mut buf).await {
                return;
            }
        }
        let request = ExportTraceServiceRequest::decode(&buf[head_end..head_end + length])
            .expect("the body is an OTLP trace export");
        buf.drain(..head_end + length);
        let accepted = state.seen.fetch_add(1, Ordering::SeqCst) >= state.fail_first;
        state
            .received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Received {
                path,
                headers,
                accepted,
                request,
            });
        let status = if accepted {
            "200 OK"
        } else {
            "503 Service Unavailable"
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\n\r\n"
        );
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

impl Collector {
    async fn start() -> Self {
        Self::start_with(Mode::Ok, 0, None).await
    }

    async fn start_with(mode: Mode, fail_first: usize, tls: Option<&TestCert>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind collector");
        let addr = listener.local_addr().expect("collector address");
        let received = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(CollectorState {
            mode,
            fail_first,
            seen: AtomicUsize::new(0),
            received: Arc::clone(&received),
        });
        let acceptor = tls.map(|cert| {
            let chain = rustls::pki_types::CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("certificate chain");
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes())
                .expect("private key");
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server certificate");
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
        });
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&state);
                match acceptor.clone() {
                    Some(acceptor) => {
                        tokio::spawn(async move {
                            if let Ok(stream) = acceptor.accept(stream).await {
                                serve(stream, state).await;
                            }
                        });
                    }
                    None => {
                        tokio::spawn(serve(stream, state));
                    }
                }
            }
        });
        Self { addr, received }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> usize {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Every span of the accepted exports so far.
    fn spans(&self) -> Vec<OtlpSpan> {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|received| received.accepted)
            .flat_map(|received| &received.request.resource_spans)
            .flat_map(|resource| &resource.scope_spans)
            .flat_map(|scope| scope.spans.clone())
            .collect()
    }

    /// Waits until at least `count` spans arrived, and returns all of them.
    async fn wait_spans(&self, count: usize) -> Vec<OtlpSpan> {
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let spans = self.spans();
            if spans.len() >= count {
                return spans;
            }
            assert!(
                Instant::now() < deadline,
                "wanted {count} spans, the collector has {}",
                spans.len()
            );
            sleep(Duration::from_millis(50)).await;
        }
    }
}

/// The headers of each request an [`Echo`] got.
type Seen = Arc<Mutex<Vec<Vec<(String, String)>>>>;

/// A backend that records the headers of every request it gets.
struct Echo {
    addr: SocketAddr,
    seen: Seen,
}

impl Echo {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let addr = listener.local_addr().expect("upstream address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(echo_connection(stream, Arc::clone(&log)));
            }
        });
        Self { addr, seen }
    }

    /// The values of header `name` in the last request, joined with `, `; `None` when absent.
    fn last_header(&self, name: &str) -> Option<String> {
        let seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let values: Vec<&str> = seen
            .last()?
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }
}

async fn echo_connection(mut stream: TcpStream, log: Seen) {
    const RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let mut buf = Vec::new();
    loop {
        while let Some(end) = find(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            buf.drain(..end + 4);
            let headers = head
                .split("\r\n")
                .skip(1)
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
                .collect();
            log.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(headers);
            if stream.write_all(RESPONSE.as_bytes()).await.is_err() {
                return;
            }
        }
        if !read_more(&mut stream, &mut buf).await {
            return;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Attr {
    Str(String),
    Int(i64),
    List(Vec<String>),
}

fn attrs(span: &OtlpSpan) -> BTreeMap<String, Attr> {
    span.attributes
        .iter()
        .map(|pair| {
            let value = match pair.value.as_ref().and_then(|any| any.value.as_ref()) {
                Some(any_value::Value::String(text)) => Attr::Str(text.clone()),
                Some(any_value::Value::Int(number)) => Attr::Int(*number),
                Some(any_value::Value::Array(list)) => Attr::List(
                    list.values
                        .iter()
                        .map(|item| match &item.value {
                            Some(any_value::Value::String(text)) => text.clone(),
                            other => panic!("list item is not a string: {other:?}"),
                        })
                        .collect(),
                ),
                None => panic!("attribute {} has no value", pair.key),
            };
            (pair.key.clone(), value)
        })
        .collect()
}

fn text(value: &str) -> Attr {
    Attr::Str(value.to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn server_and_client(spans: &[OtlpSpan]) -> (&OtlpSpan, &OtlpSpan) {
    let server = spans
        .iter()
        .find(|span| span.kind == 2)
        .expect("a server span");
    let client = spans
        .iter()
        .find(|span| span.kind == 3)
        .expect("a client span");
    (server, client)
}

/// Splits `00-<trace>-<span>-<flags>`.
fn parts(traceparent: &str) -> (String, String, String) {
    let fields: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(fields.len(), 4, "{traceparent}");
    assert_eq!(fields[0], "00");
    assert_eq!(fields[1].len(), 32, "{traceparent}");
    assert_eq!(fields[2].len(), 16, "{traceparent}");
    (
        fields[1].to_owned(),
        fields[2].to_owned(),
        fields[3].to_owned(),
    )
}

fn collector_env(collector: &Collector) -> Vec<(String, String)> {
    vec![("OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(), collector.url())]
}

async fn start(env: &[(String, String)], tracing: Value) -> (Podgate, Echo) {
    start_as(env, tracing, false).await
}

/// [`start`] with the loopback peer trusted by the `web` entry point's `forwarded_headers`.
async fn start_trusted(env: &[(String, String)], tracing: Value) -> (Podgate, Echo) {
    start_as(env, tracing, true).await
}

async fn start_as(env: &[(String, String)], tracing: Value, trusted: bool) -> (Podgate, Echo) {
    let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let podgate = Podgate::start_with_env(&pairs).await;
    let echo = Echo::start().await;
    push_as(&podgate, &echo, 1, tracing, trusted).await;
    (podgate, echo)
}

async fn push(podgate: &Podgate, echo: &Echo, version: u64, tracing: Value) {
    push_as(podgate, echo, version, tracing, false).await;
}

async fn push_as(podgate: &Podgate, echo: &Echo, version: u64, tracing: Value, trusted: bool) {
    let mut pushed = snapshot(
        version,
        &[app("a.test", &["a.test"], &[serving("r1", echo.addr)])],
    );
    if !tracing.is_null() {
        pushed["observability"] = json!({ "tracing": tracing });
    }
    if trusted {
        pushed["entry_points"] =
            json!([{ "name": "web", "forwarded_headers": { "trusted_ips": ["127.0.0.1/32"] } }]);
    }
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
}

fn sampled_parent() -> String {
    format!("00-{TRACE}-{PARENT}-01")
}

fn metric(metrics: &str, name: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(name)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("{name} is not in /metrics:\n{metrics}"))
}

#[tokio::test]
async fn trace_exported_to_otlp() {
    let collector = Collector::start().await;
    let mut env = collector_env(&collector);
    env.push((
        "OTEL_EXPORTER_OTLP_HEADERS".into(),
        "x-api-key=s3cret".into(),
    ));
    env.push(("OTEL_SERVICE_NAME".into(), "edge".into()));
    let (podgate, _echo) = start(&env, json!({})).await;

    let response = podgate.get("a.test", "/hello").await;
    assert_eq!((response.status, response.body.as_str()), (200, "hello"));

    let spans = collector.wait_spans(2).await;
    assert_eq!(spans.len(), 2, "one server span and one upstream span");
    let (server, client) = server_and_client(&spans);
    assert_eq!(server.trace_id, client.trace_id);
    assert_eq!(
        client.parent_span_id, server.span_id,
        "the upstream span is the server span's child"
    );
    assert!(
        server.parent_span_id.is_empty(),
        "a root request has no parent"
    );
    assert!(server.end_time_unix_nano >= server.start_time_unix_nano);
    assert!(client.start_time_unix_nano >= server.start_time_unix_nano);
    assert!(client.end_time_unix_nano <= server.end_time_unix_nano + 1_000_000);
    assert_eq!(server.name, "GET default");

    let received = collector
        .received
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let first = received.first().expect("an export");
    assert_eq!(first.path, "/v1/traces");
    let header = |name: &str| {
        first
            .headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    assert_eq!(header("content-type"), Some("application/x-protobuf"));
    assert_eq!(
        header("x-api-key"),
        Some("s3cret"),
        "OTEL_EXPORTER_OTLP_HEADERS are sent"
    );
    let resource = first.request.resource_spans[0]
        .resource
        .as_ref()
        .expect("resource");
    assert_eq!(resource.attributes[0].key, "service.name");
    assert_eq!(
        resource.attributes[0]
            .value
            .as_ref()
            .and_then(|any| any.value.clone()),
        Some(any_value::Value::String("edge".to_owned()))
    );
}

#[tokio::test]
async fn trace_attributes_documented() {
    let collector = Collector::start().await;
    let (podgate, echo) = start(&collector_env(&collector), json!({})).await;

    let response = podgate.get("a.test", "/hello").await;
    assert_eq!(response.status, 200);
    let spans = collector.wait_spans(2).await;
    let (server, client) = server_and_client(&spans);

    let mut wanted: BTreeMap<String, Attr> = BTreeMap::new();
    for (key, value) in [
        ("http.request.method", text("GET")),
        ("url.path", text("/hello")),
        ("http.response.status_code", Attr::Int(200)),
        ("server.address", text("a.test")),
        ("network.peer.address", text("127.0.0.1")),
        ("podgate.tenant", text("t1")),
        ("podgate.app", text("a.test")),
        ("podgate.router", text("default")),
        ("podgate.service", text("web")),
        ("podgate.revision", text("r1")),
    ] {
        wanted.insert(key.to_owned(), value);
    }
    assert_eq!(
        attrs(server),
        wanted,
        "the server span carries exactly the documented attributes"
    );
    assert!(server.status.is_none(), "a 200 is not an error");

    let mut wanted: BTreeMap<String, Attr> = BTreeMap::new();
    for (key, value) in [
        ("http.request.method", text("GET")),
        ("http.response.status_code", Attr::Int(200)),
        ("server.address", text("127.0.0.1")),
        ("server.port", Attr::Int(i64::from(echo.addr.port()))),
        ("podgate.revision", text("r1")),
    ] {
        wanted.insert(key.to_owned(), value);
    }
    assert_eq!(
        attrs(client),
        wanted,
        "the upstream span carries exactly the documented attributes"
    );
    assert_eq!(client.name, "GET");
}

#[tokio::test]
async fn failed_upstream_marks_the_spans_as_errors() {
    let collector = Collector::start().await;
    let refused = common::refused();
    let podgate =
        Podgate::start_with_env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", &collector.url())]).await;
    let mut pushed = snapshot(
        1,
        &[app("a.test", &["a.test"], &[serving("r1", refused.addr)])],
    );
    pushed["observability"] = json!({ "tracing": {} });
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 502, "{response:?}");
    let spans = collector.wait_spans(2).await;
    let (server, client) = server_and_client(&spans);
    assert_eq!(server.status.as_ref().map(|status| status.code), Some(2));
    assert_eq!(
        attrs(server).get("http.response.status_code"),
        Some(&Attr::Int(502))
    );
    assert_eq!(client.status.as_ref().map(|status| status.code), Some(2));
}

#[tokio::test]
async fn traceparent_propagated_to_upstream() {
    let collector = Collector::start().await;
    let (podgate, echo) = start(&collector_env(&collector), json!({})).await;
    let incoming = sampled_parent();

    let response = podgate
        .get_with_headers("a.test", "/", &[("traceparent", &incoming)])
        .await;
    assert_eq!(response.status, 200);

    let sent = echo
        .last_header("traceparent")
        .expect("the upstream got a traceparent");
    let (trace, span, flags) = parts(&sent);
    assert_eq!(trace, TRACE, "the trace continues");
    assert_ne!(
        span, PARENT,
        "the upstream is told a child span, not the caller's"
    );
    assert_eq!(flags, "01");

    let spans = collector.wait_spans(2).await;
    let (server, client) = server_and_client(&spans);
    assert_eq!(hex(&server.trace_id), TRACE);
    assert_eq!(
        hex(&server.parent_span_id),
        PARENT,
        "the server span's parent is the caller's span"
    );
    assert_eq!(
        hex(&client.span_id),
        span,
        "the upstream's parent is the upstream span"
    );
    assert_eq!(client.parent_span_id, server.span_id);
}

#[tokio::test]
async fn traceparent_generated_when_absent() {
    let (podgate, echo) = start(&[], json!({})).await;

    podgate.get("a.test", "/").await;
    let first = parts(
        &echo
            .last_header("traceparent")
            .expect("a generated traceparent"),
    );
    assert_ne!(first.0, "0".repeat(32));
    assert_ne!(first.1, "0".repeat(16));
    podgate.get("a.test", "/").await;
    let second = parts(
        &echo
            .last_header("traceparent")
            .expect("a generated traceparent"),
    );
    assert_ne!(first.0, second.0, "each request starts its own trace");

    for bad in [
        "garbage".to_owned(),
        format!("00-{}-{PARENT}-01", "0".repeat(32)),
        format!("00-{}-{PARENT}-01", TRACE.to_uppercase()),
    ] {
        podgate
            .get_with_headers(
                "a.test",
                "/",
                &[("traceparent", &bad), ("tracestate", "vendor=forged")],
            )
            .await;
        let replaced = parts(&echo.last_header("traceparent").expect("a traceparent"));
        assert_ne!(replaced.0, TRACE, "{bad}");
        assert_eq!(
            echo.last_header("tracestate"),
            None,
            "the tracestate of a request whose traceparent is invalid is dropped"
        );
    }
}

#[tokio::test]
async fn tracestate_passed_through() {
    let (podgate, echo) = start(&[], json!({})).await;
    let incoming = sampled_parent();

    podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("traceparent", &incoming),
                ("tracestate", "vendor=abc,other=1"),
            ],
        )
        .await;
    assert_eq!(
        echo.last_header("tracestate").as_deref(),
        Some("vendor=abc,other=1"),
        "the caller's tracestate reaches the upstream unchanged, with no entry added"
    );
}

#[tokio::test]
async fn propagate_false_leaves_the_header_alone() {
    let (podgate, echo) = start(&[], json!({ "propagate": false })).await;
    podgate.get("a.test", "/").await;
    assert_eq!(
        echo.last_header("traceparent"),
        None,
        "no traceparent is invented"
    );
    let incoming = sampled_parent();
    podgate
        .get_with_headers("a.test", "/", &[("traceparent", &incoming)])
        .await;
    assert_eq!(
        echo.last_header("traceparent"),
        Some(incoming),
        "the caller's header is passed as it is"
    );
}

#[tokio::test]
async fn router_switch_turns_tracing_off() {
    let collector = Collector::start().await;
    let podgate =
        Podgate::start_with_env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", &collector.url())]).await;
    let echo = Echo::start().await;
    let mut quiet = app("a.test", &["a.test"], &[serving("r1", echo.addr)]);
    quiet["routers"][0]["observability"] = json!({ "tracing": false });
    let mut pushed = snapshot(1, &[quiet]);
    pushed["observability"] = json!({ "tracing": {} });
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    podgate.get("a.test", "/").await;
    assert_eq!(echo.last_header("traceparent"), None);
    sleep(SETTLE).await;
    assert_eq!(collector.requests(), 0);

    let mut loud = app("a.test", &["a.test"], &[serving("r1", echo.addr)]);
    loud["routers"][0]["observability"] = json!({ "tracing": true });
    let pushed = snapshot(2, &[loud]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    podgate.get("a.test", "/").await;
    assert!(echo.last_header("traceparent").is_some());
    collector.wait_spans(2).await;
}

#[tokio::test]
async fn sample_zero_exports_nothing_but_propagates() {
    let collector = Collector::start().await;
    let (podgate, echo) = start(&collector_env(&collector), json!({ "sample_percent": 0 })).await;

    for _ in 0..5 {
        podgate.get("a.test", "/").await;
    }
    let (_, _, flags) = parts(&echo.last_header("traceparent").expect("still propagated"));
    assert_eq!(flags, "00", "an unsampled trace says so");
    sleep(SETTLE).await;
    assert_eq!(collector.requests(), 0, "nothing was exported");

    push(&podgate, &echo, 2, json!({ "sample_percent": 100 })).await;
    podgate.get("a.test", "/").await;
    let spans = collector.wait_spans(2).await;
    assert_eq!(
        spans.len(),
        2,
        "the collector works: only the sampled request exported"
    );
    let (_, _, flags) = parts(&echo.last_header("traceparent").expect("propagated"));
    assert_eq!(flags, "01");
}

#[tokio::test]
async fn parent_based_honours_incoming_flag() {
    let collector = Collector::start().await;
    let (podgate, echo) =
        start_trusted(&collector_env(&collector), json!({ "sample_percent": 0 })).await;
    let sampled = sampled_parent();
    let unsampled = format!("00-{TRACE}-{PARENT}-00");

    podgate
        .get_with_headers("a.test", "/", &[("traceparent", &sampled)])
        .await;
    let (_, _, flags) = parts(&echo.last_header("traceparent").expect("propagated"));
    assert_eq!(flags, "01", "parent_based keeps a sampled caller sampled");
    let spans = collector.wait_spans(2).await;
    assert_eq!(hex(&spans[0].trace_id), TRACE);

    push_as(
        &podgate,
        &echo,
        2,
        json!({ "sample_percent": 0, "parent_based": false }),
        true,
    )
    .await;
    podgate
        .get_with_headers("a.test", "/", &[("traceparent", &sampled)])
        .await;
    let (_, _, flags) = parts(&echo.last_header("traceparent").expect("propagated"));
    assert_eq!(
        flags, "00",
        "without parent_based the caller's flag decides nothing"
    );

    push_as(
        &podgate,
        &echo,
        3,
        json!({ "sample_percent": 100, "parent_based": true }),
        true,
    )
    .await;
    podgate
        .get_with_headers("a.test", "/", &[("traceparent", &unsampled)])
        .await;
    let (_, _, flags) = parts(&echo.last_header("traceparent").expect("propagated"));
    assert_eq!(
        flags, "00",
        "parent_based keeps an unsampled caller unsampled"
    );

    sleep(SETTLE).await;
    assert_eq!(
        collector.spans().len(),
        2,
        "only the first request was exported"
    );
}

#[tokio::test]
async fn forced_sampling_is_rate_capped() {
    let collector = Collector::start().await;
    let mut env = collector_env(&collector);
    env.push(("OTEL_MAX_SPANS_PER_SEC".into(), "10".into()));
    let (podgate, _echo) = start_trusted(&env, json!({ "sample_percent": 0 })).await;
    let forced = sampled_parent();

    let started = Instant::now();
    for _ in 0..60 {
        let response = podgate
            .get_with_headers("a.test", "/", &[("traceparent", &forced)])
            .await;
        assert_eq!(response.status, 200);
    }
    let elapsed = started.elapsed().as_secs_f64();
    sleep(SETTLE).await;

    let exported = collector.spans().len();
    // A burst of one second's worth, then ten a second.
    let ceiling = 10.0 + 10.0 * elapsed + 2.0;
    assert!(
        exported >= 2,
        "the cap still lets some through, got {exported}"
    );
    #[allow(clippy::cast_precision_loss, reason = "a handful of spans")]
    let exported_f = exported as f64;
    assert!(
        exported_f <= ceiling,
        "60 forced requests over {elapsed:.2}s exported {exported} spans, the cap allows at most {ceiling:.0}"
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metric(&metrics, "podgate_trace_rate_limited_total") > 0,
        "{metrics}"
    );
}

#[tokio::test]
async fn exporter_retries_then_succeeds() {
    let collector = Collector::start_with(Mode::Ok, 1, None).await;
    let (podgate, _echo) = start(&collector_env(&collector), json!({})).await;
    podgate.get("a.test", "/").await;
    let spans = collector.wait_spans(2).await;
    assert_eq!(spans.len(), 2);
    assert_eq!(collector.requests(), 2, "the 503 was retried");
}

/// 100 sequential requests and the slowest of them.
async fn slowest_of_a_hundred(podgate: &Podgate) -> Duration {
    let mut slowest = Duration::ZERO;
    for _ in 0..100 {
        let started = Instant::now();
        let response = podgate.get("a.test", "/").await;
        assert_eq!(response.status, 200);
        slowest = slowest.max(started.elapsed());
    }
    slowest
}

#[tokio::test]
async fn exporter_down_does_not_slow_requests() {
    // A collector that takes the connection and never answers: an export waits 3 seconds.
    let hung = Collector::start_with(Mode::Blackhole, 0, None).await;
    let (podgate, _echo) = start(&collector_env(&hung), json!({})).await;
    let slowest = slowest_of_a_hundred(&podgate).await;
    assert!(
        slowest < Duration::from_millis(1500),
        "a hung collector slowed a request to {slowest:?}"
    );

    // A collector that is not there: connecting is refused.
    let refused = common::refused();
    let env = vec![(
        "OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(),
        format!("http://{}", refused.addr),
    )];
    let (podgate, _echo) = start(&env, json!({})).await;
    let slowest = slowest_of_a_hundred(&podgate).await;
    assert!(
        slowest < Duration::from_millis(1500),
        "a dead collector slowed a request to {slowest:?}"
    );
    sleep(SETTLE).await;
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metric(&metrics, "podgate_trace_dropped_total") > 0,
        "spans that could not be delivered are counted:\n{metrics}"
    );
}

#[tokio::test]
async fn trace_queue_bounded() {
    let hung = Collector::start_with(Mode::Blackhole, 0, None).await;
    let mut env = collector_env(&hung);
    env.push(("OTEL_MAX_SPANS_PER_SEC".into(), "1000000".into()));
    let (podgate, _echo) = start(&env, json!({})).await;
    let podgate = Arc::new(podgate);

    // 1600 requests make 3200 spans: more than the queue (2048) and the batch in flight (512).
    let mut sent = JoinSet::new();
    for _ in 0..1600 {
        let podgate = Arc::clone(&podgate);
        sent.spawn(async move { podgate.get("a.test", "/").await.status });
        if sent.len() >= 32 {
            let status = sent.join_next().await.expect("a request").expect("joined");
            assert_eq!(status, 200);
        }
    }
    while let Some(status) = sent.join_next().await {
        assert_eq!(status.expect("joined"), 200);
    }

    let metrics = podgate.admin_get("/metrics").await.body;
    let queued = metric(&metrics, "podgate_trace_queue_spans");
    let dropped = metric(&metrics, "podgate_trace_dropped_total");
    assert!(
        queued <= 2048,
        "the queue holds {queued} spans, its bound is 2048:\n{metrics}"
    );
    assert!(
        dropped >= 100,
        "spans past the bound are counted as dropped, got {dropped}:\n{metrics}"
    );
}

#[tokio::test]
async fn header_attributes_allowlist_only() {
    let collector = Collector::start().await;
    let policy = json!({ "attribute_headers": ["X-Request-Id", "accept"] });
    let (podgate, _echo) = start(&collector_env(&collector), policy).await;

    podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("X-Request-Id", "req-42"),
                ("Accept", "text/html"),
                ("Accept", "text/plain"),
                ("Authorization", "Bearer hunter2"),
                ("Cookie", "session=hunter2"),
                ("X-Other", "not-listed"),
                ("User-Agent", "probe/1"),
            ],
        )
        .await;
    let spans = collector.wait_spans(2).await;
    let (server, client) = server_and_client(&spans);
    let found = attrs(server);
    assert_eq!(
        found.get("http.request.header.x-request-id"),
        Some(&Attr::List(vec!["req-42".into()]))
    );
    assert_eq!(
        found.get("http.request.header.accept"),
        Some(&Attr::List(vec!["text/html".into(), "text/plain".into()]))
    );
    let headers: Vec<&String> = found
        .keys()
        .filter(|key| key.starts_with("http.request.header."))
        .collect();
    assert_eq!(
        headers.len(),
        2,
        "only the allow-listed headers: {headers:?}"
    );
    for span in [server, client] {
        let dump = format!("{:?}", attrs(span));
        for secret in ["hunter2", "Bearer", "session=", "not-listed", "probe/1"] {
            assert!(
                !dump.contains(secret),
                "{secret} leaked into a span: {dump}"
            );
        }
    }

    // A tenant cannot ask for credentials to be copied into the operator's trace store.
    for header in [
        "Authorization",
        "proxy-authorization",
        "Cookie",
        "set-cookie",
    ] {
        let mut pushed = snapshot(
            9,
            &[app(
                "a.test",
                &["a.test"],
                &[serving("r1", "127.0.0.1:9".parse().expect("addr"))],
            )],
        );
        pushed["observability"] = json!({ "tracing": { "attribute_headers": [header] } });
        let response = podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 422, "{header}: {response:?}");
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_tracing",
            "{header}"
        );
    }
}

#[tokio::test]
async fn query_never_in_span() {
    let collector = Collector::start().await;
    let (podgate, _echo) = start(&collector_env(&collector), json!({})).await;

    podgate
        .get("a.test", "/search?token=hunter2&user=alice%40example.com")
        .await;
    let spans = collector.wait_spans(2).await;
    let (server, client) = server_and_client(&spans);
    assert_eq!(attrs(server).get("url.path"), Some(&text("/search")));
    for span in [server, client] {
        let dump = format!("{:?}", attrs(span));
        for leaked in ["hunter2", "token", "alice", "user=", "?"] {
            assert!(
                !dump.contains(leaked),
                "{leaked} leaked into a span: {dump}"
            );
        }
        assert!(!span.name.contains('?'));
    }
}

#[tokio::test]
async fn snapshot_cannot_set_otlp_endpoint() {
    let real = Collector::start().await;
    let decoy = Collector::start().await;
    let (podgate, echo) = start(&collector_env(&real), json!({})).await;

    for field in ["endpoint", "otlp_endpoint", "headers", "collector"] {
        let mut pushed = snapshot(
            5,
            &[app("a.test", &["a.test"], &[serving("r1", echo.addr)])],
        );
        pushed["observability"] = json!({ "tracing": { field: decoy.url() } });
        let response = podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 422, "{field}: {response:?}");
        let conflict = &response.json()["conflicts"][0];
        assert_eq!(conflict["code"], "invalid_tracing", "{field}");
        assert!(
            conflict["message"]
                .as_str()
                .unwrap_or_default()
                .contains("OTEL_EXPORTER_OTLP_ENDPOINT"),
            "{conflict}"
        );
    }
    let mut routed = app("a.test", &["a.test"], &[serving("r1", echo.addr)]);
    routed["routers"][0]["observability"] = json!({ "tracing": { "endpoint": decoy.url() } });
    let response = podgate.push_snapshot(&snapshot(6, &[routed])).await;
    assert_eq!(response.status, 422, "{response:?}");
    assert_eq!(response.json()["conflicts"][0]["code"], "invalid_tracing");

    podgate.get("a.test", "/").await;
    real.wait_spans(2).await;
    sleep(SETTLE).await;
    assert_eq!(
        decoy.requests(),
        0,
        "nothing was ever sent to an address a snapshot named"
    );
}

#[tokio::test]
async fn exports_over_https_with_the_operators_ca() {
    let cert = TestCert::new(&["localhost"]);
    let collector = Collector::start_with(Mode::Ok, 0, Some(&cert)).await;
    let dir = std::env::temp_dir().join(format!("podgate-otel-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the directory");
    let ca: PathBuf = dir.join("ca.pem");
    std::fs::write(&ca, &cert.cert_pem).expect("write the CA");
    let env = vec![
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(),
            format!("https://localhost:{}", collector.addr.port()),
        ),
        (
            "OTEL_EXPORTER_OTLP_CERTIFICATE".to_owned(),
            ca.display().to_string(),
        ),
    ];
    let (podgate, _echo) = start(&env, json!({})).await;

    podgate.get("a.test", "/").await;
    let spans = collector.wait_spans(2).await;
    assert_eq!(spans.len(), 2);
    drop(std::fs::remove_dir_all(&dir));
}

#[tokio::test]
async fn bad_otel_settings_stop_startup() {
    for (var, value) in [
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "not a url"),
        ("OTEL_MAX_SPANS_PER_SEC", "0"),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_podgate"))
            .env(var, value)
            .env(
                "ADMIN_SOCKET",
                std::env::temp_dir().join("podgate-otel-bad.sock"),
            )
            .output()
            .expect("run podgate");
        assert!(!output.status.success(), "{var}={value} must stop startup");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(var), "the error names {var}: {stderr}");
    }
}

#[tokio::test]
async fn tracing_untrusted_sampled_flag_not_honoured() {
    let collector = Collector::start().await;
    let (podgate, echo) = start(&collector_env(&collector), json!({ "sample_percent": 0 })).await;
    let forced = sampled_parent();

    for _ in 0..5 {
        podgate
            .get_with_headers("a.test", "/", &[("traceparent", &forced)])
            .await;
    }
    let (trace, span, flags) = parts(&echo.last_header("traceparent").expect("propagated"));
    assert_eq!(
        trace, TRACE,
        "the trace id is still continued, for correlation"
    );
    assert_ne!(span, PARENT);
    assert_eq!(
        flags, "00",
        "an untrusted peer's sampled flag is not believed"
    );
    sleep(SETTLE).await;
    assert_eq!(collector.requests(), 0, "nothing was exported");

    // A trust policy that does not cover the peer changes nothing.
    let mut pushed = snapshot(
        2,
        &[app("a.test", &["a.test"], &[serving("r1", echo.addr)])],
    );
    pushed["observability"] = json!({ "tracing": { "sample_percent": 0 } });
    pushed["entry_points"] =
        json!([{ "name": "web", "forwarded_headers": { "trusted_ips": ["10.0.0.0/8"] } }]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    podgate
        .get_with_headers("a.test", "/", &[("traceparent", &forced)])
        .await;
    let (_, _, flags) = parts(&echo.last_header("traceparent").expect("propagated"));
    assert_eq!(flags, "00");
    sleep(SETTLE).await;
    assert_eq!(collector.requests(), 0);
}

#[tokio::test]
async fn tracing_trusted_peer_sampled_flag_honoured() {
    let collector = Collector::start().await;
    let (podgate, echo) =
        start_trusted(&collector_env(&collector), json!({ "sample_percent": 0 })).await;
    let forced = sampled_parent();

    podgate
        .get_with_headers("a.test", "/", &[("traceparent", &forced)])
        .await;
    let (trace, _, flags) = parts(&echo.last_header("traceparent").expect("propagated"));
    assert_eq!((trace.as_str(), flags.as_str()), (TRACE, "01"));
    let spans = collector.wait_spans(2).await;
    let (server, _) = server_and_client(&spans);
    assert_eq!(hex(&server.parent_span_id), PARENT);
}

#[tokio::test]
async fn tracing_one_tenant_cannot_take_the_whole_cap() {
    let collector = Collector::start().await;
    let mut env = collector_env(&collector);
    env.push(("OTEL_MAX_SPANS_PER_SEC".into(), "20".into()));
    let podgate = Podgate::start_with_env(
        &env.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
    )
    .await;
    let echo = Echo::start().await;
    let mut pushed = snapshot(
        1,
        &[
            app("a.test", &["a.test"], &[serving("r1", echo.addr)]),
            app("b.test", &["b.test"], &[serving("r1", echo.addr)]),
        ],
    );
    pushed["tenants"] = json!([
        { "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
        { "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
    ]);
    pushed["apps"][1]["tenant"] = json!("t2");
    pushed["observability"] = json!({ "tracing": {} });
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let started = Instant::now();
    for _ in 0..200 {
        podgate.get("a.test", "/").await;
    }
    let flood = started.elapsed().as_secs_f64();
    for _ in 0..3 {
        podgate.get("b.test", "/").await;
    }
    sleep(SETTLE).await;

    let spans = collector.spans();
    let traced = |tenant: &str| {
        spans
            .iter()
            .filter(|span| span.kind == 2)
            .filter(|span| attrs(span).get("podgate.tenant") == Some(&text(tenant)))
            .count()
    };
    assert_eq!(
        traced("t2"),
        3,
        "the quiet tenant's requests are all traced"
    );
    // A tenant's bucket is half of 20 spans a second: 10 up front, 10 a second, two spans a request.
    #[allow(clippy::cast_precision_loss, reason = "a handful of requests")]
    let ceiling = (10.0 + 10.0 * flood) / 2.0 + 1.0;
    #[allow(clippy::cast_precision_loss, reason = "a handful of requests")]
    let flooder = traced("t1") as f64;
    assert!(flooder >= 2.0, "the flooder still gets its share");
    assert!(
        flooder <= ceiling,
        "200 requests over {flood:.2}s traced {flooder}, a tenant's share allows {ceiling:.0}"
    );
}
