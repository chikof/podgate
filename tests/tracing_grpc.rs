//! Tracing over OTLP/gRPC through the real binary, against a fake collector built on
//! `h2`. The queue, sampling and caps are change 0067's and tested in `tests/tracing.rs`; these
//! tests cover what the gRPC wire adds and that the same protections hold on it.

mod common;

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::Bytes;
use common::grpc::{Messages, frame};
use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use h2::RecvStream;
use h2::server::SendResponse;
use http::{HeaderMap, HeaderValue, Request, Response};
use podgate::observe::tracing::proto::{
    ExportTracePartialSuccess, ExportTraceServiceRequest, ExportTraceServiceResponse, OtlpSpan,
    any_value,
};
use prost::Message;
use rustls_pki_types::pem::PemObject;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time::sleep;

/// The exporter sends what it has every two seconds; a test that expects no span waits longer.
const SETTLE: Duration = Duration::from_millis(3200);

const EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT: &str = "00f067aa0ba902b7";

// ---------------------------------------------------------------------------------------
// The fake collector
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Reply {
    /// `OK` and an empty response.
    Ok,
    /// A trailers-only error, with the server's retry delay when given.
    Status {
        code: u32,
        retry_after: Option<Duration>,
    },
    /// `OK` and a partial success refusing this many spans.
    Partial(i64),
    /// Take the call and never answer.
    Blackhole,
}

#[derive(Debug)]
struct Received {
    path: String,
    headers: Vec<(String, String)>,
    compressed: bool,
    at: Instant,
    connection: u64,
    accepted: bool,
    request: ExportTraceServiceRequest,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Copy)]
enum Tls<'a> {
    None,
    /// A server certificate, and a client certificate the server requires and trusts.
    Mutual(&'a TestCert, &'a TestCert),
}

struct State {
    script: Mutex<VecDeque<Reply>>,
    received: Mutex<Vec<Received>>,
    connections: AtomicU64,
    handshake_failures: AtomicU64,
    /// Close each connection after its first call, so the exporter must reconnect.
    one_call_per_connection: bool,
}

struct Collector {
    addr: SocketAddr,
    state: Arc<State>,
}

#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<Any>,
}

#[derive(Clone, PartialEq, Message)]
struct Any {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct RetryInfo {
    #[prost(message, optional, tag = "1")]
    retry_delay: Option<Delay>,
}

#[derive(Clone, PartialEq, Message)]
struct Delay {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}

/// `grpc-status-details-bin` carrying a `google.rpc.RetryInfo` of `delay`.
fn retry_details(code: u32, delay: Duration) -> HeaderValue {
    let info = RetryInfo {
        retry_delay: Some(Delay {
            seconds: i64::try_from(delay.as_secs()).expect("seconds"),
            nanos: i32::try_from(delay.subsec_nanos()).expect("nanos"),
        }),
    };
    let status = RpcStatus {
        code: i32::try_from(code).expect("code"),
        message: String::new(),
        details: vec![Any {
            type_url: "type.googleapis.com/google.rpc.RetryInfo".to_owned(),
            value: info.encode_to_vec(),
        }],
    };
    let text = base64::engine::general_purpose::STANDARD_NO_PAD.encode(status.encode_to_vec());
    HeaderValue::from_str(&text).expect("header value")
}

/// The body of a gzip stream; checks the header, the CRC and the length.
fn gunzip(data: &[u8]) -> Vec<u8> {
    assert_eq!(&data[..3], [0x1f, 0x8b, 8], "a gzip stream");
    assert_eq!(data[3], 0, "no optional header fields");
    let (body, trailer) = data[10..].split_at(data.len() - 18);
    let plain = miniz_oxide::inflate::decompress_to_vec(body).expect("inflates");
    let crc = u32::from_le_bytes(trailer[..4].try_into().expect("crc"));
    let size = u32::from_le_bytes(trailer[4..].try_into().expect("size"));
    assert_eq!(crc, crc32fast::hash(&plain), "the gzip CRC matches");
    assert_eq!(size as usize, plain.len(), "the gzip length matches");
    plain
}

fn tls_acceptor(tls: Tls<'_>) -> Option<tokio_rustls::TlsAcceptor> {
    let (server, client) = match tls {
        Tls::None => return None,
        Tls::Mutual(server, client) => (server, Some(client)),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions");
    let builder = match client {
        None => builder.with_no_client_auth(),
        Some(client) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(client.der.clone()).expect("client root");
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .expect("client verifier");
            builder.with_client_cert_verifier(verifier)
        }
    };
    let chain = rustls::pki_types::CertificateDer::pem_slice_iter(server.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("certificate chain");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(server.key_pem.as_bytes())
        .expect("private key");
    let mut config = builder
        .with_single_cert(chain, key)
        .expect("server certificate");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

async fn serve_connection<T>(io: T, number: u64, state: Arc<State>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(io).await else {
        return;
    };
    while let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(handle_call(request, respond, number, Arc::clone(&state)));
        if state.one_call_per_connection {
            connection.graceful_shutdown();
        }
    }
}

async fn handle_call(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    connection: u64,
    state: Arc<State>,
) {
    let (head, mut body) = request.into_parts();
    let mut buffer = Messages::default();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return };
        drop(body.flow_control().release_capacity(chunk.len()));
        buffer.push(&chunk);
    }
    let (flag, payload) = buffer.next().expect("one gRPC message");
    let payload = if flag == 1 { gunzip(&payload) } else { payload };
    let request = ExportTraceServiceRequest::decode(payload.as_slice())
        .expect("the message is an OTLP trace export");
    let reply = state
        .script
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .pop_front()
        .unwrap_or(Reply::Ok);
    state
        .received
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Received {
            path: head.uri.path().to_owned(),
            headers: head
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            compressed: flag == 1,
            at: Instant::now(),
            connection,
            accepted: matches!(reply, Reply::Ok | Reply::Partial(_)),
            request,
        });
    let response = Response::builder()
        .status(200)
        .header("content-type", "application/grpc");
    match reply {
        Reply::Blackhole => std::future::pending::<()>().await,
        Reply::Status { code, retry_after } => {
            let mut response = response
                .header("grpc-status", code)
                .header("grpc-message", "refused")
                .body(())
                .expect("response");
            if let Some(delay) = retry_after {
                response
                    .headers_mut()
                    .insert("grpc-status-details-bin", retry_details(code, delay));
            }
            drop(respond.send_response(response, true));
        }
        Reply::Ok | Reply::Partial(_) => {
            let answer = match reply {
                Reply::Partial(rejected) => ExportTraceServiceResponse {
                    partial_success: Some(ExportTracePartialSuccess {
                        rejected_spans: rejected,
                        error_message: "span too old".to_owned(),
                    }),
                },
                _ => ExportTraceServiceResponse::default(),
            };
            let Ok(mut send) = respond.send_response(response.body(()).expect("response"), false)
            else {
                return;
            };
            drop(send.send_data(Bytes::from(frame(&answer.encode_to_vec())), false));
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            drop(send.send_trailers(trailers));
        }
    }
}

impl Collector {
    async fn start() -> Self {
        Self::start_with(&[], Tls::None, false).await
    }

    async fn scripted(script: &[Reply]) -> Self {
        Self::start_with(script, Tls::None, false).await
    }

    async fn start_with(script: &[Reply], tls: Tls<'_>, one_call_per_connection: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind collector");
        let addr = listener.local_addr().expect("collector address");
        let state = Arc::new(State {
            script: Mutex::new(script.iter().copied().collect()),
            received: Mutex::new(Vec::new()),
            connections: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
            one_call_per_connection,
        });
        let acceptor = tls_acceptor(tls);
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let number = shared.connections.fetch_add(1, Ordering::Relaxed) + 1;
                let (state, acceptor) = (Arc::clone(&shared), acceptor.clone());
                tokio::spawn(async move {
                    match acceptor {
                        None => serve_connection(tcp, number, state).await,
                        Some(acceptor) => match acceptor.accept(tcp).await {
                            Ok(stream) => serve_connection(stream, number, state).await,
                            Err(_) => {
                                state.handshake_failures.fetch_add(1, Ordering::Relaxed);
                            }
                        },
                    }
                });
            }
        });
        Self { addr, state }
    }

    /// The `OTEL_EXPORTER_OTLP_ENDPOINT` for this collector.
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> usize {
        self.received(|all| all.len())
    }

    fn received<T>(&self, read: impl FnOnce(&[Received]) -> T) -> T {
        read(
            &self
                .state
                .received
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    fn connections(&self) -> u64 {
        self.state.connections.load(Ordering::Relaxed)
    }

    fn handshake_failures(&self) -> u64 {
        self.state.handshake_failures.load(Ordering::Relaxed)
    }

    /// Every span of the accepted exports so far.
    fn spans(&self) -> Vec<OtlpSpan> {
        self.received(|all| {
            all.iter()
                .filter(|received| received.accepted)
                .flat_map(|received| &received.request.resource_spans)
                .flat_map(|resource| &resource.scope_spans)
                .flat_map(|scope| scope.spans.clone())
                .collect()
        })
    }

    /// Waits until at least `count` spans arrived, and returns all of them.
    async fn wait_spans(&self, count: usize) -> Vec<OtlpSpan> {
        let deadline = Instant::now() + Duration::from_secs(15);
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

    /// Waits until `count` calls arrived, accepted or not.
    async fn wait_requests(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.requests() < count {
            assert!(
                Instant::now() < deadline,
                "wanted {count} calls, the collector got {}",
                self.requests()
            );
            sleep(Duration::from_millis(50)).await;
        }
    }
}

// ---------------------------------------------------------------------------------------
// A fake OTLP/HTTP collector, to compare the two wires
// ---------------------------------------------------------------------------------------

struct HttpCollector {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<(String, ExportTraceServiceRequest)>>>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn serve_http<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    received: Arc<Mutex<Vec<(String, ExportTraceServiceRequest)>>>,
) {
    let mut buf = Vec::new();
    loop {
        let head_end = loop {
            if let Some(at) = find(&buf, b"\r\n\r\n") {
                break at + 4;
            }
            if !matches!(stream.read_buf(&mut buf).await, Ok(read) if read > 0) {
                return;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let path = head
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let length: usize = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse().ok())
            .unwrap_or(0);
        while buf.len() < head_end + length {
            if !matches!(stream.read_buf(&mut buf).await, Ok(read) if read > 0) {
                return;
            }
        }
        let request = ExportTraceServiceRequest::decode(&buf[head_end..head_end + length])
            .expect("an OTLP trace export");
        buf.drain(..head_end + length);
        received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((path, request));
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

impl HttpCollector {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HTTP collector");
        let addr = listener.local_addr().expect("address");
        let received = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::clone(&received);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_http(stream, Arc::clone(&shared)));
            }
        });
        Self { addr, received }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn exports(&self) -> Vec<(String, ExportTraceServiceRequest)> {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn wait_exports(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.exports().len() < count {
            assert!(Instant::now() < deadline, "no export reached the collector");
            sleep(Duration::from_millis(50)).await;
        }
    }
}

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

fn env_of(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

/// The environment of a node that exports to `collector` over gRPC.
fn grpc_env(collector: &Collector) -> Vec<(String, String)> {
    let mut env = env_of(&[("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")]);
    env.push(("OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(), collector.url()));
    env
}

fn pairs(env: &[(String, String)]) -> Vec<(&str, &str)> {
    env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

async fn push(
    podgate: &Podgate,
    upstream: &Upstream,
    version: u64,
    tracing: &Value,
    trusted: bool,
) {
    let mut pushed = snapshot(
        version,
        &[app("a.test", &["a.test"], &[serving("r1", upstream.addr)])],
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

async fn start(env: &[(String, String)]) -> (Podgate, Upstream) {
    start_with(env, &json!({}), false).await
}

async fn start_with(
    env: &[(String, String)],
    tracing: &Value,
    trusted: bool,
) -> (Podgate, Upstream) {
    let podgate = Podgate::start_with_env(&pairs(env)).await;
    let upstream = Upstream::start("hello").await;
    push(&podgate, &upstream, 1, tracing, trusted).await;
    (podgate, upstream)
}

fn metric(metrics: &str, name: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(name)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("{name} is not in /metrics:\n{metrics}"))
}

async fn wait_metric(podgate: &Podgate, name: &str, at_least: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let metrics = podgate.admin_get("/metrics").await.body;
        let value = metric(&metrics, name);
        if value >= at_least {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "{name} is {value}, wanted {at_least}:\n{metrics}"
        );
        sleep(Duration::from_millis(100)).await;
    }
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

/// A span's attributes as `key -> printed value`.
fn attrs(span: &OtlpSpan) -> BTreeMap<String, String> {
    span.attributes
        .iter()
        .map(|pair| (pair.key.clone(), format!("{:?}", pair.value)))
        .collect()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podgate-otlp-grpc-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the directory");
    dir
}

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

// ---------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_export_reaches_collector() {
    let collector = Collector::start().await;
    let mut env = grpc_env(&collector);
    env.extend(env_of(&[("OTEL_SERVICE_NAME", "edge")]));
    let (podgate, _upstream) = start(&env).await;

    let response = podgate.get("a.test", "/hello").await;
    assert_eq!((response.status, response.body.as_str()), (200, "hello"));

    let spans = collector.wait_spans(2).await;
    assert_eq!(spans.len(), 2, "one server span and one upstream span");
    let (server, client) = server_and_client(&spans);
    assert_eq!(server.trace_id, client.trace_id);
    assert_eq!(client.parent_span_id, server.span_id);
    assert!(server.parent_span_id.is_empty());
    assert_eq!(server.name, "GET default");
    let attributes = attrs(server);
    for key in [
        "http.request.method",
        "url.path",
        "http.response.status_code",
        "server.address",
        "network.peer.address",
        "podgate.tenant",
        "podgate.app",
        "podgate.router",
        "podgate.service",
        "podgate.revision",
    ] {
        assert!(attributes.contains_key(key), "{key} in {attributes:?}");
    }

    collector.received(|all| {
        let first = all.first().expect("an export");
        assert_eq!(first.path, EXPORT_PATH);
        assert_eq!(first.header("content-type"), Some("application/grpc"));
        assert_eq!(first.header("te"), Some("trailers"));
        assert!(
            first.header("grpc-timeout").is_some(),
            "the deadline is sent"
        );
        assert!(!first.compressed);
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
    });
}

#[tokio::test]
async fn grpc_spans_match_http_exporter() {
    let http = HttpCollector::start().await;
    let grpc = Collector::start().await;
    let upstream = Upstream::start("hello").await;
    let shared = env_of(&[("OTEL_SERVICE_NAME", "edge")]);

    let mut http_env = shared.clone();
    http_env.push(("OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(), http.url()));
    let mut grpc_env = grpc_env(&grpc);
    grpc_env.extend(shared);

    for env in [&http_env, &grpc_env] {
        let podgate = Podgate::start_with_env(&pairs(env)).await;
        push(
            &podgate,
            &upstream,
            1,
            &json!({ "attribute_headers": ["accept"] }),
            false,
        )
        .await;
        let response = podgate
            .get_with_headers("a.test", "/same?q=1", &[("accept", "text/plain")])
            .await;
        assert_eq!(response.status, 200);
        if env == &http_env {
            http.wait_exports(1).await;
        } else {
            grpc.wait_spans(2).await;
        }
    }

    let http_export = http.exports().remove(0);
    assert_eq!(http_export.0, "/v1/traces");
    let grpc_export = grpc.received(|all| all[0].request.clone());
    let (http_resource, grpc_resource) = (
        &http_export.1.resource_spans[0],
        &grpc_export.resource_spans[0],
    );
    assert_eq!(http_resource.resource, grpc_resource.resource);
    assert_eq!(
        http_resource.scope_spans[0].scope,
        grpc_resource.scope_spans[0].scope
    );

    let http_spans = &http_resource.scope_spans[0].spans;
    let grpc_spans = &grpc_resource.scope_spans[0].spans;
    assert_eq!(http_spans.len(), grpc_spans.len());
    for kind in [2, 3] {
        let pick = |spans: &'_ [OtlpSpan]| {
            spans
                .iter()
                .find(|span| span.kind == kind)
                .cloned()
                .expect("a span of each kind")
        };
        let (over_http, over_grpc) = (pick(http_spans), pick(grpc_spans));
        assert_eq!(over_http.name, over_grpc.name);
        assert_eq!(over_http.status, over_grpc.status);
        assert_eq!(
            over_http.parent_span_id.is_empty(),
            over_grpc.parent_span_id.is_empty()
        );
        assert_eq!(attrs(&over_http), attrs(&over_grpc), "kind {kind}");
    }
}

#[tokio::test]
async fn grpc_headers_as_metadata() {
    let collector = Collector::start().await;
    let mut env = grpc_env(&collector);
    env.extend(env_of(&[(
        "OTEL_EXPORTER_OTLP_HEADERS",
        "x-api-key=s3cret, X-Tenant=acme",
    )]));
    let (podgate, _upstream) = start(&env).await;
    podgate.get("a.test", "/").await;
    collector.wait_spans(2).await;
    collector.received(|all| {
        let first = all.first().expect("an export");
        assert_eq!(first.header("x-api-key"), Some("s3cret"));
        assert_eq!(
            first.header("x-tenant"),
            Some("acme"),
            "names are lowercased"
        );
        assert_eq!(first.header("content-type"), Some("application/grpc"));
    });
}

#[tokio::test]
async fn grpc_gzip_compression() {
    let collector = Collector::start().await;
    let mut env = grpc_env(&collector);
    env.extend(env_of(&[("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip")]));
    let (podgate, _upstream) = start(&env).await;
    podgate.get("a.test", "/").await;
    let spans = collector.wait_spans(2).await;
    assert_eq!(spans.len(), 2, "the compressed export decodes to its spans");
    collector.received(|all| {
        let first = all.first().expect("an export");
        assert!(first.compressed, "the message flag says compressed");
        assert_eq!(first.header("grpc-encoding"), Some("gzip"));
    });
}

// ---------------------------------------------------------------------------------------
// TLS and the plaintext rule
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_tls_and_client_cert() {
    let server_cert = TestCert::new(&["localhost"]);
    let client_cert = TestCert::new(&["podgate-client"]);
    let collector =
        Collector::start_with(&[], Tls::Mutual(&server_cert, &client_cert), false).await;
    let dir = temp_dir("tls");
    let ca = dir.join("ca.pem");
    let cert = dir.join("client.pem");
    let key = dir.join("client.key");
    std::fs::write(&ca, &server_cert.cert_pem).expect("write the CA");
    std::fs::write(&cert, &client_cert.cert_pem).expect("write the client certificate");
    std::fs::write(&key, &client_cert.key_pem).expect("write the client key");
    let endpoint = format!("https://localhost:{}", collector.addr.port());
    let (ca_path, cert_path, key_path) = (
        ca.display().to_string(),
        cert.display().to_string(),
        key.display().to_string(),
    );

    // Without a client certificate the collector refuses the handshake and nothing arrives.
    let anonymous = env_of(&[
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", &endpoint),
        ("OTEL_EXPORTER_OTLP_CERTIFICATE", &ca_path),
    ]);
    let (podgate, _upstream) = start(&anonymous).await;
    podgate.get("a.test", "/").await;
    let deadline = Instant::now() + Duration::from_secs(15);
    while collector.handshake_failures() == 0 {
        assert!(
            Instant::now() < deadline,
            "the collector never refused a handshake"
        );
        sleep(Duration::from_millis(50)).await;
    }
    assert!(collector.spans().is_empty());
    drop(podgate);

    let mut mutual = anonymous.clone();
    mutual.extend(env_of(&[
        ("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", &cert_path),
        ("OTEL_EXPORTER_OTLP_CLIENT_KEY", &key_path),
    ]));
    let (podgate, _upstream) = start(&mutual).await;
    podgate.get("a.test", "/").await;
    let spans = collector.wait_spans(2).await;
    assert_eq!(
        spans.len(),
        2,
        "spans arrive over TLS with a client certificate"
    );
    drop(std::fs::remove_dir_all(&dir));
}

#[tokio::test]
async fn grpc_plaintext_remote_refused() {
    let var = "OTEL_EXPORTER_OTLP_ENDPOINT";
    let run = |extra: &[(&str, &str)]| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_podgate"));
        command
            .env("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
            .env(var, "http://192.0.2.1:4317")
            .env(
                "ADMIN_SOCKET",
                std::env::temp_dir().join("podgate-otel-grpc-bad.sock"),
            );
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().expect("run podgate")
    };
    let output = run(&[]);
    assert!(
        !output.status.success(),
        "a remote plaintext endpoint must stop startup"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(var), "the error names {var}: {stderr}");

    // The operator's decision: it starts, and says so.
    let podgate = Podgate::start_logged(&[
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        (var, "http://192.0.2.1:4317"),
        ("OTEL_EXPORTER_OTLP_INSECURE", "true"),
    ])
    .await;
    assert!(
        podgate.log().contains("OTEL_EXPORTER_OTLP_INSECURE=true"),
        "the warning is logged:\n{}",
        podgate.log()
    );
}

// ---------------------------------------------------------------------------------------
// Status handling
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_retry_on_unavailable() {
    // UNAVAILABLE with a one second retry delay, RESOURCE_EXHAUSTED without, then OK.
    let collector = Collector::scripted(&[
        Reply::Status {
            code: 14,
            retry_after: Some(Duration::from_secs(1)),
        },
        Reply::Status {
            code: 8,
            retry_after: None,
        },
    ])
    .await;
    let (podgate, _upstream) = start(&grpc_env(&collector)).await;
    podgate.get("a.test", "/").await;
    let spans = collector.wait_spans(2).await;
    assert_eq!(spans.len(), 2);
    assert_eq!(collector.requests(), 3, "both refusals were retried");
    collector.received(|all| {
        let waited = all[1].at.duration_since(all[0].at);
        assert!(
            waited >= Duration::from_millis(900),
            "the server's retry delay was honoured, waited {waited:?}"
        );
        let waited = all[2].at.duration_since(all[1].at);
        assert!(
            waited >= Duration::from_millis(200) && waited < Duration::from_millis(900),
            "without a delay the exporter backs off by its own schedule, waited {waited:?}"
        );
    });
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(&metrics, "podgate_trace_dropped_total"),
        0,
        "{metrics}"
    );
    assert_eq!(
        metric(&metrics, "podgate_trace_spans_exported_total"),
        2,
        "{metrics}"
    );
}

#[tokio::test]
async fn grpc_drop_on_invalid_argument() {
    let collector = Collector::scripted(&[
        Reply::Status {
            code: 3,
            retry_after: None,
        },
        Reply::Status {
            code: 16,
            retry_after: None,
        },
    ])
    .await;
    let (podgate, _upstream) = start(&grpc_env(&collector)).await;
    podgate.get("a.test", "/").await;
    collector.wait_requests(1).await;
    wait_metric(&podgate, "podgate_trace_dropped_total", 2).await;
    podgate.get("a.test", "/").await;
    collector.wait_requests(2).await;
    wait_metric(&podgate, "podgate_trace_dropped_total", 4).await;

    sleep(SETTLE).await;
    assert_eq!(
        collector.requests(),
        2,
        "INVALID_ARGUMENT and UNAUTHENTICATED are not retried"
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(&metrics, "podgate_trace_dropped_total"),
        4,
        "{metrics}"
    );
    assert_eq!(
        metric(&metrics, "podgate_trace_spans_exported_total"),
        0,
        "{metrics}"
    );
}

#[tokio::test]
async fn grpc_partial_success_counted() {
    let collector = Collector::scripted(&[Reply::Partial(1)]).await;
    let (podgate, _upstream) = start(&grpc_env(&collector)).await;
    podgate.get("a.test", "/").await;
    collector.wait_requests(1).await;
    wait_metric(&podgate, "podgate_trace_dropped_total", 1).await;
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(&metrics, "podgate_trace_dropped_total"),
        1,
        "one span was refused:\n{metrics}"
    );
    assert_eq!(
        metric(&metrics, "podgate_trace_spans_exported_total"),
        1,
        "one was kept:\n{metrics}"
    );
    sleep(SETTLE).await;
    assert_eq!(collector.requests(), 1, "a partial success is not retried");
}

// ---------------------------------------------------------------------------------------
// Latency and bounds
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_collector_down_does_not_slow_requests() {
    // A collector that takes the call and never answers.
    let hung = Collector::scripted(&[Reply::Blackhole; 64]).await;
    let (podgate, _upstream) = start(&grpc_env(&hung)).await;
    let slowest = slowest_of_a_hundred(&podgate).await;
    assert!(
        slowest < Duration::from_millis(1500),
        "a hung collector slowed a request to {slowest:?}"
    );
    drop(podgate);

    // A collector that is not there.
    let refused = common::refused();
    let env = env_of(&[
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            &format!("http://{}", refused.addr),
        ),
    ]);
    let (podgate, _upstream) = start(&env).await;
    let slowest = slowest_of_a_hundred(&podgate).await;
    assert!(
        slowest < Duration::from_millis(1500),
        "a dead collector slowed a request to {slowest:?}"
    );
    wait_metric(&podgate, "podgate_trace_dropped_total", 1).await;
    drop(podgate);

    // A collector that closes the connection after every call: the channel reconnects.
    let flapping = Collector::start_with(&[], Tls::None, true).await;
    let (podgate, _upstream) = start(&grpc_env(&flapping)).await;
    let mut slowest = Duration::ZERO;
    for _ in 0..3 {
        let started = Instant::now();
        assert_eq!(podgate.get("a.test", "/").await.status, 200);
        slowest = slowest.max(started.elapsed());
        flapping.wait_requests(flapping.requests() + 1).await;
    }
    assert!(slowest < Duration::from_millis(1500), "{slowest:?}");
    let spans = flapping.wait_spans(6).await;
    assert_eq!(spans.len(), 6, "every export got through after a reconnect");
    assert!(
        flapping.connections() >= 3,
        "each export needed a new connection, got {}",
        flapping.connections()
    );
    flapping.received(|all| {
        let connections: std::collections::BTreeSet<u64> =
            all.iter().map(|received| received.connection).collect();
        assert!(connections.len() >= 3, "{connections:?}");
    });
}

#[tokio::test]
async fn grpc_queue_bounded() {
    let hung = Collector::scripted(&[Reply::Blackhole; 64]).await;
    let mut env = grpc_env(&hung);
    env.extend(env_of(&[("OTEL_MAX_SPANS_PER_SEC", "1000000")]));
    let (podgate, _upstream) = start(&env).await;
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
    assert!(queued <= 2048, "the queue holds {queued} spans:\n{metrics}");
    assert!(
        dropped >= 100,
        "spans past the bound are dropped, got {dropped}:\n{metrics}"
    );
}

#[tokio::test]
async fn grpc_rate_cap_holds() {
    let collector = Collector::start().await;
    let mut env = grpc_env(&collector);
    env.extend(env_of(&[("OTEL_MAX_SPANS_PER_SEC", "10")]));
    let (podgate, _upstream) = start_with(&env, &json!({ "sample_percent": 0 }), true).await;
    let forced = format!("00-{TRACE}-{PARENT}-01");

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

// ---------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_protocol_only_from_environment() {
    let grpc = Collector::start().await;
    let http = HttpCollector::start().await;
    let upstream = Upstream::start("hello").await;

    // Without OTEL_EXPORTER_OTLP_PROTOCOL the exporter is OTLP/HTTP.
    let env = env_of(&[("OTEL_EXPORTER_OTLP_ENDPOINT", &http.url())]);
    let podgate = Podgate::start_with_env(&pairs(&env)).await;
    push(&podgate, &upstream, 1, &json!({}), false).await;
    podgate.get("a.test", "/").await;
    http.wait_exports(1).await;
    assert_eq!(http.exports()[0].0, "/v1/traces");
    drop(podgate);

    // A snapshot cannot ask for gRPC, or name a collector, whatever the node uses.
    let podgate = Podgate::start_with_env(&pairs(&env)).await;
    for (field, value) in [
        ("protocol", json!("grpc")),
        ("otlp_protocol", json!("grpc")),
        ("grpc", json!({ "endpoint": grpc.url() })),
        (
            "otlp",
            json!({ "grpc": { "endpoint": grpc.url(), "insecure": true } }),
        ),
    ] {
        let mut pushed = snapshot(
            5,
            &[app("a.test", &["a.test"], &[serving("r1", upstream.addr)])],
        );
        pushed["observability"] = json!({ "tracing": { field: value } });
        let response = podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 422, "{field}: {response:?}");
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_tracing",
            "{field}"
        );
    }
    drop(podgate);

    // The node's environment picks gRPC.
    let env = grpc_env(&grpc);
    let podgate = Podgate::start_with_env(&pairs(&env)).await;
    push(&podgate, &upstream, 1, &json!({}), false).await;
    podgate.get("a.test", "/").await;
    grpc.wait_spans(2).await;
    assert_eq!(
        http.exports().len(),
        1,
        "nothing more went to the HTTP collector"
    );
    drop(podgate);

    // An unknown protocol stops startup instead of falling back.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_podgate"))
        .env("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json")
        .env(
            "ADMIN_SOCKET",
            std::env::temp_dir().join("podgate-otel-grpc-protocol.sock"),
        )
        .output()
        .expect("run podgate");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OTEL_EXPORTER_OTLP_PROTOCOL"), "{stderr}");
}

#[tokio::test]
async fn snapshot_cannot_set_otlp_endpoint() {
    let real = Collector::start().await;
    let decoy = Collector::start().await;
    let (podgate, upstream) = start(&grpc_env(&real)).await;

    for field in ["endpoint", "otlp_endpoint", "headers", "collector"] {
        let mut pushed = snapshot(
            5,
            &[app("a.test", &["a.test"], &[serving("r1", upstream.addr)])],
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
    let mut routed = app("a.test", &["a.test"], &[serving("r1", upstream.addr)]);
    routed["routers"][0]["observability"] = json!({ "tracing": { "endpoint": decoy.url() } });
    let response = podgate.push_snapshot(&snapshot(6, &[routed])).await;
    assert_eq!(response.status, 422, "{response:?}");

    podgate.get("a.test", "/").await;
    real.wait_spans(2).await;
    sleep(SETTLE).await;
    assert_eq!(
        decoy.connections(),
        0,
        "nothing was ever sent to an address a snapshot named"
    );
}

#[tokio::test]
async fn grpc_headers_never_logged() {
    const SECRET: &str = "s3cret-token-value";
    let collector = Collector::scripted(&[
        Reply::Status {
            code: 16,
            retry_after: None,
        },
        Reply::Status {
            code: 14,
            retry_after: Some(Duration::from_millis(100)),
        },
    ])
    .await;
    let mut env = grpc_env(&collector);
    env.extend(env_of(&[
        (
            "OTEL_EXPORTER_OTLP_HEADERS",
            &format!("authorization=Bearer {SECRET},x-api-key={SECRET}"),
        ),
        ("RUST_LOG", "trace"),
    ]));
    let podgate = Podgate::start_logged(&pairs(&env)).await;
    let upstream = Upstream::start("hello").await;
    push(&podgate, &upstream, 1, &json!({}), false).await;

    // The first export is refused outright (a dropped batch is logged), the second is retried.
    podgate.get("a.test", "/").await;
    collector.wait_requests(1).await;
    wait_metric(&podgate, "podgate_trace_dropped_total", 2).await;
    podgate.get("a.test", "/").await;
    collector.wait_spans(2).await;
    collector.received(|all| {
        assert!(
            all.iter()
                .any(|received| received.header("x-api-key") == Some(SECRET)),
            "the credential did reach the collector"
        );
    });

    let log = podgate.log();
    assert!(
        log.contains("dropped a batch of spans"),
        "the failure path was logged:\n{log}"
    );
    assert!(!log.contains(SECRET), "a credential reached the log");
    drop(podgate);

    // The same for a collector that cannot be reached.
    let refused = common::refused();
    let env = env_of(&[
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            &format!("http://{}", refused.addr),
        ),
        ("OTEL_EXPORTER_OTLP_HEADERS", &format!("x-api-key={SECRET}")),
        ("RUST_LOG", "trace"),
    ]);
    let podgate = Podgate::start_logged(&pairs(&env)).await;
    push(&podgate, &upstream, 1, &json!({}), false).await;
    podgate.get("a.test", "/").await;
    wait_metric(&podgate, "podgate_trace_dropped_total", 2).await;
    assert!(
        !podgate.log().contains(SECRET),
        "a credential reached the log"
    );
}
