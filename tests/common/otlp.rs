//! A fake OTLP collector that records raw calls, for every signal: it never decodes a message, so
//! a test decodes `Received::body` into the `ExportXServiceRequest` it expects (traces, metrics
//! or logs). It speaks OTLP/HTTP (`POST <path>`, protobuf) or OTLP/gRPC (unary, on `h2`, with
//! optional TLS and a required client certificate), and answers from a script.
//!
//! - [`Collector::http`], [`Collector::grpc`], [`Collector::start`]: start one on a free port.
//! - [`Collector::received`], [`Collector::wait_requests`]: what arrived, in order.
//! - [`Reply`]: what the next calls answer; [`Collector::set_fallback`] changes the answer once
//!   the script is used up, which is how a test takes a collector down and brings it back.
//! - `common::refused()` is an address nothing accepts on, a collector that is down.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::Bytes;
use h2::RecvStream;
use h2::server::SendResponse;
use http::{HeaderMap, HeaderValue, Request, Response};
use podgate::observe::otlp::common::{PartialSuccess, PartialSuccessResponse};
use prost::Message;
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

use super::TestCert;
use super::grpc::{Messages, frame};

/// What a call is answered with.
#[derive(Clone, Copy, Debug)]
pub enum Reply {
    /// Accepted: `OK` over gRPC, `200` over HTTP.
    Ok,
    /// Refused with a gRPC status (`14` is `UNAVAILABLE`) and, when given, a `RetryInfo` delay;
    /// over HTTP it is a `503`.
    Status {
        /// The gRPC status code.
        code: u32,
        /// The delay the collector asks the exporter to wait.
        retry_after: Option<Duration>,
    },
    /// Accepted, refusing this many items (a partial success); over HTTP the same as `Ok`.
    Partial(i64),
    /// Takes the call and never answers.
    Blackhole,
}

/// How the collector is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    /// OTLP/HTTP, protobuf.
    Http,
    /// OTLP/gRPC.
    Grpc,
}

/// TLS for a gRPC collector.
#[derive(Clone, Copy)]
pub enum Tls<'a> {
    /// Plaintext.
    None,
    /// A server certificate, and a client certificate the server requires and trusts.
    Mutual(&'a TestCert, &'a TestCert),
}

/// One call, as it arrived.
#[derive(Debug, Clone)]
pub struct Received {
    /// The request path: `/v1/metrics`, or the gRPC method.
    pub path: String,
    /// The request headers (gRPC metadata included), names lower case.
    pub headers: Vec<(String, String)>,
    /// The protobuf message, gunzipped when it came compressed.
    pub body: Vec<u8>,
    /// Whether the gRPC message was compressed.
    pub compressed: bool,
    /// When it arrived.
    pub at: Instant,
    /// The connection it came on, counting from 1.
    pub connection: u64,
    /// Whether the call was answered as accepted.
    pub accepted: bool,
}

impl Received {
    /// The value of header `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The body decoded as `M`.
    pub fn decode<M: Message + Default>(&self) -> M {
        M::decode(self.body.as_slice()).expect("the body is the OTLP message the test expects")
    }
}

struct State {
    script: Mutex<VecDeque<Reply>>,
    fallback: Mutex<Reply>,
    received: Mutex<Vec<Received>>,
    connections: AtomicU64,
    handshake_failures: AtomicU64,
}

impl State {
    fn next_reply(&self) -> Reply {
        let scripted = self
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front();
        scripted.unwrap_or_else(|| *self.fallback.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn record(&self, received: Received) {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(received);
    }
}

/// The fake collector.
pub struct Collector {
    /// Where it listens.
    pub addr: SocketAddr,
    wire: Wire,
    https: bool,
    state: Arc<State>,
}

#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
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

fn retry_details(code: u32, delay: Duration) -> HeaderValue {
    let info = RetryInfo {
        retry_delay: Some(Delay {
            seconds: i64::try_from(delay.as_secs()).expect("seconds"),
            nanos: i32::try_from(delay.subsec_nanos()).expect("nanos"),
        }),
    };
    let status = RpcStatus {
        code: i32::try_from(code).expect("code"),
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
    let (body, trailer) = data[10..].split_at(data.len() - 18);
    let plain = miniz_oxide::inflate::decompress_to_vec(body).expect("inflates");
    let crc = u32::from_le_bytes(trailer[..4].try_into().expect("crc"));
    assert_eq!(crc, crc32fast::hash(&plain), "the gzip CRC matches");
    plain
}

fn tls_acceptor(tls: Tls<'_>) -> Option<tokio_rustls::TlsAcceptor> {
    let Tls::Mutual(server, client) = tls else {
        return None;
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(client.der.clone()).expect("client root");
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .expect("client verifier");
    let chain = rustls::pki_types::CertificateDer::pem_slice_iter(server.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("certificate chain");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(server.key_pem.as_bytes())
        .expect("private key");
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("server certificate");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

async fn serve_grpc<T>(io: T, number: u64, state: Arc<State>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(io).await else {
        return;
    };
    while let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(grpc_call(request, respond, number, Arc::clone(&state)));
    }
}

async fn grpc_call(
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
    let reply = state.next_reply();
    state.record(Received {
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
        body: if flag == 1 { gunzip(&payload) } else { payload },
        compressed: flag == 1,
        at: Instant::now(),
        connection,
        accepted: matches!(reply, Reply::Ok | Reply::Partial(_)),
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
                Reply::Partial(rejected) => PartialSuccessResponse {
                    partial_success: Some(PartialSuccess {
                        rejected,
                        error_message: "too old".to_owned(),
                    }),
                },
                _ => PartialSuccessResponse::default(),
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

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn serve_http<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    number: u64,
    state: Arc<State>,
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
        let headers: Vec<(String, String)> = head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let length: usize = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);
        while buf.len() < head_end + length {
            if !matches!(stream.read_buf(&mut buf).await, Ok(read) if read > 0) {
                return;
            }
        }
        let body = buf[head_end..head_end + length].to_vec();
        buf.drain(..head_end + length);
        let reply = state.next_reply();
        state.record(Received {
            path,
            headers,
            body,
            compressed: false,
            at: Instant::now(),
            connection: number,
            accepted: matches!(reply, Reply::Ok | Reply::Partial(_)),
        });
        let response = match reply {
            Reply::Blackhole => {
                std::future::pending::<()>().await;
                return;
            }
            Reply::Status { .. } => "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            Reply::Ok | Reply::Partial(_) => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        };
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

impl Collector {
    /// An OTLP/HTTP collector that accepts everything.
    pub async fn http() -> Self {
        Self::start(Wire::Http, &[], Tls::None).await
    }

    /// An OTLP/gRPC collector that accepts everything.
    pub async fn grpc() -> Self {
        Self::start(Wire::Grpc, &[], Tls::None).await
    }

    /// A collector on `wire` that answers the first calls from `script`, then [`Reply::Ok`].
    /// `tls` applies to gRPC only.
    pub async fn start(wire: Wire, script: &[Reply], tls: Tls<'_>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind collector");
        let addr = listener.local_addr().expect("collector address");
        let state = Arc::new(State {
            script: Mutex::new(script.iter().copied().collect()),
            fallback: Mutex::new(Reply::Ok),
            received: Mutex::new(Vec::new()),
            connections: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
        });
        let acceptor = tls_acceptor(tls);
        let https = acceptor.is_some();
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let number = shared.connections.fetch_add(1, Ordering::Relaxed) + 1;
                let (state, acceptor) = (Arc::clone(&shared), acceptor.clone());
                tokio::spawn(async move {
                    match (wire, acceptor) {
                        (Wire::Http, _) => serve_http(tcp, number, state).await,
                        (Wire::Grpc, None) => serve_grpc(tcp, number, state).await,
                        (Wire::Grpc, Some(acceptor)) => match acceptor.accept(tcp).await {
                            Ok(stream) => serve_grpc(stream, number, state).await,
                            Err(_) => {
                                state.handshake_failures.fetch_add(1, Ordering::Relaxed);
                            }
                        },
                    }
                });
            }
        });
        Self {
            addr,
            wire,
            https,
            state,
        }
    }

    /// The `OTEL_EXPORTER_OTLP_ENDPOINT` for this collector (`localhost` for TLS, which is the
    /// name of the test certificate).
    pub fn url(&self) -> String {
        if self.https {
            format!("https://localhost:{}", self.addr.port())
        } else {
            format!("http://{}", self.addr)
        }
    }

    /// The environment that points a node at this collector over its wire.
    pub fn env(&self) -> Vec<(String, String)> {
        let mut env = vec![("OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(), self.url())];
        if self.wire == Wire::Grpc {
            env.push(("OTEL_EXPORTER_OTLP_PROTOCOL".to_owned(), "grpc".to_owned()));
        }
        env
    }

    /// What answers a call once the script is used up; the default is [`Reply::Ok`].
    pub fn set_fallback(&self, reply: Reply) {
        *self
            .state
            .fallback
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = reply;
    }

    /// Every call so far, in order.
    pub fn received(&self) -> Vec<Received> {
        self.state
            .received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The number of calls so far.
    pub fn requests(&self) -> usize {
        self.state
            .received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> u64 {
        self.state.connections.load(Ordering::Relaxed)
    }

    /// TLS handshakes the collector refused.
    pub fn handshake_failures(&self) -> u64 {
        self.state.handshake_failures.load(Ordering::Relaxed)
    }

    /// Waits until `count` calls arrived, accepted or not.
    pub async fn wait_requests(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(20);
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
