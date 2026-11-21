//! The OTLP/gRPC wire: one unary `TraceService/Export` call on an HTTP/2 connection built on
//! `h2`, so the exporter needs no gRPC framework.
//!
//! Only the wire differs from the OTLP/HTTP exporter (`export.rs`): the batch, the queue, the
//! caps and the retry loop are shared. [`Channel::export`] sends one encoded
//! `ExportTraceServiceRequest` and maps the outcome onto [`Failure`]:
//!
//! - `OK`: success; a partial success answer reports how many spans the collector refused.
//! - `UNAVAILABLE`, `RESOURCE_EXHAUSTED` and `DEADLINE_EXCEEDED`, a connection that fails or
//!   breaks, an HTTP `429`, `502`, `503` or `504` from something in between: retry, after the
//!   delay of the server's `google.rpc.RetryInfo` when it gave one.
//! - Any other status (`INVALID_ARGUMENT`, `UNAUTHENTICATED`, ...): the batch is dropped.
//!
//! The connection is made on demand and kept; one that breaks, times out or is closed by the
//! collector is forgotten, and the next attempt (the retry loop's backoff) connects again. The
//! collector's `grpc-message` is never logged: it is the collector's text and may echo what it
//! was sent.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use bytes::Bytes;
use h2::client::SendRequest;
use h2::{Reason, SendStream};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Uri};
use prost::Message;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::export::{ExportConfig, Failure, bad, roots};
use super::otlp::ExportTraceServiceResponse;
use crate::config::ConfigError;

/// The method every export calls.
const EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

/// The most a collector's answer may weigh; anything past it is not read.
const RESPONSE_MAX: usize = 1024 * 1024;

/// The longest a server's retry delay is believed: the exporter must not sit out an hour.
const RETRY_DELAY_MAX: Duration = Duration::from_secs(5);

/// The gzip header: deflate, no flags, no mtime, no extra flags, unknown OS.
const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];

/// `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED` and `UNAVAILABLE`: worth another try.
const RETRYABLE: [u32; 3] = [4, 8, 14];

/// Request headers the call sets itself; metadata may not use them.
const RESERVED: [&str; 7] = [
    "content-type",
    "content-length",
    "content-encoding",
    "te",
    "host",
    "connection",
    "transfer-encoding",
];

/// Whether `name` may be gRPC metadata: not an HTTP/2 or gRPC protocol header.
pub(super) fn metadata_name_allowed(name: &HeaderName) -> bool {
    !RESERVED.contains(&name.as_str()) && !name.as_str().starts_with("grpc-")
}

/// The pieces of a `google.rpc.Status` that carry the retry delay.
#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(message, repeated, tag = "3")]
    details: Vec<Any>,
}

/// `google.protobuf.Any`.
#[derive(Clone, PartialEq, Message)]
struct Any {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

/// `google.rpc.RetryInfo`.
#[derive(Clone, PartialEq, Message)]
struct RetryInfo {
    #[prost(message, optional, tag = "1")]
    retry_delay: Option<Delay>,
}

/// `google.protobuf.Duration`.
#[derive(Clone, PartialEq, Message)]
struct Delay {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}

/// The delay a `grpc-status-details-bin` value asks for, at most [`RETRY_DELAY_MAX`].
fn retry_delay(details: &HeaderValue) -> Option<Duration> {
    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let raw = LENIENT.decode(details.as_bytes()).ok()?;
    let status = RpcStatus::decode(raw.as_slice()).ok()?;
    let info = status
        .details
        .iter()
        .find(|any| any.type_url.ends_with("google.rpc.RetryInfo"))?;
    let delay = RetryInfo::decode(info.value.as_slice()).ok()?.retry_delay?;
    let seconds = u64::try_from(delay.seconds).ok()?;
    let nanos = u32::try_from(delay.nanos).ok()?;
    Some(Duration::new(seconds, nanos.min(999_999_999)).min(RETRY_DELAY_MAX))
}

/// `data` as a gzip stream.
fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = GZIP_HEADER.to_vec();
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend(crc32fast::hash(data).to_le_bytes());
    out.extend(u32::try_from(data.len()).unwrap_or_default().to_le_bytes());
    out
}

/// One gRPC message: the compressed flag, a big-endian length, the payload.
fn frame(payload: &[u8], compressed: bool) -> Bytes {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(u8::from(compressed));
    out.extend(
        u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    Bytes::from(out)
}

/// The first message in `body`, when it is whole and not compressed.
fn first_message(body: &[u8]) -> Option<&[u8]> {
    let head = body.get(..5)?;
    let len = u32::from_be_bytes([*head.get(1)?, *head.get(2)?, *head.get(3)?, *head.get(4)?]);
    if head.first() != Some(&0) {
        return None;
    }
    body.get(5..5 + usize::try_from(len).ok()?)
}

/// Sends `data`, waiting for the peer's flow-control window as it must, then ends the stream.
async fn send_message(stream: &mut SendStream<Bytes>, mut data: Bytes) -> Result<(), h2::Error> {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| h2::Error::from(Reason::CANCEL))??;
        if capacity > 0 {
            stream.send_data(data.split_to(capacity.min(data.len())), false)?;
        }
    }
    stream.send_data(Bytes::new(), true)
}

/// The grpc status name for the log, never the collector's message.
const fn status_name(code: u32) -> &'static str {
    match code {
        1 => "CANCELLED",
        2 => "UNKNOWN",
        3 => "INVALID_ARGUMENT",
        4 => "DEADLINE_EXCEEDED",
        5 => "NOT_FOUND",
        6 => "ALREADY_EXISTS",
        7 => "PERMISSION_DENIED",
        8 => "RESOURCE_EXHAUSTED",
        9 => "FAILED_PRECONDITION",
        10 => "ABORTED",
        11 => "OUT_OF_RANGE",
        12 => "UNIMPLEMENTED",
        13 => "INTERNAL",
        14 => "UNAVAILABLE",
        15 => "DATA_LOSS",
        16 => "UNAUTHENTICATED",
        _ => "an unknown status",
    }
}

fn transport(err: &impl std::fmt::Display) -> Failure {
    Failure::Retry(format!("the collector connection failed: {err}"), None)
}

/// The collector's address, resolved on each connect.
struct Target {
    host: String,
    port: u16,
    /// `scheme://authority/path` of the call.
    uri: Uri,
    /// Present for `https`.
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

/// A gRPC channel to the collector: connects on demand and reuses the connection.
pub(super) struct Channel {
    target: Target,
    metadata: Vec<(HeaderName, HeaderValue)>,
    gzip: bool,
    timeout: Duration,
    connection: Mutex<Option<SendRequest<Bytes>>>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("uri", &self.target.uri)
            .finish_non_exhaustive()
    }
}

fn client_config(config: &ExportConfig) -> Result<TlsConnector, ConfigError> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| bad("OTEL_EXPORTER_OTLP_ENDPOINT", err.to_string()))?;
    let builder = match &config.ca_file {
        Some(path) => builder.with_root_certificates(roots(path)?),
        None => builder.with_platform_verifier().map_err(|err| {
            bad(
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                format!("cannot load the platform's root certificates: {err}"),
            )
        })?,
    };
    let mut tls = match (&config.client_cert, &config.client_key) {
        (Some(cert), Some(key)) => {
            let chain = CertificateDer::pem_file_iter(cert)
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                .map_err(|err| {
                    bad(
                        "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE",
                        format!("cannot read {}: {err}", cert.display()),
                    )
                })?;
            let key = PrivateKeyDer::from_pem_file(key).map_err(|err| {
                bad(
                    "OTEL_EXPORTER_OTLP_CLIENT_KEY",
                    format!("cannot read {}: {err}", key.display()),
                )
            })?;
            builder.with_client_auth_cert(chain, key).map_err(|err| {
                bad(
                    "OTEL_EXPORTER_OTLP_CLIENT_KEY",
                    format!("the certificate and key do not make a client identity: {err}"),
                )
            })?
        }
        _ => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsConnector::from(Arc::new(tls)))
}

impl Channel {
    /// The channel for `config`, whose endpoint is `http://` or `https://` without a path.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] when a certificate or key cannot be loaded.
    pub(super) fn new(config: &ExportConfig, endpoint: &Uri) -> Result<Self, ConfigError> {
        let https = endpoint.scheme_str() == Some("https");
        let host = endpoint
            .host()
            .map(|host| {
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned()
            })
            .ok_or_else(|| bad("OTEL_EXPORTER_OTLP_ENDPOINT", "has no host"))?;
        let port = endpoint.port_u16().unwrap_or(if https { 443 } else { 80 });
        let authority = endpoint
            .authority()
            .ok_or_else(|| bad("OTEL_EXPORTER_OTLP_ENDPOINT", "has no host"))?
            .clone();
        let uri = Uri::builder()
            .scheme(if https { "https" } else { "http" })
            .authority(authority)
            .path_and_query(EXPORT_PATH)
            .build()
            .map_err(|err| bad("OTEL_EXPORTER_OTLP_ENDPOINT", err.to_string()))?;
        let tls = if https {
            let name = ServerName::try_from(host.clone()).map_err(|err| {
                bad(
                    "OTEL_EXPORTER_OTLP_ENDPOINT",
                    format!("the host is not a valid TLS name ({err})"),
                )
            })?;
            Some((client_config(config)?, name))
        } else {
            None
        };
        Ok(Self {
            target: Target {
                host,
                port,
                uri,
                tls,
            },
            metadata: config.headers.clone(),
            gzip: config.gzip,
            timeout: config.timeout,
            connection: Mutex::new(None),
        })
    }

    fn stored(&self) -> Option<SendRequest<Bytes>> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn store(&self, sender: Option<SendRequest<Bytes>>) {
        *self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = sender;
    }

    /// A connection that can take a request: the kept one, or a new one.
    async fn ready(&self) -> Result<SendRequest<Bytes>, Failure> {
        if let Some(sender) = self.stored() {
            if let Ok(sender) = sender.ready().await {
                return Ok(sender);
            }
            self.store(None);
        }
        let sender = self.connect().await?;
        self.store(Some(sender.clone()));
        Ok(sender)
    }

    async fn connect(&self) -> Result<SendRequest<Bytes>, Failure> {
        let tcp = TcpStream::connect((self.target.host.as_str(), self.target.port))
            .await
            .map_err(|err| transport(&err))?;
        // Small frames (settings acknowledgements, window updates) must not wait on Nagle.
        drop(tcp.set_nodelay(true));
        let sender = match &self.target.tls {
            None => handshake(tcp).await?,
            Some((connector, name)) => {
                let stream = connector
                    .connect(name.clone(), tcp)
                    .await
                    .map_err(|err| transport(&err))?;
                handshake(stream).await?
            }
        };
        sender.ready().await.map_err(|err| transport(&err))
    }

    fn request(&self) -> Result<Request<()>, Failure> {
        let mut request = Request::post(self.target.uri.clone())
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header(
                "grpc-timeout",
                format!("{}m", self.timeout.as_millis().max(1)),
            )
            .header("user-agent", concat!("podgate/", env!("CARGO_PKG_VERSION")));
        if self.gzip {
            request = request.header("grpc-encoding", "gzip");
        }
        let mut request = request
            .body(())
            .map_err(|err| Failure::Refused(err.to_string()))?;
        for (name, value) in &self.metadata {
            request.headers_mut().append(name.clone(), value.clone());
        }
        Ok(request)
    }

    /// Sends one encoded `ExportTraceServiceRequest`. `Ok` is the number of spans the collector
    /// reported refusing.
    ///
    /// # Errors
    ///
    /// A [`Failure`]: retryable for a connection problem or a status that asks for a retry.
    pub(super) async fn export(&self, body: &[u8]) -> Result<i64, Failure> {
        match timeout(self.timeout, self.call(body)).await {
            Ok(Ok(rejected)) => Ok(rejected),
            Ok(Err(failure)) => Err(failure),
            Err(_) => {
                self.store(None);
                Err(Failure::Retry(
                    "the collector did not answer in time".to_owned(),
                    None,
                ))
            }
        }
    }

    async fn call(&self, body: &[u8]) -> Result<i64, Failure> {
        let mut sender = self.ready().await?;
        let (response, mut stream) =
            sender.send_request(self.request()?, false).map_err(|err| {
                self.store(None);
                transport(&err)
            })?;
        let message = if self.gzip {
            frame(&gzip(body), true)
        } else {
            frame(body, false)
        };
        // The answer can come before the request is all sent (an error status), so both run.
        let (_, response) = tokio::join!(send_message(&mut stream, message), response);
        let (head, mut recv) = response
            .map_err(|err| {
                self.store(None);
                transport(&err)
            })?
            .into_parts();
        let mut received = Vec::new();
        let mut trailers = HeaderMap::new();
        if !head.headers.contains_key("grpc-status") {
            while let Some(chunk) = recv.data().await {
                let chunk = chunk.map_err(|err| {
                    self.store(None);
                    transport(&err)
                })?;
                drop(recv.flow_control().release_capacity(chunk.len()));
                if received.len() + chunk.len() > RESPONSE_MAX {
                    return Err(Failure::Refused(
                        "the collector's answer is too large".to_owned(),
                    ));
                }
                received.extend_from_slice(&chunk);
            }
            trailers = recv
                .trailers()
                .await
                .map_err(|err| {
                    self.store(None);
                    transport(&err)
                })?
                .unwrap_or_default();
        }
        let status = if head.headers.contains_key("grpc-status") {
            &head.headers
        } else {
            &trailers
        };
        let Some(code) = status
            .get("grpc-status")
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.parse::<u32>().ok())
        else {
            // No grpc-status: something that is not a gRPC server answered, or the stream broke.
            return Err(match head.status.as_u16() {
                200 => Failure::Retry("the collector ended the call without a status".into(), None),
                429 | 502..=504 => {
                    Failure::Retry(format!("the collector answered {}", head.status), None)
                }
                _ => Failure::Refused(format!("the collector answered {}", head.status)),
            });
        };
        match code {
            0 => Ok(first_message(&received)
                .and_then(|message| ExportTraceServiceResponse::decode(message).ok())
                .and_then(|response| response.partial_success)
                .map_or(0, |partial| partial.rejected_spans)),
            code if RETRYABLE.contains(&code) => Err(Failure::Retry(
                format!("the collector answered {}", status_name(code)),
                status.get("grpc-status-details-bin").and_then(retry_delay),
            )),
            code => Err(Failure::Refused(format!(
                "the collector answered {}",
                status_name(code)
            ))),
        }
    }
}

/// An HTTP/2 client handshake on `io`; the connection is driven by a task that ends with it.
async fn handshake<T>(io: T) -> Result<SendRequest<Bytes>, Failure>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The handshake future is several kilobytes; boxed, it does not inflate every caller.
    let (sender, connection) = Box::pin(h2::client::handshake(io))
        .await
        .map_err(|err| transport(&err))?;
    tokio::spawn(async move { drop(connection.await) });
    Ok(sender)
}

#[cfg(test)]
mod test {
    use super::*;

    fn details(delay: Delay) -> HeaderValue {
        let info = RetryInfo {
            retry_delay: Some(delay),
        };
        let status = RpcStatus {
            details: vec![Any {
                type_url: "type.googleapis.com/google.rpc.RetryInfo".to_owned(),
                value: info.encode_to_vec(),
            }],
        };
        let text = base64::engine::general_purpose::STANDARD.encode(status.encode_to_vec());
        HeaderValue::from_str(&text).expect("header value")
    }

    #[test]
    fn grpc_retry_delay_is_read_and_capped() {
        let half = Delay {
            seconds: 0,
            nanos: 500_000_000,
        };
        assert_eq!(
            retry_delay(&details(half)),
            Some(Duration::from_millis(500))
        );
        let hour = Delay {
            seconds: 3600,
            nanos: 0,
        };
        assert_eq!(retry_delay(&details(hour)), Some(RETRY_DELAY_MAX));
        let negative = Delay {
            seconds: -1,
            nanos: 0,
        };
        assert_eq!(retry_delay(&details(negative)), None);
        assert_eq!(retry_delay(&HeaderValue::from_static("!!!")), None);
    }

    #[test]
    fn grpc_frames_round_trip_and_gzip_is_a_gzip_stream() {
        let framed = frame(b"hello", false);
        assert_eq!(first_message(&framed), Some(&b"hello"[..]));
        assert_eq!(
            first_message(&framed[..7]),
            None,
            "a cut message is not read"
        );
        assert_eq!(
            first_message(&frame(b"x", true)),
            None,
            "compressed is not read"
        );
        let packed = gzip(b"hello hello hello");
        assert_eq!(packed[..2], [0x1f, 0x8b]);
        let deflated = packed.get(10..packed.len() - 8).expect("body");
        assert_eq!(
            miniz_oxide::inflate::decompress_to_vec(deflated).expect("inflates"),
            b"hello hello hello"
        );
    }

    #[test]
    fn grpc_metadata_cannot_name_protocol_headers() {
        for name in [
            "content-type",
            "te",
            "grpc-timeout",
            "grpc-encoding",
            "host",
        ] {
            let name = HeaderName::from_bytes(name.as_bytes()).expect("name");
            assert!(!metadata_name_allowed(&name), "{name}");
        }
        assert!(metadata_name_allowed(&HeaderName::from_static("x-api-key")));
    }
}
