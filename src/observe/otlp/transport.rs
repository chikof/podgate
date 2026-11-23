//! The wire to the collector for one signal: an OTLP/HTTP client or an OTLP/gRPC channel
//! ([`grpc`](super::grpc)), the timeout, and the retry loop with backoff. A signal hands it one
//! encoded `ExportXServiceRequest` and learns how many items the collector refused, or why the
//! export failed; what is batched and what is dropped on failure is the signal's.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{HeaderName, HeaderValue, Request, StatusCode, Uri};
use http_body_util::Full;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio::time::{sleep, timeout};

use super::collector::{Collector, Protocol, Signal, bad, is_loopback};
use super::grpc;
use crate::config::ConfigError;

/// Sends per request: the first and two retries.
pub const ATTEMPTS: u32 = 3;

/// The wait before the first retry; each retry doubles it.
const BACKOFF: Duration = Duration::from_millis(250);

type OtlpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Why one send failed.
pub enum Failure {
    /// Worth another try: the collector was unreachable, slow, or told us to back off. The delay
    /// is the one the collector asked for, when it did.
    Retry(String, Option<Duration>),
    /// The collector refused the request; sending it again will not help.
    Refused(String),
}

/// The wire one signal goes out on.
enum Wire {
    Http {
        client: Box<OtlpClient>,
        url: Uri,
        headers: Vec<(HeaderName, HeaderValue)>,
        timeout: Duration,
    },
    Grpc(grpc::Channel),
}

/// The connection to the collector for one signal. Its `Debug` output never shows header values.
pub struct Transport {
    wire: Wire,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut shown = f.debug_struct("Transport");
        match &self.wire {
            Wire::Http { url, .. } => shown.field("url", url),
            Wire::Grpc(channel) => shown.field("channel", channel),
        };
        shown.finish_non_exhaustive()
    }
}

fn tls_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig, rustls::Error> {
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// The PEM certificates of `path` as a trust store.
pub(super) fn roots(path: &Path) -> Result<rustls::RootCertStore, ConfigError> {
    let mut roots = rustls::RootCertStore::empty();
    let certificates = CertificateDer::pem_file_iter(path).map_err(|err| {
        bad(
            "OTEL_EXPORTER_OTLP_CERTIFICATE",
            format!("cannot read {}: {err}", path.display()),
        )
    })?;
    for certificate in certificates {
        let certificate = certificate.map_err(|err| {
            bad(
                "OTEL_EXPORTER_OTLP_CERTIFICATE",
                format!("{} is not PEM certificates: {err}", path.display()),
            )
        })?;
        roots.add(certificate).map_err(|err| {
            bad(
                "OTEL_EXPORTER_OTLP_CERTIFICATE",
                format!("{} holds a bad certificate: {err}", path.display()),
            )
        })?;
    }
    Ok(roots)
}

fn client(config: &Collector, https: bool) -> Result<OtlpClient, ConfigError> {
    let builder = if let Some(path) = &config.ca_file {
        let tls = tls_config(roots(path)?)
            .map_err(|err| bad("OTEL_EXPORTER_OTLP_CERTIFICATE", err.to_string()))?;
        HttpsConnectorBuilder::new().with_tls_config(tls)
    } else if https {
        HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|err| {
                bad(
                    "OTEL_EXPORTER_OTLP_ENDPOINT",
                    format!("cannot load the platform's root certificates: {err}"),
                )
            })?
    } else {
        let tls = tls_config(rustls::RootCertStore::empty())
            .map_err(|err| bad("OTEL_EXPORTER_OTLP_ENDPOINT", err.to_string()))?;
        HttpsConnectorBuilder::new().with_tls_config(tls)
    };
    let connector = builder.https_or_http().enable_http1().build();
    Ok(Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(connector))
}

impl Transport {
    /// The wire for `signal` to `collector`; `None` when the collector has no endpoint.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] when the root certificates or the client certificate cannot be loaded.
    pub fn new(collector: &Collector, signal: Signal) -> Result<Option<Self>, ConfigError> {
        let Some(url) = collector.url(signal) else {
            return Ok(None);
        };
        let wire = match collector.protocol {
            Protocol::Http => Wire::Http {
                client: Box::new(client(collector, url.scheme_str() == Some("https"))?),
                url,
                headers: collector.headers.clone(),
                timeout: collector.timeout,
            },
            Protocol::Grpc => {
                if url.scheme_str() == Some("http") && !is_loopback(&url) {
                    ::tracing::warn!(
                        host = url.host().unwrap_or_default(),
                        "OTEL_EXPORTER_OTLP_INSECURE=true: spans go to the collector unencrypted"
                    );
                }
                Wire::Grpc(grpc::Channel::new(collector, &url, signal.grpc_path())?)
            }
        };
        Ok(Some(Self { wire }))
    }

    /// One attempt to send one encoded request. `Ok` is the number of items the collector
    /// reported refusing (a partial success).
    ///
    /// # Errors
    ///
    /// A [`Failure`]: retryable for a connection problem or an answer that asks for a retry.
    pub async fn send(&self, body: &Bytes) -> Result<usize, Failure> {
        match &self.wire {
            Wire::Grpc(channel) => channel
                .export(body)
                .await
                .map(|rejected| usize::try_from(rejected).unwrap_or(0)),
            Wire::Http {
                client,
                url,
                headers,
                timeout: limit,
            } => {
                let mut request = Request::post(url.clone())
                    .header(CONTENT_TYPE, "application/x-protobuf")
                    .body(Full::new(body.clone()))
                    .map_err(|err| Failure::Refused(err.to_string()))?;
                for (name, value) in headers {
                    request.headers_mut().insert(name.clone(), value.clone());
                }
                let response = timeout(*limit, client.request(request))
                    .await
                    .map_err(|_| {
                        Failure::Retry("the collector did not answer in time".to_owned(), None)
                    })?
                    .map_err(|err| Failure::Retry(err.to_string(), None))?;
                let status = response.status();
                if status.is_success() {
                    Ok(0)
                } else if matches!(
                    status,
                    StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
                ) {
                    Err(Failure::Retry(
                        format!("the collector answered {status}"),
                        None,
                    ))
                } else {
                    Err(Failure::Refused(format!("the collector answered {status}")))
                }
            }
        }
    }

    /// Sends `body` at most `attempts` times: the wait before a retry is 250 ms, doubling, or the
    /// delay the collector asked for. `Ok` is the number of items the collector refused.
    ///
    /// # Errors
    ///
    /// The reason of the last failure, safe to log: it is never the collector's own text.
    pub async fn deliver(&self, body: &Bytes, attempts: u32) -> Result<usize, Box<str>> {
        let mut why = String::new();
        for attempt in 0..attempts {
            let wait = match self.send(body).await {
                Ok(rejected) => return Ok(rejected),
                Err(Failure::Refused(reason)) => {
                    why = reason;
                    break;
                }
                Err(Failure::Retry(reason, asked)) => {
                    why = reason;
                    asked.unwrap_or(BACKOFF * 2_u32.pow(attempt))
                }
            };
            if attempt + 1 < attempts {
                sleep(wait).await;
            }
        }
        Err(why.into())
    }
}
