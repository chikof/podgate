//! The exporter: the operator's collector settings and the background service that batches the
//! queue and POSTs it as OTLP/HTTP protobuf.
//!
//! The service never runs on the request path. A batch is 512 spans or whatever has queued in
//! two seconds; an export gives up after 3 seconds and is retried twice with backoff, then its
//! spans are dropped and counted. Meanwhile the queue keeps its bound, so a collector that is
//! down or slow costs spans and nothing else.

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{HeaderName, HeaderValue, Request, StatusCode, Uri};
use http_body_util::Full;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio::time::{MissedTickBehavior, interval, sleep, timeout};

use super::otlp;
use super::span::Span;
use super::tracer::{BATCH_SPANS, DEFAULT_MAX_SPANS_PER_SEC, Tracer};
use crate::config::ConfigError;

/// How long the exporter waits before sending a batch that is not full.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// One export request gives up after this long, connecting included.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// Sends per batch: the first and two retries.
const ATTEMPTS: u32 = 3;

/// The wait before the first retry; each retry doubles it.
const BACKOFF: Duration = Duration::from_millis(250);

/// Batches sent on the way out; whatever is left after them is dropped.
const SHUTDOWN_BATCHES: usize = 4;

/// The longest `OTEL_SERVICE_NAME`.
const SERVICE_NAME_MAX: usize = 128;

/// The most spans a second `OTEL_MAX_SPANS_PER_SEC` may allow.
const MAX_SPANS_PER_SEC_LIMIT: u32 = 1_000_000;

/// The operator's tracing settings, from the environment (never from a snapshot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportConfig {
    /// Where spans are POSTed: `OTEL_EXPORTER_OTLP_ENDPOINT` with `/v1/traces` appended. Absent:
    /// spans are not recorded, requests are still sampled and propagated.
    pub traces_url: Option<Uri>,
    /// `OTEL_EXPORTER_OTLP_HEADERS`, sent with every export (an API key, say). Their values are
    /// marked sensitive so they never print.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// `OTEL_EXPORTER_OTLP_CERTIFICATE`: PEM roots to trust for an `https` collector instead of
    /// the platform's.
    pub ca_file: Option<PathBuf>,
    /// `OTEL_SERVICE_NAME`: the `service.name` resource attribute.
    pub service_name: Box<str>,
    /// `OTEL_MAX_SPANS_PER_SEC`: spans a second this node lets be traced, whoever asks.
    pub max_spans_per_sec: NonZeroU32,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            traces_url: None,
            headers: Vec::new(),
            ca_file: None,
            service_name: "podgate".into(),
            max_spans_per_sec: NonZeroU32::new(DEFAULT_MAX_SPANS_PER_SEC)
                .unwrap_or(NonZeroU32::MIN),
        }
    }
}

fn bad(var: &'static str, reason: impl Into<Box<str>>) -> ConfigError {
    ConfigError {
        var,
        reason: reason.into(),
    }
}

/// `endpoint` plus the traces path: `http://c:4318` becomes `http://c:4318/v1/traces`.
fn traces_url(endpoint: &str) -> Result<Uri, String> {
    let uri: Uri = endpoint
        .parse()
        .map_err(|err| format!("is not a URL ({err})"))?;
    let scheme = uri.scheme_str().unwrap_or_default();
    if scheme != "http" && scheme != "https" {
        return Err("must start with http:// or https://".to_owned());
    }
    let authority = uri
        .authority()
        .ok_or_else(|| "has no host".to_owned())?
        .as_str();
    if authority.contains('@') {
        return Err("must not carry credentials; use OTEL_EXPORTER_OTLP_HEADERS".to_owned());
    }
    if uri.query().is_some() {
        return Err("must not have a query".to_owned());
    }
    let base = uri.path().trim_end_matches('/');
    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(format!("{base}/v1/traces"))
        .build()
        .map_err(|err| format!("is not a URL ({err})"))
}

/// `name=value,name2=value2`. The values are used as written (no percent-decoding).
fn parse_headers(raw: &str) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    let mut headers = Vec::new();
    for pair in raw
        .split(',')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
    {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| "must be name=value pairs separated by commas".to_owned())?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| "has an entry whose name is not a header name".to_owned())?;
        let mut value = HeaderValue::from_str(value.trim())
            .map_err(|_| format!("has an invalid value for {name}"))?;
        value.set_sensitive(true);
        headers.push((name, value));
    }
    Ok(headers)
}

impl ExportConfig {
    /// Reads the `OTEL_*` variables through `lookup`.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] naming the variable whose value is not usable. Header values are never
    /// quoted in it.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        let present = |var: &'static str| -> Result<Option<String>, ConfigError> {
            match lookup(var) {
                Some(raw) if raw.trim().is_empty() => Err(bad(var, "is empty")),
                Some(raw) => Ok(Some(raw.trim().to_owned())),
                None => Ok(None),
            }
        };
        if let Some(endpoint) = present("OTEL_EXPORTER_OTLP_ENDPOINT")? {
            config.traces_url =
                Some(traces_url(&endpoint).map_err(|why| bad("OTEL_EXPORTER_OTLP_ENDPOINT", why))?);
        }
        if let Some(raw) = present("OTEL_EXPORTER_OTLP_HEADERS")? {
            config.headers =
                parse_headers(&raw).map_err(|why| bad("OTEL_EXPORTER_OTLP_HEADERS", why))?;
        }
        config.ca_file = present("OTEL_EXPORTER_OTLP_CERTIFICATE")?.map(PathBuf::from);
        if let Some(name) = present("OTEL_SERVICE_NAME")? {
            if name.len() > SERVICE_NAME_MAX {
                return Err(bad(
                    "OTEL_SERVICE_NAME",
                    format!("is longer than {SERVICE_NAME_MAX} bytes"),
                ));
            }
            config.service_name = name.into();
        }
        if let Some(raw) = present("OTEL_MAX_SPANS_PER_SEC")? {
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
        Tracer::new(self.max_spans_per_sec.get(), self.traces_url.is_some())
    }
}

type OtlpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Why one send failed.
enum Failure {
    /// Worth another try: the collector was unreachable, slow, or told us to back off.
    Retry(String),
    /// The collector refused the batch; sending it again will not help.
    Refused(String),
}

/// Sends the tracer's queue to the collector. Register it with the server as a background
/// service.
pub struct TraceService {
    tracer: Tracer,
    client: OtlpClient,
    url: Uri,
    headers: Vec<(HeaderName, HeaderValue)>,
    service_name: Box<str>,
}

impl std::fmt::Debug for TraceService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceService")
            .field("url", &self.url)
            .finish_non_exhaustive()
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

fn client(config: &ExportConfig, https: bool) -> Result<OtlpClient, ConfigError> {
    let builder = if let Some(path) = &config.ca_file {
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
        let tls = tls_config(roots)
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

impl TraceService {
    /// The exporter for `config`, draining `tracer`; `None` when the node has no collector.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] when the root certificates cannot be loaded.
    pub fn new(tracer: &Tracer, config: &ExportConfig) -> Result<Option<Self>, ConfigError> {
        let Some(url) = &config.traces_url else {
            return Ok(None);
        };
        Ok(Some(Self {
            tracer: tracer.clone(),
            client: client(config, url.scheme_str() == Some("https"))?,
            url: url.clone(),
            headers: config.headers.clone(),
            service_name: config.service_name.clone(),
        }))
    }

    async fn send(&self, body: &Bytes) -> Result<(), Failure> {
        let mut request = Request::post(self.url.clone())
            .header(CONTENT_TYPE, "application/x-protobuf")
            .body(Full::new(body.clone()))
            .map_err(|err| Failure::Refused(err.to_string()))?;
        for (name, value) in &self.headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        let response = timeout(EXPORT_TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| Failure::Retry("the collector did not answer in time".to_owned()))?
            .map_err(|err| Failure::Retry(err.to_string()))?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else if matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        ) {
            Err(Failure::Retry(format!("the collector answered {status}")))
        } else {
            Err(Failure::Refused(format!("the collector answered {status}")))
        }
    }

    /// Sends `batch`, at most `attempts` times; counts it exported or lost.
    async fn export(&self, batch: Vec<Span>, attempts: u32) {
        let count = batch.len();
        let body = Bytes::from(otlp::encode(&self.service_name, &batch));
        drop(batch);
        let mut why = String::new();
        for attempt in 0..attempts {
            match self.send(&body).await {
                Ok(()) => {
                    self.tracer.exported(count);
                    return;
                }
                Err(Failure::Refused(reason)) => {
                    why = reason;
                    break;
                }
                Err(Failure::Retry(reason)) => {
                    why = reason;
                    if attempt + 1 < attempts {
                        sleep(BACKOFF * 2_u32.pow(attempt)).await;
                    }
                }
            }
        }
        self.tracer.lost(count);
        ::tracing::warn!(spans = count, reason = %why, "dropped a batch of spans: export failed");
    }

    /// Sends what is queued, a batch at a time, until the queue is empty.
    async fn drain(&self) {
        loop {
            let batch = self.tracer.take(BATCH_SPANS);
            let full = batch.len() == BATCH_SPANS;
            if batch.is_empty() {
                return;
            }
            self.export(batch, ATTEMPTS).await;
            if !full {
                return;
            }
        }
    }

    /// One try for each of the last few batches, on the way out.
    async fn flush_on_exit(&self) {
        for _ in 0..SHUTDOWN_BATCHES {
            let batch = self.tracer.take(BATCH_SPANS);
            if batch.is_empty() {
                return;
            }
            self.export(batch, 1).await;
        }
        let left = self.tracer.take(usize::MAX).len();
        self.tracer.lost(left);
    }
}

#[async_trait]
impl BackgroundService for TraceService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut tick = interval(FLUSH_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tick.tick() => {}
                () = self.tracer.batch_ready() => {}
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                () = self.drain() => {}
            }
        }
        self.flush_on_exit().await;
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
        assert!(parsed.traces_url.is_none());
        assert_eq!(&*parsed.service_name, "podgate");
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
            assert_eq!(parsed.traces_url.expect("url").to_string(), wanted);
        }
    }

    #[test]
    fn otel_reads_every_variable() {
        let parsed = config(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "x-api-key=s3cret, other=1"),
            ("OTEL_EXPORTER_OTLP_CERTIFICATE", "/etc/otel-ca.pem"),
            ("OTEL_SERVICE_NAME", "edge"),
            ("OTEL_MAX_SPANS_PER_SEC", "50"),
        ])
        .expect("parses");
        assert_eq!(parsed.headers.len(), 2);
        assert!(
            !format!("{parsed:?}").contains("s3cret"),
            "header values never print"
        );
        assert_eq!(parsed.ca_file, Some(PathBuf::from("/etc/otel-ca.pem")));
        assert_eq!(&*parsed.service_name, "edge");
        assert_eq!(parsed.max_spans_per_sec.get(), 50);
    }

    #[tokio::test]
    async fn otel_exporter_debug_never_prints_header_values() {
        let parsed = config(&[
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
            ("OTEL_SERVICE_NAME", " "),
            ("OTEL_MAX_SPANS_PER_SEC", "0"),
            ("OTEL_MAX_SPANS_PER_SEC", "1000001"),
            ("OTEL_MAX_SPANS_PER_SEC", "many"),
        ] {
            let err = config(&[(var, value)]).expect_err("value must be rejected");
            assert_eq!(err.var, var);
            assert!(!err.to_string().contains("pw@"), "{err}");
        }
        let err = config(&[("OTEL_EXPORTER_OTLP_HEADERS", "k=bad\nvalue")]).expect_err("refused");
        assert!(!err.to_string().contains("bad"), "{err}");
    }
}
