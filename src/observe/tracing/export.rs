//! The exporter: the operator's collector settings and the background service that batches the
//! queue and sends it as OTLP, over HTTP (protobuf POST) or gRPC (`grpc.rs`).
//!
//! The service never runs on the request path. A batch is 512 spans or whatever has queued in
//! two seconds; an export gives up after `OTEL_EXPORTER_OTLP_TIMEOUT` (3 seconds) and is retried
//! twice with backoff, then its spans are dropped and counted. Meanwhile the queue keeps its
//! bound, so a collector that is down or slow costs spans and nothing else. Both wires share all
//! of this; only the call that carries one encoded batch differs.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
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

use super::grpc;
use super::otlp;
use super::span::Span;
use super::tracer::{BATCH_SPANS, DEFAULT_MAX_SPANS_PER_SEC, Tracer};
use crate::config::ConfigError;

/// How long the exporter waits before sending a batch that is not full.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// The default for `OTEL_EXPORTER_OTLP_TIMEOUT`: one export gives up after this long, connecting
/// included.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// The most `OTEL_EXPORTER_OTLP_TIMEOUT` may allow, in milliseconds.
const EXPORT_TIMEOUT_MAX_MS: u64 = 10_000;

/// The largest encoded request sent in one call: collectors refuse more than 4 MiB by default.
/// A batch over it is split in halves.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;

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

/// How spans reach the collector: `OTEL_EXPORTER_OTLP_PROTOCOL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    /// `http/protobuf`: `POST <endpoint>/v1/traces`.
    #[default]
    Http,
    /// `grpc`: the unary `TraceService/Export` call.
    Grpc,
}

/// The operator's tracing settings, from the environment (never from a snapshot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportConfig {
    /// `OTEL_EXPORTER_OTLP_PROTOCOL`: `http/protobuf` (the default) or `grpc`.
    pub protocol: Protocol,
    /// The collector: for `http/protobuf` where spans are POSTed (`OTEL_EXPORTER_OTLP_ENDPOINT`
    /// with `/v1/traces` appended), for `grpc` the endpoint itself, without a path. Absent: spans
    /// are not recorded, requests are still sampled and propagated.
    pub traces_url: Option<Uri>,
    /// `OTEL_EXPORTER_OTLP_HEADERS`, sent with every export (an API key, say; gRPC metadata for
    /// `grpc`). Their values are marked sensitive so they never print.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// `OTEL_EXPORTER_OTLP_CERTIFICATE`: PEM roots to trust for an `https` collector instead of
    /// the platform's.
    pub ca_file: Option<PathBuf>,
    /// `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE` (`grpc` only): the client's certificate chain, PEM.
    pub client_cert: Option<PathBuf>,
    /// `OTEL_EXPORTER_OTLP_CLIENT_KEY` (`grpc` only): the key of the client certificate, PEM.
    pub client_key: Option<PathBuf>,
    /// `OTEL_EXPORTER_OTLP_COMPRESSION=gzip` (`grpc` only).
    pub gzip: bool,
    /// `OTEL_EXPORTER_OTLP_INSECURE=true` (`grpc` only): allows a plaintext endpoint that is not
    /// on loopback.
    pub insecure: bool,
    /// `OTEL_EXPORTER_OTLP_TIMEOUT`: how long one export may take, connecting included.
    pub timeout: Duration,
    /// `OTEL_SERVICE_NAME`: the `service.name` resource attribute.
    pub service_name: Box<str>,
    /// `OTEL_MAX_SPANS_PER_SEC`: spans a second this node lets be traced, whoever asks.
    pub max_spans_per_sec: NonZeroU32,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            protocol: Protocol::Http,
            traces_url: None,
            headers: Vec::new(),
            ca_file: None,
            client_cert: None,
            client_key: None,
            gzip: false,
            insecure: false,
            timeout: EXPORT_TIMEOUT,
            service_name: "podgate".into(),
            max_spans_per_sec: NonZeroU32::new(DEFAULT_MAX_SPANS_PER_SEC)
                .unwrap_or(NonZeroU32::MIN),
        }
    }
}

pub(super) fn bad(var: &'static str, reason: impl Into<Box<str>>) -> ConfigError {
    ConfigError {
        var,
        reason: reason.into(),
    }
}

/// `endpoint` checked as an `http` or `https` URL without credentials or query, as `(scheme,
/// authority, uri)`.
fn collector_uri(endpoint: &str) -> Result<Uri, String> {
    let uri: Uri = endpoint
        .parse()
        .map_err(|err| format!("is not a URL ({err})"))?;
    let scheme = uri.scheme_str().unwrap_or_default();
    if scheme != "http" && scheme != "https" {
        return Err("must start with http:// or https://".to_owned());
    }
    let authority = uri.authority().ok_or_else(|| "has no host".to_owned())?;
    if authority.as_str().contains('@') {
        return Err("must not carry credentials; use OTEL_EXPORTER_OTLP_HEADERS".to_owned());
    }
    if uri.query().is_some() {
        return Err("must not have a query".to_owned());
    }
    Ok(uri)
}

/// `endpoint` plus the traces path: `http://c:4318` becomes `http://c:4318/v1/traces`.
fn traces_url(endpoint: &str) -> Result<Uri, String> {
    let uri = collector_uri(endpoint)?;
    let authority = uri.authority().map(http::uri::Authority::as_str);
    let base = uri.path().trim_end_matches('/');
    Uri::builder()
        .scheme(uri.scheme_str().unwrap_or_default())
        .authority(authority.unwrap_or_default())
        .path_and_query(format!("{base}/v1/traces"))
        .build()
        .map_err(|err| format!("is not a URL ({err})"))
}

/// A gRPC endpoint is a host and port: a path means nothing to the call, so one is refused rather
/// than ignored.
fn grpc_endpoint(endpoint: &str) -> Result<Uri, String> {
    let uri = collector_uri(endpoint)?;
    if !matches!(uri.path(), "" | "/") {
        return Err("must not have a path for grpc".to_owned());
    }
    Ok(uri)
}

/// Whether `uri` names this machine: `localhost` or a loopback address.
fn is_loopback(uri: &Uri) -> bool {
    let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
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
        if let Some(raw) = present("OTEL_EXPORTER_OTLP_PROTOCOL")? {
            config.protocol = match raw.as_str() {
                "http/protobuf" => Protocol::Http,
                "grpc" => Protocol::Grpc,
                _ => {
                    return Err(bad(
                        "OTEL_EXPORTER_OTLP_PROTOCOL",
                        "must be `http/protobuf` or `grpc`",
                    ));
                }
            };
        }
        let grpc = config.protocol == Protocol::Grpc;
        if let Some(endpoint) = present("OTEL_EXPORTER_OTLP_ENDPOINT")? {
            let parsed = if grpc {
                grpc_endpoint(&endpoint)
            } else {
                traces_url(&endpoint)
            };
            config.traces_url =
                Some(parsed.map_err(|why| bad("OTEL_EXPORTER_OTLP_ENDPOINT", why))?);
        }
        if let Some(raw) = present("OTEL_EXPORTER_OTLP_HEADERS")? {
            config.headers =
                parse_headers(&raw).map_err(|why| bad("OTEL_EXPORTER_OTLP_HEADERS", why))?;
            if grpc
                && config
                    .headers
                    .iter()
                    .any(|(name, _)| !grpc::metadata_name_allowed(name))
            {
                return Err(bad(
                    "OTEL_EXPORTER_OTLP_HEADERS",
                    "names a header that gRPC sets itself (`content-type`, `te`, `grpc-*`, ...)",
                ));
            }
        }
        config.ca_file = present("OTEL_EXPORTER_OTLP_CERTIFICATE")?.map(PathBuf::from);
        config.client_cert = present("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE")?.map(PathBuf::from);
        config.client_key = present("OTEL_EXPORTER_OTLP_CLIENT_KEY")?.map(PathBuf::from);
        if config.client_cert.is_some() != config.client_key.is_some() {
            return Err(bad(
                "OTEL_EXPORTER_OTLP_CLIENT_KEY",
                "and OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE must be set together",
            ));
        }
        if let Some(raw) = present("OTEL_EXPORTER_OTLP_COMPRESSION")? {
            config.gzip = match raw.as_str() {
                "gzip" => true,
                "none" => false,
                _ => {
                    return Err(bad(
                        "OTEL_EXPORTER_OTLP_COMPRESSION",
                        "must be `gzip` or `none`",
                    ));
                }
            };
        }
        if let Some(raw) = present("OTEL_EXPORTER_OTLP_INSECURE")? {
            config.insecure = match raw.to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(bad(
                        "OTEL_EXPORTER_OTLP_INSECURE",
                        "must be `true` or `false`",
                    ));
                }
            };
        }
        if let Some(raw) = present("OTEL_EXPORTER_OTLP_TIMEOUT")? {
            let millis: u64 = raw
                .parse()
                .ok()
                .filter(|millis| (1..=EXPORT_TIMEOUT_MAX_MS).contains(millis))
                .ok_or_else(|| {
                    bad(
                        "OTEL_EXPORTER_OTLP_TIMEOUT",
                        format!("must be milliseconds in 1..={EXPORT_TIMEOUT_MAX_MS}"),
                    )
                })?;
            config.timeout = Duration::from_millis(millis);
        }
        if !grpc {
            for (var, set) in [
                (
                    "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE",
                    config.client_cert.is_some(),
                ),
                ("OTEL_EXPORTER_OTLP_COMPRESSION", config.gzip),
                ("OTEL_EXPORTER_OTLP_INSECURE", config.insecure),
            ] {
                if set {
                    return Err(bad(var, "applies only to OTEL_EXPORTER_OTLP_PROTOCOL=grpc"));
                }
            }
        } else if let Some(endpoint) = &config.traces_url
            && endpoint.scheme_str() == Some("http")
            && !is_loopback(endpoint)
            && !config.insecure
        {
            return Err(bad(
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "is plaintext and not on loopback: spans carry hostnames and paths; use https:// \
                 or set OTEL_EXPORTER_OTLP_INSECURE=true",
            ));
        }
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
pub(super) enum Failure {
    /// Worth another try: the collector was unreachable, slow, or told us to back off. The delay
    /// is the one the collector asked for, when it did.
    Retry(String, Option<Duration>),
    /// The collector refused the batch; sending it again will not help.
    Refused(String),
}

/// Encodes `batch` as requests of at most `limit` bytes each, splitting it in halves as often as
/// needed, in order. Returns each request as its span count and body, and the number of spans
/// that alone exceed `limit` and so cannot be sent.
fn split_requests(
    service_name: &str,
    batch: Vec<Span>,
    limit: usize,
) -> (Vec<(usize, Bytes)>, usize) {
    let mut requests = Vec::new();
    let mut oversized = 0;
    let mut work = vec![batch];
    while let Some(mut batch) = work.pop() {
        let body = otlp::encode(service_name, &batch);
        if body.len() <= limit {
            requests.push((batch.len(), Bytes::from(body)));
        } else if batch.len() > 1 {
            let upper = batch.split_off(batch.len() / 2);
            work.push(upper);
            work.push(batch);
        } else {
            oversized += batch.len();
        }
    }
    (requests, oversized)
}

/// The wire spans go out on.
enum Wire {
    Http {
        client: Box<OtlpClient>,
        url: Uri,
        headers: Vec<(HeaderName, HeaderValue)>,
        timeout: Duration,
    },
    Grpc(grpc::Channel),
}

/// Sends the tracer's queue to the collector. Register it with the server as a background
/// service.
pub struct TraceService {
    tracer: Tracer,
    wire: Wire,
    service_name: Box<str>,
}

impl std::fmt::Debug for TraceService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut shown = f.debug_struct("TraceService");
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

fn client(config: &ExportConfig, https: bool) -> Result<OtlpClient, ConfigError> {
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

impl TraceService {
    /// The exporter for `config`, draining `tracer`; `None` when the node has no collector.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] when the root certificates or the client certificate cannot be loaded.
    pub fn new(tracer: &Tracer, config: &ExportConfig) -> Result<Option<Self>, ConfigError> {
        let Some(url) = &config.traces_url else {
            return Ok(None);
        };
        let wire = match config.protocol {
            Protocol::Http => Wire::Http {
                client: Box::new(client(config, url.scheme_str() == Some("https"))?),
                url: url.clone(),
                headers: config.headers.clone(),
                timeout: config.timeout,
            },
            Protocol::Grpc => {
                if url.scheme_str() == Some("http") && !is_loopback(url) {
                    ::tracing::warn!(
                        host = url.host().unwrap_or_default(),
                        "OTEL_EXPORTER_OTLP_INSECURE=true: spans go to the collector unencrypted"
                    );
                }
                Wire::Grpc(grpc::Channel::new(config, url)?)
            }
        };
        Ok(Some(Self {
            tracer: tracer.clone(),
            wire,
            service_name: config.service_name.clone(),
        }))
    }

    /// Sends one encoded request. `Ok` is the number of spans the collector refused.
    async fn send(&self, body: &Bytes) -> Result<i64, Failure> {
        match &self.wire {
            Wire::Grpc(channel) => channel.export(body).await,
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

    /// Sends `batch`, split until each request fits [`MAX_MESSAGE`]; counts the spans exported or
    /// lost.
    async fn export(&self, batch: Vec<Span>, attempts: u32) {
        let (requests, oversized) = split_requests(&self.service_name, batch, MAX_MESSAGE);
        if oversized > 0 {
            self.tracer.lost(oversized);
            ::tracing::warn!(
                spans = oversized,
                "dropped spans: each alone is larger than the 4 MiB message limit"
            );
        }
        for (count, body) in requests {
            self.export_one(count, body, attempts).await;
        }
    }

    /// Sends one encoded request of `count` spans, at most `attempts` times.
    async fn export_one(&self, count: usize, body: Bytes, attempts: u32) {
        let mut why = String::new();
        for attempt in 0..attempts {
            let wait = match self.send(&body).await {
                Ok(rejected) => {
                    let rejected = usize::try_from(rejected).unwrap_or(0).min(count);
                    self.tracer.exported(count - rejected);
                    if rejected > 0 {
                        self.tracer.lost(rejected);
                        ::tracing::warn!(spans = rejected, "the collector refused some spans");
                    }
                    return;
                }
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
        assert_eq!(parsed.protocol, Protocol::Http);
        assert_eq!(parsed.timeout, Duration::from_secs(3));
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
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
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
        assert_eq!(parsed.timeout, Duration::from_millis(2500));
        assert_eq!(&*parsed.service_name, "edge");
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
        assert_eq!(parsed.protocol, Protocol::Grpc);
        assert_eq!(
            parsed.traces_url.expect("url").to_string(),
            "https://collector.test:4317/"
        );
        assert!(parsed.gzip);
        assert_eq!(parsed.client_key, Some(PathBuf::from("/etc/k.pem")));
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
        assert!(config(&allowed).expect("operator decision").insecure);
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

        let (requests, oversized) = split_requests("edge", batch.clone(), whole);
        assert_eq!(oversized, 0);
        assert_eq!(requests.len(), 1, "a batch at the limit is one request");
        assert_eq!(requests[0].0, 8);
        assert_eq!(ids(&requests[0].1), (1..=8).collect::<Vec<u8>>());

        let (requests, oversized) = split_requests("edge", batch, whole - 1);
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
        let (requests, oversized) = split_requests("edge", batch, one + 10);
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
            split_requests("edge", vec![span(1, 10), span(2, 1000), span(3, 10)], limit);
        assert_eq!(oversized, 1, "the big span alone exceeds the limit");
        let all: Vec<u8> = requests.iter().flat_map(|(_, body)| ids(body)).collect();
        assert_eq!(all, vec![1, 3], "the others are still sent");

        let (requests, oversized) = split_requests("edge", vec![span(2, 1000)], limit);
        assert!(requests.is_empty());
        assert_eq!(oversized, 1);
    }
}
