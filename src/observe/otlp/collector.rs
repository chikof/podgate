//! The operator's collector settings every signal shares: where the OTLP collector is, how to
//! reach it and who we are. They come from the standard `OTEL_EXPORTER_OTLP_*` variables and
//! `OTEL_SERVICE_NAME`, never from a snapshot.
//!
//! A signal (traces, metrics, logs) adds only its own variables and takes a `&`[`Collector`]; it
//! never reads these again, so the plaintext, loopback and certificate checks live in one place.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use http::{HeaderName, HeaderValue, Uri};

use super::grpc;
use crate::config::ConfigError;

/// The default for `OTEL_EXPORTER_OTLP_TIMEOUT`: one export gives up after this long, connecting
/// included.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// The most `OTEL_EXPORTER_OTLP_TIMEOUT` may allow, in milliseconds.
const EXPORT_TIMEOUT_MAX_MS: u64 = 10_000;

/// The longest `OTEL_SERVICE_NAME`.
const SERVICE_NAME_MAX: usize = 128;

/// How telemetry reaches the collector: `OTEL_EXPORTER_OTLP_PROTOCOL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    /// `http/protobuf`: `POST <endpoint>/v1/<signal>`.
    #[default]
    Http,
    /// `grpc`: the unary `<Signal>Service/Export` call.
    Grpc,
}

/// What is being exported: it picks the path of the HTTP request and the gRPC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Spans.
    Traces,
    /// Metrics.
    Metrics,
    /// Log records.
    Logs,
}

impl Signal {
    /// The path an HTTP export is POSTed to, appended to the endpoint.
    #[must_use]
    pub const fn http_path(self) -> &'static str {
        match self {
            Self::Traces => "/v1/traces",
            Self::Metrics => "/v1/metrics",
            Self::Logs => "/v1/logs",
        }
    }

    /// The gRPC method an export calls.
    #[must_use]
    pub const fn grpc_path(self) -> &'static str {
        match self {
            Self::Traces => "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
            Self::Metrics => "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
            Self::Logs => "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
        }
    }
}

/// The operator's collector settings, from the environment (never from a snapshot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collector {
    /// `OTEL_EXPORTER_OTLP_PROTOCOL`: `http/protobuf` (the default) or `grpc`.
    pub protocol: Protocol,
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`, checked: an `http` or `https` URL without credentials or
    /// query and, for `grpc`, without a path. Absent: nothing is exported.
    pub endpoint: Option<Uri>,
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
}

impl Default for Collector {
    fn default() -> Self {
        Self {
            protocol: Protocol::Http,
            endpoint: None,
            headers: Vec::new(),
            ca_file: None,
            client_cert: None,
            client_key: None,
            gzip: false,
            insecure: false,
            timeout: EXPORT_TIMEOUT,
            service_name: "podgate".into(),
        }
    }
}

/// A [`ConfigError`] naming `var`.
pub fn bad(var: &'static str, reason: impl Into<Box<str>>) -> ConfigError {
    ConfigError {
        var,
        reason: reason.into(),
    }
}

/// The trimmed value of `var`: `None` when unset, an error when set to nothing.
///
/// # Errors
///
/// A [`ConfigError`] naming `var` when it is empty.
pub fn present(
    lookup: &dyn Fn(&str) -> Option<String>,
    var: &'static str,
) -> Result<Option<String>, ConfigError> {
    match lookup(var) {
        Some(raw) if raw.trim().is_empty() => Err(bad(var, "is empty")),
        Some(raw) => Ok(Some(raw.trim().to_owned())),
        None => Ok(None),
    }
}

/// `endpoint` checked as an `http` or `https` URL without credentials or query.
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

/// `endpoint` plus the signal's path: `http://c:4318` becomes `http://c:4318/v1/traces`.
fn http_url(endpoint: &Uri, signal: Signal) -> Result<Uri, String> {
    let authority = endpoint.authority().map(http::uri::Authority::as_str);
    let base = endpoint.path().trim_end_matches('/');
    Uri::builder()
        .scheme(endpoint.scheme_str().unwrap_or_default())
        .authority(authority.unwrap_or_default())
        .path_and_query(format!("{base}{}", signal.http_path()))
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
pub(super) fn is_loopback(uri: &Uri) -> bool {
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

impl Collector {
    /// Reads the `OTEL_EXPORTER_OTLP_*` variables and `OTEL_SERVICE_NAME` through `lookup`.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] naming the variable whose value is not usable. Header values are never
    /// quoted in it.
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        if let Some(raw) = present(lookup, "OTEL_EXPORTER_OTLP_PROTOCOL")? {
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
        if let Some(endpoint) = present(lookup, "OTEL_EXPORTER_OTLP_ENDPOINT")? {
            let parsed = if grpc {
                grpc_endpoint(&endpoint)
            } else {
                collector_uri(&endpoint).and_then(|uri| http_url(&uri, Signal::Traces).map(|_| uri))
            };
            config.endpoint = Some(parsed.map_err(|why| bad("OTEL_EXPORTER_OTLP_ENDPOINT", why))?);
        }
        if let Some(raw) = present(lookup, "OTEL_EXPORTER_OTLP_HEADERS")? {
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
        config.ca_file = present(lookup, "OTEL_EXPORTER_OTLP_CERTIFICATE")?.map(PathBuf::from);
        config.client_cert =
            present(lookup, "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE")?.map(PathBuf::from);
        config.client_key = present(lookup, "OTEL_EXPORTER_OTLP_CLIENT_KEY")?.map(PathBuf::from);
        if config.client_cert.is_some() != config.client_key.is_some() {
            return Err(bad(
                "OTEL_EXPORTER_OTLP_CLIENT_KEY",
                "and OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE must be set together",
            ));
        }
        if let Some(raw) = present(lookup, "OTEL_EXPORTER_OTLP_COMPRESSION")? {
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
        if let Some(raw) = present(lookup, "OTEL_EXPORTER_OTLP_INSECURE")? {
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
        if let Some(raw) = present(lookup, "OTEL_EXPORTER_OTLP_TIMEOUT")? {
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
        } else if let Some(endpoint) = &config.endpoint
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
        if let Some(name) = present(lookup, "OTEL_SERVICE_NAME")? {
            if name.len() > SERVICE_NAME_MAX {
                return Err(bad(
                    "OTEL_SERVICE_NAME",
                    format!("is longer than {SERVICE_NAME_MAX} bytes"),
                ));
            }
            config.service_name = name.into();
        }
        Ok(config)
    }

    /// Where `signal` is sent: for `http/protobuf` the endpoint with the signal's path appended
    /// (`http://c:4318` becomes `http://c:4318/v1/traces`), for `grpc` the endpoint itself.
    /// `None` when no endpoint is set.
    #[must_use]
    pub fn url(&self, signal: Signal) -> Option<Uri> {
        let endpoint = self.endpoint.as_ref()?;
        match self.protocol {
            Protocol::Grpc => Some(endpoint.clone()),
            Protocol::Http => http_url(endpoint, signal).ok(),
        }
    }
}
