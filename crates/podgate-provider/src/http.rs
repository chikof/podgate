//! The HTTP source: apps (or a Traefik dynamic configuration) fetched from an endpoint the
//! operator chose, polled with conditional requests.
//!
//! ```toml
//! [[source]]
//! kind = "http"
//! name = "web"
//! url = "https://config.internal/podgate.json"   # the operator's, never derived from data
//! poll_secs = 30                                   # at least 5
//! timeout_secs = 10                                # the whole request, redirects and body
//! max_bytes = 4194304                              # at most 16 MiB
//! format = "podgate"                               # or "traefik"
//! tenant = "acme"                                  # the tenant of everything it returns
//! allow_local = false                              # true: a loopback or link-local server
//!
//! [source.headers]
//! Authorization = "file:/etc/podgate/config-token" # read at start, never logged
//!
//! [source.tls]
//! ca_file = "/etc/podgate/config-ca.pem"
//! cert_file = "/etc/podgate/config-client.pem"
//! key_file = "/etc/podgate/config-client-key.pem"
//! ```
//!
//! `format = "podgate"` is a partial snapshot as the file source reads it (`apps`,
//! `certificates`); its apps and certificates go through the key-value layer ([`crate::kv`]), so
//! the trust rules are the same ones: the tenant is the source's, a document that names a tenant
//! is left out, unknown fields reject the object, and [`crate::kv::Mapping::new`] refuses a tenant that
//! has no allow list of its own. `format = "traefik"` goes through the Traefik file converter in
//! its no-disk mode ([`crate::traefik_file::convert_inline`]): the answer is remote, so no option
//! of it may make this machine read a file.
//!
//! The poll is a `GET` with `If-None-Match` and `If-Modified-Since` from the last good answer. A
//! redirect is followed only inside the same origin, at most 3 times; the body is cut at
//! `max_bytes` while it streams; the `Content-Type` must be JSON or YAML. A failed poll keeps the
//! last good state, is reported as an outage, and the next try waits longer, up to 5 minutes. A
//! connection goes only to addresses that are not loopback or link-local, unless `allow_local`.
//! The URL, the header values and the TLS key are read once at start and never logged.
//!
//! The reference is `docs/ref/provider-http.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    ACCEPT, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST, HeaderName,
    HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION, USER_AGENT,
};
use http::uri::PathAndQuery;
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_rustls::ConfigBuilderExt as _;
use hyper_util::rt::TokioIo;
use podgate_model::App;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::abort::Abort;
use crate::config::SourceConfig;
use crate::kv::{Built, Layout, Mapping, RawPrefix};
use crate::policy::UpstreamPolicy;
use crate::push::Backoff;
use crate::source::{
    Origin, Source, SourceApp, SourceCertificate, State, TenantClaim, Update, UpdateBody,
};
use crate::traefik_file::{self, Syntax};

/// The shortest `poll_secs`.
pub const MIN_POLL_SECS: u64 = 5;

/// The default `poll_secs`.
const DEFAULT_POLL_SECS: u64 = 30;

/// The default `timeout_secs`.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// The longest `timeout_secs`.
const MAX_TIMEOUT_SECS: u64 = 300;

/// The default `max_bytes`: 4 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// The largest `max_bytes`: 16 MiB.
pub const LIMIT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The longest wait after failed polls.
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// The most redirects one poll follows, all inside one origin.
const MAX_REDIRECTS: usize = 3;

/// The most report lines a Traefik conversion adds to the state's report.
const MAX_REPORTS: usize = 50;

/// The `declared_by` placeholder of an app; the core overwrites it.
const DECLARED_BY: &str = "http";

/// The local id of the one app a Traefik document becomes.
const TRAEFIK_APP: &str = "traefik";

/// Headers the source sets itself.
const RESERVED_HEADERS: [&str; 10] = [
    "host",
    "accept",
    "connection",
    "content-length",
    "transfer-encoding",
    "if-none-match",
    "if-modified-since",
    "if-match",
    "if-unmodified-since",
    "te",
];

/// A `[[source]]` entry of kind `http` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct HttpConfigError {
    /// The source's name.
    pub name: Box<str>,
    /// What is wrong, naming the key and never quoting a value.
    pub reason: Box<str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    ca_file: Option<PathBuf>,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
}

/// What the answer holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Format {
    /// A partial snapshot, as the file source reads it.
    #[default]
    Podgate,
    /// Traefik dynamic configuration.
    Traefik,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    url: String,
    tenant: String,
    poll_secs: Option<u64>,
    timeout_secs: Option<u64>,
    max_bytes: Option<u64>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    tls: Option<RawTls>,
    #[serde(default)]
    format: Format,
    #[serde(default)]
    allow_local: bool,
}

/// The HTTP source.
pub struct HttpSource {
    name: Box<str>,
    target: Target,
    headers: Vec<(HeaderName, HeaderValue)>,
    connector: Option<TlsConnector>,
    allow_local: bool,
    poll: Duration,
    backoff_max: Duration,
    timeout: Duration,
    max_bytes: usize,
    plan: Arc<Plan>,
}

impl std::fmt::Debug for HttpSource {
    /// Shows the endpoint without its path and query (a token may sit in either) and the header
    /// names without their values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpSource")
            .field("name", &self.name)
            .field("endpoint", &self.target.origin())
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("tenant", &self.plan.tenant)
            .field("format", &self.plan.format)
            .finish_non_exhaustive()
    }
}

/// `scheme://host:port` and the path of the endpoint.
#[derive(Clone)]
struct Target {
    https: bool,
    host: Box<str>,
    port: u16,
    path_and_query: Box<str>,
}

impl Target {
    fn of(uri: &Uri) -> Result<Self, &'static str> {
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err("must be an http:// or https:// URL"),
        };
        let authority = uri.authority().ok_or("needs a host")?;
        if authority.as_str().contains('@') {
            return Err("must not carry credentials; they go in headers");
        }
        let host = authority.host().trim_matches(['[', ']']);
        if host.is_empty() {
            return Err("needs a host");
        }
        Ok(Self {
            https,
            host: host.into(),
            port: authority.port_u16().unwrap_or(if https { 443 } else { 80 }),
            path_and_query: uri
                .path_and_query()
                .map_or("/", PathAndQuery::as_str)
                .into(),
        })
    }

    /// `scheme://host:port`, which is all a log line or a debug output may show.
    fn origin(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        if self.host.contains(':') {
            format!("{scheme}://[{}]:{}", self.host, self.port)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }

    fn host_header(&self) -> String {
        let default = if self.https { 443 } else { 80 };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.to_string()
        };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    fn same_origin(&self, other: &Self) -> bool {
        self.https == other.https
            && self.host.eq_ignore_ascii_case(&other.host)
            && self.port == other.port
    }

    /// Where a `Location` points, or why it may not be followed.
    fn follow(&self, location: &str) -> Result<Self, &'static str> {
        let next = if location.starts_with('/') {
            Self {
                path_and_query: location
                    .parse::<PathAndQuery>()
                    .map_err(|_| "redirects to something that is not a URL")?
                    .as_str()
                    .into(),
                ..self.clone()
            }
        } else {
            let uri: Uri = location
                .parse()
                .map_err(|_| "redirects to something that is not a URL")?;
            if uri.scheme().is_none() {
                return Err(
                    "redirects to a relative path; only absolute URLs and paths are followed",
                );
            }
            Self::of(&uri).map_err(|_| "redirects to something that is not an http(s) URL")?
        };
        if self.same_origin(&next) {
            Ok(next)
        } else {
            Err("redirects to another origin, which is refused")
        }
    }
}

/// Whether `ip` is an address a config server must not be on unless the operator says so.
fn is_local(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_link_local() || ip.is_unspecified(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_local_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host.parse::<IpAddr>().is_ok_and(is_local)
}

fn read(key: &str, path: &std::path::Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|err| format!("{key}: cannot read {}: {err}", path.display()))
}

#[derive(Default)]
struct TlsPem {
    ca: Option<Vec<u8>>,
    cert: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
}

fn tls_config(pem: TlsPem) -> Result<rustls::ClientConfig, String> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| format!("TLS: {err}"))?;
    let builder = match pem.ca {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(&ca) {
                let cert = cert.map_err(|err| format!("tls.ca_file: {err}"))?;
                roots
                    .add(cert)
                    .map_err(|err| format!("tls.ca_file: {err}"))?;
            }
            if roots.is_empty() {
                return Err("tls.ca_file: holds no certificate".to_owned());
            }
            builder.with_root_certificates(roots)
        }
        None => builder
            .with_native_roots()
            .map_err(|err| format!("cannot load the platform's root certificates ({err})"))?,
    };
    let mut config = match (pem.cert, pem.key) {
        (Some(cert), Some(key)) => {
            let chain = CertificateDer::pem_slice_iter(&cert)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| format!("tls.cert_file: {err}"))?;
            if chain.is_empty() {
                return Err("tls.cert_file: holds no certificate".to_owned());
            }
            // The error of a bad key names the file, never its content.
            let key = PrivateKeyDer::from_pem_slice(&key)
                .map_err(|_| "tls.key_file: holds no private key".to_owned())?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|err| format!("tls.cert_file and tls.key_file: {err}"))?
        }
        _ => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// One header of the configuration: a literal value, or `file:/path` to read it from.
fn header(name: &str, value: &str) -> Result<(HeaderName, HeaderValue), String> {
    let header_name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| format!("headers: {name:?} is not a header name"))?;
    if RESERVED_HEADERS.contains(&header_name.as_str()) {
        return Err(format!(
            "headers.{name}: the source sets this header itself"
        ));
    }
    let text = match value.strip_prefix("file:") {
        Some(path) => {
            let bytes = read(&format!("headers.{name}"), std::path::Path::new(path))?;
            String::from_utf8(bytes)
                .map_err(|_| format!("headers.{name}: the file is not UTF-8"))?
                .trim_end_matches(['\n', '\r'])
                .to_owned()
        }
        None => value.to_owned(),
    };
    if text.is_empty() {
        return Err(format!("headers.{name}: the value is empty"));
    }
    let mut header_value = HeaderValue::from_str(&text)
        .map_err(|_| format!("headers.{name}: the value is not a valid header value"))?;
    header_value.set_sensitive(true);
    Ok((header_name, header_value))
}

impl HttpSource {
    /// An HTTP source from its `[[source]]` entry, checking its tenant against `policy`.
    ///
    /// # Errors
    ///
    /// [`HttpConfigError`] when a key is unknown or has the wrong type, `url` is not an
    /// `http://` or `https://` URL with a host, without credentials, or names a loopback or
    /// link-local host while `allow_local` is not set, a number is out of range, a header name
    /// is invalid or reserved or its file cannot be read, headers would cross a network over
    /// plain `http://`, a TLS file cannot be read, or the tenant has no allow list of its own in
    /// `policy` (code `kv_source_requires_tenant_allowlist`). An unknown key is an error so a
    /// misspelt `tenant` cannot move the source's apps to another tenant.
    pub fn from_config(
        config: &SourceConfig,
        policy: &UpstreamPolicy,
    ) -> Result<Self, HttpConfigError> {
        let invalid = |reason: String| HttpConfigError {
            name: config.name.clone(),
            reason: reason.into(),
        };
        let raw = Raw::deserialize(toml::Value::Table(config.settings.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        // The URL is never quoted in an error: a token may sit in its query.
        let uri: Uri = raw
            .url
            .parse()
            .map_err(|_| invalid("url: is not a URL".to_owned()))?;
        let target = Target::of(&uri).map_err(|why| invalid(format!("url: {why}")))?;
        if !raw.allow_local && is_local_host(&target.host) {
            return Err(invalid(
                "url: names a loopback or link-local address; set allow_local = true to read a configuration server on this machine"
                    .to_owned(),
            ));
        }
        let poll_secs = raw.poll_secs.unwrap_or(DEFAULT_POLL_SECS);
        if poll_secs < MIN_POLL_SECS {
            return Err(invalid(format!(
                "poll_secs: must be at least {MIN_POLL_SECS}, got {poll_secs}"
            )));
        }
        let timeout_secs = raw.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if !(1..=MAX_TIMEOUT_SECS).contains(&timeout_secs) {
            return Err(invalid(format!(
                "timeout_secs: must be 1 to {MAX_TIMEOUT_SECS}, got {timeout_secs}"
            )));
        }
        let max_bytes = raw.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
        if !(1..=LIMIT_MAX_BYTES).contains(&max_bytes) {
            return Err(invalid(format!(
                "max_bytes: must be 1 to {LIMIT_MAX_BYTES}, got {max_bytes}"
            )));
        }
        if !raw.headers.is_empty() && !target.https && !is_local_host(&target.host) {
            return Err(invalid(
                "headers: would cross the network in clear over http://; use an https:// url"
                    .to_owned(),
            ));
        }
        let mut headers = Vec::with_capacity(raw.headers.len());
        for (name, value) in &raw.headers {
            headers.push(header(name, value).map_err(invalid)?);
        }
        let connector = match raw.tls {
            None => target
                .https
                .then(|| tls_config(TlsPem::default()))
                .transpose()
                .map_err(invalid)?,
            Some(tls) => {
                if !target.https {
                    return Err(invalid("tls: needs an https:// url".to_owned()));
                }
                if tls.cert_file.is_some() != tls.key_file.is_some() {
                    return Err(invalid(
                        "tls: cert_file and key_file go together".to_owned(),
                    ));
                }
                let mut pem = TlsPem::default();
                for (key, path, slot) in [
                    ("tls.ca_file", tls.ca_file, &mut pem.ca),
                    ("tls.cert_file", tls.cert_file, &mut pem.cert),
                    ("tls.key_file", tls.key_file, &mut pem.key),
                ] {
                    if let Some(path) = path {
                        *slot = Some(read(key, &path).map_err(invalid)?);
                    }
                }
                Some(tls_config(pem).map_err(invalid)?)
            }
        }
        .map(|config| TlsConnector::from(Arc::new(config)));
        // The tenant and the allow list requirement are the key-value layer's: this source is one
        // prefix of the `podgate-json` layout.
        let mapping = Mapping::new(
            vec![RawPrefix {
                prefix: config.name.to_string(),
                tenant: raw.tenant.clone(),
                layout: Layout::PodgateJson,
                app: None,
            }],
            policy,
        )
        .map_err(|err| invalid(err.to_string()))?;
        Ok(Self {
            name: config.name.clone(),
            target,
            headers,
            connector,
            allow_local: raw.allow_local,
            poll: Duration::from_secs(poll_secs),
            backoff_max: MAX_BACKOFF,
            timeout: Duration::from_secs(timeout_secs),
            // `max_bytes` is at most 16 MiB, which fits `usize` on every supported target.
            max_bytes: usize::try_from(max_bytes).unwrap_or(usize::MAX),
            plan: Arc::new(Plan {
                name: config.name.clone(),
                tenant: raw.tenant.into(),
                format: raw.format,
                mapping,
            }),
        })
    }

    /// The poll interval and the longest wait after failures, in place of `poll_secs` and the
    /// 5 minutes. They bypass the minimum of [`MIN_POLL_SECS`]: for tests and for embedding the
    /// source in a program that wants other timing.
    #[must_use]
    pub fn with_timing(mut self, poll: Duration, backoff_max: Duration) -> Self {
        self.poll = poll;
        self.backoff_max = backoff_max;
        self
    }
}

// ---- fetching -------------------------------------------------------------------------------

/// What an answer was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Json,
    Yaml,
}

/// The kind a `Content-Type` names, or why it is refused.
fn kind_of(content_type: Option<&HeaderValue>) -> Result<Kind, String> {
    let Some(value) = content_type else {
        return Err("the answer has no Content-Type; JSON or YAML is required".to_owned());
    };
    let text = value
        .to_str()
        .map_err(|_| "the Content-Type is not text".to_owned())?;
    let mut parts = text.split(';');
    let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    for parameter in parts {
        if let Some((key, charset)) = parameter.split_once('=')
            && key.trim().eq_ignore_ascii_case("charset")
            && !charset
                .trim()
                .trim_matches('"')
                .eq_ignore_ascii_case("utf-8")
        {
            return Err("the Content-Type names a charset other than UTF-8".to_owned());
        }
    }
    match media.as_str() {
        "application/json" => Ok(Kind::Json),
        "application/yaml" | "application/x-yaml" | "text/yaml" | "text/x-yaml" => Ok(Kind::Yaml),
        m if m.ends_with("+json") => Ok(Kind::Json),
        m if m.ends_with("+yaml") => Ok(Kind::Yaml),
        _ => Err(format!(
            "the Content-Type {media:?} is not JSON or YAML",
            media = media.chars().take(60).collect::<String>()
        )),
    }
}

/// The last good answer's validators, sent back to ask whether it changed.
#[derive(Debug, Clone, Default)]
struct Validators {
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
}

impl Validators {
    fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

struct Document {
    bytes: Vec<u8>,
    kind: Kind,
    validators: Validators,
}

enum Answer {
    NotModified,
    Document(Document),
}

/// An answer's head and body, with the task that drives its connection.
struct Exchange {
    response: http::Response<Incoming>,
    _driver: Abort,
}

async fn send<S>(stream: S, request: Request<Empty<Bytes>>) -> Result<Exchange, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|err| format!("cannot talk HTTP to the server: {err}"))?;
    let driver = Abort(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = sender
        .send_request(request)
        .await
        .map_err(|err| format!("the request failed: {err}"))?;
    Ok(Exchange {
        response,
        _driver: driver,
    })
}

impl HttpSource {
    /// The addresses of `target`, none of them local unless the operator allows it. The check is
    /// on every connection, so a name that starts to resolve to a local address is caught.
    async fn resolve(&self, target: &Target) -> Result<Vec<SocketAddr>, String> {
        let found: Vec<SocketAddr> = tokio::net::lookup_host((&*target.host, target.port))
            .await
            .map_err(|err| format!("cannot resolve the host: {err}"))?
            .collect();
        if found.is_empty() {
            return Err("the host has no address".to_owned());
        }
        if !self.allow_local && found.iter().any(|addr| is_local(addr.ip())) {
            return Err(
                "the host resolves to a loopback or link-local address; set allow_local = true to allow it"
                    .to_owned(),
            );
        }
        Ok(found)
    }

    async fn exchange(
        &self,
        target: &Target,
        validators: Option<&Validators>,
    ) -> Result<Exchange, String> {
        let addresses = self.resolve(target).await?;
        let mut last = String::new();
        let mut connected = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(err) => last = err.to_string(),
            }
        }
        let stream = connected.ok_or_else(|| format!("cannot connect: {last}"))?;
        let mut request = Request::get(&*target.path_and_query)
            .header(HOST, target.host_header())
            .header(ACCEPT, "application/json, application/yaml;q=0.9")
            .header(USER_AGENT, "podgate-provider")
            .header(CONNECTION, "close")
            .body(Empty::<Bytes>::new())
            .map_err(|_| "the url cannot be used as a request target".to_owned())?;
        let headers = request.headers_mut();
        if let Some(validators) = validators {
            if let Some(etag) = &validators.etag {
                headers.insert(IF_NONE_MATCH, etag.clone());
            }
            if let Some(modified) = &validators.last_modified {
                headers.insert(IF_MODIFIED_SINCE, modified.clone());
            }
        }
        for (name, value) in &self.headers {
            headers.insert(name.clone(), value.clone());
        }
        match (&self.connector, target.https) {
            (Some(connector), true) => {
                let name = ServerName::try_from(target.host.to_string())
                    .map_err(|_| "the host is not a valid TLS server name".to_owned())?;
                let tls = connector
                    .connect(name, stream)
                    .await
                    .map_err(|err| format!("TLS handshake failed: {err}"))?;
                send(tls, request).await
            }
            _ => send(stream, request).await,
        }
    }

    /// One poll, within `timeout`.
    async fn fetch(&self, validators: Option<&Validators>) -> Result<Answer, String> {
        match tokio::time::timeout(self.timeout, self.walk(validators)).await {
            Ok(answer) => answer,
            Err(_) => Err(format!(
                "no complete answer within {} s",
                self.timeout.as_secs()
            )),
        }
    }

    async fn walk(&self, validators: Option<&Validators>) -> Result<Answer, String> {
        let mut target = self.target.clone();
        let mut hops = 0;
        loop {
            let Exchange { response, _driver } = self.exchange(&target, validators).await?;
            let status = response.status();
            if status == StatusCode::NOT_MODIFIED {
                return if validators.is_some_and(|validators| !validators.is_empty()) {
                    Ok(Answer::NotModified)
                } else {
                    Err("the server answered 304 to a request that was not conditional".to_owned())
                };
            }
            if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
                if hops == MAX_REDIRECTS {
                    return Err(format!("more than {MAX_REDIRECTS} redirects"));
                }
                hops += 1;
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or("a redirect without a usable Location")?;
                target = target.follow(location).map_err(str::to_owned)?;
                continue;
            }
            if status != StatusCode::OK {
                return Err(format!("the server answered {}", status.as_u16()));
            }
            return self.document(response).await.map(Answer::Document);
        }
    }

    async fn document(&self, response: http::Response<Incoming>) -> Result<Document, String> {
        let (head, mut body) = response.into_parts();
        let kind = kind_of(head.headers.get(CONTENT_TYPE))?;
        if head
            .headers
            .get(CONTENT_ENCODING)
            .is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return Err(
                "the answer is encoded (Content-Encoding); it was not asked for".to_owned(),
            );
        }
        let oversize = || format!("the answer is larger than max_bytes ({})", self.max_bytes);
        if head
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > self.max_bytes as u64)
        {
            return Err(oversize());
        }
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|err| format!("the answer broke off: {err}"))?;
            if let Ok(data) = frame.into_data() {
                if bytes.len() + data.len() > self.max_bytes {
                    return Err(oversize());
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok(Document {
            bytes,
            kind,
            validators: Validators {
                etag: head.headers.get(ETAG).cloned(),
                last_modified: head.headers.get(LAST_MODIFIED).cloned(),
            },
        })
    }
}

// ---- parsing --------------------------------------------------------------------------------

/// What the source needs to turn a document into objects.
struct Plan {
    name: Box<str>,
    tenant: Box<str>,
    format: Format,
    mapping: Mapping,
}

/// A decode error as a line and column, never the text: a type error quotes the value.
fn json_error(err: &serde_json::Error) -> String {
    format!(
        "the answer is not valid JSON (line {}, column {})",
        err.line(),
        err.column()
    )
}

fn yaml_error(err: &serde_yaml_ng::Error) -> String {
    err.location().map_or_else(
        || "the answer is not valid YAML".to_owned(),
        |at| {
            format!(
                "the answer is not valid YAML (line {}, column {})",
                at.line(),
                at.column()
            )
        },
    )
}

/// Whether `text` uses a YAML alias. A document can expand through nested aliases to a thousand
/// times its size, and a remote one is not trusted to refrain, so aliases are refused. A `*` that
/// starts a token and is followed by a name is what an alias is. It errs on the side of refusing.
fn has_yaml_alias(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(at, byte)| {
        *byte == b'*'
            && (at == 0
                || bytes[at - 1].is_ascii_whitespace()
                || matches!(bytes[at - 1], b'[' | b'{' | b','))
            && bytes.get(at + 1).is_some_and(|next| {
                !next.is_ascii_whitespace() && !matches!(next, b',' | b']' | b'}')
            })
    })
}

/// The answer as a JSON value.
fn decode(kind: Kind, bytes: &[u8]) -> Result<Value, String> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err("the answer is empty".to_owned());
    }
    match kind {
        Kind::Json => serde_json::from_slice(bytes).map_err(|err| json_error(&err)),
        Kind::Yaml => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| "the answer is not valid UTF-8".to_owned())?;
            if has_yaml_alias(text) {
                return Err("the answer uses YAML aliases, which are not accepted".to_owned());
            }
            serde_yaml_ng::from_str(text).map_err(|err| yaml_error(&err))
        }
    }
}

fn quoted(text: &str) -> String {
    format!("{:?}", text.chars().take(63).collect::<String>())
}

impl Plan {
    fn parse(&self, kind: Kind, bytes: &[u8]) -> Result<Built, String> {
        match self.format {
            Format::Podgate => self.podgate(kind, bytes),
            Format::Traefik => self.traefik(kind, bytes),
        }
    }

    /// `{apps: [...], certificates: [...]}`: each object goes to the key-value layer as the
    /// document of a key, so the tenant, the unknown-field check and the limits are its.
    fn podgate(&self, kind: Kind, bytes: &[u8]) -> Result<Built, String> {
        let Value::Object(mut top) = decode(kind, bytes)? else {
            return Err("the answer must be an object with an `apps` list".to_owned());
        };
        if top.remove("tenants").is_some() {
            warn!(
                source = %self.name,
                "ignoring the tenants of the answer: tenants come from the provider's configuration only"
            );
        }
        let unknown: Vec<String> = top
            .keys()
            .filter(|key| !matches!(key.as_str(), "apps" | "certificates"))
            .map(|key| quoted(key))
            .collect();
        if !unknown.is_empty() {
            return Err(format!(
                "unknown top-level key{} {}; the document holds `apps` and `certificates`",
                if unknown.len() == 1 { "" } else { "s" },
                unknown.join(", ")
            ));
        }
        let Some(apps) = top.remove("apps") else {
            return Err(
                "the answer has no `apps` key; write `apps: []` to declare no apps".to_owned(),
            );
        };
        let list = |value: Value, what: &str| match value {
            Value::Array(items) => Ok(items),
            _ => Err(format!("`{what}` must be a list")),
        };
        let apps = list(apps, "apps")?;
        let certificates = match top.remove("certificates") {
            Some(value) => list(value, "certificates")?,
            None => Vec::new(),
        };

        let path = &self.mapping.prefixes()[0].path;
        let mut reports: Vec<String> = Vec::new();
        let mut documents: Vec<(String, Vec<u8>)> = Vec::new();
        let mut ids: BTreeMap<String, usize> = BTreeMap::new();
        let mut named: Vec<(String, Value)> = Vec::new();
        for (index, app) in apps.into_iter().enumerate() {
            match app.get("id").and_then(Value::as_str) {
                Some(id) if app.is_object() => {
                    *ids.entry(id.to_owned()).or_default() += 1;
                    named.push((id.to_owned(), app));
                }
                _ => reports.push(format!(
                    "apps[{index}]: must be a map with a text `id`; ignored"
                )),
            }
        }
        let repeated: BTreeSet<&String> = ids
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(id, _)| id)
            .collect();
        for id in &repeated {
            reports.push(format!(
                "apps: the id {} is declared more than once; every declaration of it is ignored",
                quoted(id)
            ));
        }
        for (id, app) in named {
            if !repeated.contains(&id) {
                documents.push((format!("{path}apps/{id}"), encode(&app)));
            }
        }
        for (index, certificate) in certificates.into_iter().enumerate() {
            documents.push((
                format!("{path}certificates/certificate-{index}"),
                encode(&certificate),
            ));
        }
        let mut built = self.mapping.build(&self.name, documents);
        reports.extend(built.reports.drain(..).map(String::from));
        built.reports = reports.into_iter().map(Into::into).collect();
        Ok(built)
    }

    /// A Traefik dynamic configuration: one app, through the converter, which refuses every file
    /// reference of an answer.
    fn traefik(&self, kind: Kind, bytes: &[u8]) -> Result<Built, String> {
        if bytes.len() as u64 > traefik_file::MAX_FILE_BYTES {
            return Err(format!(
                "a Traefik document is at most {} bytes",
                traefik_file::MAX_FILE_BYTES
            ));
        }
        // The same emptiness rule as the apps list: a document that parses but names no section
        // is not an instruction to delete every route.
        let root = decode(kind, bytes)?;
        let Value::Object(sections) = &root else {
            return Err("the answer must be a Traefik configuration (a map)".to_owned());
        };
        if !sections.keys().any(|key| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "http" | "tcp" | "udp" | "tls"
            )
        }) {
            return Err(
                "the answer has none of `http`, `tcp`, `udp` or `tls`; write `http: {}` to declare nothing"
                    .to_owned(),
            );
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| "the answer is not valid UTF-8".to_owned())?;
        let converted = traefik_file::convert_inline(TRAEFIK_APP, text, Syntax::Yaml)
            .map_err(|err| format!("the Traefik document cannot be converted: {err}"))?;
        let mut built = Built::default();
        let mut problems = converted.problems.iter();
        for problem in problems.by_ref().take(MAX_REPORTS) {
            built.reports.push(format!("rejected: {problem}").into());
        }
        let more = problems.count();
        if more > 0 {
            built.reports.push(format!("and {more} more").into());
        }
        let Value::Object(mut app) = converted.app else {
            return Err("the converted configuration is not an app".to_owned());
        };
        app.insert("tenant".to_owned(), Value::String(self.tenant.to_string()));
        app.insert(
            "declared_by".to_owned(),
            Value::String(DECLARED_BY.to_owned()),
        );
        let app: App = serde_json::from_value(Value::Object(app))
            .map_err(|_| "the converted configuration is not a valid app".to_owned())?;
        built.apps.push(SourceApp {
            origin: Origin {
                source: self.name.clone(),
                object: TRAEFIK_APP.into(),
                first_seen: 0,
            },
            tenant: TenantClaim::mapped(&self.tenant),
            app,
        });
        for (index, certificate) in converted.certificates.into_iter().enumerate() {
            built.certificates.push(SourceCertificate {
                origin: Origin {
                    source: self.name.clone(),
                    object: format!("certificate-{index}").into(),
                    first_seen: 0,
                },
                tenant: TenantClaim::mapped(&self.tenant),
                certificate,
            });
        }
        Ok(built)
    }
}

fn encode(value: &Value) -> Vec<u8> {
    // Serializing a JSON value cannot fail; an empty document is then reported by the key-value
    // layer as empty.
    serde_json::to_vec(value).unwrap_or_default()
}

// ---- the loop -------------------------------------------------------------------------------

/// What was last told to the core.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Unavailable(Box<str>),
    Available {
        state: State,
        report: Option<Box<str>>,
    },
}

/// The last good document, parsed.
struct Good {
    hash: u64,
    state: State,
    report: Option<Box<str>>,
}

fn hash_of(kind: Kind, bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    kind.hash(&mut hasher);
    bytes.hash(&mut hasher);
    hasher.finish()
}

impl HttpSource {
    /// One poll. A document that parses replaces `good` and the validators; an answer of "not
    /// modified" or a document equal to the last one changes nothing; anything else is the error.
    async fn poll(
        &self,
        good: &mut Option<Good>,
        validators: &mut Option<Validators>,
    ) -> Result<(), String> {
        let asked = good.as_ref().and(validators.as_ref());
        match self.fetch(asked).await? {
            Answer::NotModified => Ok(()),
            Answer::Document(Document {
                bytes,
                kind,
                validators: fresh,
            }) => {
                let hash = hash_of(kind, &bytes);
                if good.as_ref().is_some_and(|good| good.hash == hash) {
                    *validators = Some(fresh);
                    return Ok(());
                }
                let plan = Arc::clone(&self.plan);
                let parsed = tokio::task::spawn_blocking(move || plan.parse(kind, &bytes))
                    .await
                    .map_err(|_| "the answer could not be parsed (internal error)".to_owned())??;
                let report = parsed.report_text();
                *good = Some(Good {
                    hash,
                    state: parsed.into_state(),
                    report,
                });
                *validators = Some(fresh);
                Ok(())
            }
        }
    }
}

impl Source for HttpSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let mut backoff = Backoff::new(self.poll, self.backoff_max).jittered();
        let mut good: Option<Good> = None;
        let mut validators: Option<Validators> = None;
        let mut sent: Option<Sent> = None;
        loop {
            let (observed, delay) = match self.poll(&mut good, &mut validators).await {
                Ok(()) => {
                    backoff.reset();
                    let observed = match &good {
                        Some(good) => Sent::Available {
                            state: good.state.clone(),
                            report: good.report.clone(),
                        },
                        None => Sent::Unavailable("no document has been read yet".into()),
                    };
                    (observed, self.poll)
                }
                Err(why) => {
                    warn!(
                        source = %self.name,
                        endpoint = %self.target.origin(),
                        "poll failed: {why}"
                    );
                    (Sent::Unavailable(why.into()), backoff.next_delay())
                }
            };
            if sent.as_ref() != Some(&observed) {
                let outgoing = match &observed {
                    Sent::Unavailable(why) => vec![Update::outage(&self.name, why)],
                    Sent::Available { state, report } => {
                        let mut outgoing = vec![Update {
                            source: self.name.clone(),
                            body: UpdateBody::State(state.clone()),
                        }];
                        if let Some(report) = report {
                            warn!(source = %self.name, "{report}");
                            outgoing.push(Update::outage(&self.name, report));
                        }
                        outgoing
                    }
                };
                sent = Some(observed);
                for update in outgoing {
                    if updates.send(update).await.is_err() {
                        return;
                    }
                }
            }
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = updates.closed() => return,
            }
        }
    }
}
