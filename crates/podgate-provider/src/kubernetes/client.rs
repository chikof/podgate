//! A small Kubernetes API client: list and watch of any resource kind, nothing else.
//!
//! It is generic over the resource: a type that implements [`Resource`] names its API group,
//! version and plural and carries an [`ObjectMeta`]; the [`Watcher`] then keeps a consistent view
//! of every object of that kind, the way a client-go reflector does:
//!
//! 1. `LIST` all pages and hand the objects over as [`Event::Reset`], remembering the list's
//!    `resourceVersion`.
//! 2. `WATCH` from that version with bookmarks requested. [`Event::Applied`] and
//!    [`Event::Deleted`] follow each change; a `BOOKMARK` only moves the remembered version, so a
//!    reconnect after a quiet period resumes close to now.
//! 3. A watch that the server ends resumes from the remembered version. `410 Gone`, as an HTTP
//!    status or as an `ERROR` frame, means that version is no longer kept: the watcher lists
//!    again and sends a new [`Event::Reset`], which replaces everything the consumer held.
//! 4. Any other failure sends [`Event::Outage`], waits an exponentially growing, jittered delay
//!    and tries again. The consumer keeps what it has: an unreachable API server must not delete
//!    routes.
//!
//! The client speaks HTTP/1.1 over a fresh TCP connection per request (rustls, no OpenSSL), reads
//! no more than [`MAX_BODY_BYTES`] of a list page or [`MAX_FRAME_BYTES`] of a watch frame, and
//! sends only `GET`. It authenticates with a bearer token (re-read from its file on every
//! request, because the kubelet rotates service account tokens) or a client certificate. Exec
//! plugins, auth providers, basic auth, proxies and `insecure-skip-tls-verify` are refused when
//! the configuration is read, never ignored.
//!
//! Plain `http://` servers are accepted only on a loopback address (`kubectl proxy`), so a
//! bearer token never crosses a network in clear text.

use std::collections::BTreeMap;
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ACCEPT, AUTHORIZATION, HOST, USER_AGENT};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep, timeout};
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

/// The largest list page or error body read, in bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The largest single watch frame (one object), in bytes. Kubernetes caps objects at about
/// 1.5 MiB, so a frame beyond this is a broken or hostile server.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// How many objects one list request asks for.
pub const DEFAULT_PAGE_SIZE: u32 = 500;

const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// How long a connection (TCP and TLS) may take to come up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Extra time a watch may stay silent beyond its `timeoutSeconds` before it is treated as dead
/// (a half-open connection never closes by itself).
const WATCH_GRACE: Duration = Duration::from_secs(30);

/// A watch that ends sooner than this without a single frame counts as a failure, so a server
/// that closes every watch at once cannot make the client spin.
const MIN_WATCH_LIFE: Duration = Duration::from_secs(1);

/// An API object of one kind, as the typed structs of the mappings read it.
pub trait Resource: DeserializeOwned + Send + 'static {
    /// The API group, empty for the core group.
    const GROUP: &'static str;
    /// The API version, such as `v1`.
    const VERSION: &'static str;
    /// The plural resource name used in URLs, such as `ingresses`.
    const PLURAL: &'static str;
    /// The kind, for messages: `Ingress`.
    const KIND: &'static str;
    /// Whether objects live in a namespace.
    const NAMESPACED: bool = true;

    /// The object's metadata.
    fn meta(&self) -> &ObjectMeta;
}

/// The metadata fields podgate reads; every other field is ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    /// The name, unique within its namespace.
    #[serde(default)]
    pub name: String,
    /// The namespace; absent for cluster-scoped kinds.
    #[serde(default)]
    pub namespace: Option<String>,
    /// The version of this object; opaque.
    #[serde(default)]
    pub resource_version: Option<String>,
    /// When the object was created, RFC 3339 in UTC.
    #[serde(default)]
    pub creation_timestamp: Option<String>,
    /// Annotations.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    /// Labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl ObjectMeta {
    /// The namespace, empty for a cluster-scoped object.
    #[must_use]
    pub fn namespace(&self) -> &str {
        self.namespace.as_deref().unwrap_or("")
    }

    /// `namespace/name`, or `name` for a cluster-scoped object.
    #[must_use]
    pub fn key(&self) -> String {
        match self.namespace.as_deref() {
            Some(namespace) if !namespace.is_empty() => format!("{namespace}/{}", self.name),
            _ => self.name.clone(),
        }
    }
}

/// What to list or watch: one namespace or all, optionally narrowed by a field selector.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// The namespace. `None`: all namespaces (the cluster-wide path).
    pub namespace: Option<Box<str>>,
    /// A field selector such as `type=kubernetes.io/tls`, applied by the API server.
    pub field_selector: Option<Box<str>>,
}

impl Query {
    /// Every object of the kind in every namespace.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// The objects of one namespace.
    #[must_use]
    pub fn in_namespace(namespace: &str) -> Self {
        Self {
            namespace: Some(namespace.into()),
            field_selector: None,
        }
    }

    /// The same query, narrowed by a field selector.
    #[must_use]
    pub fn with_field_selector(mut self, selector: &str) -> Self {
        self.field_selector = Some(selector.into());
        self
    }

    fn path<R: Resource>(&self) -> String {
        let mut path = if R::GROUP.is_empty() {
            format!("/api/{}", R::VERSION)
        } else {
            format!("/apis/{}/{}", R::GROUP, R::VERSION)
        };
        if let (true, Some(namespace)) = (R::NAMESPACED, &self.namespace) {
            path.push_str("/namespaces/");
            path.push_str(&encode(namespace));
        }
        path.push('/');
        path.push_str(R::PLURAL);
        path
    }

    fn url<R: Resource>(&self, params: &[(&str, &str)]) -> String {
        let mut url = self.path::<R>();
        let mut separator = '?';
        let mut push = |key: &str, value: &str| {
            url.push(separator);
            url.push_str(key);
            url.push('=');
            url.push_str(&encode(value));
            separator = '&';
        };
        for (key, value) in params {
            push(key, value);
        }
        if let Some(selector) = &self.field_selector {
            push("fieldSelector", selector);
        }
        url
    }
}

/// Percent-encodes everything but unreserved characters.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A client that cannot be built, or a request that failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The kubeconfig or the in-cluster environment cannot be used. Found at start-up.
    #[error("{0}")]
    Config(Box<str>),
    /// The connection could not be made or broke.
    #[error("{0}")]
    Connect(Box<str>),
    /// The API server answered with an error status.
    #[error("{status}: {message}")]
    Status {
        /// The HTTP status code.
        status: u16,
        /// The `message` of the Status object, or a short reason.
        message: Box<str>,
    },
    /// The resource version asked for is no longer kept (`410 Gone`): list again.
    #[error("the resource version is gone: {0}")]
    Gone(Box<str>),
    /// The answer is not what the API promises.
    #[error("{0}")]
    Decode(Box<str>),
    /// Nothing happened within the allowed time.
    #[error("timed out {0}")]
    Timeout(&'static str),
}

/// The credentials a request carries.
#[derive(Clone)]
enum Auth {
    None,
    Token(Box<str>),
    TokenFile(PathBuf),
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Token(_) => f.write_str("Token([redacted])"),
            Self::TokenFile(path) => write!(f, "TokenFile({})", path.display()),
        }
    }
}

/// How to reach the API server, from a kubeconfig or the pod's service account.
#[derive(Clone)]
pub struct ClientConfig {
    server: Uri,
    host: Box<str>,
    port: u16,
    tls: Option<Arc<rustls::ClientConfig>>,
    auth: Auth,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("server", &self.server.to_string())
            .field("tls", &self.tls.is_some())
            .field("auth", &self.auth)
            .finish()
    }
}

impl ClientConfig {
    /// The pod's service account: `KUBERNETES_SERVICE_HOST` and `_PORT`, the CA and the token
    /// under `/var/run/secrets/kubernetes.io/serviceaccount`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Config`] when the environment or the files are missing.
    pub fn in_cluster() -> Result<Self, ClientError> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
            config_error(
                "not running in a cluster: KUBERNETES_SERVICE_HOST is not set; set `kubeconfig`",
            )
        })?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_owned());
        let server = if host.contains(':') && !host.starts_with('[') {
            format!("https://[{host}]:{port}")
        } else {
            format!("https://{host}:{port}")
        };
        let dir = Path::new(SERVICE_ACCOUNT_DIR);
        let ca = read(&dir.join("ca.crt"))?;
        let token_file = dir.join("token");
        // Fail now, not at the first request, when the token is not mounted.
        read(&token_file)?;
        Self::build(&server, &[ca], None, Auth::TokenFile(token_file))
    }

    /// The cluster and user of a kubeconfig file.
    ///
    /// # Errors
    ///
    /// [`ClientError::Config`] when the file cannot be read or parsed, the context is missing,
    /// or it uses a setting this client refuses (see the module documentation).
    pub fn from_kubeconfig(path: &Path, context: Option<&str>) -> Result<Self, ClientError> {
        let text = read(path)?;
        let file: Kubeconfig = serde_yaml_ng::from_slice(&text)
            .map_err(|err| config_error(format!("{}: {err}", path.display())))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let wanted = context.or(file.current_context.as_deref()).ok_or_else(|| {
            config_error(format!(
                "{}: no current-context; set `context`",
                path.display()
            ))
        })?;
        let named = file
            .contexts
            .iter()
            .find(|candidate| candidate.name == wanted)
            .ok_or_else(|| config_error(format!("{}: no context {wanted:?}", path.display())))?;
        let cluster = file
            .clusters
            .iter()
            .find(|candidate| candidate.name == named.context.cluster)
            .ok_or_else(|| {
                config_error(format!(
                    "{}: context {wanted:?} names no known cluster",
                    path.display()
                ))
            })?
            .cluster
            .clone();
        let user = match &named.context.user {
            Some(user) => file
                .users
                .iter()
                .find(|candidate| &candidate.name == user)
                .ok_or_else(|| {
                    config_error(format!(
                        "{}: context {wanted:?} names no known user",
                        path.display()
                    ))
                })?
                .user
                .clone(),
            None => KubeUser::default(),
        };
        refuse_unsupported(&cluster, &user)?;
        let server = cluster.server.as_deref().ok_or_else(|| {
            config_error(format!("{}: the cluster has no server", path.display()))
        })?;
        let mut cas = Vec::new();
        if let Some(data) = &cluster.certificate_authority_data {
            cas.push(decode_base64("certificate-authority-data", data)?);
        }
        if let Some(file) = &cluster.certificate_authority {
            cas.push(read(&resolve(base, file))?);
        }
        let client_cert = match (
            (&user.client_certificate_data, &user.client_certificate),
            (&user.client_key_data, &user.client_key),
        ) {
            ((None, None), (None, None)) => None,
            (cert, key) => Some((
                from_data_or_file(base, "client-certificate", cert)?,
                from_data_or_file(base, "client-key", key)?,
            )),
        };
        let auth = match (&user.token, &user.token_file) {
            (Some(token), None) => Auth::Token(token.trim().into()),
            (None, Some(file)) => {
                let file = resolve(base, file);
                read(&file)?;
                Auth::TokenFile(file)
            }
            (None, None) => Auth::None,
            (Some(_), Some(_)) => {
                return Err(config_error("the user sets both token and tokenFile"));
            }
        };
        Self::build(server, &cas, client_cert, auth)
    }

    fn build(
        server: &str,
        cas: &[Vec<u8>],
        client_cert: Option<(Vec<u8>, Vec<u8>)>,
        auth: Auth,
    ) -> Result<Self, ClientError> {
        let uri: Uri = server
            .parse()
            .map_err(|err| config_error(format!("server {server:?} is not a URL: {err}")))?;
        let host = uri
            .host()
            .ok_or_else(|| config_error(format!("server {server:?} has no host")))?
            .trim_matches(['[', ']'])
            .to_owned();
        let tls = match uri.scheme_str() {
            Some("https") => Some(Arc::new(tls_config(cas, client_cert)?)),
            Some("http") if is_loopback(&host) => None,
            Some("http") => {
                return Err(config_error(format!(
                    "server {server:?} is plain http on a non-loopback address; the bearer token would cross the network in clear text"
                )));
            }
            _ => {
                return Err(config_error(format!(
                    "server {server:?} must be an https:// URL"
                )));
            }
        };
        let port = uri
            .port_u16()
            .unwrap_or(if tls.is_some() { 443 } else { 80 });
        Ok(Self {
            server: uri,
            host: host.into(),
            port,
            tls,
            auth,
        })
    }
}

fn config_error(message: impl fmt::Display) -> ClientError {
    ClientError::Config(message.to_string().into())
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn read(path: &Path) -> Result<Vec<u8>, ClientError> {
    std::fs::read(path)
        .map_err(|err| config_error(format!("cannot read {}: {err}", path.display())))
}

fn resolve(base: &Path, file: &str) -> PathBuf {
    let path = Path::new(file);
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

fn decode_base64(field: &str, data: &str) -> Result<Vec<u8>, ClientError> {
    STANDARD
        .decode(data.trim())
        .map_err(|_| config_error(format!("{field} is not valid base64")))
}

fn from_data_or_file(
    base: &Path,
    field: &str,
    (data, file): (&Option<String>, &Option<String>),
) -> Result<Vec<u8>, ClientError> {
    match (data, file) {
        (Some(data), None) => decode_base64(&format!("{field}-data"), data),
        (None, Some(file)) => read(&resolve(base, file)),
        _ => Err(config_error(format!(
            "set exactly one of {field} and {field}-data, and both a certificate and a key"
        ))),
    }
}

fn tls_config(
    cas: &[Vec<u8>],
    client_cert: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<rustls::ClientConfig, ClientError> {
    let mut roots = rustls::RootCertStore::empty();
    for pem in cas {
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|err| config_error(format!("certificate authority: {err}")))?;
            roots
                .add(cert)
                .map_err(|err| config_error(format!("certificate authority: {err}")))?;
        }
    }
    if roots.is_empty() {
        return Err(config_error(
            "the cluster has no certificate authority (certificate-authority or -data); the API server's certificate cannot be verified without one",
        ));
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| config_error(format!("TLS: {err}")))?
    .with_root_certificates(roots);
    match client_cert {
        None => Ok(builder.with_no_client_auth()),
        Some((cert, key)) => {
            let chain = CertificateDer::pem_slice_iter(&cert)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| config_error(format!("client certificate: {err}")))?;
            let key = PrivateKeyDer::from_pem_slice(&key)
                .map_err(|err| config_error(format!("client key: {err}")))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|err| config_error(format!("client certificate: {err}")))
        }
    }
}

fn refuse_unsupported(cluster: &KubeCluster, user: &KubeUser) -> Result<(), ClientError> {
    let refusals = [
        (
            cluster.insecure_skip_tls_verify == Some(true),
            "insecure-skip-tls-verify (the API server's certificate is always verified)",
        ),
        (cluster.proxy_url.is_some(), "proxy-url"),
        (cluster.tls_server_name.is_some(), "tls-server-name"),
        (
            user.exec.is_some(),
            "exec credential plugins (use a service account token or a client certificate)",
        ),
        (user.auth_provider.is_some(), "auth-provider"),
        (
            user.username.is_some() || user.password.is_some(),
            "basic authentication",
        ),
    ];
    match refusals.iter().find(|(present, _)| *present) {
        Some((_, what)) => Err(config_error(format!(
            "the kubeconfig uses {what}, which is not supported"
        ))),
        None => Ok(()),
    }
}

#[derive(Deserialize)]
struct Kubeconfig {
    #[serde(rename = "current-context")]
    current_context: Option<String>,
    #[serde(default)]
    clusters: Vec<NamedCluster>,
    #[serde(default)]
    users: Vec<NamedUser>,
    #[serde(default)]
    contexts: Vec<NamedContext>,
}

#[derive(Deserialize)]
struct NamedCluster {
    name: String,
    cluster: KubeCluster,
}

#[derive(Deserialize)]
struct NamedUser {
    name: String,
    #[serde(default)]
    user: KubeUser,
}

#[derive(Deserialize)]
struct NamedContext {
    name: String,
    context: KubeContext,
}

#[derive(Deserialize)]
struct KubeContext {
    cluster: String,
    user: Option<String>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
struct KubeCluster {
    server: Option<String>,
    certificate_authority: Option<String>,
    certificate_authority_data: Option<String>,
    insecure_skip_tls_verify: Option<bool>,
    proxy_url: Option<String>,
    tls_server_name: Option<String>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "kebab-case")]
struct KubeUser {
    token: Option<String>,
    #[serde(rename = "tokenFile")]
    token_file: Option<String>,
    client_certificate: Option<String>,
    client_certificate_data: Option<String>,
    client_key: Option<String>,
    client_key_data: Option<String>,
    exec: Option<Value>,
    auth_provider: Option<Value>,
    username: Option<String>,
    password: Option<String>,
}

/// Timing and sizing of the client. The defaults suit a real cluster; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// The `timeoutSeconds` of a watch: the server ends it after this long and the watcher
    /// resumes. Kubernetes' own default is 30 to 60 minutes; shorter keeps dead connections
    /// from lingering.
    pub watch_timeout: Duration,
    /// The longest a list page may take, headers and body.
    pub request_timeout: Duration,
    /// The first retry delay after a failure; doubles up to `backoff_max`.
    pub backoff_min: Duration,
    /// The longest retry delay.
    pub backoff_max: Duration,
    /// Objects per list request.
    pub page_size: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            watch_timeout: Duration::from_secs(240),
            request_timeout: Duration::from_secs(60),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

/// A connection to one API server. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ApiClient {
    config: Arc<ClientConfig>,
    tuning: Tuning,
}

/// One page-merged list answer.
#[derive(Debug)]
pub struct Listing<R> {
    /// The list's `resourceVersion`: where a watch continues.
    pub resource_version: Box<str>,
    /// Every object.
    pub items: Vec<R>,
}

#[derive(Deserialize)]
struct ListBody<R> {
    #[serde(default)]
    metadata: ListMeta,
    #[serde(default = "Vec::new")]
    items: Vec<R>,
}

#[derive(Deserialize, Default)]
struct ListMeta {
    #[serde(rename = "resourceVersion")]
    resource_version: Option<String>,
    #[serde(rename = "continue")]
    continue_token: Option<String>,
}

impl ApiClient {
    /// A client for `config` with `tuning`.
    #[must_use]
    pub fn new(config: ClientConfig, tuning: Tuning) -> Self {
        Self {
            config: Arc::new(config),
            tuning,
        }
    }

    /// The tuning in force.
    #[must_use]
    pub fn tuning(&self) -> Tuning {
        self.tuning
    }

    /// Lists every object of `R` matching `query`, following `continue` tokens.
    ///
    /// # Errors
    ///
    /// [`ClientError`]; [`ClientError::Gone`] when a continue token expired mid-list.
    pub async fn list<R: Resource>(&self, query: &Query) -> Result<Listing<R>, ClientError> {
        let limit = self.tuning.page_size.to_string();
        let mut items = Vec::new();
        let mut version: Option<Box<str>> = None;
        let mut token: Option<String> = None;
        loop {
            let mut params = vec![("limit", limit.as_str())];
            if let Some(token) = &token {
                params.push(("continue", token));
            }
            let url = query.url::<R>(&params);
            let page: ListBody<R> = timeout(self.tuning.request_timeout, async {
                let response = self.get(&url).await?;
                let body = read_body(response, R::KIND).await?;
                serde_json::from_slice(&body).map_err(|err| {
                    ClientError::Decode(format!("the {} list is not valid: {err}", R::KIND).into())
                })
            })
            .await
            .map_err(|_| ClientError::Timeout("listing"))??;
            items.extend(page.items);
            // Every page of one list reports the same version; the first one is the snapshot.
            if version.is_none() {
                version = page.metadata.resource_version.map(Into::into);
            }
            match page
                .metadata
                .continue_token
                .filter(|token| !token.is_empty())
            {
                Some(next) => token = Some(next),
                None => break,
            }
        }
        let resource_version = version.ok_or_else(|| {
            ClientError::Decode(format!("the {} list carries no resourceVersion", R::KIND).into())
        })?;
        Ok(Listing {
            resource_version,
            items,
        })
    }

    /// One `GET`. The connection setup (TCP, the TLS handshake, the HTTP handshake) carries a
    /// few KiB of state, so it is boxed here once instead of in every caller's future.
    async fn get(&self, path_and_query: &str) -> Result<Response<Incoming>, ClientError> {
        Box::pin(self.connect_and_get(path_and_query)).await
    }

    async fn connect_and_get(
        &self,
        path_and_query: &str,
    ) -> Result<Response<Incoming>, ClientError> {
        let config = &self.config;
        let tcp = timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((&*config.host, config.port)),
        )
        .await
        .map_err(|_| ClientError::Timeout("connecting"))?
        .map_err(|err| {
            ClientError::Connect(
                format!("cannot connect to {}:{}: {err}", config.host, config.port).into(),
            )
        })?;
        // Latency matters more than packet count for these small requests.
        let _ = tcp.set_nodelay(true);
        let mut request = Request::get(path_and_query)
            .header(HOST, authority(config))
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, "podgate-provider");
        match &config.auth {
            Auth::None => {}
            Auth::Token(token) => request = request.header(AUTHORIZATION, bearer(token)?),
            Auth::TokenFile(path) => {
                let token = std::fs::read_to_string(path).map_err(|err| {
                    ClientError::Connect(
                        format!("cannot read the token {}: {err}", path.display()).into(),
                    )
                })?;
                request = request.header(AUTHORIZATION, bearer(token.trim())?);
            }
        }
        let request = request
            .body(Empty::<Bytes>::new())
            .map_err(|err| ClientError::Decode(format!("bad request: {err}").into()))?;
        let response = match &config.tls {
            Some(tls) => {
                let name = ServerName::try_from(config.host.to_string()).map_err(|err| {
                    ClientError::Connect(format!("bad server name {}: {err}", config.host).into())
                })?;
                let stream = timeout(
                    CONNECT_TIMEOUT,
                    TlsConnector::from(Arc::clone(tls)).connect(name, tcp),
                )
                .await
                .map_err(|_| ClientError::Timeout("in the TLS handshake"))?
                .map_err(|err| {
                    ClientError::Connect(format!("TLS to the API server failed: {err}").into())
                })?;
                send(TokioIo::new(stream), request).await?
            }
            None => send(TokioIo::new(tcp), request).await?,
        };
        Ok(response)
    }

    /// Opens a watch of `R` from `resource_version`.
    async fn open_watch<R: Resource>(
        &self,
        query: &Query,
        resource_version: &str,
    ) -> Result<FrameStream, ClientError> {
        let seconds = self.tuning.watch_timeout.as_secs().max(1).to_string();
        let url = query.url::<R>(&[
            ("watch", "true"),
            ("resourceVersion", resource_version),
            ("allowWatchBookmarks", "true"),
            ("timeoutSeconds", &seconds),
        ]);
        let response = timeout(self.tuning.request_timeout, self.get(&url))
            .await
            .map_err(|_| ClientError::Timeout("opening the watch"))??;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error(status, response, R::KIND).await);
        }
        Ok(FrameStream {
            body: response.into_body(),
            buffer: Vec::new(),
            start: 0,
            idle: self.tuning.watch_timeout + WATCH_GRACE,
        })
    }
}

fn authority(config: &ClientConfig) -> String {
    let host = if config.host.contains(':') {
        format!("[{}]", config.host)
    } else {
        config.host.to_string()
    };
    format!("{host}:{}", config.port)
}

fn bearer(token: &str) -> Result<hyper::header::HeaderValue, ClientError> {
    let mut value = hyper::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| ClientError::Connect("the bearer token is not a valid header value".into()))?;
    value.set_sensitive(true);
    Ok(value)
}

async fn send<T>(
    io: TokioIo<T>,
    request: Request<Empty<Bytes>>,
) -> Result<Response<Incoming>, ClientError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|err| ClientError::Connect(format!("HTTP handshake failed: {err}").into()))?;
    // The connection task ends with the response body or the sender, whichever comes last.
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            debug!(error = %err, "API server connection ended");
        }
    });
    let response = sender
        .send_request(request)
        .await
        .map_err(|err| ClientError::Connect(format!("request failed: {err}").into()))?;
    // The sender must outlive the body read only through the connection task; dropping it here
    // is fine: hyper keeps the connection open for the response body.
    drop(sender);
    Ok(response)
}

async fn read_body(response: Response<Incoming>, kind: &str) -> Result<Bytes, ClientError> {
    let status = response.status();
    if !status.is_success() {
        return Err(status_error(status, response, kind).await);
    }
    Limited::new(response.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|err| {
            ClientError::Connect(format!("reading the {kind} answer failed: {err}").into())
        })
}

async fn status_error(status: StatusCode, response: Response<Incoming>, kind: &str) -> ClientError {
    let body = Limited::new(response.into_body(), 64 * 1024)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let message: Box<str> = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("{kind} request refused"))
        .into();
    if status == StatusCode::GONE {
        ClientError::Gone(message)
    } else {
        ClientError::Status {
            status: status.as_u16(),
            message,
        }
    }
}

/// What the server sent on a watch.
enum Frame {
    Applied(Value),
    Deleted(Value),
    Bookmark(Box<str>),
}

struct FrameStream {
    body: Incoming,
    buffer: Vec<u8>,
    start: usize,
    idle: Duration,
}

impl FrameStream {
    /// The next frame, or `None` when the server ended the watch.
    async fn next(&mut self, kind: &str) -> Result<Option<Frame>, ClientError> {
        loop {
            if let Some(line) = self.take_line()? {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                return parse_frame(&line, kind).map(Some);
            }
            let frame = timeout(self.idle, self.body.frame())
                .await
                .map_err(|_| ClientError::Timeout("waiting for a watch frame"))?;
            match frame {
                None => return Ok(None),
                Some(Err(err)) => {
                    return Err(ClientError::Connect(
                        format!("the {kind} watch broke: {err}").into(),
                    ));
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if self.buffer.len() - self.start + data.len() > MAX_FRAME_BYTES {
                            return Err(ClientError::Decode(
                                format!("a {kind} watch frame exceeds {MAX_FRAME_BYTES} bytes")
                                    .into(),
                            ));
                        }
                        self.buffer.extend_from_slice(&data);
                    }
                }
            }
        }
    }

    fn take_line(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        let pending = &self.buffer[self.start..];
        let Some(end) = pending.iter().position(|byte| *byte == b'\n') else {
            if self.start > 0 {
                self.buffer.drain(..self.start);
                self.start = 0;
            }
            return Ok(None);
        };
        let line = pending[..end].to_vec();
        self.start += end + 1;
        if self.start == self.buffer.len() {
            self.buffer.clear();
            self.start = 0;
        }
        Ok(Some(line))
    }
}

fn parse_frame(line: &[u8], kind: &str) -> Result<Frame, ClientError> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(rename = "type")]
        kind: String,
        object: Value,
    }
    let raw: Raw = serde_json::from_slice(line).map_err(|err| {
        ClientError::Decode(format!("a {kind} watch frame is not valid: {err}").into())
    })?;
    match raw.kind.as_str() {
        "ADDED" | "MODIFIED" => Ok(Frame::Applied(raw.object)),
        "DELETED" => Ok(Frame::Deleted(raw.object)),
        "BOOKMARK" => raw
            .object
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .map(|version| Frame::Bookmark(version.into()))
            .ok_or_else(|| {
                ClientError::Decode(format!("a {kind} bookmark has no resourceVersion").into())
            }),
        "ERROR" => {
            let code = raw.object.get("code").and_then(Value::as_u64).unwrap_or(0);
            let message: Box<str> = raw
                .object
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("watch error")
                .into();
            if code == 410 {
                Err(ClientError::Gone(message))
            } else {
                Err(ClientError::Status {
                    status: u16::try_from(code).unwrap_or(500),
                    message,
                })
            }
        }
        other => Err(ClientError::Decode(
            format!("a {kind} watch frame has the unknown type {other:?}").into(),
        )),
    }
}

/// What a [`Watcher`] tells its consumer.
#[derive(Debug)]
pub enum Event<R> {
    /// The complete current set, after a list. Replaces everything the consumer holds.
    Reset(Vec<R>),
    /// An object was added or changed.
    Applied(R),
    /// An object was deleted (its last known state).
    Deleted(R),
    /// The API server cannot be used; the watcher retries on its own. Keep what you have.
    Outage(Box<str>),
}

/// The delay between retries: doubles from a minimum to a maximum, with up to a quarter of
/// jitter so many watchers do not retry in step.
#[derive(Debug)]
struct Backoff {
    min: Duration,
    max: Duration,
    failures: u32,
}

impl Backoff {
    fn next(&mut self) -> Duration {
        let shift = self.failures.min(16);
        self.failures = self.failures.saturating_add(1);
        let base = self.min.saturating_mul(1 << shift).min(self.max);
        // `RandomState` is randomly keyed per instance: enough jitter without a new dependency.
        let random = RandomState::new().hash_one(self.failures);
        let spread = base.as_millis().max(4) as u64 / 4;
        base + Duration::from_millis(random % spread)
    }

    fn reset(&mut self) {
        self.failures = 0;
    }
}

enum Phase {
    /// The next call lists.
    List,
    /// The next call reads the watch, opening it first when `stream` is `None`.
    Watch {
        resource_version: Box<str>,
        stream: Option<(FrameStream, Instant, bool)>,
    },
}

/// Keeps one resource kind in sync; see the module documentation.
pub struct Watcher<R: Resource> {
    client: ApiClient,
    query: Query,
    phase: Phase,
    backoff: Backoff,
    wait: Option<Duration>,
    marker: std::marker::PhantomData<fn() -> R>,
}

impl<R: Resource> fmt::Debug for Watcher<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Watcher")
            .field("kind", &R::KIND)
            .field("query", &self.query)
            .finish_non_exhaustive()
    }
}

impl<R: Resource> Watcher<R> {
    /// A watcher of `R` objects selected by `query`.
    #[must_use]
    pub fn new(client: ApiClient, query: Query) -> Self {
        let tuning = client.tuning();
        Self {
            client,
            query,
            phase: Phase::List,
            backoff: Backoff {
                min: tuning.backoff_min,
                max: tuning.backoff_max,
                failures: 0,
            },
            wait: None,
            marker: std::marker::PhantomData,
        }
    }

    /// The next event. Waits out the retry delay of the previous failure first. Never returns
    /// while everything is quiet, and never gives up: failures come back as [`Event::Outage`]
    /// and the next call tries again.
    pub async fn next(&mut self) -> Event<R> {
        loop {
            if let Some(delay) = self.wait.take() {
                sleep(delay).await;
            }
            match std::mem::replace(&mut self.phase, Phase::List) {
                Phase::List => match self.client.list::<R>(&self.query).await {
                    Ok(listing) => {
                        self.backoff.reset();
                        self.phase = Phase::Watch {
                            resource_version: listing.resource_version,
                            stream: None,
                        };
                        return Event::Reset(listing.items);
                    }
                    Err(err) => return self.fail(&err, Phase::List),
                },
                Phase::Watch {
                    resource_version,
                    stream,
                } => {
                    let (mut stream, opened, got) = match stream {
                        Some(open) => open,
                        None => match self
                            .client
                            .open_watch::<R>(&self.query, &resource_version)
                            .await
                        {
                            Ok(stream) => (stream, Instant::now(), false),
                            Err(ClientError::Gone(why)) => {
                                self.relist(&why);
                                continue;
                            }
                            Err(err) => {
                                return self.fail(
                                    &err,
                                    Phase::Watch {
                                        resource_version,
                                        stream: None,
                                    },
                                );
                            }
                        },
                    };
                    match stream.next(R::KIND).await {
                        Ok(Some(Frame::Bookmark(version))) => {
                            self.phase = Phase::Watch {
                                resource_version: version,
                                stream: Some((stream, opened, true)),
                            };
                        }
                        Ok(Some(frame)) => {
                            let (value, deleted) = match frame {
                                Frame::Applied(value) => (value, false),
                                Frame::Deleted(value) => (value, true),
                                Frame::Bookmark(_) => {
                                    // Handled above; kept for exhaustiveness without a panic.
                                    self.phase = Phase::Watch {
                                        resource_version,
                                        stream: Some((stream, opened, true)),
                                    };
                                    continue;
                                }
                            };
                            let object: R = match serde_json::from_value(value) {
                                Ok(object) => object,
                                Err(err) => {
                                    let err = ClientError::Decode(
                                        format!("a {} object cannot be read: {err}", R::KIND)
                                            .into(),
                                    );
                                    return self.fail(&err, Phase::List);
                                }
                            };
                            let version = object
                                .meta()
                                .resource_version
                                .as_deref()
                                .map_or(resource_version, Into::into);
                            self.backoff.reset();
                            self.phase = Phase::Watch {
                                resource_version: version,
                                stream: Some((stream, opened, true)),
                            };
                            return if deleted {
                                Event::Deleted(object)
                            } else {
                                Event::Applied(object)
                            };
                        }
                        Ok(None) => {
                            // The server ended the watch (its `timeoutSeconds`): resume.
                            if !got && opened.elapsed() < MIN_WATCH_LIFE {
                                self.wait = Some(self.backoff.next());
                            }
                            self.phase = Phase::Watch {
                                resource_version,
                                stream: None,
                            };
                        }
                        Err(ClientError::Gone(why)) => self.relist(&why),
                        Err(err @ (ClientError::Connect(_) | ClientError::Timeout(_))) => {
                            // A connection that breaks after it was up is routine (a load
                            // balancer, an API server restart): resume quietly. If the reconnect
                            // fails too, that is an outage and is reported as one.
                            debug!(kind = R::KIND, error = %err, "the watch ended abnormally; resuming");
                            self.wait = Some(self.backoff.next());
                            self.phase = Phase::Watch {
                                resource_version,
                                stream: None,
                            };
                        }
                        Err(err) => {
                            let phase = Phase::Watch {
                                resource_version,
                                stream: None,
                            };
                            return self.fail(&err, phase);
                        }
                    }
                }
            }
        }
    }

    fn relist(&mut self, why: &str) {
        info!(
            kind = R::KIND,
            reason = why,
            "the watch version expired; listing again"
        );
        self.phase = Phase::List;
        // Rare, but a server that answers 410 to every list would otherwise spin.
        self.wait = Some(self.backoff.next().min(self.client.tuning().backoff_min));
    }

    fn fail(&mut self, err: &ClientError, resume: Phase) -> Event<R> {
        self.phase = match err {
            // An expired list continue token or watch version: start over.
            ClientError::Gone(_) => Phase::List,
            _ => resume,
        };
        self.wait = Some(self.backoff.next());
        Event::Outage(format!("cannot watch {}: {err}", R::PLURAL).into())
    }
}

/// The objects of one query, kept current by applying a [`Watcher`]'s events.
#[derive(Debug)]
pub struct Store<R> {
    items: BTreeMap<(Box<str>, Box<str>), R>,
    synced: bool,
}

impl<R> Default for Store<R> {
    fn default() -> Self {
        Self {
            items: BTreeMap::new(),
            synced: false,
        }
    }
}

impl<R: Resource> Store<R> {
    /// An empty store that has not listed yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the first list has arrived.
    #[must_use]
    pub fn is_synced(&self) -> bool {
        self.synced
    }

    /// Applies one event. Returns whether the store's content may have changed; an
    /// [`Event::Outage`] changes nothing.
    pub fn apply(&mut self, event: Event<R>) -> bool {
        match event {
            Event::Reset(items) => {
                self.items = items
                    .into_iter()
                    .map(|item| (key_of(&item), item))
                    .collect();
                self.synced = true;
                true
            }
            Event::Applied(item) => {
                self.items.insert(key_of(&item), item);
                true
            }
            Event::Deleted(item) => self.items.remove(&key_of(&item)).is_some(),
            Event::Outage(_) => false,
        }
    }

    /// The object `name` in `namespace`.
    #[must_use]
    pub fn get(&self, namespace: &str, name: &str) -> Option<&R> {
        self.items.get(&(namespace.into(), name.into()))
    }

    /// Every object, ordered by namespace and name.
    pub fn values(&self) -> impl Iterator<Item = &R> {
        self.items.values()
    }

    /// How many objects the store holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the store holds no object.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

fn key_of<R: Resource>(item: &R) -> (Box<str>, Box<str>) {
    let meta = item.meta();
    (meta.namespace().into(), meta.name.as_str().into())
}
