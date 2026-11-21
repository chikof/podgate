//! The `fastcgi` service: runs PHP (or any FastCGI application) through a PHP-FPM socket the
//! operator declared. Full reference: `docs/ref/svc-fastcgi.md`.
//!
//! ```json
//! { "name": "app", "type": "fastcgi", "upstream": "php", "index": "index.php",
//!   "split_path_info": true, "try_files": ["{path}", "{path}/index.php", "/index.php"],
//!   "env": { "APP_ENV": "production" } }
//! ```
//!
//! `upstream` is a name, never an address. The operator declares, per tenant, where each
//! PHP-FPM pool listens and which directory holds its code in `FASTCGI_FILE` (see [`roots`]); a
//! service can name only an entry of its own tenant (`unknown_fastcgi_upstream` otherwise), so a
//! snapshot cannot point a tenant at another tenant's pool or code.
//!
//! The script is never taken from the request. The normalized request path is only a key: each
//! `try_files` candidate is opened relative to the operator's root handle (no `..`, no symlink
//! out, the rules of `static`), and only a regular file whose name ends in one of `extensions`
//! (`.php` by default) runs. `SCRIPT_FILENAME` is that file's resolved path, `PATH_INFO` is what
//! followed the script in the URL, and no other file is ever handed to the application.
//!
//! A fastcgi service has no server: [`super::NO_SERVER`] stands in for the address a balancer
//! would pick, and the proxy answers through [`serve`].

mod params;
mod pool;
mod protocol;
mod response;
mod roots;

use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, EXPECT, HOST, TRANSFER_ENCODING};
use http::{Method, StatusCode, Version};
use pingora::ErrorType::InternalError;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::{ProxyHttp, Session};
use pingora::{BError, Error};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::timeout;

use self::params::{Cgi, Script};
use self::pool::{Conn, PoolError, Stream};
use self::protocol::Record;
use self::response::HeadParser;
use self::roots::Upstream;
use super::state::{Lease, ServerState};
use super::static_files::roots::{Kind, OpenError, Opened, RelPath};
use crate::budget::{Budgets, BufferGuard, TenantBudget};
use crate::client_ip::Proto;
use crate::compile::Invalid as CompileInvalid;
use crate::error::AppError;
use crate::middleware;
use crate::proxy::{Ctx, Gateway};
use crate::respond;
use crate::router::path;
use podgate_model::Declared;

pub use roots::{FastcgiRoots, LoadError, TenantFastcgi};

/// Largest request body a service accepts unless its `max_request_body_bytes` says otherwise.
const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 8 << 20;

/// Bytes read from the client and from the application at a time.
const CHUNK: u64 = 64 * 1024;

/// Buffer bytes a request in flight charges to its tenant: one request chunk and one response
/// chunk. A body that is buffered (chunked, no length) is charged on top, as it grows.
pub(super) const RESERVATION: u64 = 2 * CHUNK;

/// How long a client has to send a request body that is buffered.
const BODY_DEADLINE: Duration = Duration::from_secs(30);

/// Most bytes of `FCGI_STDERR` one request logs.
const STDERR_LOG_BYTES: usize = 4096;

/// Most `try_files`, `extensions` and `deny` entries a service lists.
const MAX_LIST: usize = 16;

/// The configuration of a `fastcgi` service.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The name of an upstream the operator declared for the tenant in `FASTCGI_FILE`.
    upstream: String,
    /// The script a directory runs; a plain file name that ends in one of `extensions`. Default
    /// `index.php`.
    #[serde(default)]
    index: Option<String>,
    /// Splits `/app.php/extra/path` into the script `/app.php` and `PATH_INFO` `/extra/path`.
    /// Default `true`.
    #[serde(default)]
    split_path_info: Option<bool>,
    /// Path templates tried in order (`{path}` is the request path); a trailing status code
    /// (`"404"`) is answered when none runs. Default `["{path}", "{path}/<index>", "/<index>"]`.
    #[serde(default)]
    try_files: Option<Vec<String>>,
    /// File name endings that may run. Default `[".php"]`.
    #[serde(default)]
    extensions: Option<Vec<String>>,
    /// Paths under the root that never run, however a request names them.
    #[serde(default)]
    deny: Option<Vec<String>>,
    /// Extra environment for the application: names `^[A-Z][A-Z0-9_]{0,63}$` that podgate and PHP
    /// do not already decide.
    #[serde(default)]
    env: Option<BTreeMap<String, String>>,
    /// Largest request body, in bytes. Default 8 MiB.
    #[serde(default)]
    max_request_body_bytes: Option<u64>,
}

/// A compiled `fastcgi` service.
#[derive(Debug)]
pub struct FastcgiSite {
    upstream: Arc<Upstream>,
    index: Box<str>,
    try_files: Box<[Box<str>]>,
    split_path_info: bool,
    extensions: Box<[Box<str>]>,
    deny: Box<[Box<str>]>,
    env: Box<[(Box<str>, Box<str>)]>,
    max_request_body_bytes: u64,
    state: Arc<ServerState>,
}

/// What explain and the overview say about a `fastcgi` service.
#[derive(Debug, Serialize)]
pub struct Summary<'a> {
    /// The upstream's name.
    pub upstream: &'a str,
    /// The script a directory runs.
    pub index: &'a str,
}

fn invalid(message: impl Into<String>) -> CompileInvalid {
    CompileInvalid::new("invalid_service", format!("fastcgi: {}", message.into()))
}

/// A name that is one path segment.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && !matches!(name, "." | "..") && !name.contains(['/', '\\', '\0'])
}

/// A template is a path (`/index.php`) or starts with `{path}`, and has no other placeholder.
fn template_is_valid(template: &str) -> bool {
    if !(template.starts_with('/') || template.starts_with("{path}")) {
        return false;
    }
    !template
        .replace("{path}", "")
        .contains(['{', '}', '\\', '\0'])
}

fn allows(extensions: &[Box<str>], name: &str) -> bool {
    extensions
        .iter()
        .any(|extension| name.len() > extension.len() && name.ends_with(&**extension))
}

fn denied(deny: &[Box<str>], rel: &str) -> bool {
    deny.iter().any(|prefix| {
        rel == &**prefix
            || rel
                .strip_prefix(&**prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn decode_path_info(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let hex = |at: usize| {
                bytes
                    .get(at)
                    .and_then(|digit| char::from(*digit).to_digit(16))
                    .and_then(|digit| u8::try_from(digit).ok())
            };
            out.push(hex(index + 1)? << 4 | hex(index + 2)?);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out)
        .ok()
        .filter(|decoded| !decoded.contains('\0'))
}

/// Why a script lookup could not finish.
#[derive(Debug, PartialEq, Eq)]
struct Exhausted;

impl FastcgiSite {
    /// Compiles one declared service against the upstreams of its app's tenant.
    pub(super) fn compile(
        declared: &Declared,
        upstreams: Option<&TenantFastcgi>,
    ) -> Result<Self, CompileInvalid> {
        let config: Config =
            serde_json::from_value(serde_json::Value::Object(declared.config.clone()))
                .map_err(|err| invalid(err.to_string()))?;
        let upstream = upstreams
            .and_then(|upstreams| upstreams.get(config.upstream.as_str()))
            .ok_or_else(|| {
                CompileInvalid::new(
                    "unknown_fastcgi_upstream",
                    format!(
                        "fastcgi upstream {:?} is not declared for this tenant (the operator declares upstreams in FASTCGI_FILE)",
                        config.upstream
                    ),
                )
                .with("upstream", config.upstream.as_str())
            })?;
        let extensions = extensions_of(config.extensions)?;
        let index = config.index.unwrap_or_else(|| "index.php".to_owned());
        if !plain_name(&index) || !allows(&extensions, &index) {
            return Err(invalid(format!(
                "index {index:?} is not a plain file name that ends in one of the extensions"
            )));
        }
        let try_files = try_files_of(config.try_files, &index)?;
        let deny = deny_of(config.deny)?;
        let env = params::check_env(&config.env.unwrap_or_default()).map_err(invalid)?;
        Ok(Self {
            upstream: Arc::clone(upstream),
            index: index.into_boxed_str(),
            try_files,
            split_path_info: config.split_path_info.unwrap_or(true),
            extensions,
            deny,
            env: env.into_boxed_slice(),
            max_request_body_bytes: config
                .max_request_body_bytes
                .unwrap_or(DEFAULT_MAX_REQUEST_BODY_BYTES),
            state: Arc::default(),
        })
    }

    /// The upstream's name and the index script, for explain and the overview.
    #[must_use]
    pub fn summary(&self) -> Summary<'_> {
        Summary {
            upstream: self.upstream.name(),
            index: &self.index,
        }
    }

    /// Refuses the service when `tenant`'s whole `max_buffer_bytes` is below what one request
    /// reserves: such a tenant could never run a script, and the refusal at request time is a
    /// capacity answer that auto-revert does not count.
    ///
    /// # Errors
    ///
    /// `invalid_service` naming the tenant, the bytes one request needs and the budget.
    pub(crate) fn check_budget(
        &self,
        tenant: &str,
        max_buffer_bytes: u64,
    ) -> Result<(), CompileInvalid> {
        if max_buffer_bytes >= RESERVATION {
            return Ok(());
        }
        Err(invalid(format!(
            "tenant {tenant} has max_buffer_bytes {max_buffer_bytes}, below the {RESERVATION} bytes one fastcgi request reserves"
        ))
        .with("tenant", tenant)
        .with("needed_bytes", RESERVATION)
        .with("max_buffer_bytes", max_buffer_bytes))
    }

    /// Counts a request on the service, for the revision's in-flight bookkeeping.
    pub(super) fn lease(&self) -> Lease {
        Lease::take(&self.state, None)
    }

    /// The script a request for `path` (normalized) runs, `None` when no `try_files` candidate
    /// is an allowed file under the root. Blocks on the file system.
    fn resolve(&self, path: &str) -> Result<Option<Script>, Exhausted> {
        for template in &self.try_files {
            if let Some(script) = self.candidate(&template.replace("{path}", path))? {
                return Ok(Some(script));
            }
        }
        Ok(None)
    }

    /// The script one candidate path names. With `split_path_info`, the first segment that ends
    /// in an allowed extension ends the script (`/app.php/a/b`); the file must then exist
    /// exactly there, so `/uploads/evil.jpg/x.php` looks for a file `x.php` inside the file
    /// `evil.jpg`, which cannot exist, and never runs `evil.jpg`.
    fn candidate(&self, text: &str) -> Result<Option<Script>, Exhausted> {
        if self.split_path_info
            && let Some((script, info)) = self.split(text)
        {
            let (Ok(rel), Some(info)) = (RelPath::parse(script), decode_path_info(info)) else {
                return Ok(None);
            };
            return self.script_at(&rel, info, false);
        }
        let Ok(rel) = RelPath::parse(text) else {
            return Ok(None);
        };
        self.script_at(&rel, String::new(), true)
    }

    /// Splits `text` after its first segment with an allowed extension, when something follows.
    fn split<'a>(&self, text: &'a str) -> Option<(&'a str, &'a str)> {
        let mut end = 0;
        for segment in text.split('/') {
            end += segment.len();
            if allows(&self.extensions, segment) {
                let rest = text.get(end..)?;
                return rest.starts_with('/').then(|| (&text[..end], rest));
            }
            end += 1;
        }
        None
    }

    fn open(&self, rel: &RelPath) -> Result<Option<Opened>, Exhausted> {
        match self.upstream.root().open_path(rel) {
            Ok(opened) => Ok(Some(opened)),
            Err(OpenError::Missing) => Ok(None),
            Err(OpenError::Exhausted) => Err(Exhausted),
        }
    }

    fn script_at(
        &self,
        rel: &RelPath,
        path_info: String,
        directories: bool,
    ) -> Result<Option<Script>, Exhausted> {
        let Some(opened) = self.open(rel)? else {
            return Ok(None);
        };
        let (rel, opened) = match opened.kind {
            Kind::File => (rel.clone(), opened),
            Kind::Dir if directories => {
                let Some(inner) = rel.join(&self.index) else {
                    return Ok(None);
                };
                match self.open(&inner)? {
                    Some(file) if file.kind == Kind::File => (inner, file),
                    _ => return Ok(None),
                }
            }
            Kind::Dir => return Ok(None),
        };
        Ok(self.runnable(&rel, &opened, path_info))
    }

    /// The script for an open file, when its name and its real location both pass the extension
    /// and `deny` rules: a symlink inside the root to another file there is judged by the file
    /// it leads to, so it cannot make a `.txt` run as `.php`.
    fn runnable(&self, rel: &RelPath, opened: &Opened, path_info: String) -> Option<Script> {
        let name = rel.as_str().rsplit('/').next()?;
        if !allows(&self.extensions, name) || denied(&self.deny, rel.as_str()) {
            return None;
        }
        let real = real_path(&opened.file)?;
        let under = real.strip_prefix(self.upstream.real_root()).ok()?;
        let under_text = under.to_str()?;
        if !allows(&self.extensions, under.file_name()?.to_str()?) || denied(&self.deny, under_text)
        {
            return None;
        }
        Some(Script {
            filename: real.to_str()?.to_owned(),
            name: format!("/{}", rel.as_str()),
            path_info,
            document_root: self.upstream.real_root().to_str()?.to_owned(),
        })
    }
}

/// Where an open file really is. Linux's `/proc/self/fd` names the file the descriptor holds,
/// after every symlink, which a path check on the request could never do.
fn real_path(file: &std::fs::File) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

fn extensions_of(list: Option<Vec<String>>) -> Result<Box<[Box<str>]>, CompileInvalid> {
    let list = list.unwrap_or_else(|| vec![".php".to_owned()]);
    if list.is_empty() || list.len() > MAX_LIST {
        return Err(invalid(format!("extensions lists 1 to {MAX_LIST} entries")));
    }
    for extension in &list {
        let tail = extension.strip_prefix('.').unwrap_or("");
        if tail.is_empty()
            || tail.len() > 15
            || !tail.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(invalid(format!(
                "extension {extension:?} is not a dot and up to 15 letters or digits"
            )));
        }
    }
    Ok(list.into_iter().map(String::into_boxed_str).collect())
}

fn try_files_of(list: Option<Vec<String>>, index: &str) -> Result<Box<[Box<str>]>, CompileInvalid> {
    let Some(entries) = list else {
        return Ok(Box::new([
            Box::from("{path}"),
            format!("{{path}}/{index}").into_boxed_str(),
            format!("/{index}").into_boxed_str(),
        ]));
    };
    if entries.is_empty() || entries.len() > MAX_LIST {
        return Err(invalid(format!("try_files lists 1 to {MAX_LIST} entries")));
    }
    if let Some(bad) = entries.iter().find(|entry| !template_is_valid(entry)) {
        return Err(invalid(format!(
            "try_files entry {bad:?} must start with / or {{path}} and use no placeholder but {{path}}"
        )));
    }
    Ok(entries.into_iter().map(String::into_boxed_str).collect())
}

fn deny_of(list: Option<Vec<String>>) -> Result<Box<[Box<str>]>, CompileInvalid> {
    let list = list.unwrap_or_default();
    if list.len() > MAX_LIST {
        return Err(invalid(format!("deny lists at most {MAX_LIST} entries")));
    }
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        let trimmed = entry.trim_matches('/');
        if trimmed.is_empty() || !trimmed.split('/').all(plain_name) {
            return Err(invalid(format!(
                "deny entry {entry:?} is not a path of plain names under the root"
            )));
        }
        out.push(Box::from(trimmed));
    }
    Ok(out.into_boxed_slice())
}

/// Why a fastcgi request was answered with an error of podgate's own.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum Failure {
    /// No connection to the application freed up within a second: `503`, retry in a second.
    #[error("fastcgi application is busy")]
    Busy,
    /// The tenant's buffer budget cannot take the request's buffers: `503`, retry in a second.
    #[error("fastcgi buffers are over the tenant's budget")]
    OverBudget,
    /// The application cannot be reached or closed the connection: `502`.
    #[error("fastcgi application unavailable")]
    Unavailable,
    /// The application's answer is not valid CGI output: `502`.
    #[error("invalid response from the fastcgi application")]
    BadResponse,
    /// The application did not answer in time: `504`.
    #[error("fastcgi application timed out")]
    Timeout,
}

impl Failure {
    /// The status this failure answers with.
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::Busy | Self::OverBudget => StatusCode::SERVICE_UNAVAILABLE,
            Self::Unavailable | Self::BadResponse => StatusCode::BAD_GATEWAY,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// Seconds for `retry-after`, when the client should try again.
    #[must_use]
    pub fn retry_after_secs(self) -> Option<u32> {
        matches!(self, Self::Busy | Self::OverBudget).then_some(1)
    }

    /// Whether the answer says the proxy or tenant is busy, not that the deploy is broken.
    #[must_use]
    pub fn is_capacity_refusal(self) -> bool {
        matches!(self, Self::Busy | Self::OverBudget)
    }

    /// The reason the access log gives.
    #[must_use]
    pub fn log_reason(self) -> &'static str {
        match self {
            Self::Busy => "fastcgi_busy",
            Self::OverBudget => "over_budget",
            Self::Unavailable => "fastcgi_unavailable",
            Self::BadResponse => "fastcgi_bad_response",
            Self::Timeout => "fastcgi_timeout",
        }
    }
}

impl From<PoolError> for Failure {
    fn from(err: PoolError) -> Self {
        match err {
            PoolError::Busy => Self::Busy,
            PoolError::DialTimeout => Self::Timeout,
            PoolError::Dial(_) => Self::Unavailable,
        }
    }
}

/// How a request ends early: with an answer of podgate's own (nothing has been written yet), or
/// with the connection cut (the response has started, or the client is gone).
enum Fail {
    Refused(Box<AppError>),
    Broken(BError),
}

impl From<AppError> for Fail {
    fn from(err: AppError) -> Self {
        Self::Refused(Box::new(err))
    }
}

impl From<Failure> for Fail {
    fn from(failure: Failure) -> Self {
        AppError::Fastcgi(failure).into()
    }
}

impl From<BError> for Fail {
    fn from(err: BError) -> Self {
        Self::Broken(err)
    }
}

/// The request body, as it reaches the application.
enum Body {
    Empty,
    /// Streamed as the client sends it; the declared length.
    Streamed(u64),
    /// Held whole before the application is contacted, with the charges that pay for it.
    Held {
        data: Vec<u8>,
        _charges: Vec<BufferGuard>,
    },
}

impl Body {
    fn len(&self) -> u64 {
        match self {
            Self::Empty => 0,
            Self::Streamed(len) => *len,
            Self::Held { data, .. } => len(data),
        }
    }
}

/// The declared length of the request body: `Ok(None)` for a chunked or unmarked message,
/// `Err` for a `Content-Length` that is not a number.
fn declared_length(headers: &http::HeaderMap) -> Result<Option<u64>, ()> {
    let chunked = headers
        .get_all(TRANSFER_ENCODING)
        .iter()
        .any(|value| value.as_bytes().eq_ignore_ascii_case(b"chunked"));
    if chunked {
        return Ok(None);
    }
    headers
        .get(CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|text| text.trim().parse().ok())
                .ok_or(())
        })
        .transpose()
}

fn expects_continue(request: &RequestHeader) -> bool {
    request.version == Version::HTTP_11
        && request
            .headers
            .get(EXPECT)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"100-continue"))
}

fn len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// Decides how the body travels and, when it has no declared length, reads it whole under the
/// tenant's budget.
async fn plan_body(
    session: &mut Session,
    request: &RequestHeader,
    site: &FastcgiSite,
    tenant: &Arc<TenantBudget>,
) -> Result<Body, Fail> {
    let max = site.max_request_body_bytes;
    let declared = declared_length(&request.headers)
        .map_err(|()| AppError::BadRequest("invalid content-length".into()))?;
    match declared {
        Some(0) => return Ok(Body::Empty),
        Some(length) if length > max => return Err(AppError::PayloadTooLarge.into()),
        Some(_) => {}
        None if session.is_body_empty() => return Ok(Body::Empty),
        None => {}
    }
    if expects_continue(request) {
        session.write_continue_response().await?;
    }
    if let Some(length) = declared {
        return Ok(Body::Streamed(length));
    }
    let mut data = Vec::new();
    let mut guards = Vec::new();
    let mut charged = 0_u64;
    let read = async {
        while let Some(chunk) = session.read_request_body().await? {
            let total = len(&data).saturating_add(len(&chunk));
            if total > max {
                return Ok::<_, BError>(Err(AppError::PayloadTooLarge));
            }
            if total > charged {
                let step = (total - charged).max(CHUNK).min(max - charged);
                let Some(guard) = tenant.charge(step) else {
                    return Ok::<_, BError>(Err(AppError::Fastcgi(Failure::OverBudget)));
                };
                guards.push(guard);
                charged += step;
            }
            data.extend_from_slice(&chunk);
        }
        pingora::Result::Ok(Ok(()))
    };
    match timeout(BODY_DEADLINE, read).await {
        Ok(read) => read??,
        Err(_) => return Err(AppError::RequestTimeout.into()),
    }
    Ok(Body::Held {
        data,
        _charges: guards,
    })
}

/// The host a client asked for and the port it reached.
fn server_name_and_port(request: &RequestHeader, ctx: &Ctx) -> (String, u16) {
    let host = request
        .headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            request
                .uri
                .authority()
                .map(|authority| authority.as_str().to_owned())
        })
        .unwrap_or_default();
    let (name, port) = match host.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        Some((name, rest)) => (
            name.to_owned(),
            rest.strip_prefix(':').and_then(|p| p.parse().ok()),
        ),
        None => match host.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => {
                (name.to_owned(), port.parse().ok())
            }
            _ => (host.clone(), None),
        },
    };
    let https = ctx.forwarded.proto == Proto::Https;
    let port = port
        .or(ctx.forwarded.port)
        .unwrap_or(if https { 443 } else { 80 });
    (
        ctx.forwarded
            .host
            .as_deref()
            .map_or_else(|| name.to_ascii_lowercase(), str::to_owned),
        port,
    )
}

/// Collects what the application writes to `FCGI_STDERR` and logs it when the request is over,
/// whichever way it ends.
struct Stderr {
    app: Box<str>,
    upstream: Box<str>,
    text: Vec<u8>,
    truncated: bool,
}

impl Stderr {
    fn add(&mut self, chunk: &[u8]) {
        let room = STDERR_LOG_BYTES.saturating_sub(self.text.len());
        let take = chunk.len().min(room);
        self.text
            .extend_from_slice(chunk.get(..take).unwrap_or_default());
        self.truncated |= take < chunk.len();
    }
}

impl Drop for Stderr {
    fn drop(&mut self) {
        if !self.text.is_empty() {
            tracing::warn!(
                app = &*self.app,
                upstream = &*self.upstream,
                truncated = self.truncated,
                stderr = %String::from_utf8_lossy(&self.text),
                "fastcgi stderr"
            );
        }
    }
}

/// Writes one body chunk through the response body hooks.
async fn send(
    gateway: &Gateway,
    session: &mut Session,
    ctx: &mut Ctx,
    chunk: Option<Bytes>,
    last: bool,
) -> pingora::Result<()> {
    let mut body = chunk;
    gateway.response_body_filter(session, &mut body, last, ctx)?;
    if body.is_some() || last {
        session.write_response_body(body, last).await?;
    }
    Ok(())
}

/// Sends the request to the application: begin, parameters, then the body.
///
/// An error from the application's side stops the sending; the answer may already be on its way
/// (a script that refuses the body answers before it has read it), so the caller reads on.
async fn send_request(
    session: &mut Session,
    stream: &mut Stream,
    encoded: &[u8],
    body: &Body,
    limit: Duration,
) -> Result<Result<(), ()>, Fail> {
    let app_side = async {
        protocol::write_begin(stream, true).await?;
        protocol::write_params(stream, encoded).await?;
        if let Body::Held { data, .. } = body {
            protocol::write_stdin(stream, data).await?;
        }
        if matches!(body, Body::Empty | Body::Held { .. }) {
            protocol::end_stdin(stream).await?;
        }
        Ok::<(), protocol::ProtocolError>(())
    };
    match timeout(limit, app_side).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => return Ok(Err(())),
    }
    let Body::Streamed(expected) = body else {
        return Ok(Ok(()));
    };
    let mut sent = 0_u64;
    while let Some(chunk) = session.read_request_body().await? {
        sent = sent.saturating_add(len(&chunk));
        if sent > *expected {
            return Err(AppError::BadRequest("body longer than content-length".into()).into());
        }
        match timeout(limit, protocol::write_stdin(stream, &chunk)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return Ok(Err(())),
        }
    }
    if sent != *expected {
        return Err(AppError::BadRequest("body shorter than content-length".into()).into());
    }
    match timeout(limit, protocol::end_stdin(stream)).await {
        Ok(Ok(())) => Ok(Ok(())),
        Ok(Err(_)) | Err(_) => Ok(Err(())),
    }
}

/// What the answer needs to know about the request it answers.
struct Reply {
    head_only: bool,
    chunked: bool,
}

/// Reads the application's answer and writes it to the client. Returns whether the connection
/// can serve another request.
async fn answer(
    gateway: &Gateway,
    session: &mut Session,
    ctx: &mut Ctx,
    stream: &mut Stream,
    limit: Duration,
    reply: &Reply,
    stderr: &mut Stderr,
) -> Result<bool, Fail> {
    let mut parser = HeadParser::default();
    let mut started = false;
    let mut writes_body = true;
    let fail = |started: bool, failure: Failure| -> Fail {
        if started {
            Fail::Broken(Error::explain(
                InternalError,
                "the fastcgi application failed in the middle of its response",
            ))
        } else {
            failure.into()
        }
    };
    loop {
        let record = match timeout(limit, protocol::read_record(stream)).await {
            Err(_) => return Err(fail(started, Failure::Timeout)),
            Ok(Err(protocol::ProtocolError::Io(_))) => {
                return Err(fail(started, Failure::Unavailable));
            }
            Ok(Err(protocol::ProtocolError::Unexpected)) => {
                return Err(fail(started, Failure::BadResponse));
            }
            Ok(Ok(record)) => record,
        };
        match record {
            Record::Stderr(chunk) => stderr.add(&chunk),
            Record::Other => {}
            Record::Stdout(chunk) if chunk.is_empty() => {}
            Record::Stdout(chunk) if !started => match parser.push(&chunk) {
                Ok(None) => {}
                Ok(Some((head, rest))) => {
                    started = true;
                    writes_body = start(gateway, session, ctx, head, reply).await?;
                    if writes_body && !rest.is_empty() {
                        send(gateway, session, ctx, Some(rest), false).await?;
                    }
                }
                Err(_) => {
                    return Err(Failure::BadResponse.into());
                }
            },
            Record::Stdout(chunk) => {
                if writes_body {
                    send(gateway, session, ctx, Some(chunk), false).await?;
                }
            }
            Record::End(end) => {
                if !started {
                    return Err(Failure::BadResponse.into());
                }
                if end.protocol_status != 0 {
                    return Err(fail(true, Failure::BadResponse));
                }
                if writes_body {
                    send(gateway, session, ctx, None, true).await?;
                }
                return Ok(true);
            }
        }
    }
}

/// Writes the response head. Returns whether a body follows.
async fn start(
    gateway: &Gateway,
    session: &mut Session,
    ctx: &mut Ctx,
    head: response::Head,
    reply: &Reply,
) -> pingora::Result<bool> {
    let bodyless = reply.head_only
        || head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED;
    let mut header = ResponseHeader::build(head.status, Some(head.headers.len() + 1))?;
    for (name, value) in head.headers {
        header.append_header(name, value)?;
    }
    if !bodyless && reply.chunked {
        header.insert_header("transfer-encoding", "chunked")?;
    }
    gateway.response_filter(session, &mut header, ctx).await?;
    session
        .write_response_header(Box::new(header), bodyless)
        .await?;
    Ok(!bodyless)
}

/// Refuses the request with an error of podgate's own.
async fn refuse(session: &mut Session, ctx: &mut Ctx, err: AppError) -> pingora::Result<()> {
    ctx.capacity_refusal = err.is_capacity_refusal();
    ctx.access.refused(&err);
    respond::write_error(session, &err).await
}

/// Answers the request the router matched with the fastcgi service it selected.
///
/// Charges [`RESERVATION`] to the tenant's buffer budget first (`503` with `retry-after` when it
/// does not fit); the charge ends with this call, which is when the response has been written or
/// the client has gone.
///
/// # Errors
///
/// A Pingora error when the response cannot be written or the application fails after the
/// response started; the connection is then closed.
pub(crate) async fn serve(
    gateway: &Gateway,
    budgets: &Budgets,
    request_timeout: Duration,
    session: &mut Session,
    ctx: &mut Ctx,
) -> pingora::Result<()> {
    let outside = || Error::explain(InternalError, "fastcgi request without a fastcgi service");
    let selected = ctx.route.ok_or_else(outside)?;
    let app = ctx.table.app(selected.app).ok_or_else(outside)?;
    let site = app
        .fastcgi_site(selected.revision, selected.router)
        .cloned()
        .ok_or_else(outside)?;
    let app_name: Box<str> = Box::from(app.id());
    let tenant = ctx
        .table
        .tenant_budget(app.tenant())
        .map(|limits| budgets.tenant(app.tenant(), limits));
    // The chain's path rewrites edit the request that goes upstream; the script lookup is that
    // request, so they apply here too, and the path is normalized again.
    let mut request = session.req_header().clone();
    if let Some((owner, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) {
        middleware::run_upstream_request(
            owner.stages(),
            router.chain(),
            &mut request,
            &mut ctx.chain,
        )?;
    }
    let limit = site.upstream.read_timeout().unwrap_or(request_timeout);
    let outcome = run(
        gateway,
        &site,
        tenant.as_ref(),
        (limit, app_name),
        session,
        ctx,
        &request,
    )
    .await;
    match outcome {
        Ok(()) => Ok(()),
        Err(Fail::Refused(err)) => refuse(session, ctx, *err).await,
        Err(Fail::Broken(err)) => Err(err),
    }
}

async fn run(
    gateway: &Gateway,
    site: &Arc<FastcgiSite>,
    tenant: Option<&Arc<TenantBudget>>,
    (limit, app_name): (Duration, Box<str>),
    session: &mut Session,
    ctx: &mut Ctx,
    request: &RequestHeader,
) -> Result<(), Fail> {
    let normalized = path::normalize(request.uri.path())
        .map_err(|_| AppError::NotFound)?
        .into_owned();
    let tenant = tenant.ok_or(Failure::OverBudget)?;
    let _reservation = tenant.charge(RESERVATION).ok_or(Failure::OverBudget)?;
    let body = plan_body(session, request, site, tenant).await?;
    let lookup = {
        let site = Arc::clone(site);
        tokio::task::spawn_blocking(move || site.resolve(&normalized))
            .await
            .map_err(|_| AppError::Internal(anyhow::anyhow!("fastcgi script lookup panicked")))?
    };
    let script = match lookup {
        Err(Exhausted) => return Err(Failure::Busy.into()),
        Ok(Some(script)) => script,
        Ok(None) => return Err(AppError::NotFound.into()),
    };
    let (server_name, server_port) = server_name_and_port(request, ctx);
    let cgi = Cgi {
        request,
        script: &script,
        server_name: &server_name,
        server_port,
        remote_addr: ctx.forwarded.client_ip,
        https: ctx.forwarded.proto == Proto::Https,
        content_length: Some(body.len()),
        env: &site.env,
    };
    let encoded = params::pairs(&cgi)
        .and_then(|pairs| params::encode(&pairs))
        .map_err(|refused| match refused {
            params::Refused::BadValue(name) => {
                AppError::BadRequest(format!("header {name} holds a control character").into())
            }
            params::Refused::TooLarge => AppError::HeadersTooLarge,
        })?;
    let mut stderr = Stderr {
        app: app_name,
        upstream: Box::from(site.upstream.name()),
        text: Vec::new(),
        truncated: false,
    };
    let reply = Reply {
        head_only: request.method == Method::HEAD,
        chunked: session.req_header().version == Version::HTTP_11,
    };
    // An idle connection the application closed since its last request fails before any answer.
    // A safe request whose body can be sent again gets one new connection; anything else is
    // the client's to retry, because the application may have started on it.
    let retryable = !matches!(body, Body::Streamed(_))
        && matches!(request.method, Method::GET | Method::HEAD | Method::OPTIONS);
    let pool = site.upstream.pool();
    let mut conn: Conn = pool.checkout().await.map_err(Failure::from)?;
    loop {
        let sent = send_request(session, conn.stream(), &encoded, &body, limit).await?;
        let outcome = answer(
            gateway,
            session,
            ctx,
            conn.stream(),
            limit,
            &reply,
            &mut stderr,
        )
        .await;
        match outcome {
            Ok(reusable) => {
                if reusable && sent.is_ok() {
                    conn.recycle();
                }
                return Ok(());
            }
            Err(Fail::Refused(err))
                if retryable
                    && conn.is_reused()
                    && matches!(*err, AppError::Fastcgi(Failure::Unavailable)) =>
            {
                drop(conn);
                conn = pool.checkout_fresh().await.map_err(Failure::from)?;
            }
            Err(other) => return Err(other),
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;

    struct Tree {
        base: PathBuf,
    }

    impl Tree {
        fn new(name: &str) -> Self {
            let base = std::env::temp_dir()
                .join(format!("podgate-fcgi-site-{name}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&base));
            std::fs::create_dir_all(base.join("root/uploads")).expect("create");
            std::fs::create_dir_all(base.join("root/sub")).expect("create");
            std::fs::write(base.join("secret.php"), "<?php secret").expect("write");
            for (file, text) in [
                ("index.php", "<?php home"),
                ("app.php", "<?php app"),
                ("note.txt", "text"),
                ("sub/index.php", "<?php sub"),
                ("uploads/evil.jpg", "<?php evil"),
                ("uploads/ok.php", "<?php ok"),
            ] {
                std::fs::write(base.join("root").join(file), text).expect("write");
            }
            std::os::unix::fs::symlink("../secret.php", base.join("root/up.php")).expect("link");
            std::os::unix::fs::symlink("note.txt", base.join("root/alias.php")).expect("link");
            std::os::unix::fs::symlink("app.php", base.join("root/same.php")).expect("link");
            Self { base }
        }

        fn upstreams(&self) -> TenantFastcgi {
            let file = self.base.join("fastcgi.json");
            let json = json!({ "t": { "php": {
                "address": "unix:/nonexistent.sock",
                "root": self.base.join("root"),
            }}});
            std::fs::write(&file, json.to_string()).expect("write");
            let roots = FastcgiRoots::load(&file).expect("loads");
            roots.of("t").expect("tenant").clone()
        }

        fn site(&self, config: Value) -> Result<FastcgiSite, CompileInvalid> {
            let Value::Object(mut fields) = json!({ "upstream": "php" }) else {
                unreachable!()
            };
            if let Value::Object(extra) = config {
                fields.extend(extra);
            }
            FastcgiSite::compile(
                &Declared {
                    name: "app".into(),
                    kind: "fastcgi".into(),
                    config: fields,
                },
                Some(&self.upstreams()),
            )
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.base));
        }
    }

    fn run(site: &FastcgiSite, path: &str) -> Option<(String, String)> {
        site.resolve(path)
            .expect("no exhaustion")
            .map(|script| (script.name, script.path_info))
    }

    #[test]
    fn only_allowed_files_run_and_directories_use_the_index() {
        let tree = Tree::new("run");
        let site = tree
            .site(json!({ "try_files": ["{path}"] }))
            .expect("compiles");
        assert_eq!(
            run(&site, "/app.php"),
            Some(("/app.php".into(), String::new()))
        );
        assert_eq!(run(&site, "/"), Some(("/index.php".into(), String::new())));
        assert_eq!(
            run(&site, "/sub/"),
            Some(("/sub/index.php".into(), String::new()))
        );
        assert_eq!(
            run(&site, "/note.txt"),
            None,
            "a text file is never executed"
        );
        assert_eq!(
            run(&site, "/uploads/evil.jpg"),
            None,
            "nor an upload named .jpg"
        );
        assert_eq!(run(&site, "/missing.php"), None);
    }

    #[test]
    fn path_info_is_what_follows_the_script() {
        let tree = Tree::new("info");
        let site = tree
            .site(json!({ "try_files": ["{path}"] }))
            .expect("compiles");
        assert_eq!(
            run(&site, "/app.php/a/b%20c"),
            Some(("/app.php".into(), "/a/b c".into()))
        );
        let unsplit = tree
            .site(json!({ "try_files": ["{path}"], "split_path_info": false }))
            .expect("compiles");
        assert_eq!(run(&unsplit, "/app.php/a"), None);
    }

    #[test]
    fn a_file_named_php_inside_a_non_php_file_never_makes_it_run() {
        let tree = Tree::new("attack");
        let site = tree
            .site(json!({ "try_files": ["{path}"] }))
            .expect("compiles");
        assert_eq!(run(&site, "/uploads/evil.jpg/x.php"), None);
        assert_eq!(run(&site, "/uploads/evil.jpg/x.php/more"), None);
        let with_fallback = tree.site(json!({})).expect("compiles");
        assert_eq!(
            run(&with_fallback, "/uploads/evil.jpg/x.php"),
            Some(("/index.php".into(), String::new())),
            "the fallback script runs, never evil.jpg"
        );
    }

    #[test]
    fn traversal_and_symlink_escapes_do_not_resolve() {
        let tree = Tree::new("escape");
        let site = tree
            .site(json!({ "try_files": ["{path}"] }))
            .expect("compiles");
        assert_eq!(run(&site, "/../secret.php"), None);
        assert_eq!(run(&site, "/sub/../../secret.php"), None);
        assert_eq!(run(&site, "/up.php"), None, "a symlink out of the root");
        assert_eq!(
            run(&site, "/alias.php"),
            None,
            "a symlink to a file that may not run"
        );
        assert!(
            run(&site, "/same.php").is_some(),
            "a symlink to an allowed file in the root"
        );
        assert_eq!(run(&site, "/.env"), None);
    }

    #[test]
    fn deny_blocks_paths_under_the_root() {
        let tree = Tree::new("deny");
        let site = tree
            .site(json!({ "try_files": ["{path}"], "deny": ["uploads"] }))
            .expect("compiles");
        assert_eq!(run(&site, "/uploads/ok.php"), None);
        assert!(run(&site, "/app.php").is_some());
    }

    #[test]
    fn the_real_path_is_the_script_filename() {
        let tree = Tree::new("real");
        let site = tree
            .site(json!({ "try_files": ["{path}"] }))
            .expect("compiles");
        let script = site.resolve("/same.php").expect("ok").expect("script");
        let real_root = std::fs::canonicalize(tree.base.join("root")).expect("canonical");
        assert_eq!(
            script.filename,
            real_root.join("app.php").to_str().expect("utf8")
        );
        assert_eq!(script.name, "/same.php");
        assert_eq!(script.document_root, real_root.to_str().expect("utf8"));
    }

    #[test]
    fn unknown_upstream_and_bad_settings_are_refused_at_compile() {
        let tree = Tree::new("compile");
        let unknown = FastcgiSite::compile(
            &Declared {
                name: "a".into(),
                kind: "fastcgi".into(),
                config: json!({ "upstream": "other" })
                    .as_object()
                    .cloned()
                    .expect("object"),
            },
            Some(&tree.upstreams()),
        )
        .expect_err("not declared");
        assert_eq!(unknown.code, "unknown_fastcgi_upstream");
        let none = FastcgiSite::compile(
            &Declared {
                name: "a".into(),
                kind: "fastcgi".into(),
                config: json!({ "upstream": "php" })
                    .as_object()
                    .cloned()
                    .expect("object"),
            },
            None,
        )
        .expect_err("tenant has none");
        assert_eq!(none.code, "unknown_fastcgi_upstream");
        for bad in [
            json!({ "address": "unix:/x" }),
            json!({ "index": "index.txt" }),
            json!({ "index": "a/b.php" }),
            json!({ "extensions": ["php"] }),
            json!({ "extensions": [] }),
            json!({ "try_files": ["x"] }),
            json!({ "try_files": ["404"] }),
            json!({ "try_files": ["{path}/{other}"] }),
            json!({ "deny": ["../x"] }),
            json!({ "env": { "HTTP_PROXY": "x" } }),
            json!({ "env": { "lower": "x" } }),
            json!({ "env": { "PHP_INI_SCAN_DIR": "/tmp" } }),
        ] {
            let err = tree.site(bad.clone()).expect_err(&bad.to_string());
            assert_eq!(err.code, "invalid_service", "{bad}");
        }
    }

    #[test]
    fn a_budget_below_one_request_is_refused() {
        let tree = Tree::new("budget");
        let site = tree.site(json!({})).expect("compiles");
        assert!(site.check_budget("t", RESERVATION).is_ok());
        assert!(site.check_budget("t", RESERVATION - 1).is_err());
    }

    #[test]
    fn failures_map_to_statuses() {
        assert_eq!(Failure::Busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(Failure::Busy.retry_after_secs(), Some(1));
        assert_eq!(Failure::Unavailable.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(Failure::BadResponse.retry_after_secs(), None);
        assert!(Failure::OverBudget.is_capacity_refusal());
        assert!(!Failure::Unavailable.is_capacity_refusal());
    }

    #[test]
    fn declared_length_reads_content_length_and_ignores_chunked() {
        let mut headers = http::HeaderMap::new();
        assert_eq!(declared_length(&headers), Ok(None));
        headers.insert(CONTENT_LENGTH, "12".parse().expect("value"));
        assert_eq!(declared_length(&headers), Ok(Some(12)));
        headers.insert(CONTENT_LENGTH, "x".parse().expect("value"));
        assert_eq!(declared_length(&headers), Err(()));
        headers.insert(TRANSFER_ENCODING, "chunked".parse().expect("value"));
        assert_eq!(declared_length(&headers), Ok(None));
    }
}
