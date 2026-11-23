//! The structured access log: one line per request with a chosen set of fields, filters and
//! sampling, on stdout or in a file, never in the way of a request. Reference:
//! `docs/ref/access-log.md`.
//!
//! - `policy`: the snapshot's `observability.access_log`, parsed at compile time.
//! - [`Pending`]: what the request path notes while it runs (a start time, the upstream timing,
//!   retries and the reason podgate refused it); lives in [`Ctx`].
//! - [`log`]: called from `Gateway::logging`; decides whether the request is logged and, if it
//!   is, copies what the line needs into a [`Record`].
//! - `format`: turns a [`Record`] into a JSON or Common Log Format line.
//! - `sink`: the bounded queues, the writer task and the stdout and file sinks.
//! - `otlp` and `export`: the same records as OTLP log records, sent to a collector.
//!
//! A [`Record`] is built only for a request that is selected, and only with the fields its policy
//! keeps. Every string is cut at `FIELD_MAX` bytes when it is copied, so a hostile request
//! cannot make the queue hold more than a bounded amount of text.

mod export;
mod format;
mod otlp;
mod policy;
mod sink;

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime};

use pingora::http::RequestHeader;
use pingora::proxy::Session;
use podgate_model::Snapshot;
use serde_json::Value;

use crate::compile::Invalid;
use crate::error::AppError;
use crate::middleware::jwt_auth::Credentials;
use crate::observe::tracing::Ids;
use crate::proxy::Ctx;
use crate::route;
use crate::sni;

pub use export::{LogService, LogsExporter};
use format::FIELD_MAX;
pub use policy::{Action, Field, Format, HeaderAction, Mask, Policy};
pub use sink::{AccessLog, AccessLogService, FileSink, LineSink, QUEUE_CAPACITY, StdoutSink};

/// The OTLP log messages the exporter sends, for a collector that decodes them.
pub mod proto {
    pub use super::otlp::*;
}

/// The most headers a line lists, request and response each.
const HEADERS_MAX: usize = 64;

/// The longest request id a trusted proxy may supply.
const REQUEST_ID_MAX: usize = 128;

/// What the request path notes for the access log while a request runs. A new request starts
/// the clock.
#[derive(Debug)]
pub struct Pending {
    started: Instant,
    upstream_connected: Option<Instant>,
    upstream_done: Option<Instant>,
    upstream_responded: bool,
    /// Times the request was retried on another server (the retry middleware, counts
    /// them here); the `retry_attempts` field and filter read it.
    pub retry_attempts: u32,
    /// Why podgate refused or failed the request, when a stage knows better than the status does
    /// (`rate_limited`, `circuit_open`, `auth_failed`, ...). Set it where the refusal is made.
    pub reason: Option<&'static str>,
}

impl Default for Pending {
    fn default() -> Self {
        Self::new()
    }
}

impl Pending {
    /// Starts the clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            upstream_connected: None,
            upstream_done: None,
            upstream_responded: false,
            retry_attempts: 0,
            reason: None,
        }
    }

    /// A connection to the upstream is ready: the upstream's time starts.
    pub fn upstream_connected(&mut self) {
        self.upstream_connected = Some(Instant::now());
        self.upstream_done = None;
    }

    /// The upstream sent a response head.
    pub fn upstream_responded(&mut self) {
        self.upstream_responded = true;
    }

    /// The upstream's response body ended: the upstream's time stops.
    pub fn upstream_done(&mut self) {
        if self.upstream_connected.is_some() {
            self.upstream_done = Some(Instant::now());
        }
    }

    /// Notes why podgate answers with `err` itself.
    pub fn refused(&mut self, err: &AppError) {
        self.reason = Some(err.log_reason());
    }

    fn upstream_duration(&self) -> Option<Duration> {
        let connected = self.upstream_connected?;
        Some(self.upstream_done.unwrap_or_else(Instant::now) - connected)
    }
}

/// The snapshot-wide policy: `access_log` absent or `false` logs nothing, `true` or `{}` logs the
/// default fields.
///
/// # Errors
///
/// `invalid_access_log` for a setting [`Policy::parse`] refuses.
pub fn compile(snapshot: &Snapshot) -> Result<Option<Arc<Policy>>, Invalid> {
    match snapshot
        .observability
        .as_ref()
        .and_then(|set| set.access_log.as_ref())
    {
        None | Some(Value::Bool(false)) => Ok(None),
        Some(Value::Bool(true)) => Ok(Some(Arc::new(Policy::default()))),
        Some(setting) => Policy::parse(setting).map(|policy| Some(Arc::new(policy))),
    }
}

/// A router's own `observability.access_log` switch, when it sets one.
#[must_use]
pub fn router_override(observability: &Value) -> Option<bool> {
    observability.get("access_log")?.as_bool()
}

/// The policy that applies to a request: the router's switch over the snapshot's policy. A router
/// that turns the log on in a snapshot with no policy logs the default fields.
#[must_use]
pub fn effective(snapshot: Option<&Arc<Policy>>, router: Option<bool>) -> Option<&Arc<Policy>> {
    static ENABLED: LazyLock<Arc<Policy>> = LazyLock::new(|| Arc::new(Policy::default()));
    match router {
        Some(false) => None,
        Some(true) => Some(snapshot.unwrap_or(&ENABLED)),
        None => snapshot,
    }
}

/// Everything one line shows, copied out of the request so the request can end. Boxed in the
/// queue; formatted by the writer task.
#[derive(Debug)]
pub struct Record {
    policy: Arc<Policy>,
    time: SystemTime,
    request_id: Box<str>,
    entry_point: Box<str>,
    tenant: Option<Box<str>>,
    app: Option<Box<str>>,
    router: Option<Box<str>>,
    service: Option<Box<str>>,
    revision: Option<Box<str>>,
    server: Option<SocketAddr>,
    method: Box<str>,
    host: Option<Box<str>>,
    path: Box<str>,
    query: Option<Box<str>>,
    proto: &'static str,
    status: u16,
    bytes_in: u64,
    bytes_out: u64,
    duration: Duration,
    upstream: Option<Duration>,
    client_ip: Option<IpAddr>,
    tls_version: Option<Box<str>>,
    sni: Option<Box<str>>,
    retry_attempts: u32,
    origin: &'static str,
    reason: Option<&'static str>,
    user_agent: Option<Box<str>>,
    referer: Option<Box<str>>,
    request_headers: Vec<(Box<str>, Box<str>)>,
    response_headers: Vec<(Box<str>, Box<str>)>,
    truncated: Vec<&'static str>,
    /// The ids of the request's trace, when its router is traced: the OTLP record carries them.
    trace: Option<Ids>,
}

// 512: it is queued behind two `Arc`s, so the size is paid once per logged request. The strings
// are `Box<str>` (16 each, 14 of them with the optional ones), three `Vec`s (24 each), the
// socket address (32), the times and durations, the client address (17) and the trace ids.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Record>() == 512);

/// Cuts `value` to [`FIELD_MAX`] bytes at a character boundary; the flag says it was cut.
fn clip(value: &str) -> (&str, bool) {
    if value.len() <= FIELD_MAX {
        return (value, false);
    }
    let mut end = FIELD_MAX;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value.get(..end).unwrap_or_default(), true)
}

/// Copies request-controlled strings into a record, remembering which were cut.
#[derive(Debug, Default)]
struct Copier {
    truncated: Vec<&'static str>,
}

impl Copier {
    fn text(&mut self, name: &'static str, value: &str) -> Box<str> {
        let (kept, cut) = clip(value);
        if cut && !self.truncated.contains(&name) {
            self.truncated.push(name);
        }
        kept.into()
    }

    fn headers(
        &mut self,
        name: &'static str,
        policy: &Policy,
        tokens: &Credentials,
        headers: &http::HeaderMap,
    ) -> Vec<(Box<str>, Box<str>)> {
        let mut out: Vec<(Box<str>, Box<str>)> = Vec::new();
        for (header, value) in headers {
            let header = header.as_str();
            let action = if tokens.header(header) {
                HeaderAction::Redact
            } else {
                policy.header_action(header)
            };
            let Some(shown) = (match action {
                HeaderAction::Keep => Some(String::from_utf8_lossy(value.as_bytes())),
                HeaderAction::Redact => Some(Cow::Borrowed(policy::REDACTED)),
                HeaderAction::Drop => None,
            }) else {
                continue;
            };
            if let Some((last, joined)) = out.last_mut()
                && &**last == header
            {
                let both = format!("{joined}, {shown}");
                *joined = self.text(name, &both);
                continue;
            }
            if out.len() >= HEADERS_MAX {
                if !self.truncated.contains(&name) {
                    self.truncated.push(name);
                }
                break;
            }
            out.push((header.into(), self.text(name, &shown)));
        }
        out
    }
}

/// `query` of a request for `path` with the values of the parameters the policy names, of those
/// a `jwt_auth` stage of the route reads a token from, and of the code of an `oidc` callback,
/// replaced by `[redacted]`.
fn redact_query(policy: &Policy, tokens: &Credentials, path: &str, query: &str) -> String {
    let query = tokens.redact_query(path, query);
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) if policy.redacts_query_param(name) => {
                format!("{name}={}", policy::REDACTED)
            }
            _ => pair.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn generated_id() -> Box<str> {
    static BOOT: LazyLock<u32> = LazyLock::new(|| {
        let mut bytes = [0_u8; 4];
        // Without entropy the ids still differ by their counter.
        let _ = getrandom::fill(&mut bytes);
        u32::from_be_bytes(bytes)
    });
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("{:08x}{:012x}", *BOOT, NEXT.fetch_add(1, Ordering::Relaxed)).into()
}

/// The request's id: the one a trusted proxy sent in `X-Request-Id` when it is a short visible
/// string, else a fresh one. A client the proxy does not trust never picks its id, so it cannot
/// choose whether sampling logs it.
fn request_id(request: &RequestHeader, trusted: bool) -> Box<str> {
    let supplied = trusted
        .then(|| request.headers.get("x-request-id"))
        .flatten()
        .and_then(|value| value.to_str().ok())
        .filter(|id| {
            (1..=REQUEST_ID_MAX).contains(&id.len())
                && id.bytes().all(|b| (0x21..=0x7e).contains(&b))
        });
    supplied.map_or_else(generated_id, Box::from)
}

fn proto(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

/// Logs the finished request, if the live policy asks for it. Called from `Gateway::logging`,
/// after the response is written; costs one table lookup when nothing is logged.
pub fn log(access_log: Option<&AccessLog>, session: &Session, ctx: &Ctx) {
    let Some(queue) = access_log else { return };
    let Some(policy) = ctx.table.access_log(ctx.matched) else {
        return;
    };
    let status = session
        .response_written()
        .map_or(0, |head| head.status.as_u16());
    let duration = ctx.access.started.elapsed();
    if !policy.selects(status, duration, ctx.access.retry_attempts) {
        return;
    }
    let request = session.req_header();
    let id = request_id(request, ctx.forwarded.trusted);
    if !policy.sampled(&id) {
        return;
    }
    queue.record(Arc::new(Record::capture(
        Arc::clone(policy),
        session,
        ctx,
        id,
        status,
        duration,
    )));
}

impl Record {
    fn capture(
        policy: Arc<Policy>,
        session: &Session,
        ctx: &Ctx,
        request_id: Box<str>,
        status: u16,
        duration: Duration,
    ) -> Self {
        let wants = |field: Field| policy.action(field) != Action::Drop;
        let request = session.req_header();
        let mut copy = Copier::default();
        let (app, router) = ctx
            .matched
            .and_then(|matched| ctx.table.router(matched))
            .unzip();
        let revision = ctx
            .route
            .as_ref()
            .and_then(|selected| app?.revisions().get(selected.revision).map(|rev| rev.id()));
        let mut name = |field: Field, value: Option<&str>| {
            value
                .filter(|_| wants(field))
                .map(|value| copy.text(field.name(), value))
        };
        let tenant = name(Field::Tenant, app.map(|app| app.tenant()));
        let app_id = name(Field::App, app.map(|app| app.id()));
        let router_name = name(Field::Router, router.map(|router| router.name()));
        let service = name(Field::Service, router.map(|router| router.service()));
        let revision = name(Field::Revision, revision);
        let host = route::request_host(request);
        let host = name(Field::Host, host.as_deref());
        let tls = session
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref());
        let tls_version = name(Field::TlsVersion, tls.map(|digest| &*digest.version));
        let server_name = name(Field::Sni, sni::server_name(session));
        let user_agent = name(Field::UserAgent, header(request, "user-agent"));
        let referer = name(Field::Referer, header(request, "referer"));
        let tokens = match (app, router) {
            (Some(app), Some(router)) => Credentials::of(app, router.chain()),
            _ => Credentials::default(),
        };
        let query = request
            .uri
            .query()
            .filter(|_| wants(Field::Query))
            .map(|query| {
                let shown = redact_query(&policy, &tokens, request.uri.path(), query);
                copy.text("query", &shown)
            });
        let method = copy.text("method", request.method.as_str());
        let path = copy.text("path", request.uri.path());
        let response = session.response_written();
        let (request_headers, response_headers) = if policy.logs_headers() {
            (
                copy.headers("request_headers", &policy, &tokens, &request.headers),
                response.map_or_else(Vec::new, |head| {
                    copy.headers(
                        "response_headers",
                        &policy,
                        &Credentials::default(),
                        &head.headers,
                    )
                }),
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let origin = if ctx.access.upstream_responded {
            "upstream"
        } else {
            "podgate"
        };
        Self {
            time: SystemTime::now(),
            request_id,
            entry_point: Box::from(&*ctx.entry_point),
            tenant,
            app: app_id,
            router: router_name,
            service,
            revision,
            // A static service has no server; it reports the unspecified address.
            server: ctx
                .route
                .as_ref()
                .map(|selected| selected.upstream)
                .filter(|addr| !addr.ip().is_unspecified()),
            method,
            host,
            path,
            query,
            proto: proto(request.version),
            status,
            bytes_in: u64::try_from(session.body_bytes_read()).unwrap_or(u64::MAX),
            bytes_out: u64::try_from(session.body_bytes_sent()).unwrap_or(u64::MAX),
            duration,
            upstream: ctx.access.upstream_duration(),
            client_ip: ctx.forwarded.known_client(),
            tls_version,
            sni: server_name,
            retry_attempts: ctx.access.retry_attempts,
            origin,
            reason: reason(status, origin, ctx),
            user_agent,
            referer,
            request_headers,
            response_headers,
            truncated: copy.truncated,
            trace: ctx.trace.ids(),
            policy,
        }
    }
}

fn header<'a>(request: &'a RequestHeader, name: &str) -> Option<&'a str> {
    request.headers.get(name)?.to_str().ok()
}

/// Why podgate itself produced a response of `status`: what a stage noted, else derived from how
/// far the request got. `None` for a response the upstream wrote and for non-errors.
fn reason(status: u16, origin: &str, ctx: &Ctx) -> Option<&'static str> {
    if let Some(noted) = ctx.access.reason {
        return Some(noted);
    }
    if origin == "upstream" {
        return None;
    }
    if status == 0 {
        return Some("no_response");
    }
    if status < 400 {
        return None;
    }
    Some(match (ctx.matched, ctx.route, status) {
        (None, _, 400) => "bad_request",
        (None, _, 421) => "misdirected",
        (None, _, 403) => "client_cert_required",
        (None, _, _) => "no_route",
        (Some(_), None, 503) if !ctx.chain_answered => "no_upstream",
        (Some(_), None, _) => "middleware",
        (Some(_), Some(_), _) => "upstream_unavailable",
    })
}

#[cfg(test)]
impl Record {
    /// A record of a plain `GET /` that got `200` with 12 bytes, for the format and sink tests.
    pub(crate) fn sample(policy: &serde_json::Value) -> Self {
        Self {
            policy: Arc::new(Policy::parse(policy).expect("valid policy")),
            time: SystemTime::UNIX_EPOCH,
            request_id: "r1".into(),
            entry_point: "web".into(),
            tenant: Some("t".into()),
            app: Some("a".into()),
            router: Some("web".into()),
            service: Some("web".into()),
            revision: Some("v1".into()),
            server: Some(SocketAddr::from(([127, 0, 0, 1], 9000))),
            method: "GET".into(),
            host: Some("a.test".into()),
            path: "/".into(),
            query: None,
            proto: "HTTP/1.1",
            status: 200,
            bytes_in: 0,
            bytes_out: 12,
            duration: Duration::from_millis(3),
            upstream: Some(Duration::from_millis(2)),
            client_ip: Some(IpAddr::from([203, 0, 113, 7])),
            tls_version: None,
            sni: None,
            retry_attempts: 0,
            origin: "upstream",
            reason: None,
            user_agent: None,
            referer: None,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            truncated: Vec::new(),
            trace: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn long_values_are_cut_on_a_character_boundary() {
        let (kept, cut) = clip("short");
        assert_eq!((kept, cut), ("short", false));
        let long = "é".repeat(FIELD_MAX);
        let (kept, cut) = clip(&long);
        assert!(cut);
        assert!(kept.len() <= FIELD_MAX);
        assert!(kept.chars().all(|ch| ch == 'é'));
    }

    #[test]
    fn access_log_truncates_long_fields() {
        let mut copy = Copier::default();
        let huge = "a".repeat(1 << 20);
        let kept = copy.text("path", &huge);
        assert_eq!(kept.len(), FIELD_MAX);
        assert_eq!(copy.truncated, ["path"]);
        copy.text("path", &huge);
        assert_eq!(copy.truncated, ["path"], "each field is listed once");

        let mut record = Record::sample(&serde_json::json!({}));
        record.path = kept;
        record.truncated = copy.truncated;
        let mut line = String::new();
        record.render(&mut line);
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).expect("json");
        assert_eq!(parsed["path"].as_str().map(str::len), Some(FIELD_MAX));
        assert_eq!(parsed["truncated"], serde_json::json!(["path"]));
    }

    #[test]
    fn query_parameters_marked_sensitive_are_redacted() {
        let policy = Policy::parse(&serde_json::json!({"fields": {
            "names": {"query": "keep"}, "query_redact": ["token", "key"]}}))
        .expect("policy");
        assert_eq!(
            redact_query(
                &policy,
                &Credentials::default(),
                "/p",
                "a=1&token=secret&b&key=x=y&c=3"
            ),
            "a=1&token=[redacted]&b&key=[redacted]&c=3"
        );
    }

    #[test]
    fn credential_headers_are_never_copied_by_default() {
        let policy =
            Policy::parse(&serde_json::json!({"headers": {"default": "keep"}})).expect("policy");
        let mut headers = http::HeaderMap::new();
        for (name, value) in [
            ("authorization", "Bearer s3cret"),
            ("proxy-authorization", "Basic s3cret"),
            ("cookie", "session=s3cret"),
            ("set-cookie", "session=s3cret"),
            ("accept", "text/html"),
        ] {
            headers.append(name, value.parse().expect("header value"));
        }
        headers.append("accept", "text/plain".parse().expect("header value"));
        let copied = Copier::default().headers(
            "request_headers",
            &policy,
            &Credentials::default(),
            &headers,
        );
        let shown: Vec<_> = copied
            .iter()
            .map(|(name, value)| (&**name, &**value))
            .collect();
        assert!(!format!("{shown:?}").contains("s3cret"));
        assert!(shown.contains(&("authorization", "[redacted]")));
        assert!(shown.contains(&("accept", "text/html, text/plain")));
    }

    #[test]
    fn a_trusted_peers_request_id_is_kept_and_anyone_elses_is_replaced() {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request
            .insert_header("x-request-id", "abc-123")
            .expect("header");
        assert_eq!(&*request_id(&request, true), "abc-123");
        assert_ne!(&*request_id(&request, false), "abc-123");
        let generated = request_id(&request, false);
        assert_ne!(generated, request_id(&request, false), "ids are unique");
        request
            .insert_header("x-request-id", "has space")
            .expect("header");
        assert_ne!(&*request_id(&request, true), "has space");
    }
}
