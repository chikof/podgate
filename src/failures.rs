//! Failed-request recorder: the last [`RING_CAP`] failed requests of every app, kept
//! in memory so an engineer can list and replay them over the admin API.
//!
//! # What is recorded
//!
//! A request is recorded when it was routed to an app and the client got a 5xx for it, whether
//! the upstream sent that 5xx ([`Origin::Upstream`]) or podgate did, for example a `502` when
//! the upstream refused the connection ([`Origin::Podgate`]). A request podgate answered before
//! routing (404, 421, `503 no upstream available`) is not recorded: it names no app revision to
//! replay against.
//!
//! The record holds the request line, the request and response headers and the revision and
//! upstream that served it. `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie`
//! values are replaced by `[redacted]` before anything is stored, so a secret never sits in
//! memory. Bodies are kept only for apps with `record_bodies`, and only when they are at most
//! [`BODY_CAP`] bytes; a larger body is dropped and marked [`Body::TooLarge`]. Nothing is
//! written to disk.
//!
//! # Order against compression
//!
//! `response_filter` and `response_body_filter` call the capture before the compressor (spec
//! 0009), so a recorded 5xx keeps the upstream's headers and its uncompressed body, which read
//! together. The status is the one the client got, read in `logging` from the written response;
//! compression never changes it.
//!
//! # Cost on the hot path
//!
//! [`Capture`] copies body chunks as they stream past; it never holds one back, so streaming to
//! the upstream and to the client is not delayed. A request buffers at most [`BODY_CAP`] bytes
//! per direction and only when its app opted in; the buffer is freed as soon as the body turns
//! out to be larger.
//!
//! # Replay
//!
//! [`replay`] re-sends a record to one upstream address. The redacted headers are dropped, not
//! sent as `[redacted]`, so a request that needed credentials is replayed without them and
//! the upstream may refuse it. Hop-by-hop headers and the framing headers are rebuilt. When the
//! body was not kept, the request goes without one.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use pingora::connectors::http::v1::Connector;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use pingora::upstreams::peer::HttpPeer;
use serde_json::{Value, json};
use thiserror::Error;

use crate::proxy::Ctx;
use crate::table::{CompiledApp, RoutingTable};

/// Failed requests kept per app; the oldest is dropped first.
pub const RING_CAP: usize = 100;

/// Largest request or response body kept, in bytes.
pub const BODY_CAP: usize = 64 * 1024;

/// How long a replay waits to connect to, write to and read from the upstream.
const REPLAY_TIMEOUT: Duration = Duration::from_secs(10);

/// What replaces the value of a secret header.
const REDACTED: &str = "[redacted]";

/// Headers whose values are never stored or returned.
const SECRET_HEADERS: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// Headers that belong to one connection or to the body framing; a replay rebuilds them.
const CONNECTION_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

/// Header names and values in wire order. Names are lowercase; a secret value is `[redacted]`.
pub type Headers = Vec<(String, String)>;

/// Who produced the 5xx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The upstream answered with it.
    Upstream,
    /// podgate answered, because the upstream refused, reset or timed out.
    Podgate,
}

/// A request or response body of a recorded failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Not kept: the app does not set `record_bodies`, or nothing was seen.
    NotRecorded,
    /// Dropped because it is larger than [`BODY_CAP`].
    TooLarge,
    /// The complete body.
    Kept(Bytes),
}

impl Body {
    /// The body as JSON text (lossy for bytes that are not UTF-8), `null` unless kept.
    fn text(&self) -> Value {
        match self {
            Self::Kept(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
            Self::NotRecorded | Self::TooLarge => Value::Null,
        }
    }

    fn too_large(&self) -> bool {
        *self == Self::TooLarge
    }
}

/// One failed request.
#[derive(Debug, Clone)]
pub struct FailedRequest {
    /// Unique and increasing across all apps of one process; [`Failures::record`] assigns it.
    pub id: u64,
    /// When the request finished, milliseconds since the Unix epoch.
    pub at_unix_ms: u64,
    /// Who produced the 5xx.
    pub origin: Origin,
    /// Request method.
    pub method: String,
    /// Request path and query.
    pub uri: String,
    /// Normalized request host.
    pub host: String,
    /// The revision that was chosen; `null` for a request a middleware answered first.
    pub revision: Option<Box<str>>,
    /// The backend that was chosen; `null` for a request a middleware answered first.
    pub upstream: Option<SocketAddr>,
    /// Request headers, secrets redacted.
    pub request_headers: Headers,
    /// Request body, when the app keeps bodies.
    pub request_body: Body,
    /// The 5xx status the client got.
    pub status: u16,
    /// Response headers, secrets redacted.
    pub response_headers: Headers,
    /// Response body, when the app keeps bodies and the upstream sent one.
    pub response_body: Body,
}

impl FailedRequest {
    /// The record as the admin API lists it. Bodies are text, lossy for non-UTF-8 bytes.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "at_unix_ms": self.at_unix_ms,
            "origin": match self.origin {
                Origin::Upstream => "upstream",
                Origin::Podgate => "podgate",
            },
            "method": self.method,
            "uri": self.uri,
            "host": self.host,
            "revision": self.revision,
            "upstream": self.upstream.map(|upstream| upstream.to_string()),
            "request_headers": headers_json(&self.request_headers),
            "request_body": self.request_body.text(),
            "request_body_too_large": self.request_body.too_large(),
            "status": self.status,
            "response_headers": headers_json(&self.response_headers),
            "response_body": self.response_body.text(),
            "response_body_too_large": self.response_body.too_large(),
        })
    }
}

fn headers_json(headers: &Headers) -> Vec<Value> {
    headers
        .iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect()
}

/// The per-app rings. Cheap to clone; every clone shares the same rings.
///
/// Rings are keyed by app id, so they survive snapshot swaps; [`Self::retain_apps`] drops the
/// rings of apps a new table no longer has.
#[derive(Debug, Clone, Default)]
pub struct Failures {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    next_id: AtomicU64,
    rings: Mutex<HashMap<Box<str>, VecDeque<Arc<FailedRequest>>>>,
}

impl Failures {
    /// An empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn rings(&self) -> std::sync::MutexGuard<'_, HashMap<Box<str>, VecDeque<Arc<FailedRequest>>>> {
        self.inner
            .rings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores `failed` as the newest record of `app`, assigning its id, and drops the app's
    /// oldest record when the ring is full. Returns the id.
    pub fn record(&self, app: &str, mut failed: FailedRequest) -> u64 {
        // Ids start at 1 so 0 never names a record.
        failed.id = self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let id = failed.id;
        let mut rings = self.rings();
        let ring = match rings.get_mut(app) {
            Some(ring) => ring,
            None => rings.entry(app.into()).or_default(),
        };
        if ring.len() == RING_CAP {
            ring.pop_front();
        }
        ring.push_back(Arc::new(failed));
        id
    }

    /// The records of `app`, newest first.
    #[must_use]
    pub fn list(&self, app: &str) -> Vec<Arc<FailedRequest>> {
        self.rings()
            .get(app)
            .map(|ring| ring.iter().rev().cloned().collect())
            .unwrap_or_default()
    }

    /// The record `id` of `app`.
    #[must_use]
    pub fn get(&self, app: &str, id: u64) -> Option<Arc<FailedRequest>> {
        let rings = self.rings();
        rings
            .get(app)?
            .iter()
            .find(|failed| failed.id == id)
            .cloned()
    }

    /// Drops the rings of apps that `table` does not have, so apps that come and go cannot grow
    /// the recorder without bound.
    pub fn retain_apps(&self, table: &RoutingTable) {
        let live: HashSet<&str> = apps(table).map(CompiledApp::id).collect();
        self.rings().retain(|app, _| live.contains(&**app));
    }

    /// Records the request of `session` when it was routed and got a 5xx. Call it from
    /// `ProxyHttp::logging`, which runs once per request after the response is written.
    pub fn log(&self, session: &Session, ctx: &mut Ctx) {
        // A request answered by the middleware chain never reached `select`: it has a router but
        // no revision or backend. One refused for capacity, or for lack of an upstream, has
        // neither flag and is not recorded.
        let Some(matched) = ctx
            .matched
            .filter(|_| ctx.route.is_some() || ctx.chain_answered)
        else {
            return;
        };
        let Some(response) = session.response_written() else {
            return;
        };
        if !response.status.is_server_error() {
            return;
        }
        let Some(app) = ctx.table.app(matched.app) else {
            return;
        };
        let revision = ctx
            .route
            .and_then(|selected| app.revisions().get(selected.revision));
        let capture = std::mem::take(&mut ctx.failures);
        let request = session.req_header();
        let failed = FailedRequest {
            id: 0,
            at_unix_ms: now_unix_ms(),
            origin: if capture.upstream_answered {
                Origin::Upstream
            } else {
                Origin::Podgate
            },
            method: request.method.as_str().to_owned(),
            uri: request
                .uri
                .path_and_query()
                .map_or("/", |target| target.as_str())
                .to_owned(),
            host: crate::route::request_host(request)
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_default(),
            revision: revision.map(|revision| revision.id().into()),
            upstream: ctx.route.map(|selected| selected.upstream),
            request_headers: redacted(&request.headers),
            request_body: capture.request.into_body(),
            status: response.status.as_u16(),
            response_headers: capture
                .upstream_headers
                .unwrap_or_else(|| redacted(&response.headers)),
            response_body: capture.response.into_body(),
        };
        self.record(app.id(), failed);
    }
}

/// The apps of `table` in table order.
pub fn apps(table: &RoutingTable) -> impl Iterator<Item = &CompiledApp> {
    (0..).map_while(|index| table.app(index))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or_default()
}

fn is_secret(name: &str) -> bool {
    SECRET_HEADERS.contains(&name)
}

fn redacted(headers: &pingora::http::HMap) -> Headers {
    headers
        .iter()
        .map(|(name, value)| {
            let shown = if is_secret(name.as_str()) {
                REDACTED.to_owned()
            } else {
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            };
            (name.as_str().to_owned(), shown)
        })
        .collect()
}

/// The body of one direction while it streams: nothing, the bytes so far, or too many to keep.
#[derive(Debug, Default)]
enum Buffer {
    #[default]
    Off,
    Collecting(Vec<u8>),
    TooLarge,
}

impl Buffer {
    fn push(&mut self, chunk: &[u8]) {
        if let Self::Collecting(kept) = self {
            if kept.len() + chunk.len() > BODY_CAP {
                *self = Self::TooLarge;
            } else {
                kept.extend_from_slice(chunk);
            }
        }
    }

    fn into_body(self) -> Body {
        match self {
            Self::Off => Body::NotRecorded,
            Self::Collecting(kept) => Body::Kept(kept.into()),
            Self::TooLarge => Body::TooLarge,
        }
    }
}

/// Per-request state of the recorder; the `failures` field of [`Ctx`]. Idle unless the app
/// keeps bodies, apart from one flag.
#[derive(Debug, Default)]
pub struct Capture {
    keep_bodies: bool,
    upstream_answered: bool,
    upstream_headers: Option<Headers>,
    request: Buffer,
    response: Buffer,
}

impl Capture {
    /// Starts capturing for a routed request; `keep_bodies` is the app's `record_bodies`.
    pub fn begin(&mut self, keep_bodies: bool) {
        self.keep_bodies = keep_bodies;
        if keep_bodies {
            self.request = Buffer::Collecting(Vec::new());
        }
    }

    /// Copies a request body chunk, as seen by `request_body_filter`. The chunk is not changed.
    pub fn request_chunk(&mut self, chunk: Option<&Bytes>) {
        if let Some(chunk) = chunk {
            self.request.push(chunk);
        }
    }

    /// Notes that the upstream answered, as seen by `response_filter`, which must call it before
    /// compression rewrites the headers. A 5xx keeps the upstream's headers and starts the response
    /// body capture.
    pub fn upstream_response(&mut self, response: &ResponseHeader) {
        self.upstream_answered = true;
        if response.status.is_server_error() {
            self.upstream_headers = Some(redacted(&response.headers));
            if self.keep_bodies {
                self.response = Buffer::Collecting(Vec::new());
            }
        }
    }

    /// Copies a response body chunk, as seen by `response_body_filter`. The chunk is not changed.
    pub fn response_chunk(&mut self, chunk: Option<&Bytes>) {
        if let Some(chunk) = chunk {
            self.response.push(chunk);
        }
    }
}

/// Why a replay failed.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct ReplayError(#[from] Box<pingora::Error>);

/// The upstream's answer to a replayed request.
#[derive(Debug)]
pub struct Replayed {
    /// Response status.
    pub status: u16,
    /// Response headers, secrets redacted.
    pub headers: Headers,
    /// The response body, at most [`BODY_CAP`] bytes.
    pub body: Vec<u8>,
    /// Whether the response had more body than [`BODY_CAP`].
    pub body_truncated: bool,
}

impl Replayed {
    /// The answer as the replay endpoint returns it. The body is text, lossy for non-UTF-8 bytes.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "status": self.status,
            "headers": headers_json(&self.headers),
            "body": String::from_utf8_lossy(&self.body),
            "body_truncated": self.body_truncated,
        })
    }
}

/// Re-sends `failed` to `peer`, the upstream as the proxy would reach it (TLS settings included),
/// on a new connection and returns the answer.
///
/// # Errors
///
/// Fails when the upstream cannot be reached, resets, times out after 10 seconds or
/// answers something that is not HTTP/1.1.
pub async fn replay(failed: &FailedRequest, mut peer: HttpPeer) -> Result<Replayed, ReplayError> {
    let body: &[u8] = match &failed.request_body {
        Body::Kept(bytes) => bytes,
        Body::NotRecorded | Body::TooLarge => &[],
    };
    let mut request = RequestHeader::build(failed.method.as_str(), failed.uri.as_bytes(), None)?;
    for (name, value) in &failed.request_headers {
        if !is_secret(name) && !CONNECTION_HEADERS.contains(&name.as_str()) {
            request.append_header(name.clone(), value.clone())?;
        }
    }
    if !body.is_empty() || !matches!(failed.method.as_str(), "GET" | "HEAD") {
        request.insert_header("content-length", body.len().to_string())?;
    }

    peer.options.connection_timeout = Some(REPLAY_TIMEOUT);
    peer.options.read_timeout = Some(REPLAY_TIMEOUT);
    peer.options.write_timeout = Some(REPLAY_TIMEOUT);
    let (mut session, _) = Box::pin(Connector::new(None).get_http_session(&peer)).await?;
    session.write_request_header(Box::new(request)).await?;
    if !body.is_empty() {
        session.write_body(body).await?;
    }
    session.finish_body().await?;

    let (status, headers) = loop {
        session.read_response().await?;
        if let Some(response) = session.resp_header()
            && !response.status.is_informational()
        {
            break (response.status.as_u16(), redacted(&response.headers));
        }
    };
    let mut answer = Vec::new();
    let mut body_truncated = false;
    while let Some(chunk) = session.read_body_ref().await? {
        if answer.len() + chunk.len() > BODY_CAP {
            let room = BODY_CAP - answer.len();
            answer.extend_from_slice(&chunk[..room]);
            body_truncated = true;
            break;
        }
        answer.extend_from_slice(chunk);
    }
    session.shutdown().await;
    Ok(Replayed {
        status,
        headers,
        body: answer,
        body_truncated,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    fn failed(uri: &str) -> FailedRequest {
        FailedRequest {
            id: 0,
            at_unix_ms: 0,
            origin: Origin::Upstream,
            method: "GET".into(),
            uri: uri.into(),
            host: "a.test".into(),
            revision: Some("r1".into()),
            upstream: Some(SocketAddr::from(([127, 0, 0, 1], 9000))),
            request_headers: Vec::new(),
            request_body: Body::NotRecorded,
            status: 500,
            response_headers: Vec::new(),
            response_body: Body::NotRecorded,
        }
    }

    #[test]
    fn ring_keeps_the_newest_and_lists_newest_first() {
        let failures = Failures::new();
        for n in 0..RING_CAP + 5 {
            failures.record("a", failed(&format!("/{n}")));
        }
        let listed = failures.list("a");
        assert_eq!(listed.len(), RING_CAP);
        assert_eq!(listed[0].uri, format!("/{}", RING_CAP + 4));
        assert_eq!(listed[RING_CAP - 1].uri, "/5");
        assert!(failures.list("b").is_empty());
    }

    #[test]
    fn buffer_gives_up_past_the_cap() {
        let mut buffer = Buffer::Collecting(Vec::new());
        buffer.push(&vec![0; BODY_CAP]);
        assert!(matches!(&buffer, Buffer::Collecting(kept) if kept.len() == BODY_CAP));
        buffer.push(&[0]);
        assert_eq!(buffer.into_body(), Body::TooLarge);
    }

    #[test]
    fn secret_headers_are_redacted_by_name() {
        let mut map = pingora::http::HMap::new();
        map.insert("authorization", "Bearer s3cret".parse().expect("valid"));
        map.insert("x-keep", "visible".parse().expect("valid"));
        let shown = redacted(&map);
        assert!(shown.contains(&("authorization".into(), REDACTED.into())));
        assert!(shown.contains(&("x-keep".into(), "visible".into())));
    }
}
