//! OpenTelemetry tracing: W3C trace context to the upstream, spans to an OTLP/HTTP collector,
//! sampling that a client cannot turn into unbounded work. Reference: `docs/ref/tracing.md`.
//!
//! The collector is process configuration (`OTEL_EXPORTER_OTLP_ENDPOINT`, see
//! [`crate::Config`]), never part of a snapshot: a snapshot is tenant-influenced data, and
//! letting it name an address podgate calls would be an SSRF primitive. The snapshot's
//! `observability.tracing` ([`Policy`]) sets only sampling, propagation and the recorded headers.
//!
//! - `context`: reading and writing `traceparent`, pure.
//! - `policy`: the snapshot setting, parsed at compile time.
//! - [`State`]: what one request carries in its [`Ctx`]: its ids, its sampling verdict and, only
//!   when sampled, the request data its spans need, copied and length-capped at the start.
//! - `tracer`: the handle the request path and the exporter share: the per-node rate cap, a
//!   bounded queue that drops new spans when full, the counters.
//! - `otlp` and `export`: the protobuf messages and the background service that batches the
//!   queue and POSTs it, never on the request path.
//!
//! A request is traced when its router's effective [`Policy`] exists. The verdict: with
//! `parent_based` (the default) a valid incoming `traceparent` decides by its sampled flag, but only
//! when the peer is trusted by the entry point's `forwarded_headers`; otherwise the trace id is
//! continued and the root rate `sample_percent` decides. Either way the rate caps have the last
//! word: the node's `OTEL_MAX_SPANS_PER_SEC` and half of it per tenant, so a client that sends
//! `traceparent: ...-01` on every request cannot make podgate export more than the operator allows
//! or take every other tenant's traces. The upstream gets a `traceparent` carrying the
//! verdict whether or not the node exports, so a downstream service samples consistently.

mod context;
mod export;
mod otlp;
mod policy;
mod span;
mod tracer;

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::HeaderName;
use pingora::Error;
use pingora::http::RequestHeader;
use pingora::proxy::Session;

use crate::client_ip;
use crate::proxy::Ctx;
use crate::route;

use context::{SpanId, TraceId};
use span::{Kind, Span, Value};

pub use export::{ExportConfig, TraceService};
pub use policy::{Policy, compile, effective, router_override};
pub use tracer::{DEFAULT_MAX_SPANS_PER_SEC, QUEUE_CAPACITY, Tracer};

/// The protobuf messages the exporter sends, for a collector that decodes them.
pub mod proto {
    pub use super::otlp::*;
}

/// The longest request path, host or header value copied into a span.
const VALUE_MAX: usize = 256;

/// Most values of one header recorded.
const HEADER_VALUES_MAX: usize = 8;

/// Cuts `value` to [`VALUE_MAX`] bytes at a character boundary.
fn clip(value: &str) -> Box<str> {
    if value.len() <= VALUE_MAX {
        return value.into();
    }
    let mut end = VALUE_MAX;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.get(..end).unwrap_or_default().into()
}

/// The request data a sampled request's spans need, copied when the request starts so a
/// middleware that rewrites the request cannot change what is recorded, and so nothing here
/// grows with the request: every string is capped.
#[derive(Debug)]
struct Record {
    wall: SystemTime,
    started: Instant,
    method: Box<str>,
    path: Box<str>,
    host: Option<Box<str>>,
    peer: Option<IpAddr>,
    headers: Vec<(HeaderName, Vec<Box<str>>)>,
}

/// Who sent the request, for the sampling verdict.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Peer<'a> {
    /// The connection's address.
    pub(crate) addr: IpAddr,
    /// Whether the entry point's `forwarded_headers` trusts the peer (see [`crate::client_ip`]).
    pub(crate) trusted: bool,
    /// The tenant of the matched router: its share of the rate cap is spent.
    pub(crate) tenant: &'a str,
}

/// The upstream attempt: from the request being sent to the response body ending.
#[derive(Debug)]
struct Upstream {
    wall: SystemTime,
    started: Instant,
    ended: Option<Instant>,
    status: Option<u16>,
}

#[derive(Debug)]
struct Active {
    trace_id: TraceId,
    span_id: SpanId,
    /// The caller's span, when the request named one.
    parent: Option<SpanId>,
    /// The span of the upstream attempt, the id the upstream is told is its parent.
    client_span_id: SpanId,
    sampled: bool,
    /// Whether the request carried a valid `traceparent` (its `tracestate` is then the caller's).
    continued: bool,
    propagate: bool,
    trace_state: Option<Box<str>>,
    record: Option<Record>,
    upstream: Option<Upstream>,
}

/// The tracing state of one request: nothing when its router is not traced.
#[derive(Debug, Default)]
pub struct State(Option<Box<Active>>);

// 8: one nullable pointer; a request that is not traced pays nothing more.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<State>() == 8);

impl State {
    /// Decides the verdict for `request`, which arrived from `peer`, under `policy`. The trace id
    /// continues whatever the peer sent; its sampled flag counts only when the peer is trusted.
    #[must_use]
    pub(crate) fn begin(
        tracer: &Tracer,
        policy: &Policy,
        request: &RequestHeader,
        peer: Peer<'_>,
    ) -> Self {
        let mut seed = [0_u8; 36];
        // Without entropy the request is not traced; tracing never fails a request.
        if getrandom::fill(&mut seed).is_err() {
            return Self(None);
        }
        let roll: [u8; 4] = take(&seed, 0);
        let span_id = SpanId(nonzero(take(&seed, 4)));
        let client_span_id = SpanId(nonzero(take(&seed, 12)));
        let fresh = TraceId(nonzero(take(&seed, 20)));
        let parent = context::incoming(&request.headers);
        let wanted = match parent {
            Some(parent) if policy.parent_based() && peer.trusted => parent.sampled,
            _ => policy.samples(u32::from_le_bytes(roll)),
        };
        let sampled = wanted && tracer.admit(peer.tenant);
        let trace_id = parent.map_or(fresh, |parent| parent.trace_id);
        let record = (sampled && tracer.exports()).then(|| record(policy, request, peer.addr));
        Self(Some(Box::new(Active {
            trace_id,
            span_id,
            parent: parent.map(|parent| parent.span_id),
            client_span_id,
            sampled,
            continued: parent.is_some(),
            propagate: policy.propagates(),
            trace_state: parent.and_then(|_| context::tracestate(&request.headers)),
            record,
            upstream: None,
        })))
    }

    /// Writes the trace context into the request sent to the upstream: a `traceparent` whose span
    /// id is the upstream attempt's, and no `tracestate` unless the caller's trace is continued.
    ///
    /// # Errors
    ///
    /// When the header cannot be set.
    pub(crate) fn inject(&self, upstream_request: &mut RequestHeader) -> pingora::Result<()> {
        let Some(active) = self.0.as_deref() else {
            return Ok(());
        };
        if !active.propagate {
            return Ok(());
        }
        let value = context::format(active.trace_id, active.client_span_id, active.sampled);
        upstream_request.insert_header("traceparent", value)?;
        if !active.continued {
            upstream_request.remove_header("tracestate");
        }
        Ok(())
    }

    /// The request is about to be sent to an upstream: the upstream span starts, once, at the first
    /// attempt (a connection that fails still counts as an attempt).
    pub(crate) fn upstream_starting(&mut self) {
        if let Some(active) = self.0.as_deref_mut()
            && active.record.is_some()
            && active.upstream.is_none()
        {
            active.upstream = Some(Upstream {
                wall: SystemTime::now(),
                started: Instant::now(),
                ended: None,
                status: None,
            });
        }
    }

    /// The upstream sent a response with `status`.
    pub(crate) fn upstream_responded(&mut self, status: u16) {
        if let Some(upstream) = self.upstream_mut() {
            upstream.status = Some(status);
        }
    }

    /// The upstream's response body ended.
    pub(crate) fn upstream_done(&mut self) {
        if let Some(upstream) = self.upstream_mut()
            && upstream.ended.is_none()
        {
            upstream.ended = Some(Instant::now());
        }
    }

    fn upstream_mut(&mut self) -> Option<&mut Upstream> {
        self.0.as_deref_mut()?.upstream.as_mut()
    }

    /// Turns the request into spans and queues them. Does nothing for a request that was not
    /// sampled or whose node has no collector.
    pub(crate) fn finish(self, tracer: &Tracer, outcome: &Outcome<'_>) {
        let Some(active) = self.0 else { return };
        let Some(record) = &active.record else { return };
        let ended = Instant::now();
        let mut spans = Vec::with_capacity(2);
        spans.push(server_span(&active, record, outcome, ended));
        if let Some(upstream) = &active.upstream {
            spans.push(client_span(&active, upstream, outcome, ended));
        }
        tracer.submit(spans);
    }
}

fn take<const N: usize>(seed: &[u8; 36], at: usize) -> [u8; N] {
    let mut out = [0_u8; N];
    if let Some(source) = seed.get(at..at + N) {
        out.copy_from_slice(source);
    }
    out
}

/// Ids are never all zero; a zero draw (one in 2^64 at best) becomes a one.
fn nonzero<const N: usize>(mut id: [u8; N]) -> [u8; N] {
    if id == [0; N]
        && let Some(last) = id.last_mut()
    {
        *last = 1;
    }
    id
}

fn record(policy: &Policy, request: &RequestHeader, peer: IpAddr) -> Record {
    let headers = policy
        .headers()
        .iter()
        .filter_map(|name| {
            let values: Vec<Box<str>> = request
                .headers
                .get_all(name)
                .iter()
                .take(HEADER_VALUES_MAX)
                .map(|value| clip(&String::from_utf8_lossy(value.as_bytes())))
                .collect();
            (!values.is_empty()).then(|| (name.clone(), values))
        })
        .collect();
    Record {
        wall: SystemTime::now(),
        started: Instant::now(),
        method: clip(request.method.as_str()),
        path: clip(request.uri.path()),
        host: route::request_host(request).map(|host| clip(&host)),
        peer: (peer != client_ip::UNKNOWN).then_some(peer),
        headers,
    }
}

/// What the request turned out to be, for the span attributes: filled in `logging`.
#[derive(Debug, Default)]
pub(crate) struct Outcome<'a> {
    /// The status the client got; `None` when no response was written.
    pub(crate) status: Option<u16>,
    /// Whether Pingora ended the request with an error.
    pub(crate) failed: bool,
    pub(crate) tenant: Option<&'a str>,
    pub(crate) app: Option<&'a str>,
    pub(crate) router: Option<&'a str>,
    pub(crate) service: Option<&'a str>,
    pub(crate) revision: Option<&'a str>,
    /// The upstream server the request was sent to.
    pub(crate) server: Option<SocketAddr>,
}

fn unix_nanos(wall: SystemTime, after: Duration) -> u64 {
    let since = (wall + after)
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
}

fn text(key: &'static str, value: &str) -> (Cow<'static, str>, Value) {
    (Cow::Borrowed(key), Value::Str(clip(value)))
}

fn server_span(active: &Active, record: &Record, outcome: &Outcome<'_>, ended: Instant) -> Span {
    let mut attributes = vec![
        text("http.request.method", &record.method),
        text("url.path", &record.path),
    ];
    if let Some(status) = outcome.status {
        attributes.push((
            Cow::Borrowed("http.response.status_code"),
            Value::Int(i64::from(status)),
        ));
    }
    let optional = [
        ("server.address", record.host.as_deref()),
        ("podgate.tenant", outcome.tenant),
        ("podgate.app", outcome.app),
        ("podgate.router", outcome.router),
        ("podgate.service", outcome.service),
        ("podgate.revision", outcome.revision),
    ];
    for (key, value) in optional {
        if let Some(value) = value {
            attributes.push(text(key, value));
        }
    }
    if let Some(peer) = record.peer {
        attributes.push(text("network.peer.address", &peer.to_string()));
    }
    for (name, values) in &record.headers {
        attributes.push((
            Cow::Owned(format!("http.request.header.{name}")),
            Value::Strs(values.clone()),
        ));
    }
    let name = match outcome.router {
        Some(router) => format!("{} {router}", record.method),
        None => record.method.to_string(),
    };
    Span {
        trace_id: active.trace_id,
        span_id: active.span_id,
        parent: active.parent,
        trace_state: active.trace_state.clone(),
        name: name.into(),
        kind: Kind::Server,
        start_unix_nanos: unix_nanos(record.wall, Duration::ZERO),
        end_unix_nanos: unix_nanos(record.wall, ended.duration_since(record.started)),
        attributes,
        error: outcome
            .status
            .map_or(outcome.failed, |status| status >= 500),
    }
}

fn client_span(
    active: &Active,
    upstream: &Upstream,
    outcome: &Outcome<'_>,
    ended: Instant,
) -> Span {
    let method = active
        .record
        .as_ref()
        .map_or("", |record| record.method.as_ref());
    let mut attributes = vec![text("http.request.method", method)];
    if let Some(status) = upstream.status {
        attributes.push((
            Cow::Borrowed("http.response.status_code"),
            Value::Int(i64::from(status)),
        ));
    }
    if let Some(server) = outcome.server {
        attributes.push(text("server.address", &server.ip().to_string()));
        attributes.push((
            Cow::Borrowed("server.port"),
            Value::Int(i64::from(server.port())),
        ));
    }
    if let Some(revision) = outcome.revision {
        attributes.push(text("podgate.revision", revision));
    }
    let end = upstream.ended.unwrap_or(ended);
    Span {
        trace_id: active.trace_id,
        span_id: active.client_span_id,
        parent: Some(active.span_id),
        trace_state: active.trace_state.clone(),
        name: method.into(),
        kind: Kind::Client,
        start_unix_nanos: unix_nanos(upstream.wall, Duration::ZERO),
        end_unix_nanos: unix_nanos(upstream.wall, end.duration_since(upstream.started)),
        attributes,
        error: upstream
            .status
            .map_or(outcome.failed, |status| status >= 500),
    }
}

/// Starts tracing the request if its router is traced. Called from `request_filter` once a router
/// matched, before anything answers the request.
pub fn begin(tracer: &Tracer, session: &Session, ctx: &mut Ctx) {
    let Some(policy) = ctx.table.tracing(ctx.matched) else {
        return;
    };
    let tenant = ctx
        .matched
        .and_then(|matched| ctx.table.router(matched))
        .map_or("", |(app, _)| app.tenant());
    let peer = Peer {
        addr: ctx.forwarded.peer,
        trusted: ctx.forwarded.trusted,
        tenant,
    };
    let state = State::begin(tracer, policy, session.req_header(), peer);
    ctx.trace = state;
}

/// Ends the request's tracing and queues its spans. Called from `Gateway::logging`.
pub fn finish(tracer: &Tracer, session: &Session, error: Option<&Error>, ctx: &mut Ctx) {
    let trace = std::mem::take(&mut ctx.trace);
    if trace
        .0
        .as_ref()
        .is_none_or(|active| active.record.is_none())
    {
        return;
    }
    let (app, router) = ctx
        .matched
        .and_then(|matched| ctx.table.router(matched))
        .unzip();
    let revision = ctx
        .route
        .as_ref()
        .and_then(|selected| app?.revisions().get(selected.revision).map(|rev| rev.id()));
    let outcome = Outcome {
        status: session.response_written().map(|head| head.status.as_u16()),
        failed: error.is_some(),
        tenant: app.map(|app| app.tenant()),
        app: app.map(|app| app.id()),
        router: router.map(|router| router.name()),
        service: router.map(|router| router.service()),
        revision,
        server: ctx.route.as_ref().map(|selected| selected.upstream),
    };
    trace.finish(tracer, &outcome);
}
