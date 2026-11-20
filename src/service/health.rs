//! Active health checks: `health_check {path, interval_secs, timeout_secs, ...}` on a
//! `loadbalancer` makes podgate probe each of its declared servers from a background service and
//! write [`super::ServerState::healthy`], which every balancer already reads through
//! [`super::Server::available`].
//!
//! ```json
//! { "name": "web", "type": "loadbalancer",
//!   "health_check": { "path": "/healthz", "interval_secs": 5, "timeout_secs": 2,
//!                     "expect_status": [200, "300-399"], "unhealthy_threshold": 3 },
//!   "servers": [ { "url": "http://10.0.0.5:8080" }, { "url": "http://10.0.0.6:8080" } ] }
//! ```
//!
//! The reference for the fields, the limits and the semantics is `docs/ref/svc-health.md`.
//!
//! # Pieces
//!
//! - [`Check`]: the compiled `health_check` object, built by the load balancer's compile step
//!   (every problem is a `422`); it knows how to write the probe request and judge the response.
//! - [`Streak`]: the pass/fail state machine, pure code: consecutive results against the
//!   thresholds, no clock and no I/O.
//! - [`Scheduler`]: one tokio task per registered probe with an initial jitter, one global
//!   semaphore that caps probes in flight, a timeout around every probe and the write of the
//!   verdict into [`ServerState`]. It knows nothing about HTTP: [`Scheduler::register`] takes any
//!   async probe function, so the TCP checks of change 0095 use the same jitter, cap and state.
//! - [`HttpProbe`]: the HTTP/1.1 probe. It dials through Pingora's `TransportConnector` (the
//!   connect path of the proxy) and speaks HTTP/1.1 by hand over the stream, so it reads at most
//!   a fixed number of bytes and never follows a redirect.
//! - [`HealthService`]: the background service. It reconciles the scheduler with the live table
//!   at start and after every swap.
//!
//! # Where the state lives
//!
//! The flag a request reads is `ServerState::healthy`, which `super::state::Registry` carries
//! over a swap for every service whose declaration did not change. The *streak* (how many
//! consecutive results point the other way) lives in the scheduler, keyed by
//! `(owner, app, revision, service, server URL, fingerprint of the check)`: a push that leaves
//! the check alone keeps it, a changed check is a new key and starts fresh with a server that is
//! healthy until proven otherwise. When a push changes another part of the service (its
//! algorithm, say) the registry hands out a fresh `ServerState`; the scheduler writes its
//! verdict into it at the next [`Scheduler::register`], so the verdict survives that too.
//!
//! # Rules the probes obey
//!
//! - **Targets.** Only the declared servers: the address of the server, with `port` replacing its
//!   port when the check sets one. Nothing from a request, a response header or a redirect is
//!   ever dialled.
//! - **Policy.** [`HttpProbe::run`] calls [`UpstreamPolicy::check`] with the tenant and the exact
//!   IP it is about to dial, on every probe.
//! - **Bounds.** At most [`Config`](crate::Config)'s `HEALTH_MAX_CONCURRENT` probes run at once
//!   (64 by default); each has a timeout of `timeout_secs`; a response head is read up to
//!   [`MAX_HEAD_BYTES`] and a body up to [`MAX_BODY_BYTES`]. Probes are not requests: they take
//!   no tenant slot, no backend slot and are not counted in the outcomes auto-revert reads.
//! - **Transport.** [`Check::peer`] builds the `HttpPeer` from the service's transport
//!   ([`Upstream::peer`]): an `https://` server is probed over TLS with the SNI, trust anchors and
//!   client certificate its requests use, and `scheme` overrides the server's. The dialled IP is
//!   still checked against the upstream policy.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use http::{HeaderName, HeaderValue, Method};
use pingora::connectors::TransportConnector;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use pingora::upstreams::peer::HttpPeer;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use super::upstream_policy::UpstreamPolicy;
use super::{Server, ServerState, Service, Upstream};
use crate::compile::Invalid;
use crate::router::digest;
use crate::table::RoutingTable;
use podgate_model::RevisionState;

/// The most bytes of a response body a probe reads and matches `expect_body_regex` against.
pub const MAX_BODY_BYTES: usize = 4096;
/// The most bytes a probe reads to find the end of the response head; a longer head fails the
/// probe.
pub const MAX_HEAD_BYTES: usize = 8192;
/// How many probes run at once when `HEALTH_MAX_CONCURRENT` is not set.
pub const DEFAULT_MAX_CONCURRENT: usize = 64;
/// The most servers one service may declare: every one is a probe task and a connection a tenant
/// can make podgate open.
pub const MAX_SERVERS: usize = 256;

/// The `owner` of the probes this module registers; see [`Key::owner`].
const HTTP_OWNER: &str = "http";
/// One read of a response never asks for more than this many bytes.
const READ_CHUNK: usize = 2048;
const REGEX_SIZE_LIMIT: usize = 1 << 16;
const MAX_PATH_BYTES: usize = 2048;
const MAX_HEADERS: usize = 32;
const MAX_HEADER_VALUE_BYTES: usize = 1024;
const MAX_INTERVAL_SECS: u64 = 3600;
const MAX_TIMEOUT_SECS: u64 = 300;
const MAX_THRESHOLD: u32 = 100;
/// Headers a check may not set: the ones that frame the message or the connection (`hostname`
/// sets `Host`).
const FORBIDDEN_HEADERS: [&str; 10] = [
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "keep-alive",
    "proxy-connection",
];

/// The outcome of one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The server is fine.
    Pass,
    /// The server is not; the reason is for the log.
    Fail(Box<str>),
}

impl Verdict {
    fn fail(reason: impl Into<Box<str>>) -> Self {
        Self::Fail(reason.into())
    }
}

/// How often a server is probed and how many results flip its health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// Time from the end of one probe to the start of the next.
    pub interval: Duration,
    /// A probe that has not finished by then fails.
    pub timeout: Duration,
    /// Consecutive passes that mark a down server up.
    pub healthy_threshold: u32,
    /// Consecutive failures that mark an up server down.
    pub unhealthy_threshold: u32,
}

/// The pass/fail state machine of one server: pure code, no clock.
///
/// It starts healthy. The opposite result of the current state counts; any result that agrees
/// with the state resets the count, so thresholds are *consecutive* results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Streak {
    healthy: bool,
    run: u32,
}

impl Default for Streak {
    fn default() -> Self {
        Self::new()
    }
}

impl Streak {
    /// A server nobody has probed yet: healthy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            healthy: true,
            run: 0,
        }
    }

    /// The verdict so far.
    #[must_use]
    pub const fn healthy(self) -> bool {
        self.healthy
    }

    /// Takes one probe result. `Some(healthy)` when it flips the verdict.
    pub fn record(&mut self, pass: bool, schedule: &Schedule) -> Option<bool> {
        if pass == self.healthy {
            self.run = 0;
            return None;
        }
        self.run = self.run.saturating_add(1);
        let needed = if self.healthy {
            schedule.unhealthy_threshold
        } else {
            schedule.healthy_threshold
        };
        if self.run < needed {
            return None;
        }
        self.healthy = !self.healthy;
        self.run = 0;
        Some(self.healthy)
    }
}

/// An inclusive range of status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatusRange {
    low: u16,
    high: u16,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StatusSpec {
    Code(u16),
    Range(String),
}

impl StatusSpec {
    fn parse(&self) -> Result<StatusRange, String> {
        let bounds = |low: u16, high: u16| {
            if (100..=599).contains(&low) && (100..=599).contains(&high) && low <= high {
                Ok(StatusRange { low, high })
            } else {
                Err(format!("expect_status {self:?} is not within 100..=599"))
            }
        };
        match self {
            Self::Code(code) => bounds(*code, *code),
            Self::Range(text) => {
                let number = |part: &str| {
                    part.trim()
                        .parse::<u16>()
                        .map_err(|_| format!("expect_status {text:?} is not a code or low-high"))
                };
                match text.split_once('-') {
                    Some((low, high)) => bounds(number(low)?, number(high)?),
                    None => number(text).and_then(|code| bounds(code, code)),
                }
            }
        }
    }
}

/// The fields of a `health_check`, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    path: String,
    interval_secs: u64,
    timeout_secs: u64,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    expect_status: Option<Vec<StatusSpec>>,
    #[serde(default)]
    expect_body_regex: Option<String>,
    #[serde(default)]
    headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    healthy_threshold: Option<u32>,
    #[serde(default)]
    unhealthy_threshold: Option<u32>,
}

/// A compiled `health_check`.
#[derive(Debug)]
pub struct Check {
    path: Box<str>,
    method: Method,
    schedule: Schedule,
    statuses: Box<[StatusRange]>,
    body: Option<Regex>,
    headers: Box<[(HeaderName, HeaderValue)]>,
    host: Option<Box<str>>,
    port: Option<u16>,
    tls: Option<bool>,
    fingerprint: u64,
}

fn invalid(why: impl fmt::Display) -> Invalid {
    Invalid::new(
        "invalid_service",
        format!("loadbalancer health_check: {why}"),
    )
}

impl Check {
    /// Compiles the `health_check` object of a service.
    ///
    /// # Errors
    ///
    /// `invalid_service` for a field that is missing, unknown, out of range or malformed (a
    /// path that is not `/...`, a status outside `100..=599`, a header the check may not set,
    /// a body regex on a `HEAD` probe, a regex that is too large, an unknown `scheme`).
    pub fn compile(value: &Value) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(value.clone()).map_err(invalid)?;
        if !config.path.starts_with('/')
            || config.path.len() > MAX_PATH_BYTES
            || http::uri::PathAndQuery::from_str(&config.path).is_err()
        {
            return Err(invalid(format!(
                "path must be an origin-form path starting with /, at most {MAX_PATH_BYTES} bytes"
            )));
        }
        if !(1..=MAX_INTERVAL_SECS).contains(&config.interval_secs) {
            return Err(invalid(format!(
                "interval_secs must be in 1..={MAX_INTERVAL_SECS}"
            )));
        }
        if !(1..=MAX_TIMEOUT_SECS).contains(&config.timeout_secs) {
            return Err(invalid(format!(
                "timeout_secs must be in 1..={MAX_TIMEOUT_SECS}"
            )));
        }
        let threshold = |name: &str, value: Option<u32>| match value.unwrap_or(1) {
            count @ 1..=MAX_THRESHOLD => Ok(count),
            _ => Err(invalid(format!("{name} must be in 1..={MAX_THRESHOLD}"))),
        };
        let schedule = Schedule {
            interval: Duration::from_secs(config.interval_secs),
            timeout: Duration::from_secs(config.timeout_secs),
            healthy_threshold: threshold("healthy_threshold", config.healthy_threshold)?,
            unhealthy_threshold: threshold("unhealthy_threshold", config.unhealthy_threshold)?,
        };
        let method = match config.method.as_deref() {
            None => Method::GET,
            Some(name) => Method::from_bytes(name.as_bytes())
                .ok()
                .filter(|method| *method != Method::CONNECT)
                .ok_or_else(|| invalid(format!("method {name:?} is not an HTTP method")))?,
        };
        let tls = match config.scheme.as_deref() {
            None => None,
            Some("http") => Some(false),
            Some("https") => Some(true),
            Some(other) => {
                return Err(invalid(format!("scheme {other:?} is not http or https")));
            }
        };
        let statuses: Box<[StatusRange]> = match &config.expect_status {
            None => Box::new([StatusRange {
                low: 200,
                high: 399,
            }]),
            Some(list) if list.is_empty() => {
                return Err(invalid("expect_status is empty"));
            }
            Some(list) => list
                .iter()
                .map(StatusSpec::parse)
                .collect::<Result<_, _>>()
                .map_err(invalid)?,
        };
        let body = match &config.expect_body_regex {
            None => None,
            Some(_) if method == Method::HEAD => {
                return Err(invalid(
                    "expect_body_regex needs a method with a body, not HEAD",
                ));
            }
            Some(pattern) => Some(
                RegexBuilder::new(pattern)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .build()
                    .map_err(|err| invalid(format!("expect_body_regex: {err}")))?,
            ),
        };
        let headers = parse_headers(config.headers.as_ref())?;
        let host = config.hostname.as_deref().map(parse_hostname).transpose()?;
        if config.port == Some(0) {
            return Err(invalid("port must be in 1..=65535"));
        }
        Ok(Self {
            path: config.path.into(),
            method,
            schedule,
            statuses,
            body,
            headers,
            host,
            port: config.port,
            tls,
            fingerprint: digest(value.to_string()),
        })
    }

    /// How often servers are probed and how many results flip them.
    #[must_use]
    pub fn schedule(&self) -> Schedule {
        self.schedule
    }

    /// A digest of the check as declared: part of the key of the probe state, so a changed
    /// check starts fresh and an equal one keeps its streak.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// The address a probe of a server at `server` dials: the same IP, on `port` when the check
    /// sets one.
    #[must_use]
    pub fn target(&self, server: SocketAddr) -> SocketAddr {
        match self.port {
            Some(port) => SocketAddr::new(server.ip(), port),
            None => server,
        }
    }

    /// The peer a probe of `upstream` dials: its server's IP on `port` when the check sets one,
    /// over TLS when the server is `https://` (or `scheme` says so), with the transport of the
    /// service: the SNI, trust anchors and client certificate its requests use. Timeouts are
    /// the check's `timeout_secs`.
    #[must_use]
    pub fn peer(&self, upstream: Upstream<'_>) -> HttpPeer {
        let server = upstream.server;
        let probed = Server {
            url: Box::default(),
            addr: self.target(server.addr),
            tls: self.tls.unwrap_or(server.tls),
            weight: server.weight,
            state: Arc::clone(&server.state),
        };
        let mut peer = Upstream {
            server: &probed,
            transport: upstream.transport,
        }
        .peer();
        let timeout = self.schedule.timeout;
        peer.options.connection_timeout = Some(timeout);
        peer.options.read_timeout = Some(timeout);
        peer.options.write_timeout = Some(timeout);
        peer
    }

    /// The request bytes for a probe of `target`: `Host` is the check's `hostname`, else the
    /// address being probed.
    fn request(&self, target: SocketAddr) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(self.method.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        match &self.host {
            Some(host) => out.extend_from_slice(host.as_bytes()),
            None => out.extend_from_slice(target.to_string().as_bytes()),
        }
        out.extend_from_slice(b"\r\nConnection: close\r\n");
        let sets = |name: &str| self.headers.iter().any(|(set, _)| set == name);
        if !sets("user-agent") {
            out.extend_from_slice(b"User-Agent: podgate-health/1\r\n");
        }
        if !sets("accept") {
            out.extend_from_slice(b"Accept: */*\r\n");
        }
        if self.method != Method::GET
            && self.method != Method::HEAD
            && self.method != Method::OPTIONS
        {
            out.extend_from_slice(b"Content-Length: 0\r\n");
        }
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    fn accepts(&self, status: u16) -> bool {
        self.statuses
            .iter()
            .any(|range| (range.low..=range.high).contains(&status))
    }
}

fn parse_headers(
    headers: Option<&BTreeMap<String, String>>,
) -> Result<Box<[(HeaderName, HeaderValue)]>, Invalid> {
    let Some(headers) = headers else {
        return Ok(Box::default());
    };
    if headers.len() > MAX_HEADERS {
        return Err(invalid(format!("at most {MAX_HEADERS} headers")));
    }
    headers
        .iter()
        .map(|(name, value)| {
            let parsed = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| invalid(format!("header name {name:?} is not valid")))?;
            if FORBIDDEN_HEADERS.contains(&parsed.as_str()) {
                return Err(invalid(format!(
                    "header {name} cannot be set (use hostname for Host)"
                )));
            }
            if value.len() > MAX_HEADER_VALUE_BYTES {
                return Err(invalid(format!(
                    "the value of header {name} is over {MAX_HEADER_VALUE_BYTES} bytes"
                )));
            }
            let parsed_value = HeaderValue::from_str(value)
                .map_err(|_| invalid(format!("the value of header {name} is not valid")))?;
            Ok((parsed, parsed_value))
        })
        .collect()
}

fn parse_hostname(host: &str) -> Result<Box<str>, Invalid> {
    let plain = !host.is_empty()
        && host.len() <= 255
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        });
    if plain {
        Ok(host.into())
    } else {
        Err(invalid(format!(
            "hostname {host:?} is not a host name (letters, digits, . - _ and an optional :port)"
        )))
    }
}

/// How one HTTP response is judged: its head, then at most [`MAX_BODY_BYTES`] of its body.
struct Head {
    status: u16,
    chunked: bool,
    content_length: Option<usize>,
}

fn parse_head(head: &[u8]) -> Result<Head, Box<str>> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|code| (100..=999).contains(code));
    let (true, Some(status)) = (version.starts_with("HTTP/1."), status) else {
        return Err("the response is not HTTP/1.x".into());
    };
    let mut parsed = Head {
        status,
        chunked: false,
        content_length: None,
    };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            parsed.chunked = value.to_ascii_lowercase().contains("chunked");
        } else if name.eq_ignore_ascii_case("content-length") {
            parsed.content_length = value.parse().ok();
        }
    }
    Ok(parsed)
}

/// The data of the chunked body `raw` that has arrived, and whether its last chunk has.
fn dechunk(raw: &[u8]) -> (Vec<u8>, bool) {
    let mut data = Vec::new();
    let mut rest = raw;
    loop {
        let Some(line_end) = rest.windows(2).position(|pair| pair == b"\r\n") else {
            return (data, false);
        };
        let size_text = String::from_utf8_lossy(&rest[..line_end]);
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            return (data, true);
        };
        rest = &rest[line_end + 2..];
        if size == 0 {
            return (data, true);
        }
        if rest.len() < size {
            data.extend_from_slice(rest);
            return (data, false);
        }
        data.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
}

/// Sends `request` over `stream` and judges the response by `check`; also how many bytes of the
/// response were read. At most [`MAX_HEAD_BYTES`] bytes find the end of the head, and the body
/// part of what was read is never more than [`MAX_BODY_BYTES`].
async fn exchange<S>(stream: &mut S, request: &[u8], check: &Check) -> (Verdict, usize)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut read_total = 0;
    if let Err(err) = stream.write_all(request).await {
        return (Verdict::fail(format!("write: {err}")), read_total);
    }
    let mut buffer: Vec<u8> = Vec::with_capacity(READ_CHUNK);
    let mut chunk = [0_u8; READ_CHUNK];
    let head_end = loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        if buffer.len() >= MAX_HEAD_BYTES {
            return (
                Verdict::fail(format!("the response head is over {MAX_HEAD_BYTES} bytes")),
                read_total,
            );
        }
        let want = READ_CHUNK.min(MAX_HEAD_BYTES - buffer.len());
        match stream.read(&mut chunk[..want]).await {
            Ok(0) => {
                return (
                    Verdict::fail("the connection closed before the response head ended"),
                    read_total,
                );
            }
            Ok(read) => {
                read_total += read;
                buffer.extend_from_slice(&chunk[..read]);
            }
            Err(err) => return (Verdict::fail(format!("read: {err}")), read_total),
        }
    };
    let head = match parse_head(&buffer[..head_end]) {
        Ok(head) => head,
        Err(why) => return (Verdict::Fail(why), read_total),
    };
    if !check.accepts(head.status) {
        return (
            Verdict::fail(format!("status {} is not expected", head.status)),
            read_total,
        );
    }
    let Some(pattern) = &check.body else {
        return (Verdict::Pass, read_total);
    };
    let judge = |raw: &[u8]| {
        let body = if head.chunked {
            std::borrow::Cow::Owned(dechunk(raw).0)
        } else {
            std::borrow::Cow::Borrowed(raw)
        };
        let seen = &body[..body.len().min(MAX_BODY_BYTES)];
        if pattern.is_match(&String::from_utf8_lossy(seen)) {
            Verdict::Pass
        } else {
            Verdict::fail("the body does not match expect_body_regex")
        }
    };
    // What the head read already brought in counts, so the body never exceeds the cap.
    let mut raw = buffer.split_off(head_end);
    loop {
        let finished = if head.chunked {
            dechunk(&raw).1
        } else {
            head.content_length
                .is_some_and(|length| raw.len() >= length)
        };
        if finished || raw.len() >= MAX_BODY_BYTES {
            return (judge(&raw), read_total);
        }
        let want = READ_CHUNK.min(MAX_BODY_BYTES - raw.len());
        match stream.read(&mut chunk[..want]).await {
            Ok(0) => return (judge(&raw), read_total),
            Ok(read) => {
                read_total += read;
                raw.extend_from_slice(&chunk[..read]);
            }
            Err(err) => return (Verdict::fail(format!("read: {err}")), read_total),
        }
    }
}

/// The HTTP/1.1 probe of one server.
pub struct HttpProbe {
    check: Arc<Check>,
    tenant: Box<str>,
    peer: HttpPeer,
    policy: UpstreamPolicy,
    connector: Arc<TransportConnector>,
}

impl fmt::Debug for HttpProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProbe")
            .field("tenant", &self.tenant)
            .field("peer", &self.peer._address)
            .field("tls", &self.peer.is_tls())
            .finish_non_exhaustive()
    }
}

impl HttpProbe {
    /// A probe by `check` of the declared server that `peer` (from [`Check::peer`]) points at,
    /// for an app of `tenant`, subject to `policy`, dialling through `connector`.
    #[must_use]
    pub fn new(
        check: Arc<Check>,
        tenant: &str,
        peer: HttpPeer,
        policy: UpstreamPolicy,
        connector: Arc<TransportConnector>,
    ) -> Self {
        Self {
            check,
            tenant: tenant.into(),
            peer,
            policy,
            connector,
        }
    }

    /// A Pingora connector for probes. One is shared by every probe of a [`HealthService`].
    #[must_use]
    pub fn connector() -> Arc<TransportConnector> {
        Arc::new(TransportConnector::new(None))
    }

    /// Probes the server once. The caller bounds the time ([`Scheduler`] does).
    pub async fn run(&self) -> Verdict {
        let Some(target) = self.peer._address.as_inet().copied() else {
            return Verdict::fail("the probe target is not an IP address");
        };
        // The exact address about to be dialled, every time.
        if let Err(refused) = self.policy.check(&self.tenant, target.ip()) {
            return Verdict::fail(format!("refused by the upstream address policy: {refused}"));
        }
        let mut stream = match Box::pin(self.connector.new_stream(&self.peer)).await {
            Ok(stream) => stream,
            Err(err) => return Verdict::fail(format!("connect: {err}")),
        };
        exchange(&mut stream, &self.check.request(target), &self.check)
            .await
            .0
    }
}

/// Identifies one probed server in the [`Scheduler`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    /// Who registers it (`"http"` here, change 0095's TCP checks use their own): one owner never
    /// prunes another's probes, see [`Scheduler::retain`].
    pub owner: &'static str,
    /// The app.
    pub app: Box<str>,
    /// The revision that declares the service; `None` for a service the app shares.
    pub revision: Option<Box<str>>,
    /// The service name.
    pub service: Box<str>,
    /// The server URL as declared.
    pub server: Box<str>,
    /// A digest of the whole check: it must change whenever the schedule or the probe does.
    pub fingerprint: u64,
}

/// A probe function: each call is one probe of one server.
pub type ProbeFn = Arc<dyn Fn() -> ProbeFuture + Send + Sync>;
/// What a [`ProbeFn`] returns.
pub type ProbeFuture = Pin<Box<dyn Future<Output = Verdict> + Send>>;

struct Live {
    state: Arc<ServerState>,
    probe: ProbeFn,
    streak: Streak,
}

struct Entry {
    live: Arc<Mutex<Live>>,
    task: JoinHandle<()>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Inner {
    permits: Arc<Semaphore>,
    entries: Mutex<HashMap<Key, Entry>>,
}

/// Runs probes: one task per registered server, a global cap on probes in flight, the streak
/// state machine and the write of the verdict.
///
/// Cheap to clone; clones share everything. Dropping the last clone aborts every probe task.
#[derive(Clone)]
pub struct Scheduler {
    inner: Arc<Inner>,
}

impl fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scheduler")
            .field("probes", &self.len())
            .finish_non_exhaustive()
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Scheduler {
    /// A scheduler that runs at most `max_concurrent` probes at once, across everything
    /// registered with it.
    #[must_use]
    pub fn new(max_concurrent: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(Inner {
                permits: Arc::new(Semaphore::new(max_concurrent.get())),
                entries: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// How many probes are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        locked(&self.inner.entries).len()
    }

    /// Whether no probe is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Registers the probe of one server, or refreshes it.
    ///
    /// New `key`: a task starts that waits a jitter (a fraction of the shorter of the interval
    /// and the timeout, taken from the key), then probes with `probe` forever: wait for a free
    /// permit, run it for at most `schedule.timeout`, record the result in a [`Streak`], write
    /// `healthy` into `state` when the verdict flips, sleep `schedule.interval`. A server starts
    /// healthy.
    ///
    /// Known `key`: its streak and timing are kept. `probe` replaces the old function, and when
    /// `state` is another `Arc` than the registered one (a push changed something else about the
    /// service) the verdict so far is written into it. `schedule` is not read again: the key's
    /// fingerprint stands for it.
    ///
    /// # Panics
    ///
    /// When called outside a tokio runtime and `key` is new.
    pub fn register(&self, key: Key, schedule: Schedule, state: Arc<ServerState>, probe: ProbeFn) {
        let mut entries = locked(&self.inner.entries);
        if let Some(entry) = entries.get(&key) {
            let mut live = locked(&entry.live);
            live.probe = probe;
            if !Arc::ptr_eq(&live.state, &state) {
                state
                    .healthy
                    .store(live.streak.healthy(), Ordering::Relaxed);
                live.state = state;
            }
            return;
        }
        let window = schedule.timeout.min(schedule.interval);
        let jitter = window * u32::try_from(digest(&key) % 1000).unwrap_or(0) / 1000;
        let live = Arc::new(Mutex::new(Live {
            state,
            probe,
            streak: Streak::new(),
        }));
        let task = tokio::spawn(drive(
            Arc::clone(&self.inner.permits),
            Arc::clone(&live),
            schedule,
            jitter,
            key.clone(),
        ));
        entries.insert(key, Entry { live, task });
    }

    /// Stops the probes of `owner` whose key `keep` refuses. Another owner's probes stay.
    pub fn retain(&self, owner: &'static str, mut keep: impl FnMut(&Key) -> bool) {
        locked(&self.inner.entries).retain(|key, _| key.owner != owner || keep(key));
    }
}

async fn drive(
    permits: Arc<Semaphore>,
    live: Arc<Mutex<Live>>,
    schedule: Schedule,
    first: Duration,
    key: Key,
) {
    sleep(first).await;
    loop {
        let probe = Arc::clone(&locked(&live).probe);
        let verdict = {
            let Ok(_permit) = permits.acquire().await else {
                return;
            };
            match timeout(schedule.timeout, probe()).await {
                Ok(verdict) => verdict,
                Err(_) => Verdict::fail("the probe timed out"),
            }
        };
        {
            let mut live = locked(&live);
            let pass = verdict == Verdict::Pass;
            if let Some(healthy) = live.streak.record(pass, &schedule) {
                live.state.healthy.store(healthy, Ordering::Relaxed);
                let reason = match &verdict {
                    Verdict::Pass => "passed",
                    Verdict::Fail(reason) => &**reason,
                };
                tracing::warn!(
                    app = &*key.app,
                    service = &*key.service,
                    server = &*key.server,
                    healthy,
                    reason,
                    "server health changed"
                );
            }
        }
        sleep(schedule.interval).await;
    }
}

/// Probes the servers of the live table, as a Pingora background service.
pub struct HealthService {
    table: crate::TableHandle,
    scheduler: Scheduler,
    policy: UpstreamPolicy,
    connector: Arc<TransportConnector>,
}

impl fmt::Debug for HealthService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthService")
            .field("scheduler", &self.scheduler)
            .finish_non_exhaustive()
    }
}

impl HealthService {
    /// Probes the services of `table`, never more than `max_concurrent` probes at once, every
    /// connection checked by `policy`.
    #[must_use]
    pub fn new(
        table: crate::TableHandle,
        policy: UpstreamPolicy,
        max_concurrent: NonZeroUsize,
    ) -> Self {
        Self {
            table,
            scheduler: Scheduler::new(max_concurrent),
            policy,
            connector: HttpProbe::connector(),
        }
    }

    /// The scheduler, for the registrars that share its cap.
    #[must_use]
    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// Makes the registered HTTP probes those `table` calls for: one per server of every service
    /// with a `health_check`, except in `draining` revisions (they take no new requests).
    /// Probes of servers that are gone stop.
    pub fn reconcile(&self, table: &RoutingTable) {
        let mut wanted: HashSet<Key> = HashSet::new();
        for app in table.apps() {
            let shared = app.services().iter().map(|named| (None, named));
            let own = app
                .revisions()
                .iter()
                .filter(|revision| revision.state() != RevisionState::Draining)
                .flat_map(|revision| {
                    revision
                        .services()
                        .iter()
                        .map(move |named| (Some(revision.id()), named))
                });
            for (revision, named) in shared.chain(own) {
                let Service::LoadBalancer(balancer) = &named.service else {
                    continue;
                };
                let Some(check) = balancer.health_check() else {
                    continue;
                };
                for server in balancer.servers() {
                    let Some(upstream) = balancer.upstream(server.addr) else {
                        continue;
                    };
                    let key = Key {
                        owner: HTTP_OWNER,
                        app: app.id().into(),
                        revision: revision.map(Into::into),
                        service: named.name.clone(),
                        server: server.url.clone(),
                        fingerprint: check.fingerprint(),
                    };
                    wanted.insert(key.clone());
                    self.scheduler.register(
                        key,
                        check.schedule(),
                        Arc::clone(&server.state),
                        self.probe_of(check, app.tenant(), upstream),
                    );
                }
            }
        }
        self.scheduler
            .retain(HTTP_OWNER, |key| wanted.contains(key));
    }

    fn probe_of(&self, check: &Arc<Check>, tenant: &str, upstream: Upstream<'_>) -> ProbeFn {
        let probe = Arc::new(HttpProbe::new(
            Arc::clone(check),
            tenant,
            check.peer(upstream),
            self.policy.clone(),
            Arc::clone(&self.connector),
        ));
        Arc::new(move || {
            let probe = Arc::clone(&probe);
            Box::pin(async move { probe.run().await })
        })
    }
}

#[async_trait]
impl BackgroundService for HealthService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // Subscribed before the first load: a swap in between is seen by `changed`.
        let mut swaps = self.table.subscribe();
        loop {
            self.reconcile(&self.table.load());
            tokio::select! {
                changed = swaps.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
        self.scheduler.retain(HTTP_OWNER, |_| false);
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use serde_json::json;
    use tokio::io::duplex;

    use super::*;

    fn schedule(healthy: u32, unhealthy: u32) -> Schedule {
        Schedule {
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(200),
            healthy_threshold: healthy,
            unhealthy_threshold: unhealthy,
        }
    }

    fn check(extra: &Value) -> Check {
        let mut value = json!({ "path": "/h", "interval_secs": 1, "timeout_secs": 1 });
        value
            .as_object_mut()
            .expect("object")
            .extend(extra.as_object().expect("object").clone());
        Check::compile(&value).expect("compiles")
    }

    fn refused(extra: &Value) -> Invalid {
        let mut value = json!({ "path": "/h", "interval_secs": 1, "timeout_secs": 1 });
        value
            .as_object_mut()
            .expect("object")
            .extend(extra.as_object().expect("object").clone());
        Check::compile(&value).expect_err("refused")
    }

    #[test]
    fn streak_flips_after_the_thresholds_of_consecutive_results() {
        let mut streak = Streak::new();
        let rule = schedule(2, 3);
        assert!(streak.healthy());
        assert_eq!(streak.record(false, &rule), None);
        assert_eq!(streak.record(false, &rule), None);
        assert_eq!(
            streak.record(true, &rule),
            None,
            "a pass resets the failures"
        );
        assert_eq!(streak.record(false, &rule), None);
        assert_eq!(streak.record(false, &rule), None);
        assert_eq!(streak.record(false, &rule), Some(false));
        assert!(!streak.healthy());
        assert_eq!(streak.record(true, &rule), None);
        assert_eq!(
            streak.record(false, &rule),
            None,
            "a failure resets the passes"
        );
        assert_eq!(streak.record(true, &rule), None);
        assert_eq!(streak.record(true, &rule), Some(true));
        assert!(streak.healthy());
    }

    #[test]
    fn check_defaults_and_fingerprint() {
        let one = check(&json!({}));
        assert_eq!(one.schedule().healthy_threshold, 1);
        assert_eq!(one.schedule().unhealthy_threshold, 1);
        assert!(one.accepts(200) && one.accepts(399));
        assert!(!one.accepts(199) && !one.accepts(400) && !one.accepts(503));
        assert_eq!(one.fingerprint(), check(&json!({})).fingerprint());
        assert_ne!(
            one.fingerprint(),
            check(&json!({ "path": "/other" })).fingerprint()
        );
        let target: SocketAddr = ([10, 0, 0, 5], 8080).into();
        assert_eq!(one.target(target), target);
        assert_eq!(
            check(&json!({ "port": 9000 })).target(target),
            SocketAddr::from(([10, 0, 0, 5], 9000))
        );
    }

    #[test]
    fn check_refuses_what_it_cannot_honour() {
        let cases = [
            json!({ "path": "healthz" }),
            json!({ "path": "/a b" }),
            json!({ "interval_secs": 0 }),
            json!({ "timeout_secs": 301 }),
            json!({ "healthy_threshold": 0 }),
            json!({ "unhealthy_threshold": 101 }),
            json!({ "method": "GE T" }),
            json!({ "method": "CONNECT" }),
            json!({ "expect_status": [] }),
            json!({ "expect_status": [99] }),
            json!({ "expect_status": ["300-200"] }),
            json!({ "expect_status": ["ok"] }),
            json!({ "expect_body_regex": "(" }),
            json!({ "method": "HEAD", "expect_body_regex": "ok" }),
            json!({ "headers": { "Host": "x" } }),
            json!({ "headers": { "Content-Length": "5" } }),
            json!({ "headers": { "X-A": "a\r\nInjected: 1" } }),
            json!({ "hostname": "a b" }),
            json!({ "hostname": "a\r\nb" }),
            json!({ "port": 0 }),
            json!({ "scheme": "ftp" }),
            json!({ "nope": 1 }),
        ];
        for case in cases {
            assert_eq!(refused(&case).code, "invalid_service", "{case}");
        }
        for missing in ["path", "interval_secs", "timeout_secs"] {
            let mut value = json!({ "path": "/h", "interval_secs": 1, "timeout_secs": 1 });
            value.as_object_mut().expect("object").remove(missing);
            assert_eq!(
                Check::compile(&value).expect_err("required").code,
                "invalid_service",
                "{missing}"
            );
        }
    }

    #[test]
    fn the_request_carries_method_host_and_headers() {
        let target: SocketAddr = ([10, 0, 0, 5], 8080).into();
        let default =
            String::from_utf8(check(&json!({ "path": "/p?x=1" })).request(target)).expect("ascii");
        assert!(default.starts_with("GET /p?x=1 HTTP/1.1\r\nHost: 10.0.0.5:8080\r\n"));
        assert!(default.contains("Connection: close\r\n") && default.ends_with("\r\n\r\n"));
        let custom = String::from_utf8(
            check(&json!({
                "method": "POST", "hostname": "app.internal",
                "headers": { "X-Probe": "yes", "User-Agent": "mine" },
            }))
            .request(target),
        )
        .expect("ascii");
        assert!(custom.starts_with("POST /h HTTP/1.1\r\nHost: app.internal\r\n"));
        assert!(custom.contains("x-probe: yes\r\n") && custom.contains("user-agent: mine\r\n"));
        assert!(!custom.contains("podgate-health"));
        assert!(custom.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn dechunk_reads_what_arrived() {
        assert_eq!(
            dechunk(b"5\r\nhello\r\n4;x=1\r\n abc\r\n0\r\n\r\n"),
            (b"hello abc".to_vec(), true)
        );
        assert_eq!(dechunk(b"5\r\nhey"), (b"hey".to_vec(), false));
        assert_eq!(dechunk(b"5\r\nhello\r\n"), (b"hello".to_vec(), false));
        assert_eq!(dechunk(b""), (Vec::new(), false));
        assert_eq!(
            dechunk(b"zz\r\n"),
            (Vec::new(), true),
            "garbage ends the body"
        );
    }

    /// Runs `exchange` against a server that answers `response` and keeps the connection open
    /// after it, like a server that ignores `Connection: close`.
    async fn answered(check: &Check, response: Vec<u8>) -> (Verdict, usize) {
        let (mut client, mut server) = duplex(1 << 20);
        tokio::spawn(async move {
            let mut request = [0_u8; 1024];
            let _ = server.read(&mut request).await;
            let _ = server.write_all(&response).await;
            // Held open until the test ends: the probe must not wait for EOF.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(server);
        });
        let request = check.request(([127, 0, 0, 1], 1).into());
        timeout(
            Duration::from_secs(5),
            exchange(&mut client, &request, check),
        )
        .await
        .expect("the probe finishes without the server closing")
    }

    #[tokio::test]
    async fn exchange_judges_the_status_and_stops_at_the_head() {
        let plain = check(&json!({}));
        let (verdict, read) = answered(&plain, b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()).await;
        assert_eq!(verdict, Verdict::Pass);
        assert_eq!(read, 27);
        let (verdict, _) = answered(&plain, b"HTTP/1.1 503 Unavailable\r\n\r\n".to_vec()).await;
        assert!(matches!(verdict, Verdict::Fail(_)));
        let (verdict, _) = answered(&plain, b"SSH-2.0-OpenSSH\r\n\r\n".to_vec()).await;
        assert!(matches!(verdict, Verdict::Fail(_)), "not HTTP");
    }

    #[tokio::test]
    async fn exchange_reads_a_capped_body_for_the_regex() {
        let ready = check(&json!({ "expect_body_regex": "ready" }));
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nall ready :)".to_vec();
        assert_eq!(answered(&ready, ok).await.0, Verdict::Pass);
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nall\r\n6\r\n ready\r\n0\r\n\r\n"
            .to_vec();
        assert_eq!(answered(&ready, chunked).await.0, Verdict::Pass);
        let wrong = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndown".to_vec();
        assert!(matches!(answered(&ready, wrong).await.0, Verdict::Fail(_)));

        // The word is past the cap: it is never read, so the probe fails, and it reads no more
        // than the head and the capped body.
        let head = b"HTTP/1.1 200 OK\r\n\r\n";
        let mut late = head.to_vec();
        late.extend(std::iter::repeat_n(b'a', 64 * 1024));
        late.extend_from_slice(b"ready");
        let (verdict, read) = answered(&ready, late).await;
        assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
        assert!(
            read <= head.len() + MAX_BODY_BYTES,
            "read {read} bytes, the cap is {}",
            head.len() + MAX_BODY_BYTES
        );
        // A match inside the cap passes however much follows.
        let mut early = head.to_vec();
        early.extend_from_slice(b"ready");
        early.extend(std::iter::repeat_n(b'a', 64 * 1024));
        let (verdict, read) = answered(&ready, early).await;
        assert_eq!(verdict, Verdict::Pass);
        assert!(read <= head.len() + MAX_BODY_BYTES, "{read}");
    }

    #[tokio::test]
    async fn exchange_refuses_a_head_that_never_ends() {
        let plain = check(&json!({}));
        let mut endless = b"HTTP/1.1 200 OK\r\n".to_vec();
        endless.extend(std::iter::repeat_n(b'x', 64 * 1024));
        let (verdict, read) = answered(&plain, endless).await;
        assert!(matches!(verdict, Verdict::Fail(_)));
        assert!(read <= MAX_HEAD_BYTES, "read {read}");
    }

    async fn settle(condition: impl Fn() -> bool) -> bool {
        for _ in 0..200 {
            if condition() {
                return true;
            }
            sleep(Duration::from_millis(10)).await;
        }
        condition()
    }

    fn key(service: &str, fingerprint: u64) -> Key {
        Key {
            owner: "test",
            app: "a".into(),
            revision: Some("r".into()),
            service: service.into(),
            server: "http://127.0.0.1:1".into(),
            fingerprint,
        }
    }

    fn flipping(pass: &Arc<AtomicBool>, runs: &Arc<AtomicUsize>) -> ProbeFn {
        let (pass, runs) = (Arc::clone(pass), Arc::clone(runs));
        Arc::new(move || {
            let (pass, runs) = (Arc::clone(&pass), Arc::clone(&runs));
            Box::pin(async move {
                runs.fetch_add(1, Ordering::Relaxed);
                if pass.load(Ordering::Relaxed) {
                    Verdict::Pass
                } else {
                    Verdict::fail("down")
                }
            })
        })
    }

    #[tokio::test]
    async fn scheduler_writes_the_verdict_and_keeps_it_across_a_new_state() {
        let scheduler = Scheduler::new(NonZeroUsize::MIN);
        let (pass, runs) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicUsize::new(0)),
        );
        let state = Arc::new(ServerState::default());
        scheduler.register(
            key("web", 1),
            schedule(2, 2),
            Arc::clone(&state),
            flipping(&pass, &runs),
        );
        assert!(
            state.healthy.load(Ordering::Relaxed),
            "a server starts healthy"
        );
        assert!(
            settle(|| !state.healthy.load(Ordering::Relaxed)).await,
            "marked down"
        );
        pass.store(true, Ordering::Relaxed);
        assert!(
            settle(|| state.healthy.load(Ordering::Relaxed)).await,
            "marked up again"
        );
        pass.store(false, Ordering::Relaxed);
        assert!(settle(|| !state.healthy.load(Ordering::Relaxed)).await);

        // The same key with a fresh state (a push changed another part of the service): the
        // verdict is written into it, the streak is the same task's.
        let fresh = Arc::new(ServerState::default());
        scheduler.register(
            key("web", 1),
            schedule(2, 2),
            Arc::clone(&fresh),
            flipping(&pass, &runs),
        );
        assert!(!fresh.healthy.load(Ordering::Relaxed));
        assert_eq!(scheduler.len(), 1);
        // A changed check is another key: a new task, healthy until it fails.
        let other = Arc::new(ServerState::default());
        scheduler.register(
            key("web", 2),
            schedule(2, 2),
            Arc::clone(&other),
            flipping(&pass, &runs),
        );
        assert!(other.healthy.load(Ordering::Relaxed));
        assert_eq!(scheduler.len(), 2);
        // Retain prunes its owner only.
        scheduler.retain("someone else", |_| false);
        assert_eq!(scheduler.len(), 2);
        scheduler.retain("test", |key| key.fingerprint == 2);
        assert_eq!(scheduler.len(), 1);
        scheduler.retain("test", |_| false);
        assert!(scheduler.is_empty());
        let after = runs.load(Ordering::Relaxed);
        sleep(Duration::from_millis(100)).await;
        assert_eq!(
            runs.load(Ordering::Relaxed),
            after,
            "stopped probes stop probing"
        );
    }

    #[tokio::test]
    async fn scheduler_times_a_probe_out_and_caps_probes_in_flight() {
        let scheduler = Scheduler::new(NonZeroUsize::new(2).expect("two"));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let hanging: ProbeFn = {
            let (running, peak) = (Arc::clone(&running), Arc::clone(&peak));
            Arc::new(move || {
                let (running, peak) = (Arc::clone(&running), Arc::clone(&peak));
                Box::pin(async move {
                    struct Running(Arc<AtomicUsize>);
                    impl Drop for Running {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::SeqCst);
                        }
                    }
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    let _counted = Running(running);
                    peak.fetch_max(now, Ordering::SeqCst);
                    sleep(Duration::from_secs(60)).await;
                    Verdict::Pass
                })
            })
        };
        let rule = Schedule {
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(60),
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };
        let states: Vec<_> = (0..8).map(|_| Arc::new(ServerState::default())).collect();
        for (index, state) in states.iter().enumerate() {
            scheduler.register(
                key(&format!("s{index}"), 1),
                rule,
                Arc::clone(state),
                Arc::clone(&hanging),
            );
        }
        // A probe that hangs fails after its timeout, so every server ends up down, two at a time.
        assert!(
            settle(|| states
                .iter()
                .all(|state| !state.healthy.load(Ordering::Relaxed)))
            .await,
            "every hanging probe times out"
        );
        assert_eq!(
            peak.load(Ordering::SeqCst),
            2,
            "never more than the cap, and the cap is used"
        );
    }
}
