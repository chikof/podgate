//! What bounds the HTTP/3 front: the operator's settings, the memory a QUIC connection may hold,
//! the counters of connections and handshakes, the stream-reset limit, and the metrics.
//!
//! Everything here is fixed before a packet is read. The transport configuration derives its
//! windows from [`Settings`], the tenant is charged [`Settings::reservation`] for the life of a
//! connection, and nothing a peer sends changes either.
//!
//! The metrics have fixed label sets, never a tenant, a host or an address, so a remote party
//! cannot grow the series:
//!
//! - `podgate_h3_connections` and `podgate_h3_handshakes`: QUIC connections open and handshakes
//!   in flight now.
//! - `podgate_h3_refused_total{reason}`: connections turned away before a tenant was known or
//!   when its budget was full.
//! - `podgate_h3_handshake_refused_total{reason}`: handshakes the certificate resolver refused.
//! - `podgate_h3_retries_total`: retry tokens demanded of unvalidated clients.
//! - `podgate_h3_closed_total{reason}`: connections podgate closed for abuse.
//! - `podgate_h3_requests_total`: requests bridged to the pipeline.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::config::ConfigError;

/// Connections the node serves at once unless `H3_MAX_CONNECTIONS` says otherwise.
const DEFAULT_MAX_CONNECTIONS: u32 = 10_000;
/// QUIC handshakes in flight unless `H3_MAX_HANDSHAKES` says otherwise.
const DEFAULT_MAX_HANDSHAKES: u32 = 256;
/// Request streams a client may have open on one connection unless `H3_MAX_STREAMS` says
/// otherwise.
const DEFAULT_MAX_STREAMS: u32 = 100;
/// The connection receive and send window unless `H3_CONNECTION_WINDOW` says otherwise.
const DEFAULT_CONNECTION_WINDOW: u32 = 256 * 1024;
/// The UDP socket's receive buffer unless `H3_UDP_RECV_BUFFER` says otherwise.
const DEFAULT_UDP_RECV_BUFFER: u32 = 2 * 1024 * 1024;

/// Unidirectional streams a client may open: its control stream and the two QPACK streams.
pub(crate) const UNI_STREAMS: u32 = 3;
/// A connection with no traffic for this long is closed; keep-alive is off.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest header section a request may carry (`SETTINGS_MAX_FIELD_SECTION_SIZE`). The
/// `h3` crate decodes QPACK statelessly: it advertises a dynamic table capacity of 0 and no
/// blocked streams, stricter than the 4096 bytes and 16 streams podgate would allow, so no
/// request can name a table entry.
pub(crate) const MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;
/// More stream resets than this in one second close the connection.
pub(crate) const RESETS_PER_SECOND: u32 = 200;
/// The HTTP/2 flow control window of the internal connection, per connection and per stream: the
/// most response or request bytes the bridge holds for one QUIC connection while it moves them.
pub(crate) const INTERNAL_WINDOW: u32 = 65_535;
/// How long a client has to finish the QUIC and TLS handshake.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// `H3_NO_ERROR` (RFC 9114 section 8.1): the code of an orderly close.
pub(crate) const H3_NO_ERROR: u32 = 0x100;
/// `H3_EXCESSIVE_LOAD`: the code podgate closes a connection with when its peer asks for more
/// than its tenant's budget or the node's limits give.
pub(crate) const H3_EXCESSIVE_LOAD: u32 = 0x107;

const MIN_WINDOW: u32 = 128 * 1024;
const MAX_WINDOW: u32 = 16 * 1024 * 1024;
const MIN_RECV_BUFFER: u32 = 64 * 1024;
const MAX_RECV_BUFFER: u32 = 256 * 1024 * 1024;

/// Whether a new connection must prove its address with a retry token before the handshake
/// costs anything (`H3_RETRY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Every client with an unvalidated address.
    Always,
    /// Only while the handshake or connection counts are high.
    OnLoad,
    /// Never: the amplification limit alone protects a spoofed address.
    Never,
}

/// The operator's HTTP/3 settings (`H3_*`), read once at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Connections served at once, handshakes included (`H3_MAX_CONNECTIONS`).
    pub max_connections: u32,
    /// Handshakes in flight at once (`H3_MAX_HANDSHAKES`).
    pub max_handshakes: u32,
    /// When a retry token is demanded (`H3_RETRY`).
    pub retry: Retry,
    /// Bytes of kernel receive buffer asked for the UDP socket (`H3_UDP_RECV_BUFFER`).
    pub udp_recv_buffer: u32,
    /// Request streams open at once on one connection (`H3_MAX_STREAMS`).
    pub max_streams: u32,
    /// The connection's receive window and its send window (`H3_CONNECTION_WINDOW`).
    pub connection_window: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_handshakes: DEFAULT_MAX_HANDSHAKES,
            retry: Retry::OnLoad,
            udp_recv_buffer: DEFAULT_UDP_RECV_BUFFER,
            max_streams: DEFAULT_MAX_STREAMS,
            connection_window: DEFAULT_CONNECTION_WINDOW,
        }
    }
}

fn number(
    lookup: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    range: std::ops::RangeInclusive<u32>,
    into: &mut u32,
) -> Result<(), ConfigError> {
    let Some(raw) = lookup(var) else {
        return Ok(());
    };
    *into = raw
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|value| range.contains(value))
        .ok_or_else(|| ConfigError {
            var,
            reason: format!(
                "{raw:?} is not a whole number in {}..={}",
                range.start(),
                range.end()
            )
            .into(),
        })?;
    Ok(())
}

impl Settings {
    /// Reads the `H3_*` variables through `lookup`; unset ones keep their default.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first variable that is set but not a whole number in its range,
    /// or an `H3_RETRY` other than `always`, `on_load` or `never`.
    pub fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut settings = Self::default();
        number(
            lookup,
            "H3_MAX_CONNECTIONS",
            1..=1_000_000,
            &mut settings.max_connections,
        )?;
        number(
            lookup,
            "H3_MAX_HANDSHAKES",
            1..=65_536,
            &mut settings.max_handshakes,
        )?;
        number(
            lookup,
            "H3_UDP_RECV_BUFFER",
            MIN_RECV_BUFFER..=MAX_RECV_BUFFER,
            &mut settings.udp_recv_buffer,
        )?;
        number(
            lookup,
            "H3_MAX_STREAMS",
            1..=1000,
            &mut settings.max_streams,
        )?;
        number(
            lookup,
            "H3_CONNECTION_WINDOW",
            MIN_WINDOW..=MAX_WINDOW,
            &mut settings.connection_window,
        )?;
        if let Some(raw) = lookup("H3_RETRY") {
            settings.retry = match raw.trim().to_ascii_lowercase().as_str() {
                "always" => Retry::Always,
                "on_load" => Retry::OnLoad,
                "never" => Retry::Never,
                _ => {
                    return Err(ConfigError {
                        var: "H3_RETRY",
                        reason: format!("{raw:?} is not always, on_load or never").into(),
                    });
                }
            };
        }
        Ok(settings)
    }

    /// The most bytes one QUIC connection can hold in the process: its receive window, its send
    /// window, and the HTTP/2 window of the internal connection it is bridged over. It is what a
    /// tenant is charged for each of its connections, from the handshake to the close, and what
    /// the total of `H3_MAX_CONNECTIONS` connections is made of.
    #[must_use]
    pub fn reservation(&self) -> u64 {
        2 * u64::from(self.connection_window) + u64::from(INTERNAL_WINDOW)
    }

    /// The receive window of one stream: half the connection's, never under a header section.
    #[must_use]
    pub fn stream_window(&self) -> u32 {
        self.connection_window / 2
    }

    /// Whether a client whose address is not validated must send a retry token now, given the
    /// handshakes and connections in progress.
    #[must_use]
    pub fn demands_retry(&self, handshakes: u32, connections: u32) -> bool {
        match self.retry {
            Retry::Always => true,
            Retry::Never => false,
            Retry::OnLoad => {
                u64::from(handshakes) * 2 >= u64::from(self.max_handshakes)
                    || u64::from(connections) * 5 >= u64::from(self.max_connections) * 4
            }
        }
    }
}

/// A count of what the node holds now, whose increments are returned when the [`Held`] guard
/// drops. The two the front caps (connections and handshakes) are process-wide statics, since
/// the caps are the node's, whatever the number of HTTP/3 entry points.
#[derive(Debug, Default)]
pub(crate) struct Counter(AtomicU32);

/// Connections open now, handshakes in progress included.
pub(crate) static CONNECTIONS: Counter = Counter::new();
/// Handshakes in flight now.
pub(crate) static HANDSHAKES: Counter = Counter::new();

impl Counter {
    const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    /// The count now.
    pub(crate) fn load(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    /// Counts one more until the guard drops.
    #[must_use]
    pub(crate) fn take(&'static self) -> Held {
        self.0.fetch_add(1, Ordering::Relaxed);
        Held(self)
    }
}

/// One unit of a [`Counter`].
#[derive(Debug)]
pub(crate) struct Held(&'static Counter);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counts the stream resets of one connection in a window of one second.
#[derive(Debug)]
pub(crate) struct ResetWindow {
    started: Instant,
    seen: u32,
}

impl ResetWindow {
    /// An empty window starting at `now`.
    #[must_use]
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            started: now,
            seen: 0,
        }
    }

    /// Counts a reset at `now`; `true` when this second has passed [`RESETS_PER_SECOND`].
    pub(crate) fn record(&mut self, now: Instant) -> bool {
        if now.duration_since(self.started) >= Duration::from_secs(1) {
            self.started = now;
            self.seen = 0;
        }
        self.seen = self.seen.saturating_add(1);
        self.seen > RESETS_PER_SECOND
    }
}

/// Why a connection was turned away before the handshake or right after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// The node holds `H3_MAX_CONNECTIONS`.
    ConnectionCap,
    /// The node has `H3_MAX_HANDSHAKES` in flight.
    HandshakeCap,
    /// The tenant's `max_buffer_bytes` cannot take another connection.
    OverBudget,
    /// The connection arrived without a name that an app claims.
    NoTenant,
}

const REFUSED: [(Refused, &str); 4] = [
    (Refused::ConnectionCap, "connection_cap"),
    (Refused::HandshakeCap, "handshake_cap"),
    (Refused::OverBudget, "over_budget"),
    (Refused::NoTenant, "no_tenant"),
];

/// Why the certificate resolver refused a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Declined {
    /// The ClientHello has no server name.
    NoName,
    /// No app claims the name.
    UnknownHost,
    /// An app that may serve the name does not allow HTTP/3: it asks for client certificates,
    /// lists cipher suites, or sets `http3: false`.
    NotAllowed,
    /// No certificate covers the name.
    NoCertificate,
}

const DECLINED: [(Declined, &str); 4] = [
    (Declined::NoName, "no_name"),
    (Declined::UnknownHost, "unknown_host"),
    (Declined::NotAllowed, "not_allowed"),
    (Declined::NoCertificate, "no_certificate"),
];

/// Why podgate closed an established connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Closed {
    /// More than [`RESETS_PER_SECOND`] stream resets in a second.
    RapidReset,
    /// The tenant had no budget for the connection.
    OverBudget,
}

const CLOSED: [(Closed, &str); 2] = [
    (Closed::RapidReset, "rapid_reset"),
    (Closed::OverBudget, "over_budget"),
];

/// The process's HTTP/3 counters.
#[derive(Debug)]
pub(super) struct Stats {
    refused: [AtomicU64; REFUSED.len()],
    declined: [AtomicU64; DECLINED.len()],
    closed: [AtomicU64; CLOSED.len()],
    retries: AtomicU64,
    requests: AtomicU64,
}

/// The process's counters.
pub(super) static STATS: Stats = Stats::new();

impl Stats {
    const fn new() -> Self {
        Self {
            refused: [const { AtomicU64::new(0) }; REFUSED.len()],
            declined: [const { AtomicU64::new(0) }; DECLINED.len()],
            closed: [const { AtomicU64::new(0) }; CLOSED.len()],
            retries: AtomicU64::new(0),
            requests: AtomicU64::new(0),
        }
    }

    pub(super) fn refused(&self, reason: Refused) {
        bump(&self.refused, &REFUSED, reason);
    }

    pub(super) fn declined(&self, reason: Declined) {
        bump(&self.declined, &DECLINED, reason);
    }

    pub(super) fn closed(&self, reason: Closed) {
        bump(&self.closed, &CLOSED, reason);
    }

    pub(super) fn retry(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }
}

fn bump<T: PartialEq + Copy, const N: usize>(
    counts: &[AtomicU64; N],
    names: &[(T, &str); N],
    reason: T,
) {
    if let Some(count) = names
        .iter()
        .position(|(known, _)| *known == reason)
        .and_then(|at| counts.get(at))
    {
        count.fetch_add(1, Ordering::Relaxed);
    }
}

fn labelled<T, const N: usize>(
    out: &mut String,
    name: &str,
    help: &str,
    names: &[(T, &str); N],
    counts: &[AtomicU64; N],
) {
    // Writing to a `String` cannot fail.
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
    for ((_, reason), count) in names.iter().zip(counts) {
        let _ = writeln!(
            out,
            "{name}{{reason=\"{reason}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
}

/// Appends the Prometheus text exposition of the HTTP/3 metrics to `out`.
pub fn render(out: &mut String) {
    let stats = &STATS;
    let _ = write!(
        out,
        "# HELP podgate_h3_connections QUIC connections open now.\n\
         # TYPE podgate_h3_connections gauge\n\
         podgate_h3_connections {}\n\
         # HELP podgate_h3_handshakes QUIC handshakes in flight now.\n\
         # TYPE podgate_h3_handshakes gauge\n\
         podgate_h3_handshakes {}\n\
         # HELP podgate_h3_retries_total Retry tokens demanded of clients whose address was not validated.\n\
         # TYPE podgate_h3_retries_total counter\n\
         podgate_h3_retries_total {}\n\
         # HELP podgate_h3_requests_total Requests the HTTP/3 front sent into the pipeline.\n\
         # TYPE podgate_h3_requests_total counter\n\
         podgate_h3_requests_total {}\n",
        CONNECTIONS.load(),
        HANDSHAKES.load(),
        stats.retries.load(Ordering::Relaxed),
        stats.requests.load(Ordering::Relaxed),
    );
    labelled(
        out,
        "podgate_h3_refused_total",
        "QUIC connections turned away, by reason.",
        &REFUSED,
        &stats.refused,
    );
    labelled(
        out,
        "podgate_h3_handshake_refused_total",
        "QUIC handshakes the certificate resolver refused, by reason.",
        &DECLINED,
        &stats.declined,
    );
    labelled(
        out,
        "podgate_h3_closed_total",
        "QUIC connections podgate closed, by reason.",
        &CLOSED,
        &stats.closed,
    );
}

#[cfg(test)]
mod test {
    use super::*;

    fn lookup(vars: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let vars = vars.to_vec();
        move |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn defaults_when_nothing_is_set() {
        assert_eq!(Settings::from_lookup(&lookup(&[])), Ok(Settings::default()));
    }

    #[test]
    fn reads_every_variable() {
        let settings = Settings::from_lookup(&lookup(&[
            ("H3_MAX_CONNECTIONS", "50"),
            ("H3_MAX_HANDSHAKES", "8"),
            ("H3_RETRY", "Always"),
            ("H3_UDP_RECV_BUFFER", "1048576"),
            ("H3_MAX_STREAMS", "10"),
            ("H3_CONNECTION_WINDOW", "524288"),
        ]))
        .expect("valid");
        assert_eq!(
            settings,
            Settings {
                max_connections: 50,
                max_handshakes: 8,
                retry: Retry::Always,
                udp_recv_buffer: 1_048_576,
                max_streams: 10,
                connection_window: 524_288,
            }
        );
    }

    #[test]
    fn refuses_out_of_range_and_unknown_values() {
        for (var, value) in [
            ("H3_MAX_CONNECTIONS", "0"),
            ("H3_MAX_CONNECTIONS", "lots"),
            ("H3_MAX_HANDSHAKES", "65537"),
            ("H3_UDP_RECV_BUFFER", "1"),
            ("H3_MAX_STREAMS", "1001"),
            ("H3_CONNECTION_WINDOW", "1024"),
            ("H3_RETRY", "sometimes"),
        ] {
            let err = Settings::from_lookup(&lookup(&[(var, value)])).expect_err(var);
            assert_eq!(err.var, var);
        }
    }

    #[test]
    fn a_connection_reserves_both_windows_and_the_internal_one() {
        let settings = Settings::default();
        assert_eq!(settings.reservation(), 2 * 262_144 + 65_535);
        assert_eq!(settings.stream_window(), 131_072);
    }

    #[test]
    fn retry_follows_the_mode_and_the_load() {
        let on_load = Settings {
            max_connections: 100,
            max_handshakes: 10,
            ..Settings::default()
        };
        assert!(!on_load.demands_retry(4, 79));
        assert!(on_load.demands_retry(5, 0), "half the handshakes");
        assert!(on_load.demands_retry(0, 80), "80% of the connections");
        let always = Settings {
            retry: Retry::Always,
            ..on_load.clone()
        };
        assert!(always.demands_retry(0, 0));
        let never = Settings {
            retry: Retry::Never,
            ..on_load
        };
        assert!(!never.demands_retry(10, 100));
    }

    #[test]
    fn the_counter_returns_what_a_guard_took() {
        static COUNT: Counter = Counter::new();
        let first = COUNT.take();
        let second = COUNT.take();
        assert_eq!(COUNT.load(), 2);
        drop(first);
        assert_eq!(COUNT.load(), 1);
        drop(second);
        assert_eq!(COUNT.load(), 0);
    }

    #[test]
    fn resets_pass_the_limit_only_inside_one_second() {
        let start = Instant::now();
        let mut window = ResetWindow::new(start);
        for _ in 0..RESETS_PER_SECOND {
            assert!(!window.record(start));
        }
        assert!(window.record(start), "the 201st reset in the second");
        let later = start + Duration::from_millis(1_001);
        assert!(!window.record(later), "a new second starts from zero");
    }
}
