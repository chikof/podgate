//! The metrics of the UDP listeners, process-wide.
//!
//! The labels are fixed sets of reasons, never a tenant, an app or a client address, so a remote
//! party cannot grow the series.
//!
//! - `podgate_udp_sessions`: sessions open now.
//! - `podgate_udp_dropped_total{reason}`: datagrams podgate dropped.
//! - `podgate_udp_sessions_closed_total{reason}`: sessions that ended.
//! - `podgate_udp_datagrams_total{direction}` and `podgate_udp_bytes_total{direction}`: what
//!   arrived from clients (`in`) and what went back to them (`out`).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// Why a datagram was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Dropped {
    /// No UDP router listens on the entry point (any more).
    NoRoute,
    /// The router's session table is full of sessions that have had a reply.
    TableFull,
    /// The tenant holds its cap of UDP sessions.
    TenantLimit,
    /// The node holds its cap of UDP sessions.
    NodeLimit,
    /// The tenant has no buffer budget left for another session.
    OverBudget,
    /// The upstream address policy refused the server.
    UpstreamForbidden,
    /// The datagram is larger than the session buffer.
    Oversize,
    /// A reply would pass the router's `max_reply_ratio`.
    ReplyRatio,
    /// The source address is `0.0.0.0`, multicast or port 0.
    BadSource,
    /// A socket could not be opened.
    SocketError,
    /// A datagram could not be sent.
    SendError,
}

const DROPPED: [(Dropped, &str); 11] = [
    (Dropped::NoRoute, "no_route"),
    (Dropped::TableFull, "table_full"),
    (Dropped::TenantLimit, "tenant_limit"),
    (Dropped::NodeLimit, "node_limit"),
    (Dropped::OverBudget, "over_budget"),
    (Dropped::UpstreamForbidden, "upstream_forbidden"),
    (Dropped::Oversize, "oversize"),
    (Dropped::ReplyRatio, "reply_ratio"),
    (Dropped::BadSource, "bad_source"),
    (Dropped::SocketError, "socket_error"),
    (Dropped::SendError, "send_error"),
];

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Close {
    /// Idle for `session_timeout_secs`.
    Expired,
    /// Given up for a new client, the table being full.
    Evicted,
    /// A snapshot removed its server.
    ServerRemoved,
    /// A snapshot removed its router, or moved it to another app or tenant.
    RouterRemoved,
    /// The process is stopping.
    Shutdown,
}

const CLOSED: [(Close, &str); 5] = [
    (Close::Expired, "expired"),
    (Close::Evicted, "evicted"),
    (Close::ServerRemoved, "server_removed"),
    (Close::RouterRemoved, "router_removed"),
    (Close::Shutdown, "shutdown"),
];

/// The counters.
#[derive(Debug)]
pub(super) struct Stats {
    dropped: [AtomicU64; DROPPED.len()],
    closed: [AtomicU64; CLOSED.len()],
    sessions: AtomicU64,
    datagrams_in: AtomicU64,
    datagrams_out: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

/// The process's counters.
pub(super) static STATS: Stats = Stats::new();

impl Stats {
    const fn new() -> Self {
        Self {
            dropped: [const { AtomicU64::new(0) }; DROPPED.len()],
            closed: [const { AtomicU64::new(0) }; CLOSED.len()],
            sessions: AtomicU64::new(0),
            datagrams_in: AtomicU64::new(0),
            datagrams_out: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        }
    }

    pub(super) fn dropped(&self, reason: Dropped) {
        if let Some(count) = DROPPED
            .iter()
            .position(|(known, _)| *known == reason)
            .and_then(|at| self.dropped.get(at))
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn closed(&self, reason: Close) {
        if let Some(count) = CLOSED
            .iter()
            .position(|(known, _)| *known == reason)
            .and_then(|at| self.closed.get(at))
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn session_opened(&self) {
        self.sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn session_ended(&self) {
        self.sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn received(&self, bytes: usize) {
        self.datagrams_in.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn sent(&self, bytes: usize) {
        self.datagrams_out.fetch_add(1, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// Appends the Prometheus text exposition of the UDP metrics to `out`.
pub fn render(out: &mut String) {
    let stats = &STATS;
    // Writing to a `String` cannot fail.
    let _ = write!(
        out,
        "# HELP podgate_udp_sessions UDP sessions open now.\n\
         # TYPE podgate_udp_sessions gauge\n\
         podgate_udp_sessions {}\n",
        stats.sessions.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "# HELP podgate_udp_dropped_total UDP datagrams dropped, by reason.\n\
         # TYPE podgate_udp_dropped_total counter"
    );
    for ((_, reason), count) in DROPPED.iter().zip(&stats.dropped) {
        let _ = writeln!(
            out,
            "podgate_udp_dropped_total{{reason=\"{reason}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        out,
        "# HELP podgate_udp_sessions_closed_total UDP sessions that ended, by reason.\n\
         # TYPE podgate_udp_sessions_closed_total counter"
    );
    for ((_, reason), count) in CLOSED.iter().zip(&stats.closed) {
        let _ = writeln!(
            out,
            "podgate_udp_sessions_closed_total{{reason=\"{reason}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    for (name, help, inbound, outbound) in [
        (
            "podgate_udp_datagrams_total",
            "UDP datagrams received from clients (in) and returned to them (out).",
            &stats.datagrams_in,
            &stats.datagrams_out,
        ),
        (
            "podgate_udp_bytes_total",
            "UDP payload bytes received from clients (in) and returned to them (out).",
            &stats.bytes_in,
            &stats.bytes_out,
        ),
    ] {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n\
             {name}{{direction=\"in\"}} {}\n{name}{{direction=\"out\"}} {}",
            inbound.load(Ordering::Relaxed),
            outbound.load(Ordering::Relaxed)
        );
    }
}
