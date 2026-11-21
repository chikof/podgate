//! The metrics of the TCP listeners, process-wide.
//!
//! The labels are fixed sets of reasons, never a tenant, an app or a client address, so a remote
//! party cannot grow the series.
//!
//! - `podgate_tcp_connections`: connections open now.
//! - `podgate_tcp_connections_total`: connections accepted.
//! - `podgate_l4_refused_total{reason}`: connections closed at once, before a server was dialled.
//! - `podgate_tcp_closed_total{reason}`: connections that ended after one was.
//! - `podgate_tcp_bytes_total{direction}`: bytes from clients (`in`) and back to them (`out`).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// Why a connection was closed before a server was dialled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// No TCP router of the live table takes the connection.
    NoRoute,
    /// The tenant is at `max_inflight`.
    OverInflight,
    /// The tenant has no buffer budget left for the copy buffers.
    OverBudget,
    /// The service has no server that can take it, or every server tried failed.
    NoServer,
    /// The service has a health check and it has marked every server down.
    NoHealthyServer,
    /// The upstream address policy refused every server tried.
    UpstreamForbidden,
}

const REFUSED: [(Refused, &str); 6] = [
    (Refused::NoRoute, "no_route"),
    (Refused::OverInflight, "over_inflight"),
    (Refused::OverBudget, "over_budget"),
    (Refused::NoServer, "no_server"),
    (Refused::NoHealthyServer, "no_healthy_server"),
    (Refused::UpstreamForbidden, "upstream_forbidden"),
];

/// Why a connection that reached a server ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Closed {
    /// Both directions finished.
    Done,
    /// No byte moved for `idle_timeout_secs`.
    Idle,
    /// A read or write failed, or a side reset the connection.
    Error,
    /// The process is stopping and the grace period ran out.
    Shutdown,
}

const CLOSED: [(Closed, &str); 4] = [
    (Closed::Done, "done"),
    (Closed::Idle, "idle"),
    (Closed::Error, "error"),
    (Closed::Shutdown, "shutdown"),
];

/// The counters.
#[derive(Debug)]
pub(super) struct Stats {
    refused: [AtomicU64; REFUSED.len()],
    closed: [AtomicU64; CLOSED.len()],
    open: AtomicU64,
    accepted: AtomicU64,
    connect_failures: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

/// The process's counters.
pub(super) static STATS: Stats = Stats::new();

impl Stats {
    const fn new() -> Self {
        Self {
            refused: [const { AtomicU64::new(0) }; REFUSED.len()],
            closed: [const { AtomicU64::new(0) }; CLOSED.len()],
            open: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            connect_failures: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        }
    }

    pub(super) fn refused(&self, reason: Refused) {
        if let Some(count) = REFUSED
            .iter()
            .position(|(known, _)| *known == reason)
            .and_then(|at| self.refused.get(at))
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn closed(&self, reason: Closed) {
        if let Some(count) = CLOSED
            .iter()
            .position(|(known, _)| *known == reason)
            .and_then(|at| self.closed.get(at))
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn opened(&self) {
        self.open.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn ended(&self) {
        self.open.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn connect_failed(&self) {
        self.connect_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn client_sent(&self, bytes: usize) {
        self.bytes_in.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn client_received(&self, bytes: usize) {
        self.bytes_out.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// Appends the Prometheus text exposition of the TCP metrics to `out`.
pub fn render(out: &mut String) {
    let stats = &STATS;
    // Writing to a `String` cannot fail.
    let _ = write!(
        out,
        "# HELP podgate_tcp_connections TCP connections open now.\n\
         # TYPE podgate_tcp_connections gauge\n\
         podgate_tcp_connections {}\n\
         # HELP podgate_tcp_connections_total TCP connections accepted.\n\
         # TYPE podgate_tcp_connections_total counter\n\
         podgate_tcp_connections_total {}\n\
         # HELP podgate_tcp_connect_failures_total Connections to a TCP server that failed, each \
         one a try of the next server.\n\
         # TYPE podgate_tcp_connect_failures_total counter\n\
         podgate_tcp_connect_failures_total {}\n",
        stats.open.load(Ordering::Relaxed),
        stats.accepted.load(Ordering::Relaxed),
        stats.connect_failures.load(Ordering::Relaxed),
    );
    let _ = writeln!(
        out,
        "# HELP podgate_l4_refused_total Connections closed before a server was dialled, by reason.\n\
         # TYPE podgate_l4_refused_total counter"
    );
    for ((_, reason), count) in REFUSED.iter().zip(&stats.refused) {
        let _ = writeln!(
            out,
            "podgate_l4_refused_total{{reason=\"{reason}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        out,
        "# HELP podgate_tcp_closed_total TCP connections that reached a server and ended, by reason.\n\
         # TYPE podgate_tcp_closed_total counter"
    );
    for ((_, reason), count) in CLOSED.iter().zip(&stats.closed) {
        let _ = writeln!(
            out,
            "podgate_tcp_closed_total{{reason=\"{reason}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        out,
        "# HELP podgate_tcp_bytes_total TCP bytes received from clients (in) and returned to them (out).\n\
         # TYPE podgate_tcp_bytes_total counter\n\
         podgate_tcp_bytes_total{{direction=\"in\"}} {}\n\
         podgate_tcp_bytes_total{{direction=\"out\"}} {}",
        stats.bytes_in.load(Ordering::Relaxed),
        stats.bytes_out.load(Ordering::Relaxed)
    );
}
