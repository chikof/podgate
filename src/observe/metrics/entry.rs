//! The series of one entry point and the per-request handle that records into it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use super::series::Series;
use crate::router::Matched;
use crate::table::RoutingTable;

/// What one entry point reports: its requests and latency, and how many requests are being served
/// on it now. Operator named, so the label set is bounded by `ENTRY_POINTS`.
#[derive(Debug, Default)]
pub struct EntrySeries {
    pub(super) requests: Series,
    pub(super) open: AtomicU32,
}

impl EntrySeries {
    /// Requests being served on the entry point now.
    #[must_use]
    pub fn open(&self) -> u32 {
        self.open.load(Ordering::Relaxed)
    }

    /// The requests and latency recorded on the entry point.
    #[must_use]
    pub fn requests(&self) -> &Series {
        &self.requests
    }
}

/// One request's claim on the series it will be recorded under: it counts the request as open on
/// its entry point from [`Self::begin`] until it is dropped, however the request ends, and times
/// it. Created with the request's `Ctx`.
#[derive(Debug)]
pub struct InFlight {
    entry: Arc<EntrySeries>,
    started: Instant,
}

// 24: the entry point's `Arc` (8) and the start `Instant` (16); one lives in every request's `Ctx`.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<InFlight>() == 24);

impl InFlight {
    /// Counts a request that just arrived on `entry`.
    #[must_use]
    pub fn begin(entry: &Arc<EntrySeries>) -> Self {
        entry.open.fetch_add(1, Ordering::Relaxed);
        Self {
            entry: Arc::clone(entry),
            started: Instant::now(),
        }
    }

    /// Records the finished request, answered with `status`, on its entry point and, when a router
    /// matched it, on that router's series; `routed` adds the router's service, for a request that
    /// got as far as choosing a server. The handles were resolved when `table` compiled, so this
    /// is a few atomic increments: no lookup, no lock and no allocation.
    pub fn finish(
        &self,
        table: &RoutingTable,
        matched: Option<Matched>,
        routed: bool,
        status: u16,
    ) {
        let elapsed = self.started.elapsed();
        self.entry.requests.record(status, elapsed);
        let Some(route) = matched.and_then(|matched| table.series().route(matched)) else {
            return;
        };
        route.router().record(status, elapsed);
        if routed {
            route.service().record(status, elapsed);
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.entry.open.fetch_sub(1, Ordering::Relaxed);
    }
}
