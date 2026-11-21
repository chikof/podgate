//! The `podgate_ocsp_*` series. Process-wide atomics, like the other series that no routing
//! table owns, so [`render`] needs no handle and `observe::metrics::render` keeps its signature.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use super::reason::Reason;

static REJECTED: [AtomicU64; Reason::ALL.len()] = [const { AtomicU64::new(0) }; Reason::ALL.len()];
static STAPLED: AtomicU64 = AtomicU64::new(0);
static FETCHES: AtomicU64 = AtomicU64::new(0);
static IN_FLIGHT: AtomicU64 = AtomicU64::new(0);
static STAPLES: AtomicU64 = AtomicU64::new(0);

/// Counts one discarded response, or one fetch that never produced one.
pub(super) fn rejected(reason: Reason) {
    REJECTED[reason.index()].fetch_add(1, Ordering::Relaxed);
}

/// Counts one response that passed verification.
pub(super) fn stapled() {
    STAPLED.fetch_add(1, Ordering::Relaxed);
}

/// Sets the number of certificates that have a live staple.
pub(super) fn set_staples(count: usize) {
    STAPLES.store(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
}

/// Marks a fetch as running until the returned guard drops.
pub(super) fn fetch_started() -> InFlight {
    FETCHES.fetch_add(1, Ordering::Relaxed);
    IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
    InFlight
}

/// One running fetch.
#[derive(Debug)]
pub(super) struct InFlight;

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Appends the `podgate_ocsp_*` families to the metrics exposition `out`.
pub fn render(out: &mut String) {
    // Writing to a `String` cannot fail.
    let _ = write!(
        out,
        "# HELP podgate_ocsp_staples Certificates that currently carry a verified OCSP staple.\n\
         # TYPE podgate_ocsp_staples gauge\npodgate_ocsp_staples {}\n\
         # HELP podgate_ocsp_stapled_total OCSP responses that passed verification.\n\
         # TYPE podgate_ocsp_stapled_total counter\npodgate_ocsp_stapled_total {}\n\
         # HELP podgate_ocsp_fetches_total OCSP responder fetches started.\n\
         # TYPE podgate_ocsp_fetches_total counter\npodgate_ocsp_fetches_total {}\n\
         # HELP podgate_ocsp_fetches_in_flight OCSP responder fetches running now.\n\
         # TYPE podgate_ocsp_fetches_in_flight gauge\npodgate_ocsp_fetches_in_flight {}\n\
         # HELP podgate_ocsp_rejected_total OCSP responses discarded and fetches that failed, by reason.\n\
         # TYPE podgate_ocsp_rejected_total counter\n",
        STAPLES.load(Ordering::Relaxed),
        STAPLED.load(Ordering::Relaxed),
        FETCHES.load(Ordering::Relaxed),
        IN_FLIGHT.load(Ordering::Relaxed),
    );
    for reason in Reason::ALL {
        let _ = writeln!(
            out,
            "podgate_ocsp_rejected_total{{reason=\"{}\"}} {}",
            reason.as_str(),
            REJECTED[reason.index()].load(Ordering::Relaxed)
        );
    }
}
