//! [`Series`]: the counters and the latency histogram of one entry point, router or service.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The `code_class` label values, indexed by `status / 100 - 1`.
pub(super) const CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

/// Upper bounds of the finite histogram buckets: microseconds, and the `le` label as printed. The
/// buckets are fixed, so every series costs the same and no snapshot can reshape them.
pub(super) const BOUNDS: [(u64, &str); 12] = [
    (5_000, "0.005"),
    (10_000, "0.01"),
    (25_000, "0.025"),
    (50_000, "0.05"),
    (100_000, "0.1"),
    (250_000, "0.25"),
    (500_000, "0.5"),
    (1_000_000, "1"),
    (2_500_000, "2.5"),
    (5_000_000, "5"),
    (7_500_000, "7.5"),
    (10_000_000, "10"),
];

/// The bucket counts: one per finite bound, then the overflow (`+Inf`) bucket.
const BUCKETS: usize = BOUNDS.len() + 1;

/// Requests by status class and a latency histogram, all atomics: recording takes no lock and
/// allocates nothing.
///
/// A request does one increment of its class, one of its bucket and one of the latency sum.
/// Buckets are stored apart (not cumulative), so the histogram count is their sum and a scrape
/// can never show a count that disagrees with its buckets.
#[derive(Debug, Default)]
pub struct Series {
    classes: [AtomicU64; CLASSES.len()],
    buckets: [AtomicU64; BUCKETS],
    sum_micros: AtomicU64,
    retries: AtomicU64,
}
// 160: five classes, thirteen buckets, the sum and the retry counter, 8 bytes each.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Series>() == 160);

impl Series {
    /// Counts one finished request that was answered with `status` after `elapsed`. A status
    /// outside `100..=599` is not recorded.
    pub fn record(&self, status: u16, elapsed: Duration) {
        let class = usize::from(status / 100).wrapping_sub(1);
        let Some(counter) = self.classes.get(class) else {
            return;
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let bucket = BOUNDS.partition_point(|(bound, _)| *bound < micros);
        if let Some(count) = self.buckets.get(bucket) {
            count.fetch_add(1, Ordering::Relaxed);
        }
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// Counts one retry of a request against this series (a service).
    pub fn retry(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }

    /// Requests recorded so far, all classes.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.classes
            .iter()
            .map(|class| class.load(Ordering::Relaxed))
            .sum()
    }

    /// Requests recorded in class `class` (`0` is `1xx`, `4` is `5xx`).
    pub(super) fn class(&self, class: usize) -> u64 {
        self.classes
            .get(class)
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }

    /// The bucket counts, not cumulative.
    pub(super) fn buckets(&self) -> [u64; BUCKETS] {
        std::array::from_fn(|index| self.buckets[index].load(Ordering::Relaxed))
    }

    /// The sum of the recorded latencies in microseconds.
    pub(super) fn sum_micros(&self) -> u64 {
        self.sum_micros.load(Ordering::Relaxed)
    }

    /// The retries counted so far.
    pub(super) fn retries(&self) -> u64 {
        self.retries.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn metrics_latency_histogram_buckets() {
        let series = Series::default();
        for micros in [0, 5_000, 5_001, 9_999_999, 10_000_000, 10_000_001] {
            series.record(200, Duration::from_micros(micros));
        }
        let buckets = series.buckets();
        // 0 and 5 ms are in `le=0.005`; 5.001 ms is the next; 10 s is still finite.
        assert_eq!(buckets[0], 2);
        assert_eq!(buckets[1], 1);
        assert_eq!(buckets[BOUNDS.len() - 1], 2);
        assert_eq!(buckets[BOUNDS.len()], 1, "past 10 s is the +Inf bucket");
        assert_eq!(buckets.iter().sum::<u64>(), series.total());
        assert_eq!(
            series.sum_micros(),
            5_000 + 5_001 + 9_999_999 + 10_000_000 + 10_000_001
        );
    }

    #[test]
    fn statuses_outside_the_classes_are_not_recorded() {
        let series = Series::default();
        for status in [0, 99, 600, 999] {
            series.record(status, Duration::ZERO);
        }
        assert_eq!(series.total(), 0);
        for status in [100, 204, 301, 404, 599] {
            series.record(status, Duration::ZERO);
        }
        assert_eq!(
            [0, 1, 2, 3, 4].map(|class| series.class(class)),
            [1, 1, 1, 1, 1]
        );
    }
}
