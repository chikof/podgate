//! Response outcomes per (app id, revision id) over a sliding time window.
//!
//! The proxy records the final status of every request it served in the `logging` callback
//! ([`record_request`]). Readers ask how many requests an app or one revision answered in the
//! last few seconds and how many of them were `5xx` ([`Outcomes::window`]): auto-revert
//! (`src/revert.rs`) reads per app, the canary reads per revision.
//!
//! What counts: the status of the response podgate wrote to the client, so an upstream `5xx` and
//! a `5xx` podgate made itself (`502`/`504` on a refused or slow upstream, or the `503` of an app
//! with no serving revision) are both errors. Capacity refusals are not: the tenant `503` and the
//! wake-timeout `503` of a scale-to-zero app (both carry `retry-after`) say busy or cold, not
//! broken, and are left out. A request that got no response
//! (the client left first) counts as nothing. A request with a route counts under its revision;
//! one without a route but with a known host counts under the app only (`revision` is `None`),
//! so a deploy that leaves an app without a serving revision still shows. A request for an
//! unknown host belongs to no app and is not counted.
//!
//! Layout: each series is a ring of [`RING_SECS`] one-second buckets of atomic counters, stamped
//! with the second they belong to; a bucket of an older lap is reset by the first request of its
//! new second. The request path is a lock-free map lookup (`ArcSwap`, no allocation) and two
//! relaxed atomic increments. The map only changes when a revision gets its first request or
//! [`Outcomes::sync`] drops revisions a snapshot removed, under a mutex that requests never take
//! on a known revision. A request that lands exactly while its bucket rolls over to a new second
//! can be lost from the count; that is a rounding error for a ratio, and never an overcount.

use std::collections::{HashMap, HashSet};
use std::ops::Add;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use pingora::proxy::Session;

use crate::proxy::Ctx;
use crate::route;
use crate::table::RoutingTable;

/// Seconds of history a series keeps; the longest window that can be asked for.
pub const RING_SECS: u64 = 300;

/// Requests and server errors counted over a window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Requests answered.
    pub total: u64,
    /// Of those, answered with a `5xx` status.
    pub errors_5xx: u64,
}

impl Counts {
    /// `5xx` responses per thousand requests, rounded down; `None` before the first request.
    #[must_use]
    pub fn error_permille(self) -> Option<u64> {
        (self.errors_5xx * 1000).checked_div(self.total)
    }
}

impl Add for Counts {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            total: self.total + other.total,
            errors_5xx: self.errors_5xx + other.errors_5xx,
        }
    }
}

#[derive(Debug, Default)]
struct Bucket {
    // The second this bucket counts, plus one, so a fresh bucket (0) matches no second.
    stamp: AtomicU64,
    total: AtomicU64,
    errors: AtomicU64,
}

#[derive(Debug)]
struct Series {
    buckets: Box<[Bucket]>,
}

impl Series {
    fn new() -> Self {
        Self {
            buckets: (0..RING_SECS).map(|_| Bucket::default()).collect(),
        }
    }

    fn bucket(&self, second: u64) -> Option<&Bucket> {
        self.buckets.get(usize::try_from(second % RING_SECS).ok()?)
    }

    fn record(&self, second: u64, error: bool) {
        let Some(bucket) = self.bucket(second) else {
            return;
        };
        let stamp = second + 1;
        let seen = bucket.stamp.load(Ordering::Acquire);
        if seen != stamp
            && bucket
                .stamp
                .compare_exchange(seen, stamp, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            bucket.total.store(0, Ordering::Relaxed);
            bucket.errors.store(0, Ordering::Relaxed);
        }
        bucket.total.fetch_add(1, Ordering::Relaxed);
        if error {
            bucket.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counts of the `span` seconds ending with `now` (inclusive).
    fn window(&self, now: u64, span: u64) -> Counts {
        let newest = now + 1;
        let oldest = newest.saturating_sub(span.saturating_sub(1)).max(1);
        self.buckets
            .iter()
            .filter(|bucket| (oldest..=newest).contains(&bucket.stamp.load(Ordering::Acquire)))
            .fold(Counts::default(), |sum, bucket| Counts {
                total: sum.total + bucket.total.load(Ordering::Relaxed),
                errors_5xx: sum.errors_5xx + bucket.errors.load(Ordering::Relaxed),
            })
    }
}

#[derive(Debug, Clone)]
struct AppSeries {
    unrouted: Arc<Series>,
    revisions: HashMap<Box<str>, Arc<Series>>,
}

impl AppSeries {
    fn get(&self, revision: Option<&str>) -> Option<&Series> {
        match revision {
            None => Some(&self.unrouted),
            Some(revision) => self.revisions.get(revision).map(|series| &**series),
        }
    }
}

type Apps = HashMap<Box<str>, Arc<AppSeries>>;

#[derive(Debug)]
struct Inner {
    epoch: Instant,
    apps: ArcSwap<Apps>,
    // Serializes the rare copy-on-write changes of `apps`.
    writers: Mutex<()>,
}

/// The outcome counters. Cheap to clone; every clone is the same set of counters.
#[derive(Debug, Clone)]
pub struct Outcomes {
    inner: Arc<Inner>,
}

impl Default for Outcomes {
    fn default() -> Self {
        Self::new()
    }
}

impl Outcomes {
    /// Empty counters.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                epoch: Instant::now(),
                apps: ArcSwap::from_pointee(HashMap::new()),
                writers: Mutex::new(()),
            }),
        }
    }

    fn second(&self, at: Instant) -> u64 {
        at.saturating_duration_since(self.inner.epoch).as_secs()
    }

    /// Counts one request that `app` answered with `status`: under `revision` when it was routed
    /// to one, under the app alone (`None`) when it was refused before routing.
    pub fn record(&self, app: &str, revision: Option<&str>, status: u16) {
        self.record_at(app, revision, status, Instant::now());
    }

    /// [`Self::record`] at an explicit time, for tests.
    pub fn record_at(&self, app: &str, revision: Option<&str>, status: u16, at: Instant) {
        let second = self.second(at);
        let error = (500..600).contains(&status);
        {
            let apps = self.inner.apps.load();
            if let Some(series) = apps.get(app).and_then(|app| app.get(revision)) {
                series.record(second, error);
                return;
            }
        }
        self.create(app, revision).record(second, error);
    }

    /// The first request for a revision: add its series to a copy of the map and publish it.
    fn create(&self, app: &str, revision: Option<&str>) -> Arc<Series> {
        let _writers = self
            .inner
            .writers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut apps: Apps = (**self.inner.apps.load()).clone();
        let entry = apps.get(app).map(|entry| (**entry).clone());
        let mut entry = entry.unwrap_or_else(|| AppSeries {
            unrouted: Arc::new(Series::new()),
            revisions: HashMap::new(),
        });
        let series = match revision {
            None => Arc::clone(&entry.unrouted),
            Some(revision) => Arc::clone(
                entry
                    .revisions
                    .entry(revision.into())
                    .or_insert_with(|| Arc::new(Series::new())),
            ),
        };
        apps.insert(app.into(), Arc::new(entry));
        self.inner.apps.store(Arc::new(apps));
        series
    }

    /// The counts over the last `span` (rounded up to whole seconds, at least one, at most
    /// [`RING_SECS`]) of `app`: of one `revision`, or `None` for the whole app, requests refused
    /// before routing included.
    #[must_use]
    pub fn window(&self, app: &str, revision: Option<&str>, span: Duration) -> Counts {
        self.window_at(app, revision, span, Instant::now())
    }

    /// [`Self::window`] ending at an explicit time, for tests.
    #[must_use]
    pub fn window_at(
        &self,
        app: &str,
        revision: Option<&str>,
        span: Duration,
        now: Instant,
    ) -> Counts {
        let now = self.second(now);
        let seconds = span.as_secs() + u64::from(span.subsec_nanos() > 0);
        let span = seconds.clamp(1, RING_SECS);
        let apps = self.inner.apps.load();
        let Some(app) = apps.get(app) else {
            return Counts::default();
        };
        match revision {
            Some(revision) => app
                .get(Some(revision))
                .map_or_else(Counts::default, |series| series.window(now, span)),
            None => app
                .revisions
                .values()
                .fold(app.unrouted.window(now, span), |sum, series| {
                    sum + series.window(now, span)
                }),
        }
    }

    /// Forgets the revisions `table` no longer has, and the apps it no longer has, so counters
    /// do not grow with revision churn. Call after a snapshot swap or revert.
    pub fn sync(&self, table: &RoutingTable) {
        let _writers = self
            .inner
            .writers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let current = self.inner.apps.load();
        let mut kept = Apps::new();
        for app in (0..).map_while(|index| table.app(index)) {
            let Some(old) = current.get(app.id()) else {
                continue;
            };
            let live: HashSet<&str> = app.revisions().iter().map(|rev| rev.id()).collect();
            let revisions = old
                .revisions
                .iter()
                .filter(|(id, _)| live.contains(&***id))
                .map(|(id, series)| (id.clone(), Arc::clone(series)))
                .collect();
            kept.insert(
                app.id().into(),
                Arc::new(AppSeries {
                    unrouted: Arc::clone(&old.unrouted),
                    revisions,
                }),
            );
        }
        self.inner.apps.store(Arc::new(kept));
    }
}

/// Records the outcome of a finished request; the one call `Gateway::logging` makes.
///
/// A request that has no response is not counted. A routed request counts under its revision;
/// an unrouted one counts under the app its host names, when there is one, except a capacity
/// refusal: an unrouted `503` that carries `retry-after` is the tenant being at `max_inflight`
/// or a scale-to-zero app that did not wake in time. Both say the app is busy or cold, not that
/// the deploy is broken, so they never count toward a revert. (The `503` for an app with no
/// serving revision has no `retry-after` and does count.)
pub fn record_request(outcomes: &Outcomes, session: &Session, ctx: &Ctx) {
    let Some(status) = session.response_written().map(|head| head.status.as_u16()) else {
        return;
    };
    if let Some(selected) = ctx.route {
        let revision = ctx
            .table
            .app(selected.app)
            .and_then(|app| Some((app, app.revisions().get(selected.revision)?)));
        if let Some((app, revision)) = revision {
            outcomes.record(app.id(), Some(revision.id()), status);
        }
        return;
    }
    let capacity_refusal = status == 503
        && session
            .response_written()
            .is_some_and(|head| head.headers.contains_key("retry-after"));
    if capacity_refusal {
        return;
    }
    let app = route::request_host(session.req_header())
        .and_then(|host| ctx.table.find_app(&host).map(|(_, app)| app));
    if let Some(app) = app {
        outcomes.record(app.id(), None, status);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn error_ratio_window() {
        let outcomes = Outcomes::new();
        let base = Instant::now();
        // Seconds 0..2: 10 ok + 10 errors on r1; second 100: 5 ok on r2; second 101: one
        // refused request with no revision.
        for second in 0..2 {
            for _ in 0..10 {
                outcomes.record_at("a", Some("r1"), 200, at(base, second));
                outcomes.record_at("a", Some("r1"), 502, at(base, second));
            }
        }
        for _ in 0..5 {
            outcomes.record_at("a", Some("r2"), 204, at(base, 100));
        }
        outcomes.record_at("a", None, 503, at(base, 101));
        outcomes.record_at("other", Some("r1"), 500, at(base, 101));

        let span = Duration::from_secs(60);
        let counts = |rev, now| outcomes.window_at("a", rev, span, at(base, now));

        // Early on only r1 traffic is inside the window.
        assert_eq!(
            counts(Some("r1"), 1),
            Counts {
                total: 40,
                errors_5xx: 20
            }
        );
        assert_eq!(counts(Some("r1"), 1).error_permille(), Some(500));
        // Whole app, much later: the old seconds slid out, the newer ones are in.
        assert_eq!(
            counts(None, 101),
            Counts {
                total: 6,
                errors_5xx: 1
            }
        );
        assert_eq!(counts(Some("r2"), 101).error_permille(), Some(0));
        // Another app's errors never leak in; unknown names are empty.
        assert_eq!(counts(Some("nope"), 101), Counts::default());
        assert_eq!(
            outcomes.window_at("ghost", None, span, at(base, 101)),
            Counts::default()
        );
        assert_eq!(Counts::default().error_permille(), None);
        // A one-second window sees only the newest second.
        assert_eq!(
            outcomes
                .window_at("a", None, Duration::from_millis(1), at(base, 101))
                .total,
            1
        );
    }

    #[test]
    fn a_lap_of_the_ring_resets_the_bucket() {
        let outcomes = Outcomes::new();
        let base = Instant::now();
        outcomes.record_at("a", Some("r"), 500, at(base, 3));
        outcomes.record_at("a", Some("r"), 200, at(base, 3 + RING_SECS));
        let counts = outcomes.window_at(
            "a",
            Some("r"),
            Duration::from_secs(RING_SECS),
            at(base, 3 + RING_SECS),
        );
        assert_eq!(
            counts,
            Counts {
                total: 1,
                errors_5xx: 0
            }
        );
    }

    #[test]
    fn sync_drops_removed_revisions_and_apps() {
        use crate::snapshot::Snapshot;

        let outcomes = Outcomes::new();
        let base = Instant::now();
        for (app, rev) in [("a", "r1"), ("a", "r2"), ("gone", "r1")] {
            outcomes.record_at(app, Some(rev), 200, base);
        }
        let snapshot: Snapshot = serde_json::from_str(
            r#"{"version":1,"tenants":[{"id":"t","weight":1,"budget":{"max_inflight":1,"max_buffer_bytes":1}}],
            "apps":[{"id":"a","tenant":"t","declared_by":"x","hosts":["a.test"],"tls":{"mode":"acme"},
            "revisions":[{"id":"r1","upstreams":["127.0.0.1:1"],"weight":1,"state":"serving"}]}]}"#,
        )
        .expect("valid snapshot");
        outcomes.sync(&RoutingTable::compile(&snapshot).expect("compiles"));

        let span = Duration::from_secs(10);
        let total = |app, rev| outcomes.window_at(app, rev, span, base).total;
        assert_eq!(total("a", Some("r1")), 1);
        assert_eq!(total("a", Some("r2")), 0);
        assert_eq!(total("gone", None), 0);
    }
}
