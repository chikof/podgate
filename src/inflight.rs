//! Requests in flight per revision, and the `revision_drained` event that rides on them.
//!
//! Counters are keyed by `(app id, revision id)` and live in a registry outside the routing
//! table, so they survive snapshot swaps: a request that started on a revision is still counted
//! after a swap removed or redefined it. The proxy takes an [`InflightGuard`] once a request is
//! routed and keeps it in its `Ctx`; dropping it, however the request ends, releases the count.
//!
//! # Hot path
//!
//! [`Inflight::sync`] builds a new registry holding one counter per revision of the live table
//! and publishes it through an [`ArcSwap`]. Acquiring on such a revision loads the registry
//! without a lock, looks the counter up by `&str` and bumps an atomic; a guard drop is one atomic
//! subtraction. Neither allocates and no lock is shared between requests. The only lock is
//! `writer`, taken by [`Inflight::sync`] and by the slow path of [`Inflight::acquire`], which
//! runs for a revision the registry does not know yet (a request routed with a table newer than
//! the last `sync`).
//!
//! # Drain handshake
//!
//! A `draining` revision gets exactly one [`EventKind::RevisionDrained`] per draining period, as
//! soon as its count is zero: either when [`Inflight::sync`] sees it already idle, or when its
//! last guard drops. A period ends when a later snapshot makes the revision something else.
//!
//! Each counter packs its phase and its count into one atomic word (`count << 2 | phase`), so
//! the two always change together. The races are settled by compare-and-swap on that word:
//!
//! - `sync` starts a period while the last guard drops. Either the drop's subtraction lands
//!   first, and `sync` then sees count 0 and emits; or `sync`'s phase change lands first, and the
//!   drop sees `Draining` with count 0 and emits. A compare-and-swap that loses re-reads the
//!   word, so exactly one side emits.
//! - A new guard against the last drop: the drop's `Draining` to `Drained` swap expects count 0,
//!   so it fails when the guard got in between, and that guard's own drop emits later.
//! - `sync` ends a period while the last guard drops: the drop's swap expects `Draining` and
//!   fails, so nothing is emitted for a period that already ended.
//! - `sync` removes an idle counter while a request acquires it: removal first moves the counter
//!   from count 0 to `Retired`. An acquire that meets `Retired` takes the slow path and finds or
//!   creates the counter in the new registry. A counter with requests in flight is never removed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use arc_swap::ArcSwap;

use crate::events::{EventFeed, EventKind};
use crate::route::Selected;
use crate::snapshot::RevisionState;
use crate::table::RoutingTable;

/// Two levels so a lookup borrows `&str` and does not allocate.
type Registry = HashMap<Box<str>, HashMap<Box<str>, Arc<Counter>>>;

/// Where a revision stands in its draining period: the low bits of [`Counter::state`].
const PHASE_MASK: u64 = 0b11;
/// Not draining in the newest table seen.
const LIVE: u64 = 0;
/// Draining, requests still in flight; the last one to finish emits the event.
const DRAINING: u64 = 1;
/// Draining and already reported.
const DRAINED: u64 = 2;
/// Removed from the registry; nothing may enter it any more.
const RETIRED: u64 = 3;
/// The count lives above the phase bits; one request adds this much.
const ONE: u64 = 1 << 2;

fn count_of(state: u64) -> u64 {
    state >> 2
}

/// Why [`Counter::enter`] refused.
enum Refused {
    /// The revision already drained: route again with the live table.
    Drained,
    /// The counter left the registry: look it up again.
    Retired,
}

/// The count and drain phase of one revision, in one atomic word.
#[derive(Debug)]
struct Counter {
    app: Box<str>,
    revision: Box<str>,
    state: AtomicU64,
    events: EventFeed,
}

impl Counter {
    fn new(app: &str, revision: &str, events: &EventFeed) -> Arc<Self> {
        Arc::new(Self {
            app: app.into(),
            revision: revision.into(),
            state: AtomicU64::new(LIVE),
            events: events.clone(),
        })
    }

    fn enter(&self) -> Result<(), Refused> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            match state & PHASE_MASK {
                DRAINED => return Err(Refused::Drained),
                RETIRED => return Err(Refused::Retired),
                _ => {}
            }
            match self.state.compare_exchange_weak(
                state,
                state + ONE,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(seen) => state = seen,
            }
        }
    }

    fn leave(&self) {
        let before = self.state.fetch_sub(ONE, Ordering::AcqRel);
        if count_of(before) == 1
            && before & PHASE_MASK == DRAINING
            && self
                .state
                .compare_exchange(DRAINING, DRAINED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.emit_drained();
        }
    }

    /// Starts a draining period unless one is under way. Emits at once when the counter is idle.
    fn begin_drain(&self) {
        let mut state = self.state.load(Ordering::Acquire);
        while state & PHASE_MASK == LIVE {
            let idle = count_of(state) == 0;
            let next = if idle { DRAINED } else { state | DRAINING };
            match self
                .state
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if idle {
                        self.emit_drained();
                    }
                    return;
                }
                Err(seen) => state = seen,
            }
        }
    }

    /// Ends the draining period, if any.
    fn end_drain(&self) {
        let mut state = self.state.load(Ordering::Acquire);
        while matches!(state & PHASE_MASK, DRAINING | DRAINED) {
            match self.state.compare_exchange_weak(
                state,
                state & !PHASE_MASK,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(seen) => state = seen,
            }
        }
    }

    /// Takes an idle counter out of service. `false` when a request is in flight; the counter
    /// is then left not draining.
    fn retire(&self) -> bool {
        self.end_drain();
        self.state
            .compare_exchange(LIVE, RETIRED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn count(&self) -> usize {
        usize::try_from(count_of(self.state.load(Ordering::Acquire))).unwrap_or(usize::MAX)
    }

    fn emit_drained(&self) {
        self.events.emit(EventKind::RevisionDrained {
            app: self.app.clone(),
            revision: self.revision.clone(),
        });
    }
}

#[derive(Debug)]
struct Shared {
    events: EventFeed,
    registry: ArcSwap<Registry>,
    /// Serializes registry changes. Holds the version of the newest table passed to
    /// [`Inflight::sync`]; older ones are ignored.
    writer: Mutex<u64>,
}

/// The in-flight counters. Cheap to clone; every clone is the same set of counters.
#[derive(Debug, Clone)]
pub struct Inflight {
    shared: Arc<Shared>,
}

impl Inflight {
    /// Counters that report drained revisions into `events`.
    #[must_use]
    pub fn new(events: EventFeed) -> Self {
        Self {
            shared: Arc::new(Shared {
                events,
                registry: ArcSwap::from_pointee(Registry::new()),
                writer: Mutex::new(0),
            }),
        }
    }

    /// Counts one request on `app`/`revision` until the returned guard drops.
    ///
    /// Returns `None` when the revision was already reported drained: the caller routed with a
    /// table older than the one that drained it and must route again with the live table.
    ///
    /// Allocates nothing and takes no lock for a revision of the table last passed to
    /// [`Self::sync`].
    #[must_use]
    pub fn acquire(&self, app: &str, revision: &str) -> Option<InflightGuard> {
        let registry = self.shared.registry.load();
        if let Some(counter) = lookup(&registry, app, revision) {
            match counter.enter() {
                Ok(()) => {
                    return Some(InflightGuard {
                        counter: Arc::clone(counter),
                    });
                }
                Err(Refused::Drained) => return None,
                Err(Refused::Retired) => {}
            }
        }
        drop(registry);
        self.acquire_unknown(app, revision)
    }

    /// The slow path: the registry has no live counter for the revision yet.
    fn acquire_unknown(&self, app: &str, revision: &str) -> Option<InflightGuard> {
        let _writer = self.lock_writer();
        let registry = self.shared.registry.load_full();
        let counter = match lookup(&registry, app, revision) {
            Some(counter) => Arc::clone(counter),
            None => {
                let counter = Counter::new(app, revision, &self.shared.events);
                let mut next = Registry::clone(&registry);
                next.entry(app.into())
                    .or_default()
                    .insert(revision.into(), Arc::clone(&counter));
                self.shared.registry.store(Arc::new(next));
                counter
            }
        };
        // `sync` retires counters under the writer lock and publishes the new registry before
        // releasing it, so a counter found here is never `Retired`.
        counter.enter().ok()?;
        Some(InflightGuard { counter })
    }

    /// [`Self::acquire`] for the revision `selected` points at in `table`, the table the request
    /// was routed with.
    #[must_use]
    pub fn admit(&self, table: &RoutingTable, selected: &Selected) -> Option<InflightGuard> {
        let app = table.app(selected.app)?;
        let revision = app.revisions().get(selected.revision)?;
        self.acquire(app.id(), revision.id())
    }

    /// Requests currently counted on `app`/`revision`.
    #[must_use]
    pub fn count(&self, app: &str, revision: &str) -> usize {
        lookup(&self.shared.registry.load(), app, revision).map_or(0, |counter| counter.count())
    }

    /// Brings the counters in line with a table that just went live: starts a draining period
    /// for each revision the table marks `draining` (emitting at once when it is idle), and ends
    /// it for revisions that are not. Call after every successful apply. A table older than one
    /// already synced is ignored.
    ///
    /// Publishes a registry with a counter for every revision of `table`, so requests routed
    /// with it take the allocation-free path of [`Self::acquire`]. Counters of revisions the
    /// table dropped stay while requests are in flight on them.
    pub fn sync(&self, table: &RoutingTable) {
        let mut version = self.lock_writer();
        if table.version() < *version {
            return;
        }
        *version = table.version();

        let old = self.shared.registry.load_full();
        let mut next = Registry::new();
        for app in (0..).map_while(|index| table.app(index)) {
            for revision in app.revisions() {
                if lookup(&next, app.id(), revision.id()).is_some() {
                    continue;
                }
                let counter = lookup(&old, app.id(), revision.id()).map_or_else(
                    || Counter::new(app.id(), revision.id(), &self.shared.events),
                    Arc::clone,
                );
                if revision.state() == RevisionState::Draining {
                    counter.begin_drain();
                } else {
                    counter.end_drain();
                }
                next.entry(app.id().into())
                    .or_default()
                    .insert(revision.id().into(), counter);
            }
        }
        for (app, revisions) in &*old {
            for (revision, counter) in revisions {
                if lookup(&next, app, revision).is_none() && !counter.retire() {
                    next.entry(app.clone())
                        .or_default()
                        .insert(revision.clone(), Arc::clone(counter));
                }
            }
        }
        self.shared.registry.store(Arc::new(next));
    }

    fn lock_writer(&self) -> MutexGuard<'_, u64> {
        self.shared
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

fn lookup<'a>(registry: &'a Registry, app: &str, revision: &str) -> Option<&'a Arc<Counter>> {
    registry.get(app)?.get(revision)
}

/// One request counted on a revision. Dropping it releases the count and, when it was the last
/// request of a draining revision, emits the drain event.
#[derive(Debug)]
#[must_use = "the request is only counted while the guard lives"]
pub struct InflightGuard {
    counter: Arc<Counter>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.counter.leave();
    }
}

#[cfg(test)]
mod test {
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::events::Event;
    use crate::snapshot::Snapshot;

    fn table(version: u64, state: &str) -> RoutingTable {
        let json = format!(
            r#"{{
            "version": {version},
            "tenants": [{{"id": "t", "weight": 1, "budget": {{"max_inflight": 1, "max_buffer_bytes": 1}}}}],
            "apps": [{{
                "id": "a", "tenant": "t", "declared_by": "test", "hosts": ["a.test"],
                "tls": {{"mode": "acme"}},
                "revisions": [{{"id": "r", "upstreams": ["127.0.0.1:9000"], "weight": 1, "state": "{state}"}}]
            }}]
        }}"#
        );
        let snapshot: Snapshot = serde_json::from_str(&json).expect("valid snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    async fn events(feed: &EventFeed) -> Vec<Event> {
        feed.poll(0, Duration::ZERO).await.expect("retained")
    }

    #[tokio::test]
    async fn inflight_counter_follows_guards() {
        let inflight = Inflight::new(EventFeed::new());
        let one = inflight.acquire("a", "r").expect("counted");
        let two = inflight.acquire("a", "r").expect("counted");
        assert_eq!(inflight.count("a", "r"), 2);
        drop(one);
        assert_eq!(inflight.count("a", "r"), 1);
        drop(two);
        assert_eq!(inflight.count("a", "r"), 0);
    }

    #[tokio::test]
    async fn inflight_counter_survives_sync_and_drain_waits_for_the_last_guard() {
        let feed = EventFeed::new();
        let inflight = Inflight::new(feed.clone());
        let one = inflight.acquire("a", "r").expect("counted");
        let two = inflight.acquire("a", "r").expect("counted");

        inflight.sync(&table(1, "draining"));
        assert_eq!(inflight.count("a", "r"), 2);
        assert!(events(&feed).await.is_empty());
        drop(one);
        assert!(events(&feed).await.is_empty());
        drop(two);
        let seen = events(&feed).await;
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].kind,
            EventKind::RevisionDrained {
                app: "a".into(),
                revision: "r".into()
            }
        );
    }

    #[tokio::test]
    async fn inflight_counter_idle_revision_drains_once_per_period() {
        let feed = EventFeed::new();
        let inflight = Inflight::new(feed.clone());
        inflight.sync(&table(1, "draining"));
        assert_eq!(events(&feed).await.len(), 1);
        // Still draining in the next snapshot: same period, no second event.
        inflight.sync(&table(2, "draining"));
        assert_eq!(events(&feed).await.len(), 1);
        // Serving again ends the period; draining once more starts a new one.
        inflight.sync(&table(3, "serving"));
        inflight.sync(&table(4, "draining"));
        assert_eq!(events(&feed).await.len(), 2);
    }

    #[tokio::test]
    async fn inflight_counter_refuses_a_revision_already_drained() {
        let inflight = Inflight::new(EventFeed::new());
        inflight.sync(&table(1, "draining"));
        assert!(inflight.acquire("a", "r").is_none());
        inflight.sync(&table(2, "serving"));
        assert!(inflight.acquire("a", "r").is_some());
    }

    #[tokio::test]
    async fn inflight_counter_ignores_an_older_table() {
        let feed = EventFeed::new();
        let inflight = Inflight::new(feed.clone());
        inflight.sync(&table(2, "serving"));
        inflight.sync(&table(1, "draining"));
        assert!(events(&feed).await.is_empty());
    }

    fn registered(inflight: &Inflight, app: &str, revision: &str) -> bool {
        lookup(&inflight.shared.registry.load(), app, revision).is_some()
    }

    #[tokio::test]
    async fn inflight_counter_forgets_idle_revisions_the_table_dropped() {
        let inflight = Inflight::new(EventFeed::new());
        inflight.sync(&table(1, "serving"));
        assert!(registered(&inflight, "a", "r"));

        // Unknown to the table: counted through the slow path.
        let guard = inflight.acquire("a", "gone").expect("counted");
        assert!(registered(&inflight, "a", "gone"));
        // A request in flight keeps its counter across a swap.
        inflight.sync(&table(2, "serving"));
        assert_eq!(inflight.count("a", "gone"), 1);
        drop(guard);
        assert_eq!(inflight.count("a", "gone"), 0);
        inflight.sync(&table(3, "serving"));
        assert!(!registered(&inflight, "a", "gone"));
        assert!(registered(&inflight, "a", "r"));
    }

    #[tokio::test]
    async fn inflight_counter_survives_a_swap_with_the_same_ids() {
        let feed = EventFeed::new();
        let inflight = Inflight::new(feed.clone());
        inflight.sync(&table(1, "serving"));
        let guard = inflight.acquire("a", "r").expect("counted");
        inflight.sync(&table(2, "draining"));
        assert_eq!(inflight.count("a", "r"), 1);
        assert!(events(&feed).await.is_empty());
        drop(guard);
        assert_eq!(events(&feed).await.len(), 1);
    }

    #[tokio::test]
    async fn inflight_parallel() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 100_000;
        let feed = EventFeed::new();
        let inflight = Inflight::new(feed.clone());
        inflight.sync(&table(1, "serving"));
        let draining = table(2, "draining");
        let progress = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for round in 0..ROUNDS {
                        // `None` once the revision drained: the proxy would route again.
                        let Some(guard) = inflight.acquire("a", "r") else {
                            return;
                        };
                        drop(guard);
                        if round % 1000 == 0 {
                            progress.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
            while progress.load(Ordering::Relaxed) < THREADS * 10 {
                std::thread::yield_now();
            }
            inflight.sync(&draining);
        });

        assert_eq!(inflight.count("a", "r"), 0);
        let seen = events(&feed).await;
        assert_eq!(seen.len(), 1, "{seen:?}");
    }

    /// `sync` starting a draining period while the last guard drops: one event, whoever wins.
    #[tokio::test]
    async fn inflight_race_sync_vs_last_drop() {
        let serving = table(1, "serving");
        let draining = table(2, "draining");
        for round in 0..2000 {
            let feed = EventFeed::new();
            let inflight = Inflight::new(feed.clone());
            inflight.sync(&serving);
            let guard = inflight.acquire("a", "r").expect("counted");
            let start = Barrier::new(2);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    start.wait();
                    drop(guard);
                });
                start.wait();
                inflight.sync(&draining);
            });
            let seen = events(&feed).await;
            assert_eq!(seen.len(), 1, "round {round}: {seen:?}");
        }
    }
}
