//! Requests in flight per revision, and the `revision_drained` event that rides on them.
//!
//! Counters live outside the routing table, keyed by `(app id, revision id)`, so they survive
//! snapshot swaps: a request that started on a revision is still counted after a swap removed or
//! redefined it. The proxy takes an [`InflightGuard`] once a request is routed and keeps it in its
//! `Ctx`; dropping it, however the request ends, releases the count.
//!
//! A `draining` revision gets exactly one [`EventKind::RevisionDrained`] per draining period, as
//! soon as its count is zero: either when [`Inflight::sync`] sees it already idle, or when its
//! last guard drops. A period ends when a later snapshot makes the revision something else.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::events::{EventFeed, EventKind};
use crate::route::Selected;
use crate::snapshot::RevisionState;
use crate::table::RoutingTable;

#[derive(Debug, PartialEq, Eq)]
struct Key {
    app: Box<str>,
    revision: Box<str>,
}

/// Where a revision stands in its draining period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Not draining in the newest table seen.
    Live,
    /// Draining, requests still in flight; the last one to finish emits the event.
    Draining,
    /// Draining and already reported.
    Drained,
}

#[derive(Debug)]
struct Entry {
    key: Arc<Key>,
    count: usize,
    phase: Phase,
}

#[derive(Debug, Default)]
struct State {
    /// Version of the newest table passed to [`Inflight::sync`]; older ones are ignored.
    version: u64,
    // Two levels so a lookup borrows `&str` and does not allocate.
    entries: HashMap<Box<str>, HashMap<Box<str>, Entry>>,
}

impl State {
    fn entry(&mut self, app: &str, revision: &str) -> Option<&mut Entry> {
        self.entries.get_mut(app)?.get_mut(revision)
    }

    /// Creates the idle, not-draining entry when there is none yet. Only a first request for a
    /// revision allocates its names.
    fn ensure(&mut self, app: &str, revision: &str) {
        if self.entry(app, revision).is_some() {
            return;
        }
        self.entries.entry(app.into()).or_default().insert(
            revision.into(),
            Entry {
                key: Arc::new(Key {
                    app: app.into(),
                    revision: revision.into(),
                }),
                count: 0,
                phase: Phase::Live,
            },
        );
    }
}

#[derive(Debug)]
struct Shared {
    events: EventFeed,
    state: Mutex<State>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn emit_drained(&self, key: &Key) {
        self.events.emit(EventKind::RevisionDrained {
            app: key.app.clone(),
            revision: key.revision.clone(),
        });
    }
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
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Counts one request on `app`/`revision` until the returned guard drops.
    ///
    /// Returns `None` when the revision was already reported drained: the caller routed with a
    /// table older than the one that drained it and must route again with the live table.
    #[must_use]
    pub fn acquire(&self, app: &str, revision: &str) -> Option<InflightGuard> {
        let mut state = self.shared.lock();
        state.ensure(app, revision);
        let entry = state.entry(app, revision)?;
        if entry.phase == Phase::Drained {
            return None;
        }
        entry.count += 1;
        Some(InflightGuard {
            shared: Arc::clone(&self.shared),
            key: Arc::clone(&entry.key),
        })
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
        self.shared
            .lock()
            .entry(app, revision)
            .map_or(0, |entry| entry.count)
    }

    /// Brings the counters in line with a table that just went live: starts a draining period
    /// for each revision the table marks `draining` (emitting at once when it is idle), and ends
    /// it for revisions that are not. Call after every successful apply. A table older than one
    /// already synced is ignored.
    pub fn sync(&self, table: &RoutingTable) {
        let draining: HashSet<(&str, &str)> = (0..)
            .map_while(|index| table.app(index))
            .flat_map(|app| {
                app.revisions()
                    .iter()
                    .filter(|revision| revision.state() == RevisionState::Draining)
                    .map(|revision| (app.id(), revision.id()))
            })
            .collect();

        let mut state = self.shared.lock();
        if table.version() < state.version {
            return;
        }
        state.version = table.version();
        for (app, revisions) in &mut state.entries {
            for (revision, entry) in revisions {
                if !draining.contains(&(&**app, &**revision)) {
                    entry.phase = Phase::Live;
                }
            }
        }
        for (app, revision) in draining {
            state.ensure(app, revision);
            let Some(entry) = state.entry(app, revision) else {
                continue;
            };
            if entry.phase != Phase::Live {
                continue;
            }
            if entry.count == 0 {
                entry.phase = Phase::Drained;
                self.shared.emit_drained(&entry.key);
            } else {
                entry.phase = Phase::Draining;
            }
        }
        for revisions in state.entries.values_mut() {
            revisions.retain(|_, entry| entry.count > 0 || entry.phase != Phase::Live);
        }
        state.entries.retain(|_, revisions| !revisions.is_empty());
    }
}

/// One request counted on a revision. Dropping it releases the count and, when it was the last
/// request of a draining revision, emits the drain event.
#[derive(Debug)]
#[must_use = "the request is only counted while the guard lives"]
pub struct InflightGuard {
    shared: Arc<Shared>,
    key: Arc<Key>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        let Some(entry) = state.entry(&self.key.app, &self.key.revision) else {
            return;
        };
        entry.count = entry.count.saturating_sub(1);
        if entry.count > 0 {
            return;
        }
        match entry.phase {
            Phase::Draining => {
                entry.phase = Phase::Drained;
                self.shared.emit_drained(&self.key);
            }
            Phase::Live => {
                if let Some(revisions) = state.entries.get_mut(&*self.key.app) {
                    revisions.remove(&*self.key.revision);
                    if revisions.is_empty() {
                        state.entries.remove(&*self.key.app);
                    }
                }
            }
            Phase::Drained => {}
        }
    }
}

#[cfg(test)]
mod test {
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

    #[tokio::test]
    async fn inflight_counter_forgets_idle_revisions() {
        let inflight = Inflight::new(EventFeed::new());
        drop(inflight.acquire("a", "r"));
        assert!(inflight.shared.lock().entries.is_empty());
    }
}
