//! Auto-revert: a snapshot that makes the apps it changed fail is undone by podgate itself.
//!
//! After every successful `PUT /v1/snapshot`, [`Reverter::applied`] remembers the snapshot that
//! was live before and the apps the new one serves differently ([`plan::changed_apps`]), and a
//! watcher task checks their `5xx` ratio (see [`crate::outcomes`]) twice a second for
//! `revert_window_secs` (snapshot field; default [`DEFAULT_WINDOW_SECS`], `0` turns it off,
//! capped at [`RING_SECS`]). The ratio counts only requests since the swap. It trips when at
//! least [`MIN_REQUESTS`] requests were answered and more than [`MAX_ERROR_PERCENT`] percent of
//! them were `5xx`; the minimum keeps one failure out of one request from reverting a deploy,
//! and means an app with less traffic than that in the window is never reverted. Apps the
//! snapshot did not change are not looked at, so an unrelated outage cannot revert a deploy.
//! While the pushed snapshot gives an app a canary policy ([`crate::canary`]), the `5xx` of the
//! canary revision do not count: the canary already isolates them and pulls itself back.
//!
//! On a trip the previous snapshot is compiled again and goes live ([`TableHandle::revert_to`]),
//! `config_reverted {from_version, to_version}` goes into the event feed, and
//! [`Inflight::sync`] runs like after any swap. The recompile can fail (a certificate that
//! expired since the first push, say). Then the current table stays live,
//! `config_revert_failed {from_version, to_version, error}` is emitted and the change is no
//! longer watched.
//!
//! Version semantics: the restored table is built as a new table whose version is
//! `from_version` (the reverted snapshot's), so the live version never goes down while the
//! routing is `to_version`'s. The next push must therefore be newer than the reverted one: the
//! control plane cannot re-push the bad snapshot by accident, and must publish a new version to
//! try again. `to_version` in the event is the content version that is serving again.
//!
//! Only the newest push is watched. A later push cancels the watch of an earlier one, and
//! reverts to the snapshot it replaced, which may itself be unvetted. The very first snapshot
//! of a process (no previous snapshot) is never watched, because the only thing to go back to
//! is an empty table.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::time::{MissedTickBehavior, interval};

use crate::events::{EventFeed, EventKind};
use crate::inflight::Inflight;
use crate::outcomes::{Counts, Outcomes, RING_SECS};
use crate::plan;
use crate::snapshot::Snapshot;
use crate::table::{Replaced, TableHandle};

/// Length of the watch when the snapshot does not set `revert_window_secs`.
pub const DEFAULT_WINDOW_SECS: u64 = 60;
/// Fewest requests in the window before the ratio means anything.
pub const MIN_REQUESTS: u64 = 20;
/// The ratio of `5xx` responses above which the snapshot is reverted, in percent.
pub const MAX_ERROR_PERCENT: u64 = 5;
const CHECK_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug)]
struct Armed {
    generation: u64,
    apps: Vec<Box<str>>,
    canaries: HashMap<Box<str>, Box<str>>,
    previous: Arc<Snapshot>,
    from_version: u64,
    to_version: u64,
    armed_at: Instant,
    window: Duration,
}

impl Armed {
    /// Whether the watched apps failed too much between the swap and `now`.
    fn breached(&self, outcomes: &Outcomes, now: Instant) -> bool {
        let span = now
            .saturating_duration_since(self.armed_at)
            .min(self.window);
        let counts = self
            .apps
            .iter()
            .map(|app| self.counted(outcomes, app, span, now))
            .fold(Counts::default(), |sum, counts| sum + counts);
        counts.total >= MIN_REQUESTS && counts.errors_5xx * 100 > counts.total * MAX_ERROR_PERCENT
    }

    /// The counts of one watched app, less its canary revision when it has one.
    fn counted(&self, outcomes: &Outcomes, app: &str, span: Duration, now: Instant) -> Counts {
        let all = outcomes.window_at(app, None, span, now);
        let Some(revision) = self.canaries.get(app) else {
            return all;
        };
        let own = outcomes.window_at(app, Some(revision), span, now);
        Counts {
            total: all.total.saturating_sub(own.total),
            errors_5xx: all.errors_5xx.saturating_sub(own.errors_5xx),
        }
    }
}

#[derive(Debug)]
struct Inner {
    table: TableHandle,
    events: EventFeed,
    inflight: Inflight,
    outcomes: Outcomes,
    // Bumped by every push; a watcher of an older one stops.
    generation: AtomicU64,
}

/// Watches the newest snapshot and reverts it on a `5xx` spike. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Reverter {
    inner: Arc<Inner>,
}

impl Reverter {
    /// A reverter over the live `table`, reading `outcomes` and reporting into `events`.
    #[must_use]
    pub fn new(
        table: TableHandle,
        events: EventFeed,
        inflight: Inflight,
        outcomes: Outcomes,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                table,
                events,
                inflight,
                outcomes,
                generation: AtomicU64::new(0),
            }),
        }
    }

    /// The outcome counters this reverter reads.
    #[must_use]
    pub fn outcomes(&self) -> &Outcomes {
        &self.inner.outcomes
    }

    /// Starts watching a push that just succeeded. `window_secs` is the snapshot's
    /// `revert_window_secs`. Must run inside a tokio runtime.
    pub fn applied(&self, replaced: &Replaced, window_secs: Option<u64>) {
        let inner = &self.inner;
        let generation = inner.generation.fetch_add(1, Ordering::AcqRel) + 1;
        inner.outcomes.sync(&replaced.current);
        let secs = window_secs.unwrap_or(DEFAULT_WINDOW_SECS).min(RING_SECS);
        let Some(previous) = replaced.previous_snapshot.clone() else {
            return;
        };
        let apps = plan::changed_apps(&replaced.previous, &replaced.current);
        // The canary revision of a watched app: its own 5xx do not count (see [`crate::canary`]).
        let canaries: HashMap<Box<str>, Box<str>> = (0..)
            .map_while(|index| replaced.current.app(index))
            .filter(|app| apps.contains(&Box::from(app.id())))
            .filter_map(|app| Some((app.id().into(), app.canary_policy()?.revision.clone())))
            .collect();
        if secs == 0 || apps.is_empty() {
            return;
        }
        let armed = Armed {
            generation,
            apps,
            to_version: previous.version,
            previous,
            from_version: replaced.current.version(),
            armed_at: Instant::now(),
            canaries,
            window: Duration::from_secs(secs),
        };
        tokio::spawn(Arc::clone(inner).watch(armed));
    }
}

impl Inner {
    async fn watch(self: Arc<Self>, armed: Armed) {
        let armed = Arc::new(armed);
        let mut ticks = interval(CHECK_INTERVAL);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            if self.generation.load(Ordering::Acquire) != armed.generation {
                return;
            }
            let now = Instant::now();
            if armed.breached(&self.outcomes, now) {
                // Compiling can be slow (WASM filter modules): keep it off the runtime.
                let (inner, armed) = (Arc::clone(&self), Arc::clone(&armed));
                // A panicked revert task has already logged itself; there is nothing to add.
                drop(tokio::task::spawn_blocking(move || inner.revert(&armed)).await);
                return;
            }
            if now >= armed.armed_at + armed.window {
                return;
            }
        }
    }

    fn revert(&self, armed: &Armed) {
        match self.table.revert_to(&armed.previous, armed.from_version) {
            Ok(true) => {
                tracing::warn!(
                    from_version = armed.from_version,
                    to_version = armed.to_version,
                    apps = ?armed.apps,
                    "5xx spike after a snapshot, reverted to the previous one"
                );
                self.events.emit(EventKind::ConfigReverted {
                    from_version: armed.from_version,
                    to_version: armed.to_version,
                });
                let live = self.table.load();
                self.inflight.sync(&live);
                self.outcomes.sync(&live);
            }
            // A newer push landed meanwhile and wins.
            Ok(false) => {}
            Err(err) => {
                tracing::error!(
                    from_version = armed.from_version,
                    to_version = armed.to_version,
                    %err,
                    "5xx spike after a snapshot, but the previous one no longer compiles"
                );
                self.events.emit(EventKind::ConfigRevertFailed {
                    from_version: armed.from_version,
                    to_version: armed.to_version,
                    error: err.to_string().into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const TENANT: &str =
        r#""tenants":[{"id":"t","weight":1,"budget":{"max_inflight":1,"max_buffer_bytes":1}}]"#;

    fn snapshot(version: u64, tenant_of_app: &str) -> Snapshot {
        serde_json::from_str(&format!(
            r#"{{"version":{version},{TENANT},"apps":[{{"id":"a","tenant":"{tenant_of_app}",
            "declared_by":"x","hosts":["a.test"],"tls":{{"mode":"acme"}},
            "revisions":[{{"id":"r","upstreams":["127.0.0.1:1"],"weight":1,"state":"serving"}}]}}]}}"#
        ))
        .expect("valid snapshot")
    }

    fn armed(apps: &[&str], window_secs: u64) -> Armed {
        Armed {
            generation: 1,
            apps: apps.iter().map(|app| (*app).into()).collect(),
            previous: Arc::new(snapshot(1, "t")),
            from_version: 2,
            to_version: 1,
            armed_at: Instant::now(),
            canaries: HashMap::new(),
            window: Duration::from_secs(window_secs),
        }
    }

    fn record(outcomes: &Outcomes, app: &str, status: u16, times: u64, at: Instant) {
        for _ in 0..times {
            outcomes.record_at(app, Some("r"), status, at);
        }
    }

    #[test]
    fn breach_needs_enough_requests_and_more_than_five_percent() {
        let outcomes = Outcomes::new();
        let watch = armed(&["a"], 60);
        let now = watch.armed_at + Duration::from_secs(3);

        record(&outcomes, "a", 502, 1, now);
        assert!(
            !watch.breached(&outcomes, now),
            "1 of 1 is below the minimum"
        );

        // 1 error in 20 is exactly 5%: not above it.
        record(&outcomes, "a", 200, 19, now);
        assert!(!watch.breached(&outcomes, now));

        record(&outcomes, "a", 500, 1, now);
        assert!(watch.breached(&outcomes, now), "2 of 21 is above 5%");
    }

    #[test]
    fn only_watched_apps_count() {
        let outcomes = Outcomes::new();
        let watch = armed(&["a"], 60);
        let now = watch.armed_at + Duration::from_secs(3);
        record(&outcomes, "other", 500, 100, now);
        record(&outcomes, "a", 200, 100, now);
        assert!(!watch.breached(&outcomes, now));
    }

    fn reverter() -> (Reverter, TableHandle, EventFeed) {
        let table = TableHandle::new();
        let events = EventFeed::new();
        let reverter = Reverter::new(
            table.clone(),
            events.clone(),
            Inflight::new(events.clone()),
            Outcomes::new(),
        );
        (reverter, table, events)
    }

    #[tokio::test]
    async fn revert_recompiles_the_previous_snapshot_at_the_live_version() {
        let (reverter, table, events) = reverter();
        table.apply(&snapshot(1, "t")).expect("first push");
        let before = table.load();
        table.apply(&snapshot(2, "t")).expect("second push");
        let bad = table.load();

        reverter.inner.revert(&armed(&["a"], 60));

        let live = table.load();
        assert_eq!(live.version(), 2, "the live version does not go down");
        assert!(!Arc::ptr_eq(&live, &bad), "a new table went live");
        assert!(!Arc::ptr_eq(&live, &before), "tables are never reused");
        assert_eq!(bad.version(), 2, "the table a request holds is untouched");
        assert_eq!(
            events.poll(0, Duration::ZERO).await.expect("poll")[0].kind,
            EventKind::ConfigReverted {
                from_version: 2,
                to_version: 1
            }
        );
    }

    #[tokio::test]
    async fn a_previous_snapshot_that_no_longer_compiles_is_reported_and_not_applied() {
        let (reverter, table, events) = reverter();
        table.apply(&snapshot(1, "t")).expect("first push");
        table.apply(&snapshot(2, "t")).expect("second push");
        let live = table.load();

        // The remembered snapshot names a tenant it does not declare: it cannot compile now.
        let mut watch = armed(&["a"], 60);
        watch.previous = Arc::new(snapshot(1, "nobody"));
        reverter.inner.revert(&watch);

        assert!(Arc::ptr_eq(&live, &table.load()), "the current table stays");
        let events = events.poll(0, Duration::ZERO).await.expect("poll");
        assert_eq!(events.len(), 1);
        assert!(
            matches!(
                &events[0].kind,
                EventKind::ConfigRevertFailed { from_version: 2, to_version: 1, error }
                    if error.contains("unknown tenant")
            ),
            "{:?}",
            events[0].kind
        );
    }

    #[tokio::test]
    async fn a_newer_push_wins_over_a_late_revert() {
        let (reverter, table, events) = reverter();
        table.apply(&snapshot(1, "t")).expect("first push");
        table.apply(&snapshot(2, "t")).expect("second push");
        table.apply(&snapshot(3, "t")).expect("third push");

        reverter.inner.revert(&armed(&["a"], 60));

        assert_eq!(table.load().version(), 3);
        assert!(
            events
                .poll(0, Duration::ZERO)
                .await
                .expect("poll")
                .is_empty()
        );
    }
}
