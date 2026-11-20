//! SLO-driven canary: one revision of an app gains traffic only while it stays healthy.
//!
//! The snapshot owns the policy ([`Canary`]); podgate owns the live share. It is kept outside
//! the table, in a registry the [`crate::table::TableHandle`] owns, keyed by app id and a
//! fingerprint of the canary policy plus the app's serving set (every revision's id, state and
//! weight, never its backends). A swap that leaves that fingerprint as it was gives the new table the same
//! runtime, so a push for another app neither restarts a ramp nor revives a regressed canary;
//! any change to the policy or the serving set, and an auto-revert that restores a different
//! one, starts the canary over. Entries of apps that lost their canary are dropped.
//!
//! # Weight model
//!
//! The canary revision gets `share` percent of the new, unpinned sessions of its app. The other
//! `serving` revisions with a weight split the remaining `100 - share` percent in proportion to
//! their configured weights. The canary's own configured `weight` is ignored. Because the split is
//! no longer the configured weights, [`crate::table::CompiledRevision::effective_weight`] then
//! counts in parts of [`crate::table::CANARY_TOTAL_WEIGHT`] (`10000`) shared by all revisions of
//! the app: the canary at `25` percent shows `2500`. Both the picker and `GET /v1/explain` read
//! that one value. When no other revision takes new requests, the canary takes all of them while
//! its share is above `0`. A canary needs another serving revision with a weight to fall back to,
//! or the snapshot is refused (`canary_no_baseline`).
//!
//! # Judging
//!
//! The share starts at `step_percent`. A [`CanaryService`] judges every canary each
//! `interval_secs`, from the 5xx rate [`Outcomes`] holds for the canary revision, over the time
//! since the last decision:
//!
//! - fewer than [`MIN_REQUESTS`] requests: the share holds, and the window keeps growing until
//!   enough requests arrive, so one failure in one request never regresses a canary and a quiet
//!   canary neither ramps nor regresses;
//! - `5xx` rate below `max_error_permille`: the share grows by `step_percent`, up to `100`, and
//!   the next judgment starts from now;
//! - at or above it: the share drops to `0` for good and `canary_regressed {app, revision,
//!   error_permille}` is emitted once. The canary stays at `0`, and
//!   [`crate::table::CompiledApp::pick_pinned`] refuses it, so sessions pinned to it fall back to
//!   the weighted pick and get a fresh cookie. Only a change to the canary policy or the app's
//!   serving set gives it traffic again; a push for another app does not.
//!
//! At `100` the canary is promoted and judging stops; the control plane makes it the only
//!
//! # With auto-revert
//!
//! The 5xx of the canary revision do not count toward the auto-revert of its app
//! ([`crate::revert`]) while the pushed snapshot has a canary policy: the canary already
//! isolates them to its share and pulls itself back. The other revisions of the app still count.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

use crate::events::{EventFeed, EventKind};
use crate::outcomes::Outcomes;
use crate::snapshot::{App, Canary, RevisionState};
use crate::table::{CompiledApp, TableHandle};

/// Fewest requests of the canary in a window before its error rate means anything.
pub const MIN_REQUESTS: u64 = 20;

/// How often the background service checks whether a judgment is due.
const TICK: Duration = Duration::from_millis(250);

/// Why a canary policy is refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Reason {
    /// `revision` is not a revision of the app.
    #[error("revision {0} does not exist")]
    UnknownRevision(Box<str>),
    /// The canary revision is not `serving`.
    #[error("revision {0} must be serving")]
    NotServing(Box<str>),
    /// `step_percent` is outside `1..=100`.
    #[error("step_percent must be 1..=100, got {0}")]
    InvalidStep(u32),
    /// `interval_secs` is `0`.
    #[error("interval_secs must be at least 1")]
    InvalidInterval,
    /// `max_error_permille` is outside `1..=1000`.
    #[error("max_error_permille must be 1..=1000, got {0}")]
    InvalidThreshold(u32),
    /// No other serving revision with a weight exists to take the rest of the traffic.
    #[error("no other serving revision with a weight to share traffic with the canary")]
    NoBaseline,
}

/// A canary policy the compiler refuses, with where it was declared.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("app {app} ({declared_by}) canary: {reason}")]
pub struct Rejection {
    /// The declaring app.
    pub app: Box<str>,
    /// Its `declared_by` source.
    pub declared_by: Box<str>,
    /// What is wrong.
    pub reason: Reason,
}

impl Rejection {
    /// The stable code: `canary_revision_missing`, `canary_revision_not_serving`,
    /// `canary_step_invalid`, `canary_interval_invalid`, `canary_threshold_invalid` or
    /// `canary_no_baseline`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self.reason {
            Reason::UnknownRevision(_) => "canary_revision_missing",
            Reason::NotServing(_) => "canary_revision_not_serving",
            Reason::InvalidStep(_) => "canary_step_invalid",
            Reason::InvalidInterval => "canary_interval_invalid",
            Reason::InvalidThreshold(_) => "canary_threshold_invalid",
            Reason::NoBaseline => "canary_no_baseline",
        }
    }

    /// The object in the `conflicts` list of a `422` body: `code`, `message`, `app` and
    /// `declared_by`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code(), "message": self.to_string(),
            "app": self.app, "declared_by": self.declared_by,
        })
    }
}

/// The messages of `rejections`, separated by `; `.
pub(crate) fn join(rejections: &[Rejection]) -> String {
    rejections
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Every reason `app`'s canary policy is refused; empty when it has none or it is sound.
pub(crate) fn validate(app: &App) -> Vec<Rejection> {
    let Some(policy) = &app.canary else {
        return Vec::new();
    };
    let mut reasons = Vec::new();
    if !(1..=100).contains(&policy.step_percent) {
        reasons.push(Reason::InvalidStep(policy.step_percent));
    }
    if policy.interval_secs == 0 {
        reasons.push(Reason::InvalidInterval);
    }
    if !(1..=1000).contains(&policy.max_error_permille) {
        reasons.push(Reason::InvalidThreshold(policy.max_error_permille));
    }
    match app.revisions.iter().find(|rev| rev.id == policy.revision) {
        None => reasons.push(Reason::UnknownRevision(policy.revision.clone())),
        Some(revision) if revision.state != RevisionState::Serving => {
            reasons.push(Reason::NotServing(policy.revision.clone()));
        }
        Some(_) => {}
    }
    let has_baseline = app.revisions.iter().any(|rev| {
        rev.id != policy.revision && rev.state == RevisionState::Serving && rev.weight > 0
    });
    if !has_baseline {
        reasons.push(Reason::NoBaseline);
    }
    reasons
        .into_iter()
        .map(|reason| Rejection {
            app: app.id.clone(),
            declared_by: app.declared_by.clone(),
            reason,
        })
        .collect()
}

/// What a canary's runtime state is valid for: the policy (which names the canary revision) and
/// the serving set of its app, every revision's id, state and weight in order. Backends are not
/// part of it: autoscaling changes them all the time and must not reset a verdict. A new
/// snapshot that leaves all of it as it was keeps the state; any difference starts over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fingerprint {
    policy: Canary,
    revisions: Box<[Slot]>,
}

/// One revision of a [`Fingerprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Slot {
    id: Box<str>,
    state: RevisionState,
    weight: u16,
}

impl Fingerprint {
    pub(crate) fn of(app: &App, policy: &Canary) -> Self {
        Self {
            policy: policy.clone(),
            revisions: app
                .revisions
                .iter()
                .map(|rev| Slot {
                    id: rev.id.clone(),
                    state: rev.state,
                    weight: rev.weight,
                })
                .collect(),
        }
    }
}

/// The live state of one app's canary. Shared by every table of the app that has the same
/// [`Fingerprint`]: the registry ([`Registry`]) hands the same runtime to each, so a push that
/// does not touch the app neither resets the share nor forgets a regression.
#[derive(Debug)]
pub(crate) struct Runtime {
    fingerprint: Fingerprint,
    /// Index of the canary in the app's revisions.
    index: usize,
    share: AtomicU8,
    regressed: AtomicBool,
    /// Where the window of the next judgment starts.
    since: Mutex<Instant>,
    /// The effective weight of each revision, shared with the revisions of every table using
    /// this runtime, so a share change reaches requests that still hold an older table.
    weights: Box<[Arc<AtomicU16>]>,
}

impl Runtime {
    /// A canary at its first step. Judging starts one second after `now`: outcomes are counted in
    /// whole seconds, so this keeps what the revision did before the snapshot out of the first window.
    pub(crate) fn new(
        fingerprint: Fingerprint,
        index: usize,
        weights: Box<[Arc<AtomicU16>]>,
        now: Instant,
    ) -> Self {
        let share = u8::try_from(fingerprint.policy.step_percent.min(100)).unwrap_or(100);
        Self {
            fingerprint,
            index,
            share: AtomicU8::new(share),
            regressed: AtomicBool::new(false),
            since: Mutex::new(now + Duration::from_secs(1)),
            weights,
        }
    }

    pub(crate) fn policy(&self) -> &Canary {
        &self.fingerprint.policy
    }

    pub(crate) fn index(&self) -> usize {
        self.index
    }

    pub(crate) fn weights(&self) -> &[Arc<AtomicU16>] {
        &self.weights
    }

    pub(crate) fn share(&self) -> u8 {
        self.share.load(Ordering::Relaxed)
    }

    pub(crate) fn set_share(&self, percent: u8) {
        self.share.store(percent, Ordering::Relaxed);
    }

    pub(crate) fn regressed(&self) -> bool {
        self.regressed.load(Ordering::Acquire)
    }
}

/// The canary runtimes of the live table, by app id. Owned by [`crate::table::TableHandle`],
/// outside any table, so they outlive swaps like [`crate::Outcomes`] and [`crate::Inflight`].
#[derive(Debug, Default)]
pub(crate) struct Registry {
    runtimes: Mutex<HashMap<Box<str>, Arc<Runtime>>>,
}

impl Registry {
    /// Settles the canaries of a table about to go live: an app whose [`Fingerprint`] equals the
    /// registered one takes over the registered runtime (and its share, verdict and weights);
    /// any other app keeps the fresh runtime compiled for it, which replaces the old entry.
    /// Entries of apps the table no longer has, or no longer gives a canary, are dropped.
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        let mut runtimes = self.runtimes.lock().unwrap_or_else(PoisonError::into_inner);
        let mut kept = HashMap::new();
        for app in apps {
            let Some(fresh) = app.canary_runtime() else {
                continue;
            };
            let id: Box<str> = app.id().into();
            let runtime = match runtimes.get(&id) {
                Some(old) if old.fingerprint == fresh.fingerprint => {
                    let old = Arc::clone(old);
                    app.adopt_canary(Arc::clone(&old));
                    old
                }
                _ => Arc::clone(fresh),
            };
            kept.insert(id, runtime);
        }
        *runtimes = kept;
    }
}

/// What `GET /v1/explain` reports about a canary.
#[derive(Debug, Serialize)]
pub struct Status<'a> {
    /// The canary revision.
    pub revision: &'a str,
    /// Percent of new sessions it gets now; `0` once regressed.
    pub share_percent: u8,
    /// Whether it breached `max_error_permille` and was pulled back.
    pub regressed: bool,
    /// As configured.
    pub step_percent: u32,
    /// As configured.
    pub interval_secs: u64,
    /// As configured.
    pub max_error_permille: u32,
}

impl<'a> Status<'a> {
    pub(crate) fn of(runtime: &'a Runtime) -> Self {
        Self {
            revision: &runtime.policy().revision,
            share_percent: runtime.share(),
            regressed: runtime.regressed(),
            step_percent: runtime.policy().step_percent,
            interval_secs: runtime.policy().interval_secs,
            max_error_permille: runtime.policy().max_error_permille,
        }
    }
}

/// Judges the canary of `app` if a judgment is due at `now`; see the module docs for the rules.
pub fn judge(app: &CompiledApp, outcomes: &Outcomes, events: &EventFeed, now: Instant) {
    let Some(runtime) = app.canary_runtime() else {
        return;
    };
    let share = runtime.share();
    if runtime.regressed() || share >= 100 {
        return;
    }
    let policy = runtime.policy();
    let mut since = runtime.since.lock().unwrap_or_else(PoisonError::into_inner);
    let elapsed = now.saturating_duration_since(*since);
    if elapsed < Duration::from_secs(policy.interval_secs) {
        return;
    }
    let counts = outcomes.window_at(app.id(), Some(&policy.revision), elapsed, now);
    if counts.total < MIN_REQUESTS {
        return;
    }
    let breached = counts.errors_5xx * 1000 >= u64::from(policy.max_error_permille) * counts.total;
    if !breached {
        let next = u8::try_from(policy.step_percent)
            .unwrap_or(100)
            .saturating_add(share)
            .min(100);
        app.set_canary_share(next);
        *since = now;
    } else if !runtime.regressed.swap(true, Ordering::AcqRel) {
        app.set_canary_share(0);
        let error_permille = counts.error_permille().unwrap_or(1000);
        tracing::warn!(
            app = app.id(),
            revision = &*policy.revision,
            error_permille,
            "canary regressed, pulled back to 0"
        );
        events.emit(EventKind::CanaryRegressed {
            app: app.id().into(),
            revision: policy.revision.clone(),
            error_permille,
        });
    }
}

/// Runs [`judge`] for every app of the live table until shutdown. Run it as a Pingora
/// background service.
#[derive(Debug)]
pub struct CanaryService {
    table: TableHandle,
    outcomes: Outcomes,
    events: EventFeed,
}

impl CanaryService {
    /// Judges the canaries of the table behind `table` by `outcomes`, reporting into `events`.
    #[must_use]
    pub fn new(table: TableHandle, outcomes: Outcomes, events: EventFeed) -> Self {
        Self {
            table,
            outcomes,
            events,
        }
    }
}

#[async_trait]
impl BackgroundService for CanaryService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // The timeout elapsing is the tick; the channel changing or closing is the shutdown.
        while tokio::time::timeout(TICK, shutdown.changed())
            .await
            .is_err()
        {
            let table = self.table.load();
            let now = Instant::now();
            for app in (0..).map_while(|index| table.app(index)) {
                judge(app, &self.outcomes, &self.events, now);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;
    use crate::snapshot::Snapshot;
    use crate::table::{CompileError, RoutingTable, TableHandle};

    fn snapshot(canary: &serde_json::Value) -> Snapshot {
        serde_json::from_value(json!({
            "version": 1,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "test", "hosts": ["a.test"],
                "tls": {"mode": "acme"},
                "canary": canary,
                "revisions": [
                    {"id": "old", "upstreams": ["127.0.0.1:1"], "weight": 3, "state": "serving"},
                    {"id": "new", "upstreams": ["127.0.0.1:2"], "weight": 1, "state": "serving"},
                    {"id": "gone", "upstreams": ["127.0.0.1:3"], "weight": 1, "state": "draining"}
                ]
            }]
        }))
        .expect("valid snapshot")
    }

    fn codes(canary: &serde_json::Value) -> Vec<&'static str> {
        match RoutingTable::compile(&snapshot(canary)) {
            Err(CompileError::Canary(rejections)) => {
                rejections.iter().map(Rejection::code).collect()
            }
            other => panic!("expected canary rejections, got {other:?}"),
        }
    }

    fn policy(revision: &str, step: u32, interval: u64, max: u32) -> serde_json::Value {
        json!({"revision": revision, "step_percent": step,
               "interval_secs": interval, "max_error_permille": max})
    }

    #[test]
    fn canary_compile_accepts_a_sound_policy_and_starts_at_one_step() {
        let table = RoutingTable::compile(&snapshot(&policy("new", 10, 5, 50))).expect("compiles");
        let status = table.app(0).and_then(CompiledApp::canary).expect("canary");
        assert_eq!(
            (status.revision, status.share_percent, status.regressed),
            ("new", 10, false)
        );
    }

    #[test]
    fn canary_compile_refuses_each_unsound_policy_with_a_code() {
        assert_eq!(
            codes(&policy("nope", 10, 5, 50)),
            ["canary_revision_missing"]
        );
        assert_eq!(
            codes(&policy("gone", 10, 5, 50)),
            ["canary_revision_not_serving"]
        );
        assert_eq!(codes(&policy("new", 0, 5, 50)), ["canary_step_invalid"]);
        assert_eq!(codes(&policy("new", 101, 5, 50)), ["canary_step_invalid"]);
        assert_eq!(
            codes(&policy("new", 10, 0, 50)),
            ["canary_interval_invalid"]
        );
        assert_eq!(
            codes(&policy("new", 10, 5, 0)),
            ["canary_threshold_invalid"]
        );
        assert_eq!(
            codes(&policy("new", 10, 5, 1001)),
            ["canary_threshold_invalid"]
        );
    }

    #[test]
    fn canary_compile_reports_every_problem_of_a_policy() {
        assert_eq!(
            codes(&policy("nope", 0, 0, 0)),
            [
                "canary_step_invalid",
                "canary_interval_invalid",
                "canary_threshold_invalid",
                "canary_revision_missing",
            ]
        );
    }

    #[test]
    fn canary_weights_split_the_rest_by_configured_weight() {
        let table = RoutingTable::compile(&snapshot(&policy("new", 20, 5, 50))).expect("compiles");
        let app = table.app(0).expect("app");
        let live: Vec<u16> = app
            .revisions()
            .iter()
            .map(crate::table::CompiledRevision::effective_weight)
            .collect();
        assert_eq!(live, [8000, 2000, 0]);
        app.set_canary_share(0);
        let live: Vec<u16> = app
            .revisions()
            .iter()
            .map(crate::table::CompiledRevision::effective_weight)
            .collect();
        assert_eq!(live, [10000, 0, 0]);
    }

    #[test]
    fn canary_pick_follows_the_share_and_a_regressed_canary_keeps_no_pins() {
        let table = RoutingTable::compile(&snapshot(&policy("new", 20, 5, 50))).expect("compiles");
        let app = table.app(0).expect("app");
        let on_canary = |app: &CompiledApp| {
            (0..1000)
                .filter(|_| app.pick().is_some_and(|pick| pick.upstream.port() == 2))
                .count()
        };
        assert!((190..=210).contains(&on_canary(app)));
        assert!(app.pick_pinned("new").is_some());

        let runtime = app.canary_runtime().expect("canary");
        runtime.regressed.store(true, Ordering::Release);
        app.set_canary_share(0);
        assert_eq!(on_canary(app), 0);
        assert!(app.pick_pinned("new").is_none());
        assert!(app.pick_pinned("old").is_some());
    }

    fn regress(handle: &TableHandle) {
        let table = handle.load();
        let app = table.app(0).expect("app");
        app.canary_runtime()
            .expect("canary")
            .regressed
            .store(true, Ordering::Release);
        app.set_canary_share(0);
    }

    fn with_version(version: u64, mut snapshot: Snapshot) -> Snapshot {
        snapshot.version = version;
        snapshot
    }

    #[test]
    fn canary_state_follows_the_registry_across_swaps() {
        let handle = TableHandle::new();
        let first = snapshot(&policy("new", 20, 5, 50));
        handle.apply(&first).expect("applies");
        let held = handle.load();
        regress(&handle);

        // Another app appears: the canary app is untouched, so its verdict carries over, in the
        // new table and in the one a request still holds.
        let mut with_other = with_version(2, first.clone());
        let mut other = with_other.apps[0].clone();
        other.id = "b".into();
        other.hosts = vec!["b.test".into()];
        other.canary = None;
        with_other.apps.push(other);
        handle.apply(&with_other).expect("applies");
        let live = handle.load();
        let status = live.app(0).and_then(CompiledApp::canary).expect("canary");
        assert_eq!((status.share_percent, status.regressed), (0, true));
        assert_eq!(live.app(0).map(|app| app.pick().is_some()), Some(true));
        let weights = |table: &RoutingTable| -> Vec<u16> {
            table.app(0).map_or_else(Vec::new, |app| {
                app.revisions()
                    .iter()
                    .map(|rev| rev.effective_weight())
                    .collect()
            })
        };
        assert_eq!(weights(&live), [10_000, 0, 0]);
        assert_eq!(
            weights(&held),
            weights(&live),
            "an older table shares the weights"
        );

        // A different serving set starts over.
        let mut changed = with_version(3, with_other.clone());
        changed.apps[0].revisions[0].weight = 4;
        handle.apply(&changed).expect("applies");
        let status = handle
            .load()
            .app(0)
            .and_then(CompiledApp::canary)
            .map(|s| (s.share_percent, s.regressed));
        assert_eq!(status, Some((20, false)));

        // Losing the canary drops its entry; a canary that comes back is new.
        regress(&handle);
        let mut without = with_version(4, changed.clone());
        without.apps[0].canary = None;
        handle.apply(&without).expect("applies");
        let back = with_version(5, changed);
        handle.apply(&back).expect("applies");
        let status = handle
            .load()
            .app(0)
            .and_then(CompiledApp::canary)
            .map(|s| (s.share_percent, s.regressed));
        assert_eq!(status, Some((20, false)));
    }

    #[test]
    fn canary_state_ignores_backend_changes_but_weights_follow_them() {
        let handle = TableHandle::new();
        let first = snapshot(&policy("new", 20, 5, 50));
        handle.apply(&first).expect("applies");
        regress(&handle);
        let weights = |handle: &TableHandle| -> Vec<u16> {
            handle.load().app(0).map_or_else(Vec::new, |app| {
                app.revisions()
                    .iter()
                    .map(crate::table::CompiledRevision::effective_weight)
                    .collect()
            })
        };
        assert_eq!(weights(&handle), [10_000, 0, 0]);

        // A scale-out of the baseline keeps the verdict.
        let mut scaled = with_version(2, first.clone());
        scaled.apps[0].revisions[0]
            .upstreams
            .push(std::net::SocketAddr::from(([127, 0, 0, 1], 9)));
        handle.apply(&scaled).expect("applies");
        let table = handle.load();
        let status = table.app(0).and_then(CompiledApp::canary);
        assert_eq!(
            status.map(|status| (status.share_percent, status.regressed)),
            Some((0, true))
        );
        assert_eq!(weights(&handle), [10_000, 0, 0]);

        // The baseline loses every backend: it takes nothing, and the weights say so.
        let mut empty = with_version(3, first);
        empty.apps[0].revisions[0].upstreams.clear();
        handle.apply(&empty).expect("applies");
        let table = handle.load();
        let status = table.app(0).and_then(CompiledApp::canary);
        assert_eq!(
            status.map(|status| (status.share_percent, status.regressed)),
            Some((0, true))
        );
        assert_eq!(weights(&handle), [0, 0, 0]);
    }
}
