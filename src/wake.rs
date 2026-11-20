//! Scale to zero: hold requests for a sleeping app until it wakes, and report idle apps.
//!
//! An app with [`crate::snapshot::ScaleToZero`] may have no upstream at all. A request for it is not refused: it
//! is *held* ([`Wake::hold`]) until a snapshot gives the app an upstream or `wake_timeout_secs`
//! pass. Holding starts a *wake cycle*, which lasts while at least one request of the app is
//! held; the first held request of a cycle emits [`EventKind::WakeRequested`], later ones emit
//! nothing. A held request keeps a tenant in-flight slot, so held requests count against
//! `max_inflight` like running ones.
//!
//! The other half is [`EventKind::AppIdle`]: [`Wake::sweep`] reports an awake app once after
//! `idle_secs` with no request in flight and none started, and a new request re-arms it. A
//! [`WakeService`] runs the sweep in the background.
//!
//! State is keyed by app id and lives in [`Wake`], outside the routing table, so it survives
//! snapshot swaps.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

use crate::budget::{self, Budgets, TenantSlot};
use crate::error::AppError;
use crate::events::{EventFeed, EventKind};
use crate::route::RouteError;
use crate::router::Matched;
use crate::table::{CompiledApp, RoutingTable, TableHandle};

/// How often the background service looks for idle apps.
const SWEEP_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A request is running or about to run on an awake app.
    Active,
    /// A request is held for a sleeping app.
    Waiting,
}

#[derive(Debug)]
struct Entry {
    waiting: u32,
    active: u32,
    last_activity: Instant,
    idle_reported: bool,
}

#[derive(Debug)]
struct Shared {
    events: EventFeed,
    apps: Mutex<HashMap<Box<str>, Entry>>,
}

/// Wake and idle bookkeeping of every scale-to-zero app. Cheap to clone; every clone shares it.
#[derive(Debug, Clone)]
pub struct Wake {
    shared: Arc<Shared>,
}

impl Default for Wake {
    /// A `Wake` whose events go to a feed nobody reads.
    fn default() -> Self {
        Self::new(EventFeed::new())
    }
}

/// A request counted on an app until it drops.
#[derive(Debug)]
struct Counted {
    shared: Arc<Shared>,
    app: Box<str>,
    kind: Kind,
}

impl Drop for Counted {
    fn drop(&mut self) {
        let mut apps = self
            .shared
            .apps
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = apps.get_mut(&self.app) else {
            return;
        };
        match self.kind {
            Kind::Active => {
                entry.active = entry.active.saturating_sub(1);
                entry.last_activity = Instant::now();
            }
            Kind::Waiting => entry.waiting = entry.waiting.saturating_sub(1),
        }
    }
}

/// The tenant slot a held request keeps while it waits, and the tenant it was charged to.
#[derive(Debug)]
struct Held {
    tenant: Box<str>,
    slot: TenantSlot,
}

/// Per-request wake state, one field of the proxy's `Ctx`.
#[derive(Debug, Default)]
pub struct State {
    /// Keeps the app counted as active while the request runs.
    active: Option<Counted>,
    /// The tenant slot taken when the request was held, handed on by [`Wake::admit`].
    held: Option<Held>,
    /// When this request stops waiting for the app to wake; set by the first hold.
    deadline: Option<Instant>,
}

impl Wake {
    /// Bookkeeping that reports into `events`.
    #[must_use]
    pub fn new(events: EventFeed) -> Self {
        Self {
            shared: Arc::new(Shared {
                events,
                apps: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Counts a request of `app` as `kind`. Returns whether it is the first waiting request.
    fn enter(&self, app: &str, kind: Kind) -> (Counted, bool) {
        let mut apps = self
            .shared
            .apps
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !apps.contains_key(app) {
            apps.insert(
                app.into(),
                Entry {
                    waiting: 0,
                    active: 0,
                    last_activity: Instant::now(),
                    idle_reported: false,
                },
            );
        }
        let mut first = false;
        if let Some(entry) = apps.get_mut(app) {
            match kind {
                Kind::Active => {
                    entry.active += 1;
                    entry.last_activity = Instant::now();
                    entry.idle_reported = false;
                }
                Kind::Waiting => {
                    first = entry.waiting == 0;
                    entry.waiting += 1;
                    entry.last_activity = Instant::now();
                    entry.idle_reported = false;
                }
            }
        }
        let counted = Counted {
            shared: Arc::clone(&self.shared),
            app: app.into(),
            kind,
        };
        (counted, first)
    }

    /// Admits a routed request to the app at index `app` of `table`: takes the in-flight slot
    /// of its tenant, or hands on the one [`Self::hold`] already took, and marks a
    /// scale-to-zero app as active until `state` drops. Call it where the proxy charges the
    /// tenant.
    ///
    /// # Errors
    ///
    /// [`AppError::Overloaded`] when the tenant is at `max_inflight`; see [`budget::admit`].
    pub fn admit(
        &self,
        state: &mut State,
        budgets: &Budgets,
        table: &RoutingTable,
        app: usize,
    ) -> Result<Option<TenantSlot>, AppError> {
        let compiled = table.app(app);
        if let Some(compiled) = compiled.filter(|compiled| compiled.scale_to_zero().is_some()) {
            // Built before the previous guard drops, so the count never dips to zero.
            state.active = Some(self.enter(compiled.id(), Kind::Active).0);
        }
        if let Some(held) = state.held.take()
            && compiled.is_some_and(|compiled| compiled.tenant() == &*held.tenant)
        {
            return Ok(Some(held.slot));
        }
        budget::admit(budgets, table, app)
    }

    /// Holds a request that found its app without an upstream, until the live table gives the
    /// app one.
    ///
    /// `matched` is the router the request matched in `table`. On `Ok` the request must select
    /// again: `table` is the live table and `matched` the same router in it (see
    /// [`RoutingTable::rematch`]; a request never continues under a different chain or TLS
    /// policy than it started with). The first request held for an app emits `wake_requested`,
    /// and all of them take a tenant slot, kept until [`Self::admit`] hands it on.
    ///
    /// # Errors
    ///
    /// The usual no-upstream `503` when the app does not scale to zero, or when a snapshot
    /// changed the router's middleware chain or the app's TLS policy while the request waited.
    /// `404` when a snapshot removed the app. [`AppError::Overloaded`] when the tenant has no
    /// slot for the held request. [`AppError::WakeTimeout`] when the request's
    /// `wake_timeout_secs` pass without an upstream; the budget is per request, not per hold.
    pub async fn hold(
        &self,
        state: &mut State,
        table: &mut Arc<RoutingTable>,
        live: &TableHandle,
        budgets: &Budgets,
        matched: &mut Matched,
    ) -> Result<(), AppError> {
        let asleep = || AppError::from(RouteError::NoUpstream);
        let app = table.app(matched.app).ok_or_else(asleep)?;
        let policy = app.scale_to_zero().ok_or_else(asleep)?;
        let id: Box<str> = app.id().into();
        if state.held.is_none() {
            state.held = budget::admit(budgets, table, matched.app)?.map(|slot| Held {
                tenant: app.tenant().into(),
                slot,
            });
        }
        let deadline = *state
            .deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(policy.wake_timeout_secs));

        let (_waiting, first) = self.enter(&id, Kind::Waiting);
        if first {
            self.shared
                .events
                .emit(EventKind::WakeRequested { app: id.clone() });
        }
        // Subscribed before the first load: a swap in between is seen by `changed`.
        let mut swaps = live.subscribe();
        loop {
            let newest = live.load();
            if is_awake_or_gone(&newest, &id) {
                let found = newest.rematch(table, *matched);
                let gone = newest.app_by_id(&id).is_none();
                // On failure `table` and `matched` stay as they were, so they still agree.
                return match found {
                    Some(rematched) => {
                        *table = newest;
                        *matched = rematched;
                        Ok(())
                    }
                    None if gone => Err(AppError::NotFound),
                    None => Err(asleep()),
                };
            }
            let left = deadline.saturating_duration_since(Instant::now());
            // A closed signal cannot happen while `live` is borrowed; it would end the wait too.
            if !matches!(
                tokio::time::timeout(left, swaps.changed()).await,
                Ok(Ok(()))
            ) {
                return Err(AppError::WakeTimeout);
            }
        }
    }

    /// Reports every app of `table` that has `scale_to_zero`, is awake and has seen no request
    /// since `idle_secs` before `now`, once per idle period. Forgets apps that are no longer
    /// scale-to-zero once nothing of theirs is running or held.
    pub fn sweep(&self, table: &RoutingTable, now: Instant) {
        let mut apps = self
            .shared
            .apps
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut kept = HashSet::new();
        for app in (0..).map_while(|index| table.app(index)) {
            let Some(policy) = app.scale_to_zero() else {
                continue;
            };
            kept.insert(app.id());
            if !apps.contains_key(app.id()) {
                apps.insert(
                    app.id().into(),
                    Entry {
                        waiting: 0,
                        active: 0,
                        last_activity: now,
                        idle_reported: false,
                    },
                );
            }
            let Some(entry) = apps.get_mut(app.id()) else {
                continue;
            };
            if !has_upstream(app) {
                // Asleep: the idle clock starts when it wakes.
                entry.last_activity = now;
                entry.idle_reported = false;
                continue;
            }
            let quiet = now.saturating_duration_since(entry.last_activity);
            if entry.active == 0
                && !entry.idle_reported
                && quiet >= Duration::from_secs(policy.idle_secs)
            {
                entry.idle_reported = true;
                self.shared.events.emit(EventKind::AppIdle {
                    app: app.id().into(),
                });
            }
        }
        apps.retain(|id, entry| kept.contains(&**id) || entry.active > 0 || entry.waiting > 0);
    }
}

fn has_upstream(app: &CompiledApp) -> bool {
    app.revisions()
        .iter()
        .any(|revision| revision.effective_weight() > 0)
}

/// Whether a request for app `id` should stop waiting: the app has an upstream, or it is gone
/// or no longer scales to zero, in which case routing gives the final answer.
fn is_awake_or_gone(table: &RoutingTable, id: &str) -> bool {
    table
        .app_by_id(id)
        .is_none_or(|(_, app)| app.scale_to_zero().is_none() || has_upstream(app))
}

/// Runs [`Wake::sweep`] against the live table until shutdown. Run it as a Pingora background
/// service.
#[derive(Debug)]
pub struct WakeService {
    wake: Wake,
    table: TableHandle,
}

impl WakeService {
    /// Sweeps `wake` against the table behind `table`.
    #[must_use]
    pub fn new(wake: Wake, table: TableHandle) -> Self {
        Self { wake, table }
    }
}

#[async_trait]
impl BackgroundService for WakeService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // The timeout elapsing is the tick; the channel changing or closing is the shutdown.
        while tokio::time::timeout(SWEEP_INTERVAL, shutdown.changed())
            .await
            .is_err()
        {
            self.wake.sweep(&self.table.load(), Instant::now());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::events::EventFeed;
    use crate::snapshot::Snapshot;

    fn table(servers: &str, idle_secs: u64) -> RoutingTable {
        let json = format!(
            r#"{{
            "version": 1,
            "tenants": [{{"id": "t", "weight": 1, "budget": {{"max_inflight": 5, "max_buffer_bytes": 1}}}}],
            "apps": [{{
                "id": "a", "tenant": "t", "declared_by": "test",
                "tls": {{"mode": "acme"}},
                "scale_to_zero": {{"idle_secs": {idle_secs}}},
                "routers": [{{"name": "all", "match": {{"host": "a.test"}}, "service": "web"}}],
                "revisions": [{{"id": "r", "weight": 1, "state": "serving", "services": [
                    {{"name": "web", "type": "loadbalancer", "servers": {servers}}}]}}]
            }}]
        }}"#
        );
        let snapshot: Snapshot = serde_json::from_str(&json).expect("valid snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    #[test]
    fn scale_to_zero_compile_defaults_the_wake_timeout() {
        let table = table("[]", 60);
        let policy = table
            .app(0)
            .and_then(CompiledApp::scale_to_zero)
            .expect("policy compiled");
        assert_eq!((policy.idle_secs, policy.wake_timeout_secs), (60, 30));
    }

    #[test]
    fn idle_is_reported_once_per_period_and_rearmed_by_a_request() {
        let feed = EventFeed::new();
        let wake = Wake::new(feed.clone());
        let table = table(r#"[{"url": "http://127.0.0.1:9"}]"#, 10);
        let start = Instant::now();
        wake.sweep(&table, start);
        wake.sweep(&table, start + Duration::from_secs(9));
        wake.sweep(&table, start + Duration::from_secs(11));
        wake.sweep(&table, start + Duration::from_secs(12));

        let mut state = State::default();
        let budgets = Budgets::new();
        let slot = wake
            .admit(&mut state, &budgets, &table, 0)
            .expect("admitted");
        wake.sweep(&table, start + Duration::from_secs(100));
        drop(slot);
        drop(state);
        wake.sweep(&table, Instant::now() + Duration::from_secs(11));

        let kinds: Vec<_> = events_of(&feed);
        assert_eq!(
            kinds,
            vec![
                EventKind::AppIdle { app: "a".into() },
                EventKind::AppIdle { app: "a".into() },
            ]
        );
    }

    fn events_of(feed: &EventFeed) -> Vec<EventKind> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let events = runtime
            .block_on(feed.poll(0, Duration::ZERO))
            .expect("events retained");
        events.into_iter().map(|event| event.kind).collect()
    }
}
