//! [`Registry`]: every series outside the routing table, so counters survive snapshot pushes.
//!
//! # Lifetime
//!
//! A table compiles without handles. At the one swap site ([`crate::table::TableHandle`] calls
//! [`Registry::settle`] just before a table goes live, next to the circuit breakers and the
//! canary) each router and each service a router names gets a [`Series`]:
//!
//! - an object the registry already knows keeps its series when its fingerprint is unchanged, so
//!   a push that touches another app, or only other parts of this one, loses no counter. A router
//!   whose fingerprint changed (its matcher, priority, service or entry points) starts a fresh
//!   series: it is another route now;
//! - an object a snapshot no longer declares keeps being reported for [`RETENTION`], so a scrape
//!   that lands just after a deploy still sees its last counts, and is then forgotten;
//! - services are keyed by app and name only. Every revision that defines a service of that name
//!   records into it, so a deploy that replaces a revision's service does not reset the series.
//!
//! # Cardinality
//!
//! Each tenant may own at most `series_per_tenant` series: a router, a service and a server each
//! cost one (the status classes and histogram buckets are fixed multipliers, not labels). An
//! object past the cap records into the app's `other` series instead, and
//! `podgate_metrics_collapsed_total{tenant}` counts each object that newly collapsed. A series
//! that was retained for a removed object is dropped early to make room, oldest first, so the
//! cap bounds what a tenant can make the registry hold however fast it churns names. Servers past
//! the cap are not reported on `service_server_up`. The `other` series themselves (two per app)
//! do not count against the cap.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::entry::EntrySeries;
use super::series::Series;
use super::table::{AppSeries, RouteSeries, TableSeries};
use super::text;
use crate::router::{CompiledRouter, digest};
use crate::table::{ApplyError, CompileError, CompiledApp, RoutingTable};
use std::num::NonZeroU32;

/// The name every over-cap object records under.
const OTHER: &str = "other";

/// Series per tenant when nothing says otherwise.
pub const DEFAULT_SERIES_PER_TENANT: NonZeroU32 = match NonZeroU32::new(500) {
    Some(cap) => cap,
    None => NonZeroU32::MIN,
};

/// How long a removed object's series is still reported.
pub const RETENTION: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Router,
    Service,
    /// Only to tell whether a server over the cap was already counted as collapsed.
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    app: Box<str>,
    kind: Kind,
    name: Box<str>,
}

#[derive(Debug)]
struct Slot {
    series: Arc<Series>,
    fingerprint: u64,
    tenant: Box<str>,
    /// An app's `other` series: not counted against the cap, kept while the app exists.
    overflow: bool,
    /// When the object left the snapshot, `None` while it is declared.
    removed: Option<Instant>,
}

#[derive(Debug, Default)]
struct Inner {
    slots: HashMap<Key, Slot>,
    /// What collapsed at the last swap, to count only what is new.
    collapsed: HashSet<Key>,
    collapsed_total: BTreeMap<Box<str>, u64>,
}

/// What a router or service was wanted as.
#[derive(Debug)]
struct Want<'a> {
    tenant: &'a str,
    key: Key,
    fingerprint: u64,
}

/// The shared metric state of one process: the series of entry points, routers and services, the
/// snapshot counters, and the cap that bounds them. Owned by [`crate::TableHandle`]; render it
/// with [`super::render`].
#[derive(Debug)]
pub struct Registry {
    per_tenant: usize,
    retention: Duration,
    inner: Mutex<Inner>,
    entry_points: Mutex<BTreeMap<Box<str>, Arc<EntrySeries>>>,
    rejected: Mutex<BTreeMap<&'static str, u64>>,
    applied_unix_secs: AtomicU64,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new(DEFAULT_SERIES_PER_TENANT)
    }
}

impl Registry {
    /// A registry that lets each tenant own `series_per_tenant` series.
    #[must_use]
    pub fn new(series_per_tenant: NonZeroU32) -> Self {
        Self {
            per_tenant: usize::try_from(series_per_tenant.get()).unwrap_or(usize::MAX),
            retention: RETENTION,
            inner: Mutex::default(),
            entry_points: Mutex::default(),
            rejected: Mutex::default(),
            applied_unix_secs: AtomicU64::new(0),
        }
    }

    /// Reports removed objects for `retention` instead of [`RETENTION`].
    #[must_use]
    pub fn with_retention(mut self, retention: Duration) -> Self {
        self.retention = retention;
        self
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The series of the entry point called `name`, created on first use. A gateway resolves it
    /// once when it is built; the request path never looks it up.
    #[must_use]
    pub fn entry_point(&self, name: &str) -> Arc<EntrySeries> {
        let mut points = self
            .entry_points
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(found) = points.get(name) {
            return Arc::clone(found);
        }
        let created = Arc::new(EntrySeries::default());
        points.insert(name.into(), Arc::clone(&created));
        created
    }

    /// Counts a snapshot that was refused, once per distinct code it was refused with.
    pub(crate) fn rejected(&self, err: &ApplyError) {
        let mut codes = rejection_codes(err);
        codes.sort_unstable();
        codes.dedup();
        let mut counts = self.rejected.lock().unwrap_or_else(PoisonError::into_inner);
        for code in codes {
            *counts.entry(code).or_default() += 1;
        }
    }

    /// Gives `table`, about to go live, the series of its routers and services.
    pub(crate) fn settle(&self, table: &mut RoutingTable) {
        self.settle_at(table, Instant::now());
    }

    fn settle_at(&self, table: &mut RoutingTable, now: Instant) {
        let mut guard = self.inner();
        let inner = &mut *guard;
        inner.expire(now, self.retention);

        let mut wants = Vec::new();
        // For each app: the index of each router's want, and of each service name's.
        let mut plans: Vec<(Vec<usize>, HashMap<&str, usize>)> = Vec::new();
        for app in table.apps() {
            let mut routers = Vec::with_capacity(app.routers().len());
            let mut services: HashMap<&str, usize> = HashMap::new();
            for router in app.routers() {
                routers.push(wants.len());
                wants.push(want(
                    app,
                    Kind::Router,
                    router.name(),
                    router_fingerprint(router),
                ));
            }
            for router in app.routers() {
                services.entry(router.service()).or_insert_with(|| {
                    wants.push(want(app, Kind::Service, router.service(), 0));
                    wants.len() - 1
                });
            }
            plans.push((routers, services));
        }

        // Pass one: what the table no longer declares starts its retention, what it declares
        // again is revived, and an app that is gone takes its `other` series with it.
        let declared: HashSet<&Key> = wants.iter().map(|want| &want.key).collect();
        let present: HashSet<&str> = table.apps().iter().map(CompiledApp::id).collect();
        for (key, slot) in &mut inner.slots {
            let keep = if slot.overflow {
                present.contains(&*key.app)
            } else {
                declared.contains(key)
            };
            slot.removed = if keep {
                None
            } else {
                slot.removed.or(Some(now))
            };
        }

        // Pass two: every wanted object gets a series, in declaration order, so the first
        // objects of a tenant are the ones that keep their own.
        let mut held: HashMap<Box<str>, usize> = HashMap::new();
        let mut victims: HashMap<Box<str>, Vec<(Instant, Key)>> = HashMap::new();
        for (key, slot) in &inner.slots {
            if slot.overflow {
                continue;
            }
            *held.entry(slot.tenant.clone()).or_default() += 1;
            if let Some(since) = slot.removed {
                victims
                    .entry(slot.tenant.clone())
                    .or_default()
                    .push((since, key.clone()));
            }
        }
        // Newest first, so `pop` takes the oldest.
        for list in victims.values_mut() {
            list.sort_by_key(|(since, _)| std::cmp::Reverse(*since));
        }
        let mut live: HashMap<&str, usize> = HashMap::new();
        let mut collapsed: HashMap<Key, Box<str>> = HashMap::new();
        let mut handles: Vec<Arc<Series>> = Vec::with_capacity(wants.len());
        for want in &wants {
            if want.key.name.as_ref() == OTHER {
                handles.push(inner.overflow(&want.key, want.tenant));
                continue;
            }
            if let Some(slot) = inner.slots.get_mut(&want.key) {
                if slot.fingerprint != want.fingerprint {
                    slot.series = Arc::new(Series::default());
                    slot.fingerprint = want.fingerprint;
                }
                *live.entry(want.tenant).or_default() += 1;
                handles.push(Arc::clone(&slot.series));
                continue;
            }
            // A tenant under its cap takes a free slot; at the cap, the oldest series kept for
            // a removed object makes room, and with none the object collapses.
            let count = held.entry(want.tenant.into()).or_default();
            let room = if *count < self.per_tenant {
                *count += 1;
                true
            } else {
                victims
                    .get_mut(want.tenant)
                    .and_then(Vec::pop)
                    .is_some_and(|(_, victim)| inner.slots.remove(&victim).is_some())
            };
            if !room {
                collapsed.insert(want.key.clone(), want.tenant.into());
                handles.push(inner.overflow(&want.key, want.tenant));
                continue;
            }
            *live.entry(want.tenant).or_default() += 1;
            let series = Arc::new(Series::default());
            handles.push(Arc::clone(&series));
            inner.slots.insert(
                want.key.clone(),
                Slot {
                    series,
                    fingerprint: want.fingerprint,
                    tenant: want.tenant.into(),
                    overflow: false,
                    removed: None,
                },
            );
        }

        // Servers are read from the table at scrape time; they share the tenant's budget with
        // the series above, and the ones past it are not reported.
        let mut left: HashMap<&str, usize> = HashMap::new();
        let mut apps = Vec::with_capacity(plans.len());
        for (app, (routers, services)) in table.apps().iter().zip(&plans) {
            let routes = app
                .routers()
                .iter()
                .zip(routers)
                .filter_map(|(router, want)| {
                    let service = handles.get(*services.get(router.service())?)?;
                    Some(RouteSeries::new(
                        Arc::clone(handles.get(*want)?),
                        Arc::clone(service),
                    ))
                })
                .collect();
            let rows = servers_of(app);
            let budget = left.entry(app.tenant()).or_insert_with(|| {
                self.per_tenant
                    .saturating_sub(live.get(app.tenant()).copied().unwrap_or(0))
            });
            let shown = rows.len().min(*budget);
            *budget -= shown;
            for row in rows.iter().skip(shown) {
                collapsed.insert(
                    Key {
                        app: app.id().into(),
                        kind: Kind::Server,
                        name: format!("{}\0{}\0{}", row.revision, row.service, row.url).into(),
                    },
                    app.tenant().into(),
                );
            }
            apps.push(AppSeries {
                routes,
                servers_shown: shown,
            });
        }

        for (key, tenant) in &collapsed {
            if !inner.collapsed.contains(key) {
                *inner.collapsed_total.entry(tenant.clone()).or_default() += 1;
            }
        }
        inner.collapsed = collapsed.into_keys().collect();
        let tenants: HashSet<&str> = table.apps().iter().map(CompiledApp::tenant).collect();
        inner
            .collapsed_total
            .retain(|tenant, _| tenants.contains(&**tenant));

        drop(guard);
        table.set_series(TableSeries::new(apps));
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        self.applied_unix_secs.store(unix, Ordering::Relaxed);
    }

    /// Appends the series this registry owns, and the ones read from `live`, to `out`.
    pub(crate) fn render(&self, out: &mut String, live: &RoutingTable) {
        self.render_at(out, live, Instant::now());
    }

    fn render_at(&self, out: &mut String, live: &RoutingTable, now: Instant) {
        let (routers, services, collapsed) = {
            let mut inner = self.inner();
            inner.expire(now, self.retention);
            let rows = |kind| {
                let mut rows: Vec<(Key, Arc<Series>)> = inner
                    .slots
                    .iter()
                    .filter(|(key, _)| key.kind == kind)
                    .map(|(key, slot)| (key.clone(), Arc::clone(&slot.series)))
                    .collect();
                rows.sort_by(|(left, _), (right, _)| {
                    (&left.app, &left.name).cmp(&(&right.app, &right.name))
                });
                rows
            };
            (
                rows(Kind::Router),
                rows(Kind::Service),
                inner.collapsed_total.clone(),
            )
        };
        self.render_entry_points(out);
        render_scope(
            out,
            &Scope {
                requests: "podgate_router_requests_total",
                duration: "podgate_router_request_duration_seconds",
                noun: "router",
                label: "router",
            },
            &routers,
        );
        render_scope(
            out,
            &Scope {
                requests: "podgate_service_requests_total",
                duration: "podgate_service_request_duration_seconds",
                noun: "service",
                label: "service",
            },
            &services,
        );
        render_retries(out, &services);
        render_servers(out, live);
        render_certificates(out, live);

        let name = "podgate_snapshot_version";
        text::header(
            out,
            name,
            "gauge",
            "Version of the live snapshot, 0 before the first.",
        );
        text::sample(out, name, "", live.version());
        let name = "podgate_snapshot_applied_timestamp_seconds";
        text::header(
            out,
            name,
            "gauge",
            "Unix time the live snapshot went live, 0 before the first.",
        );
        text::sample(
            out,
            name,
            "",
            self.applied_unix_secs.load(Ordering::Relaxed),
        );
        let name = "podgate_snapshot_rejected_total";
        text::header(
            out,
            name,
            "counter",
            "Snapshots refused, by rejection code; a snapshot refused for several codes counts once under each.",
        );
        let rejected = self.rejected.lock().unwrap_or_else(PoisonError::into_inner);
        for (code, count) in rejected.iter() {
            text::sample(out, name, &text::labels(&[("code", code)]), count);
        }
        drop(rejected);
        let name = "podgate_metrics_collapsed_total";
        text::header(
            out,
            name,
            "counter",
            "Objects of the tenant whose series were folded into `other` because the tenant is over METRICS_SERIES_PER_TENANT.",
        );
        for (tenant, count) in &collapsed {
            text::sample(out, name, &text::labels(&[("tenant", &**tenant)]), count);
        }
    }

    fn render_entry_points(&self, out: &mut String) {
        let points: Vec<(Box<str>, Arc<EntrySeries>)> = self
            .entry_points
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(name, series)| (name.clone(), Arc::clone(series)))
            .collect();
        let rows: Vec<(String, &Series)> = points
            .iter()
            .map(|(name, series)| (text::labels(&[("entry_point", &**name)]), &series.requests))
            .collect();
        text::requests(
            out,
            "podgate_entry_point_requests_total",
            "Requests answered on the entry point, by status class.",
            &rows,
        );
        text::duration(
            out,
            "podgate_entry_point_request_duration_seconds",
            "Time from the request arriving on the entry point to its response being written.",
            &rows,
        );
        let name = "podgate_entry_point_open_connections";
        text::header(
            out,
            name,
            "gauge",
            "Requests being served on the entry point now (what Traefik reports as open connections).",
        );
        for (point, series) in &points {
            let labels = text::labels(&[("entry_point", &**point)]);
            text::sample(out, name, &labels, series.open());
        }
    }
}

impl Inner {
    /// Forgets what was removed more than `retention` ago.
    fn expire(&mut self, now: Instant, retention: Duration) {
        self.slots.retain(|_, slot| {
            slot.removed
                .is_none_or(|since| now.saturating_duration_since(since) < retention)
        });
    }

    /// The `other` series of the app and kind of `key`.
    fn overflow(&mut self, key: &Key, tenant: &str) -> Arc<Series> {
        let key = Key {
            app: key.app.clone(),
            kind: key.kind,
            name: OTHER.into(),
        };
        let slot = self.slots.entry(key).or_insert_with(|| Slot {
            series: Arc::new(Series::default()),
            fingerprint: 0,
            tenant: tenant.into(),
            overflow: true,
            removed: None,
        });
        Arc::clone(&slot.series)
    }
}

fn want<'a>(app: &'a CompiledApp, kind: Kind, name: &str, fingerprint: u64) -> Want<'a> {
    Want {
        tenant: app.tenant(),
        key: Key {
            app: app.id().into(),
            kind,
            name: name.into(),
        },
        fingerprint,
    }
}

/// What makes a router another route: where it matches, how it ranks and where it goes. The
/// middleware chain is not part of it; changing a header does not reset the route's counters.
fn router_fingerprint(router: &CompiledRouter) -> u64 {
    digest((
        router.priority(),
        router.service(),
        router.entry_points(),
        format!("{:?}", router.matcher()),
    ))
}

/// The metric names of one scope (routers or services).
struct Scope {
    requests: &'static str,
    duration: &'static str,
    noun: &'static str,
    label: &'static str,
}

fn render_scope(out: &mut String, scope: &Scope, rows: &[(Key, Arc<Series>)]) {
    let labelled: Vec<(String, &Series)> = rows
        .iter()
        .map(|(key, series)| {
            (
                text::labels(&[("app", &*key.app), (scope.label, &*key.name)]),
                &**series,
            )
        })
        .collect();
    text::requests(
        out,
        scope.requests,
        &format!("Requests of the {}, by status class.", scope.noun),
        &labelled,
    );
    text::duration(
        out,
        scope.duration,
        &format!(
            "Time from a request arriving to its response being written, by {}.",
            scope.noun
        ),
        &labelled,
    );
}

fn render_retries(out: &mut String, services: &[(Key, Arc<Series>)]) {
    let name = "podgate_service_retries_total";
    text::header(
        out,
        name,
        "counter",
        "Attempts repeated against a service after a failure.",
    );
    for (key, series) in services {
        let retries = series.retries();
        if retries > 0 {
            let labels = text::labels(&[("app", &*key.app), ("service", &*key.name)]);
            text::sample(out, name, &labels, retries);
        }
    }
}

/// The servers of an app as `service_server_up` reports them, in a fixed order.
struct ServerRow<'a> {
    /// The revision that defines the service; empty for a service the app shares.
    revision: &'a str,
    service: &'a str,
    url: &'a str,
    up: bool,
}

/// Every server of every service of `app`, the app's own (revision empty) and each revision's,
/// once per revision, service name and URL: health and ejection are state of a revision's
/// server, so two revisions naming one URL are two rows.
fn servers_of(app: &CompiledApp) -> Vec<ServerRow<'_>> {
    let shared = app.services().iter().map(|named| ("", named));
    let own = app.revisions().iter().flat_map(|revision| {
        revision
            .services()
            .iter()
            .map(move |named| (revision.id(), named))
    });
    let mut rows: Vec<ServerRow<'_>> = Vec::new();
    let mut seen: HashMap<(&str, &str, &str), usize> = HashMap::new();
    for (revision, named) in shared.chain(own) {
        for server in named.service.servers() {
            let up = server.available();
            match seen.get(&(revision, &*named.name, &*server.url)) {
                Some(at) => rows[*at].up |= up,
                None => {
                    seen.insert((revision, &*named.name, &*server.url), rows.len());
                    rows.push(ServerRow {
                        revision,
                        service: &named.name,
                        url: &server.url,
                        up,
                    });
                }
            }
        }
    }
    rows
}

fn render_servers(out: &mut String, live: &RoutingTable) {
    let name = "podgate_service_server_up";
    text::header(
        out,
        name,
        "gauge",
        "1 when the server may take a new request (healthy and not ejected), else 0.",
    );
    for (index, app) in live.apps().iter().enumerate() {
        let shown = live.series().servers_shown(index);
        for row in servers_of(app).iter().take(shown) {
            let labels = text::labels(&[
                ("app", app.id()),
                ("revision", row.revision),
                ("service", row.service),
                ("server", row.url),
            ]);
            text::sample(out, name, &labels, u8::from(row.up));
        }
    }
}

fn render_certificates(out: &mut String, live: &RoutingTable) {
    let name = "podgate_tls_cert_not_after_seconds";
    text::header(
        out,
        name,
        "gauge",
        "Unix time the certificate for the declared host stops being valid.",
    );
    for (host, not_after) in live.certificates().expiries() {
        text::sample(out, name, &text::labels(&[("host", host)]), not_after);
    }
}

/// The codes a refused snapshot is counted under; the same codes the `422` body carries.
fn rejection_codes(err: &ApplyError) -> Vec<&'static str> {
    match err {
        ApplyError::Stale { .. } => vec!["stale"],
        ApplyError::Compile(err) => match err {
            CompileError::Conflicts(conflicts) => {
                conflicts.iter().map(crate::Conflict::code).collect()
            }
            CompileError::Rejected(rejected) => rejected
                .iter()
                .map(crate::compile::Rejected::code)
                .collect(),
            CompileError::Canary(rejections) => rejections
                .iter()
                .map(crate::canary::Rejection::code)
                .collect(),
            CompileError::UnknownTenant { .. } => vec!["unknown_tenant"],
            CompileError::Certificate(_) => vec!["invalid_certificate"],
            CompileError::SkewSecretTooShort => vec!["invalid_skew_secret"],
            CompileError::ClientCa(_) => vec!["invalid_client_ca"],
            CompileError::Acme(_) => vec!["invalid_acme"],
        },
    }
}
