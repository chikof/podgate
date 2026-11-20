//! The routing table: a [`Snapshot`] compiled into immutable lookup structures, and the shared
//! handle that swaps it atomically.
//!
//! A request calls [`TableHandle::load`] once and keeps that [`Arc`] for its whole life, so a
//! swap never changes the routing of a request in flight. A snapshot that does not compile
//! leaves the live table untouched.

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use arc_swap::ArcSwap;
use thiserror::Error;
use tokio::sync::watch;

use crate::canary::{self, Runtime};

use crate::acme::{Plan, PlanError};
use crate::conflict::{self, Conflict};
use crate::host::{HostMap, HostPattern, InvalidHost, MatchKind};
use crate::skew::SkewSecret;
use crate::snapshot::{
    App, Budget, Filter, Revision, RevisionState, ScaleToZero, Snapshot, TlsPolicy,
};
use crate::tls::{CertError, CertStore};
use crate::wasm::{self, CompiledFilter};

/// A snapshot the compiler refuses.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompileError {
    /// An app declares a host that is neither a name nor a `*.` wildcard.
    #[error("app {app}: {source}")]
    InvalidHost {
        /// The declaring app.
        app: Box<str>,
        /// What is wrong with the host.
        #[source]
        source: InvalidHost,
    },
    /// An app names a tenant the snapshot does not declare.
    #[error("app {app}: unknown tenant {tenant}")]
    UnknownTenant {
        /// The declaring app.
        app: Box<str>,
        /// The missing tenant.
        tenant: Box<str>,
    },
    /// Declarations conflict on security. Nothing is merged: the snapshot is refused and every
    /// conflict is listed.
    #[error("{}", conflict::join(.0))]
    Conflicts(Vec<Conflict>),
    /// A certificate cannot be served.
    #[error(transparent)]
    Certificate(#[from] CertError),
    /// The `skew_secret` is shorter than [`SkewSecret::MIN_LEN`] bytes.
    #[error("skew_secret must be at least {} bytes", SkewSecret::MIN_LEN)]
    SkewSecretTooShort,
    /// A WASM filter module is invalid or imports something podgate does not provide. Every
    /// rejected filter is listed.
    #[error("{}", wasm::join(.0))]
    Wasm(Vec<wasm::Rejection>),
    /// A canary policy is unsound. Every rejected policy is listed.
    #[error("{}", canary::join(.0))]
    Canary(Vec<canary::Rejection>),

    /// The ACME settings or a certificate's validity cannot be used.
    #[error(transparent)]
    Acme(#[from] PlanError),
}

/// Why a snapshot was not applied.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyError {
    /// Its version is not newer than the live one.
    #[error("stale snapshot: version {offered} is not newer than live version {live}")]
    Stale {
        /// Version of the live table.
        live: u64,
        /// Version that was offered.
        offered: u64,
    },
    /// It does not compile.
    #[error(transparent)]
    Compile(#[from] CompileError),
}

/// The two tables of one successful [`TableHandle::apply_replacing`], and the snapshot the old
/// one was compiled from.
#[derive(Debug, Clone)]
pub struct Replaced {
    /// The table that was live before the swap.
    pub previous: Arc<RoutingTable>,
    /// The table that is live now.
    pub current: Arc<RoutingTable>,
    /// The snapshot `previous` was compiled from: what [`TableHandle::revert_to`] restores.
    /// `None` for the first snapshot of the process, which replaced the empty table.
    pub previous_snapshot: Option<Arc<Snapshot>>,
}

/// One revision of an app, ready for routing.
#[derive(Debug)]
pub struct CompiledRevision {
    id: Box<str>,
    upstreams: Box<[SocketAddr]>,
    weight: u16,
    state: RevisionState,
    live: Arc<AtomicU16>,
    next_upstream: AtomicU64,
}

impl CompiledRevision {
    fn new(revision: &Revision) -> Self {
        Self {
            id: revision.id.clone(),
            upstreams: revision.upstreams.clone().into_boxed_slice(),
            weight: revision.weight,
            state: revision.state,
            live: Arc::new(AtomicU16::new(0)),
            next_upstream: AtomicU64::new(0),
        }
    }

    /// The revision id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The revision's lifecycle state.
    #[must_use]
    pub fn state(&self) -> RevisionState {
        self.state
    }

    /// The revision's configured weight.
    #[must_use]
    pub fn weight(&self) -> u16 {
        self.weight
    }

    /// The weight [`CompiledApp::pick`] gives this revision right now, the one value the picker
    /// and `GET /v1/explain` both read; `0` when the revision takes no new requests (not
    /// `serving`, no weight, or no backend).
    ///
    /// Without a canary it is the configured weight. With one it counts in parts of
    /// [`CANARY_TOTAL_WEIGHT`] shared by the app's revisions, following the canary's share; see
    /// [`crate::canary`].
    #[must_use]
    pub fn effective_weight(&self) -> u16 {
        self.live.load(Ordering::Relaxed)
    }

    /// The revision's backends.
    #[must_use]
    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }

    /// Whether new requests may be sent here: serving, weighted, and with a backend.
    fn takes_new_requests(&self) -> bool {
        self.state == RevisionState::Serving && self.weight > 0 && !self.upstreams.is_empty()
    }

    /// Whether the revision is `serving` and has a backend, whatever its weight.
    fn serving_with_backend(&self) -> bool {
        self.state == RevisionState::Serving && !self.upstreams.is_empty()
    }

    /// The next backend, in turn; `None` without backends.
    fn take_upstream(&self) -> Option<SocketAddr> {
        if self.upstreams.is_empty() {
            return None;
        }
        let turn = self.next_upstream.fetch_add(1, Ordering::Relaxed);
        let slot = usize::try_from(turn % self.upstreams.len() as u64).ok()?;
        self.upstreams.get(slot).copied()
    }
}

/// The result of [`RoutingTable::lookup`].
#[derive(Debug)]
pub struct Lookup<'a> {
    /// The app that answers for the host.
    pub app: &'a CompiledApp,
    /// Whether an exact host or a wildcard matched.
    pub kind: MatchKind,
    /// The declared host that matched, as written in the snapshot: `a.test` or `*.a.test`.
    pub pattern: String,
}

/// An app ready for routing.
#[derive(Debug)]
pub struct CompiledApp {
    id: Box<str>,
    tenant: Box<str>,
    declared_by: Box<str>,
    allow_domain_fronting: bool,
    record_bodies: bool,
    scale_to_zero: Option<ScaleToZero>,
    filters: Box<[CompiledFilter]>,
    revisions: Box<[CompiledRevision]>,
    next_revision: AtomicU64,
    filters_digest: u64,
    hosts: Box<[Box<str>]>,
    tls: TlsPolicy,
    canary: Option<Arc<Runtime>>,
}

fn filters_digest(filters: &[Filter]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for filter in filters {
        filter.wasm_base64.hash(&mut hasher);
        filter.fuel.hash(&mut hasher);
        filter.max_memory_bytes.hash(&mut hasher);
    }
    hasher.finish()
}

/// What the effective weights of an app's revisions add up to while it has a canary.
pub const CANARY_TOTAL_WEIGHT: u64 = 10_000;

/// Multiplier that spreads picks over a turn of tickets; a prime above any ticket total.
const TICKET_STRIDE: u64 = 2_654_435_761;

/// Where [`CompiledApp::pick`] sent a new request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pick {
    /// Index into [`CompiledApp::revisions`].
    pub revision: usize,
    /// The chosen backend.
    pub upstream: SocketAddr,
}

impl CompiledApp {
    fn new(app: &App, filters: Box<[CompiledFilter]>) -> Self {
        let revisions: Box<[CompiledRevision]> =
            app.revisions.iter().map(CompiledRevision::new).collect();
        let canary = app.canary.as_ref().and_then(|policy| {
            let index = app
                .revisions
                .iter()
                .position(|rev| rev.id == policy.revision)?;
            let weights = revisions.iter().map(|rev| Arc::clone(&rev.live)).collect();
            Some(Arc::new(Runtime::new(
                canary::Fingerprint::of(app, policy),
                index,
                weights,
                Instant::now(),
            )))
        });
        let compiled = Self {
            filters,
            id: app.id.clone(),
            tenant: app.tenant.clone(),
            declared_by: app.declared_by.clone(),
            allow_domain_fronting: app.allow_domain_fronting,
            record_bodies: app.record_bodies,
            scale_to_zero: app.scale_to_zero,
            revisions,
            next_revision: AtomicU64::new(0),
            hosts: app
                .hosts
                .iter()
                .map(|host| host.to_ascii_lowercase().into())
                .collect(),
            filters_digest: filters_digest(&app.filters),
            tls: app.tls.clone(),
            canary,
        };
        compiled.reweigh();
        compiled
    }

    /// Computes every revision's [`CompiledRevision::effective_weight`] from its configuration
    /// and the canary's share. The only place those weights are defined.
    fn reweigh(&self) {
        let Some(canary) = &self.canary else {
            for revision in &self.revisions {
                let weight = if revision.takes_new_requests() {
                    revision.weight
                } else {
                    0
                };
                revision.live.store(weight, Ordering::Relaxed);
            }
            return;
        };
        let others: u64 = self
            .revisions
            .iter()
            .enumerate()
            .filter(|(index, revision)| *index != canary.index() && revision.takes_new_requests())
            .map(|(_, revision)| u64::from(revision.weight))
            .sum();
        let share = u64::from(canary.share());
        let canary_serves = self
            .revisions
            .get(canary.index())
            .is_some_and(CompiledRevision::serving_with_backend);
        let canary_part = match (canary_serves, others, share) {
            (false, _, _) | (_, _, 0) => 0,
            (true, 0, _) => CANARY_TOTAL_WEIGHT,
            (true, _, share) => share * CANARY_TOTAL_WEIGHT / 100,
        };
        let rest = CANARY_TOTAL_WEIGHT - canary_part;
        for (index, revision) in self.revisions.iter().enumerate() {
            let part = if index == canary.index() {
                canary_part
            } else if revision.takes_new_requests() && rest > 0 {
                (u64::from(revision.weight) * rest / others).max(1)
            } else {
                0
            };
            revision
                .live
                .store(u16::try_from(part).unwrap_or(u16::MAX), Ordering::Relaxed);
        }
    }

    /// Takes over `runtime`, the state of an equal canary of an earlier table: from now on this
    /// app's revisions share its weights. Only the registry calls this, before the table is live.
    pub(crate) fn adopt_canary(&mut self, runtime: Arc<Runtime>) {
        for (revision, weight) in self.revisions.iter_mut().zip(runtime.weights()) {
            revision.live = Arc::clone(weight);
        }
        self.canary = Some(runtime);
    }
    /// The canary's runtime state, for [`canary::judge`].
    pub(crate) fn canary_runtime(&self) -> Option<&Arc<Runtime>> {
        self.canary.as_ref()
    }

    /// Moves the canary to `percent` of new sessions and reweighs the revisions.
    pub(crate) fn set_canary_share(&self, percent: u8) {
        if let Some(canary) = &self.canary {
            canary.set_share(percent);
            self.reweigh();
        }
    }

    /// The canary policy as declared, `None` when the app has none.
    #[must_use]
    pub fn canary_policy(&self) -> Option<&crate::snapshot::Canary> {
        self.canary.as_deref().map(Runtime::policy)
    }

    /// The canary's policy and where it stands, `None` when the app has none.
    #[must_use]
    pub fn canary(&self) -> Option<canary::Status<'_>> {
        self.canary.as_deref().map(canary::Status::of)
    }

    /// The app's WASM request filters, in the order they run.
    #[must_use]
    pub fn filters(&self) -> &[CompiledFilter] {
        &self.filters
    }

    /// A digest of the declared filter modules and limits, to tell whether two tables run the
    /// same filters without comparing modules. Equal inputs give equal digests within a process.
    #[must_use]
    pub fn filters_digest(&self) -> u64 {
        self.filters_digest
    }

    /// Whether a TLS request may name a host other than its SNI.
    #[must_use]
    pub fn allow_domain_fronting(&self) -> bool {
        self.allow_domain_fronting
    }

    /// The host patterns the app declares, lowercased: exact names and `*.` wildcards.
    #[must_use]
    pub fn hosts(&self) -> &[Box<str>] {
        &self.hosts
    }

    /// The app's TLS policy.
    #[must_use]
    pub fn tls(&self) -> &TlsPolicy {
        &self.tls
    }

    /// Whether failed requests keep their bodies for replay.
    #[must_use]
    pub fn record_bodies(&self) -> bool {
        self.record_bodies
    }

    /// The app's scale-to-zero policy; `None` when it never sleeps.
    #[must_use]
    pub fn scale_to_zero(&self) -> Option<ScaleToZero> {
        self.scale_to_zero
    }

    /// The app id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The owning tenant id.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The source named in the snapshot declaration.
    #[must_use]
    pub fn declared_by(&self) -> &str {
        &self.declared_by
    }

    /// The app's revisions in snapshot order.
    #[must_use]
    pub fn revisions(&self) -> &[CompiledRevision] {
        &self.revisions
    }

    /// Chooses a revision and backend for a new request, or `None` when no revision takes new
    /// requests.
    ///
    /// Only `serving` revisions with a weight and a backend are candidates; `retiring` and
    /// `draining` ones never get new requests here. Revisions share traffic in proportion to
    /// their [`CompiledRevision::effective_weight`], backends of one revision take turns.
    #[must_use]
    pub fn pick(&self) -> Option<Pick> {
        let total: u64 = self
            .revisions
            .iter()
            .map(|revision| u64::from(revision.effective_weight()))
            .sum();
        if total == 0 {
            return None;
        }
        // Walking tickets in order would send the first `weight` requests to the first
        // revision; the stride is coprime to `total`, so every turn of `total` tickets still
        // visits each ticket exactly once, but interleaved.
        let turn = self.next_revision.fetch_add(1, Ordering::Relaxed) % total;
        let mut ticket = turn * (TICKET_STRIDE % total) % total;
        for (index, revision) in self.revisions.iter().enumerate() {
            let weight = u64::from(revision.effective_weight());
            if ticket < weight {
                return Some(Pick {
                    revision: index,
                    upstream: revision.take_upstream()?,
                });
            }
            ticket -= weight;
        }
        // A canary step landed between summing and walking: take the last revision in use.
        let (index, revision) = self
            .revisions
            .iter()
            .enumerate()
            .rev()
            .find(|(_, revision)| revision.effective_weight() > 0)?;
        Some(Pick {
            revision: index,
            upstream: revision.take_upstream()?,
        })
    }

    /// The pick for a session pinned to revision `id`: `serving` or `retiring` revisions with a
    /// backend only, weight ignored. `None` when the revision is `draining`, gone or has no
    /// backend, and the request must be routed by [`Self::pick`].
    #[must_use]
    pub fn pick_pinned(&self, id: &str) -> Option<Pick> {
        let (index, revision) = self
            .revisions
            .iter()
            .enumerate()
            .find(|(_, revision)| &*revision.id == id)?;
        if revision.state == RevisionState::Draining {
            return None;
        }
        // A regressed canary keeps no session: they fall back to the weighted pick.
        if self
            .canary
            .as_ref()
            .is_some_and(|canary| canary.index() == index && canary.regressed())
        {
            return None;
        }
        Some(Pick {
            revision: index,
            upstream: revision.take_upstream()?,
        })
    }
}

/// An immutable, compiled [`Snapshot`].
#[derive(Debug, Default)]
pub struct RoutingTable {
    version: u64,
    apps: Box<[CompiledApp]>,
    hosts: HostMap<usize>,
    certificates: CertStore,
    acme: Plan,
    budgets: HashMap<Box<str>, Budget>,
    skew_secret: Option<SkewSecret>,
}

impl RoutingTable {
    /// Compiles a snapshot. Nothing is merged or repaired: any problem rejects it whole.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] for an invalid host, an unknown tenant, declarations that
    /// conflict (every [`Conflict`] is reported at once), a certificate that cannot be served or a
    /// `skew_secret` that is too short.
    pub fn compile(snapshot: &Snapshot) -> Result<Self, CompileError> {
        if snapshot
            .skew_secret
            .as_ref()
            .is_some_and(|secret| !secret.is_long_enough())
        {
            return Err(CompileError::SkewSecretTooShort);
        }
        let tenants: HashSet<&str> = snapshot.tenants.iter().map(|tenant| &*tenant.id).collect();
        let mut claims = Vec::new();
        for (index, app) in snapshot.apps.iter().enumerate() {
            if !tenants.contains(&*app.tenant) {
                return Err(CompileError::UnknownTenant {
                    app: app.id.clone(),
                    tenant: app.tenant.clone(),
                });
            }
            for raw in &app.hosts {
                let pattern =
                    HostPattern::parse(raw).map_err(|source| CompileError::InvalidHost {
                        app: app.id.clone(),
                        source,
                    })?;
                claims.push((pattern, index));
            }
        }
        let conflicts = conflict::detect(&snapshot.apps, &claims);
        if !conflicts.is_empty() {
            return Err(CompileError::Conflicts(conflicts));
        }
        let unsound: Vec<_> = snapshot.apps.iter().flat_map(canary::validate).collect();
        if !unsound.is_empty() {
            return Err(CompileError::Canary(unsound));
        }
        let mut wasm = wasm::Compiler::default();
        let mut filters = Vec::with_capacity(snapshot.apps.len());
        let mut rejected = Vec::new();
        for app in &snapshot.apps {
            match wasm.compile_app(app) {
                Ok(compiled) => filters.push(compiled),
                Err(errors) => rejected.extend(errors),
            }
        }
        if !rejected.is_empty() {
            return Err(CompileError::Wasm(rejected));
        }
        let mut hosts = HostMap::default();
        for (pattern, index) in claims {
            hosts.insert(pattern, index);
        }
        Ok(Self {
            version: snapshot.version,
            apps: snapshot
                .apps
                .iter()
                .zip(filters)
                .map(|(app, filters)| CompiledApp::new(app, filters))
                .collect(),
            hosts,
            certificates: CertStore::build(&snapshot.certificates)?,
            acme: Plan::compile(snapshot)?,
            budgets: snapshot
                .tenants
                .iter()
                .map(|tenant| (tenant.id.clone(), tenant.budget))
                .collect(),
            skew_secret: snapshot.skew_secret.clone(),
        })
    }

    /// The version of the snapshot this table was compiled from; `0` for the empty table.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The app that answers for `host`, and its index for [`Self::app`]. `host` must be
    /// normalized (see [`crate::host::normalize`]).
    #[must_use]
    pub fn find_app(&self, host: &str) -> Option<(usize, &CompiledApp)> {
        let index = *self.hosts.lookup(host)?;
        Some((index, self.apps.get(index)?))
    }

    /// Like [`Self::find_app`], and says which declared pattern matched and how. `host` must be
    /// normalized.
    #[must_use]
    pub fn lookup(&self, host: &str) -> Option<Lookup<'_>> {
        let matched = self.hosts.find(host)?;
        Some(Lookup {
            app: self.apps.get(*matched.value)?,
            kind: matched.kind,
            pattern: matched.pattern(),
        })
    }

    /// The declared wildcard nearest to `host`, for explaining a miss; see
    /// [`HostMap::nearest_wildcard`].
    #[must_use]
    pub fn nearest_wildcard(&self, host: &str) -> Option<String> {
        self.hosts.nearest_wildcard(host)
    }

    /// The app at `index`, as returned by [`Self::find_app`].
    #[must_use]
    pub fn app(&self, index: usize) -> Option<&CompiledApp> {
        self.apps.get(index)
    }

    /// The resource budget of tenant `id`, or `None` when the snapshot does not declare it.
    #[must_use]
    pub fn tenant_budget(&self, id: &str) -> Option<Budget> {
        self.budgets.get(id).copied()
    }

    /// Certificates for the TLS listener.
    #[must_use]
    pub fn certificates(&self) -> &CertStore {
        &self.certificates
    }

    /// The key signing session cookies, when the snapshot sets a `skew_secret`.
    #[must_use]
    pub fn skew_secret(&self) -> Option<&SkewSecret> {
        self.skew_secret.as_ref()
    }

    /// The ACME view of the snapshot: HTTP-01 answers, missing and due certificates.
    #[must_use]
    pub fn acme(&self) -> &Plan {
        &self.acme
    }
}

/// Shared handle to the live [`RoutingTable`]. Cheap to clone; every clone sees the same table.
#[derive(Debug, Clone, Default)]
pub struct TableHandle {
    live: Arc<ArcSwap<RoutingTable>>,
    // Serializes `apply`, so the version check and the swap are one step.
    apply_lock: Arc<Mutex<()>>,
    // Holds the version of the newest table; every swap sends, so waiters see each one.
    swapped: Arc<watch::Sender<u64>>,
    // The snapshot the live table was compiled from; touched only while `apply_lock` is held.
    source: Arc<Mutex<Option<Arc<Snapshot>>>>,
    // Canary state that outlives swaps; touched only by `swap`.
    canaries: Arc<canary::Registry>,
}

impl TableHandle {
    /// A handle on the empty table: no apps, version `0`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The live table. Call once per request and keep the result.
    #[must_use]
    pub fn load(&self) -> Arc<RoutingTable> {
        self.live.load_full()
    }

    /// Compiles `snapshot` and, when it is newer than the live table, swaps it in.
    ///
    /// # Errors
    ///
    /// [`ApplyError::Stale`] when `snapshot.version` is not greater than the live version,
    /// [`ApplyError::Compile`] when it does not compile. The live table stays in both cases.
    pub fn apply(&self, snapshot: &Snapshot) -> Result<(), ApplyError> {
        self.apply_replacing(snapshot).map(drop)
    }

    /// Like [`Self::apply`], and returns the table that went out, the one that came in and the
    /// snapshot that went out, all read under the lock of the swap, so concurrent pushes cannot
    /// mix them up.
    ///
    /// # Errors
    ///
    /// The same as [`Self::apply`].
    pub fn apply_replacing(&self, snapshot: &Snapshot) -> Result<Replaced, ApplyError> {
        let _guard = self
            .apply_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let previous = self.live.load_full();
        let live = previous.version();
        if snapshot.version <= live {
            return Err(ApplyError::Stale {
                live,
                offered: snapshot.version,
            });
        }
        let table = RoutingTable::compile(snapshot)?;
        tracing::info!(
            version = table.version,
            apps = table.apps.len(),
            "snapshot applied"
        );
        self.swap(table);
        // Nothing else swaps while `apply_lock` is held, so this is the table just stored.
        let current = self.live.load_full();
        let previous_snapshot = self.source().replace(Arc::new(snapshot.clone()));
        Ok(Replaced {
            previous,
            current,
            previous_snapshot,
        })
    }

    /// Puts `previous`, the snapshot of an earlier live table, back in service, but only while
    /// the live version is still `keep_version`: a snapshot that landed since wins and
    /// `Ok(false)` is returned.
    ///
    /// The snapshot is compiled again with its version set to `keep_version`, the version it
    /// replaces, and swapped in as a new table; tables never change once built, so requests
    /// holding the reverted table keep seeing it. The live version therefore never goes down:
    /// the next push must be newer than the reverted snapshot, so the control plane cannot
    /// replay it by accident, and [`crate::Inflight::sync`] does not discard the restored table
    /// as older.
    ///
    /// # Errors
    ///
    /// [`CompileError`] when `previous` no longer compiles (a certificate that expired since,
    /// say). The live table stays.
    pub fn revert_to(&self, previous: &Snapshot, keep_version: u64) -> Result<bool, CompileError> {
        let _guard = self
            .apply_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.live.load().version() != keep_version {
            return Ok(false);
        }
        let mut restored = previous.clone();
        restored.version = keep_version;
        self.swap(RoutingTable::compile(&restored)?);
        *self.source() = Some(Arc::new(restored));
        Ok(true)
    }

    fn source(&self) -> MutexGuard<'_, Option<Arc<Snapshot>>> {
        self.source.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The one place the live table is replaced: stores `table` and fires the [`Self::subscribe`]
    /// signal. Every path that changes the live table goes through here.
    fn swap(&self, mut table: RoutingTable) {
        self.canaries.settle(&mut table.apps);
        let version = table.version;
        self.live.store(Arc::new(table));
        self.swapped.send_replace(version);
    }

    /// A signal that fires after every swap of the live table, carrying the new table's
    /// version. Any code that replaces the table does it through this handle, so a waiter never
    /// misses a swap: it subscribes first, then [`Self::load`]s, then awaits
    /// [`watch::Receiver::changed`]. A swap that lands in between makes `changed` return at
    /// once; the received value is not needed, reload the table instead.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.swapped.subscribe()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::snapshot::{Budget, Tenant, TlsMode, TlsPolicy};

    fn revision(id: &str, port: u16, weight: u16, state: RevisionState) -> Revision {
        Revision {
            id: id.into(),
            upstreams: vec![SocketAddr::from(([127, 0, 0, 1], port))],
            weight,
            state,
        }
    }

    fn app(id: &str, hosts: &[&str], revisions: Vec<Revision>) -> App {
        App {
            id: id.into(),
            tenant: "t1".into(),
            declared_by: format!("test/{id}").into(),
            hosts: hosts.iter().map(|host| (*host).into()).collect(),
            tls: TlsPolicy {
                mode: TlsMode::Acme,
                client_ca_pem: None,
            },
            revisions,
            allow_domain_fronting: false,
            record_bodies: false,
            scale_to_zero: None,
            filters: Vec::new(),
            canary: None,
        }
    }

    fn snapshot(version: u64, apps: Vec<App>) -> Snapshot {
        Snapshot {
            version,
            tenants: vec![Tenant {
                id: "t1".into(),
                weight: 1,
                budget: Budget {
                    max_inflight: 10,
                    max_buffer_bytes: 1024,
                },
            }],
            apps,
            certificates: Vec::new(),
            skew_secret: None,
            revert_window_secs: None,
            acme: None,
        }
    }

    fn serving(port: u16) -> Vec<Revision> {
        vec![revision("r1", port, 100, RevisionState::Serving)]
    }

    #[test]
    fn finds_exact_and_wildcard_hosts() {
        let table = RoutingTable::compile(&snapshot(
            1,
            vec![
                app("a", &["a.test"], serving(1)),
                app("w", &["*.w.test"], serving(2)),
            ],
        ))
        .expect("compiles");
        assert_eq!(table.find_app("a.test").map(|(_, a)| a.id()), Some("a"));
        assert_eq!(table.find_app("x.w.test").map(|(_, a)| a.id()), Some("w"));
        assert!(table.find_app("w.test").is_none());
        assert!(table.find_app("nope.test").is_none());
    }

    #[test]
    fn only_serving_revisions_get_new_requests() {
        let revisions = vec![
            revision("old", 1, 100, RevisionState::Draining),
            revision("mid", 2, 100, RevisionState::Retiring),
            revision("new", 3, 1, RevisionState::Serving),
        ];
        let table = RoutingTable::compile(&snapshot(1, vec![app("a", &["a.test"], revisions)]))
            .expect("compiles");
        let (_, app) = table.find_app("a.test").expect("known host");
        for _ in 0..10 {
            let pick = app.pick().expect("serving revision exists");
            assert_eq!(app.revisions()[pick.revision].id(), "new");
            assert_eq!(pick.upstream.port(), 3);
        }
    }

    #[test]
    fn no_serving_revision_means_no_pick() {
        let revisions = vec![revision("old", 1, 100, RevisionState::Draining)];
        let table = RoutingTable::compile(&snapshot(1, vec![app("a", &["a.test"], revisions)]))
            .expect("compiles");
        let (_, app) = table.find_app("a.test").expect("known host");
        assert_eq!(app.pick(), None);
    }

    #[test]
    fn revisions_share_traffic_by_weight() {
        let revisions = vec![
            revision("a", 1, 3, RevisionState::Serving),
            revision("b", 2, 1, RevisionState::Serving),
        ];
        let table = RoutingTable::compile(&snapshot(1, vec![app("a", &["a.test"], revisions)]))
            .expect("compiles");
        let (_, app) = table.find_app("a.test").expect("known host");
        let on_a = (0..400)
            .filter(|_| app.pick().is_some_and(|pick| pick.upstream.port() == 1))
            .count();
        assert_eq!(on_a, 300);
    }

    #[test]
    fn upstreams_of_a_revision_take_turns() {
        let mut revision = revision("r", 1, 1, RevisionState::Serving);
        revision
            .upstreams
            .push(SocketAddr::from(([127, 0, 0, 1], 2)));
        let table =
            RoutingTable::compile(&snapshot(1, vec![app("a", &["a.test"], vec![revision])]))
                .expect("compiles");
        let (_, app) = table.find_app("a.test").expect("known host");
        let ports: Vec<u16> = (0..4)
            .filter_map(|_| app.pick().map(|pick| pick.upstream.port()))
            .collect();
        assert_eq!(ports, [1, 2, 1, 2]);
    }

    #[test]
    fn rejects_duplicate_hosts_unknown_tenants_and_bad_hosts() {
        let duplicate = snapshot(
            1,
            vec![
                app("a", &["a.test"], serving(1)),
                app("b", &["A.TEST"], serving(2)),
            ],
        );
        assert!(matches!(
            RoutingTable::compile(&duplicate),
            Err(CompileError::Conflicts(conflicts))
                if matches!(conflicts.as_slice(), [Conflict::Host { .. }])
        ));

        let mut unknown = snapshot(1, vec![app("a", &["a.test"], serving(1))]);
        unknown.apps[0].tenant = "nobody".into();
        assert!(matches!(
            RoutingTable::compile(&unknown),
            Err(CompileError::UnknownTenant { .. })
        ));

        let bad = snapshot(1, vec![app("a", &["a b"], serving(1))]);
        assert!(matches!(
            RoutingTable::compile(&bad),
            Err(CompileError::InvalidHost { .. })
        ));
    }

    #[test]
    fn apply_swaps_forward_and_refuses_stale_versions() {
        let handle = TableHandle::new();
        assert_eq!(handle.load().version(), 0);

        handle
            .apply(&snapshot(2, vec![app("a", &["a.test"], serving(1))]))
            .expect("newer than the empty table");
        let before = handle.load();

        for stale in [2, 1] {
            let result = handle.apply(&snapshot(stale, vec![app("b", &["b.test"], serving(2))]));
            assert_eq!(
                result,
                Err(ApplyError::Stale {
                    live: 2,
                    offered: stale
                })
            );
        }
        assert!(
            Arc::ptr_eq(&before, &handle.load()),
            "table must not change"
        );
        assert!(handle.load().find_app("a.test").is_some());
    }

    #[test]
    fn a_rejected_snapshot_leaves_the_live_table() {
        let handle = TableHandle::new();
        handle
            .apply(&snapshot(1, vec![app("a", &["a.test"], serving(1))]))
            .expect("applies");
        let bad = snapshot(2, vec![app("a", &["a b"], serving(1))]);
        assert!(matches!(handle.apply(&bad), Err(ApplyError::Compile(_))));
        assert_eq!(handle.load().version(), 1);
    }

    #[test]
    fn a_table_in_flight_survives_a_swap() {
        let handle = TableHandle::new();
        handle
            .apply(&snapshot(1, vec![app("a", &["a.test"], serving(1))]))
            .expect("applies");
        let in_flight = handle.load();
        handle
            .apply(&snapshot(2, vec![app("b", &["b.test"], serving(2))]))
            .expect("applies");
        assert!(in_flight.find_app("a.test").is_some());
        assert!(handle.load().find_app("a.test").is_none());
    }

    #[test]
    fn table_lookup() {
        let revisions = vec![
            revision("old", 1, 50, RevisionState::Draining),
            revision("new", 2, 70, RevisionState::Serving),
            revision("zero", 3, 0, RevisionState::Serving),
        ];
        let table = RoutingTable::compile(&snapshot(
            1,
            vec![
                app("a", &["a.test"], revisions),
                app("w", &["*.w.test"], serving(4)),
            ],
        ))
        .expect("compiles");

        let exact = table.lookup("a.test").expect("exact host");
        assert_eq!(exact.app.id(), "a");
        assert_eq!(exact.kind, MatchKind::Exact);
        assert_eq!(exact.pattern, "a.test");
        let weights: Vec<(u16, u16)> = exact
            .app
            .revisions()
            .iter()
            .map(|revision| (revision.weight(), revision.effective_weight()))
            .collect();
        assert_eq!(weights, [(50, 0), (70, 70), (0, 0)]);

        let wild = table.lookup("x.w.test").expect("wildcard host");
        assert_eq!(wild.app.id(), "w");
        assert_eq!(wild.kind, MatchKind::Wildcard);
        assert_eq!(wild.pattern, "*.w.test");

        assert!(table.lookup("w.test").is_none());
        assert_eq!(
            table.nearest_wildcard("w.test").as_deref(),
            Some("*.w.test")
        );
        assert_eq!(
            table.nearest_wildcard("p.q.w.test").as_deref(),
            Some("*.w.test")
        );
        assert_eq!(table.nearest_wildcard("nope.test"), None);
    }
}
