//! The routing table: a [`Snapshot`] compiled into immutable lookup structures, and the shared
//! handle that swaps it atomically.
//!
//! A request calls [`TableHandle::load`] once and keeps that [`Arc`] for its whole life, so a
//! swap never changes the routing of a request in flight. A snapshot that does not compile
//! leaves the live table untouched. The compile passes themselves are in [`crate::compile`]
//! (`build`); this file holds what they produce and how it is used: the apps with their
//! routers, middleware stages, services and revisions, the router index, and the weighted
//! choice of a revision and server.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use thiserror::Error;
use tokio::sync::watch;

use crate::acme::{Plan, PlanError};
use crate::canary::{self, Runtime};
use crate::client_ip::Trust;
use crate::clientauth::{self, ClientAuth};
use crate::compile::{self, Rejected};
use crate::conflict::{self, Conflict};
use crate::entry::CompileContext;
use crate::entry::policy::{self as entry_policy, Policy as EntryPolicy};
use crate::middleware;
use crate::observe::access_log::{self, Policy};
use crate::observe::metrics::{self, TableSeries};
use crate::observe::tracing as trace;
use crate::router::{CompiledRouter, Index, Matched};
use crate::service::{self, Lease, PickCx, Upstream};
use crate::tls::{CertError, CertStore, Options};
use podgate_model::SkewSecret;
use podgate_model::{
    App, Budget, Forwarded, Revision, RevisionState, ScaleToZero, Snapshot, TlsPolicy,
};

/// A snapshot the compiler refuses.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompileError {
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
    /// A matcher, middleware, service, entry point or other object is refused. Every problem of
    /// the failing pass is listed.
    #[error("{}", compile::join(.0))]
    Rejected(Vec<Rejected>),
    /// A certificate cannot be served.
    #[error(transparent)]
    Certificate(#[from] CertError),
    /// The `skew_secret` is shorter than [`SkewSecret::MIN_LEN`] bytes.
    #[error("skew_secret must be at least {} bytes", SkewSecret::MIN_LEN)]
    SkewSecretTooShort,
    /// A canary policy is unsound. Every rejected policy is listed.
    #[error("{}", canary::join(.0))]
    Canary(Vec<canary::Rejection>),
    /// A client CA that cannot be used. Every rejected app is listed.
    #[error("{}", clientauth::join(.0))]
    ClientCa(Vec<clientauth::Rejection>),
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

/// Where a router finds its service in one revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceRef {
    /// Index into the revision's own services.
    Own(usize),
    /// Index into the app's services.
    App(usize),
}

/// One revision of an app, ready for routing.
#[derive(Debug)]
pub struct CompiledRevision {
    id: Box<str>,
    weight: u16,
    state: RevisionState,
    live: Arc<AtomicU16>,
    services: Box<[service::Named]>,
    /// For each router of the app, in order: the service it uses in this revision.
    routes: Box<[Option<ServiceRef>]>,
    /// Whether some router's service here can answer: it has a server, or is a static service.
    backed: bool,
}

impl CompiledRevision {
    pub(crate) fn new(
        revision: &Revision,
        services: Vec<service::Named>,
        routes: Vec<Option<ServiceRef>>,
        backed: bool,
    ) -> Self {
        Self {
            id: revision.id.clone(),
            weight: revision.weight,
            state: revision.state,
            live: Arc::new(AtomicU16::new(0)),
            services: services.into_boxed_slice(),
            routes: routes.into_boxed_slice(),
            backed,
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

    /// The revision's own services; the app's shared ones are in [`CompiledApp::services`].
    #[must_use]
    pub fn services(&self) -> &[service::Named] {
        &self.services
    }

    /// Whether new requests may be sent here: serving, weighted, and with a backend.
    fn takes_new_requests(&self) -> bool {
        self.state == RevisionState::Serving && self.weight > 0 && self.backed
    }

    /// Whether the revision is `serving` and has a backend, whatever its weight.
    fn serving_with_backend(&self) -> bool {
        self.state == RevisionState::Serving && self.backed
    }
}

/// An app ready for routing.
#[derive(Debug)]
pub struct CompiledApp {
    id: Box<str>,
    tenant: Box<str>,
    declared_by: Box<str>,
    allow_domain_fronting: bool,
    record_bodies: bool,
    forwarded: Forwarded,
    scale_to_zero: Option<ScaleToZero>,
    routers: Box<[CompiledRouter]>,
    stages: Box<[middleware::Named]>,
    services: Box<[service::Named]>,
    revisions: Box<[CompiledRevision]>,
    next_revision: AtomicU64,
    hosts: Box<[Box<str>]>,
    tls: TlsPolicy,
    client_auth: Option<Arc<ClientAuth>>,
    tls_options: Option<Arc<Options>>,
    canary: Option<Arc<Runtime>>,
    fingerprint: u64,
}

/// What the compile passes hand to [`CompiledApp::assemble`].
#[derive(Debug)]
pub(crate) struct Parts {
    pub(crate) routers: Vec<CompiledRouter>,
    pub(crate) stages: Vec<middleware::Named>,
    pub(crate) services: Vec<service::Named>,
    pub(crate) revisions: Vec<CompiledRevision>,
    pub(crate) fingerprint: u64,
    pub(crate) client_auth: Option<Arc<ClientAuth>>,
    pub(crate) tls_options: Option<Arc<Options>>,
}

/// What the effective weights of an app's revisions add up to while it has a canary.
pub const CANARY_TOTAL_WEIGHT: u64 = 10_000;

/// Multiplier that spreads picks over a turn of tickets; a prime above any ticket total.
const TICKET_STRIDE: u64 = 2_654_435_761;

/// Where [`CompiledApp::pick`] sent a new request.
#[derive(Debug)]
pub struct Pick {
    /// Index into [`CompiledApp::revisions`].
    pub revision: usize,
    /// The chosen backend.
    pub upstream: SocketAddr,
    /// Counts the request on the backend until dropped; keep it for the life of the request.
    pub lease: Lease,
}

impl CompiledApp {
    pub(crate) fn assemble(app: &App, parts: Parts) -> Self {
        let revisions: Box<[CompiledRevision]> = parts.revisions.into_boxed_slice();
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
        let mut hosts: Vec<Box<str>> = Vec::new();
        for router in &parts.routers {
            for pattern in router.patterns() {
                let shown: Box<str> = match pattern {
                    crate::host::HostPattern::Exact(name) => name.clone(),
                    crate::host::HostPattern::Wildcard(base) => format!("*.{base}").into(),
                };
                if !hosts.contains(&shown) {
                    hosts.push(shown);
                }
            }
        }
        let compiled = Self {
            id: app.id.clone(),
            tenant: app.tenant.clone(),
            declared_by: app.declared_by.clone(),
            allow_domain_fronting: app.allow_domain_fronting,
            record_bodies: app.record_bodies,
            forwarded: app.forwarded.unwrap_or_default(),
            scale_to_zero: app.scale_to_zero,
            routers: parts.routers.into_boxed_slice(),
            stages: parts.stages.into_boxed_slice(),
            services: parts.services.into_boxed_slice(),
            revisions,
            next_revision: AtomicU64::new(0),
            hosts: hosts.into_boxed_slice(),
            tls: app.tls.clone(),
            canary,
            fingerprint: parts.fingerprint,
            client_auth: parts.client_auth,
            tls_options: parts.tls_options,
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
        // The backends may differ from those the weights were made for, and a revision without one
        // takes no requests: recompute them from this table and the shared share.
        self.reweigh();
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
    pub fn canary_policy(&self) -> Option<&podgate_model::Canary> {
        self.canary.as_deref().map(Runtime::policy)
    }

    /// The canary's policy and where it stands, `None` when the app has none.
    #[must_use]
    pub fn canary(&self) -> Option<canary::Status<'_>> {
        self.canary.as_deref().map(canary::Status::of)
    }

    /// A digest of everything the app declares except `declared_by`, to tell whether two tables
    /// serve the app the same way. Equal inputs give equal digests within a process.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// Whether a TLS request may name a host other than its SNI.
    #[must_use]
    pub fn allow_domain_fronting(&self) -> bool {
        self.allow_domain_fronting
    }

    /// The literal host patterns the app's routers claim, lowercased: exact names and `*.`
    /// wildcards, in declaration order.
    #[must_use]
    pub fn hosts(&self) -> &[Box<str>] {
        &self.hosts
    }

    /// The app's TLS policy.
    #[must_use]
    pub fn tls(&self) -> &TlsPolicy {
        &self.tls
    }

    /// The app's compiled client CA; `None` when `tls.client_ca_pem` is absent and clients are
    /// not asked for a certificate.
    #[must_use]
    pub fn client_auth(&self) -> Option<&Arc<ClientAuth>> {
        self.client_auth.as_ref()
    }

    /// The app's compiled TLS options; `None` when it asks for nothing beyond the
    /// listener's baseline.
    #[must_use]
    pub fn tls_options(&self) -> Option<&Options> {
        self.tls_options.as_deref()
    }

    /// Whether failed requests keep their bodies for replay.
    #[must_use]
    pub fn record_bodies(&self) -> bool {
        self.record_bodies
    }

    /// The forwarding headers the app's upstreams receive.
    #[must_use]
    pub fn forwarded(&self) -> Forwarded {
        self.forwarded
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

    /// The app's routers in snapshot order.
    #[must_use]
    pub fn routers(&self) -> &[CompiledRouter] {
        &self.routers
    }

    /// The compiled middlewares, by declaration order; routers' chains index into this.
    #[must_use]
    pub fn stages(&self) -> &[middleware::Named] {
        &self.stages
    }

    /// The compiled middlewares, for the registry that hands a swapped-in table the runtime
    /// state of equal ones before the table is live.
    pub(crate) fn stages_mut(&mut self) -> &mut [middleware::Named] {
        &mut self.stages
    }

    /// The app's own services, shared by every revision.
    #[must_use]
    pub fn services(&self) -> &[service::Named] {
        &self.services
    }

    /// The app's revisions in snapshot order.
    #[must_use]
    pub fn revisions(&self) -> &[CompiledRevision] {
        &self.revisions
    }

    /// The service router `router` uses in revision `revision`: the revision's own, else the
    /// app's. `None` when either index is out of range or the revision does not define it.
    #[must_use]
    pub fn service(&self, revision: usize, router: usize) -> Option<&service::Service> {
        let revision = self.revisions.get(revision)?;
        match (*revision.routes.get(router)?)? {
            ServiceRef::Own(index) => revision.services.get(index),
            ServiceRef::App(index) => self.services.get(index),
        }
        .map(|named| &named.service)
    }

    /// The `static` service router `router` uses in revision `revision`, or `None` when it uses
    /// another type: the proxy answers such a request from the file system and never dials.
    #[must_use]
    pub fn static_site(&self, revision: usize, router: usize) -> Option<&Arc<service::StaticSite>> {
        self.service(revision, router)?.as_static()
    }

    /// Every server address the app can send to, in any revision.
    pub fn upstream_addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.services
            .iter()
            .chain(self.revisions.iter().flat_map(|rev| rev.services.iter()))
            .flat_map(|named| named.service.servers().iter().map(|server| server.addr))
    }

    /// The first server of revision `revision`, whichever service it belongs to: the revision's
    /// own services first, then the app's, with the transport that reaches it. `None` when it
    /// has none.
    #[must_use]
    pub fn first_upstream(&self, revision: usize) -> Option<Upstream<'_>> {
        let revision = self.revisions.get(revision)?;
        revision
            .services
            .iter()
            .chain(self.services.iter())
            .find_map(|named| {
                let addr = named.service.servers().first()?.addr;
                named.service.upstream(addr)
            })
    }

    /// The names of the services, the app's and every revision's, that connect to an `https://`
    /// server without verifying its certificate: what a plan compares to list the relaxation.
    #[must_use]
    pub fn unverified_services(&self) -> BTreeSet<&str> {
        self.services
            .iter()
            .chain(self.revisions.iter().flat_map(|rev| rev.services.iter()))
            .filter(|named| named.service.skips_tls_verification())
            .map(|named| &*named.name)
            .collect()
    }

    fn take(&self, revision: usize, router: usize, cx: PickCx<'_>) -> Option<Pick> {
        let (upstream, lease) = self.service(revision, router)?.pick(cx)?;
        Some(Pick {
            revision,
            upstream,
            lease,
        })
    }

    /// Every service of the app with the revision it belongs to (`None` for the app's own, shared
    /// by all revisions), for the registry that settles their runtime state.
    pub(crate) fn services_mut(
        &mut self,
    ) -> impl Iterator<Item = (Option<&str>, &mut service::Named)> {
        let shared = self.services.iter_mut().map(|named| (None, named));
        let own = self.revisions.iter_mut().flat_map(|revision| {
            let CompiledRevision { id, services, .. } = revision;
            let id: &str = id;
            services.iter_mut().map(move |named| (Some(id), named))
        });
        shared.chain(own)
    }

    /// Chooses a revision and backend for a new request that matched router `router`, or `None`
    /// when no revision takes new requests or the router's service there has no available
    /// server.
    ///
    /// Only `serving` revisions with a weight and a backend are candidates; `retiring` and
    /// `draining` ones never get new requests here. Revisions share traffic in proportion to
    /// their [`CompiledRevision::effective_weight`], the servers of a service are picked by its
    /// algorithm.
    #[must_use]
    pub fn pick(&self, router: usize, cx: PickCx<'_>) -> Option<Pick> {
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
                return self.take(index, router, cx);
            }
            ticket -= weight;
        }
        // A canary step landed between summing and walking: take the last revision in use.
        let (index, _) = self
            .revisions
            .iter()
            .enumerate()
            .rev()
            .find(|(_, revision)| revision.effective_weight() > 0)?;
        self.take(index, router, cx)
    }

    /// The pick for a session pinned to revision `id`: `serving` or `retiring` revisions with a
    /// backend only, weight ignored. `None` when the revision is `draining`, gone or has no
    /// backend, and the request must be routed by [`Self::pick`].
    #[must_use]
    pub fn pick_pinned(&self, router: usize, id: &str, cx: PickCx<'_>) -> Option<Pick> {
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
        self.take(index, router, cx)
    }

    /// [`Self::pick`] for the first router with a request that has no headers, for tests of the
    /// weighted choice.
    #[cfg(test)]
    pub(crate) fn pick_any(&self) -> Option<Pick> {
        let request = pingora::http::RequestHeader::build("GET", b"/", None).ok()?;
        self.pick(0, PickCx::new(&request))
    }

    /// [`Self::pick_pinned`] for the first router, for tests.
    #[cfg(test)]
    pub(crate) fn pick_pinned_any(&self, id: &str) -> Option<Pick> {
        let request = pingora::http::RequestHeader::build("GET", b"/", None).ok()?;
        self.pick_pinned(0, id, PickCx::new(&request))
    }
}

/// An immutable, compiled [`Snapshot`].
#[derive(Debug, Default)]
pub struct RoutingTable {
    version: u64,
    apps: Box<[CompiledApp]>,
    index: Index,
    by_id: HashMap<Box<str>, usize>,
    certificates: CertStore,
    acme: Plan,
    tls_hello_policy: bool,
    budgets: HashMap<Box<str>, Budget>,
    weights: HashMap<Box<str>, u32>,
    skew_secret: Option<SkewSecret>,
    forwarded: HashMap<Box<str>, Trust>,
    entry_policies: HashMap<Box<str>, EntryPolicy>,
    context: CompileContext,
    access_log: Option<Arc<Policy>>,
    series: TableSeries,
    applied_at: u64,
    tracing: Option<Arc<trace::Policy>>,
}

impl RoutingTable {
    /// Compiles a snapshot with the default entry points. Nothing is merged or repaired: any
    /// problem rejects it whole.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] for an unknown tenant, a matcher, middleware, service or entry
    /// point that is refused, declarations that conflict (every [`Conflict`] is reported at
    /// once), a certificate that cannot be served or a `skew_secret` that is too short.
    pub fn compile(snapshot: &Snapshot) -> Result<Self, CompileError> {
        Self::compile_with(snapshot, &CompileContext::default())
    }

    /// Like [`Self::compile`], for a process whose bound entry points are `context`.
    ///
    /// # Errors
    ///
    /// The same as [`Self::compile`].
    pub fn compile_with(
        snapshot: &Snapshot,
        context: &CompileContext,
    ) -> Result<Self, CompileError> {
        let built = compile::build(snapshot, context)?;
        let index = Index::build(&built.apps);
        let tls_hello_policy = built
            .apps
            .iter()
            .any(|app| app.tls_options().is_some_and(Options::needs_hello));
        Ok(Self {
            version: snapshot.version,
            by_id: built
                .apps
                .iter()
                .enumerate()
                .map(|(index, app)| (Box::from(app.id()), index))
                .collect(),
            index,
            apps: built.apps.into_boxed_slice(),
            tls_hello_policy,
            certificates: built.certificates,
            acme: built.acme,
            budgets: snapshot
                .tenants
                .iter()
                .map(|tenant| (tenant.id.clone(), tenant.budget))
                .collect(),
            weights: snapshot
                .tenants
                .iter()
                .map(|tenant| (tenant.id.clone(), tenant.weight))
                .collect(),
            skew_secret: snapshot.skew_secret.clone(),
            forwarded: crate::client_ip::policies(snapshot),
            entry_policies: entry_policy::build(snapshot, context),
            context: context.clone(),
            // `compile::shape` refused an invalid policy before this runs.
            access_log: access_log::compile(snapshot).ok().flatten(),
            series: TableSeries::default(),
            applied_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
            tracing: trace::compile(snapshot).ok().flatten(),
        })
    }

    /// The version of the snapshot this table was compiled from; `0` for the empty table.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// When this table was compiled, in seconds since the Unix epoch: the moment its snapshot
    /// went live, or the moment a revert put it back. `0` for the empty table.
    #[must_use]
    pub fn applied_at(&self) -> u64 {
        self.applied_at
    }

    /// The ids of the tenants the snapshot declares, in no particular order.
    pub fn tenant_ids(&self) -> impl Iterator<Item = &str> {
        self.budgets.keys().map(AsRef::as_ref)
    }

    /// The router index, for [`crate::route`].
    #[must_use]
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// The apps in snapshot order.
    #[must_use]
    pub fn apps(&self) -> &[CompiledApp] {
        &self.apps
    }

    /// The app at `index`, as in [`Matched::app`].
    #[must_use]
    pub fn app(&self, index: usize) -> Option<&CompiledApp> {
        self.apps.get(index)
    }

    /// The app with id `id`, and its index.
    #[must_use]
    pub fn app_by_id(&self, id: &str) -> Option<(usize, &CompiledApp)> {
        let index = *self.by_id.get(id)?;
        Some((index, self.apps.get(index)?))
    }

    /// The router `matched` points at, with its app.
    #[must_use]
    pub fn router(&self, matched: Matched) -> Option<(&CompiledApp, &CompiledRouter)> {
        let app = self.apps.get(matched.app)?;
        Some((app, app.routers.get(matched.router)?))
    }

    /// Finds, in this table, the router `matched` pointed at in `earlier`: the app with the same
    /// id and tenant and TLS policy, and the router with the same name and the same middleware
    /// chain. `None` when any of that differs, so a request that waited (for a wake, or after a
    /// revision drained) never continues under a chain or a policy it did not start with.
    #[must_use]
    pub fn rematch(&self, earlier: &Self, matched: Matched) -> Option<Matched> {
        let (old_app, old_router) = earlier.router(matched)?;
        let (app_index, app) = self.app_by_id(old_app.id())?;
        if app.tenant != old_app.tenant || app.tls != old_app.tls {
            return None;
        }
        let router = app
            .routers
            .iter()
            .position(|router| router.name() == old_router.name())?;
        (app.routers.get(router)?.chain_digest() == old_router.chain_digest()).then_some(Matched {
            app: app_index,
            router,
        })
    }

    /// The apps whose routers may serve `host` (normalized): those with a literal claim on it
    /// and every app with a fallback router. A superset of what [`crate::route::matching`] can
    /// pick; the TLS handshake uses it to decide whether to ask for a client certificate.
    pub fn may_serve<'a>(&'a self, host: &str) -> impl Iterator<Item = &'a CompiledApp> {
        self.index.may_serve(&self.apps, host)
    }

    /// The declared wildcard nearest to `host`, for explaining a miss; see
    /// [`Index::nearest_wildcard`].
    #[must_use]
    pub fn nearest_wildcard(&self, host: &str) -> Option<String> {
        self.index.nearest_wildcard(host)
    }

    /// The resource budget of tenant `id`, or `None` when the snapshot does not declare it.
    #[must_use]
    pub fn tenant_budget(&self, id: &str) -> Option<Budget> {
        self.budgets.get(id).copied()
    }

    /// The fair-share weight of tenant `id`, or `None` when the snapshot does not declare it.
    #[must_use]
    pub fn tenant_weight(&self, id: &str) -> Option<u32> {
        self.weights.get(id).copied()
    }

    /// Whether some app has TLS options that a ClientHello can already refuse: the
    /// pre-TLS hook reads hellos only then, or for on-demand certificates.
    #[must_use]
    pub fn tls_hello_policy(&self) -> bool {
        self.tls_hello_policy
    }

    /// Certificates for the TLS listener.
    #[must_use]
    pub fn certificates(&self) -> &CertStore {
        &self.certificates
    }

    /// The entry points this table was compiled for, with their protocols.
    #[must_use]
    pub fn context(&self) -> &CompileContext {
        &self.context
    }

    /// The key signing session cookies, when the snapshot sets a `skew_secret`.
    #[must_use]
    pub fn skew_secret(&self) -> Option<&SkewSecret> {
        self.skew_secret.as_ref()
    }

    /// Whom the entry point called `entry_point` believes about the client (see
    /// [`crate::client_ip`]); `None` when its policy says nothing, so nobody is trusted.
    #[must_use]
    pub fn forwarded_trust(&self, entry_point: &str) -> Option<&Trust> {
        self.forwarded.get(entry_point)
    }

    /// Every entry point that has a forwarded-header policy, with it, by name.
    pub fn forwarded_trusts(&self) -> impl Iterator<Item = (&str, &Trust)> {
        self.forwarded.iter().map(|(name, trust)| (&**name, trust))
    }

    /// The request policy of the entry point called `entry_point`: redirect, timeouts, HTTP/2
    /// limits, encoded slash and header rules. [`EntryPolicy::none`] when the snapshot
    /// says nothing about it.
    #[must_use]
    pub fn entry_policy(&self, entry_point: &str) -> &EntryPolicy {
        self.entry_policies
            .get(entry_point)
            .unwrap_or(EntryPolicy::none())
    }

    /// Every entry point that has a request policy, with it, by name.
    pub fn entry_policies(&self) -> impl Iterator<Item = (&str, &EntryPolicy)> {
        self.entry_policies
            .iter()
            .map(|(name, policy)| (&**name, policy))
    }

    /// The access log policy for a request that matched `matched` (`None`: it matched no router),
    /// or `None` when the request is not logged.
    #[must_use]
    pub fn access_log(&self, matched: Option<Matched>) -> Option<&Arc<Policy>> {
        let router = matched
            .and_then(|matched| self.router(matched))
            .and_then(|(_, router)| router.access_log());
        access_log::effective(self.access_log.as_ref(), router)
    }

    /// The tracing policy for a request that matched `matched`, or `None` when it is not traced.
    #[must_use]
    pub fn tracing(&self, matched: Option<Matched>) -> Option<&Arc<trace::Policy>> {
        let router = matched
            .and_then(|matched| self.router(matched))
            .and_then(|(_, router)| router.tracing());
        trace::effective(self.tracing.as_ref(), router)
    }

    /// The ACME view of the snapshot: HTTP-01 answers, missing and due certificates.
    #[must_use]
    pub fn acme(&self) -> &Plan {
        &self.acme
    }

    /// The metric handles of the routers and services, resolved when the table went live.
    #[must_use]
    pub fn series(&self) -> &TableSeries {
        &self.series
    }

    /// Gives the table the handles the registry settled for it, just before it goes live.
    pub(crate) fn set_series(&mut self, series: TableSeries) {
        self.series = series;
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
    // Server and balancer state that outlives swaps; touched only by `swap`.
    states: Arc<service::Registry>,
    // Circuit breaker state that outlives swaps; touched only by `swap`.
    breakers: Arc<crate::middleware::circuit_breaker::Registry>,
    // Failure counters and credential cache of `basic_auth`; touched only by `swap`.
    basic_auth: Arc<middleware::basic_auth::Registry>,
    // Nonce secret, replay table and failure counters of `digest_auth`; touched only by `swap`.
    digest_auth: Arc<middleware::digest_auth::Registry>,
    // Buckets of `rate_limit` middlewares; touched only by `swap`.
    rate_limits: Arc<middleware::rate_limit::Registry>,
    // Counts of `in_flight_req` middlewares; touched only by `swap`.
    in_flight_reqs: Arc<middleware::in_flight_req::Registry>,
    // Permits of `forward_auth` middlewares; touched only by `swap`.
    forward_auths: Arc<middleware::forward_auth::Registry>,
    // Series of entry points, routers and services, and the snapshot counters; touched by
    // `swap` and when a snapshot is refused.
    metrics: Arc<metrics::Registry>,
    // The entry points this process bound; fixed for the life of the handle.
    context: Arc<CompileContext>,
}

impl TableHandle {
    /// A handle on the empty table: no apps, version `0`, the default entry points.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A handle that compiles snapshots for a process with the entry points of `context`.
    #[must_use]
    pub fn with_context(context: CompileContext) -> Self {
        Self {
            context: Arc::new(context),
            ..Self::default()
        }
    }

    /// Reports and settles metrics through `metrics`, the registry [`crate::observe::metrics`]
    /// renders, instead of a default one. Call it before the handle is cloned.
    #[must_use]
    pub fn with_metrics(mut self, metrics: metrics::Registry) -> Self {
        self.metrics = Arc::new(metrics);
        self
    }

    /// The metric registry of this process: where entry points find their series and what the
    /// endpoints render.
    #[must_use]
    pub fn metrics(&self) -> &metrics::Registry {
        &self.metrics
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
            let err = ApplyError::Stale {
                live,
                offered: snapshot.version,
            };
            self.metrics.rejected(&err);
            return Err(err);
        }
        let table = self.compile(snapshot).map_err(|err| {
            let err = ApplyError::from(err);
            self.metrics.rejected(&err);
            err
        })?;
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

    /// Compiles `snapshot` as [`Self::apply`] would and swaps nothing in: what `POST
    /// /v1/snapshot/plan` compares the live table with.
    ///
    /// # Errors
    ///
    /// The same as [`Self::apply`], including the version check.
    pub fn compile_candidate(&self, snapshot: &Snapshot) -> Result<RoutingTable, ApplyError> {
        let live = self.live.load().version();
        if snapshot.version <= live {
            return Err(ApplyError::Stale {
                live,
                offered: snapshot.version,
            });
        }
        Ok(self.compile(snapshot)?)
    }

    /// Compiles `snapshot` as [`Self::apply`] would and discards the table: what `POST
    /// /v1/snapshot/validate` answers with. It ignores the version, and touches no state: no
    /// swap, no registry, no metric.
    ///
    /// # Errors
    ///
    /// The [`CompileError`] [`Self::apply`] would refuse the snapshot with.
    pub fn validate(&self, snapshot: &Snapshot) -> Result<(), CompileError> {
        self.compile(snapshot).map(drop)
    }

    /// The one compile every path uses: apply, plan, validate and revert cannot disagree on what
    /// a snapshot means, because none compiles it any other way.
    fn compile(&self, snapshot: &Snapshot) -> Result<RoutingTable, CompileError> {
        RoutingTable::compile_with(snapshot, &self.context)
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
        self.swap(self.compile(&restored)?);
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
        self.states.settle(&mut table.apps);
        self.breakers.settle(&mut table.apps);
        self.basic_auth.settle(&mut table.apps);
        self.digest_auth.settle(&mut table.apps);
        self.rate_limits.settle(&mut table.apps);
        self.in_flight_reqs.settle(&mut table.apps);
        self.forward_auths.settle(&mut table.apps);
        self.metrics.settle(&mut table);
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
    use serde_json::{Value, json};

    use super::*;
    use crate::router::View;

    fn revision(id: &str, port: u16, weight: u16, state: &str) -> Value {
        json!({
            "id": id, "state": state, "weight": weight,
            "services": [{ "name": "web", "type": "loadbalancer",
                "servers": [{ "url": format!("http://127.0.0.1:{port}") }] }],
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "test helper: callers pass fixtures by value"
    )]
    fn app(id: &str, hosts: &[&str], revisions: Vec<Value>) -> Value {
        json!({
            "id": id, "tenant": "t1", "declared_by": format!("test/{id}"),
            "tls": { "mode": "acme" },
            "routers": [{ "name": "all", "match": { "host": hosts }, "service": "web" }],
            "revisions": revisions,
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "test helper: callers pass fixtures by value"
    )]
    fn snapshot(version: u64, apps: Vec<Value>) -> Snapshot {
        serde_json::from_value(json!({
            "version": version,
            "tenants": [{ "id": "t1", "weight": 1, "budget": { "max_inflight": 10, "max_buffer_bytes": 1024 } }],
            "apps": apps,
        }))
        .expect("snapshot")
    }

    fn serving(port: u16) -> Vec<Value> {
        vec![revision("r1", port, 100, "serving")]
    }

    fn find<'a>(table: &'a RoutingTable, host: &str, path: &str) -> Option<&'a CompiledApp> {
        let request =
            pingora::http::RequestHeader::build("GET", path.as_bytes(), None).expect("request");
        let view = View {
            host,
            path,
            entry_point: "web",
            tls: false,
            request: &request,
            client_ip: None,
        };
        let matched = table.index().find(table.apps(), &view)?;
        table.app(matched.app)
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
        assert_eq!(find(&table, "a.test", "/").map(CompiledApp::id), Some("a"));
        assert_eq!(
            find(&table, "x.w.test", "/").map(CompiledApp::id),
            Some("w")
        );
        assert!(find(&table, "w.test", "/").is_none());
        assert!(find(&table, "nope.test", "/").is_none());
    }

    #[test]
    fn only_serving_revisions_get_new_requests() {
        let revisions = vec![
            revision("old", 1, 100, "draining"),
            revision("mid", 2, 100, "retiring"),
            revision("new", 3, 1, "serving"),
        ];
        let table = RoutingTable::compile(&snapshot(1, vec![app("a", &["a.test"], revisions)]))
            .expect("compiles");
        let app = find(&table, "a.test", "/").expect("known host");
        for _ in 0..10 {
            let pick = app.pick_any().expect("serving revision exists");
            assert_eq!(app.revisions()[pick.revision].id(), "new");
            assert_eq!(pick.upstream.port(), 3);
        }
    }

    #[test]
    fn no_serving_revision_means_no_pick() {
        let revisions = vec![revision("old", 1, 100, "draining")];
        let table = RoutingTable::compile(&snapshot(1, vec![app("a", &["a.test"], revisions)]))
            .expect("compiles");
        let app = find(&table, "a.test", "/").expect("known host");
        assert!(app.pick_any().is_none());
    }

    #[test]
    fn revisions_share_traffic_by_weight() {
        let revisions = vec![
            revision("a", 1, 3, "serving"),
            revision("b", 2, 1, "serving"),
        ];
        let table = RoutingTable::compile(&snapshot(1, vec![app("a", &["a.test"], revisions)]))
            .expect("compiles");
        let app = find(&table, "a.test", "/").expect("known host");
        let on_a = (0..400)
            .filter(|_| app.pick_any().is_some_and(|pick| pick.upstream.port() == 1))
            .count();
        assert_eq!(on_a, 300);
    }

    #[test]
    fn servers_of_a_service_take_turns() {
        let mut one = revision("r", 1, 1, "serving");
        one["services"][0]["servers"]
            .as_array_mut()
            .expect("servers")
            .push(json!({ "url": "http://127.0.0.1:2" }));
        let table = RoutingTable::compile(&snapshot(1, vec![app("a", &["a.test"], vec![one])]))
            .expect("compiles");
        let app = find(&table, "a.test", "/").expect("known host");
        let ports: Vec<u16> = (0..4)
            .filter_map(|_| app.pick_any().map(|pick| pick.upstream.port()))
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

        let mut unknown = app("a", &["a.test"], serving(1));
        unknown["tenant"] = json!("nobody");
        assert!(matches!(
            RoutingTable::compile(&snapshot(1, vec![unknown])),
            Err(CompileError::UnknownTenant { .. })
        ));

        let bad = snapshot(1, vec![app("a", &["a b"], serving(1))]);
        assert!(matches!(
            RoutingTable::compile(&bad),
            Err(CompileError::Rejected(rejected))
                if rejected.iter().all(|one| one.code() == "invalid_host")
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
        assert!(find(&handle.load(), "a.test", "/").is_some());
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
        assert!(find(&in_flight, "a.test", "/").is_some());
        assert!(find(&handle.load(), "a.test", "/").is_none());
    }

    #[test]
    fn revision_weights_follow_state_weight_and_backends() {
        let revisions = vec![
            revision("old", 1, 50, "draining"),
            revision("new", 2, 70, "serving"),
            revision("zero", 3, 0, "serving"),
        ];
        let table = RoutingTable::compile(&snapshot(
            1,
            vec![
                app("a", &["a.test"], revisions),
                app("w", &["*.w.test"], serving(4)),
            ],
        ))
        .expect("compiles");
        let exact = find(&table, "a.test", "/").expect("exact host");
        let weights: Vec<(u16, u16)> = exact
            .revisions()
            .iter()
            .map(|revision| (revision.weight(), revision.effective_weight()))
            .collect();
        assert_eq!(weights, [(50, 0), (70, 70), (0, 0)]);
        assert_eq!(exact.hosts(), [Box::<str>::from("a.test")]);
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

    #[test]
    fn a_waiting_request_keeps_only_a_router_with_the_same_chain() {
        let before = RoutingTable::compile(&snapshot(1, vec![app("a", &["a.test"], serving(1))]))
            .expect("compiles");
        let same = RoutingTable::compile(&snapshot(2, vec![app("a", &["a.test"], serving(9))]))
            .expect("compiles");
        let matched = Matched { app: 0, router: 0 };
        assert_eq!(same.rematch(&before, matched), Some(matched));

        let mut changed = app("a", &["a.test"], serving(1));
        changed["tls"] =
            json!({ "mode": "acme", "client_ca_pem": crate::clientauth::test_ca_pem("ca") });
        let stricter = RoutingTable::compile(&snapshot(3, vec![changed])).expect("compiles");
        assert_eq!(stricter.rematch(&before, matched), None);
    }
}
