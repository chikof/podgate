//! The routing table: a [`Snapshot`] compiled into immutable lookup structures, and the shared
//! handle that swaps it atomically.
//!
//! A request calls [`TableHandle::load`] once and keeps that [`Arc`] for its whole life, so a
//! swap never changes the routing of a request in flight. A snapshot that does not compile
//! leaves the live table untouched.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use thiserror::Error;

use crate::conflict::{self, Conflict};
use crate::host::{HostMap, HostPattern, InvalidHost, MatchKind};
use crate::snapshot::{App, Budget, Revision, RevisionState, Snapshot};
use crate::tls::{CertError, CertStore};

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

/// One revision of an app, ready for routing.
#[derive(Debug)]
pub struct CompiledRevision {
    id: Box<str>,
    upstreams: Box<[SocketAddr]>,
    weight: u16,
    state: RevisionState,
    next_upstream: AtomicU64,
}

impl CompiledRevision {
    fn new(revision: &Revision) -> Self {
        Self {
            id: revision.id.clone(),
            upstreams: revision.upstreams.clone().into_boxed_slice(),
            weight: revision.weight,
            state: revision.state,
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

    /// The weight [`CompiledApp::pick`] gives this revision right now: the configured weight
    /// while it takes new requests, `0` otherwise (not `serving`, or no backend).
    #[must_use]
    pub fn effective_weight(&self) -> u16 {
        if self.takes_new_requests() {
            self.weight
        } else {
            0
        }
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
    revisions: Box<[CompiledRevision]>,
    next_revision: AtomicU64,
}

/// Where [`CompiledApp::pick`] sent a new request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pick {
    /// Index into [`CompiledApp::revisions`].
    pub revision: usize,
    /// The chosen backend.
    pub upstream: SocketAddr,
}

impl CompiledApp {
    fn new(app: &App) -> Self {
        Self {
            id: app.id.clone(),
            tenant: app.tenant.clone(),
            declared_by: app.declared_by.clone(),
            allow_domain_fronting: app.allow_domain_fronting,
            revisions: app.revisions.iter().map(CompiledRevision::new).collect(),
            next_revision: AtomicU64::new(0),
        }
    }

    /// Whether a TLS request may name a host other than its SNI.
    #[must_use]
    pub fn allow_domain_fronting(&self) -> bool {
        self.allow_domain_fronting
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
    /// their weights, backends of one revision take turns.
    #[must_use]
    pub fn pick(&self) -> Option<Pick> {
        let total: u64 = self
            .revisions
            .iter()
            .filter(|revision| revision.takes_new_requests())
            .map(|revision| u64::from(revision.weight))
            .sum();
        if total == 0 {
            return None;
        }
        let mut ticket = self.next_revision.fetch_add(1, Ordering::Relaxed) % total;
        for (index, revision) in self.revisions.iter().enumerate() {
            if !revision.takes_new_requests() {
                continue;
            }
            let weight = u64::from(revision.weight);
            if ticket < weight {
                let turn = revision.next_upstream.fetch_add(1, Ordering::Relaxed);
                let slot = usize::try_from(turn % revision.upstreams.len() as u64).ok()?;
                return Some(Pick {
                    revision: index,
                    upstream: *revision.upstreams.get(slot)?,
                });
            }
            ticket -= weight;
        }
        None
    }
}

/// An immutable, compiled [`Snapshot`].
#[derive(Debug, Default)]
pub struct RoutingTable {
    version: u64,
    apps: Box<[CompiledApp]>,
    hosts: HostMap<usize>,
    certificates: CertStore,
    budgets: HashMap<Box<str>, Budget>,
}

impl RoutingTable {
    /// Compiles a snapshot. Nothing is merged or repaired: any problem rejects it whole.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] for an invalid host, an unknown tenant, declarations that
    /// conflict (every [`Conflict`] is reported at once) or a certificate that cannot be served.
    pub fn compile(snapshot: &Snapshot) -> Result<Self, CompileError> {
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
        let mut hosts = HostMap::default();
        for (pattern, index) in claims {
            hosts.insert(pattern, index);
        }
        Ok(Self {
            version: snapshot.version,
            apps: snapshot.apps.iter().map(CompiledApp::new).collect(),
            hosts,
            certificates: CertStore::build(&snapshot.certificates)?,
            budgets: snapshot
                .tenants
                .iter()
                .map(|tenant| (tenant.id.clone(), tenant.budget))
                .collect(),
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
}

/// Shared handle to the live [`RoutingTable`]. Cheap to clone; every clone sees the same table.
#[derive(Debug, Clone, Default)]
pub struct TableHandle {
    live: Arc<ArcSwap<RoutingTable>>,
    // Serializes `apply`, so the version check and the swap are one step.
    apply_lock: Arc<Mutex<()>>,
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
        let _guard = self
            .apply_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let live = self.live.load().version();
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
        self.live.store(Arc::new(table));
        Ok(())
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
