//! Compiling a snapshot, and what a compile refuses with.
//!
//! `build` runs the passes in a fixed order and stops at the first pass that finds problems,
//! reporting all of that pass's problems at once: tenants, the shape of every object (names,
//! planned-but-unbuilt facets, entry point policies), routers (matchers and entry points),
//! conflicts between declarations ([`crate::conflict`]), canary policies, middlewares and
//! chains, services and the revisions' routes, then certificates and ACME.
//!
//! A kind module (a middleware, a service, a matcher leaf) never adds a variant to
//! [`crate::table::CompileError`]: it returns an [`Invalid`] naming a stable code, and the
//! compiler wraps it into a [`Rejected`] that says where it was declared. Every `Rejected` of a
//! pass is reported in the `conflicts` list of the `422` body.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::acme::{Plan, alpn01, dns01};
use crate::canary;
use crate::client_ip::Trust;
use crate::clientauth::ClientAuth;
use crate::conflict;
use crate::entry::CompileContext;
use crate::entry::policy as entry_policy;
use crate::host::HostPattern;
use crate::l4;
use crate::middleware::{self, CompileCx, Stage};
use crate::observe;
use crate::router::{self, CompiledRouter, Tier, rule};
use crate::service::graph;
use crate::service::mirroring::{Plan as MirrorPlan, Scope as MirrorScope, Scopes as MirrorScopes};
use crate::service::resolve::{NameBudget, Resolver};
use crate::service::upstream_policy::UpstreamPolicy;
use crate::service::{self, NamedTransport, RingBudget, Service, Transport};
use crate::table::{CompileError, CompiledApp, CompiledRevision, Parts, ServiceRef};
use crate::tls::{CertStore, Options};
use crate::wasm as engine;
use podgate_model::{App, Declared, RevisionState, SkewSecret, Snapshot};

/// One configuration problem: a stable code, a message, and optional extra fields for the `422`
/// body (the WASM rejection adds `module` and `name`, for example).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    /// The stable code, such as `invalid_middleware`.
    pub code: &'static str,
    /// What is wrong.
    pub message: String,
    /// Extra fields of the `422` entry.
    pub details: Map<String, Value>,
}

impl Invalid {
    /// A problem with no extra fields.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: Map::new(),
        }
    }

    /// Adds one extra field to the `422` entry.
    #[must_use]
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_owned(), value.into());
        self
    }
}

/// An [`Invalid`] with its place in the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// The declaring app; empty for a problem of the snapshot itself.
    pub app: Box<str>,
    /// Its `declared_by` source.
    pub declared_by: Box<str>,
    /// The object, like `router api` or `revision r2 service web`.
    pub at: Box<str>,
    /// What is wrong.
    pub invalid: Invalid,
}

impl Rejected {
    /// Places `invalid` at `at` of app `app`.
    #[must_use]
    pub fn new(app: &App, at: impl Into<Box<str>>, invalid: Invalid) -> Self {
        Self {
            app: app.id.clone(),
            declared_by: app.declared_by.clone(),
            at: at.into(),
            invalid,
        }
    }

    /// Places `invalid` at `at` of the snapshot itself.
    #[must_use]
    pub fn snapshot(at: impl Into<Box<str>>, invalid: Invalid) -> Self {
        Self {
            app: "".into(),
            declared_by: "".into(),
            at: at.into(),
            invalid,
        }
    }

    /// The stable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.invalid.code
    }

    /// The object in the `conflicts` list of a `422` body: `code`, `message`, `app`,
    /// `declared_by`, `at` and the extra fields.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "code": self.invalid.code, "message": self.to_string(),
            "app": self.app, "declared_by": self.declared_by, "at": self.at,
        });
        if let Some(object) = value.as_object_mut() {
            for (key, extra) in &self.invalid.details {
                object.insert(key.clone(), extra.clone());
            }
        }
        value
    }
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.app.is_empty() {
            write!(f, "{}: {}", self.at, self.invalid.message)
        } else {
            write!(
                f,
                "app {} ({}) {}: {}",
                self.app, self.declared_by, self.at, self.invalid.message
            )
        }
    }
}

/// The messages of `rejected`, separated by `; `.
pub(crate) fn join(rejected: &[Rejected]) -> String {
    rejected
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// What `build` hands to the routing table.
pub(crate) struct Built {
    pub(crate) apps: Vec<CompiledApp>,
    pub(crate) certificates: CertStore,
    pub(crate) acme: Plan,
}

/// Compiles `snapshot` for a process with the entry points of `context`.
pub(crate) fn build(snapshot: &Snapshot, context: &CompileContext) -> Result<Built, CompileError> {
    if snapshot
        .skew_secret
        .as_ref()
        .is_some_and(|secret| !secret.is_long_enough())
    {
        return Err(CompileError::SkewSecretTooShort);
    }
    let tenants: HashSet<&str> = snapshot.tenants.iter().map(|tenant| &*tenant.id).collect();
    if let Some(app) = snapshot
        .apps
        .iter()
        .find(|app| !tenants.contains(&*app.tenant))
    {
        return Err(CompileError::UnknownTenant {
            app: app.id.clone(),
            tenant: app.tenant.clone(),
        });
    }
    let rejected = shape(snapshot, context, &tenants);
    if !rejected.is_empty() {
        return Err(CompileError::Rejected(rejected));
    }
    // A router that can match a host nobody claims takes that host from whoever deploys there
    // next, so only an exclusive entry point or the operator allows it.
    let mut rejected = Vec::new();
    let mut routers: Vec<Vec<CompiledRouter>> = snapshot
        .apps
        .iter()
        .map(|app| routers_of(app, snapshot, context, &mut rejected))
        .collect();
    for (app, list) in snapshot.apps.iter().zip(&routers) {
        catch_all_rule(app, list, context, &mut rejected);
    }
    let mut names = NameBudget::default();
    let l4s: Vec<l4::Compiled> = snapshot
        .apps
        .iter()
        .map(|app| l4::compile(app, snapshot, context, &mut names, &mut rejected))
        .collect();
    if !rejected.is_empty() {
        return Err(CompileError::Rejected(rejected));
    }
    let sni_claims: Vec<Vec<HostPattern>> = l4s
        .iter()
        .map(|l4| l4.tcp().claims().cloned().collect())
        .collect();
    let mut conflicts = conflict::detect(&snapshot.apps, &routers, &sni_claims);
    conflicts.extend(l4::detect(&snapshot.apps, &l4s));
    if !conflicts.is_empty() {
        return Err(CompileError::Conflicts(conflicts));
    }
    let unsound: Vec<_> = snapshot.apps.iter().flat_map(canary::validate).collect();
    if !unsound.is_empty() {
        return Err(CompileError::Canary(unsound));
    }
    let mut client_auth = Vec::with_capacity(snapshot.apps.len());
    let mut bad_cas = Vec::new();
    for app in &snapshot.apps {
        match ClientAuth::compile(app, context.spiffe()) {
            Ok(compiled) => client_auth.push(compiled),
            Err(rejection) => bad_cas.push(rejection),
        }
    }
    if !bad_cas.is_empty() {
        return Err(CompileError::ClientCa(bad_cas));
    }
    let mut tls_options = Vec::with_capacity(snapshot.apps.len());
    let mut rejected = Vec::new();
    for app in &snapshot.apps {
        match Options::compile(app, context.tls_floor()) {
            Ok(compiled) => tls_options.push(compiled),
            Err(problems) => rejected.extend(
                problems
                    .into_iter()
                    .map(|invalid| Rejected::new(app, "tls".to_owned(), invalid)),
            ),
        }
    }
    if !rejected.is_empty() {
        return Err(CompileError::Rejected(rejected));
    }

    let mut engine = engine::Compiler::default();
    let mut rejected = Vec::new();
    let mut parts = Vec::with_capacity(snapshot.apps.len());
    let mut rings = RingBudget::default();
    for (app, app_routers) in snapshot.apps.iter().zip(&mut routers) {
        let limits = crate::cache::Limits {
            tenant_budget: snapshot
                .tenants
                .iter()
                .find(|tenant| tenant.id == app.tenant)
                .map_or(0, |tenant| tenant.budget.max_buffer_bytes),
            max_percent: context.cache_tenant_max_percent(),
        };
        let stages = stages_of(
            app,
            app_routers,
            &mut engine,
            limits,
            &mut rejected,
            context.resolver(),
            snapshot.skew_secret.as_ref(),
        );
        reject_oidc_on_plain_entry_points(
            snapshot,
            context,
            app,
            app_routers,
            &stages,
            &mut rejected,
        );
        let max_buffer_bytes = snapshot
            .tenants
            .iter()
            .find(|tenant| tenant.id == app.tenant)
            .map_or(u64::MAX, |tenant| tenant.budget.max_buffer_bytes);
        for named in &stages {
            if let Stage::Errors(errors) = &named.stage
                && let Err(invalid) = errors.check_budget(&app.tenant, max_buffer_bytes)
            {
                rejected.push(Rejected::new(
                    app,
                    format!("middleware {}", named.name),
                    invalid,
                ));
            }
            if let Stage::ForwardAuth(auth) = &named.stage
                && let Err(invalid) = auth.check_budget(&app.tenant, max_buffer_bytes)
            {
                rejected.push(Rejected::new(
                    app,
                    format!("middleware {}", named.name),
                    invalid,
                ));
            }
        }
        let transports = transports_of(app, context.spiffe(), &mut rejected);
        let services = services_of(
            app,
            app_routers,
            context.upstream_policy(),
            &transports,
            snapshot.skew_secret.as_ref(),
            Limits {
                statics: StaticCx {
                    locals: service::Locals {
                        statics: context.static_roots().of(&app.tenant),
                        fastcgi: context.fastcgi().of(&app.tenant),
                    },
                    max_buffer_bytes,
                },
                rings: &mut rings,
                names: &mut names,
                resolver: context.resolver(),
            },
            &mut rejected,
        );
        parts.push((stages, services));
    }
    rejected.extend(middleware::plugin::bind(
        snapshot,
        context.plugins(),
        parts.iter_mut().map(|(stages, _)| stages.as_mut_slice()),
    ));
    let stage_lists: Vec<&[middleware::Named]> =
        parts.iter().map(|(stages, _)| stages.as_slice()).collect();
    let l4_lists: Vec<&[l4::middleware::Named]> =
        l4s.iter().map(|l4| l4.tcp().middlewares()).collect();
    rejected.extend(middleware::limits::over_budget(
        snapshot,
        &stage_lists,
        &l4_lists,
    ));
    rejected.extend(middleware::jwt_auth::check_snapshot(
        snapshot,
        &stage_lists,
        context.upstream_policy(),
    ));
    rejected.extend(middleware::rate_limit::check_snapshot(
        snapshot,
        &stage_lists,
        context.rate_limit_stores(),
    ));
    rejected.extend(middleware::in_flight_req::check_snapshot(
        snapshot,
        &stage_lists,
        context.rate_limit_stores(),
    ));
    rejected.extend(middleware::oidc::check_snapshot(
        snapshot,
        &stage_lists,
        context.upstream_policy(),
    ));
    if !rejected.is_empty() {
        return Err(CompileError::Rejected(rejected));
    }

    // The names a terminating TCP router serves need certificates like an HTTP host does.
    let claims: Vec<Vec<HostPattern>> = routers
        .iter()
        .zip(&l4s)
        .map(|(list, l4)| {
            list.iter()
                .flat_map(|r| r.patterns().cloned())
                .chain(l4.tcp().terminated_claims().cloned())
                .collect()
        })
        .collect();
    let mut rejected = dns01::reject(snapshot, &claims, context);
    rejected.extend(alpn01::reject(snapshot, &claims));
    if !rejected.is_empty() {
        return Err(CompileError::Rejected(rejected));
    }
    let apps: Vec<CompiledApp> = snapshot
        .apps
        .iter()
        .zip(routers)
        .zip(parts)
        .zip(client_auth)
        .zip(tls_options)
        .zip(l4s)
        .map(
            |(
                ((((app, routers), (stages, (services, revisions))), client_auth), tls_options),
                l4,
            )| {
                let digest = fingerprint(app, &routers, l4.tcp());
                CompiledApp::assemble(
                    app,
                    Parts {
                        routers,
                        stages,
                        services,
                        revisions,
                        fingerprint: digest,
                        client_auth,
                        tls_options,
                        l4,
                    },
                )
            },
        )
        .collect();
    let refused = grpc_needs_http2(snapshot, &apps);
    if !refused.is_empty() {
        return Err(CompileError::Rejected(refused));
    }
    Ok(Built {
        apps,
        certificates: CertStore::build(&snapshot.certificates)?,
        acme: Plan::compile(snapshot, &claims)?,
    })
}

/// gRPC cannot be spoken over HTTP/1.1, so a router whose chain has a `grpc_web` stage may only
/// reach services that speak HTTP/2 in every revision that takes requests.
fn grpc_needs_http2(snapshot: &Snapshot, apps: &[CompiledApp]) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    for (app, compiled) in snapshot.apps.iter().zip(apps) {
        for (router_index, router) in compiled.routers().iter().enumerate() {
            let Some(stage) = router
                .chain()
                .iter()
                .filter_map(|index| compiled.stages().get(*index))
                .find(|named| matches!(named.stage, Stage::GrpcWeb(_)))
            else {
                continue;
            };
            for (revision_index, revision) in compiled.revisions().iter().enumerate() {
                if revision.state() == RevisionState::Draining {
                    continue;
                }
                let Some((leaf, reason)) = compiled
                    .root(revision_index, router_index)
                    .and_then(|root| service::graph::http2_refusal(compiled, root, 0))
                else {
                    continue;
                };
                rejected.push(Rejected::new(
                    app,
                    format!("router {} revision {}", router.name(), revision.id()),
                    Invalid::new(
                        "invalid_middleware",
                        format!(
                            "middleware {} (grpc_web) needs an HTTP/2 upstream, and service {leaf} {reason}",
                            stage.name
                        ),
                    ),
                ));
            }
        }
    }
    rejected
}

/// A digest of everything the app declares except where it was declared. A router declared with a
/// `rule` counts as the tree and the priority the rule compiled to, so rewriting a rule without
/// changing its meaning is not a change.
fn fingerprint(app: &App, routers: &[CompiledRouter], tcp: &l4::tcp::Compiled) -> u64 {
    let mut value = serde_json::to_value(app).unwrap_or(Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.remove("declared_by");
        if let Some(Value::Array(declared)) = object.get_mut("routers") {
            for (router, compiled) in declared.iter_mut().zip(routers) {
                if let Some(router) = router.as_object_mut() {
                    router.remove("declared_by");
                    if router.remove("rule").is_some() {
                        router.insert("match".to_owned(), rule::canonical(compiled.matcher_json()));
                        router.insert("priority".to_owned(), compiled.priority().into());
                    }
                }
            }
        }
        if let Some(Value::Array(declared)) = object
            .get_mut("tcp")
            .and_then(Value::as_object_mut)
            .and_then(|tcp| tcp.get_mut("routers"))
        {
            for (router, compiled) in declared.iter_mut().zip(tcp.routers()) {
                if let Some(router) = router.as_object_mut()
                    && router.remove("rule").is_some()
                    && let Some(tree) = compiled.match_json()
                {
                    router.insert("match".to_owned(), rule::canonical(tree));
                }
            }
        }
    }
    router::digest(value.to_string())
}

/// Duplicate names, facets that are planned and not built, and entry point policies.
fn shape(snapshot: &Snapshot, context: &CompileContext, tenants: &HashSet<&str>) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    if let Some(invalid) = observe::reject(snapshot) {
        rejected.push(Rejected::snapshot("observability", invalid));
    }
    let mut policies = HashSet::new();
    for policy in &snapshot.entry_points {
        let at = format!("entry point {}", policy.name);
        let mut problem = |invalid: Invalid| rejected.push(Rejected::snapshot(at.clone(), invalid));
        if !context.knows(&policy.name) {
            problem(Invalid::new(
                "unknown_entry_point",
                format!("entry point {} is not bound by this node", policy.name),
            ));
        }
        if !policies.insert(&*policy.name) {
            problem(Invalid::new(
                "duplicate_name",
                format!("entry point {} has two policies", policy.name),
            ));
        }
        if let Some(Err(invalid)) = policy.forwarded_headers.as_ref().map(Trust::parse) {
            problem(invalid);
        }
        for tenant in policy.tenants.iter().flatten() {
            if !tenants.contains(&**tenant) {
                problem(Invalid::new(
                    "unknown_tenant",
                    format!("entry point {} names unknown tenant {tenant}", policy.name),
                ));
            }
        }
    }
    for (name, invalid) in entry_policy::check_all(&snapshot.entry_points, context) {
        rejected.push(Rejected::snapshot(format!("entry point {name}"), invalid));
    }
    for app in &snapshot.apps {
        let mut problem =
            |at: String, invalid: Invalid| rejected.push(Rejected::new(app, at, invalid));
        duplicates(
            "router",
            app.routers.iter().map(|router| &*router.name),
            &mut problem,
        );
        duplicates(
            "middleware",
            app.middlewares.iter().map(|declared| &*declared.name),
            &mut problem,
        );
        duplicates(
            "service",
            app.services.iter().map(|declared| &*declared.name),
            &mut problem,
        );
        for revision in &app.revisions {
            duplicates(
                &format!("revision {} service", revision.id),
                revision.services.iter().map(|declared| &*declared.name),
                &mut problem,
            );
            for declared in &revision.services {
                if app
                    .services
                    .iter()
                    .any(|shared| shared.name == declared.name)
                {
                    problem(
                        format!("revision {} service {}", revision.id, declared.name),
                        Invalid::new(
                            "duplicate_name",
                            format!("service {} is also declared by the app", declared.name),
                        ),
                    );
                }
            }
        }
        duplicates(
            "transport",
            app.transports.iter().map(|declared| &*declared.name),
            &mut problem,
        );
    }
    rejected
}

fn duplicates<'a>(
    what: &str,
    names: impl Iterator<Item = &'a str>,
    problem: &mut impl FnMut(String, Invalid),
) {
    let mut seen = HashSet::new();
    for name in names {
        if !seen.insert(name) {
            problem(
                format!("{what} {name}"),
                Invalid::new("duplicate_name", format!("{what} {name} is declared twice")),
            );
        }
    }
}

/// Compiles the routers of `app`: matchers, and the entry points each may listen on.
fn routers_of(
    app: &App,
    snapshot: &Snapshot,
    context: &CompileContext,
    rejected: &mut Vec<Rejected>,
) -> Vec<CompiledRouter> {
    let policy_of = |name: &str| snapshot.entry_points.iter().find(|p| &*p.name == name);
    let admits = |name: &str| {
        policy_of(name)
            .and_then(|policy| policy.tenants.as_ref())
            .is_none_or(|tenants| tenants.contains(&app.tenant))
    };
    let mut compiled = Vec::with_capacity(app.routers.len());
    for router in &app.routers {
        let at = format!("router {}", router.name);
        let resolved = match rule::resolve(router) {
            Ok(resolved) => resolved,
            Err(invalid) => {
                rejected.push(Rejected::new(app, at, invalid));
                continue;
            }
        };
        let mut compile = match CompiledRouter::compile(&resolved, app, &snapshot.entry_points) {
            Ok(compiled) => compiled,
            Err(err) => {
                let invalid = if router.rule.is_some() {
                    Invalid::new("invalid_rule", format!("rule: {err}"))
                } else {
                    Invalid::new(err.code, format!("match: {err}"))
                };
                rejected.push(Rejected::new(app, at, invalid));
                continue;
            }
        };
        match router.entry_points.as_deref() {
            Some([]) => rejected.push(Rejected::new(
                app,
                at,
                Invalid::new("unknown_entry_point", "entry_points lists no entry point"),
            )),
            Some(list) => {
                for name in list {
                    if !context.knows(name) {
                        rejected.push(Rejected::new(
                            app,
                            at.clone(),
                            Invalid::new(
                                "unknown_entry_point",
                                format!("entry point {name} is not bound by this node"),
                            ),
                        ));
                    } else {
                        if context.protocol_of(name).is_some_and(|p| !p.is_http()) {
                            rejected.push(Rejected::new(
                                app,
                                at.clone(),
                                Invalid::new(
                                    "entry_point_protocol",
                                    format!(
                                        "entry point {name} is not http or https, so an HTTP router cannot listen on it"
                                    ),
                                ),
                            ));
                        }
                        if !admits(name) {
                            rejected.push(Rejected::new(
                                app,
                                at.clone(),
                                Invalid::new(
                                    "entry_point_forbidden",
                                    format!(
                                        "entry point {name} does not admit tenant {}",
                                        app.tenant
                                    ),
                                ),
                            ));
                        }
                    }
                }
            }
            None => {
                let open: Vec<Box<str>> = context
                    .http_entry_points()
                    .filter(|name| admits(name))
                    .map(Box::from)
                    .collect();
                if open.is_empty() {
                    rejected.push(Rejected::new(
                        app,
                        at,
                        Invalid::new(
                            "no_reachable_entry_point",
                            format!(
                                "router {} lists no entry points and no http or https entry point of this node admits tenant {}, so it would serve nothing",
                                router.name, app.tenant
                            ),
                        ),
                    ));
                } else if open.len() != context.entry_points().count() {
                    compile.narrow_entry_points(open.into_boxed_slice());
                }
            }
        }
        compiled.push(compile);
    }
    compiled
}

/// Refuses the routers of `app` that can match a host no one claims, unless the operator or the
/// entry point allows them.
///
/// A router with no host constraint, or a `host_regexp` without a literal host next to it,
/// matches every host nobody claims right now: an app mid-redeploy, a deleted app, a lookalike
/// domain. Whoever declares it first would receive that traffic, and with it the cookies
/// browsers send to the host. It compiles only when every entry point it listens on admits
/// that tenant alone (`tenants` in the entry point policy), or the operator lists the tenant in
/// `CATCH_ALL_TENANTS`; otherwise `catch_all_not_allowed`.
///
/// A `host_regexp` next to a literal `host` in an `all` is not a catch-all: the literal claim
/// bounds the router, and the regexp can only narrow it, so no regexp text is ever inspected.
fn catch_all_rule(
    app: &App,
    routers: &[CompiledRouter],
    context: &CompileContext,
    rejected: &mut Vec<Rejected>,
) {
    if context.allows_catch_all(&app.tenant) {
        return;
    }
    for router in routers
        .iter()
        .filter(|router| router.is_fallback() && !router.is_unrestricted())
    {
        let what = match router.tier() {
            Tier::Hostless => "has no host constraint",
            _ => "has a host_regexp and no literal host beside it",
        };
        rejected.push(Rejected::new(
            app,
            format!("router {}", router.name()),
            Invalid::new(
                "catch_all_not_allowed",
                format!(
                    "the router {what}, so it would match every host nobody claims; add a literal host in an `all`, attach it only to an entry point whose tenants policy names this tenant alone, or ask the operator to list the tenant in CATCH_ALL_TENANTS"
                ),
            ),
        ));
    }
}

/// The configuration of a `chain` middleware.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainConfig {
    middlewares: Vec<Box<str>>,
}

/// Compiles the middlewares of `app` and sets each router's effective chain.
fn stages_of(
    app: &App,
    routers: &mut [CompiledRouter],
    engine: &mut engine::Compiler,
    limits: crate::cache::Limits,
    rejected: &mut Vec<Rejected>,
    resolver: &Resolver,
    skew_secret: Option<&SkewSecret>,
) -> Vec<middleware::Named> {
    let mut stages: Vec<middleware::Named> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut chains: HashMap<&str, Vec<Box<str>>> = HashMap::new();
    let mut failed: HashSet<&str> = HashSet::new();
    for declared in &app.middlewares {
        let at = format!("middleware {}", declared.name);
        if &*declared.kind == "chain" {
            match serde_json::from_value::<ChainConfig>(Value::Object(declared.config.clone())) {
                Ok(config) => {
                    chains.insert(&declared.name, config.middlewares);
                }
                Err(err) => rejected.push(Rejected::new(
                    app,
                    at,
                    Invalid::new("invalid_middleware", format!("chain: {err}")),
                )),
            }
            continue;
        }
        let compiled =
            Stage::compile(declared, &mut CompileCx { app, engine }).and_then(|mut stage| {
                // The one kind whose limits depend on the tenant's budget and the operator.
                if let middleware::Stage::Cache(cache) = &mut stage {
                    cache.bind(limits)?;
                }
                // The kinds that dial a host name of their configuration, and the one that keys
                // its cookies with the snapshot's `skew_secret`.
                match &mut stage {
                    middleware::Stage::ForwardAuth(auth) => auth.bind(resolver),
                    middleware::Stage::JwtAuth(auth) => auth.bind(resolver),
                    middleware::Stage::Oidc(auth) => auth.bind(skew_secret, resolver)?,
                    _ => {}
                }
                Ok(stage)
            });
        match compiled {
            Ok(stage) => {
                index.insert(&declared.name, stages.len());
                texts.push(Value::Object(declared.config.clone()).to_string() + &declared.kind);
                stages.push(middleware::Named {
                    name: declared.name.clone(),
                    stage,
                });
            }
            Err(invalid) => {
                failed.insert(&declared.name);
                rejected.push(Rejected::new(app, at, invalid));
            }
        }
    }
    let expand = |names: &[Box<str>]| -> Result<Vec<usize>, Invalid> {
        let mut out = Vec::new();
        let mut stack = Vec::new();
        for name in names {
            if failed.contains(&**name) {
                continue;
            }
            expand_name(name, &index, &chains, &mut stack, &mut out)?;
        }
        Ok(out)
    };
    let default = match expand(&app.default_chain) {
        Ok(chain) => chain,
        Err(invalid) => {
            rejected.push(Rejected::new(app, "default_chain", invalid));
            Vec::new()
        }
    };
    for (router, compiled) in app.routers.iter().zip(routers) {
        match expand(&router.chain) {
            Ok(own) => {
                let chain: Vec<usize> = default.iter().copied().chain(own).collect();
                if let Err(invalid) = middleware::check_cache_order(&stages, &chain) {
                    rejected.push(Rejected::new(
                        app,
                        format!("router {}", router.name),
                        invalid,
                    ));
                    continue;
                }
                let digest = router::digest(
                    chain
                        .iter()
                        .map(|stage| (stage, texts.get(*stage)))
                        .collect::<Vec<_>>(),
                );
                compiled.set_chain(chain.into_boxed_slice(), digest);
            }
            Err(invalid) => rejected.push(Rejected::new(
                app,
                format!("router {}", router.name),
                invalid,
            )),
        }
    }
    stages
}

/// Deepest nesting of `chain` middlewares.
const MAX_CHAIN_DEPTH: usize = 8;

fn expand_name<'a>(
    name: &'a str,
    index: &HashMap<&str, usize>,
    chains: &'a HashMap<&str, Vec<Box<str>>>,
    stack: &mut Vec<&'a str>,
    out: &mut Vec<usize>,
) -> Result<(), Invalid> {
    if let Some(stage) = index.get(name) {
        out.push(*stage);
        return Ok(());
    }
    let Some(members) = chains.get(name) else {
        return Err(Invalid::new(
            "unknown_middleware_ref",
            format!("no middleware called {name}"),
        ));
    };
    if stack.contains(&name) || stack.len() >= MAX_CHAIN_DEPTH {
        return Err(Invalid::new(
            "invalid_middleware",
            format!("chain {name} contains itself or nests deeper than {MAX_CHAIN_DEPTH}"),
        ));
    }
    stack.push(name);
    for member in members {
        expand_name(member, index, chains, stack, out)?;
    }
    stack.pop();
    Ok(())
}

/// Compiles the transports of `app`. A transport no service names is still compiled, so a bad one
/// is refused whether or not it is used. A bad one keeps its name with a placeholder, so the
/// services naming it do not add an `unknown_transport` to the one real problem; the snapshot is
/// refused, so the placeholder is never used.
pub(crate) fn transports_of(
    app: &App,
    spiffe: &crate::spiffe::Spiffe,
    rejected: &mut Vec<Rejected>,
) -> Vec<NamedTransport> {
    app.transports
        .iter()
        .map(|declared| {
            let transport = Transport::compile_for(declared, Some((spiffe, &app.tenant)))
                .unwrap_or_else(|invalid| {
                    rejected.push(Rejected::new(
                        app,
                        format!("transport {}", declared.name),
                        invalid,
                    ));
                    Transport::default()
                });
            NamedTransport {
                name: declared.name.clone(),
                transport: Arc::new(transport),
            }
        })
        .collect()
}

/// What `static` services need to know about their app's tenant.
#[derive(Clone, Copy)]
struct StaticCx<'a> {
    /// The roots the operator declared for the tenant.
    locals: service::Locals<'a>,
    /// The tenant's `max_buffer_bytes`.
    max_buffer_bytes: u64,
}

/// What the services of one app are checked against while they are built.
struct Limits<'a> {
    /// What `static` services need to know about their tenant.
    statics: StaticCx<'a>,
    /// The hash ring points the snapshot has used so far.
    rings: &'a mut RingBudget,
    /// The distinct DNS names the snapshot's servers use so far, per app and per tenant.
    names: &'a mut NameBudget,
    /// Where servers named by host name find their addresses.
    resolver: &'a Resolver,
}

/// Compiles the services of `app` and of each of its revisions, and finds every router's
/// service in every revision. The literal server addresses of every service must pass `policy`.
fn services_of(
    app: &App,
    routers: &[CompiledRouter],
    policy: &UpstreamPolicy,
    transports: &[NamedTransport],
    skew_secret: Option<&SkewSecret>,
    limits: Limits<'_>,
    rejected: &mut Vec<Rejected>,
) -> (Vec<service::Named>, Vec<CompiledRevision>) {
    let Limits {
        statics,
        rings,
        names,
        resolver,
    } = limits;
    let problems = rejected.len();
    // Once a cap on hash rings is exceeded the snapshot is rejected: the remaining services are
    // not built, so one push cannot make the proxy build rings without end.
    let compile = |declared: &Declared,
                   at: String,
                   rings: &mut RingBudget,
                   names: &mut NameBudget,
                   rejected: &mut Vec<Rejected>| {
        if rings.refused() {
            return None;
        }
        match Service::compile(
            declared,
            transports,
            Some(&statics.locals),
            &app.tenant,
            resolver,
        )
        .and_then(|mut service| {
            service.bind_sticky(skew_secret, &app.id, &declared.name)?;
            rings.charge(&app.tenant, service.ring_points())?;
            names.charge(&app.tenant, &app.id, service.dns_names())?;
            names.charge_srv(&app.tenant, &app.id, service.srv_names())?;
            Ok(service)
        }) {
            Ok(service) => {
                if let Some(site) = service.as_static()
                    && let Err(invalid) = site.check_budget(&app.tenant, statics.max_buffer_bytes)
                {
                    rejected.push(Rejected::new(app, at.as_str(), invalid));
                }
                if let Some(site) = service.as_fastcgi()
                    && let Err(invalid) = site.check_budget(&app.tenant, statics.max_buffer_bytes)
                {
                    rejected.push(Rejected::new(app, at.as_str(), invalid));
                }
                if let Some(mirroring) = service.as_mirroring()
                    && let Err(invalid) =
                        mirroring.check_budget(&app.tenant, statics.max_buffer_bytes)
                {
                    rejected.push(Rejected::new(app, at.as_str(), invalid));
                }
                for invalid in
                    policy.forbidden_servers(&app.tenant, &declared.name, &service.servers())
                {
                    rejected.push(Rejected::new(app, at.as_str(), invalid));
                }
                Some(service::Named {
                    name: declared.name.clone(),
                    service,
                })
            }
            Err(invalid) => {
                rejected.push(Rejected::new(app, at, invalid));
                None
            }
        }
    };
    let shared: Vec<service::Named> = app
        .services
        .iter()
        .filter_map(|declared| {
            compile(
                declared,
                format!("service {}", declared.name),
                rings,
                names,
                rejected,
            )
        })
        .collect();
    let owns: Vec<Vec<service::Named>> = app
        .revisions
        .iter()
        .map(|revision| {
            revision
                .services
                .iter()
                .filter_map(|declared| {
                    compile(
                        declared,
                        format!("revision {} service {}", revision.id, declared.name),
                        rings,
                        names,
                        rejected,
                    )
                })
                .collect()
        })
        .collect();
    // Mirror names are resolved once every service of every revision exists, because `name@rev`
    // reaches into another revision. A snapshot that already has a problem in this app is not
    // resolved: its missing services would only add noise to the real error.
    let resolvable = rejected.len() == problems && !rings.refused();
    let scopes: Vec<MirrorScope<'_>> = app
        .revisions
        .iter()
        .zip(&owns)
        .map(|(revision, own)| MirrorScope {
            id: &revision.id,
            draining: revision.state == RevisionState::Draining,
            own,
        })
        .collect();
    let scoped = MirrorScopes {
        shared: &shared,
        revisions: &scopes,
    };
    // `weighted` and `failover` children are resolved the same way, then every graph is walked
    // for cycles, depth and size.
    let (links, graph_problems) = graph::resolve(&scoped);
    let graphs_resolved = graph_problems.is_empty();
    if resolvable {
        for (at, invalid) in graph_problems {
            rejected.push(Rejected::new(app, at, invalid));
        }
    }
    let compiling = graph::Compiling {
        scopes: &scoped,
        links: &links,
    };
    if resolvable && graphs_resolved {
        for (at, scope) in scopes.iter().enumerate() {
            let own = scope
                .own
                .iter()
                .enumerate()
                .map(|(index, named)| (ServiceRef::Own(index), named));
            let shared = shared
                .iter()
                .enumerate()
                .map(|(index, named)| (ServiceRef::App(index), named));
            for (service, named) in own
                .chain(shared)
                .filter(|(_, named)| named.service.is_graph())
            {
                let node = graph::Node {
                    revision: at,
                    service,
                };
                if let Err(invalid) = graph::validate(&compiling, node) {
                    let place = match service {
                        ServiceRef::Own(_) => {
                            format!("revision {} service {}", scope.id, named.name)
                        }
                        ServiceRef::App(_) => {
                            format!("service {} revision {}", named.name, scope.id)
                        }
                    };
                    rejected.push(Rejected::new(app, place, invalid));
                }
            }
        }
    }
    let mut wiring = Vec::with_capacity(app.revisions.len());
    for (at, revision) in app.revisions.iter().enumerate() {
        let own = &owns[at];
        let plans = mirror_plans(app, &scoped, at, resolvable, rejected);
        let mut routes = Vec::with_capacity(routers.len());
        let mut mirrors = Vec::with_capacity(routers.len());
        for router in routers {
            let found = own
                .iter()
                .position(|named| &*named.name == router.service())
                .map(ServiceRef::Own)
                .or_else(|| {
                    shared
                        .iter()
                        .position(|named| &*named.name == router.service())
                        .map(ServiceRef::App)
                });
            if found.is_none() && revision.state != RevisionState::Draining && !rings.refused() {
                rejected.push(Rejected::new(
                    app,
                    format!("router {} revision {}", router.name(), revision.id),
                    Invalid::new(
                        "unknown_service",
                        format!(
                            "service {} is defined by neither the revision nor the app",
                            router.service()
                        ),
                    ),
                ));
            }
            // A router whose service mirrors is answered by the mirroring service's main.
            let planned =
                found.and_then(|found| plans.iter().find(|(declared, _)| *declared == found));
            let plan = planned.and_then(|(_, plan)| plan.clone());
            routes.push(match planned {
                Some(_) => plan.as_ref().map(|plan| plan.main()),
                None => found,
            });
            mirrors.push(plan);
        }
        let backed = routes.iter().flatten().any(|route| {
            let node = graph::Node {
                revision: at,
                service: *route,
            };
            graph::backed(&compiling, node, 0)
        });
        wiring.push((routes, mirrors, backed));
    }
    let revisions = app
        .revisions
        .iter()
        .zip(owns)
        .zip(links)
        .zip(wiring)
        .map(|(((revision, own), links), (routes, mirrors, backed))| {
            CompiledRevision::new(revision, own, routes, mirrors, links, backed)
        })
        .collect();
    (shared, revisions)
}

/// Resolves every `mirroring` service of `app` for revision `at`: the plan for each, or none when
/// the revision is `draining` and lacks its main service. A refusal is recorded when `resolvable`.
fn mirror_plans(
    app: &App,
    scopes: &MirrorScopes<'_>,
    at: usize,
    resolvable: bool,
    rejected: &mut Vec<Rejected>,
) -> Vec<(ServiceRef, Option<Arc<MirrorPlan>>)> {
    let Some(scope) = scopes.revisions.get(at) else {
        return Vec::new();
    };
    let own = scope
        .own
        .iter()
        .enumerate()
        .map(|(index, named)| (ServiceRef::Own(index), named));
    let shared = scopes
        .shared
        .iter()
        .enumerate()
        .map(|(index, named)| (ServiceRef::App(index), named));
    own.chain(shared)
        .filter_map(|(found, named)| Some((found, named, named.service.as_mirroring()?)))
        .map(
            |(found, named, mirroring)| match mirroring.resolve(scopes, at) {
                Ok(plan) => (found, plan.map(Arc::new)),
                Err(invalid) => {
                    if resolvable {
                        let at = match found {
                            ServiceRef::Own(_) => {
                                format!("revision {} service {}", scope.id, named.name)
                            }
                            ServiceRef::App(_) => {
                                format!("service {} revision {}", named.name, scope.id)
                            }
                        };
                        rejected.push(Rejected::new(app, at, invalid));
                    }
                    (found, None)
                }
            },
        )
        .collect()
}

/// Hashes anything that is `Hash`, for fingerprints that only need equality within a process.
pub(crate) fn hash_of(value: &impl Hash) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Refuses an `oidc` stage on a router that a plain `http` entry point serves: its cookies are
/// always `Secure`, so a browser that reached the route over plain HTTP drops them and loops
/// through the login. An entry point is fine when the snapshot makes it redirect, or trusts
/// `forwarded_headers` (TLS ends in front of it and the browser sees `https`). The operator puts
/// the HTTPS redirect on the plain entry point.
fn reject_oidc_on_plain_entry_points(
    snapshot: &Snapshot,
    context: &CompileContext,
    app: &App,
    routers: &[CompiledRouter],
    stages: &[middleware::Named],
    rejected: &mut Vec<Rejected>,
) {
    let covered = |name: &str| {
        snapshot.entry_points.iter().any(|policy| {
            &*policy.name == name
                && (policy.redirect.is_some() || policy.forwarded_headers.is_some())
        })
    };
    for router in routers {
        let has_oidc = router.chain().iter().any(|index| {
            matches!(
                stages.get(*index).map(|named| &named.stage),
                Some(middleware::Stage::Oidc(_))
            )
        });
        if !has_oidc {
            continue;
        }
        let plain = context
            .entry_points()
            .filter(|(name, protocol)| {
                *protocol == crate::entry::Protocol::Http
                    && router.listens_on(name)
                    && !covered(name)
            })
            .map(|(name, _)| name)
            .next();
        if let Some(name) = plain {
            rejected.push(Rejected::new(
                app,
                format!("router {}", router.name()),
                Invalid::new(
                    "invalid_middleware",
                    format!(
                        "oidc: router {} is served by the plain http entry point {name}, where the session cookie (always Secure) would be dropped by the browser; put a `redirect` to an https entry point on {name}, or list only https entry points",
                        router.name()
                    ),
                )
                .with("entry_point", name),
            ));
        }
    }
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn extra_fields_land_next_to_the_standard_ones() {
        let app: App = serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "src", "tls": { "mode": "acme" },
            "routers": [], "revisions": [],
        }))
        .expect("app");
        let rejected = Rejected::new(
            &app,
            "middleware w",
            Invalid::new("wasm_forbidden_import", "no").with("module", "env"),
        );
        let json = rejected.to_json();
        assert_eq!(json["code"], "wasm_forbidden_import");
        assert_eq!(json["at"], "middleware w");
        assert_eq!(json["module"], "env");
        assert_eq!(json["message"], "app a (src) middleware w: no");
        let snapshot =
            Rejected::snapshot("entry point x", Invalid::new("unknown_entry_point", "no"));
        assert_eq!(snapshot.to_string(), "entry point x: no");
    }
}
