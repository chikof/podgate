//! The Gateway API half of the Kubernetes source: `Gateway`, `HTTPRoute` and `GRPCRoute`.
//!
//! ```toml
//! [[source]]
//! kind = "kubernetes"
//! name = "k8s"
//! gateway_api = true                       # default false: the cluster needs the Gateway API CRDs
//! gateway_class = "podgate"                # the GatewayClass whose Gateways are served
//! [source.listener_entry_points]           # Gateway listener port to podgate entry point
//! 80 = "web"
//! 443 = "websecure"
//! ```
//!
//! - [`types`]: the objects, as serde structs of the fields the translation reads.
//! - [`listener`]: which routes attach to which listeners (`allowedRoutes`, host names,
//!   entry points) and the certificates of `HTTPS` listeners.
//! - [`httproute`], [`grpcroute`]: a rule's matches as podgate matcher leaves.
//! - [`filters`]: filters as middlewares and mirrors.
//! - [`backend`]: `backendRefs` as services, with `ReferenceGrant`s and the tenant rule.
//! - [`route`]: one route as routers, middlewares and services.
//! - [`precedence`]: the Gateway API's match order as explicit `priority` values.
//!
//! The source serves a `Gateway` of the class `gateway_class` only when a `GatewayClass` of that
//! name names the controller [`types::CONTROLLER`]. Everything the API lets a route say that
//! podgate cannot say rejects the route with a reason: [`translate`] returns a [`RouteReport`]
//! for every route that names one of our Gateways, which change 0074 writes into the route's
//! status. The reference is `docs/ref/provider-gateway.md`.

pub mod backend;
pub mod filters;
pub mod grpcroute;
pub mod httproute;
pub mod listener;
pub mod precedence;
pub mod route;
pub mod types;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use podgate_model::{App, Declared, Router};
use serde_json::json;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tracing::debug;

use self::backend::{Backends, Grants};
use self::listener::{Attachment, Certs, Gateways, ParentReport, RouteInfo};
use self::precedence::{Candidate, priorities};
use self::types::{
    CONTROLLER, Gateway, GatewayClass, GrpcRoute, HttpRoute, Namespace, ReferenceGrant,
};
use super::client::{ApiClient, Event, ObjectMeta, Query, Resource, Store};
use super::ingress::{Cluster, REVISION};
use super::{Tagged, track, watch};
use crate::source::{Origin, SourceApp, SourceCertificate, TenantClaim};
use crate::trust::HostPattern;

/// The default `GatewayClass` name.
pub const DEFAULT_CLASS: &str = "podgate";

/// The kind of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// An `HTTPRoute`.
    Http,
    /// A `GRPCRoute`.
    Grpc,
}

impl Kind {
    /// The kind as the API names it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Http => "HTTPRoute",
            Self::Grpc => "GRPCRoute",
        }
    }

    /// The prefix of the local app id: it holds `_`, which no namespace has, so no Ingress app
    /// (`<namespace>.<name>`) can have the same id.
    fn id_prefix(self) -> &'static str {
        match self {
            Self::Http => "httproute_",
            Self::Grpc => "grpcroute_",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a route is not served, with the Gateway API's name for the reason where there is one
/// (`UnsupportedValue`, `RefNotPermitted`, `BackendNotFound`, `InvalidKind`,
/// `NotAllowedByListeners`, `NoMatchingListenerHostname`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// The reason, as a condition's `reason`.
    pub reason: &'static str,
    /// What is wrong.
    pub message: String,
}

fn reject(reason: &'static str, message: impl Into<String>) -> Rejection {
    Rejection {
        reason,
        message: message.into(),
    }
}

/// The settings of the Gateway API half of a `[[source]]` entry.
#[derive(Debug, Clone)]
pub struct Options {
    /// The `GatewayClass` whose Gateways are served.
    pub class: Box<str>,
    /// Listener port to entry point.
    pub entry_points: BTreeMap<u16, Box<str>>,
}

impl Options {
    /// The options from the `gateway_class` and `listener_entry_points` keys.
    ///
    /// # Errors
    ///
    /// A message naming the key when the class is empty, a port is not `1..=65535`, or an entry
    /// point name is empty.
    pub fn new(
        class: Option<String>,
        entry_points: Option<BTreeMap<String, String>>,
    ) -> Result<Self, String> {
        let class = class.unwrap_or_else(|| DEFAULT_CLASS.to_owned());
        if class.is_empty() {
            return Err("gateway_class: is empty".to_owned());
        }
        let entry_points = match entry_points {
            Some(map) => {
                let mut ports = BTreeMap::new();
                for (port, entry) in map {
                    let number: u16 =
                        port.parse().ok().filter(|port| *port != 0).ok_or_else(|| {
                            format!("listener_entry_points: {port:?} is not a port")
                        })?;
                    if entry.is_empty() {
                        return Err(format!("listener_entry_points[{port}]: is empty"));
                    }
                    ports.insert(number, entry.into());
                }
                ports
            }
            None => BTreeMap::from([(80, "web".into()), (443, "websecure".into())]),
        };
        Ok(Self {
            class: class.into(),
            entry_points,
        })
    }
}

/// One change of a Gateway API kind.
pub enum Change {
    /// A `GatewayClass`.
    Class(Event<GatewayClass>),
    /// A `Namespace`.
    Namespace(Event<Namespace>),
    /// A `Gateway`.
    Gateway(Event<Gateway>),
    /// An `HTTPRoute`.
    Http(Event<HttpRoute>),
    /// A `GRPCRoute`.
    Grpc(Event<GrpcRoute>),
    /// A `ReferenceGrant`.
    Grant(Event<ReferenceGrant>),
}

/// Everything the source has read of the Gateway API: one store per kind, and per namespace
/// scope for the namespaced ones.
pub struct Cache {
    classes: Store<GatewayClass>,
    namespaces: Store<Namespace>,
    gateways: Vec<Store<Gateway>>,
    http: Vec<Store<HttpRoute>>,
    grpc: Vec<Store<GrpcRoute>>,
    grants: Vec<Store<ReferenceGrant>>,
}

fn stores<R: Resource>(scopes: usize) -> Vec<Store<R>> {
    (0..scopes).map(|_| Store::new()).collect()
}

impl Cache {
    /// An empty cache for `scopes` namespace scopes.
    #[must_use]
    pub fn new(scopes: usize) -> Self {
        Self {
            classes: Store::new(),
            namespaces: Store::new(),
            gateways: stores(scopes),
            http: stores(scopes),
            grpc: stores(scopes),
            grants: stores(scopes),
        }
    }

    /// Applies one change, recording the watcher's outage in `outages`.
    pub fn apply(
        &mut self,
        outages: &mut BTreeMap<(&'static str, usize), Box<str>>,
        scope: usize,
        change: Change,
    ) {
        match change {
            Change::Class(event) => track(outages, &mut self.classes, 0, event),
            Change::Namespace(event) => track(outages, &mut self.namespaces, 0, event),
            Change::Gateway(event) => track(outages, &mut self.gateways[scope], scope, event),
            Change::Http(event) => track(outages, &mut self.http[scope], scope, event),
            Change::Grpc(event) => track(outages, &mut self.grpc[scope], scope, event),
            Change::Grant(event) => track(outages, &mut self.grants[scope], scope, event),
        }
    }

    /// Whether every list has succeeded once.
    #[must_use]
    pub fn synced(&self) -> bool {
        self.classes.is_synced()
            && self.namespaces.is_synced()
            && self.gateways.iter().all(Store::is_synced)
            && self.http.iter().all(Store::is_synced)
            && self.grpc.iter().all(Store::is_synced)
            && self.grants.iter().all(Store::is_synced)
    }
}

/// Starts the watchers of the Gateway API kinds: the cluster-scoped ones once, the namespaced
/// ones per scope.
pub(super) fn watch_all(
    tasks: &mut JoinSet<()>,
    client: &ApiClient,
    scopes: &[Option<Box<str>>],
    tx: &Sender<Tagged>,
) {
    watch::<GatewayClass>(tasks, client, Query::all(), 0, tx, |event| {
        super::Change::Gateway(Change::Class(event))
    });
    watch::<Namespace>(tasks, client, Query::all(), 0, tx, |event| {
        super::Change::Gateway(Change::Namespace(event))
    });
    for (scope, namespace) in scopes.iter().enumerate() {
        let query = || match namespace {
            Some(namespace) => Query::in_namespace(namespace),
            None => Query::all(),
        };
        watch::<Gateway>(tasks, client, query(), scope, tx, |event| {
            super::Change::Gateway(Change::Gateway(event))
        });
        watch::<HttpRoute>(tasks, client, query(), scope, tx, |event| {
            super::Change::Gateway(Change::Http(event))
        });
        watch::<GrpcRoute>(tasks, client, query(), scope, tx, |event| {
            super::Change::Gateway(Change::Grpc(event))
        });
        watch::<ReferenceGrant>(tasks, client, query(), scope, tx, |event| {
            super::Change::Gateway(Change::Grant(event))
        });
    }
}

/// What became of one route that names a Gateway of ours.
#[derive(Debug)]
pub struct RouteReport {
    /// `HTTPRoute` or `GRPCRoute`.
    pub kind: Kind,
    /// `namespace/name`.
    pub key: String,
    /// One entry per parent reference that names a Gateway of ours.
    pub parents: Vec<ParentReport>,
    /// Why the route is not served, when it is not.
    pub rejected: Option<Rejection>,
}

/// What the Gateway API objects become.
#[derive(Debug, Default)]
pub struct Translation {
    /// One app per served route.
    pub apps: Vec<SourceApp>,
    /// The certificates of `HTTPS` listeners.
    pub certificates: Vec<SourceCertificate>,
    /// What was left out and why, for the outage report: rejected routes, routers of a route
    /// that its tenant may not have, and certificates that could not be read.
    pub notes: Vec<String>,
    /// The report of every route that names a Gateway of ours, in order, for the status.
    pub routes: Vec<RouteReport>,
}

/// A route that is accepted, waiting for its routers' priorities.
struct Pending {
    kind: Kind,
    namespace: String,
    name: String,
    first_seen: u64,
    claim: TenantClaim,
    attachments: Vec<Attachment>,
    built: Vec<route::Built>,
    middlewares: Vec<Declared>,
    services: BTreeMap<Box<str>, route::Service>,
}

fn creation(meta: &ObjectMeta) -> u64 {
    meta.creation_timestamp
        .as_deref()
        .and_then(super::ingress::unix_seconds)
        .unwrap_or(0)
}

/// The route as both kinds share it.
struct RouteMeta<'a> {
    kind: Kind,
    meta: &'a ObjectMeta,
    parent_refs: &'a [types::ParentRef],
    hostnames: &'a [String],
}

/// Translates the Gateway API objects of `cache`.
///
/// `cluster` gives the Services, Secrets and tenant rules, as for Ingresses. Nothing here fails
/// as a whole: a route that cannot be served is left out and reported.
#[must_use]
pub fn translate(cache: &Cache, options: &Options, cluster: &Cluster<'_>) -> Translation {
    let mut out = Translation::default();
    let class_served = cache
        .classes
        .get("", &options.class)
        .is_some_and(|class| class.spec.controller_name == CONTROLLER);
    if !class_served {
        debug!(class = %options.class, "no GatewayClass of ours with that name; no Gateway is served");
        return out;
    }
    let labels: BTreeMap<&str, &BTreeMap<String, String>> = cache
        .namespaces
        .values()
        .map(|namespace| (namespace.metadata.name.as_str(), &namespace.metadata.labels))
        .collect();
    let gateways = Gateways::new(
        cache
            .gateways
            .iter()
            .flat_map(Store::values)
            .filter(|gateway| gateway.spec.gateway_class_name == *options.class),
        labels,
        &options.entry_points,
        cluster.tenancy,
    );
    let grants = Grants::new(cache.grants.iter().flat_map(Store::values));
    let backends = Backends {
        tenancy: cluster.tenancy,
        index: cluster.services,
        grants: &grants,
    };

    let mut pending: Vec<Pending> = Vec::new();
    let mut handle =
        |route: &RouteMeta<'_>, rules: &dyn Fn() -> Result<Vec<httproute::Rule>, Rejection>| {
            let namespace = route.meta.namespace();
            let key = route.meta.key();
            let claim = cluster.tenancy.claim(namespace, None);
            let parsed: Result<Vec<HostPattern>, Rejection> = route
                .hostnames
                .iter()
                .map(|host| {
                    HostPattern::parse(host).map_err(|_| {
                        reject(
                            "UnsupportedValue",
                            format!("hostname {host:?} is not valid"),
                        )
                    })
                })
                .collect();
            let attached = gateways.attach(&RouteInfo {
                kind: route.kind,
                namespace,
                parent_refs: route.parent_refs,
                hostnames: parsed.as_deref().unwrap_or(&[]),
                claim: &claim,
            });
            if !attached.ours {
                return;
            }
            let result = (|| -> Result<Pending, Rejection> {
                parsed?;
                if attached.attachments.is_empty() {
                    let first = attached.parents.iter().find(|parent| !parent.accepted);
                    return Err(first.map_or_else(
                        || reject("NoMatchingParent", "no parent reference names a listener"),
                        |parent| reject(parent.reason, parent.message.clone()),
                    ));
                }
                let rules = rules()?;
                let groups = route::groups(&attached.attachments);
                let draft = route::translate(route.kind, namespace, &rules, &groups, &backends)?;
                let routers: Vec<Router> = draft
                    .routers
                    .iter()
                    .map(|built| built.router.clone())
                    .collect();
                let vetted = cluster.tenancy.vet(&claim, &routers).map_err(|problem| {
                    reject(
                        "NotAllowedByListeners",
                        format!("{}: {}", problem.code, problem.message),
                    )
                })?;
                let mut built = Vec::new();
                let mut left_out = Vec::new();
                for (item, refused) in draft.routers.into_iter().zip(vetted.refused) {
                    match refused {
                        Some(problem) => left_out.push(format!(
                            "router {} left out: {}: {}",
                            item.router.name, problem.code, problem.message
                        )),
                        None => built.push(item),
                    }
                }
                if built.is_empty() {
                    return Err(reject("NotAllowedByListeners", left_out.join("; ")));
                }
                for note in left_out {
                    out.notes.push(format!("{} {key}: {note}", route.kind));
                }
                Ok(Pending {
                    kind: route.kind,
                    namespace: namespace.to_owned(),
                    name: route.meta.name.clone(),
                    first_seen: creation(route.meta),
                    claim: claim.clone(),
                    attachments: attached.attachments.clone(),
                    built,
                    middlewares: draft.middlewares,
                    services: draft.services,
                })
            })();
            let rejected = match result {
                Ok(done) => {
                    pending.push(done);
                    None
                }
                Err(rejection) => {
                    out.notes.push(format!(
                        "{} {key} rejected: {}: {}",
                        route.kind, rejection.reason, rejection.message
                    ));
                    Some(rejection)
                }
            };
            out.routes.push(RouteReport {
                kind: route.kind,
                key,
                parents: attached.parents,
                rejected,
            });
        };
    for route in cache.http.iter().flat_map(Store::values) {
        handle(
            &RouteMeta {
                kind: Kind::Http,
                meta: &route.metadata,
                parent_refs: &route.spec.parent_refs,
                hostnames: &route.spec.hostnames,
            },
            &|| httproute::rules(route),
        );
    }
    for route in cache.grpc.iter().flat_map(Store::values) {
        handle(
            &RouteMeta {
                kind: Kind::Grpc,
                meta: &route.metadata,
                parent_refs: &route.spec.parent_refs,
                hostnames: &route.spec.hostnames,
            },
            &|| grpcroute::rules(route),
        );
    }

    // Priorities: one order per tenant over all of its routers.
    let candidates: Vec<Candidate> = pending
        .iter()
        .flat_map(|route| {
            route.built.iter().map(|built| Candidate {
                tenant: route.claim.mapped.clone(),
                rank: built.rank,
                created: route.first_seen,
                namespace: route.namespace.as_str().into(),
                name: route.name.as_str().into(),
                rule: built.rule,
                matched: built.matched,
                router: built.router.name.clone(),
            })
        })
        .collect();
    let mut priorities = priorities(&candidates).into_iter();
    let gateway_tenants: BTreeMap<String, Option<Box<str>>> = gateways
        .all()
        .map(|gateway| {
            (
                gateway.metadata.key(),
                cluster
                    .tenancy
                    .claim(gateway.metadata.namespace(), None)
                    .mapped,
            )
        })
        .collect();
    let mut served: BTreeMap<(String, Box<str>), BTreeSet<HostPattern>> = BTreeMap::new();
    for route in &mut pending {
        for built in &mut route.built {
            built.router.priority = priorities.next();
        }
        for attachment in &route.attachments {
            if gateway_tenants.get(&attachment.gateway) == Some(&route.claim.mapped)
                && let Some(hosts) = &attachment.hosts
            {
                served
                    .entry((attachment.gateway.clone(), attachment.listener.clone()))
                    .or_default()
                    .extend(hosts.iter().cloned());
            }
        }
    }
    for route in pending {
        match app(cluster.source, route) {
            Ok(app) => out.apps.push(app),
            Err(why) => out.notes.push(why),
        }
    }
    out.apps
        .sort_by(|a, b| a.origin.object.cmp(&b.origin.object));

    let certs = Certs {
        tenancy: cluster.tenancy,
        grants: &grants,
        secret: cluster.secret,
        source: cluster.source,
    };
    for gateway in gateways.all() {
        let key = gateway.metadata.key();
        out.certificates.extend(listener::certificates(
            gateway,
            &|listener| {
                served
                    .get(&(key.clone(), listener.into()))
                    .map(|hosts| hosts.iter().cloned().collect())
                    .unwrap_or_default()
            },
            &certs,
            &mut out.notes,
        ));
    }
    out.certificates
        .sort_by(|a, b| a.origin.object.cmp(&b.origin.object));
    out
}

/// The app of an accepted route: the routers that were kept, and only the middlewares and
/// services they use.
fn app(source: &str, route: Pending) -> Result<SourceApp, String> {
    let key = format!("{}/{}", route.namespace, route.name);
    let routers: Vec<Router> = route.built.into_iter().map(|built| built.router).collect();
    let used_chain: BTreeSet<&str> = routers
        .iter()
        .flat_map(|router| router.chain.iter().map(AsRef::as_ref))
        .collect();
    let middlewares: Vec<&Declared> = route
        .middlewares
        .iter()
        .filter(|middleware| used_chain.contains(&*middleware.name))
        .collect();
    let mut wanted: Vec<&str> = routers.iter().map(|router| &*router.service).collect();
    let mut used: BTreeSet<&str> = BTreeSet::new();
    while let Some(name) = wanted.pop() {
        if used.insert(name)
            && let Some(service) = route.services.get(name)
        {
            wanted.extend(service.children.iter().map(AsRef::as_ref));
        }
    }
    let services: Vec<&Declared> = route
        .services
        .iter()
        .filter(|(name, _)| used.contains(&***name))
        .map(|(_, service)| &service.declared)
        .collect();
    let app: App = serde_json::from_value(json!({
        // The core replaces `tenant` and `declared_by`; they only have to exist.
        "id": format!("{}{}_{}", route.kind.id_prefix(), route.namespace, route.name),
        "tenant": "default",
        "declared_by": format!("kubernetes/{source}:{} {key}", route.kind),
        "tls": { "mode": "on_demand" },
        "routers": routers,
        "middlewares": middlewares,
        "services": services,
        "revisions": [{ "id": REVISION, "state": "serving", "weight": 1 }],
    }))
    .map_err(|err: serde_json::Error| format!("{} {key}: {err}", route.kind))?;
    Ok(SourceApp {
        origin: Origin {
            source: source.into(),
            object: format!("{}/{key}", route.kind).into(),
            first_seen: route.first_seen,
        },
        tenant: route.claim,
        app,
    })
}
