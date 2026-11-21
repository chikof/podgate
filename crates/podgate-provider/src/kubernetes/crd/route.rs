//! `PodgateRoute` to one podgate app.
//!
//! One route becomes one app, `route_<namespace>.<name>` (the `_` cannot occur in the ids
//! Ingresses get, which are built from Kubernetes names), with one revision `k8s`: Kubernetes
//! rolls pods out through readiness, so podgate sees no revision states. The spec mirrors the
//! snapshot model, with three differences that keep addresses and secrets out of manifests:
//!
//! | Route | App |
//! |---|---|
//! | `services[]` of type `loadbalancer` with `serviceRef {name, port}` | `servers` from the ready addresses in the Service's EndpointSlices (see [`crate::kubernetes::endpoints`]) |
//! | `transports[]` with `clientCertSecret` | `client_cert` from the `kubernetes.io/tls` Secret of that name |
//! | a name in `default_chain` or a router's `chain` that is no inline middleware | a copy of the PodgateMiddleware of that name, in the app's `middlewares` |
//!
//! A router, service or transport that names an address (`servers`) or carries a key
//! (`client_cert`) rejects the whole route, and so does every reference that leaves the route's
//! namespace: the Service, the Secret and the middleware are all looked up in the namespace of
//! the PodgateRoute, and a `namespace/name` middleware reference is accepted only for that same
//! namespace. A route that quietly differs from what the manifest says is worse than a missing
//! one.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use podgate_model::{App, Declared, Router, TlsPolicy};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::middleware::Middlewares;
use super::{GROUP, VERSION};
use crate::kubernetes::client::{ObjectMeta, Resource};
use crate::kubernetes::endpoints::PortRef;
use crate::kubernetes::ingress::{Cluster, Mapped, REVISION, unix_seconds};
use crate::source::{Origin, SourceApp};

/// A `podgate.io/v1alpha1` PodgateRoute.
///
/// The spec stays raw JSON until it is translated, so an object that cannot be read is refused
/// with a reason and never breaks the watch of the others (a decode error would).
#[derive(Debug, Deserialize)]
pub struct PodgateRoute {
    /// Name, namespace, creation time.
    pub metadata: ObjectMeta,
    /// The [`Spec`].
    #[serde(default)]
    pub spec: Value,
}

impl Resource for PodgateRoute {
    const GROUP: &'static str = GROUP;
    const VERSION: &'static str = VERSION;
    const PLURAL: &'static str = "podgateroutes";
    const KIND: &'static str = "PodgateRoute";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

/// What the manifest says. Every field is the snapshot model's, but for the three above.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    /// A tenant label claim (the namespace already maps to a tenant).
    #[serde(default)]
    pub tenant: Option<String>,
    /// How the app gets certificates. Absent: `on_demand`, as for an Ingress.
    #[serde(default)]
    pub tls: Option<TlsPolicy>,
    /// Middlewares that run before every router's own chain.
    #[serde(default)]
    pub default_chain: Vec<Box<str>>,
    /// The routers.
    #[serde(default)]
    pub routers: Vec<Router>,
    /// The services, as objects with `serviceRef` in place of `servers`.
    #[serde(default)]
    pub services: Vec<Value>,
    /// The transports, as objects with `clientCertSecret` in place of `client_cert`.
    #[serde(default)]
    pub transports: Vec<Value>,
    /// The app's own middlewares.
    #[serde(default)]
    pub middlewares: Vec<Declared>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRef {
    name: String,
    port: Port,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Port {
    Number(u16),
    Name(String),
}

/// The object key a route has as a source object: distinct from every Ingress's `namespace/name`.
#[must_use]
pub fn object_key(meta: &ObjectMeta) -> String {
    format!("route/{}", meta.key())
}

/// Maps `route`.
///
/// # Errors
///
/// The reason the route is refused as a whole.
pub fn map(
    route: &PodgateRoute,
    cluster: &Cluster<'_>,
    shared: &Middlewares<'_>,
) -> Result<Mapped, String> {
    let meta = &route.metadata;
    let namespace = meta.namespace();
    let spec = Spec::deserialize(&route.spec).map_err(|err| format!("spec: {err}"))?;
    if spec.routers.is_empty() {
        return Err("spec.routers is empty, so there is nothing to route".to_owned());
    }
    for router in &spec.routers {
        if router.declared_by.is_some() {
            return Err(format!(
                "router {}: declared_by is the provider's to write, not the manifest's",
                router.name
            ));
        }
    }

    let mut chains = Chains {
        namespace,
        inline: spec.middlewares.iter().map(|m| m.name.clone()).collect(),
        shared,
        copied: BTreeMap::new(),
    };
    let default_chain = chains.names("default_chain", &spec.default_chain)?;
    let mut routers = spec.routers;
    for router in &mut routers {
        router.chain = chains.names(&format!("router {}: chain", router.name), &router.chain)?;
    }
    let mut middlewares = spec.middlewares;
    middlewares.extend(chains.copied.into_values());

    let services = spec
        .services
        .into_iter()
        .enumerate()
        .map(|(index, service)| {
            declare_service(service, namespace, cluster)
                .map_err(|why| format!("services[{index}]: {why}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let transports = spec
        .transports
        .into_iter()
        .enumerate()
        .map(|(index, transport)| {
            declare_transport(transport, namespace, cluster)
                .map_err(|why| format!("transports[{index}]: {why}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let claim = cluster.tenancy.claim(namespace, spec.tenant.as_deref());
    let vetted = cluster
        .tenancy
        .vet(&claim, &routers)
        .map_err(|problem| format!("{}: {}", problem.code, problem.message))?;
    let mut notes = Vec::new();
    let mut kept = Vec::new();
    for (router, refused) in routers.into_iter().zip(vetted.refused) {
        match refused {
            Some(problem) => notes.push(format!(
                "router {} left out: {}: {}",
                router.name, problem.code, problem.message
            )),
            None => kept.push(router),
        }
    }
    if kept.is_empty() {
        return Err(notes.join("; "));
    }

    let tls = match &spec.tls {
        Some(tls) => serde_json::to_value(tls).map_err(|err| err.to_string())?,
        None => json!({ "mode": "on_demand" }),
    };
    let app: App = serde_json::from_value(json!({
        // The core replaces `tenant` and `declared_by`; they only have to exist.
        "id": format!("route_{namespace}.{}", meta.name),
        "tenant": "default",
        "declared_by": format!("kubernetes/{}:podgateroute/{}", cluster.source, meta.key()),
        "tls": tls,
        "default_chain": default_chain,
        "routers": kept,
        "middlewares": middlewares,
        "services": services,
        "transports": transports,
        "revisions": [{ "id": REVISION, "state": "serving", "weight": 1 }],
    }))
    .map_err(|err| err.to_string())?;
    Ok(Mapped {
        app: SourceApp {
            origin: Origin {
                source: cluster.source.into(),
                object: object_key(meta).into(),
                first_seen: meta
                    .creation_timestamp
                    .as_deref()
                    .and_then(unix_seconds)
                    .unwrap_or(0),
            },
            tenant: claim,
            app,
        },
        certificates: Vec::new(),
        notes,
    })
}

/// Resolves the middleware names of chains, copying the shared ones the route uses.
struct Chains<'a> {
    namespace: &'a str,
    inline: BTreeSet<Box<str>>,
    shared: &'a Middlewares<'a>,
    copied: BTreeMap<Box<str>, Declared>,
}

impl Chains<'_> {
    /// The plain names for `references`: a name is an inline middleware, else a PodgateMiddleware
    /// of the route's namespace; `namespace/name` is that PodgateMiddleware only, and only when
    /// the namespace is the route's own.
    fn names(&mut self, at: &str, references: &[Box<str>]) -> Result<Vec<Box<str>>, String> {
        references
            .iter()
            .map(|reference| self.name(reference).map_err(|why| format!("{at}: {why}")))
            .collect()
    }

    fn name(&mut self, reference: &str) -> Result<Box<str>, String> {
        let (name, qualified) = match reference.split_once('/') {
            Some((namespace, name)) if namespace == self.namespace => (name, true),
            Some((namespace, _)) => {
                return Err(format!(
                    "middleware {reference:?} is in the namespace {namespace:?}; a route uses only the middlewares of its own namespace ({:?})",
                    self.namespace
                ));
            }
            None => (reference, false),
        };
        if !qualified && self.inline.contains(name) {
            return Ok(name.into());
        }
        if self.inline.contains(name) {
            return Err(format!(
                "middleware {reference:?} would be copied under the name {name:?}, which spec.middlewares already uses"
            ));
        }
        if !self.copied.contains_key(name) {
            let declared = match self.shared.get(self.namespace, name) {
                None => {
                    return Err(format!(
                        "middleware {name:?} is not in spec.middlewares and there is no PodgateMiddleware {}/{name}",
                        self.namespace
                    ));
                }
                Some(Err(why)) => {
                    return Err(format!(
                        "PodgateMiddleware {}/{name} cannot be used: {why}",
                        self.namespace
                    ));
                }
                Some(Ok(declared)) => declared.clone(),
            };
            self.copied.insert(name.into(), declared);
        }
        Ok(name.into())
    }
}

fn object_of(value: Value, what: &str) -> Result<Map<String, Value>, String> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(format!("a {what} must be an object")),
    }
}

fn label(object: &Map<String, Value>) -> String {
    object
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("(unnamed)")
        .to_owned()
}

/// A service with its `serviceRef` resolved to servers.
fn declare_service(
    service: Value,
    namespace: &str,
    cluster: &Cluster<'_>,
) -> Result<Declared, String> {
    let mut object = object_of(service, "service")?;
    let name = label(&object);
    if object.contains_key("servers") {
        return Err(format!(
            "service {name}: `servers` are addresses and a manifest does not carry any; name the Service with serviceRef"
        ));
    }
    let is_loadbalancer = object
        .get("type")
        .is_some_and(|kind| kind == "loadbalancer");
    match (object.remove("serviceRef"), is_loadbalancer) {
        (Some(reference), true) => {
            let servers = resolve(reference, namespace, cluster)
                .map_err(|why| format!("service {name}: serviceRef: {why}"))?;
            object.insert(
                "servers".to_owned(),
                Value::Array(servers.iter().map(|url| json!({ "url": &**url })).collect()),
            );
        }
        (Some(_), false) => {
            return Err(format!(
                "service {name}: serviceRef belongs to a loadbalancer"
            ));
        }
        (None, true) => {
            return Err(format!("service {name}: a loadbalancer needs a serviceRef"));
        }
        (None, false) => {}
    }
    serde_json::from_value(Value::Object(object))
        .map_err(|err| format!("service {name} is not a service: {err}"))
}

fn resolve(
    reference: Value,
    namespace: &str,
    cluster: &Cluster<'_>,
) -> Result<Vec<Box<str>>, String> {
    let ServiceRef { name, port } =
        ServiceRef::deserialize(reference).map_err(|err| err.to_string())?;
    if name.is_empty() || name.contains(['/', '.']) {
        return Err(format!(
            "{name:?}: a Service is named plainly and lives in the namespace of the route, never another namespace or a host"
        ));
    }
    let port = match port {
        Port::Number(number) => PortRef::Number(number),
        Port::Name(port) if !port.is_empty() => PortRef::Name(port.into()),
        Port::Name(_) => return Err("the port is empty".to_owned()),
    };
    cluster.services.servers(namespace, &name, &port)
}

/// A transport with its `clientCertSecret` resolved to a client certificate.
fn declare_transport(
    transport: Value,
    namespace: &str,
    cluster: &Cluster<'_>,
) -> Result<Declared, String> {
    let mut object = object_of(transport, "transport")?;
    let name = label(&object);
    if object.contains_key("client_cert") {
        return Err(format!(
            "transport {name}: `client_cert` would put a private key in the manifest; name a kubernetes.io/tls Secret with clientCertSecret"
        ));
    }
    if let Some(secret) = object.remove("clientCertSecret") {
        let Value::String(secret) = secret else {
            return Err(format!(
                "transport {name}: clientCertSecret must be a string"
            ));
        };
        if secret.is_empty() || secret.contains('/') {
            return Err(format!(
                "transport {name}: clientCertSecret {secret:?} must be the plain name of a Secret of the route's namespace"
            ));
        }
        let found = (cluster.secret)(namespace, &secret).ok_or_else(|| {
            format!(
                "transport {name}: no Secret {namespace}/{secret} of type kubernetes.io/tls (it is missing, or has another type)"
            )
        })?;
        let pem = |key: &str| -> Result<String, String> {
            let value = found.data.get(key).ok_or_else(|| {
                format!("transport {name}: Secret {namespace}/{secret} has no {key}")
            })?;
            let bytes = STANDARD.decode(value.trim()).map_err(|_| {
                format!(
                    "transport {name}: {key} of Secret {namespace}/{secret} is not valid base64"
                )
            })?;
            String::from_utf8(bytes).map_err(|_| {
                format!("transport {name}: {key} of Secret {namespace}/{secret} is not PEM text")
            })
        };
        object.insert(
            "client_cert".to_owned(),
            json!({ "cert_pem": pem("tls.crt")?, "key_pem": pem("tls.key")? }),
        );
    }
    serde_json::from_value(Value::Object(object))
        .map_err(|err| format!("transport {name} is not a transport: {err}"))
}
