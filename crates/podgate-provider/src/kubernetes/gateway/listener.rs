//! Gateways and listeners: which routes may attach where, and the certificates of `HTTPS`
//! listeners.
//!
//! A Gateway of the configured class produces nothing by itself. Its listeners bound what routes
//! can do: a route attaches to a listener when
//!
//! - its `parentRefs` name the Gateway (and the listener, by `sectionName` or `port`);
//! - the listener's protocol is `HTTP` or `HTTPS` and its port has an entry point
//!   (`listener_entry_points`);
//! - `allowedRoutes` lets the route's kind and namespace in (`Same`, `All`, or a label
//!   `Selector`);
//! - the route's host names intersect the listener's `hostname` (a route with none inherits it);
//! - the tenant of the route may use the entry point (the operator's `exclusive_entry_points`).
//!
//! A route that is accepted by no listener is rejected, with the reason of each parent.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;

use super::backend::{Grants, cross_namespace};
use super::types::{GROUP, Gateway, Listener, ParentRef, SelectorRequirement};
use super::{Kind, Rejection, reject};
use crate::kubernetes::client::ObjectMeta;
use crate::kubernetes::endpoints::Secret;
use crate::kubernetes::tenancy::Tenancy;
use crate::source::{Origin, SourceCertificate, TenantClaim};
use crate::trust::HostPattern;

/// One accepted attachment of a route to a listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// `namespace/name` of the Gateway.
    pub gateway: String,
    /// The listener's name.
    pub listener: Box<str>,
    /// The entry point of the listener's port.
    pub entry_point: Box<str>,
    /// The host names the route serves on this listener; `None` is every host.
    pub hosts: Option<Vec<HostPattern>>,
}

/// What became of one `parentRefs` entry; `0074` writes it into the route's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentReport {
    /// `namespace/name` of the Gateway named.
    pub gateway: String,
    /// The `sectionName`, when the entry names one.
    pub section: Option<String>,
    /// Whether the route attached to at least one listener of it.
    pub accepted: bool,
    /// The Gateway API reason: `Accepted`, `NotAllowedByListeners`, `NoMatchingListenerHostname`
    /// or `NoMatchingParent`.
    pub reason: &'static str,
    /// What is wrong, when something is.
    pub message: String,
}

/// The result of attaching one route.
#[derive(Debug, Default)]
pub struct Attached {
    /// Whether any parent reference names a Gateway of this source's class.
    pub ours: bool,
    /// The listeners it attached to.
    pub attachments: Vec<Attachment>,
    /// One report per parent reference that names one of our Gateways.
    pub parents: Vec<ParentReport>,
}

/// What attaching needs to know about the route.
pub struct RouteInfo<'a> {
    /// `HTTPRoute` or `GRPCRoute`.
    pub kind: Kind,
    /// The route's namespace.
    pub namespace: &'a str,
    /// Its `parentRefs`.
    pub parent_refs: &'a [ParentRef],
    /// Its host names, already read.
    pub hostnames: &'a [HostPattern],
    /// The tenant of its namespace.
    pub claim: &'a TenantClaim,
}

/// The Gateways of our class and the rules for attaching to them.
pub struct Gateways<'a> {
    gateways: BTreeMap<(&'a str, &'a str), &'a Gateway>,
    labels: BTreeMap<&'a str, &'a BTreeMap<String, String>>,
    /// Listener port to entry point.
    entry_points: &'a BTreeMap<u16, Box<str>>,
    tenancy: &'a Tenancy,
}

impl<'a> Gateways<'a> {
    /// The Gateways `gateways` (already filtered to our class), the labels of namespaces and
    /// the port to entry point map.
    #[must_use]
    pub fn new(
        gateways: impl Iterator<Item = &'a Gateway>,
        labels: BTreeMap<&'a str, &'a BTreeMap<String, String>>,
        entry_points: &'a BTreeMap<u16, Box<str>>,
        tenancy: &'a Tenancy,
    ) -> Self {
        Self {
            gateways: gateways
                .map(|gateway| {
                    (
                        (gateway.metadata.namespace(), gateway.metadata.name.as_str()),
                        gateway,
                    )
                })
                .collect(),
            labels,
            entry_points,
            tenancy,
        }
    }

    /// Every Gateway, in order.
    pub fn all(&self) -> impl Iterator<Item = &'a Gateway> + '_ {
        self.gateways.values().copied()
    }

    /// Attaches `route` to the listeners its `parentRefs` name.
    #[must_use]
    pub fn attach(&self, route: &RouteInfo<'_>) -> Attached {
        let mut attached = Attached::default();
        for parent in route.parent_refs {
            let group = parent.group.as_deref().unwrap_or(GROUP);
            let kind = parent.kind.as_deref().unwrap_or("Gateway");
            if group != GROUP || kind != "Gateway" {
                continue;
            }
            let namespace = parent.namespace.as_deref().unwrap_or(route.namespace);
            let Some(gateway) = self.gateways.get(&(namespace, parent.name.as_str())) else {
                continue;
            };
            attached.ours = true;
            let key = gateway.metadata.key();
            let mut report = ParentReport {
                gateway: key.clone(),
                section: parent.section_name.clone(),
                accepted: false,
                reason: "NoMatchingParent",
                message: format!(
                    "Gateway {key} has no listener{}",
                    parent
                        .section_name
                        .as_deref()
                        .map(|name| format!(" called {name}"))
                        .unwrap_or_default()
                ),
            };
            let mut first_refusal: Option<(&'static str, String)> = None;
            for listener in &gateway.spec.listeners {
                if parent
                    .section_name
                    .as_deref()
                    .is_some_and(|name| name != listener.name)
                    || parent.port.is_some_and(|port| port != listener.port)
                {
                    continue;
                }
                match self.listener(gateway, listener, route) {
                    Ok(attachment) => {
                        report.accepted = true;
                        report.reason = "Accepted";
                        report.message.clear();
                        if !attached.attachments.contains(&attachment) {
                            attached.attachments.push(attachment);
                        }
                    }
                    Err(refusal) => {
                        first_refusal.get_or_insert((refusal.reason, refusal.message));
                    }
                }
            }
            if !report.accepted
                && let Some((reason, message)) = first_refusal
            {
                report.reason = reason;
                report.message = message;
            }
            attached.parents.push(report);
        }
        attached
    }

    fn listener(
        &self,
        gateway: &Gateway,
        listener: &Listener,
        route: &RouteInfo<'_>,
    ) -> Result<Attachment, Rejection> {
        let key = gateway.metadata.key();
        let name = &listener.name;
        let entry_point = self.usable(listener).map_err(|why| {
            reject(
                "NotAllowedByListeners",
                format!("listener {name} of Gateway {key}: {why}"),
            )
        })?;
        self.allowed(gateway, listener, route).map_err(|why| {
            reject(
                "NotAllowedByListeners",
                format!("listener {name} of Gateway {key} does not allow this route: {why}"),
            )
        })?;
        let hosts = intersect(listener.hostname.as_deref(), route.hostnames).map_err(|why| {
            reject(
                "NoMatchingListenerHostname",
                format!("listener {name} of Gateway {key}: {why}"),
            )
        })?;
        self.tenancy
            .check_entry_points(route.claim, std::slice::from_ref(&entry_point))
            .map_err(|problem| {
                reject(
                    "NotAllowedByListeners",
                    format!(
                        "listener {name} of Gateway {key}: {}: {}",
                        problem.code, problem.message
                    ),
                )
            })?;
        Ok(Attachment {
            gateway: key,
            listener: name.as_str().into(),
            entry_point,
            hosts,
        })
    }

    /// The entry point of a listener that can carry HTTP routes.
    fn usable(&self, listener: &Listener) -> Result<Box<str>, String> {
        match listener.protocol.as_str() {
            "HTTP" => {}
            "HTTPS" => {
                if listener
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.mode.as_deref())
                    .is_some_and(|mode| mode != "Terminate")
                {
                    return Err("an HTTPS listener must terminate TLS".to_owned());
                }
            }
            other => {
                return Err(format!(
                    "the protocol {other:?} carries no HTTP route (only HTTP and HTTPS do)"
                ));
            }
        }
        self.entry_points
            .get(&listener.port)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "port {} has no entry point; add it to listener_entry_points",
                    listener.port
                )
            })
    }

    fn allowed(
        &self,
        gateway: &Gateway,
        listener: &Listener,
        route: &RouteInfo<'_>,
    ) -> Result<(), String> {
        let allowed = listener.allowed_routes.as_ref();
        let kinds = allowed.map_or(&[][..], |allowed| allowed.kinds.as_slice());
        if !kinds.is_empty()
            && !kinds.iter().any(|kind| {
                kind.group.as_deref().unwrap_or(GROUP) == GROUP && kind.kind == route.kind.name()
            })
        {
            return Err(format!(
                "allowedRoutes.kinds does not list {}",
                route.kind.name()
            ));
        }
        let namespaces = allowed.and_then(|allowed| allowed.namespaces.as_ref());
        match namespaces
            .and_then(|namespaces| namespaces.from.as_deref())
            .unwrap_or("Same")
        {
            "Same" => {
                if route.namespace != gateway.metadata.namespace() {
                    return Err(format!(
                        "allowedRoutes.namespaces.from is Same and the route is in namespace {}",
                        route.namespace
                    ));
                }
            }
            "All" => {}
            "Selector" => {
                let selector = namespaces
                    .and_then(|namespaces| namespaces.selector.as_ref())
                    .ok_or("allowedRoutes.namespaces.from is Selector without a selector")?;
                let labels = self
                    .labels
                    .get(route.namespace)
                    .copied()
                    .ok_or_else(|| format!("namespace {} is not known", route.namespace))?;
                let matches = selector
                    .match_labels
                    .iter()
                    .all(|(key, value)| labels.get(key) == Some(value))
                    && selector
                        .match_expressions
                        .iter()
                        .all(|requirement| requirement_holds(requirement, labels));
                if !matches {
                    return Err(format!(
                        "the labels of namespace {} do not match allowedRoutes.namespaces.selector",
                        route.namespace
                    ));
                }
            }
            other => {
                return Err(format!(
                    "allowedRoutes.namespaces.from {other:?} is not Same, All or Selector"
                ));
            }
        }
        Ok(())
    }
}

fn requirement_holds(requirement: &SelectorRequirement, labels: &BTreeMap<String, String>) -> bool {
    let value = labels.get(&requirement.key);
    match requirement.operator.as_str() {
        "In" => value.is_some_and(|value| requirement.values.contains(value)),
        "NotIn" => value.is_none_or(|value| !requirement.values.contains(value)),
        "Exists" => value.is_some(),
        "DoesNotExist" => value.is_none(),
        _ => false,
    }
}

/// The host names a route serves on a listener of host name `listener`.
///
/// `Ok(None)`: every host (neither names one). A route with no names inherits the listener's;
/// otherwise each route name is intersected with the listener's, the more specific of the two
/// winning, and the names that do not intersect are dropped.
fn intersect(
    listener: Option<&str>,
    route: &[HostPattern],
) -> Result<Option<Vec<HostPattern>>, String> {
    let listener = match listener.filter(|host| !host.is_empty()) {
        Some(host) => Some(
            HostPattern::parse(host).map_err(|_| format!("the hostname {host:?} is not valid"))?,
        ),
        None => None,
    };
    let Some(listener) = listener else {
        return Ok((!route.is_empty()).then(|| route.to_vec()));
    };
    if route.is_empty() {
        return Ok(Some(vec![listener]));
    }
    let mut hosts: Vec<HostPattern> = Vec::new();
    for host in route {
        if let Some(common) = narrower(&listener, host)
            && !hosts.contains(&common)
        {
            hosts.push(common);
        }
    }
    if hosts.is_empty() {
        return Err(format!(
            "none of the route's host names intersects the hostname {listener}"
        ));
    }
    Ok(Some(hosts))
}

/// Whether `name` is `base` or lies under it at any depth (the Gateway API's wildcard).
fn under(name: &str, base: &str) -> bool {
    name.strip_suffix(base)
        .is_some_and(|head| head.ends_with('.') && head.len() > 1)
}

/// The more specific of two host patterns when one covers the other.
fn narrower(a: &HostPattern, b: &HostPattern) -> Option<HostPattern> {
    use HostPattern::{Exact, Wildcard};
    match (a, b) {
        (Exact(x), Exact(y)) => (x == y).then(|| a.clone()),
        (Exact(name), Wildcard(base)) => under(name, base).then(|| a.clone()),
        (Wildcard(base), Exact(name)) => under(name, base).then(|| b.clone()),
        (Wildcard(x), Wildcard(y)) => {
            if x == y || under(x, y) {
                Some(a.clone())
            } else {
                under(y, x).then(|| b.clone())
            }
        }
    }
}

/// The PEM text of one key of a TLS Secret.
fn pem(secret: &Secret, key: &str) -> Result<String, String> {
    let value = secret
        .data
        .get(key)
        .ok_or_else(|| format!("it has no {key}"))?;
    let bytes = STANDARD
        .decode(value.trim())
        .map_err(|_| format!("{key} is not valid base64"))?;
    String::from_utf8(bytes).map_err(|_| format!("{key} is not PEM text"))
}

/// What reading the certificates of a Gateway needs.
pub struct Certs<'a, 's> {
    /// The tenant rules.
    pub tenancy: &'a Tenancy,
    /// The `ReferenceGrant`s.
    pub grants: &'a Grants<'a>,
    /// Looks a `kubernetes.io/tls` Secret up by namespace and name.
    pub secret: &'a dyn Fn(&str, &str) -> Option<&'s Secret>,
    /// The name of the source.
    pub source: &'a str,
}

/// The certificates of the `HTTPS` listeners of `gateway`.
///
/// `served` gives, for a listener name, the host names the accepted routes of the Gateway's own
/// tenant use on it: a listener without `hostname` holds a certificate for those names. A Secret
/// in another namespace needs a `ReferenceGrant` from this Gateway, and must lie in the same
/// tenant. A problem with one certificate is a note; the Gateway and its routes are unaffected.
pub fn certificates(
    gateway: &Gateway,
    served: &dyn Fn(&str) -> Vec<HostPattern>,
    certs: &Certs<'_, '_>,
    notes: &mut Vec<String>,
) -> Vec<SourceCertificate> {
    let meta: &ObjectMeta = &gateway.metadata;
    let claim = certs.tenancy.claim(meta.namespace(), None);
    let first_seen = meta
        .creation_timestamp
        .as_deref()
        .and_then(crate::kubernetes::ingress::unix_seconds)
        .unwrap_or(0);
    let mut out = Vec::new();
    for listener in &gateway.spec.listeners {
        let Some(tls) = listener
            .tls
            .as_ref()
            .filter(|tls| listener.protocol == "HTTPS" && !tls.certificate_refs.is_empty())
        else {
            continue;
        };
        let hosts: Vec<HostPattern> = match listener.hostname.as_deref().filter(|h| !h.is_empty()) {
            Some(host) => match HostPattern::parse(host) {
                Ok(host) => vec![host],
                Err(_) => {
                    notes.push(format!(
                        "Gateway {} listener {}: the hostname {host:?} is not valid",
                        meta.key(),
                        listener.name
                    ));
                    continue;
                }
            },
            None => served(&listener.name),
        };
        if hosts.is_empty() {
            continue;
        }
        for (index, reference) in tls.certificate_refs.iter().enumerate() {
            let place = format!(
                "Gateway {} listener {} certificateRefs[{index}]",
                meta.key(),
                listener.name
            );
            let result: Result<SourceCertificate, String> = (|| {
                let group = reference.group.as_deref().unwrap_or("");
                let kind = reference.kind.as_deref().unwrap_or("Secret");
                if !group.is_empty() || kind != "Secret" {
                    return Err(format!("{kind} (group {group:?}) is not a Secret"));
                }
                let namespace = reference.namespace.as_deref().unwrap_or(meta.namespace());
                cross_namespace(
                    certs.tenancy,
                    certs.grants,
                    "Gateway",
                    meta.namespace(),
                    namespace,
                    "",
                    "Secret",
                    &reference.name,
                )?;
                let secret = (certs.secret)(namespace, &reference.name).ok_or_else(|| {
                    format!(
                        "no Secret {namespace}/{} of type kubernetes.io/tls (it is missing, or has another type)",
                        reference.name
                    )
                })?;
                certs
                    .tenancy
                    .check_hosts(&claim, &hosts)
                    .map_err(|problem| format!("{}: {}", problem.code, problem.message))?;
                let certificate = serde_json::from_value(json!({
                    "hosts": hosts.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "cert_pem": pem(secret, "tls.crt").map_err(|why| format!("Secret {namespace}/{}: {why}", reference.name))?,
                    "key_pem": pem(secret, "tls.key").map_err(|why| format!("Secret {namespace}/{}: {why}", reference.name))?,
                }))
                .map_err(|err: serde_json::Error| err.to_string())?;
                Ok(SourceCertificate {
                    origin: Origin {
                        source: certs.source.into(),
                        object: format!("Gateway/{}#{}-{index}", meta.key(), listener.name).into(),
                        first_seen,
                    },
                    tenant: claim.clone(),
                    certificate,
                })
            })();
            match result {
                Ok(certificate) => out.push(certificate),
                Err(why) => notes.push(format!("{place}: {why}")),
            }
        }
    }
    out
}
