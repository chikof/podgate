//! From the instances Consul lists to the apps the source declares.
//!
//! Which instances count, which address is their server, which tenant they belong to: the
//! decisions that are Consul's. The tags themselves are read by [`crate::docker::labels`].

use std::net::{IpAddr, SocketAddr};

use crate::docker::labels::{self, Labels, Member};
use crate::source::{Origin, SourceApp, TenantClaim};

use super::model::Instance;
use super::tags;
use super::{Scope, Settings, TenantSource};

/// The longest app id and tenant name, as in the label parser.
const MAX_NAME: usize = 63;

/// The service kind of a Connect sidecar proxy.
const CONNECT_PROXY: &str = "connect-proxy";

/// The instances of one service in one scope.
#[derive(Debug)]
pub(super) struct Service<'a> {
    pub(super) scope: &'a Scope,
    pub(super) name: &'a str,
    pub(super) instances: &'a [Instance],
}

/// The apps of one pass over the catalog, and what was left out and why.
#[derive(Debug, Default)]
pub(super) struct Built {
    pub(super) apps: Vec<SourceApp>,
    /// One line per instance (or service) that is not used although it asked to be.
    pub(super) reports: Vec<Box<str>>,
}

struct Candidate<'a> {
    instance: &'a Instance,
    labels: Labels,
    server: SocketAddr,
    claim: TenantClaim,
    name: String,
}

/// Builds the apps of `services`.
///
/// Consul has no creation time (`CreateIndex` is a raft index, not a time), so every app has
/// `first_seen` `0`. A host conflict between two Consul apps then falls back to source and
/// object name, which do not change when the provider restarts.
pub(super) fn build(source: &str, settings: &Settings, services: &[Service<'_>]) -> Built {
    let mut built = Built::default();
    for service in services {
        let wanted: Vec<&Instance> = service
            .instances
            .iter()
            .filter(|instance| {
                (instance.kind.is_empty() || settings.connect && &*instance.kind == CONNECT_PROXY)
                    && tags::exposed(&instance.tags, settings.exposed_by_default)
            })
            .collect();
        if wanted.is_empty() {
            continue;
        }
        let app = match local_id(service.scope, service.name) {
            Ok(app) => app,
            Err(why) => {
                built
                    .reports
                    .push(format!("service {}: {why}", service.name).into());
                continue;
            }
        };
        let mut candidates = Vec::new();
        for instance in wanted {
            match candidate(settings, service, instance) {
                Ok(candidate) => candidates.push(candidate),
                Err(why) => built.reports.push(report(service.name, instance, &why)),
            }
        }
        if candidates.is_empty() {
            continue;
        }
        let members: Vec<Member<'_>> = candidates
            .iter()
            .map(|candidate| Member {
                name: &candidate.name,
                labels: &candidate.labels,
                server: candidate.server,
                claim: &candidate.claim,
                created: candidate.instance.create_index,
            })
            .collect();
        let assembled = match labels::assemble(&app, &members) {
            Ok(assembled) => assembled,
            Err(why) => {
                for candidate in &candidates {
                    built
                        .reports
                        .push(report(service.name, candidate.instance, &why.to_string()));
                }
                continue;
            }
        };
        for (index, why) in &assembled.rejected {
            built.reports.push(report(
                service.name,
                candidates[*index].instance,
                &why.to_string(),
            ));
        }
        built.apps.push(SourceApp {
            origin: Origin {
                source: source.into(),
                object: app,
                first_seen: 0,
            },
            tenant: assembled.claim,
            app: assembled.app,
        });
    }
    built
}

fn report(service: &str, instance: &Instance, why: &str) -> Box<str> {
    format!(
        "service {service} instance {} on node {}: {why}",
        instance.id, instance.node
    )
    .into()
}

/// The app id of a service: its name, led by its partition and namespace when the source
/// watches those, so two namespaces cannot make one app.
fn local_id(scope: &Scope, name: &str) -> Result<Box<str>, String> {
    let id: Vec<&str> = [scope.partition.as_deref(), scope.namespace.as_deref()]
        .into_iter()
        .flatten()
        .chain([name])
        .collect();
    let id = id.join(".");
    if valid_name(&id) {
        Ok(id.into())
    } else {
        Err(format!(
            "{id:?} cannot be an app id: it must be 1 to {MAX_NAME} letters, digits, `-`, `_` or `.`"
        ))
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The labels, address and tenant claim of one instance, or why it is not used.
fn candidate<'a>(
    settings: &Settings,
    service: &Service<'_>,
    instance: &'a Instance,
) -> Result<Candidate<'a>, String> {
    let pairs = tags::pairs(&instance.tags).map_err(|why| why.to_string())?;
    let labels = labels::parse(pairs.iter().copied()).map_err(|why| why.to_string())?;
    if let Some(app) = labels.app.as_deref().filter(|app| *app != service.name) {
        return Err(format!(
            "podgate.app: {app:?} is not the service's name; the app of a Consul service is its name, {:?}",
            service.name
        ));
    }
    if labels.port.is_some() {
        return Err(
            "podgate.port: not used with Consul; the port of a server is the one the service registered"
                .to_owned(),
        );
    }
    if instance.port == 0 {
        return Err(
            "the service registered no port; a server is the registered address and port"
                .to_owned(),
        );
    }
    let address: IpAddr = instance.address.parse().map_err(|_| {
        format!(
            "address {:?} is not an IP address; a server is the registered IP address and port",
            instance.address
        )
    })?;
    let claim = match &settings.tenants {
        TenantSource::Fixed(tenant) => TenantClaim::mapped(tenant),
        TenantSource::Meta { tenant, key } => {
            let claim = tenant
                .as_deref()
                .map_or_else(TenantClaim::none, TenantClaim::mapped);
            match instance.meta.get(&**key) {
                Some(named) => {
                    let named = named.trim();
                    if !valid_name(named) {
                        return Err(format!(
                            "meta {key}: {named:?} must be 1 to {MAX_NAME} letters, digits, `-`, `_` or `.`"
                        ));
                    }
                    claim.with_label(named)
                }
                None => claim,
            }
        }
        TenantSource::Namespace(mapping) => service
            .scope
            .namespace
            .as_deref()
            .and_then(|namespace| mapping.get(namespace))
            .map(|tenant| TenantClaim::mapped(tenant))
            .ok_or_else(|| "its namespace has no tenant".to_owned())?,
    };
    Ok(Candidate {
        instance,
        labels,
        server: SocketAddr::new(address, instance.port),
        claim,
        name: format!("{}/{}", instance.node, instance.id),
    })
}
