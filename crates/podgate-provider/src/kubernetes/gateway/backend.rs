//! Backends: `backendRefs` to Services and their pod addresses, `ReferenceGrant`s, and the one
//! rule that holds with or without a grant: a route never refers to another tenant's objects.

use super::types::{BackendRef, GROUP, ReferenceGrant};
use super::{Kind, Rejection, reject};
use crate::kubernetes::endpoints::{PortRef, ServiceIndex, Wire};
use crate::kubernetes::tenancy::Tenancy;

/// The `ReferenceGrant`s of the cluster, by the namespace they sit in (the target's).
pub struct Grants<'a> {
    grants: Vec<&'a ReferenceGrant>,
}

impl<'a> Grants<'a> {
    /// The grants the source holds.
    #[must_use]
    pub fn new(grants: impl Iterator<Item = &'a ReferenceGrant>) -> Self {
        Self {
            grants: grants.collect(),
        }
    }

    /// Whether a grant in `to_namespace` lets a `from_kind` of the Gateway API in
    /// `from_namespace` refer to the object `to_name` of `to_kind` (of the group `to_group`,
    /// empty for the core group).
    #[must_use]
    pub fn allows(
        &self,
        from_kind: &str,
        from_namespace: &str,
        to_namespace: &str,
        to_group: &str,
        to_kind: &str,
        to_name: &str,
    ) -> bool {
        self.grants
            .iter()
            .filter(|grant| grant.metadata.namespace() == to_namespace)
            .any(|grant| {
                grant.spec.from.iter().any(|from| {
                    from.group == GROUP
                        && from.kind == from_kind
                        && from.namespace == from_namespace
                }) && grant.spec.to.iter().any(|to| {
                    to.group == to_group
                        && to.kind == to_kind
                        && to.name.as_deref().is_none_or(|name| name == to_name)
                })
            })
    }
}

/// What a reference across namespaces needs: the same tenant on both sides, and a grant.
///
/// # Errors
///
/// The reason, with the Gateway API's `RefNotPermitted`.
#[allow(
    clippy::too_many_arguments,
    reason = "one call site names the referrer and the target field by field, as a grant does"
)]
pub fn cross_namespace(
    tenancy: &Tenancy,
    grants: &Grants<'_>,
    from_kind: &str,
    from_namespace: &str,
    to_namespace: &str,
    to_group: &str,
    to_kind: &str,
    to_name: &str,
) -> Result<(), String> {
    if from_namespace == to_namespace {
        return Ok(());
    }
    if !tenancy.same_tenant(from_namespace, to_namespace) {
        return Err(format!(
            "{to_kind} {to_namespace}/{to_name} belongs to another tenant than namespace {from_namespace}; a reference never crosses tenants, with a ReferenceGrant or without"
        ));
    }
    if grants.allows(
        from_kind,
        from_namespace,
        to_namespace,
        to_group,
        to_kind,
        to_name,
    ) {
        return Ok(());
    }
    Err(format!(
        "{to_kind} {to_namespace}/{to_name} is in another namespace than the {from_kind} in {from_namespace}, and no ReferenceGrant in {to_namespace} allows it"
    ))
}

/// What the translation reads to resolve a backend.
pub struct Backends<'a> {
    /// The tenant rules.
    pub tenancy: &'a Tenancy,
    /// Services and EndpointSlices.
    pub index: &'a ServiceIndex<'a>,
    /// The `ReferenceGrant`s.
    pub grants: &'a Grants<'a>,
}

/// A backend that resolved to a Service port and its servers.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The name of its `loadbalancer` service.
    pub key: Box<str>,
    /// Its servers, as `scheme://address:port`.
    pub servers: Vec<Box<str>>,
    /// Its weight, `1` when the reference gave none.
    pub weight: u32,
}

impl Backends<'_> {
    /// Resolves `backend` of a route of `kind` in `namespace`. `grpc` makes plain `http://`
    /// servers `h2c://`: gRPC needs HTTP/2, and a Service port without `appProtocol` is one.
    ///
    /// # Errors
    ///
    /// A [`Rejection`] for a kind that is not a Service, a missing port, a backend filter, a
    /// reference that is not permitted, and a Service or port the cluster does not have.
    pub fn resolve(
        &self,
        kind: Kind,
        namespace: &str,
        backend: &BackendRef,
        grpc: bool,
    ) -> Result<Resolved, Rejection> {
        self.resolve_with(kind, namespace, backend, Wire::Http, grpc)
    }

    /// [`Self::resolve`] for the backend of a `TCPRoute`, `TLSRoute` or `UDPRoute`: the servers
    /// are plain `address:port` entries of a Service port of `wire`'s protocol.
    ///
    /// # Errors
    ///
    /// As [`Self::resolve`].
    pub fn resolve_stream(
        &self,
        kind: Kind,
        namespace: &str,
        backend: &BackendRef,
        wire: Wire,
    ) -> Result<Resolved, Rejection> {
        self.resolve_with(kind, namespace, backend, wire, false)
    }

    fn resolve_with(
        &self,
        kind: Kind,
        namespace: &str,
        backend: &BackendRef,
        wire: Wire,
        grpc: bool,
    ) -> Result<Resolved, Rejection> {
        let group = backend.group.as_deref().unwrap_or("");
        let target = backend.kind.as_deref().unwrap_or("Service");
        if !group.is_empty() || target != "Service" {
            return Err(reject(
                "InvalidKind",
                format!(
                    "backend {} of kind {target} (group {group:?}) is not supported: only Services are",
                    backend.name
                ),
            ));
        }
        if backend.name.is_empty() || backend.name.contains('/') {
            return Err(reject(
                "UnsupportedValue",
                format!("backend name {:?} is not a Service name", backend.name),
            ));
        }
        let Some(port) = backend.port.filter(|port| *port != 0) else {
            return Err(reject(
                "UnsupportedValue",
                format!("backend {} names no port", backend.name),
            ));
        };
        if !backend.filters.is_empty() {
            return Err(reject(
                "UnsupportedValue",
                format!(
                    "backend {} has filters of its own, which podgate cannot apply to one backend of a rule; put them on the rule",
                    backend.name
                ),
            ));
        }
        let service_namespace = backend.namespace.as_deref().unwrap_or(namespace);
        cross_namespace(
            self.tenancy,
            self.grants,
            kind.name(),
            namespace,
            service_namespace,
            "",
            "Service",
            &backend.name,
        )
        .map_err(|why| reject("RefNotPermitted", why))?;
        let mut servers = self
            .index
            .addresses(
                service_namespace,
                &backend.name,
                &PortRef::Number(port),
                wire,
            )
            .map_err(|why| reject("BackendNotFound", why))?;
        if grpc {
            for server in &mut servers {
                if let Some(rest) = server.strip_prefix("http://") {
                    *server = format!("h2c://{rest}").into();
                }
            }
        }
        Ok(Resolved {
            key: format!("{service_namespace}.{}.{port}", backend.name).into(),
            servers,
            weight: backend.weight.unwrap_or(1),
        })
    }
}
