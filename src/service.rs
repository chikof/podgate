//! Services: where a routed request goes. A router names a service; the service picks a server.
//!
//! A service is a [`podgate_model::Declared`] object of one `type`. `loadbalancer` and `static`
//! are built (a `static` service has no server: it answers from an operator-declared directory);
//! `weighted`, `mirroring` and `failover` are planned and refused with `service_not_built`; any
//! other type is `invalid_service`. A router's service is looked up in the revision the request
//! picked, then in the app's own services. Each kind lives in its own file:
//!
//! | Type | File |
//! |---|---|
//! | `loadbalancer` | `loadbalancer.rs`, with its algorithms in `lb/` |
//! | `static` | `static_files.rs`, with its helpers in `static_files/` |
//! | `weighted` | `weighted.rs` |
//! | `mirroring` | `mirroring.rs` |
//! | `failover` | `failover.rs` |
//!
//! Shared by the load balancer's helpers: the runtime state that outlives a snapshot push
//! (`state.rs`, see [`state`]), upstream transports (`transport.rs`: the TLS settings of the
//! connection to a server), active health checks (`health.rs`, see [`health`]), passive outlier
//! ejection (`outlier.rs`, see [`outlier`]) and, empty until its spec lands, DNS
//! upstreams (`resolve.rs`). [`upstream_policy`] is built: the operator's rule for which
//! addresses a tenant's servers may have, checked by the compiler and before every connection.
//! Sticky cookies (`sticky.rs`) are built: the load balancer's `pick` consults them first.
//!
//! Adding a service type: a file here with `compile` and `pick`, one variant in [`Service`] and
//! one arm in each of its `match` statements, and its name removed from `UNBUILT`.

mod failover;
pub mod health;
pub mod lb;
mod loadbalancer;
mod mirroring;
pub mod outlier;
mod resolve;
pub mod state;
mod static_files;
pub mod sticky;
mod transport;
pub mod upstream_policy;
mod weighted;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::compile::Invalid;
use podgate_model::{Declared, SkewSecret};

pub use lb::PickCx;
pub use loadbalancer::{LoadBalancer, Server};
pub(crate) use state::Registry;
pub use state::{Lease, ServerState, ServiceState};
pub(crate) use static_files::serve as serve_static;
pub use static_files::{
    LoadError as StaticRootsError, NO_SERVER, Reads as StaticReads, Root as StaticRoot,
    StaticRoots, StaticSite, TenantRoots,
};
pub use sticky::Sticky;
pub use transport::{Named as NamedTransport, Summary as TransportSummary, Transport, Upstream};

/// Service types that are planned and not built yet.
const UNBUILT: [&str; 3] = ["weighted", "mirroring", "failover"];

/// A compiled service.
#[derive(Debug)]
pub enum Service {
    /// `loadbalancer`: a set of servers and an algorithm.
    LoadBalancer(LoadBalancer),
    /// `static`: files from an operator-declared directory. Has no server.
    Static(Arc<StaticSite>),
}

/// A service and the name it was declared under.
#[derive(Debug)]
pub struct Named {
    /// The declared name, unique among services of its scope (the app or one revision).
    pub name: Box<str>,
    /// The compiled service.
    pub service: Service,
}

impl Service {
    /// Compiles one declared service. `static_roots` are the roots the operator declared for the
    /// tenant that owns it.
    ///
    /// # Errors
    ///
    /// `service_not_built` for a planned type nobody has built, `invalid_service` for an unknown
    /// type or a configuration the type refuses, `dns_upstream_not_built` for a server named by
    /// host name, `unknown_static_root` for a `static` service naming a root the tenant lacks.
    pub fn compile(
        declared: &Declared,
        transports: &[NamedTransport],
        static_roots: Option<&TenantRoots>,
    ) -> Result<Self, Invalid> {
        match &*declared.kind {
            "loadbalancer" => LoadBalancer::compile(declared, transports).map(Self::LoadBalancer),
            "static" => {
                StaticSite::compile(declared, static_roots).map(|site| Self::Static(Arc::new(site)))
            }
            other if UNBUILT.contains(&other) => Err(Invalid::new(
                "service_not_built",
                format!("service type {other} is planned and not built yet"),
            )),
            other => Err(Invalid::new(
                "invalid_service",
                format!("unknown service type {other}"),
            )),
        }
    }

    /// The type name, as written in a snapshot.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LoadBalancer(_) => "loadbalancer",
            Self::Static(_) => "static",
        }
    }

    /// The name of the balancing algorithm, for a type that has one.
    #[must_use]
    pub fn algorithm(&self) -> Option<&'static str> {
        match self {
            Self::LoadBalancer(balancer) => Some(balancer.algorithm()),
        }
    }

    /// Whether the service probes its servers actively (`health_check`).
    #[must_use]
    pub fn has_health_check(&self) -> bool {
        match self {
            Self::LoadBalancer(balancer) => balancer.health_check().is_some(),
        }
    }

    /// Whether the service ejects servers that fail real requests (`passive`).
    #[must_use]
    pub fn has_outlier_detection(&self) -> bool {
        match self {
            Self::LoadBalancer(balancer) => balancer.passive().is_some(),
        }
    }

    /// The servers the service may send to, in declaration order.
    #[must_use]
    pub fn servers(&self) -> &[Server] {
        match self {
            Self::LoadBalancer(balancer) => balancer.servers(),
            Self::Static(_) => &[],
        }
    }

    /// The sticky cookie setting, when the service pins clients to a server.
    #[must_use]
    pub fn sticky(&self) -> Option<&Sticky> {
        match self {
            Self::LoadBalancer(balancer) => balancer.sticky(),
            Self::Static(_) => None,
        }
    }

    /// Keys the service's sticky cookie, if it has one, with the snapshot's `secret` for `app`.
    ///
    /// # Errors
    ///
    /// `invalid_service` when the service is sticky and the snapshot has no `skew_secret`.
    pub fn bind_sticky(
        &mut self,
        secret: Option<&SkewSecret>,
        app: &str,
        service: &str,
    ) -> Result<(), Invalid> {
        match self {
            Self::LoadBalancer(balancer) => balancer.bind_sticky(secret, app, service),
            Self::Static(_) => Ok(()),
        }
    }

    /// Whether the service has at least one server.
    #[must_use]
    pub fn has_servers(&self) -> bool {
        !self.servers().is_empty()
    }

    /// Whether the service can answer a request: a load balancer with a server, or a static
    /// service, which answers from its directory and never sleeps.
    #[must_use]
    pub fn is_backed(&self) -> bool {
        matches!(self, Self::Static(_)) || self.has_servers()
    }

    /// The compiled `static` service, or `None` for any other type.
    #[must_use]
    pub fn as_static(&self) -> Option<&Arc<StaticSite>> {
        match self {
            Self::Static(site) => Some(site),
            Self::LoadBalancer(_) => None,
        }
    }

    /// The server at `addr` and the transport that reaches it, or `None` when the service has no
    /// such server.
    #[must_use]
    pub fn upstream(&self, addr: SocketAddr) -> Option<Upstream<'_>> {
        match self {
            Self::LoadBalancer(balancer) => balancer.upstream(addr),
            Self::Static(_) => None,
        }
    }

    /// Whether some `https://` server of the service skips certificate verification
    /// (`insecure_skip_verify`).
    #[must_use]
    pub fn skips_tls_verification(&self) -> bool {
        match self {
            Self::LoadBalancer(balancer) => balancer.skips_tls_verification(),
            Self::Static(_) => false,
        }
    }

    /// The address of the server a new request goes to and the [`Lease`] that counts the request
    /// on it, or `None` when no server can take it. Keep the lease until the request is done.
    #[must_use]
    pub fn pick(&self, cx: PickCx<'_>) -> Option<(SocketAddr, Lease)> {
        match self {
            Self::LoadBalancer(balancer) => balancer.pick(cx),
            Self::Static(site) => Some((NO_SERVER, site.lease())),
        }
    }
}
