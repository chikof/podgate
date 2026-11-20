//! Services: where a routed request goes. A router names a service; the service picks a server.
//!
//! A service is a [`podgate_model::Declared`] object of one `type`. `loadbalancer` is built;
//! `weighted`, `mirroring` and `failover` are planned and refused with `service_not_built`; any
//! other type is `invalid_service`. A router's service is looked up in the revision the request
//! picked, then in the app's own services. Each kind lives in its own file:
//!
//! | Type | File |
//! |---|---|
//! | `loadbalancer` | `loadbalancer.rs`, with its algorithms in `lb/` |
//! | `weighted` | `weighted.rs` |
//! | `mirroring` | `mirroring.rs` |
//! | `failover` | `failover.rs` |
//!
//! Shared by the load balancer's helpers, and empty until their specs land: active health checks
//! (`health.rs`), passive outlier ejection (`outlier.rs`), sticky cookies (`sticky.rs`), upstream
//! transports (`transport.rs`) and DNS upstreams (`resolve.rs`).
//!
//! Adding a service type: a file here with `compile` and `pick`, one variant in [`Service`] and
//! one arm in each of its `match` statements, and its name removed from `UNBUILT`.

mod failover;
mod health;
pub mod lb;
mod loadbalancer;
mod mirroring;
mod outlier;
mod resolve;
mod sticky;
mod transport;
mod weighted;

use std::net::SocketAddr;

use crate::compile::Invalid;
use podgate_model::Declared;

pub use lb::PickCx;
pub use loadbalancer::{LoadBalancer, Server, ServerState};

/// Service types that are planned and not built yet.
const UNBUILT: [&str; 3] = ["weighted", "mirroring", "failover"];

/// A compiled service.
#[derive(Debug)]
pub enum Service {
    /// `loadbalancer`: a set of servers and an algorithm.
    LoadBalancer(LoadBalancer),
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
    /// Compiles one declared service.
    ///
    /// # Errors
    ///
    /// `service_not_built` for a planned type nobody has built, `invalid_service` for an unknown
    /// type or a configuration the type refuses, `dns_upstream_not_built` for a server named by
    /// host name.
    pub fn compile(declared: &Declared) -> Result<Self, Invalid> {
        match &*declared.kind {
            "loadbalancer" => LoadBalancer::compile(declared).map(Self::LoadBalancer),
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
        }
    }

    /// The servers the service may send to, in declaration order.
    #[must_use]
    pub fn servers(&self) -> &[Server] {
        match self {
            Self::LoadBalancer(balancer) => balancer.servers(),
        }
    }

    /// Whether the service has at least one server.
    #[must_use]
    pub fn has_servers(&self) -> bool {
        !self.servers().is_empty()
    }

    /// The address of the server a new request goes to, or `None` when no server can take it.
    #[must_use]
    pub fn pick(&self, cx: PickCx<'_>) -> Option<SocketAddr> {
        match self {
            Self::LoadBalancer(balancer) => balancer.pick(cx),
        }
    }
}
