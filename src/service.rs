//! Services: where a routed request goes. A router names a service; the service picks a server.
//!
//! A service is a [`podgate_model::Declared`] object of one `type`. `loadbalancer`, `static`,
//! `mirroring`, `weighted` and `failover` are built (a `static` service has no server: it answers
//! from an operator-declared directory; a `mirroring` service has none either: the table routes
//! to its main service and hands the copies to [`mirroring`]; a `weighted` or `failover` service
//! has none of its own: it picks among other services, see [`graph`]); any other type is
//! `invalid_service`. A router's service is looked up in the revision the request
//! picked, then in the app's own services. Each kind lives in its own file:
//!
//! | Type | File |
//! |---|---|
//! | `loadbalancer` | `loadbalancer.rs`, with its algorithms in `lb/` |
//! | `static` | `static_files.rs`, with its helpers in `static_files/` |
//! | `weighted` | `weighted.rs` |
//! | `mirroring` | `mirroring.rs` |
//! | `failover` | `failover.rs` |
//! | `fastcgi` | `fastcgi.rs`, with its helpers in `fastcgi/` |
//!
//! Shared by the load balancer's helpers: the runtime state that outlives a snapshot push
//! (`state.rs`, see [`state`]), upstream transports (`transport.rs`: the TLS settings of the
//! connection to a server), active health checks (`health.rs`, see [`health`]), passive outlier
//! ejection (`outlier.rs`, see [`outlier`]), DNS upstreams (`resolve.rs`, see [`resolve`]: servers
//! named by host name, resolved off the request path) and the upstream policy
//! ([`upstream_policy`]). It is built: the operator's rule for which
//! addresses a tenant's servers may have, checked by the compiler and before every connection.
//! Sticky cookies (`sticky.rs`) are built: the load balancer's `pick` consults them first.
//!
//! Adding a service type: a file here with `compile` and `pick`, one variant in [`Service`] and
//! one arm in each of its `match` statements, and its name removed from `UNBUILT`.

mod failover;
mod fastcgi;
pub mod graph;
pub mod health;
pub mod lb;
mod loadbalancer;
pub mod mirroring;
pub mod outlier;
pub mod resolve;
pub mod state;
mod static_files;
pub mod sticky;
mod transport;
pub mod upstream_policy;
mod weighted;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::compile::Invalid;
use pingora::upstreams::peer::HttpPeer;
use podgate_model::{Declared, SkewSecret};
use resolve::Resolver;

pub use failover::Failover;
pub(crate) use fastcgi::serve as serve_fastcgi;
pub use fastcgi::{
    Failure as FastcgiFailure, FastcgiRoots, FastcgiSite, LoadError as FastcgiLoadError,
    Summary as FastcgiSummary, TenantFastcgi,
};
pub use lb::PickCx;
pub(crate) use lb::RingBudget;
pub use loadbalancer::{LoadBalancer, Server, Servers};
pub use mirroring::Mirroring;
pub(crate) use state::Registry;
pub use state::{Lease, ServerState, ServiceState};
pub(crate) use static_files::serve as serve_static;
pub use static_files::{
    LoadError as StaticRootsError, NO_SERVER, Reads as StaticReads, Root as StaticRoot,
    StaticRoots, StaticSite, TenantRoots,
};
pub use sticky::Sticky;
pub use transport::extras;
pub use transport::{
    Named as NamedTransport, Summary as TransportSummary, Transport, Upstream, timed_out,
};
pub use weighted::Weighted;

/// Service types that are planned and not built yet.
pub const UNBUILT: [&str; 0] = [];

/// Every service type `Service::compile` builds. `compile` refuses a type that is not listed here
/// before it looks at its arms, so an arm for a new type is dead until its name is listed; the
/// schema guard (`every_built_kind_has_a_schema`) compares this list with `schemas()`.
pub const BUILT: [&str; 6] = [
    "loadbalancer",
    "static",
    "mirroring",
    "weighted",
    "failover",
    "fastcgi",
];

/// Generates [`schemas`] from one list: `"type" => path::Config,` for a built type, whose
/// configuration struct derives `schemars::JsonSchema`. Keep one entry per line, a blank line
/// between entries. The test `every_built_kind_has_a_schema` fails for a type that [`BUILT`]
/// lists and this list lacks.
macro_rules! schemas {
    ($($ty:literal => $config:ty,)*) => {
        /// The JSON Schema of the configuration of every built service type, by type name.
        #[must_use]
        pub fn schemas() -> Vec<(&'static str, serde_json::Value)> {
            vec![$(($ty, $crate::admin::schema::of::<$config>()),)*]
        }
    };
}

schemas! {
    "loadbalancer" => loadbalancer::Config,

    "static" => static_files::Config,

    "mirroring" => mirroring::Config,

    "weighted" => weighted::Config,

    "failover" => failover::Config,

    "fastcgi" => fastcgi::Config,
}

/// The `type` of an upstream transport in a snapshot and its JSON Schema.
#[must_use]
pub fn transport_schema() -> (&'static str, serde_json::Value) {
    (transport::KIND, transport::schema())
}

/// A compiled service.
#[derive(Debug)]
pub enum Service {
    /// `loadbalancer`: a set of servers and an algorithm.
    LoadBalancer(Box<LoadBalancer>),
    /// `static`: files from an operator-declared directory. Has no server.
    Static(Arc<StaticSite>),
    /// `mirroring`: copies of a share of the requests of another service. Has no server.
    Mirroring(Box<Mirroring>),
    /// `weighted`: a weighted choice among other services. Has no server of its own.
    Weighted(Box<Weighted>),
    /// `failover`: a primary service and a fallback. Has no server of its own.
    Failover(Box<Failover>),
    /// `fastcgi`: a script run by an operator-declared FastCGI application. Has no server.
    Fastcgi(Arc<FastcgiSite>),
}

/// A service and the name it was declared under.
#[derive(Debug)]
pub struct Named {
    /// The declared name, unique among services of its scope (the app or one revision).
    pub name: Box<str>,
    /// The compiled service.
    pub service: Service,
}

/// What the operator declared for one tenant that its services may name: the directories of
/// `static` services (`STATIC_ROOTS_FILE`) and the applications of `fastcgi` services
/// (`FASTCGI_FILE`). A snapshot names an entry and never supplies a path or an address.
#[derive(Clone, Copy, Debug, Default)]
pub struct Locals<'a> {
    /// The roots `static` services serve.
    pub statics: Option<&'a TenantRoots>,
    /// The upstreams `fastcgi` services run.
    pub fastcgi: Option<&'a TenantFastcgi>,
}

impl Service {
    /// Compiles one declared service of `tenant`. `locals` are the directories and FastCGI
    /// upstreams the operator declared for the tenant; `resolver` holds the answers for servers
    /// named by host name.
    ///
    /// # Errors
    ///
    /// `service_not_built` for a planned type nobody has built, `invalid_service` for an unknown
    /// type or a configuration the type refuses (a server host that is not an IP address or a
    /// valid host name included), `unknown_static_root` for a `static` service naming a root the
    /// tenant lacks.
    /// `unknown_fastcgi_upstream` for a `fastcgi` service naming an upstream the tenant lacks.
    pub fn compile(
        declared: &Declared,
        transports: &[NamedTransport],
        locals: Option<&Locals<'_>>,
        tenant: &str,
        resolver: &Resolver,
    ) -> Result<Self, Invalid> {
        match &*declared.kind {
            other if !BUILT.contains(&other) && UNBUILT.contains(&other) => Err(Invalid::new(
                "service_not_built",
                format!("service type {other} is planned and not built yet"),
            )),
            other if !BUILT.contains(&other) => Err(Invalid::new(
                "invalid_service",
                format!("unknown service type {other}"),
            )),
            "loadbalancer" => LoadBalancer::compile(declared, transports, tenant, resolver)
                .map(|balancer| Self::LoadBalancer(Box::new(balancer))),
            "static" => StaticSite::compile(declared, locals.and_then(|locals| locals.statics))
                .map(|site| Self::Static(Arc::new(site))),
            "mirroring" => {
                Mirroring::compile(declared).map(|mirroring| Self::Mirroring(Box::new(mirroring)))
            }
            "weighted" => {
                Weighted::compile(declared).map(|weighted| Self::Weighted(Box::new(weighted)))
            }
            "failover" => {
                Failover::compile(declared).map(|failover| Self::Failover(Box::new(failover)))
            }
            "fastcgi" => FastcgiSite::compile(declared, locals.and_then(|locals| locals.fastcgi))
                .map(|site| Self::Fastcgi(Arc::new(site))),
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
            Self::Mirroring(_) => "mirroring",
            Self::Weighted(_) => "weighted",
            Self::Failover(_) => "failover",
            Self::Fastcgi(_) => "fastcgi",
        }
    }

    /// The name of the balancing algorithm, for a type that has one.
    #[must_use]
    pub fn algorithm(&self) -> Option<&'static str> {
        match self {
            Self::LoadBalancer(balancer) => Some(balancer.algorithm()),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => None,
            Self::Fastcgi(_) => None,
        }
    }

    /// Whether the service probes its servers actively (`health_check`).
    #[must_use]
    pub fn has_health_check(&self) -> bool {
        match self {
            Self::LoadBalancer(balancer) => balancer.health_check().is_some(),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => false,
            Self::Fastcgi(_) => false,
        }
    }

    /// Whether the service ejects servers that fail real requests (`passive`).
    #[must_use]
    pub fn has_outlier_detection(&self) -> bool {
        match self {
            Self::LoadBalancer(balancer) => balancer.passive().is_some(),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => false,
            Self::Fastcgi(_) => false,
        }
    }

    /// The servers the service may send to, in declaration order, as of now. A server named by
    /// DNS is one server per address its name resolves to. Hold the result for one use: see
    /// [`Servers`].
    #[must_use]
    pub fn servers(&self) -> Servers {
        match self {
            Self::LoadBalancer(balancer) => balancer.servers(),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => {
                Servers::default()
            }
            Self::Fastcgi(_) => Servers::default(),
        }
    }

    /// The points of the service's hash ring, `0` when it has none: what the compile pass
    /// charges to a `RingBudget`.
    #[must_use]
    pub fn ring_points(&self) -> u64 {
        match self {
            Self::LoadBalancer(balancer) => balancer.ring_points(),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => 0,
            Self::Fastcgi(_) => 0,
        }
    }

    /// The sticky cookie setting, when the service pins clients to a server.
    #[must_use]
    pub fn sticky(&self) -> Option<&Sticky> {
        match self {
            Self::LoadBalancer(balancer) => balancer.sticky(),
            Self::Weighted(weighted) => weighted.sticky(),
            Self::Static(_) | Self::Mirroring(_) | Self::Failover(_) => None,
            Self::Fastcgi(_) => None,
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
            Self::Weighted(weighted) => weighted.bind_sticky(secret, app, service),
            Self::Static(_) | Self::Mirroring(_) | Self::Failover(_) => Ok(()),
            Self::Fastcgi(_) => Ok(()),
        }
    }

    /// Whether the service has at least one server to send to now.
    #[must_use]
    pub fn has_servers(&self) -> bool {
        !self.servers().is_empty()
    }

    /// Whether the service can answer a request on its own: a load balancer with a server declared
    /// (one whose name has no address yet is still backed: it answers `503`, it is not asleep), or
    /// a static service, which answers from its directory and never sleeps. A `weighted` or
    /// `failover` service is never backed by itself: `graph::backed` asks its children.
    #[must_use]
    pub fn is_backed(&self) -> bool {
        match self {
            Self::LoadBalancer(balancer) => balancer.is_backed(),
            Self::Static(_) => true,
            Self::Fastcgi(_) => true,
            Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => false,
        }
    }

    /// The distinct DNS names the service's servers use, in lower case.
    pub fn dns_names(&self) -> impl Iterator<Item = &str> {
        match self {
            Self::LoadBalancer(balancer) => Some(balancer.dns_names()),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => None,
            Self::Fastcgi(_) => None,
        }
        .into_iter()
        .flatten()
    }

    /// The distinct SRV owner names the service's servers use, in lower case.
    pub fn srv_names(&self) -> impl Iterator<Item = &str> {
        match self {
            Self::LoadBalancer(balancer) => Some(balancer.srv_names()),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => None,
            Self::Fastcgi(_) => None,
        }
        .into_iter()
        .flatten()
    }

    /// Takes the addresses the DNS resolver holds now for the names of the service's servers.
    /// Returns whether its servers changed.
    #[must_use]
    pub fn refresh(&self) -> bool {
        match self {
            Self::LoadBalancer(balancer) => balancer.refresh(),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => false,
            Self::Fastcgi(_) => false,
        }
    }

    /// Whether the service is a `weighted` or `failover` service: it picks among other services.
    #[must_use]
    pub fn is_graph(&self) -> bool {
        matches!(self, Self::Weighted(_) | Self::Failover(_))
    }

    /// The children a `weighted` or `failover` service declares, empty for any other type.
    #[must_use]
    pub fn children(&self) -> &[graph::ChildRef] {
        match self {
            Self::Weighted(weighted) => weighted.children(),
            Self::Failover(failover) => failover.children(),
            Self::LoadBalancer(_) | Self::Static(_) | Self::Mirroring(_) => &[],
            Self::Fastcgi(_) => &[],
        }
    }

    /// The compiled `static` service, or `None` for any other type.
    #[must_use]
    pub fn as_static(&self) -> Option<&Arc<StaticSite>> {
        match self {
            Self::Static(site) => Some(site),
            Self::LoadBalancer(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => {
                None
            }
            Self::Fastcgi(_) => None,
        }
    }

    /// The compiled `fastcgi` service, or `None` for any other type.
    #[must_use]
    pub fn as_fastcgi(&self) -> Option<&Arc<FastcgiSite>> {
        match self {
            Self::Fastcgi(site) => Some(site),
            Self::LoadBalancer(_)
            | Self::Static(_)
            | Self::Mirroring(_)
            | Self::Weighted(_)
            | Self::Failover(_) => None,
        }
    }

    /// The compiled `mirroring` service, or `None` for any other type.
    #[must_use]
    pub fn as_mirroring(&self) -> Option<&Mirroring> {
        match self {
            Self::Mirroring(mirroring) => Some(mirroring),
            Self::LoadBalancer(_) | Self::Static(_) | Self::Weighted(_) | Self::Failover(_) => None,
            Self::Fastcgi(_) => None,
        }
    }

    /// The transport the service's `https://` servers are reached through, `None` for a type
    /// that has no server.
    #[must_use]
    pub fn transport(&self) -> Option<&Transport> {
        match self {
            Self::LoadBalancer(balancer) => Some(balancer.transport()),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => None,
            Self::Fastcgi(_) => None,
        }
    }

    /// Runs `f` on the server at `addr` and the transport that reaches it. `None` when the
    /// service has no such server: a request that picked it may find it gone when the DNS answer
    /// of its name changed in between.
    pub fn with_upstream<R>(
        &self,
        addr: SocketAddr,
        f: impl FnOnce(Upstream<'_>) -> R,
    ) -> Option<R> {
        match self {
            Self::LoadBalancer(balancer) => balancer.with_upstream(addr, f),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => None,
            Self::Fastcgi(_) => None,
        }
    }

    /// A peer for the first server of the service, with the transport that reaches it, and
    /// whether that server is `h2c://`.
    #[must_use]
    pub fn first_peer(&self) -> Option<(HttpPeer, bool)> {
        let addr = self.servers().first()?.addr;
        self.with_upstream(addr, |upstream| (upstream.peer(), upstream.server.h2c))
    }

    /// Whether some `https://` server of the service skips certificate verification
    /// (`insecure_skip_verify`).
    #[must_use]
    pub fn skips_tls_verification(&self) -> bool {
        match self {
            Self::LoadBalancer(balancer) => balancer.skips_tls_verification(),
            Self::Static(_) | Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => false,
            Self::Fastcgi(_) => false,
        }
    }

    /// Why this service cannot carry gRPC, which needs HTTP/2 to the upstream; `None` when it
    /// can. A `weighted` or `failover` service has no server of its own and answers `None` here:
    /// `graph::http2_refusal` asks every service reachable below it, and names the one that
    /// refuses.
    #[must_use]
    pub fn http2_refusal(&self) -> Option<String> {
        match self {
            Self::LoadBalancer(balancer) => balancer.http1_only_server().map(|url| {
                format!(
                    "has the server {url}, which is reached over HTTP/1.1 (use `h2c://`, or `https://` with a transport that does not set `http2: false`)"
                )
            }),
            Self::Static(_) => Some("is a static service, which answers no gRPC".to_owned()),
            Self::Fastcgi(_) => Some("is a fastcgi service, which answers no gRPC".to_owned()),
            Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => None,
        }
    }

    /// The address of the server a new request goes to and the [`Lease`] that counts the request
    /// on it, or `None` when no server can take it. Keep the lease until the request is done.
    /// A `weighted` or `failover` service picks nothing by itself: its children are in the
    /// revision's links, and [`graph::pick`] walks them.
    #[must_use]
    pub fn pick(&self, cx: PickCx<'_>) -> Option<(SocketAddr, Lease)> {
        match self {
            Self::LoadBalancer(balancer) => balancer.pick(cx),
            Self::Static(site) => Some((NO_SERVER, site.lease())),
            Self::Fastcgi(site) => Some((NO_SERVER, site.lease())),
            // The table never routes a request to a mirroring service: it routes to its main.
            Self::Mirroring(_) | Self::Weighted(_) | Self::Failover(_) => None,
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn declared(kind: &str) -> Declared {
        serde_json::from_value(json!({ "name": "s", "type": kind })).expect("declared")
    }

    #[test]
    fn built_lists_exactly_the_types_compile_builds() {
        for kind in BUILT {
            // An empty declaration is refused by the type itself, never as unknown or planned.
            let err = Service::compile(&declared(kind), &[], None, "t", &Resolver::default())
                .expect_err(kind);
            assert!(
                !err.message.starts_with("unknown service type")
                    && !err.message.contains("planned and not built"),
                "{kind} is listed in BUILT and has no arm: {}",
                err.message
            );
        }
        let err = Service::compile(
            &declared("zzz_unlisted"),
            &[],
            None,
            "t",
            &Resolver::default(),
        )
        .expect_err("unlisted");
        assert_eq!(
            (err.code, err.message.as_str()),
            ("invalid_service", "unknown service type zzz_unlisted")
        );
        for kind in UNBUILT {
            let err = Service::compile(&declared(kind), &[], None, "t", &Resolver::default())
                .expect_err(kind);
            assert_eq!(err.code, "service_not_built", "{kind}");
            assert!(!BUILT.contains(&kind));
        }
    }
}
