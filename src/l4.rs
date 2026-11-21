//! TCP and UDP routing (layer 4). The model is in [`podgate_model::Tcp`] and
//! [`podgate_model::Udp`]. Pingora has no UDP support and no L4 router, so these run as podgate's
//! own services on tokio.
//!
//! The compile step is shared: `compile` turns an app's L4 declarations into a [`Compiled`]
//! that the app carries in the routing table, and `detect` finds the conflicts between apps.
//! Each protocol owns its own module and adds one field to [`Compiled`] and one call to
//! `compile` and `detect`:
//!
//! - [`udp`]: UDP routers and services. Built.
//! - `tcp`: TCP routers and services. Not built; [`reject`] refuses a snapshot that carries any
//!   with `l4_not_built`, so nothing is silently left unrouted.
//!
//! What every L4 protocol needs is here: `reserve` checks that the entry point a router
//! listens on exists, speaks the router's protocol and is reserved to the router's tenant (an L4
//! listener has no host to tell tenants apart by), and `server_address` parses a server
//! address and applies the upstream address policy.

mod tcp;
pub mod udp;

use std::net::SocketAddr;

use crate::compile::{Invalid, Rejected};
use crate::conflict::Conflict;
use crate::entry::{CompileContext, Protocol};
use podgate_model::{App, Snapshot};

/// The L4 side of a compiled app.
#[derive(Debug, Default)]
pub struct Compiled {
    udp: udp::Compiled,
}

impl Compiled {
    /// The app's UDP routers and services.
    #[must_use]
    pub fn udp(&self) -> &udp::Compiled {
        &self.udp
    }
}

/// The refusal for an app that declares TCP routers, services or middlewares (not built), `None`
/// when it declares none.
#[must_use]
pub fn reject(app: &App) -> Option<Invalid> {
    app.tcp
        .as_ref()
        .is_some_and(|tcp| {
            !(tcp.routers.is_empty() && tcp.services.is_empty() && tcp.middlewares.is_empty())
        })
        .then(|| {
            Invalid::new(
                "l4_not_built",
                "TCP routers and services are planned and not built yet",
            )
        })
}

/// Compiles the L4 routers and services of `app`; every problem goes to `rejected`.
pub(crate) fn compile(
    app: &App,
    snapshot: &Snapshot,
    context: &CompileContext,
    rejected: &mut Vec<Rejected>,
) -> Compiled {
    Compiled {
        udp: udp::compile(app, snapshot, context, rejected),
    }
}

/// The conflicts among the L4 routers of `apps` (`compiled[i]` belongs to `apps[i]`), in
/// declaration order.
pub(crate) fn detect(apps: &[App], compiled: &[Compiled]) -> Vec<Conflict> {
    udp::detect(apps, compiled)
}

/// Checks that the router of `app` may listen on `entry_point` as a `protocol` router: the node
/// binds the entry point, it speaks `protocol`, and its policy reserves it to the app's tenant
/// alone. An L4 router matches no host, so a listener shared between tenants could not keep their
/// traffic apart.
pub(crate) fn reserve(
    app: &App,
    entry_point: &str,
    protocol: Protocol,
    snapshot: &Snapshot,
    context: &CompileContext,
) -> Option<Invalid> {
    let Some(bound) = context.protocol_of(entry_point) else {
        return Some(Invalid::new(
            "unknown_entry_point",
            format!("entry point {entry_point} is not bound by this node"),
        ));
    };
    if bound != protocol {
        return Some(Invalid::new(
            "entry_point_protocol",
            format!(
                "entry point {entry_point} is {}, so a {} router cannot listen on it",
                bound.as_str(),
                protocol.as_str()
            ),
        ));
    }
    let reserved = snapshot
        .entry_points
        .iter()
        .find(|policy| &*policy.name == entry_point)
        .and_then(|policy| policy.tenants.as_deref())
        .is_some_and(|tenants| {
            !tenants.is_empty() && tenants.iter().all(|tenant| *tenant == app.tenant)
        });
    (!reserved).then(|| {
        Invalid::new(
            "entry_point_forbidden",
            format!(
                "{} entry point {entry_point} must be reserved to tenant {}: its policy `tenants` must list that tenant alone",
                protocol.as_str(),
                app.tenant
            ),
        )
    })
}

/// Parses the IP literal `text` (`ip:port`) of a server of `service` and checks it against the
/// upstream address policy of `context`.
///
/// # Errors
///
/// `invalid_service` for text that is not `ip:port` (a host name says the resolver is not wired
/// for `protocol` yet), `upstream_forbidden` for an address the tenant may not dial.
pub(crate) fn server_address(
    text: &str,
    service: &str,
    protocol: Protocol,
    app: &App,
    context: &CompileContext,
) -> Result<SocketAddr, Invalid> {
    let invalid = |why: String| {
        Invalid::new(
            "invalid_service",
            format!("service {service} server {text}: {why}"),
        )
    };
    let Ok(addr) = text.parse::<SocketAddr>() else {
        let named = text.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty() && port.parse::<u16>().is_ok() && !host.contains(':')
        });
        return Err(invalid(if named {
            format!(
                "servers by host name need the resolver, which is not wired for {} yet; use an IP address",
                protocol.as_str().to_ascii_uppercase()
            )
        } else {
            "expected ip:port, like 10.0.0.5:53 or [::1]:53".to_owned()
        }));
    };
    if addr.port() == 0 {
        return Err(invalid("the port must not be 0".to_owned()));
    }
    context
        .upstream_policy()
        .evaluate(&app.tenant, addr.ip())
        .map_err(|refused| {
            Invalid::new(
                "upstream_forbidden",
                format!(
                    "service {service} server {text}: {refused} (rule: {})",
                    refused.rule()
                ),
            )
            .with("service", service)
            .with("server", text)
            .with("rule", refused.rule())
        })?;
    Ok(addr)
}
