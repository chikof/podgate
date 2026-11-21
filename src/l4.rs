//! TCP and UDP routing (layer 4). The model is in [`podgate_model::Tcp`] and
//! [`podgate_model::Udp`]. Pingora has no UDP support and no L4 router, so these run as podgate's
//! own services: TCP as a Pingora `ServerApp` on a listening service, UDP on tokio.
//!
//! The compile step is shared: `compile` turns an app's L4 declarations into a [`Compiled`]
//! that the app carries in the routing table, and `detect` finds the conflicts between apps.
//! Each protocol owns its own module and adds one field to [`Compiled`] and one call to
//! `compile` and `detect`:
//!
//! - [`tcp`]: TCP routers and services, TLS on TCP routers (with the
//!   [`tls`] module), and change 0061: the TCP middlewares a router's `chain` runs
//!   ([`middleware`]) and what a service does towards its servers, a PROXY protocol header,
//!   upstream TLS and the termination delay ([`upstream`]).
//! - [`udp`]: UDP routers and services. Built.
//!
//! What every L4 protocol needs is here: `reserve` checks that the entry point a router
//! listens on exists, speaks the router's protocol and is reserved to the router's tenant (an L4
//! listener has no host to tell tenants apart by), `access` is the same check for a TLS router,
//! whose server name does tell tenants apart, and `server_address` parses a server
//! address and applies the upstream address policy.

pub mod health;
pub mod middleware;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod upstream;

use std::net::SocketAddr;

use crate::compile::{Invalid, Rejected};
use crate::conflict::Conflict;
use crate::entry::{CompileContext, Protocol};
use crate::service::resolve::NameBudget;
use podgate_model::{App, Snapshot};

/// The L4 side of a compiled app.
#[derive(Debug, Default)]
pub struct Compiled {
    tcp: tcp::Compiled,
    udp: udp::Compiled,
}

impl Compiled {
    /// The app's TCP routers and services.
    #[must_use]
    pub fn tcp(&self) -> &tcp::Compiled {
        &self.tcp
    }

    /// The TCP side, mutable, for the registry that carries service state across a push.
    pub(crate) fn tcp_mut(&mut self) -> &mut tcp::Compiled {
        &mut self.tcp
    }

    /// The app's UDP routers and services.
    #[must_use]
    pub fn udp(&self) -> &udp::Compiled {
        &self.udp
    }
}

/// Compiles the L4 routers and services of `app`; every problem goes to `rejected`. `names`
/// counts the DNS names the servers use, with those of the app's HTTP services.
pub(crate) fn compile(
    app: &App,
    snapshot: &Snapshot,
    context: &CompileContext,
    names: &mut NameBudget,
    rejected: &mut Vec<Rejected>,
) -> Compiled {
    Compiled {
        tcp: tcp::compile(app, snapshot, context, names, rejected),
        udp: udp::compile(app, snapshot, context, rejected),
    }
}

/// The conflicts among the L4 routers of `apps` (`compiled[i]` belongs to `apps[i]`), in
/// declaration order.
pub(crate) fn detect(apps: &[App], compiled: &[Compiled]) -> Vec<Conflict> {
    let mut found = tcp::detect(apps, compiled);
    found.extend(udp::detect(apps, compiled));
    found
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
    if let Some(invalid) = unbound(entry_point, protocol, context) {
        return Some(invalid);
    }
    (!reserved_to(app, entry_point, snapshot)).then(|| {
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

/// The refusal for an entry point that does not exist or does not speak `protocol`.
fn unbound(entry_point: &str, protocol: Protocol, context: &CompileContext) -> Option<Invalid> {
    let Some(bound) = context.protocol_of(entry_point) else {
        return Some(Invalid::new(
            "unknown_entry_point",
            format!("entry point {entry_point} is not bound by this node"),
        ));
    };
    (bound != protocol).then(|| {
        Invalid::new(
            "entry_point_protocol",
            format!(
                "entry point {entry_point} is {}, so a {} router cannot listen on it",
                bound.as_str(),
                protocol.as_str()
            ),
        )
    })
}

/// Whether the policy of `entry_point` lists `app`'s tenant and no other.
fn reserved_to(app: &App, entry_point: &str, snapshot: &Snapshot) -> bool {
    snapshot
        .entry_points
        .iter()
        .find(|policy| &*policy.name == entry_point)
        .and_then(|policy| policy.tenants.as_deref())
        .is_some_and(|tenants| {
            !tenants.is_empty() && tenants.iter().all(|tenant| *tenant == app.tenant)
        })
}

/// Checks that a TLS router of `app` may listen on `entry_point`: it exists, speaks `protocol`,
/// and its policy admits the tenant (no `tenants` admits every tenant, like an HTTP entry
/// point). A router that names the server names it serves tells tenants apart by them, so it
/// need not have the entry point to itself. Returns whether the tenant does have it alone.
///
/// # Errors
///
/// `unknown_entry_point`, `entry_point_protocol`, or `entry_point_forbidden` when the policy
/// does not list the tenant.
pub(crate) fn access(
    app: &App,
    entry_point: &str,
    protocol: Protocol,
    snapshot: &Snapshot,
    context: &CompileContext,
) -> Result<bool, Invalid> {
    if let Some(invalid) = unbound(entry_point, protocol, context) {
        return Err(invalid);
    }
    let admits = snapshot
        .entry_points
        .iter()
        .find(|policy| &*policy.name == entry_point)
        .and_then(|policy| policy.tenants.as_ref())
        .is_none_or(|tenants| tenants.contains(&app.tenant));
    if admits {
        Ok(reserved_to(app, entry_point, snapshot))
    } else {
        Err(Invalid::new(
            "entry_point_forbidden",
            format!(
                "{} entry point {entry_point} does not admit tenant {}",
                protocol.as_str(),
                app.tenant
            ),
        ))
    }
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
