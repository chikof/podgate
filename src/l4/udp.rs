//! UDP routers and services: per-client sessions to a load-balanced set of servers.
//!
//! ```json
//! { "udp": {
//!   "routers":  [ { "name": "dns", "entry_points": ["dns"], "service": "resolvers" } ],
//!   "services": [ { "name": "resolvers", "type": "loadbalancer", "session_timeout_secs": 30,
//!                   "servers": [ { "address": "10.0.0.5:53" }, { "address": "10.0.0.6:53" } ] } ]
//! } }
//! ```
//!
//! A UDP router has `entry_points` and `service` and nothing to match on, so a `udp` entry point
//! carries one router and is reserved to one tenant (`tenants` in its policy). `max_sessions`
//! (default 4096, at most 65,536) bounds the sessions the router holds per entry point, and
//! `max_reply_ratio` optionally bounds the bytes a client can get back before it sends a second
//! datagram. A service is a `loadbalancer` of IP-literal `servers`; each new client goes to the
//! next one in turn and stays there until its session expires after `session_timeout_secs`
//! (default 30, at most 3600) without traffic.
//!
//! This file is the compiled model; the runtime is in `listener` (the socket loop), `table` (the
//! session table), `tenants` (the per-tenant and node session caps) and `stats` (the metrics).
//! `docs/ref/l4-udp.md` has the operator's view.

mod listener;
mod stats;
mod table;
mod tenants;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use super::Compiled as L4;
use crate::compile::{Invalid, Rejected};
use crate::conflict::Conflict;
use crate::entry::{CompileContext, Protocol};
use podgate_model::{App, Declared, Snapshot};

pub use listener::{Listener, bind};
pub use stats::render;
pub use tenants::{NODE_MAX_SESSIONS, TENANT_MAX_SESSIONS, Tenants};

/// Sessions a router holds per entry point when it does not say.
pub const DEFAULT_MAX_SESSIONS: u32 = 4096;
/// Most sessions a router may ask for.
pub const MAX_SESSIONS: u32 = 65_536;
/// Idle seconds before a session expires when the service does not say.
pub const DEFAULT_TIMEOUT_SECS: u32 = 30;
/// Longest `session_timeout_secs`.
pub const MAX_TIMEOUT_SECS: u32 = 3600;
/// Most servers a service declares.
pub const MAX_SERVERS: usize = 256;
/// Largest `max_reply_ratio`.
pub const MAX_REPLY_RATIO: u32 = 1000;
/// The largest datagram podgate forwards, either way. It is the buffer of a session, so a larger
/// datagram is dropped, never cut.
pub const DATAGRAM_MAX: usize = 4096;
/// What a session charges the tenant's `max_buffer_bytes`: its buffer, fixed.
pub const SESSION_BYTES: u64 = 4096;

/// The configuration of a UDP router.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouterConfig {
    /// Unique among the app's UDP routers.
    name: Box<str>,
    /// The `udp` entry points the router listens on; each is reserved to the app's tenant.
    entry_points: Vec<Box<str>>,
    /// The UDP service that answers.
    service: Box<str>,
    /// Sessions held per entry point: 1 to 65,536, default 4096.
    #[serde(default)]
    max_sessions: Option<u32>,
    /// Until a client has sent a second datagram, the most bytes returned to it, as a multiple of
    /// its first datagram's bytes: 1 to 1000. Absent: no limit.
    #[serde(default)]
    max_reply_ratio: Option<u32>,
}

/// The configuration of a UDP `loadbalancer`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// The servers, as IP literals; 1 to 256.
    servers: Vec<ServerConfig>,
    /// Idle seconds before a session expires: 1 to 3600, default 30.
    #[serde(default)]
    session_timeout_secs: Option<u32>,
}

/// One server as declared.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    /// `ip:port`, like `10.0.0.5:53` or `[2001:db8::5]:53`.
    address: String,
}

/// A compiled UDP router.
#[derive(Debug)]
pub struct Router {
    name: Box<str>,
    entry_points: Box<[Box<str>]>,
    service: usize,
    max_sessions: u32,
    max_reply_ratio: Option<NonZeroU32>,
}

impl Router {
    /// The router's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The entry points it listens on.
    #[must_use]
    pub fn entry_points(&self) -> &[Box<str>] {
        &self.entry_points
    }

    /// Sessions it holds per entry point.
    #[must_use]
    pub fn max_sessions(&self) -> u32 {
        self.max_sessions
    }

    /// The reply byte ratio before a client's second datagram, when limited.
    #[must_use]
    pub fn max_reply_ratio(&self) -> Option<u32> {
        self.max_reply_ratio.map(NonZeroU32::get)
    }
}

/// A compiled UDP service: the servers, handed out in turn, and the idle timeout.
#[derive(Debug)]
pub struct Service {
    name: Box<str>,
    servers: Box<[SocketAddr]>,
    timeout: Duration,
    next: AtomicUsize,
}

impl Service {
    /// The service's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The servers, in declaration order.
    #[must_use]
    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    /// How long a session may be idle.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The next server in turn; `None` only for a service with no server, which compile refuses.
    #[must_use]
    pub fn pick(&self) -> Option<SocketAddr> {
        let turn = self.next.fetch_add(1, Ordering::Relaxed);
        self.servers.get(turn % self.servers.len().max(1)).copied()
    }
}

/// The UDP routers and services of one app.
#[derive(Debug, Default)]
pub struct Compiled {
    routers: Box<[Router]>,
    services: Box<[Service]>,
}

impl Compiled {
    /// The routers, in declaration order.
    #[must_use]
    pub fn routers(&self) -> &[Router] {
        &self.routers
    }

    /// The services, in declaration order.
    #[must_use]
    pub fn services(&self) -> &[Service] {
        &self.services
    }

    /// The index of the router that listens on `entry_point`.
    #[must_use]
    pub fn locate(&self, entry_point: &str) -> Option<usize> {
        self.routers.iter().position(|router| {
            router
                .entry_points
                .iter()
                .any(|name| &**name == entry_point)
        })
    }

    /// The router at `index` and its service.
    #[must_use]
    pub fn route(&self, index: usize) -> Option<(&Router, &Service)> {
        let router = self.routers.get(index)?;
        Some((router, self.services.get(router.service)?))
    }
}

/// Compiles the UDP routers and services of `app`; every problem goes to `rejected`.
pub(super) fn compile(
    app: &App,
    snapshot: &Snapshot,
    context: &CompileContext,
    rejected: &mut Vec<Rejected>,
) -> Compiled {
    let Some(udp) = app.udp.as_ref() else {
        return Compiled::default();
    };
    let mut problem = |at: String, invalid: Invalid| rejected.push(Rejected::new(app, at, invalid));
    let mut seen = HashSet::new();
    for declared in &udp.services {
        if !seen.insert(&*declared.name) {
            problem(
                format!("udp service {}", declared.name),
                Invalid::new(
                    "duplicate_name",
                    format!("udp service {} is declared twice", declared.name),
                ),
            );
        }
    }
    let mut services = Vec::with_capacity(udp.services.len());
    let mut broken: HashSet<&str> = HashSet::new();
    for declared in &udp.services {
        match compile_service(declared, app, context) {
            Ok(service) => services.push(service),
            Err(invalid) => {
                broken.insert(&declared.name);
                problem(format!("udp service {}", declared.name), invalid);
            }
        }
    }
    let mut routers = Vec::with_capacity(udp.routers.len());
    let mut names = HashSet::new();
    for value in &udp.routers {
        let at = format!(
            "udp router {}",
            value.get("name").and_then(Value::as_str).unwrap_or("?")
        );
        let config = match serde_json::from_value::<RouterConfig>(value.clone()) {
            Ok(config) => config,
            Err(err) => {
                problem(
                    at,
                    Invalid::new("invalid_router", format!("udp router: {err}")),
                );
                continue;
            }
        };
        if !names.insert(config.name.clone()) {
            problem(
                at.clone(),
                Invalid::new(
                    "duplicate_name",
                    format!("udp router {} is declared twice", config.name),
                ),
            );
        }
        match compile_router(&config, app, snapshot, context, &services, &broken) {
            Ok(router) => routers.push(router),
            Err(invalids) => {
                for invalid in invalids {
                    problem(at.clone(), invalid);
                }
            }
        }
    }
    Compiled {
        routers: routers.into_boxed_slice(),
        services: services.into_boxed_slice(),
    }
}

fn compile_service(
    declared: &Declared,
    app: &App,
    context: &CompileContext,
) -> Result<Service, Invalid> {
    if &*declared.kind != "loadbalancer" {
        return Err(Invalid::new(
            "invalid_service",
            format!(
                "udp service {} is of type {}; UDP has only `loadbalancer`",
                declared.name, declared.kind
            ),
        ));
    }
    let invalid = |why: String| Invalid::new("invalid_service", format!("udp loadbalancer: {why}"));
    let config: ServiceConfig = serde_json::from_value(Value::Object(declared.config.clone()))
        .map_err(|err| invalid(err.to_string()))?;
    if config.servers.is_empty() || config.servers.len() > MAX_SERVERS {
        return Err(invalid(format!(
            "declares {} servers, between 1 and {MAX_SERVERS} are required",
            config.servers.len()
        )));
    }
    let timeout = config.session_timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    if !(1..=MAX_TIMEOUT_SECS).contains(&timeout) {
        return Err(invalid(format!(
            "session_timeout_secs is {timeout}, between 1 and {MAX_TIMEOUT_SECS} is allowed"
        )));
    }
    let servers = config
        .servers
        .iter()
        .map(|server| {
            super::server_address(&server.address, &declared.name, Protocol::Udp, app, context)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Service {
        name: declared.name.clone(),
        servers: servers.into_boxed_slice(),
        timeout: Duration::from_secs(u64::from(timeout)),
        next: AtomicUsize::new(0),
    })
}

fn compile_router(
    config: &RouterConfig,
    app: &App,
    snapshot: &Snapshot,
    context: &CompileContext,
    services: &[Service],
    broken: &HashSet<&str>,
) -> Result<Router, Vec<Invalid>> {
    let mut problems = Vec::new();
    if config.entry_points.is_empty() {
        problems.push(Invalid::new(
            "unknown_entry_point",
            "entry_points lists no entry point",
        ));
    }
    for (at, name) in config.entry_points.iter().enumerate() {
        if config.entry_points[..at].contains(name) {
            problems.push(Invalid::new(
                "duplicate_name",
                format!("entry point {name} is listed twice"),
            ));
        } else if let Some(invalid) = super::reserve(app, name, Protocol::Udp, snapshot, context) {
            problems.push(invalid);
        }
    }
    let max_sessions = config.max_sessions.unwrap_or(DEFAULT_MAX_SESSIONS);
    if !(1..=MAX_SESSIONS).contains(&max_sessions) {
        problems.push(Invalid::new(
            "invalid_router",
            format!("max_sessions is {max_sessions}, between 1 and {MAX_SESSIONS} is allowed"),
        ));
    }
    let ratio = match config.max_reply_ratio {
        None => None,
        Some(ratio) => {
            match NonZeroU32::new(ratio).filter(|ratio| ratio.get() <= MAX_REPLY_RATIO) {
                Some(ratio) => Some(ratio),
                None => {
                    problems.push(Invalid::new(
                        "invalid_router",
                        format!(
                            "max_reply_ratio is {ratio}, between 1 and {MAX_REPLY_RATIO} is allowed"
                        ),
                    ));
                    None
                }
            }
        }
    };
    let service = services
        .iter()
        .position(|service| service.name == config.service);
    if service.is_none() && !broken.contains(&*config.service) {
        problems.push(Invalid::new(
            "unknown_service",
            format!("udp service {} is not declared by the app", config.service),
        ));
    }
    match service {
        Some(service) if problems.is_empty() => Ok(Router {
            name: config.name.clone(),
            entry_points: config.entry_points.clone().into_boxed_slice(),
            service,
            max_sessions,
            max_reply_ratio: ratio,
        }),
        _ => Err(problems),
    }
}

/// The entry points claimed by more than one UDP router (`route_ambiguity`): a UDP listener has
/// nothing to tell routers apart by.
pub(super) fn detect(apps: &[App], compiled: &[L4]) -> Vec<Conflict> {
    let mut claims: Vec<(&str, usize, &str)> = Vec::new();
    let mut found = Vec::new();
    for (index, (app, l4)) in apps.iter().zip(compiled).enumerate() {
        for router in l4.udp().routers() {
            for entry in router.entry_points() {
                if let Some(&(_, first, first_router)) = claims.iter().find(|claim| {
                    claim.0 == &**entry && !(claim.1 == index && claim.2 == router.name())
                }) {
                    let (first_app, first_name) = (&apps[first], first_router);
                    found.push(Conflict::EntryPoint {
                        entry_point: entry.clone(),
                        apps: [first_app.id.clone(), app.id.clone()],
                        routers: [first_name.into(), router.name().into()],
                        declared_by: [first_app.declared_by.clone(), app.declared_by.clone()],
                    });
                } else {
                    claims.push((entry, index, router.name()));
                }
            }
        }
    }
    found
}
