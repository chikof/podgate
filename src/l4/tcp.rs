//! TCP routers and services: raw TCP connections to a load-balanced set of servers.
//!
//! ```json
//! { "tcp": {
//!   "routers":  [ { "name": "db", "entry_points": ["pg"], "service": "primary",
//!                   "match": { "client_ip": ["10.0.0.0/8"] } } ],
//!   "services": [ { "name": "primary", "type": "loadbalancer", "algorithm": "round_robin",
//!                   "idle_timeout_secs": 300,
//!                   "servers": [ { "address": "10.0.0.5:5432" }, { "address": "db.internal:5432" } ] } ]
//! } }
//! ```
//!
//! A TCP router has `entry_points`, a `service` and an optional `match`: a matcher tree whose only
//! leaf is `client_ip` (with `all`, `any` and `not`). A router without `match` is a catch-all:
//! it takes the connections no router with a `match` takes. The `tcp` entry point is reserved to
//! one tenant (`tenants` in its policy), so the routers on it, in any of that tenant's apps, are
//! ranked by whether they have a `match` and then by specificity; two of the same rank that can
//! match one client are `route_ambiguity`, which makes a second catch-all one.
//!
//! A service is a `loadbalancer` of `servers` (`ip:port` or `name:port`; a name is resolved off
//! the connection path by the DNS resolver, and every answer passes the upstream address policy
//! like an HTTP server's) and an `algorithm`. It reuses the HTTP load balancer, so the balancing
//! state survives a snapshot push and a name expands into the addresses it resolves to. Only
//! the algorithms that need nothing from an HTTP request are built here: `round_robin`,
//! `weighted_round_robin`, `least_conn`, `random` and `hrw` (the client address).
//!
//! This file is the compiled model; the runtime is in `app` (the Pingora application of an entry
//! point), `copy` (the byte copy) and `stats` (the metrics). `docs/ref/l4-tcp.md` has the
//! operator's view.

mod app;
mod copy;
mod stats;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pingora::http::RequestHeader;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::Compiled as L4;
use super::health;
use crate::compile::{Invalid, Rejected};
use crate::conflict::Conflict;
use crate::entry::{CompileContext, Protocol};
use crate::router::Matcher;
use crate::router::matcher::{self, View};
use crate::service::resolve::{self, NameBudget};
use crate::service::{self, Lease, PickCx};
use podgate_model::{App, Declared, Snapshot};

pub use app::App as Listener;
pub use stats::render;

/// Idle seconds before a connection is closed when the service does not say.
pub const DEFAULT_IDLE_SECS: u32 = 300;
/// Longest `idle_timeout_secs`: a day.
pub const MAX_IDLE_SECS: u32 = 86_400;
/// Most servers a service declares.
pub const MAX_SERVERS: usize = 256;
/// Servers one connection tries before it is closed.
pub const CONNECT_ATTEMPTS: usize = 3;
/// What each of the two copy buffers of a connection holds, in bytes. A connection charges both
/// to the tenant's `max_buffer_bytes`, and they are all the memory it has.
pub const COPY_BUFFER: usize = 16 * 1024;
/// What a connection charges the tenant's `max_buffer_bytes`: its two copy buffers.
pub const CONNECTION_BYTES: u64 = 2 * COPY_BUFFER as u64;
/// The algorithms a TCP service builds: the ones that need no HTTP request and no hash ring.
pub const ALGORITHMS: [&str; 5] = [
    "round_robin",
    "weighted_round_robin",
    "least_conn",
    "random",
    "hrw",
];
/// The most conflicts one entry point reports, so a snapshot of thousands of routers cannot make
/// the answer as big as the square of its size.
const MAX_CONFLICTS: usize = 32;

/// The configuration of a TCP router.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouterConfig {
    /// Unique among the app's TCP routers.
    name: Box<str>,
    /// The `tcp` entry points the router listens on; each is reserved to the app's tenant.
    entry_points: Vec<Box<str>>,
    /// The TCP service that takes the connections.
    service: Box<str>,
    /// A matcher tree over `client_ip`, `all`, `any` and `not`. Absent: a catch-all, of which an
    /// entry point carries one.
    #[serde(default, rename = "match")]
    matcher: Option<Value>,
}

/// The configuration of a TCP `loadbalancer`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// The servers: 1 to 256.
    servers: Vec<ServerConfig>,
    /// The balancing algorithm; absent: `round_robin`.
    #[serde(default)]
    #[schemars(schema_with = "algorithm_schema")]
    algorithm: Option<Box<str>>,
    /// Seconds without a byte in either direction before the connection is closed: 1 to 86,400,
    /// default 300.
    #[serde(default)]
    idle_timeout_secs: Option<u32>,
    /// Active probe of each server; absent: none. See `docs/ref/l4-health.md`.
    #[serde(default)]
    #[schemars(with = "Option<health::Config>")]
    health_check: Option<Value>,
}

fn algorithm_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "description": "The balancing algorithm. Absent: `round_robin`.",
        "enum": ALGORITHMS
    })
}

/// One server as declared.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    /// `host:port`: an IP literal (`10.0.0.5:5432`, `[2001:db8::5]:5432`) or a DNS name
    /// (`db.internal:5432`). With `resolve: "srv"`, the full SRV owner name without a port
    /// (`_db._tcp.shop.service.consul`): the records choose the targets and ports.
    address: String,
    /// Relative weight, `1` by default; only `weighted_round_robin` and `hrw` take one. Not
    /// allowed with `resolve: "srv"`: the records carry the weights.
    #[serde(default)]
    weight: Option<u32>,
    /// `a` (the default): `address` is `host:port`. `srv`: `address` is an SRV owner name.
    #[serde(default)]
    resolve: Option<ResolveKind>,
}

/// How a server's `address` is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ResolveKind {
    /// An IP literal, or a name looked up for `A` and `AAAA` records.
    A,
    /// A name looked up for `SRV` records.
    Srv,
}

/// A compiled TCP router.
#[derive(Debug)]
pub struct Router {
    name: Box<str>,
    entry_points: Box<[Box<str>]>,
    matcher: Option<Matcher>,
    matcher_json: Option<Value>,
    service: usize,
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

    /// Whether the router has no `match` and so takes what no router with one takes.
    #[must_use]
    pub fn is_catch_all(&self) -> bool {
        self.matcher.is_none()
    }

    /// The `match` as declared, `None` for a catch-all.
    #[must_use]
    pub fn match_json(&self) -> Option<&Value> {
        self.matcher_json.as_ref()
    }

    /// Whether the router listens on `entry_point`.
    #[must_use]
    pub fn listens_on(&self, entry_point: &str) -> bool {
        self.entry_points.iter().any(|name| &**name == entry_point)
    }

    /// Which router wins over which: a router with a `match` over a catch-all, then the one with
    /// more constraints.
    fn rank(&self) -> (bool, u32) {
        self.matcher
            .as_ref()
            .map_or((false, 0), |matcher| (true, matcher.spec().others))
    }

    /// Whether a connection from `client` matches. `probe` is the request head the matcher
    /// interface asks for; only `client_ip` is ever read from the view.
    fn matches(&self, entry_point: &str, client: IpAddr, probe: &RequestHeader) -> bool {
        self.matcher.as_ref().is_none_or(|matcher| {
            matcher.matches(&View {
                host: "",
                path: "/",
                entry_point,
                tls: false,
                request: probe,
                client_ip: Some(client),
            })
        })
    }
}

/// A compiled TCP service: the HTTP load balancer over the servers, and the idle timeout.
#[derive(Debug)]
pub struct Service {
    name: Box<str>,
    balancer: service::Service,
    idle: Duration,
    health: Option<Arc<health::Check>>,
}

impl Service {
    /// The service's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The balancer: its servers (a name expanded into its addresses, as of now), algorithm and
    /// state.
    #[must_use]
    pub fn balancer(&self) -> &service::Service {
        &self.balancer
    }

    /// How long a connection may carry no byte before it is closed.
    #[must_use]
    pub fn idle(&self) -> Duration {
        self.idle
    }

    /// The compiled `health_check`, when the service has one.
    #[must_use]
    pub fn health_check(&self) -> Option<&Arc<health::Check>> {
        self.health.as_ref()
    }

    /// Whether the service has a `health_check` that has marked every one of its servers down:
    /// a connection to it is refused at once, as `no_healthy_server`.
    #[must_use]
    pub fn all_down(&self) -> bool {
        let servers = self.balancer.servers();
        self.health.is_some()
            && !servers.is_empty()
            && servers.iter().all(|server| !server.available())
    }

    /// The server a connection from `client` goes to and the lease that counts the connection on
    /// it, skipping `excluded` (the servers this connection already tried). `probe` is the
    /// request head the HTTP balancer interface asks for; no algorithm built here reads it.
    #[must_use]
    pub fn pick(
        &self,
        client: Option<IpAddr>,
        excluded: &[SocketAddr],
        probe: &RequestHeader,
    ) -> Option<(SocketAddr, Lease)> {
        self.balancer.pick(PickCx {
            request: probe,
            excluded,
            client,
        })
    }
}

/// The TCP routers and services of one app.
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

    /// The balancer of every service with its name and the fingerprint of its `health_check`
    /// (`0` without one), for the registry that carries their state across a snapshot push: a
    /// changed check starts its servers healthy.
    pub(crate) fn balancers_mut(
        &mut self,
    ) -> impl Iterator<Item = (&str, u64, &mut service::Service)> {
        self.services.iter_mut().map(|service| {
            let check = service
                .health
                .as_ref()
                .map_or(0, |check| check.fingerprint());
            (&*service.name, check, &mut service.balancer)
        })
    }

    /// The router at `index` and its service.
    #[must_use]
    pub fn route(&self, index: usize) -> Option<(&Router, &Service)> {
        let router = self.routers.get(index)?;
        Some((router, self.services.get(router.service)?))
    }
}

/// Compiles the TCP routers and services of `app`; every problem goes to `rejected`.
pub(super) fn compile(
    app: &App,
    snapshot: &Snapshot,
    context: &CompileContext,
    names: &mut NameBudget,
    rejected: &mut Vec<Rejected>,
) -> Compiled {
    let Some(tcp) = app.tcp.as_ref() else {
        return Compiled::default();
    };
    let mut problem = |at: String, invalid: Invalid| rejected.push(Rejected::new(app, at, invalid));
    let mut seen = HashSet::new();
    for declared in &tcp.services {
        if !seen.insert(&*declared.name) {
            problem(
                format!("tcp service {}", declared.name),
                Invalid::new(
                    "duplicate_name",
                    format!("tcp service {} is declared twice", declared.name),
                ),
            );
        }
    }
    let mut services = Vec::with_capacity(tcp.services.len());
    let mut broken: HashSet<&str> = HashSet::new();
    for declared in &tcp.services {
        match compile_service(declared, app, context, names) {
            Ok(service) => services.push(service),
            Err(invalid) => {
                broken.insert(&declared.name);
                problem(format!("tcp service {}", declared.name), invalid);
            }
        }
    }
    let mut routers = Vec::with_capacity(tcp.routers.len());
    let mut taken = HashSet::new();
    for value in &tcp.routers {
        let at = format!(
            "tcp router {}",
            value.get("name").and_then(Value::as_str).unwrap_or("?")
        );
        let config = match router_config(value) {
            Ok(config) => config,
            Err(invalid) => {
                problem(at, invalid);
                continue;
            }
        };
        if !taken.insert(config.name.clone()) {
            problem(
                at.clone(),
                Invalid::new(
                    "duplicate_name",
                    format!("tcp router {} is declared twice", config.name),
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

/// The fields of a router that belong to later specs: refused by name, not as unknown.
const ROUTER_PLANNED: [&str; 2] = ["tls", "chain"];
/// The fields of a service that belong to later specs.
const SERVICE_PLANNED: [&str; 2] = ["proxy_protocol", "termination_delay_ms"];

fn router_config(value: &Value) -> Result<RouterConfig, Invalid> {
    if let Some(field) = ROUTER_PLANNED
        .iter()
        .find(|field| value.get(**field).is_some())
    {
        return Err(Invalid::new(
            "l4_not_built",
            format!("tcp router {field} is planned and not built yet (TLS on TCP routers)"),
        ));
    }
    serde_json::from_value(value.clone())
        .map_err(|err| Invalid::new("invalid_router", format!("tcp router: {err}")))
}

/// `host:port` as a server of the balancer: its `http://` URL (the scheme is the balancer's
/// vocabulary and never reaches a connection) and whether the host is a DNS name.
fn server_url(
    text: &str,
    service: &str,
    app: &App,
    context: &CompileContext,
) -> Result<String, Invalid> {
    if text.parse::<SocketAddr>().is_ok() {
        let addr = super::server_address(text, service, Protocol::Tcp, app, context)?;
        return Ok(format!("http://{addr}"));
    }
    let named = text.rsplit_once(':').and_then(|(host, port)| {
        let port = port.parse::<u16>().ok()?;
        (!host.contains(':') && resolve::is_host_name(host)).then_some((host, port))
    });
    match named {
        Some((_, 0)) => Err(Invalid::new(
            "invalid_service",
            format!("service {service} server {text}: the port must not be 0"),
        )),
        Some((host, port)) => Ok(format!("http://{host}:{port}")),
        None => super::server_address(text, service, Protocol::Tcp, app, context)
            .map(|addr| format!("http://{addr}")),
    }
}

fn compile_service(
    declared: &Declared,
    app: &App,
    context: &CompileContext,
    names: &mut NameBudget,
) -> Result<Service, Invalid> {
    if &*declared.kind != "loadbalancer" {
        return Err(Invalid::new(
            "invalid_service",
            format!(
                "tcp service {} is of type {}; TCP has only `loadbalancer` (`weighted` and \
                 `failover` pick among the app's HTTP services by name and have no TCP form)",
                declared.name, declared.kind
            ),
        ));
    }
    let invalid = |why: String| Invalid::new("invalid_service", format!("tcp loadbalancer: {why}"));
    if let Some(field) = SERVICE_PLANNED
        .iter()
        .find(|field| declared.config.contains_key(**field))
    {
        return Err(Invalid::new(
            "service_not_built",
            format!("tcp loadbalancer {field} is planned and not built yet"),
        ));
    }
    let planned_tls = declared
        .config
        .get("servers")
        .and_then(Value::as_array)
        .is_some_and(|servers| servers.iter().any(|server| server.get("tls").is_some()));
    if planned_tls {
        return Err(Invalid::new(
            "service_not_built",
            "tcp loadbalancer server tls is planned and not built yet",
        ));
    }
    let config: ServiceConfig = serde_json::from_value(Value::Object(declared.config.clone()))
        .map_err(|err| invalid(err.to_string()))?;
    if config.servers.is_empty() || config.servers.len() > MAX_SERVERS {
        return Err(invalid(format!(
            "declares {} servers, between 1 and {MAX_SERVERS} are required",
            config.servers.len()
        )));
    }
    let idle = config.idle_timeout_secs.unwrap_or(DEFAULT_IDLE_SECS);
    if !(1..=MAX_IDLE_SECS).contains(&idle) {
        return Err(invalid(format!(
            "idle_timeout_secs is {idle}, between 1 and {MAX_IDLE_SECS} is allowed"
        )));
    }
    let health = config
        .health_check
        .as_ref()
        .map(|value| health::Check::compile(value).map(Arc::new))
        .transpose()?;
    if let Some(algorithm) = config
        .algorithm
        .as_deref()
        .filter(|algorithm| !ALGORITHMS.contains(algorithm))
    {
        return Err(invalid(format!(
            "algorithm {algorithm} is not built for TCP; use one of {}",
            ALGORITHMS.join(", ")
        )));
    }
    let servers = config
        .servers
        .iter()
        .map(|server| {
            if server.resolve == Some(ResolveKind::Srv) {
                let mut entry =
                    json!({ "url": format!("http://{}", server.address), "resolve": "srv" });
                if let Some(weight) = server.weight {
                    entry["weight"] = json!(weight);
                }
                return Ok(entry);
            }
            let url = server_url(&server.address, &declared.name, app, context)?;
            let mut entry = json!({ "url": url });
            if let Some(weight) = server.weight {
                entry["weight"] = json!(weight);
            }
            Ok(entry)
        })
        .collect::<Result<Vec<_>, Invalid>>()?;
    let mut balancer = Map::new();
    balancer.insert("servers".to_owned(), Value::Array(servers));
    if let Some(algorithm) = &config.algorithm {
        balancer.insert("algorithm".to_owned(), json!(algorithm));
    }
    let derived = Declared {
        name: declared.name.clone(),
        kind: "loadbalancer".into(),
        config: balancer,
    };
    let balancer = service::Service::compile(&derived, &[], None, &app.tenant, context.resolver())
        .map_err(|mut err| {
            err.message = err.message.replace("http://", "");
            err
        })?;
    names.charge(&app.tenant, &app.id, balancer.dns_names())?;
    names.charge_srv(&app.tenant, &app.id, balancer.srv_names())?;
    Ok(Service {
        name: declared.name.clone(),
        balancer,
        idle: Duration::from_secs(u64::from(idle)),
        health,
    })
}

/// Parses the `match` of a TCP router: any matcher tree, then only `client_ip` and the
/// combinators are kept.
fn parse_match(value: &Value) -> Result<Matcher, Invalid> {
    let parsed = matcher::parse(value)
        .map_err(|err| Invalid::new(err.code, format!("tcp router match: {err}")))?;
    if only_client_ip(&parsed) {
        Ok(parsed)
    } else {
        Err(Invalid::new(
            "invalid_matcher",
            "a TCP router matches on `client_ip` only, with `all`, `any` and `not`: the HTTP \
             leaves read a request, and matching the TLS server name or ALPN is change 0059",
        ))
    }
}

fn only_client_ip(matcher: &Matcher) -> bool {
    match matcher {
        Matcher::ClientIp(_) => true,
        Matcher::All(children) | Matcher::Any(children) => children.iter().all(only_client_ip),
        Matcher::Not(child) => only_client_ip(child),
        _ => false,
    }
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
        } else if let Some(invalid) = super::reserve(app, name, Protocol::Tcp, snapshot, context) {
            problems.push(invalid);
        }
    }
    let matcher = match config.matcher.as_ref().map(parse_match).transpose() {
        Ok(matcher) => matcher,
        Err(invalid) => {
            problems.push(invalid);
            None
        }
    };
    let service = services
        .iter()
        .position(|service| service.name == config.service);
    if service.is_none() && !broken.contains(&*config.service) {
        problems.push(Invalid::new(
            "unknown_service",
            format!("tcp service {} is not declared by the app", config.service),
        ));
    }
    match service {
        Some(service) if problems.is_empty() => Ok(Router {
            name: config.name.clone(),
            entry_points: config.entry_points.clone().into_boxed_slice(),
            matcher,
            matcher_json: config.matcher.clone(),
            service,
        }),
        _ => Err(problems),
    }
}

/// The routers of one entry point that can match the same connection and nothing ranks apart
/// (`route_ambiguity`): two catch-all routers, or two with a `match` of the same specificity that are
/// not provably disjoint.
pub(super) fn detect(apps: &[App], compiled: &[L4]) -> Vec<Conflict> {
    let mut found = Vec::new();
    let mut entry_points: Vec<&str> = Vec::new();
    for l4 in compiled {
        for router in l4.tcp().routers() {
            for entry in router.entry_points() {
                if !entry_points.contains(&&**entry) {
                    entry_points.push(entry);
                }
            }
        }
    }
    for entry in entry_points {
        let routers: Vec<(usize, &Router)> = compiled
            .iter()
            .enumerate()
            .flat_map(|(index, l4)| l4.tcp().routers().iter().map(move |router| (index, router)))
            .filter(|(_, router)| router.listens_on(entry))
            .collect();
        for (at, (first_app, first)) in routers.iter().enumerate() {
            for (second_app, second) in &routers[at + 1..] {
                let overlap = first.rank() == second.rank()
                    && match (&first.matcher, &second.matcher) {
                        (Some(a), Some(b)) => !matcher::disjoint(a, b),
                        (None, None) => true,
                        _ => false,
                    };
                if overlap && found.len() < MAX_CONFLICTS {
                    let (a, b) = (&apps[*first_app], &apps[*second_app]);
                    found.push(Conflict::RouteAmbiguity {
                        host: None,
                        apps: [a.id.clone(), b.id.clone()],
                        routers: [first.name.clone(), second.name.clone()],
                        declared_by: [a.declared_by.clone(), b.declared_by.clone()],
                    });
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn context() -> CompileContext {
        CompileContext::new([("pg", Protocol::Tcp), ("web", Protocol::Http)])
    }

    fn snapshot(tcp: &Value) -> Snapshot {
        serde_json::from_value(json!({
            "version": 1,
            "tenants": [{"id": "t", "weight": 1,
                         "budget": {"max_inflight": 10, "max_buffer_bytes": 1_048_576}}],
            "entry_points": [{"name": "pg", "tenants": ["t"]}],
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "test", "tls": {"mode": "acme"},
                "routers": [], "revisions": [], "tcp": tcp,
            }],
        }))
        .expect("snapshot")
    }

    fn compiled(tcp: &Value) -> Result<Compiled, Vec<String>> {
        let snapshot = snapshot(tcp);
        let mut rejected = Vec::new();
        let result = compile(
            &snapshot.apps[0],
            &snapshot,
            &context(),
            &mut NameBudget::default(),
            &mut rejected,
        );
        if rejected.is_empty() {
            Ok(result)
        } else {
            Err(rejected
                .iter()
                .map(|rejected| format!("{}: {}", rejected.invalid.code, rejected.invalid.message))
                .collect())
        }
    }

    fn service(extra: &Value) -> Value {
        let mut value = json!({
            "name": "s", "type": "loadbalancer",
            "servers": [{ "address": "10.0.0.5:5432" }],
        });
        if let (Some(value), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
            value.extend(extra.clone());
        }
        value
    }

    fn router(extra: &Value) -> Value {
        let mut value = json!({ "name": "r", "entry_points": ["pg"], "service": "s" });
        if let (Some(value), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
            value.extend(extra.clone());
        }
        value
    }

    fn refusal(routers: &[Value], services: &[Value]) -> String {
        compiled(&json!({ "routers": routers, "services": services }))
            .expect_err("refused")
            .join("; ")
    }

    #[test]
    fn a_router_and_a_service_compile() {
        let tcp = compiled(&json!({
            "routers": [router(&json!({ "match": { "client_ip": ["10.0.0.0/8"] } }))],
            "services": [service(&json!({ "algorithm": "least_conn", "idle_timeout_secs": 5 }))],
        }))
        .expect("compiles");
        let (router, service) = tcp.route(0).expect("route");
        assert!(!router.is_catch_all());
        assert_eq!(service.idle(), Duration::from_secs(5));
        assert_eq!(service.balancer().algorithm(), Some("least_conn"));
        assert_eq!(service.balancer().servers().len(), 1);
    }

    #[test]
    fn a_dns_name_expands_through_the_balancer() {
        let tcp = compiled(&json!({
            "routers": [router(&json!({}))],
            "services": [service(&json!({
                "servers": [{ "address": "db.internal:5432" }, { "address": "10.0.0.5:5432" }]
            }))],
        }))
        .expect("compiles");
        let names: Vec<&str> = tcp.services()[0].balancer().dns_names().collect();
        assert_eq!(names, ["db.internal"]);
    }

    #[test]
    fn matches_other_than_client_ip_are_refused() {
        for bad in [
            json!({ "host": "a.test" }),
            json!({ "all": [{ "path_prefix": "/" }] }),
        ] {
            let message = refusal(&[router(&json!({ "match": bad }))], &[service(&json!({}))]);
            assert!(message.starts_with("invalid_matcher"), "{message}");
        }
        let message = refusal(
            &[router(&json!({ "match": { "sni": "a.test" } }))],
            &[service(&json!({}))],
        );
        assert!(message.starts_with("invalid_matcher"), "{message}");
    }

    #[test]
    fn planned_fields_are_refused_by_name() {
        let message = refusal(
            &[router(&json!({ "tls": { "passthrough": true } }))],
            &[service(&json!({}))],
        );
        assert!(message.starts_with("l4_not_built"), "{message}");
        for field in ["proxy_protocol", "termination_delay_ms"] {
            let message = refusal(&[router(&json!({}))], &[service(&json!({ field: 1 }))]);
            assert!(message.starts_with("service_not_built"), "{message}");
        }
        let message = refusal(
            &[router(&json!({}))],
            &[service(
                &json!({ "servers": [{ "address": "10.0.0.5:1", "tls": true }] }),
            )],
        );
        assert!(message.starts_with("service_not_built"), "{message}");
    }

    #[test]
    fn service_settings_are_checked() {
        for (extra, code) in [
            (json!({ "servers": [] }), "invalid_service"),
            (json!({ "algorithm": "ip_hash" }), "invalid_service"),
            (json!({ "algorithm": "nonsense" }), "invalid_service"),
            (json!({ "idle_timeout_secs": 0 }), "invalid_service"),
            (json!({ "idle_timeout_secs": 86_401 }), "invalid_service"),
            (
                json!({ "servers": [{ "address": "10.0.0.5:0" }] }),
                "invalid_service",
            ),
            (
                json!({ "servers": [{ "address": "db.internal:0" }] }),
                "invalid_service",
            ),
            (
                json!({ "servers": [{ "address": "no-port" }] }),
                "invalid_service",
            ),
            (
                json!({ "servers": [{ "address": "10.0.0.5:1", "weight": 2 }] }),
                "invalid_service",
            ),
            (json!({ "type": "weighted" }), "invalid_service"),
            (json!({ "type": "nonsense" }), "invalid_service"),
        ] {
            let message = refusal(&[router(&json!({}))], &[service(&extra)]);
            assert!(message.starts_with(code), "{extra}: {message}");
        }
    }

    #[test]
    fn a_router_must_name_a_service_and_a_reserved_tcp_entry_point() {
        let message = refusal(&[router(&json!({ "service": "missing" }))], &[]);
        assert!(message.starts_with("unknown_service"), "{message}");
        let message = refusal(
            &[router(&json!({ "entry_points": ["web"] }))],
            &[service(&json!({}))],
        );
        assert!(message.starts_with("entry_point_protocol"), "{message}");
        let message = refusal(
            &[router(&json!({ "entry_points": ["nowhere"] }))],
            &[service(&json!({}))],
        );
        assert!(message.starts_with("unknown_entry_point"), "{message}");
    }

    #[test]
    fn overlapping_routers_of_one_rank_are_ambiguous() {
        let tcp = |routers: &[Value]| {
            let snapshot = snapshot(&json!({
                "routers": routers, "services": [service(&json!({}))]
            }));
            let mut rejected = Vec::new();
            let l4 = crate::l4::compile(
                &snapshot.apps[0],
                &snapshot,
                &context(),
                &mut NameBudget::default(),
                &mut rejected,
            );
            assert!(rejected.is_empty());
            detect(&snapshot.apps, &[l4])
        };
        let named = |name: &str, extra: &Value| {
            let mut value = router(extra);
            value["name"] = json!(name);
            value
        };
        let ten = json!({ "match": { "client_ip": "10.0.0.0/8" } });
        let other = json!({ "match": { "client_ip": "192.168.0.0/16" } });
        let overlapping = json!({ "match": { "client_ip": "10.1.0.0/16" } });
        assert_eq!(
            tcp(&[named("x", &json!({})), named("y", &json!({}))]).len(),
            1,
            "two catch-all routers"
        );
        assert!(tcp(&[named("x", &ten), named("y", &other), named("z", &json!({}))]).is_empty());
        assert_eq!(
            tcp(&[named("x", &ten), named("y", &overlapping)]).len(),
            1,
            "two matches of one specificity that overlap"
        );
    }
}
