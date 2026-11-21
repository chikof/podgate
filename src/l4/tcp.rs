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
//! A TCP router has `entry_points`, a `service`, an optional `match` and an optional `tls`. The
//! `match` is a matcher tree of the TCP dialect: the leaves `client_ip`, `sni`, `sni_regexp` and
//! `alpn` with `all`, `any` and `not`. A router without `match` is a catch-all: it takes the
//! connections no router with a `match` takes. `tls` says the router speaks TLS:
//! `{"passthrough": true}` forwards the stream untouched, `{}` terminates it with the app's
//! certificates and forwards plain bytes; see [`super::tls`]. A router with `sni`, `sni_regexp`
//! or `alpn` needs `tls`, because only a TLS connection has a server name or protocols.
//!
//! A router without `tls` owns its entry point's tenant: the `tcp` entry point is reserved to
//! one tenant (`tenants` in its policy). A router with `tls` that names literal server names
//! (`sni`) may share an entry point between tenants, because the names tell them apart and a
//! name has one owner. Routers on one entry point are ranked by whether they have a `match` or
//! `tls`, then by specificity (exact `sni` over wildcard over `sni_regexp`, then the number of
//! other leaves); two of the same rank that can match one connection are `route_ambiguity`,
//! which makes a second catch-all one.
//!
//! A service is a `loadbalancer` of `servers` (`ip:port` or `name:port`; a name is resolved off
//! the connection path by the DNS resolver, and every answer passes the upstream address policy
//! like an HTTP server's) and an `algorithm`. It reuses the HTTP load balancer, so the balancing
//! state survives a snapshot push and a name expands into the addresses it resolves to. Only
//! the algorithms that need nothing from an HTTP request are built here: `round_robin`,
//! `weighted_round_robin`, `least_conn`, `random` and `hrw` (the client address).
//!
//! Change 0061 adds three things to it. A router's `chain` names TCP middlewares of the app
//! (`ip_allow_list`, `in_flight_conn`, see [`super::middleware`]) that every connection passes
//! before it takes a tenant slot or reaches a server. A server with `tls: true` is reached over
//! TLS with the service's `transport` (the `servers_transport` of the HTTP services), and the
//! service's `proxy_protocol` and `termination_delay_ms` are in [`super::upstream`].
//!
//! This file is the compiled model; the runtime is in `app` (the Pingora application of an entry
//! point), `copy` (the byte copy) and `stats` (the metrics), and the TLS side is in
//! [`super::tls`]. `docs/ref/l4-tcp.md`, `docs/ref/l4-tls.md` and `docs/ref/l4-middleware.md`
//! have the operator's view.

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
use super::tls::Offer;
use super::{health, middleware, upstream};
use crate::compile::{Invalid, Rejected};
use crate::conflict::Conflict;
use crate::entry::{CompileContext, Protocol};
use crate::host::{HostPattern, overlaps};
use crate::router::Matcher;
use crate::router::matcher::{self, Claim, Dialect, Spec, View};
use crate::router::rule;
use crate::service::extras::ProxyProtocolConfig;
use crate::service::resolve::{self, NameBudget};
use crate::service::{self, Lease, NamedTransport, PickCx, Transport};
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
    /// A Traefik rule over the L4 functions (`HostSNI`, `HostSNIRegexp`, `ALPN`, `ClientIP`)
    /// instead of `match`; both set is `invalid_router`. Compiled to the tree before anything else
    /// looks at the router.
    #[serde(default)]
    rule: Option<Box<str>>,
    /// `{"passthrough": true}` forwards the TLS stream untouched; `{}` terminates TLS with the
    /// app's certificates. Absent: the router does not look at TLS (and cannot match `sni`,
    /// `sni_regexp` or `alpn`).
    #[serde(default)]
    tls: Option<TlsConfig>,
    /// Names of the app's TCP middlewares (`ip_allow_list`, `in_flight_conn`), run in this order
    /// before the connection is routed to a server, the tenant takes a slot or a server is dialled.
    #[serde(default)]
    chain: Vec<Box<str>>,
}

/// What a TCP router does with TLS.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Forward the encrypted stream to the server untouched; the server completes the
    /// handshake. Default `false`: podgate terminates TLS and forwards plain bytes.
    #[serde(default)]
    passthrough: bool,
}

/// How a TLS router treats the connection's TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tls {
    /// The bytes are forwarded as they are.
    Passthrough,
    /// podgate completes the handshake with the app's certificates and forwards the plaintext.
    Terminate,
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
    /// Write a PROXY protocol header, `{"version": 1|2}`, first on every connection to a server:
    /// the client's real address and the entry point's. Absent: none.
    #[serde(default)]
    proxy_protocol: Option<ProxyProtocolConfig>,
    /// Milliseconds the server's side of a connection lives on after the client half-closed, so a
    /// late reply is not cut: 0 to 86,400,000, default 100.
    #[serde(default)]
    #[schemars(range(min = 0, max = 86_400_000))]
    termination_delay_ms: Option<u64>,
    /// The `servers_transport` of the app that reaches the servers with `tls: true`. Only its TLS
    /// fields and `dial_timeout_secs` apply to a TCP service.
    #[serde(default)]
    transport: Option<Box<str>>,
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
    /// Reach the server over TLS, with the service's `transport` (SNI, CA, client certificate).
    /// Default `false`: plain TCP.
    #[serde(default)]
    tls: Option<bool>,
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
    tls: Option<Tls>,
    /// The literal names the matcher is limited to; empty for a router that is not.
    claims: Vec<HostPattern>,
    /// The ALPN protocols the matcher names, which a handshake of this router can negotiate.
    protocols: Box<[Box<[u8]>]>,
    /// The router's `chain`, resolved to indices into the app's TCP middlewares.
    chain: Box<[usize]>,
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

    /// What the router does with TLS, `None` when it does not look at it.
    #[must_use]
    pub fn tls(&self) -> Option<Tls> {
        self.tls
    }

    /// Whether the router is limited to literal server names (`sni`), which it claims. A router
    /// that is not takes connections whatever name they carry.
    #[must_use]
    pub fn is_claimed(&self) -> bool {
        !self.claims.is_empty()
    }

    /// The middlewares the router runs before it takes a connection, as indices into
    /// [`Compiled::middlewares`], in order.
    #[must_use]
    pub fn chain(&self) -> &[usize] {
        &self.chain
    }

    /// The ALPN protocols the matcher names: what a terminating handshake can negotiate.
    fn protocols(&self) -> &[Box<[u8]>] {
        &self.protocols
    }

    /// Whether the router listens on `entry_point`.
    #[must_use]
    pub fn listens_on(&self, entry_point: &str) -> bool {
        self.entry_points.iter().any(|name| &**name == entry_point)
    }

    /// Which router wins over which: a router with a `match` or `tls` over a catch-all, then the
    /// more specific matcher.
    fn rank(&self) -> (bool, Spec) {
        (
            self.matcher.is_some() || self.tls.is_some(),
            self.matcher.as_ref().map_or(Spec::default(), Matcher::spec),
        )
    }

    /// Whether a connection from `client` with `offer` matches. `probe` is the request head the
    /// matcher interface asks for; no TCP leaf reads it. A router with `tls` takes only a
    /// connection that starts with a ClientHello.
    fn matches(
        &self,
        entry_point: &str,
        client: IpAddr,
        probe: &RequestHeader,
        offer: &Offer,
    ) -> bool {
        if self.tls.is_some() && !offer.is_tls() {
            return false;
        }
        self.matcher.as_ref().is_none_or(|matcher| {
            matcher.matches(&View {
                host: "",
                path: "/",
                entry_point,
                tls: offer.is_tls(),
                request: probe,
                client_ip: Some(client),
                hello: offer.hello(),
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
    upstream: upstream::Settings,
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

    /// The service's PROXY protocol header and termination delay.
    #[must_use]
    pub fn upstream(&self) -> &upstream::Settings {
        &self.upstream
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
    middlewares: Box<[middleware::Named]>,
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

    /// The app's TCP middlewares, the ones a router's `chain` indexes.
    #[must_use]
    pub fn middlewares(&self) -> &[middleware::Named] {
        &self.middlewares
    }

    /// [`Self::middlewares`], mutable, for the registry that carries their counts across a push.
    pub(crate) fn middlewares_mut(&mut self) -> &mut [middleware::Named] {
        &mut self.middlewares
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

    /// Every literal server name a router of the app is limited to, terminating or not.
    pub(crate) fn claims(&self) -> impl Iterator<Item = &HostPattern> {
        self.routers.iter().flat_map(|router| &router.claims)
    }

    /// The names the app's terminating routers serve: the app needs a certificate for them.
    pub(crate) fn terminated_claims(&self) -> impl Iterator<Item = &HostPattern> {
        self.routers
            .iter()
            .filter(|router| router.tls == Some(Tls::Terminate))
            .flat_map(|router| &router.claims)
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
    let transports = transports_of(app, context.spiffe());
    let mut services = Vec::with_capacity(tcp.services.len());
    let mut broken: HashSet<&str> = HashSet::new();
    for declared in &tcp.services {
        match compile_service(declared, app, context, names, &transports) {
            Ok(service) => services.push(service),
            Err(invalid) => {
                broken.insert(&declared.name);
                problem(format!("tcp service {}", declared.name), invalid);
            }
        }
    }
    let (middlewares, broken_middlewares) = middleware::compile_all(&tcp.middlewares, &mut problem);
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
        let scope = Scope {
            services: &services,
            broken_services: &broken,
            middlewares: &middlewares,
            broken_middlewares: &broken_middlewares,
        };
        match compile_router(&config, app, snapshot, context, &scope) {
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
        middlewares: middlewares.into_boxed_slice(),
    }
}

fn router_config(value: &Value) -> Result<RouterConfig, Invalid> {
    serde_json::from_value(value.clone())
        .map_err(|err| Invalid::new("invalid_router", format!("tcp router: {err}")))
}

/// The transports of `app`, compiled when a TCP service names one. A transport that does not
/// compile is replaced by the default one here and refused once, by the compile step of the HTTP
/// side, which compiles every transport of the app whether or not a service names it.
fn transports_of(app: &App, spiffe: &crate::spiffe::Spiffe) -> Vec<NamedTransport> {
    let named = app.tcp.as_ref().is_some_and(|tcp| {
        tcp.services
            .iter()
            .any(|service| service.config.contains_key("transport"))
    });
    if named {
        crate::compile::transports_of(app, spiffe, &mut Vec::new())
    } else {
        Vec::new()
    }
}

/// `host:port` as a server of the balancer: its URL (the scheme, `http` or `https`, is the
/// balancer's vocabulary for plain and TLS, and never reaches a connection) and whether the host
/// is a DNS name.
fn server_url(
    scheme: &str,
    text: &str,
    service: &str,
    app: &App,
    context: &CompileContext,
) -> Result<String, Invalid> {
    if text.parse::<SocketAddr>().is_ok() {
        let addr = super::server_address(text, service, Protocol::Tcp, app, context)?;
        return Ok(format!("{scheme}://{addr}"));
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
        Some((host, port)) => Ok(format!("{scheme}://{host}:{port}")),
        None => super::server_address(text, service, Protocol::Tcp, app, context)
            .map(|addr| format!("{scheme}://{addr}")),
    }
}

fn compile_service(
    declared: &Declared,
    app: &App,
    context: &CompileContext,
    names: &mut NameBudget,
    transports: &[NamedTransport],
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
    let config: ServiceConfig = serde_json::from_value(Value::Object(declared.config.clone()))
        .map_err(|err| invalid(err.to_string()))?;
    let upstream = upstream::Settings::compile(config.proxy_protocol, config.termination_delay_ms)?;
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
            let scheme = if server.tls == Some(true) {
                "https"
            } else {
                "http"
            };
            if server.resolve == Some(ResolveKind::Srv) {
                let mut entry =
                    json!({ "url": format!("{scheme}://{}", server.address), "resolve": "srv" });
                if let Some(weight) = server.weight {
                    entry["weight"] = json!(weight);
                }
                return Ok(entry);
            }
            let url = server_url(scheme, &server.address, &declared.name, app, context)?;
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
    if let Some(transport) = &config.transport {
        balancer.insert("transport".to_owned(), json!(transport));
    }
    let derived = Declared {
        name: declared.name.clone(),
        kind: "loadbalancer".into(),
        config: balancer,
    };
    let balancer =
        service::Service::compile(&derived, transports, None, &app.tenant, context.resolver())
            .map_err(|mut err| {
                err.message = err.message.replace("https://", "").replace("http://", "");
                err
            })?;
    if let Some(unsupported) = balancer.transport().and_then(Transport::tcp_refusal) {
        return Err(Invalid::new(
            "invalid_transport",
            format!(
                "tcp loadbalancer {}: the transport sets {unsupported}, which a TCP service cannot use (it takes the TLS fields and `dial_timeout_secs`)",
                declared.name
            ),
        ));
    }
    names.charge(&app.tenant, &app.id, balancer.dns_names())?;
    names.charge_srv(&app.tenant, &app.id, balancer.srv_names())?;
    Ok(Service {
        name: declared.name.clone(),
        balancer,
        idle: Duration::from_secs(u64::from(idle)),
        health,
        upstream,
    })
}

/// Parses the `match` of a TCP router: the TCP dialect of the matcher grammar.
fn parse_match(value: &Value) -> Result<Matcher, Invalid> {
    matcher::parse_in(Dialect::Tcp, value)
        .map_err(|err| Invalid::new(err.code, format!("tcp router match: {err}")))
}

/// The literal names `matcher` is limited to; empty when it is not limited to literal names:
/// no `sni`, or one that is `any` of a literal name and a regular expression, which takes names
/// no literal claim bounds (an `sni_regexp` in an `all` with a literal one only narrows it).
fn literal_claims(matcher: &Matcher) -> Vec<HostPattern> {
    let claims = matcher.claims().unwrap_or_default();
    let literal: Vec<HostPattern> = claims
        .iter()
        .filter_map(|claim| match claim {
            Claim::Pattern(pattern) => Some(pattern.clone()),
            Claim::Regexp => None,
        })
        .collect();
    if literal.len() == claims.len() {
        literal
    } else {
        Vec::new()
    }
}

/// What the names of a router resolve to in its app: the compiled services and middlewares, and
/// the names of those that did not compile (the problem is already reported).
struct Scope<'a> {
    services: &'a [Service],
    broken_services: &'a HashSet<&'a str>,
    middlewares: &'a [middleware::Named],
    broken_middlewares: &'a HashSet<&'a str>,
}

fn compile_router(
    config: &RouterConfig,
    app: &App,
    snapshot: &Snapshot,
    context: &CompileContext,
    scope: &Scope<'_>,
) -> Result<Router, Vec<Invalid>> {
    let mut problems = Vec::new();
    let tls = config.tls.as_ref().map(|tls| {
        if tls.passthrough {
            Tls::Passthrough
        } else {
            Tls::Terminate
        }
    });
    let source = match rule::resolve_tcp(config.matcher.as_ref(), config.rule.as_deref()) {
        Ok(source) => source,
        Err(invalid) => {
            problems.push(invalid);
            None
        }
    };
    let matcher = match source.as_ref().map(parse_match).transpose() {
        Ok(matcher) => matcher,
        Err(invalid) => {
            problems.push(invalid);
            None
        }
    };
    if tls.is_none() && matcher.as_ref().is_some_and(Matcher::reads_hello) {
        problems.push(Invalid::new(
            "invalid_router",
            "the match uses `sni`, `sni_regexp` or `alpn`, which read the TLS ClientHello: the router needs `tls` (`{\"passthrough\": true}` to forward the stream, `{}` to terminate it)",
        ));
    }
    let claims = matcher.as_ref().map(literal_claims).unwrap_or_default();
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
        } else if tls.is_none() {
            problems.extend(super::reserve(app, name, Protocol::Tcp, snapshot, context));
        } else {
            match super::access(app, name, Protocol::Tcp, snapshot, context) {
                Err(invalid) => problems.push(invalid),
                Ok(exclusive) => {
                    if claims.is_empty() && !exclusive && !context.allows_catch_all(&app.tenant) {
                        problems.push(Invalid::new(
                            "catch_all_not_allowed",
                            format!(
                                "the router can take a connection whatever server name it carries, so on entry point {name}, which other tenants may use, it could capture their names; add a literal `sni` in an `all`, attach it only to an entry point whose tenants policy names this tenant alone, or ask the operator to list the tenant in CATCH_ALL_TENANTS"
                            ),
                        ));
                    }
                }
            }
        }
    }
    let service = scope
        .services
        .iter()
        .position(|service| service.name == config.service);
    if service.is_none() && !scope.broken_services.contains(&*config.service) {
        problems.push(Invalid::new(
            "unknown_service",
            format!("tcp service {} is not declared by the app", config.service),
        ));
    }
    let mut chain = Vec::with_capacity(config.chain.len());
    for (at, name) in config.chain.iter().enumerate() {
        if config.chain[..at].contains(name) {
            problems.push(Invalid::new(
                "duplicate_name",
                format!("tcp middleware {name} is listed twice in the chain"),
            ));
        } else if let Some(index) = scope
            .middlewares
            .iter()
            .position(|named| named.name == *name)
        {
            chain.push(index);
        } else if !scope.broken_middlewares.contains(&**name) {
            problems.push(Invalid::new(
                "unknown_middleware_ref",
                format!("tcp middleware {name} is not declared by the app"),
            ));
        }
    }
    match service {
        Some(service) if problems.is_empty() => Ok(Router {
            name: config.name.clone(),
            entry_points: config.entry_points.clone().into_boxed_slice(),
            protocols: matcher
                .as_ref()
                .map(|matcher| {
                    matcher
                        .alpn_protocols()
                        .into_iter()
                        .map(Box::from)
                        .collect()
                })
                .unwrap_or_default(),
            matcher,
            matcher_json: source,
            service,
            tls,
            claims,
            chain: chain.into_boxed_slice(),
        }),
        _ => Err(problems),
    }
}

/// The routers of one entry point that can match the same connection and nothing ranks apart
/// (`route_ambiguity`): two catch-all routers, or two with a `match` of the same specificity that
/// are not provably disjoint; and two tenants' routers that can take any server name on a
/// shared entry point (`cross_tenant_catch_all`).
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
                let (a, b) = (&apps[*first_app], &apps[*second_app]);
                if found.len() >= MAX_CONFLICTS {
                    continue;
                }
                // Two tenants that claim a common name are `host_conflict` (or
                // `cross_tenant_wildcard`) already; the same pair is not also ambiguous.
                if a.tenant != b.tenant
                    && first
                        .claims
                        .iter()
                        .any(|left| second.claims.iter().any(|right| overlaps(left, right)))
                {
                    continue;
                }
                if a.tenant != b.tenant && !first.is_claimed() && !second.is_claimed() {
                    found.push(Conflict::CrossTenantCatchAll {
                        tenants: [a.tenant.clone(), b.tenant.clone()],
                        apps: [a.id.clone(), b.id.clone()],
                        routers: [first.name.clone(), second.name.clone()],
                        declared_by: [a.declared_by.clone(), b.declared_by.clone()],
                    });
                    continue;
                }
                let overlap = first.rank() == second.rank()
                    && match (&first.matcher, &second.matcher) {
                        (Some(a), Some(b)) => !matcher::disjoint(a, b),
                        _ => true,
                    };
                if overlap {
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
    fn matches_other_than_the_tcp_dialect_are_refused() {
        for bad in [
            json!({ "host": "a.test" }),
            json!({ "all": [{ "path_prefix": "/" }] }),
            json!({ "not": { "header": { "name": "x" } } }),
        ] {
            let message = refusal(&[router(&json!({ "match": bad }))], &[service(&json!({}))]);
            assert!(message.starts_with("invalid_matcher"), "{message}");
        }
    }

    #[test]
    fn a_hello_leaf_needs_tls() {
        for leaf in [
            json!({ "sni": "a.test" }),
            json!({ "sni_regexp": "a" }),
            json!({ "alpn": "h2" }),
            json!({ "all": [{ "client_ip": "10.0.0.0/8" }, { "not": { "alpn": "h2" } }] }),
        ] {
            let message = refusal(&[router(&json!({ "match": leaf }))], &[service(&json!({}))]);
            assert!(message.starts_with("invalid_router"), "{leaf}: {message}");
        }
        for tls in [json!({}), json!({ "passthrough": true })] {
            let tcp = compiled(&json!({
                "routers": [router(&json!({ "match": { "sni": "a.test" }, "tls": tls }))],
                "services": [service(&json!({}))],
            }))
            .expect("compiles");
            assert!(tcp.routers()[0].tls().is_some());
        }
        let message = refusal(
            &[router(&json!({ "tls": { "passthru": true } }))],
            &[service(&json!({}))],
        );
        assert!(message.starts_with("invalid_router"), "{message}");
    }

    #[test]
    fn routers_rank_by_the_most_specific_name_leaf() {
        let tcp = compiled(&json!({
            "routers": [
                router(&json!({ "name": "plain" })),
                router(&json!({ "name": "tls", "tls": {} })),
                router(&json!({ "name": "regexp", "tls": {}, "match": { "sni_regexp": "a" } })),
                router(&json!({ "name": "wild", "tls": {}, "match": { "sni": "*.a.test" } })),
                router(&json!({ "name": "exact", "tls": {}, "match": { "sni": "x.a.test" } })),
                router(&json!({ "name": "alpn", "tls": {},
                    "match": { "all": [{ "sni": "x.a.test" }, { "alpn": "h2" }] } })),
            ],
            "services": [service(&json!({}))],
        }))
        .expect("compiles");
        let mut ranked: Vec<_> = tcp.routers().iter().collect();
        ranked.sort_by_key(|router| std::cmp::Reverse(router.rank()));
        let names: Vec<&str> = ranked.iter().map(|router| router.name()).collect();
        assert_eq!(names, ["alpn", "exact", "wild", "regexp", "tls", "plain"]);
        let claimed: Vec<bool> = ranked.iter().map(|router| router.is_claimed()).collect();
        assert_eq!(claimed, [true, true, true, false, false, false]);
    }

    #[test]
    fn a_router_chain_resolves_to_the_declared_middlewares() {
        let middleware = |name: &str, kind: &str, config: Value| {
            let mut value = json!({ "name": name, "type": kind });
            if let (Some(value), Some(config)) = (value.as_object_mut(), config.as_object()) {
                value.extend(config.clone());
            }
            value
        };
        let tcp = |chain: Value, middlewares: Vec<Value>| {
            compiled(&json!({
                "routers": [router(&json!({ "chain": chain }))],
                "services": [service(&json!({}))],
                "middlewares": middlewares,
            }))
        };
        let list = middleware(
            "office",
            "ip_allow_list",
            json!({ "source_range": ["10.0.0.0/8"] }),
        );
        let cap = middleware("cap", "in_flight_conn", json!({ "amount": 3 }));
        let ok = tcp(json!(["cap", "office"]), vec![list.clone(), cap.clone()]).expect("compiles");
        assert_eq!(
            ok.routers()[0].chain(),
            [1, 0],
            "in the order the router lists them"
        );
        assert_eq!(ok.middlewares().len(), 2);
        let message = |chain: Value, middlewares: Vec<Value>| {
            tcp(chain, middlewares).expect_err("refused").join("; ")
        };
        assert!(
            message(json!(["missing"]), vec![list.clone()]).starts_with("unknown_middleware_ref"),
            "an unknown name"
        );
        assert!(
            message(json!(["office", "office"]), vec![list.clone()]).starts_with("duplicate_name"),
            "a name listed twice"
        );
        let broken = middleware("office", "ip_allow_list", json!({ "source_range": [] }));
        let broken_only = message(json!(["office"]), vec![broken]);
        assert!(
            broken_only.starts_with("invalid_middleware")
                && !broken_only.contains("unknown_middleware_ref"),
            "a router naming a middleware that does not compile adds no second problem: {broken_only}"
        );
        let http = middleware("h", "headers", json!({}));
        assert!(message(json!([]), vec![http]).starts_with("invalid_middleware"));
        let twice = message(json!([]), vec![list.clone(), list]);
        assert!(twice.starts_with("duplicate_name"), "{twice}");
    }

    #[test]
    fn upstream_settings_are_checked() {
        for extra in [
            json!({ "proxy_protocol": { "version": 3 } }),
            json!({ "proxy_protocol": { "version": 0 } }),
            json!({ "proxy_protocol": { "version": 2, "extra": 1 } }),
            json!({ "proxy_protocol": 2 }),
            json!({ "termination_delay_ms": 86_400_001_u64 }),
            json!({ "termination_delay_ms": -1 }),
            json!({ "transport": "missing" }),
            json!({ "servers": [{ "address": "10.0.0.5:1", "tls": "yes" }] }),
        ] {
            let message = refusal(&[router(&json!({}))], &[service(&extra)]);
            assert!(
                message.starts_with("invalid_service") || message.starts_with("unknown_transport"),
                "{extra}: {message}"
            );
        }
        let tcp = compiled(&json!({
            "routers": [router(&json!({}))],
            "services": [service(&json!({
                "proxy_protocol": { "version": 1 },
                "termination_delay_ms": 0,
                "servers": [{ "address": "10.0.0.5:5432", "tls": true }],
            }))],
        }))
        .expect("compiles");
        let upstream = tcp.services()[0].upstream();
        assert_eq!(upstream.proxy_protocol(), Some(1));
        assert_eq!(upstream.termination_delay(), Duration::ZERO);
        assert!(tcp.services()[0].balancer().servers()[0].tls);
        let plain = compiled(&json!({
            "routers": [router(&json!({}))],
            "services": [service(&json!({}))],
        }))
        .expect("compiles");
        let upstream = plain.services()[0].upstream();
        assert_eq!(upstream.proxy_protocol(), None);
        assert_eq!(upstream.termination_delay(), Duration::from_millis(100));
        assert!(!plain.services()[0].balancer().servers()[0].tls);
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
