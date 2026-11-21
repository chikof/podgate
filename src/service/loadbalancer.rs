//! The `loadbalancer` service: a set of servers and an algorithm that picks one per request.
//!
//! ```json
//! { "name": "web", "type": "loadbalancer", "algorithm": "round_robin",
//!   "servers": [ { "url": "http://10.0.0.5:8080" }, { "url": "http://app.internal:8080" } ] }
//! ```
//!
//! `servers` may be empty: the service then has no server, and a `scale_to_zero` app wakes on
//! the first request. Built today: `http://host:port`, `https://host:port` and `h2c://host:port`
//! (cleartext HTTP/2 by prior knowledge, for gRPC) servers, `host` being an IP address or a DNS
//! name (see below), and the algorithms `round_robin`,
//! `weighted_round_robin`, `least_conn`, `p2c_ewma`, `random`,
//! `ip_hash`, `uri_hash`, `header_hash` and `hrw` (see [`super::lb`]); `algorithm` is a name or
//! an object such as `{"type": "header_hash", "header": "x-tenant"}`. Only
//! `weighted_round_robin` and the hashing algorithms take server weights, and a weight of `0`
//! there means the server receives nothing. A server is reached through the service's
//! `transport` (`transport.rs`): TLS settings for `https://`, HTTP/2 and timeouts for all.
//! `health_check` probes the servers ([`super::health`]), `passive` ejects servers that fail real
//! requests ([`super::outlier`]), `sticky` pins a client to one server by cookie
//! ([`super::sticky`]), and a service declares at most 256 servers. Planned fields (a `false`
//! `pass_host_header`) are refused with `service_not_built`, and so is an HTTP `health_check` on
//! a service with an `h2c://` server (the probe speaks HTTP/1.1).
//!
//! # Servers named by DNS
//!
//! A server whose host is a name is an *entry* that expands into one [`Server`] per address its
//! name resolves to (`http://app.internal:8080` becomes `10.0.0.5:8080` and `10.0.0.6:8080`,
//! each with the entry's weight and scheme). The compiler resolves nothing: [`super::resolve`] keeps the
//! answers fresh and [`LoadBalancer::refresh`] rebuilds the list and the algorithm from them
//! when they change. The list a pick reads is swapped atomically, so a request in flight keeps
//! the servers it chose from. A name that has not resolved yet expands into nothing, and a
//! service with only such names answers `503` (it is still backed, so it never counts as
//! asleep). The balancer holds addresses the upstream policy has already passed; a name never
//! reaches a connection.
//!
//! The runtime state of the servers (`healthy`, `ejected_until_ms`, `active`, `ewma_us`) and of
//! the service (its turn counter) is in [`super::state`], outside the table, so a push that
//! leaves the service alone keeps it. `pick` of every balancer reads [`Server::available`] and
//! nothing else about health.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::slice;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;
use serde_json::Value;

use super::graph::Readiness;
use super::health::{self, Check};
use super::lb::{Balancer, MAX_SERVICE_POINTS, PickCx, WeightUse};
use super::outlier::Passive;
use super::resolve::{self, Resolver, srv};
use super::state::{self, Lease, ServerState, ServiceState};
use super::sticky::Sticky;
use super::transport::{self, Transport, Upstream};
use crate::compile::Invalid;
use podgate_model::{Declared, SkewSecret};

/// The configuration of a `loadbalancer`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    servers: Vec<ServerConfig>,
    #[serde(default)]
    #[schemars(schema_with = "super::lb::algorithm_schema")]
    algorithm: Option<Value>,
    #[serde(default)]
    #[schemars(with = "Option<super::health::Config>")]
    health_check: Option<Value>,
    #[serde(default)]
    #[schemars(with = "Option<super::outlier::Config>")]
    passive: Option<Value>,
    #[serde(default)]
    #[schemars(with = "Option<super::sticky::Config>")]
    sticky: Option<Value>,
    #[serde(default)]
    pass_host_header: Option<bool>,
    #[serde(default)]
    transport: Option<Box<str>>,
}

/// How the host of a server's URL is resolved.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ResolveKind {
    /// `A` and `AAAA` records: the host is a server name and the URL carries the port.
    A,
    /// An `SRV` record: the host is the full owner name (`_web._tcp.shop.service.consul`), the
    /// URL has no port, and the targets, ports, priorities and weights come from DNS.
    Srv,
}

/// One server as declared.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    /// `http://host:port` or `https://host:port`. `host` is an IP address or a DNS name, which
    /// podgate resolves again on the record's TTL and checks against the upstream address
    /// policy on every answer. With `resolve: "srv"` it is `http://owner.name` without a port.
    url: String,
    #[serde(default)]
    weight: Option<u32>,
    /// `a` (the default) or `srv`.
    #[serde(default)]
    resolve: Option<ResolveKind>,
}

/// One upstream server of a load balancer.
#[derive(Debug, Clone)]
pub struct Server {
    /// The URL as declared; for a server named by DNS, the URL of the name, the same for every
    /// address the name resolves to.
    pub url: Box<str>,
    /// The address to connect to.
    pub addr: SocketAddr,
    /// Whether the server is reached over TLS (`https://`).
    pub tls: bool,
    /// Whether the server is reached by cleartext HTTP/2 with prior knowledge (`h2c://`). Never
    /// together with `tls`.
    pub h2c: bool,
    /// The relative weight, `1` by default; only `weighted_round_robin` uses it, and there `0`
    /// means no requests.
    pub weight: u32,
    /// The state the balancer and its helpers share; shared with the previous table's server of
    /// the same service, see [`super::state`].
    pub state: Arc<ServerState>,
}

/// The host of `url` (`scheme://host:port`), brackets of an IPv6 literal removed.
fn host_of(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    let (host, _port) = authority.rsplit_once(':')?;
    Some(host.trim_start_matches('[').trim_end_matches(']'))
}

impl Server {
    /// Whether the server may take a new request: healthy and not ejected.
    #[must_use]
    pub fn available(&self) -> bool {
        self.state.available()
    }

    /// The DNS name of the server's URL, as declared; `None` for an IP address, which is
    /// dialled as it is.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        host_of(&self.url).filter(|host| host.parse::<IpAddr>().is_err())
    }

    /// The name to present as TLS server name (SNI) and to verify the certificate against: the
    /// URL's DNS name in lower case without a trailing dot, `None` for an IP address.
    #[must_use]
    pub fn sni_name(&self) -> Option<String> {
        let host = self.host()?;
        Some(host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase())
    }

    /// What tells this server from the others of its service: the URL, and for a server named by
    /// DNS the address too, since every address of a name has the same URL.
    #[must_use]
    pub fn identity(&self) -> Cow<'_, str> {
        if self.host().is_some() {
            Cow::Owned(format!("{}@{}", self.url, self.addr))
        } else {
            Cow::Borrowed(&*self.url)
        }
    }
}

/// The servers of a service at one moment. A service whose servers are named by DNS swaps its
/// list when an answer changes; this keeps the list it was taken from alive and unchanged for as
/// long as it is held, so hold it for one use, not across requests.
#[derive(Debug, Clone, Default)]
pub struct Servers(Option<Arc<Live>>);

impl Deref for Servers {
    type Target = [Server];

    fn deref(&self) -> &[Server] {
        self.0.as_ref().map_or(&[], |live| &live.servers)
    }
}

impl<'a> IntoIterator for &'a Servers {
    type Item = &'a Server;
    type IntoIter = slice::Iter<'a, Server>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The servers a balancer picks from and the algorithm compiled for exactly them.
#[derive(Debug)]
struct Live {
    servers: Box<[Server]>,
    balancer: Arc<Balancer>,
}

/// Where a declared server is.
#[derive(Debug, Clone)]
enum Target {
    Addr(SocketAddr),
    Name {
        host: Box<str>,
        port: u16,
    },
    /// The owner name of an `SRV` record, whose targets are the servers.
    Srv {
        owner: Box<str>,
    },
}

/// One server as declared and parsed.
#[derive(Debug, Clone)]
struct Entry {
    url: Box<str>,
    tls: bool,
    h2c: bool,
    weight: u32,
    target: Target,
}

/// Who resolves the names of a service and for whom.
#[derive(Debug)]
struct Dns {
    tenant: Box<str>,
    resolver: Resolver,
}

/// A compiled `loadbalancer`.
#[derive(Debug)]
pub struct LoadBalancer {
    entries: Box<[Entry]>,
    live: ArcSwap<Live>,
    algorithm: Option<Value>,
    dns: Option<Dns>,
    /// Whether the algorithm builds a ring, which a service with names is charged for at its
    /// largest.
    ring: bool,
    /// How the algorithm takes the weights of SRV records.
    weight_use: WeightUse,
    shared: Arc<ServiceState>,
    fingerprint: u64,
    transport: Arc<Transport>,
    health: Option<Arc<Check>>,
    passive: Option<Passive>,
    sticky: Option<Sticky>,
}

fn not_built(what: &str) -> Invalid {
    Invalid::new(
        "service_not_built",
        format!("loadbalancer {what} is planned and not built yet"),
    )
}

const EXPECTED: &str = "expected http://host:port, https://host:port or h2c://host:port";

/// Parses `http://host:port`, `https://host:port` and `h2c://host:port`, `host` an IP address or
/// a DNS name; with `resolve: "srv"`, `http://owner.name`, `https://owner.name` or
/// `h2c://owner.name` without a port.
fn parse_server(config: &ServerConfig) -> Result<Entry, Invalid> {
    let url = config.url.as_str();
    let invalid = |why: &str| Invalid::new("invalid_service", format!("server {url}: {why}"));
    let (rest, tls, h2c) = match url.split_once("://") {
        Some(("http", rest)) => (rest, false, false),
        Some(("https", rest)) => (rest, true, false),
        Some(("h2c", rest)) => (rest, false, true),
        _ => return Err(invalid(EXPECTED)),
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let target = if config.resolve == Some(ResolveKind::Srv) {
        if config.weight.is_some() {
            return Err(invalid(
                "a weight is set by the SRV records, not by the snapshot",
            ));
        }
        if rest.contains(':') {
            return Err(invalid(
                "an SRV server has no port in its URL, the records choose it: write scheme://owner.name",
            ));
        }
        if !resolve::is_host_name(rest) {
            return Err(invalid(&format!("{rest:?} is not a valid SRV owner name")));
        }
        let owner = rest.strip_suffix('.').unwrap_or(rest);
        Target::Srv {
            owner: owner.to_ascii_lowercase().into(),
        }
    } else {
        match rest.parse::<SocketAddr>() {
            Ok(addr) => Target::Addr(addr),
            Err(_) => {
                let (host, port) = rest
                    .rsplit_once(':')
                    .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
                    .filter(|(host, _)| !host.is_empty() && !host.starts_with('['))
                    .ok_or_else(|| invalid(EXPECTED))?;
                if !resolve::is_host_name(host) {
                    return Err(invalid(&format!("{host:?} is not a valid host name")));
                }
                let host = host.strip_suffix('.').unwrap_or(host);
                Target::Name {
                    host: host.to_ascii_lowercase().into(),
                    port,
                }
            }
        }
    };
    Ok(Entry {
        url: url.into(),
        tls,
        h2c,
        weight: config.weight.unwrap_or(1),
        target,
    })
}

impl Entry {
    fn literal(&self, addr: SocketAddr, state: Arc<ServerState>) -> Server {
        Server {
            url: self.url.clone(),
            addr,
            tls: self.tls,
            h2c: self.h2c,
            weight: self.weight,
            state,
        }
    }
}

impl LoadBalancer {
    pub(super) fn compile(
        declared: &Declared,
        transports: &[transport::Named],
        tenant: &str,
        resolver: &Resolver,
    ) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| Invalid::new("invalid_service", format!("loadbalancer: {err}")))?;
        let health = config
            .health_check
            .as_ref()
            .map(|value| Check::compile(value).map(Arc::new))
            .transpose()?;
        if config.servers.len() > health::MAX_SERVERS {
            return Err(Invalid::new(
                "invalid_service",
                format!(
                    "loadbalancer declares {} servers, at most {} are allowed",
                    config.servers.len(),
                    health::MAX_SERVERS
                ),
            ));
        }
        let passive = config.passive.as_ref().map(Passive::compile).transpose()?;
        let sticky = config.sticky.as_ref().map(Sticky::compile).transpose()?;
        let transport = match config.transport.as_deref() {
            Some(name) => transport::find(transports, name)?,
            None => Arc::new(Transport::default()),
        };
        if config.pass_host_header == Some(false) {
            return Err(not_built("pass_host_header: false"));
        }
        let entries: Box<[Entry]> = config
            .servers
            .iter()
            .map(parse_server)
            .collect::<Result<_, _>>()?;
        if entries.iter().any(|entry| entry.h2c) {
            if health.is_some() {
                return Err(not_built(
                    "health_check on an h2c:// server (the probe speaks HTTP/1.1)",
                ));
            }
            if transport.has_tls_settings() {
                return Err(Invalid::new(
                    "invalid_transport",
                    "the transport sets TLS options and a server is h2c:// (cleartext)",
                ));
            }
            if transport.disables_http2() {
                return Err(Invalid::new(
                    "invalid_transport",
                    "the transport sets http2: false and a server is h2c:// (HTTP/2 only)",
                ));
            }
        } else if !entries.iter().all(|entry| entry.tls) && transport.has_tls_settings() {
            return Err(Invalid::new(
                "invalid_service",
                "the transport sets TLS options and a server is plain http://",
            ));
        }
        // The proxy picks a server by address: one address has one scheme.
        for (index, entry) in entries.iter().enumerate() {
            let Target::Addr(addr) = entry.target else {
                continue;
            };
            if entries[..index].iter().any(|earlier| {
                matches!(earlier.target, Target::Addr(other) if other == addr)
                    && (earlier.tls != entry.tls || earlier.h2c != entry.h2c)
            }) {
                return Err(Invalid::new(
                    "invalid_service",
                    format!(
                        "server {}: the address is also a server with another scheme",
                        entry.url
                    ),
                ));
            }
        }
        // The algorithm must accept the weights whatever the names resolve to, so it is checked
        // once against a stand-in address for each name.
        let probe: Vec<Server> = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let port = match &entry.target {
                    Target::Addr(addr) => return entry.literal(*addr, Arc::default()),
                    Target::Name { port, .. } => *port,
                    Target::Srv { .. } => 1,
                };
                entry.literal(
                    SocketAddr::new(
                        // 192.0.2.0/24 is TEST-NET-1; it is never dialled, only weighed.
                        IpAddr::V4(Ipv4Addr::new(192, 0, 2, u8::try_from(index).unwrap_or(0))),
                        port,
                    ),
                    Arc::default(),
                )
            })
            .collect();
        let probed = Arc::new(Balancer::compile(config.algorithm.as_ref(), &probe)?);
        let named = entries
            .iter()
            .any(|entry| matches!(entry.target, Target::Name { .. } | Target::Srv { .. }));
        let mut balancer = Self {
            ring: named && probed.ring_points() > 0,
            weight_use: probed.weight_use(),
            live: ArcSwap::from_pointee(Live {
                servers: Box::default(),
                balancer: Arc::clone(&probed),
            }),
            entries,
            algorithm: config.algorithm,
            dns: named.then(|| Dns {
                tenant: tenant.into(),
                resolver: resolver.clone(),
            }),
            shared: Arc::default(),
            fingerprint: state::fingerprint(declared),
            transport,
            health,
            passive,
            sticky,
        };
        if !named {
            // Every address is literal, so the probe list is the server list and its ring is the
            // real one: building it again costs as much as the first time (ketama dominates).
            balancer.live = ArcSwap::from_pointee(Live {
                servers: probe.into(),
                balancer: probed,
            });
            return Ok(balancer);
        }
        // Whatever the names have resolved to so far. When the algorithm cannot take those
        // addresses (a ring heavier than the cap), the names stay unresolved: the answer of a
        // resolver must not decide whether a snapshot compiles.
        let mut servers = balancer.expand(&[], true);
        let compiled = match Balancer::compile(balancer.algorithm.as_ref(), &servers) {
            Ok(compiled) => compiled,
            Err(err) if named => {
                tracing::warn!(err = %err.message, "a DNS answer cannot be balanced, starting without it");
                servers = balancer.expand(&[], false);
                Balancer::compile(balancer.algorithm.as_ref(), &servers)?
            }
            Err(err) => return Err(err),
        };
        balancer.live = ArcSwap::from_pointee(Live {
            servers: servers.into(),
            balancer: Arc::new(compiled),
        });
        Ok(balancer)
    }

    /// The servers the entries stand for now, in declaration order. With `names`, each name is
    /// expanded into the addresses the tenant may use. `current` supplies the state of servers
    /// that stay.
    fn expand(&self, current: &[Server], names: bool) -> Vec<Server> {
        let mut servers: Vec<Server> = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            match &entry.target {
                Target::Addr(addr) => {
                    let state = current
                        .iter()
                        .find(|server| server.url == entry.url && server.addr == *addr)
                        .map(|server| Arc::clone(&server.state))
                        .unwrap_or_default();
                    servers.push(entry.literal(*addr, state));
                }
                Target::Name { host, port } => {
                    let Some(dns) = self.dns.as_ref().filter(|_| names) else {
                        continue;
                    };
                    for ip in dns.resolver.peek(&dns.tenant, host) {
                        let addr = SocketAddr::new(ip, *port);
                        // Two names (or a name and a literal) may share an address; the proxy
                        // finds a server by address, so it is listed once.
                        if servers.len() >= health::MAX_SERVERS
                            || servers.iter().any(|server| server.addr == addr)
                        {
                            continue;
                        }
                        let state = self.shared.named_state(&entry.url, addr);
                        servers.push(entry.literal(addr, state));
                    }
                }
                Target::Srv { owner } => {
                    let Some(dns) = self.dns.as_ref().filter(|_| names) else {
                        continue;
                    };
                    let resolved = dns.resolver.peek_srv(&dns.tenant, owner);
                    let mut weights: Vec<u32> = resolved.iter().map(|found| found.weight).collect();
                    match self.weight_use {
                        WeightUse::Ignored => weights.fill(1),
                        WeightUse::Exact => {}
                        WeightUse::Total(cap) => srv::fit(&mut weights, cap),
                    }
                    for (found, weight) in resolved.iter().zip(weights) {
                        if servers.len() >= health::MAX_SERVERS
                            || servers.iter().any(|server| server.addr == found.addr)
                        {
                            continue;
                        }
                        let state = self.shared.named_state(&entry.url, found.addr);
                        let mut server = entry.literal(found.addr, state);
                        server.weight = weight;
                        servers.push(server);
                    }
                }
            }
        }
        servers
    }

    /// Takes the addresses the resolver has now. Returns whether the servers the balancer picks
    /// from changed. A service without names does nothing.
    pub(super) fn refresh(&self) -> bool {
        if self.dns.is_none() {
            return false;
        }
        let current = self.live.load_full();
        let servers = self.expand(&current.servers, true);
        let same_addrs = servers.len() == current.servers.len()
            && servers.iter().zip(&current.servers).all(|(new, old)| {
                new.addr == old.addr && new.url == old.url && new.weight == old.weight
            });
        let same_states = same_addrs
            && servers
                .iter()
                .zip(&current.servers)
                .all(|(new, old)| Arc::ptr_eq(&new.state, &old.state));
        if same_states {
            return false;
        }
        let balancer = if same_addrs {
            Arc::clone(&current.balancer)
        } else {
            match Balancer::compile(self.algorithm.as_ref(), &servers) {
                Ok(balancer) => Arc::new(balancer),
                Err(err) => {
                    tracing::warn!(err = %err.message, "a DNS answer cannot be balanced, keeping the previous servers");
                    return false;
                }
            }
        };
        self.shared.retain_named(&servers);
        self.live.store(Arc::new(Live {
            servers: servers.into(),
            balancer,
        }));
        !same_addrs
    }

    /// The servers, in declaration order, names expanded into their addresses.
    #[must_use]
    pub fn servers(&self) -> Servers {
        Servers(Some(self.live.load_full()))
    }

    /// The `passive` outlier detection setting, if the service has one.
    #[must_use]
    pub fn passive(&self) -> Option<&Passive> {
        self.passive.as_ref()
    }

    /// The points of the hash ring of the service, `0` without one. A service whose servers are
    /// named by DNS counts the largest ring it could ever hold.
    #[must_use]
    pub fn ring_points(&self) -> u64 {
        if self.ring {
            MAX_SERVICE_POINTS
        } else {
            self.live.load().balancer.ring_points()
        }
    }

    /// The name of the algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        self.live.load().balancer.name()
    }

    /// The distinct DNS names the servers use, as written in lower case.
    pub fn dns_names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().filter_map(|entry| match &entry.target {
            Target::Name { host, .. } => Some(&**host),
            Target::Addr(_) | Target::Srv { .. } => None,
        })
    }

    /// The distinct SRV owner names the servers use, as written in lower case.
    pub fn srv_names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().filter_map(|entry| match &entry.target {
            Target::Srv { owner } => Some(&**owner),
            Target::Addr(_) | Target::Name { .. } => None,
        })
    }

    /// Whether the service has a server declared, even one whose name has no address yet: a
    /// revision with such a service is not asleep.
    #[must_use]
    pub fn is_backed(&self) -> bool {
        !self.entries.is_empty()
    }

    /// The transport every `https://` server of the service is reached through.
    #[must_use]
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Runs `f` on the server at `addr` and the transport that reaches it. `None` when the
    /// service has no such server.
    pub fn with_upstream<R>(
        &self,
        addr: SocketAddr,
        f: impl FnOnce(Upstream<'_>) -> R,
    ) -> Option<R> {
        let live = self.live.load();
        let server = live.servers.iter().find(|server| server.addr == addr)?;
        Some(f(Upstream {
            server,
            transport: &self.transport,
        }))
    }

    /// Whether some `https://` server skips certificate verification.
    #[must_use]
    pub fn skips_tls_verification(&self) -> bool {
        self.transport.insecure_skip_verify() && self.entries.iter().any(|entry| entry.tls)
    }

    /// How the service can take `cx`: `Ready` when some server that has a weight is allowed,
    /// `Asleep` when it declares no server at all, `Down` when it declares servers and none may
    /// take the request. A server named by DNS whose name has no address yet is declared: the
    /// service is `Down` (it answers `503` and wakes nothing), as `is_backed` says. The rule a
    /// `weighted` or `failover` parent and the revision split share.
    #[must_use]
    pub fn readiness(&self, cx: PickCx<'_>) -> Readiness {
        if self.entries.is_empty() {
            Readiness::Asleep
        } else if self
            .live
            .load()
            .servers
            .iter()
            .any(|server| server.weight > 0 && cx.allows(server))
        {
            Readiness::Ready
        } else {
            Readiness::Down
        }
    }

    /// The first server declared that cannot speak HTTP/2: a plain `http://` one, or an
    /// `https://` one whose transport says `http2: false`. An `h2c://` server and an `https://`
    /// server that is offered `h2` can; a gRPC route needs every server to.
    #[must_use]
    pub fn http1_only_server(&self) -> Option<&str> {
        let offered = !self.transport.disables_http2();
        self.entries
            .iter()
            .find(|entry| !(entry.h2c || (entry.tls && offered)))
            .map(|entry| &*entry.url)
    }

    /// The address of the server a new request goes to, with the [`Lease`] that counts the
    /// request on it until dropped. Lock-free and allocation-free.
    #[must_use]
    pub fn pick(&self, cx: PickCx<'_>) -> Option<(SocketAddr, Lease)> {
        let live = self.live.load();
        let index = match self
            .sticky
            .as_ref()
            .and_then(|sticky| sticky.pinned(cx, &live.servers))
        {
            Some(index) => index,
            None => live.balancer.pick(cx, &live.servers, &self.shared)?,
        };
        let server = live.servers.get(index)?;
        Some((
            server.addr,
            Lease::take(&server.state, live.balancer.observe()),
        ))
    }

    /// The compiled `health_check`, when the service has one.
    #[must_use]
    pub fn health_check(&self) -> Option<&Arc<Check>> {
        self.health.as_ref()
    }

    /// The sticky cookie setting, when the service has one.
    #[must_use]
    pub fn sticky(&self) -> Option<&Sticky> {
        self.sticky.as_ref()
    }

    /// Keys the sticky cookie, if any, for this service of `app`; see `Sticky::bind`.
    pub(super) fn bind_sticky(
        &mut self,
        secret: Option<&SkewSecret>,
        app: &str,
        service: &str,
    ) -> Result<(), Invalid> {
        match &mut self.sticky {
            Some(sticky) => sticky.bind(secret, app, service),
            None => Ok(()),
        }
    }

    /// The service's fingerprint, for [`state::Registry`].
    pub(super) fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// The service's shared state, for [`state::Registry`] to keep.
    pub(super) fn shared(&self) -> Arc<ServiceState> {
        Arc::clone(&self.shared)
    }

    /// Takes over `old`, the state of the same service in the previous table, and gives the
    /// servers named by DNS the states `old` holds for them.
    pub(super) fn adopt_shared(&mut self, old: Arc<ServiceState>) {
        self.shared = old;
        self.refresh();
    }

    /// Lets `adopt` replace the state of every server declared by IP address, for
    /// [`state::Registry`]. The servers named by DNS keep theirs in [`ServiceState`].
    pub(super) fn settle_servers(&mut self, mut adopt: impl FnMut(&mut Server)) {
        let current = self.live.load_full();
        let mut servers = current.servers.to_vec();
        for server in servers.iter_mut().filter(|server| server.host().is_none()) {
            adopt(server);
        }
        self.live.store(Arc::new(Live {
            servers: servers.into(),
            balancer: Arc::clone(&current.balancer),
        }));
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn compile(value: Value) -> Result<LoadBalancer, Invalid> {
        compile_with(value, &Resolver::default())
    }

    fn compile_with(value: Value, resolver: &Resolver) -> Result<LoadBalancer, Invalid> {
        let declared: Declared = serde_json::from_value(value).expect("declared");
        LoadBalancer::compile(&declared, &[], "t", resolver)
    }

    fn code(value: Value) -> &'static str {
        compile(value).expect_err("refused").code
    }

    fn lb(servers: &Value) -> Value {
        json!({ "name": "web", "type": "loadbalancer", "servers": servers })
    }

    #[test]
    fn plain_http_servers_compile_and_an_empty_list_is_allowed() {
        let balancer = compile(lb(&json!([
            { "url": "http://127.0.0.1:1" },
            { "url": "http://[::1]:2/" },
        ])))
        .expect("compiles");
        assert_eq!(balancer.servers().len(), 2);
        assert_eq!(balancer.algorithm(), "round_robin");
        assert!(compile(lb(&json!([]))).expect("empty").servers().is_empty());
    }

    #[test]
    fn https_servers_compile_and_summarize_their_transport() {
        let balancer = compile(lb(&json!([{ "url": "https://127.0.0.1:1" }]))).expect("https");
        assert!(balancer.servers()[0].tls);
        let summary = balancer
            .with_upstream("127.0.0.1:1".parse().expect("addr"), |upstream| {
                upstream.summary().is_some()
            })
            .expect("known");
        assert!(summary);
        assert!(
            balancer
                .with_upstream("127.0.0.1:2".parse().expect("addr"), |_| ())
                .is_none()
        );
        let plain = compile(lb(&json!([{ "url": "http://127.0.0.1:1" }]))).expect("http");
        let summary = plain
            .with_upstream("127.0.0.1:1".parse().expect("addr"), |upstream| {
                upstream.summary().is_some()
            })
            .expect("known");
        assert!(!summary);
    }

    #[test]
    fn h2c_servers_compile_and_never_carry_tls_or_http1_only_transports() {
        let balancer = compile(lb(&json!([{ "url": "h2c://127.0.0.1:1" }]))).expect("h2c");
        let server = &balancer.servers()[0];
        assert!(server.h2c && !server.tls);
        let protocol = balancer
            .with_upstream(server.addr, |upstream| {
                upstream.summary().expect("shown").protocol
            })
            .expect("known");
        assert_eq!(protocol, "h2c");
        let transported = |fields: Value| {
            let mut declared = fields;
            declared["name"] = json!("t");
            declared["type"] = json!("servers_transport");
            let declared: Declared = serde_json::from_value(declared).expect("declared");
            let named = transport::Named {
                name: "t".into(),
                transport: Arc::new(Transport::compile(&declared).expect("transport")),
            };
            let mut service = lb(&json!([{ "url": "h2c://127.0.0.1:1" }]));
            service["transport"] = json!("t");
            let declared: Declared = serde_json::from_value(service).expect("declared");
            LoadBalancer::compile(&declared, &[named], "t", &Resolver::default())
                .expect_err("refused")
                .code
        };
        assert_eq!(
            transported(json!({ "server_name": "x.test" })),
            "invalid_transport"
        );
        assert_eq!(transported(json!({ "http2": false })), "invalid_transport");
    }

    #[test]
    fn planned_and_malformed_settings_are_refused_with_their_codes() {
        assert_eq!(
            code(lb(&json!([
                { "url": "https://127.0.0.1:1" },
                { "url": "http://127.0.0.1:1" },
            ]))),
            "invalid_service"
        );
        assert_eq!(
            code(lb(&json!([
                { "url": "h2c://127.0.0.1:1" },
                { "url": "http://127.0.0.1:1" },
            ]))),
            "invalid_service",
            "one address has one scheme"
        );
        let mut probed = lb(&json!([{ "url": "h2c://127.0.0.1:1" }]));
        probed["health_check"] =
            json!({ "path": "/healthz", "interval_secs": 1, "timeout_secs": 1 });
        assert_eq!(code(probed), "service_not_built");
        for bad in [
            "http://-app.internal:80",
            "http://bad host:80",
            "http://300.1.1.1:80",
            "http://app..internal:80",
            "http://app.internal",
            "http://app.internal:99999",
            "http://:80",
            "http://[nope]:80",
        ] {
            assert_eq!(
                code(lb(&json!([{ "url": bad }]))),
                "invalid_service",
                "{bad}"
            );
        }
        assert_eq!(
            code(lb(&json!([{ "url": "ftp://127.0.0.1:1" }]))),
            "invalid_service"
        );
        assert_eq!(
            code(lb(&json!([{ "url": "http://127.0.0.1:1", "weight": 0 }]))),
            "invalid_service",
            "round_robin does not use weights"
        );
        assert_eq!(
            code(lb(&json!([{ "url": "http://127.0.0.1:1", "priority": 2 }]))),
            "invalid_service"
        );
        let mut sticky = lb(&json!([]));
        sticky["sticky"] = json!({});
        assert_eq!(code(sticky), "invalid_service");
        let mut misspelt = lb(&json!([]));
        misspelt["algorithms"] = json!("round_robin");
        assert_eq!(code(misspelt), "invalid_service");
    }

    #[test]
    fn only_weighted_round_robin_takes_weights_and_zero_means_nothing() {
        let mut weighted = lb(&json!([
            { "url": "http://127.0.0.1:1", "weight": 3 },
            { "url": "http://127.0.0.1:2", "weight": 0 },
        ]));
        weighted["algorithm"] = json!("weighted_round_robin");
        let balancer = compile(weighted.clone()).expect("compiles");
        assert_eq!(balancer.algorithm(), "weighted_round_robin");
        let request = pingora::http::RequestHeader::build("GET", b"/", None).expect("request");
        for _ in 0..10 {
            let (addr, _lease) = balancer.pick(PickCx::new(&request)).expect("a server");
            assert_eq!(addr.port(), 1);
        }
        weighted["algorithm"] = json!("random");
        assert_eq!(code(weighted), "invalid_service");
    }

    fn ips(text: &[&str]) -> Vec<IpAddr> {
        text.iter().map(|ip| ip.parse().expect("ip")).collect()
    }

    fn addrs(balancer: &LoadBalancer) -> Vec<String> {
        balancer
            .servers()
            .iter()
            .map(|server| server.addr.to_string())
            .collect()
    }

    #[test]
    fn a_name_compiles_with_no_address_and_the_service_stays_backed() {
        let balancer = compile(lb(&json!([{ "url": "http://App.Internal:8080" }]))).expect("name");
        assert!(balancer.servers().is_empty());
        assert!(balancer.is_backed());
        assert!(!compile(lb(&json!([]))).expect("empty").is_backed());
        assert_eq!(balancer.dns_names().collect::<Vec<_>>(), ["app.internal"]);
        let request = pingora::http::RequestHeader::build("GET", b"/", None).expect("request");
        assert!(balancer.pick(PickCx::new(&request)).is_none());
    }

    #[test]
    fn a_name_expands_into_one_server_per_address_and_follows_the_resolver() {
        let resolver = Resolver::default();
        let balancer = compile_with(
            lb(&json!([
                { "url": "http://10.0.0.1:80" },
                { "url": "https://app.internal:8443" },
            ])),
            &resolver,
        )
        .expect("compiles");
        assert_eq!(addrs(&balancer), ["10.0.0.1:80"]);

        resolver.seed("app.internal", &ips(&["10.0.0.7", "10.0.0.8"]));
        assert!(balancer.refresh(), "two addresses arrived");
        assert_eq!(
            addrs(&balancer),
            ["10.0.0.1:80", "10.0.0.7:8443", "10.0.0.8:8443"]
        );
        assert!(!balancer.refresh(), "nothing changed");
        let servers = balancer.servers();
        let named = &servers[1];
        assert_eq!(named.host(), Some("app.internal"));
        assert_eq!(named.sni_name().as_deref(), Some("app.internal"));
        assert!(named.tls && servers[0].host().is_none());
        assert_ne!(named.identity(), servers[2].identity());
        let state = Arc::clone(&named.state);

        resolver.seed("app.internal", &ips(&["10.0.0.8", "10.0.0.9"]));
        assert!(balancer.refresh());
        assert_eq!(
            addrs(&balancer),
            ["10.0.0.1:80", "10.0.0.8:8443", "10.0.0.9:8443"]
        );
        assert!(
            !Arc::ptr_eq(&state, &balancer.servers()[1].state),
            "10.0.0.7 is gone and 10.0.0.8 keeps its own state"
        );
        let kept = Arc::clone(&balancer.servers()[1].state);
        resolver.seed("app.internal", &ips(&["10.0.0.8"]));
        assert!(balancer.refresh());
        assert!(Arc::ptr_eq(&kept, &balancer.servers()[1].state));
    }

    #[test]
    fn expansion_drops_what_the_policy_refuses_dedupes_and_caps() {
        let policy = crate::service::upstream_policy::UpstreamPolicy::builtin();
        let resolver = Resolver::new(resolve::Settings::default(), policy);
        resolver.seed(
            "a.internal",
            &ips(&["127.0.0.1", "10.0.0.5", "169.254.169.254", "10.0.0.6"]),
        );
        resolver.seed("b.internal", &ips(&["10.0.0.5"]));
        let balancer = compile_with(
            lb(&json!([
                { "url": "http://a.internal:80" },
                { "url": "http://b.internal:80" },
            ])),
            &resolver,
        )
        .expect("compiles");
        assert_eq!(addrs(&balancer), ["10.0.0.5:80", "10.0.0.6:80"]);
        let many: Vec<IpAddr> = (1..=200_u8)
            .map(|n| IpAddr::V4(Ipv4Addr::new(10, 1, 0, n)))
            .collect();
        resolver.seed("c.internal", &many);
        let big = compile_with(lb(&json!([{ "url": "http://c.internal:80" }])), &resolver)
            .expect("compiles");
        assert_eq!(big.servers().len(), resolve::MAX_ADDRESSES_PER_NAME);
    }

    #[test]
    fn weights_are_checked_against_the_algorithm_whatever_the_name_resolves_to() {
        assert_eq!(
            code(lb(
                &json!([{ "url": "http://app.internal:80", "weight": 2 }])
            )),
            "invalid_service",
            "round_robin ignores weights"
        );
        let mut hashed = lb(&json!([{ "url": "http://app.internal:80", "weight": 0 }]));
        hashed["algorithm"] = json!("ip_hash");
        assert_eq!(
            code(hashed),
            "invalid_service",
            "no server could take a request"
        );
    }

    #[test]
    fn a_service_with_names_is_charged_for_its_largest_ring() {
        let mut hashed = lb(&json!([{ "url": "http://app.internal:80" }]));
        hashed["algorithm"] = json!("ip_hash");
        assert_eq!(
            compile(hashed).expect("compiles").ring_points(),
            crate::service::lb::MAX_SERVICE_POINTS
        );
        let mut literal = lb(&json!([{ "url": "http://10.0.0.1:80" }]));
        literal["algorithm"] = json!("ip_hash");
        assert_eq!(compile(literal).expect("compiles").ring_points(), 160);
    }

    const OWNER: &str = "_web._tcp.shop.test";

    fn srv_lb(algorithm: &str) -> Value {
        let mut value = lb(&json!([{ "url": format!("http://{OWNER}"), "resolve": "srv" }]));
        value["algorithm"] = json!(algorithm);
        value
    }

    fn weights(balancer: &LoadBalancer) -> Vec<u32> {
        balancer
            .servers()
            .iter()
            .map(|server| server.weight)
            .collect()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    #[test]
    fn an_srv_name_is_backed_charged_and_counted_as_an_srv_name_only() {
        let balancer = compile(srv_lb("round_robin")).expect("compiles");
        assert!(balancer.servers().is_empty());
        assert!(balancer.is_backed());
        assert_eq!(balancer.srv_names().collect::<Vec<_>>(), [OWNER]);
        assert_eq!(balancer.dns_names().count(), 0);
        assert_eq!(
            compile(srv_lb("ip_hash")).expect("compiles").ring_points(),
            crate::service::lb::MAX_SERVICE_POINTS
        );
        let mixed = compile(lb(&json!([
            { "url": "http://Api.Shop.Test:80" },
            { "url": "http://_Web._tcp.Shop.test.", "resolve": "srv" },
        ])))
        .expect("compiles");
        assert_eq!(mixed.dns_names().collect::<Vec<_>>(), ["api.shop.test"]);
        assert_eq!(mixed.srv_names().collect::<Vec<_>>(), [OWNER]);
    }

    #[test]
    fn bad_srv_entries_are_invalid_service() {
        for server in [
            json!({ "url": format!("http://{OWNER}:8080"), "resolve": "srv" }),
            json!({ "url": "http://bad owner.test", "resolve": "srv" }),
            json!({ "url": "http://10.0.0.1", "resolve": "srv" }),
            json!({ "url": "http://[::1]", "resolve": "srv" }),
            json!({ "url": format!("http://{OWNER}/path"), "resolve": "srv" }),
            json!({ "url": format!("http://{OWNER}"), "resolve": "srv", "weight": 2 }),
            json!({ "url": format!("ftp://{OWNER}"), "resolve": "srv" }),
        ] {
            assert_eq!(
                code(lb(&json!([server.clone()]))),
                "invalid_service",
                "{server}"
            );
        }
        let unknown = json!({ "url": format!("http://{OWNER}"), "resolve": "mx" });
        assert_eq!(code(lb(&json!([unknown]))), "invalid_service");
        compile(lb(&json!([
            { "url": "http://api.shop.test:80", "resolve": "a" },
            { "url": "http://10.0.0.1:80", "resolve": "a" },
        ])))
        .expect("resolve a is the default");
    }

    #[test]
    fn srv_servers_take_the_lowest_priority_and_the_weights_the_algorithm_can_use() {
        let resolver = Resolver::default();
        let wrr = compile_with(srv_lb("weighted_round_robin"), &resolver).expect("compiles");
        let robin = compile_with(srv_lb("round_robin"), &resolver).expect("compiles");
        let hashed = compile_with(srv_lb("ip_hash"), &resolver).expect("compiles");
        let hrw = compile_with(srv_lb("hrw"), &resolver).expect("compiles");
        resolver.seed_srv(
            OWNER,
            &[
                (10, 30_000, 8080, ip("10.0.0.1")),
                (10, 10_000, 8081, ip("10.0.0.2")),
                (20, 5, 9000, ip("10.0.0.3")),
            ],
        );
        for balancer in [&wrr, &robin, &hashed, &hrw] {
            assert!(balancer.refresh());
            assert_eq!(addrs(balancer), ["10.0.0.1:8080", "10.0.0.2:8081"]);
            assert!(!balancer.refresh(), "nothing changed");
        }
        assert_eq!(
            weights(&wrr),
            [3, 1],
            "exact: divided by the common divisor"
        );
        assert_eq!(weights(&hrw), [30_000, 10_000], "hrw takes any weight");
        assert_eq!(weights(&robin), [1, 1], "round_robin has no weights");
        assert_eq!(weights(&hashed), [3, 1]);

        // A change of weight alone rebuilds the algorithm.
        resolver.seed_srv(
            OWNER,
            &[
                (10, 100, 8080, ip("10.0.0.1")),
                (10, 100, 8081, ip("10.0.0.2")),
            ],
        );
        assert!(wrr.refresh());
        assert_eq!(weights(&wrr), [1, 1]);

        // Weights too big for a ring are scaled into it, and a weight of 0 is the lowest.
        resolver.seed_srv(
            OWNER,
            &[
                (10, 65_535, 8080, ip("10.0.0.1")),
                (10, 0, 8081, ip("10.0.0.2")),
            ],
        );
        assert!(hashed.refresh());
        let fitted = weights(&hashed);
        assert!(fitted.iter().sum::<u32>() <= 256 && fitted[1] >= 1 && fitted[0] > fitted[1]);
        assert!(wrr.refresh());
        let cycle = weights(&wrr);
        assert!(cycle.iter().sum::<u32>() <= 4096 && cycle[1] == 1 && cycle[0] > 4000);
    }

    #[test]
    fn srv_servers_drop_what_the_policy_refuses_and_fall_to_the_next_priority() {
        let policy = crate::service::upstream_policy::UpstreamPolicy::parse(
            r#"{"srv_deny_ports": [5432], "tenants": {"t": {"allow": ["10.0.0.0/8"], "srv_allow_ports": [8080, 5432, 9000]}}}"#,
        )
        .expect("policy");
        let resolver = Resolver::new(resolve::Settings::default(), policy);
        let balancer = compile_with(srv_lb("round_robin"), &resolver).expect("compiles");
        resolver.seed_srv(
            OWNER,
            &[
                (10, 1, 5432, ip("10.0.0.1")),
                (10, 1, 8080, ip("127.0.0.1")),
                (10, 1, 7000, ip("10.0.0.2")),
                (20, 1, 9000, ip("10.0.0.3")),
            ],
        );
        assert!(balancer.refresh());
        assert_eq!(
            addrs(&balancer),
            ["10.0.0.3:9000"],
            "denied port, denied address and port outside the tenant's list leave the next priority"
        );
    }
}
