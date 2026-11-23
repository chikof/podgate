//! Entry points (listeners) as the process and the request path see them.
//!
//! Where an entry point listens is process configuration, because Pingora binds its sockets
//! before it runs; what it allows is snapshot data ([`podgate_model::EntryPointPolicy`]).
//! `ENTRY_POINTS` lists the listeners (`name=address/protocol[;proxy_protocol][;http3[=port]]`);
//! `PROXY_ADDR` and `PROXY_TLS_ADDR` stay as the shorthand for `web` and `websecure`.
//!
//! - [`EntryPoint`], [`Protocol`] and [`parse_list`]: one configured listener, and the parser of
//!   the `ENTRY_POINTS` value.
//! - [`CompileContext`]: the entry point names and protocols the compiler checks routers and
//!   policies against, so a snapshot written for another node fails closed.
//! - [`normalize_request`]: the first thing the request path does with a request: the path that
//!   is matched is rewritten to the path that is served.
//!
//! The listener a request arrived on is `Ctx.entry_point` (set from [`crate::Gateway`]'s name,
//! one gateway per listener), which `route::matching` filters routers by.

pub mod app;
pub mod policy;
pub mod proxy_protocol;

use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use pingora::http::RequestHeader;
use pingora::proxy::Session;
use thiserror::Error;

use crate::router::path::{self, Refused};
use crate::service::resolve::Resolver;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::service::{FastcgiRoots, StaticRoots};
use podgate_model::TlsVersion;

/// The built-in plain HTTP entry point.
pub const WEB: &str = "web";
/// The built-in TLS entry point.
pub const WEBSECURE: &str = "websecure";

/// Longest entry point name.
const NAME_MAX: usize = 63;

/// What an entry point speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Plain HTTP/1.1.
    Http,
    /// HTTP/2 and HTTP/1.1 over TLS; podgate terminates the TLS.
    Https,
    /// Raw TCP.
    Tcp,
    /// UDP datagrams.
    Udp,
}
// 1: four dataless variants; the unused values are a niche.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Protocol>() == 1);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Option<Protocol>>() == std::mem::size_of::<Protocol>());

impl Protocol {
    /// The word `ENTRY_POINTS` uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// Whether HTTP routers can listen on it.
    #[must_use]
    pub fn is_http(self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }

    fn parse(word: &str) -> Option<Self> {
        match word {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

impl EntryPoint {
    /// Whether the address is bound for TCP and for UDP: a port can carry one of each, not two of
    /// one. An `https` entry point with `;http3` binds both.
    fn transports(&self) -> (bool, bool) {
        match self.protocol {
            Protocol::Udp => (false, true),
            Protocol::Https if self.http3.is_some() => (true, true),
            _ => (true, false),
        }
    }

    /// Whether `self` and `other` would bind the same transport on the same address.
    fn clashes_with(&self, other: &Self) -> bool {
        let (stream, datagram) = self.transports();
        let (other_stream, other_datagram) = other.transports();
        self.addr == other.addr && ((stream && other_stream) || (datagram && other_datagram))
    }
}

/// One listener the process binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPoint {
    /// The name routers and policies refer to.
    pub name: Box<str>,
    /// Where it listens.
    pub addr: SocketAddr,
    /// What it speaks.
    pub protocol: Protocol,
    /// Whether peers send a PROXY protocol header first (`;proxy_protocol`).
    pub proxy_protocol: bool,
    /// The port `Alt-Svc` advertises for HTTP/3 (`;http3` is the entry point's own port,
    /// `;http3=<port>` another, for a mapped port), when the entry point also serves HTTP/3 over
    /// QUIC on its address. Only an `https` entry point has it.
    pub http3: Option<NonZeroU16>,
}
// 56: name (16) + SocketAddr (32) + protocol, flag and advertised port, padded to 8.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<EntryPoint>() == 56);

impl EntryPoint {
    /// The built-in `web` entry point of `PROXY_ADDR`.
    #[must_use]
    pub fn web(addr: SocketAddr) -> Self {
        Self::builtin(WEB, addr, Protocol::Http)
    }

    /// The built-in `websecure` entry point of `PROXY_TLS_ADDR`.
    #[must_use]
    pub fn websecure(addr: SocketAddr) -> Self {
        Self::builtin(WEBSECURE, addr, Protocol::Https)
    }

    fn builtin(name: &str, addr: SocketAddr, protocol: Protocol) -> Self {
        Self {
            name: name.into(),
            addr,
            protocol,
            proxy_protocol: false,
            http3: None,
        }
    }
}

/// An `ENTRY_POINTS` entry that cannot be used. Names the entry.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("entry {entry:?}: {reason}")]
pub struct ParseError {
    entry: Box<str>,
    reason: Box<str>,
}

impl ParseError {
    fn new(entry: &str, reason: impl Into<Box<str>>) -> Self {
        Self {
            entry: entry.into(),
            reason: reason.into(),
        }
    }
}

/// Parses the value of `ENTRY_POINTS`: `name=address/protocol[;proxy_protocol][;http3[=port]]`,
/// comma separated. `protocol` is `http`, `https`, `tcp` or `udp`.
///
/// # Errors
///
/// [`ParseError`] naming the first entry that is empty, malformed, repeats a name or an address
/// on the same transport, sets an option other than `proxy_protocol` and `http3`, or sets `http3`
/// on anything but an `https` entry point or together with `proxy_protocol`.
pub fn parse_list(raw: &str) -> Result<Vec<EntryPoint>, ParseError> {
    let mut parsed: Vec<EntryPoint> = Vec::new();
    for entry in raw.split(',').map(str::trim) {
        let point = parse_entry(entry)?;
        if parsed.iter().any(|other| other.name == point.name) {
            return Err(ParseError::new(
                entry,
                format!("the name {} is already used", point.name),
            ));
        }
        if let Some(other) = parsed.iter().find(|other| other.clashes_with(&point)) {
            return Err(ParseError::new(
                entry,
                format!("{} is already the address of {}", point.addr, other.name),
            ));
        }
        parsed.push(point);
    }
    Ok(parsed)
}

fn parse_entry(entry: &str) -> Result<EntryPoint, ParseError> {
    let shape = "expected name=address/protocol, like web=0.0.0.0:80/http";
    let bad = |reason: String| ParseError::new(entry, reason);
    let (name, rest) = entry.split_once('=').ok_or_else(|| bad(shape.to_owned()))?;
    let name = name.trim();
    if name.is_empty()
        || name.len() > NAME_MAX
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(bad(format!(
            "the name must be 1 to {NAME_MAX} letters, digits, `-` or `_`"
        )));
    }
    let mut parts = rest.split(';').map(str::trim);
    let (address, protocol) = parts
        .next()
        .and_then(|head| head.rsplit_once('/'))
        .ok_or_else(|| bad(shape.to_owned()))?;
    let addr: SocketAddr = address.trim().parse().map_err(|err| {
        bad(format!(
            "{:?} is not a socket address like 0.0.0.0:8080 ({err})",
            address.trim()
        ))
    })?;
    let protocol = Protocol::parse(protocol.trim()).ok_or_else(|| {
        bad(format!(
            "{:?} is not a protocol: http, https, tcp or udp",
            protocol.trim()
        ))
    })?;
    let mut proxy_protocol = false;
    let mut http3 = None;
    for option in parts {
        match option {
            "proxy_protocol" => proxy_protocol = true,
            "http3" => http3 = NonZeroU16::new(addr.port()),
            _ => match option.strip_prefix("http3=") {
                Some(port) => {
                    http3 = Some(port.trim().parse().map_err(|err| {
                        bad(format!("http3={port:?} is not a port in 1..=65535 ({err})"))
                    })?);
                }
                None => {
                    return Err(bad(format!(
                        "{option:?} is not an option: proxy_protocol and http3 are known"
                    )));
                }
            },
        }
    }
    if http3.is_some() && protocol != Protocol::Https {
        return Err(bad("http3 needs an https entry point".to_owned()));
    }
    if http3.is_some() && proxy_protocol {
        return Err(bad(
            "http3 and proxy_protocol cannot be combined: QUIC carries no PROXY protocol header, so HTTP/3 clients would all appear to come from the load balancer".to_owned(),
        ));
    }
    Ok(EntryPoint {
        name: name.into(),
        addr,
        protocol,
        proxy_protocol,
        http3,
    })
}

/// What the compiler knows about this process.
#[derive(Debug, Clone)]
pub struct CompileContext {
    bound: Vec<(Box<str>, Protocol)>,
    catch_all_tenants: Vec<Box<str>>,
    acme_dns_zones: Vec<Box<str>>,
    cache_tenant_max_percent: u8,
    upstream_policy: UpstreamPolicy,
    tls_floor: TlsVersion,
    static_roots: StaticRoots,
    fastcgi: FastcgiRoots,
    addrs: Vec<(Box<str>, SocketAddr)>,
    proxy_header: Option<Vec<Box<str>>>,
    resolver: Resolver,
    rate_limit_stores: crate::ratelimit_store::Stores,
    spiffe: crate::spiffe::Spiffe,
    plugins: crate::middleware::plugin::Plugins,
    content_classifiers: crate::middleware::content_guard::Classifiers,
    portal: Arc<crate::middleware::portal::pin::Grants>,
}

impl Default for CompileContext {
    /// The two built-in entry points, and no tenant allowed a catch-all router.
    fn default() -> Self {
        Self::new([(WEB, Protocol::Http), (WEBSECURE, Protocol::Https)])
    }
}

impl CompileContext {
    /// A context with the entry points `bound`, in the order the process lists them.
    #[must_use]
    pub fn new<'a>(bound: impl IntoIterator<Item = (&'a str, Protocol)>) -> Self {
        Self {
            bound: bound
                .into_iter()
                .map(|(name, protocol)| (Box::from(name), protocol))
                .collect(),
            catch_all_tenants: Vec::new(),
            acme_dns_zones: Vec::new(),
            cache_tenant_max_percent: crate::cache::DEFAULT_TENANT_MAX_PERCENT,
            upstream_policy: UpstreamPolicy::allow_all(),
            tls_floor: TlsVersion::V1_2,
            static_roots: StaticRoots::default(),
            fastcgi: FastcgiRoots::default(),
            addrs: Vec::new(),
            proxy_header: None,
            resolver: Resolver::default(),
            rate_limit_stores: crate::ratelimit_store::Stores::default(),
            spiffe: crate::spiffe::Spiffe::default(),
            plugins: crate::middleware::plugin::Plugins::default(),
            content_classifiers: crate::middleware::content_guard::Classifiers::default(),
            portal: Arc::default(),
        }
    }

    /// A context for the listeners `points`, with their addresses (an entry point `redirect`
    /// builds its `Location` from the target's).
    #[must_use]
    pub fn of_entry_points(points: &[EntryPoint]) -> Self {
        let mut context = Self::new(points.iter().map(|point| (&*point.name, point.protocol)));
        context.addrs = points
            .iter()
            .map(|point| (point.name.clone(), point.addr))
            .collect();
        context.proxy_header = Some(
            points
                .iter()
                .filter(|point| point.proxy_protocol)
                .map(|point| point.name.clone())
                .collect(),
        );
        context
    }

    /// Where the entry point called `name` listens, when the process told the compiler. A
    /// context built by [`Self::new`] knows no addresses.
    #[must_use]
    pub fn addr_of(&self, name: &str) -> Option<SocketAddr> {
        self.addrs
            .iter()
            .find(|(bound, _)| &**bound == name)
            .map(|(_, addr)| *addr)
    }

    /// Whether the entry point called `name` was configured with `;proxy_protocol`. `None` when
    /// the context was not built from the process's entry points ([`Self::new`]), which knows no
    /// options.
    #[must_use]
    pub fn reads_proxy_header(&self, name: &str) -> Option<bool> {
        let listed = self.proxy_header.as_ref()?;
        Some(listed.iter().any(|listed| &**listed == name))
    }

    /// Lets the tenants called `tenants` declare routers that match hosts nobody claims (a
    /// `host_regexp` or host-free router) on a shared entry point. Only the operator calls this
    /// (`CATCH_ALL_TENANTS`); a snapshot never can.
    #[must_use]
    pub fn with_catch_all_tenants<'a>(
        mut self,
        tenants: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        self.catch_all_tenants = tenants.into_iter().map(Box::from).collect();
        self
    }

    /// Lets apps use the `dns-01` challenge for hosts in or under `zones`. Only the operator
    /// calls this (`ACME_DNS_ZONES`); a snapshot never can. Without zones `dns-01` is off.
    #[must_use]
    pub fn with_acme_dns_zones<'a>(mut self, zones: impl IntoIterator<Item = &'a str>) -> Self {
        self.acme_dns_zones = zones.into_iter().map(Box::from).collect();
        self
    }

    /// The zones `dns-01` may be used for; empty means it is off.
    #[must_use]
    pub fn acme_dns_zones(&self) -> &[Box<str>] {
        &self.acme_dns_zones
    }

    /// The most a tenant's response cache may hold, in percent of its `max_buffer_bytes`: the
    /// upper limit for any `cache` middleware's `max_bytes`.
    #[must_use]
    pub fn cache_tenant_max_percent(&self) -> u8 {
        self.cache_tenant_max_percent
    }

    /// Limits every `cache` middleware to `percent` of its tenant's `max_buffer_bytes`. Only the
    /// operator calls this (`CACHE_TENANT_MAX_PERCENT`); a snapshot never can.
    #[must_use]
    pub fn with_cache_tenant_max_percent(mut self, percent: u8) -> Self {
        self.cache_tenant_max_percent = percent;
        self
    }

    /// Checks the literal server addresses of every service against `policy` (`upstream_forbidden`).
    /// `run` always installs the operator's policy; a context without one refuses nothing, which
    /// is for tests and tools that compile snapshots outside a running process.
    #[must_use]
    pub fn with_upstream_policy(mut self, policy: UpstreamPolicy) -> Self {
        self.upstream_policy = policy;
        self
    }

    /// Sets the lowest TLS version the process serves (`TLS_MIN_VERSION`); an app's
    /// `tls.min_version` below it is refused with `unsupported_setting`.
    #[must_use]
    pub fn with_tls_floor(mut self, floor: TlsVersion) -> Self {
        self.tls_floor = floor;
        self
    }

    /// The lowest TLS version the process serves.
    #[must_use]
    pub fn tls_floor(&self) -> TlsVersion {
        self.tls_floor
    }

    /// The directories the operator declared for static services, per tenant. Only the operator
    /// calls this (`STATIC_ROOTS_FILE`); a snapshot names a root by label and never supplies a path.
    #[must_use]
    pub fn with_static_roots(mut self, roots: StaticRoots) -> Self {
        self.static_roots = roots;
        self
    }

    /// The static roots the compiler resolves `static` services against.
    #[must_use]
    pub fn static_roots(&self) -> &StaticRoots {
        &self.static_roots
    }

    /// The FastCGI upstreams the operator declared, per tenant. Only the operator calls this
    /// (`FASTCGI_FILE`); a snapshot names an upstream and never supplies an address or a root.
    #[must_use]
    pub fn with_fastcgi(mut self, fastcgi: FastcgiRoots) -> Self {
        self.fastcgi = fastcgi;
        self
    }

    /// The FastCGI upstreams the compiler resolves `fastcgi` services against.
    #[must_use]
    pub fn fastcgi(&self) -> &FastcgiRoots {
        &self.fastcgi
    }

    /// The stores a cluster-scope `rate_limit` may name (`RATE_LIMIT_STORES_FILE`). Only the
    /// operator calls this; a snapshot names a store by label and never supplies an address.
    #[must_use]
    pub fn with_rate_limit_stores(mut self, stores: crate::ratelimit_store::Stores) -> Self {
        self.rate_limit_stores = stores;
        self
    }

    /// The stores the compiler checks cluster-scope `rate_limit` middlewares against.
    #[must_use]
    pub fn rate_limit_stores(&self) -> &crate::ratelimit_store::Stores {
        &self.rate_limit_stores
    }

    /// Sets the process's SPIFFE configuration (`SPIFFE_ENDPOINT_SOCKET`, `SPIFFE_POLICY_FILE`);
    /// without one every `spiffe` and `tls.spiffe_client` is refused with `spiffe_not_allowed`.
    #[must_use]
    pub fn with_spiffe(mut self, spiffe: crate::spiffe::Spiffe) -> Self {
        self.spiffe = spiffe;
        self
    }

    /// The SPIFFE configuration transports and client authentication are bound to.
    #[must_use]
    pub fn spiffe(&self) -> &crate::spiffe::Spiffe {
        &self.spiffe
    }

    /// The plugins a `plugin` middleware may name (`PLUGINS_FILE`). Only the operator calls
    /// this; a snapshot names a plugin and never a socket or a command.
    #[must_use]
    pub fn with_plugins(mut self, plugins: crate::middleware::plugin::Plugins) -> Self {
        self.plugins = plugins;
        self
    }

    /// The plugins the compiler checks `plugin` middlewares against.
    #[must_use]
    pub fn plugins(&self) -> &crate::middleware::plugin::Plugins {
        &self.plugins
    }

    /// The classifiers a `content_guard` middleware may name (`CONTENT_CLASSIFIERS_FILE`). Only
    /// the operator calls this; a snapshot names a classifier and never an address.
    #[must_use]
    pub fn with_content_classifiers(
        mut self,
        classifiers: crate::middleware::content_guard::Classifiers,
    ) -> Self {
        self.content_classifiers = classifiers;
        self
    }

    /// The classifiers the compiler checks `content_guard` middlewares against.
    #[must_use]
    pub fn content_classifiers(&self) -> &crate::middleware::content_guard::Classifiers {
        &self.content_classifiers
    }

    /// The apps that may declare a `portal` middleware, with the pin of each one's login
    /// (`PORTAL_APPS`). Only the operator calls this; a snapshot cannot name an app into it.
    #[must_use]
    pub fn with_portal(mut self, apps: crate::middleware::portal::pin::Apps) -> Self {
        self.portal = Arc::new(crate::middleware::portal::pin::Grants::new(apps));
        self
    }

    /// The apps allowed a `portal` middleware, and the table those stages read.
    #[must_use]
    pub fn portal(&self) -> &crate::middleware::portal::pin::Grants {
        &self.portal
    }

    /// Resolves servers named by host name from `resolver`'s answers. `run` installs the
    /// resolver its DNS service drives; a context without one never resolves a name, which is
    /// for tests and tools that compile snapshots outside a running process.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Resolver) -> Self {
        self.resolver = resolver;
        self
    }

    /// The resolver servers named by host name take their addresses from.
    #[must_use]
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// The policy the compiler checks literal server addresses against.
    #[must_use]
    pub fn upstream_policy(&self) -> &UpstreamPolicy {
        &self.upstream_policy
    }

    /// Whether the operator allows `tenant` catch-all routers on shared entry points.
    #[must_use]
    pub fn allows_catch_all(&self, tenant: &str) -> bool {
        self.catch_all_tenants
            .iter()
            .any(|allowed| &**allowed == tenant)
    }

    /// The bound entry points with their protocols, in listing order.
    pub fn entry_points(&self) -> impl Iterator<Item = (&str, Protocol)> {
        self.bound
            .iter()
            .map(|(name, protocol)| (&**name, *protocol))
    }

    /// The bound entry points HTTP routers can listen on, in listing order.
    pub fn http_entry_points(&self) -> impl Iterator<Item = &str> {
        self.entry_points()
            .filter(|(_, protocol)| protocol.is_http())
            .map(|(name, _)| name)
    }

    /// The protocol of the entry point called `name`, when the process bound it.
    #[must_use]
    pub fn protocol_of(&self, name: &str) -> Option<Protocol> {
        self.entry_points()
            .find(|(bound, _)| *bound == name)
            .map(|(_, protocol)| protocol)
    }

    /// Whether the process bound an entry point called `name`.
    #[must_use]
    pub fn knows(&self, name: &str) -> bool {
        self.protocol_of(name).is_some()
    }
}

/// Whether the request's connection is TLS: the connection has a TLS digest.
#[must_use]
pub fn is_tls(session: &Session) -> bool {
    session
        .digest()
        .is_some_and(|digest| digest.ssl_digest.is_some())
}

/// Normalizes the path of `request` (see [`crate::router::path`]) and rewrites the request with
/// the result, so routing, middlewares and the upstream all see one path. `allow_encoded_slash`
/// is the entry point's policy: it keeps an encoded `/` as data inside its segment instead of
/// refusing the request (see [`path::normalize_with`]).
///
/// # Errors
///
/// [`Refused`] for a path that cannot be normalized without changing what it names; the request
/// must be answered `400`.
pub fn normalize_request(
    request: &mut RequestHeader,
    allow_encoded_slash: bool,
) -> Result<(), Refused> {
    let normalized = match path::normalize_with(request.uri.path(), allow_encoded_slash)? {
        std::borrow::Cow::Borrowed(_) => return Ok(()),
        std::borrow::Cow::Owned(path) => path,
    };
    let target = match request.uri.query() {
        Some(query) => format!("{normalized}?{query}"),
        None => normalized,
    };
    let mut parts = request.uri.clone().into_parts();
    if let Ok(path_and_query) = target.parse() {
        parts.path_and_query = Some(path_and_query);
        if let Ok(uri) = http::Uri::from_parts(parts) {
            request.set_uri(uri);
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn the_request_is_rewritten_to_the_path_that_was_matched() {
        let mut request = RequestHeader::build("GET", b"/a/./b//c?x=1", None).expect("request");
        normalize_request(&mut request, false).expect("normalizes");
        assert_eq!(request.uri.path(), "/a/b/c");
        assert_eq!(request.uri.query(), Some("x=1"));
    }

    #[test]
    fn a_clean_request_is_untouched_and_a_bad_one_refused() {
        let mut clean = RequestHeader::build("GET", b"/a?x=1", None).expect("request");
        normalize_request(&mut clean, false).expect("clean");
        assert_eq!(
            clean.uri.path_and_query().map(|pq| pq.as_str()),
            Some("/a?x=1")
        );
        let mut bad = RequestHeader::build("GET", b"/a%2fb", None).expect("request");
        assert_eq!(
            normalize_request(&mut bad, false),
            Err(Refused::EncodedSeparator)
        );
        let mut allowed = RequestHeader::build("GET", b"/a%2fb/c?x=1", None).expect("request");
        normalize_request(&mut allowed, true).expect("allowed");
        assert_eq!(
            allowed.uri.path_and_query().map(|pq| pq.as_str()),
            Some("/a%2Fb/c?x=1")
        );
    }

    #[test]
    fn the_default_context_knows_web_and_websecure() {
        let context = CompileContext::default();
        assert!(context.knows("web") && context.knows("websecure") && !context.knows("db"));
        assert_eq!(context.protocol_of("websecure"), Some(Protocol::Https));
    }

    #[test]
    fn http_entry_points_skip_tcp_and_udp() {
        let context = CompileContext::new([
            ("a", Protocol::Http),
            ("db", Protocol::Tcp),
            ("dns", Protocol::Udp),
            ("b", Protocol::Https),
        ]);
        assert_eq!(context.http_entry_points().collect::<Vec<_>>(), ["a", "b"]);
    }

    #[test]
    fn parses_every_protocol_and_the_proxy_protocol_option() {
        let parsed = parse_list(
            "web=0.0.0.0:80/http, secure=[::1]:443/https;proxy_protocol,db=127.0.0.1:5432/tcp,dns=127.0.0.1:53/udp",
        )
        .expect("parses");
        let shape: Vec<_> = parsed
            .iter()
            .map(|point| (&*point.name, point.protocol, point.proxy_protocol))
            .collect();
        assert_eq!(
            shape,
            [
                ("web", Protocol::Http, false),
                ("secure", Protocol::Https, true),
                ("db", Protocol::Tcp, false),
                ("dns", Protocol::Udp, false),
            ]
        );
        assert_eq!(parsed[1].addr, "[::1]:443".parse().expect("addr"));
    }

    #[test]
    fn the_http3_option_names_the_advertised_port() {
        let parsed = parse_list(
            "web=0.0.0.0:80/http,a=0.0.0.0:443/https;http3,b=0.0.0.0:8443/https;http3=443,c=0.0.0.0:9443/https",
        )
        .expect("parses");
        let ports: Vec<_> = parsed
            .iter()
            .map(|point| point.http3.map(NonZeroU16::get))
            .collect();
        assert_eq!(ports, [None, Some(443), Some(443), None]);
    }

    #[test]
    fn http3_is_for_https_without_proxy_protocol_and_binds_udp() {
        for bad in [
            "web=0.0.0.0:80/http;http3",
            "db=0.0.0.0:5432/tcp;http3",
            "a=0.0.0.0:443/https;http3;proxy_protocol",
            "a=0.0.0.0:443/https;http3=0",
            "a=0.0.0.0:443/https;http3=https",
            // The UDP port of the QUIC front is taken.
            "a=0.0.0.0:443/https;http3,dns=0.0.0.0:443/udp",
            "dns=0.0.0.0:443/udp,a=0.0.0.0:443/https;http3",
        ] {
            let err = parse_list(bad).expect_err(bad);
            assert!(err.to_string().starts_with("entry \""), "{bad}: {err}");
        }
        // Without the option the port is free for a `udp` entry point, as before.
        assert!(parse_list("a=0.0.0.0:443/https,dns=0.0.0.0:443/udp").is_ok());
    }

    #[test]
    fn a_bad_entry_is_named() {
        for bad in [
            "",
            "web",
            "web=0.0.0.0:80",
            "web=nope/http",
            "web=0.0.0.0:80/ftp",
            "web=0.0.0.0:80/http;tls",
            "we b=0.0.0.0:80/http",
            "=0.0.0.0:80/http",
            "web=0.0.0.0:80/http,",
            "a=0.0.0.0:80/http,a=0.0.0.0:81/http",
            "a=0.0.0.0:80/http,b=0.0.0.0:80/tcp",
        ] {
            let err = parse_list(bad).expect_err(bad);
            assert!(err.to_string().starts_with("entry \""), "{bad}: {err}");
        }
        let one_port_two_transports = parse_list("a=0.0.0.0:53/tcp,b=0.0.0.0:53/udp");
        assert!(one_port_two_transports.is_ok());
    }

    fn compiled(
        context: &CompileContext,
        entry_points: Option<serde_json::Value>,
    ) -> Result<crate::RoutingTable, crate::CompileError> {
        let mut router = serde_json::json!({
            "name": "r", "match": { "host": "a.test" }, "service": "web",
        });
        if let Some(list) = entry_points {
            router["entry_points"] = list;
        }
        let snapshot = serde_json::from_value(serde_json::json!({
            "version": 1,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "src/a", "tls": {"mode": "acme"},
                "routers": [router],
                "revisions": [{"id": "r", "weight": 1, "state": "serving", "services": [
                    {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:9000"}]}]}]
            }]
        }))
        .expect("snapshot");
        crate::RoutingTable::compile_with(&snapshot, context)
    }

    fn node_with_a_database_port() -> CompileContext {
        CompileContext::new([
            ("web", Protocol::Http),
            ("db", Protocol::Tcp),
            ("secure", Protocol::Https),
        ])
    }

    #[test]
    fn entry_point_protocol_rejected() {
        let context = node_with_a_database_port();
        let Err(crate::CompileError::Rejected(rejected)) =
            compiled(&context, Some(serde_json::json!(["web", "db"])))
        else {
            panic!("an HTTP router on a tcp entry point must be rejected");
        };
        let codes: Vec<_> = rejected
            .iter()
            .map(|rejected| rejected.to_json()["code"].clone())
            .collect();
        assert_eq!(codes, [serde_json::json!("entry_point_protocol")]);
        assert!(rejected[0].to_string().contains("db"));
    }

    #[test]
    fn a_router_without_entry_points_skips_tcp_and_udp() {
        let context = node_with_a_database_port();
        let table = compiled(&context, None).expect("compiles");
        let router = &table.app(0).expect("app").routers()[0];
        assert!(router.listens_on("web") && router.listens_on("secure"));
        assert!(!router.listens_on("db"));
        assert_eq!(table.context().protocol_of("db"), Some(Protocol::Tcp));
    }
}
