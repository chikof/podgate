//! Entry points (listeners) as the process and the request path see them.
//!
//! Where an entry point listens is process configuration, because Pingora binds its sockets
//! before it runs; what it allows is snapshot data ([`podgate_model::EntryPointPolicy`]).
//! `ENTRY_POINTS` lists the listeners (`name=address/protocol[;proxy_protocol]`); `PROXY_ADDR`
//! and `PROXY_TLS_ADDR` stay as the shorthand for `web` and `websecure`.
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

pub mod policy;
pub mod proxy_protocol;

use std::net::SocketAddr;

use pingora::http::RequestHeader;
use pingora::proxy::Session;
use thiserror::Error;

use crate::router::path::{self, Refused};
use crate::service::StaticRoots;
use crate::service::upstream_policy::UpstreamPolicy;
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

    /// The transport the socket binds: a port can carry TCP and UDP at once, not two of one.
    fn is_datagram(self) -> bool {
        self == Self::Udp
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
}
// 56: name (16) + SocketAddr (32) + protocol and flag, padded to 8.
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

/// Parses the value of `ENTRY_POINTS`: `name=address/protocol[;proxy_protocol]`, comma
/// separated. `protocol` is `http`, `https`, `tcp` or `udp`.
///
/// # Errors
///
/// [`ParseError`] naming the first entry that is empty, malformed, repeats a name or an address
/// on the same transport, or sets an option other than `proxy_protocol`.
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
        if let Some(other) = parsed.iter().find(|other| {
            other.addr == point.addr && other.protocol.is_datagram() == point.protocol.is_datagram()
        }) {
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
    for option in parts {
        if option != "proxy_protocol" {
            return Err(bad(format!(
                "{option:?} is not an option: only proxy_protocol is known"
            )));
        }
        proxy_protocol = true;
    }
    Ok(EntryPoint {
        name: name.into(),
        addr,
        protocol,
        proxy_protocol,
    })
}

/// What the compiler knows about this process.
#[derive(Debug, Clone)]
pub struct CompileContext {
    bound: Vec<(Box<str>, Protocol)>,
    catch_all_tenants: Vec<Box<str>>,
    acme_dns_zones: Vec<Box<str>>,
    upstream_policy: UpstreamPolicy,
    tls_floor: TlsVersion,
    static_roots: StaticRoots,
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
            upstream_policy: UpstreamPolicy::allow_all(),
            tls_floor: TlsVersion::V1_2,
            static_roots: StaticRoots::default(),
        }
    }

    /// A context for the listeners `points`.
    #[must_use]
    pub fn of_entry_points(points: &[EntryPoint]) -> Self {
        Self::new(points.iter().map(|point| (&*point.name, point.protocol)))
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
/// the result, so routing, middlewares and the upstream all see one path.
///
/// # Errors
///
/// [`Refused`] for a path that cannot be normalized without changing what it names; the request
/// must be answered `400`.
pub fn normalize_request(request: &mut RequestHeader) -> Result<(), Refused> {
    let normalized = match path::normalize(request.uri.path())? {
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
        normalize_request(&mut request).expect("normalizes");
        assert_eq!(request.uri.path(), "/a/b/c");
        assert_eq!(request.uri.query(), Some("x=1"));
    }

    #[test]
    fn a_clean_request_is_untouched_and_a_bad_one_refused() {
        let mut clean = RequestHeader::build("GET", b"/a?x=1", None).expect("request");
        normalize_request(&mut clean).expect("clean");
        assert_eq!(
            clean.uri.path_and_query().map(|pq| pq.as_str()),
            Some("/a?x=1")
        );
        let mut bad = RequestHeader::build("GET", b"/a%2fb", None).expect("request");
        assert_eq!(normalize_request(&mut bad), Err(Refused::EncodedSeparator));
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
