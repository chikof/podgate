//! Who the client is, and which forwarding headers to believe.
//!
//! Every request has one [`ForwardedView`], built before routing by [`ForwardedView::of`]. A
//! peer that the entry point does not trust ([`Trust`], from `EntryPointPolicy.forwarded_headers`)
//! cannot say anything about itself: its `X-Forwarded-*`, `X-Real-IP` and `Forwarded` headers are
//! removed from the request and the view comes from the connection. A trusted peer's headers are
//! kept and read: the `X-Forwarded-For` chain (else `Forwarded: for=`, else `X-Real-IP`) is
//! walked from the right, skipping trusted addresses, and the first untrusted one is the client.
//!
//! Everything that needs a client address goes through this module so a trust bug is fixed once:
//! the `client_ip` matcher, and the IP middlewares and balancers that call [`ClientIp::resolve`]
//! with their own [`IpStrategy`]. Writing the headers the upstream sees is `src/forwarded.rs`'s
//! job; it reads the view.
//!
//! All addresses are normalized first: an IPv4-mapped IPv6 address (`::ffff:10.0.0.1`) becomes
//! the IPv4 address, so an IPv4 allow list cannot be bypassed by writing the address in IPv6.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::str::FromStr;

use http::HeaderName;
use ipnet::IpNet;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use podgate_model::Snapshot;
use serde::Deserialize;
use serde_json::Value;

use crate::compile::Invalid;
use crate::host;

/// The address a view reports when the connection has no IP peer (a unix socket). It is never
/// matched by [`crate::router::Matcher`] and is not a client an allow list should admit.
pub const UNKNOWN: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// Most addresses kept from one forwarding header: the rightmost ones, which trusted proxies
/// wrote. Bounds what a trusted but careless peer can make one request allocate.
const MAX_CHAIN: usize = 64;

/// Longest `X-Forwarded-Host` value accepted.
const MAX_HOST_LEN: usize = 255;

/// The headers a peer that is not trusted may not set, besides every `x-forwarded-*` one.
const FORGEABLE: [&str; 2] = ["x-real-ip", "forwarded"];

/// Rewrites an IPv4-mapped IPv6 address as the IPv4 address it carries.
#[must_use]
pub fn normalize(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// A CIDR block, or a single address (a block as long as the address). IPv4 and IPv6 blocks mix
/// freely; a block of IPv4-mapped addresses (`::ffff:10.0.0.0/104`) is read as the IPv4 block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr(IpNet);

impl Cidr {
    /// Whether `addr` is in the block. Addresses are normalized first, so an IPv4 block contains
    /// the IPv4-mapped form of its addresses.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.0.contains(&normalize(addr))
    }

    /// Whether some address is in both blocks. Blocks of different families never overlap.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.0.contains(&other.0.network()) || other.0.contains(&self.0.network())
    }

    /// Whether every address of `other` is in this block.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        self.0.contains(&other.0)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// `text` is neither an address nor a `address/prefix` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCidr(Box<str>);

impl fmt::Display for InvalidCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not an IP address or a CIDR block", self.0)
    }
}

impl std::error::Error for InvalidCidr {}

impl FromStr for Cidr {
    type Err = InvalidCidr;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let net = text
            .parse::<IpNet>()
            .or_else(|_| text.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| InvalidCidr(text.into()))?
            .trunc();
        Ok(Self(match net {
            IpNet::V6(v6) if v6.prefix_len() >= 96 => match v6.network().to_ipv4_mapped() {
                Some(v4) => ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96).map_or(net, IpNet::V4),
                None => net,
            },
            other => other,
        }))
    }
}

impl TryFrom<String> for Cidr {
    type Error = InvalidCidr;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// How an IP-keyed feature (`ip_allow_list`, `rate_limit`, the hash balancers) picks the client
/// out of the forwarding chain, as Traefik's `ipStrategy`. The default is the entry point's own
/// decision, [`ForwardedView::client_ip`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpStrategy {
    /// The position from the right of the forwarded chain, counted after `excluded` addresses
    /// are removed: `1` is the last address, `2` the one before it.
    #[serde(default)]
    pub depth: Option<NonZeroU16>,
    /// Addresses and blocks never taken for the client: the chain is walked from the right and
    /// they are skipped.
    #[serde(default)]
    pub excluded: Vec<Cidr>,
}

/// The one place a feature turns a request into a client address.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp;

impl ClientIp {
    /// The client address of `view` under `strategy`. With the default strategy that is the
    /// view's own decision. Otherwise the forwarded chain is read from the right with the
    /// strategy's `excluded` addresses removed, and `depth` picks one (the first when absent).
    /// A peer that is not trusted has no chain, and a chain that runs out gives the connection
    /// peer. [`UNKNOWN`] when the connection has none.
    #[must_use]
    pub fn resolve(view: &ForwardedView, strategy: &IpStrategy) -> IpAddr {
        if strategy.depth.is_none() && strategy.excluded.is_empty() {
            return view.client_ip;
        }
        let mut candidates = view
            .chain
            .iter()
            .rev()
            .filter(|addr| !strategy.excluded.iter().any(|block| block.contains(**addr)));
        let picked = match strategy.depth {
            Some(depth) => candidates.nth(usize::from(depth.get()) - 1),
            None => candidates.next(),
        };
        picked.copied().unwrap_or(view.peer)
    }
}

/// `EntryPointPolicy.forwarded_headers`: which peers may speak for the client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trust {
    insecure: bool,
    trusted: Box<[Cidr]>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustConfig {
    #[serde(default)]
    trusted_ips: Vec<Cidr>,
    #[serde(default)]
    insecure: bool,
}

/// The `kind` of a posture change this module reports, see [`Trust::relaxation`].
pub mod kind {
    /// `insecure: true`: every peer's forwarding headers are believed.
    pub const FORWARDED_HEADERS_INSECURE: &str = "forwarded_headers_insecure";
    /// `trusted_ips` covers addresses it did not: more peers may now speak for the client.
    pub const FORWARDED_TRUSTED_IPS_WIDENED: &str = "forwarded_trusted_ips_widened";
}

impl Trust {
    /// Reads the policy: `{"trusted_ips": ["10.0.0.0/8", "2001:db8::1"], "insecure": false}`,
    /// both fields optional.
    ///
    /// # Errors
    ///
    /// `invalid_forwarded_headers` for an unknown field or an entry that is not an address or
    /// CIDR block.
    pub fn parse(value: &Value) -> Result<Self, Invalid> {
        let config: TrustConfig = serde_json::from_value(value.clone()).map_err(|err| {
            Invalid::new(
                "invalid_forwarded_headers",
                format!("forwarded_headers: {err}"),
            )
        })?;
        Ok(Self {
            insecure: config.insecure,
            trusted: config.trusted_ips.into(),
        })
    }

    /// Whether `peer` may speak for the client: always with `insecure`, else when it is in
    /// `trusted_ips`. A connection with no IP peer is trusted only with `insecure`.
    #[must_use]
    pub fn trusts(&self, peer: Option<IpAddr>) -> bool {
        self.insecure || peer.is_some_and(|peer| self.is_trusted(peer))
    }

    fn is_trusted(&self, addr: IpAddr) -> bool {
        self.trusted.iter().any(|block| block.contains(addr))
    }

    /// Whether every peer is trusted.
    #[must_use]
    pub fn is_insecure(&self) -> bool {
        self.insecure
    }

    /// How this policy trusts more than `before` (`None`: the entry point had no policy and so
    /// trusted nobody), as a [`kind`], for the posture changes of a plan.
    #[must_use]
    pub fn relaxation(&self, before: Option<&Self>) -> Option<&'static str> {
        if self.insecure && !before.is_some_and(|old| old.insecure) {
            return Some(kind::FORWARDED_HEADERS_INSECURE);
        }
        let widened = self
            .trusted
            .iter()
            .any(|block| !before.is_some_and(|old| old.trusted.iter().any(|b| b.covers(block))));
        widened.then_some(kind::FORWARDED_TRUSTED_IPS_WIDENED)
    }
}

/// The forwarded-header policy of every entry point of `snapshot` that has one. A policy that does
/// not parse is left out, which trusts nobody; the compiler refuses such a snapshot before a table
/// is built from it.
#[must_use]
pub fn policies(snapshot: &Snapshot) -> HashMap<Box<str>, Trust> {
    snapshot
        .entry_points
        .iter()
        .filter_map(|policy| {
            let trust = Trust::parse(policy.forwarded_headers.as_ref()?).ok()?;
            Some((policy.name.clone(), trust))
        })
        .collect()
}

/// `http` or `https`: the scheme the client used, as far as the proxy can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
}

impl Proto {
    /// `"http"` or `"https"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn of(tls: bool) -> Self {
        if tls { Self::Https } else { Self::Http }
    }

    fn parse(token: &str) -> Option<Self> {
        if token.eq_ignore_ascii_case("https") {
            Some(Self::Https)
        } else if token.eq_ignore_ascii_case("http") {
            Some(Self::Http)
        } else {
            None
        }
    }
}

/// What podgate believes about where a request came from. Built once per request by
/// [`ForwardedView::of`], then read by the matcher, the IP middlewares and the upstream header
/// writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedView {
    /// The address of the connection's peer, normalized; [`UNKNOWN`] when there is none. With
    /// PROXY protocol this is the address the PROXY header carries.
    pub peer: IpAddr,
    /// The resolved client: the peer when it is not trusted, else the first untrusted address
    /// from the right of the chain it sent (the leftmost one when all are trusted).
    pub client_ip: IpAddr,
    /// The scheme of the client's request: the connection's TLS state, unless a trusted peer
    /// said otherwise in `X-Forwarded-Proto`. Never the request line's scheme.
    pub proto: Proto,
    /// The host a trusted peer reported in `X-Forwarded-Host` (lowercase, no port). `None`: the
    /// request's own `Host` is the client's host.
    pub host: Option<Box<str>>,
    /// The port a trusted peer reported in `X-Forwarded-Port`, else the local port of the
    /// connection the request arrived on.
    pub port: Option<u16>,
    /// The addresses a trusted peer forwarded, leftmost (closest to the client) first, without
    /// the peer itself. Empty for a peer that is not trusted.
    pub chain: Vec<IpAddr>,
    /// Whether the peer was trusted to speak for the client.
    pub trusted: bool,
}

impl Default for ForwardedView {
    /// A request nobody has looked at yet: unknown peer, plain HTTP, not trusted.
    fn default() -> Self {
        Self {
            peer: UNKNOWN,
            client_ip: UNKNOWN,
            proto: Proto::Http,
            host: None,
            port: None,
            chain: Vec::new(),
            trusted: false,
        }
    }
}

impl ForwardedView {
    /// Builds the view of the request on `session` and removes the headers it does not believe.
    /// `trust` is the policy of the entry point the request arrived on (`None`: it has none, so
    /// nobody is trusted), `tls` whether the connection is TLS.
    #[must_use]
    pub fn of(session: &mut Session, tls: bool, trust: Option<&Trust>) -> Self {
        // The one accessor that says who the peer is; the PROXY protocol spec replaces its
        // answer with the address in the header.
        let peer = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(std::net::SocketAddr::ip);
        let local_port = session
            .server_addr()
            .and_then(|addr| addr.as_inet())
            .map(std::net::SocketAddr::port);
        Self::from_request(session.req_header_mut(), peer, local_port, tls, trust)
    }

    /// [`Self::of`] over the parts it reads, so it needs no session.
    #[must_use]
    pub fn from_request(
        request: &mut RequestHeader,
        peer: Option<IpAddr>,
        local_port: Option<u16>,
        tls: bool,
        trust: Option<&Trust>,
    ) -> Self {
        let peer = peer.map(normalize);
        let peer_or_unknown = peer.unwrap_or(UNKNOWN);
        let Some(trust) = trust.filter(|trust| trust.trusts(peer)) else {
            strip_forwarded(request);
            return Self {
                peer: peer_or_unknown,
                client_ip: peer_or_unknown,
                proto: Proto::of(tls),
                port: local_port,
                ..Self::default()
            };
        };
        let mut chain = forwarded_chain(request);
        if chain.len() > MAX_CHAIN {
            chain.drain(..chain.len() - MAX_CHAIN);
        }
        let client_ip = chain
            .iter()
            .rev()
            .find(|addr| !trust.is_trusted(**addr))
            .or(chain.first())
            .copied()
            .unwrap_or(peer_or_unknown);
        Self {
            peer: peer_or_unknown,
            client_ip,
            proto: last_token(request, "x-forwarded-proto", Proto::parse)
                .unwrap_or_else(|| Proto::of(tls)),
            host: last_token(request, "x-forwarded-host", forwarded_host),
            port: last_token(request, "x-forwarded-port", |token| token.parse().ok())
                .or(local_port),
            chain,
            trusted: true,
        }
    }

    /// The client address for a feature that takes no strategy: [`Self::client_ip`], or `None`
    /// when the connection had no IP peer.
    #[must_use]
    pub fn known_client(&self) -> Option<IpAddr> {
        (self.client_ip != UNKNOWN).then_some(self.client_ip)
    }
}

/// Removes every header a peer that is not trusted could use to claim an address or scheme:
/// `X-Forwarded-*`, `X-Real-IP` and `Forwarded`.
fn strip_forwarded(request: &mut RequestHeader) {
    let doomed: Vec<HeaderName> = request
        .headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-forwarded-") || FORGEABLE.contains(&name.as_str())
        })
        .cloned()
        .collect();
    for name in doomed {
        request.remove_header(&name);
    }
}

/// The addresses a trusted peer forwarded, leftmost first: `X-Forwarded-For`, else the `for` of
/// `Forwarded`, else `X-Real-IP`. Entries that are not addresses are skipped.
fn forwarded_chain(request: &RequestHeader) -> Vec<IpAddr> {
    let from = |name: &str, parse: fn(&str) -> Option<IpAddr>| -> Vec<IpAddr> {
        request
            .headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|line| line.split(','))
            .filter_map(parse)
            .collect()
    };
    let chain = from("x-forwarded-for", parse_node);
    if !chain.is_empty() {
        return chain;
    }
    let chain = request
        .headers
        .get_all("forwarded")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split(','))
        .filter_map(forwarded_for)
        .collect::<Vec<_>>();
    if !chain.is_empty() {
        return chain;
    }
    request
        .headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_node)
        .into_iter()
        .collect()
}

/// The last well-formed comma-separated token of header `name` (every header line counts), as
/// the nearest trusted proxy wrote it.
fn last_token<T>(
    request: &RequestHeader,
    name: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Option<T> {
    request
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split(','))
        .filter_map(|token| parse(token.trim()))
        .last()
}

fn forwarded_host(token: &str) -> Option<Box<str>> {
    let valid = !token.is_empty()
        && token.len() <= MAX_HOST_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:[]".contains(&b));
    valid.then(|| host::normalize(token).into())
}

/// The `for` of one `Forwarded` element (RFC 7239), `None` for an obfuscated or unknown node.
fn forwarded_for(element: &str) -> Option<IpAddr> {
    element.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("for")
            .then(|| parse_node(value.trim().trim_matches('"')))
            .flatten()
    })
}

/// An address as a forwarding header writes it: `192.0.2.1`, `192.0.2.1:4711`, `2001:db8::1`,
/// `[2001:db8::1]` or `[2001:db8::1]:4711`, normalized. Anything else is `None`.
fn parse_node(token: &str) -> Option<IpAddr> {
    let token = token.trim();
    let is_port = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = token.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        if !(after.is_empty() || after.strip_prefix(':').is_some_and(is_port)) {
            return None;
        }
        return inside
            .parse::<Ipv6Addr>()
            .ok()
            .map(|v6| normalize(v6.into()));
    }
    if let Ok(addr) = token.parse::<IpAddr>() {
        return Some(normalize(addr));
    }
    let (addr, port) = token.rsplit_once(':')?;
    if !is_port(port) {
        return None;
    }
    addr.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

#[cfg(test)]
mod test {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn trust(value: &Value) -> Trust {
        Trust::parse(value).expect("valid policy")
    }

    fn request(headers: &[(&str, &str)]) -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        for (name, value) in headers {
            request
                .append_header(name.to_string(), *value)
                .expect("header");
        }
        request
    }

    fn view(
        peer: &str,
        policy: Option<&Trust>,
        tls: bool,
        headers: &[(&str, &str)],
    ) -> (ForwardedView, RequestHeader) {
        let mut request = request(headers);
        let view =
            ForwardedView::from_request(&mut request, Some(ip(peer)), Some(8080), tls, policy);
        (view, request)
    }

    #[test]
    fn mapped_addresses_become_ipv4() {
        assert_eq!(normalize(ip("::ffff:10.1.2.3")), ip("10.1.2.3"));
        assert_eq!(normalize(ip("::10.1.2.3")), ip("::10.1.2.3"));
        assert_eq!(normalize(ip("2001:db8::1")), ip("2001:db8::1"));
    }

    #[test]
    fn cidr_parses_blocks_addresses_and_mapped_blocks() {
        let block: Cidr = "10.0.0.0/8".parse().expect("block");
        assert!(block.contains(ip("10.9.9.9")) && block.contains(ip("::ffff:10.9.9.9")));
        assert!(!block.contains(ip("11.0.0.1")) && !block.contains(ip("::1")));
        let one: Cidr = "::1".parse().expect("address");
        assert!(one.contains(ip("::1")) && !one.contains(ip("::2")));
        let host_bits: Cidr = "10.1.2.3/8".parse().expect("block");
        assert!(host_bits.contains(ip("10.200.0.1")));
        let mapped: Cidr = "::ffff:10.0.0.0/104".parse().expect("mapped block");
        assert_eq!(mapped, block);
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("nope".parse::<Cidr>().is_err());
    }

    #[test]
    fn cidr_overlap_is_containment() {
        let cidr = |text: &str| text.parse::<Cidr>().expect("block");
        assert!(cidr("10.0.0.0/8").overlaps(&cidr("10.1.0.0/16")));
        assert!(cidr("10.1.0.0/16").overlaps(&cidr("10.0.0.0/8")));
        assert!(!cidr("10.0.0.0/8").overlaps(&cidr("11.0.0.0/8")));
        assert!(!cidr("10.0.0.0/8").overlaps(&cidr("2001:db8::/32")));
        assert!(cidr("10.0.0.0/8").covers(&cidr("10.1.0.0/16")));
        assert!(!cidr("10.1.0.0/16").covers(&cidr("10.0.0.0/8")));
    }

    #[test]
    fn nodes_with_ports_and_brackets_parse() {
        for (text, want) in [
            ("192.0.2.1", Some("192.0.2.1")),
            (" 192.0.2.1:4711 ", Some("192.0.2.1")),
            ("2001:db8::1", Some("2001:db8::1")),
            ("[2001:db8::1]", Some("2001:db8::1")),
            ("[2001:db8::1]:4711", Some("2001:db8::1")),
            ("::ffff:192.0.2.1", Some("192.0.2.1")),
            ("[::ffff:192.0.2.1]:80", Some("192.0.2.1")),
            ("unknown", None),
            ("_hidden", None),
            ("", None),
            ("999.1.1.1", None),
            ("192.0.2.1:", None),
            ("192.0.2.1:x", None),
            ("[2001:db8::1", None),
            ("[2001:db8::1]x", None),
            ("1.2.3.4, 5.6.7.8", None),
            ("fe80::1%eth0", None),
        ] {
            assert_eq!(parse_node(text), want.map(ip), "{text:?}");
        }
    }

    #[test]
    fn untrusted_peer_gets_the_view_of_its_connection() {
        let policy = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/8"]}));
        let (view, request) = view(
            "203.0.113.9",
            Some(&policy),
            false,
            &[
                ("X-Forwarded-For", "1.1.1.1"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "evil.test"),
                ("X-Forwarded-Port", "443"),
                ("X-Forwarded-Server", "evil"),
                ("X-Forwarded-Tls-Client-Cert-Subject", "CN=admin"),
                ("X-Real-IP", "1.1.1.1"),
                ("Forwarded", "for=1.1.1.1;proto=https"),
                ("X-Other", "kept"),
            ],
        );
        assert_eq!(view.client_ip, ip("203.0.113.9"));
        assert_eq!(view.proto, Proto::Http);
        assert_eq!(
            (view.host, view.port, view.trusted),
            (None, Some(8080), false)
        );
        assert!(view.chain.is_empty());
        let names: Vec<_> = request.headers.keys().map(|name| name.as_str()).collect();
        assert_eq!(names, ["x-other"]);
    }

    #[test]
    fn an_entry_point_without_a_policy_trusts_nobody() {
        let (view, request) = view("10.0.0.1", None, true, &[("X-Forwarded-For", "1.1.1.1")]);
        assert_eq!(view.client_ip, ip("10.0.0.1"));
        assert_eq!(view.proto, Proto::Https);
        assert!(request.headers.get("x-forwarded-for").is_none());
    }

    #[test]
    fn a_trusted_peer_is_walked_from_the_right_skipping_trusted_hops() {
        let policy = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/8", "192.168.0.0/16"]}));
        let walk = |xff: &str| {
            view(
                "10.0.0.1",
                Some(&policy),
                false,
                &[("X-Forwarded-For", xff)],
            )
            .0
            .client_ip
        };
        assert_eq!(walk("203.0.113.7"), ip("203.0.113.7"));
        assert_eq!(
            walk("9.9.9.9, 203.0.113.7, 10.0.0.2, 192.168.1.1"),
            ip("203.0.113.7")
        );
        assert_eq!(walk("10.0.0.5, 192.168.0.9"), ip("10.0.0.5"));
        assert_eq!(walk("::ffff:203.0.113.7, 10.0.0.2"), ip("203.0.113.7"));
        let (empty, _) = view("10.0.0.1", Some(&policy), false, &[]);
        assert_eq!(empty.client_ip, ip("10.0.0.1"));
    }

    #[test]
    fn a_trusted_peer_keeps_its_headers_and_proto_host_port() {
        let policy = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/8"]}));
        let (view, request) = view(
            "10.0.0.1",
            Some(&policy),
            false,
            &[
                ("X-Forwarded-For", "203.0.113.7"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "App.Test:8443"),
                ("X-Forwarded-Port", "8443"),
            ],
        );
        assert!(view.trusted);
        assert_eq!(view.proto, Proto::Https);
        assert_eq!(view.host.as_deref(), Some("app.test"));
        assert_eq!(view.port, Some(8443));
        assert_eq!(view.chain, [ip("203.0.113.7")]);
        assert_eq!(request.headers.len(), 4, "a trusted peer's headers stay");
    }

    #[test]
    fn a_trusted_peer_without_proto_falls_back_to_the_connection() {
        let policy = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/8"]}));
        let (plain, _) = view(
            "10.0.0.1",
            Some(&policy),
            false,
            &[("X-Forwarded-Proto", "ftp")],
        );
        assert_eq!((plain.proto, plain.port), (Proto::Http, Some(8080)));
        let (tls, _) = view("10.0.0.1", Some(&policy), true, &[]);
        assert_eq!(tls.proto, Proto::Https);
    }

    #[test]
    fn forwarded_and_real_ip_are_read_only_from_a_trusted_peer() {
        let policy = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/8"]}));
        let client =
            |headers: &[(&str, &str)]| view("10.0.0.1", Some(&policy), false, headers).0.client_ip;
        assert_eq!(
            client(&[(
                "Forwarded",
                "for=198.51.100.1;proto=https, for=\"[2001:db8::1]:4711\""
            )]),
            ip("2001:db8::1")
        );
        assert_eq!(
            client(&[("Forwarded", "for=_obfuscated, for=unknown")]),
            ip("10.0.0.1")
        );
        assert_eq!(client(&[("X-Real-IP", "198.51.100.2")]), ip("198.51.100.2"));
        assert_eq!(
            client(&[
                ("X-Forwarded-For", "198.51.100.3"),
                ("X-Real-IP", "198.51.100.2")
            ]),
            ip("198.51.100.3"),
            "X-Forwarded-For wins"
        );
    }

    #[test]
    fn malformed_entries_are_skipped_and_never_become_the_client() {
        let policy = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/8"]}));
        let walk = |xff: &str| {
            view(
                "10.0.0.1",
                Some(&policy),
                false,
                &[("X-Forwarded-For", xff)],
            )
            .0
        };
        assert_eq!(
            walk("203.0.113.7, not-an-ip, , 999.9.9.9, <script>").client_ip,
            ip("203.0.113.7")
        );
        let only_junk = walk("garbage, ,,");
        assert_eq!(
            only_junk.client_ip,
            ip("10.0.0.1"),
            "falls back to the peer"
        );
        assert!(only_junk.chain.is_empty());
        let long = vec!["1.2.3.4"; 5000].join(",");
        assert_eq!(walk(&long).chain.len(), MAX_CHAIN);
    }

    #[test]
    fn insecure_trusts_every_peer() {
        let policy = trust(&serde_json::json!({"insecure": true}));
        let (view, request) = view(
            "203.0.113.9",
            Some(&policy),
            false,
            &[("X-Forwarded-For", "1.1.1.1, 2.2.2.2")],
        );
        assert!(view.trusted && request.headers.contains_key("x-forwarded-for"));
        assert_eq!(view.client_ip, ip("2.2.2.2"));
        assert!(policy.is_insecure() && policy.trusts(None));
        assert!(!Trust::default().trusts(None));
    }

    #[test]
    fn a_connection_without_an_ip_peer_is_unknown() {
        let mut request = request(&[("X-Forwarded-For", "1.1.1.1")]);
        let view = ForwardedView::from_request(&mut request, None, None, false, None);
        assert_eq!(view.client_ip, UNKNOWN);
        assert_eq!(view.known_client(), None);
        assert!(request.headers.is_empty());
    }

    #[test]
    fn ip_strategy_depth() {
        let policy = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/8"]}));
        let (view, _) = view(
            "10.0.0.1",
            Some(&policy),
            false,
            &[("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")],
        );
        let at = |depth: u16| {
            ClientIp::resolve(
                &view,
                &IpStrategy {
                    depth: NonZeroU16::new(depth),
                    excluded: Vec::new(),
                },
            )
        };
        assert_eq!(at(0), ip("3.3.3.3"), "the entry point's own decision");
        assert_eq!(at(1), ip("3.3.3.3"));
        assert_eq!(at(2), ip("2.2.2.2"));
        assert_eq!(at(3), ip("1.1.1.1"));
        assert_eq!(at(4), ip("10.0.0.1"), "past the chain: the connection");
    }

    #[test]
    fn ip_strategy_excluded() {
        let policy = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/8"]}));
        let (view, _) = view(
            "10.0.0.1",
            Some(&policy),
            false,
            &[("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")],
        );
        let strategy = |depth: u16, excluded: &[&str]| IpStrategy {
            depth: NonZeroU16::new(depth),
            excluded: excluded
                .iter()
                .map(|text| text.parse().expect("block"))
                .collect(),
        };
        assert_eq!(
            ClientIp::resolve(&view, &strategy(0, &["3.3.3.3"])),
            ip("2.2.2.2")
        );
        assert_eq!(
            ClientIp::resolve(&view, &strategy(0, &["2.0.0.0/8", "3.3.3.3"])),
            ip("1.1.1.1")
        );
        assert_eq!(
            ClientIp::resolve(&view, &strategy(2, &["3.3.3.3"])),
            ip("1.1.1.1")
        );
        assert_eq!(
            ClientIp::resolve(&view, &strategy(1, &["::ffff:3.3.3.3"])),
            ip("2.2.2.2")
        );
        assert_eq!(
            ClientIp::resolve(&view, &strategy(0, &["0.0.0.0/0"])),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn an_untrusted_peer_has_no_chain_to_pick_from() {
        let (view, _) = view(
            "203.0.113.9",
            None,
            false,
            &[("X-Forwarded-For", "1.1.1.1")],
        );
        let strategy = IpStrategy {
            depth: NonZeroU16::new(1),
            excluded: Vec::new(),
        };
        assert_eq!(ClientIp::resolve(&view, &strategy), ip("203.0.113.9"));
    }

    #[test]
    fn strategies_are_read_from_json() {
        let strategy: IpStrategy = serde_json::from_value(
            serde_json::json!({"depth": 2, "excluded": ["10.0.0.0/8", "::1"]}),
        )
        .expect("strategy");
        assert_eq!(strategy.depth.map(NonZeroU16::get), Some(2));
        assert_eq!(strategy.excluded.len(), 2);
        assert!(serde_json::from_value::<IpStrategy>(serde_json::json!({"depth": 0})).is_err());
        assert!(serde_json::from_value::<IpStrategy>(serde_json::json!({"deep": 1})).is_err());
    }

    #[test]
    fn policies_that_do_not_parse_are_invalid() {
        for bad in [
            serde_json::json!({"trusted": ["10.0.0.0/8"]}),
            serde_json::json!({"trusted_ips": ["nope"]}),
            serde_json::json!({"trusted_ips": "10.0.0.0/8"}),
            serde_json::json!({"insecure": "yes"}),
            serde_json::json!(true),
        ] {
            let err = Trust::parse(&bad).expect_err(&bad.to_string());
            assert_eq!(err.code, "invalid_forwarded_headers", "{bad}");
        }
        assert_eq!(Trust::parse(&serde_json::json!({})), Ok(Trust::default()));
    }

    #[test]
    fn relaxations_are_insecure_or_wider_trust() {
        let narrow = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/16"]}));
        let wide = trust(&serde_json::json!({"trusted_ips": ["10.0.0.0/8"]}));
        let insecure = trust(&serde_json::json!({"insecure": true}));
        assert_eq!(
            insecure.relaxation(None),
            Some(kind::FORWARDED_HEADERS_INSECURE)
        );
        assert_eq!(
            insecure.relaxation(Some(&narrow)),
            Some(kind::FORWARDED_HEADERS_INSECURE)
        );
        assert_eq!(insecure.relaxation(Some(&insecure)), None);
        assert_eq!(
            wide.relaxation(Some(&narrow)),
            Some(kind::FORWARDED_TRUSTED_IPS_WIDENED)
        );
        assert_eq!(
            wide.relaxation(None),
            Some(kind::FORWARDED_TRUSTED_IPS_WIDENED)
        );
        assert_eq!(narrow.relaxation(Some(&wide)), None);
        assert_eq!(Trust::default().relaxation(None), None);
        assert_eq!(Trust::default().relaxation(Some(&wide)), None);
    }
}
