//! The forwarding headers an upstream receives.
//!
//! [`apply`] writes them from the request's [`ForwardedView`], the trust decision of
//! [`crate::client_ip`]: a peer the entry point does not trust has already had its own
//! `X-Forwarded-*`, `X-Real-IP` and `Forwarded` headers removed, so nothing a client sent can
//! reappear here, and a trusted peer's chain is extended with the peer's address. Reference:
//! `docs/ref/forwarded-headers.md`.
//!
//! | Header | Value |
//! |---|---|
//! | `X-Forwarded-For` | trusted peer: its chain, then the peer; else the peer |
//! | `X-Forwarded-Proto` | `https` when the connection is TLS (or a trusted peer said so), else `http` |
//! | `X-Forwarded-Host` | the `Host` or `:authority` the client sent (a trusted peer's value is kept) |
//! | `X-Forwarded-Port` | the entry point's port (a trusted peer's value is kept) |
//! | `X-Real-IP` | the resolved client |
//! | `Forwarded` | `for`, `proto` and `host`, RFC 7239, opt-in |
//! | `X-Forwarded-Server` | the node's name, opt-in |
//!
//! Every value is built from parsed addresses and validated host and port bytes into a stack
//! buffer, then set with replace semantics, so no header is ever duplicated and no byte a client
//! chose reaches a value unchecked. The chain is bounded to [`MAX_VALUE`] bytes by dropping its
//! oldest entries; [`render`] counts them. Headers this module does not write, such as
//! `X-Forwarded-Prefix` and `X-Forwarded-Tls-Client-Cert*`, are never touched.

use std::fmt::{self, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use pingora::http::RequestHeader;
use podgate_model::Forwarded;
use thiserror::Error;

use crate::client_ip::{ForwardedView, Proto, UNKNOWN, normalize};

/// Longest value written for `X-Forwarded-For` and `Forwarded`, in bytes.
pub const MAX_VALUE: usize = 1024;

/// Longest host written, in bytes.
const MAX_HOST: usize = 255;

/// Longest text of one address (`ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255`) plus quotes.
const MAX_NODE: usize = 48;

/// Longest single `Forwarded` element: `for="[..]";proto=https;host="<host>"`.
const MAX_ELEMENT: usize = MAX_HOST + 2 * MAX_NODE + 32;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PORT: HeaderName = HeaderName::from_static("x-forwarded-port");
const X_FORWARDED_SERVER: HeaderName = HeaderName::from_static("x-forwarded-server");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");

/// Entries dropped from over-long chains since the process started.
static TRUNCATED: AtomicU64 = AtomicU64::new(0);

/// Why a request cannot get its forwarding headers.
#[derive(Debug, Error)]
pub enum Error {
    /// The request's `Connection` header names a header podgate writes, which would make the next
    /// hop strip it: refused like Pingora refuses the ones it writes itself.
    #[error("the Connection header nominates {0}, which podgate sets")]
    Nominated(&'static str),
    /// The header could not be set. Values are validated first, so this is a bug.
    #[error("cannot set a forwarding header: {0}")]
    Set(#[source] Box<pingora::Error>),
}

/// The names of the headers [`apply`] writes for `set`, in the order they are written.
#[must_use]
pub fn names(set: Forwarded) -> Vec<&'static str> {
    let mut names = Vec::new();
    if set.x_forwarded {
        names.extend(["X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"]);
        names.push("X-Forwarded-Port");
    }
    if set.real_ip {
        names.push("X-Real-IP");
    }
    if set.rfc7239 {
        names.push("Forwarded");
    }
    if set.server {
        names.push("X-Forwarded-Server");
    }
    names
}

/// Writes the forwarding headers `set` asks for into `request`, replacing any copy already
/// there. `node` is the value of `X-Forwarded-Server`; without one that header is left out.
///
/// # Errors
///
/// [`Error::Nominated`] when the request's `Connection` header names one of the headers written,
/// which the caller answers `400`; [`Error::Set`] when a header cannot be set.
pub fn apply(
    request: &mut RequestHeader,
    view: &ForwardedView,
    set: Forwarded,
    node: Option<&HeaderValue>,
) -> Result<(), Error> {
    if !(set.x_forwarded || set.real_ip || set.rfc7239 || set.server) {
        return Ok(());
    }
    refuse_nominated(request, set)?;
    let peer = normalize(view.peer);
    let client = normalize(view.client_ip);
    let host = client_host(request, view);
    let port = client_port(view, host.as_ref());
    let proto = view.proto;

    if set.x_forwarded {
        match peer_chain(view, peer) {
            Some(value) => put(request, &X_FORWARDED_FOR, "X-Forwarded-For", value.bytes())?,
            None => drop_header(request, &X_FORWARDED_FOR),
        }
        put(
            request,
            &X_FORWARDED_PROTO,
            "X-Forwarded-Proto",
            proto.as_str().as_bytes(),
        )?;
        match &host {
            Some((host, _)) => put(request, &X_FORWARDED_HOST, "X-Forwarded-Host", host.bytes())?,
            None => drop_header(request, &X_FORWARDED_HOST),
        }
        let mut digits = Buf::<5>::new();
        write_into(&mut digits, format_args!("{port}"));
        put(
            request,
            &X_FORWARDED_PORT,
            "X-Forwarded-Port",
            digits.bytes(),
        )?;
    }
    if set.real_ip {
        if client == UNKNOWN {
            drop_header(request, &X_REAL_IP);
        } else {
            let mut text = Buf::<MAX_NODE>::new();
            write_into(&mut text, format_args!("{client}"));
            put(request, &X_REAL_IP, "X-Real-IP", text.bytes())?;
        }
    }
    if set.rfc7239 {
        match rfc7239(view, peer, host.as_ref().map(|(host, _)| host), proto) {
            Some(value) => put(request, &FORWARDED, "Forwarded", value.bytes())?,
            None => drop_header(request, &FORWARDED),
        }
    }
    if set.server {
        match node {
            Some(node) => {
                store(
                    request,
                    &X_FORWARDED_SERVER,
                    "X-Forwarded-Server",
                    node.clone(),
                )?;
            }
            None => drop_header(request, &X_FORWARDED_SERVER),
        }
    }
    Ok(())
}

/// Appends the counter of dropped chain entries, `podgate_forwarded_chain_truncated_total`, to
/// the metrics exposition `out`.
pub fn render(out: &mut String) {
    let name = "podgate_forwarded_chain_truncated_total";
    let _ = writeln!(
        out,
        "# HELP {name} Entries dropped from over-long X-Forwarded-For and Forwarded values.\n\
         # TYPE {name} counter\n{name} {}",
        TRUNCATED.load(Ordering::Relaxed)
    );
}

/// Refuses a `Connection` header that names a header written here.
fn refuse_nominated(request: &RequestHeader, set: Forwarded) -> Result<(), Error> {
    for line in request.headers.get_all(http::header::CONNECTION) {
        for token in line.as_bytes().split(|byte| *byte == b',') {
            let token = token.trim_ascii();
            let named = [
                (set.real_ip, "x-real-ip", "X-Real-IP"),
                (set.x_forwarded, "x-forwarded-port", "X-Forwarded-Port"),
                (set.rfc7239, "forwarded", "Forwarded"),
                (set.server, "x-forwarded-server", "X-Forwarded-Server"),
            ]
            .into_iter()
            .find(|(on, lower, _)| *on && token.eq_ignore_ascii_case(lower.as_bytes()));
            if let Some((_, _, shown)) = named {
                return Err(Error::Nominated(shown));
            }
        }
    }
    Ok(())
}

/// The host the client asked for, lowercase, with its port when it had one, and the port a
/// trusted peer's `X-Forwarded-Host` carried. `None` when the request names no valid host.
fn client_host(
    request: &RequestHeader,
    view: &ForwardedView,
) -> Option<(Buf<MAX_HOST>, Option<u16>)> {
    let own = || {
        let raw = match request.uri.authority() {
            Some(authority) => Some(authority.as_str()),
            None => request
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok()),
        };
        raw.and_then(Buf::host)
    };
    let reported = view
        .trusted
        .then(|| {
            request
                .headers
                .get_all("x-forwarded-host")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|line| line.split(','))
                .filter_map(|token| Buf::host(token.trim()))
                .next_back()
        })
        .flatten();
    let host = reported.or_else(own)?;
    let port = host.text().and_then(port_of);
    Some((host, port))
}

/// The port of the entry point, or the one a trusted proxy reported: in its `X-Forwarded-Port`,
/// else in its `X-Forwarded-Host`.
fn client_port(view: &ForwardedView, host: Option<&(Buf<MAX_HOST>, Option<u16>)>) -> u16 {
    let from_host = host
        .and_then(|(_, port)| *port)
        .filter(|_| view.trusted && !view.port_reported);
    from_host.or(view.port).unwrap_or(match view.proto {
        Proto::Http => 80,
        Proto::Https => 443,
    })
}

/// The port after the host of `host` (`a.test:8080`, `[::1]:8080`).
fn port_of(host: &str) -> Option<u16> {
    let after = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']')?.1.strip_prefix(':')?,
        None => host.split_once(':')?.1,
    };
    after.parse().ok()
}

/// `X-Forwarded-For`: a trusted peer's chain and then the peer, else the peer alone; the oldest
/// entries go first when the value would pass [`MAX_VALUE`]. `None` when the peer has no IP
/// address.
fn peer_chain(view: &ForwardedView, peer: IpAddr) -> Option<Buf<MAX_VALUE>> {
    if peer == UNKNOWN {
        return None;
    }
    let chain: &[IpAddr] = if view.trusted { &view.chain } else { &[] };
    let (value, dropped) = join(chain.len() + 1, |index, out: &mut Buf<MAX_ELEMENT>| {
        let addr = chain.get(index).map_or(peer, |addr| normalize(*addr));
        write!(out, "{addr}")
    });
    count_dropped(dropped);
    Some(value)
}

/// `Forwarded`: one `for` element per chain entry, the last one carrying `proto` and `host`.
fn rfc7239(
    view: &ForwardedView,
    peer: IpAddr,
    host: Option<&Buf<MAX_HOST>>,
    proto: Proto,
) -> Option<Buf<MAX_VALUE>> {
    if peer == UNKNOWN {
        return None;
    }
    let chain: &[IpAddr] = if view.trusted { &view.chain } else { &[] };
    let (value, dropped) = join(
        chain.len() + 1,
        |index, out: &mut Buf<MAX_ELEMENT>| match chain.get(index) {
            Some(addr) => write_node(out, normalize(*addr)),
            None => {
                write_node(out, peer)?;
                write!(out, ";proto={}", proto.as_str())?;
                match host {
                    Some(host) => write!(out, ";host=\"{}\"", host.text().unwrap_or_default()),
                    None => Ok(()),
                }
            }
        },
    );
    count_dropped(dropped);
    Some(value)
}

/// `for=` and the node: an IPv6 address is bracketed and quoted (RFC 7239 section 6).
fn write_node(out: &mut impl fmt::Write, addr: IpAddr) -> fmt::Result {
    match addr {
        IpAddr::V4(v4) => write!(out, "for={v4}"),
        IpAddr::V6(v6) => write!(out, "for=\"[{v6}]\""),
    }
}

/// Joins `count` elements with `, `, keeping the newest ones that fit [`MAX_VALUE`] (the last
/// element always stays). Returns the value and how many of the oldest were dropped.
fn join(
    count: usize,
    element: impl Fn(usize, &mut Buf<MAX_ELEMENT>) -> fmt::Result,
) -> (Buf<MAX_VALUE>, usize) {
    let mut scratch = Buf::<MAX_ELEMENT>::new();
    let mut first = count;
    let mut total = 0;
    while first > 0 {
        scratch.clear();
        if element(first - 1, &mut scratch).is_err() {
            break;
        }
        let needed = scratch.len() + if first == count { 0 } else { 2 };
        if total + needed > MAX_VALUE && first != count {
            break;
        }
        total += needed;
        first -= 1;
    }
    let mut out = Buf::<MAX_VALUE>::new();
    for index in first..count {
        scratch.clear();
        // Measured above: an element that failed there stops the loop before `first`.
        if element(index, &mut scratch).is_err() {
            continue;
        }
        if index > first {
            out.push(b", ");
        }
        out.push(scratch.bytes());
    }
    (out, first)
}

fn count_dropped(dropped: usize) {
    if dropped > 0 {
        TRUNCATED.fetch_add(dropped as u64, Ordering::Relaxed);
    }
}

/// Sets `name` to the bytes `value`, replacing every existing copy. `shown` is the casing an
/// HTTP/1 upstream sees.
fn put(
    request: &mut RequestHeader,
    name: &HeaderName,
    shown: &'static str,
    value: &[u8],
) -> Result<(), Error> {
    let value = HeaderValue::from_bytes(value).map_err(|err| {
        Error::Set(pingora::Error::because(
            pingora::ErrorType::InvalidHTTPHeader,
            "forwarding header value",
            err,
        ))
    })?;
    store(request, name, shown, value)
}

/// Sets `name` to `value`. Pingora keeps a second map of header case beside the header map and
/// exposes no way to change only one, so `insert_header` it is, and it parses and clones the
/// name on every call.
fn store(
    request: &mut RequestHeader,
    name: &HeaderName,
    shown: &'static str,
    value: HeaderValue,
) -> Result<(), Error> {
    request.remove_header(name);
    request
        .insert_header(Bytes::from_static(shown.as_bytes()), value)
        .map_err(Error::Set)
}

/// Removes every copy of `name`: podgate cannot say what it should be.
fn drop_header(request: &mut RequestHeader, name: &HeaderName) {
    request.remove_header(name);
}

/// Formats into a buffer that cannot overflow here: every caller sizes it for its content.
fn write_into<const N: usize>(out: &mut Buf<N>, args: fmt::Arguments<'_>) {
    // A formatting error means the buffer was too small, which the caller's size excludes; the
    // value is then cut short instead of panicking.
    let _ = out.write_fmt(args);
}

/// A fixed-capacity ASCII buffer on the stack: forwarding values are built here, so the only
/// allocation a header costs is the copy into the request.
#[derive(Clone)]
struct Buf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Buf<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn len(&self) -> usize {
        self.len
    }

    fn bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    fn text(&self) -> Option<&str> {
        std::str::from_utf8(self.bytes()).ok()
    }

    /// Appends `extra`, or nothing when it does not fit.
    fn push(&mut self, extra: &[u8]) -> bool {
        let Some(end) = self.len.checked_add(extra.len()).filter(|end| *end <= N) else {
            return false;
        };
        self.bytes[self.len..end].copy_from_slice(extra);
        self.len = end;
        true
    }
}

impl Buf<MAX_HOST> {
    /// `raw` lowercased, when it is a plausible host: 1 to [`MAX_HOST`] bytes of letters,
    /// digits and `-._:[]`. Anything else (a space, a control byte, `@`, `/`) is not a host
    /// podgate vouches for.
    fn host(raw: &str) -> Option<Self> {
        let valid = !raw.is_empty()
            && raw.len() <= MAX_HOST
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._:[]".contains(&byte));
        if !valid {
            return None;
        }
        let mut out = Self::new();
        for byte in raw.bytes() {
            out.push(&[byte.to_ascii_lowercase()]);
        }
        Some(out)
    }
}

impl<const N: usize> fmt::Write for Buf<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.push(text.as_bytes()) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn request(host: &str, extra: &[(&str, &str)]) -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request
            .insert_header("Host", host.to_owned())
            .expect("host header");
        for (name, value) in extra {
            request
                .append_header((*name).to_owned(), (*value).to_owned())
                .expect("header");
        }
        request
    }

    fn view(peer: &str, trusted: bool, chain: &[&str]) -> ForwardedView {
        ForwardedView {
            peer: ip(peer),
            client_ip: chain.first().map_or_else(|| ip(peer), |first| ip(first)),
            proto: Proto::Http,
            host: None,
            port: Some(8080),
            chain: chain.iter().map(|addr| ip(addr)).collect(),
            port_reported: false,
            trusted,
        }
    }

    fn values(request: &RequestHeader, name: &str) -> Vec<String> {
        request
            .headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().expect("ASCII").to_owned())
            .collect()
    }

    fn everything() -> Forwarded {
        Forwarded {
            rfc7239: true,
            server: true,
            ..Forwarded::default()
        }
    }

    #[test]
    fn forwarded_ipv6_and_mapped() {
        let mut req = request("a.test", &[]);
        let direct = view("2001:db8::1", false, &[]);

        apply(&mut req, &direct, everything(), None).expect("applies");

        assert_eq!(values(&req, "x-forwarded-for"), ["2001:db8::1"]);
        assert_eq!(values(&req, "x-real-ip"), ["2001:db8::1"]);
        assert_eq!(
            values(&req, "forwarded"),
            ["for=\"[2001:db8::1]\";proto=http;host=\"a.test\""],
            "no brackets in X-Forwarded-For, bracketed and quoted in Forwarded"
        );

        let mut req = request("a.test", &[]);
        let mut mapped = view(
            "::ffff:192.0.2.1",
            true,
            &["::ffff:198.51.100.2", "2001:db8::2"],
        );
        mapped.client_ip = ip("::ffff:198.51.100.2");
        apply(&mut req, &mapped, everything(), None).expect("applies");
        assert_eq!(
            values(&req, "x-forwarded-for"),
            ["198.51.100.2, 2001:db8::2, 192.0.2.1"],
            "IPv4-mapped addresses are written as IPv4"
        );
        assert_eq!(values(&req, "x-real-ip"), ["198.51.100.2"]);
        assert_eq!(
            values(&req, "forwarded"),
            ["for=198.51.100.2, for=\"[2001:db8::2]\", for=192.0.2.1;proto=http;host=\"a.test\""]
        );
    }

    #[test]
    fn forwarded_uses_proxy_protocol_address() {
        // The PROXY protocol replaces `Session::client_addr`, which is the only source of the
        // view's peer: the load balancer's own address (the socket peer) is never read here.
        let mut req = request("a.test", &[("x-forwarded-for", "10.9.9.9")]);
        let mut proxied = view("198.51.100.4", false, &[]);
        proxied.client_ip = ip("198.51.100.4");

        apply(&mut req, &proxied, Forwarded::default(), None).expect("applies");

        assert_eq!(values(&req, "x-forwarded-for"), ["198.51.100.4"]);
        assert_eq!(values(&req, "x-real-ip"), ["198.51.100.4"]);
    }

    #[test]
    fn forwarded_without_ip_peer_writes_no_address() {
        let mut req = request(
            "a.test",
            &[("x-forwarded-for", "10.9.9.9"), ("x-real-ip", "1.1.1.1")],
        );

        apply(&mut req, &ForwardedView::default(), everything(), None).expect("applies");

        assert!(values(&req, "x-forwarded-for").is_empty());
        assert!(values(&req, "x-real-ip").is_empty());
        assert!(values(&req, "forwarded").is_empty());
        assert_eq!(values(&req, "x-forwarded-proto"), ["http"]);
    }

    #[test]
    fn forwarded_replace_not_duplicate() {
        let mut req = request(
            "a.test",
            &[
                ("x-forwarded-for", "1.1.1.1"),
                ("x-forwarded-for", "2.2.2.2"),
                ("X-Real-IP", "3.3.3.3"),
                ("x-real-ip", "4.4.4.4"),
                ("forwarded", "for=5.5.5.5"),
            ],
        );

        apply(&mut req, &view("192.0.2.1", false, &[]), everything(), None).expect("applies");
        apply(&mut req, &view("192.0.2.1", false, &[]), everything(), None).expect("again");

        for name in [
            "x-forwarded-for",
            "x-real-ip",
            "forwarded",
            "x-forwarded-port",
        ] {
            assert_eq!(
                values(&req, name).len(),
                1,
                "{name}: {:?}",
                values(&req, name)
            );
        }
        assert_eq!(values(&req, "x-forwarded-for"), ["192.0.2.1"]);
    }

    #[test]
    fn forwarded_chain_bounded() {
        let chain: Vec<String> = (1..=200)
            .map(|n| format!("10.0.{}.{}", n / 250, n % 250))
            .collect();
        let (value, dropped) = join(chain.len(), |index, out: &mut Buf<MAX_ELEMENT>| {
            write!(out, "{}", chain[index])
        });

        let text = value.text().expect("ASCII");
        assert!(text.len() <= MAX_VALUE, "{}", text.len());
        assert!(
            text.ends_with("10.0.0.200"),
            "the newest entry stays: {text}"
        );
        assert!(dropped > 0);
        assert_eq!(
            text.split(", ").count() + dropped,
            chain.len(),
            "every entry is either kept or counted as dropped"
        );
        assert!(
            text.len() > MAX_VALUE - 20,
            "as many as fit are kept: {}",
            text.len()
        );
    }

    #[test]
    fn forwarded_host_is_validated_bytes() {
        for bad in ["a.test/evil", "user@a.test", "a b", "a.test\u{7f}", ""] {
            assert!(Buf::host(bad).is_none(), "{bad:?}");
        }
        let long = "a".repeat(MAX_HOST + 1);
        assert!(Buf::host(&long).is_none());
        let ok = Buf::host("[2001:DB8::1]:8443").expect("a bracketed host");
        assert_eq!(ok.text(), Some("[2001:db8::1]:8443"));
        assert_eq!(port_of("[2001:db8::1]:8443"), Some(8443));
        assert_eq!(port_of("[2001:db8::1]"), None);
        assert_eq!(port_of("a.test:80"), Some(80));
        assert_eq!(port_of("a.test"), None);
    }

    #[test]
    fn forwarded_leaves_other_headers_alone() {
        let mut req = request(
            "a.test",
            &[
                ("x-forwarded-prefix", "/app"),
                ("x-forwarded-tls-client-cert-info", "Subject=x"),
            ],
        );

        apply(&mut req, &view("192.0.2.1", false, &[]), everything(), None).expect("applies");

        assert_eq!(values(&req, "x-forwarded-prefix"), ["/app"]);
        assert_eq!(
            values(&req, "x-forwarded-tls-client-cert-info"),
            ["Subject=x"]
        );
    }

    #[test]
    fn forwarded_connection_nomination_is_an_error() {
        let mut req = request("a.test", &[("connection", "keep-alive, X-Forwarded-Port")]);

        let refused = apply(
            &mut req,
            &view("192.0.2.1", false, &[]),
            Forwarded::default(),
            None,
        );

        assert!(matches!(refused, Err(Error::Nominated("X-Forwarded-Port"))));
        let mut off = request("a.test", &[("connection", "x-real-ip")]);
        let set = Forwarded {
            real_ip: false,
            ..Forwarded::default()
        };
        assert!(apply(&mut off, &view("192.0.2.1", false, &[]), set, None).is_ok());
    }
}
