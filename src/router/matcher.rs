//! The matcher tree of a router.
//!
//! A matcher is JSON with exactly one key: a leaf (`host`, `path_prefix`, `method`, ...) or a
//! combinator (`all`, `any`, `not`). Each leaf lives in its own file and offers the same four
//! things: `parse`, `matches`, its contribution to the specificity ([`Spec`]), and `claims` (a
//! host leaf says which hosts the router is for). [`disjoint`] says when two matchers can
//! never both match, which the ambiguity check needs. Leaves of the planned set that no spec has
//! built yet (none today) are refused with `matcher_not_built`; a key that is not planned is
//! `invalid_matcher`.
//!
//! There are two dialects. An HTTP router matches a request (`host`, `path*`, `method`,
//! `header*`, `query*`, `client_ip`); a TCP router matches a connection (`sni`, `sni_regexp`,
//! `alpn`, `client_ip`). A leaf of the other dialect is `invalid_matcher`, so a router never
//! carries a leaf that has nothing to read. The combinators and `client_ip` belong to both.
//!
//! Adding a leaf: a file in this directory with the four functions, one variant in [`Matcher`],
//! and one arm in each of its `match` statements (the compiler lists them); remove the key from
//! `UNBUILT` and add its schema to `schema.rs` (`GET /v1/schema`).

use std::fmt;
use std::net::IpAddr;

use pingora::http::RequestHeader;
use serde_json::Value;

use crate::host::HostPattern;

mod alpn;
mod client_ip;
mod combinator;
mod header;
mod header_regexp;
mod host;
mod host_regexp;
mod method;
mod path;
mod path_prefix;
mod path_regexp;
mod query;
mod query_regexp;
mod schema;
mod sni;
mod sni_regexp;

use alpn::Alpn;
use client_ip::ClientIp;
use header::Header;
use header_regexp::HeaderRegexp;
use host::Host;
use host_regexp::HostRegexp;
use method::Method;
use path::Path;
use path_prefix::PathPrefix;
use path_regexp::PathRegexp;
use query::Query;
use query_regexp::QueryRegexp;
use sni::Sni;
use sni_regexp::SniRegexp;

pub use schema::schemas;

/// Deepest nesting of combinators a matcher may have.
pub const MAX_DEPTH: usize = 8;

/// Compiled size limit of one regular expression, in bytes.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Every key `parse_at` builds. `parse_at` refuses a key that is not listed here before it
/// looks at its arms, so an arm for a new leaf is dead until its key is listed; the schema
/// guard (`every_built_kind_has_a_schema`) compares this list with `schemas()`.
pub const BUILT: [&str; 17] = [
    "host",
    "host_regexp",
    "path",
    "path_prefix",
    "path_regexp",
    "method",
    "client_ip",
    "header",
    "header_regexp",
    "query",
    "query_regexp",
    "sni",
    "sni_regexp",
    "alpn",
    "all",
    "any",
    "not",
];

/// The leaves only an HTTP router has.
const HTTP_ONLY: [&str; 10] = [
    "host",
    "host_regexp",
    "path",
    "path_prefix",
    "path_regexp",
    "method",
    "header",
    "header_regexp",
    "query",
    "query_regexp",
];

/// The leaves only a TCP router has.
const TCP_ONLY: [&str; 3] = ["sni", "sni_regexp", "alpn"];

/// Leaves that are planned and not built: refused with `matcher_not_built`.
pub const UNBUILT: [&str; 0] = [];

/// Why a matcher is refused: a stable code and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// `invalid_matcher`, `invalid_host` or `matcher_not_built`.
    pub code: &'static str,
    /// What is wrong, naming the key.
    pub message: String,
}

impl Error {
    pub(super) fn invalid(message: impl fmt::Display) -> Self {
        Self {
            code: "invalid_matcher",
            message: message.to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// What a matcher sees of one request. Built once per request, after path normalization.
#[derive(Debug, Clone, Copy)]
pub struct View<'a> {
    /// The normalized host: lowercase, no port.
    pub host: &'a str,
    /// The normalized path (see [`super::path`]).
    pub path: &'a str,
    /// The entry point the request arrived on.
    pub entry_point: &'a str,
    /// Whether the connection is TLS.
    pub tls: bool,
    /// The request head: method, headers, query.
    pub request: &'a RequestHeader,
    /// The resolved client address (see [`crate::client_ip`]); `None` when it is not known, which
    /// no `client_ip` leaf matches.
    pub client_ip: Option<IpAddr>,
    /// What the connection's TLS ClientHello offered; [`Hello::NONE`] for an HTTP request, and
    /// for a TCP connection that is not TLS.
    pub hello: Hello<'a>,
}

/// What a TLS ClientHello offered, as the TCP leaves read it.
#[derive(Debug, Clone, Copy)]
pub struct Hello<'a> {
    /// The normalized server name; `None` when the client sent none.
    pub server_name: Option<&'a str>,
    /// The ALPN protocols offered, in the client's order; empty when it sent none.
    pub alpn: &'a [Vec<u8>],
}

impl Hello<'_> {
    /// No ClientHello: no server name and no protocols.
    pub const NONE: Hello<'static> = Hello {
        server_name: None,
        alpn: &[],
    };
}

/// Which leaves a matcher tree may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// The `match` of an HTTP router.
    Http,
    /// The `match` of a TCP router.
    Tcp,
}

/// A host a router is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// An exact name or a `*.` wildcard.
    Pattern(HostPattern),
    /// A regular expression: claims no literal host.
    Regexp,
}

/// How specific a matcher is, beyond its host: compared field by field, larger is more specific.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Spec {
    /// The path constraint: exact beats prefix beats regexp beats none, and within one class
    /// more segments beat fewer.
    pub path: u32,
    /// How many other constraints (method, header, query, client IP) there are.
    pub others: u32,
}

/// A leaf that kept a request from matching: what explain shows for a near miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The matcher key (`header`, `path_prefix`, `not`, ...).
    pub leaf: &'static str,
    /// What the leaf wanted, for the leaves that say (`header`, `header_regexp`, `query`,
    /// `query_regexp`); empty otherwise.
    pub wanted: String,
}

impl Failure {
    fn key(leaf: &'static str) -> Self {
        Self {
            leaf,
            wanted: String::new(),
        }
    }

    /// Whether the leaf is about the host, which a near miss must not be.
    #[must_use]
    pub fn is_host(&self) -> bool {
        matches!(self.leaf, "host" | "host_regexp")
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wanted.is_empty() {
            f.write_str(self.leaf)
        } else {
            write!(f, "{} {}", self.leaf, self.wanted)
        }
    }
}

/// A parsed matcher tree.
#[derive(Debug)]
pub enum Matcher {
    /// `host`
    Host(Host),
    /// `host_regexp`
    HostRegexp(HostRegexp),
    /// `path`
    Path(Path),
    /// `path_prefix`
    PathPrefix(PathPrefix),
    /// `path_regexp`
    PathRegexp(PathRegexp),
    /// `method`
    Method(Method),
    /// `client_ip`
    ClientIp(ClientIp),
    /// `header`
    Header(Header),
    /// `header_regexp`
    HeaderRegexp(HeaderRegexp),
    /// `query`
    Query(Query),
    /// `query_regexp`
    QueryRegexp(QueryRegexp),
    /// `sni`
    Sni(Sni),
    /// `sni_regexp`
    SniRegexp(SniRegexp),
    /// `alpn`
    Alpn(Alpn),
    /// `all`: every child matches.
    All(Vec<Matcher>),
    /// `any`: some child matches.
    Any(Vec<Matcher>),
    /// `not`: the child does not match.
    Not(Box<Matcher>),
}

/// Parses the matcher tree of an HTTP router.
///
/// # Errors
///
/// [`Error`] for a value that is not an object with exactly one key, an unknown or unbuilt key,
/// a TCP leaf, a leaf with a bad argument (including a bad host or regular expression), or
/// nesting deeper than [`MAX_DEPTH`].
pub fn parse(value: &Value) -> Result<Matcher, Error> {
    parse_in(Dialect::Http, value)
}

/// Parses the matcher tree of a router of `dialect`; see [`parse`] for the errors.
///
/// # Errors
///
/// [`Error`], and `invalid_matcher` for a leaf of the other dialect.
pub fn parse_in(dialect: Dialect, value: &Value) -> Result<Matcher, Error> {
    parse_at(dialect, value, 0)
}

pub(super) fn parse_at(dialect: Dialect, value: &Value, depth: usize) -> Result<Matcher, Error> {
    if depth > MAX_DEPTH {
        return Err(Error::invalid(format!(
            "matchers nest at most {MAX_DEPTH} deep"
        )));
    }
    let object = value
        .as_object()
        .ok_or_else(|| Error::invalid("a matcher is an object with exactly one key"))?;
    let mut entries = object.iter();
    let (Some((key, argument)), None) = (entries.next(), entries.next()) else {
        return Err(Error::invalid(
            "a matcher is an object with exactly one key",
        ));
    };
    let (wrong, other_dialect) = match dialect {
        Dialect::Http => (&TCP_ONLY[..], "TCP"),
        Dialect::Tcp => (&HTTP_ONLY[..], "HTTP"),
    };
    if wrong.contains(&key.as_str()) {
        return Err(Error::invalid(format!(
            "{key} is a {other_dialect} leaf: {}",
            match dialect {
                Dialect::Http => {
                    "a router on an HTTP entry point matches host, path, method, header, query and client_ip"
                }
                Dialect::Tcp => {
                    "a TCP router matches sni, sni_regexp, alpn and client_ip, because a connection has no request yet"
                }
            }
        )));
    }
    Ok(match key.as_str() {
        other if !BUILT.contains(&other) && UNBUILT.contains(&other) => {
            return Err(Error {
                code: "matcher_not_built",
                message: format!("matcher {other} is planned and not built yet"),
            });
        }
        other if !BUILT.contains(&other) => {
            return Err(Error::invalid(format!("unknown matcher {other}")));
        }
        "host" => Matcher::Host(Host::parse(argument)?),
        "host_regexp" => Matcher::HostRegexp(HostRegexp::parse(argument)?),
        "path" => Matcher::Path(Path::parse(argument)?),
        "path_prefix" => Matcher::PathPrefix(PathPrefix::parse(argument)?),
        "path_regexp" => Matcher::PathRegexp(PathRegexp::parse(argument)?),
        "method" => Matcher::Method(Method::parse(argument)?),
        "client_ip" => Matcher::ClientIp(ClientIp::parse(argument)?),
        "header" => Matcher::Header(Header::parse(argument)?),
        "header_regexp" => Matcher::HeaderRegexp(HeaderRegexp::parse(argument)?),
        "query" => Matcher::Query(Query::parse(argument)?),
        "query_regexp" => Matcher::QueryRegexp(QueryRegexp::parse(argument)?),
        "sni" => Matcher::Sni(Sni::parse(argument)?),
        "sni_regexp" => Matcher::SniRegexp(SniRegexp::parse(argument)?),
        "alpn" => Matcher::Alpn(Alpn::parse(argument)?),
        "all" => Matcher::All(combinator::parse_list(dialect, key, argument, depth)?),
        "any" => Matcher::Any(combinator::parse_list(dialect, key, argument, depth)?),
        "not" => Matcher::Not(Box::new(parse_at(dialect, argument, depth + 1)?)),
        other => return Err(Error::invalid(format!("unknown matcher {other}"))),
    })
}

/// Compiles `pattern`, refusing one whose compiled form is too large.
pub(super) fn regex(key: &str, pattern: &str) -> Result<regex::Regex, Error> {
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|err| Error::invalid(format!("{key}: {err}")))
}

impl Matcher {
    /// Whether `view` matches.
    #[must_use]
    pub fn matches(&self, view: &View<'_>) -> bool {
        match self {
            Self::Host(leaf) => leaf.matches(view),
            Self::HostRegexp(leaf) => leaf.matches(view),
            Self::Path(leaf) => leaf.matches(view),
            Self::PathPrefix(leaf) => leaf.matches(view),
            Self::PathRegexp(leaf) => leaf.matches(view),
            Self::Method(leaf) => leaf.matches(view),
            Self::ClientIp(leaf) => leaf.matches(view),
            Self::Header(leaf) => leaf.matches(view),
            Self::HeaderRegexp(leaf) => leaf.matches(view),
            Self::Query(leaf) => leaf.matches(view),
            Self::QueryRegexp(leaf) => leaf.matches(view),
            Self::Sni(leaf) => leaf.matches(view),
            Self::SniRegexp(leaf) => leaf.matches(view),
            Self::Alpn(leaf) => leaf.matches(view),
            Self::All(children) => children.iter().all(|child| child.matches(view)),
            Self::Any(children) => children.iter().any(|child| child.matches(view)),
            Self::Not(child) => !child.matches(view),
        }
    }

    /// The leaves that keep `view` from matching, empty when it matches. `all` names every child
    /// that fails, `any` (when none matches) the failures of every branch, and `not` itself when
    /// its child matches.
    #[must_use]
    pub fn failures(&self, view: &View<'_>) -> Vec<Failure> {
        let mut failed = Vec::new();
        self.collect_failures(view, &mut failed);
        failed
    }

    fn collect_failures(&self, view: &View<'_>, failed: &mut Vec<Failure>) {
        if self.matches(view) {
            return;
        }
        let said = |leaf, wanted| Failure { leaf, wanted };
        let failure = match self {
            Self::Host(_) => Failure::key("host"),
            Self::HostRegexp(_) => Failure::key("host_regexp"),
            Self::Path(_) => Failure::key("path"),
            Self::PathPrefix(_) => Failure::key("path_prefix"),
            Self::PathRegexp(_) => Failure::key("path_regexp"),
            Self::Method(_) => Failure::key("method"),
            Self::ClientIp(_) => Failure::key("client_ip"),
            Self::Header(leaf) => said("header", leaf.describe()),
            Self::HeaderRegexp(leaf) => said("header_regexp", leaf.describe()),
            Self::Query(leaf) => said("query", leaf.describe()),
            Self::QueryRegexp(leaf) => said("query_regexp", leaf.describe()),
            Self::Sni(_) => Failure::key("sni"),
            Self::SniRegexp(_) => Failure::key("sni_regexp"),
            Self::Alpn(_) => Failure::key("alpn"),
            Self::Not(_) => Failure::key("not"),
            Self::All(children) | Self::Any(children) => {
                for child in children {
                    child.collect_failures(view, failed);
                }
                return;
            }
        };
        failed.push(failure);
    }

    /// The hosts a match can be for, or `None` when the matcher does not limit the host (so the
    /// router can match any host). `all` is limited by its limited children, and a child that
    /// names only literal hosts bounds it: a `host_regexp` next to a literal host narrows that
    /// claim and never widens it. `any` is limited only when every branch is, `not` never.
    #[must_use]
    pub fn claims(&self) -> Option<Vec<Claim>> {
        match self {
            Self::Host(leaf) => Some(leaf.claims()),
            Self::HostRegexp(_) | Self::SniRegexp(_) => Some(vec![Claim::Regexp]),
            Self::Sni(leaf) => Some(leaf.claims()),
            Self::Path(_)
            | Self::PathPrefix(_)
            | Self::PathRegexp(_)
            | Self::Method(_)
            | Self::ClientIp(_)
            | Self::Header(_)
            | Self::HeaderRegexp(_)
            | Self::Query(_)
            | Self::QueryRegexp(_)
            | Self::Alpn(_)
            | Self::Not(_) => None,
            Self::All(children) => {
                let limited: Vec<Vec<Claim>> = children.iter().filter_map(Self::claims).collect();
                if limited.is_empty() {
                    return None;
                }
                let literal: Vec<Claim> = limited
                    .iter()
                    .filter(|claims| {
                        claims
                            .iter()
                            .all(|claim| matches!(claim, Claim::Pattern(_)))
                    })
                    .flatten()
                    .cloned()
                    .collect();
                Some(if literal.is_empty() {
                    limited.into_iter().flatten().collect()
                } else {
                    literal
                })
            }
            Self::Any(children) => {
                let mut all = Vec::new();
                for child in children {
                    all.extend(child.claims()?);
                }
                Some(all)
            }
        }
    }

    /// The specificity beyond the host. `all` takes the largest of each field, `any` the
    /// smallest, `not` counts as nothing.
    #[must_use]
    pub fn spec(&self) -> Spec {
        match self {
            Self::Host(_) | Self::HostRegexp(_) | Self::Not(_) => Spec::default(),
            Self::Path(leaf) => leaf.spec(),
            Self::PathPrefix(leaf) => leaf.spec(),
            Self::PathRegexp(leaf) => leaf.spec(),
            Self::Method(leaf) => leaf.spec(),
            Self::ClientIp(leaf) => leaf.spec(),
            Self::Header(leaf) => leaf.spec(),
            Self::HeaderRegexp(leaf) => leaf.spec(),
            Self::Query(leaf) => leaf.spec(),
            Self::QueryRegexp(leaf) => leaf.spec(),
            Self::Sni(leaf) => leaf.spec(),
            Self::SniRegexp(leaf) => leaf.spec(),
            Self::Alpn(leaf) => leaf.spec(),
            Self::All(children) => {
                children
                    .iter()
                    .map(Self::spec)
                    .fold(Spec::default(), |best, next| Spec {
                        path: best.path.max(next.path),
                        others: best.others.max(next.others),
                    })
            }
            Self::Any(children) => children
                .iter()
                .map(Self::spec)
                .reduce(|least, next| Spec {
                    path: least.path.min(next.path),
                    others: least.others.min(next.others),
                })
                .unwrap_or_default(),
        }
    }

    /// Whether the tree has a leaf that reads the TLS ClientHello (`sni`, `sni_regexp`,
    /// `alpn`): such a router can only take a TLS connection.
    #[must_use]
    pub fn reads_hello(&self) -> bool {
        match self {
            Self::Sni(_) | Self::SniRegexp(_) | Self::Alpn(_) => true,
            Self::All(children) | Self::Any(children) => children.iter().any(Self::reads_hello),
            Self::Not(child) => child.reads_hello(),
            _ => false,
        }
    }

    /// The protocols of the `alpn` leaves that are not under a `not`, in the order written and
    /// without repeats: what a handshake for this matcher can negotiate.
    #[must_use]
    pub fn alpn_protocols(&self) -> Vec<&[u8]> {
        let mut found: Vec<&[u8]> = Vec::new();
        self.collect_alpn(&mut found);
        found
    }

    fn collect_alpn<'a>(&'a self, found: &mut Vec<&'a [u8]>) {
        match self {
            Self::Alpn(leaf) => {
                for protocol in leaf.protocols() {
                    if !found.contains(&protocol) {
                        found.push(protocol);
                    }
                }
            }
            Self::All(children) | Self::Any(children) => {
                for child in children {
                    child.collect_alpn(found);
                }
            }
            _ => {}
        }
    }
}

/// Whether no request can match both `a` and `b`. Conservative: `false` means "may overlap".
/// Regular expressions and `not` are never provably disjoint.
#[must_use]
pub fn disjoint(a: &Matcher, b: &Matcher) -> bool {
    match (a, b) {
        (Matcher::All(children), other) | (other, Matcher::All(children)) => {
            children.iter().any(|child| disjoint(child, other))
        }
        (Matcher::Any(children), other) | (other, Matcher::Any(children)) => {
            children.iter().all(|child| disjoint(child, other))
        }
        (Matcher::Not(_), _) | (_, Matcher::Not(_)) => false,
        (Matcher::Path(a), Matcher::Path(b)) => path::exact_disjoint(a, b),
        (Matcher::Path(exact), Matcher::PathPrefix(prefix))
        | (Matcher::PathPrefix(prefix), Matcher::Path(exact)) => {
            !path_prefix::covers(prefix, exact.as_str())
        }
        (Matcher::PathPrefix(a), Matcher::PathPrefix(b)) => path_prefix::disjoint(a, b),
        (Matcher::Method(a), Matcher::Method(b)) => method::disjoint(a, b),
        (Matcher::ClientIp(a), Matcher::ClientIp(b)) => client_ip::disjoint(a, b),
        (Matcher::Header(a), Matcher::Header(b)) => header::disjoint(a, b),
        (Matcher::Query(a), Matcher::Query(b)) => query::disjoint(a, b),
        (Matcher::Sni(a), Matcher::Sni(b)) => sni::disjoint(a, b),
        _ => false,
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn parsed(value: &Value) -> Matcher {
        parse(value).expect("parses")
    }

    #[test]
    fn rejects_zero_or_several_keys_and_unknown_leaves() {
        for bad in [
            json!({}),
            json!({"host": "a.test", "path": "/x"}),
            json!("host"),
            json!({"hots": "a.test"}),
            json!({"all": []}),
            json!({"host": []}),
            json!({"method": ["NOT A METHOD"]}),
            json!({"path": "no-slash"}),
            json!({"path": "/a//b"}),
            json!({"path_regexp": "("}),
        ] {
            let err = parse(&bad).expect_err(&bad.to_string());
            assert_eq!(err.code, "invalid_matcher", "{bad}: {err}");
        }
        assert_eq!(
            parse(&json!({"host": "a b"})).expect_err("bad host").code,
            "invalid_host"
        );
    }

    #[test]
    fn planned_but_unbuilt_leaves_say_so() {
        for key in UNBUILT {
            let err = parse(&json!({ key: "x" })).expect_err(key);
            assert_eq!(err.code, "matcher_not_built", "{key}");
        }
    }

    #[test]
    fn built_lists_exactly_the_keys_the_parser_builds() {
        for key in BUILT {
            let dialect = if TCP_ONLY.contains(&key) {
                Dialect::Tcp
            } else {
                Dialect::Http
            };
            let err = parse_in(dialect, &json!({ key: null })).expect_err(key);
            assert_ne!(err.code, "matcher_not_built", "{key}");
            assert!(
                !err.message.starts_with("unknown matcher"),
                "{key} is listed in BUILT and has no arm: {err}"
            );
        }
        let err = parse(&json!({ "zzz_unlisted": "x" })).expect_err("unlisted");
        assert_eq!(err.message, "unknown matcher zzz_unlisted");
        assert!(UNBUILT.iter().all(|key| !BUILT.contains(key)));
        let shared = ["client_ip"];
        let dialects = HTTP_ONLY.iter().chain(&TCP_ONLY).chain(&shared);
        assert!(
            BUILT
                .iter()
                .filter(|key| !["all", "any", "not"].contains(key))
                .all(|key| dialects.clone().any(|known| known == key)),
            "every leaf belongs to a dialect"
        );
    }

    #[test]
    fn matcher_dialect_enforced() {
        let http_leaves = [
            json!({"host": "a.test"}),
            json!({"host_regexp": "a"}),
            json!({"path": "/a"}),
            json!({"path_prefix": "/a"}),
            json!({"path_regexp": "a"}),
            json!({"method": "GET"}),
            json!({"header": {"name": "x"}}),
            json!({"header_regexp": {"name": "x", "regex": "y"}}),
            json!({"query": {"name": "x"}}),
            json!({"query_regexp": {"name": "x", "regex": "y"}}),
        ];
        let tcp_leaves = [
            json!({"sni": "a.test"}),
            json!({"sni_regexp": "a"}),
            json!({"alpn": "h2"}),
        ];
        let both = [
            json!({"client_ip": "10.0.0.0/8"}),
            json!({"all": [{"client_ip": "10.0.0.0/8"}]}),
        ];
        for leaf in &http_leaves {
            assert!(parse_in(Dialect::Http, leaf).is_ok(), "{leaf}");
            let err = parse_in(Dialect::Tcp, leaf).expect_err("an HTTP leaf on a TCP router");
            assert_eq!(err.code, "invalid_matcher", "{leaf}: {err}");
            // Nested under every combinator it is still refused.
            for wrap in ["all", "any"] {
                let nested = json!({ wrap: [{"client_ip": "10.0.0.0/8"}, leaf] });
                assert!(parse_in(Dialect::Tcp, &nested).is_err(), "{nested}");
            }
            let nested = json!({"not": leaf});
            assert!(parse_in(Dialect::Tcp, &nested).is_err(), "{nested}");
        }
        for leaf in &tcp_leaves {
            assert!(parse_in(Dialect::Tcp, leaf).is_ok(), "{leaf}");
            let err = parse_in(Dialect::Http, leaf).expect_err("a TCP leaf on an HTTP router");
            assert_eq!(err.code, "invalid_matcher", "{leaf}: {err}");
            assert!(parse(leaf).is_err(), "`parse` is the HTTP dialect");
            for wrap in ["all", "any"] {
                let nested = json!({ wrap: [{"client_ip": "10.0.0.0/8"}, leaf] });
                assert!(parse_in(Dialect::Http, &nested).is_err(), "{nested}");
            }
            let nested = json!({"not": leaf});
            assert!(parse_in(Dialect::Http, &nested).is_err(), "{nested}");
        }
        for leaf in &both {
            assert!(parse_in(Dialect::Http, leaf).is_ok(), "{leaf}");
            assert!(parse_in(Dialect::Tcp, leaf).is_ok(), "{leaf}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let mut value = json!({"host": "a.test"});
        for _ in 0..MAX_DEPTH {
            value = json!({"not": value});
        }
        assert!(parse(&value).is_ok());
        assert!(parse(&json!({"not": value})).is_err());
    }

    #[test]
    fn claims_follow_the_boolean_structure() {
        let literal = |matcher: &Matcher| {
            matcher
                .claims()
                .map(|claims| claims.len())
                .map_or(-1, |len| i32::try_from(len).expect("small"))
        };
        assert_eq!(
            literal(&parsed(&json!({"host": ["a.test", "*.b.test"]}))),
            2
        );
        assert_eq!(literal(&parsed(&json!({"path": "/x"}))), -1);
        let all = parsed(&json!({"all": [{"host": "a.test"}, {"path": "/x"}]}));
        assert_eq!(literal(&all), 1);
        let any = parsed(&json!({"any": [{"host": "a.test"}, {"path": "/x"}]}));
        assert_eq!(literal(&any), -1, "one branch is host-free");
        let any = parsed(&json!({"any": [{"host": "a.test"}, {"host": "b.test"}]}));
        assert_eq!(literal(&any), 2);
        assert_eq!(literal(&parsed(&json!({"not": {"host": "a.test"}}))), -1);
        // A regexp next to a literal host only narrows the claim: the router is limited to the
        // literal host and stays a literal router, so the regexp cannot widen it.
        let narrowed = parsed(
            &json!({"all": [{"host": "*.a.test"}, {"host_regexp": "^(other\\.test|x\\.a\\.test)$"}]}),
        );
        assert_eq!(literal(&narrowed), 1);
        let alone = parsed(&json!({"all": [{"host_regexp": "^a"}, {"path": "/x"}]}));
        assert!(
            alone
                .claims()
                .is_some_and(|claims| claims.contains(&Claim::Regexp))
        );
    }

    #[test]
    fn specificity_orders_path_classes_and_segments() {
        let spec = |value: Value| parsed(&value).spec();
        assert!(spec(json!({"path": "/a"})) > spec(json!({"path_prefix": "/a"})));
        assert!(spec(json!({"path_prefix": "/a/b"})) > spec(json!({"path_prefix": "/a"})));
        assert!(spec(json!({"path_prefix": "/a"})) > spec(json!({"path_regexp": "^/a"})));
        assert!(spec(json!({"path_regexp": "^/a"})) > spec(json!({"host": "a.test"})));
        let both = spec(json!({"all": [{"method": ["GET"]}, {"path_prefix": "/a"}]}));
        assert_eq!(both.others, 1);
        let either = spec(json!({"any": [{"method": ["GET"]}, {"path_prefix": "/a"}]}));
        assert_eq!(either, Spec::default());
    }

    #[test]
    fn disjointness_is_proved_only_for_literals() {
        let pair = |a: Value, b: Value| disjoint(&parsed(&a), &parsed(&b));
        assert!(pair(json!({"path": "/a"}), json!({"path": "/b"})));
        assert!(!pair(json!({"path": "/a"}), json!({"path": "/a"})));
        assert!(pair(json!({"path": "/a"}), json!({"path_prefix": "/b"})));
        assert!(!pair(json!({"path": "/b/x"}), json!({"path_prefix": "/b"})));
        assert!(pair(
            json!({"path_prefix": "/a"}),
            json!({"path_prefix": "/b"})
        ));
        assert!(!pair(
            json!({"path_prefix": "/a"}),
            json!({"path_prefix": "/a/b"})
        ));
        assert!(pair(
            json!({"method": ["GET"]}),
            json!({"method": ["POST"]})
        ));
        assert!(!pair(json!({"path_regexp": "^/a"}), json!({"path": "/b"})));
        assert!(pair(
            json!({"all": [{"host": "a.test"}, {"path": "/a"}]}),
            json!({"path": "/b"})
        ));
        assert!(pair(
            json!({"any": [{"path": "/a"}, {"path": "/b"}]}),
            json!({"path": "/c"})
        ));
        assert!(!pair(
            json!({"any": [{"path": "/a"}, {"path": "/c"}]}),
            json!({"path": "/c"})
        ));
    }

    #[test]
    fn request_leaves_specificity() {
        let spec = |value: Value| parsed(&value).spec();
        for leaf in [
            json!({"header": {"name": "x-env", "value": "a"}}),
            json!({"header": {"name": "x-env"}}),
            json!({"header_regexp": {"name": "x-env", "regex": "^a"}}),
            json!({"query": {"name": "debug", "value": "1"}}),
            json!({"query_regexp": {"name": "debug", "regex": "1"}}),
        ] {
            assert_eq!(spec(leaf.clone()), Spec { path: 0, others: 1 }, "{leaf}");
        }
        let several = spec(json!({"all": [
            {"header": {"name": "x-env", "value": "a"}},
            {"query": {"name": "debug"}},
            {"method": ["GET"]},
        ]}));
        assert_eq!(several.others, 1, "`all` takes the largest, not the sum");
        assert!(
            spec(json!({"all": [{"path_prefix": "/a"}, {"header": {"name": "x"}}]}))
                > spec(json!({"path_prefix": "/a"}))
        );
        let either = spec(json!({"any": [
            {"header": {"name": "x-env", "value": "a"}},
            {"path_prefix": "/a"},
        ]}));
        assert_eq!(either.others, 0);
    }

    #[test]
    fn request_leaves_disjoint() {
        let pair = |a: Value, b: Value| disjoint(&parsed(&a), &parsed(&b));
        let header = |name: &str, value: &str| json!({"header": {"name": name, "value": value}});
        assert!(pair(header("x-env", "a"), header("X-Env", "b")));
        assert!(!pair(header("x-env", "a"), header("x-env", "a")));
        assert!(!pair(header("x-env", "a"), header("x-other", "b")));
        assert!(!pair(
            header("x-env", "a"),
            json!({"header": {"name": "x-env"}})
        ));
        assert!(!pair(
            header("x-env", "a"),
            json!({"header_regexp": {"name": "x-env", "regex": "b"}})
        ));
        let query = |name: &str, value: &str| json!({"query": {"name": name, "value": value}});
        assert!(pair(query("debug", "1"), query("debug", "2")));
        assert!(!pair(query("debug", "1"), query("debug", "1")));
        assert!(!pair(query("debug", "1"), query("trace", "2")));
        assert!(!pair(query("debug", "1"), header("debug", "2")));
        assert!(!pair(
            query("debug", "1"),
            json!({"query_regexp": {"name": "debug", "regex": "2"}})
        ));
        assert!(pair(
            json!({"all": [{"host": "a.test"}, header("x-env", "a")]}),
            header("x-env", "b")
        ));
    }

    #[test]
    fn regexp_leaf_too_large_rejected() {
        let huge = "(a{1000}){1000}";
        for leaf in [
            json!({"header_regexp": {"name": "x", "regex": huge}}),
            json!({"query_regexp": {"name": "x", "regex": huge}}),
        ] {
            let err = parse(&leaf).expect_err("over the compiled-size limit");
            assert_eq!(err.code, "invalid_matcher", "{leaf}: {err}");
        }
        assert!(parse(&json!({"header_regexp": {"name": "x", "regex": "(a{10}){10}"}})).is_ok());
    }

    #[test]
    fn failures_name_the_leaves_that_fail() {
        let request = {
            let mut request =
                pingora::http::RequestHeader::build("GET", b"/a?debug=1", None).expect("request");
            request.insert_header("x-env", "prod").expect("header");
            request
        };
        let view = View {
            host: "a.test",
            path: "/a",
            entry_point: "web",
            tls: false,
            request: &request,
            client_ip: None,
            hello: Hello::NONE,
        };
        let failed = |value: Value| -> Vec<String> {
            parsed(&value)
                .failures(&view)
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        assert!(failed(json!({"path": "/a"})).is_empty());
        assert_eq!(
            failed(json!({"all": [
                {"host": "a.test"},
                {"header": {"name": "x-env", "value": "canary"}},
                {"query": {"name": "debug", "value": "1"}},
                {"method": ["POST"]},
            ]})),
            ["header x-env = \"canary\"", "method"]
        );
        assert_eq!(
            failed(
                json!({"any": [{"path": "/b"}, {"header_regexp": {"name": "x-env", "regex": "^c"}}]})
            ),
            ["path", "header_regexp x-env ~ \"^c\""]
        );
        assert_eq!(failed(json!({"not": {"host": "a.test"}})), ["not"]);
        assert!(Failure::key("host").is_host() && !Failure::key("not").is_host());
    }
}
