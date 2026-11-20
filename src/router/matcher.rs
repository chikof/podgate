//! The matcher tree of a router.
//!
//! A matcher is JSON with exactly one key: a leaf (`host`, `path_prefix`, `method`, ...) or a
//! combinator (`all`, `any`, `not`). Each leaf lives in its own file and offers the same four
//! things: `parse`, `matches`, its contribution to the specificity ([`Spec`]), and `claims` (a
//! host leaf says which hosts the router is for). [`disjoint`] says when two matchers can
//! never both match, which the ambiguity check needs. Leaves of the planned set that no spec has
//! built yet (`header`, `header_regexp`, `query`, `query_regexp`) are refused with
//! `matcher_not_built`; a key that is not planned is `invalid_matcher`.
//!
//! Adding a leaf: a file in this directory with the four functions, one variant in [`Matcher`],
//! and one arm in each of its `match` statements (the compiler lists them); remove the key from
//! `UNBUILT`.

use std::fmt;
use std::net::IpAddr;

use pingora::http::RequestHeader;
use serde_json::Value;

use crate::host::HostPattern;

mod client_ip;
mod combinator;
mod host;
mod host_regexp;
mod method;
mod path;
mod path_prefix;
mod path_regexp;

use client_ip::ClientIp;
use host::Host;
use host_regexp::HostRegexp;
use method::Method;
use path::Path;
use path_prefix::PathPrefix;
use path_regexp::PathRegexp;

/// Deepest nesting of combinators a matcher may have.
pub const MAX_DEPTH: usize = 8;

/// Compiled size limit of one regular expression, in bytes.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Leaves that are planned and not built: refused with `matcher_not_built`.
const UNBUILT: [&str; 4] = ["header", "header_regexp", "query", "query_regexp"];

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
    /// `all`: every child matches.
    All(Vec<Matcher>),
    /// `any`: some child matches.
    Any(Vec<Matcher>),
    /// `not`: the child does not match.
    Not(Box<Matcher>),
}

/// Parses a matcher tree.
///
/// # Errors
///
/// [`Error`] for a value that is not an object with exactly one key, an unknown or unbuilt key,
/// a leaf with a bad argument (including a bad host or regular expression), or nesting deeper
/// than [`MAX_DEPTH`].
pub fn parse(value: &Value) -> Result<Matcher, Error> {
    parse_at(value, 0)
}

pub(super) fn parse_at(value: &Value, depth: usize) -> Result<Matcher, Error> {
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
    Ok(match key.as_str() {
        "host" => Matcher::Host(Host::parse(argument)?),
        "host_regexp" => Matcher::HostRegexp(HostRegexp::parse(argument)?),
        "path" => Matcher::Path(Path::parse(argument)?),
        "path_prefix" => Matcher::PathPrefix(PathPrefix::parse(argument)?),
        "path_regexp" => Matcher::PathRegexp(PathRegexp::parse(argument)?),
        "method" => Matcher::Method(Method::parse(argument)?),
        "client_ip" => Matcher::ClientIp(ClientIp::parse(argument)?),
        "all" => Matcher::All(combinator::parse_list(key, argument, depth)?),
        "any" => Matcher::Any(combinator::parse_list(key, argument, depth)?),
        "not" => Matcher::Not(Box::new(parse_at(argument, depth + 1)?)),
        other if UNBUILT.contains(&other) => {
            return Err(Error {
                code: "matcher_not_built",
                message: format!("matcher {other} is planned and not built yet"),
            });
        }
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
            Self::All(children) => children.iter().all(|child| child.matches(view)),
            Self::Any(children) => children.iter().any(|child| child.matches(view)),
            Self::Not(child) => !child.matches(view),
        }
    }

    /// The hosts a match can be for, or `None` when the matcher does not limit the host (so the
    /// router can match any host). `all` is limited by its limited children, and a child that
    /// names only literal hosts bounds it: a `host_regexp` next to a literal host narrows that
    /// claim and never widens it. `any` is limited only when every branch is, `not` never.
    #[must_use]
    pub fn claims(&self) -> Option<Vec<Claim>> {
        match self {
            Self::Host(leaf) => Some(leaf.claims()),
            Self::HostRegexp(_) => Some(vec![Claim::Regexp]),
            Self::Path(_)
            | Self::PathPrefix(_)
            | Self::PathRegexp(_)
            | Self::Method(_)
            | Self::ClientIp(_)
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
}
