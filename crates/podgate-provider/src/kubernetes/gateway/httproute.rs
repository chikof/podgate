//! `HTTPRoute` rules to matches.
//!
//! A match is the leaves of the podgate matcher that all must hold, plus what the precedence
//! needs to rank it (`precedence.rs`).
//!
//! | `matches[]` | podgate leaf |
//! |---|---|
//! | `path` `Exact` | `{"path": p}` |
//! | `path` `PathPrefix` (the default, `/`) | `{"path_prefix": p}`; the API's element-wise prefix is podgate's whole-segment prefix |
//! | `path` `RegularExpression` | `{"path_regexp": "^(?:re)$"}`, anchored: the API leaves the semantics to the implementation |
//! | `headers` `Exact`, `RegularExpression` | `header`, `header_regexp` (anchored); a repeated name counts once, the first wins |
//! | `queryParams` `Exact`, `RegularExpression` | `query`, `query_regexp` (anchored) |
//! | `method` | `{"method": "GET"}` |
//!
//! The several matches of a rule are alternatives. Each becomes its own router with the same
//! service, so that each carries its own precedence.

use std::collections::BTreeSet;

use regex::RegexBuilder;
use serde_json::{Value, json};

use super::precedence::PathRank;
use super::types::{BackendRef, Filter, HttpMatch, HttpRoute, NameMatch};
use super::{Rejection, reject};

/// The largest compiled regular expression a leaf may have, as in the daemon.
const REGEX_LIMIT: usize = 1 << 20;

/// One match of a rule.
#[derive(Debug, Clone)]
pub struct MatchSpec {
    /// The leaves that all must hold.
    pub leaves: Vec<Value>,
    /// How specific the path is.
    pub path: PathRank,
    /// Whether it names a method.
    pub method: bool,
    /// How many header matches it has.
    pub headers: usize,
    /// How many query matches it has.
    pub queries: usize,
    /// The path prefix when the path match is a `PathPrefix`, for `ReplacePrefixMatch`.
    pub prefix: Option<String>,
}

/// One rule, read once for both route kinds.
#[derive(Debug, Clone)]
pub struct Rule {
    /// The alternatives; never empty.
    pub matches: Vec<MatchSpec>,
    /// The filters, in order.
    pub filters: Vec<Filter>,
    /// The backends.
    pub backends: Vec<BackendRef>,
}

/// Anchors `expression` and checks that it compiles within the daemon's limit.
///
/// # Errors
///
/// A [`Rejection`] naming `what` when the expression is not valid.
pub fn anchored(what: &str, expression: &str) -> Result<String, Rejection> {
    let anchored = format!("^(?:{expression})$");
    RegexBuilder::new(&anchored)
        .size_limit(REGEX_LIMIT)
        .build()
        .map_err(|err| {
            reject(
                "UnsupportedValue",
                format!("{what} {expression:?} is not a valid regular expression: {err}"),
            )
        })?;
    Ok(anchored)
}

/// The header or query leaves of `matches`: `header`/`header_regexp` (or `query`/
/// `query_regexp`) per entry. A name that repeats counts once, the first entry winning, as the
/// API says.
///
/// # Errors
///
/// A [`Rejection`] for a type other than `Exact` and `RegularExpression`, or a bad expression.
pub fn name_leaves(
    plain: &str,
    pattern: &str,
    case_insensitive: bool,
    matches: &[NameMatch],
) -> Result<Vec<Value>, Rejection> {
    let mut seen = BTreeSet::new();
    let mut leaves = Vec::new();
    for item in matches {
        let key = if case_insensitive {
            item.name.to_ascii_lowercase()
        } else {
            item.name.clone()
        };
        if item.name.is_empty() {
            return Err(reject(
                "UnsupportedValue",
                format!("a {plain} match has no name"),
            ));
        }
        if !seen.insert(key) {
            continue;
        }
        match item.kind.as_deref().unwrap_or("Exact") {
            "Exact" => {
                leaves.push(json!({ plain: { "name": item.name, "value": item.value } }));
            }
            "RegularExpression" => {
                let regex = anchored(&format!("the {plain} match {}", item.name), &item.value)?;
                leaves.push(json!({ pattern: { "name": item.name, "regex": regex } }));
            }
            other => {
                return Err(reject(
                    "UnsupportedValue",
                    format!("the {plain} match type {other:?} is not supported"),
                ));
            }
        }
    }
    Ok(leaves)
}

fn one(matched: &HttpMatch) -> Result<MatchSpec, Rejection> {
    let mut leaves = Vec::new();
    let path = matched.path.as_ref();
    let kind = path
        .and_then(|path| path.kind.as_deref())
        .unwrap_or("PathPrefix");
    let value = path.and_then(|path| path.value.as_deref()).unwrap_or("/");
    let (rank, prefix) = match kind {
        "Exact" | "PathPrefix" => {
            if !value.starts_with('/') {
                return Err(reject(
                    "UnsupportedValue",
                    format!("the {kind} path {value:?} must start with /"),
                ));
            }
            if kind == "Exact" {
                leaves.push(json!({ "path": value }));
                (PathRank::exact(), None)
            } else {
                leaves.push(json!({ "path_prefix": value }));
                (
                    PathRank::prefix(value.trim_end_matches('/').len()),
                    Some(value.to_owned()),
                )
            }
        }
        "RegularExpression" => {
            leaves.push(json!({ "path_regexp": anchored("the path", value)? }));
            (PathRank::regex(), None)
        }
        other => {
            return Err(reject(
                "UnsupportedValue",
                format!("the path match type {other:?} is not supported"),
            ));
        }
    };
    let headers = name_leaves("header", "header_regexp", true, &matched.headers)?;
    let queries = name_leaves("query", "query_regexp", false, &matched.query_params)?;
    let (header_count, query_count) = (headers.len(), queries.len());
    leaves.extend(headers);
    leaves.extend(queries);
    if let Some(method) = matched.method.as_deref() {
        if http::Method::from_bytes(method.as_bytes()).is_err() {
            return Err(reject(
                "UnsupportedValue",
                format!("{method:?} is not an HTTP method"),
            ));
        }
        leaves.push(json!({ "method": method }));
    }
    Ok(MatchSpec {
        leaves,
        path: rank,
        method: matched.method.is_some(),
        headers: header_count,
        queries: query_count,
        prefix,
    })
}

/// The rules of an `HTTPRoute`.
///
/// # Errors
///
/// A [`Rejection`] for a match, expression or rule field that podgate cannot honour:
/// `timeouts`, `sessionPersistence`, `retry`.
pub fn rules(route: &HttpRoute) -> Result<Vec<Rule>, Rejection> {
    let mut rules = Vec::new();
    for (index, rule) in route.spec.rules.iter().enumerate() {
        for (field, value) in [
            ("timeouts", &rule.timeouts),
            ("sessionPersistence", &rule.session_persistence),
            ("retry", &rule.retry),
        ] {
            if value.as_ref().is_some_and(|value| !value.is_null()) {
                return Err(reject(
                    "UnsupportedValue",
                    format!("rules[{index}].{field} is not supported"),
                ));
            }
        }
        let matches = if rule.matches.is_empty() {
            vec![one(&HttpMatch::default())?]
        } else {
            rule.matches
                .iter()
                .enumerate()
                .map(|(at, matched)| {
                    one(matched)
                        .map_err(|why| prefixed(&format!("rules[{index}].matches[{at}]"), why))
                })
                .collect::<Result<_, _>>()?
        };
        rules.push(Rule {
            matches,
            filters: rule.filters.clone(),
            backends: rule.backend_refs.clone(),
        });
    }
    Ok(rules)
}

/// `why` with the place it was found in.
#[must_use]
pub fn prefixed(place: &str, mut why: Rejection) -> Rejection {
    why.message = format!("{place}: {}", why.message);
    why
}
