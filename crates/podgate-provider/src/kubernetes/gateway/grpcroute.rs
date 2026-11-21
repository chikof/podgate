//! `GRPCRoute` rules to matches.
//!
//! A gRPC call is an HTTP/2 `POST` to `/<service>/<method>` with a `content-type` that starts
//! with `application/grpc`. Every match therefore carries the content-type leaf, so a plain HTTP
//! request to the same path is not taken for a gRPC call, and `grpc-web` (a different content
//! type) is not either.
//!
//! | `method` | podgate |
//! |---|---|
//! | `Exact` service and method | `{"path": "/<service>/<method>"}` |
//! | `Exact` service only | `{"path_prefix": "/<service>"}` |
//! | `Exact` method only | `{"path_regexp": "^/[^/]+/<method>$"}` |
//! | `RegularExpression` | `{"path_regexp": "^/(?:<service>)/(?:<method>)$"}`, a missing part is `[^/]+` |
//! | absent | the content-type leaf alone |
//!
//! The backends of a gRPC route speak HTTP/2 without TLS: plain `http://` servers become
//! `h2c://`, as `appProtocol: kubernetes.io/h2c` already says.

use regex::escape;
use serde_json::{Value, json};

use super::httproute::{MatchSpec, Rule, anchored, name_leaves, prefixed};
use super::precedence::PathRank;
use super::types::{GrpcMatch, GrpcRoute};
use super::{Rejection, reject};

/// The content types of a gRPC call: `application/grpc`, `application/grpc+proto`,
/// `application/grpc;charset=...`, but not `application/grpc-web`.
const CONTENT_TYPE: &str = r"^application/grpc(?:\+[^;]*)?(?:;.*)?$";

/// A service or method name as the API allows it: no `/`.
fn name(what: &str, value: &str) -> Result<(), Rejection> {
    if value.contains('/') || value.is_empty() {
        return Err(reject(
            "UnsupportedValue",
            format!("the gRPC {what} {value:?} is empty or holds a /"),
        ));
    }
    Ok(())
}

fn one(matched: &GrpcMatch) -> Result<MatchSpec, Rejection> {
    let mut leaves: Vec<Value> = Vec::new();
    let mut rank = PathRank::grpc(0, 0, true);
    let mut prefix = None;
    if let Some(method) = &matched.method {
        let service = method.service.as_deref().filter(|name| !name.is_empty());
        let name_of = method.method.as_deref().filter(|name| !name.is_empty());
        for (what, value) in [("service", service), ("method", name_of)] {
            if let Some(value) = value {
                name(what, value)?;
            }
        }
        let exact = match method.kind.as_deref().unwrap_or("Exact") {
            "Exact" => true,
            "RegularExpression" => false,
            other => {
                return Err(reject(
                    "UnsupportedValue",
                    format!("the gRPC method match type {other:?} is not supported"),
                ));
            }
        };
        rank = PathRank::grpc(
            service.map_or(0, str::len),
            name_of.map_or(0, str::len),
            exact,
        );
        if exact {
            match (service, name_of) {
                (Some(service), Some(method)) => {
                    leaves.push(json!({ "path": format!("/{service}/{method}") }));
                }
                (Some(service), None) => {
                    prefix = Some(format!("/{service}"));
                    leaves.push(json!({ "path_prefix": format!("/{service}") }));
                }
                (None, Some(method)) => {
                    leaves.push(json!({ "path_regexp": format!("^/[^/]+/{}$", escape(method)) }));
                }
                (None, None) => {}
            }
        } else if service.is_some() || name_of.is_some() {
            let part =
                |value: Option<&str>| value.map_or_else(|| "[^/]+".to_owned(), str::to_owned);
            let expression = format!("/(?:{})/(?:{})", part(service), part(name_of));
            leaves.push(json!({ "path_regexp": anchored("the gRPC method", &expression)? }));
        }
    }
    leaves.push(json!({ "header_regexp": { "name": "content-type", "regex": CONTENT_TYPE } }));
    let headers = name_leaves("header", "header_regexp", true, &matched.headers)?;
    // The content-type leaf counts as one header match: a gRPC match is more specific than a
    // plain HTTP match of the same path.
    let header_count = headers.len() + 1;
    leaves.extend(headers);
    Ok(MatchSpec {
        leaves,
        path: rank,
        method: false,
        headers: header_count,
        queries: 0,
        prefix,
    })
}

/// The rules of a `GRPCRoute`.
///
/// # Errors
///
/// A [`Rejection`] for a match or a rule field that podgate cannot honour
/// (`sessionPersistence`).
pub fn rules(route: &GrpcRoute) -> Result<Vec<Rule>, Rejection> {
    let mut rules = Vec::new();
    for (index, rule) in route.spec.rules.iter().enumerate() {
        if rule
            .session_persistence
            .as_ref()
            .is_some_and(|value| !value.is_null())
        {
            return Err(reject(
                "UnsupportedValue",
                format!("rules[{index}].sessionPersistence is not supported"),
            ));
        }
        let matches = if rule.matches.is_empty() {
            vec![one(&GrpcMatch::default())?]
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
