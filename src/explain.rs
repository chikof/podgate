//! Why a request goes where it goes: the logic behind `GET /v1/explain`.
//!
//! [`explain`] reads the live [`RoutingTable`], the same compiled table the proxy routes with,
//! so the answer cannot drift from real routing. It never parses a snapshot. It only reads:
//! it does not pick a backend, so it does not advance any round-robin or counter.

use axum::http::{Method, Uri};
use serde::Serialize;
use thiserror::Error;

use crate::canary;
use crate::host::{self, MatchKind};
use crate::proxy;
use crate::table::RoutingTable;

/// What a caller asks about: a request as the proxy would see it.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    host: String,
    tls: bool,
    method: Method,
}

/// A `url` or `method` that cannot be explained.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetError {
    /// `url` is not an absolute `http` or `https` URL with a host.
    #[error("url must be an absolute http or https URL with a host, like https://app.example/")]
    InvalidUrl,
    /// `method` is not an HTTP method token.
    #[error("method {0:?} is not an HTTP method")]
    InvalidMethod(Box<str>),
}

impl Target {
    /// Parses the query of `GET /v1/explain`. `method` defaults to `GET`; the scheme decides
    /// whether the request is treated as arriving over TLS (`https`).
    ///
    /// # Errors
    ///
    /// [`TargetError::InvalidUrl`] unless `url` is an absolute `http` or `https` URL with a
    /// host, [`TargetError::InvalidMethod`] for a method that is not a token.
    pub fn parse(url: &str, method: Option<&str>) -> Result<Self, TargetError> {
        let uri: Uri = url.parse().map_err(|_| TargetError::InvalidUrl)?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(TargetError::InvalidUrl),
        };
        let authority = uri.authority().ok_or(TargetError::InvalidUrl)?;
        let host = host::normalize(authority.host()).into_owned();
        if host.is_empty() {
            return Err(TargetError::InvalidUrl);
        }
        let method = match method {
            None => Method::GET,
            Some(raw) => Method::from_bytes(raw.as_bytes())
                .map_err(|_| TargetError::InvalidMethod(raw.into()))?,
        };
        Ok(Self { host, tls, method })
    }
}

/// The answer for a host with a route: `200` body of `GET /v1/explain`.
#[derive(Debug, Serialize)]
pub struct Explanation<'a> {
    /// Version of the live table this answer came from.
    version: u64,
    /// The normalized host that was looked up.
    host: &'a str,
    /// The request method asked about.
    method: &'a str,
    app: &'a str,
    tenant: &'a str,
    declared_by: &'a str,
    matched: Matched,
    revisions: Vec<RevisionView<'a>>,
    /// The canary policy and its live share; absent when the app has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    canary: Option<canary::Status<'a>>,
    middleware: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct Matched {
    /// The declared host that matched, as written in the snapshot.
    pattern: String,
    kind: MatchKind,
}

#[derive(Debug, Serialize)]
struct RevisionView<'a> {
    id: &'a str,
    state: crate::snapshot::RevisionState,
    /// As configured in the snapshot.
    weight: u16,
    /// What the picker uses for new requests right now: `0` unless the revision is `serving`
    /// with a positive weight and a backend. With a canary, parts of 10000 shared by the app.
    effective_weight: u16,
    upstreams: &'a [std::net::SocketAddr],
}

/// The answer for a host without a route: `404` body of `GET /v1/explain`.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Miss {
    /// Always `"not found"`, the same error every other 404 carries.
    error: &'static str,
    /// The declared wildcard nearest to the host, or `None` when no declared wildcard shares a
    /// suffix with it; see [`RoutingTable::nearest_wildcard`] for what "nearest" means.
    nearest_wildcard: Option<String>,
}

/// Explains how `table` routes `target`.
///
/// # Errors
///
/// [`Miss`] when no app answers for the host.
pub fn explain<'a>(table: &'a RoutingTable, target: &'a Target) -> Result<Explanation<'a>, Miss> {
    let Some(found) = table.lookup(&target.host) else {
        return Err(Miss {
            error: "not found",
            nearest_wildcard: table.nearest_wildcard(&target.host),
        });
    };
    let app = found.app;
    Ok(Explanation {
        version: table.version(),
        host: &target.host,
        method: target.method.as_str(),
        app: app.id(),
        tenant: app.tenant(),
        declared_by: app.declared_by(),
        matched: Matched {
            pattern: found.pattern,
            kind: found.kind,
        },
        revisions: app
            .revisions()
            .iter()
            .map(|revision| RevisionView {
                id: revision.id(),
                state: revision.state(),
                weight: revision.weight(),
                effective_weight: revision.effective_weight(),
                upstreams: revision.upstreams(),
            })
            .collect(),
        canary: app.canary(),
        middleware: proxy::middleware_chain(app, target.tls),
    })
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;
    use crate::snapshot::Snapshot;

    fn table() -> RoutingTable {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "version": 3,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": [{
                "id": "w", "tenant": "t", "declared_by": "test/w", "hosts": ["*.w.test"],
                "tls": {"mode": "acme"},
                "revisions": [
                    {"id": "old", "upstreams": ["127.0.0.1:1"], "weight": 5, "state": "retiring"},
                    {"id": "new", "upstreams": ["127.0.0.1:2"], "weight": 7, "state": "serving"}
                ]
            }]
        }))
        .expect("valid snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    fn target(url: &str) -> Target {
        Target::parse(url, None).expect("valid target")
    }

    #[test]
    fn parses_the_url_into_host_and_transport() {
        let plain = target("http://A.W.test:8080/x?y=1");
        assert_eq!((plain.host.as_str(), plain.tls), ("a.w.test", false));
        let tls = target("https://user@a.w.test/");
        assert_eq!((tls.host.as_str(), tls.tls), ("a.w.test", true));
        assert_eq!(target("https://[::1]:8443/").host, "::1");
        assert_eq!(
            Target::parse("http://a.test/", Some("POST")).map(|t| t.method),
            Ok(Method::POST)
        );
    }

    #[test]
    fn rejects_urls_and_methods_that_name_no_request() {
        for bad in [
            "",
            "a.test",
            "/path",
            "ftp://a.test/",
            "http://",
            "https:///x",
        ] {
            assert_eq!(
                Target::parse(bad, None),
                Err(TargetError::InvalidUrl),
                "{bad:?}"
            );
        }
        assert_eq!(
            Target::parse("http://a.test/", Some("not a method")),
            Err(TargetError::InvalidMethod("not a method".into()))
        );
    }

    #[test]
    fn explains_a_wildcard_match_with_effective_weights() {
        let table = table();
        let target = target("https://x.w.test/");
        let body = serde_json::to_value(explain(&table, &target).expect("known host"))
            .expect("serializes");
        assert_eq!(
            body,
            json!({
                "version": 3, "host": "x.w.test", "method": "GET",
                "app": "w", "tenant": "t", "declared_by": "test/w",
                "matched": {"pattern": "*.w.test", "kind": "wildcard"},
                "revisions": [
                    {"id": "old", "state": "retiring", "weight": 5, "effective_weight": 0, "upstreams": ["127.0.0.1:1"]},
                    {"id": "new", "state": "serving", "weight": 7, "effective_weight": 7, "upstreams": ["127.0.0.1:2"]}
                ],
                "middleware": ["sni_check", "route", "inflight_admit", "tenant_admit", "failure_capture"],
            })
        );
    }

    #[test]
    fn a_miss_names_the_nearest_wildcard() {
        let table = table();
        let target = target("http://w.test/");
        assert_eq!(
            explain(&table, &target).expect_err("apex is not matched"),
            Miss {
                error: "not found",
                nearest_wildcard: Some("*.w.test".into())
            }
        );
    }
}
