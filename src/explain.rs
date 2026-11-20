//! Why a request goes where it goes: the logic behind `GET /v1/explain`.
//!
//! [`explain`] reads the live [`RoutingTable`], the same compiled table the proxy routes with,
//! and runs the same router index, so the answer cannot drift from real routing. It never
//! parses a snapshot. It only reads: it does not pick a backend, so it does not advance any
//! round-robin or counter.

use axum::http::{Method, Uri};
use pingora::http::RequestHeader;
use serde::Serialize;
use thiserror::Error;

use crate::canary;
use crate::entry;
use crate::host;
use crate::pipeline;
use crate::router::{View, path};
use crate::table::RoutingTable;

/// What a caller asks about: a request as the proxy would see it.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    host: String,
    path: String,
    query: Option<String>,
    tls: bool,
    method: Method,
    entry_point: Option<String>,
}

/// A `url` or `method` that cannot be explained.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetError {
    /// `url` is not an absolute `http` or `https` URL with a host.
    #[error("url must be an absolute http or https URL with a host, like https://app.example/")]
    Url,
    /// `url` has a path the proxy would refuse.
    #[error("url has a path the proxy refuses: {0}")]
    Path(Box<str>),
    /// `method` is not an HTTP method token.
    #[error("method {0:?} is not an HTTP method")]
    Method(Box<str>),
}

impl Target {
    /// Parses the query of `GET /v1/explain`. `method` defaults to `GET`; the scheme decides
    /// whether the request is treated as arriving over TLS (`https`) and so on which entry
    /// point (`web` or `websecure`) unless `entry_point` names one. The path is normalized as
    /// the proxy does.
    ///
    /// # Errors
    ///
    /// [`TargetError::Url`] unless `url` is an absolute `http` or `https` URL with a
    /// host, [`TargetError::Path`] for a path the proxy refuses,
    /// [`TargetError::Method`] for a method that is not a token.
    pub fn parse(
        url: &str,
        method: Option<&str>,
        entry_point: Option<&str>,
    ) -> Result<Self, TargetError> {
        let uri: Uri = url.parse().map_err(|_| TargetError::Url)?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(TargetError::Url),
        };
        let authority = uri.authority().ok_or(TargetError::Url)?;
        let host = host::normalize(authority.host()).into_owned();
        if host.is_empty() {
            return Err(TargetError::Url);
        }
        let method = match method {
            None => Method::GET,
            Some(raw) => {
                Method::from_bytes(raw.as_bytes()).map_err(|_| TargetError::Method(raw.into()))?
            }
        };
        let path = path::normalize(uri.path())
            .map_err(|refused| TargetError::Path(refused.to_string().into()))?
            .into_owned();
        Ok(Self {
            host,
            path,
            query: uri.query().map(str::to_owned),
            tls,
            method,
            entry_point: entry_point.map(str::to_owned),
        })
    }

    fn entry_point(&self) -> &str {
        self.entry_point
            .as_deref()
            .unwrap_or_else(|| entry::of(self.tls))
    }
}

/// The answer for a request with a route: `200` body of `GET /v1/explain`.
#[derive(Debug, Serialize)]
pub struct Explanation<'a> {
    /// Version of the live table this answer came from.
    version: u64,
    /// The normalized host that was looked up.
    host: &'a str,
    /// The request method asked about.
    method: &'a str,
    /// The normalized path.
    path: &'a str,
    /// The entry point the request is taken to arrive on.
    entry_point: &'a str,
    app: &'a str,
    tenant: &'a str,
    declared_by: &'a str,
    matched: Matched<'a>,
    /// Every router that matches, best first: a router shadowed by a better one is visible.
    considered: Vec<&'a str>,
    /// The service the matched router names.
    service: &'a str,
    revisions: Vec<RevisionView<'a>>,
    /// The canary policy and its live share; absent when the app has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    canary: Option<canary::Status<'a>>,
    /// The stages the request goes through, in order; see [`crate::pipeline`].
    pipeline: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct Matched<'a> {
    router: &'a str,
    priority: i32,
    /// The declared host that matched, as written in the snapshot; `null` for a router with no
    /// literal host.
    pattern: Option<String>,
    /// `exact`, `wildcard`, `regexp` or `none`.
    kind: &'static str,
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
    /// The servers of the matched router's service in this revision; empty when the revision
    /// does not define it.
    servers: Vec<ServerView<'a>>,
}

#[derive(Debug, Serialize)]
struct ServerView<'a> {
    url: &'a str,
    weight: u32,
    available: bool,
}

/// The answer for a request without a route: `404` body of `GET /v1/explain`.
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
/// [`Miss`] when no router matches.
pub fn explain<'a>(table: &'a RoutingTable, target: &'a Target) -> Result<Explanation<'a>, Miss> {
    let miss = || Miss {
        error: "not found",
        nearest_wildcard: table.nearest_wildcard(&target.host),
    };
    let mut request = RequestHeader::build(
        target.method.as_str(),
        match &target.query {
            Some(query) => format!("{}?{query}", target.path),
            None => target.path.clone(),
        }
        .as_bytes(),
        None,
    )
    .map_err(|_| miss())?;
    request
        .insert_header("host", target.host.as_str())
        .map_err(|_| miss())?;
    let view = View {
        host: &target.host,
        path: &target.path,
        entry_point: target.entry_point(),
        tls: target.tls,
        request: &request,
    };
    let candidates = table.index().find_all(table.apps(), &view);
    let best = candidates.first().ok_or_else(miss)?;
    let (app, router) = table.router(best.matched).ok_or_else(miss)?;
    Ok(Explanation {
        version: table.version(),
        host: &target.host,
        method: target.method.as_str(),
        path: &target.path,
        entry_point: target.entry_point(),
        app: app.id(),
        tenant: app.tenant(),
        declared_by: app.declared_by(),
        matched: Matched {
            router: router.name(),
            priority: router.priority(),
            pattern: best.via.pattern(),
            kind: best.via.kind(),
        },
        considered: candidates
            .iter()
            .filter_map(|candidate| table.router(candidate.matched))
            .map(|(_, router)| router.name())
            .collect(),
        service: router.service(),
        revisions: app
            .revisions()
            .iter()
            .enumerate()
            .map(|(index, revision)| RevisionView {
                id: revision.id(),
                state: revision.state(),
                weight: revision.weight(),
                effective_weight: revision.effective_weight(),
                servers: app
                    .service(index, best.matched.router)
                    .map(|service| {
                        service
                            .servers()
                            .iter()
                            .map(|server| ServerView {
                                url: &server.url,
                                weight: server.weight,
                                available: server.available(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect(),
        canary: app.canary(),
        pipeline: pipeline::describe(app, router, target.tls),
    })
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn table() -> RoutingTable {
        let snapshot = serde_json::from_value(json!({
            "version": 3,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "src/a", "tls": {"mode": "acme"},
                "routers": [
                    {"name": "api", "match": {"all": [{"host": "a.test"}, {"path_prefix": "/api"}]}, "service": "web"},
                    {"name": "site", "match": {"host": ["a.test", "*.a.test"]}, "service": "web"}
                ],
                "revisions": [{"id": "r", "weight": 1, "state": "serving", "services": [
                    {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:9000"}]}]}]
            }]
        }))
        .expect("snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    fn explained(url: &str, method: Option<&str>) -> serde_json::Value {
        let table = table();
        let target = Target::parse(url, method, None).expect("target");
        serde_json::to_value(explain(&table, &target).expect("routes")).expect("json")
    }

    #[test]
    fn parses_scheme_host_method_and_path() {
        let target =
            Target::parse("https://A.Test:8443/x/./y?q=1", Some("POST"), None).expect("parses");
        assert_eq!(target.host, "a.test");
        assert_eq!(target.path, "/x/y");
        assert_eq!(target.entry_point(), "websecure");
        assert_eq!(
            Target::parse("http://a.test/", None, None)
                .expect("plain")
                .entry_point(),
            "web"
        );
        assert_eq!(Target::parse("a.test", None, None), Err(TargetError::Url));
        assert!(matches!(
            Target::parse("http://a.test/", Some("not a method"), None),
            Err(TargetError::Method(_))
        ));
        assert!(matches!(
            Target::parse("http://a.test/a%2fb", None, None),
            Err(TargetError::Path(_))
        ));
    }

    #[test]
    fn shows_the_matched_router_the_shadowed_ones_and_the_pipeline() {
        let answer = explained("http://a.test/api/x", None);
        assert_eq!(answer["matched"]["router"], "api");
        assert_eq!(answer["considered"], json!(["api", "site"]));
        assert_eq!(answer["service"], "web");
        assert_eq!(
            answer["revisions"][0]["servers"][0]["url"],
            "http://127.0.0.1:9000"
        );
        assert_eq!(answer["pipeline"][0], json!({"stage": "acme_http01"}));

        let other = explained("http://a.test/other", None);
        assert_eq!(other["matched"]["router"], "site");
        assert_eq!(other["matched"]["pattern"], "a.test");
        assert_eq!(other["considered"], json!(["site"]));

        let wild = explained("http://x.a.test/", None);
        assert_eq!(wild["matched"]["kind"], "wildcard");
    }

    #[test]
    fn a_miss_names_the_nearest_wildcard() {
        let table = table();
        let target = Target::parse("http://a.test.other/", None, None).expect("target");
        assert!(explain(&table, &target).is_err());
        let target = Target::parse("http://p.q.a.test/", None, None).expect("target");
        let miss = explain(&table, &target).expect_err("two labels deep");
        assert_eq!(miss.nearest_wildcard.as_deref(), Some("*.a.test"));
    }
}
