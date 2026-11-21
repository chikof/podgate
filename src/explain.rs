//! Why a request goes where it goes: the logic behind `GET /v1/explain`.
//!
//! [`explain`] reads the live [`RoutingTable`], the same compiled table the proxy routes with,
//! and runs the same router index, so the answer cannot drift from real routing. It never
//! parses a snapshot. It only reads: it does not pick a backend, so it does not advance any
//! round-robin or counter.

use std::net::IpAddr;

use axum::http::{Method, Uri};
use pingora::http::RequestHeader;
use serde::Serialize;
use thiserror::Error;

use crate::canary;
use crate::entry::Protocol;
use crate::host;
use crate::pipeline;
use crate::router::{Candidate, Matched as RouterMatch, View, path};
use crate::service::graph;
use crate::service::outlier;
use crate::service::{PickCx, TransportSummary};
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
    client_ip: Option<IpAddr>,
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
    /// whether the request is treated as arriving over TLS (`https`). `entry_point` names the
    /// listener it arrives on; without it every bound entry point of that scheme is tried.
    /// The path is normalized as the proxy does.
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
        Self::parse_with(url, method, entry_point, false)
    }

    /// [`Self::parse`] for an entry point whose policy allows an encoded slash
    /// (`allow_encoded_slash`): `%2F` stays in its segment instead of refusing the path.
    ///
    /// # Errors
    ///
    /// The same as [`Self::parse`].
    pub fn parse_with(
        url: &str,
        method: Option<&str>,
        entry_point: Option<&str>,
        allow_encoded_slash: bool,
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
        let path = path::normalize_with(uri.path(), allow_encoded_slash)
            .map_err(|refused| TargetError::Path(refused.to_string().into()))?
            .into_owned();
        Ok(Self {
            host,
            path,
            query: uri.query().map(str::to_owned),
            tls,
            method,
            entry_point: entry_point.map(str::to_owned),
            client_ip: None,
        })
    }

    /// Asks as a client at `client_ip` (already resolved, as the proxy would after trusting its
    /// proxies), so routers with a `client_ip` matcher can match. Without it none does.
    #[must_use]
    pub fn with_client_ip(mut self, client_ip: IpAddr) -> Self {
        self.client_ip = Some(crate::client_ip::normalize(client_ip));
        self
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
    /// The entry point the request is taken to arrive on: the one asked for, else the first
    /// bound entry point of the URL's scheme on which a router matches.
    entry_point: &'a str,
    /// The HTTP and HTTPS entry points the matched router listens on.
    reachable_on: Vec<&'a str>,
    app: &'a str,
    tenant: &'a str,
    declared_by: &'a str,
    matched: Matched<'a>,
    /// Every router that matches, best first: a router shadowed by a better one is visible.
    considered: Vec<&'a str>,
    /// Routers that fit the host and entry point but fail on another leaf (a header, a query
    /// parameter, a method, ...), with the failing leaf. A router that fails on the host is not
    /// listed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    near_misses: Vec<NearMissView>,
    /// The service the matched router names.
    service: &'a str,
    revisions: Vec<RevisionView<'a>>,
    /// The canary policy and its live share; absent when the app has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    canary: Option<canary::Status<'a>>,
    /// Set when the entry point redirects every request before routing: the router above is
    /// the one that would match, but this redirect answers first.
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_redirect: Option<RedirectView<'a>>,
    /// The stages the request goes through, in order; see [`crate::pipeline`].
    pipeline: Vec<serde_json::Value>,
}

/// The redirect an entry point answers every request with.
#[derive(Debug, Serialize)]
struct RedirectView<'a> {
    to: &'a str,
    status: u16,
    scheme: &'static str,
    /// `null` when the target listens on the default port of its scheme.
    port: Option<u16>,
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
    state: podgate_model::RevisionState,
    /// As configured in the snapshot.
    weight: u16,
    /// What the picker uses for new requests right now: `0` unless the revision is `serving`
    /// with a positive weight and a backend. With a canary, parts of 10000 shared by the app.
    effective_weight: u16,
    /// The servers of the matched router's service in this revision; empty when the revision
    /// does not define it.
    servers: Vec<ServerView<'a>>,
    /// For a `weighted` or `failover` service: the path a request would take through its graph
    /// now (`weighted -> failover -> web-v2`) and every node with its weight, its effective
    /// weight and whether it is ready. The servers are those of the `loadbalancer`
    /// services in the graph, listed in `GET /v1/overview`.
    #[serde(skip_serializing_if = "Option::is_none")]
    graph: Option<graph::Described<'a>>,
}

#[derive(Debug, Serialize)]
struct ServerView<'a> {
    url: Box<str>,
    /// The address a server named by DNS currently stands for; absent for an IP literal.
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    weight: u32,
    available: bool,
    /// Milliseconds until passive outlier ejection ends; absent when the server is not ejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    ejected_for_ms: Option<u64>,
    /// How an `https://` server is reached; the client certificate shows as `[redacted]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<TransportSummary<'a>>,
}

/// A router that fits the request's host and entry point but not the rest of its matcher.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct NearMissView {
    app: String,
    router: String,
    /// The leaves that failed, like `header x-env = "canary"`.
    failed: Vec<String>,
}

/// The answer for a request without a route: `404` body of `GET /v1/explain`.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Miss {
    /// Always `"not found"`, the same error every other 404 carries.
    error: &'static str,
    /// The declared wildcard nearest to the host, or `None` when no declared wildcard shares a
    /// suffix with it; see [`RoutingTable::nearest_wildcard`] for what "nearest" means.
    nearest_wildcard: Option<String>,
    /// The HTTP and HTTPS entry points on which the request does match a router: the router
    /// exists but listens elsewhere than the entry point asked about.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    routed_on: Vec<String>,
    /// The routers that fit the request's host and entry point but fail on another leaf.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    near_misses: Vec<NearMissView>,
}

/// The entry points a request is tried on: the one `entry_point` names, else every bound entry
/// point of the URL's scheme, in the order the process lists them.
fn asked<'a>(table: &'a RoutingTable, target: &'a Target) -> Vec<&'a str> {
    if let Some(name) = target.entry_point.as_deref() {
        return vec![name];
    }
    let wanted = if target.tls {
        Protocol::Https
    } else {
        Protocol::Http
    };
    table
        .context()
        .entry_points()
        .filter(|(_, protocol)| *protocol == wanted)
        .map(|(name, _)| name)
        .collect()
}

/// What a matcher sees of `target` arriving on `entry_point`.
fn view_of<'v>(
    target: &'v Target,
    request: &'v RequestHeader,
    entry_point: &'v str,
    tls: bool,
) -> View<'v> {
    View {
        host: &target.host,
        path: &target.path,
        entry_point,
        tls,
        request,
        client_ip: target.client_ip,
    }
}

/// The routers that match `target` arriving on `entry_point`, best first.
fn route_on<'v>(
    table: &RoutingTable,
    target: &'v Target,
    request: &'v RequestHeader,
    entry_point: &'v str,
    tls: bool,
) -> Vec<Candidate<'v>> {
    let view = view_of(target, request, entry_point, tls);
    table.index().find_all(table.apps(), &view)
}

/// The routers that fit `target` on any of `entry_points` by host and entry point and fail on
/// another leaf, each once, with the failing leaves. The request is the one `target` describes:
/// method, path, query and `Host`, and no other header, so a header leaf fails for it.
fn near_misses(
    table: &RoutingTable,
    target: &Target,
    request: &RequestHeader,
    entry_points: &[&str],
    tls: bool,
) -> Vec<NearMissView> {
    let mut seen: Vec<RouterMatch> = Vec::new();
    let mut views = Vec::new();
    for entry_point in entry_points {
        let view = view_of(target, request, entry_point, tls);
        for miss in table.index().near_misses(table.apps(), &view) {
            if seen.contains(&miss.matched) {
                continue;
            }
            seen.push(miss.matched);
            if let Some((app, router)) = table.router(miss.matched) {
                views.push(NearMissView {
                    app: app.id().to_owned(),
                    router: router.name().to_owned(),
                    failed: miss.failed.iter().map(ToString::to_string).collect(),
                });
            }
        }
    }
    views
}

/// Explains how `table` routes `target`.
///
/// # Errors
///
/// [`Miss`] when no router matches.
pub fn explain<'a>(table: &'a RoutingTable, target: &'a Target) -> Result<Explanation<'a>, Miss> {
    let plain_miss = || Miss {
        error: "not found",
        nearest_wildcard: table.nearest_wildcard(&target.host),
        routed_on: Vec::new(),
        near_misses: Vec::new(),
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
    .map_err(|_| plain_miss())?;
    request
        .insert_header("host", target.host.as_str())
        .map_err(|_| plain_miss())?;
    let miss = || Miss {
        routed_on: table
            .context()
            .entry_points()
            .filter(|(_, protocol)| protocol.is_http())
            .filter(|(name, protocol)| {
                !route_on(table, target, &request, name, *protocol == Protocol::Https).is_empty()
            })
            .map(|(name, _)| name.to_owned())
            .collect(),
        near_misses: near_misses(table, target, &request, &asked(table, target), target.tls),
        ..plain_miss()
    };
    let (entry_point, candidates) = asked(table, target)
        .into_iter()
        .find_map(|name| {
            let found = route_on(table, target, &request, name, target.tls);
            (!found.is_empty()).then_some((name, found))
        })
        .ok_or_else(miss)?;
    let best = candidates.first().ok_or_else(miss)?;
    let (app, router) = table.router(best.matched).ok_or_else(miss)?;
    Ok(Explanation {
        version: table.version(),
        host: &target.host,
        method: target.method.as_str(),
        path: &target.path,
        entry_point,
        reachable_on: table
            .context()
            .http_entry_points()
            .filter(|name| router.listens_on(name))
            .collect(),
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
        near_misses: near_misses(table, target, &request, &[entry_point], target.tls),
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
                        let transport = service.transport();
                        service
                            .servers()
                            .iter()
                            .map(|server| ServerView {
                                url: server.url.clone(),
                                address: server.host().map(|_| server.addr.to_string()),
                                weight: server.weight,
                                available: server.available(),
                                ejected_for_ms: outlier::ejected_for(server).map(|left| {
                                    u64::try_from(left.as_millis()).unwrap_or(u64::MAX)
                                }),
                                transport: transport
                                    .filter(|transport| {
                                        server.tls || server.h2c || transport.sets_timeouts()
                                    })
                                    .map(|transport| transport.summary(server)),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                graph: app.describe_graph(index, best.matched.router, PickCx::new(&request)),
            })
            .collect(),
        canary: app.canary(),
        entry_redirect: table
            .entry_policy(entry_point)
            .redirect_to()
            .map(|redirect| RedirectView {
                to: redirect.to(),
                status: redirect.status_for(&target.method),
                scheme: redirect.scheme(),
                port: redirect.port(),
            }),
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
        assert!(target.tls && target.entry_point.is_none());
        let plain = explained("http://a.test/", None);
        assert_eq!(plain["entry_point"], "web");
        assert_eq!(plain["reachable_on"], json!(["web", "websecure"]));
        assert_eq!(
            explained("https://a.test/", None)["entry_point"],
            "websecure"
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
