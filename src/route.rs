//! Core routing: which router, revision and backend a request goes to.
//!
//! Two steps, both pure functions over a [`RoutingTable`] and a request header, so they are
//! testable without a running proxy: [`matching`] finds the router (and so the app and its
//! middleware chain), and [`select`] picks a revision and a server for it. The proxy runs the
//! middleware chain between the two; `proxy.rs` calls these and does nothing else about routing.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};

use pingora::http::RequestHeader;
use thiserror::Error;

use crate::host;
use crate::router::{Matched, View, path};
use crate::service::{Lease, PickCx};
use crate::skew;
use crate::table::RoutingTable;

/// The routing decision for one request. Indices point into the table the request was
/// resolved against, which the request keeps for its whole life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selected {
    /// Index of the app, for [`RoutingTable::app`].
    pub app: usize,
    /// Index of the matched router in [`crate::table::CompiledApp::routers`].
    pub router: usize,
    /// Index of the revision, for [`crate::table::CompiledApp::revisions`].
    pub revision: usize,
    /// The backend to connect to.
    pub upstream: SocketAddr,
    /// Whether a valid session cookie dictated the revision (see [`crate::skew`]); `false` when
    /// the weighted pick chose it.
    pub pinned: bool,
}

/// Why a request has no route.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteError {
    /// No router matches the request: no app claims its host, or none of the app's routers
    /// matches the rest of it.
    #[error("not found")]
    NoRoute,
    /// The router matched but no revision takes new requests.
    #[error("no upstream available")]
    NoUpstream,
    /// A revision takes new requests but the router's service has no available server: every
    /// one is unhealthy or ejected. Unlike [`Self::NoUpstream`] the app is not asleep, so a
    /// `scale_to_zero` app is not woken for it.
    #[error("no healthy upstream available")]
    AllUnhealthy,
}

/// The normalized host a request is for: the URI authority (HTTP/2, absolute-form) or else the
/// `Host` header.
#[must_use]
pub fn request_host(request: &RequestHeader) -> Option<Cow<'_, str>> {
    let raw = match request.uri.authority() {
        Some(authority) => authority.as_str(),
        None => request.headers.get("host")?.to_str().ok()?,
    };
    Some(host::normalize(raw))
}

/// The router that answers `request`, which arrived on entry point `entry_point` (over TLS when
/// `tls`) from `client_ip` (see [`crate::client_ip`]). `None` when the request names no host, its
/// path cannot be normalized, or no router matches.
#[must_use]
pub fn matching(
    table: &RoutingTable,
    request: &RequestHeader,
    entry_point: &str,
    tls: bool,
    client_ip: Option<IpAddr>,
) -> Option<Matched> {
    let host = request_host(request)?;
    let allow_slash = table.entry_policy(entry_point).allow_encoded_slash();
    let path = path::normalize_with(request.uri.path(), allow_slash).ok()?;
    let view = View {
        host: &host,
        path: &path,
        entry_point,
        tls,
        request,
        client_ip,
    };
    table.index().find(table.apps(), &view)
}

/// Picks a revision and a backend for a request that matched `matched`. A valid session cookie
/// (see [`crate::skew`]) pins it to the revision it names while that revision is `serving` or
/// `retiring`; otherwise the weighted pick decides. The [`Lease`] counts the request on the
/// chosen server: keep it until the request ends. `client` is the resolved client address for
/// the hashing balancers ([`crate::client_ip::ForwardedView::known_client`]).
///
/// # Errors
///
/// [`RouteError::NoRoute`] when `matched` points outside the table, [`RouteError::NoUpstream`]
/// when no revision takes new requests, [`RouteError::AllUnhealthy`] when one does and its
/// service has no available server.
pub fn select(
    table: &RoutingTable,
    matched: Matched,
    request: &RequestHeader,
    client: Option<IpAddr>,
) -> Result<(Selected, Lease), RouteError> {
    let app = table.app(matched.app).ok_or(RouteError::NoRoute)?;
    let cx = PickCx::new(request).with_client(client);
    let (pick, pinned) = match skew::pinned(table, app, matched.router, cx) {
        Some(pick) => (pick, true),
        None => (
            // A revision takes requests but none of its servers does: the app is not asleep,
            // so nothing may wake it.
            app.pick(matched.router, cx).ok_or_else(|| {
                if app
                    .revisions()
                    .iter()
                    .any(|revision| revision.effective_weight() > 0)
                {
                    RouteError::AllUnhealthy
                } else {
                    RouteError::NoUpstream
                }
            })?,
            false,
        ),
    };
    Ok((
        Selected {
            app: matched.app,
            router: matched.router,
            revision: pick.revision,
            upstream: pick.upstream,
            pinned,
        },
        pick.lease,
    ))
}

/// Another server for a request whose attempt on `selected` failed: the same revision and
/// service, a server that [`PickCx::allows`] (available, and not in `tried`). The [`Lease`]
/// counts the request on it. `None` when the service has no such server, or no longer exists.
/// `retry` calls this for every further attempt.
#[must_use]
pub fn reselect(
    table: &RoutingTable,
    selected: &Selected,
    request: &RequestHeader,
    client: Option<IpAddr>,
    tried: &[SocketAddr],
) -> Option<(Selected, Lease)> {
    let service = table
        .app(selected.app)?
        .service(selected.revision, selected.router)?;
    let cx = PickCx {
        excluded: tried,
        ..PickCx::new(request).with_client(client)
    };
    let (upstream, lease) = service.pick(cx)?;
    Some((
        Selected {
            upstream,
            ..*selected
        },
        lease,
    ))
}

/// [`matching`] then [`select`]: the whole routing decision for a request with no middleware
/// chain in between, for tests and tools.
///
/// # Errors
///
/// [`RouteError::NoRoute`] when no router matches, [`RouteError::NoUpstream`] as [`select`].
pub fn resolve(
    table: &RoutingTable,
    request: &RequestHeader,
    entry_point: &str,
    tls: bool,
    client_ip: Option<IpAddr>,
) -> Result<Selected, RouteError> {
    let matched =
        matching(table, request, entry_point, tls, client_ip).ok_or(RouteError::NoRoute)?;
    select(table, matched, request, client_ip).map(|(selected, _lease)| selected)
}

#[cfg(test)]
mod test {
    use super::*;
    use podgate_model::Snapshot;

    fn table(json: &str) -> RoutingTable {
        let snapshot: Snapshot = serde_json::from_str(json).expect("valid snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    const ONE_APP: &str = r#"{
        "version": 1,
        "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
        "apps": [{
            "id": "a", "tenant": "t", "declared_by": "test",
            "tls": {"mode": "acme"},
            "routers": [
                {"name": "api", "match": {"all": [{"host": "a.test"}, {"path_prefix": "/api"}]}, "service": "api"},
                {"name": "site", "match": {"host": "a.test"}, "service": "web"}
            ],
            "revisions": [{"id": "r", "weight": 1, "state": "serving", "services": [
                {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:9000"}]},
                {"name": "api", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:9001"}]}
            ]}]
        }]
    }"#;

    fn request(host: Option<&str>, path: &str) -> RequestHeader {
        let mut request =
            RequestHeader::build("GET", path.as_bytes(), None).expect("valid request line");
        if let Some(host) = host {
            request.insert_header("Host", host).expect("valid header");
        }
        request
    }

    fn port(table: &RoutingTable, request: &RequestHeader) -> Result<u16, RouteError> {
        resolve(table, request, "web", false, None).map(|selected| selected.upstream.port())
    }

    #[test]
    fn routes_by_host_header_ignoring_case_and_port() {
        let table = table(ONE_APP);
        assert_eq!(port(&table, &request(Some("A.Test:8080"), "/")), Ok(9000));
    }

    #[test]
    fn the_more_specific_router_wins_and_the_service_follows_it() {
        let table = table(ONE_APP);
        assert_eq!(port(&table, &request(Some("a.test"), "/api/x")), Ok(9001));
        assert_eq!(port(&table, &request(Some("a.test"), "/apix")), Ok(9000));
        assert_eq!(port(&table, &request(Some("a.test"), "/api")), Ok(9001));
    }

    #[test]
    fn prefers_the_uri_authority_over_the_host_header() {
        let table = table(ONE_APP);
        let mut request = request(None, "/");
        request.set_uri("http://a.test/".parse().expect("valid uri"));
        request
            .insert_header("Host", "other.test")
            .expect("valid header");
        assert!(resolve(&table, &request, "web", false, None).is_ok());
    }

    #[test]
    fn unknown_or_missing_host_has_no_route() {
        let table = table(ONE_APP);
        assert_eq!(
            port(&table, &request(Some("nope.test"), "/")),
            Err(RouteError::NoRoute)
        );
        assert_eq!(port(&table, &request(None, "/")), Err(RouteError::NoRoute));
    }

    #[test]
    fn a_path_that_cannot_be_normalized_has_no_route() {
        let table = table(ONE_APP);
        assert_eq!(
            port(&table, &request(Some("a.test"), "/a%2Fb")),
            Err(RouteError::NoRoute)
        );
    }

    #[test]
    fn app_without_a_serving_revision_has_no_upstream() {
        let table = table(&ONE_APP.replace("serving", "draining"));
        assert_eq!(
            port(&table, &request(Some("a.test"), "/")),
            Err(RouteError::NoUpstream)
        );
    }

    #[test]
    fn a_serving_revision_whose_servers_are_all_down_is_not_asleep() {
        let table = table(ONE_APP);
        let revision = &table.app(0).expect("app").revisions()[0];
        for named in revision.services() {
            for server in named.service.servers() {
                server
                    .state
                    .healthy
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
        assert_eq!(
            port(&table, &request(Some("a.test"), "/")),
            Err(RouteError::AllUnhealthy)
        );
    }
}
