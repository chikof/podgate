//! Core host routing: which app, revision and backend a request goes to.
//!
//! Pure functions over a [`RoutingTable`] and a request header, so they are testable without a
//! running proxy. `proxy.rs` calls [`resolve`] and does nothing else about routing.

use std::borrow::Cow;
use std::net::SocketAddr;

use pingora::http::RequestHeader;
use thiserror::Error;

use crate::host;
use crate::table::RoutingTable;

/// The routing decision for one request. Indices point into the table the request was
/// resolved against, which the request keeps for its whole life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selected {
    /// Index of the app, for [`RoutingTable::app`].
    pub app: usize,
    /// Index of the revision, for [`crate::table::CompiledApp::revisions`].
    pub revision: usize,
    /// The backend to connect to.
    pub upstream: SocketAddr,
}

/// Why a request has no route.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteError {
    /// No app answers for the request's host, or the request names none.
    #[error("unknown host")]
    UnknownHost,
    /// The app exists but no revision takes new requests.
    #[error("no upstream available")]
    NoUpstream,
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

/// Routes a request against `table`.
///
/// # Errors
///
/// [`RouteError::UnknownHost`] when no app claims the host, [`RouteError::NoUpstream`] when the
/// app has no revision that takes new requests.
pub fn resolve(table: &RoutingTable, request: &RequestHeader) -> Result<Selected, RouteError> {
    let host = request_host(request).ok_or(RouteError::UnknownHost)?;
    let (index, app) = table.find_app(&host).ok_or(RouteError::UnknownHost)?;
    let pick = app.pick().ok_or(RouteError::NoUpstream)?;
    Ok(Selected {
        app: index,
        revision: pick.revision,
        upstream: pick.upstream,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::snapshot::Snapshot;

    fn table(json: &str) -> RoutingTable {
        let snapshot: Snapshot = serde_json::from_str(json).expect("valid snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    const ONE_APP: &str = r#"{
        "version": 1,
        "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
        "apps": [{
            "id": "a", "tenant": "t", "declared_by": "test", "hosts": ["a.test"],
            "tls": {"mode": "acme"},
            "revisions": [{"id": "r", "upstreams": ["127.0.0.1:9000"], "weight": 1, "state": "serving"}]
        }]
    }"#;

    fn request(host: Option<&str>) -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("valid request line");
        if let Some(host) = host {
            request.insert_header("Host", host).expect("valid header");
        }
        request
    }

    #[test]
    fn routes_by_host_header_ignoring_case_and_port() {
        let table = table(ONE_APP);
        let selected = resolve(&table, &request(Some("A.Test:8080"))).expect("routes");
        assert_eq!(selected.upstream, SocketAddr::from(([127, 0, 0, 1], 9000)));
    }

    #[test]
    fn prefers_the_uri_authority_over_the_host_header() {
        let table = table(ONE_APP);
        let mut request = request(None);
        request.set_uri("http://a.test/".parse().expect("valid uri"));
        request
            .insert_header("Host", "other.test")
            .expect("valid header");
        assert!(resolve(&table, &request).is_ok());
    }

    #[test]
    fn unknown_or_missing_host_is_unknown() {
        let table = table(ONE_APP);
        assert_eq!(
            resolve(&table, &request(Some("nope.test"))),
            Err(RouteError::UnknownHost)
        );
        assert_eq!(
            resolve(&table, &request(None)),
            Err(RouteError::UnknownHost)
        );
    }

    #[test]
    fn app_without_a_serving_revision_has_no_upstream() {
        let table = table(&ONE_APP.replace("serving", "draining"));
        assert_eq!(
            resolve(&table, &request(Some("a.test"))),
            Err(RouteError::NoUpstream)
        );
    }
}
