//! Keeps a TLS request on the host its handshake was for: the SNI the client sent must equal
//! the `Host` and `:authority` it then asks for, unless the target app sets
//! `allow_domain_fronting`.
//!
//! Without the check, a client holding a valid connection to `a.test` can address `b.test`
//! through it and reach an app the connection's certificate and policy never covered (Traefik
//! GHSA-fh26-gfpp-7xxx).
//!
//! The SNI comes from the connection's TLS state, never from the request: [`CaptureServerName`]
//! reads rustls' `server_name()` when the handshake completes and stores it in the connection's
//! `SslDigest` extension; [`check`] reads it back from the session. So an HTTP/2 request with
//! `:scheme http` on a TLS connection is checked like any other, and plain HTTP is not
//! checked at all.
//!
//! A TLS connection with no recorded SNI is refused unless the app allows fronting. The
//! listener's certificate resolver already aborts handshakes without SNI; this keeps the check
//! closed on its own.

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::proxy::Session;

use crate::error::AppError;
use crate::host;
use crate::route;
use crate::table::RoutingTable;

/// The SNI a TLS connection negotiated, normalized like a request host. Stored in the
/// connection's `SslDigest` extension by [`CaptureServerName`].
#[derive(Debug)]
struct NegotiatedServerName(Option<Box<str>>);

/// Handshake hook that records the SNI on the connection for [`check`].
#[derive(Debug, Clone, Copy)]
pub struct CaptureServerName;

#[async_trait]
impl TlsAccept for CaptureServerName {
    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        let name = ssl.server_name().map(|name| Box::from(&*host::normalize(name)));
        Some(Arc::new(NegotiatedServerName(name)))
    }
}

/// Refuses a TLS request whose host differs from the connection's SNI.
///
/// Plain HTTP connections pass. Runs before routing so a misdirected request learns nothing
/// about the route it named.
///
/// # Errors
///
/// [`AppError::Misdirected`] when the SNI and the request host differ and the app the request
/// names does not allow domain fronting.
pub fn check(session: &Session, table: &RoutingTable) -> Result<(), AppError> {
    let Some(tls) = session
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
    else {
        return Ok(());
    };
    let sni = tls
        .extension
        .get::<NegotiatedServerName>()
        .and_then(|name| name.0.as_deref());
    verify(sni, session.req_header(), table)
}

/// The comparison behind [`check`]: `sni` is the connection's normalized SNI.
///
/// Every host the request names (the URI authority, which is `:authority` on HTTP/2, and each
/// `Host` header) must equal it. A request that names no host passes; routing answers it.
fn verify(
    sni: Option<&str>,
    request: &pingora::http::RequestHeader,
    table: &RoutingTable,
) -> Result<(), AppError> {
    let Some(routed) = route::request_host(request) else {
        return Ok(());
    };
    let authority = request
        .uri
        .authority()
        .map(|authority| Some(host::normalize(authority.as_str())));
    let headers = request
        .headers
        .get_all("host")
        .iter()
        .map(|value| value.to_str().ok().map(host::normalize));
    let matches = authority
        .into_iter()
        .chain(headers)
        .all(|named| named.as_deref().is_some_and(|name| Some(name) == sni));
    if matches {
        return Ok(());
    }
    let allowed = table
        .find_app(&routed)
        .is_some_and(|(_, app)| app.allow_domain_fronting());
    if allowed {
        Ok(())
    } else {
        Err(AppError::Misdirected)
    }
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;

    use super::*;
    use crate::snapshot::Snapshot;

    fn table(allow_a: bool, allow_b: bool) -> RoutingTable {
        let app = |id: &str, allow: bool| {
            format!(
                r#"{{"id": "{id}", "tenant": "t", "declared_by": "test", "hosts": ["{id}.test"],
                "tls": {{"mode": "acme"}}, "allow_domain_fronting": {allow},
                "revisions": [{{"id": "r", "upstreams": ["127.0.0.1:9000"], "weight": 1, "state": "serving"}}]}}"#
            )
        };
        let json = format!(
            r#"{{"version": 1,
            "tenants": [{{"id": "t", "weight": 1, "budget": {{"max_inflight": 1, "max_buffer_bytes": 1}}}}],
            "apps": [{}, {}]}}"#,
            app("a", allow_a),
            app("b", allow_b)
        );
        let snapshot: Snapshot = serde_json::from_str(&json).expect("valid snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    fn request(host: Option<&str>, authority: Option<&str>) -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("valid request line");
        if let Some(authority) = authority {
            request.set_uri(format!("http://{authority}/").parse().expect("valid uri"));
        }
        if let Some(host) = host {
            request.insert_header("Host", host).expect("valid header");
        }
        request
    }

    #[test]
    fn same_host_passes_ignoring_case_and_port() {
        let table = table(false, false);
        let request = request(Some("A.Test:8443"), None);
        assert!(verify(Some("a.test"), &request, &table).is_ok());
    }

    #[test]
    fn different_host_is_misdirected() {
        let table = table(false, false);
        let request = request(Some("b.test"), None);
        assert!(matches!(
            verify(Some("a.test"), &request, &table),
            Err(AppError::Misdirected)
        ));
    }

    #[test]
    fn authority_and_host_must_both_match() {
        let table = table(false, false);
        let request = request(Some("b.test"), Some("a.test"));
        assert!(verify(Some("a.test"), &request, &table).is_err());
    }

    #[test]
    fn missing_sni_is_misdirected() {
        let table = table(false, false);
        let request = request(Some("a.test"), None);
        assert!(verify(None, &request, &table).is_err());
    }

    #[test]
    fn the_target_app_decides_fronting() {
        let table = table(false, true);
        let to_b = request(Some("b.test"), None);
        assert!(verify(Some("a.test"), &to_b, &table).is_ok());
        let to_a = request(Some("a.test"), None);
        assert!(verify(Some("b.test"), &to_a, &table).is_err());
    }

    #[test]
    fn a_request_without_a_host_is_left_to_routing() {
        let table = table(false, false);
        assert!(verify(Some("a.test"), &request(None, None), &table).is_ok());
    }
}
