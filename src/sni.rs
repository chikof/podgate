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
//!
//! The same handshake callback records the client certificate chain the connection presented,
//! for [`crate::clientauth`].

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::{SslDigest, TlsRef};
use pingora::proxy::Session;

use crate::clientauth::ClientChain;
use crate::error::AppError;
use crate::host;
use crate::route;
use crate::router::Matched;
use crate::table::{CompiledApp, RoutingTable};

/// What a TLS connection negotiated, stored in the connection's `SslDigest` extension by
/// [`CaptureServerName`]: the SNI, normalized like a request host, and the client's chain.
#[derive(Debug)]
struct NegotiatedServerName(Option<Box<str>>, Option<ClientChain>);

/// Handshake hook that records the SNI and the client certificate chain on the connection for
/// [`check`] and [`crate::clientauth::admit`].
#[derive(Debug, Clone, Copy)]
pub struct CaptureServerName;

#[async_trait]
impl TlsAccept for CaptureServerName {
    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        let name = ssl
            .server_name()
            .map(|name| Box::from(&*host::normalize(name)));
        Some(Arc::new(NegotiatedServerName(
            name,
            ClientChain::new(ssl.peer_cert_chain_der()),
        )))
    }
}

/// The server name a TLS connection negotiated, from its digest: what [`CaptureServerName`]
/// stored, or, on the internal connection of the QUIC front, the name the front read
/// from the QUIC handshake and carried in the PROXY header (see [`crate::h3::bridge`]).
fn negotiated_name(tls: &SslDigest) -> Option<&str> {
    match tls.extension.get::<NegotiatedServerName>() {
        Some(negotiated) => negotiated.0.as_deref(),
        None if crate::h3::bridge::is_front_link(tls) => tls.organization.as_deref(),
        None => None,
    }
}

/// The server name the client sent in the handshake of the session's TLS connection, normalized;
/// `None` on plain HTTP and when it sent none.
pub(crate) fn server_name(session: &Session) -> Option<&str> {
    negotiated_name(session.digest()?.ssl_digest.as_ref()?)
}

/// The client certificate chain of the session's TLS connection; `None` on plain HTTP and when
/// the client sent no certificate.
pub(crate) fn client_chain(session: &Session) -> Option<&ClientChain> {
    session
        .digest()?
        .ssl_digest
        .as_ref()?
        .extension
        .get::<NegotiatedServerName>()?
        .1
        .as_ref()
}

/// Refuses a TLS request whose host differs from the connection's SNI.
///
/// Plain HTTP connections pass. `matched` is the router the request matched, so the app that
/// decides fronting is the one that would actually serve it, whatever kind of router (exact
/// host, wildcard, `host_regexp`) got it there. Run it right after matching, before anything
/// answers: a misdirected request gets `421` whether or not a router matched, so it learns
/// nothing about the route it named.
///
/// # Errors
///
/// [`AppError::Misdirected`] when the SNI and the request host differ and the matched app does
/// not allow domain fronting (or nothing matched).
pub fn check(
    session: &Session,
    table: &RoutingTable,
    matched: Option<Matched>,
) -> Result<(), AppError> {
    let Some(tls) = session
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
    else {
        return Ok(());
    };
    let app = matched.and_then(|matched| table.app(matched.app));
    // A request over HTTP/3 reaches only apps that allow it, so `http3: false` holds even for
    // a host named through a connection another app's name opened.
    if crate::h3::bridge::is_front_link(tls)
        && app.is_some_and(|app| !crate::h3::alt_svc::allowed(app.tls()))
    {
        return Err(AppError::Misdirected);
    }
    let fronting_allowed = app.is_some_and(CompiledApp::allow_domain_fronting);
    verify(negotiated_name(tls), session.req_header(), fronting_allowed)
}

/// The comparison behind [`check`]: `sni` is the connection's normalized SNI.
///
/// Every host the request names (the URI authority, which is `:authority` on HTTP/2, and each
/// `Host` header) must equal it. A request that names no host passes; routing answers it.
fn verify(
    sni: Option<&str>,
    request: &pingora::http::RequestHeader,
    fronting_allowed: bool,
) -> Result<(), AppError> {
    if route::request_host(request).is_none() {
        return Ok(());
    }
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
    if matches || fronting_allowed {
        Ok(())
    } else {
        Err(AppError::Misdirected)
    }
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;

    use super::*;

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
        let request = request(Some("A.Test:8443"), None);
        assert!(verify(Some("a.test"), &request, false).is_ok());
    }

    #[test]
    fn different_host_is_misdirected() {
        let request = request(Some("b.test"), None);
        assert!(matches!(
            verify(Some("a.test"), &request, false),
            Err(AppError::Misdirected)
        ));
    }

    #[test]
    fn authority_and_host_must_both_match() {
        let request = request(Some("b.test"), Some("a.test"));
        assert!(verify(Some("a.test"), &request, false).is_err());
    }

    #[test]
    fn missing_sni_is_misdirected() {
        let request = request(Some("a.test"), None);
        assert!(verify(None, &request, false).is_err());
    }

    #[test]
    fn the_matched_app_decides_fronting() {
        let to_b = request(Some("b.test"), None);
        assert!(verify(Some("a.test"), &to_b, true).is_ok());
        assert!(verify(Some("a.test"), &to_b, false).is_err());
    }

    #[test]
    fn a_request_without_a_host_is_left_to_routing() {
        assert!(verify(Some("a.test"), &request(None, None), false).is_ok());
    }
}
