//! Serves the HTTP-01 answers of the live snapshot, so the ACME server's validation request
//! succeeds on whichever node it reaches.

use bytes::Bytes;
use pingora::http::{Method, ResponseHeader};
use pingora::proxy::Session;

use crate::table::RoutingTable;

const PREFIX: &str = "/.well-known/acme-challenge/";

/// Answers `GET /.well-known/acme-challenge/<token>` on a plain HTTP connection when the
/// snapshot pushed `<token>`: `200` with the key authorization. Returns `true` when it
/// answered, so `request_filter` ends the request; anything else, including a token the
/// snapshot does not hold, is left to routing, so an app keeps its own `/.well-known` paths.
///
/// Runs before routing, because the validation request names the host being proven and that
/// host may have no certificate or backend yet. TLS connections are not served: HTTP-01
/// validates over plain HTTP.
///
/// # Errors
///
/// Fails when the response cannot be written to the client.
pub async fn serve_challenge(session: &mut Session, table: &RoutingTable) -> pingora::Result<bool> {
    let request = session.req_header();
    if request.method != Method::GET {
        return Ok(false);
    }
    let Some(token) = request.uri.path().strip_prefix(PREFIX) else {
        return Ok(false);
    };
    let Some(answer) = table.acme().challenge(token) else {
        return Ok(false);
    };
    let tls = session
        .digest()
        .is_some_and(|digest| digest.ssl_digest.is_some());
    if tls {
        return Ok(false);
    }
    let body = Bytes::from(answer.to_owned());
    let mut header = ResponseHeader::build(200, Some(2))?;
    header.insert_header("content-type", "application/octet-stream")?;
    header.insert_header("content-length", body.len().to_string())?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session.write_response_body(Some(body), true).await?;
    Ok(true)
}
