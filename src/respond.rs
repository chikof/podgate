//! Writes an [`AppError`] to a proxied client as a JSON response, ending the request.

use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;

use crate::error::AppError;

/// Answers the request with `err`: its status and `{"error": "..."}` body. Call it from a
/// `ProxyHttp` filter and return `Ok(true)` so Pingora does not forward the request.
///
/// # Errors
///
/// Fails when the response cannot be written to the client.
pub async fn write_error(session: &mut Session, err: &AppError) -> pingora::Result<()> {
    let body = Bytes::from(err.body().to_string());
    let mut header = ResponseHeader::build(err.status(), Some(2))?;
    header.insert_header("content-type", "application/json")?;
    header.insert_header("content-length", body.len().to_string())?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session.write_response_body(Some(body), true).await
}
