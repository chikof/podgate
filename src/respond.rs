//! Writes an [`AppError`] to a proxied client as a JSON response, ending the request.

use bytes::Bytes;
use pingora::ErrorType::HTTPStatus;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingora::{BError, Error};

use crate::error::AppError;

/// Answers the request with `err`: its status and `{"error": "..."}` body. Call it from a
/// `ProxyHttp` filter and return `Ok(true)` so Pingora does not forward the request.
///
/// # Errors
///
/// Fails when the response cannot be written to the client.
pub async fn write_error(session: &mut Session, err: &AppError) -> pingora::Result<()> {
    write_error_with(session, err, &[]).await
}

/// As [`write_error`], with `extra` response headers (a quota's `RateLimit-*`).
///
/// # Errors
///
/// Fails when the response cannot be written to the client.
pub async fn write_error_with(
    session: &mut Session,
    err: &AppError,
    extra: &[(&'static str, String)],
) -> pingora::Result<()> {
    let body = Bytes::from(err.body().to_string());
    let mut header = ResponseHeader::build(err.status(), Some(3 + extra.len()))?;
    header.insert_header("content-type", "application/json")?;
    header.insert_header("content-length", body.len().to_string())?;
    if let Some(secs) = err.retry_after_secs() {
        header.insert_header("retry-after", secs.to_string())?;
    }
    for (name, value) in extra {
        header.insert_header(*name, value.as_str())?;
    }
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session.write_response_body(Some(body), true).await
}

/// Ends a request that is already past `request_filter` (a body or response hook) with `err`.
/// When no response has been written yet, `err` is written as the response, as [`write_error`]
/// does; when the response has started, nothing more can be said and the connection is reset.
/// Return the result from the hook: Pingora ends the request and does not reuse the connection.
pub async fn abort(session: &mut Session, err: &AppError) -> BError {
    if session.response_written().is_none()
        && let Err(write) = write_error(session, err).await
    {
        return write;
    }
    Error::explain(HTTPStatus(err.status().as_u16()), err.to_string())
}
