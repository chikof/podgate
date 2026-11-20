//! `POST /v1/cache/purge`: clear response-cache entries of one app. The cache is
//! [`crate::cache`]; the reference is `docs/ref/mw-cache.md`.

use axum::body::Bytes;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};

use super::AppState;
use crate::cache::purge::Request;
use crate::error::AppError;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/v1/cache/purge", post(purge))
}

/// Removes the entries of the named app that one selector picks: `url`, `prefix`, `tag`, or
/// `all`, exactly one. Answers `200 {"purged": N}`; their bytes are released before the answer.
///
/// - `400`: malformed JSON, no selector or several, a URL or prefix that is not a path or an
///   `http(s)` URL.
/// - `404`: the live table has no such app. The scope is the app: an app of another tenant that
///   has the same host or path is never touched.
async fn purge(State(state): State<AppState>, body: Bytes) -> Result<Json<Value>, AppError> {
    let request: Request = serde_json::from_slice(&body)
        .map_err(|err| AppError::BadRequest(format!("invalid purge request: {err}").into()))?;
    let table = state.table().load();
    let (_, app) = table.app_by_id(&request.app).ok_or(AppError::NotFound)?;
    let purged = state
        .cache()
        .purge(app.tenant(), &request)
        .map_err(|err| AppError::BadRequest(err.to_string().into()))?;
    Ok(Json(json!({ "purged": purged })))
}
