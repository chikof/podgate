//! `PUT /v1/snapshot`: replace the routing table.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::put;
use axum::{Json, Router};
use serde_json::{Value, json};

use super::AppState;
use crate::error::AppError;
use crate::snapshot::Snapshot;

/// Largest accepted snapshot body.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/snapshot", put(put_snapshot))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Applies the pushed snapshot: `200 {"version": N}`, `400` for malformed JSON, `409` when the
/// version is not newer than the live one, `422` when it does not compile.
async fn put_snapshot(State(state): State<AppState>, body: Bytes) -> Result<Json<Value>, AppError> {
    let snapshot: Snapshot = serde_json::from_slice(&body)
        .map_err(|err| AppError::BadRequest(format!("invalid snapshot: {err}").into()))?;
    // Compiling can be slow (WASM filter modules): keep it off the admin runtime's workers.
    let table = state.table().clone();
    let (replaced, snapshot) = tokio::task::spawn_blocking(move || {
        table
            .apply_replacing(&snapshot)
            .map(|replaced| (replaced, snapshot))
    })
    .await
    .map_err(|err| AppError::Internal(err.into()))??;
    state.inflight().sync(&state.table().load());
    state.failures().retain_apps(&state.table().load());
    state
        .reverter()
        .applied(&replaced, snapshot.revert_window_secs);
    Ok(Json(json!({ "version": snapshot.version })))
}
