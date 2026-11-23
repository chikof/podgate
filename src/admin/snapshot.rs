//! `PUT /v1/snapshot`: replace the routing table.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::put;
use axum::{Json, Router};
use serde_json::{Value, json};

use super::AppState;
use super::writer::Claim;
use crate::error::AppError;
use crate::table::ApplyError;
use podgate_model::Snapshot;

/// Largest accepted snapshot body.
pub(super) const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/snapshot", put(put_snapshot))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Reads a snapshot body. The one parse of `PUT /v1/snapshot`, `POST /v1/snapshot/plan` and
/// `POST /v1/snapshot/validate`, so they refuse a malformed body alike.
///
/// # Errors
///
/// `400` for JSON that is not a snapshot.
pub(super) fn parse(body: &Bytes) -> Result<Snapshot, AppError> {
    serde_json::from_slice(body)
        .map_err(|err| AppError::BadRequest(format!("invalid snapshot: {err}").into()))
}

/// Applies the pushed snapshot: `200 {"version": N}`, `400` for malformed JSON, `409` when the
/// version is not newer than the live one or the push comes from another writer than the one
/// that owns the snapshot (see [`super::writer`]), `422` when it does not compile.
async fn put_snapshot(
    State(state): State<AppState>,
    claim: Claim,
    body: Bytes,
) -> Result<Json<Value>, AppError> {
    let push = state.writer().begin(claim).await?;
    let snapshot = parse(&body)?;
    // Compiling can be slow (WASM filter modules): keep it off the admin runtime's workers. The
    // push, with the writer gate in it, moves into the task: once the snapshot is live the writer
    // is pinned, even when the client has gone.
    let table = state.table().clone();
    let events = state.events().clone();
    let (replaced, snapshot) = tokio::task::spawn_blocking(move || {
        let replaced = table.apply_replacing(&snapshot)?;
        push.accepted(&events);
        Ok::<_, ApplyError>((replaced, snapshot))
    })
    .await
    .map_err(|err| AppError::Internal(err.into()))??;
    state.inflight().sync(&state.table().load());
    state.failures().retain_apps(&state.table().load());
    state.mcp_audit().retain_apps(&state.table().load());
    state.cache().retain(&state.table().load());
    state
        .reverter()
        .applied(&replaced, snapshot.revert_window_secs);
    Ok(Json(json!({ "version": snapshot.version })))
}
