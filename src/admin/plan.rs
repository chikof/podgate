//! `POST /v1/snapshot/plan`: what a snapshot would change, without applying it.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::post;
use axum::{Json, Router};

use super::AppState;
use super::snapshot::{MAX_BODY_BYTES, parse};
use super::writer::Claim;
use crate::error::AppError;
use crate::plan::{self, Plan};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/snapshot/plan", post(post_plan))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Diffs the pushed snapshot against the live table and applies nothing. `200` with the
/// [`Plan`]; `400`, `409` and `422` exactly as `PUT /v1/snapshot` answers the same body, since
/// the plan runs the same writer check, version check and compiler.
async fn post_plan(
    State(state): State<AppState>,
    claim: Claim,
    body: Bytes,
) -> Result<Json<Plan>, AppError> {
    state.writer().check(&claim)?;
    let snapshot = parse(&body)?;
    let live = state.table().load();
    // Compiling can be slow (WASM filter modules): keep it off the admin runtime's workers.
    let table = state.table().clone();
    let candidate = tokio::task::spawn_blocking(move || table.compile_candidate(&snapshot))
        .await
        .map_err(|err| AppError::Internal(err.into()))??;
    Ok(Json(plan::diff(&live, &candidate)))
}
