//! `POST /v1/snapshot/plan`: what a snapshot would change, without applying it.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::post;
use axum::{Json, Router};

use super::AppState;
use crate::error::AppError;
use crate::plan::{self, Plan};
use crate::snapshot::Snapshot;
use crate::table::{ApplyError, RoutingTable};

/// Largest accepted snapshot body; the same as `PUT /v1/snapshot`.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/snapshot/plan", post(post_plan))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Diffs the pushed snapshot against the live table and applies nothing. `200` with the
/// [`Plan`]; `400`, `409` and `422` exactly as `PUT /v1/snapshot` answers the same body, since
/// the plan runs the same version check and compiler.
async fn post_plan(State(state): State<AppState>, body: Bytes) -> Result<Json<Plan>, AppError> {
    let snapshot: Snapshot = serde_json::from_slice(&body)
        .map_err(|err| AppError::BadRequest(format!("invalid snapshot: {err}").into()))?;
    let live = state.table().load();
    if snapshot.version <= live.version() {
        return Err(ApplyError::Stale {
            live: live.version(),
            offered: snapshot.version,
        }
        .into());
    }
    // Compiling can be slow (WASM filter modules): keep it off the admin runtime's workers.
    let candidate = tokio::task::spawn_blocking(move || RoutingTable::compile(&snapshot))
        .await
        .map_err(|err| AppError::Internal(err.into()))?
        .map_err(ApplyError::from)?;
    Ok(Json(plan::diff(&live, &candidate)))
}
