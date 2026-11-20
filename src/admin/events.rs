//! `GET /v1/events`: the event feed as a long poll.

use std::time::Duration;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::json;

use super::AppState;
use crate::error::AppError;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/v1/events", get(get_events))
}

/// Longest a poll may wait: one second under the request timeout, which would otherwise end the
/// poll with `408`.
#[derive(Debug, Clone, Copy)]
pub(super) struct PollCap(Duration);

/// The layer that tells [`get_events`] the request `timeout` of the router it is mounted in.
pub(super) fn poll_cap(timeout: Duration) -> Extension<PollCap> {
    Extension(PollCap(timeout.saturating_sub(Duration::from_secs(1))))
}

#[derive(Debug, Deserialize)]
struct Params {
    /// Last sequence number the caller has seen.
    #[serde(default)]
    after: u64,
    /// How long to wait for a first event. Absent: answer at once.
    #[serde(default)]
    timeout_secs: u64,
}

/// `200 {"boot_id": "...", "events": [...]}` with the events after `after`, oldest first; the
/// list is empty when none arrived within `timeout_secs` (capped, see [`PollCap`]).
/// `410 {"error": "...", "boot_id": "..."}` when `after` is older than the retained ring: the
/// caller must resync. `400` for malformed query parameters.
async fn get_events(
    State(state): State<AppState>,
    Extension(PollCap(cap)): Extension<PollCap>,
    params: Result<Query<Params>, QueryRejection>,
) -> Result<Response, AppError> {
    let Query(params) =
        params.map_err(|err| AppError::BadRequest(format!("invalid query: {err}").into()))?;
    let timeout = Duration::from_secs(params.timeout_secs).min(cap);
    let boot_id = state.events().boot_id();
    Ok(match state.events().poll(params.after, timeout).await {
        Ok(events) => Json(json!({ "boot_id": boot_id, "events": events })).into_response(),
        Err(gone) => (
            StatusCode::GONE,
            Json(json!({
                "error": gone.to_string(),
                "boot_id": boot_id,
                "oldest": gone.oldest,
            })),
        )
            .into_response(),
    })
}
