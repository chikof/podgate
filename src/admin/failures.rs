//! Failed requests: `GET /v1/apps/{app}/failures` and
//! `POST /v1/apps/{app}/failures/{id}/replay`. The recording is `crate::failures`.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use super::AppState;
use crate::error::AppError;
use crate::failures;
use crate::table::{CompiledApp, RoutingTable};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/apps/{app}/failures", get(list))
        .route("/v1/apps/{app}/failures/{id}/replay", post(replay))
}

/// `200 {"failures": [...]}`, newest first, up to 100; `404` when the live table has no such
/// app.
async fn list(
    State(state): State<AppState>,
    Path(app): Path<String>,
) -> Result<Json<Value>, AppError> {
    let table = state.table().load();
    live_app(&table, &app)?;
    let failures: Vec<Value> = state
        .failures()
        .list(&app)
        .iter()
        .map(|failed| failed.to_json())
        .collect();
    Ok(Json(json!({ "failures": failures })))
}

#[derive(Debug, Deserialize)]
struct ReplayQuery {
    revision: Option<String>,
    #[serde(default)]
    force: bool,
}

/// Re-sends the recorded request to the first upstream of `revision` of the app in the live
/// table and answers `200 {"status", "headers", "body", "body_truncated"}` with the upstream's
/// new response, whatever its status. Redacted headers are dropped from the replay.
///
/// - `400`: `revision` is missing or `force` is not a boolean.
/// - `404`: unknown app, record or revision.
/// - `409`: the method is not `GET` or `HEAD` and `force=true` is not given. Replaying a `POST`
///   can repeat its side effects, so it is the caller's explicit choice. Also when the first
///   server is `h2c://`: the replay is written in HTTP/1.1, which such a server cannot answer.
/// - `502`: the upstream could not be reached or answered something that is not HTTP/1.1.
/// - `503`: the revision has no upstream.
async fn replay(
    State(state): State<AppState>,
    Path((app, id)): Path<(String, String)>,
    query: Result<Query<ReplayQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let Query(query) = query.map_err(|err| AppError::BadRequest(err.body_text().into()))?;
    let revision_id = query
        .revision
        .ok_or_else(|| AppError::BadRequest("missing query parameter: revision".into()))?;
    let table = state.table().load();
    let compiled = live_app(&table, &app)?;
    let failed = id
        .parse()
        .ok()
        .and_then(|id| state.failures().get(&app, id))
        .ok_or(AppError::NotFound)?;
    let revision = compiled
        .revisions()
        .iter()
        .position(|revision| revision.id() == revision_id)
        .ok_or(AppError::NotFound)?;
    if !matches!(failed.method.as_str(), "GET" | "HEAD") && !query.force {
        return Err(AppError::Conflict(
            format!(
                "refusing to replay a {} request: pass force=true to send it again",
                failed.method
            )
            .into(),
        ));
    }
    let (peer, h2c) = compiled
        .first_peer(revision)
        .ok_or_else(|| AppError::Unavailable("revision has no upstream".into()))?;
    if h2c {
        return Err(AppError::Conflict(
            "the first server of the revision is h2c://: a replay is written in HTTP/1.1, which \
             it cannot answer"
                .into(),
        ));
    }
    match failures::replay(&failed, peer).await {
        Ok(replayed) => Ok(Json(replayed.to_json()).into_response()),
        Err(err) => Ok((
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("replay failed: {err}") })),
        )
            .into_response()),
    }
}

fn live_app<'a>(table: &'a RoutingTable, app: &str) -> Result<&'a CompiledApp, AppError> {
    failures::apps(table)
        .find(|compiled| compiled.id() == app)
        .ok_or(AppError::NotFound)
}
