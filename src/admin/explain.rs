//! `GET /v1/explain`: why a request goes where it goes.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use super::AppState;
use crate::error::AppError;
use crate::explain::{self, Target};

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/v1/explain", get(get_explain))
}

#[derive(Debug, Deserialize)]
struct Params {
    /// The request URL: absolute, `http` or `https`. Scheme, host, path and query are read.
    url: String,
    /// The request method. Absent: `GET`.
    method: Option<String>,
    /// The entry point the request arrives on. Absent: `web` for `http`, `websecure` for `https`.
    entry_point: Option<String>,
}

/// `200` with the app, tenant, declaring source, matched router, the routers it shadows, the
/// revisions with their effective weights and servers, and the pipeline, all read from the live
/// routing table. `404 {"error": "not found", "nearest_wildcard": ...}` when no router matches.
/// `400` for a missing or invalid `url`, an invalid `method` or a malformed query.
async fn get_explain(
    State(state): State<AppState>,
    params: Result<Query<Params>, QueryRejection>,
) -> Result<Response, AppError> {
    let Query(params) =
        params.map_err(|err| AppError::BadRequest(format!("invalid query: {err}").into()))?;
    let target = Target::parse(
        &params.url,
        params.method.as_deref(),
        params.entry_point.as_deref(),
    )
    .map_err(|err| AppError::BadRequest(err.to_string().into()))?;
    let table = state.table().load();
    Ok(match explain::explain(&table, &target) {
        Ok(explanation) => Json(explanation).into_response(),
        Err(miss) => (StatusCode::NOT_FOUND, Json(miss)).into_response(),
    })
}
