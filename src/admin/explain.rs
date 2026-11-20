//! `GET /v1/explain`: why a request goes where it goes.

use std::net::IpAddr;

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
    /// The entry point the request arrives on. Absent: the bound entry points of the URL's scheme
    /// are tried in order (`web` for `http` and `websecure` for `https` by default).
    entry_point: Option<String>,
    /// The resolved client address to match `client_ip` routers against. Absent: none matches.
    client_ip: Option<IpAddr>,
}

/// `200` with the app, tenant, declaring source, matched router, the routers it shadows, the
/// revisions with their effective weights and servers, and the pipeline, all read from the live
/// routing table. `404 {"error": "not found", "nearest_wildcard": ...}` when no router matches.
/// `400` for a missing or invalid `url`, an invalid `method`, a malformed query or an
/// `entry_point` this node did not bind.
async fn get_explain(
    State(state): State<AppState>,
    params: Result<Query<Params>, QueryRejection>,
) -> Result<Response, AppError> {
    let Query(params) =
        params.map_err(|err| AppError::BadRequest(format!("invalid query: {err}").into()))?;
    let table = state.table().load();
    let allow_encoded_slash = params
        .entry_point
        .as_deref()
        .is_some_and(|name| table.entry_policy(name).allow_encoded_slash());
    let target = Target::parse_with(
        &params.url,
        params.method.as_deref(),
        params.entry_point.as_deref(),
        allow_encoded_slash,
    )
    .map_err(|err| AppError::BadRequest(err.to_string().into()))?;
    let target = match params.client_ip {
        Some(client_ip) => target.with_client_ip(client_ip),
        None => target,
    };
    if let Some(name) = params
        .entry_point
        .as_deref()
        .filter(|name| !table.context().knows(name))
    {
        return Err(AppError::BadRequest(
            format!("entry point {name} is not bound by this node").into(),
        ));
    }
    Ok(match explain::explain(&table, &target) {
        Ok(explanation) => Json(explanation).into_response(),
        Err(miss) => (StatusCode::NOT_FOUND, Json(miss)).into_response(),
    })
}
