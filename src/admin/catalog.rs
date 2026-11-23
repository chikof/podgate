//! `GET /v1/catalog`: every API the live table serves, with its version and lifecycle,
//! read-only. Reference: `docs/ref/catalog.md`.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_TYPE, RETRY_AFTER};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use super::AppState;
use crate::catalog::render::{self, Cursor, DEFAULT_LIMIT, MAX_LIMIT};
use crate::error::AppError;
use podgate_model::Lifecycle;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/v1/catalog", any(entry))
}

#[derive(Debug, Deserialize)]
pub(crate) struct Params {
    /// Only this tenant.
    tenant: Option<String>,
    /// Only this app.
    app: Option<String>,
    /// Only this lifecycle.
    lifecycle: Option<String>,
    /// Most entries. Absent: 50. At most 500.
    limit: Option<usize>,
    /// The `next` of the previous page.
    after: Option<String>,
}

/// The lifecycle called `word`, or the error that names the ones that exist.
fn lifecycle(word: &str) -> Result<Lifecycle, String> {
    const ALL: [Lifecycle; 5] = [
        Lifecycle::Draft,
        Lifecycle::Preview,
        Lifecycle::Stable,
        Lifecycle::Deprecated,
        Lifecycle::Retired,
    ];
    ALL.into_iter()
        .find(|stage| stage.name() == word)
        .ok_or_else(|| {
            let names: Vec<&str> = ALL.iter().map(|stage| stage.name()).collect();
            format!(
                "unknown lifecycle {word:?}; the lifecycles are {}",
                names.join(", ")
            )
        })
}

impl Params {
    fn into_query(self) -> Result<render::Query, AppError> {
        let bad = |message: String| AppError::BadRequest(message.into());
        let limit = match self.limit {
            None => DEFAULT_LIMIT,
            Some(0) => return Err(bad("limit must be at least 1".into())),
            Some(limit) => limit.min(MAX_LIMIT),
        };
        Ok(render::Query {
            tenant: self.tenant,
            app: self.app,
            lifecycle: self
                .lifecycle
                .as_deref()
                .map(lifecycle)
                .transpose()
                .map_err(bad)?,
            limit,
            after: self
                .after
                .as_deref()
                .map(Cursor::parse)
                .transpose()
                .map_err(bad)?,
            ..render::Query::default()
        })
    }
}

/// `GET` only, like the overview: anything else is `405` with `allow: GET`.
pub(crate) async fn entry(
    method: Method,
    state: State<AppState>,
    params: Result<Query<Params>, QueryRejection>,
) -> Result<Response, AppError> {
    if method != Method::GET {
        return Ok((
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET")],
            Json(json!({ "error": "method not allowed" })),
        )
            .into_response());
    }
    get_catalog(state, params).await
}

/// `200` with the page asked for, built from the live routing table. `400` for a malformed
/// query, an unknown lifecycle, `limit=0` or a bad cursor; `503` with `retry-after: 1` while the
/// slots the overview shares are all taken.
async fn get_catalog(
    State(state): State<AppState>,
    params: Result<Query<Params>, QueryRejection>,
) -> Result<Response, AppError> {
    let Query(params) =
        params.map_err(|err| AppError::BadRequest(format!("invalid query: {err}").into()))?;
    let query = params.into_query()?;
    let Ok(permit) = state.overview_slots().clone().try_acquire_owned() else {
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            [(RETRY_AFTER, "1")],
            Json(json!({ "error": "catalog is busy" })),
        )
            .into_response());
    };
    let table = state.table().load();
    // Walking a large table and serializing megabytes stays off the admin runtime's workers.
    let body = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        render::render(&table, &query)
    })
    .await
    .map_err(|err| AppError::Internal(err.into()))?
    .map_err(|err| AppError::Internal(err.into()))?;
    Ok(([(CONTENT_TYPE, "application/json")], body).into_response())
}

#[cfg(test)]
mod test {
    use super::*;

    fn params(limit: Option<usize>, lifecycle: Option<&str>, after: Option<&str>) -> Params {
        Params {
            tenant: None,
            app: None,
            lifecycle: lifecycle.map(str::to_owned),
            limit,
            after: after.map(str::to_owned),
        }
    }

    #[test]
    fn catalog_query_is_validated() {
        assert!(matches!(
            params(Some(0), None, None).into_query(),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            params(None, Some("old"), None).into_query(),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            params(None, None, Some("a/b")).into_query(),
            Err(AppError::BadRequest(_))
        ));
        let clamped = params(Some(100_000), Some("retired"), Some("t/a/1"))
            .into_query()
            .expect("a query");
        assert_eq!(clamped.limit, MAX_LIMIT);
        assert_eq!(clamped.lifecycle, Some(Lifecycle::Retired));
        assert!(clamped.after.is_some());
    }
}
