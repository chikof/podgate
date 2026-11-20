//! `GET /v1/overview`: what is configured and how it is doing, read-only.

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
use crate::error::AppError;
use crate::overview::{self, DEFAULT_LIMIT, MAX_LIMIT, Runtime, Section};

/// Overview computations that may run at once; more get `503`.
pub(super) const MAX_CONCURRENT: usize = 8;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/v1/overview", any(entry))
}

#[derive(Debug, Deserialize)]
struct Params {
    /// Only this tenant.
    tenant: Option<String>,
    /// Only this app.
    app: Option<String>,
    /// Most items per list. Absent: 50. At most 500.
    limit: Option<usize>,
    /// Apps after this app id.
    after: Option<String>,
    /// Comma separated sections. Absent: all.
    section: Option<String>,
}

impl Params {
    fn into_query(self) -> Result<overview::Query, AppError> {
        let bad = |message: String| AppError::BadRequest(message.into());
        let limit = match self.limit {
            None => DEFAULT_LIMIT,
            Some(0) => return Err(bad("limit must be at least 1".into())),
            Some(limit) => limit.min(MAX_LIMIT),
        };
        let sections = match self.section.as_deref() {
            None => Vec::new(),
            Some(list) => Section::parse_list(list).map_err(bad)?,
        };
        Ok(overview::Query {
            tenant: self.tenant,
            app: self.app,
            limit,
            after: self.after,
            sections,
            ..overview::Query::default()
        })
    }
}

/// `GET` only. axum's own `get` route would answer `HEAD` too, and the overview takes nothing
/// but `GET`, so the method is checked here and anything else is `405` with `allow: GET`.
async fn entry(
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
    get_overview(state, params).await
}

/// `200` with the sections asked for, built from the live routing table and the runtime
/// registries, never from a snapshot and never with a secret. `400` for a malformed query, an
/// unknown section or `limit=0`; `503` with `retry-after: 1` while [`MAX_CONCURRENT`]
/// computations already run.
async fn get_overview(
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
            Json(json!({ "error": "overview is busy" })),
        )
            .into_response());
    };
    let table = state.table().load();
    let budgets = state.budgets().clone();
    let inflight = state.inflight().clone();
    let outcomes = state.outcomes().clone();
    let boot_id = state.events().boot_id().to_owned();
    let entry_points = state.entry_points();
    let metrics_addr = state.metrics_addr();
    // Walking a large table and serializing megabytes stays off the admin runtime's workers.
    let body = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let runtime = Runtime {
            budgets: &budgets,
            inflight: &inflight,
            outcomes: &outcomes,
            boot_id: &boot_id,
            entry_points: &entry_points,
            metrics_addr,
        };
        overview::render(&table, &runtime, &query)
    })
    .await
    .map_err(|err| AppError::Internal(err.into()))?
    .map_err(|err| AppError::Internal(err.into()))?;
    Ok(([(CONTENT_TYPE, "application/json")], body).into_response())
}

#[cfg(test)]
mod test {
    use axum::body::to_bytes;

    use super::*;
    use crate::events::EventFeed;
    use crate::inflight::Inflight;
    use crate::table::TableHandle;

    fn state() -> AppState {
        AppState::new(
            TableHandle::new(),
            EventFeed::new(),
            Inflight::new(EventFeed::new()),
        )
    }

    fn params(limit: Option<usize>, section: Option<&str>) -> Params {
        Params {
            tenant: None,
            app: None,
            limit,
            after: None,
            section: section.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn overview_concurrency_capped() {
        let state = state();
        let held: Vec<_> = (0..MAX_CONCURRENT)
            .map(|_| {
                state
                    .overview_slots()
                    .clone()
                    .try_acquire_owned()
                    .expect("a free slot")
            })
            .collect();

        let busy = get_overview(State(state.clone()), Ok(Query(params(None, None))))
            .await
            .expect("response");
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(busy.headers()[RETRY_AFTER], "1");
        let body = to_bytes(busy.into_body(), usize::MAX).await.expect("body");
        assert_eq!(&body[..], br#"{"error":"overview is busy"}"#);

        drop(held);
        let served = get_overview(
            State(state.clone()),
            Ok(Query(params(None, Some("summary")))),
        )
        .await
        .expect("response");
        assert_eq!(served.status(), StatusCode::OK);
        assert_eq!(
            state.overview_slots().available_permits(),
            MAX_CONCURRENT,
            "a finished request gives its slot back"
        );
    }

    #[test]
    fn limits_and_sections_are_validated() {
        assert!(matches!(
            params(Some(0), None).into_query(),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            params(None, Some("nope")).into_query(),
            Err(AppError::BadRequest(_))
        ));
        let clamped = params(Some(100_000), None).into_query().expect("clamped");
        assert_eq!(clamped.limit, MAX_LIMIT);
        let listed = params(None, Some("summary,apps"))
            .into_query()
            .expect("sections");
        assert_eq!(listed.sections, [Section::Summary, Section::Apps]);
    }
}
