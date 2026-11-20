//! `POST /v1/snapshot/validate`: does a snapshot compile, without applying anything.
//!
//! It takes the body of `PUT /v1/snapshot` and runs the same parse ([`super::snapshot::parse`])
//! and the same compile ([`crate::table::TableHandle::validate`]), so a snapshot the `PUT` would
//! refuse is refused with the same status and body. It differs in what it leaves out: the
//! version (a candidate need not be newer than the live snapshot) and the writer check (a tool
//! may validate what it is not allowed to push). It touches no state: no swap, no event, no
//! registry, no metric, no ACME order.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::http::header::RETRY_AFTER;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::json;

use super::AppState;
use super::snapshot::{MAX_BODY_BYTES, parse};
use crate::error::AppError;
use crate::table::ApplyError;

/// Most validations compiling at once.
pub(super) const MAX_CONCURRENT: usize = 4;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/snapshot/validate", post(post_validate))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// `200 {"valid": true, "warnings": []}` for a snapshot that compiles; `400` and `422` exactly as
/// `PUT /v1/snapshot` answers the same body. `503` with `retry-after: 1` while
/// [`MAX_CONCURRENT`] validations already compile. `warnings` is reserved: the compiler has
/// nothing to warn about yet, it either accepts or refuses.
async fn post_validate(State(state): State<AppState>, body: Bytes) -> Result<Response, AppError> {
    let Ok(permit) = state.validate_slots().clone().try_acquire_owned() else {
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            [(RETRY_AFTER, "1")],
            Json(json!({ "error": "validate is busy" })),
        )
            .into_response());
    };
    let snapshot = parse(&body)?;
    // Compiling can be slow (WASM filter modules): keep it off the admin runtime's workers. The
    // permit moves into the task, so the cap holds even when the client has gone.
    let table = state.table().clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        table.validate(&snapshot)
    })
    .await
    .map_err(|err| AppError::Internal(err.into()))?
    .map_err(|err| AppError::from(ApplyError::from(err)))?;
    Ok(Json(json!({ "valid": true, "warnings": [] })).into_response())
}

#[cfg(test)]
mod test {
    use axum::body::to_bytes;
    use serde_json::{Value, json};

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

    fn body() -> Bytes {
        Bytes::from(json!({ "version": 1, "tenants": [], "apps": [] }).to_string())
    }

    async fn answer(state: &AppState) -> (StatusCode, Option<String>, Value) {
        let response = post_validate(State(state.clone()), body())
            .await
            .into_response();
        let status = response.status();
        let retry = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, retry, serde_json::from_slice(&bytes).expect("JSON"))
    }

    #[tokio::test]
    async fn validate_is_concurrency_capped() {
        let state = state();
        let held: Vec<_> = (0..MAX_CONCURRENT)
            .map(|_| {
                state
                    .validate_slots()
                    .clone()
                    .try_acquire_owned()
                    .expect("a free slot")
            })
            .collect();
        let (status, retry, body) = answer(&state).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry.as_deref(), Some("1"));
        assert_eq!(body, json!({ "error": "validate is busy" }));

        drop(held);
        let (status, retry, body) = answer(&state).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(retry, None);
        assert_eq!(body, json!({ "valid": true, "warnings": [] }));
        assert_eq!(
            state.validate_slots().available_permits(),
            MAX_CONCURRENT,
            "the slot comes back when the compile ends"
        );
    }
}
