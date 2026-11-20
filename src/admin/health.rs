//! `GET /healthz` and `GET /readyz`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

use super::AppState;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
}

/// Liveness: the process is up and the event loop answers. Never checks dependencies.
async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Readiness: `200` while the admin API serves, `503` before startup and while draining.
async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    if state.is_ready() {
        (StatusCode::OK, Json(json!({ "status": "ready" })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not ready" })),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::events::EventFeed;
    use crate::inflight::Inflight;
    use crate::table::TableHandle;

    #[tokio::test]
    async fn readyz_follows_state() {
        let state = AppState::new(TableHandle::new(), EventFeed::new(), Inflight::new(EventFeed::new()));
        let (status, Json(body)) = readyz(State(state.clone())).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "not ready");

        state.set_ready(true);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
    }
}
