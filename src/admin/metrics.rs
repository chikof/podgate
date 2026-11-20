//! `GET /metrics`: Prometheus text exposition of per-tenant usage.

use axum::Router;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;

use super::AppState;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics))
}

/// Per-tenant buffer bytes, in-flight requests and the counters behind them, as read from
/// [`crate::Budgets`] against the live table, then each backend's limit and queue from
/// [`crate::Backends`].
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        state.budgets().render(&state.table().load()) + &state.backends().render(),
    )
}

#[cfg(test)]
mod test {
    use axum::body::to_bytes;

    use super::*;
    use crate::events::EventFeed;
    use crate::inflight::Inflight;
    use crate::table::TableHandle;

    #[tokio::test]
    async fn metrics_is_prometheus_text() {
        let state = AppState::new(
            TableHandle::new(),
            EventFeed::new(),
            Inflight::new(EventFeed::new()),
        );
        let response = metrics(State(state)).await.into_response();
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(
            String::from_utf8_lossy(&body).contains("# TYPE podgate_tenant_buffer_bytes gauge\n")
        );
    }
}
