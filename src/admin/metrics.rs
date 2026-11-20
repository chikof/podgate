//! `GET /metrics`: Prometheus text exposition, rendered by [`crate::observe::metrics::render`].

use axum::Router;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;

use super::AppState;
use crate::observe::metrics::{self, CONTENT_TYPE as TEXT_FORMAT};

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/metrics", get(scrape))
}

/// Every series podgate has: the per-tenant and per-backend ones and the per entry point,
/// router and service ones. The `METRICS_ADDR` listener serves the same text.
async fn scrape(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, TEXT_FORMAT)],
        metrics::render(
            state.table(),
            state.budgets(),
            state.backends(),
            state.upstream_policy(),
            state.access_log(),
            state.tracer(),
        ),
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
        let response = scrape(State(state)).await.into_response();
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("# TYPE podgate_tenant_buffer_bytes gauge\n"));
        assert!(body.contains("# TYPE podgate_entry_point_requests_total counter\n"));
    }
}
