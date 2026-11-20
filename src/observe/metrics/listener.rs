//! The `METRICS_ADDR` listener: `GET /metrics` over TCP, and nothing else.

use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::net::TcpListener;
use tower_http::timeout::TimeoutLayer;

use super::{CONTENT_TYPE as TEXT_FORMAT, render};
use crate::budget::Budgets;
use crate::error::AppError;
use crate::fairq::Backends;
use crate::observe::access_log::AccessLog;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::table::TableHandle;

/// Binds the metrics address. Unlike the admin socket this is a TCP port other hosts can reach,
/// so it is the operator's to place: `METRICS_ADDR` is never read from a snapshot.
///
/// # Errors
///
/// Fails when the address cannot be bound.
pub fn bind(addr: SocketAddr) -> io::Result<StdTcpListener> {
    let listener = StdTcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// What the endpoint reads: the same handles the admin API's `GET /metrics` reads.
#[derive(Debug)]
struct Sources {
    table: TableHandle,
    budgets: Budgets,
    backends: Backends,
    upstream_policy: UpstreamPolicy,
    access_log: AccessLog,
}

/// Serves `GET /metrics` on a bound TCP listener. Run it as a Pingora background service.
///
/// Read-only by construction: the only route is `GET /metrics` (and `HEAD`); every other path is
/// `404` and every other method `405`. It has no access to the admin API or to the snapshot.
#[derive(Debug)]
pub struct MetricsService {
    listener: StdTcpListener,
    sources: Arc<Sources>,
    timeout: Duration,
}

impl MetricsService {
    /// Serves the metrics of `table`, `budgets`, `backends`, `upstream_policy` and `access_log` on `listener`,
    /// ending a request that runs longer than `timeout` with `408`.
    #[must_use]
    pub fn new(
        listener: StdTcpListener,
        table: TableHandle,
        budgets: Budgets,
        backends: Backends,
        upstream_policy: UpstreamPolicy,
        access_log: AccessLog,
        timeout: Duration,
    ) -> Self {
        Self {
            listener,
            sources: Arc::new(Sources {
                table,
                budgets,
                backends,
                upstream_policy,
                access_log,
            }),
            timeout,
        }
    }

    fn router(&self) -> Router {
        Router::new()
            .route("/metrics", get(scrape))
            .fallback(|| async { AppError::NotFound })
            .with_state(Arc::clone(&self.sources))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                self.timeout,
            ))
    }
}

async fn scrape(State(sources): State<Arc<Sources>>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, TEXT_FORMAT)],
        render(
            &sources.table,
            &sources.budgets,
            &sources.backends,
            &sources.upstream_policy,
            &sources.access_log,
        ),
    )
}

#[async_trait]
impl BackgroundService for MetricsService {
    async fn start(&self, _shutdown: ShutdownWatch) {
        let listener = match self.listener.try_clone().and_then(TcpListener::from_std) {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(%err, "cannot serve the metrics listener");
                return;
            }
        };
        if let Ok(addr) = listener.local_addr() {
            tracing::info!(%addr, "metrics listener ready");
        }
        // Like the admin API it serves until the process exits: a scrape is short and read-only.
        if let Err(err) = axum::serve(listener, self.router()).await {
            tracing::error!(%err, "metrics listener stopped");
        }
    }
}
