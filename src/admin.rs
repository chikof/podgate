//! The admin API: an axum router served on a unix socket as a Pingora background service.
//!
//! # Adding an endpoint
//!
//! Each feature owns a module under `src/admin/` with a `fn routes() -> Router<AppState>` and
//! adds one `.merge(<module>::routes())` line to [`router`]. Handlers return
//! `Result<_, AppError>` so every error is `{"error": "..."}`.

mod events;
mod explain;
mod health;
mod metrics;
mod snapshot;

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::http::{Request, StatusCode};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::net::UnixListener;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::budget::Budgets;
use crate::error::AppError;
use crate::events::EventFeed;
use crate::inflight::Inflight;
use crate::table::TableHandle;

/// Shared handler state. Cheap to clone.
#[derive(Clone, Debug)]
pub struct AppState {
    ready: Arc<AtomicBool>,
    table: TableHandle,
    events: EventFeed,
    inflight: Inflight,
    budgets: Budgets,
}

impl AppState {
    /// Creates a state that is not ready yet; [`AdminService`] flips it once serving.
    #[must_use]
    pub fn new(table: TableHandle, events: EventFeed, inflight: Inflight) -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            table,
            events,
            inflight,
            budgets: Budgets::new(),
        }
    }

    /// Sets what `GET /readyz` reports.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    /// Whether `GET /readyz` reports ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// The routing table the admin API reads and replaces.
    #[must_use]
    pub fn table(&self) -> &TableHandle {
        &self.table
    }

    /// The event feed `GET /v1/events` serves.
    #[must_use]
    pub fn events(&self) -> &EventFeed {
        &self.events
    }

    /// The in-flight counters, synced after every snapshot apply.
    #[must_use]
    pub fn inflight(&self) -> &Inflight {
        &self.inflight
    }

    /// Reports `budgets`, the registry the proxy charges, on `GET /metrics`.
    #[must_use]
    pub fn with_budgets(mut self, budgets: Budgets) -> Self {
        self.budgets = budgets;
        self
    }

    /// The per-tenant budget registry `GET /metrics` reports.
    #[must_use]
    pub fn budgets(&self) -> &Budgets {
        &self.budgets
    }
}

async fn not_found() -> AppError {
    AppError::NotFound
}

/// Builds the router with all routes and middleware.
///
/// Routes: `GET /healthz`, `GET /readyz`, `GET /metrics`, `PUT /v1/snapshot`, `GET /v1/events`,
/// `GET /v1/explain`; anything else is a JSON 404.
///
/// Middleware, outermost first:
///
/// 1. Request id: reuses an incoming `x-request-id` or sets a UUID.
/// 2. Trace: one span per request carrying method, path and request id.
/// 3. Request id is copied to the response `x-request-id` header.
/// 4. Timeout: a request still running after `timeout` ends with `408 Request Timeout`
///    and an empty body. 408 is used for every timeout, so clients can tell it from the 503
///    readiness answer.
pub fn router(state: AppState, timeout: Duration) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(metrics::routes())
        .merge(snapshot::routes())
        .merge(events::routes())
        .merge(explain::routes())
        .layer(events::poll_cap(timeout))
        .fallback(not_found)
        .with_state(state)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                let request_id = request
                    .headers()
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();
                tracing::info_span!(
                    "request",
                    method = %request.method(),
                    path = %request.uri().path(),
                    request_id,
                )
            }),
        )
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

/// Binds the admin socket at `path` with mode `0600`, replacing a stale socket file.
///
/// The socket is created under a temporary name, restricted, then renamed into place, so it is
/// never reachable with looser permissions.
///
/// # Errors
///
/// Fails when the directory cannot be created or the socket cannot be bound or moved.
pub fn bind(path: &Path) -> io::Result<StdUnixListener> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut staging = path.as_os_str().to_owned();
    staging.push(format!(".{}.tmp", std::process::id()));
    let staging = Path::new(&staging);
    // A leftover from a crashed run with the same pid; absent is the normal case.
    match std::fs::remove_file(staging) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }
    let listener = StdUnixListener::bind(staging)?;
    std::fs::set_permissions(staging, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    std::fs::rename(staging, path)?;
    Ok(listener)
}

/// Serves the admin API on a bound unix socket. Run it as a Pingora background service.
///
/// On shutdown it keeps serving but reports `503` on `/readyz`, so probes see the drain.
#[derive(Debug)]
pub struct AdminService {
    listener: StdUnixListener,
    state: AppState,
    timeout: Duration,
}

impl AdminService {
    /// Serves `state` on `listener`, ending requests after `timeout`.
    #[must_use]
    pub fn new(listener: StdUnixListener, state: AppState, timeout: Duration) -> Self {
        Self {
            listener,
            state,
            timeout,
        }
    }
}

#[async_trait]
impl BackgroundService for AdminService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let listener = match self.listener.try_clone().and_then(UnixListener::from_std) {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(%err, "cannot serve the admin socket");
                return;
            }
        };
        let state = self.state.clone();
        tokio::spawn(async move {
            // A closed channel also means the server is stopping, so the result is not needed.
            drop(shutdown.changed().await);
            state.set_ready(false);
            tracing::info!("shutdown requested, draining");
        });
        self.state.set_ready(true);
        tracing::info!("admin API ready");
        if let Err(err) = axum::serve(listener, router(self.state.clone(), self.timeout)).await {
            tracing::error!(%err, "admin API stopped");
        }
    }
}
