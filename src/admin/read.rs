//! The read socket: a second unix socket that serves one read route of the admin API and nothing
//! else, so a reader of it can see the fleet's counts and cannot change or probe the daemon.
//!
//! # Adding a route
//!
//! Add one `.merge(<module>::routes())` line to [`router`]. The handlers are the admin API's own.

use std::os::unix::net::UnixListener as StdUnixListener;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::{Query, Request};
use axum::http::Method;
use axum::middleware::{Next, from_fn};
use axum::response::Response;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use serde::Deserialize;
use tokio::net::UnixListener;

use super::{AppState, layered, not_found, overview};
use crate::error::AppError;

#[derive(Debug, Deserialize)]
struct SectionOnly {
    section: Option<String>,
}

/// Lets a `GET` of the overview through only when its `section` is exactly `summary`. Other
/// methods pass to the handler for its `405`.
async fn summary_only(request: Request, next: Next) -> Result<Response, AppError> {
    if request.method() == Method::GET {
        let asked = Query::<SectionOnly>::try_from_uri(request.uri())
            .ok()
            .and_then(|Query(params)| params.section);
        if asked.as_deref() != Some("summary") {
            return Err(AppError::BadRequest(
                "this socket serves section=summary only".into(),
            ));
        }
    }
    Ok(next.run(request).await)
}

/// Builds the read router: `GET /v1/overview?section=summary`; anything else is a JSON 404, a
/// non-`GET` method on the route is `405`, and the admin layers apply.
pub(super) fn router(state: AppState, timeout: Duration) -> Router {
    let router = Router::new()
        .merge(overview::routes().route_layer(from_fn(summary_only)))
        .fallback(not_found)
        .with_state(state);
    layered(router, timeout)
}

/// Serves [`router`] on a bound unix socket. Run it as a Pingora background service.
///
/// It does not touch readiness: `/readyz` is the admin socket's.
#[derive(Debug)]
pub struct ReadService {
    listener: StdUnixListener,
    state: AppState,
    timeout: Duration,
}

impl ReadService {
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
impl BackgroundService for ReadService {
    async fn start(&self, _shutdown: ShutdownWatch) {
        let listener = match self.listener.try_clone().and_then(UnixListener::from_std) {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(%err, "cannot serve the admin read socket");
                return;
            }
        };
        tracing::info!("admin read socket ready");
        if let Err(err) = axum::serve(listener, router(self.state.clone(), self.timeout)).await {
            tracing::error!(%err, "admin read socket stopped");
        }
    }
}
