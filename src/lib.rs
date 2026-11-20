//! `podgate`: memory-safe reverse proxy for our PaaS. Today this is the service scaffold the proxy grows from; the target is in `docs/architecture.md`.
//!
//! `main.rs` stays thin; everything testable lives here:
//!
//! - [`Config`]: settings read from environment variables.
//! - [`router`]: the HTTP routes plus middleware, usable in-process (see `tests/http.rs`).
//! - [`serve`] / [`serve_on`]: bind, serve and drain on shutdown.
//! - [`AppError`]: the one error type handlers return; renders as `{"error": "..."}`.

use std::future::Future;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

/// Longest name accepted by `GET /v1/greet/{name}`.
const MAX_NAME_LEN: usize = 64;

/// How log lines are rendered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable multi-line output for local development.
    #[default]
    Pretty,
    /// One JSON object per line for log collectors.
    Json,
}
// 1: two dataless variants fit in one byte; the 254 unused values are a niche.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<LogFormat>() == 1);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Option<LogFormat>>() == std::mem::size_of::<LogFormat>());

/// A bad environment variable. The message names the variable.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid {var}: {reason}")]
pub struct ConfigError {
    /// Name of the offending environment variable.
    pub var: &'static str,
    /// What is wrong with its value.
    pub reason: Box<str>,
}
// 32: &'static str (16) + Box<str> (16); the reason is immutable once built, so no capacity word.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<ConfigError>() == 32);
#[cfg(target_pointer_width = "64")]
const _: () =
    assert!(std::mem::size_of::<Option<ConfigError>>() == std::mem::size_of::<ConfigError>());

/// Service settings, read once at startup.
///
/// | Variable | Default | Meaning |
/// |---|---|---|
/// | `BIND_ADDR` | `127.0.0.1:8080` | Socket address to listen on. |
/// | `REQUEST_TIMEOUT_SECS` | `30` | Per-request limit, 1..=3600. |
/// | `LOG_FORMAT` | `pretty` | `pretty` or `json`. |
/// | `RUST_LOG` | `info` | Log filter (`tracing` env-filter syntax). |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Address to listen on.
    pub bind_addr: SocketAddr,
    /// Requests running longer than this many seconds get `408 Request Timeout`.
    pub request_timeout_secs: NonZeroU16,
    /// Log rendering.
    pub log_format: LogFormat,
}
// 36: SocketAddr (32, align 4; its V4/V6 tag is a niche) + NonZeroU16 (2) + LogFormat (1) + 1 padding.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Config>() == 36);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Option<Config>>() == std::mem::size_of::<Config>());

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            request_timeout_secs: NonZeroU16::new(30).expect("30 is not zero"),
            log_format: LogFormat::Pretty,
        }
    }
}

impl Config {
    /// The per-request limit as a [`Duration`].
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(NonZeroU64::from(self.request_timeout_secs).get())
    }

    /// Reads the settings from the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the first variable that is set but invalid.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Reads the settings through `lookup`; unset variables return `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the first variable that is set but invalid.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        if let Some(raw) = lookup("BIND_ADDR") {
            config.bind_addr = raw.trim().parse().map_err(|err| ConfigError {
                var: "BIND_ADDR",
                reason: format!("{raw:?} is not a socket address like 0.0.0.0:8080 ({err})").into(),
            })?;
        }
        if let Some(raw) = lookup("REQUEST_TIMEOUT_SECS") {
            let secs: NonZeroU16 = raw.trim().parse().map_err(|err| ConfigError {
                var: "REQUEST_TIMEOUT_SECS",
                reason: format!("{raw:?} is not a whole number of seconds in 1..=3600 ({err})")
                    .into(),
            })?;
            if secs.get() > 3600 {
                return Err(ConfigError {
                    var: "REQUEST_TIMEOUT_SECS",
                    reason: format!("{secs} is outside 1..=3600").into(),
                });
            }
            config.request_timeout_secs = secs;
        }
        if let Some(raw) = lookup("LOG_FORMAT") {
            config.log_format = match raw.trim().to_ascii_lowercase().as_str() {
                "pretty" => LogFormat::Pretty,
                "json" => LogFormat::Json,
                _ => {
                    return Err(ConfigError {
                        var: "LOG_FORMAT",
                        reason: format!("{raw:?} is not `pretty` or `json`").into(),
                    });
                }
            };
        }
        Ok(config)
    }
}

/// Errors handlers can return. Rendered as `{"error": "<message>"}`.
#[derive(Debug, Error)]
pub enum AppError {
    /// The request is malformed: `400 Bad Request`.
    #[error("{0}")]
    BadRequest(Box<str>),
    /// No such route or resource: `404 Not Found`.
    #[error("not found")]
    NotFound,
    /// Anything unexpected: `500`. The cause is logged, never sent to the client.
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}
// 24: tag word + the largest payload, Box<str> (16); two variants carry data, so the pointer niche cannot encode the tag.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<AppError>() == 24);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Option<AppError>>() == std::mem::size_of::<AppError>());

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Internal(cause) => {
                tracing::error!(error = ?cause, "internal error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

/// Shared handler state. Cheap to clone.
#[derive(Clone, Debug, Default)]
pub struct AppState {
    ready: Arc<AtomicBool>,
}
// 8: one Arc pointer; the null pointer is a niche.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<AppState>() == 8);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Option<AppState>>() == std::mem::size_of::<AppState>());

impl AppState {
    /// Creates a state that is not ready yet; [`serve_on`] flips it once listening.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
}

/// Body of `GET /v1/greet/{name}`.
#[derive(Debug, Serialize)]
struct Greeting {
    message: Box<str>,
}
// 16: a Box<str> (pointer + length), no capacity word; the null pointer is a niche.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Greeting>() == 16);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Option<Greeting>>() == std::mem::size_of::<Greeting>());

/// Liveness: the process is up and the event loop answers. Never checks dependencies.
async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Readiness: `200` while the service accepts traffic, `503` before startup and while draining.
async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    if state.is_ready() {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready" })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "not ready" })),
        )
    }
}

/// Example route: replace with your own.
async fn greet(Path(name): Path<String>) -> Result<Json<Greeting>, AppError> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(AppError::BadRequest(
            format!("name must be 1..={MAX_NAME_LEN} bytes").into(),
        ));
    }
    Ok(Json(Greeting {
        message: format!("Hello, {name}!").into(),
    }))
}

async fn not_found() -> AppError {
    AppError::NotFound
}

/// Builds the router with all routes and middleware.
///
/// Routes: `GET /healthz`, `GET /readyz`, `GET /v1/greet/{name}`; anything else is a JSON 404.
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
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/greet/{name}", get(greet))
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

/// Binds `config.bind_addr` and serves until `shutdown` completes.
///
/// # Errors
///
/// Fails when the address cannot be bound or the server stops with an I/O error.
pub async fn serve(
    config: &Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("cannot bind {}", config.bind_addr))?;
    serve_on(listener, config, shutdown).await
}

/// Serves on an already bound `listener` until `shutdown` completes.
///
/// Shutdown order: `shutdown` fires, `/readyz` turns 503, the listener stops accepting,
/// in-flight requests finish (bounded by the request timeout), then this returns.
///
/// # Errors
///
/// Fails when the listener is broken or the server stops with an I/O error.
pub async fn serve_on(
    listener: TcpListener,
    config: &Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let state = AppState::new();
    let app = router(state.clone(), config.request_timeout());
    let local_addr = listener
        .local_addr()
        .context("listener has no local address")?;
    state.set_ready(true);
    tracing::info!(%local_addr, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.await;
            state.set_ready(false);
            tracing::info!("shutdown requested, draining");
        })
        .await
        .context("server error")?;
    tracing::info!("stopped");
    Ok(())
}

/// Completes on SIGINT (Ctrl-C) or, on Unix, SIGTERM (what containers and systemd send).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = signal::ctrl_c().await {
            tracing::error!(%err, "cannot listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

/// Installs the global `tracing` subscriber. Filter comes from `RUST_LOG`, default `info`.
///
/// Call once, early in `main`. A second call is ignored.
pub fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    // `try_init` fails only when a subscriber is already set; keep the first one.
    let _ = match format {
        LogFormat::Pretty => builder.pretty().try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
}

#[cfg(test)]
mod test {
    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_lookup(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn defaults_when_nothing_set() {
        assert_eq!(config(&[]), Ok(Config::default()));
    }

    #[test]
    fn reads_every_variable() {
        let parsed = config(&[
            ("BIND_ADDR", "0.0.0.0:9000"),
            ("REQUEST_TIMEOUT_SECS", "5"),
            ("LOG_FORMAT", "JSON"),
        ]);
        assert_eq!(
            parsed,
            Ok(Config {
                bind_addr: SocketAddr::from(([0, 0, 0, 0], 9000)),
                request_timeout_secs: NonZeroU16::new(5).expect("5 is not zero"),
                log_format: LogFormat::Json,
            })
        );
    }

    #[test]
    fn errors_name_the_variable() {
        for (var, value) in [
            ("BIND_ADDR", "nope"),
            ("REQUEST_TIMEOUT_SECS", "0"),
            ("REQUEST_TIMEOUT_SECS", "abc"),
            ("LOG_FORMAT", "xml"),
        ] {
            let err = config(&[(var, value)]).expect_err("value must be rejected");
            assert_eq!(err.var, var);
            assert!(
                err.to_string().starts_with(&format!("invalid {var}:")),
                "{err}"
            );
        }
    }
}
