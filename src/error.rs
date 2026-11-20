//! The one error type the admin API and the proxy answer with. Renders as `{"error": "..."}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use thiserror::Error;

use crate::conflict::Conflict;
use crate::route::RouteError;
use crate::table::{ApplyError, CompileError};
use crate::wasm::Rejection;

/// Errors answered to clients. Rendered as `{"error": "<message>"}` with the matching status.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AppError {
    /// The request is malformed: `400 Bad Request`.
    #[error("{0}")]
    BadRequest(Box<str>),
    /// A TLS request names a host other than its SNI: `421 Misdirected Request`.
    #[error("misdirected request")]
    Misdirected,
    /// No such route or resource: `404 Not Found`.
    #[error("not found")]
    NotFound,
    /// The request contradicts the current state: `409 Conflict`.
    #[error("{0}")]
    Conflict(Box<str>),
    /// A snapshot the compiler refused: `422`, with objects under `conflicts`, each with a `code`.
    #[error("snapshot rejected")]
    SnapshotRejected(Vec<Value>),
    /// Nothing can serve the request now: `503 Service Unavailable`.
    #[error("{0}")]
    Unavailable(Box<str>),
    /// The tenant is at its in-flight limit: `503`, and the client should retry in a second.
    #[error("tenant is over its in-flight limit")]
    Overloaded,
    /// A sleeping app did not wake within its `wake_timeout_secs`: `503`, retry in a few seconds.
    #[error("app did not wake in time")]
    WakeTimeout,
    /// No WASM filter worker freed up in time: `503`, retry in a second. The pool is shared by
    /// every tenant, so this says the proxy is busy.
    #[error("wasm filter pool is busy")]
    FilterBusy,
    /// The tenant's buffer budget cannot take a filter's memory: `503`, retry in a second.
    #[error("wasm filter memory is over the tenant's budget")]
    FilterOverBudget,
    /// Anything unexpected: `500`. The cause is logged, never sent to the client.
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    /// The HTTP status this error answers with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Misdirected => StatusCode::MISDIRECTED_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::SnapshotRejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable(_)
            | Self::Overloaded
            | Self::WakeTimeout
            | Self::FilterBusy
            | Self::FilterOverBudget => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Seconds for the `retry-after` header, when the client should retry later.
    #[must_use]
    pub fn retry_after_secs(&self) -> Option<u32> {
        match self {
            Self::Overloaded | Self::FilterBusy | Self::FilterOverBudget => Some(1),
            Self::WakeTimeout => Some(5),
            _ => None,
        }
    }

    /// Whether this answer says the tenant, an app or the proxy is out of capacity (busy or
    /// cold), not that the deploy is broken. Auto-revert does not count such answers.
    /// [`Self::FilterBusy`] is one: the filter pool is shared by every tenant. A filter that
    /// does not fit its own tenant's budget ([`Self::FilterOverBudget`]) is not: the deploy
    /// raised the filter's memory above what the tenant can pay.
    #[must_use]
    pub fn is_capacity_refusal(&self) -> bool {
        matches!(
            self,
            Self::Overloaded | Self::WakeTimeout | Self::FilterBusy
        )
    }

    /// The JSON body: `{"error": "<message>"}`, plus `conflicts` for a rejected snapshot.
    #[must_use]
    pub fn body(&self) -> Value {
        match self {
            Self::SnapshotRejected(conflicts) => {
                json!({ "error": self.to_string(), "conflicts": conflicts })
            }
            _ => json!({ "error": self.to_string() }),
        }
    }
}

impl From<ApplyError> for AppError {
    fn from(err: ApplyError) -> Self {
        match err {
            ApplyError::Stale { .. } => Self::Conflict(err.to_string().into()),
            ApplyError::Compile(err) => Self::SnapshotRejected(rejection(&err)),
        }
    }
}

/// The `conflicts` list for a refused snapshot: the typed conflicts as objects, any other
/// compile error as `{"code": ..., "message": ...}`.
fn rejection(err: &CompileError) -> Vec<Value> {
    let other = |code: &str| vec![json!({ "code": code, "message": err.to_string() })];
    match err {
        CompileError::Conflicts(conflicts) => conflicts.iter().map(Conflict::to_json).collect(),
        CompileError::InvalidHost { .. } => other("invalid_host"),
        CompileError::UnknownTenant { .. } => other("unknown_tenant"),
        CompileError::Certificate(_) => other("invalid_certificate"),
        CompileError::SkewSecretTooShort => other("invalid_skew_secret"),
        CompileError::Wasm(rejections) => rejections.iter().map(Rejection::to_json).collect(),
    }
}

impl From<RouteError> for AppError {
    fn from(err: RouteError) -> Self {
        match err {
            RouteError::UnknownHost => Self::NotFound,
            RouteError::NoUpstream => Self::Unavailable(err.to_string().into()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let Self::Internal(cause) = &self {
            tracing::error!(error = ?cause, "internal error");
        }
        let retry_after = self.retry_after_secs();
        let mut response = (self.status(), Json(self.body())).into_response();
        if let Some(secs) = retry_after {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, secs.into());
        }
        response
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn renders_status_and_error_body() {
        let err = AppError::NotFound;
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(err.body(), json!({"error": "not found"}));
    }

    #[test]
    fn overloaded_is_503_with_retry_after() {
        let err = AppError::Overloaded;
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.retry_after_secs(), Some(1));
        assert_eq!(AppError::NotFound.retry_after_secs(), None);
    }

    #[test]
    fn internal_errors_hide_the_cause() {
        let err = AppError::from(anyhow::anyhow!("secret detail"));
        assert_eq!(err.body(), json!({"error": "internal error"}));
    }

    #[test]
    fn rejected_snapshot_lists_conflicts() {
        let err =
            AppError::SnapshotRejected(vec![json!({"code": "host_conflict", "host": "a.test"})]);
        assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            err.body(),
            json!({"error": "snapshot rejected", "conflicts": [{"code": "host_conflict", "host": "a.test"}]})
        );
    }
}
