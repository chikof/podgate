//! The one error type the admin API and the proxy answer with. Renders as `{"error": "..."}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use thiserror::Error;

use crate::route::RouteError;
use crate::table::ApplyError;

/// Errors answered to clients. Rendered as `{"error": "<message>"}` with the matching status.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AppError {
    /// The request is malformed: `400 Bad Request`.
    #[error("{0}")]
    BadRequest(Box<str>),
    /// No such route or resource: `404 Not Found`.
    #[error("not found")]
    NotFound,
    /// The request contradicts the current state: `409 Conflict`.
    #[error("{0}")]
    Conflict(Box<str>),
    /// A snapshot the compiler refused: `422`, with the reasons under `conflicts`.
    #[error("snapshot rejected")]
    SnapshotRejected(Vec<String>),
    /// Nothing can serve the request now: `503 Service Unavailable`.
    #[error("{0}")]
    Unavailable(Box<str>),
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
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::SnapshotRejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
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
            ApplyError::Compile(err) => Self::SnapshotRejected(vec![err.to_string()]),
        }
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
        (self.status(), Json(self.body())).into_response()
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
    fn internal_errors_hide_the_cause() {
        let err = AppError::from(anyhow::anyhow!("secret detail"));
        assert_eq!(err.body(), json!({"error": "internal error"}));
    }

    #[test]
    fn rejected_snapshot_lists_conflicts() {
        let err = AppError::SnapshotRejected(vec!["host a.test twice".into()]);
        assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            err.body(),
            json!({"error": "snapshot rejected", "conflicts": ["host a.test twice"]})
        );
    }
}
