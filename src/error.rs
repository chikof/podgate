//! The one error type the admin API and the proxy answer with. Renders as `{"error": "..."}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use thiserror::Error;

use crate::canary;
use crate::clientauth;
use crate::compile::Rejected;
use crate::conflict::Conflict;
use crate::route::RouteError;
use crate::table::{ApplyError, CompileError};

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
    /// The connection negotiated a TLS version, cipher suite or protocol the app's TLS options
    /// do not allow: `421 Misdirected Request`.
    #[error("tls policy")]
    TlsPolicy,
    /// The app requires a client certificate and the connection presented none that its CA
    /// accepts: `403 Forbidden`.
    #[error("client certificate required")]
    ClientCertRequired,
    /// No such route or resource: `404 Not Found`.
    #[error("not found")]
    NotFound,
    /// The request contradicts the current state: `409 Conflict`.
    #[error("{0}")]
    Conflict(Box<str>),
    /// A push came from a writer other than the one that owns the live snapshot:
    /// `409 Conflict`, with the owner under `writer` (`null` when the owner sent no name).
    #[error("snapshot is owned by {}", owner(.writer.as_deref()))]
    WriterOwned {
        /// The owning writer's name.
        writer: Option<Box<str>>,
    },
    /// A snapshot the compiler refused: `422`, with objects under `conflicts`, each with a `code`.
    #[error("snapshot rejected")]
    SnapshotRejected(Vec<Value>),
    /// Nothing can serve the request now: `503 Service Unavailable`.
    #[error("{0}")]
    Unavailable(Box<str>),
    /// A revision takes requests but every server of the service is unhealthy or ejected:
    /// `503 Service Unavailable`. The app is not asleep, so nothing wakes it.
    #[error("no healthy upstream available")]
    NoHealthyUpstream,
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
    /// The request body is over a `buffering` middleware's `max_request_body_bytes`: `413`.
    #[error("request body too large")]
    PayloadTooLarge,
    /// An `Expect: 100-continue` request declares a body over `max_request_body_bytes`: `417`,
    /// before the client sends it.
    #[error("request body too large")]
    ExpectationFailed,
    /// The client did not send the whole body a `buffering` middleware holds in time: `408`.
    #[error("request body timed out")]
    RequestTimeout,
    /// The request head (request line and headers) is over the entry point's `max_header_bytes`:
    /// `431`.
    #[error("request header fields too large")]
    HeadersTooLarge,
    /// The upstream response is over a `buffering` middleware's `max_response_body_bytes`: `502`.
    #[error("upstream response too large")]
    UpstreamResponseTooLarge,
    /// The tenant's buffer budget cannot take the body a `buffering` middleware holds: `503`,
    /// retry in a second.
    #[error("buffering is over the tenant's budget")]
    BufferingOverBudget,
    /// A `basic_auth` verification found no worker within the wait, or its tenant already holds
    /// its share of them: `503`, retry in a second. A flood of bad passwords causes it, not a
    /// broken deploy.
    #[error("password verification is busy")]
    AuthBusy,
    /// The memory a `basic_auth` verification needs (an argon2 hash's `m`) does not fit the
    /// tenant's buffer budget: `503`, retry in a second. Not a capacity refusal: the deploy
    /// declared a hash the tenant cannot pay for.
    #[error("password verification memory is over the tenant's budget")]
    AuthOverBudget,
    /// A `forward_auth` call failed (no connection, refused by the upstream address policy, timed
    /// out, or an answer over its cap or not valid HTTP/1.1): `503`. The request is never passed
    /// on.
    #[error("auth service unavailable")]
    AuthUnavailable,
    /// A `forward_auth` call found no room (the stage is at `max_concurrent`, or the tenant's
    /// buffer budget is full right now): `503`, retry in a second. The request is never passed
    /// on.
    #[error("auth service unavailable")]
    AuthSaturated,
    /// A `plugin` call failed (the plugin is down, too slow, answered something unusable, or
    /// its circuit is open) under `on_plugin_error: "fail_closed"`: `503`. The request is never
    /// passed on.
    #[error("plugin unavailable")]
    PluginUnavailable,
    /// A `plugin` call found no room (the plugin or the tenant is at its calls in flight, or
    /// the tenant's buffer budget is full right now): `503`, retry in a second. The request is
    /// never passed on.
    #[error("plugin unavailable")]
    PluginSaturated,
    /// A `jwt_auth` stage found no valid token: `401` with a `WWW-Authenticate` challenge. The body
    /// never says which check failed; `reason` is for the access log.
    #[error("unauthorized")]
    JwtUnauthorized {
        /// The check that failed, as `Failure::code` of `jwt_auth` names it.
        reason: &'static str,
    },
    /// A `jwt_auth` stage verified the token and its `required_claims` do not match: `403`.
    #[error("forbidden")]
    JwtForbidden {
        /// The reason for the access log.
        reason: &'static str,
    },
    /// A `jwt_auth` stage has no keys (its JWKS cannot be fetched and nothing is cached): `503`.
    #[error("authentication unavailable")]
    JwtUnavailable,
    /// An `oidc` callback that is not the answer to a login this middleware started: no flow
    /// cookie, a `state` that is not the cookie's, no code: `400`.
    #[error("bad request")]
    OidcBadCallback {
        /// The reason for the access log.
        reason: &'static str,
    },
    /// An `oidc` login that failed: the provider refused the code, or its ID token is not valid:
    /// `401`. The body never says which check failed; `reason` is for the access log.
    #[error("unauthorized")]
    OidcRejected {
        /// The reason for the access log.
        reason: &'static str,
    },
    /// An `oidc` login of a person the middleware does not admit (a `required_claims` or an
    /// `allow_subjects` that does not match), or one the provider declined: `403`.
    #[error("forbidden")]
    OidcForbidden {
        /// The reason for the access log.
        reason: &'static str,
    },
    /// An `oidc` login cannot go on because the identity provider, its discovery document or its
    /// keys cannot be had: `503`. Existing sessions are not affected.
    #[error("authentication unavailable")]
    OidcUnavailable {
        /// The reason for the access log.
        reason: &'static str,
    },
    /// An `oidc` login found no room for its call to the token endpoint (the node's permits, or
    /// the tenant's buffer budget): `503`, retry in a second.
    #[error("authentication busy")]
    OidcBusy,
    /// The backend has no slot for the request (its queue is full or the wait ran out): `503`,
    /// and the client should retry in a second. Another tenant on a shared backend can cause it.
    #[error("backend is saturated")]
    Saturated,
    /// No read slot for a static file came free in time, or the process is out of file
    /// descriptors: `503`, and the client should retry in a second. The pool is shared by every
    /// tenant, so this says the proxy is busy.
    #[error("static file reads are busy")]
    StaticBusy,
    /// The tenant's buffer budget cannot take the read buffers of a static file response: `503`,
    /// and the client should retry in a second.
    #[error("static file buffers are over the tenant's budget")]
    StaticOverBudget,
    /// A `fastcgi` service could not run the request: the application is busy, unreachable, slow
    /// or answered nonsense. The status depends on the failure.
    #[error("{0}")]
    Fastcgi(crate::service::FastcgiFailure),
    /// A `rate_limit` bucket is empty: `429`, with `retry-after` the whole seconds until it holds
    /// a token (at least 1).
    #[error("rate limit exceeded")]
    RateLimited {
        /// Seconds until the source may try again.
        retry_after_secs: u32,
    },
    /// An `in_flight_req` source is at its `amount`: `429`, retry in a second.
    #[error("too many requests in flight")]
    TooManyInFlight,
    /// The tenant's buffer budget cannot take a limiter's table of sources right now: `503`,
    /// retry in a second. Declarations that can never fit are refused when the snapshot applies.
    #[error("rate limiter memory is over the tenant's budget")]
    LimiterBusy,
    /// A cluster-scope `rate_limit` with `on_store_error: "deny"` cannot reach its store: `503`,
    /// retry in a second.
    #[error("rate limiter unavailable")]
    RateLimiterUnavailable,
    /// A cluster-scope `in_flight_req` with `on_store_error: "deny"` cannot reach its store:
    /// `503`, retry in a second.
    #[error("in-flight limiter unavailable")]
    InflightStoreUnavailable,
    /// Anything unexpected: `500`. The cause is logged, never sent to the client.
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    /// The HTTP status this error answers with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) | Self::OidcBadCallback { .. } => StatusCode::BAD_REQUEST,
            Self::Misdirected | Self::TlsPolicy => StatusCode::MISDIRECTED_REQUEST,
            Self::ClientCertRequired | Self::JwtForbidden { .. } | Self::OidcForbidden { .. } => {
                StatusCode::FORBIDDEN
            }
            Self::JwtUnauthorized { .. } | Self::OidcRejected { .. } => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::WriterOwned { .. } => StatusCode::CONFLICT,
            Self::SnapshotRejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable(_)
            | Self::NoHealthyUpstream
            | Self::Overloaded
            | Self::Saturated
            | Self::StaticBusy
            | Self::StaticOverBudget
            | Self::WakeTimeout
            | Self::FilterBusy
            | Self::FilterOverBudget
            | Self::BufferingOverBudget
            | Self::AuthBusy
            | Self::AuthUnavailable
            | Self::AuthSaturated
            | Self::PluginUnavailable
            | Self::PluginSaturated
            | Self::JwtUnavailable
            | Self::OidcUnavailable { .. }
            | Self::OidcBusy
            | Self::LimiterBusy
            | Self::RateLimiterUnavailable
            | Self::InflightStoreUnavailable
            | Self::AuthOverBudget => StatusCode::SERVICE_UNAVAILABLE,
            Self::RateLimited { .. } | Self::TooManyInFlight => StatusCode::TOO_MANY_REQUESTS,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ExpectationFailed => StatusCode::EXPECTATION_FAILED,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::HeadersTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Self::UpstreamResponseTooLarge => StatusCode::BAD_GATEWAY,
            Self::Fastcgi(failure) => failure.status(),
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Seconds for the `retry-after` header, when the client should retry later.
    #[must_use]
    pub fn retry_after_secs(&self) -> Option<u32> {
        match self {
            Self::Overloaded
            | Self::TooManyInFlight
            | Self::LimiterBusy
            | Self::RateLimiterUnavailable
            | Self::InflightStoreUnavailable
            | Self::Saturated
            | Self::StaticBusy
            | Self::StaticOverBudget
            | Self::FilterBusy
            | Self::FilterOverBudget
            | Self::BufferingOverBudget
            | Self::AuthBusy
            | Self::AuthSaturated
            | Self::PluginSaturated
            | Self::AuthOverBudget
            | Self::OidcBusy => Some(1),
            Self::RateLimited { retry_after_secs } => Some(*retry_after_secs),
            Self::WakeTimeout => Some(5),
            Self::Fastcgi(failure) => failure.retry_after_secs(),
            _ => None,
        }
    }

    /// Whether this answer says the tenant, an app or the proxy is out of capacity (busy or
    /// cold), not that the deploy is broken. Auto-revert does not count such answers.
    /// [`Self::FilterBusy`] is one: the filter pool is shared by every tenant. So is
    /// [`Self::Saturated`]: the backend may be shared, and another tenant can fill it. A filter
    /// that does not fit its own tenant's budget ([`Self::FilterOverBudget`]) is not: the deploy
    /// raised the filter's memory above what the tenant can pay; so is [`Self::AuthOverBudget`].
    #[must_use]
    pub fn is_capacity_refusal(&self) -> bool {
        matches!(
            self,
            Self::Overloaded
                | Self::RateLimited { .. }
                | Self::TooManyInFlight
                | Self::LimiterBusy
                | Self::RateLimiterUnavailable
                | Self::InflightStoreUnavailable
                | Self::Saturated
                | Self::StaticBusy
                | Self::StaticOverBudget
                | Self::WakeTimeout
                | Self::FilterBusy
                | Self::BufferingOverBudget
                | Self::AuthBusy
                | Self::AuthSaturated
                | Self::PluginSaturated
                | Self::OidcBusy
        ) || matches!(self, Self::Fastcgi(failure) if failure.is_capacity_refusal())
    }

    /// The `reason` an access log line gives when podgate answers with this error itself. A new
    /// variant names its reason here, next to its status.
    #[must_use]
    pub fn log_reason(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Misdirected => "misdirected",
            Self::TlsPolicy => "tls_policy",
            Self::ClientCertRequired => "client_cert_required",
            Self::NotFound => "no_route",
            Self::Overloaded
            | Self::FilterOverBudget
            | Self::BufferingOverBudget
            | Self::StaticOverBudget => "over_budget",
            Self::Fastcgi(failure) => failure.log_reason(),
            Self::StaticBusy => "static_busy",
            Self::PayloadTooLarge => "payload_too_large",
            Self::ExpectationFailed => "expectation_failed",
            Self::RequestTimeout => "request_timeout",
            Self::HeadersTooLarge => "headers_too_large",
            Self::UpstreamResponseTooLarge => "upstream_response_too_large",
            Self::Saturated => "backend_saturated",
            Self::WakeTimeout => "wake_timeout",
            Self::FilterBusy => "filter_busy",
            Self::AuthBusy => "auth_busy",
            Self::AuthUnavailable => "auth_unavailable",
            Self::AuthSaturated => "auth_saturated",
            Self::PluginUnavailable => "plugin_unavailable",
            Self::PluginSaturated => "plugin_saturated",
            Self::AuthOverBudget => "auth_over_budget",
            Self::JwtUnauthorized { reason } | Self::JwtForbidden { reason } => reason,
            Self::JwtUnavailable => "jwks_unavailable",
            Self::OidcBadCallback { reason }
            | Self::OidcRejected { reason }
            | Self::OidcForbidden { reason }
            | Self::OidcUnavailable { reason } => reason,
            Self::OidcBusy => "oidc_busy",
            Self::RateLimited { .. } => "rate_limited",
            Self::TooManyInFlight => "in_flight_limit",
            Self::LimiterBusy => "limiter_busy",
            Self::RateLimiterUnavailable => "rate_limit_store_unavailable",
            Self::InflightStoreUnavailable => "inflight_store_unavailable",
            Self::Unavailable(_) => "no_upstream",
            Self::NoHealthyUpstream => "no_healthy_upstream",
            Self::WriterOwned { .. } => "writer_owned",
            Self::Conflict(_) | Self::SnapshotRejected(_) | Self::Internal(_) => "internal",
        }
    }

    /// The JSON body: `{"error": "<message>"}`, plus `conflicts` for a rejected snapshot.
    #[must_use]
    pub fn body(&self) -> Value {
        match self {
            Self::SnapshotRejected(conflicts) => {
                json!({ "error": self.to_string(), "conflicts": conflicts })
            }
            Self::WriterOwned { writer } => json!({ "error": self.to_string(), "writer": writer }),
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
        CompileError::UnknownTenant { .. } => other("unknown_tenant"),
        CompileError::Certificate(_) => other("invalid_certificate"),
        CompileError::SkewSecretTooShort => other("invalid_skew_secret"),
        CompileError::Rejected(rejected) => rejected.iter().map(Rejected::to_json).collect(),
        CompileError::Canary(rejections) => {
            rejections.iter().map(canary::Rejection::to_json).collect()
        }

        CompileError::Acme(_) => other("invalid_acme"),
        CompileError::ClientCa(rejections) => rejections
            .iter()
            .map(clientauth::Rejection::to_json)
            .collect(),
    }
}

/// Who owns the snapshot, for the message of [`AppError::WriterOwned`].
fn owner(writer: Option<&str>) -> String {
    writer.map_or_else(
        || "an unnamed writer".to_owned(),
        |name| format!("writer {name}"),
    )
}

impl From<RouteError> for AppError {
    fn from(err: RouteError) -> Self {
        match err {
            RouteError::NoRoute => Self::NotFound,
            RouteError::NoUpstream => Self::Unavailable(err.to_string().into()),
            RouteError::AllUnhealthy => Self::NoHealthyUpstream,
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
        assert_eq!(
            AppError::Saturated.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(AppError::Saturated.retry_after_secs(), Some(1));
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

    #[test]
    fn auth_over_budget_counts_toward_auto_revert_but_busy_does_not() {
        for err in [AppError::AuthBusy, AppError::AuthOverBudget] {
            assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(err.retry_after_secs(), Some(1));
        }
        assert!(AppError::AuthBusy.is_capacity_refusal());
        assert!(!AppError::AuthOverBudget.is_capacity_refusal());
        assert_eq!(AppError::AuthBusy.log_reason(), "auth_busy");
        assert_eq!(AppError::AuthOverBudget.log_reason(), "auth_over_budget");
    }

    #[test]
    fn limiter_refusals_are_429_capacity_refusals_with_retry_after() {
        let limited = AppError::RateLimited {
            retry_after_secs: 7,
        };
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.retry_after_secs(), Some(7));
        assert_eq!(limited.body(), json!({"error": "rate limit exceeded"}));
        assert_eq!(limited.log_reason(), "rate_limited");
        assert_eq!(
            AppError::TooManyInFlight.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(AppError::TooManyInFlight.retry_after_secs(), Some(1));
        assert_eq!(
            AppError::LimiterBusy.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        for err in [limited, AppError::TooManyInFlight, AppError::LimiterBusy] {
            assert!(err.is_capacity_refusal(), "{err:?}");
        }
    }

    #[test]
    fn rate_limiter_unavailable_is_a_503_capacity_refusal_with_retry_after() {
        let err = AppError::RateLimiterUnavailable;
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.retry_after_secs(), Some(1));
        assert_eq!(err.body(), json!({"error": "rate limiter unavailable"}));
        assert_eq!(err.log_reason(), "rate_limit_store_unavailable");
        assert!(err.is_capacity_refusal());
    }

    #[test]
    fn inflight_store_unavailable_is_a_503_capacity_refusal_with_its_own_reason() {
        let err = AppError::InflightStoreUnavailable;
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.retry_after_secs(), Some(1));
        assert_eq!(
            err.body(),
            json!({"error": "in-flight limiter unavailable"})
        );
        assert_eq!(err.log_reason(), "inflight_store_unavailable");
        assert!(err.is_capacity_refusal());
    }
}
