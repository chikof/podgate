//! The `buffering` middleware: caps on request and response body sizes, and optionally holding
//! a whole request or response in memory before it moves on. Full reference:
//! `docs/ref/mw-buffering.md`.
//!
//! ```json
//! { "name": "b", "type": "buffering",
//!   "max_request_body_bytes": 65536, "buffer_request": true,
//!   "max_response_body_bytes": 1048576, "buffer_response": true }
//! ```
//!
//! Memory only, charged up front: every byte held is charged to the tenant's
//! `max_buffer_bytes` before it is allocated (change 0009's mechanism), and nothing ever touches
//! the disk.
//!
//! - **Request limit.** A `Content-Length` over `max_request_body_bytes` is answered `413`
//!   (`417` for `Expect: 100-continue`) before any body is read. A chunked body is counted as
//!   Pingora reads it ([`Kind::request_body`]).
//! - **`buffer_request`.** The chain's request hook reads the whole body before the upstream is
//!   chosen or dialled, so a slow client never holds an upstream connection. Pingora can hand a
//!   pre-read body to the upstream only through its replay buffer, which takes 64 KiB, so
//!   `max_request_body_bytes` may not exceed [`MAX_BUFFERED_REQUEST_BYTES`] with it. The same
//!   replay buffer is what lets a retry send the body to a second server.
//! - **Response limit.** A `Content-Length` over `max_response_body_bytes` is answered `502`
//!   instead of the response ([`Kind::response_head`]). A response of unknown length is held
//!   until it is complete and sent in one piece; over the limit, the connection is reset
//!   (Pingora has already sent the head by then).
//!
//! `Upgrade` and `CONNECT` requests are exempt: a WebSocket is not a body.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, EXPECT, TRANSFER_ENCODING};
use pingora::Error;
use pingora::ErrorType::{HTTPStatus, InternalError};
use pingora::http::{Method, RequestHeader, StatusCode};
use pingora::proxy::Session;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::timeout;

use super::{CompileCx, Flow, Kind, RequestCx, ResponseCx};
use crate::budget::{BufferGuard, TenantBudget};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::respond;
use podgate_model::Declared;

/// Most bytes `buffer_request` can hold: the size of Pingora's request replay buffer.
pub const MAX_BUFFERED_REQUEST_BYTES: u64 = 64 * 1024;

/// How long a client has to send a request body that is being held.
const REQUEST_BODY_DEADLINE: Duration = Duration::from_secs(30);

/// Granularity of the charge for a response of unknown length: Pingora reads an upstream body in
/// chunks of at most this size, so the charge stays ahead of the allocation without one guard
/// per chunk.
const CHARGE_BLOCK: u64 = 64 * 1024;

/// The configuration of a `buffering` middleware.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Largest request body, in bytes; a larger one is refused with `413`.
    #[serde(default)]
    pub max_request_body_bytes: Option<u64>,
    /// Holds the whole request body before the upstream request starts. Needs
    /// `max_request_body_bytes`, at most [`MAX_BUFFERED_REQUEST_BYTES`].
    #[serde(default)]
    pub buffer_request: bool,
    /// Largest response body, in bytes; a larger one is refused with `502`. Needs
    /// `buffer_response`.
    #[serde(default)]
    pub max_response_body_bytes: Option<u64>,
    /// Holds the whole response body before the client gets it. Needs `max_response_body_bytes`.
    #[serde(default)]
    pub buffer_response: bool,
}

impl Config {
    fn validate(self) -> Result<(), &'static str> {
        match (self.buffer_request, self.max_request_body_bytes) {
            (true, None) => return Err("buffer_request needs max_request_body_bytes"),
            (true, Some(max)) if max > MAX_BUFFERED_REQUEST_BYTES => {
                return Err(
                    "max_request_body_bytes is over 65536, the most buffer_request can hold: Pingora hands a body read ahead of the upstream request over through a 64 KiB replay buffer",
                );
            }
            _ => {}
        }
        match (self.buffer_response, self.max_response_body_bytes) {
            (true, None) => Err("buffer_response needs max_response_body_bytes"),
            (false, Some(_)) => Err(
                "max_response_body_bytes needs buffer_response: true, because a response of unknown length cannot be refused once it has started, only held back",
            ),
            _ if self.max_request_body_bytes.is_none()
                && self.max_response_body_bytes.is_none() =>
            {
                Err("set max_request_body_bytes or max_response_body_bytes")
            }
            _ => Ok(()),
        }
    }
}

/// A compiled `buffering` middleware.
#[derive(Debug)]
pub struct Buffering {
    config: Config,
}

/// What one request keeps for this stage.
#[derive(Debug, Default)]
pub struct State {
    /// `Upgrade` and `CONNECT`: no limit applies.
    exempt: bool,
    /// The charge for the request body held by `buffer_request`, until the request ends.
    request_charge: Option<BufferGuard>,
    /// The response being held.
    response: Option<Held>,
}

/// A response body held in memory until it is complete.
#[derive(Debug)]
struct Held {
    tenant: Option<Arc<TenantBudget>>,
    charges: Vec<BufferGuard>,
    charged: u64,
    data: Vec<u8>,
}

impl Held {
    fn new(tenant: Option<&Arc<TenantBudget>>) -> Self {
        Self {
            tenant: tenant.cloned(),
            charges: Vec::new(),
            charged: 0,
            data: Vec::new(),
        }
    }

    /// Charges `bytes` more, before anything is allocated for them.
    fn charge(&mut self, bytes: u64) -> Result<(), AppError> {
        let Some(tenant) = &self.tenant else {
            return Ok(());
        };
        let guard = tenant
            .reserve_buffering(bytes)
            .ok_or(AppError::BufferingOverBudget)?;
        self.charges.push(guard);
        self.charged += bytes;
        Ok(())
    }

    /// Holds `chunk`, charging first, refusing a body that would pass `max`.
    fn push(&mut self, chunk: &[u8], max: u64) -> Result<(), AppError> {
        let total = len(&self.data).saturating_add(len(chunk));
        if total > max {
            return Err(AppError::UpstreamResponseTooLarge);
        }
        if total > self.charged {
            let step = (total - self.charged)
                .max(CHARGE_BLOCK)
                .min(max - self.charged);
            self.charge(step)?;
        }
        self.data.reserve_exact(chunk.len());
        self.data.extend_from_slice(chunk);
        Ok(())
    }
}

fn len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// The declared body length, `None` for a chunked or unmarked message.
fn declared_length(headers: &http::HeaderMap) -> Option<u64> {
    let chunked = headers
        .get_all(TRANSFER_ENCODING)
        .iter()
        .any(|value| value.as_bytes().eq_ignore_ascii_case(b"chunked"));
    if chunked {
        return None;
    }
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn expects_continue(request: &RequestHeader) -> bool {
    request.version == http::Version::HTTP_11
        && request
            .headers
            .get(EXPECT)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"100-continue"))
}

/// A request whose body is not a body: a WebSocket handshake or a tunnel.
fn exempt(session: &Session) -> bool {
    session.is_upgrade_req() || session.req_header().method == Method::CONNECT
}

/// Whether the response to `request` can carry a body at all.
fn has_body(request: &RequestHeader, status: StatusCode) -> bool {
    request.method != Method::HEAD
        && !status.is_informational()
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED
}

/// Reads the whole request body, so Pingora's replay buffer holds it.
async fn read_body(session: &mut Session, max: u64) -> pingora::Result<Result<(), AppError>> {
    let mut total = 0_u64;
    while let Some(chunk) = session.read_request_body().await? {
        total = total.saturating_add(len(&chunk));
        if total > max {
            return Ok(Err(AppError::PayloadTooLarge));
        }
    }
    Ok(Ok(()))
}

impl Buffering {
    /// Whether the middleware holds or limits response bodies (its response hooks run on the
    /// upstream's response as it streams).
    pub(crate) fn limits_response(&self) -> bool {
        self.config.max_response_body_bytes.is_some()
    }

    /// Holds the request body: charge, read it all, check the replay buffer took it.
    async fn hold_request(
        &self,
        cx: &mut RequestCx<'_>,
        state: &mut State,
        max: u64,
        declared: Option<u64>,
    ) -> pingora::Result<Flow> {
        // The declared length, else the most a chunked body may reach.
        if let Some(tenant) = cx.tenant {
            let Some(guard) = tenant.reserve_buffering(declared.unwrap_or(max)) else {
                *cx.capacity_refusal = true;
                respond::write_error(cx.session, &AppError::BufferingOverBudget).await?;
                return Ok(Flow::Respond);
            };
            state.request_charge = Some(guard);
        }
        if expects_continue(cx.session.req_header()) {
            // The client waits for this before it sends the body; the upstream never sees the
            // expectation, because the body is complete when its request starts.
            cx.session.write_continue_response().await?;
            cx.session.req_header_mut().remove_header(&EXPECT);
        }
        cx.session.enable_retry_buffering();
        let refusal = match timeout(REQUEST_BODY_DEADLINE, read_body(cx.session, max)).await {
            Ok(read) => read?.err(),
            Err(_) => Some(AppError::RequestTimeout),
        };
        if let Some(refusal) = refusal {
            respond::write_error(cx.session, &refusal).await?;
            return Ok(Flow::Respond);
        }
        if cx.session.retry_buffer_truncated() {
            return Err(Error::explain(
                InternalError,
                "request body does not fit the replay buffer",
            ));
        }
        *cx.body_held = true;
        Ok(Flow::Continue)
    }
}

impl Kind for Buffering {
    type State = State;

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| Invalid::new("invalid_middleware", format!("buffering: {err}")))?;
        config
            .validate()
            .map_err(|why| Invalid::new("invalid_middleware", format!("buffering: {why}")))?;
        Ok(Self { config })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        if exempt(cx.session) {
            state.exempt = true;
            return Ok(Flow::Continue);
        }
        let Some(max) = self.config.max_request_body_bytes else {
            return Ok(Flow::Continue);
        };
        let declared = declared_length(&cx.session.req_header().headers);
        if declared.is_some_and(|declared| declared > max) {
            let refusal = if expects_continue(cx.session.req_header()) {
                AppError::ExpectationFailed
            } else {
                AppError::PayloadTooLarge
            };
            respond::write_error(cx.session, &refusal).await?;
            return Ok(Flow::Respond);
        }
        if !self.config.buffer_request || cx.session.is_body_empty() {
            return Ok(Flow::Continue);
        }
        self.hold_request(cx, state, max, declared).await
    }

    fn request_body(&self, bytes_read: u64, state: &mut State) -> Result<(), AppError> {
        match self.config.max_request_body_bytes {
            Some(max) if !state.exempt && bytes_read > max => Err(AppError::PayloadTooLarge),
            _ => Ok(()),
        }
    }

    fn response_head(&self, cx: &ResponseCx<'_>, state: &mut State) -> Result<(), AppError> {
        let Some(max) = self.config.max_response_body_bytes else {
            return Ok(());
        };
        if state.exempt || !has_body(cx.request, cx.response.status) {
            return Ok(());
        }
        let declared = declared_length(&cx.response.headers);
        if declared.is_some_and(|declared| declared > max) {
            return Err(AppError::UpstreamResponseTooLarge);
        }
        let mut held = Held::new(cx.tenant);
        if let Some(declared) = declared {
            held.charge(declared)?;
            held.data
                .reserve_exact(usize::try_from(declared).unwrap_or(0));
        }
        state.response = Some(held);
        Ok(())
    }

    fn response_body(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        state: &mut State,
    ) -> pingora::Result<()> {
        let (Some(max), Some(held)) =
            (self.config.max_response_body_bytes, state.response.as_mut())
        else {
            return Ok(());
        };
        if let Some(chunk) = body.take()
            && let Err(refusal) = held.push(&chunk, max)
        {
            state.response = None;
            return Err(Error::explain(
                HTTPStatus(refusal.status().as_u16()),
                refusal.to_string(),
            ));
        }
        if end_of_stream {
            let data = std::mem::take(&mut held.data);
            *body = (!data.is_empty()).then(|| Bytes::from(data));
        }
        Ok(())
    }

    /// A limit that went away or grew is less protection than before.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        if loosened(self.config.max_request_body_bytes, new, |config| {
            config.max_request_body_bytes
        }) {
            kinds.push("request_body_limit_loosened");
        }
        if loosened(self.config.max_response_body_bytes, new, |config| {
            config.max_response_body_bytes
        }) {
            kinds.push("response_body_limit_loosened");
        }
        kinds
    }

    fn describe(&self) -> Value {
        json!({
            "max_request_body_bytes": self.config.max_request_body_bytes,
            "buffer_request": self.config.buffer_request,
            "max_response_body_bytes": self.config.max_response_body_bytes,
            "buffer_response": self.config.buffer_response,
        })
    }
}

/// Whether a limit `old` is looser in `new` (`None`: the stage is gone): gone, or larger.
fn loosened(old: Option<u64>, new: Option<&Buffering>, limit: fn(&Config) -> Option<u64>) -> bool {
    old.is_some_and(|old| {
        !new.and_then(|stage| limit(&stage.config))
            .is_some_and(|new| new <= old)
    })
}

#[cfg(test)]
mod test {
    use podgate_model::Budget;

    use super::*;
    use crate::budget::Budgets;

    fn compile(config: &Value) -> Result<Buffering, Invalid> {
        let mut declared = json!({ "name": "b", "type": "buffering" });
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        Buffering::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    fn refused(config: &Value) -> String {
        let invalid = compile(config).expect_err("refused");
        assert_eq!(invalid.code, "invalid_middleware");
        invalid.message
    }

    fn tenant(max_buffer_bytes: u64) -> Arc<TenantBudget> {
        Budgets::new().tenant(
            "t",
            Budget {
                max_inflight: 10,
                max_buffer_bytes,
            },
        )
    }

    #[test]
    fn compile_rules() {
        assert!(compile(&json!({ "max_request_body_bytes": 10 })).is_ok());
        assert!(
            compile(&json!({ "max_request_body_bytes": 65536, "buffer_request": true })).is_ok()
        );
        assert!(
            compile(&json!({ "max_response_body_bytes": 1 << 30, "buffer_response": true }))
                .is_ok()
        );
        assert!(refused(&json!({})).contains("set max_request_body_bytes"));
        assert!(refused(&json!({ "buffer_request": true, "max_response_body_bytes": 1, "buffer_response": true }))
            .contains("buffer_request needs"));
        assert!(
            refused(&json!({ "max_request_body_bytes": 65537, "buffer_request": true }))
                .contains("replay buffer")
        );
        assert!(
            refused(&json!({ "buffer_response": true, "max_request_body_bytes": 1 }))
                .contains("buffer_response needs")
        );
        assert!(
            refused(&json!({ "max_response_body_bytes": 10 })).contains("needs buffer_response")
        );
        assert!(
            refused(&json!({ "max_request_body_bytes": 1, "mem_request_body_bytes": 1 }))
                .contains("unknown field")
        );
    }

    #[test]
    fn request_body_counts_what_was_read() {
        let stage = compile(&json!({ "max_request_body_bytes": 10 })).expect("compiles");
        let mut state = State::default();
        assert!(stage.request_body(10, &mut state).is_ok());
        assert!(matches!(
            stage.request_body(11, &mut state),
            Err(AppError::PayloadTooLarge)
        ));
        state.exempt = true;
        assert!(stage.request_body(1 << 20, &mut state).is_ok());
    }

    #[test]
    fn a_held_response_is_charged_before_it_grows_and_refused_past_the_limit() {
        let tenant = tenant(1024);
        let mut held = Held::new(Some(&tenant));
        held.push(&[1; 100], 600).expect("fits");
        assert_eq!(tenant.buffered(), 600, "charged in blocks, never past max");
        held.push(&[2; 500], 600).expect("still fits");
        assert!(matches!(
            held.push(&[3], 600),
            Err(AppError::UpstreamResponseTooLarge)
        ));
        drop(held);
        assert_eq!(tenant.buffered(), 0);

        let mut held = Held::new(Some(&tenant));
        assert!(matches!(
            held.push(&[0; 2000], 5000),
            Err(AppError::BufferingOverBudget)
        ));
        assert_eq!(tenant.buffered(), 0, "a refused charge holds nothing");
    }

    #[test]
    fn posture_names_a_limit_that_went_away_or_grew() {
        let tight = compile(&json!({ "max_request_body_bytes": 10 })).expect("tight");
        let wide = compile(&json!({ "max_request_body_bytes": 20 })).expect("wide");
        let other = compile(&json!({
            "max_response_body_bytes": 10, "buffer_response": true
        }))
        .expect("response only");
        assert_eq!(tight.posture(Some(&wide)), ["request_body_limit_loosened"]);
        assert!(wide.posture(Some(&tight)).is_empty());
        assert_eq!(tight.posture(None), ["request_body_limit_loosened"]);
        assert_eq!(tight.posture(Some(&other)), ["request_body_limit_loosened"]);
        assert_eq!(other.posture(None), ["response_body_limit_loosened"]);
    }

    #[test]
    fn declared_length_ignores_chunked_and_garbage() {
        let mut headers = http::HeaderMap::new();
        assert_eq!(declared_length(&headers), None);
        headers.insert(CONTENT_LENGTH, "12".parse().expect("value"));
        assert_eq!(declared_length(&headers), Some(12));
        headers.insert(TRANSFER_ENCODING, "chunked".parse().expect("value"));
        assert_eq!(declared_length(&headers), None);
    }
}
