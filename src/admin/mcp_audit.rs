//! The MCP audit log: `GET /v1/apps/{app}/mcp/audit` and
//! `POST /v1/apps/{app}/mcp/audit/{id}/replay`. The log is `crate::mcp_audit`; the replay is
//! `crate::middleware::mcp::replay`. Operator only: these routes exist on the admin socket and
//! nowhere else. Reference: `docs/ref/mcp-audit.md`.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::RETRY_AFTER;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};

use super::AppState;
use crate::error::AppError;
use crate::failures;
use crate::mcp_audit::{ArgumentsState, Outcome, Record};
use crate::middleware::mcp::{self, Replay, ReplayAnswer, ReplayError};
use crate::table::{CompiledApp, RoutingTable};

/// The most records one page lists, and the default.
const MAX_LIMIT: usize = crate::mcp_audit::RING_CAP;
const DEFAULT_LIMIT: usize = 100;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/apps/{app}/mcp/audit", get(list))
        .route("/v1/apps/{app}/mcp/audit/{id}/replay", post(replay))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    after: Option<u64>,
    limit: Option<usize>,
}

/// `200 {"boot_id", "evicted_through", "records", "next_after"}`: the records of the app after
/// `after` (default 0), oldest first, at most `limit` (default 100, 1 to 1000). `next_after` is
/// the last `seq` listed, or `after` when none. A reader whose `after` is below
/// `evicted_through` has lost records; one whose `boot_id` changed is reading a new process and
/// restarts at 0.
///
/// - `400`: `after` or `limit` is not a number, or `limit` is out of range.
/// - `404`: the live table has no such app.
async fn list(
    State(state): State<AppState>,
    Path(app): Path<String>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<Value>, AppError> {
    let Query(query) = query.map_err(|err| AppError::BadRequest(err.body_text().into()))?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(AppError::BadRequest(
            format!("limit is in 1..={MAX_LIMIT}").into(),
        ));
    }
    let after = query.after.unwrap_or(0);
    let table = state.table().load();
    let compiled = live_app(&table, &app)?;
    let page = state
        .mcp_audit()
        .list(&app, compiled.tenant(), after, limit);
    let next_after = page.records.last().map_or(after, |record| record.seq);
    let records: Vec<&Record> = page.records.iter().map(AsRef::as_ref).collect();
    Ok(Json(json!({
        "boot_id": state.events().boot_id(),
        "evicted_through": page.evicted_through,
        "records": records,
        "next_after": next_after,
    })))
}

#[derive(Debug, Deserialize)]
struct ReplayQuery {
    #[serde(default)]
    force: bool,
}

#[derive(Debug, Serialize)]
struct Replayed {
    audit_seq: u64,
    replay_of: u64,
    outcome: Outcome,
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Box<RawValue>>,
}

/// `{"error": <message>, "code": <code>}` with `status`: the error shape of the admin API plus a
/// stable code.
fn refusal(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({"error": message, "code": code}))).into_response()
}

/// Sends the recorded call again to its server through the gateway of the live app, and answers
/// `200 {"audit_seq", "replay_of", "outcome", "reason", "result" | "error"}`: what the server
/// said, as it came, returned to the operator and not stored. The replay is audited with
/// `replay_of`. Arguments are the ones recorded, so a call whose arguments were redacted, not
/// recorded or too large is refused.
///
/// - `400`: `force` is not a boolean.
/// - `404`: unknown app, or no record `id` in that app's log for its tenant.
/// - `409` with a `code`: `not_replayable` (the call never reached a server), `gateway_gone`,
///   `server_gone`, `tool_gone`, `not_permitted` (authorization lists the tool for nobody),
///   `needs_force` (the tool is not marked `readOnlyHint` and `force=true` is missing).
/// - `422 redacted_arguments`: the arguments were redacted, not recorded or too large.
/// - `503` with `retry-after: 1`: the tenant has no in-flight slot or buffer budget, or the
///   server is at its `max_concurrent`.
/// - `502`: the exchange with the server failed (audited as `upstream_failed`).
async fn replay(
    State(state): State<AppState>,
    Path((app, id)): Path<(String, String)>,
    query: Result<Query<ReplayQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let Query(query) = query.map_err(|err| AppError::BadRequest(err.body_text().into()))?;
    let table = state.table().load();
    let compiled = live_app(&table, &app)?;
    let record = id
        .parse()
        .ok()
        .and_then(|seq| state.mcp_audit().get(&app, compiled.tenant(), seq))
        .ok_or(AppError::NotFound)?;
    let budget = table
        .tenant_budget(compiled.tenant())
        .map(|limits| state.budgets().tenant(compiled.tenant(), limits));
    let replayed = mcp::replay(Replay {
        app: compiled,
        client: state.mcp_client(),
        policy: state.upstream_policy(),
        budget: budget.as_ref(),
        audit: state.mcp_audit(),
        record: &record,
        force: query.force,
    })
    .await;
    let replayed = match replayed {
        Ok(replayed) => replayed,
        Err(err) => return refused(&err),
    };
    let out = |result, error| Replayed {
        audit_seq: replayed.audit_seq,
        replay_of: record.seq,
        outcome: replayed.outcome,
        reason: replayed.reason,
        result,
        error,
    };
    Ok(match replayed.answer {
        ReplayAnswer::Result(raw) => Json(out(Some(raw), None)).into_response(),
        ReplayAnswer::Error(raw) => Json(out(None, Some(raw))).into_response(),
        ReplayAnswer::Failed("busy") => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(RETRY_AFTER, "1")],
            Json(json!({
                "error": "replay failed: busy",
                "audit_seq": replayed.audit_seq,
            })),
        )
            .into_response(),
        ReplayAnswer::Failed(code) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": format!("replay failed: {code}"),
                "audit_seq": replayed.audit_seq,
            })),
        )
            .into_response(),
    })
}

/// The answer to a replay that was refused before anything was sent.
fn refused(err: &ReplayError) -> Result<Response, AppError> {
    let conflict = |code, message| Ok(refusal(StatusCode::CONFLICT, code, message));
    match err {
        ReplayError::NotReplayable => conflict(
            "not_replayable",
            "the call never reached a server (it was denied or its name did not resolve), so there is nothing to send again",
        ),
        ReplayError::RedactedArguments(state) => Ok(refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "redacted_arguments",
            match state {
                ArgumentsState::Redacted => {
                    "the arguments held a secret-looking value that was redacted"
                }
                ArgumentsState::TooLarge => "the arguments were over 16 KiB and not recorded",
                _ => "the arguments were not recorded (record_arguments is off)",
            },
        )),
        ReplayError::GatewayGone => conflict(
            "gateway_gone",
            "the app no longer has the mcp_gateway the call went through",
        ),
        ReplayError::ServerGone => {
            conflict("server_gone", "the server is no longer in the registry")
        }
        ReplayError::ToolGone => conflict("tool_gone", "the server no longer lists the tool"),
        ReplayError::NotPermitted => conflict(
            "not_permitted",
            "the gateway's tool_access lists the tool for nobody",
        ),
        ReplayError::NeedsForce => conflict(
            "needs_force",
            "the server does not mark the tool readOnlyHint: pass force=true to send it again",
        ),
        ReplayError::Busy => Err(AppError::Overloaded),
        ReplayError::Internal => Err(AppError::Internal(anyhow::anyhow!(
            "a replay request could not be built"
        ))),
    }
}

fn live_app<'a>(table: &'a RoutingTable, app: &str) -> Result<&'a CompiledApp, AppError> {
    failures::apps(table)
        .find(|compiled| compiled.id() == app)
        .ok_or(AppError::NotFound)
}
