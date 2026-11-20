//! The `in_flight_req` middleware: caps the requests one source has in flight at once and
//! answers `429` over the cap. Reference: `docs/ref/mw-limits.md`; the shared source and table
//! are in `src/middleware/limits.rs`.
//!
//! ```json
//! { "name": "cap", "type": "in_flight_req", "amount": 10,
//!   "source": { "header": "x-api-key" }, "max_sources": 10000 }
//! ```
//!
//! - A request takes one slot of its source when it enters the chain and returns it when the
//!   request ends: the response is done, the upstream failed, or the client went away. The slot
//!   is a guard held in the request's chain state, so every exit drops it. A WebSocket holds its
//!   slot until the connection closes.
//! - Over `amount` the request is answered `429` with `retry-after: 1` and
//!   `{"error":"too many requests in flight"}`, before any tenant slot or backend permit is taken.
//! - Per-source state is bounded; see `src/middleware/limits.rs`. Sources that find the table full share
//!   one overflow counter capped at `amount`, and an entry with a request in flight is never
//!   reclaimed.
//! - Limits are per node.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Deserialize;
use serde_json::{Value, json};

use super::limits::{DEFAULT_MAX_SOURCES, Limiter, MAX_SOURCES, Source, SourceConfig, SourceTable};
use super::{CompileCx, FinishCx, Flow, Kind, RequestCx, Stage, state};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::table::CompiledApp;
use podgate_model::Declared;

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: nothing caps the route.
    pub const REMOVED: &str = "in_flight_req_removed";
    /// A higher `amount`.
    pub const LOOSENED: &str = "in_flight_req_loosened";
    /// Requests are counted per another source, which can let a client leave its count.
    pub const SOURCE_CHANGED: &str = "in_flight_req_source_changed";
}

/// The configuration of an `in_flight_req` middleware.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    amount: u32,
    source: SourceConfig,
    #[serde(default)]
    max_sources: Option<u32>,
}

/// A compiled `in_flight_req` middleware.
#[derive(Debug)]
pub struct InFlightReq {
    amount: u32,
    max_sources: u32,
    source_config: SourceConfig,
    source: Source,
    fingerprint: u64,
    runtime: Arc<Limiter>,
}

/// Where a request's slot is counted.
#[derive(Debug, Clone, Copy)]
enum Slot {
    /// The entry of the source with this key.
    Entry(u64),
    /// The table's shared overflow counter.
    Overflow,
}

/// One slot of a source. Dropping it returns the slot, whatever ended the request.
#[derive(Debug)]
pub struct Permit {
    limiter: Arc<Limiter>,
    slot: Slot,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let Some(table) = self.limiter.allocated() else {
            return;
        };
        match self.slot {
            Slot::Entry(key) => table.with_existing(key, |count| *count = count.saturating_sub(1)),
            Slot::Overflow => {
                // Never below zero: `try_update` stops at `None`.
                let _ = table
                    .overflow()
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        count.checked_sub(1)
                    });
            }
        }
    }
}

/// Per-request state: the slot, while the request holds one.
#[derive(Debug, Default)]
pub struct State {
    permit: Option<Permit>,
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("in_flight_req: {message}"))
}

impl InFlightReq {
    pub(super) fn max_sources(&self) -> u32 {
        self.max_sources
    }

    pub(super) fn stats(&self) -> super::limits::Stats {
        self.runtime.stats()
    }

    /// Takes a slot of source `key`, or `None` when it already has `amount` in flight.
    fn acquire(&self, table: &SourceTable, key: u64) -> Option<Permit> {
        let amount = u64::from(self.amount);
        let slot = match table.with(
            key,
            |count| count == 0,
            |count| {
                (*count < amount).then(|| {
                    *count += 1;
                })
            },
        ) {
            Some(taken) => taken.map(|()| Slot::Entry(key))?,
            None => {
                table.count_overflow();
                table
                    .overflow()
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        (count < amount).then(|| count + 1)
                    })
                    .ok()
                    .map(|_| Slot::Overflow)?
            }
        };
        Some(Permit {
            limiter: Arc::clone(&self.runtime),
            slot,
        })
    }
}

impl Kind for InFlightReq {
    type State = State;

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        if config.amount == 0 {
            return Err(invalid(
                "`amount` must be at least 1; a cap of zero refuses every request (use `respond` to close a route)",
            ));
        }
        let max_sources = config.max_sources.unwrap_or(DEFAULT_MAX_SOURCES);
        if !(1..=MAX_SOURCES).contains(&max_sources) {
            return Err(invalid(format!("`max_sources` must be 1 to {MAX_SOURCES}")));
        }
        let source = Source::compile(&config.source).map_err(invalid)?;
        Ok(Self {
            amount: config.amount,
            max_sources,
            source_config: config.source,
            source,
            fingerprint: state::fingerprint(declared),
            runtime: Arc::new(Limiter::new(max_sources)),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        let refusal = match self.runtime.table(cx.tenant) {
            None => AppError::LimiterBusy,
            Some(table) => {
                let key =
                    self.source
                        .key(self.runtime.hasher(), cx.session.req_header(), cx.forwarded);
                match self.acquire(table, key) {
                    Some(permit) => {
                        state.permit = Some(permit);
                        return Ok(Flow::Continue);
                    }
                    None => AppError::TooManyInFlight,
                }
            }
        };
        self.runtime.count_rejected();
        *cx.capacity_refusal = true;
        crate::respond::write_error(cx.session, &refusal).await?;
        Ok(Flow::Respond)
    }

    /// The slot goes back when the request ends, before the guard's own drop would return it
    /// with the connection's state.
    fn finished(&self, _cx: &FinishCx<'_>, state: &mut State) {
        state.permit = None;
    }

    /// Dropping the middleware stops capping; a higher amount lets more through; another source
    /// puts requests in other counts.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let mut kinds = Vec::new();
        if new.amount > self.amount {
            kinds.push(kind::LOOSENED);
        }
        if self.source_config != new.source_config {
            kinds.push(kind::SOURCE_CHANGED);
        }
        kinds
    }

    fn describe(&self) -> Value {
        json!({
            "amount": self.amount,
            "source": self.source_config.describe(),
            "max_sources": self.max_sources,
            "table_bytes": SourceTable::bytes(self.max_sources),
        })
    }
}

/// The [`Limiter`] of every `in_flight_req` middleware of the live table, kept by the shared
/// [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]). A push that
/// leaves a middleware's declaration as it was keeps its counts, so requests that started under
/// the old table still return their slot to the counts the new one uses; a middleware whose
/// declaration changed starts with empty ones.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Limiter>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            Stage::InFlightReq(cap) => Some((cap.fingerprint, &mut cap.runtime)),
            _ => None,
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn compiled(config: &Value) -> Result<InFlightReq, Invalid> {
        let mut object = config.as_object().cloned().unwrap_or_default();
        object.insert("name".into(), json!("cap"));
        object.insert("type".into(), json!("in_flight_req"));
        let declared: Declared = serde_json::from_value(Value::Object(object)).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        InFlightReq::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    fn cap(amount: u32, max_sources: u32) -> InFlightReq {
        compiled(&json!({
            "amount": amount, "source": {"ip": {}}, "max_sources": max_sources,
        }))
        .expect("valid")
    }

    #[test]
    fn in_flight_req_caps_per_source() {
        let cap = cap(2, 8);
        let table = cap.runtime.table(None).expect("allocates");
        let first = cap.acquire(table, 1).expect("first");
        let _second = cap.acquire(table, 1).expect("second");
        assert!(cap.acquire(table, 1).is_none(), "the third is over the cap");
        assert!(
            cap.acquire(table, 2).is_some(),
            "another source has its own"
        );
        drop(first);
        assert!(
            cap.acquire(table, 1).is_some(),
            "a returned slot is reusable"
        );
    }

    #[test]
    fn in_flight_req_slots_return_on_drop_and_never_below_zero() {
        let cap = cap(1, 8);
        let table = cap.runtime.table(None).expect("allocates");
        for _ in 0..3 {
            let permit = cap.acquire(table, 1).expect("slot");
            assert!(cap.acquire(table, 1).is_none());
            drop(permit);
        }
        assert_eq!(table.with(1, |count| count == 0, |count| *count), Some(0));
    }

    #[test]
    fn in_flight_req_overflow_is_one_shared_count() {
        let cap = cap(2, 1);
        let table = cap.runtime.table(None).expect("allocates");
        let _held = cap.acquire(table, 1).expect("takes the entry");
        let first = cap.acquire(table, 2).expect("overflow 1");
        let _second = cap.acquire(table, 3).expect("overflow 2");
        assert!(
            cap.acquire(table, 4).is_none(),
            "every source without an entry shares two slots"
        );
        assert!(cap.acquire(table, 2).is_none(), "even one that was served");
        drop(first);
        assert!(cap.acquire(table, 5).is_some());
        assert_eq!(table.overflowed(), 5);
    }

    #[test]
    fn in_flight_req_an_entry_with_requests_in_flight_is_not_reclaimed() {
        let cap = cap(1, 1);
        let table = cap.runtime.table(None).expect("allocates");
        let held = cap.acquire(table, 1).expect("slot");
        assert!(
            cap.acquire(table, 2).is_some(),
            "overflow, not source 1's entry"
        );
        assert!(
            cap.acquire(table, 1).is_none(),
            "source 1 is still at its cap"
        );
        drop(held);
        let again = cap.acquire(table, 2);
        assert!(again.is_some(), "now the entry is free for source 2");
    }

    #[test]
    fn invalid_configs_are_invalid_middleware() {
        let ok = json!({"amount": 1, "source": {"ip": {}}});
        let with = |key: &str, value: Value| {
            let mut config = ok.clone();
            config[key] = value;
            config
        };
        for config in [
            with("amount", json!(0)),
            with("amount", json!(-1)),
            with("max_sources", json!(0)),
            with("max_sources", json!(MAX_SOURCES + 1)),
            with("source", json!({"header": ""})),
            with("source", json!({"host": false})),
            with("sourceCriterion", json!({})),
            json!({"source": {"ip": {}}}),
            json!({"amount": 1}),
        ] {
            let err = compiled(&config).expect_err(&config.to_string());
            assert_eq!(err.code, "invalid_middleware", "{config}");
        }
        assert!(compiled(&ok).is_ok());
    }

    #[test]
    fn posture_lists_removal_a_higher_amount_and_another_source() {
        let cap = |amount: u32, source: Value| {
            compiled(&json!({"amount": amount, "source": source})).expect("valid")
        };
        let base = cap(5, json!({"ip": {}}));
        assert_eq!(base.posture(None), [kind::REMOVED]);
        assert!(base.posture(Some(&cap(5, json!({"ip": {}})))).is_empty());
        assert!(base.posture(Some(&cap(4, json!({"ip": {}})))).is_empty());
        assert_eq!(
            base.posture(Some(&cap(6, json!({"ip": {}})))),
            [kind::LOOSENED]
        );
        assert_eq!(
            base.posture(Some(&cap(5, json!({"header": "x-api-key"})))),
            [kind::SOURCE_CHANGED]
        );
    }
}
