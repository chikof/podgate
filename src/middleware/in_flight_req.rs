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
//! - Limits are per node unless `scope` is `"cluster"`: then a shared store counts one limit for
//!   every node, with leases that expire when a node dies (`cluster.rs`,
//!   `docs/ref/inflight-cluster.md`).

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use super::limits::{
    DEFAULT_MAX_SOURCES, Limiter, MAX_SOURCES, Permit, Source, SourceConfig, SourceTable,
};
use super::{CompileCx, FinishCx, Flow, Kind, RequestCx, Stage, state};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::table::CompiledApp;
use podgate_model::Declared;

mod cluster;

use cluster::{Cluster, FallbackConfig, Lease, OnStoreError, Scope};
pub(crate) use cluster::{check_snapshot, render};

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: nothing caps the route.
    pub const REMOVED: &str = "in_flight_req_removed";
    /// A higher `amount`.
    pub const LOOSENED: &str = "in_flight_req_loosened";
    /// Requests are counted per another source, which can let a client leave its count.
    pub const SOURCE_CHANGED: &str = "in_flight_req_source_changed";
    /// A cluster-scope limit that admits requests when its store fails: while the store is down
    /// only each node's local fallback caps them.
    pub const CLUSTER_FAIL_OPEN: &str = "in_flight_req_cluster_fail_open";
    /// A cluster-wide limit became a per-node one: a client can use every node's share.
    pub const SCOPE_NODE: &str = "in_flight_req_scope_node";
}

/// The configuration of an `in_flight_req` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    amount: u32,
    source: SourceConfig,
    #[serde(default)]
    max_sources: Option<u32>,
    #[serde(default)]
    scope: Option<Scope>,
    #[serde(default)]
    store: Option<String>,
    #[serde(default)]
    on_store_error: Option<OnStoreError>,
    #[serde(default)]
    local_fallback: Option<FallbackConfig>,
    #[serde(default)]
    lease_secs: Option<u32>,
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
    cluster: Option<Cluster>,
}

/// Per-request state: the slot, while the request holds one.
#[derive(Debug, Default)]
pub struct State {
    permit: Option<Permit>,
    lease: Option<Lease>,
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
        self.runtime.acquire(table, key, self.amount)
    }
}

impl Kind for InFlightReq {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
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
        let fingerprint = state::fingerprint(declared);
        let cluster = Cluster::compile(&config, &declared.name, fingerprint, cx.app)?;
        Ok(Self {
            amount: config.amount,
            max_sources,
            source_config: config.source,
            source,
            fingerprint,
            runtime: Arc::new(Limiter::new(max_sources)),
            cluster,
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        let refusal = match self.runtime.table(cx.tenant) {
            None => AppError::LimiterBusy,
            Some(table) => {
                let key =
                    self.source
                        .key(self.runtime.hasher(), cx.session.req_header(), cx.forwarded);
                let taken = match &self.cluster {
                    Some(cluster) => cluster.admit(self, cx, table, key).await,
                    None => self
                        .acquire(table, key)
                        .map(|permit| (permit, None))
                        .ok_or(AppError::TooManyInFlight),
                };
                match taken {
                    Ok((permit, lease)) => {
                        state.permit = Some(permit);
                        state.lease = lease;
                        return Ok(Flow::Continue);
                    }
                    Err(refusal) => refusal,
                }
            }
        };
        self.runtime.count_rejected();
        *cx.capacity_refusal = true;
        crate::respond::write_error(cx.session, &refusal).await?;
        Ok(Flow::Respond)
    }

    /// The slot goes back when the request ends, before the guard's own drop would return it
    /// with the connection's state. A cluster slot is given back to the store, too.
    fn finished(&self, _cx: &FinishCx<'_>, state: &mut State) {
        state.lease = None;
        state.permit = None;
    }

    /// Dropping the middleware stops capping; a higher amount lets more through; another source
    /// puts requests in other counts; a cluster limit that starts failing open, or becomes a
    /// per-node one, lets a client past the cluster-wide count.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let mut kinds = Vec::new();
        let fallback_loosened = match (&self.cluster, &new.cluster) {
            (Some(old), Some(new)) => old.fallback_loosened_by(new),
            _ => false,
        };
        if new.amount > self.amount || fallback_loosened {
            kinds.push(kind::LOOSENED);
        }
        if self.source_config != new.source_config {
            kinds.push(kind::SOURCE_CHANGED);
        }
        if self.cluster.is_some() && new.cluster.is_none() {
            kinds.push(kind::SCOPE_NODE);
        }
        let fails_open = |cap: &Self| cap.cluster.as_ref().is_some_and(Cluster::fails_open);
        if fails_open(new) && !fails_open(self) {
            kinds.push(kind::CLUSTER_FAIL_OPEN);
        }
        kinds
    }

    fn describe(&self) -> Value {
        let mut shown = json!({
            "scope": "node",
            "amount": self.amount,
            "source": self.source_config.describe(),
            "max_sources": self.max_sources,
            "table_bytes": SourceTable::bytes(self.max_sources),
        });
        if let (Some(cluster), Some(object)) = (&self.cluster, shown.as_object_mut())
            && let Some(extra) = cluster.describe().as_object()
        {
            object.extend(extra.clone());
        }
        shown
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
                portal: None,
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
