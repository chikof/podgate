//! The `rate_limit` middleware: a token bucket per source that answers `429` over the limit.
//! Reference: `docs/ref/mw-limits.md`; the shared source and table are in `src/middleware/limits.rs`.
//!
//! ```json
//! { "name": "rl", "type": "rate_limit", "average": 100, "period_secs": 1, "burst": 200,
//!   "source": { "ip": { "depth": 1, "excluded": ["10.0.0.0/8"] } }, "max_sources": 10000 }
//! ```
//!
//! - A source's bucket holds `burst` tokens and refills `average` tokens per `period_secs`
//!   (default 1). Each request takes one; with none left the request is answered `429` with
//!   `Retry-After` (whole seconds, at least 1) and `{"error":"rate limit exceeded"}`, and no
//!   upstream is contacted. `average: 0` is `invalid_middleware`: a limiter that limits nothing
//!   is a mistake.
//! - The bucket is the generic cell rate algorithm: one number per source, the time at which its
//!   bucket would be full again, moved by one request at a time. The time per token is
//!   `period_secs / average` rounded up to a nanosecond, so a source never gets more than
//!   configured.
//! - Per-source state is bounded; see `src/middleware/limits.rs`. Sources that find the table full share
//!   one overflow bucket with the same rate and burst.
//! - Limits are per node.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Deserialize;
use serde_json::{Value, json};

use super::limits::{DEFAULT_MAX_SOURCES, Limiter, MAX_SOURCES, Source, SourceConfig, SourceTable};
use super::{CompileCx, Flow, Kind, RequestCx, Stage, state};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::table::CompiledApp;
use podgate_model::Declared;

/// Largest `average`: at a period of one second a token takes 100 ns, so rounding the time per
/// token up to a nanosecond moves the rate by at most one percent.
const MAX_AVERAGE: u32 = 10_000_000;

/// Longest `period_secs`.
const MAX_PERIOD_SECS: u32 = 86_400;

const NANOS: u64 = 1_000_000_000;

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: nothing limits the route.
    pub const REMOVED: &str = "rate_limit_removed";
    /// More requests pass: a higher rate or a bigger burst.
    pub const LOOSENED: &str = "rate_limit_loosened";
    /// Requests are counted per another source, which can let a client leave its bucket.
    pub const SOURCE_CHANGED: &str = "rate_limit_source_changed";
}

/// The configuration of a `rate_limit` middleware.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    average: u32,
    #[serde(default)]
    period_secs: Option<u32>,
    burst: u32,
    source: SourceConfig,
    #[serde(default)]
    max_sources: Option<u32>,
}

/// The bucket arithmetic, in nanoseconds on a caller-supplied clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rate {
    /// Time per token.
    interval_ns: u64,
    /// Time to refill an empty bucket: `burst` tokens.
    burst_ns: u64,
}

impl Rate {
    fn new(average: u32, period_secs: u32, burst: u32) -> Option<Self> {
        let interval_ns = (u64::from(period_secs) * NANOS).div_ceil(u64::from(average));
        Some(Self {
            interval_ns,
            burst_ns: interval_ns.checked_mul(u64::from(burst))?,
        })
    }

    /// Takes a token from the bucket whose time-to-full is `tat`, at time `now`: the new
    /// `tat`, or how many nanoseconds until a token is there. A bucket with `tat <= now` is
    /// full.
    fn take(self, tat: u64, now: u64) -> Result<u64, u64> {
        let next = tat.max(now).saturating_add(self.interval_ns);
        let conforms_at = next.saturating_sub(self.burst_ns);
        if conforms_at <= now {
            Ok(next)
        } else {
            Err(conforms_at - now)
        }
    }
}

/// A compiled `rate_limit` middleware.
#[derive(Debug)]
pub struct RateLimit {
    average: u32,
    period_secs: u32,
    burst: u32,
    max_sources: u32,
    rate: Rate,
    source_config: SourceConfig,
    source: Source,
    fingerprint: u64,
    runtime: Arc<Limiter>,
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("rate_limit: {message}"))
}

impl RateLimit {
    pub(super) fn max_sources(&self) -> u32 {
        self.max_sources
    }

    pub(super) fn stats(&self) -> super::limits::Stats {
        self.runtime.stats()
    }

    /// Whether the source `key` may pass at `now` (nanoseconds on the limiter's clock), or
    /// the nanoseconds until it may.
    fn check(&self, table: &SourceTable, key: u64, now: u64) -> Result<(), u64> {
        let rate = self.rate;
        let outcome = table.with(
            key,
            |tat| tat <= now,
            |tat| rate.take(*tat, now).map(|next| *tat = next),
        );
        if let Some(outcome) = outcome {
            return outcome;
        }
        table.count_overflow();
        table
            .overflow()
            .try_update(Ordering::AcqRel, Ordering::Acquire, |tat| {
                rate.take(tat, now).ok()
            })
            .map(drop)
            .map_err(|tat| rate.take(tat, now).err().unwrap_or(rate.interval_ns))
    }

    /// Whether `new` lets more requests through than `self`.
    fn loosened_by(&self, new: &Self) -> bool {
        let per_second = |average: u32, period: u32| u64::from(average) * u64::from(period);
        // average/period compared as a cross product: new.average / new.period > old.average / old.period.
        per_second(new.average, self.period_secs) > per_second(self.average, new.period_secs)
            || new.burst > self.burst
    }
}

impl Kind for RateLimit {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        if config.average == 0 {
            return Err(invalid(
                "`average` must be at least 1; a limiter that limits nothing is a mistake",
            ));
        }
        if config.average > MAX_AVERAGE {
            return Err(invalid(format!("`average` is more than {MAX_AVERAGE}")));
        }
        let period_secs = config.period_secs.unwrap_or(1);
        if !(1..=MAX_PERIOD_SECS).contains(&period_secs) {
            return Err(invalid(format!(
                "`period_secs` must be 1 to {MAX_PERIOD_SECS}"
            )));
        }
        if config.burst == 0 {
            return Err(invalid("`burst` must be at least 1"));
        }
        let rate = Rate::new(config.average, period_secs, config.burst)
            .ok_or_else(|| invalid("`burst` is too large for this rate"))?;
        let max_sources = config.max_sources.unwrap_or(DEFAULT_MAX_SOURCES);
        if !(1..=MAX_SOURCES).contains(&max_sources) {
            return Err(invalid(format!("`max_sources` must be 1 to {MAX_SOURCES}")));
        }
        let source = Source::compile(&config.source).map_err(invalid)?;
        Ok(Self {
            average: config.average,
            period_secs,
            burst: config.burst,
            max_sources,
            rate,
            source_config: config.source,
            source,
            fingerprint: state::fingerprint(declared),
            runtime: Arc::new(Limiter::new(max_sources)),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let refusal = match self.runtime.table(cx.tenant) {
            None => Some(AppError::LimiterBusy),
            Some(table) => {
                let key =
                    self.source
                        .key(self.runtime.hasher(), cx.session.req_header(), cx.forwarded);
                match self.check(table, key, self.runtime.now_ns()) {
                    Ok(()) => None,
                    Err(wait_ns) => Some(AppError::RateLimited {
                        retry_after_secs: u32::try_from(wait_ns.div_ceil(NANOS).max(1))
                            .unwrap_or(u32::MAX),
                    }),
                }
            }
        };
        let Some(refusal) = refusal else {
            return Ok(Flow::Continue);
        };
        self.runtime.count_rejected();
        *cx.capacity_refusal = true;
        crate::respond::write_error(cx.session, &refusal).await?;
        Ok(Flow::Respond)
    }

    /// Dropping the middleware stops limiting; a higher rate or a bigger burst lets more
    /// through; another source puts requests in other buckets.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let mut kinds = Vec::new();
        if self.loosened_by(new) {
            kinds.push(kind::LOOSENED);
        }
        if self.source_config != new.source_config {
            kinds.push(kind::SOURCE_CHANGED);
        }
        kinds
    }

    fn describe(&self) -> Value {
        json!({
            "average": self.average,
            "period_secs": self.period_secs,
            "burst": self.burst,
            "source": self.source_config.describe(),
            "max_sources": self.max_sources,
            "table_bytes": SourceTable::bytes(self.max_sources),
        })
    }
}

/// The [`Limiter`] of every `rate_limit` middleware of the live table, kept by the shared
/// [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]). A push that
/// leaves a middleware's declaration as it was keeps its buckets; a middleware whose
/// declaration changed starts with empty ones.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Limiter>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            Stage::RateLimit(limit) => Some((limit.fingerprint, &mut limit.runtime)),
            _ => None,
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const SECOND: u64 = NANOS;

    fn compiled(config: &Value) -> Result<RateLimit, Invalid> {
        let mut object = config.as_object().cloned().unwrap_or_default();
        object.insert("name".into(), json!("rl"));
        object.insert("type".into(), json!("rate_limit"));
        let declared: Declared = serde_json::from_value(Value::Object(object)).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        RateLimit::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    fn limit(average: u32, period_secs: u32, burst: u32) -> RateLimit {
        compiled(&json!({
            "average": average, "period_secs": period_secs, "burst": burst,
            "source": {"ip": {}}, "max_sources": 8,
        }))
        .expect("valid")
    }

    /// A table the test charges nothing for.
    fn table_of(limit: &RateLimit) -> &SourceTable {
        limit.runtime.table(None).expect("allocates")
    }

    #[test]
    fn rate_limit_token_bucket_math() {
        let limit = limit(10, 1, 5);
        let table = table_of(&limit);
        let start = 10 * SECOND;
        for taken in 0..5 {
            assert_eq!(
                limit.check(table, 1, start),
                Ok(()),
                "token {taken} of the burst"
            );
        }
        assert_eq!(
            limit.check(table, 1, start),
            Err(SECOND / 10),
            "empty: the next token is one interval away"
        );
        assert_eq!(
            limit.check(table, 1, start + SECOND / 10 - 1),
            Err(1),
            "one nanosecond short"
        );
        assert_eq!(
            limit.check(table, 1, start + SECOND / 10),
            Ok(()),
            "one token refilled"
        );
        assert_eq!(limit.check(table, 1, start + SECOND / 10), Err(SECOND / 10));
        let later = start + SECOND / 10 + SECOND / 2;
        for taken in 0..5 {
            assert_eq!(
                limit.check(table, 1, later),
                Ok(()),
                "half a second refills 5: {taken}"
            );
        }
        assert_eq!(limit.check(table, 1, later), Err(SECOND / 10));
        let full = later + 10 * SECOND;
        for taken in 0..5 {
            assert_eq!(
                limit.check(table, 1, full),
                Ok(()),
                "never more than burst: {taken}"
            );
        }
        assert!(limit.check(table, 1, full).is_err());
    }

    #[test]
    fn rate_limit_period_secs_stretches_the_refill() {
        let limit = limit(2, 10, 1);
        let table = table_of(&limit);
        assert_eq!(limit.check(table, 1, SECOND), Ok(()));
        assert_eq!(limit.check(table, 1, SECOND), Err(5 * SECOND));
        assert_eq!(limit.check(table, 1, 6 * SECOND - 1), Err(1));
        assert_eq!(limit.check(table, 1, 6 * SECOND), Ok(()));
    }

    #[test]
    fn rate_limit_sources_have_their_own_buckets() {
        let limit = limit(1, 1, 1);
        let table = table_of(&limit);
        assert_eq!(limit.check(table, 1, SECOND), Ok(()));
        assert!(limit.check(table, 1, SECOND).is_err());
        assert_eq!(
            limit.check(table, 2, SECOND),
            Ok(()),
            "another source is unaffected"
        );
    }

    #[test]
    fn rate_limit_max_sources_overflow_shared() {
        let limit = compiled(&json!({
            "average": 1, "burst": 1, "source": {"ip": {}}, "max_sources": 2,
        }))
        .expect("valid");
        let table = table_of(&limit);
        assert_eq!(limit.check(table, 1, SECOND), Ok(()));
        assert_eq!(limit.check(table, 2, SECOND), Ok(()));
        assert_eq!(
            limit.check(table, 3, SECOND),
            Ok(()),
            "the first source without an entry takes the overflow bucket's one token"
        );
        assert!(
            limit.check(table, 4, SECOND).is_err(),
            "every other source without an entry shares that bucket"
        );
        assert!(limit.check(table, 5, SECOND).is_err());
        assert!(
            limit.check(table, 1, SECOND).is_err(),
            "sources with an entry keep theirs"
        );
        assert_eq!(table.overflowed(), 3);
    }

    #[test]
    fn rate_limit_idle_entries_are_reclaimed() {
        let limit = compiled(&json!({
            "average": 1, "burst": 1, "source": {"ip": {}}, "max_sources": 1,
        }))
        .expect("valid");
        let table = table_of(&limit);
        assert_eq!(limit.check(table, 1, SECOND), Ok(()));
        assert_eq!(
            limit.check(table, 2, SECOND),
            Ok(()),
            "source 1's entry is live: 2 uses the overflow"
        );
        assert_eq!(
            limit.check(table, 3, 3 * SECOND),
            Ok(()),
            "source 1's bucket is full again, so its entry is free"
        );
        assert!(
            limit.check(table, 3, 3 * SECOND).is_err(),
            "and 3 has it now"
        );
    }

    #[test]
    fn invalid_configs_are_invalid_middleware() {
        let ok = json!({"average": 1, "burst": 1, "source": {"ip": {}}});
        let with = |key: &str, value: Value| {
            let mut config = ok.clone();
            config[key] = value;
            config
        };
        for config in [
            with("average", json!(0)),
            with("average", json!(MAX_AVERAGE + 1)),
            with("average", json!(-1)),
            with("average", json!(1.5)),
            with("burst", json!(0)),
            with("period_secs", json!(0)),
            with("period_secs", json!(MAX_PERIOD_SECS + 1)),
            with("max_sources", json!(0)),
            with("max_sources", json!(MAX_SOURCES + 1)),
            with("source", json!({"header": "bad name"})),
            with("source", json!({"host": false})),
            with("source", json!({"cookie": "a"})),
            with("source", json!({"ip": {"depth": 0}})),
            with("source", json!({"ip": {}, "host": true})),
            with("sourceCriterion", json!({})),
            json!({"average": 1, "source": {"ip": {}}}),
            json!({"average": 1, "burst": 1}),
            json!({"average": 1, "burst": u32::MAX, "period_secs": MAX_PERIOD_SECS, "source": {"ip": {}}}),
        ] {
            let err = compiled(&config).expect_err(&config.to_string());
            assert_eq!(err.code, "invalid_middleware", "{config}");
        }
        assert!(compiled(&ok).is_ok());
        assert!(compiled(&with("source", json!({"header": "x-api-key"}))).is_ok());
        assert!(compiled(&with("source", json!({"host": true}))).is_ok());
    }

    #[test]
    fn posture_lists_removal_loosening_and_another_source() {
        let base = limit(10, 1, 5);
        let source = |source: Value| {
            compiled(&json!({"average": 10, "burst": 5, "source": source})).expect("valid")
        };
        assert_eq!(base.posture(None), [kind::REMOVED]);
        assert!(base.posture(Some(&limit(10, 1, 5))).is_empty());
        assert!(base.posture(Some(&limit(5, 1, 5))).is_empty(), "stricter");
        assert!(
            base.posture(Some(&limit(10, 1, 4))).is_empty(),
            "smaller burst"
        );
        assert_eq!(base.posture(Some(&limit(11, 1, 5))), [kind::LOOSENED]);
        assert_eq!(base.posture(Some(&limit(10, 1, 6))), [kind::LOOSENED]);
        assert_eq!(
            base.posture(Some(&limit(10, 2, 5))),
            Vec::<&str>::new(),
            "the same average over a longer period is stricter"
        );
        assert_eq!(
            base.posture(Some(&limit(20, 2, 5))),
            Vec::<&str>::new(),
            "the same rate"
        );
        assert_eq!(
            source(json!({"ip": {}})).posture(Some(&source(json!({"host": true})))),
            [kind::SOURCE_CHANGED]
        );
        assert_eq!(
            source(json!({"ip": {}})).posture(Some(&source(json!({"ip": {"depth": 2}})))),
            [kind::SOURCE_CHANGED]
        );
    }
}
