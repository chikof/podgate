//! The cluster scope of `rate_limit`: the bucket lives in a shared store, so all nodes count
//! one limit. Reference: `docs/ref/ratelimit-cluster.md`; the store client is
//! [`crate::ratelimit_store`].
//!
//! ```json
//! { "name": "rl", "type": "rate_limit", "average": 100, "burst": 200, "source": {"ip": {}},
//!   "scope": "cluster", "store": "main", "on_store_error": "allow",
//!   "local_fallback": {"average": 25, "burst": 50}, "store_timeout_ms": 20 }
//! ```
//!
//! - `scope: "cluster"` needs `store` (a name from `RATE_LIMIT_STORES_FILE`, usable by the
//!   app's tenant) and `on_store_error`. `allow` needs `local_fallback`; `deny` refuses it.
//!   Nothing is ignored: the cluster fields on a node-scope limit are `invalid_middleware`.
//! - A request first takes a token from the node-local bucket (a cheap pre-filter configured
//!   with the cluster limit, so a source that is clearly over it never reaches the store), then
//!   from the store's bucket, one round trip.
//! - The store key is `podgate:rl:<tenant>:<app>:<middleware>:<fingerprint>:<source>`: tenant,
//!   app and middleware are percent-escaped (`:` and `%`) so two tenants can never build the
//!   same key, the fingerprint is the declaration's digest so a changed limit starts fresh
//!   counters, and the source is the first 16 bytes of the SHA-256 of what identifies it, so
//!   no address or header value reaches the store.
//! - A store error (down, slow, saturated, an error reply) is not a verdict. `allow` admits the
//!   request only if the local fallback bucket allows it, `429` otherwise; `deny` answers
//!   `503 {"error":"rate limiter unavailable"}` with `retry-after: 1`.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Config, MAX_AVERAGE, NANOS, Rate, RateLimit, check_in, invalid};
use crate::compile::{Invalid, Rejected};
use crate::error::AppError;
use crate::middleware::limits::{Limiter, Stats};
use crate::middleware::{Named, RequestCx, Stage};
use crate::ratelimit_store::{Gcra, MAX_TIMEOUT_MS, Mode, StoreError, Stores, Verdict};
use podgate_model::{App, Snapshot};

/// The largest time to refill an empty bucket, in microseconds: the script does its arithmetic
/// in doubles, which count integers exactly up to 2^53.
const MAX_BURST_US: u64 = 1 << 52;

/// Where a limit counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum Scope {
    /// This node alone (the default).
    Node,
    /// Every node that shares the store.
    Cluster,
}

/// What a request does when the store gives no verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum OnStoreError {
    /// Admit it if the local fallback bucket allows it.
    Allow,
    /// Refuse it with `503`.
    Deny,
}

/// The limit a node applies alone while its store is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct FallbackConfig {
    average: u32,
    burst: u32,
}

/// The node-local bucket of the allow mode.
#[derive(Debug)]
struct Fallback {
    config: FallbackConfig,
    rate: Rate,
    runtime: Arc<Limiter>,
}

#[derive(Debug)]
enum OnError {
    Allow(Fallback),
    Deny,
}

/// A compiled cluster scope.
#[derive(Debug)]
pub(super) struct Cluster {
    store: Box<str>,
    on_error: OnError,
    timeout: Option<Duration>,
    key_prefix: Box<str>,
    gcra: Gcra,
}

/// `text` with `%` and `:` escaped, so a key's parts cannot run into each other.
fn escaped(text: &str) -> String {
    text.replace('%', "%25").replace(':', "%3A")
}

/// The bucket in microseconds, rounded so the rate is never more than configured.
fn gcra(average: u32, period_secs: u32, burst: u32) -> Option<Gcra> {
    let interval_us = (u64::from(period_secs) * 1_000_000).div_ceil(u64::from(average));
    let burst_us = interval_us
        .checked_mul(u64::from(burst))
        .filter(|burst_us| *burst_us <= MAX_BURST_US)?;
    Some(Gcra {
        interval_us,
        burst_us,
    })
}

fn retry_after_secs(micros: u64) -> u32 {
    u32::try_from(micros.div_ceil(1_000_000).max(1)).unwrap_or(u32::MAX)
}

impl Cluster {
    /// Validates the cluster fields of `config`; `None` for a node-scope limit.
    pub(super) fn compile(
        config: &Config,
        name: &str,
        fingerprint: u64,
        app: &App,
        period_secs: u32,
        max_sources: u32,
    ) -> Result<Option<Self>, Invalid> {
        let has_cluster_field = config.store.is_some()
            || config.on_store_error.is_some()
            || config.local_fallback.is_some()
            || config.store_timeout_ms.is_some();
        if config.scope.unwrap_or(Scope::Node) == Scope::Node {
            return if has_cluster_field {
                Err(invalid(
                    "`store`, `on_store_error`, `local_fallback` and `store_timeout_ms` need `scope: \"cluster\"`; a limit never ignores a setting",
                ))
            } else {
                Ok(None)
            };
        }
        let store = config
            .store
            .as_deref()
            .filter(|store| !store.is_empty())
            .ok_or_else(|| invalid("`scope: \"cluster\"` needs `store`, the name of a store"))?;
        let on_error = match (config.on_store_error, config.local_fallback) {
            (None, _) => {
                return Err(invalid(
                    "`scope: \"cluster\"` needs `on_store_error`: `allow` (with a `local_fallback`) or `deny`; failing open without a local limit removes the protection exactly when something is wrong, and failing closed turns a store outage into a site outage, so there is no default",
                ));
            }
            (Some(OnStoreError::Allow), None) => {
                return Err(invalid(
                    "`on_store_error: \"allow\"` needs `local_fallback {average, burst}`, the limit this node applies alone while the store is unavailable (the cluster limit divided by the number of nodes)",
                ));
            }
            (Some(OnStoreError::Deny), Some(_)) => {
                return Err(invalid(
                    "`local_fallback` is only used with `on_store_error: \"allow\"`",
                ));
            }
            (Some(OnStoreError::Deny), None) => OnError::Deny,
            (Some(OnStoreError::Allow), Some(local)) => {
                if !(1..=MAX_AVERAGE).contains(&local.average) {
                    return Err(invalid(format!(
                        "`local_fallback.average` must be 1 to {MAX_AVERAGE}"
                    )));
                }
                if local.burst == 0 {
                    return Err(invalid("`local_fallback.burst` must be at least 1"));
                }
                let rate = Rate::new(local.average, period_secs, local.burst)
                    .ok_or_else(|| invalid("`local_fallback.burst` is too large for its rate"))?;
                OnError::Allow(Fallback {
                    config: local,
                    rate,
                    runtime: Arc::new(Limiter::new(max_sources)),
                })
            }
        };
        if let Some(timeout_ms) = config.store_timeout_ms
            && !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms)
        {
            return Err(invalid(format!(
                "`store_timeout_ms` must be 1 to {MAX_TIMEOUT_MS}"
            )));
        }
        let gcra = gcra(config.average, period_secs, config.burst).ok_or_else(|| {
            invalid(
                "`burst` is too large for this rate in a store, whose clock counts microseconds",
            )
        })?;
        Ok(Some(Self {
            store: store.into(),
            on_error,
            timeout: config
                .store_timeout_ms
                .map(|millis| Duration::from_millis(u64::from(millis))),
            key_prefix: format!(
                "podgate:rl:{}:{}:{}:{fingerprint:016x}:",
                escaped(&app.tenant),
                escaped(&app.id),
                escaped(name)
            )
            .into(),
            gcra,
        }))
    }

    fn mode(&self) -> Mode {
        match self.on_error {
            OnError::Allow(_) => Mode::Allow,
            OnError::Deny => Mode::Deny,
        }
    }

    /// Whether a store error admits requests.
    pub(super) fn fails_open(&self) -> bool {
        matches!(self.on_error, OnError::Allow(_))
    }

    /// Allocates the fallback's table now, so a store outage does not meet an allocation that
    /// fails. `false` when the tenant's budget cannot take it right now.
    pub(super) fn allocate(&self, tenant: Option<&Arc<crate::budget::TenantBudget>>) -> bool {
        match &self.on_error {
            OnError::Allow(fallback) => fallback.runtime.table(tenant).is_some(),
            OnError::Deny => true,
        }
    }

    /// The fallback's runtime state, for [`crate::middleware::state::Registry`].
    pub(super) fn fallback_runtime(&mut self) -> Option<&mut Arc<Limiter>> {
        match &mut self.on_error {
            OnError::Allow(fallback) => Some(&mut fallback.runtime),
            OnError::Deny => None,
        }
    }

    /// What the fallback limiter reports.
    pub(super) fn fallback_stats(&self) -> Option<Stats> {
        match &self.on_error {
            OnError::Allow(fallback) => Some(fallback.runtime.stats()),
            OnError::Deny => None,
        }
    }

    /// Whether `new`'s fallback lets more through than `self`'s: both fail open, and the new
    /// one has a higher rate (compared over their own periods) or a bigger burst.
    pub(super) fn fallback_loosened_by(
        &self,
        period_secs: u32,
        new: &Self,
        new_period_secs: u32,
    ) -> bool {
        let (OnError::Allow(old), OnError::Allow(new)) = (&self.on_error, &new.on_error) else {
            return false;
        };
        u64::from(new.config.average) * u64::from(period_secs)
            > u64::from(old.config.average) * u64::from(new_period_secs)
            || new.config.burst > old.config.burst
    }

    /// What explain shows.
    pub(super) fn describe(&self) -> Value {
        let mut shown = json!({
            "scope": "cluster",
            "store": self.store,
            "on_store_error": match self.on_error {
                OnError::Allow(_) => "allow",
                OnError::Deny => "deny",
            },
            "store_timeout_ms": self.timeout.map(|timeout| timeout.as_millis()),
        });
        if let (OnError::Allow(fallback), Some(object)) = (&self.on_error, shown.as_object_mut()) {
            object.insert(
                "local_fallback".to_owned(),
                json!({"average": fallback.config.average, "burst": fallback.config.burst}),
            );
        }
        shown
    }

    /// The store's key for the source of the request in `cx`.
    fn key(&self, limit: &RateLimit, cx: &RequestCx<'_>) -> String {
        let digest =
            limit
                .source
                .with_material(cx.session.req_header(), cx.forwarded, |material| {
                    Sha256::digest(material)
                });
        let mut key = String::with_capacity(self.key_prefix.len() + 32);
        key.push_str(&self.key_prefix);
        for byte in &digest[..16] {
            // Writing to a `String` cannot fail.
            let _ = write!(key, "{byte:02x}");
        }
        key
    }

    /// Decides a request that passed the node-local pre-filter.
    ///
    /// # Errors
    ///
    /// The refusal to answer with: `429` over the limit, or what the store error mode says.
    pub(super) async fn admit(
        &self,
        limit: &RateLimit,
        cx: &mut RequestCx<'_>,
    ) -> Result<(), AppError> {
        let Some(store) = cx.stores.get(&self.store) else {
            // The compiler checked the name against the same stores: this cannot be reached.
            return self.on_store_error(limit, cx, None);
        };
        let key = self.key(limit, cx);
        match store
            .gcra(cx.app.tenant(), &key, self.gcra, self.timeout)
            .await
        {
            Ok(Verdict::Allowed) => Ok(()),
            Ok(Verdict::Limited { retry_after_us }) => Err(AppError::RateLimited {
                retry_after_secs: retry_after_secs(retry_after_us),
            }),
            Err(error) => self.on_store_error(limit, cx, Some((store, &error))),
        }
    }

    fn on_store_error(
        &self,
        limit: &RateLimit,
        cx: &mut RequestCx<'_>,
        store: Option<(&crate::ratelimit_store::Store, &StoreError)>,
    ) -> Result<(), AppError> {
        if let Some((store, error)) = store {
            store.count_error(self.mode());
            tracing::debug!(store = store.name(), %error, "rate limit store error");
        }
        let refusal = match &self.on_error {
            OnError::Deny => AppError::RateLimiterUnavailable,
            OnError::Allow(fallback) => {
                let Some(table) = fallback.runtime.table(cx.tenant) else {
                    return Err(AppError::LimiterBusy);
                };
                let key = limit.source.key(
                    fallback.runtime.hasher(),
                    cx.session.req_header(),
                    cx.forwarded,
                );
                match check_in(fallback.rate, table, key, fallback.runtime.now_ns()) {
                    Ok(()) => return Ok(()),
                    Err(wait_ns) => AppError::RateLimited {
                        retry_after_secs: u32::try_from(wait_ns.div_ceil(NANOS).max(1))
                            .unwrap_or(u32::MAX),
                    },
                }
            }
        };
        *cx.reason = Some(refusal.log_reason());
        Err(refusal)
    }
}

/// Refuses the cluster-scope limits whose store the tenant may not use. A store that does not
/// exist and one the tenant is not listed for give the same answer, so a tenant cannot find out
/// which stores other tenants use.
pub(crate) fn check_snapshot(
    snapshot: &Snapshot,
    stages: &[&[Named]],
    stores: &Stores,
) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    for (app, stages) in snapshot.apps.iter().zip(stages) {
        for named in *stages {
            let Stage::RateLimit(limit) = &named.stage else {
                continue;
            };
            let Some(cluster) = &limit.cluster else {
                continue;
            };
            if !stores.allows(&cluster.store, &app.tenant) {
                rejected.push(Rejected::new(
                    app,
                    format!("middleware {}", named.name),
                    invalid(format!(
                        "store {:?} is not available to tenant {}; stores are listed in the operator's RATE_LIMIT_STORES_FILE",
                        cluster.store, app.tenant
                    )),
                ));
            }
        }
    }
    rejected
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn key_parts_cannot_run_into_each_other() {
        assert_eq!(escaped("a:b%c"), "a%3Ab%25c");
        assert_ne!(
            format!("{}:{}", escaped("a:b"), escaped("c")),
            format!("{}:{}", escaped("a"), escaped("b:c")),
        );
    }

    #[test]
    fn the_bucket_is_never_looser_than_configured() {
        let bucket = gcra(3, 1, 5).expect("fits");
        assert_eq!(
            bucket.interval_us, 333_334,
            "a third of a second, rounded up"
        );
        assert_eq!(bucket.burst_us, 5 * 333_334);
        assert_eq!(gcra(MAX_AVERAGE, 1, 1).expect("fits").interval_us, 1);
        assert!(
            gcra(1, 86_400, u32::MAX).is_none(),
            "more than the script counts exactly"
        );
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        assert_eq!(retry_after_secs(0), 1);
        assert_eq!(retry_after_secs(1), 1);
        assert_eq!(retry_after_secs(1_000_001), 2);
    }
}
