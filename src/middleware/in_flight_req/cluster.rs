//! The cluster scope of `in_flight_req`: the slots live in a shared store, so all nodes count
//! one limit. Reference: `docs/ref/inflight-cluster.md`; the store client is
//! [`crate::ratelimit_store`].
//!
//! ```json
//! { "name": "cap", "type": "in_flight_req", "amount": 100, "source": {"header": "x-api-key"},
//!   "scope": "cluster", "store": "main", "on_store_error": "allow",
//!   "local_fallback": {"amount": 25}, "lease_secs": 60 }
//! ```
//!
//! - `scope: "cluster"` needs `store` (a name from `RATE_LIMIT_STORES_FILE`, usable by the
//!   app's tenant) and `on_store_error`. `allow` needs `local_fallback`; `deny` refuses it.
//!   Nothing is ignored: the cluster fields on a node-scope limit are `invalid_middleware`.
//! - A slot is a member of a sorted set in the store, scored by its lease deadline on the
//!   store's clock. Taking one removes the members whose deadline has passed and adds a member
//!   only if fewer than `amount` are left, in one script call, so the set never holds more than
//!   `amount` members. Returning it removes the member. A request that outlives half its lease
//!   extends it, and a node that dies leaks its slots only until their deadlines.
//! - The node counts its own requests as well, in the table the node scope uses, and always:
//!   that count is what limits requests while the store gives no verdict.
//! - A store error is not a verdict. `allow` admits the request only if the node's own count
//!   is under `local_fallback.amount`, `429` otherwise; `deny` answers
//!   `503 {"error":"rate limiter unavailable"}` with `retry-after: 1`.

use std::fmt::Write as _;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;

use super::{Config, InFlightReq, invalid};
use crate::compile::{Invalid, Rejected};
use crate::error::AppError;
use crate::middleware::limits::{Permit, SourceTable};
use crate::middleware::{Named, RequestCx, Stage};
use crate::ratelimit_store::{Mode, Script, Store, StoreError, Stores};
use podgate_model::{App, Snapshot};

/// Most `amount` of a cluster-scope limit: the set holds that many members, so this bounds what
/// one key takes in the store.
const MAX_AMOUNT: u32 = 10_000;

/// The seconds a lease lasts when `lease_secs` is not set.
const DEFAULT_LEASE_SECS: u32 = 60;

/// The seconds a lease may last: long enough that renewing it twice per lease is a trickle of
/// calls, short enough that a crashed node's slots come back soon.
const LEASE_SECS: RangeInclusive<u32> = 10..=3600;

/// Takes a slot. `ARGV[1]` is `amount`, `ARGV[2]` the lease in milliseconds and `ARGV[3]` the
/// request id. Returns `{1, members}` when the id was added and `{0, members}` when the set is
/// full. The store's clock sets the deadline, so nodes with skewed clocks agree; the key
/// expires with its last lease, so an idle source costs nothing.
static ACQUIRE: Script = Script::new(
    "\
if redis.replicate_commands then redis.replicate_commands() end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local held = redis.call('ZCARD', KEYS[1])
if held >= tonumber(ARGV[1]) then return {0, held} end
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[2]), ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return {1, held + 1}
",
);

/// Gives a slot back. `ARGV[1]` is the request id. Returns `{1}` when it was held.
static RELEASE: Script = Script::new("return {redis.call('ZREM', KEYS[1], ARGV[1])}");

/// Extends a slot that is still held. `ARGV[1]` is the lease in milliseconds and `ARGV[2]` the
/// request id. Returns `{1}` when it was extended and `{0}` when the lease was gone (it ran
/// out): the slot is never added again, so a renewal that reaches the store after the release
/// cannot bring it back.
static RENEW: Script = Script::new(
    "\
if redis.replicate_commands then redis.replicate_commands() end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if not redis.call('ZSCORE', KEYS[1], ARGV[2]) then return {0} end
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[1]), ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return {1}
",
);

/// Leases extended, for `podgate_inflight_lease_renewals_total`.
static RENEWALS: AtomicU64 = AtomicU64::new(0);

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
    /// Admit it if the node's own count is under the local fallback.
    Allow,
    /// Refuse it with `503`.
    Deny,
}

/// The cap a node applies alone while its store is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct FallbackConfig {
    amount: u32,
}

#[derive(Debug, Clone, Copy)]
enum OnError {
    /// Admit while the node holds fewer than this many.
    Allow {
        fallback: u32,
    },
    Deny,
}

/// A compiled cluster scope.
#[derive(Debug)]
pub(super) struct Cluster {
    store: Box<str>,
    on_error: OnError,
    lease_secs: u32,
    /// The lease in milliseconds, as the scripts take it.
    lease_ms: Box<str>,
    amount: Box<str>,
    key_prefix: Box<str>,
}

/// `text` with `%` and `:` escaped, so a key's parts cannot run into each other.
fn escaped(text: &str) -> String {
    text.replace('%', "%25").replace(':', "%3A")
}

/// A random 128-bit id in hex, or `None` when the system has no randomness.
fn request_id() -> Option<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(id, "{byte:02x}");
    }
    Some(id)
}

impl Cluster {
    /// Validates the cluster fields of `config`; `None` for a node-scope limit.
    pub(super) fn compile(
        config: &Config,
        name: &str,
        fingerprint: u64,
        app: &App,
    ) -> Result<Option<Self>, Invalid> {
        let has_cluster_field = config.store.is_some()
            || config.on_store_error.is_some()
            || config.local_fallback.is_some()
            || config.lease_secs.is_some();
        if config.scope.unwrap_or(Scope::Node) == Scope::Node {
            return if has_cluster_field {
                Err(invalid(
                    "`store`, `on_store_error`, `local_fallback` and `lease_secs` need `scope: \"cluster\"`; a limit never ignores a setting",
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
        if config.amount > MAX_AMOUNT {
            return Err(invalid(format!(
                "`amount` of a cluster-scope limit is at most {MAX_AMOUNT}: every slot is a member of a set in the store"
            )));
        }
        let on_error = match (config.on_store_error, config.local_fallback) {
            (None, _) => {
                return Err(invalid(
                    "`scope: \"cluster\"` needs `on_store_error`: `allow` (with a `local_fallback`) or `deny`; failing open without a local cap removes the protection exactly when something is wrong, and failing closed turns a store outage into a site outage, so there is no default",
                ));
            }
            (Some(OnStoreError::Allow), None) => {
                return Err(invalid(
                    "`on_store_error: \"allow\"` needs `local_fallback {amount}`, the cap this node applies alone while the store is unavailable (the cluster `amount` divided by the number of nodes)",
                ));
            }
            (Some(OnStoreError::Deny), Some(_)) => {
                return Err(invalid(
                    "`local_fallback` is only used with `on_store_error: \"allow\"`",
                ));
            }
            (Some(OnStoreError::Deny), None) => OnError::Deny,
            (Some(OnStoreError::Allow), Some(local)) => {
                if !(1..=MAX_AMOUNT).contains(&local.amount) {
                    return Err(invalid(format!(
                        "`local_fallback.amount` must be 1 to {MAX_AMOUNT}"
                    )));
                }
                OnError::Allow {
                    fallback: local.amount,
                }
            }
        };
        let lease_secs = config.lease_secs.unwrap_or(DEFAULT_LEASE_SECS);
        if !LEASE_SECS.contains(&lease_secs) {
            return Err(invalid(format!(
                "`lease_secs` must be {} to {}",
                LEASE_SECS.start(),
                LEASE_SECS.end()
            )));
        }
        Ok(Some(Self {
            store: store.into(),
            on_error,
            lease_secs,
            lease_ms: (u64::from(lease_secs) * 1000).to_string().into(),
            amount: config.amount.to_string().into(),
            key_prefix: format!(
                "podgate:ifr:{}:{}:{}:{fingerprint:016x}:",
                escaped(&app.tenant),
                escaped(&app.id),
                escaped(name)
            )
            .into(),
        }))
    }

    fn mode(&self) -> Mode {
        match self.on_error {
            OnError::Allow { .. } => Mode::Allow,
            OnError::Deny => Mode::Deny,
        }
    }

    /// Whether a store error admits requests.
    pub(super) fn fails_open(&self) -> bool {
        matches!(self.on_error, OnError::Allow { .. })
    }

    /// Whether `new` lets a node alone hold more than `self` while the store is down: both fail
    /// open, and the new fallback is higher.
    pub(super) fn fallback_loosened_by(&self, new: &Self) -> bool {
        match (self.on_error, new.on_error) {
            (OnError::Allow { fallback: old }, OnError::Allow { fallback: new }) => new > old,
            _ => false,
        }
    }

    /// What explain shows.
    pub(super) fn describe(&self) -> Value {
        let mut shown = json!({
            "scope": "cluster",
            "store": self.store,
            "on_store_error": match self.on_error {
                OnError::Allow { .. } => "allow",
                OnError::Deny => "deny",
            },
            "lease_secs": self.lease_secs,
        });
        if let (OnError::Allow { fallback }, Some(object)) = (self.on_error, shown.as_object_mut())
        {
            object.insert("local_fallback".to_owned(), json!({"amount": fallback}));
        }
        shown
    }

    /// The store's key for the source of the request in `cx`.
    fn key(&self, cap: &InFlightReq, cx: &RequestCx<'_>) -> String {
        let digest = cap
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

    /// Takes a slot for the request in `cx`: in the store, and in the node's own count
    /// (`table`, entry `source`), which the request holds until it ends.
    ///
    /// # Errors
    ///
    /// The refusal to answer with: `429` when the source holds `amount` slots in the cluster
    /// (or, with the store down, the fallback in this node), or what the store error mode says.
    pub(super) async fn admit(
        &self,
        cap: &InFlightReq,
        cx: &mut RequestCx<'_>,
        table: &SourceTable,
        source: u64,
    ) -> Result<(Permit, Option<Lease>), AppError> {
        let tenant = cx.app.tenant();
        let (Some(store), Some(id)) = (cx.stores.get(&self.store), request_id()) else {
            // The compiler checked the name against the same stores, so this is a system
            // without randomness.
            return self.on_store_error(cap, cx, table, source, None);
        };
        store.note_inflight_use();
        let key = self.key(cap, cx);
        let answer = store
            .run(
                tenant,
                &ACQUIRE,
                &key,
                &[&self.amount, &self.lease_ms, &id],
                None,
            )
            .await;
        match answer.as_ref().map(Vec::as_slice) {
            Ok([1, _]) => {
                let lease = Lease::new(
                    Held {
                        store: Arc::clone(store),
                        tenant: tenant.into(),
                        key,
                        id,
                        lease_ms: self.lease_ms.clone(),
                    },
                    Duration::from_secs(u64::from(self.lease_secs) / 2),
                );
                // Never refused: the count is kept whatever it is, an outage needs it.
                let permit = cap
                    .runtime
                    .acquire(table, source, u32::MAX)
                    .ok_or(AppError::LimiterBusy)?;
                Ok((permit, Some(lease)))
            }
            Ok([0, _]) => Err(AppError::TooManyInFlight),
            Ok(_) => self.on_store_error(
                cap,
                cx,
                table,
                source,
                Some((store, &StoreError::Unexpected)),
            ),
            Err(error) => self.on_store_error(cap, cx, table, source, Some((store, error))),
        }
    }

    fn on_store_error(
        &self,
        cap: &InFlightReq,
        cx: &mut RequestCx<'_>,
        table: &SourceTable,
        source: u64,
        failed: Option<(&Arc<Store>, &StoreError)>,
    ) -> Result<(Permit, Option<Lease>), AppError> {
        if let Some((store, error)) = failed {
            store.count_inflight_error(self.mode());
            tracing::debug!(store = store.name(), %error, "in-flight limit store error");
        }
        let refusal = match self.on_error {
            OnError::Deny => AppError::RateLimiterUnavailable,
            OnError::Allow { fallback } => {
                return cap
                    .runtime
                    .acquire(table, source, fallback)
                    .map(|permit| (permit, None))
                    .ok_or(AppError::TooManyInFlight);
            }
        };
        *cx.reason = Some(refusal.log_reason());
        Err(refusal)
    }
}

/// What a lease needs to be extended and given back, shared by the guard and its renewer.
#[derive(Debug)]
struct Held {
    store: Arc<Store>,
    tenant: Box<str>,
    key: String,
    id: String,
    lease_ms: Box<str>,
}

impl Held {
    async fn release(&self) {
        let answer = self
            .store
            .run(&self.tenant, &RELEASE, &self.key, &[&self.id], None)
            .await;
        // Not retried: the lease expires by itself.
        if let Err(error) = answer {
            tracing::debug!(store = self.store.name(), %error, "in-flight slot not returned; its lease will expire");
        }
    }

    /// Extends the lease every `every` while it is held.
    async fn renew(&self, every: Duration) {
        loop {
            tokio::time::sleep(every).await;
            let answer = self
                .store
                .run(
                    &self.tenant,
                    &RENEW,
                    &self.key,
                    &[&self.lease_ms, &self.id],
                    None,
                )
                .await;
            match answer.as_ref().map(Vec::as_slice) {
                Ok([1]) => {
                    RENEWALS.fetch_add(1, Ordering::Relaxed);
                }
                Ok(_) => {
                    tracing::debug!(
                        store = self.store.name(),
                        "in-flight lease ran out; the request is no longer counted in the store"
                    );
                    return;
                }
                Err(error) => {
                    tracing::debug!(store = self.store.name(), %error, "in-flight lease not renewed");
                }
            }
        }
    }
}

/// One slot in the store. Dropping it, whatever ended the request, gives the slot back and stops
/// the renewals.
#[derive(Debug)]
pub(crate) struct Lease {
    held: Arc<Held>,
    renewer: JoinHandle<()>,
}

impl Lease {
    /// Holds `held`, extending it every `every`. Must run inside the runtime.
    fn new(held: Held, every: Duration) -> Self {
        let held = Arc::new(held);
        let renewing = Arc::clone(&held);
        Self {
            held,
            renewer: tokio::spawn(async move { renewing.renew(every).await }),
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.renewer.abort();
        let held = Arc::clone(&self.held);
        // Without a runtime (the process is going down) the lease expires by itself.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(async move { held.release().await }));
        }
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
            let Stage::InFlightReq(cap) = &named.stage else {
                continue;
            };
            let Some(cluster) = &cap.cluster else {
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

/// Appends `podgate_inflight_lease_renewals_total` to the metrics exposition `out`.
pub(crate) fn render(out: &mut String) {
    let name = "podgate_inflight_lease_renewals_total";
    // Writing to a `String` cannot fail.
    let _ = writeln!(
        out,
        "# HELP {name} Leases of cluster in_flight_req slots this node extended because their request outlived half the lease.\n# TYPE {name} counter\n{name} {}",
        RENEWALS.load(Ordering::Relaxed)
    );
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
    fn request_ids_are_128_bits_of_hex_and_differ() {
        let (first, second) = (request_id().expect("id"), request_id().expect("id"));
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }
}
