//! The response cache: memory only, bounded per tenant, never shared across tenants.
//! The middleware is [`crate::middleware::cache`]; the reference is `docs/ref/mw-cache.md`.
//!
//! # Layout
//!
//! - [`Cache`] (this file) is the registry the gateway and the admin API share: one store per
//!   tenant, the table of upstream fetches in flight (so concurrent misses collapse into one),
//!   and the counters behind the metrics. It outlives snapshot swaps.
//! - `store` holds a tenant's entries: LRU eviction, purge by key, prefix and tag, and the
//!   `Charge` every entry owns against the tenant's `max_buffer_bytes`.
//! - `policy` decides what may be stored, for how long and under which `Vary` variant: pure
//!   functions, no I/O.
//! - `key` is the cache key; the tenant and the app are in every one.
//! - `fill` copies a streaming response into the cache, charging every byte first.
//! - `refresh` runs a revalidation as a Pingora subrequest through the whole proxy pipeline.
//!
//! # Storage: why not `pingora-cache`
//!
//! The spike found three things `pingora-cache` cannot do without a
//! fork. Its lookup runs after `request_filter` has taken the tenant's slot and the backend's
//! admission, so a hit would still cost both. Its eviction manager and its storage are keyed
//! by a hash of the key, so entries cannot be listed by app, prefix or tag, and one manager is
//! shared by whatever storage it is given, not scoped to a tenant. Every byte must also be
//! charged to a per-tenant budget the storage trait has no place for. The store here is a
//! `HashMap` per tenant and an ordered LRU index, on `std` only.

pub(crate) mod fill;
pub(crate) mod key;
pub(crate) mod policy;
pub(crate) mod purge;
pub(crate) mod refresh;
pub(crate) mod store;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use podgate_model::RevisionState;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::budget::Escaped;
use crate::cache::key::ResourceKey;
use crate::cache::purge::{Invalid, Request, Selector};
use crate::cache::store::TenantCache;
use crate::table::RoutingTable;

/// Most requests that may wait for one upstream fetch of a key; the rest go to the upstream
/// themselves.
pub(crate) const MAX_WAITERS: u32 = 64;

/// The most a tenant's cache may be of its `max_buffer_bytes`, in percent, unless the operator
/// says otherwise (`CACHE_TENANT_MAX_PERCENT`).
pub const DEFAULT_TENANT_MAX_PERCENT: u8 = 50;

/// What a `cache` middleware may declare, known while a snapshot compiles.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// `max_buffer_bytes` of the app's tenant.
    pub tenant_budget: u64,
    /// The operator's `CACHE_TENANT_MAX_PERCENT`.
    pub max_percent: u8,
}

impl Limits {
    /// The most bytes any `cache` middleware of the tenant may take: the operator's share of
    /// the budget.
    #[must_use]
    pub fn ceiling(self) -> u64 {
        // u128: `tenant_budget * percent` could pass u64.
        u64::try_from(u128::from(self.tenant_budget) * u128::from(self.max_percent) / 100)
            .unwrap_or(u64::MAX)
    }

    /// What a middleware that sets no `max_bytes` gets: a quarter of the budget.
    #[must_use]
    pub fn default_bytes(self) -> u64 {
        (self.tenant_budget / 4).min(self.ceiling())
    }
}

/// What a fetch that other requests wait for ended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A new entry is stored.
    Stored,
    /// The origin confirmed the existing entry with a `304`.
    Revalidated,
    /// The response was not stored (uncacheable, over a limit, or the cache had no room).
    NotStored,
    /// The upstream failed: refused, reset, timed out or answered 5xx.
    Failed,
}

#[derive(Debug)]
struct Flight {
    done: watch::Sender<Option<Outcome>>,
    waiters: AtomicU32,
}

#[derive(Debug, Default)]
struct Inner {
    tenants: RwLock<HashMap<Box<str>, Arc<TenantCache>>>,
    flights: Mutex<HashMap<ResourceKey, Arc<Flight>>>,
    requests: Mutex<BTreeMap<(Box<str>, &'static str), u64>>,
    collapsed: AtomicU64,
}

/// The registry of every tenant's cache. Cheap to clone; every clone shares it.
#[derive(Debug, Clone, Default)]
pub struct Cache {
    inner: Arc<Inner>,
}

/// The right to fetch one key from the upstream: everyone else asking for it waits. Dropping it
/// wakes them with the outcome set by [`Lead::set`] (not stored, by default).
#[derive(Debug)]
pub(crate) struct Lead {
    cache: Arc<Inner>,
    key: ResourceKey,
    flight: Arc<Flight>,
    outcome: Outcome,
}

impl Lead {
    /// What the waiters are told when this lead ends.
    pub(crate) fn set(&mut self, outcome: Outcome) {
        self.outcome = outcome;
    }

    /// The key this lead fetches.
    pub(crate) fn key(&self) -> &ResourceKey {
        &self.key
    }

    /// A receiver for the end of this fetch, for the request that started it to wait on.
    pub(crate) fn watch(&self) -> Waiter {
        Waiter {
            done: self.flight.done.subscribe(),
            slot: None,
        }
    }
}

impl Drop for Lead {
    fn drop(&mut self) {
        {
            let mut flights = self
                .cache
                .flights
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if flights
                .get(&self.key)
                .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
            {
                flights.remove(&self.key);
            }
        }
        self.flight.done.send_replace(Some(self.outcome));
    }
}

/// A request waiting for the fetch another request leads.
#[derive(Debug)]
pub(crate) struct Waiter {
    done: watch::Receiver<Option<Outcome>>,
    slot: Option<Arc<Flight>>,
}

impl Waiter {
    /// Waits for the fetch to end, at most `limit`. `None` when it did not end in time.
    pub(crate) async fn wait(mut self, limit: Duration) -> Option<Outcome> {
        match timeout(limit, self.done.wait_for(Option::is_some)).await {
            Ok(Ok(outcome)) => *outcome,
            _ => None,
        }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        if let Some(flight) = &self.slot {
            flight.waiters.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// What [`Cache::claim`] decided for a request that found no usable entry.
#[derive(Debug)]
pub(crate) enum Claim {
    /// Nobody is fetching this key: the caller fetches it.
    Lead(Lead),
    /// Someone is: wait for them.
    Follow(Waiter),
    /// Someone is, and [`MAX_WAITERS`] requests are already waiting: go to the upstream alone.
    Crowded,
}

impl Cache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The store of tenant `id`, created on first use.
    pub(crate) fn tenant(&self, id: &str) -> Arc<TenantCache> {
        if let Some(found) = self
            .inner
            .tenants
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
        {
            return Arc::clone(found);
        }
        let mut tenants = self
            .inner
            .tenants
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(tenants.entry(id.into()).or_default())
    }

    /// Decides who fetches `key`: the first caller leads, later ones wait, up to
    /// [`MAX_WAITERS`] of them.
    pub(crate) fn claim(&self, key: &ResourceKey) -> Claim {
        let mut flights = self
            .inner
            .flights
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(flight) = flights.get(key) {
            let taken = flight
                .waiters
                .try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
                    (now < MAX_WAITERS).then_some(now + 1)
                });
            if taken.is_err() {
                return Claim::Crowded;
            }
            self.inner.collapsed.fetch_add(1, Ordering::Relaxed);
            return Claim::Follow(Waiter {
                done: flight.done.subscribe(),
                slot: Some(Arc::clone(flight)),
            });
        }
        let (done, _) = watch::channel(None);
        let flight = Arc::new(Flight {
            done,
            waiters: AtomicU32::new(0),
        });
        flights.insert(key.clone(), Arc::clone(&flight));
        Claim::Lead(Lead {
            cache: Arc::clone(&self.inner),
            key: key.clone(),
            flight,
            outcome: Outcome::NotStored,
        })
    }

    /// Whether anyone is fetching `key` now.
    pub(crate) fn fetching(&self, key: &ResourceKey) -> bool {
        self.inner
            .flights
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(key)
    }

    /// Counts one request of `app` that ended as `result`.
    pub(crate) fn count(&self, app: &str, result: &'static str) {
        let mut requests = self
            .inner
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *requests.entry((app.into(), result)).or_insert(0) += 1;
    }

    /// Removes the entries of `app` (of tenant `tenant`) that `request` selects. The caller has
    /// already checked that the app exists. Returns how many entries went; their bytes are
    /// released at once.
    ///
    /// # Errors
    ///
    /// [`Invalid`] when the request does not name exactly one selector, or one is malformed.
    pub(crate) fn purge(&self, tenant: &str, request: &Request) -> Result<usize, Invalid> {
        let selector = Selector::of(request)?;
        let store = self
            .inner
            .tenants
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(tenant)
            .cloned();
        Ok(store.map_or(0, |store| store.purge(&request.app, &selector)))
    }

    /// Drops what `table` no longer has a use for: entries of apps that are gone or moved to
    /// another tenant, entries of revisions that are `draining` or gone, tenants with nothing
    /// left, and the counters of vanished apps. Run it after every snapshot apply.
    pub fn retain(&self, table: &RoutingTable) {
        let live = |key: &ResourceKey| {
            let Some((_, app)) = table.app_by_id(&key.app) else {
                return false;
            };
            if app.tenant() != &*key.tenant {
                return false;
            }
            key.revision.as_deref().is_none_or(|id| {
                app.revisions().iter().any(|revision| {
                    revision.id() == id
                        && matches!(
                            revision.state(),
                            RevisionState::Serving | RevisionState::Retiring
                        )
                })
            })
        };
        let mut tenants = self
            .inner
            .tenants
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        for store in tenants.values() {
            store.retain(live);
        }
        tenants.retain(|id, store| table.tenant_budget(id).is_some() || !store.is_empty());
        drop(tenants);
        self.inner
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(app, _), _| table.app_by_id(app).is_some());
    }

    /// The cache's Prometheus series.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP podgate_cache_requests_total Requests the response cache saw, by app and result (hit, miss, stale, bypass, revalidated).\n");
        out.push_str("# TYPE podgate_cache_requests_total counter\n");
        for ((app, result), count) in &*self
            .inner
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            // Writing to a String cannot fail.
            let _ = writeln!(
                out,
                "podgate_cache_requests_total{{app=\"{}\",result=\"{result}\"}} {count}",
                Escaped(app)
            );
        }
        let mut stores: Vec<(Box<str>, Arc<TenantCache>)> = self
            .inner
            .tenants
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(id, store)| (id.clone(), Arc::clone(store)))
            .collect();
        stores.sort_by(|left, right| left.0.cmp(&right.0));
        out.push_str("# HELP podgate_cache_bytes Bytes of cached responses held for the tenant now, charged to its max_buffer_bytes.\n");
        out.push_str("# TYPE podgate_cache_bytes gauge\n");
        for (id, store) in &stores {
            let _ = writeln!(
                out,
                "podgate_cache_bytes{{tenant=\"{}\"}} {}",
                Escaped(id),
                store.bytes()
            );
        }
        out.push_str("# HELP podgate_cache_evictions_total Entries evicted to make room for the tenant's newer ones.\n");
        out.push_str("# TYPE podgate_cache_evictions_total counter\n");
        for (id, store) in &stores {
            let _ = writeln!(
                out,
                "podgate_cache_evictions_total{{tenant=\"{}\"}} {}",
                Escaped(id),
                store.evictions()
            );
        }
        out.push_str("# HELP podgate_cache_collapsed_total Requests that waited for another request's fetch instead of going to the upstream.\n");
        out.push_str("# TYPE podgate_cache_collapsed_total counter\n");
        let _ = writeln!(
            out,
            "podgate_cache_collapsed_total {}",
            self.inner.collapsed.load(Ordering::Relaxed)
        );
        out
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cache::key::Parts;
    use crate::cache::policy::Query;

    fn key(path: &str) -> ResourceKey {
        ResourceKey::new(&Parts {
            tenant: "t",
            app: "a",
            router: "r",
            revision: None,
            tls: false,
            host: "a.test",
            path,
            query: None,
            query_order: Query::AsSent,
        })
    }

    #[test]
    fn limits_take_a_share_of_the_budget() {
        let limits = Limits {
            tenant_budget: 1000,
            max_percent: 50,
        };
        assert_eq!(limits.ceiling(), 500);
        assert_eq!(limits.default_bytes(), 250);
        let tight = Limits {
            tenant_budget: 1000,
            max_percent: 10,
        };
        assert_eq!(
            tight.default_bytes(),
            100,
            "the default never passes the ceiling"
        );
    }

    #[tokio::test]
    async fn one_request_leads_and_the_rest_wait_up_to_the_cap() {
        let cache = Cache::new();
        let Claim::Lead(mut lead) = cache.claim(&key("/x")) else {
            panic!("the first claim leads");
        };
        let mut waiters = Vec::new();
        for _ in 0..MAX_WAITERS {
            match cache.claim(&key("/x")) {
                Claim::Follow(waiter) => waiters.push(waiter),
                other => panic!("expected a waiter, got {other:?}"),
            }
        }
        assert!(matches!(cache.claim(&key("/x")), Claim::Crowded));
        assert!(
            matches!(cache.claim(&key("/y")), Claim::Lead(_)),
            "another key has its own fetch"
        );
        lead.set(Outcome::Stored);
        drop(lead);
        for waiter in waiters {
            assert_eq!(
                waiter.wait(Duration::from_secs(1)).await,
                Some(Outcome::Stored)
            );
        }
        assert!(
            matches!(cache.claim(&key("/x")), Claim::Lead(_)),
            "the key is free again once the lead ends"
        );
    }

    #[tokio::test]
    async fn a_waiter_gives_up_after_its_limit() {
        let cache = Cache::new();
        let Claim::Lead(_lead) = cache.claim(&key("/x")) else {
            panic!("leads");
        };
        let Claim::Follow(waiter) = cache.claim(&key("/x")) else {
            panic!("waits");
        };
        assert_eq!(waiter.wait(Duration::from_millis(20)).await, None);
    }
}
