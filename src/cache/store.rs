//! The bounded store: one [`TenantCache`] per tenant, least-recently-used eviction inside it.
//!
//! Isolation is structural. A tenant's entries live in that tenant's own [`TenantCache`], so a
//! lookup, an insert, an eviction or a purge for one tenant cannot see another's; the tenant is
//! in the [`ResourceKey`] as well, so a mix-up would still not match. Every byte an entry holds
//! is charged to the tenant's `max_buffer_bytes` through a [`Charge`] the entry owns: it is
//! released when the last reference to the entry goes, which for an entry that is evicted or
//! purged is when the last in-flight response that is reading it ends.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use bytes::Bytes;
use pingora::http::ResponseHeader;

use crate::budget::{BufferGuard, TenantBudget};
use crate::cache::key::ResourceKey;
use crate::cache::policy::{self, Lifetimes};
use crate::cache::purge::Selector;

/// What an entry costs beyond its headers and body: the key, the maps and the bookkeeping.
const ENTRY_OVERHEAD: u64 = 512;

/// Per-header overhead on top of the name and value bytes.
const HEADER_OVERHEAD: u64 = 32;

/// What one body segment costs beyond its bytes: the `Bytes` handle, its guard and the
/// allocator's header. Charged with every segment, so many tiny chunks cannot hide behind the
/// body length.
pub(crate) const SEGMENT_OVERHEAD: u64 = 64;

/// Buffer bytes charged to a tenant on behalf of one entry or one fill in progress.
#[derive(Debug, Default)]
pub(crate) struct Charge {
    guards: Vec<BufferGuard>,
    bytes: u64,
}

impl Charge {
    /// Charges `tenant` `bytes` more. `false` when its budget does not take them; what was held
    /// before stays held.
    pub(crate) fn add(&mut self, tenant: &Arc<TenantBudget>, bytes: u64) -> bool {
        match tenant.charge(bytes) {
            Some(guard) => {
                self.guards.push(guard);
                self.bytes += bytes;
                true
            }
            None => false,
        }
    }

    /// Bytes held.
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// How old an entry is and what that allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Standing {
    /// Seconds since the origin generated the response.
    pub(crate) age: u64,
    /// Fresh: served as it is.
    pub(crate) fresh: bool,
    /// Stale, but inside its `stale-while-revalidate` allowance.
    pub(crate) revalidate_in_background: bool,
    /// Stale, but inside its `stale-if-error` allowance.
    pub(crate) usable_on_error: bool,
}

#[derive(Debug, Clone, Copy)]
struct Timing {
    stored: Instant,
    age: u64,
    lifetimes: Lifetimes,
}

/// One stored response.
#[derive(Debug)]
pub(crate) struct Entry {
    /// Status and headers as the client received them on the miss that stored this, without the
    /// hop-by-hop headers, the tag header and (unless allowed) cookies.
    pub(crate) head: ResponseHeader,
    /// The body as the chunks the upstream sent it in.
    pub(crate) body: Box<[Bytes]>,
    pub(crate) body_len: u64,
    pub(crate) tags: Box<[Box<str>]>,
    timing: Mutex<Timing>,
    charge: Charge,
}

impl Entry {
    /// What an entry's head, tags and bookkeeping cost, before any body segment.
    #[must_use]
    pub(crate) fn head_footprint(head: &ResponseHeader, tags: &[Box<str>]) -> u64 {
        let headers: u64 = head
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().len() + value.len()) as u64 + HEADER_OVERHEAD)
            .sum();
        let tags: u64 = tags.iter().map(|tag| tag.len() as u64).sum();
        ENTRY_OVERHEAD + headers + tags
    }

    /// An entry whose `charge` already covers its head and every segment of `body`.
    pub(crate) fn new(
        head: ResponseHeader,
        body: Box<[Bytes]>,
        tags: Box<[Box<str>]>,
        lifetimes: Lifetimes,
        age: u64,
        charge: Charge,
    ) -> Self {
        let body_len = body.iter().map(|segment| segment.len() as u64).sum();
        Self {
            head,
            body,
            body_len,
            tags,
            timing: Mutex::new(Timing {
                stored: Instant::now(),
                age,
                lifetimes,
            }),
            charge,
        }
    }

    fn timing(&self) -> Timing {
        *self.timing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How old the entry is and what that allows, now.
    #[must_use]
    pub(crate) fn standing(&self) -> Standing {
        let timing = self.timing();
        let age = timing.age.saturating_add(timing.stored.elapsed().as_secs());
        let lifetimes = timing.lifetimes;
        Standing {
            age,
            fresh: age < lifetimes.fresh,
            revalidate_in_background: age
                < lifetimes
                    .fresh
                    .saturating_add(lifetimes.stale_while_revalidate),
            usable_on_error: age < lifetimes.fresh.saturating_add(lifetimes.stale_if_error),
        }
    }

    /// Restarts the clock after the origin confirmed the entry with a `304`.
    pub(crate) fn revalidated(&self, lifetimes: Option<Lifetimes>, age: u64) {
        let mut timing = self.timing.lock().unwrap_or_else(PoisonError::into_inner);
        timing.stored = Instant::now();
        timing.age = age;
        if let Some(lifetimes) = lifetimes {
            timing.lifetimes = lifetimes;
        }
    }

    /// Bytes charged to the tenant for this entry.
    #[must_use]
    pub(crate) fn size(&self) -> u64 {
        self.charge.bytes()
    }

    /// Whether the entry has a validator a conditional request can use.
    #[must_use]
    pub(crate) fn has_validator(&self) -> bool {
        policy::has_validator(&self.head.headers)
    }
}

#[derive(Debug)]
struct Slot {
    entry: Arc<Entry>,
    tick: u64,
    id: Arc<(ResourceKey, Box<str>)>,
}

#[derive(Debug)]
struct Resource {
    vary: Box<[Box<str>]>,
    variants: HashMap<Box<str>, Slot>,
}

#[derive(Debug, Default)]
struct State {
    resources: HashMap<ResourceKey, Resource>,
    /// Least recently used first. The value names the slot that holds the tick.
    order: BTreeMap<u64, Arc<(ResourceKey, Box<str>)>>,
    bytes: u64,
    tick: u64,
}

/// What a lookup found.
#[derive(Debug)]
pub(crate) enum Lookup {
    /// Nothing stored for this request.
    Miss,
    /// The entry that answers the request, fresh or stale.
    Hit(Arc<Entry>),
    /// A request header the stored responses vary on is too long to key on.
    Unkeyable,
}

/// One tenant's entries.
#[derive(Debug, Default)]
pub(crate) struct TenantCache {
    state: Mutex<State>,
    evictions: AtomicU64,
    /// Bytes charged for copies in progress ([`crate::cache::fill::Fill`]): they count against
    /// the cap with the stored entries, so concurrent copies cannot take the cache past it.
    filling: AtomicU64,
}

impl State {
    fn touch(&mut self, resource: &ResourceKey, variant: &str) {
        self.tick += 1;
        let tick = self.tick;
        let Some(slot) = self
            .resources
            .get_mut(resource)
            .and_then(|found| found.variants.get_mut(variant))
        else {
            return;
        };
        self.order.remove(&slot.tick);
        slot.tick = tick;
        self.order.insert(tick, Arc::clone(&slot.id));
    }

    /// Removes one variant and returns its entry.
    fn remove_variant(&mut self, resource: &ResourceKey, variant: &str) -> Option<Arc<Entry>> {
        let found = self.resources.get_mut(resource)?;
        let slot = found.variants.remove(variant)?;
        if found.variants.is_empty() {
            self.resources.remove(resource);
        }
        self.order.remove(&slot.tick);
        self.bytes = self.bytes.saturating_sub(slot.entry.size());
        Some(slot.entry)
    }

    fn remove_resource(&mut self, resource: &ResourceKey, removed: &mut Vec<Arc<Entry>>) {
        if let Some(found) = self.resources.remove(resource) {
            for (_, slot) in found.variants {
                self.order.remove(&slot.tick);
                self.bytes = self.bytes.saturating_sub(slot.entry.size());
                removed.push(slot.entry);
            }
        }
    }

    fn evict_lru(&mut self) -> Option<Arc<Entry>> {
        let (_, id) = self.order.pop_first()?;
        let (resource, variant) = &*id;
        let found = self.resources.get_mut(resource)?;
        let slot = found.variants.remove(variant)?;
        if found.variants.is_empty() {
            self.resources.remove(resource);
        }
        self.bytes = self.bytes.saturating_sub(slot.entry.size());
        Some(slot.entry)
    }
}

impl TenantCache {
    /// The entry that answers a request for `key` with headers `request`.
    pub(crate) fn lookup(&self, key: &ResourceKey, request: &http::HeaderMap) -> Lookup {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(resource) = state.resources.get(key) else {
            return Lookup::Miss;
        };
        let Some(variant) = policy::variant(request, &resource.vary) else {
            return Lookup::Unkeyable;
        };
        let Some(slot) = resource.variants.get(&variant) else {
            return Lookup::Miss;
        };
        let entry = Arc::clone(&slot.entry);
        state.touch(key, &variant);
        Lookup::Hit(entry)
    }

    /// Counts `bytes` of a copy in progress against `cap`, together with the stored entries and
    /// the other copies. `false` when that would pass `cap`; nothing is counted then.
    pub(crate) fn reserve(&self, bytes: u64, cap: u64) -> bool {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let counted = state.bytes + self.filling.load(Ordering::Relaxed);
        if counted.saturating_add(bytes) > cap {
            return false;
        }
        self.filling.fetch_add(bytes, Ordering::Relaxed);
        true
    }

    /// Stops counting `bytes` of a copy that ended without being stored.
    pub(crate) fn release(&self, bytes: u64) {
        self.filling.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Stores `entry` under `key` and the variant `variant` of its `vary` header names. The
    /// entry's bytes were counted by [`Self::reserve`] (`moved` of them, which are now the
    /// entry's); eviction here only makes room when `cap` was lowered since.
    ///
    /// `false` when the entry alone is over `cap`; nothing changes then and `moved` stays
    /// counted as in progress.
    pub(crate) fn insert(
        &self,
        key: &ResourceKey,
        vary: Box<[Box<str>]>,
        variant: Box<str>,
        entry: Entry,
        cap: u64,
        moved: u64,
    ) -> bool {
        let size = entry.size();
        if size > cap {
            return false;
        }
        let mut gone: Vec<Arc<Entry>> = Vec::new();
        {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            // A response that varies on other headers than the stored ones replaces them all.
            if state
                .resources
                .get(key)
                .is_some_and(|stored| stored.vary != vary)
            {
                state.remove_resource(key, &mut gone);
            }
            gone.extend(state.remove_variant(key, &variant));
            while state.bytes + size > cap {
                let Some(victim) = state.evict_lru() else {
                    break;
                };
                self.evictions.fetch_add(1, Ordering::Relaxed);
                gone.push(victim);
            }
            state.tick += 1;
            let tick = state.tick;
            let id = Arc::new((key.clone(), variant.clone()));
            state.order.insert(tick, Arc::clone(&id));
            state.bytes += size;
            self.filling.fetch_sub(moved, Ordering::Relaxed);
            let resource = state
                .resources
                .entry(key.clone())
                .or_insert_with(|| Resource {
                    vary,
                    variants: HashMap::new(),
                });
            resource.variants.insert(
                variant,
                Slot {
                    entry: Arc::new(entry),
                    tick,
                    id,
                },
            );
            // Dropped under the lock: the charge is released before anyone can reserve against
            // the lowered count, so the tenant's buffer never passes the cap.
            drop(gone);
        }
        true
    }

    /// Evicts the least recently used entry. `false` when there is none.
    pub(crate) fn evict_one(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let victim = state.evict_lru();
        let evicted = victim.is_some();
        drop(victim);
        drop(state);
        if evicted {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        evicted
    }

    /// Removes every variant of `key`.
    pub(crate) fn remove(&self, key: &ResourceKey) {
        let mut gone = Vec::new();
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove_resource(key, &mut gone);
    }

    /// Removes the entries of app `app` that `selector` selects. Returns how many went.
    pub(crate) fn purge(&self, app: &str, selector: &Selector) -> usize {
        let mut gone: Vec<Arc<Entry>> = Vec::new();
        {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let mut doomed: Vec<(ResourceKey, Option<Box<str>>)> = Vec::new();
            for (key, resource) in &state.resources {
                if &*key.app != app {
                    continue;
                }
                match selector.tag() {
                    Some(tag) => {
                        for (variant, slot) in &resource.variants {
                            if slot.entry.tags.iter().any(|stored| &**stored == tag) {
                                doomed.push((key.clone(), Some(variant.clone())));
                            }
                        }
                    }
                    None if selector.matches_key(key) => doomed.push((key.clone(), None)),
                    None => {}
                }
            }
            for (key, variant) in doomed {
                match variant {
                    Some(variant) => gone.extend(state.remove_variant(&key, &variant)),
                    None => state.remove_resource(&key, &mut gone),
                }
            }
            let count = gone.len();
            drop(gone);
            count
        }
    }

    /// Removes every resource for which `keep` is `false`. Returns how many entries went.
    pub(crate) fn retain(&self, keep: impl Fn(&ResourceKey) -> bool) -> usize {
        let mut gone: Vec<Arc<Entry>> = Vec::new();
        {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let doomed: Vec<ResourceKey> = state
                .resources
                .keys()
                .filter(|key| !keep(key))
                .cloned()
                .collect();
            for key in doomed {
                state.remove_resource(&key, &mut gone);
            }
            let count = gone.len();
            drop(gone);
            count
        }
    }

    /// Bytes of the entries held now.
    pub(crate) fn bytes(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes
    }

    /// Number of entries held now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .resources
            .values()
            .map(|resource| resource.variants.len())
            .sum()
    }

    /// Entries evicted to make room since start.
    pub(crate) fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Whether this tenant holds nothing.
    pub(crate) fn is_empty(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .resources
            .is_empty()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::budget::Budgets;
    use crate::cache::key::Parts;
    use crate::cache::policy::Query;
    use podgate_model::Budget;

    fn key(tenant: &str, app: &str, target: &str) -> ResourceKey {
        ResourceKey::new(&Parts {
            tenant,
            app,
            router: "r",
            revision: None,
            tls: false,
            host: "a.test",
            path: target,
            query: None,
            query_order: Query::AsSent,
        })
    }

    fn budget(bytes: u64) -> Arc<TenantBudget> {
        Budgets::new().tenant(
            "t",
            Budget {
                max_inflight: 10,
                max_buffer_bytes: bytes,
            },
        )
    }

    fn entry(tenant: &Arc<TenantBudget>, body: usize) -> Option<Entry> {
        let head = ResponseHeader::build(200, None).expect("head");
        let mut charge = Charge::default();
        charge
            .add(tenant, Entry::head_footprint(&head, &[]))
            .then_some(())?;
        charge
            .add(tenant, body as u64 + SEGMENT_OVERHEAD)
            .then_some(())?;
        Some(Entry::new(
            head,
            Box::new([Bytes::from(vec![0; body])]),
            Box::new([]),
            Lifetimes {
                fresh: 60,
                stale_while_revalidate: 0,
                stale_if_error: 0,
            },
            0,
            charge,
        ))
    }

    #[test]
    fn inserts_evict_the_least_recently_used_entry_within_the_cap() {
        let tenant = budget(1 << 20);
        let cache = TenantCache::default();
        let one = entry(&tenant, 3000).expect("fits");
        let each = one.size();
        let cap = each * 2;
        assert!(cache.insert(&key("t", "a", "/1"), Box::new([]), "".into(), one, cap, 0));
        let two = entry(&tenant, 3000).expect("fits");
        assert!(cache.insert(&key("t", "a", "/2"), Box::new([]), "".into(), two, cap, 0));
        assert!(matches!(
            cache.lookup(&key("t", "a", "/1"), &http::HeaderMap::new()),
            Lookup::Hit(_)
        ));
        let three = entry(&tenant, 3000).expect("fits");
        assert!(cache.insert(&key("t", "a", "/3"), Box::new([]), "".into(), three, cap, 0));
        // /2 was the least recently used; /1 was just read.
        assert!(matches!(
            cache.lookup(&key("t", "a", "/2"), &http::HeaderMap::new()),
            Lookup::Miss
        ));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.evictions(), 1);
        assert_eq!(cache.bytes(), each * 2);
        assert_eq!(tenant.buffered(), each * 2, "evicted bytes are released");
    }

    #[test]
    fn copies_in_progress_count_against_the_cap_with_the_entries() {
        let cache = TenantCache::default();
        assert!(cache.reserve(600, 1000));
        assert!(
            !cache.reserve(401, 1000),
            "stored plus in progress may not pass the cap"
        );
        assert!(cache.reserve(400, 1000));
        cache.release(600);
        assert!(
            cache.reserve(600, 1000),
            "a copy that ended frees its share"
        );
    }

    #[test]
    fn a_key_of_another_tenant_or_app_never_finds_an_entry() {
        let tenant = budget(1 << 20);
        let first = TenantCache::default();
        let second = TenantCache::default();
        let made = entry(&tenant, 100).expect("fits");
        assert!(first.insert(
            &key("t1", "a", "/p"),
            Box::new([]),
            "".into(),
            made,
            1 << 20,
            0
        ));
        let headers = http::HeaderMap::new();
        assert!(matches!(
            first.lookup(&key("t1", "a", "/p"), &headers),
            Lookup::Hit(_)
        ));
        assert!(matches!(
            first.lookup(&key("t2", "a", "/p"), &headers),
            Lookup::Miss
        ));
        assert!(matches!(
            first.lookup(&key("t1", "b", "/p"), &headers),
            Lookup::Miss
        ));
        assert!(matches!(
            second.lookup(&key("t1", "a", "/p"), &headers),
            Lookup::Miss
        ));
    }

    #[test]
    fn an_entry_over_the_cap_is_refused_and_changes_nothing() {
        let tenant = budget(1 << 20);
        let cache = TenantCache::default();
        let big = entry(&tenant, 20_000).expect("fits");
        assert!(!cache.insert(
            &key("t", "a", "/big"),
            Box::new([]),
            "".into(),
            big,
            4096,
            0
        ));
        assert_eq!(cache.len(), 0);
        assert_eq!(tenant.buffered(), 0, "the refused entry is released");
    }

    #[test]
    fn purge_is_scoped_to_one_app_and_releases_the_charge() {
        let tenant = budget(1 << 20);
        let cache = TenantCache::default();
        for (app, path) in [("a", "/x"), ("a", "/y"), ("b", "/x")] {
            let made = entry(&tenant, 100).expect("fits");
            assert!(cache.insert(
                &key("t", app, path),
                Box::new([]),
                "".into(),
                made,
                1 << 20,
                0
            ));
        }
        assert_eq!(cache.purge("a", &Selector::All), 2);
        assert_eq!(cache.len(), 1, "app b keeps its entry");
        let left = cache.bytes();
        assert_eq!(tenant.buffered(), left);
    }
}
