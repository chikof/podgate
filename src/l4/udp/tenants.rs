//! How many UDP sessions each tenant and the whole node hold.
//!
//! UDP sessions take no `max_inflight` slot: a flood of spoofed sources must not use up the
//! tenant's HTTP capacity. They are limited here instead, per tenant and per node, and charge the
//! tenant's `max_buffer_bytes` for their buffer. Each session holds one file descriptor, so the
//! node cap is what keeps UDP from exhausting the process's descriptors for everyone.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use super::stats::Dropped;

/// Sessions one tenant may hold across all its UDP entry points.
pub const TENANT_MAX_SESSIONS: u32 = 8192;
/// Sessions the node may hold across all tenants. The operator's descriptor limit must be above
/// this and the descriptors the proxy listeners use.
pub const NODE_MAX_SESSIONS: u32 = 32_768;

#[derive(Debug)]
struct Counts {
    tenant_cap: u32,
    node_cap: u32,
    node: Arc<AtomicU32>,
    tenants: Mutex<HashMap<Box<str>, Arc<AtomicU32>>>,
}

/// The session counts of every tenant. Cheap to clone; every clone shares the counts.
#[derive(Debug, Clone)]
pub struct Tenants {
    counts: Arc<Counts>,
}

impl Default for Tenants {
    fn default() -> Self {
        Self::with_caps(TENANT_MAX_SESSIONS, NODE_MAX_SESSIONS)
    }
}

impl Tenants {
    /// Counts with the default caps.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts with the given caps, for tests.
    #[must_use]
    pub fn with_caps(tenant_cap: u32, node_cap: u32) -> Self {
        Self {
            counts: Arc::new(Counts {
                tenant_cap,
                node_cap,
                node: Arc::default(),
                tenants: Mutex::default(),
            }),
        }
    }

    /// Takes a session for `tenant`, held until the returned [`Slot`] drops.
    pub(super) fn acquire(&self, tenant: &str) -> Result<Slot, Dropped> {
        let counter = {
            let mut tenants = self
                .counts
                .tenants
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            Arc::clone(tenants.entry(tenant.into()).or_default())
        };
        take(&counter, self.counts.tenant_cap).ok_or(Dropped::TenantLimit)?;
        if take(&self.counts.node, self.counts.node_cap).is_none() {
            counter.fetch_sub(1, Ordering::AcqRel);
            return Err(Dropped::NodeLimit);
        }
        Ok(Slot {
            tenant: counter,
            node: Arc::clone(&self.counts.node),
        })
    }

    /// Sessions `tenant` holds now.
    #[must_use]
    pub fn held(&self, tenant: &str) -> u32 {
        let tenants = self
            .counts
            .tenants
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        tenants
            .get(tenant)
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }
}

fn take(counter: &AtomicU32, cap: u32) -> Option<u32> {
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
            (now < cap).then_some(now + 1)
        })
        .ok()
}

/// One session of a tenant, returned on drop.
#[derive(Debug)]
pub(super) struct Slot {
    tenant: Arc<AtomicU32>,
    node: Arc<AtomicU32>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.tenant.fetch_sub(1, Ordering::AcqRel);
        self.node.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn a_tenant_stops_at_its_cap_and_gets_a_slot_back_when_one_drops() {
        let tenants = Tenants::with_caps(2, 10);
        let first = tenants.acquire("t").expect("first");
        let _second = tenants.acquire("t").expect("second");
        assert_eq!(tenants.acquire("t").err(), Some(Dropped::TenantLimit));
        assert!(tenants.acquire("other").is_ok(), "the cap is per tenant");
        drop(first);
        assert!(tenants.acquire("t").is_ok());
    }

    #[test]
    fn the_node_cap_holds_across_tenants_and_gives_the_tenant_count_back() {
        let tenants = Tenants::with_caps(5, 2);
        let _a = tenants.acquire("a").expect("a");
        let _b = tenants.acquire("b").expect("b");
        assert_eq!(tenants.acquire("c").err(), Some(Dropped::NodeLimit));
        assert_eq!(tenants.held("c"), 0, "a refused session is not counted");
        assert_eq!(tenants.held("a"), 1);
    }
}
