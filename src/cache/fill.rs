//! A response being copied into the cache while it streams to the client.
//!
//! Every byte is charged to the tenant before it is copied, so the copy can never exceed the
//! tenant's budget, not even for a moment, and counted against the tenant's cache cap with the
//! stored entries and the other copies in progress. A body that passes `max_object_bytes`, a
//! copy that would take the tenant's cache over its cap, or a budget with no room (after the
//! tenant's own least recently used entries are evicted) abandons the copy: the client still
//! gets the response, the cache just does not keep it.

use std::sync::Arc;

use bytes::Bytes;
use pingora::http::ResponseHeader;

use crate::budget::TenantBudget;
use crate::cache::key::ResourceKey;
use crate::cache::policy::Lifetimes;
use crate::cache::store::{Charge, Entry, SEGMENT_OVERHEAD, TenantCache};

/// A copy in progress. Dropping it releases everything it charged and counted.
#[derive(Debug)]
pub(crate) struct Fill {
    tenant: Arc<TenantBudget>,
    store: Arc<TenantCache>,
    charge: Charge,
    /// Bytes counted in the store's cap as in progress.
    reserved: u64,
    segments: Vec<Bytes>,
    len: u64,
    max_object: u64,
    cap: u64,
}

/// What the finished response is stored as.
#[derive(Debug)]
pub(crate) struct Finished {
    pub(crate) key: ResourceKey,
    pub(crate) vary: Box<[Box<str>]>,
    pub(crate) variant: Box<str>,
    pub(crate) lifetimes: Lifetimes,
    pub(crate) age: u64,
}

impl Fill {
    /// Starts a copy of a response whose head and tags cost `head_bytes`. `None` when even that
    /// does not fit the tenant's cache cap `cap` or its budget.
    pub(crate) fn begin(
        tenant: Arc<TenantBudget>,
        store: Arc<TenantCache>,
        head_bytes: u64,
        max_object: u64,
        cap: u64,
    ) -> Option<Self> {
        let mut fill = Self {
            tenant,
            store,
            charge: Charge::default(),
            reserved: 0,
            segments: Vec::new(),
            len: 0,
            max_object,
            cap,
        };
        fill.take(head_bytes).then_some(fill)
    }

    /// Counts and charges `bytes` more, evicting the tenant's own least recently used entries
    /// while the cap or its budget is full. `false` when it cannot: nothing is left to evict.
    fn take(&mut self, bytes: u64) -> bool {
        loop {
            if self.store.reserve(bytes, self.cap) {
                if self.charge.add(&self.tenant, bytes) {
                    self.reserved += bytes;
                    return true;
                }
                self.store.release(bytes);
            }
            if !self.store.evict_one() {
                return false;
            }
        }
    }

    /// Copies one chunk. `false` abandons the copy: drop the fill.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> bool {
        if chunk.is_empty() {
            return true;
        }
        let len = chunk.len() as u64;
        if self.len + len > self.max_object || !self.take(len + SEGMENT_OVERHEAD) {
            return false;
        }
        self.len += len;
        self.segments.push(Bytes::copy_from_slice(chunk));
        true
    }

    /// Bytes copied so far.
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// Stores the copy. `false` when the cap refused it after all.
    pub(crate) fn finish(
        mut self,
        head: ResponseHeader,
        tags: Box<[Box<str>]>,
        done: Finished,
    ) -> bool {
        let Finished {
            key,
            vary,
            variant,
            lifetimes,
            age,
        } = done;
        let entry = Entry::new(
            head,
            std::mem::take(&mut self.segments).into(),
            tags,
            lifetimes,
            age,
            std::mem::take(&mut self.charge),
        );
        let moved = std::mem::take(&mut self.reserved);
        let stored = self
            .store
            .insert(&key, vary, variant, entry, self.cap, moved);
        if !stored {
            self.store.release(moved);
        }
        stored
    }
}

impl Drop for Fill {
    fn drop(&mut self) {
        // The budget charge first: the reservation is what lets another copy charge.
        drop(std::mem::take(&mut self.charge));
        self.store.release(self.reserved);
    }
}
