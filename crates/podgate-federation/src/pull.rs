//! One pull of one peer: its status, then its whole catalog, under one deadline.
//!
//! A pull is all or nothing. It reads pages from the start with parameters the hub chooses, builds
//! every cursor itself from the last key it received, and checks what the peer sends: ascending
//! keys, progress, one snapshot version across pages. A peer that breaks a rule fails the pull,
//! and the caller keeps the previous result.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::client::{PeerConn, Target};
use crate::config::Peer;
use crate::failure::{ErrorClass, Failure};
use crate::wire::{Cursor, Item, Key, Page, Status};

/// Entries asked for per page.
pub const PAGE_LIMIT: u16 = 100;
/// Most bytes read for one catalog page.
pub const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
/// Most bytes read for the status.
pub const MAX_STATUS_BYTES: usize = 64 * 1024;
/// Most pages one pull reads.
const MAX_PAGES: usize = 1000;

/// What bounds a pull.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The deadline of the whole pull, from resolving to the last page.
    pub timeout: Duration,
    /// Bytes read from the peer in total.
    pub max_bytes: usize,
    /// Entries kept.
    pub max_entries: usize,
}

/// A successful pull.
#[derive(Debug, Clone)]
pub struct Pulled {
    /// The node's status.
    pub status: Status,
    /// Every entry that passed the rules, ascending by key.
    pub entries: Arc<[Item]>,
    /// Entries left out for breaking a cap.
    pub dropped: u32,
    /// The snapshot version of the catalog.
    pub snapshot_version: u64,
}

/// Pulls `peer`. The whole call, handshake and last byte included, ends within
/// `limits.timeout`.
///
/// # Errors
///
/// A [`Failure`] whose class says why.
pub async fn pull(peer: &Peer, limits: &Limits) -> Result<Pulled, Failure> {
    match timeout(limits.timeout, walk(peer, limits)).await {
        Ok(result) => result,
        Err(_) => Err(Failure::new(ErrorClass::Timeout)),
    }
}

/// Bytes left to read in this pull.
struct Budget(usize);

impl Budget {
    fn take(&mut self, cap: usize) -> usize {
        cap.min(self.0)
    }

    fn spend(&mut self, bytes: usize) {
        self.0 = self.0.saturating_sub(bytes);
    }
}

async fn walk(peer: &Peer, limits: &Limits) -> Result<Pulled, Failure> {
    let mut budget = Budget(limits.max_bytes);
    let mut conn = PeerConn::open(peer).await?;
    let body = conn
        .get(&Target::Status, budget.take(MAX_STATUS_BYTES))
        .await?;
    budget.spend(body.len());
    let status = Status::from_peer(&body)?;
    for _attempt in 0..2 {
        if let Some(pulled) = catalog(&mut conn, &mut budget, limits, &status).await? {
            return Ok(pulled);
        }
    }
    Err(Failure::new(ErrorClass::Unstable))
}

/// Reads the catalog from the start. `None` when the snapshot version changed between pages.
async fn catalog(
    conn: &mut PeerConn,
    budget: &mut Budget,
    limits: &Limits,
    status: &Status,
) -> Result<Option<Pulled>, Failure> {
    let mut entries: Vec<Item> = Vec::new();
    let mut dropped = 0_u32;
    let mut version: Option<u64> = None;
    let mut after: Option<Cursor> = None;
    let mut last: Option<Key> = None;
    for _page in 0..MAX_PAGES {
        let target = Target::Catalog {
            limit: PAGE_LIMIT,
            after: after.clone(),
        };
        let body = conn.get(&target, budget.take(MAX_PAGE_BYTES)).await?;
        budget.spend(body.len());
        let page = Page::from_peer(&body)?;
        if version.is_some_and(|seen| seen != page.snapshot_version) {
            return Ok(None);
        }
        version = Some(page.snapshot_version);
        if page.total > u64::try_from(limits.max_entries).unwrap_or(u64::MAX) {
            return Err(Failure::new(ErrorClass::TooLarge));
        }
        // The first key of a page must be past the cursor the hub sent.
        if let (Some(cursor), Some(first)) = (&after, page.items.first())
            && Key::of(first) <= cursor.key()
        {
            return Err(Failure::new(ErrorClass::Malformed));
        }
        entries.extend(page.items);
        dropped = dropped.saturating_add(page.dropped);
        if entries.len() > limits.max_entries {
            return Err(Failure::new(ErrorClass::TooLarge));
        }
        if !page.truncated {
            return Ok(Some(Pulled {
                status: status.clone(),
                entries: entries.into(),
                dropped,
                snapshot_version: page.snapshot_version,
            }));
        }
        // The hub builds the next cursor from the last key it was sent and checks the
        // peer's own `next` against it; it never repeats the peer's text.
        let Some(key) = page.last_key else {
            return Err(Failure::new(ErrorClass::Malformed));
        };
        if last.as_ref().is_some_and(|previous| key <= *previous) {
            return Err(Failure::new(ErrorClass::Malformed));
        }
        let cursor = Cursor::after(&key);
        if page
            .next
            .as_deref()
            .is_some_and(|next| next != cursor.as_str())
        {
            return Err(Failure::new(ErrorClass::Malformed));
        }
        last = Some(key);
        after = Some(cursor);
    }
    Err(Failure::new(ErrorClass::TooLarge))
}
