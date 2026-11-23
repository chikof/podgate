//! The combined state: one slot per peer, replaced only by that peer's own task.
//!
//! Readers clone an `Arc` under a lock held for that clone alone, never across an await, so a
//! slow peer or a slow reader delays nobody else. A pull replaces a cluster's entries all at once
//! or not at all.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use crate::config::ClusterName;
use crate::failure::Failure;
use crate::pull::Pulled;
use crate::wire::{Item, Status};

/// Whether a cluster's data is current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The last pull succeeded and ended recently.
    Fresh,
    /// The last pull failed, or the last success is old, or there never was one.
    Stale,
}

/// What the hub knows about one cluster.
#[derive(Debug, Clone)]
pub struct Cluster {
    /// The operator's label.
    pub name: ClusterName,
    /// The entries of the last good pull.
    pub entries: Arc<[Item]>,
    /// The status of the last good pull.
    pub status: Option<Status>,
    /// Entries the last good pull left out.
    pub dropped: u32,
    /// The hub's clock at the last good pull.
    pub last_success: Option<SystemTime>,
    /// The hub's clock at the last pull, good or not.
    pub last_attempt: Option<SystemTime>,
    /// Why the last pull failed; `None` after a success.
    pub error: Option<Failure>,
    /// The `format_version` the peer last named, when it was readable.
    pub peer_format: Option<u32>,
}

impl Cluster {
    fn new(name: ClusterName) -> Self {
        Self {
            name,
            entries: Arc::from(Vec::new()),
            status: None,
            dropped: 0,
            last_success: None,
            last_attempt: None,
            error: None,
            peer_format: None,
        }
    }

    /// Fresh only when the last pull succeeded and ended less than `stale_after` ago. The clock
    /// is the hub's: a peer's own timestamps are shown and never trusted.
    #[must_use]
    pub fn freshness(&self, now: SystemTime, stale_after: Duration) -> Freshness {
        let recent = self
            .last_success
            .is_some_and(|at| now.duration_since(at).map_or(true, |age| age < stale_after));
        if recent && self.error.is_none() {
            Freshness::Fresh
        } else {
            Freshness::Stale
        }
    }
}

/// Every cluster, in file order.
#[derive(Debug)]
pub struct Fleet {
    slots: Box<[RwLock<Arc<Cluster>>]>,
}

impl Fleet {
    /// A fleet of clusters that have never been pulled.
    #[must_use]
    pub fn new(names: impl IntoIterator<Item = ClusterName>) -> Self {
        Self {
            slots: names
                .into_iter()
                .map(|name| RwLock::new(Arc::new(Cluster::new(name))))
                .collect(),
        }
    }

    /// Records a good pull of cluster `index`.
    pub fn succeed(&self, index: usize, pulled: Pulled, now: SystemTime) {
        let Some(slot) = self.slots.get(index) else {
            return;
        };
        let mut guard = slot.write().unwrap_or_else(PoisonError::into_inner);
        let next = Cluster {
            name: guard.name.clone(),
            entries: pulled.entries,
            status: Some(pulled.status),
            dropped: pulled.dropped,
            last_success: Some(now),
            last_attempt: Some(now),
            error: None,
            peer_format: Some(crate::wire::FORMAT_VERSION),
        };
        *guard = Arc::new(next);
    }

    /// Records a failed pull of cluster `index`; the entries of the last good pull stay.
    pub fn fail(&self, index: usize, failure: Failure, now: SystemTime) {
        let Some(slot) = self.slots.get(index) else {
            return;
        };
        let mut guard = slot.write().unwrap_or_else(PoisonError::into_inner);
        let mut next = Cluster::clone(&guard);
        next.last_attempt = Some(now);
        next.peer_format = failure.peer_format.or(next.peer_format);
        next.error = Some(failure);
        *guard = Arc::new(next);
    }

    /// The clusters as they are now, in file order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Arc<Cluster>> {
        self.slots
            .iter()
            .map(|slot| Arc::clone(&slot.read().unwrap_or_else(PoisonError::into_inner)))
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::failure::ErrorClass;
    use crate::wire::Counts;

    fn name(text: &str) -> ClusterName {
        ClusterName::parse(text).expect("a name")
    }

    fn pulled() -> Pulled {
        Pulled {
            status: Status {
                snapshot_version: 1,
                applied_at: 0,
                boot_id: "b".into(),
                writer: None,
                counts: Counts::default(),
            },
            entries: Arc::from(Vec::new()),
            dropped: 0,
            snapshot_version: 1,
        }
    }

    #[test]
    fn federation_freshness_rules() {
        let stale_after = Duration::from_secs(90);
        let fleet = Fleet::new([name("eu")]);
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let state = |now| fleet.snapshot()[0].freshness(now, stale_after);
        assert_eq!(state(t0), Freshness::Stale, "never pulled");
        fleet.succeed(0, pulled(), t0);
        assert_eq!(state(at(89)), Freshness::Fresh);
        assert_eq!(state(at(90)), Freshness::Stale, "old success");
        fleet.fail(0, Failure::new(ErrorClass::Timeout), at(10));
        assert_eq!(state(at(11)), Freshness::Stale, "the last pull failed");
        let kept = fleet.snapshot();
        assert_eq!(kept[0].last_success, Some(t0), "last success kept");
        assert_eq!(kept[0].error.map(|e| e.class), Some(ErrorClass::Timeout));
        fleet.succeed(0, pulled(), at(20));
        assert!(fleet.snapshot()[0].error.is_none());
        assert_eq!(state(at(21)), Freshness::Fresh);
    }
}
