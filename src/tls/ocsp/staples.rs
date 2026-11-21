//! The registry of staples: what is stapled to which certificate, when each is refreshed, and
//! the lock-free view the TLS handshake reads.
//!
//! Staples are keyed by [`Fingerprint`] and live outside the routing table, so a snapshot push
//! that does not touch a certificate keeps its staple, and the entry of a certificate that left
//! the table is dropped on the next [`Staples::tick`]. The registry holds at most one slot per
//! certificate of the live table that wants a staple, so it is as bounded as the table is
//! (the admin API's 16 MiB snapshot limit); a slot holds one staple of at most
//! [`MAX_RESPONSE`](super::verify::MAX_RESPONSE) bytes.
//!
//! A handshake calls [`Staples::attach`], which reads an [`ArcSwap`] and never waits for a fetch
//! or for the lock the refresher takes. The rustls `CertifiedKey` with the staple is rebuilt when
//! a response is accepted and swapped in with the rest of the map.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use arc_swap::ArcSwap;
use pingora::tls::sign::CertifiedKey;
use podgate_model::Certificate;

use super::identity::{Fingerprint, Identity};
use super::metrics;
use super::reason::Reason;
use super::schedule::{backoff, next_refresh};
use super::scope::Scope;
use super::verify::Verified;
use crate::table::RoutingTable;

/// A certificate of a snapshot that should have a staple, or that should and cannot.
#[derive(Debug)]
pub struct Candidate {
    fingerprint: Fingerprint,
    key: Arc<CertifiedKey>,
    hosts: Box<[Box<str>]>,
    default: bool,
    identity: Result<Arc<Identity>, Reason>,
}

impl Candidate {
    /// `Some` when `certificate`, parsed into `key`, is to be stapled under its `ocsp` mode.
    #[must_use]
    pub fn of(certificate: &Certificate, key: &Arc<CertifiedKey>) -> Option<Self> {
        let identity = Identity::of(&key.cert, certificate.ocsp)?;
        Some(Self {
            fingerprint: Fingerprint::of(key.cert.first()?),
            key: Arc::clone(key),
            hosts: certificate.hosts.as_slice().into(),
            default: certificate.default,
            identity: identity.map(Arc::new),
        })
    }
}

/// One fetch the refresher should run.
#[derive(Debug)]
pub struct Job {
    fingerprint: Fingerprint,
    identity: Arc<Identity>,
    key: Arc<CertifiedKey>,
    hosts: Box<[Box<str>]>,
    scope: Scope,
}

impl Job {
    /// Names the certificate in [`Staples::finish`].
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// What the response must match and the request to send.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The issuer certificate of the served chain, DER.
    #[must_use]
    pub fn issuer_der(&self) -> Option<&[u8]> {
        self.key.cert.get(1).map(AsRef::as_ref)
    }

    /// The hosts the certificate is declared for, for logs.
    #[must_use]
    pub fn hosts(&self) -> &[Box<str>] {
        &self.hosts
    }

    /// Whose address policy the fetch is held to.
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}

/// How a [`Job`] ended.
#[derive(Debug)]
pub enum Outcome {
    /// A response that passed [`verify`](super::verify::verify).
    Verified(Verified),
    /// Nothing usable came back, for this reason. A previous staple stays until its
    /// `nextUpdate`, except after [`Reason::Revoked`].
    Failed(Reason),
}

struct Slot {
    key: Arc<CertifiedKey>,
    /// The key with the staple on it and when that staple stops being valid.
    staple: Option<(Arc<CertifiedKey>, SystemTime)>,
    due: SystemTime,
    failures: u32,
    busy: bool,
}

struct Served {
    key: Arc<CertifiedKey>,
    valid_until: SystemTime,
}

#[derive(Default)]
struct Inner {
    served: ArcSwap<HashMap<Fingerprint, Served>>,
    slots: Mutex<HashMap<Fingerprint, Slot>>,
}

/// The staples of this process. Cheap to clone; clones share the registry.
#[derive(Clone, Default)]
pub struct Staples {
    inner: Arc<Inner>,
}

impl fmt::Debug for Staples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Staples")
            .field("stapled", &self.inner.served.load().len())
            .finish_non_exhaustive()
    }
}

/// `key` with `response` as its OCSP staple.
fn stapled(key: &CertifiedKey, response: Vec<u8>) -> Arc<CertifiedKey> {
    let mut with = CertifiedKey::new(key.cert.clone(), Arc::clone(&key.key));
    with.ocsp = Some(response);
    Arc::new(with)
}

impl Staples {
    /// The key a handshake should serve: `key` with a verified, unexpired staple when the
    /// registry has one for this exact chain, else `key` itself. Takes no lock and does no I/O.
    #[must_use]
    pub fn attach(&self, key: Arc<CertifiedKey>) -> Arc<CertifiedKey> {
        let served = self.inner.served.load();
        if served.is_empty() {
            return key;
        }
        let Some(leaf) = key.cert.first() else {
            return key;
        };
        match served.get(&Fingerprint::of(leaf)) {
            Some(ready) if ready.key.cert == key.cert && SystemTime::now() < ready.valid_until => {
                Arc::clone(&ready.key)
            }
            _ => key,
        }
    }

    /// Brings the registry in line with the live `table` at time `now` and returns the fetches to
    /// start, earliest due first, at most `limit` of them.
    ///
    /// New certificates are due at once; certificates that left the table are forgotten with
    /// their staples; staples past `nextUpdate` are dropped; a certificate whose chain changed
    /// keeps its staple on the new chain; a certificate that is already being fetched is never
    /// returned twice.
    pub fn tick(&self, table: &RoutingTable, now: SystemTime, limit: usize) -> Vec<Job> {
        let candidates = table.certificates().ocsp_candidates();
        let mut slots = self
            .inner
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut changed = false;
        let live: HashSet<Fingerprint> = candidates.iter().map(|c| c.fingerprint).collect();
        slots.retain(|print, slot| {
            let keep = live.contains(print);
            changed |= !keep && slot.staple.is_some();
            keep
        });
        for candidate in candidates {
            match slots.entry(candidate.fingerprint) {
                Entry::Vacant(vacant) => {
                    if let Err(reason) = &candidate.identity {
                        metrics::rejected(*reason);
                    }
                    vacant.insert(Slot {
                        key: Arc::clone(&candidate.key),
                        staple: None,
                        due: now,
                        failures: 0,
                        busy: false,
                    });
                }
                Entry::Occupied(mut occupied) => {
                    let slot = occupied.get_mut();
                    if Arc::ptr_eq(&slot.key, &candidate.key) {
                        continue;
                    }
                    slot.key = Arc::clone(&candidate.key);
                    if let Some((old, valid_until)) = &slot.staple
                        && old.cert != candidate.key.cert
                    {
                        let response = old.ocsp.clone().unwrap_or_default();
                        slot.staple = Some((stapled(&candidate.key, response), *valid_until));
                        changed = true;
                    }
                }
            }
        }
        for slot in slots.values_mut() {
            if slot.staple.as_ref().is_some_and(|(_, until)| *until <= now) {
                slot.staple = None;
                changed = true;
            }
        }
        // The same leaf declared under two entries is one certificate: one fetch.
        let mut seen = HashSet::new();
        let mut due: Vec<(SystemTime, &Candidate, Arc<Identity>)> = candidates
            .iter()
            .filter_map(|candidate| {
                let identity = candidate.identity.as_ref().ok()?;
                let slot = slots.get(&candidate.fingerprint)?;
                (!slot.busy && slot.due <= now && seen.insert(candidate.fingerprint))
                    .then(|| (slot.due, candidate, Arc::clone(identity)))
            })
            .collect();
        due.sort_by_key(|(at, ..)| *at);
        due.truncate(limit);
        let jobs = due
            .into_iter()
            .map(|(_, candidate, identity)| {
                if let Some(slot) = slots.get_mut(&candidate.fingerprint) {
                    slot.busy = true;
                }
                Job {
                    fingerprint: candidate.fingerprint,
                    identity,
                    key: Arc::clone(&candidate.key),
                    hosts: candidate.hosts.clone(),
                    scope: Scope::of(table, &candidate.hosts, candidate.default),
                }
            })
            .collect();
        if changed {
            self.publish(&slots);
        }
        jobs
    }

    /// Records how the fetch for `fingerprint` ended at `now`. `unit` is a random sample in
    /// `[0, 1)` for the jitter. A certificate that has left the table meanwhile is ignored.
    pub fn finish(&self, fingerprint: Fingerprint, outcome: Outcome, now: SystemTime, unit: f64) {
        let mut slots = self
            .inner
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(slot) = slots.get_mut(&fingerprint) else {
            return;
        };
        slot.busy = false;
        let publish = match outcome {
            Outcome::Verified(verified) => {
                metrics::stapled();
                slot.failures = 0;
                slot.due = next_refresh(verified.this_update, verified.next_update, now, unit);
                slot.staple = Some((stapled(&slot.key, verified.der), verified.next_update));
                true
            }
            Outcome::Failed(reason) => {
                metrics::rejected(reason);
                slot.failures = slot.failures.saturating_add(1);
                slot.due = now + backoff(slot.failures, unit);
                // A revoked certificate must not keep serving the staple from before.
                reason == Reason::Revoked && slot.staple.take().is_some()
            }
        };
        if publish {
            self.publish(&slots);
        }
    }

    fn publish(&self, slots: &HashMap<Fingerprint, Slot>) {
        let map: HashMap<Fingerprint, Served> = slots
            .iter()
            .filter_map(|(print, slot)| {
                let (key, valid_until) = slot.staple.as_ref()?;
                Some((
                    *print,
                    Served {
                        key: Arc::clone(key),
                        valid_until: *valid_until,
                    },
                ))
            })
            .collect();
        metrics::set_staples(map.len());
        self.inner.served.store(Arc::new(map));
    }

    /// How many certificates have a staple right now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.served.load().len()
    }

    /// Whether no certificate has a staple.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
