//! Leaving out the objects podgate rejects, so one bad object cannot block every deploy.
//!
//! podgate stays fail-closed: it rejects a whole snapshot (`422`) when anything in it is wrong.
//! The provider knows the objects, so it decides which one to leave out:
//!
//! 1. **By `declared_by`.** Every conflict of the `422` that names `declared_by` values points at
//!    objects. A conflict between two objects costs the newer one (the older keeps its place);
//!    a conflict about one costs that one. [`attribute`] picks them.
//! 2. **By bisection.** When the rejection names none (a snapshot-level error), the culprits are
//!    among the objects that changed since the last accepted snapshot. [`bisect`] finds them
//!    with `POST /v1/snapshot/validate`, the last accepted state as the base: it spends at most
//!    `1 + k * (ceil(log2 n) + 1)` validations for `k` culprits among `n` changed objects
//!    ([`bisect_bound`]). If the base itself is rejected, or no changed object explains the
//!    rejection, it gives up with an error: it never guesses and never loops, and the caller
//!    keeps the last accepted snapshot.
//!
//! An object stays quarantined until its source changes it (or stops sending it), or until
//! `resync_secs` have passed, so a deploy that fixed itself is picked up without a restart.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use thiserror::Error;

use crate::merge::{Included, Merged};
use crate::source::{ObjectKind, ObjectRef, State};

/// One quarantined object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// `<kind>/<name>:<object>`.
    pub declared_by: Box<str>,
    /// The object's [`fingerprint`](Included::fingerprint) when it was quarantined: a different
    /// one releases it.
    pub fingerprint: Box<str>,
    /// When it was quarantined, in the caller's millisecond count.
    pub since_ms: u64,
    /// Why, in words.
    pub reason: Box<str>,
}

/// The quarantined objects.
#[derive(Debug, Clone, Default)]
pub struct Quarantine {
    held: BTreeMap<ObjectRef, Held>,
}

impl Quarantine {
    /// No object is quarantined.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The quarantined objects and why.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<ObjectRef, Held> {
        &self.held
    }

    /// The identities to leave out of a merge.
    #[must_use]
    pub fn excluded(&self) -> BTreeSet<ObjectRef> {
        self.held.keys().cloned().collect()
    }

    /// Quarantines `object` at `now_ms`.
    pub fn hold(&mut self, object: &Included, reason: &str, now_ms: u64) {
        self.held.insert(
            object.object.clone(),
            Held {
                declared_by: object.declared_by.clone(),
                fingerprint: object.fingerprint.clone(),
                since_ms: now_ms,
                reason: reason.into(),
            },
        );
    }

    /// Releases the objects of `source` that `state` no longer sends or sends changed.
    pub fn release_changed(&mut self, source: &str, state: &State) -> Vec<(ObjectRef, Held)> {
        let mut current: BTreeMap<ObjectRef, Box<str>> = BTreeMap::new();
        for app in &state.apps {
            current.insert(
                ObjectRef {
                    source: source.into(),
                    kind: ObjectKind::App,
                    object: app.origin.object.clone(),
                },
                app.fingerprint(),
            );
        }
        for cert in &state.certificates {
            current.insert(
                ObjectRef {
                    source: source.into(),
                    kind: ObjectKind::Certificate,
                    object: cert.origin.object.clone(),
                },
                cert.fingerprint(),
            );
        }
        self.release(|object, held| {
            &*object.source == source && current.get(object) != Some(&held.fingerprint)
        })
    }

    /// Releases the objects held for `after_ms` or longer at `now_ms`.
    pub fn expire(&mut self, now_ms: u64, after_ms: u64) -> Vec<(ObjectRef, Held)> {
        self.release(|_, held| now_ms.saturating_sub(held.since_ms) >= after_ms)
    }

    fn release(
        &mut self,
        mut leaves: impl FnMut(&ObjectRef, &Held) -> bool,
    ) -> Vec<(ObjectRef, Held)> {
        let leaving: Vec<ObjectRef> = self
            .held
            .iter()
            .filter(|(object, held)| leaves(object, held))
            .map(|(object, _)| object.clone())
            .collect();
        leaving
            .into_iter()
            .filter_map(|object| self.held.remove(&object).map(|held| (object, held)))
            .collect()
    }
}

/// An object to quarantine and the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Culprit {
    /// The object.
    pub object: Included,
    /// Why, in words.
    pub reason: Box<str>,
}

/// The `declared_by` values a conflict names: a string, or a list of strings.
fn declared_by_of(conflict: &Value) -> Vec<&str> {
    match conflict.get("declared_by") {
        Some(Value::String(one)) => vec![one],
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// The objects of `merged` that the conflicts of a `422` name and that have to go.
///
/// Conflicts are read in order. A conflict that names an object already chosen is resolved by
/// that choice and skipped. One that names two or more objects keeps the oldest (by
/// `first_seen`, then source and object name) and drops the others; one that names a single
/// object drops it. A conflict that names no object of `merged` (a snapshot-level rejection)
/// contributes nothing.
#[must_use]
pub fn attribute(merged: &Merged, conflicts: &[Value]) -> Vec<Culprit> {
    let find = |declared_by: &str| {
        merged
            .included()
            .iter()
            .find(|included| &*included.declared_by == declared_by)
    };
    let mut chosen: Vec<Culprit> = Vec::new();
    for conflict in conflicts {
        let mut named: Vec<&Included> = declared_by_of(conflict)
            .into_iter()
            .filter_map(find)
            .collect();
        named.sort_by(|a, b| {
            (a.first_seen, &a.object.source, &a.object.object).cmp(&(
                b.first_seen,
                &b.object.source,
                &b.object.object,
            ))
        });
        named.dedup_by(|a, b| a.object == b.object);
        if named.iter().any(|object| {
            chosen
                .iter()
                .any(|culprit| culprit.object.object == object.object)
        }) {
            continue;
        }
        let code = conflict
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("rejected");
        let message = conflict
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("");
        let reason = format!("podgate rejected the snapshot ({code}): {message}");
        let losers = if named.len() == 1 {
            &named[..]
        } else {
            named.get(1..).unwrap_or(&[])
        };
        for loser in losers {
            chosen.push(Culprit {
                object: (*loser).clone(),
                reason: reason.clone().into(),
            });
        }
    }
    chosen
}

/// What validation said about one candidate.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// The compiler accepts it.
    Valid,
    /// The compiler refuses it; the `conflicts` of the `422`.
    Rejected(Vec<Value>),
}

/// Why bisection did not produce culprits.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum BisectError {
    /// Nothing changed since the last accepted snapshot, so no object can be blamed.
    #[error("nothing changed since the last accepted snapshot, so no object can be blamed")]
    NothingChanged,
    /// The last accepted state is rejected too: the cause is not in the changed objects (the
    /// daemon's configuration may have changed under it).
    #[error(
        "the last accepted state is rejected as well, so the changed objects are not the cause"
    )]
    BaseRejected(Vec<Value>),
    /// A validation could not be asked or answered. The caller retries later.
    #[error("validation failed: {0}")]
    Failed(Box<str>),
}

/// The most validations [`bisect`] spends for `culprits` culprits among `changed` changed
/// objects: `1 + culprits * (ceil(log2 changed) + 1)`.
#[must_use]
pub fn bisect_bound(changed: usize, culprits: usize) -> usize {
    let log = usize::BITS - changed.saturating_sub(1).leading_zeros();
    1 + culprits * (log as usize + 1)
}

/// The result of a bisection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bisected {
    /// The objects to leave out, oldest first.
    pub culprits: Vec<Included>,
    /// How many validations it asked.
    pub calls: usize,
}

/// Asks whether a candidate snapshot compiles: `POST /v1/snapshot/validate` in the program, a
/// rule in a test.
pub trait Validate {
    /// The compiler's verdict on `candidate`.
    ///
    /// # Errors
    ///
    /// The reason in words when the question could not be asked or answered.
    fn validate(
        &mut self,
        candidate: &Merged,
    ) -> impl Future<Output = Result<Verdict, Box<str>>> + Send;
}

/// Counts the questions and builds each candidate.
struct Asker<'a, V, B> {
    validate: &'a mut V,
    build: B,
    calls: usize,
}

impl<V: Validate, B: Fn(&BTreeSet<ObjectRef>) -> Merged> Asker<'_, V, B> {
    async fn check(&mut self, excluded: BTreeSet<ObjectRef>) -> Result<Verdict, BisectError> {
        self.calls += 1;
        let candidate = (self.build)(&excluded);
        self.validate
            .validate(&candidate)
            .await
            .map_err(BisectError::Failed)
    }
}

/// The identities of `rest[middle..]` and the found culprits: what to leave out to test the
/// snapshot with the first `middle` objects of `rest` added.
fn leave_out(rest: &[Included], middle: usize, culprits: &[Included]) -> BTreeSet<ObjectRef> {
    rest[middle..]
        .iter()
        .chain(culprits)
        .map(|included| included.object.clone())
        .collect()
}

/// Finds the objects among `changed` (oldest first) that make the snapshot rejected.
///
/// `build` makes the merged snapshot with the given objects left out on top of whatever is
/// quarantined already; `validate` asks the daemon. The base is the snapshot without any changed
/// object; the search then finds, by binary search over prefixes of `changed`, the first object
/// whose addition makes the snapshot rejected, leaves it out, and continues after it. A conflict
/// between two changed objects therefore costs the newer one.
///
/// The search assumes that adding objects does not cure a rejection; an object it names was
/// confirmed to break the snapshot when added to a snapshot that was accepted.
///
/// # Errors
///
/// [`BisectError`] when there is nothing to blame, when the base is rejected, or when a
/// validation fails.
pub async fn bisect<V: Validate>(
    changed: &[Included],
    build: impl Fn(&BTreeSet<ObjectRef>) -> Merged,
    validate: &mut V,
) -> Result<Bisected, BisectError> {
    if changed.is_empty() {
        return Err(BisectError::NothingChanged);
    }
    let mut asker = Asker {
        validate,
        build,
        calls: 0,
    };
    let mut rest: &[Included] = changed;
    let mut culprits: Vec<Included> = Vec::new();
    // The state before any changed object: everything changed is left out.
    let base: BTreeSet<ObjectRef> = rest
        .iter()
        .map(|included| included.object.clone())
        .collect();
    if let Verdict::Rejected(conflicts) = asker.check(base).await? {
        return Err(BisectError::BaseRejected(conflicts));
    }
    // The caller got the rejection for the full set, so the first round needs no check of it.
    let mut known_rejected = true;
    while !rest.is_empty() {
        if !known_rejected
            && asker.check(leave_out(rest, rest.len(), &culprits)).await? == Verdict::Valid
        {
            break;
        }
        known_rejected = false;
        // Valid with the first `low` objects added, rejected with the first `high`.
        let (mut low, mut high) = (0, rest.len());
        while high - low > 1 {
            let middle = low + (high - low) / 2;
            match asker.check(leave_out(rest, middle, &culprits)).await? {
                Verdict::Valid => low = middle,
                Verdict::Rejected(_) => high = middle,
            }
        }
        culprits.push(rest[high - 1].clone());
        rest = &rest[high..];
    }
    Ok(Bisected {
        culprits,
        calls: asker.calls,
    })
}
