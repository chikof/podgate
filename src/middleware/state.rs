//! Runtime state of middlewares that outlives a snapshot push: failure counters, caches, nonces.
//!
//! A middleware compiles with fresh state. At the one swap site ([`crate::table::TableHandle`]
//! calls each kind's `settle` just before a table goes live, like the canary and the service
//! state) a middleware that the previous table also had, under the same app, the same name and
//! the same fingerprint of its declaration ([`fingerprint`]), takes over the previous state;
//! anything else keeps the fresh state and replaces the old entry. A push that does not touch a
//! middleware keeps what it learned; a middleware whose declaration changes starts fresh.
//!
//! # Adding state to a kind
//!
//! 1. Put the state in one struct `T` (atomics or mutexes inside) and hold it as an `Arc<T>` in
//!    the compiled middleware, with the [`fingerprint`] of its declaration next to it.
//! 2. Write `fn slot(stage: &mut Stage) -> Option<(u64, &mut Arc<T>)>` returning the fingerprint
//!    and the `Arc` of your kind's stage, `None` for every other kind.
//! 3. Keep one `Registry<T>` per kind in [`crate::table::TableHandle`] (one field, one line in
//!    `swap` calling `Registry::settle` with your `slot`).
//!
//! Requests and background tasks share the `Arc`, so a request whose table was swapped away
//! finishes against the state it started with.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use super::Stage;
use crate::router::digest;
use crate::table::CompiledApp;
use podgate_model::Declared;

/// A digest of everything a middleware declares: equal digests mean the state carries over a
/// push. A kind whose state must outlive a change of part of its declaration (an option that
/// does not affect what it learned) digests only the parts that matter instead.
#[must_use]
pub fn fingerprint(declared: &Declared) -> u64 {
    digest((
        &*declared.kind,
        serde_json::Value::Object(declared.config.clone()).to_string(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    app: Box<str>,
    middleware: Box<str>,
    fingerprint: u64,
}

/// The state of every middleware of one kind in the live table; touched only at the swap site.
pub(crate) struct Registry<T> {
    settled: Mutex<HashMap<Key, Arc<T>>>,
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self {
            settled: Mutex::new(HashMap::new()),
        }
    }
}

impl<T> fmt::Debug for Registry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry").finish_non_exhaustive()
    }
}

/// Picks, from one compiled stage, the fingerprint of its declaration and its state; `None`
/// for a stage of another kind.
pub(crate) type Slot<T> = fn(&mut Stage) -> Option<(u64, &mut Arc<T>)>;

impl<T> Registry<T> {
    /// Settles the state of a table about to go live. `slot` picks, from one compiled stage,
    /// the fingerprint of its declaration and its state (`None` for another kind). A stage the
    /// previous table had under the same (app, name, fingerprint) takes over that state, every
    /// other keeps the fresh state compiled for it. Entries the new table does not have are
    /// dropped; requests that still hold them keep them.
    pub(crate) fn settle(&self, apps: &mut [CompiledApp], slot: Slot<T>) {
        let mut settled = self.settled.lock().unwrap_or_else(PoisonError::into_inner);
        let mut kept = HashMap::new();
        for app in apps {
            let app_id: Box<str> = app.id().into();
            for named in app.stages_mut() {
                let name = named.name.clone();
                let Some((fingerprint, state)) = slot(&mut named.stage) else {
                    continue;
                };
                let key = Key {
                    app: app_id.clone(),
                    middleware: name,
                    fingerprint,
                };
                if let Some(old) = settled.get(&key) {
                    *state = Arc::clone(old);
                }
                kept.insert(key, Arc::clone(state));
            }
        }
        *settled = kept;
    }
}
