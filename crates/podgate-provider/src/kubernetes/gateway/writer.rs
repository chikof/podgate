//! Writes the status patches of [`super::status::plan`], on the leader only.
//!
//! The planner hands over the complete list of patches still to be written whenever something
//! changed, replacing the previous list: a patch that is overtaken before it is written is never
//! written (coalescing). For every object the writer
//!
//! - writes nothing unless [`Leader::is_leader`] holds at that very moment, so a lost lease
//!   stops the writes at once;
//! - writes at most one patch per `min_interval` (one second), and sends the newest plan after
//!   that;
//! - never sends the same patch twice: the patch carries the `resourceVersion` it was computed
//!   from, so it is the same patch until the watch brings the object's next version and the
//!   plan changes;
//! - on `409` (another writer, or the object changed) waits for that next version, and on any
//!   other failure tries again after `retry`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, warn};

use super::status::{Target, Write};
use super::types::{Gateway, GatewayClass, GrpcRoute, HttpRoute};
use crate::kubernetes::client::{ApiClient, ClientError};
use crate::kubernetes::lease::Leader;

/// The writer's timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// The least time between two patches of one object.
    pub min_interval: Duration,
    /// How long to wait after a failed patch (other than `409`).
    pub retry: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_secs(1),
            retry: Duration::from_secs(5),
        }
    }
}

/// The plans the planner has made, newest only.
pub type Plan = watch::Sender<Arc<Vec<Write>>>;

/// Where a plan arrives.
pub type Plans = watch::Receiver<Arc<Vec<Write>>>;

/// A channel for plans, empty at first.
#[must_use]
pub fn channel() -> (Plan, Plans) {
    watch::channel(Arc::new(Vec::new()))
}

async fn patch(client: &ApiClient, write: &Write) -> Result<(), ClientError> {
    let (namespace, name) = write.target.parts();
    let body: &Value = &write.body;
    match &write.target {
        Target::Class(_) => client
            .merge_patch::<GatewayClass>(None, name, Some("status"), body)
            .await
            .map(drop),
        Target::Gateway(_) => client
            .merge_patch::<Gateway>(namespace, name, Some("status"), body)
            .await
            .map(drop),
        Target::Http(_) => client
            .merge_patch::<HttpRoute>(namespace, name, Some("status"), body)
            .await
            .map(drop),
        Target::Grpc(_) => client
            .merge_patch::<GrpcRoute>(namespace, name, Some("status"), body)
            .await
            .map(drop),
    }
}

/// Runs until the planner is gone.
pub async fn run(client: ApiClient, mut leader: Leader, mut plans: Plans, tuning: Tuning) {
    // What was sent last for each object, so that it is not sent again.
    let mut sent: BTreeMap<Target, Value> = BTreeMap::new();
    // When each object may be written next.
    let mut next: BTreeMap<Target, Instant> = BTreeMap::new();
    loop {
        let writes = Arc::clone(&plans.borrow_and_update());
        let mut wake: Option<Instant> = None;
        for write in writes.iter() {
            if sent.get(&write.target) == Some(&write.body) {
                continue;
            }
            let now = Instant::now();
            let due = next.get(&write.target).copied().unwrap_or(now);
            if due > now {
                wake = Some(wake.map_or(due, |wake| wake.min(due)));
                continue;
            }
            if !leader.is_leader() {
                break;
            }
            match patch(&client, write).await {
                Ok(()) => {
                    debug!(
                        kind = write.target.kind(),
                        object = write.target.key(),
                        "status written"
                    );
                    sent.insert(write.target.clone(), write.body.clone());
                    next.insert(write.target.clone(), Instant::now() + tuning.min_interval);
                }
                Err(err) if err.http_status() == Some(409) => {
                    debug!(
                        kind = write.target.kind(),
                        object = write.target.key(),
                        "status not written: the object moved on; the next version brings a new patch"
                    );
                    sent.insert(write.target.clone(), write.body.clone());
                    next.insert(write.target.clone(), Instant::now() + tuning.min_interval);
                }
                Err(err) => {
                    warn!(
                        kind = write.target.kind(),
                        object = write.target.key(),
                        error = %err,
                        "cannot write status; trying again"
                    );
                    let again = Instant::now() + tuning.retry;
                    next.insert(write.target.clone(), again);
                    wake = Some(wake.map_or(again, |wake| wake.min(again)));
                }
            }
        }
        sent.retain(|target, _| writes.iter().any(|write| &write.target == target));
        next.retain(|target, at| {
            *at > Instant::now() || writes.iter().any(|w| &w.target == target)
        });
        tokio::select! {
            changed = plans.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = leader.changed() => {}
            () = async {
                match wake {
                    Some(at) => sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {}
        }
    }
}
