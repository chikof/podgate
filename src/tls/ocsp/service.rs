//! The refresher: a background service that starts a fetch for every certificate that is due,
//! at most [`MAX_CONCURRENT`] at once node-wide, and one per certificate.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::sync::Semaphore;

use super::reason::Reason;
use super::runner::Runner;
use super::staples::{Outcome, Staples};
use crate::table::TableHandle;

/// Fetches in flight at once, node-wide.
pub const MAX_CONCURRENT: usize = 8;

/// How often the registry is brought in line with the live table and due fetches start. A new
/// certificate waits at most this long for its first fetch.
const TICK: Duration = Duration::from_millis(500);

/// Keeps the staples of the live table fresh.
#[derive(Debug)]
pub struct OcspService {
    table: TableHandle,
    staples: Staples,
    runner: Runner,
    permits: Arc<Semaphore>,
}

impl OcspService {
    /// A refresher for the certificates of `table`, publishing into `staples`.
    #[must_use]
    pub fn new(table: TableHandle, staples: Staples, runner: Runner) -> Self {
        Self {
            table,
            staples,
            runner,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT)),
        }
    }

    fn start_due(&self) {
        let table = self.table.load();
        let jobs = self
            .staples
            .tick(&table, SystemTime::now(), self.permits.available_permits());
        for job in jobs {
            let (staples, runner, permits) = (
                self.staples.clone(),
                self.runner.clone(),
                Arc::clone(&self.permits),
            );
            tokio::spawn(async move {
                // `tick` returned at most as many jobs as there were free permits and only this
                // loop takes them, so this does not wait; an error means shutdown.
                let Ok(_permit) = permits.acquire_owned().await else {
                    return;
                };
                let outcome = runner.run(&job).await;
                match &outcome {
                    Outcome::Failed(Reason::Revoked) => tracing::warn!(
                        hosts = %job.hosts().join(","),
                        "ocsp: the responder says this certificate is revoked; it is served without a staple"
                    ),
                    Outcome::Failed(reason) => tracing::debug!(
                        hosts = %job.hosts().join(","),
                        %reason,
                        "ocsp: no staple this time"
                    ),
                    Outcome::Verified(_) => tracing::debug!(
                        hosts = %job.hosts().join(","),
                        "ocsp: staple refreshed"
                    ),
                }
                staples.finish(job.fingerprint(), outcome, SystemTime::now(), unit());
            });
        }
    }
}

/// A random number in `[0, 1)`; `0.5` when the system has no randomness, which only removes the
/// jitter.
fn unit() -> f64 {
    let mut bytes = [0_u8; 4];
    if getrandom::fill(&mut bytes).is_err() {
        return 0.5;
    }
    f64::from(u32::from_le_bytes(bytes)) / 4_294_967_296.0
}

#[async_trait]
impl BackgroundService for OcspService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // The timeout elapsing is the tick; the channel changing or closing is the shutdown.
        while tokio::time::timeout(TICK, shutdown.changed())
            .await
            .is_err()
        {
            self.start_due();
        }
    }
}
