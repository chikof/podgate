//! The bounded executor of WASM filter runs: how many may run at once, and what each one is
//! charged.
//!
//! A run is CPU-bound for up to its fuel and holds up to `max_memory_bytes` of linear memory,
//! so two things must be bounded or one tenant's filters can starve the proxy:
//!
//! - Threads. Runs go through `spawn_blocking`, whose pool (512 threads) snapshot compiles
//!   share. An [`Executor`] hands out one permit per run from a semaphore sized by
//!   `WASM_MAX_CONCURRENT`, so filters can hold at most that many of those threads. A run that
//!   cannot get a permit within `WASM_QUEUE_TIMEOUT_MS` is refused.
//! - Memory. Before a run is instantiated, the filter's `max_memory_bytes` is reserved from the
//!   tenant's `max_buffer_bytes`, the same budget response compression draws on
//!   ([`crate::compress::RESERVATION_BYTES`] per compressed response). A run that does not fit is
//!   refused.
//!
//! Both refusals are [`AppError::FilterBusy`]: `503` with `retry-after`, never a partial run.
//! The permit comes first, so a queued request holds no memory while it waits.
//!
//! The returned [`RunSlot`] moves into the blocking closure and drops when the run ends, not
//! when the client goes away: a run keeps its thread and memory until it is done.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::budget::{BufferGuard, TenantBudget};
use crate::error::AppError;

/// Admission for filter runs. Cheap to clone; every clone shares the permits.
#[derive(Debug, Clone)]
pub struct Executor {
    permits: Arc<Semaphore>,
    wait: Duration,
}

/// What one filter run holds: a worker permit and the tenant's memory charge. Dropping it frees
/// both.
#[derive(Debug)]
pub struct RunSlot {
    _permit: OwnedSemaphorePermit,
    _charge: Option<BufferGuard>,
}

impl Executor {
    /// An executor that runs at most `max_concurrent` filters at once; a run waits up to `wait`
    /// for a free worker.
    #[must_use]
    pub fn new(max_concurrent: usize, wait: Duration) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent)),
            wait,
        }
    }

    /// Takes a worker and charges `memory` bytes to `tenant` (no charge when the request has no
    /// tenant slot).
    ///
    /// # Errors
    ///
    /// [`AppError::FilterBusy`] when no worker frees up within the wait, or the tenant's buffer
    /// budget cannot take `memory`.
    pub async fn admit(
        &self,
        tenant: Option<&Arc<TenantBudget>>,
        memory: u64,
    ) -> Result<RunSlot, AppError> {
        let permit = tokio::time::timeout(self.wait, Arc::clone(&self.permits).acquire_owned())
            .await
            .map_err(|_| AppError::FilterBusy)?
            .map_err(|_| AppError::FilterBusy)?;
        let charge = match tenant {
            Some(tenant) => Some(tenant.reserve_filter(memory).ok_or(AppError::FilterBusy)?),
            None => None,
        };
        Ok(RunSlot {
            _permit: permit,
            _charge: charge,
        })
    }
}

impl Default for Executor {
    /// One worker per available core, one second of queueing.
    fn default() -> Self {
        Self::new(
            std::thread::available_parallelism().map_or(1, usize::from),
            Duration::from_secs(1),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::budget::Budgets;
    use crate::snapshot::Budget;

    fn tenant(max_buffer_bytes: u64) -> Arc<TenantBudget> {
        Budgets::new().tenant(
            "t1",
            Budget {
                max_inflight: 10,
                max_buffer_bytes,
            },
        )
    }

    #[tokio::test]
    async fn a_run_holds_its_memory_until_the_slot_drops() {
        let executor = Executor::new(4, Duration::from_millis(50));
        let tenant = tenant(100);
        let first = executor.admit(Some(&tenant), 60).await.expect("fits");
        assert_eq!(tenant.buffered(), 60);
        assert!(matches!(
            executor.admit(Some(&tenant), 60).await,
            Err(AppError::FilterBusy)
        ));
        assert_eq!(tenant.buffered(), 60, "a refused run charges nothing");
        drop(first);
        assert_eq!(tenant.buffered(), 0);
        assert!(executor.admit(Some(&tenant), 60).await.is_ok());
    }

    #[tokio::test]
    async fn a_full_executor_refuses_after_the_wait() {
        let executor = Executor::new(1, Duration::from_millis(20));
        let held = executor.admit(None, 0).await.expect("first worker");
        assert!(matches!(
            executor.admit(None, 0).await,
            Err(AppError::FilterBusy)
        ));
        drop(held);
        assert!(executor.admit(None, 0).await.is_ok());
    }

    #[tokio::test]
    async fn a_queued_run_holds_no_memory() {
        let executor = Executor::new(1, Duration::from_millis(20));
        let tenant = tenant(100);
        let _held = executor.admit(Some(&tenant), 10).await.expect("worker");
        assert!(executor.admit(Some(&tenant), 10).await.is_err());
        assert_eq!(tenant.buffered(), 10);
    }
}
