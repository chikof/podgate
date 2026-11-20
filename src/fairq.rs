//! Backend admission: an adaptive concurrency limit per upstream address, and weighted fair
//! queuing of the tenants that wait for it.
//!
//! No static rate limits. A backend's capacity is whatever keeps its latency flat, so the limit
//! is learned from the latency the proxy observes, and tenants that contend for it share it by
//! `Tenant.weight`.
//!
//! # Where a limiter lives
//!
//! One [`Limiter`] per upstream socket address, kept in [`Backends`]. An address is what has a
//! latency and a capacity; apps and revisions that name the same address share it, and so do the
//! tenants behind them. Revisions with their own addresses (the usual case) each get their own
//! limiter, so a slow revision never throttles another. [`Backends::admit`] runs in
//! `request_filter` after the tenant slot, so a request that waits here still counts
//! against its tenant's `max_inflight`.
//!
//! # The limit
//!
//! A gradient limit in the style of Netflix `Gradient2`, driven by the time from "connected to the
//! upstream" to "upstream response headers" (a [`Slot`] measures it):
//!
//! - Every `WINDOW` samples the mean latency `short` is compared with the baseline `min_rtt`,
//!   the lowest window mean seen. The baseline creeps up by `BASELINE_DRIFT` per window, slowly
//!   enough that queueing caused by a too high limit is not mistaken for the normal latency, and
//!   follows a faster backend down at once. When the limit sits at `MIN_LIMIT` the backend has
//!   no concurrency to queue behind, so the baseline adopts `short`: a backend that became
//!   permanently slower is accepted as the new normal.
//! - `gradient = clamp(TOLERANCE * min_rtt / short, MIN_GRADIENT, 1)`.
//! - `target = limit * gradient + sqrt(limit)`: the limit shrinks while latency is more than
//!   `TOLERANCE` times the baseline and grows by the queue allowance `sqrt(limit)` otherwise.
//! - `limit = limit * (1 - SMOOTHING) + target * SMOOTHING`, clamped to
//!   [[`MIN_LIMIT`], [`MAX_LIMIT`]].
//!
//! The limit does not grow while the backend is under-used (peak in-flight of the window below
//! half the limit), or it would grow without bound on an idle backend. Responses of `5xx` are not
//! sampled: a backend that fails fast would look healthy. A `101` response releases the slot at
//! once, so a websocket does not hold a slot for its whole life. Failed or timed-out
//! requests give no signal; the limit only follows latency of requests that got a response.
//!
//! # Fair queuing
//!
//! A request that finds the limit reached waits in its tenant's queue ([`QUEUE_CAP`] entries at
//! most, then `503`; at most [`MAX_WAIT`], then `503`; both `retry-after: 1`). A freed slot goes
//! to the waiter with the smallest start tag (start-time fair queuing): a request of weight `w`
//! costs `1/w` of virtual time, so under contention tenants are served in proportion to their
//! weights, and a tenant that was idle starts at the current virtual time instead of with a
//! credit. Ties go to the older request.
//!
//! # Hot path
//!
//! With the limit not reached and nobody waiting, admission is one compare-and-swap on the
//! limiter's in-flight count after an [`ArcSwap`] registry lookup, and releasing is one
//! subtraction; no lock and no allocation. The queue lock is taken only to wait, to hand a slot
//! to a waiter, and when a waiter gives up. Latency samples are summed in atomics; the thread
//! that completes a window updates the estimate under `try_lock`, so no request ever blocks on
//! it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::{self, Write as _};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::sync::oneshot;

use crate::error::AppError;
use crate::route::Selected;
use crate::table::{CompiledApp, RoutingTable};

/// Limit a new backend starts with.
const INITIAL_LIMIT: f64 = 32.0;
/// The limit never falls below this, so a backend with a bad window still gets traffic to
/// measure.
pub const MIN_LIMIT: u32 = 4;
/// The limit never grows past this.
pub const MAX_LIMIT: u32 = 2048;
/// Latency samples per estimate update.
const WINDOW: u32 = 16;
/// How far latency may rise over the baseline before the limit shrinks.
const TOLERANCE: f64 = 1.25;
/// The strongest shrink of one update: the limit halves before smoothing.
const MIN_GRADIENT: f64 = 0.5;
/// Share of the new target taken by each update.
const SMOOTHING: f64 = 0.2;
/// Per-window upward creep of the baseline while the limit is above the floor.
const BASELINE_DRIFT: f64 = 1.0001;
/// Most requests one tenant may have waiting for one backend; the next one gets `503`.
pub const QUEUE_CAP: usize = 512;
/// Longest a request waits for a backend slot before it gets `503`.
pub const MAX_WAIT: Duration = Duration::from_secs(5);
/// Virtual time cost of one request at weight 1; a request of weight `w` costs `SCALE / w`.
const SCALE: u64 = 1 << 24;
/// Weights are clamped here so a request always costs at least `SCALE / MAX_WEIGHT` > 0.
const MAX_WEIGHT: u32 = 65_535;

/// The gradient estimate. Pure, so tests feed it latencies directly.
#[derive(Debug)]
struct Estimator {
    limit: f64,
    /// Baseline latency in nanoseconds; `0` until the first window.
    min_rtt: f64,
}

impl Estimator {
    fn new() -> Self {
        Self {
            limit: INITIAL_LIMIT,
            min_rtt: 0.0,
        }
    }

    /// Folds in one window: its mean latency in nanoseconds and the peak in-flight count seen in
    /// it. Returns the new limit.
    fn update(&mut self, short_rtt: f64, peak_inflight: u32) -> u32 {
        if short_rtt > 0.0 {
            // At the floor the backend has almost no concurrency to queue behind, so its latency
            // is its own: adopt it. Above the floor the baseline only creeps up, so queueing
            // caused by too high a limit is not mistaken for the normal latency.
            let at_floor = self.current() <= MIN_LIMIT;
            self.min_rtt = if self.min_rtt > 0.0 && !at_floor {
                short_rtt.min(self.min_rtt * BASELINE_DRIFT)
            } else {
                short_rtt
            };
            let gradient = (TOLERANCE * self.min_rtt / short_rtt).clamp(MIN_GRADIENT, 1.0);
            let target = self.limit.mul_add(gradient, self.limit.sqrt());
            let under_used = f64::from(peak_inflight) < self.limit / 2.0;
            if !(target > self.limit && under_used) {
                self.limit = self.limit.mul_add(1.0 - SMOOTHING, target * SMOOTHING);
            }
            self.limit = self.limit.clamp(f64::from(MIN_LIMIT), f64::from(MAX_LIMIT));
        }
        self.current()
    }

    fn current(&self) -> u32 {
        // The limit is clamped to [MIN_LIMIT, MAX_LIMIT] and finite, so the cast is exact.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "limit is clamped to [MIN_LIMIT, MAX_LIMIT]"
        )]
        let limit = self.limit.round() as u32;
        limit
    }
}

/// One request waiting for a slot.
struct Waiter {
    ticket: u64,
    /// Start tag: the virtual time this request is served from.
    start: u64,
    grant: oneshot::Sender<Permit>,
}

/// The waiting requests of one tenant, oldest first.
struct TenantQueue {
    id: Box<str>,
    /// Virtual time at which this tenant's last queued request finishes.
    last_finish: u64,
    waiters: VecDeque<Waiter>,
}

/// Per-tenant FIFO queues served in weighted-fair order. Holds no empty queue.
#[derive(Default)]
struct Queues {
    virtual_time: u64,
    next_ticket: u64,
    tenants: Vec<TenantQueue>,
}

impl Queues {
    fn has_waiters(&self) -> bool {
        !self.tenants.is_empty()
    }

    /// Queues a request of `tenant` and returns its ticket, or `None` when the tenant's queue is
    /// full.
    fn push(&mut self, tenant: &str, weight: u32, grant: oneshot::Sender<Permit>) -> Option<u64> {
        let index = match self.tenants.iter().position(|queue| &*queue.id == tenant) {
            Some(index) => index,
            None => {
                self.tenants.push(TenantQueue {
                    id: tenant.into(),
                    last_finish: 0,
                    waiters: VecDeque::new(),
                });
                self.tenants.len() - 1
            }
        };
        let queue = self.tenants.get_mut(index)?;
        if queue.waiters.len() >= QUEUE_CAP {
            return None;
        }
        let start = self.virtual_time.max(queue.last_finish);
        queue.last_finish = start.saturating_add(SCALE / u64::from(weight.clamp(1, MAX_WEIGHT)));
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        queue.waiters.push_back(Waiter {
            ticket,
            start,
            grant,
        });
        Some(ticket)
    }

    /// Takes the waiter to serve next: the smallest start tag, the oldest on a tie.
    fn pop_next(&mut self) -> Option<Waiter> {
        let index = self
            .tenants
            .iter()
            .enumerate()
            .filter_map(|(index, queue)| Some((index, queue.waiters.front()?)))
            .min_by_key(|(_, head)| (head.start, head.ticket))?
            .0;
        let queue = self.tenants.get_mut(index)?;
        let waiter = queue.waiters.pop_front()?;
        self.virtual_time = waiter.start;
        self.drop_if_empty(index);
        Some(waiter)
    }

    /// Takes the request `ticket` of `tenant` out; `false` when it was already served.
    fn remove(&mut self, tenant: &str, ticket: u64) -> bool {
        let Some(index) = self.tenants.iter().position(|queue| &*queue.id == tenant) else {
            return false;
        };
        let Some(queue) = self.tenants.get_mut(index) else {
            return false;
        };
        let Some(at) = queue.waiters.iter().position(|w| w.ticket == ticket) else {
            return false;
        };
        queue.waiters.remove(at);
        self.drop_if_empty(index);
        true
    }

    fn drop_if_empty(&mut self, index: usize) {
        if self
            .tenants
            .get(index)
            .is_some_and(|queue| queue.waiters.is_empty())
        {
            self.tenants.swap_remove(index);
            if self.tenants.is_empty() {
                self.virtual_time = 0;
            }
        }
    }
}

/// Why a request got no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The tenant already has [`QUEUE_CAP`] requests waiting for this backend.
    QueueFull,
    /// No slot came free within the wait bound.
    Timeout,
}

/// The adaptive limit and the fair queues of one backend.
pub struct Limiter {
    limit: AtomicU32,
    inflight: AtomicU32,
    queued: AtomicU32,
    window_samples: AtomicU32,
    window_nanos: AtomicU64,
    window_peak: AtomicU32,
    estimator: Mutex<Estimator>,
    queues: Mutex<Queues>,
    waited: AtomicU64,
    refused: AtomicU64,
}

impl fmt::Debug for Limiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Limiter")
            .field("limit", &self.limit())
            .field("inflight", &self.inflight())
            .field("queued", &self.queued())
            .finish_non_exhaustive()
    }
}

impl Limiter {
    /// A limiter at the initial limit.
    #[must_use]
    pub fn new() -> Arc<Self> {
        let estimator = Estimator::new();
        Arc::new(Self {
            limit: AtomicU32::new(estimator.current()),
            inflight: AtomicU32::new(0),
            queued: AtomicU32::new(0),
            window_samples: AtomicU32::new(0),
            window_nanos: AtomicU64::new(0),
            window_peak: AtomicU32::new(0),
            estimator: Mutex::new(estimator),
            queues: Mutex::new(Queues::default()),
            waited: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        })
    }

    /// The current concurrency limit.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Requests holding a slot now.
    #[must_use]
    pub fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// Requests waiting for a slot now.
    #[must_use]
    pub fn queued(&self) -> u32 {
        self.queued.load(Ordering::Relaxed)
    }

    fn lock_queues(&self) -> MutexGuard<'_, Queues> {
        self.queues.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes a slot if the limit allows one, without waiting.
    #[must_use]
    pub fn try_acquire(self: &Arc<Self>) -> Option<Permit> {
        let limit = self.limit.load(Ordering::Relaxed);
        self.inflight
            .try_update(Ordering::SeqCst, Ordering::Relaxed, |now| {
                (now < limit).then_some(now + 1)
            })
            .ok()?;
        Some(Permit {
            limiter: Arc::clone(self),
        })
    }

    /// Takes a slot for a request of `tenant` (fair-share `weight`): at once when the limit is not
    /// reached and nobody waits, else after queuing behind the requests the weights put first.
    ///
    /// # Errors
    ///
    /// [`Refusal::QueueFull`] when the tenant's queue is full, [`Refusal::Timeout`] when no slot
    /// came free within `max_wait`.
    pub async fn admit(
        self: &Arc<Self>,
        tenant: &str,
        weight: u32,
        max_wait: Duration,
    ) -> Result<Permit, Refusal> {
        if self.queued.load(Ordering::SeqCst) == 0
            && let Some(permit) = self.try_acquire()
        {
            return Ok(permit);
        }
        let (grant, mut granted) = oneshot::channel();
        let ticket = {
            let mut queues = self.lock_queues();
            let ticket = queues.push(tenant, weight, grant).ok_or_else(|| {
                self.refused.fetch_add(1, Ordering::Relaxed);
                Refusal::QueueFull
            })?;
            self.queued.fetch_add(1, Ordering::SeqCst);
            ticket
        };
        self.waited.fetch_add(1, Ordering::Relaxed);
        let mut waiting = Waiting {
            limiter: self,
            tenant,
            ticket,
            armed: true,
        };
        // A slot may have freed between the failed `try_acquire` and the push.
        self.dispatch();
        match tokio::time::timeout(max_wait, &mut granted).await {
            Ok(Ok(permit)) => {
                waiting.armed = false;
                Ok(permit)
            }
            // Cannot happen: a waiter's sender is dropped only after sending or when the
            // request is removed, and we remove it only below.
            Ok(Err(_)) => Err(Refusal::Timeout),
            Err(_) => {
                // A grant may have landed while the timer fired: take it rather than lose it.
                granted.close();
                if let Ok(permit) = granted.try_recv() {
                    waiting.armed = false;
                    return Ok(permit);
                }
                self.refused.fetch_add(1, Ordering::Relaxed);
                Err(Refusal::Timeout)
            }
        }
    }

    /// Hands free slots to waiters in fair order until none is free or nobody waits.
    fn dispatch(self: &Arc<Self>) {
        let mut spare: Option<Permit> = None;
        loop {
            let (permit, waiter) = {
                let mut queues = self.lock_queues();
                if !queues.has_waiters() {
                    break;
                }
                let Some(permit) = spare.take().or_else(|| self.try_acquire()) else {
                    break;
                };
                let Some(waiter) = queues.pop_next() else {
                    spare = Some(permit);
                    break;
                };
                self.queued.fetch_sub(1, Ordering::SeqCst);
                (permit, waiter)
            };
            // A waiter whose request was cancelled gives the slot back: try the next one with it.
            if let Err(back) = waiter.grant.send(permit) {
                spare = Some(back);
            }
        }
        // Outside the lock: dropping a permit may dispatch again.
        drop(spare);
    }

    /// Records the upstream latency of one response. Every `WINDOW` samples the estimate is
    /// updated and, when the limit rose, waiters are served.
    pub fn record(self: &Arc<Self>, rtt: Duration) {
        let nanos = u64::try_from(rtt.as_nanos()).unwrap_or(u64::MAX);
        self.window_peak
            .fetch_max(self.inflight.load(Ordering::Relaxed), Ordering::Relaxed);
        self.window_nanos.fetch_add(nanos, Ordering::Relaxed);
        if self.window_samples.fetch_add(1, Ordering::Relaxed) + 1 < WINDOW {
            return;
        }
        let mut estimator = match self.estimator.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            // Another thread is updating; the next sample retries.
            Err(TryLockError::WouldBlock) => return,
        };
        let samples = self.window_samples.swap(0, Ordering::Relaxed);
        let total = self.window_nanos.swap(0, Ordering::Relaxed);
        let peak = self.window_peak.swap(0, Ordering::Relaxed);
        if samples == 0 {
            return;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "a mean latency in nanoseconds needs no more than f64 precision"
        )]
        let mean = total as f64 / f64::from(samples);
        self.limit
            .store(estimator.update(mean, peak), Ordering::Relaxed);
        drop(estimator);
        if self.queued.load(Ordering::SeqCst) > 0 {
            self.dispatch();
        }
    }
}

/// Removes a request from the queue when its wait ends without a grant: timeout, or the request
/// future dropped because the client went away.
struct Waiting<'a> {
    limiter: &'a Arc<Limiter>,
    tenant: &'a str,
    ticket: u64,
    armed: bool,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if self.armed && self.limiter.lock_queues().remove(self.tenant, self.ticket) {
            self.limiter.queued.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// One slot of a backend. Dropping it frees the slot for the next waiter.
#[derive(Debug)]
pub struct Permit {
    limiter: Arc<Limiter>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.limiter.inflight.fetch_sub(1, Ordering::SeqCst);
        if self.limiter.queued.load(Ordering::SeqCst) > 0 {
            self.limiter.dispatch();
        }
    }
}

/// What one proxied request holds of its backend: the slot and the latency timer. Lives in the
/// request `Ctx`; the default holds nothing.
#[derive(Debug, Default)]
pub struct Slot {
    permit: Option<Permit>,
    connected_at: Option<Instant>,
}

impl Slot {
    /// Starts the latency timer: the connection to the upstream is ready.
    pub fn connected(&mut self) {
        if self.permit.is_some() {
            self.connected_at = Some(Instant::now());
        }
    }

    /// The upstream answered with `status`: records the latency, except for `5xx`, and frees the
    /// slot of a `101` upgrade at once.
    pub fn responded(&mut self, status: u16) {
        let started = self.connected_at.take();
        let Some(permit) = &self.permit else { return };
        if let Some(started) = started.filter(|_| status < 500) {
            permit.limiter.record(started.elapsed());
        }
        if status == 101 {
            self.permit = None;
        }
    }

    /// Frees the slot. Safe to call more than once.
    pub fn release(&mut self) {
        self.permit = None;
        self.connected_at = None;
    }
}

type Registry = HashMap<SocketAddr, Arc<Limiter>>;

/// One metric family: name, type, help text and how to read a limiter's sample.
type Family = (
    &'static str,
    &'static str,
    &'static str,
    fn(&Limiter) -> u64,
);

#[derive(Debug)]
struct Shared {
    limiters: ArcSwap<Registry>,
    /// Serializes registry changes.
    writer: Mutex<()>,
    max_wait: Duration,
}

/// The limiters of every backend. Cheap to clone; every clone is the same registry.
#[derive(Debug, Clone)]
pub struct Backends {
    shared: Arc<Shared>,
}

impl Default for Backends {
    fn default() -> Self {
        Self::new()
    }
}

impl Backends {
    /// An empty registry; requests wait at most [`MAX_WAIT`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_wait(MAX_WAIT)
    }

    /// An empty registry whose waiting requests give up after `max_wait`.
    #[must_use]
    pub fn with_max_wait(max_wait: Duration) -> Self {
        Self {
            shared: Arc::new(Shared {
                limiters: ArcSwap::from_pointee(Registry::new()),
                writer: Mutex::new(()),
                max_wait,
            }),
        }
    }

    /// The limiter of `addr`, created on first use. Creating one also drops the limiters of
    /// addresses `table` no longer names, unless they are busy.
    fn limiter(&self, table: &RoutingTable, addr: SocketAddr) -> Arc<Limiter> {
        if let Some(limiter) = self.shared.limiters.load().get(&addr) {
            return Arc::clone(limiter);
        }
        let _writer = self
            .shared
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let old = self.shared.limiters.load_full();
        if let Some(limiter) = old.get(&addr) {
            return Arc::clone(limiter);
        }
        let named: HashSet<SocketAddr> = table
            .apps()
            .iter()
            .flat_map(CompiledApp::upstream_addrs)
            .collect();
        let mut next: Registry = old
            .iter()
            .filter(|(known, limiter)| {
                named.contains(known) || limiter.inflight() > 0 || limiter.queued() > 0
            })
            .map(|(known, limiter)| (*known, Arc::clone(limiter)))
            .collect();
        let limiter = Limiter::new();
        next.insert(addr, Arc::clone(&limiter));
        self.shared.limiters.store(Arc::new(next));
        limiter
    }

    /// Admits a routed request to its backend: takes a slot of the picked upstream's limiter,
    /// waiting in the tenant's fair queue when the limit is reached.
    ///
    /// # Errors
    ///
    /// [`AppError::Saturated`] (`503`, `retry-after: 1`) when the tenant's queue is full or no
    /// slot came free within the wait bound. An app index the table does not know is let through.
    pub async fn admit(&self, table: &RoutingTable, selected: &Selected) -> Result<Slot, AppError> {
        let Some(tenant) = table.app(selected.app).map(|app| app.tenant()) else {
            return Ok(Slot::default());
        };
        let weight = table.tenant_weight(tenant).unwrap_or(1);
        let limiter = self.limiter(table, selected.upstream);
        match limiter.admit(tenant, weight, self.shared.max_wait).await {
            Ok(permit) => Ok(Slot {
                permit: Some(permit),
                connected_at: None,
            }),
            Err(_) => Err(AppError::Saturated),
        }
    }

    /// Prometheus text exposition of every backend's limit, in-flight and queue.
    #[must_use]
    pub fn render(&self) -> String {
        let mut rows: Vec<(SocketAddr, Arc<Limiter>)> = self
            .shared
            .limiters
            .load()
            .iter()
            .map(|(addr, limiter)| (*addr, Arc::clone(limiter)))
            .collect();
        rows.sort_by_key(|(addr, _)| *addr);
        let families: [Family; 5] = [
            (
                "podgate_backend_limit",
                "gauge",
                "Adaptive concurrency limit of the backend.",
                |l| u64::from(l.limit()),
            ),
            (
                "podgate_backend_inflight",
                "gauge",
                "Requests holding a slot of the backend now.",
                |l| u64::from(l.inflight()),
            ),
            (
                "podgate_backend_queued",
                "gauge",
                "Requests waiting for a slot of the backend now.",
                |l| u64::from(l.queued()),
            ),
            (
                "podgate_backend_waited_total",
                "counter",
                "Requests that had to queue for a slot of the backend.",
                |l| l.waited.load(Ordering::Relaxed),
            ),
            (
                "podgate_backend_refused_total",
                "counter",
                "Requests refused with 503 because the queue was full or the wait ran out.",
                |l| l.refused.load(Ordering::Relaxed),
            ),
        ];
        let mut out = String::new();
        for (name, kind, help, value) in families {
            // Writing to a `String` cannot fail.
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for (addr, limiter) in &rows {
                let _ = writeln!(out, "{name}{{backend=\"{addr}\"}} {}", value(limiter));
            }
        }
        out
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    const MS: f64 = 1_000_000.0;

    /// Feeds `windows` windows of constant latency `rtt_ms` with the backend fully used.
    fn feed(estimator: &mut Estimator, rtt_ms: f64, windows: u32) -> u32 {
        let mut limit = estimator.current();
        for _ in 0..windows {
            limit = estimator.update(rtt_ms * MS, MAX_LIMIT);
        }
        limit
    }

    #[test]
    fn adaptive_limit_shrinks() {
        let mut estimator = Estimator::new();
        let steady = feed(&mut estimator, 100.0, 40);
        assert!(steady > 32, "a flat 100 ms grows the limit: {steady}");

        let slowed = feed(&mut estimator, 400.0, 40);
        assert!(
            slowed < steady / 2,
            "4x latency shrinks the limit: {steady} -> {slowed}"
        );
        assert!(slowed >= MIN_LIMIT);

        let recovered = feed(&mut estimator, 100.0, 200);
        assert!(
            recovered > slowed * 2,
            "latency back to baseline recovers the limit: {slowed} -> {recovered}"
        );
    }

    #[test]
    fn adaptive_limit_stays_put_when_the_backend_is_idle() {
        let mut estimator = Estimator::new();
        let before = estimator.current();
        for _ in 0..100 {
            estimator.update(100.0 * MS, 1);
        }
        assert_eq!(estimator.current(), before, "no growth without demand");
    }

    #[test]
    fn adaptive_limit_stays_in_bounds() {
        let mut estimator = Estimator::new();
        assert_eq!(feed(&mut estimator, 10.0, 5000), MAX_LIMIT);

        let mut estimator = Estimator::new();
        feed(&mut estimator, 10.0, 1);
        let lowest = (0..500)
            .map(|_| estimator.update(10_000.0 * MS, MAX_LIMIT))
            .min();
        assert_eq!(lowest, Some(MIN_LIMIT));
    }

    #[test]
    fn adaptive_limit_accepts_a_permanently_slower_backend() {
        let mut estimator = Estimator::new();
        let fast = feed(&mut estimator, 100.0, 40);

        // The backend becomes 4x slower for good: the limit first falls to the floor, where
        // that latency is the backend's own, then the baseline follows and the limit grows again.
        let lowest = (0..100)
            .map(|_| estimator.update(400.0 * MS, MAX_LIMIT))
            .min();
        assert_eq!(lowest, Some(MIN_LIMIT), "it fell from {fast}");
        let regrown = feed(&mut estimator, 400.0, 200);
        assert!(
            regrown > 3 * MIN_LIMIT,
            "the slower latency is the new normal: {regrown}"
        );
    }

    #[test]
    fn adaptive_limit_follows_recorded_latency() {
        let limiter = Limiter::new();
        // Hold the whole limit so the windows count as demanded.
        let held: Vec<_> = (0..limiter.limit())
            .map(|_| limiter.try_acquire().expect("slot"))
            .collect();
        let before = limiter.limit();
        for _ in 0..WINDOW {
            limiter.record(Duration::from_millis(100));
        }
        assert!(limiter.limit() >= before, "a first window never shrinks");
        for _ in 0..WINDOW * 10 {
            limiter.record(Duration::from_millis(1000));
        }
        assert!(
            limiter.limit() < before,
            "slower responses shrink the limit: {before} -> {}",
            limiter.limit()
        );
        drop(held);
    }

    /// A queue of `count` requests per tenant with a dummy grant channel each.
    fn fill(queues: &mut Queues, tenant: &str, weight: u32, count: usize) {
        for _ in 0..count {
            let (grant, receiver) = oneshot::channel();
            std::mem::forget(receiver);
            queues.push(tenant, weight, grant).expect("room");
        }
    }

    #[test]
    fn fair_queue_weights() {
        let mut queues = Queues::default();
        fill(&mut queues, "a", 3, 8);
        fill(&mut queues, "b", 1, 8);
        let first_eight: Vec<_> = (0..8)
            .map(|_| queues.pop_next().expect("waiting"))
            .collect();
        let from_a = first_eight
            .iter()
            .filter(|waiter| waiter.ticket < 8)
            .count();
        assert_eq!(from_a, 6, "weight 3 against 1 is served 6 of 8");
        assert_eq!(
            first_eight.first().map(|w| w.ticket),
            Some(0),
            "ties go to the older request"
        );
    }

    #[test]
    fn fair_queue_new_tenant_does_not_wait_behind_a_backlog() {
        let mut queues = Queues::default();
        fill(&mut queues, "flood", 1, 100);
        for _ in 0..10 {
            queues.pop_next().expect("waiting");
        }
        fill(&mut queues, "quiet", 1, 1);
        let next_two: Vec<_> = (0..2)
            .map(|_| queues.pop_next().expect("waiting").ticket)
            .collect();
        assert!(
            next_two.contains(&100),
            "the quiet tenant is served next: {next_two:?}"
        );
    }

    #[test]
    fn fair_queue_is_bounded_per_tenant() {
        let mut queues = Queues::default();
        fill(&mut queues, "a", 1, QUEUE_CAP);
        let (grant, _receiver) = oneshot::channel();
        assert!(queues.push("a", 1, grant).is_none(), "tenant a is full");
        let (grant, _receiver) = oneshot::channel();
        assert!(queues.push("b", 1, grant).is_some(), "tenant b is not");
    }

    #[test]
    fn fair_queue_removes_and_resets_when_empty() {
        let mut queues = Queues::default();
        fill(&mut queues, "a", 1, 2);
        assert!(queues.remove("a", 0));
        assert!(!queues.remove("a", 0), "already gone");
        queues.pop_next().expect("one left");
        assert!(!queues.has_waiters());
        assert_eq!(queues.virtual_time, 0);
    }

    #[tokio::test]
    async fn limiter_grants_in_weight_order_and_never_over_the_limit() {
        let limiter = Limiter::new();
        let limit = limiter.limit();
        let held: Vec<_> = (0..limit)
            .map(|_| limiter.try_acquire().expect("slot"))
            .collect();
        assert!(limiter.try_acquire().is_none(), "at the limit");

        let order = Arc::new(Mutex::new(Vec::new()));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for (tenant, weight) in [("a", 3_u32), ("b", 1)] {
            for _ in 0..8 {
                let limiter = Arc::clone(&limiter);
                let order = Arc::clone(&order);
                let peak = Arc::clone(&peak);
                tasks.push(tokio::spawn(async move {
                    let permit = limiter
                        .admit(tenant, weight, Duration::from_secs(10))
                        .await
                        .expect("granted");
                    order.lock().expect("lock").push(tenant);
                    peak.fetch_max(limiter.inflight() as usize, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                    drop(permit);
                }));
            }
        }
        while limiter.queued() < 16 {
            tokio::task::yield_now().await;
        }
        drop(held);
        for task in tasks {
            task.await.expect("task");
        }
        assert!(peak.load(Ordering::Relaxed) <= limit as usize);
        assert_eq!(limiter.inflight(), 0, "every slot came back");
        assert_eq!(limiter.queued(), 0);
        let order = order.lock().expect("lock");
        assert_eq!(order.len(), 16);
        assert_eq!(
            order.iter().take(8).filter(|t| **t == "a").count(),
            6,
            "the first 8 grants follow the weights: {order:?}"
        );
    }

    #[tokio::test]
    async fn limiter_times_out_and_refuses_a_full_queue() {
        let limiter = Limiter::new();
        let held: Vec<_> = (0..limiter.limit())
            .map(|_| limiter.try_acquire().expect("slot"))
            .collect();
        let waited = limiter.admit("a", 1, Duration::from_millis(30)).await;
        assert_eq!(waited.err(), Some(Refusal::Timeout));
        assert_eq!(limiter.queued(), 0, "a timed-out request leaves the queue");

        drop(held);
        assert!(
            limiter
                .admit("a", 1, Duration::from_millis(30))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn limiter_cancelled_waiter_does_not_leak_a_slot() {
        let limiter = Limiter::new();
        let held: Vec<_> = (0..limiter.limit())
            .map(|_| limiter.try_acquire().expect("slot"))
            .collect();
        let waiting = {
            let limiter = Arc::clone(&limiter);
            tokio::spawn(async move { limiter.admit("a", 1, Duration::from_secs(10)).await })
        };
        while limiter.queued() < 1 {
            tokio::task::yield_now().await;
        }
        waiting.abort();
        let _ = waiting.await;
        assert_eq!(limiter.queued(), 0, "an aborted request leaves the queue");
        drop(held);
        assert_eq!(limiter.inflight(), 0);
    }
}
