//! The handle the request path and the exporter share: the rate cap, the bounded queue and the
//! counters.
//!
//! The request path only calls [`Tracer::admit`] (one short lock on a token bucket) and
//! [`Tracer::submit`] (one short lock to push at most two spans). A full queue drops the new
//! spans and counts them, so a collector that stalls costs spans, never latency or memory.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use tokio::sync::Notify;

use super::span::Span;

/// Spans the queue holds before it drops new ones.
pub const QUEUE_CAPACITY: usize = 2048;

/// Spans in one export request.
pub(super) const BATCH_SPANS: usize = 512;

/// A traced request exports a server span and, when it reaches an upstream, a client span; the
/// rate cap charges both up front.
const SPANS_PER_REQUEST: f64 = 2.0;

/// The default for `OTEL_MAX_SPANS_PER_SEC`.
pub const DEFAULT_MAX_SPANS_PER_SEC: u32 = 1000;

/// A token bucket: `rate` tokens a second, at most one second's worth saved up (and at least
/// enough for one traced request).
#[derive(Debug)]
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(per_second: u32) -> Self {
        let rate = f64::from(per_second);
        let burst = rate.max(SPANS_PER_REQUEST);
        Self {
            rate,
            burst,
            tokens: burst,
            last: Instant::now(),
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;
    }

    fn take(&mut self) -> bool {
        if self.tokens >= SPANS_PER_REQUEST {
            self.tokens -= SPANS_PER_REQUEST;
            true
        } else {
            false
        }
    }

    fn refund(&mut self) {
        self.tokens = (self.tokens + SPANS_PER_REQUEST).min(self.burst);
    }
}

/// The node's bucket and one bucket per tenant, behind one lock so a refusal by the node can
/// give the tenant its tokens back. A tenant's bucket is half the node's rate: while others
/// trace, no tenant can take more than half of what the node allows.
#[derive(Debug)]
struct Limiter {
    node: Bucket,
    tenant_rate: u32,
    tenants: HashMap<Box<str>, Bucket>,
}

impl Limiter {
    fn new(per_second: u32) -> Self {
        Self {
            node: Bucket::new(per_second),
            tenant_rate: (per_second / 2).max(1),
            tenants: HashMap::new(),
        }
    }

    fn allow(&mut self, tenant: &str) -> bool {
        let now = Instant::now();
        self.node.refill(now);
        if !self.tenants.contains_key(tenant) {
            self.tenants
                .insert(tenant.into(), Bucket::new(self.tenant_rate));
        }
        let Some(bucket) = self.tenants.get_mut(tenant) else {
            return false;
        };
        bucket.refill(now);
        if !bucket.take() {
            return false;
        }
        if self.node.take() {
            true
        } else {
            bucket.refund();
            false
        }
    }
}

#[derive(Debug)]
struct Shared {
    queue: Mutex<VecDeque<Span>>,
    full: Notify,
    limiter: Mutex<Limiter>,
    exports: bool,
    capacity: usize,
    exported: AtomicU64,
    dropped: AtomicU64,
    rate_limited: AtomicU64,
}

/// The tracing handle: cheap to clone, every clone is the same queue and rate cap.
#[derive(Debug, Clone)]
pub struct Tracer {
    shared: Arc<Shared>,
}

impl Default for Tracer {
    /// No exporter and the default rate cap: requests are still sampled and propagated.
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SPANS_PER_SEC, false)
    }
}

impl Tracer {
    /// A tracer that lets `max_spans_per_sec` spans a second be traced on this node, and records
    /// spans for export only when `exports` (the node has a collector).
    #[must_use]
    pub fn new(max_spans_per_sec: u32, exports: bool) -> Self {
        Self::with_capacity(max_spans_per_sec, exports, QUEUE_CAPACITY)
    }

    fn with_capacity(max_spans_per_sec: u32, exports: bool, capacity: usize) -> Self {
        Self {
            shared: Arc::new(Shared {
                queue: Mutex::new(VecDeque::new()),
                full: Notify::new(),
                limiter: Mutex::new(Limiter::new(max_spans_per_sec)),
                exports,
                capacity,
                exported: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                rate_limited: AtomicU64::new(0),
            }),
        }
    }

    /// Whether this node has a collector, so a sampled request records its spans.
    pub(super) fn exports(&self) -> bool {
        self.shared.exports
    }

    /// Takes the rate cap's tokens for one traced request of `tenant`; `false` (and a count) when
    /// the tenant's share or the node's cap is spent, so the request is not traced.
    pub(super) fn admit(&self, tenant: &str) -> bool {
        let allowed = self
            .shared
            .limiter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .allow(tenant);
        if !allowed {
            self.shared.rate_limited.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    /// Queues `spans` as one unit; never waits. A queue without room for all of them drops them.
    pub(super) fn submit(&self, spans: Vec<Span>) {
        let count = spans.len();
        let before = {
            let mut queue = self
                .shared
                .queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let before = queue.len();
            if before + count > self.shared.capacity {
                drop(queue);
                self.shared
                    .dropped
                    .fetch_add(count as u64, Ordering::Relaxed);
                return;
            }
            queue.extend(spans);
            before
        };
        if before < BATCH_SPANS && before + count >= BATCH_SPANS {
            self.shared.full.notify_one();
        }
    }

    /// Removes up to `max` spans, oldest first.
    pub(super) fn take(&self, max: usize) -> Vec<Span> {
        let mut queue = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = max.min(queue.len());
        queue.drain(..count).collect()
    }

    /// Resolves when a batch's worth of spans has queued.
    pub(super) async fn batch_ready(&self) {
        self.shared.full.notified().await;
    }

    /// Counts `count` spans as delivered to the collector.
    pub(super) fn exported(&self, count: usize) {
        self.shared
            .exported
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    /// Counts `count` spans as lost after the queue accepted them.
    pub(super) fn lost(&self, count: usize) {
        self.shared
            .dropped
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    /// Spans dropped so far: refused by a full queue, or lost with a failed export.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    /// Spans delivered to the collector so far.
    #[must_use]
    pub fn exported_total(&self) -> u64 {
        self.shared.exported.load(Ordering::Relaxed)
    }

    /// Spans waiting in the queue.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.shared
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Prometheus text for `GET /metrics`.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "# HELP podgate_trace_spans_exported_total Spans delivered to the OTLP collector.\n\
             # TYPE podgate_trace_spans_exported_total counter\n\
             podgate_trace_spans_exported_total {}\n\
             # HELP podgate_trace_dropped_total Spans dropped because the queue was full or an export failed.\n\
             # TYPE podgate_trace_dropped_total counter\n\
             podgate_trace_dropped_total {}\n\
             # HELP podgate_trace_rate_limited_total Requests not traced because OTEL_MAX_SPANS_PER_SEC was spent.\n\
             # TYPE podgate_trace_rate_limited_total counter\n\
             podgate_trace_rate_limited_total {}\n\
             # HELP podgate_trace_queue_spans Spans waiting to be exported.\n\
             # TYPE podgate_trace_queue_spans gauge\n\
             podgate_trace_queue_spans {}\n",
            self.exported_total(),
            self.dropped(),
            self.shared.rate_limited.load(Ordering::Relaxed),
            self.queued(),
        )
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::super::context::{SpanId, TraceId};
    use super::super::span::Kind;
    use super::*;

    fn span() -> Span {
        Span {
            trace_id: TraceId([1; 16]),
            span_id: SpanId([1; 8]),
            parent: None,
            trace_state: None,
            name: "GET".into(),
            kind: Kind::Server,
            start_unix_nanos: 0,
            end_unix_nanos: 0,
            attributes: Vec::new(),
            error: false,
        }
    }

    #[test]
    fn trace_queue_drops_new_spans_when_full_and_counts_them() {
        let tracer = Tracer::with_capacity(1000, true, 4);
        tracer.submit(vec![span(), span(), span()]);
        tracer.submit(vec![span(), span()]);
        assert_eq!((tracer.queued(), tracer.dropped()), (3, 2));
        tracer.submit(vec![span()]);
        assert_eq!((tracer.queued(), tracer.dropped()), (4, 2));
        assert_eq!(tracer.take(3).len(), 3);
        assert_eq!(tracer.queued(), 1);
    }

    #[test]
    fn trace_rate_cap_spends_two_tokens_a_request_and_refills() {
        let tracer = Tracer::new(10, true);
        let allowed = (0..100).filter(|_| tracer.admit("a")).count();
        assert_eq!(
            allowed, 2,
            "a tenant's burst is half the node's: 5 spans, 2 requests"
        );
        assert!(
            tracer
                .render()
                .contains("podgate_trace_rate_limited_total 98\n")
        );
        std::thread::sleep(Duration::from_millis(250));
        assert!(tracer.admit("a"), "a quarter second refills 1.25 spans");
        let slow = Tracer::new(1, true);
        assert!(
            slow.admit("a"),
            "even a cap of 1 allows one request in a burst"
        );
        assert!(!slow.admit("a"));
    }

    #[test]
    fn trace_one_tenant_cannot_take_the_whole_node_cap() {
        let tracer = Tracer::new(20, true);
        let flood = (0..1000).filter(|_| tracer.admit("flooder")).count();
        assert_eq!(flood, 5, "half of a 20 span burst is 10 spans, 5 requests");
        let quiet = (0..1000).filter(|_| tracer.admit("quiet")).count();
        assert_eq!(quiet, 5, "the other tenant still gets its half");
        assert!(!tracer.admit("third"), "the node cap itself is spent");
    }
}
