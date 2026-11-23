//! The exporter of a signal that has a bounded queue: [`BatchExporter`] takes batches from a
//! [`Feed`] and sends them through a [`Transport`], never on the request path.
//!
//! A batch is [`Feed::BATCH`] items or whatever has queued in two seconds; an export gives up
//! after `OTEL_EXPORTER_OTLP_TIMEOUT` and is retried twice with backoff, then its items are lost
//! and counted. The queue and its bound belong to the signal, so a collector that is down or slow
//! costs items and nothing else. Both wires share all of this; only the call that carries one
//! encoded request differs.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::time::{MissedTickBehavior, interval};

use super::transport::{ATTEMPTS, Transport};

/// The largest encoded request sent in one call: collectors refuse more than 4 MiB by default.
/// A batch over it is split in halves.
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;

/// How long the exporter waits before sending a batch that is not full.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// Batches sent on the way out; whatever is left after them is lost.
const SHUTDOWN_BATCHES: usize = 4;

/// Encodes `batch` as requests of at most `limit` bytes each, splitting it in halves as often as
/// needed, in order. `encode` makes one request body of the items it is given. Returns each
/// request as its item count and body, and the number of items that alone exceed `limit` and so
/// cannot be sent.
pub fn split<T>(
    batch: Vec<T>,
    limit: usize,
    encode: impl Fn(&[T]) -> Vec<u8>,
) -> (Vec<(usize, Bytes)>, usize) {
    let mut requests = Vec::new();
    let mut oversized = 0;
    let mut work = vec![batch];
    while let Some(mut batch) = work.pop() {
        let body = encode(&batch);
        if body.len() <= limit {
            requests.push((batch.len(), Bytes::from(body)));
        } else if batch.len() > 1 {
            let upper = batch.split_off(batch.len() / 2);
            work.push(upper);
            work.push(batch);
        } else {
            oversized += batch.len();
        }
    }
    (requests, oversized)
}

/// What a signal with its own bounded queue provides to [`BatchExporter`].
#[async_trait]
pub trait Feed: Send + Sync + 'static {
    /// What is queued: a span, a log record.
    type Item: Send + 'static;
    /// The plural of the item, for the warnings: `spans`, `log records`.
    const NOUN: &'static str;
    /// Items per request.
    const BATCH: usize;
    /// Removes up to `max` items, oldest first; never waits.
    fn take(&self, max: usize) -> Vec<Self::Item>;
    /// Resolves when [`Self::BATCH`] items have queued.
    async fn ready(&self);
    /// One `ExportXServiceRequest`, resource included, for `items`.
    fn encode(&self, items: &[Self::Item]) -> Vec<u8>;
    /// Counts `count` items as delivered to the collector.
    fn exported(&self, count: usize);
    /// Counts `count` items as lost after the queue accepted them: refused by the collector, a
    /// failed export, or too large to send.
    fn lost(&self, count: usize);
}

/// Sends a [`Feed`]'s queue to the collector. Register it with the server as a background
/// service.
pub struct BatchExporter<F: Feed> {
    feed: F,
    transport: Transport,
}

impl<F: Feed> std::fmt::Debug for BatchExporter<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchExporter")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl<F: Feed> BatchExporter<F> {
    /// The exporter draining `feed` through `transport`.
    #[must_use]
    pub fn new(feed: F, transport: Transport) -> Self {
        Self { feed, transport }
    }

    /// Sends `batch`, split until each request fits [`MAX_MESSAGE`]; counts the items exported or
    /// lost.
    async fn export(&self, batch: Vec<F::Item>, attempts: u32) {
        let (requests, oversized) = split(batch, MAX_MESSAGE, |items| self.feed.encode(items));
        if oversized > 0 {
            self.feed.lost(oversized);
            ::tracing::warn!(
                count = oversized,
                "dropped {}: each alone is larger than the 4 MiB message limit",
                F::NOUN
            );
        }
        for (count, body) in requests {
            self.export_one(count, body, attempts).await;
        }
    }

    /// Sends one encoded request of `count` items, at most `attempts` times.
    async fn export_one(&self, count: usize, body: Bytes, attempts: u32) {
        match self.transport.deliver(&body, attempts).await {
            Ok(rejected) => {
                let rejected = rejected.min(count);
                self.feed.exported(count - rejected);
                if rejected > 0 {
                    self.feed.lost(rejected);
                    ::tracing::warn!(count = rejected, "the collector refused some {}", F::NOUN);
                }
            }
            Err(why) => {
                self.feed.lost(count);
                ::tracing::warn!(
                    count,
                    reason = %why,
                    "dropped a batch of {}: export failed",
                    F::NOUN
                );
            }
        }
    }

    /// Sends what is queued, a batch at a time, until the queue is empty.
    async fn drain(&self) {
        loop {
            let batch = self.feed.take(F::BATCH);
            let full = batch.len() == F::BATCH;
            if batch.is_empty() {
                return;
            }
            self.export(batch, ATTEMPTS).await;
            if !full {
                return;
            }
        }
    }

    /// One try for each of the last few batches, on the way out.
    async fn flush_on_exit(&self) {
        for _ in 0..SHUTDOWN_BATCHES {
            let batch = self.feed.take(F::BATCH);
            if batch.is_empty() {
                return;
            }
            self.export(batch, 1).await;
        }
        let left = self.feed.take(usize::MAX).len();
        self.feed.lost(left);
    }
}

#[async_trait]
impl<F: Feed> BackgroundService for BatchExporter<F> {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut tick = interval(FLUSH_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tick.tick() => {}
                () = self.feed.ready() => {}
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                () = self.drain() => {}
            }
        }
        self.flush_on_exit().await;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// An item is one byte of its own value; a request is the items plus a one byte header.
    fn encode(items: &[u8]) -> Vec<u8> {
        let mut body = vec![0];
        body.extend_from_slice(items);
        body
    }

    #[test]
    fn batch_split_keeps_order_and_counts_what_cannot_fit() {
        let (requests, oversized) = split((1..=8).collect::<Vec<u8>>(), 9, encode);
        assert_eq!(oversized, 0);
        assert_eq!(requests.len(), 1);
        let (requests, oversized) = split((1..=8).collect::<Vec<u8>>(), 5, encode);
        assert_eq!(oversized, 0);
        assert_eq!(requests.len(), 2);
        let sent: Vec<u8> = requests
            .iter()
            .flat_map(|(_, body)| body.iter().skip(1).copied())
            .collect();
        assert_eq!(sent, (1..=8).collect::<Vec<u8>>());
        let (requests, oversized) = split(vec![1, 2], 1, encode);
        assert!(requests.is_empty());
        assert_eq!(oversized, 2);
    }
}
