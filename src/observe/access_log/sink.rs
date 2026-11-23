//! Where lines go without ever slowing a request down.
//!
//! The request path calls [`AccessLog::record`], which only appends to a bounded queue under a
//! lock nobody holds for longer than a push or a swap. When the queue is full the oldest line is
//! dropped and `podgate_access_log_dropped_total` rises: a sink that stalls costs lines, never
//! latency. One background task ([`AccessLogService`]) takes the queue in batches, formats them
//! and hands the text to a [`LineSink`] on a blocking thread, so even a sink that never returns
//! (a pipe nobody reads) stalls nothing but that task.
//!
//! The sinks are stdout and an append-only file. The file is reopened when its inode changes,
//! checked at most once a second, so rotation by renaming it needs no signal (Pingora owns the
//! signals). A file that was truncated in place keeps working because it is opened for append.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::sync::Notify;

use super::Record;

/// What a [`LineService`] writes for each queued item.
pub trait Render {
    /// Appends the item's line, newline included, to `out`.
    fn render(&self, out: &mut String);
}

impl Render for Record {
    fn render(&self, out: &mut String) {
        Self::render(self, out);
    }
}

/// Lines the queue holds before it drops the oldest.
pub const QUEUE_CAPACITY: usize = 8192;

/// How often the file sink compares its open file with the path.
const REOPEN_CHECK: Duration = Duration::from_secs(1);

type Queue<T = Record> = VecDeque<Arc<T>>;

/// One bounded queue of records with its counters. The line writer and the OTLP exporter each
/// drain a lane of their own, so neither can slow the other.
#[derive(Debug)]
pub(super) struct Lane<T = Record> {
    queue: Mutex<Queue<T>>,
    wake: Notify,
    capacity: usize,
    /// Queued records at which the consumer is woken: the line writer takes every record as it
    /// comes, the exporter waits for a batch.
    wake_at: usize,
    done: AtomicU64,
    dropped: AtomicU64,
}

impl<T> Lane<T> {
    fn new(capacity: usize, wake_at: usize) -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
            capacity: capacity.max(1),
            wake_at,
            done: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Queue<T>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `record`; never waits. A full queue drops its oldest record and counts it.
    fn push(&self, record: Arc<T>) {
        let (evicted, len) = {
            let mut queue = self.lock();
            let evicted = (queue.len() >= self.capacity)
                .then(|| queue.pop_front())
                .flatten();
            queue.push_back(record);
            (evicted.is_some(), queue.len())
        };
        if evicted {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        if len >= self.wake_at {
            self.wake.notify_one();
        }
    }

    /// Swaps the queued records with `spare`, which must be empty.
    fn swap(&self, spare: &mut Queue<T>) {
        std::mem::swap(&mut *self.lock(), spare);
    }

    /// Removes up to `max` records, oldest first.
    pub(super) fn take(&self, max: usize) -> Vec<Arc<T>> {
        let mut queue = self.lock();
        let count = max.min(queue.len());
        queue.drain(..count).collect()
    }

    /// Resolves when the consumer should look at the queue.
    pub(super) async fn woken(&self) {
        self.wake.notified().await;
    }

    fn len(&self) -> usize {
        self.lock().len()
    }

    /// Counts `count` records as delivered.
    pub(super) fn delivered(&self, count: usize) {
        self.done
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Counts `count` records as lost after they were queued.
    pub(super) fn lost(&self, count: usize) {
        self.dropped
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

/// The queues between requests and the writer task, and the exporter's when the node has one.
/// Cheap to clone; every clone is the same queues.
#[derive(Debug, Clone)]
pub struct AccessLog {
    lines: Arc<Lane>,
    pub(super) otlp: Option<Arc<Lane>>,
}

impl Default for AccessLog {
    fn default() -> Self {
        Self::with_capacity(QUEUE_CAPACITY)
    }
}

impl AccessLog {
    /// A queue of [`QUEUE_CAPACITY`] lines.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A queue of `capacity` lines (at least one).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            lines: Lane::new(capacity, 1),
            otlp: None,
        }
    }

    /// Adds the queue the OTLP exporter drains (`OTEL_LOGS_EXPORTER=otlp`), as long as the line
    /// queue. Every record goes into both.
    #[must_use]
    pub fn with_otlp(mut self) -> Self {
        self.otlp = Some(Lane::new(self.lines.capacity, super::export::BATCH));
        self
    }

    /// Queues `record`; never waits for a sink. A full queue drops its oldest record.
    pub fn record(&self, record: Arc<Record>) {
        if let Some(otlp) = &self.otlp {
            otlp.push(Arc::clone(&record));
        }
        self.lines.push(record);
    }

    /// Lines written to the sink so far.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.lines.done.load(Ordering::Relaxed)
    }

    /// Lines dropped so far: evicted from a full queue, or lost with a failed write.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.lines.dropped.load(Ordering::Relaxed)
    }

    /// Prometheus text for `GET /metrics`.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!(
            "# HELP podgate_access_log_lines_total Access log lines written to the sink.\n\
             # TYPE podgate_access_log_lines_total counter\n\
             podgate_access_log_lines_total {}\n\
             # HELP podgate_access_log_dropped_total Access log lines dropped because the queue was full or the sink failed.\n\
             # TYPE podgate_access_log_dropped_total counter\n\
             podgate_access_log_dropped_total {}\n",
            self.written(),
            self.dropped(),
        );
        if let Some(otlp) = &self.otlp {
            // Writing to a `String` cannot fail.
            let _ = write!(
                out,
                "# HELP podgate_access_log_otlp_exported_total Access log records the OTLP collector accepted.\n\
                 # TYPE podgate_access_log_otlp_exported_total counter\n\
                 podgate_access_log_otlp_exported_total {}\n\
                 # HELP podgate_access_log_otlp_dropped_total Access log records not exported: the queue was full, the export failed or the collector refused them.\n\
                 # TYPE podgate_access_log_otlp_dropped_total counter\n\
                 podgate_access_log_otlp_dropped_total {}\n\
                 # HELP podgate_access_log_otlp_queue_records Access log records waiting for the OTLP exporter.\n\
                 # TYPE podgate_access_log_otlp_queue_records gauge\n\
                 podgate_access_log_otlp_queue_records {}\n",
                otlp.done.load(Ordering::Relaxed),
                otlp.dropped.load(Ordering::Relaxed),
                otlp.len(),
            );
        }
        out
    }

    /// The background service that drains this queue into `sink`; register it with the server.
    #[must_use]
    pub fn service(&self, sink: Box<dyn LineSink>) -> AccessLogService {
        LineService::new(Arc::clone(&self.lines), sink, "access log")
    }
}

/// A bounded queue of items for a [`LineService`] to write, with the counters of the access log's
/// lane: [`Self::record`] never waits, and a full queue drops its oldest item and counts it.
/// Cheap to clone; every clone is the same queue.
#[derive(Debug)]
pub struct LineQueue<T> {
    lane: Arc<Lane<T>>,
}

impl<T> Clone for LineQueue<T> {
    fn clone(&self) -> Self {
        Self {
            lane: Arc::clone(&self.lane),
        }
    }
}

impl<T> LineQueue<T> {
    /// A queue of `capacity` items (at least one).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            lane: Lane::new(capacity, 1),
        }
    }

    /// Queues `item`; never waits for the sink.
    pub fn record(&self, item: Arc<T>) {
        self.lane.push(item);
    }

    /// Lines written to the sink so far.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.lane.done.load(Ordering::Relaxed)
    }

    /// Lines dropped so far: evicted from a full queue, or lost with a failed write.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.lane.dropped.load(Ordering::Relaxed)
    }

    /// The service that drains this queue into `sink`; `what` names the log in warnings.
    #[must_use]
    pub fn service(&self, sink: Box<dyn LineSink>, what: &'static str) -> LineService<T> {
        LineService::new(Arc::clone(&self.lane), sink, what)
    }
}

/// Somewhere formatted lines go. A write takes whole lines, newline included.
pub trait LineSink: Send + 'static {
    /// Writes `lines`.
    ///
    /// # Errors
    ///
    /// The I/O error; the lines of that batch count as dropped.
    fn write(&mut self, lines: &[u8]) -> io::Result<()>;
}

/// Writes to the process's standard output, one write per batch so batches never interleave.
#[derive(Debug, Default)]
pub struct StdoutSink;

impl LineSink for StdoutSink {
    fn write(&mut self, lines: &[u8]) -> io::Result<()> {
        let mut out = io::stdout().lock();
        out.write_all(lines)?;
        out.flush()
    }
}

/// Appends to a file, reopening it when the path points at another file than the one held.
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    mode: u32,
    open: Option<(File, u64)>,
    checked: Instant,
    recheck: Duration,
}

impl FileSink {
    /// A sink for `path`; the file is created on the first write.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self::rechecking(path, REOPEN_CHECK)
    }

    /// [`Self::new`] creating the file with permission bits `mode`.
    #[must_use]
    pub fn with_mode(path: PathBuf, mode: u32) -> Self {
        Self {
            mode,
            ..Self::new(path)
        }
    }

    fn rechecking(path: PathBuf, recheck: Duration) -> Self {
        Self {
            path,
            mode: 0o640,
            open: None,
            checked: Instant::now(),
            recheck,
        }
    }

    fn reopen(&mut self) -> io::Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(self.mode)
            .open(&self.path)?;
        let inode = file.metadata()?.ino();
        self.open = Some((file, inode));
        Ok(())
    }

    /// Reopens the file when the path now names another inode, or none.
    fn follow_rotation(&mut self) -> io::Result<()> {
        let Some((_, held)) = &self.open else {
            return self.reopen();
        };
        if self.checked.elapsed() < self.recheck {
            return Ok(());
        }
        self.checked = Instant::now();
        match fs::metadata(&self.path) {
            Ok(meta) if meta.ino() == *held => Ok(()),
            _ => self.reopen(),
        }
    }
}

impl LineSink for FileSink {
    fn write(&mut self, lines: &[u8]) -> io::Result<()> {
        self.follow_rotation()?;
        let Some((file, _)) = self.open.as_mut() else {
            return Err(io::Error::other("log file is not open"));
        };
        file.write_all(lines).inspect_err(|_| self.open = None)
    }
}

/// Drains a queue into its sink until shutdown.
pub struct LineService<T = Record> {
    lane: Arc<Lane<T>>,
    sink: Mutex<Option<Box<dyn LineSink>>>,
    what: &'static str,
}

/// The service that drains an [`AccessLog`].
pub type AccessLogService = LineService<Record>;

impl<T> std::fmt::Debug for LineService<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineService")
            .field("what", &self.what)
            .finish_non_exhaustive()
    }
}

/// Formats `batch` and writes it; returns the sink, the emptied batch and the result.
fn flush<T: Render>(
    mut sink: Box<dyn LineSink>,
    mut batch: Queue<T>,
) -> (Box<dyn LineSink>, Queue<T>, usize, io::Result<()>) {
    let lines = batch.len();
    let mut text = String::new();
    for record in &batch {
        record.render(&mut text);
    }
    batch.clear();
    let result = sink.write(text.as_bytes());
    (sink, batch, lines, result)
}

impl<T> LineService<T> {
    fn new(lane: Arc<Lane<T>>, sink: Box<dyn LineSink>, what: &'static str) -> Self {
        Self {
            lane,
            sink: Mutex::new(Some(sink)),
            what,
        }
    }

    fn account(&self, lines: usize, result: &io::Result<()>, failing: &mut bool) {
        match result {
            Ok(()) => {
                *failing = false;
                self.lane.delivered(lines);
            }
            Err(err) => {
                self.lane.lost(lines);
                if !std::mem::replace(failing, true) {
                    tracing::warn!(error = %err, "{} sink failed; its lines are dropped", self.what);
                }
            }
        }
    }
}

#[async_trait]
impl<T: Render + Send + Sync + 'static> BackgroundService for LineService<T> {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let taken = self
            .sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(mut sink) = taken else { return };
        // `take` swaps: the live queue gets the emptied `spare` back, so it keeps its capacity.
        let mut spare = Queue::<T>::new();
        let mut failing = false;
        loop {
            self.lane.swap(&mut spare);
            if spare.is_empty() {
                tokio::select! {
                    () = self.lane.woken() => continue,
                    _ = shutdown.changed() => break,
                }
            }
            let batch = std::mem::take(&mut spare);
            let work = tokio::task::spawn_blocking(move || flush(sink, batch));
            tokio::select! {
                done = work => match done {
                    Ok((back, emptied, lines, result)) => {
                        sink = back;
                        spare = emptied;
                        self.account(lines, &result, &mut failing);
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "{} writer stopped", self.what);
                        return;
                    }
                },
                _ = shutdown.changed() => return,
            }
        }
        self.lane.swap(&mut spare);
        if !spare.is_empty() {
            let (_, _, lines, result) = flush(sink, spare);
            self.account(lines, &result, &mut failing);
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::mpsc;

    use serde_json::json;

    use super::*;

    fn record(id: &str) -> Arc<Record> {
        let mut record = Record::sample(&json!({}));
        record.request_id = id.into();
        Arc::new(record)
    }

    fn ids(log: &AccessLog) -> Vec<String> {
        let mut queue = Queue::new();
        log.lines.swap(&mut queue);
        queue.iter().map(|r| r.request_id.to_string()).collect()
    }

    #[test]
    fn access_log_drop_counter() {
        let log = AccessLog::with_capacity(4);
        for n in 0..10 {
            log.record(record(&format!("r{n}")));
        }
        assert_eq!(log.dropped(), 6);
        assert_eq!(
            ids(&log),
            ["r6", "r7", "r8", "r9"],
            "the oldest were dropped"
        );
        assert!(
            log.render()
                .contains("podgate_access_log_dropped_total 6\n")
        );
    }

    #[test]
    fn otlp_logs_lane_drops_oldest() {
        let log = AccessLog::with_capacity(4).with_otlp();
        for n in 0..10 {
            log.record(record(&format!("r{n}")));
        }
        let otlp = log.otlp.as_ref().expect("the exporter's queue");
        let kept: Vec<String> = otlp
            .take(usize::MAX)
            .iter()
            .map(|r| r.request_id.to_string())
            .collect();
        assert_eq!(kept, ["r6", "r7", "r8", "r9"], "the oldest were dropped");
        assert_eq!(otlp.dropped.load(Ordering::Relaxed), 6);
        assert_eq!(log.dropped(), 6, "the line queue is bounded on its own");
        assert_eq!(
            ids(&log),
            ["r6", "r7", "r8", "r9"],
            "and keeps its own records"
        );
        let text = log.render();
        assert!(text.contains("podgate_access_log_otlp_dropped_total 6\n"));
        assert!(text.contains("podgate_access_log_otlp_queue_records 0\n"));
        assert!(!AccessLog::with_capacity(4).render().contains("otlp"));
    }

    struct Stuck(mpsc::Receiver<()>);

    impl LineSink for Stuck {
        fn write(&mut self, _lines: &[u8]) -> io::Result<()> {
            let _ = self.0.recv();
            Ok(())
        }
    }

    #[tokio::test]
    async fn access_log_never_blocks_requests() {
        let log = AccessLog::with_capacity(64);
        let (release, stuck) = mpsc::channel();
        let service = log.service(Box::new(Stuck(stuck)));
        let (stop, watch) = tokio::sync::watch::channel(false);
        let writer = tokio::spawn(async move { service.start(watch).await });

        let started = Instant::now();
        for n in 0..10_000 {
            log.record(record(&format!("r{n}")));
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "10000 records took {:?} behind a stuck sink",
            started.elapsed()
        );
        assert!(log.dropped() > 9_000, "dropped {}", log.dropped());

        drop(release);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = stop.send(true);
        let _ = writer.await;
        assert!(log.written() > 0);
    }

    #[test]
    fn access_log_file_sink() {
        let dir = std::env::temp_dir().join(format!("podgate-sink-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("append.log");
        let _ = fs::remove_file(&path);
        {
            let mut sink = FileSink::new(path.clone());
            sink.write(b"one\n").expect("write");
            sink.write(b"two\n").expect("write");
        }
        FileSink::new(path.clone())
            .write(b"three\n")
            .expect("write");
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            "one\ntwo\nthree\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_log_file_rotation() {
        let dir = std::env::temp_dir().join(format!("podgate-rotate-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("rotate.log");
        let moved = dir.join("rotate.log.1");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&moved);
        let mut sink = FileSink::rechecking(path.clone(), Duration::ZERO);
        sink.write(b"before\n").expect("write");
        fs::rename(&path, &moved).expect("rotate");
        sink.write(b"after\n").expect("write");
        assert_eq!(fs::read_to_string(&moved).expect("read"), "before\n");
        assert_eq!(fs::read_to_string(&path).expect("read"), "after\n");
        fs::remove_file(&path).expect("delete");
        sink.write(b"again\n").expect("write");
        assert_eq!(fs::read_to_string(&path).expect("read"), "again\n");
        let _ = fs::remove_dir_all(&dir);
    }
}
