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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::sync::Notify;

use super::Record;

/// Lines the queue holds before it drops the oldest.
pub const QUEUE_CAPACITY: usize = 8192;

/// How often the file sink compares its open file with the path.
const REOPEN_CHECK: Duration = Duration::from_secs(1);

type Queue = VecDeque<Box<Record>>;

#[derive(Debug)]
struct Shared {
    queue: Mutex<Queue>,
    wake: Notify,
    capacity: usize,
    written: AtomicU64,
    dropped: AtomicU64,
}

/// The queue between requests and the writer task. Cheap to clone; every clone is the same queue.
#[derive(Debug, Clone)]
pub struct AccessLog {
    shared: Arc<Shared>,
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
            shared: Arc::new(Shared {
                queue: Mutex::new(VecDeque::new()),
                wake: Notify::new(),
                capacity: capacity.max(1),
                written: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
            }),
        }
    }

    /// Queues `record`; never waits for the sink. A full queue drops its oldest line.
    pub fn record(&self, record: Box<Record>) {
        let evicted = {
            let mut queue = self
                .shared
                .queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let evicted = (queue.len() >= self.shared.capacity)
                .then(|| queue.pop_front())
                .flatten();
            queue.push_back(record);
            evicted
        };
        if evicted.is_some() {
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.shared.wake.notify_one();
    }

    /// Lines written to the sink so far.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.shared.written.load(Ordering::Relaxed)
    }

    /// Lines dropped so far: evicted from a full queue, or lost with a failed write.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    /// Prometheus text for `GET /metrics`.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "# HELP podgate_access_log_lines_total Access log lines written to the sink.\n\
             # TYPE podgate_access_log_lines_total counter\n\
             podgate_access_log_lines_total {}\n\
             # HELP podgate_access_log_dropped_total Access log lines dropped because the queue was full or the sink failed.\n\
             # TYPE podgate_access_log_dropped_total counter\n\
             podgate_access_log_dropped_total {}\n",
            self.written(),
            self.dropped(),
        )
    }

    /// The background service that drains this queue into `sink`; register it with the server.
    #[must_use]
    pub fn service(&self, sink: Box<dyn LineSink>) -> AccessLogService {
        AccessLogService {
            log: self.clone(),
            sink: Mutex::new(Some(sink)),
        }
    }

    /// Swaps the queued records with `spare`, which must be empty.
    fn take(&self, spare: &mut Queue) {
        let mut queue = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        std::mem::swap(&mut *queue, spare);
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

    fn rechecking(path: PathBuf, recheck: Duration) -> Self {
        Self {
            path,
            open: None,
            checked: Instant::now(),
            recheck,
        }
    }

    fn reopen(&mut self) -> io::Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
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
            return Err(io::Error::other("access log file is not open"));
        };
        file.write_all(lines).inspect_err(|_| self.open = None)
    }
}

/// Drains an [`AccessLog`] into its sink until shutdown.
pub struct AccessLogService {
    log: AccessLog,
    sink: Mutex<Option<Box<dyn LineSink>>>,
}

impl std::fmt::Debug for AccessLogService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessLogService").finish_non_exhaustive()
    }
}

/// Formats `batch` and writes it; returns the sink, the emptied batch and the result.
fn flush(
    mut sink: Box<dyn LineSink>,
    mut batch: Queue,
) -> (Box<dyn LineSink>, Queue, usize, io::Result<()>) {
    let lines = batch.len();
    let mut text = String::new();
    for record in &batch {
        record.render(&mut text);
    }
    batch.clear();
    let result = sink.write(text.as_bytes());
    (sink, batch, lines, result)
}

impl AccessLogService {
    fn account(&self, lines: usize, result: &io::Result<()>, failing: &mut bool) {
        let count = u64::try_from(lines).unwrap_or(u64::MAX);
        match result {
            Ok(()) => {
                *failing = false;
                self.log.shared.written.fetch_add(count, Ordering::Relaxed);
            }
            Err(err) => {
                self.log.shared.dropped.fetch_add(count, Ordering::Relaxed);
                if !std::mem::replace(failing, true) {
                    tracing::warn!(error = %err, "access log sink failed; its lines are dropped");
                }
            }
        }
    }
}

#[async_trait]
impl BackgroundService for AccessLogService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let taken = self
            .sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(mut sink) = taken else { return };
        // `take` swaps: the live queue gets the emptied `spare` back, so it keeps its capacity.
        let mut spare = Queue::new();
        let mut failing = false;
        loop {
            self.log.take(&mut spare);
            if spare.is_empty() {
                tokio::select! {
                    () = self.log.shared.wake.notified() => continue,
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
                        tracing::error!(error = %err, "access log writer stopped");
                        return;
                    }
                },
                _ = shutdown.changed() => return,
            }
        }
        self.log.take(&mut spare);
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

    fn record(id: &str) -> Box<Record> {
        let mut record = Record::sample(&json!({}));
        record.request_id = id.into();
        Box::new(record)
    }

    fn ids(log: &AccessLog) -> Vec<String> {
        let mut queue = Queue::new();
        log.take(&mut queue);
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
