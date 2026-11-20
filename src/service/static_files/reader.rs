//! Reading files without holding a thread or a file in memory: [`Reads`] bounds the blocking work
//! the whole process does for static files, and [`Stream`] feeds a response one chunk at a time.
//!
//! A file is never read whole. A response in flight holds at most two [`CHUNK`]s (the one being
//! written to the client and the one being read ahead), and the caller charges [`RESERVATION`]
//! bytes to the tenant before the first read starts.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

/// How long an operation waits for a read slot before the request answers `503`.
pub(super) const WAIT: Duration = Duration::from_secs(1);

/// Bytes read and written at a time.
pub(super) const CHUNK: usize = 64 * 1024;

/// Buffer bytes a response in flight charges to its tenant: two chunks.
pub(super) const RESERVATION: u64 = 2 * CHUNK as u64;

/// No read slot came free in time.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("static file reads are busy")]
pub(super) struct Busy;

/// The bounded pool of blocking reads, shared by every tenant. Cheap to clone.
///
/// Each file-system operation (an open, or one chunk read) takes one of `limit` slots for its
/// own duration; it waits at most `wait` for one. A slow client therefore never holds a slot:
/// the slot is held while the disk works, not while the response drains.
#[derive(Clone, Debug)]
pub struct Reads {
    slots: Arc<Semaphore>,
    running: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    wait: Duration,
}

impl Reads {
    /// A pool of `limit` slots (at least one) that makes a caller wait at most `wait`.
    #[must_use]
    pub fn new(limit: usize, wait: Duration) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(limit.max(1))),
            running: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            wait,
        }
    }

    /// A pool of `limit` slots that makes a caller wait at most one second.
    #[must_use]
    pub fn bounded(limit: usize) -> Self {
        Self::new(limit, WAIT)
    }

    /// Most operations that ever ran at once.
    #[must_use]
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Starts `work` on the blocking pool once a slot is free; the slot is held until it ends.
    ///
    /// # Errors
    ///
    /// [`Busy`] when no slot came free within the wait.
    pub(super) async fn start<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<JoinHandle<T>, Busy> {
        let permit = tokio::time::timeout(self.wait, Arc::clone(&self.slots).acquire_owned())
            .await
            .map_err(|_| Busy)?
            .map_err(|_| Busy)?;
        let running = Arc::clone(&self.running);
        let peak = Arc::clone(&self.peak);
        Ok(tokio::task::spawn_blocking(move || {
            let now = running.fetch_add(1, Ordering::AcqRel) + 1;
            peak.fetch_max(now, Ordering::Relaxed);
            let out = work();
            running.fetch_sub(1, Ordering::AcqRel);
            drop(permit);
            out
        }))
    }

    /// [`Self::start`] and wait for the result.
    ///
    /// # Errors
    ///
    /// [`Busy`] when no slot came free within the wait or the work panicked.
    pub(super) async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Busy> {
        self.start(work).await?.await.map_err(|_| Busy)
    }
}

impl Default for Reads {
    /// Sixty-four slots, for a gateway nobody configured (tests and tools).
    fn default() -> Self {
        Self::bounded(64)
    }
}

/// Why a response body stopped.
#[derive(Debug, Error)]
pub(super) enum StreamError {
    /// No read slot came free in time.
    #[error(transparent)]
    Busy(#[from] Busy),
    /// The file could not be read, or ended before its length: the connection must be cut,
    /// because the headers promised more.
    #[error("reading the file failed: {0}")]
    Io(#[from] io::Error),
}

/// A byte range of an open file, read ahead one chunk at a time.
#[derive(Debug)]
pub(super) struct Stream {
    file: Arc<File>,
    offset: u64,
    remaining: u64,
    ahead: Option<JoinHandle<io::Result<Vec<u8>>>>,
}

impl Stream {
    /// The `len` bytes of `file` from `start`.
    #[must_use]
    pub(super) fn new(file: File, start: u64, len: u64) -> Self {
        Self {
            file: Arc::new(file),
            offset: start,
            remaining: len,
            ahead: None,
        }
    }

    async fn spawn(&mut self, reads: &Reads) -> Result<JoinHandle<io::Result<Vec<u8>>>, Busy> {
        let want = usize::try_from(self.remaining).map_or(CHUNK, |left| left.min(CHUNK));
        let (file, at) = (Arc::clone(&self.file), self.offset);
        let handle = reads
            .start(move || {
                let mut chunk = vec![0; want];
                file.read_exact_at(&mut chunk, at)?;
                Ok(chunk)
            })
            .await?;
        self.offset += want as u64;
        self.remaining -= want as u64;
        Ok(handle)
    }

    /// Whether every byte of the range has been handed out, once [`Self::next`] has returned the
    /// last chunk.
    #[must_use]
    pub(super) fn is_done(&self) -> bool {
        self.remaining == 0 && self.ahead.is_none()
    }

    /// The next chunk, or `None` at the end of the range. While the caller writes one chunk the
    /// next is already being read.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when no read slot came free or the file is shorter than its length.
    pub(super) async fn next(&mut self, reads: &Reads) -> Result<Option<Bytes>, StreamError> {
        if self.ahead.is_none() && self.remaining > 0 {
            self.ahead = Some(self.spawn(reads).await?);
        }
        let Some(current) = self.ahead.take() else {
            return Ok(None);
        };
        if self.remaining > 0 {
            self.ahead = Some(self.spawn(reads).await?);
        }
        let chunk = current
            .await
            .map_err(|err| io::Error::other(err.to_string()))??;
        Ok(Some(Bytes::from(chunk)))
    }
}

#[cfg(test)]
mod test {
    use std::io::Write as _;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn static_read_pool_bounded() {
        let reads = Reads::new(2, Duration::from_secs(5));
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let reads = reads.clone();
                tokio::spawn(async move {
                    reads
                        .run(|| std::thread::sleep(Duration::from_millis(20)))
                        .await
                })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.expect("joins"), Ok(()));
        }
        assert_eq!(
            reads.peak(),
            2,
            "never more than the limit, and the limit is used"
        );
    }

    #[tokio::test]
    async fn static_read_pool_busy_after_the_wait() {
        let reads = Reads::new(1, Duration::from_millis(50));
        let slow = reads
            .start(|| std::thread::sleep(Duration::from_millis(400)))
            .await
            .expect("first slot");
        assert_eq!(
            reads.run(|| ()).await,
            Err(Busy),
            "the second waits 50 ms and gives up"
        );
        slow.await.expect("the slow read finishes");
        assert_eq!(reads.run(|| 7).await, Ok(7), "the slot is back");
    }

    fn file_of(bytes: &[u8]) -> File {
        let path = std::env::temp_dir().join(format!(
            "podgate-reader-{}-{}",
            std::process::id(),
            bytes.len()
        ));
        std::fs::File::create(&path)
            .expect("create")
            .write_all(bytes)
            .expect("write");
        let file = File::open(&path).expect("open");
        std::fs::remove_file(&path).expect("unlink");
        file
    }

    #[tokio::test]
    async fn a_stream_yields_exactly_its_range_in_chunks() {
        let data: Vec<u8> = (0..CHUNK * 2 + 100).map(|i| (i % 251) as u8).collect();
        let reads = Reads::new(4, Duration::from_secs(1));
        let mut stream = Stream::new(file_of(&data), 10, data.len() as u64 - 20);
        let mut got = Vec::new();
        let mut sizes = Vec::new();
        while let Some(chunk) = stream.next(&reads).await.expect("reads") {
            sizes.push(chunk.len());
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, data[10..data.len() - 10]);
        assert_eq!(sizes, [CHUNK, CHUNK, 80]);
    }

    #[tokio::test]
    async fn a_file_shorter_than_its_length_is_an_error() {
        let reads = Reads::new(1, Duration::from_secs(1));
        let mut stream = Stream::new(file_of(b"short"), 0, 100);
        let err = stream.next(&reads).await.expect_err("truncated");
        assert!(matches!(err, StreamError::Io(_)), "{err}");
    }
}
