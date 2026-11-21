//! The byte copy between a client and a server.
//!
//! `tokio::io::copy_bidirectional_with_sizes` moves the bytes: one buffer of [`COPY_BUFFER`] for
//! each direction, nothing else held, so the memory of a connection is the two buffers it
//! charged. When one side sends FIN the copy shuts down the write half of the other and goes on
//! with the opposite direction, which is the half-close of a real proxy. After the client's FIN
//! the server's direction has `termination_delay` more and is then cut, so a reply
//! still on its way gets through and a server that never ends does not hold the connection.
//!
//! The client side is wrapped in [`Wire`], which stamps every byte that moves in either
//! direction (the clock the idle timeout reads) and counts them. The copy is raced against that
//! clock and against the shutdown deadline: when Pingora announces shutdown, a connection gets
//! `grace` more to finish, the way an HTTP request does.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional_with_sizes};
use tokio::sync::Notify;
use tokio::time::sleep;

use super::COPY_BUFFER;
use super::stats::{Closed, STATS};

/// When the last byte moved, in milliseconds since the connection started, and the signal that
/// the client has hung up.
#[derive(Debug)]
struct Clock {
    start: Instant,
    last_ms: AtomicU64,
    hung_up: Notify,
}

impl Clock {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
            hung_up: Notify::new(),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.last_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    /// How long since a byte last moved.
    fn quiet_for(&self) -> Duration {
        Duration::from_millis(
            self.now_ms()
                .saturating_sub(self.last_ms.load(Ordering::Relaxed)),
        )
    }
}

/// The client's stream, counting and stamping what passes.
struct Wire<'a> {
    inner: &'a mut Stream,
    clock: &'a Clock,
}

impl AsyncRead for Wire<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let room = buf.remaining() > 0;
        let polled = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &polled {
            let moved = buf.filled().len() - before;
            if moved > 0 {
                self.clock.touch();
                STATS.client_sent(moved);
            } else if room {
                // A read that returns nothing into a buffer with room is the client's FIN.
                self.clock.hung_up.notify_one();
            }
        }
        polled
    }
}

impl AsyncWrite for Wire<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(moved)) = &polled
            && *moved > 0
        {
            self.clock.touch();
            STATS.client_received(*moved);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// Resolves `grace` after the shutdown watch turns `true`; never when the process keeps running.
async fn shutdown_deadline(mut shutdown: ShutdownWatch, grace: Duration) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        if shutdown.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
    sleep(grace).await;
}

/// Copies between `client` and `server` until both directions finish, a read or write fails, no
/// byte moves for `idle`, `termination_delay` has passed since the client's FIN, or `grace` has
/// passed since shutdown began. Returns why it ended.
pub(super) async fn relay(
    client: &mut Stream,
    server: &mut Stream,
    idle: Duration,
    termination_delay: Duration,
    shutdown: ShutdownWatch,
    grace: Duration,
) -> Closed {
    let clock = Clock::new();
    let mut wire = Wire {
        inner: client,
        clock: &clock,
    };
    let copy = copy_bidirectional_with_sizes(&mut wire, server, COPY_BUFFER, COPY_BUFFER);
    tokio::pin!(copy);
    let stopping = shutdown_deadline(shutdown, grace);
    tokio::pin!(stopping);
    let terminating = async {
        clock.hung_up.notified().await;
        sleep(termination_delay).await;
    };
    tokio::pin!(terminating);
    loop {
        let wait = idle.saturating_sub(clock.quiet_for());
        tokio::select! {
            result = &mut copy => {
                return if result.is_ok() { Closed::Done } else { Closed::Error };
            }
            () = &mut stopping => return Closed::Shutdown,
            () = &mut terminating => return Closed::Terminated,
            () = sleep(wait) => {
                if clock.quiet_for() >= idle {
                    return Closed::Idle;
                }
            }
        }
    }
}
