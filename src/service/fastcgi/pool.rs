//! The connections to one FastCGI upstream: at most `max_connections` in use at once, idle ones
//! kept for reuse (`FCGI_KEEP_CONN`), and a bounded wait for a free one.
//!
//! One request runs on one connection. A connection whose request ended cleanly goes back to the
//! idle list; anything else (an error, a client that left, an application that closed) drops it.
//! The sockets a pool holds, in use and idle together, never pass `max_connections`: PHP-FPM
//! binds a worker to every open connection, so an idle one is not free.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

/// How long a request waits for a free connection before it answers `503`.
pub(super) const WAIT: Duration = Duration::from_secs(1);

/// How long a connection may sit idle before it is closed instead of reused.
const IDLE_MAX_AGE: Duration = Duration::from_secs(10);

/// Where an application listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Address {
    /// A unix socket.
    Unix(PathBuf),
    /// `host:port`.
    Tcp(Box<str>),
}

impl Address {
    /// Parses `unix:/absolute/path` or `host:port`.
    ///
    /// # Errors
    ///
    /// A message when the text is neither.
    pub(super) fn parse(text: &str) -> Result<Self, String> {
        if let Some(path) = text.strip_prefix("unix:") {
            return if path.starts_with('/') && !path.contains('\0') {
                Ok(Self::Unix(PathBuf::from(path)))
            } else {
                Err(format!("{text:?}: a unix socket needs an absolute path"))
            };
        }
        let (host, port) = text
            .rsplit_once(':')
            .ok_or_else(|| format!("{text:?} is neither unix:/path nor host:port"))?;
        if host.is_empty() || port.parse::<u16>().is_err() || text.contains(char::is_whitespace) {
            return Err(format!("{text:?} is neither unix:/path nor host:port"));
        }
        Ok(Self::Tcp(Box::from(text)))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
            Self::Tcp(address) => f.write_str(address),
        }
    }
}

/// One open connection to the application.
#[derive(Debug)]
pub(super) enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    /// Whether the application closed the connection, or sent something nobody asked for: either
    /// way it must not be reused. A connection with nothing to read is alive.
    fn is_spent(&self) -> bool {
        let mut byte = [0_u8; 1];
        let read = match self {
            Self::Tcp(stream) => stream.try_read(&mut byte),
            Self::Unix(stream) => stream.try_read(&mut byte),
        };
        !matches!(read, Err(err) if err.kind() == io::ErrorKind::WouldBlock)
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Why no connection was handed out.
#[derive(Debug, Error)]
pub(super) enum PoolError {
    /// Every connection stayed in use for the whole wait.
    #[error("every connection is in use")]
    Busy,
    /// The application did not accept a connection in time.
    #[error("connecting timed out")]
    DialTimeout,
    /// The application refused or dropped the connection.
    #[error("connecting failed: {0}")]
    Dial(#[from] io::Error),
}

#[derive(Debug)]
struct Idle {
    stream: Stream,
    since: Instant,
}

/// The connections to one upstream.
#[derive(Debug)]
pub(super) struct Pool {
    address: Address,
    wait: Duration,
    dial_timeout: Duration,
    slots: Arc<Semaphore>,
    idle: Mutex<VecDeque<Idle>>,
}

/// A connection checked out of a [`Pool`]. Dropping it closes the connection and frees its slot;
/// [`Conn::recycle`] keeps it for the next request.
#[derive(Debug)]
pub(super) struct Conn {
    stream: Option<Stream>,
    pool: Arc<Pool>,
    reused: bool,
    _slot: OwnedSemaphorePermit,
}

impl Pool {
    /// A pool of at most `max` connections (at least one) to `address`.
    pub(super) fn new(
        address: Address,
        max: usize,
        dial_timeout: Duration,
        wait: Duration,
    ) -> Arc<Self> {
        let max = max.max(1);
        Arc::new(Self {
            address,
            wait,
            dial_timeout,
            slots: Arc::new(Semaphore::new(max)),
            idle: Mutex::new(VecDeque::new()),
        })
    }

    /// Connections in use now, of at most `max`.
    #[cfg(test)]
    fn in_use(&self, max: usize) -> usize {
        max - self.slots.available_permits()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<Idle>> {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A connection, idle if one is alive, else a new one.
    ///
    /// # Errors
    ///
    /// [`PoolError::Busy`] when no slot frees up within the wait, [`PoolError::DialTimeout`] or
    /// [`PoolError::Dial`] when a new connection cannot be made.
    pub(super) async fn checkout(self: &Arc<Self>) -> Result<Conn, PoolError> {
        self.take(true).await
    }

    /// A new connection, after closing every idle one: for a request that found the one it was
    /// given dead, whose siblings are probably dead too.
    ///
    /// # Errors
    ///
    /// As [`Self::checkout`].
    pub(super) async fn checkout_fresh(self: &Arc<Self>) -> Result<Conn, PoolError> {
        self.take(false).await
    }

    async fn take(self: &Arc<Self>, reuse: bool) -> Result<Conn, PoolError> {
        let slot = timeout(self.wait, Arc::clone(&self.slots).acquire_owned())
            .await
            .map_err(|_| PoolError::Busy)?
            .map_err(|_| PoolError::Busy)?;
        if reuse {
            loop {
                let parked = self.lock().pop_back();
                let Some(parked) = parked else { break };
                if parked.since.elapsed() <= IDLE_MAX_AGE && !parked.stream.is_spent() {
                    return Ok(self.conn(parked.stream, slot, true));
                }
            }
        } else {
            self.lock().clear();
        }
        // The idle list is empty here, so in-use plus idle sockets stay within `max`.
        let stream = self.dial().await?;
        Ok(self.conn(stream, slot, false))
    }

    fn conn(self: &Arc<Self>, stream: Stream, slot: OwnedSemaphorePermit, reused: bool) -> Conn {
        Conn {
            stream: Some(stream),
            pool: Arc::clone(self),
            reused,
            _slot: slot,
        }
    }

    async fn dial(&self) -> Result<Stream, PoolError> {
        let connect = async {
            match &self.address {
                Address::Unix(path) => UnixStream::connect(path).await.map(Stream::Unix),
                Address::Tcp(address) => {
                    let stream = TcpStream::connect(&**address).await?;
                    stream.set_nodelay(true)?;
                    Ok(Stream::Tcp(stream))
                }
            }
        };
        timeout(self.dial_timeout, connect)
            .await
            .map_err(|_| PoolError::DialTimeout)?
            .map_err(PoolError::Dial)
    }
}

impl Conn {
    /// Whether the connection served an earlier request: the application may have closed it
    /// since, so a failure before any answer says nothing about the request itself.
    pub(super) fn is_reused(&self) -> bool {
        self.reused
    }

    /// The connection's stream.
    ///
    /// # Panics
    ///
    /// Never: the stream is taken only by [`Self::recycle`], which consumes the connection.
    pub(super) fn stream(&mut self) -> &mut Stream {
        self.stream
            .as_mut()
            .expect("a connection holds its stream until it is recycled")
    }

    /// Keeps the connection for the next request. Call it only when the request ended cleanly.
    pub(super) fn recycle(mut self) {
        if let Some(stream) = self.stream.take() {
            self.pool.lock().push_back(Idle {
                stream,
                since: Instant::now(),
            });
        }
    }
}

#[cfg(test)]
mod test {
    use tokio::net::TcpListener;

    use super::*;

    async fn listener() -> (TcpListener, Address) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address =
            Address::parse(&listener.local_addr().expect("addr").to_string()).expect("address");
        (listener, address)
    }

    fn pool(address: Address, max: usize, wait: Duration) -> Arc<Pool> {
        Pool::new(address, max, Duration::from_secs(2), wait)
    }

    #[test]
    fn addresses_parse() {
        assert_eq!(
            Address::parse("unix:/run/php/a.sock"),
            Ok(Address::Unix("/run/php/a.sock".into()))
        );
        assert!(Address::parse("127.0.0.1:9000").is_ok());
        assert!(Address::parse("php:9000").is_ok());
        for bad in [
            "unix:relative",
            "unix:",
            "9000",
            "host:",
            ":9000",
            "host:99999",
            "a b:1",
        ] {
            assert!(Address::parse(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn in_use_connections_never_pass_the_limit_and_a_waiter_gives_up() {
        let (listener, address) = listener().await;
        let pool = pool(address, 2, Duration::from_millis(100));
        let first = pool.checkout().await.expect("first");
        let _second = pool.checkout().await.expect("second");
        assert_eq!(pool.in_use(2), 2);
        assert!(matches!(pool.checkout().await, Err(PoolError::Busy)));
        drop(first);
        assert!(pool.checkout().await.is_ok(), "a freed slot is usable");
        drop(listener);
    }

    #[tokio::test]
    async fn a_recycled_connection_is_reused_and_a_closed_one_is_not() {
        let (listener, address) = listener().await;
        let pool = pool(address, 2, Duration::from_millis(100));
        let first = pool.checkout().await.expect("first");
        let (kept, _) = listener.accept().await.expect("accept");
        first.recycle();
        let again = pool.checkout().await.expect("reused");
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "no second connection was dialled"
        );
        again.recycle();
        drop(kept);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _fresh = pool.checkout().await.expect("dialled again");
        assert!(
            timeout(Duration::from_secs(1), listener.accept())
                .await
                .is_ok(),
            "the closed idle connection was replaced by a new one"
        );
    }

    #[tokio::test]
    async fn a_refused_connection_is_a_dial_error() {
        let address = Address::Unix("/nonexistent/podgate-fastcgi.sock".into());
        let pool = pool(address, 1, Duration::from_millis(100));
        assert!(matches!(pool.checkout().await, Err(PoolError::Dial(_))));
        assert_eq!(pool.in_use(1), 0, "a failed dial frees its slot");
    }
}
