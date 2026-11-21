//! The shared store of cluster-scope rate limits: a Redis-compatible server (Redis, Valkey,
//! KeyDB, Dragonfly) that every node asks, over RESP2, to take one token from a bucket.
//! Reference: `docs/ref/ratelimit-cluster.md`.
//!
//! # Where the store comes from
//!
//! Stores are process configuration: `RATE_LIMIT_STORES_FILE` names them, with their address,
//! credentials and the tenants that may use each. A snapshot only names a store; it never
//! supplies an address, because a snapshot-chosen address would be an outbound-connection
//! primitive. The address is the operator's, so the upstream address policy does not apply to
//! it (the operator may well point it at a private network, which the policy denies by
//! default). See [`Stores`].
//!
//! # One call
//!
//! [`Store::gcra`] sends `EVALSHA` for one Lua script (the generic cell rate algorithm, with the
//! time taken from the store's own clock, so nodes with skewed clocks agree) and loads the
//! script with `SCRIPT LOAD` when the store answers `NOSCRIPT`. One round trip decides.
//!
//! # When the store fails
//!
//! A call that errors, times out, finds the circuit open or finds too many calls in flight is a
//! [`StoreError`]; what to do about it is the middleware's choice. The circuit opens after
//! [`OPEN_AFTER_ERRORS`] consecutive errors for [`OPEN_FOR`], then lets one probe through, so a
//! dead store costs one timeout per period. At most [`MAX_IN_FLIGHT`] calls are in flight per
//! store, shared fairly by the tenants the store lists, so one tenant cannot use up the
//! slots of the others. No call outlives its deadline, which is at most [`MAX_TIMEOUT_MS`]
//! milliseconds.

mod circuit;
mod file;
mod resp;

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, Weak};
use std::time::Duration;

use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::budget::Escaped;
use circuit::{Change, Circuit};
pub use circuit::{OPEN_AFTER_ERRORS, OPEN_FOR};
pub use file::{LoadError, MAX_TIMEOUT_MS};
use resp::{Reader, Reply, RespError, encode};

/// Most calls in flight to one store, whoever makes them.
pub const MAX_IN_FLIGHT: usize = 256;

/// The generic cell rate algorithm on one key. `ARGV[1]` is the time per token and `ARGV[2]`
/// the time to refill an empty bucket, both in microseconds; the key holds the time at which
/// the bucket would be full again and expires when it is. Returns `{1, 0}` when a token was
/// taken and `{0, microseconds until one is there}` when none was.
const SCRIPT: &str = "\
if redis.replicate_commands then redis.replicate_commands() end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local interval = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local stored = redis.call('GET', KEYS[1])
local tat = now
if stored then tat = math.max(tonumber(stored), now) end
local next = tat + interval
local wait = next - burst - now
if wait > 0 then return {0, wait} end
redis.call('SET', KEYS[1], string.format('%.0f', next), 'PX', math.ceil((next - now) / 1000) + 1)
return {1, 0}
";

/// The digest `EVALSHA` names the script by.
static SCRIPT_SHA: LazyLock<String> = LazyLock::new(|| {
    Sha1::digest(SCRIPT.as_bytes())
        .iter()
        .fold(String::with_capacity(40), |mut hex, byte| {
            // Writing to a `String` cannot fail.
            let _ = write!(hex, "{byte:02x}");
            hex
        })
});

/// The stores that are alive, for the metrics exposition.
static LIVE: Mutex<Vec<Weak<Store>>> = Mutex::new(Vec::new());

/// The rate of a bucket, in microseconds: the store's clock counts no finer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gcra {
    /// Time per token.
    pub interval_us: u64,
    /// Time to refill an empty bucket: `burst` tokens.
    pub burst_us: u64,
}

/// What the store said about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A token was taken.
    Allowed,
    /// The bucket is empty.
    Limited {
        /// Microseconds until a token is there.
        retry_after_us: u64,
    },
}

/// Why a call did not produce a [`Verdict`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The circuit is open: the call was not made.
    #[error("the store's circuit is open")]
    CircuitOpen,
    /// Too many calls are in flight: the call was not made.
    #[error("too many calls in flight to the store")]
    Saturated,
    /// The tenant is not one the store lists.
    #[error("the tenant may not use the store")]
    Forbidden,
    /// The call did not finish within its deadline.
    #[error("the store did not answer in time")]
    Timeout,
    /// Connecting, reading or writing failed.
    #[error("the connection to the store failed: {0}")]
    Io(#[from] std::io::Error),
    /// The store answered something that is not RESP2, or too much of it.
    #[error("the store sent a malformed reply: {0}")]
    Protocol(&'static str),
    /// The store answered with an error: bad credentials, out of memory, read only.
    #[error("the store answered an error: {0}")]
    Server(Box<str>),
    /// The store answered something the script never returns.
    #[error("the store sent an unexpected reply")]
    Unexpected,
}

impl From<RespError> for StoreError {
    fn from(err: RespError) -> Self {
        match err {
            RespError::Io(err) => Self::Io(err),
            RespError::Protocol(what) => Self::Protocol(what),
        }
    }
}

/// What a request does when the store fails, for the error counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The request is admitted if the local fallback allows it.
    Allow,
    /// The request is refused.
    Deny,
}

/// `up` before any call.
const UNKNOWN: u8 = 0;
/// `up` after a call succeeded.
const UP: u8 = 1;
/// `up` after a call failed.
const DOWN: u8 = 2;

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// One connection with its read buffer.
struct Conn {
    io: Box<dyn Duplex>,
    reader: Reader,
}

impl Conn {
    async fn roundtrip(&mut self, args: &[&[u8]]) -> Result<Reply, StoreError> {
        let mut command = Vec::with_capacity(160);
        encode(&mut command, args);
        self.io.write_all(&command).await?;
        self.io.flush().await?;
        Ok(self.reader.reply(&mut self.io).await?)
    }
}

/// Connections of one store.
#[derive(Debug)]
struct Pool {
    /// One permit per connection in use, so at most `max_connections` exist.
    permits: Semaphore,
    idle: Mutex<Vec<Conn>>,
    max_idle: usize,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

/// The right to have one call in flight; released on drop.
struct Slot<'a> {
    store: &'a Store,
    tenant: &'a AtomicUsize,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.tenant.fetch_sub(1, Ordering::AcqRel);
        self.store.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One store: its connections, circuit and counters. Shared by every request that names it.
pub struct Store {
    name: Box<str>,
    spec: file::Spec,
    pool: Pool,
    circuit: Circuit,
    in_flight: AtomicUsize,
    /// Calls in flight per listed tenant.
    tenants: Box<[(Box<str>, AtomicUsize)]>,
    /// Calls one tenant may have in flight.
    share: usize,
    up: AtomicU8,
    /// Calls that failed, by [`Mode`] of the middleware that made them.
    errors: [AtomicU64; 2],
}

impl fmt::Debug for Store {
    /// The name, address and tenants. Credentials are not shown: the password type hides them
    /// and this does not even reach for them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("name", &self.name)
            .field("host", &self.spec.host)
            .field("port", &self.spec.port)
            .field("tls", &self.spec.tls.is_some())
            .field("authenticated", &self.spec.auth.is_some())
            .field("tenants", &self.spec.tenants)
            .finish_non_exhaustive()
    }
}

impl Store {
    fn new(name: &str, spec: file::Spec) -> Arc<Self> {
        let listed = spec.tenants.len();
        let share = if listed > 1 {
            (MAX_IN_FLIGHT / listed).max(1)
        } else {
            MAX_IN_FLIGHT
        };
        let max_connections = usize::from(spec.max_connections);
        let store = Arc::new(Self {
            name: name.into(),
            pool: Pool {
                permits: Semaphore::new(max_connections),
                idle: Mutex::new(Vec::new()),
                max_idle: max_connections,
            },
            circuit: Circuit::new(OPEN_AFTER_ERRORS, OPEN_FOR),
            in_flight: AtomicUsize::new(0),
            tenants: spec
                .tenants
                .iter()
                .map(|tenant| (tenant.clone(), AtomicUsize::new(0)))
                .collect(),
            share,
            up: AtomicU8::new(UNKNOWN),
            errors: [AtomicU64::new(0), AtomicU64::new(0)],
            spec,
        });
        let mut live = LIVE.lock().unwrap_or_else(PoisonError::into_inner);
        live.retain(|other| other.strong_count() > 0);
        live.push(Arc::downgrade(&store));
        store
    }

    /// The name a snapshot refers to the store by.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How long a call may take when the middleware does not say.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.spec.timeout
    }

    /// Whether `tenant` may use this store.
    #[must_use]
    pub fn allows(&self, tenant: &str) -> bool {
        self.spec.tenants.iter().any(|listed| &**listed == tenant)
    }

    /// Counts a request that met a store error and took the `mode` of its middleware.
    pub fn count_error(&self, mode: Mode) {
        self.errors[mode as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Whether the last call succeeded; `None` before the first call.
    #[must_use]
    pub fn is_up(&self) -> Option<bool> {
        match self.up.load(Ordering::Relaxed) {
            UP => Some(true),
            DOWN => Some(false),
            _ => None,
        }
    }

    fn slot<'a>(&'a self, tenant: &str) -> Result<Slot<'a>, StoreError> {
        let counter = self
            .tenants
            .iter()
            .find(|(listed, _)| &**listed == tenant)
            .map(|(_, counter)| counter)
            .ok_or(StoreError::Forbidden)?;
        if counter.fetch_add(1, Ordering::AcqRel) >= self.share {
            counter.fetch_sub(1, Ordering::AcqRel);
            return Err(StoreError::Saturated);
        }
        if self.in_flight.fetch_add(1, Ordering::AcqRel) >= MAX_IN_FLIGHT {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            counter.fetch_sub(1, Ordering::AcqRel);
            return Err(StoreError::Saturated);
        }
        Ok(Slot {
            store: self,
            tenant: counter,
        })
    }

    /// Takes one token from the bucket `key` for `tenant`. The call ends within `timeout` (the
    /// store's own when `None`, never more than [`MAX_TIMEOUT_MS`]), whatever the store does.
    ///
    /// # Errors
    ///
    /// A [`StoreError`] when no verdict could be had; the caller decides what that means for
    /// the request.
    pub async fn gcra(
        &self,
        tenant: &str,
        key: &str,
        rate: Gcra,
        timeout: Option<Duration>,
    ) -> Result<Verdict, StoreError> {
        let _slot = self.slot(tenant)?;
        let permit = self.circuit.admit().ok_or(StoreError::CircuitOpen)?;
        let deadline = timeout
            .unwrap_or(self.spec.timeout)
            .min(Duration::from_millis(u64::from(MAX_TIMEOUT_MS)));
        let result = tokio::time::timeout(deadline, self.call(key, rate))
            .await
            .unwrap_or(Err(StoreError::Timeout));
        let ok = result.is_ok();
        self.up.store(if ok { UP } else { DOWN }, Ordering::Relaxed);
        match (permit.settle(ok), &result) {
            (Change::Opened, Err(err)) => tracing::warn!(
                store = &*self.name,
                error = %err,
                "rate limit store unavailable: calls are refused for {OPEN_FOR:?}, then one probe is made"
            ),
            (Change::Closed, _) => {
                tracing::info!(store = &*self.name, "rate limit store is back");
            }
            _ => {}
        }
        result
    }

    async fn call(&self, key: &str, rate: Gcra) -> Result<Verdict, StoreError> {
        let _connection = self
            .pool
            .permits
            .acquire()
            .await
            .map_err(|_| StoreError::Unexpected)?;
        let idle = self
            .pool
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        if let Some(mut conn) = idle {
            match self.eval(&mut conn, key, rate).await {
                Ok(verdict) => {
                    self.put_back(conn);
                    return Ok(verdict);
                }
                // The store closed an idle connection: use a fresh one.
                Err(StoreError::Io(_)) => {}
                Err(err) => return Err(err),
            }
        }
        let mut conn = self.connect().await?;
        let verdict = self.eval(&mut conn, key, rate).await?;
        self.put_back(conn);
        Ok(verdict)
    }

    fn put_back(&self, conn: Conn) {
        let mut idle = self
            .pool
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if idle.len() < self.pool.max_idle {
            idle.push(conn);
        }
    }

    async fn connect(&self) -> Result<Conn, StoreError> {
        let tcp = TcpStream::connect((&*self.spec.host, self.spec.port)).await?;
        tcp.set_nodelay(true)?;
        let io: Box<dyn Duplex> = match &self.spec.tls {
            Some(tls) => Box::new(tls.connector.connect(tls.server_name.clone(), tcp).await?),
            None => Box::new(tcp),
        };
        let mut conn = Conn {
            io,
            reader: Reader::default(),
        };
        if let Some(auth) = &self.spec.auth {
            let mut args: Vec<&[u8]> = vec![b"AUTH"];
            if let Some(username) = &auth.username {
                args.push(username.as_bytes());
            }
            args.push(auth.password.expose());
            match conn.roundtrip(&args).await? {
                Reply::Status(_) => {}
                Reply::Error(text) => return Err(StoreError::Server(text)),
                _ => return Err(StoreError::Unexpected),
            }
        }
        Ok(conn)
    }

    async fn eval(&self, conn: &mut Conn, key: &str, rate: Gcra) -> Result<Verdict, StoreError> {
        let interval = rate.interval_us.to_string();
        let burst = rate.burst_us.to_string();
        let sha = SCRIPT_SHA.as_bytes();
        let evalsha: [&[u8]; 6] = [
            b"EVALSHA",
            sha,
            b"1",
            key.as_bytes(),
            interval.as_bytes(),
            burst.as_bytes(),
        ];
        let mut reply = conn.roundtrip(&evalsha).await?;
        if matches!(&reply, Reply::Error(text) if text.starts_with("NOSCRIPT")) {
            match conn
                .roundtrip(&[b"SCRIPT", b"LOAD", SCRIPT.as_bytes()])
                .await?
            {
                Reply::Bulk(_) => {}
                Reply::Error(text) => return Err(StoreError::Server(text)),
                _ => return Err(StoreError::Unexpected),
            }
            reply = conn.roundtrip(&evalsha).await?;
        }
        match reply {
            Reply::Array(items) => match items.as_slice() {
                [Reply::Int(1), Reply::Int(_)] => Ok(Verdict::Allowed),
                [Reply::Int(0), Reply::Int(wait)] => Ok(Verdict::Limited {
                    retry_after_us: u64::try_from(*wait).unwrap_or(0),
                }),
                _ => Err(StoreError::Unexpected),
            },
            Reply::Error(text) => Err(StoreError::Server(text)),
            _ => Err(StoreError::Unexpected),
        }
    }
}

/// The stores of `RATE_LIMIT_STORES_FILE`, by name. Cheap to clone; empty when the file is not
/// set, so a snapshot that names a store is refused.
#[derive(Debug, Clone, Default)]
pub struct Stores {
    by_name: Arc<BTreeMap<Box<str>, Arc<Store>>>,
}

impl Stores {
    /// Reads and validates the file at `path`. No store is contacted: a store that is down at
    /// startup does not stop the proxy, its circuit handles it.
    ///
    /// # Errors
    ///
    /// [`LoadError`] naming the file or the entry that is wrong; it never quotes a credential.
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let by_name = file::load(path)?
            .into_iter()
            .map(|(name, spec)| {
                let store = Store::new(&name, spec);
                (name, store)
            })
            .collect();
        Ok(Self {
            by_name: Arc::new(by_name),
        })
    }

    /// The store called `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Arc<Store>> {
        self.by_name.get(name)
    }

    /// Whether `tenant` may use the store called `name`. A store that does not exist and one the
    /// tenant may not use are the same answer: a tenant learns nothing about other tenants' stores.
    #[must_use]
    pub fn allows(&self, name: &str, tenant: &str) -> bool {
        self.get(name).is_some_and(|store| store.allows(tenant))
    }
}

/// Appends `podgate_ratelimit_store_up` and `podgate_ratelimit_store_errors_total` for every
/// store of this process to the metrics exposition `out`.
pub fn render(out: &mut String) {
    let mut stores: Vec<Arc<Store>> = LIVE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter_map(Weak::upgrade)
        .collect();
    stores.sort_by(|a, b| a.name.cmp(&b.name));
    let up = "podgate_ratelimit_store_up";
    let _ = writeln!(
        out,
        "# HELP {up} 1 when the last call to a cluster rate limit store succeeded, 0 when it failed or its circuit is open; absent before the first call.\n# TYPE {up} gauge"
    );
    for store in &stores {
        if let Some(is_up) = store.is_up() {
            let _ = writeln!(
                out,
                "{up}{{store=\"{}\"}} {}",
                Escaped(&store.name),
                u8::from(is_up && !store.circuit.is_open())
            );
        }
    }
    let errors = "podgate_ratelimit_store_errors_total";
    let _ = writeln!(
        out,
        "# HELP {errors} Requests that met a store error, by what their middleware's on_store_error did.\n# TYPE {errors} counter"
    );
    for store in &stores {
        for (mode, counter) in [Mode::Allow, Mode::Deny].into_iter().zip(&store.errors) {
            let _ = writeln!(
                out,
                "{errors}{{store=\"{}\",mode=\"{}\"}} {}",
                Escaped(&store.name),
                match mode {
                    Mode::Allow => "allow",
                    Mode::Deny => "deny",
                },
                counter.load(Ordering::Relaxed)
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn the_script_digest_is_forty_hex_digits() {
        assert_eq!(SCRIPT_SHA.len(), 40);
        assert!(SCRIPT_SHA.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
