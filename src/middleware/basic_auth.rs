//! The `basic_auth` middleware: HTTP Basic credentials checked against bcrypt or argon2 hashes.
//! Full reference: `docs/ref/mw-basic-auth.md`.
//!
//! ```json
//! {
//!   "name": "auth", "type": "basic_auth",
//!   "users": ["alice:$2b$10$..."], "realm": "admin",
//!   "header_field": "x-user", "remove_header": true
//! }
//! ```
//!
//! Hashing is attacker-triggered CPU and memory, so it is bounded and charged like any other
//! resource a tenant can make podgate spend:
//!
//! - Cost caps at compile: bcrypt cost at most 14, argon2 memory at most 64 MiB, time and
//!   parallelism at most 4.
//! - A [`Pool`] runs every verification on the blocking pool behind a permit. A tenant may hold
//!   at most half of the permits, so one tenant's flood cannot take them all, and a verification
//!   waits at most one second for a permit before the request answers `503` with
//!   `retry-after: 1`.
//! - An argon2 verification reserves its memory from the tenant's `max_buffer_bytes` first.
//! - A source with five failed attempts in a minute waits a second before each further attempt
//!   is verified.
//! - A verified credential is remembered for 30 seconds under a keyed hash, at most 4096 of
//!   them per middleware, so a client that re-sends its credentials on every request does not
//!   rehash each time.
//!
//! An unknown user is verified against one of the configured hashes and the result is thrown
//! away, so the time taken does not say which users exist. Password comparison is done by the
//! hash libraries in constant time. Neither a hash nor a password is ever logged or printed.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use argon2::password_hash::PasswordVerifier;
use argon2::password_hash::phc::PasswordHash;
use argon2::{Algorithm, Argon2, Params};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use pingora::http::ResponseHeader;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{CompileCx, Flow, Kind, RequestCx, Stage, headers, state};
use crate::budget::{BufferGuard, TenantBudget};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::table::CompiledApp;
use podgate_model::Declared;

/// Highest bcrypt cost (work factor, a power of two) a hash may carry.
const MAX_BCRYPT_COST: u32 = 14;
/// Lowest cost the bcrypt algorithm defines.
const MIN_BCRYPT_COST: u32 = 4;
/// Largest argon2 memory, in KiB, a hash may ask for.
const MAX_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Largest argon2 time cost (passes) and parallelism (lanes).
const MAX_ARGON2_TIME: u32 = 4;
const MAX_ARGON2_LANES: u32 = 4;
/// Most users one middleware may declare.
const MAX_USERS: usize = 4096;
/// Longest user name and password, in bytes, that is verified; longer ones are refused unhashed.
const MAX_USER_BYTES: usize = 255;
const MAX_PASSWORD_BYTES: usize = 1024;
/// Longest `Authorization` value that is decoded at all.
const MAX_HEADER_BYTES: usize = 2048;
const DEFAULT_REALM: &str = "podgate";

/// How long a verified credential is remembered, and how many are.
const CACHE_TTL: Duration = Duration::from_secs(30);
const CACHE_ENTRIES: usize = 4096;
/// Failed attempts a source gets per [`FAILURE_WINDOW`] before each further one is delayed by
/// [`FAILURE_DELAY`], and how many sources are tracked.
const FAILURES_FREE: u32 = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
const FAILURE_DELAY: Duration = Duration::from_secs(1);
const FAILURE_SOURCES: usize = 4096;

/// The configuration of a `basic_auth` middleware.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// htpasswd entries, `user:hash`, with a bcrypt (`$2a$`, `$2b$`, `$2y$`) or argon2
    /// (`$argon2id$`, `$argon2i$`, `$argon2d$`, PHC form) hash.
    pub users: Vec<String>,
    /// The realm of the challenge; default `podgate`.
    #[serde(default)]
    pub realm: Option<String>,
    /// A request header that receives the user name; a value the client sent for it is replaced.
    #[serde(default)]
    pub header_field: Option<String>,
    /// Remove `Authorization` before the request goes to the upstream; default `false`, as in
    /// Traefik.
    #[serde(default)]
    pub remove_header: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("users", &format_args!("[redacted; {}]", self.users.len()))
            .field("realm", &self.realm)
            .field("header_field", &self.header_field)
            .field("remove_header", &self.remove_header)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Bcrypt,
    Argon2,
}

/// One user's stored hash. Its `Debug` never shows the hash.
struct Entry {
    scheme: Scheme,
    hash: Box<str>,
    /// Memory one verification holds, charged to the tenant.
    memory: u64,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("scheme", &self.scheme)
            .field("hash", &"[redacted]")
            .field("memory", &self.memory)
            .finish()
    }
}

impl Entry {
    /// Whether `password` matches. The libraries compare in constant time.
    fn matches(&self, password: &str) -> bool {
        match self.scheme {
            Scheme::Bcrypt => bcrypt::non_truncating_verify(password, &self.hash).unwrap_or(false),
            Scheme::Argon2 => Argon2::default()
                .verify_password(password.as_bytes(), &*self.hash)
                .is_ok(),
        }
    }
}

/// Parses `hash` for `user`; the error is a message that never repeats the hash.
fn classify(user: &str, hash: &str) -> Result<Entry, String> {
    if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
        bcrypt_entry(user, hash)
    } else if hash.starts_with("$argon2id$")
        || hash.starts_with("$argon2i$")
        || hash.starts_with("$argon2d$")
    {
        argon2_entry(user, hash)
    } else {
        Err(format!(
            "user {user:?}: the hash is not bcrypt or argon2; MD5 ($apr1$), SHA1 ({{SHA}}), crypt and plaintext entries are refused"
        ))
    }
}

fn bcrypt_entry(user: &str, hash: &str) -> Result<Entry, String> {
    let bytes = hash.as_bytes();
    let well_formed = bytes.len() == 60
        && bytes.get(3) == Some(&b'$')
        && bytes.get(6) == Some(&b'$')
        && bytes.get(7..).is_some_and(|rest| {
            rest.iter()
                .all(|c| c.is_ascii_alphanumeric() || b"./".contains(c))
        });
    let cost = hash.get(4..6).and_then(|digits| digits.parse::<u32>().ok());
    let Some(cost) = cost.filter(|_| well_formed) else {
        return Err(format!("user {user:?}: the bcrypt hash is malformed"));
    };
    if cost < MIN_BCRYPT_COST {
        return Err(format!(
            "user {user:?}: bcrypt cost {cost} is below {MIN_BCRYPT_COST}"
        ));
    }
    if cost > MAX_BCRYPT_COST {
        return Err(format!(
            "user {user:?}: bcrypt cost {cost} is above the limit of {MAX_BCRYPT_COST}"
        ));
    }
    Ok(Entry {
        scheme: Scheme::Bcrypt,
        hash: hash.into(),
        memory: 0,
    })
}

fn argon2_entry(user: &str, hash: &str) -> Result<Entry, String> {
    let malformed = || format!("user {user:?}: the argon2 hash is malformed");
    let parsed = PasswordHash::new(hash).map_err(|_| malformed())?;
    if parsed.salt.is_none() || parsed.hash.is_none() {
        return Err(malformed());
    }
    Algorithm::try_from(parsed.algorithm.as_str()).map_err(|_| malformed())?;
    let params = Params::try_from(&parsed).map_err(|_| malformed())?;
    let (memory, time, lanes) = (params.m_cost(), params.t_cost(), params.p_cost());
    if memory > MAX_ARGON2_MEMORY_KIB {
        return Err(format!(
            "user {user:?}: argon2 memory {memory} KiB is above the limit of {MAX_ARGON2_MEMORY_KIB} KiB"
        ));
    }
    if time > MAX_ARGON2_TIME {
        return Err(format!(
            "user {user:?}: argon2 time cost {time} is above the limit of {MAX_ARGON2_TIME}"
        ));
    }
    if lanes > MAX_ARGON2_LANES {
        return Err(format!(
            "user {user:?}: argon2 parallelism {lanes} is above the limit of {MAX_ARGON2_LANES}"
        ));
    }
    Ok(Entry {
        scheme: Scheme::Argon2,
        hash: hash.into(),
        memory: u64::from(memory) * 1024,
    })
}

/// The bounded executor of password verifications, shared by every `basic_auth` middleware.
/// Cheap to clone; every clone shares the permits.
#[derive(Debug, Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

#[derive(Debug)]
struct PoolInner {
    permits: Arc<Semaphore>,
    /// Most permits one tenant may hold at once.
    per_tenant: usize,
    wait: Duration,
    holding: Mutex<HashMap<Box<str>, usize>>,
    runs: AtomicU64,
}

/// What one verification holds: the tenant's share, a worker permit and the tenant's memory
/// charge. It moves into the blocking closure, so it is freed when the hashing ends, not when
/// the client goes away.
#[derive(Debug)]
struct Run {
    pool: Arc<PoolInner>,
    tenant: Box<str>,
    _permit: Option<OwnedSemaphorePermit>,
    _memory: Option<BufferGuard>,
}

impl Drop for Run {
    fn drop(&mut self) {
        let mut holding = self
            .pool
            .holding
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = holding.get_mut(&self.tenant) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                holding.remove(&self.tenant);
            }
        }
    }
}

impl Pool {
    /// A pool of `max` workers; a verification waits at most `wait` for one.
    #[must_use]
    pub fn new(max: usize, wait: Duration) -> Self {
        let max = max.max(1);
        Self {
            inner: Arc::new(PoolInner {
                permits: Arc::new(Semaphore::new(max)),
                per_tenant: (max / 2).max(1),
                wait,
                holding: Mutex::new(HashMap::new()),
                runs: AtomicU64::new(0),
            }),
        }
    }

    /// Verifications started since the process began.
    #[must_use]
    pub fn runs(&self) -> u64 {
        self.inner.runs.load(Ordering::Relaxed)
    }

    /// Takes the tenant's share, a worker and the memory charge, in that order, so a request
    /// that cannot be served holds nothing while it waits.
    async fn admit(
        &self,
        tenant: &str,
        budget: Option<&Arc<TenantBudget>>,
        memory: u64,
    ) -> Result<Run, AppError> {
        {
            let mut holding = self
                .inner
                .holding
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let count = holding.get(tenant).copied().unwrap_or(0);
            if count >= self.inner.per_tenant {
                return Err(AppError::AuthBusy);
            }
            holding.insert(tenant.into(), count + 1);
        }
        let mut run = Run {
            pool: Arc::clone(&self.inner),
            tenant: tenant.into(),
            _permit: None,
            _memory: None,
        };
        let permit = tokio::time::timeout(
            self.inner.wait,
            Arc::clone(&self.inner.permits).acquire_owned(),
        )
        .await
        .map_err(|_| AppError::AuthBusy)?
        .map_err(|_| AppError::AuthBusy)?;
        run._permit = Some(permit);
        if memory > 0
            && let Some(budget) = budget
        {
            run._memory = Some(budget.charge(memory).ok_or(if budget.fits_at_all(memory) {
                AppError::AuthBusy
            } else {
                AppError::AuthOverBudget
            })?);
        }
        Ok(run)
    }

    /// Runs `entry.matches(password)` on the blocking pool under an admitted [`Run`].
    async fn verify(
        &self,
        tenant: &str,
        budget: Option<&Arc<TenantBudget>>,
        entry: Arc<Entry>,
        password: String,
    ) -> Result<bool, AppError> {
        let run = self.admit(tenant, budget, entry.memory).await?;
        self.inner.runs.fetch_add(1, Ordering::Relaxed);
        tokio::task::spawn_blocking(move || {
            let _run = run;
            entry.matches(&password)
        })
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("password verification task failed")))
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::new(
            std::thread::available_parallelism().map_or(1, usize::from),
            Duration::from_secs(1),
        )
    }
}

type Digest = [u8; 32];

/// Credentials that verified, by keyed hash, with the time they did.
#[derive(Debug, Default)]
struct Cache {
    verified: HashMap<Digest, Instant>,
    order: VecDeque<Digest>,
}

impl Cache {
    fn hit(&mut self, key: &Digest, now: Instant) -> bool {
        match self.verified.get(key) {
            Some(at) if now.duration_since(*at) < CACHE_TTL => true,
            Some(_) => {
                self.verified.remove(key);
                false
            }
            None => false,
        }
    }

    fn insert(&mut self, key: Digest, now: Instant) {
        if self.verified.insert(key, now).is_some() {
            return;
        }
        while self.order.len() >= CACHE_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.verified.remove(&oldest);
            }
        }
        self.order.push_back(key);
    }
}

/// Failed attempts per source in the current window.
#[derive(Debug, Default)]
struct Failures {
    sources: HashMap<IpAddr, (Instant, u32)>,
}

impl Failures {
    fn delayed(&self, source: IpAddr, now: Instant) -> bool {
        self.sources.get(&source).is_some_and(|(start, count)| {
            now.duration_since(*start) < FAILURE_WINDOW && *count >= FAILURES_FREE
        })
    }

    fn record(&mut self, source: IpAddr, now: Instant) {
        if !self.sources.contains_key(&source) && self.sources.len() >= FAILURE_SOURCES {
            self.sources
                .retain(|_, (start, _)| now.duration_since(*start) < FAILURE_WINDOW);
            if self.sources.len() >= FAILURE_SOURCES {
                let oldest = self
                    .sources
                    .iter()
                    .min_by_key(|(_, (start, _))| *start)
                    .map(|(source, _)| *source);
                if let Some(oldest) = oldest {
                    self.sources.remove(&oldest);
                }
            }
        }
        let slot = self.sources.entry(source).or_insert((now, 0));
        if now.duration_since(slot.0) >= FAILURE_WINDOW {
            *slot = (now, 0);
        }
        slot.1 = slot.1.saturating_add(1);
    }
}

/// The source a failure counts against: an IPv4 address, or the /64 of an IPv6 one, so a client
/// that owns a whole /64 cannot rotate addresses.
fn source_key(addr: Option<IpAddr>) -> IpAddr {
    match addr.map(|addr| addr.to_canonical()) {
        Some(IpAddr::V6(v6)) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0_u128 << 64))),
        Some(v4) => v4,
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

/// What the middleware decided about the credentials of a request.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Known user, right password.
    Allow(Box<str>),
    /// No, malformed or wrong credentials: `401`.
    Deny,
}

/// Who is asking, for the pool and the failure counter.
struct Who<'a> {
    pool: &'a Pool,
    tenant: &'a str,
    budget: Option<&'a Arc<TenantBudget>>,
    source: Option<IpAddr>,
}

/// A compiled `basic_auth` middleware.
pub struct BasicAuth(Box<Parts>);

/// The state of a [`BasicAuth`], boxed so the stage enum stays small.
pub struct Parts {
    realm: Box<str>,
    challenge: HeaderValue,
    header_field: Option<HeaderName>,
    remove_header: bool,
    users: HashMap<Box<str>, Arc<Entry>>,
    /// The entry an unknown user is verified against, so the work is the same.
    dummy: Arc<Entry>,
    runtime: Arc<Runtime>,
    /// A digest of the whole declaration: the registry hands state to an equal one only.
    fingerprint: u64,
}

/// What a middleware learns while it runs, shared by every compiled table that declares the
/// same middleware (see [`Registry`]): the cache key, the verified credentials and the failed
/// attempts per source.
#[derive(Debug)]
pub(crate) struct Runtime {
    key: [u8; 32],
    cache: Mutex<Cache>,
    failures: Mutex<Failures>,
}

/// The [`Runtime`] of every `basic_auth` middleware of the live table, kept by the shared
/// [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]). A push
/// that leaves a middleware's declaration as it was keeps its failure counters and cache; a
/// middleware whose users or any other field changed starts fresh, so a changed password is
/// never served from the cache.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtime>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            Stage::BasicAuth(auth) => Some((auth.0.fingerprint, &mut auth.0.runtime)),
            _ => None,
        });
    }
}

impl Deref for BasicAuth {
    type Target = Parts;

    fn deref(&self) -> &Parts {
        &self.0
    }
}

impl fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuth")
            .field("realm", &self.realm)
            .field("header_field", &self.header_field)
            .field("remove_header", &self.remove_header)
            .field("users", &format_args!("[redacted; {}]", self.users.len()))
            .finish_non_exhaustive()
    }
}

fn invalid(message: impl fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("basic_auth: {message}"))
}

/// `user:password` out of an `Authorization` value, when it is a well-formed Basic credential.
fn credentials(value: &[u8]) -> Option<(String, String)> {
    if value.len() > MAX_HEADER_BYTES {
        return None;
    }
    let (scheme, rest) = value.split_at_checked(5)?;
    if !scheme.eq_ignore_ascii_case(b"basic") {
        return None;
    }
    let token = rest.strip_prefix(b" ")?.trim_ascii_start();
    let decoded = STANDARD.decode(token).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    if user.len() > MAX_USER_BYTES || password.len() > MAX_PASSWORD_BYTES {
        return None;
    }
    Some((user.to_owned(), password.to_owned()))
}

impl BasicAuth {
    fn digest(&self, user: &str, password: &str) -> Option<Digest> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.runtime.key).ok()?;
        mac.update(&u32::try_from(user.len()).ok()?.to_be_bytes());
        mac.update(user.as_bytes());
        mac.update(password.as_bytes());
        Digest::try_from(mac.finalize().into_bytes().as_slice()).ok()
    }

    /// Decides one request from its `Authorization` header (`None`: absent or repeated).
    async fn authenticate(
        &self,
        who: &Who<'_>,
        header: Option<&[u8]>,
    ) -> Result<Verdict, AppError> {
        let Some((user, password)) = header.and_then(credentials) else {
            return Ok(Verdict::Deny);
        };
        let key = self.digest(&user, &password);
        let source = source_key(who.source);
        if let Some(key) = &key {
            let hit = self
                .runtime
                .cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .hit(key, Instant::now());
            if hit {
                return Ok(Verdict::Allow(user.into()));
            }
        }
        let delayed = self
            .runtime
            .failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .delayed(source, Instant::now());
        if delayed {
            tokio::time::sleep(FAILURE_DELAY).await;
        }
        let known = self.users.get(user.as_str());
        let entry = Arc::clone(known.unwrap_or(&self.dummy));
        let matched = who
            .pool
            .verify(who.tenant, who.budget, entry, password)
            .await?;
        let now = Instant::now();
        if matched && known.is_some() {
            if let Some(key) = key {
                self.runtime
                    .cache
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(key, now);
            }
            return Ok(Verdict::Allow(user.into()));
        }
        self.runtime
            .failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(source, now);
        Ok(Verdict::Deny)
    }

    async fn challenge(&self, cx: &mut RequestCx<'_>) -> pingora::Result<()> {
        let body = Bytes::from_static(br#"{"error":"unauthorized"}"#);
        let mut header = ResponseHeader::build(401, Some(4))?;
        header.insert_header("www-authenticate", self.challenge.clone())?;
        header.insert_header("content-type", "application/json")?;
        header.insert_header("content-length", body.len().to_string())?;
        header.insert_header("cache-control", "no-store")?;
        cx.session
            .write_response_header(Box::new(header), false)
            .await?;
        cx.session.write_response_body(Some(body), true).await
    }
}

impl Kind for BasicAuth {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        if config.users.is_empty() {
            return Err(invalid(
                "`users` is empty; a chain that admits nobody is a mistake",
            ));
        }
        if config.users.len() > MAX_USERS {
            return Err(invalid(format!("more than {MAX_USERS} users")));
        }
        let mut users = HashMap::with_capacity(config.users.len());
        let mut dummy = None;
        for line in &config.users {
            let (user, hash) = line
                .split_once(':')
                .ok_or_else(|| invalid("a user entry is not `user:hash`"))?;
            if user.is_empty()
                || user.len() > MAX_USER_BYTES
                || user.chars().any(char::is_control)
                || user.starts_with(' ')
                || user.ends_with(' ')
            {
                return Err(invalid(format!("{user:?} is not a usable user name")));
            }
            let entry = Arc::new(classify(user, hash).map_err(invalid)?);
            dummy.get_or_insert_with(|| Arc::clone(&entry));
            if users.insert(Box::<str>::from(user), entry).is_some() {
                return Err(invalid(format!("user {user:?} is declared twice")));
            }
        }
        let dummy = dummy.ok_or_else(|| invalid("`users` is empty"))?;
        let realm = config.realm.unwrap_or_else(|| DEFAULT_REALM.to_owned());
        if realm.is_empty()
            || realm
                .chars()
                .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err(invalid(
                "`realm` must be non-empty and free of control characters, `\"` and `\\`",
            ));
        }
        let challenge = HeaderValue::from_bytes(
            format!("Basic realm=\"{realm}\", charset=\"UTF-8\"").as_bytes(),
        )
        .map_err(|_| invalid("`realm` is not a valid header value"))?;
        let header_field = config
            .header_field
            .as_deref()
            .map(|raw| {
                let name = HeaderName::from_bytes(raw.as_bytes())
                    .map_err(|_| invalid(format!("`header_field` {raw:?} is not a header name")))?;
                if headers::FORBIDDEN.contains(&name.as_str())
                    || name.as_str().starts_with("proxy-")
                    || name == AUTHORIZATION
                {
                    return Err(invalid(format!(
                        "`header_field` {name} cannot carry the user name: it belongs to the connection or to authorization"
                    )));
                }
                Ok(name)
            })
            .transpose()?;
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|_| invalid("the system has no randomness"))?;
        Ok(Self(Box::new(Parts {
            realm: realm.into(),
            challenge,
            header_field,
            remove_header: config.remove_header,
            users,
            dummy,
            runtime: Arc::new(Runtime {
                key,
                cache: Mutex::new(Cache::default()),
                failures: Mutex::new(Failures::default()),
            }),
            fingerprint: state::fingerprint(declared),
        })))
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let who = Who {
            pool: cx.hashing,
            tenant: cx.app.tenant(),
            budget: cx.tenant,
            source: cx.forwarded.known_client(),
        };
        let verdict = {
            let mut values = cx
                .session
                .req_header()
                .headers
                .get_all(AUTHORIZATION)
                .iter();
            let header = values.next();
            let header = if values.next().is_some() {
                None
            } else {
                header
            };
            self.authenticate(&who, header.map(HeaderValue::as_bytes))
                .await
        };
        match verdict {
            Ok(Verdict::Allow(user)) => {
                let request = cx.session.req_header_mut();
                if let Some(field) = &self.header_field {
                    request.insert_header(field.clone(), user.as_bytes())?;
                }
                if self.remove_header {
                    request.remove_header(&AUTHORIZATION);
                }
                Ok(Flow::Continue)
            }
            Ok(Verdict::Deny) => {
                self.challenge(cx).await?;
                Ok(Flow::Respond)
            }
            Err(err) => {
                tracing::warn!(app = cx.app.id(), "basic_auth refused: {err}");
                *cx.capacity_refusal = err.is_capacity_refusal();
                crate::respond::write_error(cx.session, &err).await?;
                Ok(Flow::Respond)
            }
        }
    }

    /// Dropping the middleware lets everyone in; losing users locks some out, which a plan
    /// shows too.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        match new {
            None => vec!["basic_auth_removed"],
            Some(new) => {
                let kept: HashSet<&str> = new.users.keys().map(AsRef::as_ref).collect();
                if self.users.keys().any(|user| !kept.contains(&**user)) {
                    vec!["basic_auth_users_removed"]
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn describe(&self) -> Value {
        json!({
            "realm": &*self.realm,
            "users": self.users.len(),
            "header_field": self.header_field.as_ref().map(HeaderName::as_str),
            "remove_header": self.remove_header,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use argon2::PasswordHasher;
    use argon2::Version;

    fn bcrypt_hash(password: &str) -> String {
        bcrypt::hash(password, MIN_BCRYPT_COST).expect("bcrypt hash")
    }

    fn argon2_hash(password: &str, memory_kib: u32) -> String {
        let params = Params::new(memory_kib, 1, 1, None).expect("params");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_with_salt(password.as_bytes(), b"saltsaltsalt")
            .expect("argon2 hash")
            .to_string()
    }

    fn compile(config: &Value) -> Result<BasicAuth, Invalid> {
        let mut declared = json!({ "name": "a", "type": "basic_auth" });
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        BasicAuth::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    fn header(user: &str, password: &str) -> Vec<u8> {
        format!("Basic {}", STANDARD.encode(format!("{user}:{password}"))).into_bytes()
    }

    fn who(pool: &Pool) -> Who<'_> {
        Who {
            pool,
            tenant: "t",
            budget: None,
            source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        }
    }

    #[tokio::test]
    async fn basic_auth_accepts_bcrypt() {
        let auth = compile(&json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))] }))
            .expect("compile");
        let pool = Pool::default();
        let ok = auth
            .authenticate(&who(&pool), Some(&header("alice", "s3cret")))
            .await
            .expect("verdict");
        assert_eq!(ok, Verdict::Allow("alice".into()));
        let bad = auth
            .authenticate(&who(&pool), Some(&header("alice", "wrong")))
            .await
            .expect("verdict");
        assert_eq!(bad, Verdict::Deny);
    }

    #[tokio::test]
    async fn basic_auth_accepts_argon2() {
        let auth = compile(&json!({ "users": [format!("bob:{}", argon2_hash("hunter2", 64))] }))
            .expect("compile");
        let pool = Pool::default();
        let ok = auth
            .authenticate(&who(&pool), Some(&header("bob", "hunter2")))
            .await
            .expect("verdict");
        assert_eq!(ok, Verdict::Allow("bob".into()));
        let bad = auth
            .authenticate(&who(&pool), Some(&header("bob", "hunter3")))
            .await
            .expect("verdict");
        assert_eq!(bad, Verdict::Deny);
    }

    #[tokio::test]
    async fn basic_auth_unknown_user_runs_dummy_hash() {
        let auth = compile(&json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))] }))
            .expect("compile");
        let pool = Pool::default();
        let before = pool.runs();
        let verdict = auth
            .authenticate(&who(&pool), Some(&header("mallory", "anything")))
            .await
            .expect("verdict");
        assert_eq!(verdict, Verdict::Deny);
        assert_eq!(
            pool.runs(),
            before + 1,
            "an unknown user costs one verification"
        );
        // Even alice's own password does not let an unknown name in.
        let verdict = auth
            .authenticate(&who(&pool), Some(&header("mallory", "s3cret")))
            .await
            .expect("verdict");
        assert_eq!(verdict, Verdict::Deny);
        assert_eq!(pool.runs(), before + 2);
    }

    #[tokio::test]
    async fn basic_auth_no_hash_for_absent_or_malformed_header() {
        let auth = compile(&json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))] }))
            .expect("compile");
        let pool = Pool::default();
        for header in [
            None,
            Some(&b"Bearer abc"[..]),
            Some(b"Basic !!!not-base64"),
            Some(b"Basic bm9jb2xvbg=="),
        ] {
            let verdict = auth
                .authenticate(&who(&pool), header)
                .await
                .expect("verdict");
            assert_eq!(verdict, Verdict::Deny, "{header:?}");
        }
        assert_eq!(pool.runs(), 0);
    }

    #[tokio::test]
    async fn basic_auth_positive_result_is_cached() {
        let auth = compile(&json!({ "users": [format!("alice:{}", bcrypt_hash("s3cret"))] }))
            .expect("compile");
        let pool = Pool::default();
        for _ in 0..3 {
            let verdict = auth
                .authenticate(&who(&pool), Some(&header("alice", "s3cret")))
                .await
                .expect("verdict");
            assert_eq!(verdict, Verdict::Allow("alice".into()));
        }
        assert_eq!(pool.runs(), 1, "one verification, two cache hits");
    }

    #[tokio::test]
    async fn basic_auth_over_budget_argon2_is_refused() {
        let auth = compile(&json!({ "users": [format!("bob:{}", argon2_hash("hunter2", 64))] }))
            .expect("compile");
        let pool = Pool::default();
        let budgets = crate::budget::Budgets::new();
        let tenant = budgets.tenant(
            "t",
            podgate_model::Budget {
                max_inflight: 10,
                max_buffer_bytes: 32 * 1024,
            },
        );
        let who = Who {
            budget: Some(&tenant),
            ..who(&pool)
        };
        let refused = auth
            .authenticate(&who, Some(&header("bob", "hunter2")))
            .await;
        assert!(
            matches!(refused, Err(AppError::AuthOverBudget)),
            "{refused:?}"
        );
        assert_eq!(pool.runs(), 0);
        assert_eq!(tenant.buffered(), 0, "the failed charge is not kept");
    }

    #[tokio::test]
    async fn basic_auth_budget_full_but_hash_fits_is_busy() {
        let auth = compile(&json!({ "users": [format!("bob:{}", argon2_hash("hunter2", 64))] }))
            .expect("compile");
        let pool = Pool::default();
        let budgets = crate::budget::Budgets::new();
        let tenant = budgets.tenant(
            "t",
            podgate_model::Budget {
                max_inflight: 10,
                max_buffer_bytes: 128 * 1024,
            },
        );
        // The hash (64 KiB) fits the budget alone, but 100 KiB is held by something else.
        let _held = tenant.reserve(100 * 1024).expect("most of the budget");
        let who = Who {
            budget: Some(&tenant),
            ..who(&pool)
        };
        let refused = auth
            .authenticate(&who, Some(&header("bob", "hunter2")))
            .await
            .expect_err("budget is full now");
        assert!(matches!(refused, AppError::AuthBusy), "{refused:?}");
        assert!(
            refused.is_capacity_refusal(),
            "a busy tenant cannot revert a deploy"
        );
        assert_eq!(pool.runs(), 0);
    }

    #[test]
    fn basic_auth_weak_hash_rejected() {
        for entry in [
            "alice:$apr1$salt$hashhashhashhashhashhash",
            "alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=",
            "alice:$1$salt$hashhashhashhashhashhash",
            "alice:$6$salt$hashhashhashhashhashhash",
            "alice:rl3bvrRxVqPIA",
            "alice:plaintext",
            "alice:",
            "alice:$2b$10$tooshort",
        ] {
            let err = compile(&json!({ "users": [entry] })).expect_err(entry);
            assert_eq!(err.code, "invalid_middleware", "{entry}");
            assert!(!err.message.contains("hashhash"), "{}", err.message);
        }
        for config in [
            json!({ "users": [] }),
            json!({ "users": ["nocolon"] }),
            json!({ "users": [format!("a:{}", bcrypt_hash("x")), format!("a:{}", bcrypt_hash("y"))] }),
            json!({ "users": [format!(":{}", bcrypt_hash("x"))] }),
            json!({ "users": [format!("a:{}", bcrypt_hash("x"))], "extra": true }),
        ] {
            assert_eq!(
                compile(&config).expect_err("invalid").code,
                "invalid_middleware"
            );
        }
    }

    #[test]
    fn basic_auth_cost_cap_rejected() {
        let rest = "A".repeat(53);
        let cost15 = format!("alice:$2b$15${rest}");
        let cost14 = format!("alice:$2b$14${rest}");
        let cost3 = format!("alice:$2b$03${rest}");
        assert!(compile(&json!({ "users": [cost14] })).is_ok());
        assert!(
            compile(&json!({ "users": [cost15] }))
                .expect_err("cost 15")
                .message
                .contains("above the limit")
        );
        assert!(compile(&json!({ "users": [cost3] })).is_err());
        let digest = "A".repeat(43);
        let argon = |memory: u32, time: u32, lanes: u32| {
            format!("bob:$argon2id$v=19$m={memory},t={time},p={lanes}$c2FsdHNhbHRzYWx0${digest}")
        };
        assert!(compile(&json!({ "users": [argon(65536, 4, 4)] })).is_ok());
        for over in [argon(65537, 1, 1), argon(1024, 5, 1), argon(1024, 1, 5)] {
            let err = compile(&json!({ "users": [over] })).expect_err("over the cap");
            assert!(err.message.contains("above the limit"), "{}", err.message);
        }
    }

    #[test]
    fn basic_auth_secrets_redacted() {
        let hash = bcrypt_hash("s3cret");
        let config = json!({ "users": [format!("alice:{hash}")] });
        let parsed: Config = serde_json::from_value(config.clone()).expect("config");
        let auth = compile(&config).expect("compile");
        for shown in [
            format!("{parsed:?}"),
            format!("{auth:?}"),
            auth.describe().to_string(),
            format!("{:?}", auth.dummy),
        ] {
            assert!(
                !shown.contains(&hash) && !shown.contains(&hash[7..]),
                "{shown}"
            );
        }
    }

    #[test]
    fn credentials_parse() {
        assert_eq!(
            credentials(b"Basic YWxpY2U6czNjcmV0"),
            Some(("alice".into(), "s3cret".into()))
        );
        assert_eq!(
            credentials(b"bAsIc  YWxpY2U6czNjcmV0"),
            Some(("alice".into(), "s3cret".into()))
        );
        assert_eq!(credentials(b"Basic"), None);
        assert_eq!(credentials(b"Digest YWxpY2U6czNjcmV0"), None);
    }

    #[test]
    fn failure_table_is_bounded_and_windowed() {
        let mut failures = Failures::default();
        let start = Instant::now();
        let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..FAILURES_FREE {
            assert!(!failures.delayed(first, start));
            failures.record(first, start);
        }
        assert!(failures.delayed(first, start));
        assert!(!failures.delayed(first, start + FAILURE_WINDOW));
        for n in 0..(FAILURE_SOURCES as u32 + 10) {
            failures.record(IpAddr::V4(Ipv4Addr::from(n + 1000)), start);
        }
        assert!(failures.sources.len() <= FAILURE_SOURCES);
    }

    #[test]
    fn cache_is_bounded_and_expires() {
        let mut cache = Cache::default();
        let start = Instant::now();
        for n in 0..(CACHE_ENTRIES as u32 + 10) {
            let mut key = [0_u8; 32];
            key[..4].copy_from_slice(&n.to_be_bytes());
            cache.insert(key, start);
        }
        assert!(cache.verified.len() <= CACHE_ENTRIES);
        let newest = {
            let mut key = [0_u8; 32];
            key[..4].copy_from_slice(&(CACHE_ENTRIES as u32 + 9).to_be_bytes());
            key
        };
        assert!(cache.hit(&newest, start));
        assert!(!cache.hit(&newest, start + CACHE_TTL));
    }

    #[test]
    fn ipv6_sources_share_a_slash_64() {
        let a = source_key(Some("2001:db8::1:2:3:4".parse().expect("ip")));
        let b = source_key(Some("2001:db8::9:9:9:9".parse().expect("ip")));
        let c = source_key(Some("2001:db8:0:1::1".parse().expect("ip")));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
