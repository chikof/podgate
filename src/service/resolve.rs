//! DNS upstreams: servers named by host name, resolved on a TTL by a background service.
//!
//! A `loadbalancer` server `http://app.internal:8080` is a *name*. The balancer never dials the
//! name: [`Resolver`] turns it into IP addresses off the request path, and the balancer holds
//! those addresses as ordinary servers (see `loadbalancer.rs`). The connection dials the
//! address; the name is only the TLS SNI and the `Host` a health probe sends. Because no name is
//! ever resolved at connect time, a resolver cannot answer differently between the check and the
//! connection: that is the defence against DNS rebinding, and the policy check at connect time
//! is the second line behind it.
//!
//! # Pieces
//!
//! - [`Resolver`]: the node-wide cache of answers and the tasks that keep it fresh. One task per
//!   distinct (name, address family) across the node, whoever names it (single flight), re-run at
//!   the answer's TTL clamped to `DNS_MIN_TTL_SECS`..=`DNS_MAX_TTL_SECS`. A node-wide token
//!   bucket (`DNS_MAX_QUERIES_PER_SEC`) and a cap on lookups in flight bound what a snapshot
//!   with many names can make podgate send. The tasks run inside [`ResolveService`], which starts
//!   them from the live table and never from a request.
//! - [`ResolveService`]: the background service. After every swap and every change of an answer
//!   it reconciles the tasks with the names the live table uses, and tells each service to take
//!   the new addresses ([`super::Service::refresh`]).
//! - `NameBudget`: how many distinct names an app (64) and a tenant (256) may use, and how many
//!   distinct SRV names (32 and 128), checked by the compiler.
//! - [`srv`]: servers named by an SRV record (`"resolve": "srv"`), whose targets, ports,
//!   priorities and weights come from DNS; every target and port passes the same policy.
//!
//! # The upstream address policy
//!
//! Every answer is checked with [`UpstreamPolicy::check`] for each tenant that names the
//! host, on every resolution, and a refused address is dropped and never dialled: a name that
//! starts answering `127.0.0.1` or `169.254.169.254` after it answered something allowed loses
//! that address, counts in `podgate_upstream_refused_total{tenant}` and is logged with the
//! tenant and the name. [`Resolver::peek`], the view a balancer takes, applies the same verdict
//! ([`UpstreamPolicy::evaluate`]) to what the cache holds, so no refused address reaches a
//! server list even before the next resolution.
//!
//! # Failure
//!
//! A failed or empty resolution keeps the last good set while it is stale for less than
//! `DNS_MAX_STALE_SECS` (counted from when the answer's TTL ran out), then the name has no
//! addresses. Failures retry with a doubling delay from the minimum TTL up to the maximum. A
//! lookup never takes longer than `DNS_TIMEOUT_MS`. A name that has never resolved is a server
//! without addresses: requests to it get `503`, which does not wake a `scale_to_zero` app.

pub mod srv;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver as Client, TokioResolver};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::sync::{Semaphore, watch};
use tokio::task::AbortHandle;
use tokio::time::{sleep, timeout};

use super::upstream_policy::UpstreamPolicy;
use crate::compile::Invalid;
use crate::config::ConfigError;
use crate::table::{RoutingTable, TableHandle};

/// The most distinct host names one app's servers may use.
pub const MAX_NAMES_PER_APP: usize = 64;
/// The most distinct host names one tenant's servers may use, over every app.
pub const MAX_NAMES_PER_TENANT: usize = 256;
/// The most addresses one name contributes to a service; the lowest ones (IPv4 first) are kept.
pub const MAX_ADDRESSES_PER_NAME: usize = 32;
/// Lookups in flight at once, whatever the rate allows.
const MAX_IN_FLIGHT: usize = 32;
/// How long the service waits after a change before it walks the table, so a burst of answers
/// costs one walk.
const DEBOUNCE: Duration = Duration::from_millis(50);
/// The most a failure's retry delay doubles: `min_ttl` times 2^10 is far above any maximum.
const MAX_BACKOFF_DOUBLINGS: u32 = 10;

/// What the resolver is configured with; see `Config` (`DNS_*`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The name servers to ask, `DNS_SERVERS`. Empty: the system configuration.
    pub servers: Vec<SocketAddr>,
    /// The shortest time an answer is kept, whatever its TTL says.
    pub min_ttl: Duration,
    /// The longest time an answer is kept, whatever its TTL says.
    pub max_ttl: Duration,
    /// The longest one lookup takes.
    pub timeout: Duration,
    /// How long after its TTL ran out the last good answer is still used while resolution
    /// fails.
    pub max_stale: Duration,
    /// Lookups a second this node sends, in all.
    pub max_queries_per_sec: NonZeroU32,
}

impl Default for Settings {
    /// The defaults of the `DNS_*` variables.
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            min_ttl: Duration::from_secs(1),
            max_ttl: Duration::from_secs(60),
            timeout: Duration::from_millis(2000),
            max_stale: Duration::from_secs(300),
            max_queries_per_sec: NonZeroU32::MIN.saturating_add(199),
        }
    }
}

/// A whole number in `range` from the variable `var`, when it is set.
fn number(
    lookup: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    range: std::ops::RangeInclusive<u64>,
) -> Result<Option<u64>, ConfigError> {
    let Some(raw) = lookup(var) else {
        return Ok(None);
    };
    raw.trim()
        .parse::<u64>()
        .ok()
        .filter(|value| range.contains(value))
        .map(Some)
        .ok_or_else(|| ConfigError {
            var,
            reason: format!(
                "{raw:?} is not a whole number in {}..={}",
                range.start(),
                range.end()
            )
            .into(),
        })
}

impl Settings {
    /// Reads the `DNS_*` variables through `lookup`; unset ones keep their default.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first variable that is set but invalid: `DNS_SERVERS` that has
    /// no entry or an entry that is not `ip` or `ip:port`, a number out of range, or a
    /// `DNS_MIN_TTL_SECS` above `DNS_MAX_TTL_SECS`.
    pub fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut settings = Self::default();
        if let Some(raw) = lookup("DNS_SERVERS") {
            settings.servers = raw
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(|entry| {
                    entry
                        .parse::<SocketAddr>()
                        .or_else(|_| entry.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
                        .map_err(|_| ConfigError {
                            var: "DNS_SERVERS",
                            reason: format!(
                                "{entry:?} is not an address like 10.0.0.2, 10.0.0.2:5353 or [fd00::2]:53"
                            )
                            .into(),
                        })
                })
                .collect::<Result<_, _>>()?;
            if settings.servers.is_empty() {
                return Err(ConfigError {
                    var: "DNS_SERVERS",
                    reason: "is empty".into(),
                });
            }
        }
        if let Some(secs) = number(lookup, "DNS_MIN_TTL_SECS", 1..=86_400)? {
            settings.min_ttl = Duration::from_secs(secs);
        }
        if let Some(secs) = number(lookup, "DNS_MAX_TTL_SECS", 1..=86_400)? {
            settings.max_ttl = Duration::from_secs(secs);
        }
        if settings.min_ttl > settings.max_ttl {
            return Err(ConfigError {
                var: "DNS_MIN_TTL_SECS",
                reason: format!(
                    "{} is above DNS_MAX_TTL_SECS ({})",
                    settings.min_ttl.as_secs(),
                    settings.max_ttl.as_secs()
                )
                .into(),
            });
        }
        if let Some(millis) = number(lookup, "DNS_TIMEOUT_MS", 1..=60_000)? {
            settings.timeout = Duration::from_millis(millis);
        }
        if let Some(secs) = number(lookup, "DNS_MAX_STALE_SECS", 0..=86_400)? {
            settings.max_stale = Duration::from_secs(secs);
        }
        if let Some(rate) = number(lookup, "DNS_MAX_QUERIES_PER_SEC", 1..=100_000)? {
            settings.max_queries_per_sec = u32::try_from(rate)
                .ok()
                .and_then(NonZeroU32::new)
                .unwrap_or(settings.max_queries_per_sec);
        }
        Ok(settings)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Family {
    V4,
    V6,
}

impl Family {
    const BOTH: [Self; 2] = [Self::V4, Self::V6];

    fn label(self) -> &'static str {
        match self {
            Self::V4 => "A",
            Self::V6 => "AAAA",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    name: Box<str>,
    family: Family,
}

/// The last good answer of one family of one name.
#[derive(Debug, Default)]
struct Slot {
    addrs: Vec<IpAddr>,
    /// When the answer stops being used if nothing refreshes it: its TTL plus the stale grace.
    expires: Option<Instant>,
}

impl Slot {
    fn usable(&self, now: Instant) -> &[IpAddr] {
        match self.expires {
            Some(expires) if expires > now => &self.addrs,
            _ => &[],
        }
    }
}

#[derive(Debug, Default)]
struct NameEntry {
    v4: Slot,
    v6: Slot,
    /// The tenants whose services use the name, each with the addresses the policy refused at
    /// the last resolution (to log a change once).
    tenants: HashMap<Box<str>, Vec<IpAddr>>,
}

impl NameEntry {
    fn slot(&mut self, family: Family) -> &mut Slot {
        match family {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        }
    }

    /// The addresses to use now: IPv4 then IPv6, each sorted, at most [`MAX_ADDRESSES_PER_NAME`].
    fn current(&self, now: Instant) -> Vec<IpAddr> {
        let mut all: Vec<IpAddr> = self
            .v4
            .usable(now)
            .iter()
            .chain(self.v6.usable(now))
            .copied()
            .collect();
        all.sort_unstable();
        all.dedup();
        all.truncate(MAX_ADDRESSES_PER_NAME);
        all
    }
}

#[derive(Debug, Default)]
struct State {
    names: HashMap<Box<str>, NameEntry>,
    tasks: HashMap<Key, AbortHandle>,
    srv: srv::Srv,
}

/// A token bucket: `rate` tokens a second, holding at most a tenth of a second's worth (at
/// least one), so no one-second window sees much more than `rate` lookups.
#[derive(Debug)]
struct Limiter {
    rate: f64,
    burst: f64,
    bucket: Mutex<(f64, Instant)>,
}

impl Limiter {
    fn new(rate: NonZeroU32) -> Self {
        let rate = f64::from(rate.get());
        let burst = (rate / 10.0).max(1.0);
        Self {
            rate,
            burst,
            bucket: Mutex::new((burst, Instant::now())),
        }
    }

    /// Takes one token, or says how long until there is one.
    fn take(&self, now: Instant) -> Result<(), Duration> {
        let mut bucket = self.bucket.lock().unwrap_or_else(PoisonError::into_inner);
        let (tokens, last) = *bucket;
        let tokens = (tokens + now.saturating_duration_since(last).as_secs_f64() * self.rate)
            .min(self.burst);
        if tokens >= 1.0 {
            *bucket = (tokens - 1.0, now);
            Ok(())
        } else {
            *bucket = (tokens, now);
            Err(Duration::from_secs_f64((1.0 - tokens) / self.rate))
        }
    }

    async fn acquire(&self) {
        while let Err(wait) = self.take(Instant::now()) {
            sleep(wait).await;
        }
    }
}

/// Why a resolution gave nothing.
#[derive(Debug)]
enum Failure {
    /// The name does not exist (`NXDOMAIN`), or the answer holds no address of the family and
    /// is not a clean "none".
    Empty,
    /// A successful answer with no record of the family (`NODATA`, such as `AAAA` for a name with
    /// only an `A` record). A valid result, with the negative TTL of the SOA when it came with one.
    NoData(Option<u32>),
    /// The lookup failed or timed out.
    Error(String),
}

struct Inner {
    settings: Settings,
    policy: UpstreamPolicy,
    client: Mutex<Option<TokioResolver>>,
    state: Mutex<State>,
    limiter: Limiter,
    permits: Semaphore,
    changes: watch::Sender<u64>,
}

impl fmt::Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// The node-wide DNS cache and the tasks that fill it. Cheap to clone: clones share it.
#[derive(Clone, Debug)]
pub struct Resolver {
    inner: Arc<Inner>,
}

impl Default for Resolver {
    /// A resolver nothing drives: names never resolve. What a compile outside a running process
    /// (tests, tools) uses.
    fn default() -> Self {
        Self::new(Settings::default(), UpstreamPolicy::allow_all())
    }
}

impl Resolver {
    /// A resolver with `settings` that checks every answer against `policy`. Nothing is resolved
    /// until a [`ResolveService`] (or [`Self::reconcile`]) starts the tasks.
    #[must_use]
    pub fn new(settings: Settings, policy: UpstreamPolicy) -> Self {
        Self {
            inner: Arc::new(Inner {
                limiter: Limiter::new(settings.max_queries_per_sec),
                settings,
                policy,
                client: Mutex::new(None),
                state: Mutex::new(State::default()),
                permits: Semaphore::new(MAX_IN_FLIGHT),
                changes: watch::channel(0).0,
            }),
        }
    }

    /// The addresses `tenant` may use for `name` now: the cached answers (IPv4 then IPv6, sorted,
    /// at most [`MAX_ADDRESSES_PER_NAME`]) the upstream policy lets the tenant dial. Empty for a
    /// name that has not resolved, or whose answer went stale for good. Takes a lock, resolves
    /// nothing and has no side effect.
    #[must_use]
    pub fn peek(&self, tenant: &str, name: &str) -> Vec<IpAddr> {
        let mut found = self
            .inner
            .lock()
            .names
            .get(name)
            .map(|entry| entry.current(Instant::now()))
            .unwrap_or_default();
        found.retain(|ip| self.inner.policy.evaluate(tenant, *ip).is_ok());
        found
    }

    /// Resolves `name` once, now, for a caller that dials the answer immediately and checks every
    /// address with the upstream policy itself (OCSP responders). Nothing is cached
    /// and no task is started, so a name that no service uses costs one lookup per call; it
    /// shares the node-wide query rate and the lookups-in-flight cap with the tasks. The
    /// addresses are IPv4 then IPv6, sorted, at most [`MAX_ADDRESSES_PER_NAME`]; a failed lookup
    /// contributes none, so an empty answer means the name did not resolve. Policy-refused
    /// addresses are not removed here: the caller's `check` counts and logs them.
    pub async fn resolve_once(&self, name: &str) -> Vec<IpAddr> {
        let mut found = Vec::new();
        for family in Family::BOTH {
            self.inner.limiter.acquire().await;
            let Ok(_permit) = self.inner.permits.acquire().await else {
                break;
            };
            let key = Key {
                name: name.into(),
                family,
            };
            if let Ok((addrs, _ttl)) = self.inner.lookup(&key).await {
                found.extend(addrs);
            }
        }
        found.sort_unstable();
        found.dedup();
        found.truncate(MAX_ADDRESSES_PER_NAME);
        found
    }

    /// A signal that fires whenever an answer changes: gained or lost an address, or went
    /// stale. The value counts changes; read the addresses with [`Self::peek`].
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.changes.subscribe()
    }

    /// Makes the running tasks and the tenants checked at each resolution those the names of
    /// `table` call for: a task per (name, family) of every name any service uses, none for a
    /// name nothing uses. Must run inside the tokio runtime.
    pub fn reconcile(&self, table: &RoutingTable) {
        let wanted = names_of(table);
        let now = Instant::now();
        let mut guard = self.inner.lock();
        let State { names, tasks, srv } = &mut *guard;
        srv.reconcile(&self.inner, &wanted.srv);
        let wanted = wanted.names;
        names.retain(|name, _| wanted.contains_key(name));
        tasks.retain(|key, task| {
            let keep = wanted.contains_key(&key.name);
            if !keep {
                task.abort();
            }
            keep
        });
        for (name, tenants) in &wanted {
            let entry = names.entry(name.clone()).or_default();
            entry.tenants.retain(|tenant, _| tenants.contains(tenant));
            let current = entry.current(now);
            for tenant in tenants {
                if !entry.tenants.contains_key(tenant) {
                    let refused = self.inner.refused_by(tenant, name, &current);
                    entry.tenants.insert(tenant.clone(), refused);
                }
            }
            for family in Family::BOTH {
                let key = Key {
                    name: name.clone(),
                    family,
                };
                tasks.entry(key.clone()).or_insert_with(|| {
                    tokio::spawn(run(Arc::clone(&self.inner), key)).abort_handle()
                });
            }
        }
    }

    /// Stops every task and forgets every answer.
    pub fn stop(&self) {
        let mut state = self.inner.lock();
        for task in state.tasks.values() {
            task.abort();
        }
        state.srv.abort_all();
        *state = State::default();
    }
}

#[cfg(test)]
impl Resolver {
    /// Puts `addrs` in the cache as a fresh answer for `name`, as a resolution would.
    pub(crate) fn seed(&self, name: &str, addrs: &[IpAddr]) {
        self.inner.lock().names.entry(name.into()).or_default();
        let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = addrs.iter().copied().partition(IpAddr::is_ipv4);
        for (family, found) in [(Family::V4, v4), (Family::V6, v6)] {
            let key = Key {
                name: name.into(),
                family,
            };
            self.inner.record_good(&key, found, 3600, Instant::now());
        }
    }
}

/// The tenants that use each name of `table`'s services (the HTTP ones and the TCP ones), by
/// kind of name.
struct Wanted {
    /// Names resolved to `A` and `AAAA` addresses.
    names: HashMap<Box<str>, HashSet<Box<str>>>,
    /// Owner names resolved as `SRV` records.
    srv: HashMap<Box<str>, HashSet<Box<str>>>,
}

fn names_of(table: &RoutingTable) -> Wanted {
    let mut wanted = Wanted {
        names: HashMap::new(),
        srv: HashMap::new(),
    };
    for app in table.apps() {
        let own = app
            .revisions()
            .iter()
            .flat_map(|revision| revision.services());
        let http = app.services().iter().chain(own).map(|named| &named.service);
        let tcp = app
            .l4()
            .tcp()
            .services()
            .iter()
            .map(|service| service.balancer());
        for service in http.chain(tcp) {
            for name in service.dns_names() {
                wanted
                    .names
                    .entry(name.into())
                    .or_default()
                    .insert(app.tenant().into());
            }
            for name in service.srv_names() {
                wanted
                    .srv
                    .entry(name.into())
                    .or_default()
                    .insert(app.tenant().into());
            }
        }
    }
    wanted
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn bump(&self) {
        self.changes.send_modify(|count| *count += 1);
    }

    /// Runs `check` for `tenant` on every address of `found`, which counts and logs each refusal,
    /// and returns the refused ones.
    fn refused_by(&self, tenant: &str, name: &str, found: &[IpAddr]) -> Vec<IpAddr> {
        let refused: Vec<IpAddr> = found
            .iter()
            .filter(|ip| self.policy.check(tenant, **ip).is_err())
            .copied()
            .collect();
        if !refused.is_empty() {
            tracing::warn!(
                tenant,
                name,
                ?refused,
                "DNS answer dropped by the upstream address policy"
            );
        }
        refused
    }

    fn client(&self) -> Result<TokioResolver, String> {
        let mut cached = self.client.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(client) = &*cached {
            return Ok(client.clone());
        }
        let mut builder = if self.settings.servers.is_empty() {
            TokioResolver::builder_tokio()
                .map_err(|err| format!("cannot read the system DNS configuration: {err}"))?
        } else {
            let servers = self
                .settings
                .servers
                .iter()
                .map(|addr| {
                    let mut server = NameServerConfig::udp_and_tcp(addr.ip());
                    for connection in &mut server.connections {
                        connection.port = addr.port();
                    }
                    server
                })
                .collect();
            let mut builder = Client::builder_with_config(
                ResolverConfig::from_parts(None, Vec::new(), servers),
                TokioRuntimeProvider::default(),
            );
            builder.options_mut().use_hosts_file = ResolveHosts::Never;
            builder
        };
        let options = builder.options_mut();
        options.timeout = self.settings.timeout;
        options.attempts = 1;
        // The cache here is ours: it needs the TTL and the failure rules of this module.
        options.cache_size = 0;
        let client = builder.build().map_err(|err| err.to_string())?;
        *cached = Some(client.clone());
        Ok(client)
    }

    /// One lookup of `name` for `record_type`, with the module's timeout. A clean "no such
    /// record" is [`Failure::NoData`] (the name exists) or [`Failure::Empty`] (`NXDOMAIN`).
    async fn query(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<hickory_resolver::lookup::Lookup, Failure> {
        let client = self.client().map_err(Failure::Error)?;
        let asked = timeout(self.settings.timeout, client.lookup(name, record_type)).await;
        match asked {
            Err(_) => Err(Failure::Error("timed out".to_owned())),
            Ok(Err(NetError::Dns(DnsError::NoRecordsFound(none)))) => {
                Err(if none.response_code == ResponseCode::NoError {
                    Failure::NoData(none.negative_ttl)
                } else {
                    Failure::Empty
                })
            }
            Ok(Err(err)) => Err(Failure::Error(err.to_string())),
            Ok(Ok(lookup)) => Ok(lookup),
        }
    }

    /// One lookup of `key`: the addresses and the smallest TTL of the answer.
    async fn lookup(&self, key: &Key) -> Result<(Vec<IpAddr>, u32), Failure> {
        let record_type = match key.family {
            Family::V4 => RecordType::A,
            Family::V6 => RecordType::AAAA,
        };
        let lookup = self.query(&key.name, record_type).await?;
        let mut addrs = Vec::new();
        let mut ttl = u32::MAX;
        for record in lookup.answers() {
            let ip = match (&record.data, key.family) {
                (RData::A(a), Family::V4) => IpAddr::V4(a.0),
                (RData::AAAA(a), Family::V6) => IpAddr::V6(a.0),
                _ => continue,
            };
            addrs.push(ip);
            ttl = ttl.min(record.ttl);
        }
        if addrs.is_empty() {
            return Err(Failure::NoData(None));
        }
        Ok((addrs, ttl))
    }

    /// The delay before the next attempt after `failures` failures in a row.
    fn backoff(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(MAX_BACKOFF_DOUBLINGS);
        self.settings
            .min_ttl
            .saturating_mul(1 << doublings)
            .min(self.settings.max_ttl)
            .max(self.settings.min_ttl)
    }

    /// How long to keep an answer whose records say `ttl` seconds.
    fn keep_for(&self, ttl: u32) -> Duration {
        Duration::from_secs(u64::from(ttl))
            .max(self.settings.min_ttl)
            .min(self.settings.max_ttl)
    }

    /// Stores a good answer for `key`, checks it for every tenant that uses the name and
    /// signals when the usable addresses changed. Returns when the answer is to be refreshed.
    fn record_good(&self, key: &Key, mut addrs: Vec<IpAddr>, ttl: u32, now: Instant) -> Duration {
        addrs.sort_unstable();
        addrs.dedup();
        addrs.truncate(MAX_ADDRESSES_PER_NAME);
        let keep = self.keep_for(ttl);
        let mut state = self.lock();
        let Some(entry) = state.names.get_mut(&*key.name) else {
            return keep;
        };
        let before = entry.current(now);
        let slot = entry.slot(key.family);
        slot.addrs = addrs;
        slot.expires = Some(now + keep + self.settings.max_stale);
        let after = entry.current(now);
        let tenants: Vec<Box<str>> = entry.tenants.keys().cloned().collect();
        for tenant in tenants {
            let refused = self.refused_by(&tenant, &key.name, &after);
            if let Some(logged) = entry.tenants.get_mut(&tenant) {
                *logged = refused;
            }
        }
        drop(state);
        if before != after {
            self.bump();
        }
        keep
    }

    /// Notes that a resolution of `key` gave nothing: the last good answer stays until it is
    /// stale for too long. Returns how long until something changes: the retry, or the moment
    /// the answer is dropped when that is sooner.
    fn record_failure(
        &self,
        key: &Key,
        failure: &Failure,
        failures: u32,
        now: Instant,
    ) -> Duration {
        match failure {
            Failure::Empty | Failure::NoData(_) => {
                tracing::debug!(
                    name = &*key.name,
                    family = key.family.label(),
                    "DNS answer has no addresses"
                );
            }
            Failure::Error(why) => {
                tracing::warn!(name = &*key.name, family = key.family.label(), %why, "DNS resolution failed");
            }
        }
        let retry = self.backoff(failures);
        self.expire(key, now);
        let state = self.lock();
        let left = state
            .names
            .get(&*key.name)
            .and_then(|entry| match key.family {
                Family::V4 => entry.v4.expires,
                Family::V6 => entry.v6.expires,
            })
            .map(|expires| expires.saturating_duration_since(now));
        match left {
            Some(left) if !left.is_zero() => retry.min(left),
            _ => retry,
        }
    }

    /// Whether the last good answer of `key` holds an address.
    fn has_addresses(&self, key: &Key) -> bool {
        self.lock()
            .names
            .get(&*key.name)
            .is_some_and(|entry| match key.family {
                Family::V4 => !entry.v4.addrs.is_empty(),
                Family::V6 => !entry.v6.addrs.is_empty(),
            })
    }

    /// Drops the answer of `key` when it has been stale for too long, and signals it.
    fn expire(&self, key: &Key, now: Instant) {
        let mut state = self.lock();
        let Some(entry) = state.names.get_mut(&*key.name) else {
            return;
        };
        let slot = entry.slot(key.family);
        if !slot.addrs.is_empty() && slot.expires.is_none_or(|expires| expires <= now) {
            slot.addrs.clear();
            slot.expires = None;
            drop(state);
            self.bump();
        }
    }
}

/// Keeps the answer of one (name, family) fresh until the task is aborted.
async fn run(inner: Arc<Inner>, key: Key) {
    let mut failures = 0_u32;
    loop {
        inner.expire(&key, Instant::now());
        inner.limiter.acquire().await;
        let outcome = {
            let Ok(_permit) = inner.permits.acquire().await else {
                return;
            };
            inner.lookup(&key).await
        };
        let now = Instant::now();
        let wait = match outcome {
            Ok((addrs, ttl)) => {
                failures = 0;
                inner.record_good(&key, addrs, ttl, now)
            }
            // A clean "no such record" for a family that has no address is an answer: cached
            // empty for its negative TTL (the SOA's; `DNS_MAX_TTL_SECS` when the answer has none,
            // since the minimum would ask again every second), clamped to min..max, and not
            // retried as a failure.
            // A family that had addresses keeps them like it does for any failure.
            Err(Failure::NoData(negative)) if !inner.has_addresses(&key) => {
                failures = 0;
                inner.record_good(&key, Vec::new(), negative.unwrap_or(u32::MAX), now)
            }
            Err(failure) => {
                failures = failures.saturating_add(1);
                inner.record_failure(&key, &failure, failures, now)
            }
        };
        sleep(wait.max(Duration::from_millis(10))).await;
    }
}

/// Runs the [`Resolver`]'s tasks for the names of the live table and hands every change of an
/// answer to the services that use it. Run it as a Pingora background service.
#[derive(Debug)]
pub struct ResolveService {
    resolver: Resolver,
    table: TableHandle,
}

impl ResolveService {
    /// A service that resolves the names of the table behind `table` through `resolver`.
    #[must_use]
    pub fn new(resolver: Resolver, table: TableHandle) -> Self {
        Self { resolver, table }
    }

    /// Reconciles the resolver with `table` and gives every service its current addresses.
    /// Tells the table's watchers when a server list changed.
    fn sync(&self, table: &RoutingTable) {
        self.resolver.reconcile(table);
        let mut changed = false;
        for app in table.apps() {
            let own = app
                .revisions()
                .iter()
                .flat_map(|revision| revision.services());
            let http = app.services().iter().chain(own).map(|named| &named.service);
            let tcp = app
                .l4()
                .tcp()
                .services()
                .iter()
                .map(|service| service.balancer());
            for service in http.chain(tcp) {
                changed |= service.refresh();
            }
        }
        if changed {
            self.table.servers_changed();
        }
    }
}

#[async_trait]
impl BackgroundService for ResolveService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // Subscribed before the first load: a swap or an answer in between is seen by `changed`.
        let mut swaps = self.table.subscribe();
        let mut answers = self.resolver.subscribe();
        loop {
            self.sync(&self.table.load());
            tokio::select! {
                changed = swaps.changed() => if changed.is_err() { break },
                changed = answers.changed() => if changed.is_err() { break },
                _ = shutdown.changed() => break,
            }
            sleep(DEBOUNCE).await;
        }
        self.resolver.stop();
    }
}

/// Whether `host` is a syntactically valid DNS host name: dot-separated labels of at most 63
/// letters, digits, `-` and `_`, none empty and none starting or ending with `-`, at most 253
/// bytes, one trailing dot allowed, and a last label that is not all digits (that would be a
/// malformed IPv4 address, not a name).
#[must_use]
pub fn is_host_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let mut last = "";
    for label in host.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
        if !valid {
            return false;
        }
        last = label;
    }
    !last.bytes().all(|b| b.is_ascii_digit())
}

/// The distinct names of one kind the services of one snapshot use, per app and per tenant.
#[derive(Debug, Default)]
struct Names {
    apps: HashMap<Box<str>, HashSet<Box<str>>>,
    tenants: HashMap<Box<str>, HashSet<Box<str>>>,
}

impl Names {
    fn charge<'a>(
        &mut self,
        tenant: &str,
        app: &str,
        names: impl IntoIterator<Item = &'a str>,
        kind: &str,
        (max_app, max_tenant): (usize, usize),
    ) -> Result<(), Invalid> {
        for name in names {
            let of_app = self.apps.entry(app.into()).or_default();
            of_app.insert(name.into());
            if of_app.len() > max_app {
                return Err(Invalid::new(
                    "invalid_service",
                    format!(
                        "app {app} uses {} distinct {kind} names in its servers, at most \
                         {max_app} are allowed",
                        of_app.len()
                    ),
                ));
            }
            let of_tenant = self.tenants.entry(tenant.into()).or_default();
            of_tenant.insert(name.into());
            if of_tenant.len() > max_tenant {
                return Err(Invalid::new(
                    "invalid_service",
                    format!(
                        "tenant {tenant} uses {} distinct {kind} names in its servers, at most \
                         {max_tenant} are allowed",
                        of_tenant.len()
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// The distinct host names and SRV owner names the services of one snapshot use, per app and per
/// tenant, so the compiler can refuse a snapshot that asks for too many.
#[derive(Debug, Default)]
pub(crate) struct NameBudget {
    hosts: Names,
    srv: Names,
}

impl NameBudget {
    /// Counts `names`, used by a service of `app` of `tenant`.
    ///
    /// # Errors
    ///
    /// `invalid_service` when the app would use more than [`MAX_NAMES_PER_APP`] distinct names
    /// or the tenant more than [`MAX_NAMES_PER_TENANT`].
    pub(crate) fn charge<'a>(
        &mut self,
        tenant: &str,
        app: &str,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), Invalid> {
        self.hosts.charge(
            tenant,
            app,
            names,
            "DNS",
            (MAX_NAMES_PER_APP, MAX_NAMES_PER_TENANT),
        )
    }

    /// Counts the SRV owner `names` of a service of `app` of `tenant`.
    ///
    /// # Errors
    ///
    /// `invalid_service` when the app would use more than [`srv::MAX_NAMES_PER_APP`] distinct
    /// SRV names or the tenant more than [`srv::MAX_NAMES_PER_TENANT`].
    pub(crate) fn charge_srv<'a>(
        &mut self,
        tenant: &str,
        app: &str,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), Invalid> {
        self.srv.charge(
            tenant,
            app,
            names,
            "SRV",
            (srv::MAX_NAMES_PER_APP, srv::MAX_NAMES_PER_TENANT),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn resolver(min: u64, max: u64, stale: u64) -> Resolver {
        Resolver::new(
            Settings {
                min_ttl: Duration::from_secs(min),
                max_ttl: Duration::from_secs(max),
                max_stale: Duration::from_secs(stale),
                ..Settings::default()
            },
            UpstreamPolicy::builtin(),
        )
    }

    fn key(name: &str, family: Family) -> Key {
        Key {
            name: name.into(),
            family,
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    fn with_entry(resolver: &Resolver, name: &str, tenants: &[&str]) {
        let mut state = resolver.inner.lock();
        let entry = state.names.entry(name.into()).or_default();
        for tenant in tenants {
            entry.tenants.insert((*tenant).into(), Vec::new());
        }
    }

    #[test]
    fn host_names_are_checked_label_by_label() {
        for good in [
            "app",
            "app.internal",
            "a-b.c_d.example.com",
            "app.internal.",
            "x1.y2",
            "1app.com",
        ] {
            assert!(is_host_name(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "a..b",
            ".a",
            "-a.com",
            "a-.com",
            "a b.com",
            "a/b.com",
            "300.1.1.1",
            "1.2.3",
            "a.1",
            "ünï.com",
            &"a".repeat(64),
            &format!("{}.com", "a".repeat(250)),
        ] {
            assert!(!is_host_name(bad), "{bad}");
        }
        assert!(is_host_name(&"a".repeat(63)));
    }

    #[test]
    fn ttl_is_clamped_and_failures_back_off_to_the_maximum() {
        let resolver = resolver(2, 30, 300);
        let inner = &resolver.inner;
        assert_eq!(inner.keep_for(0), Duration::from_secs(2));
        assert_eq!(inner.keep_for(10), Duration::from_secs(10));
        assert_eq!(inner.keep_for(86_400), Duration::from_secs(30));
        let delays: Vec<u64> = [1, 2, 3, 4, 5, 6, 50]
            .into_iter()
            .map(|failures| inner.backoff(failures).as_secs())
            .collect();
        assert_eq!(delays, [2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn a_good_answer_is_used_until_its_ttl_and_the_stale_grace_pass() {
        let resolver = resolver(1, 60, 10);
        with_entry(&resolver, "a.test", &[]);
        let start = Instant::now();
        let wait = resolver.inner.record_good(
            &key("a.test", Family::V4),
            vec![ip("10.0.0.2"), ip("10.0.0.1"), ip("10.0.0.2")],
            5,
            start,
        );
        assert_eq!(wait, Duration::from_secs(5));
        let state = resolver.inner.lock();
        let entry = state.names.get("a.test").expect("entry");
        assert_eq!(
            entry.current(start + Duration::from_secs(14)),
            [ip("10.0.0.1"), ip("10.0.0.2")]
        );
        assert!(entry.current(start + Duration::from_secs(15)).is_empty());
    }

    #[test]
    fn a_failure_keeps_the_answer_then_drops_it_and_signals_both_changes() {
        let resolver = resolver(1, 60, 10);
        with_entry(&resolver, "a.test", &[]);
        let mut seen = resolver.subscribe();
        let a = key("a.test", Family::V4);
        let start = Instant::now();
        resolver
            .inner
            .record_good(&a, vec![ip("10.0.0.1")], 2, start);
        assert!(seen.has_changed().expect("open"));
        seen.mark_unchanged();
        let wait =
            resolver
                .inner
                .record_failure(&a, &Failure::Empty, 1, start + Duration::from_secs(2));
        assert_eq!(wait, Duration::from_secs(1), "the retry delay");
        assert!(!seen.has_changed().expect("open"), "kept, nothing changed");
        let wait = resolver.inner.record_failure(
            &a,
            &Failure::Error("down".into()),
            9,
            start + Duration::from_secs(11),
        );
        assert_eq!(wait, Duration::from_secs(1), "the answer goes in a second");
        resolver
            .inner
            .record_failure(&a, &Failure::Empty, 10, start + Duration::from_secs(12));
        assert!(seen.has_changed().expect("open"), "dropped when stale");
        assert!(
            resolver
                .inner
                .lock()
                .names
                .get("a.test")
                .expect("entry")
                .current(start + Duration::from_secs(12))
                .is_empty()
        );
    }

    #[test]
    fn addresses_of_both_families_merge_and_are_capped() {
        let resolver = resolver(1, 60, 10);
        with_entry(&resolver, "a.test", &[]);
        let now = Instant::now();
        let many: Vec<IpAddr> = (1..=40_u8).map(|n| ip(&format!("10.0.0.{n}"))).collect();
        resolver
            .inner
            .record_good(&key("a.test", Family::V4), many, 5, now);
        resolver
            .inner
            .record_good(&key("a.test", Family::V6), vec![ip("fd00::1")], 5, now);
        let state = resolver.inner.lock();
        let current = state.names.get("a.test").expect("entry").current(now);
        assert_eq!(current.len(), MAX_ADDRESSES_PER_NAME);
        assert_eq!(current[0], ip("10.0.0.1"));
        assert!(current.iter().all(IpAddr::is_ipv4), "IPv4 sorts first");
    }

    #[test]
    fn peek_drops_what_the_tenants_policy_refuses_without_counting_it() {
        let policy = UpstreamPolicy::parse(r#"{"tenants": {"t1": {"allow": ["10.0.0.0/8"]}}}"#)
            .expect("policy");
        let resolver = Resolver::new(Settings::default(), policy.clone());
        with_entry(&resolver, "a.test", &[]);
        resolver.inner.record_good(
            &key("a.test", Family::V4),
            vec![ip("10.0.0.1"), ip("127.0.0.1"), ip("192.168.0.1")],
            5,
            Instant::now(),
        );
        assert_eq!(resolver.peek("t1", "a.test"), [ip("10.0.0.1")]);
        assert_eq!(
            resolver.peek("t2", "a.test"),
            [ip("10.0.0.1"), ip("192.168.0.1")],
            "t2 has no allow list but loopback is denied for everyone"
        );
        assert!(resolver.peek("t1", "other.test").is_empty());
        assert!(
            !policy.render().contains("tenant=\"t1\""),
            "peek counts nothing"
        );
    }

    #[test]
    fn every_resolution_checks_the_answer_for_each_tenant_and_counts_refusals() {
        let policy = UpstreamPolicy::builtin();
        let resolver = Resolver::new(Settings::default(), policy.clone());
        with_entry(&resolver, "a.test", &["t1", "t2"]);
        let a = key("a.test", Family::V4);
        for _ in 0..2 {
            resolver.inner.record_good(
                &a,
                vec![ip("10.0.0.1"), ip("127.0.0.1")],
                5,
                Instant::now(),
            );
        }
        let metrics = policy.render();
        assert!(
            metrics.contains("podgate_upstream_refused_total{tenant=\"t1\"} 2"),
            "{metrics}"
        );
        assert!(
            metrics.contains("podgate_upstream_refused_total{tenant=\"t2\"} 2"),
            "{metrics}"
        );
    }

    #[tokio::test]
    async fn the_limiter_spaces_lookups_at_the_rate() {
        let limiter = Limiter::new(NonZeroU32::new(10).expect("non-zero"));
        let start = Instant::now();
        // The bucket starts with its burst (one token at 10 a second), then one per 100 ms.
        for _ in 0..4 {
            limiter.acquire().await;
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(295) && elapsed < Duration::from_millis(400),
            "{elapsed:?}"
        );
    }

    #[test]
    fn name_budget_caps_names_per_app_and_per_tenant() {
        let mut budget = NameBudget::default();
        let names: Vec<String> = (0..=MAX_NAMES_PER_APP)
            .map(|n| format!("n{n}.test"))
            .collect();
        let refs = || names.iter().map(String::as_str);
        assert!(
            budget
                .charge("t", "a", refs().take(MAX_NAMES_PER_APP))
                .is_ok()
        );
        assert!(
            budget
                .charge("t", "a", refs().take(MAX_NAMES_PER_APP))
                .is_ok(),
            "the same names again are not new"
        );
        let err = budget.charge("t", "a", refs()).expect_err("65th name");
        assert_eq!(err.code, "invalid_service");

        let mut budget = NameBudget::default();
        for app in 0..5 {
            let own: Vec<String> = (0..60).map(|n| format!("app{app}-{n}.test")).collect();
            let result = budget.charge("t", &format!("a{app}"), own.iter().map(String::as_str));
            assert_eq!(
                result.is_ok(),
                app < 4,
                "app {app}: 60 names each, 256 for the tenant"
            );
        }
        assert!(
            budget.charge("other", "b", ["x.test"].into_iter()).is_ok(),
            "another tenant has its own count"
        );
    }
}
