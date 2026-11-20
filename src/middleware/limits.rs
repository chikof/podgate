//! What `rate_limit` and `in_flight_req` share: choosing the source of a request, the bounded
//! table of per-source state, its memory charge, and the series both report.
//! Reference: `docs/ref/mw-limits.md`.
//!
//! # The source
//!
//! A limiter counts per source. [`Source`] turns a request into a 64-bit key:
//!
//! - `{"ip": {depth?, excluded?, ipv6_subnet_bits?}}`: [`ClientIp::resolve`] over the request's
//!   [`ForwardedView`], the address the entry point's trust policy allows the request to name,
//!   with an IPv6 client counted by its first `ipv6_subnet_bits` bits (default 64). The
//!   middleware never reads `X-Forwarded-For` itself.
//! - `{"header": "<name>"}`: the first value of that request header.
//! - `{"host": true}`: the host a trusted proxy reported, else the request's own host.
//!
//! A header or host that is absent is the source `"-"`, so a client cannot leave a limit by
//! omitting the value. The key is a hash under keys chosen at random when the middleware is
//! compiled, so a client cannot aim two sources at one entry. A collision merges two sources,
//! which limits more, never less.
//!
//! # The table
//!
//! [`SourceTable`] is a fixed-size, set-associative table: `max_sources` entries in sets of
//! eight, each set behind its own mutex, each entry a 16-byte `(key, value)` record. A request
//! locks one set for a few instructions and never waits on a request of another set, never
//! allocates, and never takes a lock shared by the whole table. The table never grows and never
//! evicts a live entry: when the eight ways of a source's set all hold live sources, the
//! source uses the table's one shared overflow value instead. An attacker who invents sources
//! fills sets and is then limited together, as one source; honest sources that already have an
//! entry are untouched. The number of requests that took the overflow is a metric.
//!
//! The overflow trade-off: a source that finds its set full is limited together with every
//! other such source, so it can be throttled by sources that are not its own. That limits more,
//! never less. A flood of distinct sources can therefore throttle innocent clients whose set
//! it filled; counting IPv6 clients by prefix keeps one network from doing that with its
//! addresses.
//!
//! An entry is reclaimable when it holds nothing a limit still needs (`rate_limit`: the bucket
//! would be full again; `in_flight_req`: no request is in flight), which the caller states per
//! call, so idle sources expire without a sweep.
//!
//! # Memory
//!
//! The table is allocated on the first request that reaches the middleware, after its whole
//! size ([`SourceTable::bytes`]) was charged to the tenant's `max_buffer_bytes`, and lives as
//! long as the middleware's runtime state does. A snapshot whose limiter tables do not fit the
//! tenant's declared `max_buffer_bytes` together is refused at apply time with
//! `invalid_middleware` ([`over_budget`]); a first request that finds the tenant's budget full
//! right now is answered `503` with `retry-after`, a capacity refusal, and tries to charge
//! again on the next one.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::fmt::Write as _;
use std::hash::BuildHasher;
use std::mem::size_of;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Instant;

use http::header::{HeaderName, HeaderValue};
use pingora::http::RequestHeader;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Named, Stage};
use crate::budget::{BufferGuard, Escaped, TenantBudget};
use crate::client_ip::{Cidr, ClientIp, ForwardedView, IpStrategy, normalize};
use crate::compile::{Invalid, Rejected};
use crate::route::request_host;
use crate::table::RoutingTable;
use podgate_model::Snapshot;

/// Sources a table holds when `max_sources` is absent.
pub(super) const DEFAULT_MAX_SOURCES: u32 = 10_000;

/// Most sources a table may hold.
pub(super) const MAX_SOURCES: u32 = 1_000_000;

/// Most blocks in `source.ip.excluded`: each is tested against every address of the chain.
const MAX_EXCLUDED: usize = 64;

/// Prefix length an IPv6 client is counted by when `ipv6_subnet_bits` is absent: a client that
/// owns a /64 has 2^64 addresses, and counting each would let it spread over every set of the
/// table.
const DEFAULT_IPV6_SUBNET_BITS: u8 = 64;

/// Entries per set: the most sources that can share one mutex.
const WAYS: usize = 8;

/// What an absent header or host counts as.
const ABSENT: &[u8] = b"-";

/// A `source.ip` as written in a snapshot: Traefik's `ipStrategy`, plus the IPv6 prefix.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IpSource {
    #[serde(default)]
    depth: Option<NonZeroU16>,
    #[serde(default)]
    excluded: Vec<Cidr>,
    /// Prefix length an IPv6 client is counted by; default [`DEFAULT_IPV6_SUBNET_BITS`].
    #[serde(default)]
    ipv6_subnet_bits: Option<u8>,
}

/// A `source` as written in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SourceConfig {
    /// The client address under an `ipStrategy`.
    Ip(IpSource),
    /// The first value of a request header.
    Header(String),
    /// The host of the request; only `true` is valid.
    Host(bool),
}

impl SourceConfig {
    /// What explain shows.
    pub(super) fn describe(&self) -> Value {
        match self {
            Self::Ip(ip) => json!({ "ip": {
                "depth": ip.depth,
                "excluded": ip.excluded.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "ipv6_subnet_bits": ip.ipv6_subnet_bits.unwrap_or(DEFAULT_IPV6_SUBNET_BITS),
            } }),
            Self::Header(name) => json!({ "header": name }),
            Self::Host(on) => json!({ "host": on }),
        }
    }
}

/// A compiled `source`.
#[derive(Debug)]
pub(super) enum Source {
    Ip {
        strategy: IpStrategy,
        subnet_bits: u8,
    },
    Header(HeaderName),
    Host,
}

/// `addr` as the first address of the `/bits` subnet it belongs to, when it is IPv6.
fn subnet_of(addr: IpAddr, bits: u8) -> IpAddr {
    match addr {
        IpAddr::V6(v6) if bits < 128 => {
            let mask = u128::MAX << (128 - u32::from(bits));
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
        _ => addr,
    }
}

impl Source {
    /// Validates `config`.
    ///
    /// # Errors
    ///
    /// The message of what is wrong with it.
    pub(super) fn compile(config: &SourceConfig) -> Result<Self, String> {
        match config {
            SourceConfig::Ip(ip) => {
                if ip.excluded.len() > MAX_EXCLUDED {
                    return Err(format!(
                        "`source.ip.excluded` has more than {MAX_EXCLUDED} entries"
                    ));
                }
                let subnet_bits = ip.ipv6_subnet_bits.unwrap_or(DEFAULT_IPV6_SUBNET_BITS);
                if !(1..=128).contains(&subnet_bits) {
                    return Err("`source.ip.ipv6_subnet_bits` must be 1 to 128".to_owned());
                }
                Ok(Self::Ip {
                    strategy: IpStrategy {
                        depth: ip.depth,
                        excluded: ip.excluded.clone(),
                    },
                    subnet_bits,
                })
            }
            SourceConfig::Header(name) => HeaderName::from_bytes(name.as_bytes())
                .map(Self::Header)
                .map_err(|_| format!("`source.header` {name:?} is not a header name")),
            SourceConfig::Host(true) => Ok(Self::Host),
            SourceConfig::Host(false) => Err("`source.host` must be true".to_owned()),
        }
    }

    /// The key of the source `request` comes from. Never zero: zero marks an empty entry.
    pub(super) fn key(
        &self,
        hasher: &RandomState,
        request: &RequestHeader,
        view: &ForwardedView,
    ) -> u64 {
        let hash = match self {
            Self::Ip {
                strategy,
                subnet_bits,
            } => hasher.hash_one(subnet_of(
                normalize(ClientIp::resolve(view, strategy)),
                *subnet_bits,
            )),
            Self::Header(name) => hasher.hash_one(
                request
                    .headers
                    .get(name)
                    .map_or(ABSENT, HeaderValue::as_bytes),
            ),
            Self::Host => {
                let own = request_host(request);
                let host = view.host.as_deref().or(own.as_deref());
                hasher.hash_one(host.map_or(ABSENT, str::as_bytes))
            }
        };
        hash.max(1)
    }
}

/// One record of the table.
#[derive(Debug, Clone, Copy, Default)]
struct Entry {
    /// Zero: the entry is empty.
    key: u64,
    value: u64,
}

type Set = [Entry; WAYS];

/// Bytes one set takes: the mutex and its eight records.
const SET_BYTES: u64 = size_of::<Mutex<Set>>() as u64;

/// The fixed-size table of per-source values. See the module docs.
#[derive(Debug)]
pub(super) struct SourceTable {
    sets: Box<[Mutex<Set>]>,
    /// Entries the table may hold, `max_sources`; the last set can have fewer than [`WAYS`].
    capacity: usize,
    /// The value every source without an entry shares.
    overflow: AtomicU64,
    /// Requests that used `overflow`.
    overflowed: AtomicU64,
}

impl SourceTable {
    /// Bytes a table of `max_sources` entries takes, what is charged to the tenant first.
    pub(super) fn bytes(max_sources: u32) -> u64 {
        u64::from(max_sources).div_ceil(WAYS as u64) * SET_BYTES + size_of::<Self>() as u64
    }

    fn new(max_sources: u32) -> Self {
        let capacity = usize::try_from(max_sources).unwrap_or(usize::MAX);
        let sets = capacity.div_ceil(WAYS).max(1);
        Self {
            sets: (0..sets)
                .map(|_| Mutex::new([Entry::default(); WAYS]))
                .collect(),
            capacity,
            overflow: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
        }
    }

    /// The set `key` belongs to, and how many of its entries the table may use.
    fn set_of(&self, key: u64) -> (&Mutex<Set>, usize) {
        let count = self.sets.len();
        // Multiply-shift: a uniform index in `0..count` from the top bits of the hash.
        let index = usize::try_from((u128::from(key) * count as u128) >> 64).unwrap_or(0);
        let ways = self.capacity.saturating_sub(index * WAYS).min(WAYS);
        (&self.sets[index.min(count.saturating_sub(1))], ways)
    }

    /// Runs `update` on the value of source `key`. A source with no entry takes an empty one,
    /// or one whose value `idle` calls reclaimable, starting from zero. `None` when every entry
    /// of the source's set holds a live source: the caller uses [`Self::overflow`].
    pub(super) fn with<R>(
        &self,
        key: u64,
        idle: impl Fn(u64) -> bool,
        update: impl FnOnce(&mut u64) -> R,
    ) -> Option<R> {
        let (set, ways) = self.set_of(key);
        let mut set = set.lock().unwrap_or_else(PoisonError::into_inner);
        let entries = &mut set[..ways];
        if let Some(found) = entries.iter_mut().find(|entry| entry.key == key) {
            return Some(update(&mut found.value));
        }
        let free = entries
            .iter_mut()
            .find(|entry| entry.key == 0 || idle(entry.value))?;
        *free = Entry { key, value: 0 };
        Some(update(&mut free.value))
    }

    /// Runs `update` on the value of source `key` when it has an entry.
    pub(super) fn with_existing(&self, key: u64, update: impl FnOnce(&mut u64)) {
        let (set, ways) = self.set_of(key);
        let mut set = set.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(found) = set[..ways].iter_mut().find(|entry| entry.key == key) {
            update(&mut found.value);
        }
    }

    /// The value the sources without an entry share.
    pub(super) fn overflow(&self) -> &AtomicU64 {
        &self.overflow
    }

    /// Counts a request that used [`Self::overflow`].
    pub(super) fn count_overflow(&self) {
        self.overflowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Requests that used [`Self::overflow`] so far.
    pub(super) fn overflowed(&self) -> u64 {
        self.overflowed.load(Ordering::Relaxed)
    }
}

/// The runtime state of one limiter middleware: what the registry carries across pushes.
#[derive(Debug)]
pub(crate) struct Limiter {
    hasher: RandomState,
    started: Instant,
    max_sources: u32,
    /// Serializes the first charge and allocation.
    gate: Mutex<()>,
    table: OnceLock<Charged>,
    rejected: AtomicU64,
}

/// The table and the charge that pays for it, released together.
#[derive(Debug)]
struct Charged {
    table: SourceTable,
    _charge: Option<BufferGuard>,
}

impl Limiter {
    pub(super) fn new(max_sources: u32) -> Self {
        Self {
            hasher: RandomState::new(),
            started: Instant::now(),
            max_sources,
            gate: Mutex::new(()),
            table: OnceLock::new(),
            rejected: AtomicU64::new(0),
        }
    }

    pub(super) fn hasher(&self) -> &RandomState {
        &self.hasher
    }

    /// Nanoseconds since the limiter was created: the clock of its buckets.
    pub(super) fn now_ns(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// The table, allocated on first use after charging `tenant` for it. `None` when the
    /// tenant's budget cannot take it right now; nothing is allocated then and the next call
    /// tries again. A request with no tenant budget (an app index the table does not know)
    /// allocates uncharged, as the other kinds do.
    pub(super) fn table(&self, tenant: Option<&Arc<TenantBudget>>) -> Option<&SourceTable> {
        if let Some(charged) = self.table.get() {
            return Some(&charged.table);
        }
        let _gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(charged) = self.table.get() {
            return Some(&charged.table);
        }
        let charge = match tenant {
            Some(tenant) => Some(tenant.charge(SourceTable::bytes(self.max_sources))?),
            None => None,
        };
        let charged = self.table.get_or_init(|| Charged {
            table: SourceTable::new(self.max_sources),
            _charge: charge,
        });
        Some(&charged.table)
    }

    /// The table, when a request has allocated it.
    pub(super) fn allocated(&self) -> Option<&SourceTable> {
        self.table.get().map(|charged| &charged.table)
    }

    /// Counts a refused request.
    pub(super) fn count_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn stats(&self) -> Stats {
        let table = self.allocated();
        Stats {
            overflow: table.map_or(0, SourceTable::overflowed),
            rejected: self.rejected.load(Ordering::Relaxed),
            bytes: table.map_or(0, |_| SourceTable::bytes(self.max_sources)),
        }
    }
}

/// What a limiter reports.
#[derive(Debug, Clone, Copy)]
pub(super) struct Stats {
    overflow: u64,
    rejected: u64,
    bytes: u64,
}

/// Rejects the apps whose limiter tables, added up per tenant, do not fit the tenant's declared
/// `max_buffer_bytes`. `stages` holds the compiled middlewares of each app of `snapshot`, in
/// order. A table is charged on first use, but fitting is checked for every declared one, so a
/// later request cannot be the first to find out.
pub(crate) fn over_budget(snapshot: &Snapshot, stages: &[&[Named]]) -> Vec<Rejected> {
    let budgets: HashMap<&str, u64> = snapshot
        .tenants
        .iter()
        .map(|tenant| (&*tenant.id, tenant.budget.max_buffer_bytes))
        .collect();
    let mut used: HashMap<&str, u64> = HashMap::new();
    let mut rejected = Vec::new();
    for (app, stages) in snapshot.apps.iter().zip(stages) {
        let Some(&budget) = budgets.get(&*app.tenant) else {
            continue;
        };
        for named in *stages {
            let (kind, max_sources) = match &named.stage {
                Stage::RateLimit(limit) => ("rate_limit", limit.max_sources()),
                Stage::InFlightReq(limit) => ("in_flight_req", limit.max_sources()),
                _ => continue,
            };
            let bytes = SourceTable::bytes(max_sources);
            let total = used.entry(&app.tenant).or_insert(0);
            *total = total.saturating_add(bytes);
            if *total > budget {
                rejected.push(Rejected::new(
                    app,
                    format!("middleware {}", named.name),
                    Invalid::new(
                        "invalid_middleware",
                        format!(
                            "{kind}: its table of {max_sources} sources takes {bytes} bytes, and with the other limiters of tenant {} that is {total} bytes, over the tenant's max_buffer_bytes of {budget}; lower max_sources or raise the budget",
                            app.tenant
                        ),
                    )
                    .with("tenant", &*app.tenant)
                    .with("table_bytes", bytes)
                    .with("max_buffer_bytes", budget),
                ));
            }
        }
    }
    rejected
}

/// One metric family of the exposition: its header lines and how to read a limiter's sample.
struct Family {
    name: &'static str,
    kind: &'static str,
    help: &'static str,
    value: fn(&Stats) -> u64,
}

/// The Prometheus exposition of every limiter in `live`.
#[must_use]
pub(crate) fn render(live: &RoutingTable) -> String {
    let mut rows = Vec::new();
    for app in live.apps() {
        for named in app.stages() {
            let (kind, stats) = match &named.stage {
                Stage::RateLimit(limit) => ("rate_limit", limit.stats()),
                Stage::InFlightReq(limit) => ("in_flight_req", limit.stats()),
                _ => continue,
            };
            rows.push((app.id(), &*named.name, kind, stats));
        }
    }
    let families = [
        Family {
            name: "podgate_limiter_rejected_total",
            kind: "counter",
            help: "Requests a rate_limit or in_flight_req middleware refused with 429.",
            value: |stats| stats.rejected,
        },
        Family {
            name: "podgate_limiter_overflow_total",
            kind: "counter",
            help: "Requests counted in a limiter's shared overflow bucket because its table of sources was full.",
            value: |stats| stats.overflow,
        },
        Family {
            name: "podgate_limiter_table_bytes",
            kind: "gauge",
            help: "Buffer bytes a limiter's table of sources holds, charged to the tenant.",
            value: |stats| stats.bytes,
        },
    ];
    let mut out = String::new();
    for Family {
        name,
        kind,
        help,
        value,
    } in families
    {
        // Writing to a `String` cannot fail.
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
        for (app, middleware, type_, stats) in &rows {
            let _ = writeln!(
                out,
                "{name}{{app=\"{}\",middleware=\"{}\",type=\"{type_}\"}} {}",
                Escaped(app),
                Escaped(middleware),
                value(stats)
            );
        }
    }
    out
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::budget::Budgets;
    use podgate_model::Budget;

    #[test]
    fn an_ipv6_address_is_counted_by_its_prefix_and_ipv4_is_not_masked() {
        let v6 = |text: &str| text.parse::<IpAddr>().expect("address");
        assert_eq!(
            subnet_of(v6("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), 64),
            v6("2001:db8:1:2::")
        );
        assert_eq!(
            subnet_of(v6("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), 128),
            v6("2001:db8:1:2:aaaa:bbbb:cccc:dddd")
        );
        assert_eq!(subnet_of(v6("2001:db8::1"), 1), v6("::"));
        assert_eq!(subnet_of(v6("203.0.113.9"), 64), v6("203.0.113.9"));
    }

    fn tenant(max_buffer_bytes: u64) -> Arc<TenantBudget> {
        Budgets::new().tenant(
            "t",
            Budget {
                max_inflight: 1,
                max_buffer_bytes,
            },
        )
    }

    #[test]
    fn entries_are_small_and_a_set_is_one_mutex_and_eight_of_them() {
        assert_eq!(size_of::<Entry>(), 16);
        assert_eq!(SET_BYTES, 8 + 8 * 16);
    }

    #[test]
    fn the_table_never_holds_more_live_sources_than_it_has_entries() {
        let table = SourceTable::new(3);
        let live = |_| false;
        let mut taken = 0;
        for key in 1..=100_u64 {
            if table.with(key, live, |value| *value = 1).is_some() {
                taken += 1;
            }
        }
        assert_eq!(taken, 3, "a table of 3 entries holds 3 sources");
    }

    #[test]
    fn an_idle_entry_is_taken_over_by_the_next_source() {
        let table = SourceTable::new(1);
        assert!(
            table
                .with(1, |value| value == 0, |value| *value = 5)
                .is_some()
        );
        assert!(
            table.with(2, |value| value == 0, |_| ()).is_none(),
            "the one entry is live"
        );
        table.with_existing(1, |value| *value = 0);
        assert!(
            table
                .with(2, |value| value == 0, |value| *value = 1)
                .is_some(),
            "the entry went idle and was reclaimed"
        );
        assert!(table.with(1, |value| value == 0, |_| ()).is_none());
    }

    #[test]
    fn a_source_with_an_entry_is_found_again() {
        let table = SourceTable::new(8);
        let idle = |_| false;
        table.with(42, idle, |value| *value = 9);
        assert_eq!(table.with(42, idle, |value| *value), Some(9));
    }

    #[test]
    fn memory_is_charged_before_the_table_exists_and_released_with_it() {
        let tenant = tenant(SourceTable::bytes(100));
        let limiter = Limiter::new(100);
        assert!(limiter.allocated().is_none());
        assert_eq!(tenant.buffered(), 0, "nothing is charged before a request");
        assert!(limiter.table(Some(&tenant)).is_some());
        assert_eq!(tenant.buffered(), SourceTable::bytes(100));
        assert!(limiter.table(Some(&tenant)).is_some(), "charged once");
        assert_eq!(tenant.buffered(), SourceTable::bytes(100));
        drop(limiter);
        assert_eq!(tenant.buffered(), 0);
    }

    #[test]
    fn a_budget_that_is_full_allocates_nothing_and_is_retried() {
        let tenant = tenant(SourceTable::bytes(100));
        let held = tenant.charge(1).expect("fits");
        let limiter = Limiter::new(100);
        assert!(limiter.table(Some(&tenant)).is_none());
        assert!(limiter.allocated().is_none());
        drop(held);
        assert!(limiter.table(Some(&tenant)).is_some());
    }
}
