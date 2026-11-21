//! SRV upstreams: servers named by a DNS `SRV` record.
//!
//! `{"url": "http://_web._tcp.shop.service.consul", "resolve": "srv"}` names no host and no port.
//! The author writes the full owner name (podgate never builds `_service._proto` itself), and the
//! records under it decide the targets, their ports, priorities and weights. Like every DNS
//! name here, an SRV name is resolved off the request path, on its TTL, by one task per owner
//! name across the node; the balancer only ever holds checked `ip:port` addresses.
//!
//! # Why there is a port policy
//!
//! With `A` records the author of the snapshot chooses the port and DNS chooses the address.
//! With `SRV` whoever edits the zone chooses both, so the address allow list alone would let a
//! record point a tenant's server at an allowed host's database port. Every target therefore
//! passes [`UpstreamPolicy::check`](crate::service::upstream_policy::UpstreamPolicy::check) for
//! each tenant that uses the name (on every address of the target) and
//! [`check_port`](crate::service::upstream_policy::UpstreamPolicy::check_port) (the operator's
//! `srv_deny_ports`, and the tenant's
//! `srv_allow_ports`), on every resolution, and the servers a balancer takes are filtered by the
//! same verdict again ([`Resolver::peek_srv`]), so a refused target is never a server and never
//! dialled.
//!
//! # Targets
//!
//! - A record with port `0` ("the service is not available here", RFC 2782), with the root `.` as
//!   its target, or whose target is not a syntactically valid host name is dropped.
//! - At most [`MAX_TARGETS_PER_NAME`] records are kept: the lowest priorities first, the highest
//!   weights first within one, then by name.
//! - A target host is resolved to `A` and `AAAA` addresses: the address records of the answer's
//!   additional section when it holds some for the host, else two follow-up lookups per host,
//!   counted against `DNS_MAX_QUERIES_PER_SEC` like any lookup. The name is never dialled.
//! - A target that is a `CNAME` is refused and dropped (RFC 2782 forbids it).
//! - Only the records of the lowest priority value that has a usable target are used; a higher
//!   value serves only while every target of the lower ones is unusable (no address, or refused
//!   by the policy). Health is the balancer's business, not this module's.
//!
//! # Weights
//!
//! A record of weight `w` gives each of its addresses the weight `max(1, w)` (a target with `n`
//! addresses splits it, `max(1, w / n)` each, so a multi-address target is only approximate).
//! Weight `0` therefore becomes `1`, the lowest weight, the same whether or not the other
//! records are zero as well. `fit` scales weights down for algorithms that cap their total.
//!
//! # Failure
//!
//! As for `A` names: a failed lookup, `NXDOMAIN` or an answer with no SRV record keeps the last
//! good set until `DNS_MAX_STALE_SECS` after its TTL ran out, then the name has no targets. A
//! target host that fails to resolve while its record is still listed keeps its last addresses on
//! the same terms. Records that are all unusable (port `0`, a `CNAME` target) are an answer: the
//! name has no target.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use tokio::task::AbortHandle;
use tokio::time::sleep;

use super::{Failure, Inner, MAX_ADDRESSES_PER_NAME, Resolver, is_host_name};

/// The most distinct SRV names one app's servers may use.
pub const MAX_NAMES_PER_APP: usize = 32;
/// The most distinct SRV names one tenant's servers may use, over every app.
pub const MAX_NAMES_PER_TENANT: usize = 128;
/// The most SRV records one name contributes to a service.
pub const MAX_TARGETS_PER_NAME: usize = 64;

/// One usable SRV record.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Rec {
    priority: u16,
    weight: u16,
    port: u16,
    /// The target host name, lower case, without the trailing dot.
    host: Box<str>,
}

/// A record and the addresses its host resolved to.
#[derive(Clone, Debug)]
struct Target {
    rec: Rec,
    addrs: Vec<IpAddr>,
    /// When the addresses stop being used if nothing refreshes them: their TTL plus the stale
    /// grace.
    until: Instant,
}

/// The usable targets of a name: records with the addresses to dial for each.
type View = Vec<(Rec, Vec<IpAddr>)>;

#[derive(Debug, Default)]
struct Entry {
    targets: Vec<Target>,
    /// When the answer stops being used if nothing refreshes it: its TTL plus the stale grace.
    expires: Option<Instant>,
    /// The tenants whose services use the name, whose policy each resolution is checked against.
    tenants: HashSet<Box<str>>,
}

impl Entry {
    /// The targets that may be used at `now`, sorted so two views compare equal when nothing
    /// changed.
    fn view(&self, now: Instant) -> View {
        if self.expires.is_none_or(|expires| expires <= now) {
            return Vec::new();
        }
        let mut view: View = self
            .targets
            .iter()
            .filter(|target| target.until > now)
            .map(|target| (target.rec.clone(), target.addrs.clone()))
            .collect();
        view.sort_by(|(a, _), (b, _)| {
            (a.priority, a.port, &a.host, a.weight).cmp(&(b.priority, b.port, &b.host, b.weight))
        });
        view
    }
}

/// The SRV names the resolver keeps fresh and the tasks that do it.
#[derive(Debug, Default)]
pub(super) struct Srv {
    entries: HashMap<Box<str>, Entry>,
    tasks: HashMap<Box<str>, AbortHandle>,
}

impl Srv {
    /// Makes the names and tasks those `wanted` (owner name to its tenants) calls for.
    pub(super) fn reconcile(
        &mut self,
        inner: &Arc<Inner>,
        wanted: &HashMap<Box<str>, HashSet<Box<str>>>,
    ) {
        self.entries.retain(|owner, _| wanted.contains_key(owner));
        self.tasks.retain(|owner, task| {
            let keep = wanted.contains_key(owner);
            if !keep {
                task.abort();
            }
            keep
        });
        for (owner, tenants) in wanted {
            self.entries.entry(owner.clone()).or_default().tenants = tenants.clone();
            self.tasks.entry(owner.clone()).or_insert_with(|| {
                tokio::spawn(run(Arc::clone(inner), owner.clone())).abort_handle()
            });
        }
    }

    pub(super) fn abort_all(&self) {
        for task in self.tasks.values() {
            task.abort();
        }
    }
}

/// One address of an SRV name a service may use, with its weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// Where to connect: a checked address and the port of its record.
    pub addr: SocketAddr,
    /// The weight of the address, at least `1`.
    pub weight: u32,
}

/// The addresses to use among `view`: those of the lowest priority value that has any address,
/// each with its weight, sorted by address. An address in two records of that priority is listed
/// once with the weights added.
fn choose(view: &[(Rec, Vec<IpAddr>)]) -> Vec<Resolved> {
    let Some(lowest) = view
        .iter()
        .filter(|(_, addrs)| !addrs.is_empty())
        .map(|(rec, _)| rec.priority)
        .min()
    else {
        return Vec::new();
    };
    let mut chosen: Vec<Resolved> = Vec::new();
    for (rec, addrs) in view
        .iter()
        .filter(|(rec, addrs)| rec.priority == lowest && !addrs.is_empty())
    {
        let weight = u32::from(rec.weight).max(1);
        let count = u32::try_from(addrs.len()).unwrap_or(u32::MAX);
        let share = (weight / count).max(1);
        for ip in addrs {
            let addr = SocketAddr::new(*ip, rec.port);
            match chosen.iter_mut().find(|found| found.addr == addr) {
                Some(found) => found.weight = found.weight.saturating_add(share),
                None => chosen.push(Resolved {
                    addr,
                    weight: share,
                }),
            }
        }
    }
    chosen.sort_by_key(|resolved| resolved.addr);
    chosen
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Scales `weights` so that, divided by their greatest common divisor, they add up to at most
/// `cap`, keeping every weight at least `1`. Weights that already fit are only divided by their
/// common divisor, which keeps their proportions exactly; weights that do not are scaled down,
/// which rounds.
pub(crate) fn fit(weights: &mut [u32], cap: u64) {
    let divisor = weights
        .iter()
        .fold(0, |divisor, weight| gcd(divisor, u64::from(*weight)));
    if divisor == 0 {
        return;
    }
    for weight in weights.iter_mut() {
        *weight = u32::try_from(u64::from(*weight) / divisor).unwrap_or(u32::MAX);
    }
    let total: u64 = weights.iter().map(|weight| u64::from(*weight)).sum();
    if total <= cap {
        return;
    }
    // Every weight keeps one unit, so what the rest may share is the cap minus the count.
    let spare = cap.saturating_sub(u64::try_from(weights.len()).unwrap_or(u64::MAX));
    for weight in weights.iter_mut() {
        let scaled = u64::from(*weight) * spare / total;
        *weight = u32::try_from(scaled).unwrap_or(u32::MAX).max(1);
    }
}

/// A host name as the resolver and the policy know it: lower case, no trailing dot. The root
/// name is empty.
fn normalized(name: &Name) -> Box<str> {
    let text = name.to_ascii().to_ascii_lowercase();
    text.strip_suffix('.').unwrap_or(&text).into()
}

/// The usable records of an answer: the SRV records with a port and a valid target host, the
/// preferred [`MAX_TARGETS_PER_NAME`] of them.
fn records_of(answers: &[Record]) -> Vec<Rec> {
    let mut found: Vec<Rec> = answers
        .iter()
        .filter_map(|record| {
            let RData::SRV(srv) = &record.data else {
                return None;
            };
            let host = normalized(&srv.target);
            // Port 0 is "decidedly not available here", and the root target says the same.
            if srv.port == 0 || !is_host_name(&host) {
                return None;
            }
            Some(Rec {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                host,
            })
        })
        .collect();
    found.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then(b.weight.cmp(&a.weight))
            .then_with(|| a.host.cmp(&b.host))
            .then(a.port.cmp(&b.port))
    });
    found.dedup();
    found.truncate(MAX_TARGETS_PER_NAME);
    found
}

/// What the additional section of an SRV answer says about target hosts.
#[derive(Debug, Default)]
struct Glue {
    addrs: HashMap<Box<str>, (Vec<IpAddr>, u32)>,
    cnames: HashSet<Box<str>>,
}

fn glue_of(additionals: &[Record]) -> Glue {
    let mut glue = Glue::default();
    for record in additionals {
        let host = normalized(&record.name);
        let ip = match &record.data {
            RData::A(a) => IpAddr::V4(a.0),
            RData::AAAA(a) => IpAddr::V6(a.0),
            RData::CNAME(_) => {
                glue.cnames.insert(host);
                continue;
            }
            _ => continue,
        };
        let (addrs, ttl) = glue.addrs.entry(host).or_insert((Vec::new(), u32::MAX));
        addrs.push(ip);
        *ttl = (*ttl).min(record.ttl);
    }
    glue
}

/// What resolving one target host gave.
enum Host {
    Addrs(Vec<IpAddr>, u32),
    /// The host is a `CNAME`.
    Cname,
    /// No address, whether the lookups failed or the host has none.
    None,
}

impl Resolver {
    /// The addresses `tenant` may use for the SRV name `owner` now: the targets of the lowest
    /// priority that has any the upstream policy lets the tenant dial (address and port), each
    /// with its weight, sorted by address. Empty for a name that has not resolved or whose
    /// answer went stale for good. Takes a lock, resolves nothing and has no side effect.
    #[must_use]
    pub fn peek_srv(&self, tenant: &str, owner: &str) -> Vec<Resolved> {
        let view = self
            .inner
            .lock()
            .srv
            .entries
            .get(owner)
            .map(|entry| entry.view(Instant::now()))
            .unwrap_or_default();
        let policy = &self.inner.policy;
        let allowed: View = view
            .into_iter()
            .filter(|(rec, _)| policy.evaluate_port(tenant, rec.port).is_ok())
            .map(|(rec, mut addrs)| {
                addrs.retain(|ip| policy.evaluate(tenant, *ip).is_ok());
                (rec, addrs)
            })
            .collect();
        choose(&allowed)
    }
}

#[cfg(test)]
impl Resolver {
    /// Puts `targets` (priority, weight, port, address) in the cache as a fresh answer for the
    /// SRV name `owner`, as a resolution would.
    pub(crate) fn seed_srv(&self, owner: &str, targets: &[(u16, u16, u16, IpAddr)]) {
        let now = Instant::now();
        let mut state = self.inner.lock();
        let entry = state.srv.entries.entry(owner.into()).or_default();
        entry.expires = Some(now + Duration::from_secs(3600));
        entry.targets = targets
            .iter()
            .map(|(priority, weight, port, ip)| Target {
                rec: Rec {
                    priority: *priority,
                    weight: *weight,
                    port: *port,
                    host: format!("t{port}.{owner}").into(),
                },
                addrs: vec![*ip],
                until: now + Duration::from_secs(3600),
            })
            .collect();
    }
}

impl Inner {
    /// Resolves one target host: from the glue of the SRV answer when it has addresses for it,
    /// else with a lookup per family. A `CNAME` is refused wherever it shows.
    async fn srv_host(&self, host: &str, glue: &Glue) -> Host {
        if glue.cnames.contains(host) {
            return Host::Cname;
        }
        if let Some((addrs, ttl)) = glue.addrs.get(host) {
            return Host::Addrs(addrs.clone(), *ttl);
        }
        let mut addrs = Vec::new();
        let mut ttl = u32::MAX;
        for record_type in [RecordType::A, RecordType::AAAA] {
            self.limiter.acquire().await;
            let Ok(_permit) = self.permits.acquire().await else {
                return Host::None;
            };
            // A failed or empty lookup of one family contributes nothing; the other may.
            let Ok(lookup) = self.query(host, record_type).await else {
                continue;
            };
            for record in lookup.answers() {
                match (&record.data, record_type) {
                    (RData::CNAME(_), _) => return Host::Cname,
                    (RData::A(a), RecordType::A) => addrs.push(IpAddr::V4(a.0)),
                    (RData::AAAA(a), RecordType::AAAA) => addrs.push(IpAddr::V6(a.0)),
                    _ => continue,
                }
                ttl = ttl.min(record.ttl);
            }
        }
        if addrs.is_empty() {
            Host::None
        } else {
            Host::Addrs(addrs, ttl)
        }
    }

    /// The addresses each target host of `owner` has now and when they stop being used.
    fn srv_previous(&self, owner: &str) -> HashMap<Box<str>, (Vec<IpAddr>, Instant)> {
        self.lock()
            .srv
            .entries
            .get(owner)
            .map(|entry| {
                entry
                    .targets
                    .iter()
                    .map(|target| {
                        (
                            target.rec.host.clone(),
                            (target.addrs.clone(), target.until),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Resolves the hosts of `records`, lowering `ttl` to the smallest TTL used. A host that is
    /// a `CNAME` loses its records; one that does not resolve keeps its last addresses until
    /// they are stale for too long.
    async fn srv_targets(
        &self,
        owner: &str,
        records: Vec<Rec>,
        glue: &Glue,
        ttl: &mut u32,
    ) -> Vec<Target> {
        let previous = self.srv_previous(owner);
        let mut hosts: HashMap<Box<str>, Option<(Vec<IpAddr>, Instant)>> = HashMap::new();
        let mut targets = Vec::with_capacity(records.len());
        for rec in records {
            if !hosts.contains_key(&rec.host) {
                let now = Instant::now();
                let resolved = match self.srv_host(&rec.host, glue).await {
                    Host::Addrs(mut addrs, host_ttl) => {
                        addrs.sort_unstable();
                        addrs.dedup();
                        addrs.truncate(MAX_ADDRESSES_PER_NAME);
                        *ttl = (*ttl).min(host_ttl);
                        let until = now + self.keep_for(host_ttl) + self.settings.max_stale;
                        Some((addrs, until))
                    }
                    Host::Cname => {
                        tracing::warn!(
                            name = owner,
                            target = &*rec.host,
                            "SRV target is a CNAME, which RFC 2782 forbids; its records are dropped"
                        );
                        None
                    }
                    Host::None => previous
                        .get(&rec.host)
                        .filter(|(_, until)| *until > now)
                        .cloned(),
                };
                hosts.insert(rec.host.clone(), resolved);
            }
            if let Some(Some((addrs, until))) = hosts.get(&rec.host) {
                targets.push(Target {
                    rec,
                    addrs: addrs.clone(),
                    until: *until,
                });
            }
        }
        targets
    }

    /// Whether the last good answer of `owner` holds a target.
    fn srv_has_targets(&self, owner: &str) -> bool {
        self.lock()
            .srv
            .entries
            .get(owner)
            .is_some_and(|entry| !entry.targets.is_empty())
    }

    /// Runs the policy on the targets of one resolution for `tenant`, which counts and logs
    /// every refusal: the port of a record, then each address of it.
    fn srv_refused_by(&self, tenant: &str, owner: &str, view: &View) {
        for (rec, addrs) in view {
            if let Err(why) = self.policy.check_port(tenant, rec.port) {
                tracing::warn!(
                    tenant,
                    name = owner,
                    target = &*rec.host,
                    port = rec.port,
                    %why,
                    "SRV target dropped by the upstream port policy"
                );
                continue;
            }
            let refused: Vec<IpAddr> = addrs
                .iter()
                .filter(|ip| self.policy.check(tenant, **ip).is_err())
                .copied()
                .collect();
            if !refused.is_empty() {
                tracing::warn!(
                    tenant,
                    name = owner,
                    target = &*rec.host,
                    ?refused,
                    "SRV target addresses dropped by the upstream address policy"
                );
            }
        }
    }

    /// Stores a good answer for `owner`, checks it for every tenant that uses the name and
    /// signals when the usable targets changed. Returns when it is to be refreshed.
    fn record_srv(&self, owner: &str, targets: Vec<Target>, ttl: u32, now: Instant) -> Duration {
        let keep = self.keep_for(ttl);
        let soonest = targets
            .iter()
            .map(|target| target.until.saturating_duration_since(now))
            .min();
        let mut state = self.lock();
        let wait = keep.min(soonest.unwrap_or(keep));
        let Some(entry) = state.srv.entries.get_mut(owner) else {
            return wait;
        };
        let before = entry.view(now);
        entry.targets = targets;
        entry.expires = Some(now + keep + self.settings.max_stale);
        let after = entry.view(now);
        let tenants: Vec<Box<str>> = entry.tenants.iter().cloned().collect();
        drop(state);
        for tenant in &tenants {
            self.srv_refused_by(tenant, owner, &after);
        }
        if before != after {
            self.bump();
        }
        wait
    }

    /// Drops what has been stale for too long, and signals it.
    fn srv_expire(&self, owner: &str, now: Instant) {
        let mut state = self.lock();
        let Some(entry) = state.srv.entries.get_mut(owner) else {
            return;
        };
        let before = entry.targets.len();
        if entry.expires.is_none_or(|expires| expires <= now) {
            entry.targets.clear();
            entry.expires = None;
        } else {
            entry.targets.retain(|target| target.until > now);
        }
        if entry.targets.len() != before {
            drop(state);
            self.bump();
        }
    }

    /// Notes that a resolution of `owner` gave nothing: the last good answer stays until it is
    /// stale for too long. Returns how long until something changes.
    fn record_srv_failure(
        &self,
        owner: &str,
        failure: &Failure,
        failures: u32,
        now: Instant,
    ) -> Duration {
        match failure {
            Failure::Empty | Failure::NoData(_) => {
                tracing::debug!(name = owner, "SRV answer has no usable target");
            }
            Failure::Error(why) => {
                tracing::warn!(name = owner, %why, "SRV resolution failed");
            }
        }
        let retry = self.backoff(failures);
        self.srv_expire(owner, now);
        let left = self
            .lock()
            .srv
            .entries
            .get(owner)
            .and_then(|entry| entry.expires)
            .map(|expires| expires.saturating_duration_since(now));
        match left {
            Some(left) if !left.is_zero() => retry.min(left),
            _ => retry,
        }
    }
}

/// Keeps the answer of one SRV name fresh until the task is aborted.
async fn run(inner: Arc<Inner>, owner: Box<str>) {
    let mut failures = 0_u32;
    loop {
        inner.srv_expire(&owner, Instant::now());
        inner.limiter.acquire().await;
        let outcome = {
            let Ok(_permit) = inner.permits.acquire().await else {
                return;
            };
            inner.query(&owner, RecordType::SRV).await
        };
        let wait = match outcome {
            Ok(lookup) => {
                let answered = lookup
                    .answers()
                    .iter()
                    .any(|record| matches!(record.data, RData::SRV(_)));
                let records = records_of(lookup.answers());
                let glue = glue_of(lookup.additionals());
                let mut ttl = lookup
                    .answers()
                    .iter()
                    .filter(|record| matches!(record.data, RData::SRV(_)))
                    .map(|record| record.ttl)
                    .min()
                    .unwrap_or(u32::MAX);
                let targets = inner.srv_targets(&owner, records, &glue, &mut ttl).await;
                let now = Instant::now();
                // Records that are all unusable (port 0, a CNAME target) are an answer: the name
                // has no target. An answer with no SRV record at all is a failure that keeps
                // the last good set.
                if !answered && inner.srv_has_targets(&owner) {
                    failures = failures.saturating_add(1);
                    inner.record_srv_failure(&owner, &Failure::Empty, failures, now)
                } else {
                    failures = 0;
                    inner.record_srv(&owner, targets, ttl, now)
                }
            }
            // A name with no SRV record at all is an answer when nothing was known before: cached
            // empty for its negative TTL like an `A` name without an address.
            Err(Failure::NoData(negative)) if !inner.srv_has_targets(&owner) => {
                failures = 0;
                inner.record_srv(
                    &owner,
                    Vec::new(),
                    negative.unwrap_or(u32::MAX),
                    Instant::now(),
                )
            }
            Err(failure) => {
                failures = failures.saturating_add(1);
                inner.record_srv_failure(&owner, &failure, failures, Instant::now())
            }
        };
        sleep(wait.max(Duration::from_millis(10))).await;
    }
}

#[cfg(test)]
mod test {
    use hickory_resolver::proto::rr::rdata::SRV;

    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    fn rec(priority: u16, weight: u16, port: u16, host: &str) -> Rec {
        Rec {
            priority,
            weight,
            port,
            host: host.into(),
        }
    }

    fn answer(priority: u16, weight: u16, port: u16, target: &str) -> Record {
        let owner = Name::from_ascii("_web._tcp.shop.test.").expect("owner name");
        let target = Name::from_ascii(target).expect("target name");
        Record::from_rdata(
            owner,
            30,
            RData::SRV(SRV::new(priority, weight, port, target)),
        )
    }

    #[test]
    fn srv_port_zero_dropped() {
        let found = records_of(&[
            answer(10, 5, 0, "off.shop.test."),
            answer(10, 5, 8080, "on.shop.test."),
            answer(10, 5, 8081, "."),
        ]);
        assert_eq!(found, vec![rec(10, 5, 8080, "on.shop.test")]);
    }

    #[test]
    fn srv_target_cap() {
        let answers: Vec<Record> = (0..100_u16)
            .map(|n| answer(n % 4, n, 8000 + n, &format!("t{n}.shop.test.")))
            .collect();
        let found = records_of(&answers);
        assert_eq!(found.len(), MAX_TARGETS_PER_NAME);
        assert!(
            found.iter().all(|rec| rec.priority <= 2),
            "the lowest priorities are the ones kept: {found:?}"
        );
        assert!(
            found
                .windows(2)
                .all(|pair| pair[0].priority <= pair[1].priority)
        );
    }

    #[test]
    fn srv_lowest_priority_group_used() {
        let view = vec![
            (rec(20, 1, 80, "b"), vec![ip("10.0.0.2")]),
            (rec(10, 3, 80, "a"), vec![ip("10.0.0.1")]),
            (rec(10, 1, 81, "c"), vec![ip("10.0.0.3")]),
        ];
        let chosen = choose(&view);
        assert_eq!(
            chosen,
            vec![
                Resolved {
                    addr: "10.0.0.1:80".parse().expect("addr"),
                    weight: 3
                },
                Resolved {
                    addr: "10.0.0.3:81".parse().expect("addr"),
                    weight: 1
                },
            ]
        );
    }

    #[test]
    fn srv_next_priority_when_lower_empty() {
        let view = vec![
            (rec(10, 3, 80, "a"), Vec::new()),
            (rec(20, 2, 80, "b"), vec![ip("10.0.0.2")]),
        ];
        assert_eq!(
            choose(&view),
            vec![Resolved {
                addr: "10.0.0.2:80".parse().expect("addr"),
                weight: 2
            }]
        );
        assert!(choose(&[(rec(10, 3, 80, "a"), Vec::new())]).is_empty());
    }

    #[test]
    fn srv_weight_zero_is_the_lowest_weight() {
        let zero = vec![
            (rec(1, 0, 80, "a"), vec![ip("10.0.0.1")]),
            (rec(1, 0, 80, "b"), vec![ip("10.0.0.2")]),
        ];
        assert!(choose(&zero).iter().all(|resolved| resolved.weight == 1));
        let mixed = vec![
            (rec(1, 0, 80, "a"), vec![ip("10.0.0.1")]),
            (rec(1, 7, 80, "b"), vec![ip("10.0.0.2")]),
        ];
        let weights: Vec<u32> = choose(&mixed).iter().map(|r| r.weight).collect();
        assert_eq!(weights, vec![1, 7]);
    }

    #[test]
    fn srv_multi_address_target_splits_its_weight() {
        let view = vec![(rec(1, 10, 80, "a"), vec![ip("10.0.0.1"), ip("10.0.0.2")])];
        let weights: Vec<u32> = choose(&view).iter().map(|r| r.weight).collect();
        assert_eq!(weights, vec![5, 5]);
    }

    #[test]
    fn fit_keeps_proportions_when_they_fit_and_scales_when_they_do_not() {
        let mut exact = [50, 100, 150];
        fit(&mut exact, 256);
        assert_eq!(exact, [1, 2, 3]);
        let mut big = [65535, 1, 30000];
        fit(&mut big, 256);
        let total: u64 = big.iter().map(|w| u64::from(*w)).sum();
        assert!(total <= 256, "{big:?}");
        assert!(big.iter().all(|w| *w >= 1), "{big:?}");
        assert!(big[0] > big[2] && big[2] > big[1], "{big:?}");
        let mut many = [3_u32; 256];
        fit(&mut many, 256);
        assert_eq!(many, [1; 256]);
        let mut empty: [u32; 0] = [];
        fit(&mut empty, 256);
    }

    #[test]
    fn glue_collects_addresses_and_cnames_by_host() {
        let name = |text: &str| Name::from_ascii(text).expect("name");
        let glue = glue_of(&[
            Record::from_rdata(
                name("A.shop.test."),
                30,
                RData::A(hickory_resolver::proto::rr::rdata::A::new(10, 0, 0, 1)),
            ),
            Record::from_rdata(
                name("a.shop.test."),
                10,
                RData::A(hickory_resolver::proto::rr::rdata::A::new(10, 0, 0, 2)),
            ),
            Record::from_rdata(
                name("alias.shop.test."),
                30,
                RData::CNAME(hickory_resolver::proto::rr::rdata::CNAME(name(
                    "a.shop.test.",
                ))),
            ),
        ]);
        assert_eq!(
            glue.addrs.get("a.shop.test"),
            Some(&(vec![ip("10.0.0.1"), ip("10.0.0.2")], 10))
        );
        assert!(glue.cnames.contains("alias.shop.test"));
    }
}
