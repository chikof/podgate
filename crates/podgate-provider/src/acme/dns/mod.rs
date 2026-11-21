//! DNS-01 solvers for the ACME broker: publish a TXT record through an RFC 2136 update (TSIG) or a
//! webhook, and report it only when every authoritative server serves it.
//!
//! podgate holds no DNS credential: it emits `acme_challenge {type: dns-01, name, value}` and
//! waits for `acme.dns_ready` (`docs/ref/acme-dns01.md`). The broker hands each challenge to the
//! [`Solver`] this module provides, and pushes `dns_ready` only after [`Solver::present`] returned
//! `Ok`. The reference is `docs/ref/provider-acme-dns.md`.
//!
//! One challenge goes through these steps, each of which can refuse or fail:
//!
//! 1. `zones`: the zone is the configured one with the longest suffix of the name (none:
//!    `no_solver`), and the app that asked must belong to a tenant that owns the base domain
//!    (otherwise `foreign_name`). Neither is retried: the answer would be the same.
//! 2. The target: a `CNAME` at the name (an `_acme-challenge` delegation) is followed when the zone
//!    allows it, and the update goes to the zone of its target.
//! 3. The backend publishes the record with a 60 second TTL: `rfc2136` or `webhook`.
//! 4. `verify`: every authoritative server of the zone is asked until all return the value.
//!
//! A transient failure at step 2 to 4 is logged and retried with backoff until the challenge ends
//! (`cleanup`) or [`Timing::give_up`] passes. [`Solver::cleanup`] removes exactly the value this
//! solver published; other values at the name stay.

mod rfc2136;
mod verify;
mod webhook;
mod zones;

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{Name, TSigner};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::Instant;
use tracing::{info, warn};

use self::rfc2136::Rfc2136;
use self::webhook::Webhook;
use super::events::{DnsChallenge, SolveError, Solver, SolverFuture};
use super::store::{StoreError, read_secret_file};
use super::{Claims, Secret};
use crate::config::{Config, ConfigError};
use crate::push::Backoff;
use crate::trust::{HostPattern, Trust};

/// Default wait for every authoritative server to serve a record.
const PROPAGATION_SECS: u64 = 120;
/// Default deadline of one webhook call.
const WEBHOOK_SECS: u64 = 10;
/// CNAMEs followed from one name before the chain is refused as a loop.
const MAX_CNAME_HOPS: usize = 8;
/// Attempts to remove a record.
const CLEANUP_ATTEMPTS: u32 = 5;

/// TSIG algorithms the solver signs with: `hmac-sha256` or stronger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Algorithm {
    /// `hmac-sha256`.
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
    /// `hmac-sha384`.
    #[serde(rename = "hmac-sha384")]
    HmacSha384,
    /// `hmac-sha512`.
    #[serde(rename = "hmac-sha512")]
    HmacSha512,
}

impl Algorithm {
    fn tsig(self) -> TsigAlgorithm {
        match self {
            Self::HmacSha256 => TsigAlgorithm::HmacSha256,
            Self::HmacSha384 => TsigAlgorithm::HmacSha384,
            Self::HmacSha512 => TsigAlgorithm::HmacSha512,
        }
    }
}

/// How a zone's records are published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// An RFC 2136 update to the zone's primary, signed with TSIG.
    Rfc2136 {
        /// `host:port` of the primary (port 53 when absent).
        server: Box<str>,
        /// The TSIG key name.
        tsig_key_name: Box<str>,
        /// The TSIG algorithm.
        tsig_algorithm: Algorithm,
        /// The file with the base64 key, mode `0600`.
        tsig_secret_file: PathBuf,
    },
    /// An HTTP webhook (`POST <url>/present`, `POST <url>/cleanup`).
    Webhook {
        /// The base URL, `http://` or `https://`.
        url: Box<str>,
        /// The file with the bearer token, mode `0600`.
        bearer_token_file: PathBuf,
        /// The deadline of one call.
        timeout: Duration,
    },
}

/// One `[[acme.dns]]` entry. It holds paths, never secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSettings {
    /// The zone, lowercase, no trailing dot.
    pub zone: Box<str>,
    /// How its records are published.
    pub backend: Backend,
    /// How long to wait for every authoritative server to serve a record.
    pub propagation_timeout: Duration,
    /// The servers to ask. Empty: the authoritative servers found by an NS lookup of the zone.
    pub check_resolvers: Vec<SocketAddr>,
    /// Whether a `CNAME` at `_acme-challenge.<name>` is followed.
    pub cname_follow: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Rfc2136,
    Webhook,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawZone {
    zone: String,
    kind: Kind,
    server: Option<String>,
    tsig_key_name: Option<String>,
    tsig_algorithm: Option<Algorithm>,
    tsig_secret_file: Option<PathBuf>,
    url: Option<String>,
    bearer_token_file: Option<PathBuf>,
    timeout_secs: Option<u64>,
    propagation_timeout_secs: Option<u64>,
    #[serde(default)]
    check_resolvers: Vec<String>,
    cname_follow: Option<bool>,
}

fn resolver_address(text: &str) -> Option<SocketAddr> {
    text.parse::<SocketAddr>().ok().or_else(|| {
        text.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

/// Validates the `[[acme.dns]]` entries.
pub(crate) fn parse(raw: Vec<RawZone>) -> Result<Vec<ZoneSettings>, ConfigError> {
    let mut zones: Vec<ZoneSettings> = Vec::with_capacity(raw.len());
    for (at, entry) in raw.into_iter().enumerate() {
        let field = |key: &str| format!("acme.dns[{at}].{key}");
        let bad = |key: &str, why: &str| ConfigError::invalid(field(key), why);
        let name = zones::normalize(&entry.zone);
        if !matches!(HostPattern::parse(&name), Ok(HostPattern::Exact(_))) {
            return Err(bad("zone", "is not a domain name"));
        }
        if zones.iter().any(|known| *known.zone == *name) {
            return Err(bad("zone", "is configured twice"));
        }
        let foreign = |keys: &[(&str, bool)]| {
            keys.iter()
                .find(|(_, present)| *present)
                .map(|(key, _)| bad(key, "does not belong to this kind"))
        };
        let backend = match entry.kind {
            Kind::Rfc2136 => {
                if let Some(err) = foreign(&[
                    ("url", entry.url.is_some()),
                    ("bearer_token_file", entry.bearer_token_file.is_some()),
                    ("timeout_secs", entry.timeout_secs.is_some()),
                ]) {
                    return Err(err);
                }
                let server = entry.server.ok_or_else(|| bad("server", "is required"))?;
                let key_name = entry
                    .tsig_key_name
                    .ok_or_else(|| bad("tsig_key_name", "is required"))?;
                if Name::from_ascii(&key_name).is_err() {
                    return Err(bad("tsig_key_name", "is not a domain name"));
                }
                Backend::Rfc2136 {
                    server: if server.contains(':') || server.is_empty() {
                        server.into()
                    } else {
                        format!("{server}:53").into()
                    },
                    tsig_key_name: key_name.into(),
                    tsig_algorithm: entry.tsig_algorithm.ok_or_else(|| {
                        bad("tsig_algorithm", "is required (hmac-sha256 or stronger)")
                    })?,
                    tsig_secret_file: entry
                        .tsig_secret_file
                        .ok_or_else(|| bad("tsig_secret_file", "is required"))?,
                }
            }
            Kind::Webhook => {
                if let Some(err) = foreign(&[
                    ("server", entry.server.is_some()),
                    ("tsig_key_name", entry.tsig_key_name.is_some()),
                    ("tsig_algorithm", entry.tsig_algorithm.is_some()),
                    ("tsig_secret_file", entry.tsig_secret_file.is_some()),
                ]) {
                    return Err(err);
                }
                let url = entry.url.ok_or_else(|| bad("url", "is required"))?;
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(bad("url", "must start with http:// or https://"));
                }
                let timeout = entry.timeout_secs.unwrap_or(WEBHOOK_SECS);
                if timeout == 0 {
                    return Err(bad("timeout_secs", "must be at least 1"));
                }
                Backend::Webhook {
                    url: url.into(),
                    bearer_token_file: entry
                        .bearer_token_file
                        .ok_or_else(|| bad("bearer_token_file", "is required"))?,
                    timeout: Duration::from_secs(timeout),
                }
            }
        };
        let propagation = entry.propagation_timeout_secs.unwrap_or(PROPAGATION_SECS);
        if propagation == 0 {
            return Err(bad("propagation_timeout_secs", "must be at least 1"));
        }
        let check_resolvers = entry
            .check_resolvers
            .iter()
            .map(|text| {
                resolver_address(text).ok_or_else(|| {
                    bad(
                        "check_resolvers",
                        "holds an address that is not `ip` or `ip:port`",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        zones.push(ZoneSettings {
            zone: name.into(),
            backend,
            propagation_timeout: Duration::from_secs(propagation),
            check_resolvers,
            cname_follow: entry.cname_follow.unwrap_or(true),
        });
    }
    Ok(zones)
}

/// Why a solver cannot be built, or why a challenge was not solved. `Display` is the message the
/// broker logs: it starts with the code the operator can grep for, and never holds a secret.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DnsError {
    /// No configured zone covers the name.
    #[error("no_solver: no configured DNS zone covers {name}")]
    NoSolver {
        /// The challenge name.
        name: Box<str>,
    },
    /// The requesting tenant does not own the name's domain.
    #[error("foreign_name: {name} is not published: {why}")]
    ForeignName {
        /// The challenge name.
        name: Box<str>,
        /// Why.
        why: Box<str>,
    },
    /// The backend refused in a way retrying will not change.
    #[error("{0}")]
    Refused(Box<str>),
    /// The challenge ended while the record was being published.
    #[error("cancelled: the challenge ended")]
    Cancelled,
    /// Retries did not publish the record in time.
    #[error("gave_up: not published after {secs}s: {last}")]
    GaveUp {
        /// How long it tried.
        secs: u64,
        /// The last failure.
        last: Box<str>,
    },
    /// A secret file is missing or not private.
    #[error("DNS zone {zone}: cannot use the secret file")]
    Secret {
        /// The zone.
        zone: Box<str>,
        /// The cause: names the path and the mode, never the content.
        #[source]
        source: StoreError,
    },
    /// The zone's settings do not make a client.
    #[error("DNS zone {zone}: {reason}")]
    Setup {
        /// The zone.
        zone: Box<str>,
        /// What is wrong.
        reason: Box<str>,
    },
}

/// A step failed.
#[derive(Debug)]
enum Failure {
    /// Worth trying again.
    Retry(String),
    /// Trying again will not help.
    Permanent(String),
}

/// The clock of one solver. The defaults are the documented ones; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Deadline of one DNS query to an authoritative server.
    pub query_timeout: Duration,
    /// Pause between two passes over the authoritative servers.
    pub poll_interval: Duration,
    /// Deadline of one RFC 2136 update.
    pub update_timeout: Duration,
    /// First retry delay after a failed step.
    pub retry_min: Duration,
    /// The retry delay stops doubling here.
    pub retry_max: Duration,
    /// Retries stop after this long (the issuer abandons an order after ten minutes).
    pub give_up: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(3),
            poll_interval: Duration::from_secs(2),
            update_timeout: Duration::from_secs(10),
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
            give_up: Duration::from_secs(15 * 60),
        }
    }
}

/// One challenge in progress: its cancellation and where it published.
struct Job {
    cancelled: AtomicBool,
    wake: Notify,
    /// Held by `present` while it runs and by `cleanup` while it removes, so a removal never
    /// races the publish it undoes.
    run: AsyncMutex<()>,
    /// The zone (index) and name a record was, or may have been, published at.
    target: Mutex<Option<(usize, Name)>>,
}

impl Job {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            wake: Notify::new(),
            run: AsyncMutex::new(()),
            target: Mutex::new(None),
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    /// Sleeps `pause`, or until the job is cancelled. `false` when it was cancelled.
    async fn nap(&self, pause: Duration) -> bool {
        if !self.is_cancelled() {
            tokio::select! {
                () = tokio::time::sleep(pause) => {}
                () = self.wake.notified() => {}
            }
        }
        !self.is_cancelled()
    }

    fn set_target(&self, zone: usize, name: Name) {
        *self.target.lock().unwrap_or_else(PoisonError::into_inner) = Some((zone, name));
    }

    fn target(&self) -> Option<(usize, Name)> {
        self.target
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

enum Client {
    Rfc2136(Rfc2136),
    Webhook(Box<Webhook>),
}

enum Authority {
    Fixed(Vec<SocketAddr>),
    Discover,
}

struct Zone {
    name: Box<str>,
    apex: Name,
    client: Client,
    authority: Authority,
    propagation: Duration,
    cname_follow: bool,
}

fn name_of(text: &str) -> Result<Name, Failure> {
    Name::from_ascii(format!("{text}."))
        .map_err(|_| Failure::Permanent(format!("{text} is not a valid DNS name")))
}

impl Zone {
    async fn servers(&self, wait: Duration) -> Result<Vec<SocketAddr>, String> {
        match &self.authority {
            Authority::Fixed(servers) => Ok(servers.clone()),
            Authority::Discover => verify::discover(&self.name, wait).await,
        }
    }

    async fn publish(&self, name: &Name, value: &str, add: bool) -> Result<(), Failure> {
        match &self.client {
            Client::Rfc2136(client) => client.update(&self.apex, name, value, add).await,
            Client::Webhook(client) => {
                let action = if add { "present" } else { "cleanup" };
                client.call(action, &name.to_ascii(), value).await
            }
        }
    }
}

type JobKey = (Box<str>, Box<str>);

struct Inner {
    zones: Vec<Zone>,
    trust: Trust,
    timing: Timing,
    jobs: Mutex<HashMap<JobKey, Arc<Job>>>,
}

/// The DNS-01 solver of `[[acme.dns]]` zones.
pub struct DnsSolver {
    inner: Arc<Inner>,
}

impl fmt::Debug for DnsSolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let zones: Vec<&str> = self.inner.zones.iter().map(|zone| &*zone.name).collect();
        f.debug_struct("DnsSolver")
            .field("zones", &zones)
            .finish_non_exhaustive()
    }
}

fn secret(zone: &str, path: &std::path::Path) -> Result<Secret, DnsError> {
    read_secret_file(path).map_err(|source| DnsError::Secret {
        zone: zone.into(),
        source,
    })
}

fn build(settings: &ZoneSettings, timing: &Timing) -> Result<Zone, DnsError> {
    let setup = |reason: String| DnsError::Setup {
        zone: settings.zone.clone(),
        reason: reason.into(),
    };
    let apex = Name::from_ascii(format!("{}.", settings.zone))
        .map_err(|_| setup("is not a domain name".into()))?;
    let client = match &settings.backend {
        Backend::Rfc2136 {
            server,
            tsig_key_name,
            tsig_algorithm,
            tsig_secret_file,
        } => {
            let key = secret(&settings.zone, tsig_secret_file)?;
            let bytes = STANDARD
                .decode(key.expose().trim())
                .map_err(|_| setup("the TSIG secret is not base64".into()))?;
            let key_name = Name::from_ascii(tsig_key_name)
                .map_err(|_| setup("the TSIG key name is not a domain name".into()))?;
            let signer = TSigner::new(bytes, tsig_algorithm.tsig(), key_name, rfc2136::FUDGE)
                .map_err(|_| setup("the TSIG algorithm is not supported".into()))?;
            Client::Rfc2136(Rfc2136::new(server.clone(), signer, timing.update_timeout))
        }
        Backend::Webhook {
            url,
            bearer_token_file,
            timeout,
        } => {
            let token = secret(&settings.zone, bearer_token_file)?;
            Client::Webhook(Box::new(Webhook::new(url, token, *timeout).map_err(setup)?))
        }
    };
    Ok(Zone {
        name: settings.zone.clone(),
        apex,
        client,
        authority: if settings.check_resolvers.is_empty() {
            Authority::Discover
        } else {
            Authority::Fixed(settings.check_resolvers.clone())
        },
        propagation: settings.propagation_timeout,
        cname_follow: settings.cname_follow,
    })
}

/// The solver `config` asks for: the `[[acme.dns]]` zones, or [`super::events::NoSolver`] when
/// there are none.
///
/// # Errors
///
/// [`DnsError`] when a secret file is missing or not private (mode `0600`), or a key is not
/// usable.
pub fn solver(config: &Config) -> Result<Arc<dyn Solver>, DnsError> {
    if config.acme.as_ref().is_none_or(|acme| acme.dns.is_empty()) {
        return Ok(Arc::new(super::events::NoSolver));
    }
    Ok(Arc::new(DnsSolver::new(config)?))
}

impl DnsSolver {
    /// The solver of `config`'s `[[acme.dns]]` zones, with the documented timing.
    ///
    /// # Errors
    ///
    /// [`DnsError`] when a secret file is missing or not private (mode `0600`), or a key is not
    /// usable.
    pub fn new(config: &Config) -> Result<Self, DnsError> {
        Self::with_timing(config, Timing::default())
    }

    /// Like [`DnsSolver::new`], with `timing` in place of the documented one.
    ///
    /// # Errors
    ///
    /// As [`DnsSolver::new`].
    pub fn with_timing(config: &Config, timing: Timing) -> Result<Self, DnsError> {
        let settings = config.acme.as_ref().map_or(&[][..], |acme| &acme.dns[..]);
        let mut zones = settings
            .iter()
            .map(|zone| build(zone, &timing))
            .collect::<Result<Vec<_>, _>>()?;
        // Longest first, so the first zone that covers a name is the most specific one.
        zones.sort_by(|a, b| b.name.len().cmp(&a.name.len()).then(a.name.cmp(&b.name)));
        Ok(Self {
            inner: Arc::new(Inner {
                zones,
                trust: Trust::new(config),
                timing,
                jobs: Mutex::new(HashMap::new()),
            }),
        })
    }
}

impl Inner {
    fn zone_of(&self, name: &str) -> Option<usize> {
        zones::longest_suffix(self.zones.iter().map(|zone| &*zone.name), name)
    }

    fn jobs(&self) -> std::sync::MutexGuard<'_, HashMap<JobKey, Arc<Job>>> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, challenge: &DnsChallenge) -> Arc<Job> {
        let job = Arc::new(Job::new());
        let key = (challenge.name.clone(), challenge.value.clone());
        if let Some(old) = self.jobs().insert(key, Arc::clone(&job)) {
            old.cancel();
        }
        job
    }

    fn forget(&self, challenge: &DnsChallenge, job: &Arc<Job>) {
        let key = (challenge.name.clone(), challenge.value.clone());
        let mut jobs = self.jobs();
        if jobs.get(&key).is_some_and(|known| Arc::ptr_eq(known, job)) {
            jobs.remove(&key);
        }
    }

    /// Steps 1: the zone and the trust rule. Both answers are final.
    fn admit(&self, challenge: &DnsChallenge, claims: &Claims) -> Result<usize, DnsError> {
        let name = zones::normalize(&challenge.name);
        let zone = self.zone_of(&name).ok_or_else(|| DnsError::NoSolver {
            name: name.as_str().into(),
        })?;
        let owner = zones::base_domain(&name)
            .ok_or_else(|| DnsError::ForeignName {
                name: name.as_str().into(),
                why: "it is not an _acme-challenge name".into(),
            })
            .and_then(|base| zones::check_owner(&self.trust, claims, &name, base));
        owner.map(|()| zone)
    }

    /// Step 2: the zone and name the record goes to, after the CNAME delegations.
    async fn target(&self, start: usize, name: &Name) -> Result<(usize, Name), Failure> {
        let (mut at, mut current) = (start, name.clone());
        for _ in 0..MAX_CNAME_HOPS {
            let zone = &self.zones[at];
            if !zone.cname_follow {
                return Ok((at, current));
            }
            let servers = zone
                .servers(self.timing.query_timeout)
                .await
                .map_err(Failure::Retry)?;
            let mut answer = None;
            let mut last = String::from("the zone has no server to ask");
            for server in servers {
                match verify::ask(server, &current, self.timing.query_timeout).await {
                    Ok(reply) => {
                        answer = Some(reply);
                        break;
                    }
                    Err(why) => last = format!("{server}: {why}"),
                }
            }
            let reply = answer.ok_or(Failure::Retry(last))?;
            let Some(next) = reply.cname else {
                return Ok((at, current));
            };
            let text = zones::normalize(&next.to_ascii());
            let to = self.zone_of(&text).ok_or_else(|| {
                Failure::Permanent(format!(
                    "no_solver: the CNAME of {} points to {text}, outside every configured zone",
                    current.to_ascii()
                ))
            })?;
            info!(from = %current, to = %next, "following the CNAME of the challenge name");
            (at, current) = (to, next);
        }
        Err(Failure::Permanent(format!(
            "the CNAME chain of {name} is longer than {MAX_CNAME_HOPS}"
        )))
    }

    /// Steps 2 to 4 once.
    async fn attempt(
        &self,
        job: &Job,
        zone: usize,
        challenge: &DnsChallenge,
    ) -> Result<(), Failure> {
        let name = name_of(&zones::normalize(&challenge.name))?;
        let (at, target) = self.target(zone, &name).await?;
        let zone = &self.zones[at];
        // Set before publishing: a publish whose answer is lost may still have happened.
        job.set_target(at, target.clone());
        zone.publish(&target, &challenge.value, true).await?;
        info!(name = %target, zone = %zone.name, "DNS-01 record published; waiting for the authoritative servers");
        let servers = zone
            .servers(self.timing.query_timeout)
            .await
            .map_err(Failure::Retry)?;
        verify::wait_visible(
            &servers,
            &target,
            &challenge.value,
            zone.propagation,
            &self.timing,
            job,
        )
        .await
        .map_err(Failure::Retry)
    }

    async fn present(
        &self,
        job: &Job,
        challenge: &DnsChallenge,
        claims: &Claims,
    ) -> Result<(), DnsError> {
        let _running = job.run.lock().await;
        let zone = self.admit(challenge, claims)?;
        let started = Instant::now();
        let mut backoff = Backoff::new(self.timing.retry_min, self.timing.retry_max);
        loop {
            if job.is_cancelled() {
                return Err(DnsError::Cancelled);
            }
            let why = match self.attempt(job, zone, challenge).await {
                Ok(()) => return Ok(()),
                Err(Failure::Permanent(why)) => return Err(DnsError::Refused(why.into())),
                Err(Failure::Retry(why)) => why,
            };
            if started.elapsed() >= self.timing.give_up {
                return Err(DnsError::GaveUp {
                    secs: started.elapsed().as_secs(),
                    last: why.into(),
                });
            }
            let delay = backoff.next_delay();
            warn!(name = %challenge.name, retry_in_ms = delay.as_millis(), "DNS-01 record not published yet: {why}");
            if !job.nap(delay).await {
                return Err(DnsError::Cancelled);
            }
        }
    }

    async fn cleanup(&self, job: &Job, challenge: &DnsChallenge) {
        let _running = job.run.lock().await;
        let Some((at, target)) = job.target() else {
            return;
        };
        let zone = &self.zones[at];
        let mut backoff = Backoff::new(self.timing.retry_min, self.timing.retry_max);
        for attempt in 1..=CLEANUP_ATTEMPTS {
            match zone.publish(&target, &challenge.value, false).await {
                Ok(()) => {
                    info!(name = %target, "DNS-01 record removed");
                    return;
                }
                Err(Failure::Permanent(why)) => {
                    warn!(name = %target, "DNS-01 record not removed: {why}");
                    return;
                }
                Err(Failure::Retry(why)) if attempt == CLEANUP_ATTEMPTS => {
                    warn!(name = %target, "DNS-01 record not removed after {attempt} attempts: {why}");
                }
                Err(Failure::Retry(_)) => tokio::time::sleep(backoff.next_delay()).await,
            }
        }
    }
}

impl Solver for DnsSolver {
    fn present(
        &self,
        challenge: DnsChallenge,
        claims: Arc<Claims>,
    ) -> SolverFuture<Result<(), SolveError>> {
        // Registered now, not when the future first runs: a `cleanup` that follows in the same
        // batch must find the job and stop it before it publishes.
        let job = self.inner.register(&challenge);
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let outcome = inner.present(&job, &challenge, &claims).await;
            // A record that may be published stays registered, so its `cleanup` removes it.
            if outcome.is_err() && job.target().is_none() {
                inner.forget(&challenge, &job);
            }
            outcome.map_err(|err| SolveError(err.to_string().into()))
        })
    }

    fn cleanup(&self, challenge: DnsChallenge) -> SolverFuture<()> {
        let key = (challenge.name.clone(), challenge.value.clone());
        let job = self.inner.jobs().remove(&key);
        if let Some(job) = &job {
            job.cancel();
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            if let Some(job) = job {
                inner.cleanup(&job, &challenge).await;
            }
        })
    }
}
