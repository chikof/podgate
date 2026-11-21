//! The ACME broker: what turns podgate's ACME events into certificates in its snapshot.
//!
//! podgate keeps no state and never calls the control plane (`docs/architecture.md`,
//! `## ACME and on-demand TLS`): an issuer node emits `acme_challenge`, `certificate_issued` and
//! `certificate_requested` on its event feed, and only orders what the snapshot lets it. On a
//! node whose writer is `podgate-provider`, this module is the control plane's half:
//!
//! - [`events`] polls `GET /v1/events` with a stored cursor, parses the feed and runs the loop.
//! - [`Broker`] is the state machine behind it: the certificates, the challenge answers, the
//!   DNS-01 records, the approvals and the cursor. Every certificate is written to [`store`]
//!   before it can appear in a [`BrokerView`].
//! - [`approve`] decides on-demand requests under the tenant trust rule and its limits.
//! - [`settings`] is the `[acme]` configuration section.
//! - [`dns`] publishes DNS-01 records (RFC 2136 or a webhook) for the broker's solver hook.
//!
//! The engine reads the [`BrokerView`] (a `tokio::sync::watch` value) when it merges, and
//! publishes [`Claims`] (what the merged apps claim) for the broker's approvals and pruning. The
//! reference is `docs/ref/provider-acme.md`.

pub mod approve;
pub mod dns;
pub mod events;
mod follower;
pub mod settings;
pub mod store;

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use podgate_model::{Acme, App, Certificate, Challenge, DnsReady, ExternalAccount, TlsMode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use self::approve::{Approval, Approver, Decision};
use self::events::{DnsChallenge, Event, Item, Proof, Solver};
use self::settings::{AcmeSettings, Mode};
use self::store::{Store, StoreError, StoredCert, read_secret_file};
use crate::config::Config;
use crate::push::{AdminClient, Tuning};
use crate::trust::{HostPattern, RouterHosts, Trust};

/// How long an unanswered HTTP-01 or TLS-ALPN-01 answer stays in the snapshot.
const CHALLENGE_TTL_MS: u64 = 1_800_000;
/// Answers held at once; the oldest go first. podgate accepts at most 1024 TLS-ALPN-01 names.
const MAX_CHALLENGES: usize = 512;
/// Requests kept until the engine has published its first claims.
const MAX_AWAITING: usize = 256;
/// Certificates nobody claims for this long are dropped (30 days).
const PRUNE_AFTER_SECS: u64 = 30 * 86_400;
/// `last_claimed` is refreshed at most this often (seconds), so a busy node does not rewrite
/// the index on every merge.
const CLAIM_REFRESH_SECS: u64 = 3_600;

/// A secret string: private keys and the EAB key. `Debug` shows `[redacted]`; there is no
/// `Display`. Read it only where it goes to disk or into a snapshot.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Box<str>);

impl Secret {
    /// Wraps `text`.
    #[must_use]
    pub fn new(text: impl Into<Box<str>>) -> Self {
        Self(text.into())
    }

    /// The text. Do not log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// Why the broker stopped.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrokerError {
    /// The state directory failed. The last pushed state stays; nothing that could not be
    /// persisted is pushed.
    #[error("the ACME state directory failed")]
    Store(#[from] StoreError),
}

/// What the merged apps claim: the broker's view of the routing, for approvals and pruning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims {
    /// Every app of the merged snapshot.
    pub apps: Vec<ClaimedApp>,
}

/// One app's claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedApp {
    /// The app id.
    pub app: Box<str>,
    /// Its tenant.
    pub tenant: Box<str>,
    /// Whether it asks for certificates at the first handshake (`tls.mode = on_demand`).
    pub on_demand: bool,
    /// The hosts of its routers.
    pub hosts: Vec<HostPattern>,
}

impl Claims {
    /// The claims of `apps`. An app whose matcher cannot be read claims nothing (the merge
    /// dropped it already).
    #[must_use]
    pub fn of(apps: &[App]) -> Self {
        let mut claimed: Vec<ClaimedApp> = apps
            .iter()
            .map(|app| {
                let mut hosts: Vec<HostPattern> = app
                    .routers
                    .iter()
                    .filter_map(|router| RouterHosts::of(router).ok())
                    .flat_map(|router| router.hosts)
                    .collect();
                hosts.sort();
                hosts.dedup();
                ClaimedApp {
                    app: app.id.clone(),
                    tenant: app.tenant.clone(),
                    on_demand: app.tls.mode == TlsMode::OnDemand,
                    hosts,
                }
            })
            .collect();
        claimed.sort_by(|a, b| a.app.cmp(&b.app));
        Self { apps: claimed }
    }

    /// Whether an app claims a host that `pattern` covers or lies inside.
    #[must_use]
    pub fn claims(&self, pattern: &HostPattern) -> bool {
        self.apps
            .iter()
            .any(|app| app.hosts.iter().any(|host| host.overlaps(pattern)))
    }
}

/// The settings that stay the same while the broker runs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Base {
    issuer_node: Box<str>,
    directory_url: Box<str>,
    contact: Vec<String>,
    eab: Option<(Box<str>, Secret)>,
    account_key: Option<Secret>,
}

/// What the broker adds to a snapshot: certificates, and the `acme` object. Changes when the
/// broker's state changes and only then.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrokerView {
    base: Option<Base>,
    certificates: Vec<Certificate>,
    challenges: Vec<Challenge>,
    requested_hosts: Vec<Box<str>>,
    dns_ready: Vec<DnsReady>,
    /// Counts the events that make the engine check the live snapshot at once: podgate's boot
    /// id changed, or the feed lost events.
    epoch: u64,
}

impl BrokerView {
    /// No ACME: no certificates, no `acme` object.
    #[must_use]
    pub fn off() -> Self {
        Self::default()
    }

    /// The certificates the broker holds. The merge adds those an app claims.
    #[must_use]
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    /// The `acme` object of the snapshot, `None` when ACME is off.
    #[must_use]
    pub fn acme(&self) -> Option<Acme> {
        let base = self.base.as_ref()?;
        Some(Acme {
            issuer_node: base.issuer_node.clone(),
            directory_url: base.directory_url.to_string(),
            contact: base.contact.clone(),
            eab: base.eab.as_ref().map(|(key_id, hmac)| ExternalAccount {
                key_id: key_id.to_string(),
                hmac_key: hmac.expose().to_owned(),
            }),
            account_key_pem: base.account_key.as_ref().map(|key| key.expose().to_owned()),
            challenges: self.challenges.clone(),
            requested_hosts: self.requested_hosts.clone(),
            dns_ready: self.dns_ready.clone(),
        })
    }

    /// The count that tells the engine to look at the live snapshot now.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Where the event feed stood when the broker last looked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The feed's `boot_id`; sequence numbers restart when it changes.
    pub boot_id: Option<Box<str>>,
    /// The last sequence number processed.
    pub after: u64,
}

/// One answer the broker holds, as the state directory keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    /// HTTP-01 token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<Box<str>>,
    /// TLS-ALPN-01 host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Box<str>>,
    /// The key authorization to answer with.
    pub key_authorization: Box<str>,
    /// When it arrived (unix milliseconds).
    pub added_ms: u64,
}

impl Held {
    fn challenge(&self) -> Challenge {
        Challenge {
            token: self.token.clone(),
            name: self.name.clone(),
            key_authorization: self.key_authorization.clone(),
        }
    }

    fn same(&self, other: &Self) -> bool {
        self.token == other.token
            && self.name == other.name
            && self.key_authorization == other.key_authorization
    }
}

/// The shared file of answers: a follower reads it.
pub(crate) const CHALLENGES: &str = "challenges.json";
const CURSOR: &str = "cursor.json";
const APPROVALS: &str = "approvals.json";

/// What `apply` hands back to the loop: work for the DNS solver.
#[derive(Debug, Default)]
pub struct Applied {
    /// DNS-01 records to publish.
    pub solve: Vec<DnsChallenge>,
    /// DNS-01 records to remove.
    pub cleanup: Vec<DnsChallenge>,
}

/// The broker's state.
pub struct Broker {
    store: Store,
    approver: Approver,
    base: Base,
    lead_ms: u64,
    certs: Vec<StoredCert>,
    held: Vec<Held>,
    dns_ready: BTreeSet<(Box<str>, Box<str>)>,
    dns_open: BTreeSet<(Box<str>, Box<str>)>,
    awaiting: Vec<Box<str>>,
    cursor: Cursor,
    epoch: u64,
    last_prune: u64,
}

impl fmt::Debug for Broker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Broker")
            .field("certs", &self.certs.len())
            .field("held", &self.held.len())
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

/// The unix time in milliseconds. `0` before 1970, which cannot happen.
#[must_use]
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The account key to put in the snapshot: the operator's file, else the one the broker made.
/// With `create`, a missing key is generated and kept in `store`.
fn account_key(
    settings: &AcmeSettings,
    store: Option<&Store>,
    create: bool,
) -> Result<Option<Secret>, StoreError> {
    if settings.eab.is_some() {
        return Ok(None);
    }
    if let Some(path) = &settings.account_key_file {
        return read_secret_file(path).map(Some);
    }
    let Some(store) = store else {
        return Ok(None);
    };
    if let Some(key) = store.account_key()? {
        return Ok(Some(key));
    }
    if !create {
        return Ok(None);
    }
    let key = Secret::new(
        rcgen::KeyPair::generate()
            .map_err(|_| StoreError::Corrupt {
                path: "account.key".into(),
                reason: "cannot generate an account key".into(),
            })?
            .serialize_pem(),
    );
    store.save_account_key(&key)?;
    Ok(Some(key))
}

fn base_of(settings: &AcmeSettings, account_key: Option<Secret>) -> Result<Base, StoreError> {
    let eab = match &settings.eab {
        Some(eab) => Some((eab.key_id.clone(), read_secret_file(&eab.hmac_key_file)?)),
        None => None,
    };
    Ok(Base {
        issuer_node: settings.issuer_node.clone(),
        directory_url: settings.directory_url.clone(),
        contact: settings.contact.clone(),
        eab,
        account_key,
    })
}

fn certificate_of(cert: &StoredCert) -> Certificate {
    Certificate {
        hosts: cert.hosts.clone(),
        cert_pem: cert.cert_pem.clone(),
        key_pem: cert.key_pem.expose().to_owned(),
        default: false,
        ocsp: podgate_model::OcspMode::Auto,
    }
}

impl Broker {
    /// Opens the state directory (creating it), loads what is kept, and makes the account key
    /// when there is none.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the directory is not private or cannot be read or written.
    pub fn open(settings: &AcmeSettings, config: &Config) -> Result<Self, StoreError> {
        let store = Store::create(&settings.state_dir)?;
        store.clean_orphans()?;
        let certs = store.certs()?;
        let held: Vec<Held> = store.read_json(CHALLENGES)?.unwrap_or_default();
        let approvals: Vec<Approval> = store.read_json(APPROVALS)?.unwrap_or_default();
        let cursor: Cursor = store.read_json(CURSOR)?.unwrap_or_default();
        let key = account_key(settings, Some(&store), true)?;
        let base = base_of(settings, key)?;
        Ok(Self {
            approver: Approver::new(settings.on_demand, Trust::new(config), approvals),
            store,
            base,
            lead_ms: u64::try_from(settings.challenge_lead.as_millis()).unwrap_or(u64::MAX),
            certs,
            held,
            dns_ready: BTreeSet::new(),
            dns_open: BTreeSet::new(),
            awaiting: Vec::new(),
            cursor,
            epoch: 0,
            last_prune: 0,
        })
    }

    /// Where the feed was left: the broker polls with `after`.
    #[must_use]
    pub fn cursor(&self) -> &Cursor {
        &self.cursor
    }

    /// What goes into the snapshot now. Answers still inside their lead time are left out.
    #[must_use]
    pub fn view(&self, now_ms: u64) -> BrokerView {
        let mut challenges: Vec<Challenge> = self
            .held
            .iter()
            .filter(|held| now_ms >= held.added_ms.saturating_add(self.lead_ms))
            .map(Held::challenge)
            .collect();
        challenges.sort_by(|a, b| {
            (&a.token, &a.name, &a.key_authorization).cmp(&(
                &b.token,
                &b.name,
                &b.key_authorization,
            ))
        });
        let mut certificates: Vec<Certificate> = self.certs.iter().map(certificate_of).collect();
        certificates.sort_by(|a, b| a.hosts.cmp(&b.hosts));
        BrokerView {
            base: Some(self.base.clone()),
            certificates,
            challenges,
            requested_hosts: self.approver.open_hosts(),
            dns_ready: self
                .dns_ready
                .iter()
                .map(|(name, value)| DnsReady {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect(),
            epoch: self.epoch,
        }
    }

    /// The next time `view` changes by itself: an answer leaves its lead time, or one expires.
    #[must_use]
    pub fn next_wake(&self, now_ms: u64) -> Option<u64> {
        self.held
            .iter()
            .flat_map(|held| {
                [
                    held.added_ms.saturating_add(self.lead_ms),
                    held.added_ms.saturating_add(CHALLENGE_TTL_MS),
                ]
            })
            .filter(|at| *at > now_ms)
            .min()
    }

    fn write_held(&self) -> Result<(), StoreError> {
        self.store.write_json(CHALLENGES, &self.held)
    }

    fn write_approvals(&self) -> Result<(), StoreError> {
        self.store.write_json(APPROVALS, &self.approver.records())
    }

    fn write_cursor(&self) -> Result<(), StoreError> {
        self.store.write_json(CURSOR, &self.cursor)
    }

    /// Applies one batch of feed items, in order. `last_seq` is the highest sequence number of
    /// the batch, including events the broker does not act on.
    ///
    /// A certificate is written to the state directory before it joins the view; when that
    /// fails the error is returned, the certificate is not in the view, and the cursor does not
    /// move past it.
    ///
    /// # Errors
    ///
    /// [`StoreError`] from the state directory.
    pub fn apply(
        &mut self,
        items: &[Item],
        last_seq: u64,
        claims: Option<&Claims>,
        now_ms: u64,
    ) -> Result<Applied, StoreError> {
        let mut applied = Applied::default();
        let (mut held_changed, mut approvals_changed) = (false, false);
        for item in items {
            match &item.event {
                Ok(Some(Event::Challenge(proof))) => {
                    held_changed |= self.add_challenge(proof, now_ms, &mut applied);
                }
                Ok(Some(Event::ChallengeDone(proof))) => {
                    held_changed |= self.finish_challenge(proof, &mut applied);
                }
                Ok(Some(Event::Issued {
                    hosts,
                    cert_pem,
                    key_pem,
                })) => {
                    self.store_certificate(hosts, cert_pem, key_pem, now_ms)?;
                    approvals_changed |= self.release(hosts);
                    held_changed |= self.drop_answers_for(hosts);
                }
                Ok(Some(Event::Requested { host })) => {
                    approvals_changed |= self.request(host, claims, now_ms);
                }
                Ok(None) => {}
                Err(problem) => {
                    tracing::error!(seq = item.seq, "{problem}; the event is skipped");
                }
            }
        }
        if held_changed {
            self.write_held()?;
        }
        if approvals_changed {
            self.write_approvals()?;
        }
        if last_seq > self.cursor.after {
            self.cursor.after = last_seq;
            self.write_cursor()?;
        }
        Ok(applied)
    }

    fn add_challenge(&mut self, proof: &Proof, now_ms: u64, applied: &mut Applied) -> bool {
        let held = match proof {
            Proof::Http01 {
                token,
                key_authorization,
            } => Held {
                token: Some(token.clone()),
                name: None,
                key_authorization: key_authorization.clone(),
                added_ms: now_ms,
            },
            Proof::TlsAlpn01 {
                name,
                key_authorization,
            } => Held {
                token: None,
                name: Some(name.clone()),
                key_authorization: key_authorization.clone(),
                added_ms: now_ms,
            },
            Proof::Dns01 { name, value } => {
                let record = DnsChallenge {
                    name: name.clone(),
                    value: value.clone(),
                };
                if self.dns_open.insert((name.clone(), value.clone())) {
                    applied.solve.push(record);
                }
                return false;
            }
        };
        if self.held.iter().any(|known| known.same(&held)) {
            return false;
        }
        self.held.push(held);
        if self.held.len() > MAX_CHALLENGES {
            let excess = self.held.len() - MAX_CHALLENGES;
            self.held.drain(..excess);
        }
        true
    }

    fn finish_challenge(&mut self, proof: &Proof, applied: &mut Applied) -> bool {
        match proof {
            Proof::Dns01 { name, value } => {
                let key = (name.clone(), value.clone());
                self.dns_ready.remove(&key);
                if self.dns_open.remove(&key) {
                    applied.cleanup.push(DnsChallenge {
                        name: name.clone(),
                        value: value.clone(),
                    });
                }
                false
            }
            Proof::Http01 { token, .. } => {
                let before = self.held.len();
                self.held.retain(|held| held.token.as_ref() != Some(token));
                self.held.len() != before
            }
            Proof::TlsAlpn01 { name, .. } => {
                let before = self.held.len();
                self.held.retain(|held| held.name.as_ref() != Some(name));
                self.held.len() != before
            }
        }
    }

    /// Persists a certificate and only then adds it to what the view shows.
    fn store_certificate(
        &mut self,
        hosts: &[Box<str>],
        cert_pem: &str,
        key_pem: &Secret,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let stored = self
            .store
            .put_cert(hosts, cert_pem, key_pem, now_ms / 1000)?;
        self.certs
            .retain(|cert| !cert.hosts.iter().all(|host| stored.hosts.contains(host)));
        tracing::info!(hosts = ?stored.hosts, "certificate stored");
        self.certs.push(stored);
        Ok(())
    }

    fn release(&mut self, hosts: &[Box<str>]) -> bool {
        hosts
            .iter()
            .fold(false, |changed, host| self.approver.release(host) | changed)
    }

    fn drop_answers_for(&mut self, hosts: &[Box<str>]) -> bool {
        let before = self.held.len();
        self.held
            .retain(|held| held.name.as_ref().is_none_or(|name| !hosts.contains(name)));
        self.held.len() != before
    }

    fn request(&mut self, host: &str, claims: Option<&Claims>, now_ms: u64) -> bool {
        let Some(claims) = claims else {
            if self.awaiting.len() < MAX_AWAITING && !self.awaiting.iter().any(|h| **h == *host) {
                self.awaiting.push(host.into());
            }
            return false;
        };
        match self.approver.decide(host, claims, now_ms) {
            Decision::Approved { tenant } => {
                tracing::info!(host, tenant = %tenant, "on-demand certificate approved");
                true
            }
            Decision::Refused(why) => {
                tracing::warn!(host, "on-demand certificate not approved: {why}");
                false
            }
        }
    }

    /// The engine published new claims: decide the requests that waited for them, and note
    /// which stored certificates an app claims.
    ///
    /// # Errors
    ///
    /// [`StoreError`] from the state directory.
    pub fn claims_changed(&mut self, claims: &Claims, now_ms: u64) -> Result<(), StoreError> {
        let mut approvals_changed = false;
        for host in std::mem::take(&mut self.awaiting) {
            approvals_changed |= self.request(&host, Some(claims), now_ms);
        }
        if approvals_changed {
            self.write_approvals()?;
        }
        let now = now_ms / 1000;
        let claimed: Vec<u64> = self
            .certs
            .iter()
            .filter(|cert| {
                now.saturating_sub(cert.last_claimed) >= CLAIM_REFRESH_SECS
                    && cert
                        .hosts
                        .iter()
                        .filter_map(|host| HostPattern::parse(host).ok())
                        .any(|pattern| claims.claims(&pattern))
            })
            .map(|cert| cert.id)
            .collect();
        if !claimed.is_empty() {
            self.store.touch_claimed(&claimed, now)?;
            for cert in &mut self.certs {
                if claimed.contains(&cert.id) {
                    cert.last_claimed = now;
                }
            }
        }
        Ok(())
    }

    /// Time passed: expire answers and approvals, drop certificates nobody claims.
    ///
    /// # Errors
    ///
    /// [`StoreError`] from the state directory.
    pub fn tick(&mut self, now_ms: u64) -> Result<(), StoreError> {
        let before = self.held.len();
        self.held
            .retain(|held| now_ms.saturating_sub(held.added_ms) < CHALLENGE_TTL_MS);
        if self.held.len() != before {
            self.write_held()?;
        }
        if self.approver.expire(now_ms) {
            self.write_approvals()?;
        }
        let now = now_ms / 1000;
        if now.saturating_sub(self.last_prune) >= CLAIM_REFRESH_SECS {
            self.last_prune = now;
            for hosts in self.store.prune(now, PRUNE_AFTER_SECS)? {
                tracing::info!(hosts = ?hosts, "certificate dropped: no app has claimed its hosts for 30 days");
                self.certs.retain(|cert| cert.hosts != hosts);
            }
        }
        Ok(())
    }

    /// DNS-01 record `challenge` is visible on the authoritative servers: tell podgate. Ignored
    /// when its challenge ended meanwhile.
    pub fn dns_visible(&mut self, challenge: &DnsChallenge) -> bool {
        let key = (challenge.name.clone(), challenge.value.clone());
        self.dns_open.contains(&key) && self.dns_ready.insert(key)
    }

    /// The feed's `boot_id` changed: podgate restarted, its orders are gone and its sequence
    /// numbers start again. Stale answers go; certificates and approvals stay.
    ///
    /// # Errors
    ///
    /// [`StoreError`] from the state directory.
    pub fn restarted(&mut self, boot_id: &str) -> Result<(), StoreError> {
        self.cursor = Cursor {
            boot_id: Some(boot_id.into()),
            after: 0,
        };
        self.held.clear();
        self.dns_ready.clear();
        self.dns_open.clear();
        self.epoch += 1;
        self.write_held()?;
        self.write_cursor()
    }

    /// The first boot id this broker sees.
    ///
    /// # Errors
    ///
    /// [`StoreError`] from the state directory.
    pub fn adopt_boot(&mut self, boot_id: &str) -> Result<(), StoreError> {
        self.cursor.boot_id = Some(boot_id.into());
        self.write_cursor()
    }

    /// The feed lost events up to `oldest`: continue from there and make the engine check the
    /// live snapshot.
    ///
    /// # Errors
    ///
    /// [`StoreError`] from the state directory.
    pub fn lost_events(&mut self, oldest: u64) -> Result<(), StoreError> {
        self.cursor.after = oldest.saturating_sub(1);
        self.epoch += 1;
        self.write_cursor()
    }
}

/// A running broker or follower: what the engine holds.
#[derive(Debug)]
pub struct Handle {
    /// The view to merge into the snapshot.
    pub view: watch::Receiver<Arc<BrokerView>>,
    /// Where the engine publishes what the merged apps claim.
    pub claims: watch::Sender<Option<Arc<Claims>>>,
    /// Ends with the error that stopped the broker, or never.
    pub task: JoinHandle<Result<(), BrokerError>>,
}

/// Starts the broker or the follower of `settings` on the current runtime.
///
/// # Errors
///
/// [`BrokerError`] when the state directory cannot be opened.
pub fn start(
    settings: &AcmeSettings,
    config: &Config,
    client: AdminClient,
    tuning: Tuning,
    solver: Arc<dyn Solver>,
) -> Result<Handle, BrokerError> {
    let (claims_tx, claims_rx) = watch::channel(None);
    let (view_tx, view_rx) = match settings.mode {
        Mode::Broker => {
            let broker = Broker::open(settings, config)?;
            let (view_tx, view_rx) = watch::channel(Arc::new(broker.view(unix_ms())));
            let task = tokio::spawn(events::run(
                broker, client, tuning, solver, claims_rx, view_tx,
            ));
            return Ok(Handle {
                view: view_rx,
                claims: claims_tx,
                task,
            });
        }
        Mode::Follower => {
            let first = follower::load(settings)?;
            watch::channel(Arc::new(first))
        }
    };
    let task = tokio::spawn(follower::run(settings.clone(), view_tx));
    Ok(Handle {
        view: view_rx,
        claims: claims_tx,
        task,
    })
}

/// The view `print` and `check` use: what the state directory holds, read without creating or
/// changing anything.
///
/// # Errors
///
/// [`StoreError`] when the directory exists but cannot be read.
pub fn offline_view(settings: &AcmeSettings) -> Result<BrokerView, StoreError> {
    follower::load_with(settings, settings.mode == Mode::Broker)
}
