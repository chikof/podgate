//! The internal CA: certificates for internal names, from an operator-run CA.
//!
//! Apps with `tls.mode = "internal"` get leaf certificates from a CA the operator runs, instead
//! of ACME. The CA lives in the control-plane program, never in the proxy:
//!
//! - [`init`] makes a root and a name-constrained intermediate (`ca init`). The root key goes to
//!   a path the operator chooses, to be stored offline. The intermediate's key and certificate
//!   are the only CA key material the running provider holds.
//! - [`names`] holds the allowed suffixes, the wildcard switch and the public-suffix check. The
//!   same suffixes are the intermediate's critical `NameConstraints`, so a stolen intermediate
//!   key mints names under them and nowhere else.
//! - [`issue`] signs leaves: ECDSA P-256, `dNSName` only, `serverAuth`, 14 days by default.
//! - [`store`] is the CA directory, the ACME broker's state directory (`0700`, files `0600`,
//!   atomic writes) with three more files; leaves are stored with their keys and written before
//!   they can be pushed.
//! - [`Ca`] joins them: it turns what the merged apps claim ([`Wants`]) into leaves, renews at
//!   two thirds of the lifetime, and publishes the leaves as a [`CaView`] that the merge adds to
//!   the snapshot's `certificates`.
//! - [`trust`] reads the certificates for `ca export-root` and `ca status`; [`cli`] is the
//!   `ca` command.
//!
//! The daemon needs nothing but the `internal` TLS mode: it serves the certificates the snapshot
//! carries and orders nothing. The reference is `docs/ref/internal-ca.md`.

pub mod cli;
pub mod init;
pub mod issue;
pub mod names;
pub mod settings;
pub mod store;
pub mod trust;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podgate_model::{App, Certificate, OcspMode, TlsMode};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use self::issue::{Leaf, Signer};
use self::names::{Policy, SuffixError};
use self::settings::CaSettings;
use self::store::CaStore;
use self::trust::describe;
pub use crate::acme::Secret;
use crate::acme::store::{StoreError, StoredCert};
use crate::config::Config;
use crate::trust::{HostPattern, RouterHosts, Trust};

/// Leaves nobody claims for this long are dropped (7 days).
const PRUNE_AFTER_SECS: i64 = 7 * 86_400;
/// `last_claimed` is refreshed at most this often, so a quiet node does not rewrite the index
/// on every merge.
const CLAIM_REFRESH_SECS: i64 = 3_600;
/// The longest the CA task sleeps without looking at the leaves.
const MAX_SLEEP: Duration = Duration::from_secs(3_600);

/// Why the CA cannot do what was asked.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaError {
    /// The CA directory failed: a full disk, a wrong mode, a corrupt index.
    #[error("the CA directory failed")]
    Store(#[from] StoreError),
    /// The directory has no CA in it.
    #[error("{0} holds no CA: run `podgate-provider ca init` first")]
    NotInitialized(Box<str>),
    /// `ca init` would overwrite a CA.
    #[error("{0} already holds a CA; `ca init` never replaces one")]
    AlreadyInitialized(Box<str>),
    /// A secret file would overwrite an existing file (the root key, a leaf key).
    #[error("{0} already exists: secrets are written to new files only")]
    Exists(Box<str>),
    /// The root key would be written inside the CA directory.
    #[error(
        "{0} is inside the CA directory: the root key must leave the machine, not sit beside the intermediate"
    )]
    RootKeyInStateDir(Box<str>),
    /// The suffix list is not acceptable.
    #[error(transparent)]
    Suffix(#[from] SuffixError),
    /// A certificate or key is not what the CA writes.
    #[error("{what} {reason}")]
    Certificate {
        /// Which one.
        what: &'static str,
        /// What is wrong, never file content.
        reason: Box<str>,
    },
    /// The intermediate has no critical `NameConstraints` with permitted DNS subtrees.
    #[error(
        "the intermediate certificate has no critical NameConstraints with permitted DNS subtrees: an unconstrained intermediate is refused"
    )]
    Unconstrained,
    /// A configured suffix is wider than what the intermediate permits.
    #[error(
        "allowed suffix {suffix:?} is not covered by the intermediate's NameConstraints; the certificate permits only {permitted}"
    )]
    SuffixNotPermitted {
        /// The configured suffix.
        suffix: Box<str>,
        /// What the certificate permits.
        permitted: Box<str>,
    },
    /// The intermediate's validity ended.
    #[error("the intermediate certificate has expired: rotate it with `ca rotate`")]
    IntermediateExpired,
    /// A name the CA will not certify.
    #[error("{0}")]
    NotAllowed(Box<str>),
    /// A key or certificate could not be generated.
    #[error("cannot generate a certificate")]
    Generate(#[from] rcgen::Error),
    /// A time outside what a certificate can hold.
    #[error("{0} is not a time a certificate can hold")]
    Time(i64),
}

/// The unix time in seconds.
#[must_use]
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

pub(crate) fn date_time(unix: i64) -> Result<time::OffsetDateTime, CaError> {
    time::OffsetDateTime::from_unix_timestamp(unix).map_err(|_| CaError::Time(unix))
}

/// The first certificate of `pem`, DER.
pub(crate) fn pem_der(pem: &str) -> Result<Vec<u8>, CaError> {
    x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map(|(_, block)| block.contents)
        .map_err(|_| CaError::Certificate {
            what: "certificate",
            reason: "is not PEM".into(),
        })
}

/// SHA-256 of `der`, as upper-case hex pairs joined by `:`.
pub(crate) fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut text = String::with_capacity(95);
    for (index, byte) in digest.iter().enumerate() {
        if index > 0 {
            text.push(':');
        }
        text.push_str(&format!("{byte:02X}"));
    }
    text
}

/// When a leaf valid from `not_before` to `not_after` is renewed: two thirds of the way.
#[must_use]
pub fn renew_at(not_before: i64, not_after: i64) -> i64 {
    not_before + (not_after - not_before) * 2 / 3
}

/// One app that wants certificates from the CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    /// The app id.
    pub app: Box<str>,
    /// Its tenant.
    pub tenant: Box<str>,
    /// The hosts its routers claim, sorted and distinct.
    pub hosts: Vec<HostPattern>,
}

impl Want {
    fn names(&self) -> Vec<Box<str>> {
        let mut names: Vec<Box<str>> = self
            .hosts
            .iter()
            .map(|host| host.to_string().into())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

/// What the merged apps ask of the CA: the apps with `tls.mode = "internal"` and their hosts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Wants {
    /// One entry per such app, by app id.
    pub apps: Vec<Want>,
}

impl Wants {
    /// The wants of `apps`. An app whose matcher cannot be read claims nothing (the merge dropped
    /// it already).
    #[must_use]
    pub fn of(apps: &[App]) -> Self {
        let mut wanted: Vec<Want> = apps
            .iter()
            .filter(|app| app.tls.mode == TlsMode::Internal)
            .map(|app| {
                let mut hosts: Vec<HostPattern> = app
                    .routers
                    .iter()
                    .filter_map(|router| RouterHosts::of(router).ok())
                    .flat_map(|router| router.hosts)
                    .collect();
                hosts.sort();
                hosts.dedup();
                Want {
                    app: app.id.clone(),
                    tenant: app.tenant.clone(),
                    hosts,
                }
            })
            .collect();
        wanted.sort_by(|a, b| a.app.cmp(&b.app));
        Self { apps: wanted }
    }

    /// Whether an app wants exactly the hosts `hosts`: the leaf for them is current.
    #[must_use]
    pub fn holds(&self, hosts: &[Box<str>]) -> bool {
        let mut sorted = hosts.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        self.apps.iter().any(|want| want.names() == sorted)
    }
}

/// A host the CA refused, for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The app that asked.
    pub app: Box<str>,
    /// The stable code: `internal_name_not_allowed`, `foreign_host_claim`, `unknown_tenant`,
    /// `internal_issue_failed`.
    pub code: &'static str,
    /// Why, in words.
    pub reason: Box<str>,
}

/// What one [`Ca::reconcile`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The apps that got a new leaf.
    pub issued: Vec<Box<str>>,
    /// The apps the CA refused.
    pub refused: Vec<Refusal>,
}

/// The leaves the CA holds: what the merge adds to a snapshot when an app wants exactly their
/// hosts. Changes when a leaf is stored and only then.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaView {
    certificates: Vec<Certificate>,
}

impl CaView {
    /// No CA: no certificates.
    #[must_use]
    pub fn off() -> Self {
        Self::default()
    }

    /// The leaves, chain first. The merge adds those an app wants.
    #[must_use]
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }
}

struct Held {
    stored: StoredCert,
    not_before: i64,
    not_after: i64,
}

impl Held {
    fn renew_at(&self) -> i64 {
        renew_at(self.not_before, self.not_after)
    }
}

/// The opened CA: the intermediate, the policy and the stored leaves.
pub struct Ca {
    store: CaStore,
    signer: Signer,
    policy: Policy,
    trust: Trust,
    leaf_days: u32,
    leaves: Vec<Held>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("signer", &self.signer)
            .field("policy", &self.policy)
            .field("leaves", &self.leaves.len())
            .finish_non_exhaustive()
    }
}

impl Ca {
    /// Opens the CA directory of `settings` and loads its leaves.
    ///
    /// The configured suffixes must all lie inside what the intermediate permits: the provider
    /// never tries to issue what the certificate would not allow.
    ///
    /// # Errors
    ///
    /// [`CaError`] when the directory is not initialized, not private, or the intermediate does
    /// not match its key, is unconstrained, or permits less than the configuration lists.
    pub fn open(settings: &CaSettings, config: &Config) -> Result<Self, CaError> {
        let store = CaStore::open_existing(&settings.dir)?
            .filter(|store| store.is_initialized().unwrap_or(false))
            .ok_or_else(|| CaError::NotInitialized(settings.dir.display().to_string().into()))?;
        store.clean_orphans()?;
        let signer = Signer::from_pem(&store.intermediate_cert()?, &store.intermediate_key()?)?;
        let permitted: Vec<names::Suffix> = signer
            .permitted()
            .iter()
            .filter_map(|text| names::Suffix::parse(text).ok())
            .collect();
        for suffix in &settings.allowed_suffixes {
            if !permitted
                .iter()
                .any(|allowed| allowed.covers(suffix.as_str()))
            {
                return Err(CaError::SuffixNotPermitted {
                    suffix: suffix.as_str().into(),
                    permitted: signer.permitted().join(", ").into(),
                });
            }
        }
        let mut leaves = Vec::new();
        for stored in store.leaves()? {
            let info = describe(&stored.cert_pem)?;
            leaves.push(Held {
                stored,
                not_before: info.not_before,
                not_after: info.not_after,
            });
        }
        Ok(Self {
            store,
            signer,
            policy: settings.policy(),
            trust: Trust::new(config),
            leaf_days: settings.leaf_days,
            leaves,
        })
    }

    /// Signs a leaf for `names` that the operator asked for (`ca issue`), under the same policy
    /// as the provider's own: the suffixes and the wildcard switch. It is not stored.
    ///
    /// # Errors
    ///
    /// [`CaError::NotAllowed`] for a name the policy refuses, [`CaError`] when signing fails.
    pub fn issue(&self, names: &[&str], now: i64, days: u32) -> Result<Leaf, CaError> {
        for name in names {
            let pattern = HostPattern::parse(name).map_err(|err| {
                CaError::NotAllowed(format!("{:?} is not a host name", err.0).into())
            })?;
            if let Some(why) = self.policy.refusal(&pattern) {
                return Err(CaError::NotAllowed(why.into()));
            }
        }
        self.signer
            .issue_unchecked(names, now, days.min(settings::MAX_LEAF_DAYS))
    }

    /// The names this CA certifies.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Issues what `wants` lacks or what reached two thirds of its life, and stores each leaf
    /// before it joins [`Self::view`].
    ///
    /// A host the CA may not certify (outside the suffixes, a wildcard without the switch, or a
    /// host the app's tenant does not own) gets no leaf and a [`Refusal`]: one bad host refuses
    /// the app's whole leaf, since a leaf holds all of an app's names.
    ///
    /// # Errors
    ///
    /// [`CaError::Store`] when the directory cannot be written. The leaves stored so far stay;
    /// the one that failed is not in the view.
    pub fn reconcile(&mut self, wants: &Wants, now: i64) -> Result<Report, CaError> {
        let mut report = Report::default();
        let mut claimed: Vec<u64> = Vec::new();
        for want in &wants.apps {
            let names = want.names();
            if names.is_empty() {
                continue;
            }
            if let Some(refusal) = self.refuse(want) {
                warn!(app = %want.app, code = refusal.code, "{}", refusal.reason);
                report.refused.push(refusal);
                continue;
            }
            let current = self
                .leaves
                .iter()
                .find(|held| held.stored.hosts == names && now < held.renew_at());
            if let Some(held) = current {
                claimed.push(held.stored.id);
                continue;
            }
            let hosts: Vec<&str> = names.iter().map(AsRef::as_ref).collect();
            let leaf = match self.signer.issue_unchecked(&hosts, now, self.leaf_days) {
                Ok(leaf) => leaf,
                Err(err) => {
                    error!(app = %want.app, "no leaf issued: {err}");
                    report.refused.push(Refusal {
                        app: want.app.clone(),
                        code: "internal_issue_failed",
                        reason: err.to_string().into(),
                    });
                    continue;
                }
            };
            let stored = self.store.put_leaf(
                &names,
                &leaf.chain_pem,
                &leaf.key,
                u64::try_from(now).unwrap_or(0),
            )?;
            info!(app = %want.app, hosts = ?stored.hosts, "internal certificate issued");
            self.leaves.retain(|held| {
                !held
                    .stored
                    .hosts
                    .iter()
                    .all(|host| stored.hosts.contains(host))
            });
            claimed.push(stored.id);
            self.leaves.push(Held {
                stored,
                not_before: leaf.not_before,
                not_after: leaf.not_after,
            });
            report.issued.push(want.app.clone());
        }
        self.note_claims(&claimed, now)?;
        Ok(report)
    }

    fn refuse(&self, want: &Want) -> Option<Refusal> {
        let refused = |code: &'static str, reason: String| {
            Some(Refusal {
                app: want.app.clone(),
                code,
                reason: reason.into(),
            })
        };
        for host in &want.hosts {
            if let Some(why) = self.policy.refusal(host) {
                return refused(names::NOT_ALLOWED, why);
            }
        }
        let tenant = match self.trust.lookup(&want.tenant) {
            Ok(tenant) => tenant,
            Err(problem) => return refused(problem.code, problem.message.into()),
        };
        for host in &want.hosts {
            if let Err(problem) = self.trust.check_host(tenant, host) {
                return refused(problem.code, problem.message.into());
            }
        }
        None
    }

    /// Marks the leaves an app claimed and drops those nobody claimed for a week.
    fn note_claims(&mut self, claimed: &[u64], now: i64) -> Result<(), CaError> {
        let unix = u64::try_from(now).unwrap_or(0);
        let stale: Vec<u64> = self
            .leaves
            .iter()
            .filter(|held| {
                claimed.contains(&held.stored.id)
                    && now - i64::try_from(held.stored.last_claimed).unwrap_or(0)
                        >= CLAIM_REFRESH_SECS
            })
            .map(|held| held.stored.id)
            .collect();
        if !stale.is_empty() {
            self.store.touch(&stale, unix)?;
            for held in &mut self.leaves {
                if stale.contains(&held.stored.id) {
                    held.stored.last_claimed = unix;
                }
            }
        }
        for hosts in self.store.prune(unix, PRUNE_AFTER_SECS.unsigned_abs())? {
            info!(hosts = ?hosts, "internal certificate dropped: no app has wanted its hosts for 7 days");
            self.leaves.retain(|held| held.stored.hosts != hosts);
        }
        Ok(())
    }

    /// The leaves that are still valid, as certificates.
    #[must_use]
    pub fn view(&self, now: i64) -> CaView {
        let mut certificates: Vec<Certificate> = self
            .leaves
            .iter()
            .filter(|held| held.not_after > now)
            .map(|held| Certificate {
                hosts: held.stored.hosts.clone(),
                cert_pem: held.stored.cert_pem.clone(),
                key_pem: held.stored.key_pem.expose().to_owned(),
                default: false,
                ocsp: OcspMode::Auto,
            })
            .collect();
        certificates.sort_by(|a, b| a.hosts.cmp(&b.hosts));
        CaView { certificates }
    }

    /// The next time a leaf of `wants` is due for renewal, unix seconds.
    #[must_use]
    pub fn next_renewal(&self, wants: &Wants) -> Option<i64> {
        self.leaves
            .iter()
            .filter(|held| wants.holds(&held.stored.hosts))
            .map(Held::renew_at)
            .min()
    }
}

/// A running CA: what the engine holds.
#[derive(Debug)]
pub struct Handle {
    /// The leaves to merge into the snapshot.
    pub view: watch::Receiver<Arc<CaView>>,
    /// Where the engine publishes what the merged apps want.
    pub wants: watch::Sender<Option<Arc<Wants>>>,
    /// Ends with the error that stopped the CA, or never.
    pub task: JoinHandle<Result<(), CaError>>,
}

/// Opens the CA and starts its task on the current runtime. The view holds the stored leaves from
/// the first moment, so a restart re-pushes them before any app is looked at.
///
/// # Errors
///
/// [`CaError`] from [`Ca::open`].
pub fn start(settings: &CaSettings, config: &Config) -> Result<Handle, CaError> {
    let ca = Ca::open(settings, config)?;
    let (view_tx, view_rx) = watch::channel(Arc::new(ca.view(unix_now())));
    let (wants_tx, wants_rx) = watch::channel(None);
    let task = tokio::spawn(run(ca, wants_rx, view_tx));
    Ok(Handle {
        view: view_rx,
        wants: wants_tx,
        task,
    })
}

async fn run(
    mut ca: Ca,
    mut wants: watch::Receiver<Option<Arc<Wants>>>,
    view: watch::Sender<Arc<CaView>>,
) -> Result<(), CaError> {
    loop {
        let current = wants.borrow_and_update().clone();
        let mut sleep = MAX_SLEEP;
        if let Some(current) = &current {
            let now = unix_now();
            let outcome = ca.reconcile(current, now);
            // What was stored before a failure is already consistent: publish it, then stop.
            view.send_if_modified(|shown| {
                let next = ca.view(now);
                let changed = **shown != next;
                if changed {
                    *shown = Arc::new(next);
                }
                changed
            });
            outcome?;
            if let Some(at) = ca.next_renewal(current) {
                let wait = u64::try_from(at.saturating_sub(now)).unwrap_or(0);
                sleep = sleep.min(Duration::from_secs(wait.max(1)));
            }
        }
        tokio::select! {
            changed = wants.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
            }
            () = tokio::time::sleep(sleep) => {}
        }
    }
}

/// The view `print` and `check` use: the leaves the directory holds, read without creating or
/// changing anything. A directory that does not exist yet holds none.
///
/// # Errors
///
/// [`CaError::Store`] when the directory exists but cannot be read, [`CaError::Certificate`]
/// when a stored leaf is not a certificate.
pub fn offline_view(settings: &CaSettings) -> Result<CaView, CaError> {
    let Some(store) = CaStore::open_existing(&settings.dir)? else {
        return Ok(CaView::off());
    };
    let now = unix_now();
    let mut certificates = Vec::new();
    for stored in store.leaves()? {
        if describe(&stored.cert_pem)?.not_after > now {
            certificates.push(Certificate {
                hosts: stored.hosts,
                cert_pem: stored.cert_pem,
                key_pem: stored.key_pem.expose().to_owned(),
                default: false,
                ocsp: OcspMode::Auto,
            });
        }
    }
    certificates.sort_by(|a, b| a.hosts.cmp(&b.hosts));
    Ok(CaView { certificates })
}
