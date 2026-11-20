//! The issuer: on the node named by `acme.issuer_node`, a background loop that orders
//! certificates for hosts that lack one, renews the ones that are due, and reports through the
//! event feed. Every other node's loop does nothing.
//!
//! The loop wakes every [`TICK`] and reads the live
//! table, so it is stateless against the control plane: whatever the snapshot says is missing or
//! due gets an order. In-memory state only avoids repeating work:
//!
//! - [`Gate`]: after an order ends the same job waits, [`ISSUED_GRACE`] after success (the
//!   control plane has not pushed the certificate yet) and an exponential backoff after failure.
//! - [`Sched`]: the renewal time of each served certificate, from its ARI window.
//! - at most [`MAX_ORDERS`] orders run at once, each as its own task.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use instant_acme::{
    Account, AuthorizationStatus, CertificateIdentifier, ChallengeType, Error as AcmeError,
    ExternalAccountKey, Identifier, Key, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;
use tokio::task::{Id, JoinSet};
use tokio::time::{MissedTickBehavior, sleep, timeout};

use super::plan::{CertInfo, Plan, decode_hmac_key};
use super::{Acme, PrivateKeyPem};
use crate::events::{EventFeed, EventKind};
use crate::snapshot::{self, ExternalAccount};
use crate::table::TableHandle;

/// How often the loop looks at the table.
const TICK: Duration = Duration::from_secs(1);
/// Orders running at once.
const MAX_ORDERS: usize = 8;
/// How long an order waits for the control plane to publish its challenges.
const CHALLENGE_WAIT: Duration = Duration::from_secs(300);
/// An order's whole budget, including [`CHALLENGE_WAIT`].
const ORDER_DEADLINE: Duration = Duration::from_secs(600);
/// How long account creation may take.
const ACCOUNT_TIMEOUT: Duration = Duration::from_secs(30);
/// Wait before trying to create the account again.
const ACCOUNT_RETRY: Duration = Duration::from_secs(30);
/// How long one ARI request may take.
const ARI_TIMEOUT: Duration = Duration::from_secs(15);
/// ARI requests per tick, so a table with thousands of certificates does not stall the loop.
const ARI_PER_TICK: usize = 16;
/// Bounds on the `Retry-After` the CA gives for the next ARI request.
const ARI_REFRESH: (Duration, Duration) = (Duration::from_secs(60), Duration::from_secs(24 * 3600));
/// When an ARI request fails, ask again after this and renew at the fallback time meanwhile.
const ARI_ERROR_RETRY: Duration = Duration::from_secs(3600);
/// After a successful order the same job rests this long, giving the control plane time to push
/// the certificate.
const ISSUED_GRACE: Duration = Duration::from_secs(600);
/// First wait after a failed order; doubles per failure up to [`BACKOFF_MAX`].
const BACKOFF_FIRST: Duration = Duration::from_secs(60);
/// Longest wait after failed orders.
const BACKOFF_MAX: Duration = Duration::from_secs(3600);

/// Why an order did not produce a certificate.
#[derive(Debug, Error)]
enum IssueError {
    #[error(transparent)]
    Acme(#[from] AcmeError),
    #[error("account key: {0}")]
    AccountKey(Box<str>),
    #[error("the server offers no http-01 challenge")]
    NoHttp01,
    #[error("authorization is {0}")]
    Authorization(Box<str>),
    #[error("the control plane did not publish the challenge in time")]
    ChallengeNotPublished,
    #[error("the snapshot no longer has acme settings")]
    Cancelled,
    #[error("the order ended {0:?} instead of ready")]
    NotReady(OrderStatus),
    #[error("the order took longer than its deadline")]
    Deadline,
}

/// One certificate to order: the names, and the certificate it replaces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct JobKey {
    hosts: Box<[Box<str>]>,
    replaces: Option<Box<str>>,
}

#[derive(Debug)]
struct Job {
    key: JobKey,
    replaces: Option<CertificateIdentifier<'static>>,
}

impl Job {
    fn issue(hosts: &[Box<str>]) -> Self {
        let mut hosts = hosts.to_vec();
        hosts.sort_unstable();
        Self {
            key: JobKey {
                hosts: hosts.into(),
                replaces: None,
            },
            replaces: None,
        }
    }

    fn renew(cert: &CertInfo, ari: bool) -> Self {
        let mut job = Self::issue(&cert.hosts);
        // The CA only accepts `replaces` when it offers ARI.
        job.replaces = cert.id.clone().filter(|_| ari);
        job.key.replaces = cert.id.as_ref().map(|id| id.to_string().into());
        job
    }
}

/// When a certificate is renewed, and when to ask the CA again.
#[derive(Debug)]
struct Sched {
    renew_at: SystemTime,
    /// The ARI window `renew_at` was picked in; a new window gets a new pick.
    window: Option<(SystemTime, SystemTime)>,
    refresh_at: Instant,
}

/// Waits imposed on a job after its last order.
#[derive(Debug)]
struct Gate {
    until: Instant,
    failures: u32,
}

/// What an account was created from; a snapshot that changes any of it gets a new account.
struct AccountSpec {
    directory_url: String,
    contact: Vec<String>,
    eab: Option<ExternalAccount>,
    key_pem: Option<String>,
}

impl AccountSpec {
    fn of(acme: &snapshot::Acme) -> Self {
        Self {
            directory_url: acme.directory_url.clone(),
            contact: acme.contact.clone(),
            eab: acme.eab.clone(),
            key_pem: acme.account_key_pem.clone(),
        }
    }

    fn matches(&self, acme: &snapshot::Acme) -> bool {
        self.directory_url == acme.directory_url
            && self.contact == acme.contact
            && self.eab == acme.eab
            && self.key_pem == acme.account_key_pem
    }
}

struct Ready {
    spec: AccountSpec,
    account: Account,
}

/// Everything the loop remembers between ticks.
#[derive(Default)]
struct Issuer {
    account: Option<Ready>,
    account_retry: Option<Instant>,
    ari_supported: Option<bool>,
    schedule: HashMap<Box<str>, Sched>,
    orders: JoinSet<Result<(), IssueError>>,
    running: HashMap<Id, JobKey>,
    gates: HashMap<JobKey, Gate>,
}

/// The key of a certificate in [`Issuer::schedule`]: its ARI identifier, else its names.
fn sched_key(cert: &CertInfo) -> Box<str> {
    cert.id
        .as_ref()
        .map_or_else(|| cert.hosts.join(","), ToString::to_string)
        .into()
}

fn random_unit() -> f64 {
    let bits = RandomState::new().build_hasher().finish();
    (bits >> 11) as f64 / (1_u64 << 53) as f64
}

impl Issuer {
    fn stand_down(&mut self) {
        if self.account.is_some() || !self.running.is_empty() || !self.gates.is_empty() {
            tracing::info!("acme: this node is not the issuer, dropping issuer state");
            *self = Self::default();
        }
    }

    /// Records the outcome of every order that ended.
    fn reap(&mut self) {
        let now = Instant::now();
        while let Some(done) = self.orders.try_join_next_with_id() {
            let (id, outcome) = match done {
                Ok((id, outcome)) => (id, outcome),
                Err(err) => {
                    tracing::error!(%err, "acme: an order task ended abnormally");
                    (err.id(), Err(IssueError::Cancelled))
                }
            };
            let Some(key) = self.running.remove(&id) else {
                continue;
            };
            let hosts = key.hosts.join(",");
            let gate = match outcome {
                Ok(()) => {
                    tracing::info!(%hosts, "acme: certificate issued");
                    Gate {
                        until: now + ISSUED_GRACE,
                        failures: 0,
                    }
                }
                Err(err) => {
                    let failures = self.gates.get(&key).map_or(0, |gate| gate.failures) + 1;
                    let wait = BACKOFF_FIRST
                        .saturating_mul(1 << (failures - 1).min(10))
                        .min(BACKOFF_MAX);
                    tracing::warn!(%hosts, %err, retry_in = ?wait, "acme: order failed");
                    Gate {
                        until: now + wait,
                        failures,
                    }
                }
            };
            self.gates.insert(key, gate);
        }
        self.gates.retain(|_, gate| gate.until + BACKOFF_MAX > now);
    }

    fn blocked(&self, key: &JobKey, now: Instant) -> bool {
        self.running.values().any(|running| running == key)
            || self.gates.get(key).is_some_and(|gate| gate.until > now)
    }

    /// Whether `cert` is due for renewal at `wall`. A certificate whose ARI answer has not
    /// arrived yet is not due: renewing on the fallback would ignore the CA's window.
    fn due(&self, cert: &CertInfo, wall: SystemTime) -> bool {
        let at = match self.schedule.get(&sched_key(cert)) {
            Some(sched) => sched.renew_at,
            None if cert.id.is_some() && self.ari_supported != Some(false) => return false,
            None => cert.fallback_renewal(),
        };
        at <= wall
    }

    /// Asks the CA for the ARI window of up to [`ARI_PER_TICK`] certificates whose answer is
    /// missing or stale, and drops schedules of certificates the snapshot no longer serves.
    async fn refresh_schedules(&mut self, account: &Account, plan: &Plan) {
        let served: HashSet<Box<str>> = plan.certs().iter().map(sched_key).collect();
        self.schedule.retain(|key, _| served.contains(key));
        if self.ari_supported == Some(false) {
            return;
        }
        let now = Instant::now();
        let mut budget = ARI_PER_TICK;
        for cert in plan.certs().iter().filter(|cert| plan.renewable(cert)) {
            let Some(id) = &cert.id else { continue };
            let key = sched_key(cert);
            if self
                .schedule
                .get(&key)
                .is_some_and(|sched| sched.refresh_at > now)
            {
                continue;
            }
            if budget == 0 {
                break;
            }
            budget -= 1;
            let sched = match timeout(ARI_TIMEOUT, account.renewal_info(id)).await {
                Ok(Ok((info, retry_after))) => {
                    self.ari_supported = Some(true);
                    let window = (
                        SystemTime::from(info.suggested_window.start),
                        SystemTime::from(info.suggested_window.end),
                    );
                    let renew_at = match self.schedule.get(&key) {
                        Some(known) if known.window == Some(window) => known.renew_at,
                        _ => cert.pick_renewal(window.0, window.1, random_unit()),
                    };
                    Sched {
                        renew_at,
                        window: Some(window),
                        refresh_at: now + retry_after.clamp(ARI_REFRESH.0, ARI_REFRESH.1),
                    }
                }
                Ok(Err(AcmeError::Unsupported(_))) => {
                    tracing::info!(
                        "acme: the CA offers no ARI; renewing at two thirds of the lifetime"
                    );
                    self.ari_supported = Some(false);
                    self.schedule.clear();
                    return;
                }
                failed => {
                    let reason = failed.map_or_else(
                        |_| "timed out".to_owned(),
                        |result| result.err().map(|err| err.to_string()).unwrap_or_default(),
                    );
                    tracing::warn!(hosts = %cert.hosts.join(","), %reason, "acme: ARI request failed");
                    Sched {
                        renew_at: cert.fallback_renewal(),
                        window: None,
                        refresh_at: now + ARI_ERROR_RETRY,
                    }
                }
            };
            self.schedule.insert(key, sched);
        }
    }
}

impl Acme {
    async fn step(&self, issuer: &mut Issuer) {
        issuer.reap();
        let table = self.shared.table.load();
        let plan = table.acme();
        let Some(settings) = plan.settings().filter(|settings| self.is_issuer(settings)) else {
            issuer.stand_down();
            return;
        };
        let mut jobs: Vec<Job> = plan
            .missing()
            .iter()
            .map(|hosts| Job::issue(hosts))
            .collect();
        jobs.extend(
            Self::requested_hosts(plan, settings)
                .iter()
                .map(|host| Job::issue(std::slice::from_ref(host))),
        );
        if jobs.is_empty() && plan.certs().is_empty() {
            return;
        }
        let Some(account) = self.account(issuer, settings).await else {
            return;
        };
        issuer.refresh_schedules(&account, plan).await;
        let wall = SystemTime::now();
        let ari = issuer.ari_supported == Some(true);
        for cert in plan.certs() {
            if plan.renewable(cert) && issuer.due(cert, wall) {
                jobs.push(Job::renew(cert, ari));
            }
        }
        let now = Instant::now();
        for job in jobs {
            if issuer.running.len() >= MAX_ORDERS {
                break;
            }
            if issuer.blocked(&job.key, now) {
                continue;
            }
            let order = Order {
                account: account.clone(),
                table: self.shared.table.clone(),
                events: self.shared.events.clone(),
            };
            let key = job.key.clone();
            let handle = issuer.orders.spawn(async move {
                timeout(ORDER_DEADLINE, order.run(&job))
                    .await
                    .unwrap_or(Err(IssueError::Deadline))
            });
            issuer.running.insert(handle.id(), key);
        }
    }

    /// Hosts to order on demand: the control plane's `requested_hosts`, limited to hosts of
    /// `on_demand` apps that have no certificate. A handshake alone never gets a host here.
    fn requested_hosts(plan: &Plan, settings: &snapshot::Acme) -> Vec<Box<str>> {
        let mut hosts: Vec<Box<str>> = settings.requested_hosts.clone();
        hosts.retain(|host| plan.is_on_demand(host) && plan.cert_for(host).is_none());
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    }

    /// The ACME account of `settings`, created on first use and again when its inputs change.
    async fn account(&self, issuer: &mut Issuer, settings: &snapshot::Acme) -> Option<Account> {
        if let Some(ready) = &issuer.account
            && ready.spec.matches(settings)
        {
            return Some(ready.account.clone());
        }
        if issuer.account_retry.is_some_and(|at| at > Instant::now()) {
            return None;
        }
        issuer.account = None;
        issuer.ari_supported = None;
        issuer.schedule.clear();
        let created = timeout(
            ACCOUNT_TIMEOUT,
            create_account(settings, self.shared.ca_file.as_deref()),
        )
        .await
        .unwrap_or(Err(IssueError::Deadline));
        match created {
            Ok(account) => {
                tracing::info!(directory = %settings.directory_url, "acme: account ready");
                issuer.account_retry = None;
                issuer.account = Some(Ready {
                    spec: AccountSpec::of(settings),
                    account: account.clone(),
                });
                Some(account)
            }
            Err(err) => {
                tracing::warn!(%err, directory = %settings.directory_url, "acme: cannot create the account");
                issuer.account_retry = Some(Instant::now() + ACCOUNT_RETRY);
                None
            }
        }
    }
}

async fn create_account(
    settings: &snapshot::Acme,
    ca_file: Option<&Path>,
) -> Result<Account, IssueError> {
    let builder = match ca_file {
        Some(path) => Account::builder_with_root(path)?,
        None => Account::builder()?,
    };
    let directory = settings.directory_url.clone();
    if let Some(pem) = &settings.account_key_pem {
        let der = PrivatePkcs8KeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|err| IssueError::AccountKey(err.to_string().into()))?;
        let key = Key::from_pkcs8_der(der.clone_key())?;
        let (account, _) = builder
            .create_from_key((key, PrivateKeyDer::Pkcs8(der)), directory)
            .await?;
        return Ok(account);
    }
    let contact: Vec<&str> = settings.contact.iter().map(String::as_str).collect();
    let new_account = NewAccount {
        contact: &contact,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let binding = settings
        .eab
        .as_ref()
        .map(|eab| {
            decode_hmac_key(&eab.hmac_key)
                .map(|key| ExternalAccountKey::new(eab.key_id.clone(), &key))
                .map_err(|err| IssueError::AccountKey(err.to_string().into()))
        })
        .transpose()?;
    let (account, _) = builder
        .create(&new_account, directory, binding.as_ref())
        .await?;
    Ok(account)
}

/// What one order task needs; cloned out of the issuer so the task is `'static`.
struct Order {
    account: Account,
    table: TableHandle,
    events: EventFeed,
}

impl Order {
    /// Runs the order of `job` to a certificate and emits it.
    async fn run(&self, job: &Job) -> Result<(), IssueError> {
        let identifiers: Vec<Identifier> = job
            .key
            .hosts
            .iter()
            .map(|host| Identifier::Dns(host.to_string()))
            .collect();
        let mut order = match &job.replaces {
            Some(id) => {
                let replacing = NewOrder::new(&identifiers).replaces(id.clone());
                match self.account.new_order(&replacing).await {
                    Ok(order) => order,
                    Err(err) => {
                        tracing::debug!(%err, "acme: the CA refused `replaces`; ordering without it");
                        self.account.new_order(&NewOrder::new(&identifiers)).await?
                    }
                }
            }
            None => self.account.new_order(&NewOrder::new(&identifiers)).await?,
        };

        let mut tokens: Vec<Box<str>> = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(next) = authorizations.next().await {
            let mut authorization = next?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                ref other => return Err(IssueError::Authorization(format!("{other:?}").into())),
            }
            let challenge = authorization
                .challenge(ChallengeType::Http01)
                .ok_or(IssueError::NoHttp01)?;
            let token: Box<str> = challenge.token.as_str().into();
            self.events.emit(EventKind::AcmeChallenge {
                token: token.clone(),
                key_authorization: challenge.key_authorization().as_str().into(),
            });
            tokens.push(token);
        }
        self.wait_for_challenges(&tokens).await?;
        let mut authorizations = order.authorizations();
        while let Some(next) = authorizations.next().await {
            let mut authorization = next?;
            if authorization.status != AuthorizationStatus::Pending {
                continue;
            }
            authorization
                .challenge(ChallengeType::Http01)
                .ok_or(IssueError::NoHttp01)?
                .set_ready()
                .await?;
        }

        let retry = RetryPolicy::new().timeout(Duration::from_secs(90));
        let status = order.poll_ready(&retry).await?;
        if status != OrderStatus::Ready {
            return Err(IssueError::NotReady(status));
        }
        let key_pem = order.finalize().await?;
        let cert_pem = order.poll_certificate(&retry).await?;
        self.events.emit(EventKind::CertificateIssued {
            hosts: job.key.hosts.clone(),
            cert_pem: cert_pem.into(),
            key_pem: PrivateKeyPem::new(key_pem),
        });
        Ok(())
    }

    /// Waits until the live table serves every token, which is the control plane's signal that
    /// the answers are published.
    async fn wait_for_challenges(&self, tokens: &[Box<str>]) -> Result<(), IssueError> {
        let deadline = Instant::now() + CHALLENGE_WAIT;
        loop {
            let table = self.table.load();
            let plan = table.acme();
            if plan.settings().is_none() {
                return Err(IssueError::Cancelled);
            }
            if tokens.iter().all(|token| plan.challenge(token).is_some()) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(IssueError::ChallengeNotPublished);
            }
            drop(table);
            sleep(Duration::from_millis(100)).await;
        }
    }
}

#[async_trait]
impl BackgroundService for Acme {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut issuer = Issuer::default();
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tick.tick() => {}
            }
            self.step(&mut issuer).await;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn cert(id: Option<&str>) -> CertInfo {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        CertInfo {
            hosts: ["a.test".into()].into(),
            not_before: base,
            not_after: base + Duration::from_secs(900),
            id: id.map(|id| {
                let (aki, serial) = id.split_once('.').expect("aki.serial");
                CertificateIdentifier {
                    authority_key_identifier: aki.to_owned().into(),
                    serial: serial.to_owned().into(),
                }
            }),
        }
    }

    #[test]
    fn acme_due_waits_for_the_ari_answer_and_then_follows_it() {
        let mut issuer = Issuer::default();
        let with_id = cert(Some("YWJj.ZGVm"));
        let at = |secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        assert!(!issuer.due(&with_id, at(99_999)), "ARI pending: never due");
        issuer.schedule.insert(
            sched_key(&with_id),
            Sched {
                renew_at: at(1_500),
                window: None,
                refresh_at: Instant::now(),
            },
        );
        assert!(!issuer.due(&with_id, at(1_499)));
        assert!(issuer.due(&with_id, at(1_500)));
    }

    #[test]
    fn acme_due_without_ari_uses_two_thirds_of_the_lifetime() {
        let mut issuer = Issuer::default();
        let at = |secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        let no_id = cert(None);
        assert!(!issuer.due(&no_id, at(1_599)));
        assert!(issuer.due(&no_id, at(1_600)));
        issuer.ari_supported = Some(false);
        let with_id = cert(Some("YWJj.ZGVm"));
        assert!(!issuer.due(&with_id, at(1_599)));
        assert!(issuer.due(&with_id, at(1_600)));
    }

    #[test]
    fn acme_jobs_have_the_same_key_whatever_the_host_order() {
        let one = Job::issue(&["b.test".into(), "a.test".into()]);
        let two = Job::issue(&["a.test".into(), "b.test".into()]);
        assert_eq!(one.key, two.key);
        assert_ne!(one.key, Job::renew(&cert(Some("YWJj.ZGVm")), true).key);
    }
}
