//! Leader election over a `coordination.k8s.io` `Lease`.
//!
//! The provider runs once per node, so a cluster has many replicas, each serving its own
//! podgate from its own view of the cluster. Only the status writes must not fight, so one
//! replica at a time, the leader, writes status; the others keep serving and keep watching.
//!
//! The protocol is client-go's `leaderelection`. Every `retry` the elector reads the Lease:
//!
//! - it is ours (`holderIdentity`): renew it (`renewTime` now);
//! - nobody holds it, or the holder has not changed the record for `duration` as measured on
//!   *this* replica's clock from the moment it first saw that record (no clock of another node
//!   is trusted): take it over, `leaseTransitions + 1`;
//! - somebody else holds it and renews: not the leader.
//!
//! Every write carries the `resourceVersion` it read, so two replicas that race for a free
//! Lease get one `409`. A replica that cannot renew within `renew_deadline` of its last renewal
//! stops being the leader, which is shorter than `duration`, so nobody else can have taken the
//! Lease while this replica still believes it holds it. [`Leader::is_leader`] checks that
//! deadline on the spot: a stuck or failing elector cannot keep the writer writing.
//!
//! The Lease is not released at shutdown (the elector is aborted with the source), so a
//! replacement takes over after `duration`.

use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep};
use tracing::{debug, info, warn};

use super::client::{ApiClient, ClientError, ObjectMeta, Resource};
use super::time::micro_time;

/// The default Lease name.
pub const DEFAULT_NAME: &str = "podgate-provider-status";

/// A `Lease`: who holds it, and since when it was renewed.
#[derive(Debug, Deserialize)]
pub struct Lease {
    /// Name, namespace, resource version.
    pub metadata: ObjectMeta,
    /// The holder.
    #[serde(default)]
    pub spec: LeaseSpec,
}

/// The fields of a Lease spec the elector reads and writes.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseSpec {
    /// The identity of the holder; empty when released.
    #[serde(default)]
    pub holder_identity: Option<String>,
    /// How long the holder says the Lease is good for.
    #[serde(default)]
    pub lease_duration_seconds: Option<i64>,
    /// When the current holder took it.
    #[serde(default)]
    pub acquire_time: Option<String>,
    /// When the holder last renewed it.
    #[serde(default)]
    pub renew_time: Option<String>,
    /// How many times it changed hands.
    #[serde(default)]
    pub lease_transitions: Option<i64>,
}

impl Resource for Lease {
    const GROUP: &'static str = "coordination.k8s.io";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "leases";
    const KIND: &'static str = "Lease";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

/// The timing of the election.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// How long a record that does not change keeps its holder in office.
    pub duration: Duration,
    /// How long the leader may go without a successful renewal before it steps down.
    pub renew_deadline: Duration,
    /// How often the Lease is read, and renewed or taken.
    pub retry: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(15),
            renew_deadline: Duration::from_secs(10),
            retry: Duration::from_secs(2),
        }
    }
}

/// Which Lease, as whom, and how fast.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The Lease's name.
    pub name: Box<str>,
    /// The Lease's namespace.
    pub namespace: Box<str>,
    /// This replica's identity: the pod name when there is one, plus a random part so a
    /// restarted pod is not mistaken for its previous self.
    pub identity: Box<str>,
    /// The timing.
    pub timing: Timing,
}

/// An identity for this process: `HOSTNAME` (the pod name) or `podgate-provider`, and a random
/// suffix.
#[must_use]
pub fn default_identity() -> Box<str> {
    let host = std::env::var("HOSTNAME")
        .ok()
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| "podgate-provider".to_owned());
    let random = RandomState::new().hash_one(std::process::id());
    format!("{host}_{random:016x}").into()
}

/// Whether this replica leads, as the elector last found out.
#[derive(Debug, Clone)]
pub struct Leader(watch::Receiver<Option<Instant>>);

impl Leader {
    /// Whether this replica holds the Lease right now: it renewed within the renew deadline.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.0.borrow().is_some_and(|until| Instant::now() < until)
    }

    /// Waits for the elector to report; never returns once the elector is gone.
    pub async fn changed(&mut self) {
        if self.0.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Starts the elector in `tasks` and returns its [`Leader`].
pub fn spawn(tasks: &mut JoinSet<()>, client: ApiClient, settings: Settings) -> Leader {
    let (tx, rx) = watch::channel(None);
    tasks.spawn(async move {
        Elector {
            client,
            settings,
            tx,
            observed: None,
            leading: false,
            last_error: None,
        }
        .run()
        .await;
    });
    Leader(rx)
}

/// What the elector saw of the record, and when.
struct Observed {
    spec: LeaseSpec,
    at: Instant,
}

enum Step {
    /// This replica holds the Lease; the renewal started at this moment.
    Holding(Instant),
    /// Another replica holds it.
    Held(Box<str>),
}

struct Elector {
    client: ApiClient,
    settings: Settings,
    tx: watch::Sender<Option<Instant>>,
    observed: Option<Observed>,
    leading: bool,
    last_error: Option<Box<str>>,
}

impl Elector {
    async fn run(mut self) {
        loop {
            let started = Instant::now();
            match self.step(started).await {
                Ok(Step::Holding(at)) => {
                    self.last_error = None;
                    if !self.leading {
                        info!(
                            lease = %self.settings.name,
                            identity = %self.settings.identity,
                            "this replica is the leader and writes the Gateway API status"
                        );
                    }
                    self.leading = true;
                    self.tx
                        .send_replace(Some(at + self.settings.timing.renew_deadline));
                }
                Ok(Step::Held(holder)) => {
                    self.last_error = None;
                    if self.leading {
                        info!(holder = %holder, "the lease is held by another replica; status writes stop");
                    } else {
                        debug!(holder = %holder, "another replica is the leader");
                    }
                    self.leading = false;
                    self.tx.send_replace(None);
                }
                Err(err) => {
                    let why: Box<str> = err.to_string().into();
                    if self.last_error.as_ref() != Some(&why) {
                        warn!(error = %why, lease = %self.settings.name, "cannot reach the lease; a leader keeps writing until its renew deadline passes");
                        self.last_error = Some(why);
                    }
                    let expired = self
                        .tx
                        .borrow()
                        .is_some_and(|until| Instant::now() >= until);
                    if expired {
                        if self.leading {
                            info!("the lease could not be renewed in time; status writes stop");
                        }
                        self.leading = false;
                        self.tx.send_replace(None);
                    }
                }
            }
            if self.tx.is_closed() {
                return;
            }
            sleep(self.settings.timing.retry).await;
        }
    }

    fn manifest(&self, version: Option<&str>, spec: &LeaseSpec) -> Value {
        let mut metadata = json!({
            "name": &*self.settings.name,
            "namespace": &*self.settings.namespace,
        });
        if let Some(version) = version {
            metadata["resourceVersion"] = json!(version);
        }
        json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": metadata,
            "spec": {
                "holderIdentity": spec.holder_identity,
                "leaseDurationSeconds": spec.lease_duration_seconds,
                "acquireTime": spec.acquire_time,
                "renewTime": spec.renew_time,
                "leaseTransitions": spec.lease_transitions,
            },
        })
    }

    async fn step(&mut self, started: Instant) -> Result<Step, ClientError> {
        let namespace = Some(&*self.settings.namespace);
        let lease = match self
            .client
            .read::<Lease>(namespace, &self.settings.name)
            .await
        {
            Ok(lease) => lease,
            Err(err) if err.http_status() == Some(404) => {
                let spec = self.claim(None, false);
                let created: Lease = self
                    .client
                    .create(namespace, &self.manifest(None, &spec))
                    .await?;
                self.observed = Some(Observed {
                    spec: created.spec,
                    at: Instant::now(),
                });
                return Ok(Step::Holding(started));
            }
            Err(err) => return Err(err),
        };
        let now = Instant::now();
        if self
            .observed
            .as_ref()
            .is_none_or(|observed| observed.spec != lease.spec)
        {
            self.observed = Some(Observed {
                spec: lease.spec.clone(),
                at: now,
            });
        }
        let holder = lease
            .spec
            .holder_identity
            .as_deref()
            .filter(|holder| !holder.is_empty());
        let ours = holder == Some(&*self.settings.identity);
        let expired = self
            .observed
            .as_ref()
            .is_some_and(|observed| now > observed.at + self.settings.timing.duration);
        if !(ours || holder.is_none() || expired) {
            return Ok(Step::Held(holder.unwrap_or_default().into()));
        }
        let spec = self.claim(Some(&lease.spec), ours);
        let updated: Lease = self
            .client
            .replace(
                namespace,
                &self.settings.name,
                None,
                &self.manifest(lease.metadata.resource_version.as_deref(), &spec),
            )
            .await?;
        self.observed = Some(Observed {
            spec: updated.spec,
            at: Instant::now(),
        });
        Ok(Step::Holding(started))
    }

    /// The record this replica writes to hold the Lease: a renewal of `previous` when it
    /// already holds it (`ours`), a new term (`leaseTransitions` plus one) when it takes it from
    /// another holder, term zero when there is no previous record.
    fn claim(&self, previous: Option<&LeaseSpec>, ours: bool) -> LeaseSpec {
        let now = micro_time(SystemTime::now());
        let duration = self.settings.timing.duration;
        let seconds = duration.as_secs() + u64::from(duration.subsec_nanos() > 0);
        let transitions = previous.map_or(0, |spec| {
            spec.lease_transitions.unwrap_or(0) + i64::from(!ours)
        });
        LeaseSpec {
            holder_identity: Some(self.settings.identity.to_string()),
            lease_duration_seconds: Some(i64::try_from(seconds).unwrap_or(i64::MAX)),
            acquire_time: previous
                .filter(|_| ours)
                .and_then(|spec| spec.acquire_time.clone())
                .or_else(|| Some(now.clone())),
            renew_time: Some(now),
            lease_transitions: Some(transitions),
        }
    }
}
