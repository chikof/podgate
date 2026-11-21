//! The loop that joins sources, merge, quarantine and push.
//!
//! [`Engine::run`] receives the updates of the sources, merges them after the debounce window and
//! pushes the result. It keeps no state on disk and reads no clock to number snapshots; what it
//! remembers (the states of the sources, the quarantine, what was last accepted) lives in
//! memory and is rebuilt from the sources and from `GET /v1/snapshot/version` after a restart.
//!
//! One round of `Engine::sync`:
//!
//! 1. Merge. Nothing to do when the canonical snapshot equals the one last pushed.
//! 2. Read the live version. A new `boot_id`, or a live version below the last one we pushed,
//!    means podgate restarted: the whole snapshot goes again.
//! 3. `PUT` at `live + 1` as `podgate-provider`. `409` stale reads the version again;
//!    `409` owned by another writer ends the run with an error naming the writer. `422` hands
//!    over to quarantine (`crate::quarantine`), then pushes again. A missing socket, a refused
//!    connection and `5xx` retry with backoff.
//!
//! The first push after the provider starts waits for every source to have reported once, unless
//! podgate has no snapshot yet: a source that is slow to start must not delete its routes from a
//! node that is already serving them.

use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{error, info, warn};

use crate::acme::events::{NoSolver, Solver};
use crate::acme::{self, BrokerError, BrokerView, Claims};
use crate::config::Config;
use crate::merge::{Finding, Merged, Merger};
use crate::policy::UpstreamPolicy;
use crate::push::{AdminClient, Answer, Backoff, ClientError, Debounce, Live, Tuning};
use crate::quarantine::{self, BisectError, Culprit, Quarantine, Validate, Verdict};
use crate::source::{ObjectRef, Source, State, Update, UpdateBody};

/// Times a push may find the version moved under it before the round is treated as a failure.
const MAX_STALE_RETRIES: u32 = 3;

/// Times validation is asked again after `503` busy.
const MAX_BUSY_RETRIES: u32 = 5;

type SourceTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// How long the engine waits for every source before it shares claims anyway.
const CLAIMS_PATIENCE: Duration = Duration::from_secs(30);

/// Why the engine stopped.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunError {
    /// Another writer owns the snapshot. The provider does not retry and does not take over:
    /// moving the node to it is the operator's decision (`PUT /v1/snapshot?takeover=true`).
    #[error("podgate's snapshot is owned by {}; the provider will not push until the operator removes the other writer or takes the node over", owner(.writer.as_deref()))]
    WriterConflict {
        /// The owner's name, or `None` when it pushed without one.
        writer: Option<Box<str>>,
    },
    /// The ACME broker cannot start: its state directory is not usable.
    #[error("the ACME broker cannot start: {0}")]
    Acme(Box<str>),
}

fn owner(writer: Option<&str>) -> String {
    writer.map_or_else(
        || "an unnamed writer".to_owned(),
        |name| format!("writer {name}"),
    )
}

/// Why a single pass over the sources produced no snapshot.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CollectError {
    /// The sources did not all report in time.
    #[error("source {0} did not report in time")]
    Timeout(Box<str>),
    /// A source cannot reach its backend, so the merge would be partial.
    #[error("source {name} is unavailable: {error}")]
    Outage {
        /// The source.
        name: Box<str>,
        /// What it reported.
        error: Box<str>,
    },
    /// The ACME state directory cannot be read, so the merge would lack its certificates.
    #[error("cannot read the ACME state directory: {0}")]
    Acme(Box<str>),
}

/// A source's name that is not in the configuration.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("source {0:?} is not in the configuration")]
pub struct UnknownSource(pub Box<str>);

/// One quarantined object, for the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedObject {
    /// `<kind>/<name>:<object>`.
    pub declared_by: Box<str>,
    /// Why it is out.
    pub reason: Box<str>,
}

/// What the engine knows, published after every round.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// What the last merge noticed.
    pub findings: Vec<Finding>,
    /// The objects that are out of the snapshot because podgate rejected them.
    pub quarantined: Vec<QuarantinedObject>,
    /// The sources that cannot reach their backend, and what they said.
    pub outages: BTreeMap<Box<str>, Box<str>>,
    /// The version podgate last accepted from this provider.
    pub pushed_version: Option<u64>,
    /// How many snapshots podgate accepted.
    pub pushes: u64,
    /// Why the last round did not push, when it did not.
    pub error: Option<Box<str>>,
    /// Why the ACME broker stopped, when it did: no certificate or challenge is added until the
    /// provider restarts.
    pub acme_error: Option<Box<str>>,
}

#[derive(Debug)]
struct Pushed {
    fingerprint: Box<str>,
    version: u64,
    boot_id: Box<str>,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Pushed,
    Idle,
    Gated,
    Transient(Box<str>),
    Refused(Box<str>),
    WriterConflict(Option<Box<str>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Changed,
    Resync,
}

/// The provider's core: sources in, snapshots out.
pub struct Engine {
    config: Config,
    merger: Merger,
    client: AdminClient,
    tuning: Tuning,
    updates: mpsc::Sender<Update>,
    inbox: mpsc::Receiver<Update>,
    tasks: Vec<SourceTask>,
    status: watch::Sender<Status>,
    states: BTreeMap<Box<str>, State>,
    outages: BTreeMap<Box<str>, Box<str>>,
    quarantine: Quarantine,
    accepted: BTreeMap<ObjectRef, Box<str>>,
    pushed: Option<Pushed>,
    refused: Option<Box<str>>,
    repush: bool,
    pushes: u64,
    error: Option<Box<str>>,
    last_findings: Vec<Finding>,
    started: Instant,
    solver: Arc<dyn Solver>,
    acme_view: Arc<BrokerView>,
    acme_epoch: u64,
    acme_claims: Option<watch::Sender<Option<Arc<Claims>>>>,
    acme_error: Option<Box<str>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("admin_socket", &self.config.admin_socket)
            .field("sources", &self.states.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// An engine for `config`, checking upstreams against `policy`.
    #[must_use]
    pub fn new(config: Config, policy: UpstreamPolicy) -> Self {
        let tuning = Tuning::default();
        let (updates, inbox) = mpsc::channel(64);
        Self {
            merger: Merger::new(&config, policy),
            client: AdminClient::new(&config.admin_socket, tuning.request_timeout),
            config,
            tuning,
            updates,
            inbox,
            tasks: Vec::new(),
            status: watch::channel(Status::default()).0,
            states: BTreeMap::new(),
            outages: BTreeMap::new(),
            quarantine: Quarantine::new(),
            accepted: BTreeMap::new(),
            pushed: None,
            refused: None,
            repush: false,
            pushes: 0,
            error: None,
            last_findings: Vec::new(),
            started: Instant::now(),
            solver: Arc::new(NoSolver),
            acme_view: Arc::new(BrokerView::off()),
            acme_epoch: 0,
            acme_claims: None,
            acme_error: None,
        }
    }

    /// Replaces the timing knobs (retry delays, request deadline). Tests shorten them.
    #[must_use]
    pub fn with_tuning(mut self, tuning: Tuning) -> Self {
        self.client = AdminClient::new(&self.config.admin_socket, tuning.request_timeout);
        self.tuning = tuning;
        self
    }

    /// Registers a source. It starts when the engine runs.
    ///
    /// # Errors
    ///
    /// [`UnknownSource`] when the source's name is not in the configuration: its objects could
    /// not be given a `declared_by` kind.
    pub fn add_source<S: Source>(&mut self, source: S) -> Result<(), UnknownSource> {
        if !self.config.source_names().any(|name| name == source.name()) {
            return Err(UnknownSource(source.name().into()));
        }
        self.tasks.push(Box::pin(source.run(self.updates.clone())));
        Ok(())
    }

    /// Registers the DNS-01 solver that publishes TXT records for the ACME broker.
    /// Without one, DNS-01 challenges are reported and never answered.
    #[must_use]
    pub fn with_dns_solver(mut self, solver: Arc<dyn Solver>) -> Self {
        self.solver = solver;
        self
    }

    /// A receiver of the engine's status, which changes after every round.
    #[must_use]
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sources_ready(&self) -> bool {
        self.config
            .source_names()
            .all(|name| self.states.contains_key(name))
    }

    fn merge(&self) -> Merged {
        self.merger
            .merge_with(&self.states, &self.quarantine.excluded(), &self.acme_view)
    }

    /// Takes an update of a source. Returns whether the desired state may have changed.
    fn apply(&mut self, update: Update) -> bool {
        let Update { source, body } = update;
        if !self.config.source_names().any(|name| name == &*source) {
            warn!(source = %source, "update from a source that is not in the configuration");
            return false;
        }
        match body {
            UpdateBody::State(state) => {
                for (object, held) in self.quarantine.release_changed(&source, &state) {
                    info!(
                        declared_by = %held.declared_by,
                        object = %object.object,
                        "released from quarantine: its source changed it"
                    );
                }
                self.outages.remove(&source);
                self.states.insert(source, state);
                true
            }
            UpdateBody::Outage(why) => {
                warn!(source = %source, error = %why, "source cannot reach its backend; its last state stays");
                self.outages.insert(source, why);
                self.publish(None);
                false
            }
        }
    }

    fn publish(&mut self, merged: Option<&Merged>) {
        if let Some(merged) = merged {
            for finding in merged.findings() {
                if !self.last_findings.contains(finding) {
                    warn!(
                        code = finding.code,
                        declared_by = %finding.declared_by,
                        dropped = finding.dropped,
                        "{}",
                        finding.message
                    );
                }
            }
            self.last_findings = merged.findings().to_vec();
            self.share_claims(merged);
        }
        let status = Status {
            findings: self.last_findings.clone(),
            quarantined: self
                .quarantine
                .entries()
                .values()
                .map(|held| QuarantinedObject {
                    declared_by: held.declared_by.clone(),
                    reason: held.reason.clone(),
                })
                .collect(),
            outages: self.outages.clone(),
            pushed_version: self.pushed.as_ref().map(|pushed| pushed.version),
            pushes: self.pushes,
            error: self.error.clone(),
            acme_error: self.acme_error.clone(),
        };
        self.status.send_replace(status);
    }

    /// Tells the ACME broker what the apps of `merged` claim, once every source has reported
    /// (or a source has been silent for a while): a partial view would make it refuse hosts
    /// whose apps have not arrived yet.
    fn share_claims(&self, merged: &Merged) {
        let ready = self.sources_ready() || self.started.elapsed() >= CLAIMS_PATIENCE;
        let Some(claims) = self.acme_claims.as_ref().filter(|_| ready) else {
            return;
        };
        claims.send_if_modified(|current| {
            let changed = current.as_deref() != Some(&**merged.claims());
            if changed {
                *current = Some(Arc::clone(merged.claims()));
            }
            changed
        });
    }

    /// The ACME broker ended. Its last state stays pushed; the sources keep working.
    fn acme_stopped(&mut self, ended: Result<Result<(), BrokerError>, tokio::task::JoinError>) {
        let why: Box<str> = match ended {
            Ok(Ok(())) => return,
            Ok(Err(err)) => format!("{err}: {}", source_chain(&err)).into(),
            Err(err) => format!("the ACME broker task failed: {err}").into(),
        };
        error!(error = %why, "the ACME broker stopped; the last pushed state stays and no certificate is added until the provider is restarted");
        self.acme_error = Some(why);
        self.publish(None);
    }

    /// Runs until `shutdown` completes or another writer owns the snapshot.
    ///
    /// # Errors
    ///
    /// [`RunError::WriterConflict`] when podgate answers that another writer owns the snapshot.
    pub async fn run(mut self, shutdown: impl Future<Output = ()>) -> Result<(), RunError> {
        let mut sources = JoinSet::new();
        for task in std::mem::take(&mut self.tasks) {
            sources.spawn(task);
        }
        let mut debounce = Debounce::new(
            duration_ms(self.config.debounce),
            duration_ms(self.config.max_delay),
        );
        let mut backoff = Backoff::new(self.tuning.backoff_min, self.tuning.backoff_max);
        let mut retry_at: Option<Instant> = None;
        if self.config.sources.is_empty() {
            debounce.note(self.now_ms());
        }
        let mut acme_view: Option<watch::Receiver<Arc<BrokerView>>> = None;
        let mut acme_task: Option<JoinHandle<Result<(), BrokerError>>> = None;
        if let Some(settings) = self.config.acme.clone() {
            let handle = acme::start(
                &settings,
                &self.config,
                self.client.clone(),
                self.tuning,
                Arc::clone(&self.solver),
            )
            .map_err(|err| RunError::Acme(format!("{err}: {}", source_chain(&err)).into()))?;
            self.acme_view = Arc::clone(&handle.view.borrow());
            self.acme_epoch = self.acme_view.epoch();
            acme_view = Some(handle.view);
            acme_task = Some(handle.task);
            self.acme_claims = Some(handle.claims);
            debounce.note(self.now_ms());
        }
        let resync = self.config.resync;
        let mut resync_tick = tokio::time::interval_at(Instant::now() + resync, resync);
        resync_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tokio::pin!(shutdown);

        let result = loop {
            let debounce_at = debounce
                .deadline()
                .map(|ms| self.started + Duration::from_millis(ms));
            let wake = [debounce_at, retry_at].into_iter().flatten().min();
            let mode = tokio::select! {
                () = &mut shutdown => break Ok(()),
                update = self.inbox.recv() => {
                    if let Some(update) = update && self.apply(update) {
                        debounce.note(self.now_ms());
                    }
                    continue;
                }
                changed = view_changed(&mut acme_view) => {
                    let Some(view) = acme_view.as_mut().filter(|_| changed) else {
                        acme_view = None;
                        continue;
                    };
                    self.acme_view = Arc::clone(&view.borrow_and_update());
                    if self.acme_view.epoch() == self.acme_epoch {
                        debounce.note(self.now_ms());
                        continue;
                    }
                    // podgate restarted or lost events: look at the live snapshot now, not at
                    // the next resync tick.
                    self.acme_epoch = self.acme_view.epoch();
                    Mode::Resync
                }
                ended = broker_ended(&mut acme_task) => {
                    acme_task = None;
                    self.acme_stopped(ended);
                    continue;
                }
                () = sleep_until(wake) => Mode::Changed,
                _ = resync_tick.tick() => {
                    let now = self.now_ms();
                    let after = duration_ms(self.config.resync);
                    for (object, held) in self.quarantine.expire(now, after) {
                        info!(
                            declared_by = %held.declared_by,
                            object = %object.object,
                            "released from quarantine: the resync interval passed"
                        );
                    }
                    Mode::Resync
                }
            };
            if mode == Mode::Changed {
                let now = self.now_ms();
                let fire = debounce.due(now) | retry_at.is_some_and(|at| Instant::now() >= at);
                if !fire {
                    continue;
                }
                retry_at = None;
            }
            match Box::pin(self.sync(mode)).await {
                Outcome::Pushed => backoff.reset(),
                Outcome::Idle | Outcome::Gated | Outcome::Refused(_) => {}
                Outcome::Transient(why) => {
                    let delay = backoff.next_delay();
                    warn!(error = %why, retry_in_ms = delay.as_millis(), "push failed, will retry");
                    retry_at = Some(Instant::now() + delay);
                }
                Outcome::WriterConflict(writer) => {
                    let err = RunError::WriterConflict { writer };
                    error!(error = %err, "stopping");
                    self.error = Some(err.to_string().into());
                    self.publish(None);
                    break Err(err);
                }
            }
        };
        if let Some(task) = &acme_task {
            task.abort();
        }
        result
    }

    /// One round: merge, and push when something has to be pushed.
    async fn sync(&mut self, mode: Mode) -> Outcome {
        if mode == Mode::Resync {
            self.refused = None;
        }
        let merged = self.merge();
        self.publish(Some(&merged));
        let fingerprint = merged.fingerprint();
        let unchanged = self
            .pushed
            .as_ref()
            .is_some_and(|pushed| *pushed.fingerprint == *fingerprint);
        if mode == Mode::Changed
            && ((unchanged && !self.repush) || self.refused.as_deref() == Some(fingerprint))
        {
            return Outcome::Idle;
        }
        let live = match self.client.version().await {
            Ok(live) => live,
            Err(err) => return self.transient(&err),
        };
        let (restarted, diverged) = self.pushed.as_ref().map_or((false, false), |pushed| {
            (
                *pushed.boot_id != *live.boot_id || live.version < pushed.version,
                live.version != pushed.version,
            )
        });
        // A failed push must not forget why it was needed: the retry runs as an ordinary round.
        self.repush |= restarted || diverged;
        if restarted {
            info!(
                live_version = live.version,
                "podgate restarted; the whole snapshot is pushed again"
            );
        }
        if self.pushed.is_none() && live.version > 0 && !self.sources_ready() {
            self.error =
                Some("waiting for every source to report before replacing a live snapshot".into());
            self.publish(None);
            return Outcome::Gated;
        }
        if unchanged && !self.repush {
            return Outcome::Idle;
        }
        let outcome = self.push(merged, live).await;
        match &outcome {
            Outcome::Pushed | Outcome::Idle => self.error = None,
            Outcome::Gated => {}
            Outcome::Transient(why) | Outcome::Refused(why) => self.error = Some(why.clone()),
            Outcome::WriterConflict(_) => {}
        }
        self.publish(None);
        outcome
    }

    fn transient(&mut self, err: &ClientError) -> Outcome {
        let why: Box<str> = format!("{err}: {}", source_chain(err)).into();
        self.error = Some(why.clone());
        self.publish(None);
        Outcome::Transient(why)
    }

    async fn push(&mut self, mut merged: Merged, mut live: Live) -> Outcome {
        let mut stale = 0;
        loop {
            let version = live.version + 1;
            let answer = match self.client.put(&merged.body(version)).await {
                Ok(answer) => answer,
                Err(err) => return self.transient(&err),
            };
            match answer.status {
                200 => {
                    info!(
                        version,
                        apps = merged.snapshot().apps.len(),
                        "snapshot accepted"
                    );
                    self.record(&merged, version, &live);
                    return Outcome::Pushed;
                }
                409 => {
                    if let Conflict::OwnedBy(owner) = conflict_of(answer.json().as_ref()) {
                        return Outcome::WriterConflict(owner);
                    }
                    stale += 1;
                    if stale > MAX_STALE_RETRIES {
                        return Outcome::Transient("the live version keeps moving".into());
                    }
                    live = match self.client.version().await {
                        Ok(live) => live,
                        Err(err) => return self.transient(&err),
                    };
                }
                422 => match self.quarantine_round(&merged, &answer, version).await {
                    Ok(next) => {
                        self.publish(Some(&next));
                        merged = next;
                    }
                    Err(outcome) => return outcome,
                },
                status if (400..500).contains(&status) => {
                    return self.refuse(
                        &merged,
                        format!(
                            "podgate refused the snapshot with {status}: {}",
                            answer.excerpt()
                        ),
                    );
                }
                status => {
                    return Outcome::Transient(
                        format!("podgate answered {status}: {}", answer.excerpt()).into(),
                    );
                }
            }
        }
    }

    fn record(&mut self, merged: &Merged, version: u64, live: &Live) {
        self.pushed = Some(Pushed {
            fingerprint: merged.fingerprint().into(),
            version,
            boot_id: live.boot_id.clone(),
        });
        self.accepted = merged
            .included()
            .iter()
            .map(|included| (included.object.clone(), included.fingerprint.clone()))
            .collect();
        self.refused = None;
        self.repush = false;
        self.pushes += 1;
    }

    /// Gives up on `merged` until a source changes something or the resync interval passes. The
    /// last accepted snapshot stays live.
    fn refuse(&mut self, merged: &Merged, why: String) -> Outcome {
        error!(error = %why, "snapshot not pushed; the last accepted snapshot stays live");
        self.refused = Some(merged.fingerprint().into());
        Outcome::Refused(why.into())
    }

    /// Handles a `422`: finds the objects to leave out, quarantines them, and returns the merge
    /// without them. Every call either quarantines at least one object of `merged` (which has
    /// finitely many) or ends the push, so the loop in [`Self::push`] terminates.
    async fn quarantine_round(
        &mut self,
        merged: &Merged,
        answer: &Answer,
        version: u64,
    ) -> Result<Merged, Outcome> {
        let conflicts: Vec<Value> = answer
            .json()
            .and_then(|body| body.get("conflicts").and_then(Value::as_array).cloned())
            .unwrap_or_default();
        let mut culprits = quarantine::attribute(merged, &conflicts);
        if culprits.is_empty() {
            let changed: Vec<_> = merged
                .included()
                .iter()
                .filter(|included| {
                    self.accepted.get(&included.object) != Some(&included.fingerprint)
                })
                .cloned()
                .collect();
            let build = |extra: &BTreeSet<ObjectRef>| {
                let mut excluded = self.quarantine.excluded();
                excluded.extend(extra.iter().cloned());
                self.merger
                    .merge_with(&self.states, &excluded, &self.acme_view)
            };
            let mut ask = Daemon {
                client: &self.client,
                tuning: self.tuning,
                version,
            };
            match quarantine::bisect(&changed, build, &mut ask).await {
                Ok(found) => {
                    info!(
                        culprits = found.culprits.len(),
                        validations = found.calls,
                        "bisected the rejected snapshot"
                    );
                    culprits = found
                        .culprits
                        .into_iter()
                        .map(|object| Culprit {
                            object,
                            reason: "podgate rejected the snapshot and bisection found that adding this object causes it".into(),
                        })
                        .collect();
                }
                Err(BisectError::Failed(why)) => return Err(Outcome::Transient(why)),
                Err(err) => {
                    let named = summary(&conflicts);
                    return Err(self.refuse(
                        merged,
                        format!("podgate rejected the snapshot and no object can be blamed ({err}); {named}"),
                    ));
                }
            }
        }
        if culprits.is_empty() {
            return Err(self.refuse(
                merged,
                format!("podgate rejected the snapshot; {}", summary(&conflicts)),
            ));
        }
        let now = self.now_ms();
        for culprit in &culprits {
            warn!(declared_by = %culprit.object.declared_by, reason = %culprit.reason, "object quarantined");
            self.quarantine.hold(&culprit.object, &culprit.reason, now);
        }
        Ok(self.merge())
    }

    /// Starts the sources and waits until each has reported once, then merges: what
    /// `print` and `check` use. Nothing is pushed.
    ///
    /// # Errors
    ///
    /// [`CollectError`] when a source does not report within `wait`, or reports an outage:
    /// a partial merge would mislead.
    pub async fn first_pass(&mut self, wait: Duration) -> Result<Merged, CollectError> {
        if let Some(settings) = &self.config.acme {
            let view = acme::offline_view(settings).map_err(|err| {
                CollectError::Acme(format!("{err}: {}", source_chain(&err)).into())
            })?;
            self.acme_view = Arc::new(view);
        }
        let mut sources = JoinSet::new();
        for task in std::mem::take(&mut self.tasks) {
            sources.spawn(task);
        }
        let deadline = Instant::now() + wait;
        while !self.sources_ready() {
            let received = tokio::time::timeout_at(deadline, self.inbox.recv()).await;
            let Ok(Some(update)) = received else {
                let missing = self
                    .config
                    .source_names()
                    .find(|name| !self.states.contains_key(*name))
                    .unwrap_or_default();
                return Err(CollectError::Timeout(missing.into()));
            };
            if let UpdateBody::Outage(error) = &update.body {
                return Err(CollectError::Outage {
                    name: update.source,
                    error: error.clone(),
                });
            }
            self.apply(update);
        }
        let merged = self.merge();
        self.publish(Some(&merged));
        Ok(merged)
    }

    /// Asks podgate whether `merged` compiles, without applying it.
    ///
    /// # Errors
    ///
    /// The reason in words when the socket cannot be used or answers something unexpected.
    pub async fn validate(&self, merged: &Merged) -> Result<Verdict, Box<str>> {
        let version = match self.client.version().await {
            Ok(live) => live.version + 1,
            Err(err) => return Err(format!("{err}: {}", source_chain(&err)).into()),
        };
        validate(&self.client, self.tuning, merged, version).await
    }
}

/// The daemon as the validator of a bisection.
struct Daemon<'a> {
    client: &'a AdminClient,
    tuning: Tuning,
    version: u64,
}

impl Validate for Daemon<'_> {
    async fn validate(&mut self, candidate: &Merged) -> Result<Verdict, Box<str>> {
        validate(self.client, self.tuning, candidate, self.version).await
    }
}

/// Asks `POST /v1/snapshot/validate`, waiting out `503` busy answers a few times.
async fn validate(
    client: &AdminClient,
    tuning: Tuning,
    merged: &Merged,
    version: u64,
) -> Result<Verdict, Box<str>> {
    let body = merged.body(version);
    for _ in 0..=MAX_BUSY_RETRIES {
        let answer = client
            .validate(&body)
            .await
            .map_err(|err| format!("{err}: {}", source_chain(&err)))?;
        match answer.status {
            200 => return Ok(Verdict::Valid),
            422 => {
                let conflicts = answer
                    .json()
                    .and_then(|body| body.get("conflicts").and_then(Value::as_array).cloned())
                    .unwrap_or_default();
                return Ok(Verdict::Rejected(conflicts));
            }
            503 => tokio::time::sleep(tuning.busy_wait).await,
            status => {
                return Err(format!("validate answered {status}: {}", answer.excerpt()).into());
            }
        }
    }
    Err("validate stays busy".into())
}

/// What a `409` says.
enum Conflict {
    /// The version is not newer than the live one.
    Stale,
    /// Another writer owns the snapshot (`None`: one that sent no name).
    OwnedBy(Option<Box<str>>),
}

/// Tells the two `409`s apart: only the writer one names a `writer`, `null` for an unnamed
/// writer.
fn conflict_of(body: Option<&Value>) -> Conflict {
    match body
        .and_then(Value::as_object)
        .and_then(|object| object.get("writer"))
    {
        Some(writer) => Conflict::OwnedBy(writer.as_str().map(Into::into)),
        None => Conflict::Stale,
    }
}

/// The causes of an error, joined, for a log line.
fn source_chain(err: &dyn std::error::Error) -> String {
    let mut parts = Vec::new();
    let mut current = err.source();
    while let Some(cause) = current {
        parts.push(cause.to_string());
        current = cause.source();
    }
    parts.join(": ")
}

/// The codes and messages of the first conflicts, for an error line.
fn summary(conflicts: &[Value]) -> String {
    if conflicts.is_empty() {
        return "the answer lists no conflicts".to_owned();
    }
    let listed: Vec<String> = conflicts
        .iter()
        .take(3)
        .map(|conflict| {
            let code = conflict.get("code").and_then(Value::as_str).unwrap_or("?");
            let message = conflict
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("");
            format!("{code}: {message}")
        })
        .collect();
    let more = conflicts.len().saturating_sub(3);
    if more > 0 {
        format!("{} (and {more} more)", listed.join("; "))
    } else {
        listed.join("; ")
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Waits for the ACME broker to publish a new view. `false`: the broker is gone. Never ready
/// when there is no broker.
async fn view_changed(view: &mut Option<watch::Receiver<Arc<BrokerView>>>) -> bool {
    match view {
        Some(view) => view.changed().await.is_ok(),
        None => std::future::pending().await,
    }
}

/// Waits for the ACME broker's task to end. Never ready when there is none.
async fn broker_ended(
    task: &mut Option<JoinHandle<Result<(), BrokerError>>>,
) -> Result<Result<(), BrokerError>, tokio::task::JoinError> {
    match task {
        Some(task) => task.await,
        None => std::future::pending().await,
    }
}
