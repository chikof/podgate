//! The Kubernetes source: Ingresses become routers, and the ready pod addresses in their Services'
//! EndpointSlices become servers, watched live.
//!
//! ```toml
//! [[source]]
//! kind = "kubernetes"
//! name = "k8s"
//! kubeconfig = "/etc/podgate/kubeconfig"   # default: the pod's service account
//! context = "prod"                          # default: the kubeconfig's current-context
//! namespaces = ["team-a", "team-b"]         # default: all namespaces
//! ingress_class = "podgate"                 # default
//! default_tenant = "acme"                   # for namespaces not listed below
//! allow_external_name = false               # default
//! crds = false                              # true: also read PodgateRoute and PodgateMiddleware
//!
//! [source.namespace_tenants]
//! team-a = "acme"
//! team-b = "globex"
//! ```
//!
//! - [`client`]: a generic list-and-watch client (`resourceVersion` watches, bookmarks, relist on
//!   `410 Gone`, backoff). The Gateway API, status, leader election and CRD sources build on it:
//!   they implement [`client::Resource`] for their kinds and run their own [`client::Watcher`]s.
//! - [`ingress`]: the Ingress mapping and its annotations.
//! - [`endpoints`]: Services, EndpointSlices and TLS Secrets.
//! - [`crd`]: the `PodgateRoute` and `PodgateMiddleware` custom resources and the generator of
//!   their CRD manifests.
//! - [`tenancy`]: the tenant of an Ingress or a route.
//! - [`gateway`]: Gateway, HTTPRoute and GRPCRoute (`gateway_api = true`).
//!
//! The source keeps one [`client::Store`] per kind and namespace scope. Every change to any of
//! them, after a short settle time that merges a burst, recomputes the whole state and sends it
//! when it differs from the last one; an Ingress that cannot be mapped is left out and named in
//! an outage report (the previous state of the others stays in force and is not touched). A
//! failing API server is an outage too, and the last state stays: the source never sends an
//! empty state for "cannot reach the cluster". The first state goes out only when every list has
//! succeeded once, so a half-loaded cache cannot delete routes.
//!
//! The references are `docs/ref/provider-kubernetes.md` and `docs/ref/provider-crd.md`.

pub mod client;
pub mod crd;
pub mod endpoints;
pub mod gateway;
pub mod ingress;
pub mod tenancy;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use tokio::sync::mpsc::{self, Sender};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, warn};

use self::client::{ApiClient, ClientConfig, Event, Query, Resource, Store, Tuning, Watcher};
use self::endpoints::{EndpointSlice, Secret, Service, ServiceIndex, TLS_SECRET_TYPE};
use self::ingress::{Cluster, Ingress, map};
use self::tenancy::Tenancy;
use crate::config::{Config, SourceConfig};
use crate::source::{Source, SourceApp, SourceCertificate, State, Update, UpdateBody};

const DEFAULT_CLASS: &str = "podgate";

/// The default time a burst of changes is merged before the state is recomputed.
const DEFAULT_SETTLE: Duration = Duration::from_millis(100);

/// A `[[source]]` entry of kind `kubernetes` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct KubernetesConfigError {
    /// The source's name.
    pub name: Box<str>,
    /// What is wrong, naming the key.
    pub reason: Box<str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    kubeconfig: Option<PathBuf>,
    context: Option<String>,
    namespaces: Option<Vec<String>>,
    ingress_class: Option<String>,
    #[serde(default)]
    namespace_tenants: BTreeMap<String, String>,
    default_tenant: Option<String>,
    #[serde(default)]
    allow_external_name: bool,
    #[serde(default)]
    crds: bool,
    #[serde(default)]
    gateway_api: bool,
    gateway_class: Option<String>,
    listener_entry_points: Option<BTreeMap<String, String>>,
}

/// The Kubernetes source.
#[derive(Debug)]
pub struct KubernetesSource {
    name: Box<str>,
    client: ClientConfig,
    tuning: Tuning,
    settle: Duration,
    /// One scope per watched namespace, or one for all.
    scopes: Vec<Option<Box<str>>>,
    class: Box<str>,
    tenancy: Tenancy,
    allow_external_name: bool,
    crds: bool,
    gateway: Option<gateway::Options>,
}

impl KubernetesSource {
    /// A Kubernetes source from its `[[source]]` entry. `config` is the whole provider
    /// configuration, which holds the tenants the namespaces map to.
    ///
    /// # Errors
    ///
    /// [`KubernetesConfigError`] when a key is unknown or has the wrong type, the kubeconfig
    /// cannot be used, or a mapped tenant is not configured.
    pub fn from_config(
        source: &SourceConfig,
        config: &Config,
    ) -> Result<Self, KubernetesConfigError> {
        let invalid = |reason: String| KubernetesConfigError {
            name: source.name.clone(),
            reason: reason.into(),
        };
        let settings = Settings::deserialize(toml::Value::Table(source.settings.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let client = match &settings.kubeconfig {
            Some(path) => ClientConfig::from_kubeconfig(path, settings.context.as_deref()),
            None if settings.context.is_some() => {
                return Err(invalid("context: needs kubeconfig".to_owned()));
            }
            None => ClientConfig::in_cluster(),
        }
        .map_err(|err| invalid(format!("kubeconfig: {err}")))?;
        let class = settings
            .ingress_class
            .unwrap_or_else(|| DEFAULT_CLASS.to_owned());
        if class.is_empty() {
            return Err(invalid("ingress_class: is empty".to_owned()));
        }
        let scopes = match settings.namespaces {
            None => vec![None],
            Some(namespaces) if namespaces.is_empty() => {
                return Err(invalid(
                    "namespaces: is empty; leave the key out to watch every namespace".to_owned(),
                ));
            }
            Some(namespaces) => {
                let mut scopes: Vec<Option<Box<str>>> = Vec::new();
                for namespace in namespaces {
                    if namespace.is_empty() {
                        return Err(invalid("namespaces: holds an empty name".to_owned()));
                    }
                    let scope = Some(namespace.into());
                    if !scopes.contains(&scope) {
                        scopes.push(scope);
                    }
                }
                scopes
            }
        };
        let tenancy = Tenancy::new(
            &source.name,
            config,
            settings
                .namespace_tenants
                .into_iter()
                .map(|(namespace, tenant)| (namespace.into(), tenant.into()))
                .collect(),
            settings.default_tenant.map(Into::into),
        )
        .map_err(invalid)?;
        let gateway = if settings.gateway_api {
            Some(
                gateway::Options::new(settings.gateway_class, settings.listener_entry_points)
                    .map_err(invalid)?,
            )
        } else if settings.gateway_class.is_some() || settings.listener_entry_points.is_some() {
            return Err(invalid(
                "gateway_class and listener_entry_points need gateway_api = true".to_owned(),
            ));
        } else {
            None
        };
        Ok(Self {
            name: source.name.clone(),
            client,
            tuning: Tuning::default(),
            settle: DEFAULT_SETTLE,
            scopes,
            class: class.into(),
            tenancy,
            allow_external_name: settings.allow_external_name,
            crds: settings.crds,
            gateway,
        })
    }

    /// The same source with other client timing. For tests; the defaults suit a cluster.
    #[must_use]
    pub fn with_tuning(mut self, tuning: Tuning) -> Self {
        self.tuning = tuning;
        self
    }

    /// The same source with another settle time (how long a burst of changes is merged).
    #[must_use]
    pub fn with_settle(mut self, settle: Duration) -> Self {
        self.settle = settle;
        self
    }
}

/// One change, tagged with the kind it belongs to.
enum Change {
    Ingress(Event<Ingress>),
    Service(Event<Service>),
    Slice(Event<EndpointSlice>),
    Secret(Event<Secret>),
    Crd(crd::CrdChange),
    Gateway(gateway::Change),
}

struct Tagged {
    scope: usize,
    change: Change,
}

/// Everything the source has read from the cluster: one store per kind and scope.
struct Cache {
    ingresses: Vec<Store<Ingress>>,
    services: Vec<Store<Service>>,
    slices: Vec<Store<EndpointSlice>>,
    secrets: Vec<Store<Secret>>,
    crd: crd::Cache,
    gateway: Option<gateway::Cache>,
    /// What each watcher last reported as wrong, by kind and scope.
    outages: BTreeMap<(&'static str, usize), Box<str>>,
}

impl Cache {
    fn new(scopes: usize, crds: bool, with_gateway: bool) -> Self {
        Self {
            ingresses: stores(scopes),
            services: stores(scopes),
            slices: stores(scopes),
            secrets: stores(scopes),
            crd: crd::Cache::new(crds, scopes),
            gateway: with_gateway.then(|| gateway::Cache::new(scopes)),
            outages: BTreeMap::new(),
        }
    }

    fn apply(&mut self, tagged: Tagged) {
        let Tagged { scope, change } = tagged;
        match change {
            Change::Ingress(event) => {
                track(&mut self.outages, &mut self.ingresses[scope], scope, event)
            }
            Change::Service(event) => {
                track(&mut self.outages, &mut self.services[scope], scope, event)
            }
            Change::Slice(event) => track(&mut self.outages, &mut self.slices[scope], scope, event),
            Change::Secret(event) => {
                track(&mut self.outages, &mut self.secrets[scope], scope, event)
            }
            Change::Crd(change) => self.crd.apply(&mut self.outages, scope, change),
            Change::Gateway(change) => {
                if let Some(gateway) = &mut self.gateway {
                    gateway.apply(&mut self.outages, scope, change);
                }
            }
        }
    }

    fn synced(&self) -> bool {
        self.ingresses.iter().all(Store::is_synced)
            && self.services.iter().all(Store::is_synced)
            && self.slices.iter().all(Store::is_synced)
            && self.secrets.iter().all(Store::is_synced)
            && self.crd.synced()
            && self.gateway.as_ref().is_none_or(gateway::Cache::synced)
    }
}

fn track<R: Resource>(
    outages: &mut BTreeMap<(&'static str, usize), Box<str>>,
    store: &mut Store<R>,
    scope: usize,
    event: Event<R>,
) {
    if let Event::Outage(why) = &event {
        outages.insert((R::PLURAL, scope), why.clone());
    } else {
        // Any event that is not an outage proves the watcher reaches the API server again.
        outages.remove(&(R::PLURAL, scope));
    }
    store.apply(event);
}

fn watch<R: Resource>(
    tasks: &mut JoinSet<()>,
    client: &ApiClient,
    query: Query,
    scope: usize,
    tx: &Sender<Tagged>,
    wrap: fn(Event<R>) -> Change,
) {
    let mut watcher = Watcher::<R>::new(client.clone(), query);
    let tx = tx.clone();
    tasks.spawn(async move {
        loop {
            let event = watcher.next().await;
            if tx
                .send(Tagged {
                    scope,
                    change: wrap(event),
                })
                .await
                .is_err()
            {
                return;
            }
        }
    });
}

impl Source for KubernetesSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let client = ApiClient::new(self.client.clone(), self.tuning);
        let (tx, mut rx) = mpsc::channel::<Tagged>(256);
        // Dropping the set on return aborts every watcher.
        let mut tasks = JoinSet::new();
        for (scope, namespace) in self.scopes.iter().enumerate() {
            let query = || match namespace {
                Some(namespace) => Query::in_namespace(namespace),
                None => Query::all(),
            };
            watch::<Ingress>(&mut tasks, &client, query(), scope, &tx, Change::Ingress);
            watch::<Service>(&mut tasks, &client, query(), scope, &tx, Change::Service);
            watch::<EndpointSlice>(&mut tasks, &client, query(), scope, &tx, Change::Slice);
            // Only TLS Secrets are asked for: the API server never sends the others.
            let secrets = query().with_field_selector(&format!("type={TLS_SECRET_TYPE}"));
            watch::<Secret>(&mut tasks, &client, secrets, scope, &tx, Change::Secret);
            crd::watch(self.crds, &mut tasks, &client, &query(), scope, &tx);
        }
        if self.gateway.is_some() {
            gateway::watch_all(&mut tasks, &client, &self.scopes, &tx);
        }
        drop(tx);

        let mut cluster = Cache::new(self.scopes.len(), self.crds, self.gateway.is_some());
        let mut publisher = Publisher::default();
        while let Some(first) = rx.recv().await {
            cluster.apply(first);
            // Merge a burst (a rollout touches Pods' slices many times a second) into one
            // recomputation, but never wait longer than ten settle times under a steady stream.
            let limit = Instant::now() + self.settle * 10;
            loop {
                let quiet = (Instant::now() + self.settle).min(limit);
                match timeout_at(quiet, rx.recv()).await {
                    Ok(Some(more)) => cluster.apply(more),
                    Ok(None) => return,
                    Err(_) => break,
                }
            }
            for update in publisher.next(&self, &cluster) {
                if updates.send(update).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// What the source has told the core, so it sends only what changed.
#[derive(Default)]
struct Publisher {
    state: Option<State>,
    report: Option<Box<str>>,
    logged: Vec<Box<str>>,
}

impl Publisher {
    fn next(&mut self, source: &KubernetesSource, cluster: &Cache) -> Vec<Update> {
        let mut problems: Vec<String> = Vec::new();
        for why in cluster.outages.values() {
            if !problems.iter().any(|known| known == &**why) {
                problems.push(why.to_string());
            }
        }
        if !cluster.synced() {
            // No state until every list has succeeded: a half-loaded cache would delete routes.
            return self.report_only(source, &problems);
        }
        let built = build(source, cluster);
        self.log_new(&built.rejected);
        problems.extend(built.rejected);
        let report: Option<Box<str>> = (!problems.is_empty()).then(|| problems.join("; ").into());
        let changed = self.state.as_ref() != Some(&built.state);
        // A state is also what ends an outage in the core, so one goes out when the problems
        // are gone even if the state itself did not change.
        let send_state = changed || (report.is_none() && self.report.is_some());
        let mut updates = Vec::new();
        if send_state {
            updates.push(Update {
                source: source.name.clone(),
                body: UpdateBody::State(built.state.clone()),
            });
            self.state = Some(built.state);
        }
        if let Some(report) = &report
            && (send_state || self.report.as_ref() != Some(report))
        {
            updates.push(Update::outage(&source.name, report));
        }
        self.report = report;
        updates
    }

    fn report_only(&mut self, source: &KubernetesSource, problems: &[String]) -> Vec<Update> {
        if problems.is_empty() {
            return Vec::new();
        }
        let report: Box<str> = problems.join("; ").into();
        if self.report.as_ref() == Some(&report) {
            return Vec::new();
        }
        let update = Update::outage(&source.name, &report);
        self.report = Some(report);
        vec![update]
    }

    fn log_new(&mut self, rejected: &[String]) {
        for line in rejected {
            if !self.logged.iter().any(|known| &**known == line) {
                warn!("{line}");
            }
        }
        self.logged = rejected.iter().map(|line| line.as_str().into()).collect();
    }
}

/// The state computed from the cluster, and the Ingresses it had to leave out.
struct Built {
    state: State,
    rejected: Vec<String>,
}

fn build(source: &KubernetesSource, cluster: &Cache) -> Built {
    let services = ServiceIndex::new(
        cluster.services.iter().flat_map(Store::values),
        cluster.slices.iter().flat_map(Store::values),
        source.allow_external_name,
    );
    let secret = |namespace: &str, name: &str| {
        cluster
            .secrets
            .iter()
            .find_map(|store| store.get(namespace, name))
            .filter(|secret| secret.kind.as_deref() == Some(TLS_SECRET_TYPE))
    };
    let context = Cluster {
        source: &source.name,
        tenancy: &source.tenancy,
        services: &services,
        secret: &secret,
    };
    let mut apps: Vec<SourceApp> = Vec::new();
    let mut certificates: Vec<SourceCertificate> = Vec::new();
    let mut rejected = Vec::new();
    for ingress in cluster.ingresses.iter().flat_map(Store::values) {
        if !ingress.has_class(&source.class) {
            debug!(ingress = %ingress.metadata.key(), "another class; ignored");
            continue;
        }
        match map(ingress, &context) {
            Ok(mapped) => {
                for note in mapped.notes {
                    rejected.push(format!("Ingress {}: {note}", ingress.metadata.key()));
                }
                apps.push(mapped.app);
                certificates.extend(mapped.certificates);
            }
            Err(why) => rejected.push(format!(
                "Ingress {} rejected: {why}",
                ingress.metadata.key()
            )),
        }
    }
    crd::build(&cluster.crd, &context, &mut apps, &mut rejected);
    if let (Some(options), Some(gateway)) = (&source.gateway, &cluster.gateway) {
        let translated = gateway::translate(gateway, options, &context);
        apps.extend(translated.apps);
        certificates.extend(translated.certificates);
        rejected.extend(translated.notes);
    }
    apps.sort_by(|a, b| a.origin.object.cmp(&b.origin.object));
    certificates.sort_by(|a, b| a.origin.object.cmp(&b.origin.object));
    Built {
        state: State { apps, certificates },
        rejected,
    }
}

fn stores<R: Resource>(scopes: usize) -> Vec<Store<R>> {
    (0..scopes).map(|_| Store::new()).collect()
}
