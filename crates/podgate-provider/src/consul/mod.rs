//! The Consul source: catalog services tagged `podgate.*` become apps, with servers taken from
//! their healthy instances.
//!
//! ```toml
//! [[source]]
//! kind = "consul"
//! name = "consul-prod"
//! address = "http://127.0.0.1:8500"
//! token_file = "/etc/podgate/consul.token"   # sent as X-Consul-Token, never logged
//! datacenter = "dc1"
//! tenant_from = "fixed"                      # "fixed", "meta" or "namespace"
//! tenant = "acme"
//! exposed_by_default = false
//! resync_secs = 30
//! ```
//!
//! The source learns which services exist and which tags they carry from a blocking query on
//! `/v1/catalog/services`, and takes the servers of every service it cares about from a blocking
//! query on `/v1/health/service/<name>?passing=true`. Both are `GET`s (`client.rs`). A server is
//! the instance's own address and port, never an address a tag spells out. The tags are read by
//! [`crate::docker::labels`] (which reads `traefik.*` tags through [`crate::traefik`]), written
//! `key=value`.
//!
//! An instance that asks to be used but cannot be (an unknown tag, an address that is not an IP
//! address) is left out and reported next to the state, as an outage text naming it, like the
//! Docker source does for a container. A Consul that cannot be reached keeps the last state in
//! force and is reported the same way.
//!
//! The reference is `docs/ref/provider-consul.md`.

mod apps;
mod client;
mod model;
mod tags;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use http::Uri;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

use crate::abort::Abort;
use crate::acme::store::read_secret_file;
use crate::config::SourceConfig;
use crate::push::Backoff;
use crate::source::{Source, State, Update, UpdateBody};

use apps::Service;
use client::{Blocking, Client, ClientError, Query, Reply};
use model::{Catalog, Instances};

const DEFAULT_RESYNC_SECS: u64 = 30;
/// Consul's own default for a blocking query.
const DEFAULT_WAIT_SECS: u64 = 60;
/// Consul caps `wait` at ten minutes.
const MAX_WAIT_SECS: u64 = 600;
const OWN_TENANT: &str = "default";
const DEFAULT_META_KEY: &str = "podgate-tenant";

/// The most services one source watches. Each is a blocking query, so a connection to Consul.
const MAX_SERVICES: usize = 512;

/// Changes that arrive within this time of the first one are answered by one pass.
const EVENT_QUIET: Duration = Duration::from_millis(50);

const MIN_RETRY: Duration = Duration::from_millis(100);
const MAX_RETRY: Duration = Duration::from_secs(5);

/// A blocking query that comes back at once with the index it was given is not blocking: the
/// answer is not what Consul sends, and asking again at once would spin.
const IDLE_PAUSE: Duration = Duration::from_secs(1);

/// A `[[source]]` entry of kind `consul` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct ConsulConfigError {
    /// The source's name.
    pub name: Box<str>,
    /// What is wrong, naming the key.
    pub reason: Box<str>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TenantFrom {
    #[default]
    Fixed,
    Meta,
    Namespace,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    address: String,
    token_file: Option<std::path::PathBuf>,
    datacenter: Option<String>,
    namespaces: Option<Vec<String>>,
    partitions: Option<Vec<String>>,
    #[serde(default)]
    tenant_from: TenantFrom,
    tenant: Option<String>,
    namespace_tenants: Option<BTreeMap<String, String>>,
    meta_key: Option<String>,
    #[serde(default)]
    exposed_by_default: bool,
    #[serde(default)]
    connect: bool,
    #[serde(default)]
    stale: bool,
    resync_secs: Option<u64>,
    wait_secs: Option<u64>,
}

/// Where the tenant of an instance comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TenantSource {
    /// The operator names one tenant for the whole source.
    Fixed(Box<str>),
    /// The instance names it in its service's `Meta`; the core honours that only for tenants
    /// that trust the source.
    Meta {
        tenant: Option<Box<str>>,
        key: Box<str>,
    },
    /// The tenant of the Consul namespace the service lives in.
    Namespace(BTreeMap<Box<str>, Box<str>>),
}

/// One place to ask for the catalog: a partition and a namespace, each only on Enterprise.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Scope {
    partition: Option<Box<str>>,
    namespace: Option<Box<str>>,
}

impl Scope {
    /// ` in namespace x of partition y`, or nothing.
    fn describe(&self) -> String {
        let mut text = String::new();
        if let Some(namespace) = &self.namespace {
            text.push_str(&format!(" in namespace {namespace}"));
        }
        if let Some(partition) = &self.partition {
            text.push_str(&format!(" of partition {partition}"));
        }
        text
    }
}

/// The validated `[[source]]` entry.
#[derive(Debug, Clone)]
struct Settings {
    scopes: Vec<Scope>,
    tenants: TenantSource,
    exposed_by_default: bool,
    connect: bool,
    resync: Duration,
    wait: Duration,
}

/// The Consul source.
#[derive(Debug)]
pub struct ConsulSource {
    name: Box<str>,
    settings: Settings,
    client: Client,
}

/// `scheme://authority` of a Consul address, or what is wrong with it.
fn base_of(address: &str) -> Result<String, String> {
    let uri: Uri = address
        .parse()
        .map_err(|_| "address: is not a URL".to_owned())?;
    let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) else {
        return Err("address: must be http://host:port or https://host:port".to_owned());
    };
    if !matches!(scheme, "http" | "https") {
        return Err("address: must be http://host:port or https://host:port".to_owned());
    }
    if uri.path() != "/" && !uri.path().is_empty() || uri.query().is_some() {
        return Err("address: must not have a path or a query".to_owned());
    }
    Ok(format!("{scheme}://{authority}"))
}

/// The distinct, non-empty names of `list`, or what is wrong.
fn names(key: &str, list: Vec<String>) -> Result<Vec<Box<str>>, String> {
    if list.is_empty() || list.iter().any(String::is_empty) {
        return Err(format!("{key}: must name at least one {key}, none empty"));
    }
    let distinct: BTreeSet<&String> = list.iter().collect();
    if distinct.len() != list.len() {
        return Err(format!("{key}: lists a name twice"));
    }
    Ok(list.into_iter().map(Into::into).collect())
}

impl ConsulSource {
    /// A Consul source from its `[[source]]` entry.
    ///
    /// With `tenant_from = "namespace"`, `namespaces` and `namespace_tenants` must name the
    /// same namespaces.
    ///
    /// # Errors
    ///
    /// [`ConsulConfigError`] when a key is unknown or has the wrong type, `address` is not an
    /// HTTP(S) URL, the token file is unreadable or readable by others, or the tenant keys do
    /// not fit `tenant_from`. An unknown key is an error so a misspelt `tenant` cannot move the
    /// source's apps to the default tenant.
    pub fn from_config(config: &SourceConfig) -> Result<Self, ConsulConfigError> {
        let invalid = |reason: String| ConsulConfigError {
            name: config.name.clone(),
            reason: reason.into(),
        };
        let raw = Raw::deserialize(toml::Value::Table(config.settings.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let base = base_of(&raw.address).map_err(invalid)?;
        let resync_secs = raw.resync_secs.unwrap_or(DEFAULT_RESYNC_SECS);
        if resync_secs == 0 {
            return Err(invalid("resync_secs: must be at least 1".to_owned()));
        }
        let wait_secs = raw.wait_secs.unwrap_or(DEFAULT_WAIT_SECS);
        if !(1..=MAX_WAIT_SECS).contains(&wait_secs) {
            return Err(invalid(format!("wait_secs: must be 1 to {MAX_WAIT_SECS}")));
        }
        if raw.datacenter.as_deref().is_some_and(str::is_empty) {
            return Err(invalid("datacenter: is empty".to_owned()));
        }
        if raw.tenant.as_deref().is_some_and(str::is_empty) {
            return Err(invalid("tenant: is empty".to_owned()));
        }
        let token = raw
            .token_file
            .as_deref()
            .map(|path| {
                let token =
                    read_secret_file(path).map_err(|err| invalid(format!("token_file: {err}")))?;
                if token.expose().is_empty() {
                    return Err(invalid("token_file: is empty".to_owned()));
                }
                Ok(token)
            })
            .transpose()?;
        let namespaces = raw
            .namespaces
            .map(|list| names("namespaces", list))
            .transpose()
            .map_err(invalid)?;
        let partitions = raw
            .partitions
            .map(|list| names("partitions", list))
            .transpose()
            .map_err(invalid)?;
        let tenants = tenant_source(
            raw.tenant_from,
            raw.tenant,
            raw.namespace_tenants,
            raw.meta_key,
            namespaces.as_deref(),
        )
        .map_err(invalid)?;
        let scopes = scopes(partitions, namespaces);
        let client = Client::new(
            &base,
            token,
            Query {
                datacenter: raw.datacenter.map(Into::into),
                stale: raw.stale,
            },
        )
        .map_err(invalid)?;
        Ok(Self {
            name: config.name.clone(),
            settings: Settings {
                scopes,
                tenants,
                exposed_by_default: raw.exposed_by_default,
                connect: raw.connect,
                resync: Duration::from_secs(resync_secs),
                wait: Duration::from_secs(wait_secs),
            },
            client,
        })
    }
}

/// Every partition with every namespace; one scope with neither when none is configured.
fn scopes(partitions: Option<Vec<Box<str>>>, namespaces: Option<Vec<Box<str>>>) -> Vec<Scope> {
    let partitions: Vec<Option<Box<str>>> = match partitions {
        Some(list) => list.into_iter().map(Some).collect(),
        None => vec![None],
    };
    let namespaces: Vec<Option<Box<str>>> = match namespaces {
        Some(list) => list.into_iter().map(Some).collect(),
        None => vec![None],
    };
    partitions
        .iter()
        .flat_map(|partition| {
            namespaces.iter().map(|namespace| Scope {
                partition: partition.clone(),
                namespace: namespace.clone(),
            })
        })
        .collect()
}

fn tenant_source(
    from: TenantFrom,
    tenant: Option<String>,
    mapping: Option<BTreeMap<String, String>>,
    meta_key: Option<String>,
    namespaces: Option<&[Box<str>]>,
) -> Result<TenantSource, String> {
    match (from, mapping, meta_key) {
        (TenantFrom::Fixed, None, None) => Ok(TenantSource::Fixed(
            tenant.unwrap_or_else(|| OWN_TENANT.to_owned()).into(),
        )),
        (TenantFrom::Meta, None, key) => {
            if key.as_deref().is_some_and(str::is_empty) {
                return Err("meta_key: is empty".to_owned());
            }
            Ok(TenantSource::Meta {
                tenant: tenant.map(Into::into),
                key: key.unwrap_or_else(|| DEFAULT_META_KEY.to_owned()).into(),
            })
        }
        (TenantFrom::Namespace, Some(mapping), None) if tenant.is_none() => {
            let Some(namespaces) = namespaces else {
                return Err("tenant_from = \"namespace\" needs namespaces".to_owned());
            };
            if let Some(unmapped) = namespaces
                .iter()
                .find(|namespace| !mapping.contains_key(&***namespace))
            {
                return Err(format!(
                    "namespace_tenants: has no tenant for namespace {unmapped:?}"
                ));
            }
            if let Some(extra) = mapping.keys().find(|key| {
                !namespaces
                    .iter()
                    .any(|namespace| &**namespace == key.as_str())
            }) {
                return Err(format!(
                    "namespace_tenants: {extra:?} is not one of the source's namespaces"
                ));
            }
            if mapping.values().any(String::is_empty) {
                return Err("namespace_tenants: a tenant is empty".to_owned());
            }
            Ok(TenantSource::Namespace(
                mapping
                    .into_iter()
                    .map(|(namespace, tenant)| (namespace.into(), tenant.into()))
                    .collect(),
            ))
        }
        (TenantFrom::Namespace, _, _) => Err(
            "tenant_from = \"namespace\" needs namespace_tenants and takes no tenant or meta_key"
                .to_owned(),
        ),
        (TenantFrom::Meta, Some(_), _) | (TenantFrom::Fixed, Some(_), _) => {
            Err("namespace_tenants: only for tenant_from = \"namespace\"".to_owned())
        }
        (TenantFrom::Fixed, None, Some(_)) => {
            Err("meta_key: only for tenant_from = \"meta\"".to_owned())
        }
    }
}

type Key = (Scope, Box<str>);

#[derive(Default)]
struct CatalogView {
    /// `None` until the first answer.
    listed: Option<Catalog>,
    error: Option<Box<str>>,
}

#[derive(Default)]
struct ServiceView {
    /// `None` until the first answer; kept across errors.
    instances: Option<Instances>,
    error: Option<Box<str>>,
}

#[derive(Default)]
struct Views {
    catalogs: BTreeMap<Scope, CatalogView>,
    services: BTreeMap<Key, ServiceView>,
}

/// What the watchers learned, and the way they wake the main loop.
#[derive(Default)]
struct Shared {
    views: Mutex<Views>,
    wake: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Views> {
        self.views.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn catalog(&self, scope: &Scope, result: Result<Catalog, ClientError>) {
        let mut views = self.lock();
        let view = views.catalogs.entry(scope.clone()).or_default();
        let changed = match result {
            Ok(listed) => {
                let changed = view.listed.as_ref() != Some(&listed) || view.error.is_some();
                view.listed = Some(listed);
                view.error = None;
                changed
            }
            Err(err) => replace(&mut view.error, &err),
        };
        drop(views);
        if changed {
            self.wake.notify_one();
        }
    }

    fn instances(&self, key: &Key, result: Result<Instances, ClientError>) {
        let mut views = self.lock();
        // A service that is no longer watched is gone from the map: a late answer is dropped.
        let Some(view) = views.services.get_mut(key) else {
            return;
        };
        let changed = match result {
            Ok(instances) => {
                let changed = view.instances.as_ref() != Some(&instances) || view.error.is_some();
                view.instances = Some(instances);
                view.error = None;
                changed
            }
            Err(err) => replace(&mut view.error, &err),
        };
        drop(views);
        if changed {
            self.wake.notify_one();
        }
    }
}

/// Stores `err` as the error, and says whether that is news.
fn replace(slot: &mut Option<Box<str>>, err: &ClientError) -> bool {
    let text: Box<str> = err.to_string().into();
    let changed = slot.as_deref() != Some(&*text);
    *slot = Some(text);
    changed
}

/// How a watcher asks.
#[derive(Debug, Clone, Copy)]
struct Timing {
    wait: Duration,
    resync: Duration,
}

/// The index to ask with after an answer carrying `got`, when the last question used
/// `previous`. An index that went backwards (a restored snapshot, another server) starts over
/// with a full read; one that is `0` is not one to block on.
fn next_index(previous: u64, got: u64) -> u64 {
    if got == 0 {
        1
    } else if got < previous {
        0
    } else {
        got
    }
}

/// Asks `fetch` again and again: a blocking query on the last index, a full read after every
/// `resync` and after every error, and a pause that grows while errors last.
async fn watch<T, Fut>(
    timing: Timing,
    fetch: impl Fn(Blocking) -> Fut,
    deliver: impl Fn(Result<T, ClientError>),
) where
    Fut: Future<Output = Result<Reply<T>, ClientError>>,
{
    let mut backoff = Backoff::new(MIN_RETRY, MAX_RETRY).jittered();
    let mut index = 0;
    let mut full_at = Instant::now();
    loop {
        let started = Instant::now();
        if started.duration_since(full_at) >= timing.resync {
            index = 0;
        }
        if index == 0 {
            full_at = started;
        }
        let until_resync = timing
            .resync
            .saturating_sub(started.duration_since(full_at));
        let wait = Duration::from_secs(timing.wait.as_secs().min(until_resync.as_secs().max(1)));
        match fetch(Blocking { index, wait }).await {
            Ok(reply) => {
                backoff.reset();
                let next = next_index(index, reply.index);
                let spinning = index > 0 && next == index && started.elapsed() < MIN_RETRY;
                deliver(Ok(reply.body));
                index = next;
                if spinning {
                    tokio::time::sleep(IDLE_PAUSE).await;
                }
            }
            Err(err) => {
                deliver(Err(err));
                index = 0;
                tokio::time::sleep(backoff.next_delay()).await;
            }
        }
    }
}

/// What was last told to the core.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Unavailable(Box<str>),
    Available {
        state: State,
        report: Option<Box<str>>,
    },
}

/// The errors of the watchers, one line per distinct text.
fn errors_text(errors: &BTreeMap<Box<str>, Vec<String>>) -> Vec<String> {
    errors
        .iter()
        .map(|(text, whats)| {
            let shown: Vec<&str> = whats.iter().take(3).map(String::as_str).collect();
            let more = whats.len().saturating_sub(shown.len());
            if more == 0 {
                format!("{text} ({})", shown.join(", "))
            } else {
                format!("{text} ({} and {more} more)", shown.join(", "))
            }
        })
        .collect()
}

impl ConsulSource {
    fn watch_catalog(&self, scope: &Scope, shared: &Arc<Shared>) -> Abort {
        let client = Arc::new(self.client.clone());
        let (scope, shared) = (scope.clone(), Arc::clone(shared));
        let timing = Timing {
            wait: self.settings.wait,
            resync: self.settings.resync,
        };
        Abort(tokio::spawn(async move {
            let fetch = |blocking| {
                let (client, scope) = (Arc::clone(&client), scope.clone());
                async move { client.services(&scope, blocking).await }
            };
            watch(timing, fetch, |result| shared.catalog(&scope, result)).await;
        }))
    }

    fn watch_service(&self, key: &Key, shared: &Arc<Shared>) -> Abort {
        let client = Arc::new(self.client.clone());
        let (key, shared) = (key.clone(), Arc::clone(shared));
        let timing = Timing {
            wait: self.settings.wait,
            resync: self.settings.resync,
        };
        Abort(tokio::spawn(async move {
            let fetch = |blocking| {
                let (client, key) = (Arc::clone(&client), key.clone());
                async move {
                    let reply = client.instances(&key.0, &key.1, blocking).await?;
                    Ok(Reply {
                        body: Instances::from_entries(reply.body),
                        index: reply.index,
                    })
                }
            };
            watch(timing, fetch, |result| shared.instances(&key, result)).await;
        }))
    }

    /// Looks at what the watchers know: starts and stops the watchers of the services worth
    /// watching, and builds the state. `None` when there is nothing to say yet.
    fn observe(
        &self,
        shared: &Arc<Shared>,
        watchers: &mut BTreeMap<Key, Abort>,
        ready: &mut bool,
    ) -> Option<Sent> {
        let mut views = shared.lock();
        let mut notes: Vec<String> = Vec::new();
        let mut errors: BTreeMap<Box<str>, Vec<String>> = BTreeMap::new();
        let mut desired: Vec<Key> = Vec::new();
        let mut loaded = true;
        for (scope, catalog) in &views.catalogs {
            if let Some(err) = &catalog.error {
                errors
                    .entry(err.clone())
                    .or_default()
                    .push(format!("the catalog{}", scope.describe()));
            }
            match &catalog.listed {
                None => loaded = false,
                Some(listed) => desired.extend(
                    listed
                        .iter()
                        .filter(|(_, tags)| {
                            tags::worth_watching(
                                tags.as_deref().unwrap_or_default(),
                                self.settings.exposed_by_default,
                            )
                        })
                        .map(|(name, _)| (scope.clone(), name.clone())),
                ),
            }
        }
        if desired.len() > MAX_SERVICES {
            let left: Vec<&str> = desired[MAX_SERVICES..]
                .iter()
                .take(3)
                .map(|(_, name)| &**name)
                .collect();
            notes.push(format!(
                "{} services are not watched: the cap is {MAX_SERVICES} per source (first left out: {})",
                desired.len() - MAX_SERVICES,
                left.join(", ")
            ));
            desired.truncate(MAX_SERVICES);
        }

        let keep: BTreeSet<&Key> = desired.iter().collect();
        watchers.retain(|key, _| keep.contains(key));
        views.services.retain(|key, _| keep.contains(key));
        for key in &desired {
            if !watchers.contains_key(key) {
                views.services.insert(key.clone(), ServiceView::default());
                watchers.insert(key.clone(), self.watch_service(key, shared));
            }
        }

        let mut settled = loaded;
        let mut services: Vec<Service<'_>> = Vec::new();
        for key in &desired {
            let Some(view) = views.services.get(key) else {
                continue;
            };
            if let Some(err) = &view.error {
                errors
                    .entry(err.clone())
                    .or_default()
                    .push(format!("service {}", key.1));
            }
            match &view.instances {
                Some(instances) => {
                    if instances.beyond_cap > 0 {
                        notes.push(format!(
                            "service {}: {} instances more than the cap of {} are not used",
                            key.1,
                            instances.beyond_cap,
                            model::MAX_INSTANCES
                        ));
                    }
                    services.push(Service {
                        scope: &key.0,
                        name: &key.1,
                        instances: &instances.list,
                    });
                }
                None if view.error.is_none() => settled = false,
                None => {}
            }
        }
        if !*ready && !settled {
            let lines = errors_text(&errors);
            return (!lines.is_empty()).then(|| Sent::Unavailable(lines.join("; ").into()));
        }
        *ready = true;

        let mut built = apps::build(&self.name, &self.settings, &services);
        built.reports.extend(notes.into_iter().map(Into::into));
        built
            .reports
            .extend(errors_text(&errors).into_iter().map(Into::into));
        for line in &built.reports {
            debug!(source = %self.name, "{line}");
        }
        let report = (!built.reports.is_empty()).then(|| built.reports.join("; ").into());
        Some(Sent::Available {
            state: State {
                apps: built.apps,
                certificates: Vec::new(),
            },
            report,
        })
    }
}

impl Source for ConsulSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let shared = Arc::new(Shared::default());
        {
            let mut views = shared.lock();
            for scope in &self.settings.scopes {
                views.catalogs.insert(scope.clone(), CatalogView::default());
            }
        }
        let _catalogs: Vec<Abort> = self
            .settings
            .scopes
            .iter()
            .map(|scope| self.watch_catalog(scope, &shared))
            .collect();
        let mut watchers: BTreeMap<Key, Abort> = BTreeMap::new();
        let mut ready = false;
        let mut sent: Option<Sent> = None;
        loop {
            shared.wake.notified().await;
            tokio::time::sleep(EVENT_QUIET).await;
            let Some(observed) = self.observe(&shared, &mut watchers, &mut ready) else {
                continue;
            };
            if sent.as_ref() == Some(&observed) {
                continue;
            }
            let outgoing = match &observed {
                Sent::Unavailable(why) => vec![Update::outage(&self.name, why)],
                Sent::Available { state, report } => {
                    let mut outgoing = vec![Update {
                        source: self.name.clone(),
                        body: UpdateBody::State(state.clone()),
                    }];
                    if let Some(report) = report {
                        warn!(source = %self.name, "{report}");
                        outgoing.push(Update::outage(&self.name, report));
                    }
                    outgoing
                }
            };
            sent = Some(observed);
            for update in outgoing {
                if updates.send(update).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn index_resets_when_it_goes_backwards() {
        assert_eq!(next_index(0, 42), 42, "the first answer");
        assert_eq!(next_index(42, 57), 57, "a change");
        assert_eq!(next_index(42, 42), 42, "a wait that timed out");
        assert_eq!(next_index(42, 7), 0, "a restored snapshot: read in full");
        assert_eq!(
            next_index(0, 0),
            1,
            "no index: never zero, which would not block"
        );
    }

    #[test]
    fn address_is_a_bare_http_url() {
        assert_eq!(
            base_of("http://127.0.0.1:8500").as_deref(),
            Ok("http://127.0.0.1:8500")
        );
        assert_eq!(
            base_of("https://consul.example/").as_deref(),
            Ok("https://consul.example")
        );
        for bad in [
            "127.0.0.1:8500",
            "unix:///run/consul.sock",
            "http://x/v1",
            "http://x/?a=b",
            "",
        ] {
            assert!(base_of(bad).is_err(), "{bad}");
        }
    }
}
