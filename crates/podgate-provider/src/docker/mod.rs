//! The Docker and Podman source: running containers become apps through their `podgate.*`
//! labels.
//!
//! ```toml
//! [[source]]
//! kind = "docker"
//! name = "docker-prod"
//! socket = "/var/run/docker.sock"      # Podman: /run/podman/podman.sock
//! network = "podgate"                  # the network whose container addresses podgate reaches
//! tenant_from = "fixed"                # "fixed", "network" or "label"
//! tenant = "acme"
//! exposed_by_default = false
//! resync_secs = 30
//! ```
//!
//! The server of an app is the container's own address on `network` plus the port label, never
//! an address a label spells out ([`labels`]). Only running containers, and when the image has a
//! health check only healthy ones, are servers. The source lists the containers, then follows
//! the daemon's `/events` stream and lists again on every container event, on every reconnect
//! and every `resync_secs`. It only ever sends `GET` requests (see `client`), so a socket proxy
//! that allows nothing else is enough.
//!
//! A container that carries labels but cannot be used (an unknown or address-bearing label, no
//! address on the network) is left out and reported next to the state, as an outage text naming
//! it, like the file source does for a broken file. A daemon that cannot be reached keeps the
//! last state in force and is reported the same way.
//!
//! The reference is `docs/ref/provider-docker.md`.

mod apps;
pub(crate) mod client;
pub mod labels;
pub(crate) mod model;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

use crate::abort::Abort;
use crate::config::SourceConfig;
use crate::push::Backoff;
use crate::source::{Source, State, TenantClaim, Update, UpdateBody};

use client::{Client, ClientError};

const DEFAULT_SOCKET: &str = "/var/run/docker.sock";
const DEFAULT_RESYNC_SECS: u64 = 30;
const OWN_TENANT: &str = "default";

/// Events that arrive within this time of the first one are answered by one list.
const EVENT_QUIET: Duration = Duration::from_millis(50);

const MIN_RETRY: Duration = Duration::from_millis(100);
const MAX_RETRY: Duration = Duration::from_secs(5);

/// A `[[source]]` entry of kind `docker` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct DockerConfigError {
    /// The source's name.
    pub name: Box<str>,
    /// What is wrong, naming the key.
    pub reason: Box<str>,
}

/// The `network` key: one name or a list of names.
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Networks {
    One(String),
    Many(Vec<String>),
}

impl Networks {
    /// The names, in the order given.
    ///
    /// # Errors
    ///
    /// The reason, naming the key, when no name is given or one is empty.
    pub(crate) fn names(self) -> Result<Vec<String>, String> {
        let networks = match self {
            Self::One(network) => vec![network],
            Self::Many(networks) => networks,
        };
        if networks.is_empty() || networks.iter().any(String::is_empty) {
            return Err("network: must name at least one network".to_owned());
        }
        Ok(networks)
    }
}

/// The `tenant_from` key.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TenantFrom {
    #[default]
    Fixed,
    Network,
    Label,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    socket: Option<PathBuf>,
    network: Networks,
    #[serde(default)]
    tenant_from: TenantFrom,
    tenant: Option<String>,
    network_tenants: Option<BTreeMap<String, String>>,
    #[serde(default)]
    exposed_by_default: bool,
    resync_secs: Option<u64>,
}

/// Where the tenant of a container (or service) comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TenantSource {
    /// The operator names one tenant for the whole source.
    Fixed(Box<str>),
    /// The tenant of the network the container is on.
    Network(BTreeMap<String, Box<str>>),
    /// The container names it; the core honours that only for tenants that trust the source.
    Label(Option<Box<str>>),
}

/// The tenant source of the keys `tenant_from`, `tenant` and `network_tenants`, for the
/// source's `networks`.
///
/// # Errors
///
/// The reason, naming the key, when the keys do not fit `tenant_from`.
pub(crate) fn tenant_source(
    from: TenantFrom,
    tenant: Option<String>,
    network_tenants: Option<BTreeMap<String, String>>,
    networks: &[String],
) -> Result<TenantSource, String> {
    if tenant.as_deref().is_some_and(str::is_empty) {
        return Err("tenant: is empty".to_owned());
    }
    match (from, network_tenants) {
        (TenantFrom::Fixed, None) => Ok(TenantSource::Fixed(
            tenant.unwrap_or_else(|| OWN_TENANT.to_owned()).into(),
        )),
        (TenantFrom::Label, None) => Ok(TenantSource::Label(tenant.map(Into::into))),
        (TenantFrom::Network, Some(mapping)) if tenant.is_none() => {
            let unmapped: Vec<&String> = networks
                .iter()
                .filter(|network| !mapping.contains_key(*network))
                .collect();
            if !unmapped.is_empty() {
                return Err(format!(
                    "network_tenants: has no tenant for network {unmapped:?}"
                ));
            }
            if let Some(extra) = mapping.keys().find(|key| !networks.contains(key)) {
                return Err(format!(
                    "network_tenants: {extra:?} is not one of the source's networks"
                ));
            }
            Ok(TenantSource::Network(
                mapping
                    .into_iter()
                    .map(|(network, tenant)| (network, tenant.into()))
                    .collect(),
            ))
        }
        (TenantFrom::Network, _) => Err(
            "tenant_from = \"network\" needs network_tenants and takes no tenant".to_owned(),
        ),
        (_, Some(_)) => Err("network_tenants: only for tenant_from = \"network\"".to_owned()),
    }
}

impl TenantSource {
    /// The claim of an object that has an address on `reachable` networks and names `label` as
    /// its tenant, if it does.
    ///
    /// # Errors
    ///
    /// The reason, when the object is on the networks of several tenants.
    pub(crate) fn claim(
        &self,
        reachable: &[&str],
        label: Option<&str>,
    ) -> Result<TenantClaim, String> {
        let claim = match self {
            Self::Fixed(tenant) => TenantClaim::mapped(tenant),
            Self::Network(mapping) => {
                let tenants: BTreeSet<&str> = reachable
                    .iter()
                    .filter_map(|network| mapping.get(*network).map(|tenant| &**tenant))
                    .collect();
                match tenants.len() {
                    1 => TenantClaim::mapped(tenants.first().copied().unwrap_or_default()),
                    _ => {
                        return Err(format!(
                            "it is attached to the networks of several tenants ({tenants:?}); it must belong to one"
                        ));
                    }
                }
            }
            Self::Label(mapped) => {
                mapped
                    .as_deref()
                    .map_or_else(TenantClaim::none, TenantClaim::mapped)
            }
        };
        Ok(match (self, label) {
            (Self::Label(_), Some(tenant)) => claim.with_label(tenant),
            _ => claim,
        })
    }
}

/// The validated `[[source]]` entry.
#[derive(Debug, Clone)]
struct Settings {
    socket: PathBuf,
    /// In order of preference: the first one a container has an address on gives its server.
    networks: Vec<String>,
    tenants: TenantSource,
    exposed_by_default: bool,
    resync: Duration,
}

/// The Docker and Podman source.
#[derive(Debug)]
pub struct DockerSource {
    name: Box<str>,
    settings: Settings,
}

impl DockerSource {
    /// A Docker source from its `[[source]]` entry.
    ///
    /// `network` is a name or a list of names. With `tenant_from = "network"`, `network_tenants`
    /// must map every one of them to a tenant.
    ///
    /// # Errors
    ///
    /// [`DockerConfigError`] when a key is unknown or has the wrong type, `network` is missing
    /// or empty, or the tenant keys do not fit `tenant_from`. An unknown key is an error so a
    /// misspelt `tenant` cannot move the source's apps to the default tenant.
    pub fn from_config(config: &SourceConfig) -> Result<Self, DockerConfigError> {
        let invalid = |reason: String| DockerConfigError {
            name: config.name.clone(),
            reason: reason.into(),
        };
        let raw = Raw::deserialize(toml::Value::Table(config.settings.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let networks = raw.network.names().map_err(invalid)?;
        let socket = raw.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
        if socket.as_os_str().is_empty() {
            return Err(invalid("socket: is empty".to_owned()));
        }
        let resync_secs = raw.resync_secs.unwrap_or(DEFAULT_RESYNC_SECS);
        if resync_secs == 0 {
            return Err(invalid("resync_secs: must be at least 1".to_owned()));
        }
        let tenants = tenant_source(
            raw.tenant_from,
            raw.tenant,
            raw.network_tenants,
            &networks,
        )
        .map_err(invalid)?;
        Ok(Self {
            name: config.name.clone(),
            settings: Settings {
                socket,
                networks,
                tenants,
                exposed_by_default: raw.exposed_by_default,
                resync: Duration::from_secs(resync_secs),
            },
        })
    }
}

/// Holds the event stream open and wakes the main loop on every container change, and once
/// per (re)connect: a change between the last list and the connect would otherwise be seen only
/// at the next resync.
async fn watch(client: Client, wake: Arc<Notify>) {
    let mut backoff = Backoff::new(MIN_RETRY, MAX_RETRY);
    let mut failing = false;
    loop {
        match client.events().await {
            Ok(mut events) => {
                if failing {
                    debug!("the daemon's event stream is back");
                }
                backoff.reset();
                wake.notify_one();
                loop {
                    match events.next().await {
                        Ok(Some(event)) => {
                            if event.changes_containers() {
                                wake.notify_one();
                            }
                        }
                        Ok(None) => break,
                        Err(err) => {
                            warn!(error = %err, "the daemon's event stream broke");
                            break;
                        }
                    }
                }
                // The daemon may be gone: let the main loop look instead of waiting for the
                // next resync.
                failing = true;
                wake.notify_one();
            }
            Err(err) => {
                if !failing {
                    warn!(error = %err, "cannot open the daemon's event stream; changes show at the next resync");
                    wake.notify_one();
                }
                failing = true;
            }
        }
        tokio::time::sleep(backoff.next_delay()).await;
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

impl DockerSource {
    /// Lists the containers and builds the state; the error is the daemon's.
    async fn sync(
        &self,
        client: &Client,
        first_seen: &mut BTreeMap<Box<str>, u64>,
    ) -> Result<(State, Option<Box<str>>), ClientError> {
        let mut containers = Vec::new();
        for id in client.list().await? {
            if let Some(container) = client.inspect(&id).await? {
                containers.push(container);
            }
        }
        let mut built = apps::build(&self.name, &self.settings, &containers, first_seen);
        // Advisory: a socket proxy may not offer the endpoint, and a missing network shows in
        // the per-container reports as well.
        if let Ok(existing) = client.networks().await {
            for network in &self.settings.networks {
                if !existing.contains(network) {
                    built
                        .reports
                        .push(format!("network {network:?} does not exist on the daemon").into());
                }
            }
        }
        for line in &built.reports {
            debug!(source = %self.name, "{line}");
        }
        let report = (!built.reports.is_empty()).then(|| built.reports.join("; ").into());
        Ok((
            State {
                apps: built.apps,
                certificates: Vec::new(),
            },
            report,
        ))
    }
}

impl Source for DockerSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let client = Client::new(self.settings.socket.clone());
        let wake = Arc::new(Notify::new());
        let _watcher = Abort(tokio::spawn(watch(client.clone(), Arc::clone(&wake))));
        let mut first_seen = BTreeMap::new();
        let mut sent: Option<Sent> = None;
        let mut retry = Backoff::new(MIN_RETRY, MAX_RETRY);
        let mut wait = Duration::ZERO;
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = wake.notified() => tokio::time::sleep(EVENT_QUIET).await,
            }
            let observed = match self.sync(&client, &mut first_seen).await {
                Ok((state, report)) => {
                    retry.reset();
                    wait = self.settings.resync;
                    Sent::Available { state, report }
                }
                Err(err) => {
                    wait = retry.next_delay();
                    Sent::Unavailable(format!("{err}").into())
                }
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
