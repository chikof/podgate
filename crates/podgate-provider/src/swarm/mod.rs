//! The Docker Swarm source: services labelled for podgate become apps, their servers the
//! addresses of their tasks (or the service's virtual IP) on one overlay network.
//!
//! ```toml
//! [[source]]
//! kind = "swarm"
//! name = "swarm-prod"
//! socket = "/var/run/docker.sock"      # a manager node's socket, or a read-only socket proxy
//! network = "podgate_overlay"          # the overlay network podgate is attached to
//! endpoint = "tasks"                   # "tasks" (default) or "vip"
//! tenant_from = "fixed"                # "fixed", "network" or "label"
//! tenant = "acme"
//! exposed_by_default = false
//! refresh_secs = 5
//! resync_secs = 60
//! ```
//!
//! Labels are read from the service (`Spec.Labels`, a stack's `deploy.labels`), never from the
//! containers of its tasks, with the keys and the strictness of the Docker source
//! ([`crate::docker::labels`]). With `endpoint = "tasks"` the servers are the addresses the
//! engine gave the running tasks on `network`; with `"vip"` the only server is the service's
//! virtual IP on it. A task or service that cannot be used (an unknown or address-bearing label,
//! no address on the network) is left out and reported next to the state, as an outage text
//! naming it. A manager that cannot be reached keeps the last state in force and is reported the
//! same way. The source only ever sends `GET` requests.
//!
//! The reference is `docs/ref/provider-swarm.md`.

mod apps;
pub(crate) mod model;
mod tasks;
mod vip;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::sync::mpsc::Sender;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::abort::Abort;
use crate::config::SourceConfig;
use crate::docker::client::{Client, ClientError};
use crate::docker::{Networks, Stream, TenantFrom, TenantSource, tenant_source, watch};
use crate::push::Backoff;
use crate::source::{Source, State, Update, UpdateBody};

use apps::Observed;

const DEFAULT_SOCKET: &str = "/var/run/docker.sock";
const DEFAULT_REFRESH_SECS: u64 = 5;
const DEFAULT_RESYNC_SECS: u64 = 60;

/// Events that arrive within this time of the first one are answered by one refresh.
const EVENT_QUIET: Duration = Duration::from_millis(50);

const MIN_RETRY: Duration = Duration::from_millis(100);
const MAX_RETRY: Duration = Duration::from_secs(5);

/// A `[[source]]` entry of kind `swarm` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct SwarmConfigError {
    /// The source's name.
    pub name: Box<str>,
    /// What is wrong, naming the key.
    pub reason: Box<str>,
}

/// Where the servers of a service come from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EndpointMode {
    /// One server per running task: its address on the configured network.
    #[default]
    Tasks,
    /// One server: the service's virtual IP on the configured network.
    Vip,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    socket: Option<PathBuf>,
    network: Networks,
    #[serde(default)]
    endpoint: EndpointMode,
    #[serde(default)]
    tenant_from: TenantFrom,
    tenant: Option<String>,
    network_tenants: Option<BTreeMap<String, String>>,
    #[serde(default)]
    exposed_by_default: bool,
    refresh_secs: Option<u64>,
    resync_secs: Option<u64>,
}

/// The validated `[[source]]` entry.
#[derive(Debug, Clone)]
struct Settings {
    socket: PathBuf,
    /// In order of preference: the first one a task (or service) has an address on gives its
    /// server.
    networks: Vec<String>,
    endpoint: EndpointMode,
    tenants: TenantSource,
    exposed_by_default: bool,
    refresh: Duration,
    resync: Duration,
}

/// A server candidate: a task's address, or the service's virtual IP.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Backend {
    /// What reports call it: `<service>.<slot>` for a task, the service name for the VIP.
    name: String,
    address: IpAddr,
    /// The configured networks it has an address on, in the source's order of preference.
    networks: Vec<String>,
}

/// The Docker Swarm source.
#[derive(Debug)]
pub struct SwarmSource {
    name: Box<str>,
    settings: Settings,
}

impl SwarmSource {
    /// A Swarm source from its `[[source]]` entry.
    ///
    /// `network` is a name or a list of names. With `tenant_from = "network"`, `network_tenants`
    /// must map every one of them to a tenant.
    ///
    /// # Errors
    ///
    /// [`SwarmConfigError`] when a key is unknown or has the wrong type, `network` is missing or
    /// empty, or the tenant keys do not fit `tenant_from`. An unknown key is an error so a
    /// misspelt `tenant` cannot move the source's apps to the default tenant.
    pub fn from_config(config: &SourceConfig) -> Result<Self, SwarmConfigError> {
        let invalid = |reason: String| SwarmConfigError {
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
        let refresh_secs = raw.refresh_secs.unwrap_or(DEFAULT_REFRESH_SECS);
        if refresh_secs == 0 {
            return Err(invalid("refresh_secs: must be at least 1".to_owned()));
        }
        let resync_secs = raw.resync_secs.unwrap_or(DEFAULT_RESYNC_SECS);
        if resync_secs < refresh_secs {
            return Err(invalid(
                "resync_secs: must be at least refresh_secs".to_owned(),
            ));
        }
        let tenants = tenant_source(raw.tenant_from, raw.tenant, raw.network_tenants, &networks)
            .map_err(invalid)?;
        Ok(Self {
            name: config.name.clone(),
            settings: Settings {
                socket,
                networks,
                endpoint: raw.endpoint,
                tenants,
                exposed_by_default: raw.exposed_by_default,
                refresh: Duration::from_secs(refresh_secs),
                resync: Duration::from_secs(resync_secs),
            },
        })
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

/// A list the engine may refuse: a socket proxy in front of it need not offer every endpoint.
/// A refusal is `None`; a manager that cannot be reached is still an error.
fn optional<T>(answer: Result<T, ClientError>) -> Result<Option<T>, ClientError> {
    match answer {
        Ok(list) => Ok(Some(list)),
        Err(ClientError::Status { status, path, .. }) => {
            debug!(status, %path, "the engine does not offer the list; going without it");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

impl SwarmSource {
    /// Reads services, tasks, nodes and networks and builds the state; the error is the
    /// manager's.
    async fn sync(&self, client: &Client) -> Result<(State, Option<Box<str>>), ClientError> {
        let observed = Observed {
            services: client.swarm_services().await?,
            tasks: client.swarm_tasks().await?,
            nodes: optional(client.swarm_nodes().await)?,
            networks: optional(client.swarm_networks().await)?,
        };
        let built = apps::build(&self.name, &self.settings, &observed);
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

impl Source for SwarmSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let client = Client::new(self.settings.socket.clone());
        let wake = Arc::new(Notify::new());
        let _watcher = Abort(tokio::spawn(watch(
            client.clone(),
            Arc::clone(&wake),
            Stream::Swarm,
        )));
        let mut sent: Option<Sent> = None;
        let mut sent_at = Instant::now();
        let mut retry = Backoff::new(MIN_RETRY, MAX_RETRY).jittered();
        let mut wait = Duration::ZERO;
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = wake.notified() => tokio::time::sleep(EVENT_QUIET).await,
            }
            let observed = match self.sync(&client).await {
                Ok((state, report)) => {
                    retry.reset();
                    wait = self.settings.refresh;
                    Sent::Available { state, report }
                }
                Err(err) => {
                    wait = retry.next_delay();
                    Sent::Unavailable(format!("{err}").into())
                }
            };
            // An unchanged observation is told again only at the resync.
            if sent.as_ref() == Some(&observed) && sent_at.elapsed() < self.settings.resync {
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
            sent_at = Instant::now();
            for update in outgoing {
                if updates.send(update).await.is_err() {
                    return;
                }
            }
        }
    }
}
