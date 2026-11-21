//! The Nomad source: service registrations tagged `podgate.*` become apps.
//!
//! ```toml
//! [[source]]
//! kind = "nomad"
//! name = "nomad-prod"
//! address = "http://127.0.0.1:4646"
//! token_file = "/etc/podgate/nomad-token"   # sent as X-Nomad-Token, never logged
//! namespaces = ["default", "team-a"]
//! namespace_tenants = { team-a = "acme" }
//! default_tenant = "default"
//! exposed_by_default = false
//! resync_secs = 30
//! ```
//!
//! The server of an app is the registered `Address:Port` of an instance, never an address a tag
//! spells out. Instances of one service name in one namespace form one app; each namespace maps
//! to a tenant. The tags are the Docker labels written `key=value` ([`crate::docker::labels`]).
//!
//! The source lists `GET /v1/services` per namespace as a blocking query
//! (`?index=<n>&wait=60s`), and reads the instances of every service that may be exposed with
//! `GET /v1/service/<name>` whenever the index moves, on every reconnect and every
//! `resync_secs`. It only ever sends `GET` requests (see `client`).
//!
//! A registration that carries tags but cannot be used (an unknown or address-bearing tag, an
//! address that is not an IP) is left out and reported next to the state, as an outage text
//! naming it, like the Docker source does. A server that cannot be reached keeps the last state
//! in force and is reported the same way.
//!
//! The reference is `docs/ref/provider-nomad.md`.

mod apps;
mod client;
mod model;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use http::Uri;
use http::uri::Scheme;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

use crate::abort::Abort;
use crate::acme::Secret;
use crate::config::SourceConfig;
use crate::push::Backoff;
use crate::source::{Source, State, Update, UpdateBody};

use client::{Client, ClientError};
use model::Instance;

const DEFAULT_NAMESPACE: &str = "default";
const DEFAULT_RESYNC_SECS: u64 = 30;
const OWN_TENANT: &str = "default";

/// Changes that arrive within this time of the first one are answered by one pass.
const EVENT_QUIET: Duration = Duration::from_millis(50);

const MIN_RETRY: Duration = Duration::from_millis(100);
const MAX_RETRY: Duration = Duration::from_secs(5);

/// A `[[source]]` entry of kind `nomad` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct NomadConfigError {
    /// The source's name.
    pub name: Box<str>,
    /// What is wrong, naming the key.
    pub reason: Box<str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    address: String,
    token_file: Option<PathBuf>,
    namespaces: Option<Vec<String>>,
    namespace_tenants: Option<BTreeMap<String, String>>,
    default_tenant: Option<String>,
    #[serde(default)]
    exposed_by_default: bool,
    #[serde(default)]
    stale: bool,
    resync_secs: Option<u64>,
}

/// The validated `[[source]]` entry.
#[derive(Debug, Clone)]
struct Settings {
    client: Client,
    namespaces: Vec<Box<str>>,
    /// The tenant of every configured namespace.
    tenants: BTreeMap<Box<str>, Box<str>>,
    exposed_by_default: bool,
    resync: Duration,
}

/// The Nomad source.
#[derive(Debug)]
pub struct NomadSource {
    name: Box<str>,
    settings: Settings,
}

impl NomadSource {
    /// A Nomad source from its `[[source]]` entry.
    ///
    /// `namespaces` defaults to `["default"]`. A namespace without an entry in
    /// `namespace_tenants` belongs to `default_tenant`. The token file is read here, once.
    ///
    /// # Errors
    ///
    /// [`NomadConfigError`] when a key is unknown or has the wrong type, `address` is not an
    /// `http://` or `https://` URL with a host, a namespace or tenant name is empty, a key of
    /// `namespace_tenants` is not one of the namespaces, `token_file` cannot be read or holds no
    /// token, or the platform's root certificates cannot be loaded. An unknown key is an error so
    /// a misspelt `namespace_tenants` cannot move the source's apps to the default tenant.
    pub fn from_config(config: &SourceConfig) -> Result<Self, NomadConfigError> {
        let invalid = |reason: String| NomadConfigError {
            name: config.name.clone(),
            reason: reason.into(),
        };
        let raw = Raw::deserialize(toml::Value::Table(config.settings.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let base = base_url(&raw.address).map_err(|why| invalid(format!("address: {why}")))?;
        let token = raw
            .token_file
            .as_ref()
            .map(|path| {
                let text = fs::read_to_string(path)
                    .map_err(|err| format!("token_file: cannot read {}: {err}", path.display()))?;
                let token = text.trim();
                if token.is_empty() {
                    return Err(format!("token_file: {} is empty", path.display()));
                }
                Ok(Secret::new(token))
            })
            .transpose()
            .map_err(invalid)?;
        let namespaces = raw
            .namespaces
            .unwrap_or_else(|| vec![DEFAULT_NAMESPACE.to_owned()]);
        if namespaces.is_empty() {
            return Err(invalid("namespaces: must name at least one".to_owned()));
        }
        if let Some(bad) = namespaces
            .iter()
            .find(|namespace| namespace.is_empty() || namespace.contains(['*', ' ', '\t']))
        {
            return Err(invalid(format!(
                "namespaces: {bad:?} must be one namespace's name, not empty and not a wildcard"
            )));
        }
        let default_tenant = raw.default_tenant.unwrap_or_else(|| OWN_TENANT.to_owned());
        let mapping = raw.namespace_tenants.unwrap_or_default();
        if let Some(extra) = mapping.keys().find(|key| !namespaces.contains(key)) {
            return Err(invalid(format!(
                "namespace_tenants: {extra:?} is not one of the source's namespaces"
            )));
        }
        if default_tenant.is_empty() || mapping.values().any(String::is_empty) {
            return Err(invalid(
                "default_tenant and namespace_tenants: a tenant is empty".to_owned(),
            ));
        }
        let resync_secs = raw.resync_secs.unwrap_or(DEFAULT_RESYNC_SECS);
        if resync_secs == 0 {
            return Err(invalid("resync_secs: must be at least 1".to_owned()));
        }
        let tenants = namespaces
            .iter()
            .map(|namespace| {
                let tenant = mapping.get(namespace).unwrap_or(&default_tenant);
                (namespace.as_str().into(), tenant.as_str().into())
            })
            .collect();
        let client = Client::new(&base, token, raw.stale).map_err(invalid)?;
        Ok(Self {
            name: config.name.clone(),
            settings: Settings {
                client,
                namespaces: namespaces.iter().map(|n| n.as_str().into()).collect(),
                tenants,
                exposed_by_default: raw.exposed_by_default,
                resync: Duration::from_secs(resync_secs),
            },
        })
    }
}

/// `scheme://authority` of an `http` or `https` address; a path, query or credentials are
/// errors.
fn base_url(address: &str) -> Result<String, &'static str> {
    let uri: Uri = address.parse().map_err(|_| "is not a URL")?;
    let scheme = uri.scheme().ok_or("needs http:// or https://")?;
    if *scheme != Scheme::HTTP && *scheme != Scheme::HTTPS {
        return Err("must be an http:// or https:// URL");
    }
    let authority = uri.authority().ok_or("needs a host")?;
    if authority.as_str().contains('@') {
        return Err("must not carry credentials; the token goes in token_file");
    }
    if uri.path() != "/" && !uri.path().is_empty() || uri.query().is_some() {
        return Err("must be the server's origin, without a path or a query");
    }
    Ok(format!("{scheme}://{authority}"))
}

/// Holds a blocking query on the services of `namespace` open and wakes the main loop whenever
/// the index moves, and once per (re)connect: a change between the last list and the connect
/// would otherwise be seen only at the next resync.
async fn watch(client: Client, namespace: Box<str>, wake: Arc<Notify>) {
    let mut backoff = Backoff::new(MIN_RETRY, MAX_RETRY);
    let mut failing = false;
    let mut index = 0;
    loop {
        match client.block(&namespace, index).await {
            Ok(answered) => {
                if failing {
                    debug!(namespace = %namespace, "the blocking query is back");
                }
                failing = false;
                backoff.reset();
                if answered != index {
                    // An index that went backwards means the state was reset: start over.
                    index = if answered < index { 0 } else { answered };
                    wake.notify_one();
                } else {
                    // The wait ran out, or the server answered early: never spin.
                    tokio::time::sleep(MIN_RETRY).await;
                }
            }
            Err(err) => {
                if !failing {
                    warn!(namespace = %namespace, error = %err, "the blocking query failed; changes show at the next resync");
                    wake.notify_one();
                }
                failing = true;
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

impl NomadSource {
    /// Lists the registrations and builds the state; the error is Nomad's.
    async fn sync(&self) -> Result<(State, Option<Box<str>>), ClientError> {
        let client = &self.settings.client;
        let mut instances: Vec<Instance> = Vec::new();
        for namespace in &self.settings.namespaces {
            for service in client.services(namespace).await? {
                let tags = service.tags.as_deref().unwrap_or_default();
                if !apps::worth_fetching(tags, self.settings.exposed_by_default) {
                    continue;
                }
                instances.extend(client.instances(namespace, &service.name).await?);
            }
        }
        let built = apps::build(&self.name, &self.settings, &instances);
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

impl Source for NomadSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let wake = Arc::new(Notify::new());
        let _watchers: Vec<Abort> = self
            .settings
            .namespaces
            .iter()
            .map(|namespace| {
                Abort(tokio::spawn(watch(
                    self.settings.client.clone(),
                    namespace.clone(),
                    Arc::clone(&wake),
                )))
            })
            .collect();
        let mut sent: Option<Sent> = None;
        let mut retry = Backoff::new(MIN_RETRY, MAX_RETRY);
        let mut wait = Duration::ZERO;
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = wake.notified() => tokio::time::sleep(EVENT_QUIET).await,
            }
            let observed = match self.sync().await {
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
