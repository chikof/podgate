//! The etcd source: a key prefix per tenant, read through etcd's JSON gateway and followed with a
//! watch.
//!
//! ```toml
//! [[source]]
//! kind = "etcd"
//! name = "etcd"
//! endpoints = ["https://etcd-1.internal:2379", "https://etcd-2.internal:2379"]
//! username = "podgate"                      # a read-only etcd user
//! password_file = "/etc/podgate/etcd-password"
//! watch = true
//! resync_secs = 60
//!
//! [source.tls]
//! ca_file = "/etc/podgate/etcd-ca.pem"
//! cert_file = "/etc/podgate/etcd-client.pem"
//! key_file = "/etc/podgate/etcd-client-key.pem"
//!
//! [[source.prefix]]
//! prefix = "podgate/acme"
//! tenant = "acme"
//! layout = "podgate-json"
//! ```
//!
//! What the keys mean, who may write which, and the limits are the shared key-value layer's
//! ([`crate::kv`]); this module is the connection. Every prefix is read with
//! `POST /v3/kv/range` and followed with `POST /v3/watch` from the revision of that read. A
//! compaction error, a broken stream and `resync_secs` each trigger a full read, and an etcd that
//! cannot be reached keeps the last state in force. The client can only read (see `client`).
//!
//! Plain `http://` endpoints are accepted for loopback addresses only; the credentials and the
//! configuration of a tenant do not cross a network unprotected. The CA, client certificate and
//! password are read once at startup.
//!
//! The reference is `docs/ref/provider-etcd.md` and, for the layouts, `docs/ref/provider-kv.md`.

mod auth;
mod client;
mod watch;

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::Uri;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::mpsc::{self, Sender};
use tokio::time::Instant;
use tracing::warn;

use crate::abort::Abort;
use crate::acme::Secret;
use crate::config::SourceConfig;
use crate::kv::{self, Mapping, RawPrefix};
use crate::policy::UpstreamPolicy;
use crate::source::{Source, State, Update, UpdateBody};

use auth::Credentials;
use client::{Change, Client, TlsPem};
use watch::Msg;

const DEFAULT_RESYNC_SECS: u64 = 60;

/// Changes that arrive within this time of the previous one are answered by one pass.
const EVENT_QUIET: Duration = Duration::from_millis(50);

/// The longest a pass waits for the changes to settle.
const EVENT_MAX_WAIT: Duration = Duration::from_millis(250);

/// A `[[source]]` entry of kind `etcd` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct EtcdConfigError {
    /// The source's name.
    pub name: Box<str>,
    /// What is wrong, naming the key.
    pub reason: Box<str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    ca_file: Option<PathBuf>,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    endpoints: Vec<String>,
    tls: Option<RawTls>,
    username: Option<String>,
    password_file: Option<PathBuf>,
    #[serde(default)]
    prefix: Vec<RawPrefix>,
    watch: Option<bool>,
    resync_secs: Option<u64>,
}

/// The etcd source.
#[derive(Debug)]
pub struct EtcdSource {
    name: Box<str>,
    client: Client,
    mapping: Mapping,
    watch: bool,
    resync: Duration,
}

/// `scheme://authority` of an endpoint. `http` only for a loopback host.
fn endpoint(address: &str) -> Result<Box<str>, &'static str> {
    let uri: Uri = address.parse().map_err(|_| "is not a URL")?;
    let scheme = uri.scheme_str().ok_or("needs http:// or https://")?;
    if scheme != "http" && scheme != "https" {
        return Err("must be an http:// or https:// URL");
    }
    let authority = uri.authority().ok_or("needs a host")?;
    if authority.as_str().contains('@') {
        return Err("must not carry credentials; the password goes in password_file");
    }
    if uri.path() != "/" && !uri.path().is_empty() || uri.query().is_some() {
        return Err("must be the server's origin, without a path or a query");
    }
    if scheme == "http" {
        let host = authority.host().trim_matches(['[', ']']);
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !loopback {
            return Err("must be https:// unless the server is on this machine");
        }
    }
    Ok(format!("{scheme}://{authority}").into())
}

fn read(key: &str, path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|err| format!("{key}: cannot read {}: {err}", path.display()))
}

impl EtcdSource {
    /// An etcd source from its `[[source]]` entry, checking its tenants against `policy`.
    ///
    /// # Errors
    ///
    /// [`EtcdConfigError`] when a key is unknown or has the wrong type, an endpoint is not an
    /// `https://` URL (or a loopback `http://` one), `username` and `password_file` are not
    /// given together or the file is unreadable or empty, a TLS file cannot be read or holds no
    /// certificate or key, `resync_secs` is zero, or [`kv::Mapping::new`] refuses the prefixes
    /// (among them a tenant without an allow list in `policy`, code
    /// `kv_source_requires_tenant_allowlist`). An unknown key is an error so a misspelt `tenant`
    /// cannot move the source's apps to another tenant.
    pub fn from_config(
        config: &SourceConfig,
        policy: &UpstreamPolicy,
    ) -> Result<Self, EtcdConfigError> {
        let invalid = |reason: String| EtcdConfigError {
            name: config.name.clone(),
            reason: reason.into(),
        };
        let raw = Raw::deserialize(toml::Value::Table(config.settings.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        if raw.endpoints.is_empty() {
            return Err(invalid("endpoints: at least one is required".to_owned()));
        }
        let endpoints = raw
            .endpoints
            .iter()
            .map(|address| {
                endpoint(address).map_err(|why| invalid(format!("endpoints: {address:?} {why}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let credentials = match (&raw.username, &raw.password_file) {
            (None, None) => None,
            (Some(username), Some(path)) => {
                if username.is_empty() {
                    return Err(invalid("username: is empty".to_owned()));
                }
                let text = read("password_file", path).map_err(invalid)?;
                let password = String::from_utf8(text)
                    .map_err(|_| invalid("password_file: is not UTF-8".to_owned()))?;
                let password = password.trim_end_matches(['\n', '\r']);
                if password.is_empty() {
                    return Err(invalid(format!(
                        "password_file: {} is empty",
                        path.display()
                    )));
                }
                Some(Credentials::new(username, Secret::new(password)))
            }
            _ => {
                return Err(invalid(
                    "username and password_file: give both or neither".to_owned(),
                ));
            }
        };
        let mut pem = TlsPem::default();
        if let Some(tls) = raw.tls {
            if tls.cert_file.is_some() != tls.key_file.is_some() {
                return Err(invalid(
                    "tls: cert_file and key_file go together".to_owned(),
                ));
            }
            for (key, path, slot) in [
                ("tls.ca_file", tls.ca_file, &mut pem.ca),
                ("tls.cert_file", tls.cert_file, &mut pem.cert),
                ("tls.key_file", tls.key_file, &mut pem.key),
            ] {
                if let Some(path) = path {
                    *slot = Some(read(key, &path).map_err(invalid)?);
                }
            }
        }
        let resync_secs = raw.resync_secs.unwrap_or(DEFAULT_RESYNC_SECS);
        if resync_secs == 0 {
            return Err(invalid("resync_secs: must be at least 1".to_owned()));
        }
        let mapping = Mapping::new(raw.prefix, policy).map_err(|err| invalid(err.to_string()))?;
        let client = Client::new(endpoints, pem, credentials).map_err(invalid)?;
        Ok(Self {
            name: config.name.clone(),
            client,
            mapping,
            watch: raw.watch.unwrap_or(true),
            resync: Duration::from_secs(resync_secs),
        })
    }
}

/// The keys one prefix holds, as the source knows them.
#[derive(Debug, Default)]
struct Mirror {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Keys that a change would have added past [`kv::MAX_KEYS_PER_PREFIX`].
    dropped: usize,
}

impl Mirror {
    fn apply(&mut self, changes: Vec<Change>) {
        for change in changes {
            match change {
                Change::Put(key, value) => {
                    if self.entries.len() >= kv::MAX_KEYS_PER_PREFIX
                        && !self.entries.contains_key(&key)
                    {
                        self.dropped += 1;
                    } else {
                        self.entries.insert(key, value);
                    }
                }
                Change::Delete(key) => {
                    self.entries.remove(&key);
                }
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

/// What every reader has said so far.
struct Held {
    mirrors: Vec<Option<Mirror>>,
    outages: Vec<Option<Box<str>>>,
}

impl Held {
    fn apply(&mut self, msg: Msg) {
        match msg {
            Msg::Full { prefix, entries } => {
                self.mirrors[prefix] = Some(Mirror {
                    entries: entries.into_iter().collect(),
                    dropped: 0,
                });
                self.outages[prefix] = None;
            }
            Msg::Changes { prefix, changes } => {
                if let Some(mirror) = &mut self.mirrors[prefix] {
                    mirror.apply(changes);
                }
            }
            Msg::Outage { prefix, why } => self.outages[prefix] = Some(why),
        }
    }

    /// What to tell the core now, or nothing while a prefix has not been read once: a state
    /// without the apps of that prefix would only be wrong.
    fn observe(&self, source: &str, mapping: &Mapping) -> Option<Sent> {
        let outages: Vec<&str> = self.outages.iter().flatten().map(AsRef::as_ref).collect();
        if self.mirrors.iter().any(Option::is_none) {
            return (!outages.is_empty()).then(|| Sent::Unavailable(outages.join("; ").into()));
        }
        let mut pairs: Vec<(&[u8], &[u8])> = Vec::new();
        let mut extra: Vec<String> = Vec::new();
        for (mirror, prefix) in self.mirrors.iter().flatten().zip(mapping.prefixes()) {
            pairs.extend(
                mirror
                    .entries
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
            );
            if mirror.dropped > 0 {
                extra.push(format!(
                    "prefix {:?}: more than {} keys; {} ignored until the next full read",
                    prefix.path,
                    kv::MAX_KEYS_PER_PREFIX,
                    mirror.dropped
                ));
            }
        }
        let built = mapping.build(source, pairs);
        let mut lines: Vec<String> = outages.iter().map(|why| (*why).to_owned()).collect();
        lines.extend(extra);
        lines.extend(built.report_text().map(String::from));
        let report = (!lines.is_empty()).then(|| lines.join("; ").into());
        Some(Sent::Available {
            state: built.into_state(),
            report,
        })
    }
}

impl Source for EtcdSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let prefixes = self.mapping.prefixes();
        let (tx, mut rx) = mpsc::channel::<Msg>(256);
        let _readers: Vec<Abort> = prefixes
            .iter()
            .enumerate()
            .map(|(at, prefix)| {
                Abort(tokio::spawn(watch::run(
                    self.client.clone(),
                    at,
                    prefix.path.clone(),
                    self.watch,
                    self.resync,
                    tx.clone(),
                )))
            })
            .collect();
        drop(tx);
        let mut held = Held {
            mirrors: prefixes.iter().map(|_| None).collect(),
            outages: prefixes.iter().map(|_| None).collect(),
        };
        let mut sent: Option<Sent> = None;
        while let Some(first) = rx.recv().await {
            held.apply(first);
            // Changes that follow each other closely are one pass.
            let settle_by = Instant::now() + EVENT_MAX_WAIT;
            loop {
                let wait = EVENT_QUIET.min(settle_by.saturating_duration_since(Instant::now()));
                match tokio::time::timeout(wait, rx.recv()).await {
                    Ok(Some(msg)) => held.apply(msg),
                    Ok(None) | Err(_) => break,
                }
            }
            let Some(observed) = held.observe(&self.name, &self.mapping) else {
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
