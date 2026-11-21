//! The Redis source: a key prefix per tenant, read from a Redis-compatible store (Redis, Valkey,
//! KeyDB, Dragonfly) with `SCAN` and `MGET` and refreshed when the store says something changed.
//!
//! ```toml
//! [[source]]
//! kind = "redis"
//! name = "redis"
//! url = "rediss://redis.internal:6379"
//! username = "podgate"                      # a read-only ACL user
//! password_file = "/etc/podgate/redis-password"
//! db = 0
//! notify_channel = "podgate:changed"        # the writer publishes here after updating keys
//! keyspace_notifications = false            # also follow __keyspace@<db>__:<prefix>*
//! refresh_secs = 30                         # the poll, when no message arrives
//!
//! [source.tls]
//! ca_file = "/etc/podgate/redis-ca.pem"
//! cert_file = "/etc/podgate/redis-client.pem"
//! key_file = "/etc/podgate/redis-client-key.pem"
//!
//! [[source.prefix]]
//! prefix = "podgate/acme"
//! tenant = "acme"
//! layout = "podgate-json"
//! ```
//!
//! What the keys mean, who may write which, and the limits are the shared key-value layer's
//! ([`crate::kv`]); this module is the connection. Every prefix is read whole, on start, on every
//! message of `notify_channel` (and, when enabled, of the keyspace channels of the prefixes) and
//! every `refresh_secs` as the fallback for a subscription that is down or silent. A store that
//! cannot be reached keeps the last state in force while the source reconnects with growing
//! delays. The client sends only `AUTH`, `SELECT`, `SCAN`, `MGET`, `SUBSCRIBE`, `PSUBSCRIBE` and
//! `PING` (see `client`), and never changes a server setting: keyspace notifications are used
//! only when the operator enabled them. Sentinel and Redis Cluster are not supported.
//!
//! A plain `redis://` URL is accepted for loopback addresses only; the credentials and the
//! configuration of a tenant do not cross a network unprotected. The CA, client certificate and
//! password are read once at startup.
//!
//! The reference is `docs/ref/provider-redis.md` and, for the layouts, `docs/ref/provider-kv.md`.

mod client;
mod resp;

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http::Uri;
use rustls_pki_types::ServerName;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::sync::mpsc::Sender;
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, warn};

use crate::abort::Abort;
use crate::acme::Secret;
use crate::config::SourceConfig;
use crate::kv::{Mapping, RawPrefix};
use crate::policy::UpstreamPolicy;
use crate::push::Backoff;
use crate::source::{Source, State, Update, UpdateBody};
use crate::tls_client::{TlsPem, tls_config};

use client::{Client, Conn, MAX_VALUE_BYTES, Target, glob_escape};

const DEFAULT_PORT: u16 = 6379;
const DEFAULT_CHANNEL: &str = "podgate:changed";
const DEFAULT_REFRESH_SECS: u64 = 30;
const MIN_REFRESH_SECS: u64 = 5;

/// Messages that arrive within this time of the first are answered by one pass.
const EVENT_QUIET: Duration = Duration::from_millis(50);

/// The longest a pass over every prefix may take.
const PASS_TIMEOUT: Duration = Duration::from_secs(60);

/// Delays between attempts to reconnect.
const MIN_RETRY: Duration = Duration::from_millis(200);
const MAX_RETRY: Duration = Duration::from_secs(5);

/// A subscription that lived this long was healthy: the next failure starts the delays over.
const STABLE: Duration = Duration::from_secs(10);

/// The subscription sends `PING` this often, or every `refresh_secs` if that is shorter, and is
/// dropped after three intervals without a byte from the store.
const MAX_HEARTBEAT: Duration = Duration::from_secs(10);

/// The most of a key that a report quotes.
const MAX_QUOTED_KEY: usize = 200;

/// A `[[source]]` entry of kind `redis` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct RedisConfigError {
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
    url: String,
    tls: Option<RawTls>,
    username: Option<String>,
    password_file: Option<PathBuf>,
    db: Option<u32>,
    #[serde(default)]
    prefix: Vec<RawPrefix>,
    notify_channel: Option<String>,
    keyspace_notifications: Option<bool>,
    refresh_secs: Option<u64>,
}

/// The Redis source.
#[derive(Debug)]
pub struct RedisSource {
    name: Box<str>,
    client: Arc<Client>,
    mapping: Mapping,
    channel: Box<str>,
    /// The keyspace patterns to follow, one per prefix; empty unless enabled.
    keyspace: Vec<Vec<u8>>,
    refresh: Duration,
}

/// The host and port of a `redis://` or `rediss://` URL, and whether it is TLS.
fn parse_url(address: &str) -> Result<(Target, bool), &'static str> {
    let uri: Uri = address.parse().map_err(|_| "is not a URL")?;
    let tls = match uri.scheme_str() {
        Some("redis") => false,
        Some("rediss") => true,
        _ => return Err("must be a redis:// or rediss:// URL"),
    };
    let authority = uri.authority().ok_or("needs a host")?;
    if authority.as_str().contains('@') {
        return Err("must not carry credentials; the password goes in password_file");
    }
    if uri.path() != "/" && !uri.path().is_empty() || uri.query().is_some() {
        return Err(
            "must be the server's address, without a path or a query; the database is `db`",
        );
    }
    let host = authority.host().trim_matches(['[', ']']);
    if !tls {
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !loopback {
            return Err("must be rediss:// unless the server is on this machine");
        }
    }
    Ok((
        Target {
            host: host.into(),
            port: authority.port_u16().unwrap_or(DEFAULT_PORT),
        },
        tls,
    ))
}

fn read(key: &str, path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|err| format!("{key}: cannot read {}: {err}", path.display()))
}

impl RedisSource {
    /// A Redis source from its `[[source]]` entry, checking its tenants against `policy`.
    ///
    /// # Errors
    ///
    /// [`RedisConfigError`] when a key is unknown or has the wrong type, `url` is not a
    /// `rediss://` URL (or a loopback `redis://` one) without credentials, a path or a query,
    /// `username` is given without `password_file`, the password file is unreadable or empty,
    /// `tls` is given for a `redis://` URL, a TLS file cannot be read or holds no certificate or
    /// key, `notify_channel` is empty, `refresh_secs` is under 5, or [`Mapping::new`] refuses the
    /// prefixes (among them a tenant without an allow list in `policy`, code
    /// `kv_source_requires_tenant_allowlist`). An unknown key is an error so a misspelt `tenant`
    /// cannot move the source's apps to another tenant.
    pub fn from_config(
        config: &SourceConfig,
        policy: &UpstreamPolicy,
    ) -> Result<Self, RedisConfigError> {
        let invalid = |reason: String| RedisConfigError {
            name: config.name.clone(),
            reason: reason.into(),
        };
        let raw = Raw::deserialize(toml::Value::Table(config.settings.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let (target, secure) =
            parse_url(&raw.url).map_err(|why| invalid(format!("url: {:?} {why}", raw.url)))?;
        let password = match (&raw.username, &raw.password_file) {
            (Some(_), None) => {
                return Err(invalid("username: needs password_file".to_owned()));
            }
            (_, None) => None,
            (username, Some(path)) => {
                if username.as_deref() == Some("") {
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
                Some(Secret::new(password))
            }
        };
        let tls = if secure {
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
            let name = ServerName::try_from(target.host.to_string())
                .map_err(|_| invalid(format!("url: {:?} has no usable host name", raw.url)))?;
            Some((Arc::new(tls_config(pem).map_err(invalid)?), name))
        } else if raw.tls.is_some() {
            return Err(invalid("tls: needs a rediss:// url".to_owned()));
        } else {
            None
        };
        let channel = raw
            .notify_channel
            .unwrap_or_else(|| DEFAULT_CHANNEL.to_owned());
        if channel.is_empty() {
            return Err(invalid("notify_channel: is empty".to_owned()));
        }
        let refresh_secs = raw.refresh_secs.unwrap_or(DEFAULT_REFRESH_SECS);
        if refresh_secs < MIN_REFRESH_SECS {
            return Err(invalid(format!(
                "refresh_secs: must be at least {MIN_REFRESH_SECS}"
            )));
        }
        let mapping = Mapping::new(raw.prefix, policy).map_err(|err| invalid(err.to_string()))?;
        let db = raw.db.unwrap_or(0);
        let keyspace = if raw.keyspace_notifications.unwrap_or(false) {
            mapping
                .prefixes()
                .iter()
                .map(|prefix| {
                    let mut pattern = format!("__keyspace@{db}__:").into_bytes();
                    pattern.extend(glob_escape(prefix.path.as_bytes()));
                    pattern.push(b'*');
                    pattern
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(Self {
            name: config.name.clone(),
            client: Arc::new(Client::new(
                target,
                tls,
                raw.username.map(String::into_boxed_str),
                password,
                db,
            )),
            mapping,
            channel: channel.into(),
            keyspace,
            refresh: Duration::from_secs(refresh_secs),
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

/// The pairs of every prefix, as of its last successful read.
type Held = Vec<Option<Vec<(Vec<u8>, Vec<u8>)>>>;

/// A key as a report quotes it.
fn quoted(key: &[u8]) -> String {
    String::from_utf8_lossy(key)
        .chars()
        .take(MAX_QUOTED_KEY)
        .collect()
}

impl RedisSource {
    /// Reads every prefix into `held`, opening a connection when there is none. A prefix that
    /// is past a limit keeps what it held and adds a line to `lines`; any other failure drops the
    /// connection and ends the pass.
    async fn read_all(
        &self,
        conn: &mut Option<Conn>,
        held: &mut Held,
        lines: &mut Vec<String>,
    ) -> Result<(), client::ClientError> {
        let open = match conn {
            Some(open) => open,
            None => conn.insert(self.client.reader().await?),
        };
        for (at, prefix) in self.mapping.prefixes().iter().enumerate() {
            match open.read_prefix(&prefix.path).await {
                Ok(read) => {
                    for key in read.oversize {
                        lines.push(format!(
                            "key {:?}: the value is larger than {MAX_VALUE_BYTES} bytes; ignored",
                            quoted(&key)
                        ));
                    }
                    held[at] = Some(read.entries);
                }
                Err(err) if err.is_prefix_limit() => {
                    lines.push(format!("prefix {:?}: {err}", prefix.path));
                    held[at].get_or_insert_with(Vec::new);
                }
                Err(err) => {
                    *conn = None;
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    /// One pass: what to tell the core now.
    async fn observe(&self, conn: &mut Option<Conn>, held: &mut Held) -> Result<Sent, Box<str>> {
        let mut lines = Vec::new();
        let read = timeout(PASS_TIMEOUT, self.read_all(conn, held, &mut lines)).await;
        let result = read.unwrap_or(Err(client::ClientError::Timeout));
        if let Err(err) = result {
            *conn = None;
            return Err(format!("redis {}: {err}", self.client.address()).into());
        }
        let pairs = held
            .iter()
            .flatten()
            .flatten()
            .map(|(key, value)| (key.as_slice(), value.as_slice()));
        let built = self.mapping.build(&self.name, pairs);
        lines.extend(built.report_text().map(String::from));
        let report = (!lines.is_empty()).then(|| lines.join("; ").into());
        Ok(Sent::Available {
            state: built.into_state(),
            report,
        })
    }

    fn heartbeat(&self) -> Duration {
        self.refresh.min(MAX_HEARTBEAT)
    }
}

/// Follows the notification channels and wakes the source on every message. Reconnects with
/// growing delays; a reconnect wakes the source too, because messages may have been missed.
async fn follow(
    client: Arc<Client>,
    channel: Box<str>,
    patterns: Vec<Vec<u8>>,
    heartbeat: Duration,
    wake: Arc<Notify>,
) {
    let mut backoff = Backoff::new(MIN_RETRY, MAX_RETRY).jittered();
    let mut failing = false;
    loop {
        let started = Instant::now();
        let why = match client.subscription(&channel, &patterns).await {
            Err(err) => err,
            Ok(mut subscription) => {
                if failing {
                    debug!("the subscription is back");
                }
                failing = false;
                wake.notify_one();
                let _pings = subscription.take_writer().map(|mut writer| {
                    Abort(tokio::spawn(async move {
                        loop {
                            sleep(heartbeat).await;
                            if writer.ping().await.is_err() {
                                return;
                            }
                        }
                    }))
                });
                loop {
                    match subscription.next(heartbeat * 3).await {
                        Ok(true) => wake.notify_one(),
                        Ok(false) => {}
                        Err(err) => break err,
                    }
                }
            }
        };
        if !failing {
            warn!(error = %why, "the subscription is down; the poll keeps the state fresh until it is back");
        }
        failing = true;
        if started.elapsed() >= STABLE {
            backoff.reset();
        }
        sleep(backoff.next_delay()).await;
    }
}

impl Source for RedisSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let wake = Arc::new(Notify::new());
        let _subscription = Abort(tokio::spawn(follow(
            Arc::clone(&self.client),
            self.channel.clone(),
            self.keyspace.clone(),
            self.heartbeat(),
            Arc::clone(&wake),
        )));
        let mut conn: Option<Conn> = None;
        let mut held: Held = self.mapping.prefixes().iter().map(|_| None).collect();
        let mut sent: Option<Sent> = None;
        let mut backoff = Backoff::new(MIN_RETRY, MAX_RETRY).jittered();
        let mut failing = false;
        loop {
            let observed = match self.observe(&mut conn, &mut held).await {
                Ok(observed) => {
                    if failing {
                        debug!("the store can be read again");
                    }
                    failing = false;
                    backoff.reset();
                    observed
                }
                Err(why) => {
                    if !failing {
                        warn!(error = %why, "cannot read the store; the last state stays in force");
                    }
                    failing = true;
                    Sent::Unavailable(why)
                }
            };
            if sent.as_ref() != Some(&observed) {
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
            if failing {
                sleep(backoff.next_delay()).await;
            } else {
                tokio::select! {
                    () = wake.notified() => {
                        // Messages that follow each other closely are one pass.
                        sleep(EVENT_QUIET).await;
                        drop(timeout(Duration::ZERO, wake.notified()).await);
                    }
                    () = sleep(self.refresh) => {}
                }
            }
        }
    }
}
