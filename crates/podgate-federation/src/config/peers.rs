//! The hub's file, the peers file.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http::Uri;
use rustls_pki_types::ServerName;
use serde::Deserialize;

use super::{ConfigError, RawServe, ServeSettings, parse, read_text};
use crate::tls::{self, Identity};

/// Most peers one hub pulls.
const MAX_PEERS: usize = 32;

const DEFAULT_POLL: u64 = 30;
const MIN_POLL: u64 = 5;
const MAX_POLL: u64 = 3600;
const DEFAULT_TIMEOUT: u64 = 20;
const MAX_TIMEOUT: u64 = 120;
const MAX_STALE: u64 = 86_400;
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;
const MIN_MAX_BYTES: u64 = 1024 * 1024;
const MAX_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: u64 = 20_000;
const MAX_MAX_ENTRIES: u64 = 200_000;

/// A cluster's label: the operator's word, `[a-z0-9][a-z0-9._-]{0,62}`. It has no `/`, so a
/// cursor can start with it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClusterName(Box<str>);

impl ClusterName {
    /// Checks `text` as a cluster name.
    ///
    /// # Errors
    ///
    /// A message when it is empty, over 63 bytes or has a character outside the set.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let bytes = text.as_bytes();
        let first_ok = bytes
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let rest_ok = bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
        if bytes.len() <= 63 && first_ok && rest_ok {
            Ok(Self(text.into()))
        } else {
            Err(
                "must be 1 to 63 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit",
            )
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClusterName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClient {
    cert_file: PathBuf,
    key_file: PathBuf,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawPull {
    poll_secs: Option<u64>,
    timeout_secs: Option<u64>,
    stale_after_secs: Option<u64>,
    max_bytes: Option<u64>,
    max_entries: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    name: String,
    url: String,
    ca_file: PathBuf,
    server_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    view: RawServe,
    client: RawClient,
    #[serde(default)]
    pull: RawPull,
    #[serde(default)]
    peer: Vec<RawPeer>,
}

/// How a hub pulls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pull {
    /// The wait between pulls of one peer.
    pub poll: Duration,
    /// One whole pull of one peer, from resolving to the last page.
    pub timeout: Duration,
    /// How old a success may be before the cluster shows as stale.
    pub stale_after: Duration,
    /// Bytes read from one peer per pull.
    pub max_bytes: usize,
    /// Entries kept per peer.
    pub max_entries: usize,
}

/// One peer: an exporter the hub pulls.
#[derive(Clone)]
pub struct Peer {
    /// The label of its cluster, the operator's.
    pub name: ClusterName,
    /// The host to connect to.
    pub host: Box<str>,
    /// The port.
    pub port: u16,
    /// The name its certificate must carry.
    pub server_name: ServerName<'static>,
    /// The client configuration: this peer's CA only, and the hub's identity.
    pub tls: Arc<rustls::ClientConfig>,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// The hub's configuration.
#[derive(Debug, Clone)]
pub struct PeersFile {
    /// Where the combined view is served.
    pub view: ServeSettings,
    /// How peers are pulled.
    pub pull: Pull,
    /// The peers, in file order.
    pub peers: Vec<Peer>,
}

fn secs(
    field: &str,
    value: Option<u64>,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    let value = value.unwrap_or(default);
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::invalid(
            field,
            format!("must be {min} to {max}, got {value}"),
        ))
    }
}

/// `https://host[:port]`, nothing after the authority.
fn endpoint(field: &str, text: &str) -> Result<(Box<str>, u16), ConfigError> {
    let bad = |reason: &str| ConfigError::invalid(field, reason);
    let uri: Uri = text.parse().map_err(|_| bad("is not a URL"))?;
    if uri.scheme_str() != Some("https") {
        return Err(bad("must be an https:// URL; there is no plaintext mode"));
    }
    let authority = uri.authority().ok_or_else(|| bad("needs a host"))?;
    if authority.as_str().contains('@') {
        return Err(bad("must not carry credentials"));
    }
    if uri.query().is_some() || uri.path() != "/" || text.contains('#') {
        return Err(bad(
            "must be https://host[:port] with no path, query or fragment",
        ));
    }
    let host = authority.host().trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(bad("needs a host"));
    }
    Ok((host.into(), authority.port_u16().unwrap_or(443)))
}

impl PeersFile {
    /// Reads and checks the file at `path`, including every certificate and key.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the field that is wrong.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_text(&read_text(path)?)
    }

    /// Checks `text` as the file's content.
    ///
    /// # Errors
    ///
    /// As [`PeersFile::load`].
    pub fn from_text(text: &str) -> Result<Self, ConfigError> {
        let raw: Raw = parse(text)?;
        let poll = secs(
            "pull.poll_secs",
            raw.pull.poll_secs,
            DEFAULT_POLL,
            MIN_POLL,
            MAX_POLL,
        )?;
        let timeout = secs(
            "pull.timeout_secs",
            raw.pull.timeout_secs,
            DEFAULT_TIMEOUT,
            1,
            MAX_TIMEOUT,
        )?;
        let stale = secs(
            "pull.stale_after_secs",
            raw.pull.stale_after_secs,
            poll * 3,
            poll + timeout,
            MAX_STALE,
        )?;
        let max_bytes = secs(
            "pull.max_bytes",
            raw.pull.max_bytes,
            DEFAULT_MAX_BYTES,
            MIN_MAX_BYTES,
            MAX_MAX_BYTES,
        )?;
        let max_entries = secs(
            "pull.max_entries",
            raw.pull.max_entries,
            DEFAULT_MAX_ENTRIES,
            1,
            MAX_MAX_ENTRIES,
        )?;
        if raw.peer.is_empty() {
            return Err(ConfigError::invalid("peer", "needs at least one [[peer]]"));
        }
        if raw.peer.len() > MAX_PEERS {
            return Err(ConfigError::invalid(
                "peer",
                format!("at most {MAX_PEERS} peers, got {}", raw.peer.len()),
            ));
        }
        let identity = Identity::load("client", &raw.client.cert_file, &raw.client.key_file)?;
        let view = ServeSettings::from_raw("view", &raw.view)?;
        let mut peers: Vec<Peer> = Vec::with_capacity(raw.peer.len());
        for (at, peer) in raw.peer.into_iter().enumerate() {
            let field = |name: &str| format!("peer[{at}].{name}");
            let name = ClusterName::parse(&peer.name)
                .map_err(|why| ConfigError::invalid(field("name"), why))?;
            if peers.iter().any(|seen| seen.name == name) {
                return Err(ConfigError::invalid(
                    field("name"),
                    "is used by another peer",
                ));
            }
            let (host, port) = endpoint(&field("url"), &peer.url)?;
            let server_name = peer.server_name.as_deref().unwrap_or(&host).to_owned();
            let server_name = ServerName::try_from(server_name).map_err(|_| {
                ConfigError::invalid(field("server_name"), "is not a valid TLS server name")
            })?;
            let roots = tls::roots(&field("ca_file"), &peer.ca_file)?;
            peers.push(Peer {
                name,
                host,
                port,
                server_name,
                tls: identity.client_config(&format!("peer[{at}]"), roots)?,
            });
        }
        Ok(Self {
            view,
            pull: Pull {
                poll: Duration::from_secs(poll),
                timeout: Duration::from_secs(timeout),
                stale_after: Duration::from_secs(stale),
                max_bytes: usize::try_from(max_bytes).unwrap_or(usize::MAX),
                max_entries: usize::try_from(max_entries).unwrap_or(usize::MAX),
            },
            peers,
        })
    }
}
