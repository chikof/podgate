//! The two files the operator writes: the exporter's and the hub's (the peers file).
//!
//! Every value is parsed here and passed inward typed. Every error names the field. Unknown keys
//! are errors, so a misspelt option cannot turn a rule off. Certificates and keys are read once,
//! now, so a bad file stops startup and nothing changes while the process runs.

mod export;
mod peers;

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use thiserror::Error;

use crate::tls::Identity;

pub use self::export::ExportFile;
pub use self::peers::{ClusterName, Peer, PeersFile, Pull};

/// A file that cannot be used.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A file cannot be read.
    #[error("{field}: cannot read {path}: {source}")]
    Read {
        /// The setting that names the file, or `config`.
        field: Box<str>,
        /// The path.
        path: Box<str>,
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// The text is not valid TOML, or a key is unknown, missing or has the wrong type.
    #[error("config: line {line}, column {column}: {message}")]
    Syntax {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
        /// The parser's message, without the quoted line.
        message: Box<str>,
    },
    /// A value is not acceptable.
    #[error("{field}: {reason}")]
    Invalid {
        /// The field, like `peer[1].url`.
        field: Box<str>,
        /// What is wrong with it.
        reason: Box<str>,
    },
}

impl ConfigError {
    pub(crate) fn invalid(field: impl Into<Box<str>>, reason: impl std::fmt::Display) -> Self {
        Self::Invalid {
            field: field.into(),
            reason: reason.to_string().into(),
        }
    }
}

/// Parses `text` as `T`, with an error that holds a position and never the quoted line.
pub(crate) fn parse<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ConfigError> {
    toml::from_str(text).map_err(|err| {
        let (line, column) = err.span().map_or((0, 0), |span| {
            let before = &text.as_bytes()[..span.start.min(text.len())];
            let line = before.iter().filter(|b| **b == b'\n').count() + 1;
            let column = before.iter().rev().take_while(|b| **b != b'\n').count() + 1;
            (line, column)
        });
        ConfigError::Syntax {
            line,
            column,
            message: err.message().into(),
        }
    })
}

/// Reads the configuration file at `path`.
pub(crate) fn read_text(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        field: "config".into(),
        path: path.display().to_string().into(),
        source,
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawServe {
    addr: String,
    cert_file: std::path::PathBuf,
    key_file: std::path::PathBuf,
    client_ca_file: std::path::PathBuf,
    max_connections: Option<u64>,
}

/// A mutual TLS listener: where it listens, who it admits, and how many connections it holds.
#[derive(Clone)]
pub struct ServeSettings {
    /// The address to bind.
    pub addr: SocketAddr,
    /// The TLS configuration that requires a client certificate.
    pub tls: Arc<ServerConfig>,
    /// Most TLS connections at once.
    pub max_connections: usize,
}

impl std::fmt::Debug for ServeSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeSettings")
            .field("addr", &self.addr)
            .field("max_connections", &self.max_connections)
            .finish_non_exhaustive()
    }
}

/// Default and largest `max_connections`.
const DEFAULT_CONNECTIONS: u64 = 8;
const MAX_CONNECTIONS: u64 = 64;

impl ServeSettings {
    pub(crate) fn from_raw(table: &str, raw: &RawServe) -> Result<Self, ConfigError> {
        let addr = raw.addr.parse::<SocketAddr>().map_err(|_| {
            ConfigError::invalid(
                format!("{table}.addr"),
                "is not an address like 127.0.0.1:9443",
            )
        })?;
        let max = raw.max_connections.unwrap_or(DEFAULT_CONNECTIONS);
        if !(1..=MAX_CONNECTIONS).contains(&max) {
            return Err(ConfigError::invalid(
                format!("{table}.max_connections"),
                format!("must be 1 to {MAX_CONNECTIONS}, got {max}"),
            ));
        }
        let identity = Identity::load(table, &raw.cert_file, &raw.key_file)?;
        let client_roots =
            crate::tls::roots(&format!("{table}.client_ca_file"), &raw.client_ca_file)?;
        Ok(Self {
            addr,
            tls: identity.server_config(table, client_roots)?,
            max_connections: usize::try_from(max).unwrap_or(1),
        })
    }
}
