//! `RATE_LIMIT_STORES_FILE`: the stores a snapshot may name, parsed and validated at startup.
//!
//! ```json
//! {"main": {"url": "rediss://cache.internal:6379", "username": "podgate",
//!           "password_file": "/run/secrets/limits", "tls_ca_file": "/etc/podgate/cache-ca.pem",
//!           "tenants": ["acme"], "max_connections": 16, "timeout_ms": 20}}
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use serde::Deserialize;

/// The port of a URL that names none.
const DEFAULT_PORT: u16 = 6379;

/// Connections a store keeps when `max_connections` is absent.
const DEFAULT_MAX_CONNECTIONS: u16 = 16;

/// Most connections one store may hold open; also the cap of calls in flight.
pub(super) const MAX_CONNECTIONS: u16 = 256;

/// A store call's deadline when `timeout_ms` is absent.
const DEFAULT_TIMEOUT_MS: u16 = 20;

/// Longest deadline of one store call, in milliseconds: a request waits at most this long for
/// its store.
pub const MAX_TIMEOUT_MS: u16 = 200;

/// Why the file cannot be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The file or a file it names cannot be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file.
        path: String,
        /// The cause.
        source: std::io::Error,
    },
    /// The file is not the JSON object described above.
    #[error("{0}")]
    Parse(serde_json::Error),
    /// One entry is wrong; the reason never holds a credential.
    #[error("store {name:?}: {reason}")]
    Store {
        /// The entry's name.
        name: Box<str>,
        /// What is wrong.
        reason: Box<str>,
    },
}

fn bad(name: &str, reason: impl Into<Box<str>>) -> LoadError {
    LoadError::Store {
        name: name.into(),
        reason: reason.into(),
    }
}

fn read(path: &Path) -> Result<String, LoadError> {
    std::fs::read_to_string(path).map_err(|source| LoadError::Read {
        path: path.display().to_string(),
        source,
    })
}

/// A password. Never printed: `Debug` hides it and there is no `Display`.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Secret(Box<str>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl Secret {
    pub(super) fn expose(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The credentials a connection sends with `AUTH`.
#[derive(Debug, Clone)]
pub(super) struct Auth {
    pub(super) username: Option<Box<str>>,
    pub(super) password: Secret,
}

/// How to reach the store with TLS.
#[derive(Clone)]
pub(super) struct Tls {
    pub(super) connector: tokio_rustls::TlsConnector,
    pub(super) server_name: ServerName<'static>,
}

impl fmt::Debug for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// One validated entry.
#[derive(Debug, Clone)]
pub(super) struct Spec {
    pub(super) host: Box<str>,
    pub(super) port: u16,
    pub(super) tls: Option<Tls>,
    pub(super) auth: Option<Auth>,
    pub(super) tenants: Box<[Box<str>]>,
    pub(super) max_connections: u16,
    pub(super) timeout: Duration,
}

/// An entry as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    url: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password_file: Option<PathBuf>,
    #[serde(default)]
    tls_ca_file: Option<PathBuf>,
    tenants: Vec<String>,
    #[serde(default)]
    max_connections: Option<u16>,
    #[serde(default)]
    timeout_ms: Option<u16>,
}

/// Parses the file at `path`: every entry, by name.
///
/// # Errors
///
/// [`LoadError`] for the first problem.
pub(super) fn load(path: &Path) -> Result<BTreeMap<Box<str>, Spec>, LoadError> {
    parse(&read(path)?)
}

fn parse(text: &str) -> Result<BTreeMap<Box<str>, Spec>, LoadError> {
    let entries: BTreeMap<Box<str>, Entry> =
        serde_json::from_str(text).map_err(LoadError::Parse)?;
    entries
        .into_iter()
        .map(|(name, entry)| {
            let spec = spec(&name, entry)?;
            Ok((name, spec))
        })
        .collect()
}

fn spec(name: &str, entry: Entry) -> Result<Spec, LoadError> {
    let (tls, host, port) = endpoint(name, &entry)?;
    if entry.tenants.is_empty() || entry.tenants.iter().any(String::is_empty) {
        return Err(bad(
            name,
            "`tenants` must list at least one tenant id, and no empty one",
        ));
    }
    let max_connections = entry.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS);
    if !(1..=MAX_CONNECTIONS).contains(&max_connections) {
        return Err(bad(
            name,
            format!("`max_connections` must be 1 to {MAX_CONNECTIONS}"),
        ));
    }
    let timeout_ms = entry.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(bad(
            name,
            format!("`timeout_ms` must be 1 to {MAX_TIMEOUT_MS}"),
        ));
    }
    let auth = match (&entry.password_file, entry.username) {
        (Some(path), username) => {
            let text = read(path)?;
            let password = text.trim_end_matches(['\r', '\n']);
            if password.is_empty() {
                return Err(bad(name, "`password_file` is empty"));
            }
            Some(Auth {
                username: username.map(Into::into),
                password: Secret(password.into()),
            })
        }
        (None, Some(_)) => return Err(bad(name, "`username` needs a `password_file`")),
        (None, None) => None,
    };
    Ok(Spec {
        host,
        port,
        tls,
        auth,
        tenants: entry.tenants.into_iter().map(Into::into).collect(),
        max_connections,
        timeout: Duration::from_millis(u64::from(timeout_ms)),
    })
}

/// The TLS setting, host and port of `entry.url`. The URL holds no credential: the password
/// comes from a file, so it cannot end up in a log line that quotes the address.
fn endpoint(name: &str, entry: &Entry) -> Result<(Option<Tls>, Box<str>, u16), LoadError> {
    let (secure, rest) = if let Some(rest) = entry.url.strip_prefix("rediss://") {
        (true, rest)
    } else if let Some(rest) = entry.url.strip_prefix("redis://") {
        (false, rest)
    } else {
        return Err(bad(name, "`url` must start with `redis://` or `rediss://`"));
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['@', '/', '?', '#']) {
        return Err(bad(
            name,
            "`url` is `redis[s]://host[:port]` only: credentials go in `password_file`, and there is no database or path",
        ));
    }
    let (host, port) =
        split_authority(authority).ok_or_else(|| bad(name, "`url` has no host or a bad port"))?;
    let tls = match (secure, &entry.tls_ca_file) {
        (true, Some(ca)) => Some(tls(name, host, ca)?),
        (true, None) => {
            return Err(bad(
                name,
                "`rediss://` needs `tls_ca_file`: the store is verified against the CA you name, never the platform's roots",
            ));
        }
        (false, Some(_)) => {
            return Err(bad(name, "`tls_ca_file` is only valid with `rediss://`"));
        }
        (false, None) => None,
    };
    if tls.is_none() && entry.password_file.is_some() && !is_loopback(host) {
        tracing::warn!(
            store = name,
            "the password of this rate limit store is sent in clear text; use `rediss://` unless the network is private"
        );
    }
    Ok((tls, host.into(), port))
}

fn split_authority(authority: &str) -> Option<(&str, u16)> {
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, after) = inner.split_once(']')?;
        (host, after.strip_prefix(':'))
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(port) => port.parse().ok().filter(|port| *port != 0)?,
        None => DEFAULT_PORT,
    };
    (!host.is_empty()).then_some((host, port))
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.is_loopback())
}

fn tls(name: &str, host: &str, ca: &Path) -> Result<Tls, LoadError> {
    let mut roots = rustls::RootCertStore::empty();
    let certificates = CertificateDer::pem_file_iter(ca)
        .map_err(|err| bad(name, format!("cannot read {}: {err}", ca.display())))?;
    for certificate in certificates {
        let certificate = certificate.map_err(|err| {
            bad(
                name,
                format!("{} is not PEM certificates: {err}", ca.display()),
            )
        })?;
        roots.add(certificate).map_err(|err| {
            bad(
                name,
                format!("{} holds a bad certificate: {err}", ca.display()),
            )
        })?;
    }
    if roots.is_empty() {
        return Err(bad(name, format!("{} holds no certificate", ca.display())));
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| bad(name, err.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| bad(name, "`url` host is not a DNS name or an IP address"))?;
    Ok(Tls {
        connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        server_name,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    fn entry(url: &str) -> serde_json::Value {
        serde_json::json!({"url": url, "tenants": ["acme"]})
    }

    fn parse_one(value: &serde_json::Value) -> Result<Spec, LoadError> {
        let text = serde_json::json!({ "main": value }).to_string();
        parse(&text).map(|mut all| all.remove("main").expect("the entry"))
    }

    #[test]
    fn plain_urls_parse_with_defaults() {
        let spec = parse_one(&entry("redis://cache.internal")).expect("valid");
        assert_eq!((&*spec.host, spec.port), ("cache.internal", 6379));
        assert_eq!(spec.max_connections, 16);
        assert_eq!(spec.timeout, Duration::from_millis(20));
        assert!(spec.tls.is_none() && spec.auth.is_none());
        let spec = parse_one(&entry("redis://[::1]:7000/")).expect("valid");
        assert_eq!((&*spec.host, spec.port), ("::1", 7000));
    }

    #[test]
    fn bad_entries_are_refused_without_quoting_a_credential() {
        let password = std::env::temp_dir().join(format!("podgate-pw-{}", std::process::id()));
        std::fs::write(&password, "hunter2-planted\n").expect("write");
        let with = |key: &str, value: serde_json::Value| {
            let mut config = entry("redis://h:1");
            config[key] = value;
            config
        };
        let cases = [
            entry("http://h"),
            entry("redis://user:pw@h"),
            entry("redis://h/0"),
            entry("redis://h:0"),
            entry("redis://:5"),
            entry("rediss://h"),
            with("tls_ca_file", serde_json::json!("/nonexistent.pem")),
            with("tenants", serde_json::json!([])),
            with("tenants", serde_json::json!([""])),
            with("max_connections", serde_json::json!(0)),
            with("max_connections", serde_json::json!(257)),
            with("timeout_ms", serde_json::json!(0)),
            with("timeout_ms", serde_json::json!(201)),
            with("username", serde_json::json!("u")),
            with("password", serde_json::json!("inline")),
            with("password_file", serde_json::json!("/nonexistent")),
        ];
        for case in cases {
            let err = parse_one(&case).expect_err(&case.to_string());
            assert!(!err.to_string().contains("hunter2"), "{err}");
        }
        assert!(parse_one(&with("password_file", serde_json::json!(password))).is_ok());
        std::fs::remove_file(&password).expect("remove");
    }

    #[test]
    fn the_password_is_read_from_its_file_and_never_printed() {
        let path = std::env::temp_dir().join(format!("podgate-pw-debug-{}", std::process::id()));
        std::fs::write(&path, "hunter2-planted\r\n").expect("write");
        let mut config = entry("redis://localhost:1");
        config["password_file"] = serde_json::json!(path);
        config["username"] = serde_json::json!("podgate");
        let spec = parse_one(&config).expect("valid");
        std::fs::remove_file(&path).expect("remove");
        let auth = spec.auth.as_ref().expect("auth");
        assert_eq!(auth.password.expose(), b"hunter2-planted");
        let shown = format!("{spec:?} {auth:?} {:#?}", auth.password);
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("[redacted]"));
    }
}
