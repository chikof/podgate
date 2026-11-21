//! The FastCGI upstreams the operator declared, per tenant: `FASTCGI_FILE`.
//!
//! ```json
//! { "acme": { "php": { "address": "unix:/run/php/acme.sock", "root": "/srv/php/acme",
//!                      "max_connections": 16, "dial_timeout_secs": 3, "read_timeout_secs": 30 } } }
//! ```
//!
//! An entry holds everything a tenant must not be able to choose: where the PHP-FPM pool listens,
//! which directory its code lives in, and how many connections it gets. A snapshot service names
//! an entry of its own tenant and nothing else. The root is opened once, as the `cap-std`
//! directory handle `static` services use (see `static_files::roots`), but the two kinds of root
//! are separate declarations: a directory a `static` service may serve is never executable
//! because of that.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use super::pool::{Address, Pool, WAIT};
use crate::service::static_files::Root;

/// Connections an entry gets unless it says otherwise.
const DEFAULT_MAX_CONNECTIONS: usize = 16;

/// Most connections an entry may ask for.
const MAX_CONNECTIONS: usize = 256;

/// Seconds the dial may take unless the entry says otherwise.
const DEFAULT_DIAL_TIMEOUT_SECS: u64 = 3;

/// The upstreams of one tenant, by the name a snapshot service gives.
pub type TenantFastcgi = HashMap<Box<str>, Arc<Upstream>>;

/// One declared PHP-FPM pool and the code it runs.
#[derive(Debug)]
pub struct Upstream {
    name: Box<str>,
    root: Arc<Root>,
    real_root: PathBuf,
    pool: Arc<Pool>,
    read_timeout: Option<Duration>,
}

impl Upstream {
    /// The entry's name in `FASTCGI_FILE`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The code root, as a directory handle.
    pub(super) fn root(&self) -> &Root {
        &self.root
    }

    /// The code root with every symlink resolved: what `SCRIPT_FILENAME` is under.
    pub(super) fn real_root(&self) -> &Path {
        &self.real_root
    }

    pub(super) fn pool(&self) -> &Arc<Pool> {
        &self.pool
    }

    /// How long the application may stay silent; `None` means the gateway's request timeout.
    pub(super) fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }
}

/// Every tenant's FastCGI upstreams, as the operator declared them.
#[derive(Clone, Debug, Default)]
pub struct FastcgiRoots {
    tenants: Arc<HashMap<Box<str>, TenantFastcgi>>,
}

/// Why `FASTCGI_FILE` is refused. The message names the file and the entry.
#[derive(Debug, Error)]
pub enum LoadError {
    /// The file cannot be read.
    #[error("{path}: {source}")]
    Read {
        /// The file.
        path: String,
        /// Why it cannot be read.
        #[source]
        source: io::Error,
    },
    /// The file is not `{"<tenant>": {"<name>": {...}}}`.
    #[error("{path}: {reason}")]
    Parse {
        /// The file.
        path: String,
        /// What is wrong with its content.
        reason: String,
    },
    /// One entry is not usable.
    #[error("{path}: tenant {tenant:?} upstream {upstream:?}: {reason}")]
    Entry {
        /// The file.
        path: String,
        /// The tenant id of the entry.
        tenant: String,
        /// The name of the entry.
        upstream: String,
        /// What is wrong with it.
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    address: String,
    root: PathBuf,
    #[serde(default)]
    max_connections: Option<usize>,
    #[serde(default)]
    dial_timeout_secs: Option<u64>,
    #[serde(default)]
    read_timeout_secs: Option<u64>,
}

impl FastcgiRoots {
    /// Reads `FASTCGI_FILE` at `path` and opens every root in it. No connection is made.
    ///
    /// # Errors
    ///
    /// [`LoadError`] when the file is unreadable or malformed, a tenant or name is empty, an
    /// address is neither `unix:/path` nor `host:port`, a root is not an absolute directory, or
    /// a limit is out of range.
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let shown = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
            path: shown.clone(),
            source,
        })?;
        let declared: HashMap<String, HashMap<String, EntryFile>> = serde_json::from_str(&text)
            .map_err(|err| LoadError::Parse {
                path: shown.clone(),
                reason: format!(
                    "expected {{\"<tenant>\": {{\"<name>\": {{\"address\": ..., \"root\": ...}}}}}} ({err})"
                ),
            })?;
        let mut tenants = HashMap::with_capacity(declared.len());
        for (tenant, upstreams) in declared {
            let entry = |name: &str, reason: String| LoadError::Entry {
                path: shown.clone(),
                tenant: tenant.clone(),
                upstream: name.to_owned(),
                reason,
            };
            if tenant.is_empty() {
                return Err(entry("", "the tenant id is empty".into()));
            }
            let mut opened = TenantFastcgi::with_capacity(upstreams.len());
            for (name, file) in upstreams {
                if name.is_empty() {
                    return Err(entry(&name, "the upstream name is empty".into()));
                }
                let upstream = open(&name, &file).map_err(|reason| entry(&name, reason))?;
                opened.insert(name.into_boxed_str(), Arc::new(upstream));
            }
            tenants.insert(tenant.into_boxed_str(), opened);
        }
        Ok(Self {
            tenants: Arc::new(tenants),
        })
    }

    /// The upstreams of `tenant`; `None` when the operator declared none.
    #[must_use]
    pub fn of(&self, tenant: &str) -> Option<&TenantFastcgi> {
        self.tenants.get(tenant)
    }
}

fn open(name: &str, file: &EntryFile) -> Result<Upstream, String> {
    let address = Address::parse(&file.address)?;
    if !file.root.is_absolute() {
        return Err(format!("{} is not an absolute path", file.root.display()));
    }
    let max = file.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS);
    if !(1..=MAX_CONNECTIONS).contains(&max) {
        return Err(format!(
            "max_connections {max} is not 1 to {MAX_CONNECTIONS}"
        ));
    }
    let dial = file.dial_timeout_secs.unwrap_or(DEFAULT_DIAL_TIMEOUT_SECS);
    if dial == 0 || file.read_timeout_secs == Some(0) {
        return Err("a timeout of 0 seconds".to_owned());
    }
    let unusable =
        |err: io::Error| format!("{} is not a usable directory ({err})", file.root.display());
    let root = Root::open(&file.root).map_err(unusable)?;
    let real_root = std::fs::canonicalize(&file.root).map_err(unusable)?;
    Ok(Upstream {
        name: Box::from(name),
        root: Arc::new(root),
        real_root,
        pool: Pool::new(address, max, Duration::from_secs(dial), WAIT),
        read_timeout: file.read_timeout_secs.map(Duration::from_secs),
    })
}

#[cfg(test)]
mod test {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("podgate-fcgi-roots-{name}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&dir));
            std::fs::create_dir_all(dir.join("code")).expect("create");
            Self(dir)
        }

        fn load(&self, json: &str) -> Result<FastcgiRoots, LoadError> {
            let file = self.0.join("fastcgi.json");
            std::fs::write(&file, json).expect("write");
            FastcgiRoots::load(&file)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    #[test]
    fn a_valid_file_opens_every_entry() {
        let dir = Dir::new("valid");
        let json = format!(
            r#"{{"t": {{"php": {{"address": "unix:/run/php.sock", "root": "{}", "max_connections": 4, "read_timeout_secs": 9}}}}}}"#,
            dir.0.join("code").display()
        );
        let roots = dir.load(&json).expect("loads");
        let upstream = roots.of("t").and_then(|t| t.get("php")).expect("entry");
        assert_eq!(upstream.name(), "php");
        assert_eq!(upstream.read_timeout(), Some(Duration::from_secs(9)));
        assert!(roots.of("other").is_none());
    }

    #[test]
    fn bad_entries_name_the_tenant_and_the_upstream() {
        let dir = Dir::new("bad");
        let code = dir.0.join("code");
        for (json, expected) in [
            ("not json".to_owned(), "expected"),
            (
                r#"{"t": {"php": {"address": "unix:/x", "root": "relative"}}}"#.to_owned(),
                "not an absolute path",
            ),
            (
                format!(
                    r#"{{"t": {{"php": {{"address": "nonsense", "root": "{}"}}}}}}"#,
                    code.display()
                ),
                "neither unix:/path nor host:port",
            ),
            (
                r#"{"t": {"php": {"address": "unix:/x", "root": "/definitely/missing"}}}"#
                    .to_owned(),
                "not a usable directory",
            ),
            (
                format!(
                    r#"{{"t": {{"php": {{"address": "unix:/x", "root": "{}", "max_connections": 257}}}}}}"#,
                    code.display()
                ),
                "max_connections",
            ),
            (
                format!(
                    r#"{{"t": {{"php": {{"address": "unix:/x", "root": "{}", "extra": 1}}}}}}"#,
                    code.display()
                ),
                "extra",
            ),
            (
                format!(
                    r#"{{"": {{"php": {{"address": "unix:/x", "root": "{}"}}}}}}"#,
                    code.display()
                ),
                "tenant id is empty",
            ),
        ] {
            let err = dir.load(&json).expect_err(&json).to_string();
            assert!(err.contains(expected), "{json}: {err}");
            assert!(err.contains("fastcgi.json"), "{err}");
        }
        let err = dir
            .load(r#"{"t": {"php": {"address": "unix:/x", "root": "relative"}}}"#)
            .expect_err("bad")
            .to_string();
        assert!(err.contains("\"t\"") && err.contains("\"php\""), "{err}");
    }
}
