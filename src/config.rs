//! Settings read from environment variables, once at startup.

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

/// Most WASM filter runs that may execute at once: half of tokio's 512-thread blocking pool, so
/// snapshot compiles always find threads.
const WASM_WORKERS_MAX: usize = 256;

/// How log lines are rendered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable multi-line output for local development.
    #[default]
    Pretty,
    /// One JSON object per line for log collectors.
    Json,
}
// 1: two dataless variants fit in one byte; the 254 unused values are a niche.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<LogFormat>() == 1);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Option<LogFormat>>() == std::mem::size_of::<LogFormat>());

/// A bad environment variable. The message names the variable.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid {var}: {reason}")]
pub struct ConfigError {
    /// Name of the offending environment variable.
    pub var: &'static str,
    /// What is wrong with its value.
    pub reason: Box<str>,
}
// 32: &'static str (16) + Box<str> (16); the reason is immutable once built, so no capacity word.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<ConfigError>() == 32);
#[cfg(target_pointer_width = "64")]
const _: () =
    assert!(std::mem::size_of::<Option<ConfigError>>() == std::mem::size_of::<ConfigError>());

/// Service settings, read once at startup.
///
/// | Variable | Default | Meaning |
/// |---|---|---|
/// | `PROXY_ADDR` | `127.0.0.1:8080` | Plain HTTP proxy listener. |
/// | `PROXY_TLS_ADDR` | unset | HTTPS proxy listener; unset means no TLS listener. |
/// | `ADMIN_SOCKET` | `/run/podgate/admin.sock` | Unix socket of the admin API. |
/// | `REQUEST_TIMEOUT_SECS` | `30` | Admin request and upstream I/O limit, 1..=3600. |
/// | `LOG_FORMAT` | `pretty` | `pretty` or `json`. |
/// | `NODE_NAME` | unset | Name of this node; the node whose name equals the snapshot's `acme.issuer_node` orders certificates. |
/// | `ACME_CA_FILE` | unset | PEM file with the root certificate to trust for the ACME server instead of the platform's roots (private or test CAs). |
/// | `RUST_LOG` | `info` | Log filter (`tracing` env-filter syntax). |
/// | `WASM_MAX_CONCURRENT` | available cores, at most 256 | WASM filter runs at once, 1..=256. |
/// | `WASM_QUEUE_TIMEOUT_MS` | `1000` | How long a filter run waits for a worker before `503`, 1..=60000. |
/// | `CATCH_ALL_TENANTS` | unset | Comma-separated tenant ids allowed catch-all routers on shared entry points. |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Address of the plain HTTP proxy listener.
    pub proxy_addr: SocketAddr,
    /// Address of the HTTPS proxy listener, when enabled.
    pub proxy_tls_addr: Option<SocketAddr>,
    /// Path of the admin API's unix socket.
    pub admin_socket: PathBuf,
    /// Admin requests running longer than this many seconds get `408 Request Timeout`;
    /// connecting to, reading from and writing to an upstream each give up after it too.
    pub request_timeout_secs: NonZeroU16,
    /// Log rendering.
    pub log_format: LogFormat,
    /// WASM filter runs that may execute at once, across all tenants. Filters get their own
    /// permits, so they cannot take over the blocking thread pool snapshot compiles also use.
    pub wasm_max_concurrent: NonZeroUsize,
    /// A filter run waits at most this many milliseconds for a free worker; then the request
    /// answers `503` with `retry-after`.
    pub wasm_queue_timeout_ms: NonZeroU16,
    /// Name of this node, compared with the snapshot's `acme.issuer_node`. Absent: never issues.
    pub node_name: Option<Box<str>>,
    /// PEM file with the root certificate trusted for the ACME server. Absent: platform roots.
    pub acme_ca_file: Option<PathBuf>,
    /// Tenants the operator lets declare catch-all routers (a `host_regexp` or host-free router)
    /// on a shared entry point, so they can receive hosts nobody claims. Empty: none can.
    pub catch_all_tenants: Vec<Box<str>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            proxy_tls_addr: None,
            admin_socket: PathBuf::from("/run/podgate/admin.sock"),
            request_timeout_secs: NonZeroU16::MIN.saturating_add(29),
            log_format: LogFormat::Pretty,
            wasm_max_concurrent: std::thread::available_parallelism()
                .ok()
                .and_then(|cores| NonZeroUsize::new(cores.get().min(WASM_WORKERS_MAX)))
                .unwrap_or(NonZeroUsize::MIN),
            wasm_queue_timeout_ms: NonZeroU16::MIN.saturating_add(999),
            node_name: None,
            acme_ca_file: None,
            catch_all_tenants: Vec::new(),
        }
    }
}

fn parse_addr(var: &'static str, raw: &str) -> Result<SocketAddr, ConfigError> {
    raw.trim().parse().map_err(|err| ConfigError {
        var,
        reason: format!("{raw:?} is not a socket address like 0.0.0.0:8080 ({err})").into(),
    })
}

impl Config {
    /// How long a WASM filter run waits for a free worker.
    #[must_use]
    pub fn wasm_queue_timeout(&self) -> Duration {
        Duration::from_millis(NonZeroU64::from(self.wasm_queue_timeout_ms).get())
    }

    /// The request limit as a [`Duration`].
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(NonZeroU64::from(self.request_timeout_secs).get())
    }

    /// Reads the settings from the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the first variable that is set but invalid.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Reads the settings through `lookup`; unset variables return `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the first variable that is set but invalid.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        if let Some(raw) = lookup("PROXY_ADDR") {
            config.proxy_addr = parse_addr("PROXY_ADDR", &raw)?;
        }
        if let Some(raw) = lookup("PROXY_TLS_ADDR") {
            config.proxy_tls_addr = Some(parse_addr("PROXY_TLS_ADDR", &raw)?);
        }
        if let Some(raw) = lookup("ADMIN_SOCKET") {
            let path = raw.trim();
            if path.is_empty() {
                return Err(ConfigError {
                    var: "ADMIN_SOCKET",
                    reason: "is empty".into(),
                });
            }
            config.admin_socket = PathBuf::from(path);
        }
        if let Some(raw) = lookup("REQUEST_TIMEOUT_SECS") {
            let secs: NonZeroU16 = raw.trim().parse().map_err(|err| ConfigError {
                var: "REQUEST_TIMEOUT_SECS",
                reason: format!("{raw:?} is not a whole number of seconds in 1..=3600 ({err})")
                    .into(),
            })?;
            if secs.get() > 3600 {
                return Err(ConfigError {
                    var: "REQUEST_TIMEOUT_SECS",
                    reason: format!("{secs} is outside 1..=3600").into(),
                });
            }
            config.request_timeout_secs = secs;
        }
        if let Some(raw) = lookup("LOG_FORMAT") {
            config.log_format = match raw.trim().to_ascii_lowercase().as_str() {
                "pretty" => LogFormat::Pretty,
                "json" => LogFormat::Json,
                _ => {
                    return Err(ConfigError {
                        var: "LOG_FORMAT",
                        reason: format!("{raw:?} is not `pretty` or `json`").into(),
                    });
                }
            };
        }
        if let Some(raw) = lookup("WASM_MAX_CONCURRENT") {
            let workers: NonZeroUsize = raw.trim().parse().map_err(|err| ConfigError {
                var: "WASM_MAX_CONCURRENT",
                reason: format!("{raw:?} is not a whole number in 1..={WASM_WORKERS_MAX} ({err})")
                    .into(),
            })?;
            if workers.get() > WASM_WORKERS_MAX {
                return Err(ConfigError {
                    var: "WASM_MAX_CONCURRENT",
                    reason: format!("{workers} is outside 1..={WASM_WORKERS_MAX}").into(),
                });
            }
            config.wasm_max_concurrent = workers;
        }
        if let Some(raw) = lookup("WASM_QUEUE_TIMEOUT_MS") {
            let millis: NonZeroU16 = raw.trim().parse().map_err(|err| ConfigError {
                var: "WASM_QUEUE_TIMEOUT_MS",
                reason: format!(
                    "{raw:?} is not a whole number of milliseconds in 1..=60000 ({err})"
                )
                .into(),
            })?;
            if millis.get() > 60_000 {
                return Err(ConfigError {
                    var: "WASM_QUEUE_TIMEOUT_MS",
                    reason: format!("{millis} is outside 1..=60000").into(),
                });
            }
            config.wasm_queue_timeout_ms = millis;
        }
        let non_empty = |var: &'static str| match lookup(var) {
            Some(raw) if raw.trim().is_empty() => Err(ConfigError {
                var,
                reason: "is empty".into(),
            }),
            Some(raw) => Ok(Some(raw.trim().to_owned())),
            None => Ok(None),
        };
        config.node_name = non_empty("NODE_NAME")?.map(String::into_boxed_str);
        config.acme_ca_file = non_empty("ACME_CA_FILE")?.map(PathBuf::from);
        if let Some(list) = lookup("CATCH_ALL_TENANTS") {
            config.catch_all_tenants = list
                .split(',')
                .map(str::trim)
                .filter(|tenant| !tenant.is_empty())
                .map(Box::from)
                .collect();
        }
        Ok(config)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_lookup(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn defaults_when_nothing_set() {
        assert_eq!(config(&[]), Ok(Config::default()));
    }

    #[test]
    fn reads_every_variable() {
        let parsed = config(&[
            ("PROXY_ADDR", "0.0.0.0:9000"),
            ("PROXY_TLS_ADDR", "0.0.0.0:9443"),
            ("ADMIN_SOCKET", "/tmp/admin.sock"),
            ("REQUEST_TIMEOUT_SECS", "5"),
            ("LOG_FORMAT", "JSON"),
            ("WASM_MAX_CONCURRENT", "2"),
            ("WASM_QUEUE_TIMEOUT_MS", "250"),
            ("NODE_NAME", "n1"),
            ("ACME_CA_FILE", "/etc/acme-root.pem"),
            ("CATCH_ALL_TENANTS", "t1, t2,,"),
        ]);
        assert_eq!(
            parsed,
            Ok(Config {
                proxy_addr: SocketAddr::from(([0, 0, 0, 0], 9000)),
                proxy_tls_addr: Some(SocketAddr::from(([0, 0, 0, 0], 9443))),
                admin_socket: PathBuf::from("/tmp/admin.sock"),
                request_timeout_secs: NonZeroU16::new(5).expect("5 is not zero"),
                log_format: LogFormat::Json,
                wasm_max_concurrent: NonZeroUsize::new(2).expect("2 is not zero"),
                wasm_queue_timeout_ms: NonZeroU16::new(250).expect("250 is not zero"),
                node_name: Some("n1".into()),
                acme_ca_file: Some(PathBuf::from("/etc/acme-root.pem")),
                catch_all_tenants: vec!["t1".into(), "t2".into()],
            })
        );
    }

    #[test]
    fn errors_name_the_variable() {
        for (var, value) in [
            ("PROXY_ADDR", "nope"),
            ("PROXY_TLS_ADDR", "nope"),
            ("ADMIN_SOCKET", " "),
            ("REQUEST_TIMEOUT_SECS", "0"),
            ("REQUEST_TIMEOUT_SECS", "abc"),
            ("LOG_FORMAT", "xml"),
            ("WASM_MAX_CONCURRENT", "0"),
            ("WASM_MAX_CONCURRENT", "257"),
            ("WASM_MAX_CONCURRENT", "many"),
            ("WASM_QUEUE_TIMEOUT_MS", "0"),
            ("WASM_QUEUE_TIMEOUT_MS", "60001"),
            ("NODE_NAME", " "),
            ("ACME_CA_FILE", ""),
        ] {
            let err = config(&[(var, value)]).expect_err("value must be rejected");
            assert_eq!(err.var, var);
            assert!(
                err.to_string().starts_with(&format!("invalid {var}:")),
                "{err}"
            );
        }
    }
}
