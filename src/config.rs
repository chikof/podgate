//! Settings read from environment variables, once at startup.

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU64};
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

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
/// | `RUST_LOG` | `info` | Log filter (`tracing` env-filter syntax). |
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            proxy_tls_addr: None,
            admin_socket: PathBuf::from("/run/podgate/admin.sock"),
            request_timeout_secs: NonZeroU16::MIN.saturating_add(29),
            log_format: LogFormat::Pretty,
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
        ]);
        assert_eq!(
            parsed,
            Ok(Config {
                proxy_addr: SocketAddr::from(([0, 0, 0, 0], 9000)),
                proxy_tls_addr: Some(SocketAddr::from(([0, 0, 0, 0], 9443))),
                admin_socket: PathBuf::from("/tmp/admin.sock"),
                request_timeout_secs: NonZeroU16::new(5).expect("5 is not zero"),
                log_format: LogFormat::Json,
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
