//! Settings read from environment variables, once at startup.

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

use crate::acme;
use crate::entry::{self, EntryPoint};
use crate::observe::metrics::DEFAULT_SERIES_PER_TENANT;
use crate::observe::tracing::ExportConfig;
use crate::service::StaticRoots;
use crate::service::health;
use crate::service::upstream_policy::UpstreamPolicy;
use podgate_model::TlsVersion;

/// Most WASM filter runs that may execute at once: half of tokio's 512-thread blocking pool, so
/// snapshot compiles always find threads.
const WASM_WORKERS_MAX: usize = 256;
/// Most active health probes that may run at once.
const HEALTH_PROBES_MAX: usize = 4096;

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

/// Idle upstream connections one worker thread's share of the pool holds unless `UPSTREAM_POOL_SIZE`
/// says otherwise: Pingora's own default.
const DEFAULT_UPSTREAM_POOL: NonZeroUsize = NonZeroUsize::MIN.saturating_add(127);

/// The largest `UPSTREAM_POOL_SIZE`.
const UPSTREAM_POOL_MAX: usize = 65_536;

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
/// | `ENTRY_POINTS` | unset | Named listeners, `name=address/protocol[;proxy_protocol]` comma separated, protocol `http`, `https`, `tcp` or `udp`. Replaces `PROXY_ADDR` and `PROXY_TLS_ADDR`; setting both is an error. |
/// | `PROXY_ADDR` | `127.0.0.1:8080` | Shorthand for the entry point `web=<addr>/http`. |
/// | `PROXY_TLS_ADDR` | unset | Shorthand for the entry point `websecure=<addr>/https`; unset means no TLS listener. |
/// | `ADMIN_SOCKET` | `/run/podgate/admin.sock` | Unix socket of the admin API. |
/// | `REQUEST_TIMEOUT_SECS` | `30` | Admin request and upstream I/O limit, 1..=3600. |
/// | `LOG_FORMAT` | `pretty` | `pretty` or `json`. |
/// | `NODE_NAME` | unset | Name of this node; the node whose name equals the snapshot's `acme.issuer_node` orders certificates. |
/// | `ACME_CA_FILE` | unset | PEM file with the root certificate to trust for the ACME server instead of the platform's roots (private or test CAs). |
/// | `ACME_DNS_ZONES` | unset | Comma-separated DNS zones an app may use the `dns-01` challenge for. Unset: `dns-01` is off and an app asking for it is rejected. |
/// | `RUST_LOG` | `info` | Log filter (`tracing` env-filter syntax). |
/// | `WASM_MAX_CONCURRENT` | available cores, at most 256 | WASM filter runs at once, 1..=256. |
/// | `WASM_QUEUE_TIMEOUT_MS` | `1000` | How long a filter run waits for a worker before `503`, 1..=60000. |
/// | `BASIC_AUTH_MAX_CONCURRENT` | available cores, at most 256 | `basic_auth` password verifications at once, 1..=256; one tenant may hold half of them. |
/// | `HEALTH_MAX_CONCURRENT` | `64` | Active health probes in flight at once across all tenants, 1..=4096. |
/// | `CATCH_ALL_TENANTS` | unset | Comma-separated tenant ids allowed catch-all routers on shared entry points. |
/// | `UPSTREAM_POLICY_FILE` | unset | JSON file with the upstream address policy: which addresses each tenant's servers may have. Unset: loopback, link-local, metadata, unspecified and multicast are denied. |
/// | `ACCESS_LOG_FILE` | unset | File the access log is appended to; unset writes it to stdout. The file is reopened when its inode changes, so renaming it rotates it. Whether anything is logged is the snapshot's `observability.access_log`. |
/// | `METRICS_ADDR` | unset | TCP address of the read-only metrics listener, which serves `GET /metrics` and nothing else. Unset: no listener. |
/// | `METRICS_SERIES_PER_TENANT` | `500` | Metric series each tenant may own before new ones collapse into `other`, at least 1. |
/// | `TLS_MIN_VERSION` | `1.2` | Lowest TLS version the HTTPS entry points serve, `1.2` or `1.3`. Pingora builds one rustls config per listener, so a connection below it is refused after the handshake (`421`), or at the ClientHello when the client offers no TLS 1.3 suite. An app's `tls.min_version` can only raise it. |
/// | `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | Base URL of an OTLP/HTTP collector, `http://` or `https://`; spans are POSTed to `<endpoint>/v1/traces` as protobuf. Unset: nothing is exported (requests are still sampled and their trace context propagated). Never part of a snapshot. |
/// | `OTEL_EXPORTER_OTLP_HEADERS` | unset | `name=value,...` sent with every export, such as an API key. Values are used as written and never logged. |
/// | `OTEL_EXPORTER_OTLP_CERTIFICATE` | unset | PEM file with the roots to trust for an `https` collector instead of the platform's. |
/// | `OTEL_SERVICE_NAME` | `podgate` | The `service.name` of exported spans. |
/// | `OTEL_MAX_SPANS_PER_SEC` | `1000` | Spans a second this node lets be traced, whoever asks (a traced request is two spans), 1..=1000000. Each tenant may use half of it. Requests over either cap are not traced. |
/// | `STATIC_ROOTS_FILE` | unset | JSON file with the directories static services may serve, `{"<tenant id>": {"<root name>": "/absolute/dir"}}`, read and opened once at startup; a bad entry stops startup. Unset: no tenant has a static root. A snapshot names a root; it never supplies a path. |
/// | `STATIC_MAX_CONCURRENT_READS` | available cores times 4, at most 256 | Blocking file-system operations static services run at once, 1..=256; an operation that finds no free slot within a second answers `503` with `retry-after`. |
/// | `CACHE_TENANT_MAX_PERCENT` | `50` | Most a tenant's response cache may hold, as a percent of its `max_buffer_bytes`, 1..=100; the upper limit for any `cache` middleware's `max_bytes`. |
/// | `UPSTREAM_POOL_SIZE` | `128` | Idle upstream connections kept for reuse, per worker thread (one thread per core): Pingora keeps one LRU for the whole process, so the pool holds this times the thread count and evicts the least recently used past it. 1..=65536. A transport's `max_idle_per_host` is refused for the same reason. |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The listeners: `ENTRY_POINTS`, or `web` (`PROXY_ADDR`) and `websecure`
    /// (`PROXY_TLS_ADDR`, when set). Never empty.
    pub entry_points: Vec<EntryPoint>,
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
    /// `basic_auth` password verifications that may run at once, across all tenants. A tenant
    /// may hold at most half of them; a verification that finds none free within a second
    /// answers `503` with `retry-after`.
    pub basic_auth_max_concurrent: NonZeroUsize,
    /// Active health probes that may run at once, across all tenants: the cap that bounds how
    /// many connections a tenant that declares many servers can make podgate open.
    pub health_max_concurrent: NonZeroUsize,
    /// Name of this node, compared with the snapshot's `acme.issuer_node`. Absent: never issues.
    pub node_name: Option<Box<str>>,
    /// PEM file with the root certificate trusted for the ACME server. Absent: platform roots.
    pub acme_ca_file: Option<PathBuf>,
    /// Zones the operator lets apps prove with the `dns-01` challenge (`ACME_DNS_ZONES`); a host
    /// is allowed when it is a zone or lies under one. Empty: `dns-01` is off.
    pub acme_dns_zones: Vec<Box<str>>,
    /// Tenants the operator lets declare catch-all routers (a `host_regexp` or host-free router)
    /// on a shared entry point, so they can receive hosts nobody claims. Empty: none can.
    pub catch_all_tenants: Vec<Box<str>>,
    /// File with the upstream address policy. Absent: the built-in deny list. Read once at
    /// startup by [`Config::upstream_policy`].
    pub upstream_policy_file: Option<PathBuf>,
    /// File the access log is appended to. Absent: standard output.
    pub access_log_file: Option<PathBuf>,
    /// TCP address of the read-only metrics listener (`GET /metrics` and nothing else). Absent:
    /// no listener; the admin socket still serves `GET /metrics`.
    pub metrics_addr: Option<SocketAddr>,
    /// Series each tenant may own for its routers, services and servers before they collapse
    /// into `other` (see [`crate::observe::metrics`]).
    pub metrics_series_per_tenant: NonZeroU32,
    /// Lowest TLS version served (`TLS_MIN_VERSION`); the floor of every app's `tls.min_version`.
    pub tls_min_version: TlsVersion,
    /// Where traces go and how many a node allows; see [`ExportConfig`]. No endpoint: nothing is
    /// exported.
    pub otel: ExportConfig,
    /// File with the directories of static services, per tenant. Absent: none. Read once at
    /// startup by [`Config::static_roots`].
    pub static_roots_file: Option<PathBuf>,
    /// File-system operations static services run at once, across all tenants.
    pub static_max_concurrent_reads: NonZeroUsize,
    /// Percent of a tenant's `max_buffer_bytes` its response cache may hold at most
    /// (`CACHE_TENANT_MAX_PERCENT`), 1..=100.
    pub cache_tenant_max_percent: u8,
    /// Idle upstream connections the pool keeps per worker thread.
    pub upstream_pool_size: NonZeroUsize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            entry_points: vec![EntryPoint::web(SocketAddr::from(([127, 0, 0, 1], 8080)))],
            admin_socket: PathBuf::from("/run/podgate/admin.sock"),
            request_timeout_secs: NonZeroU16::MIN.saturating_add(29),
            log_format: LogFormat::Pretty,
            wasm_max_concurrent: default_workers(),
            wasm_queue_timeout_ms: NonZeroU16::MIN.saturating_add(999),
            basic_auth_max_concurrent: default_workers(),
            health_max_concurrent: NonZeroUsize::MIN
                .saturating_add(health::DEFAULT_MAX_CONCURRENT - 1),
            node_name: None,
            acme_ca_file: None,
            acme_dns_zones: Vec::new(),
            catch_all_tenants: Vec::new(),
            upstream_policy_file: None,
            access_log_file: None,
            metrics_addr: None,
            metrics_series_per_tenant: DEFAULT_SERIES_PER_TENANT,
            tls_min_version: TlsVersion::V1_2,
            otel: ExportConfig::default(),
            static_roots_file: None,
            static_max_concurrent_reads: default_static_reads(),
            cache_tenant_max_percent: crate::cache::DEFAULT_TENANT_MAX_PERCENT,
            upstream_pool_size: DEFAULT_UPSTREAM_POOL,
        }
    }
}

fn default_workers() -> NonZeroUsize {
    std::thread::available_parallelism()
        .ok()
        .and_then(|cores| NonZeroUsize::new(cores.get().min(WASM_WORKERS_MAX)))
        .unwrap_or(NonZeroUsize::MIN)
}

/// Four read slots per core: file reads wait on the disk, not on the CPU.
fn default_static_reads() -> NonZeroUsize {
    std::thread::available_parallelism()
        .ok()
        .and_then(|cores| NonZeroUsize::new(cores.get().saturating_mul(4).min(WASM_WORKERS_MAX)))
        .unwrap_or(NonZeroUsize::MIN)
}

fn parse_addr(var: &'static str, raw: &str) -> Result<SocketAddr, ConfigError> {
    raw.trim().parse().map_err(|err| ConfigError {
        var,
        reason: format!("{raw:?} is not a socket address like 0.0.0.0:8080 ({err})").into(),
    })
}

impl Config {
    /// Loads the static roots: the directories named by `STATIC_ROOTS_FILE`, each opened as a
    /// directory handle, or none when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for `STATIC_ROOTS_FILE` when the file cannot be read or is malformed, or an
    /// entry is empty, relative or not a directory; the reason names the file, the tenant and the
    /// root.
    pub fn static_roots(&self) -> Result<StaticRoots, ConfigError> {
        match &self.static_roots_file {
            None => Ok(StaticRoots::default()),
            Some(path) => StaticRoots::load(path).map_err(|err| ConfigError {
                var: "STATIC_ROOTS_FILE",
                reason: err.to_string().into(),
            }),
        }
    }

    /// Loads the upstream address policy: the file named by `UPSTREAM_POLICY_FILE`, else the
    /// built-in default.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for `UPSTREAM_POLICY_FILE` when the file cannot be read or is invalid; the
    /// reason names the file and the entry that is wrong.
    pub fn upstream_policy(&self) -> Result<UpstreamPolicy, ConfigError> {
        match &self.upstream_policy_file {
            None => Ok(UpstreamPolicy::builtin()),
            Some(path) => UpstreamPolicy::load(path).map_err(|err| ConfigError {
                var: "UPSTREAM_POLICY_FILE",
                reason: format!("{}: {err}", path.display()).into(),
            }),
        }
    }

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
        let proxy_addr = lookup("PROXY_ADDR");
        let proxy_tls_addr = lookup("PROXY_TLS_ADDR");
        if let Some(raw) = lookup("ENTRY_POINTS") {
            let shorthand: Vec<&str> = [
                proxy_addr.as_ref().map(|_| "PROXY_ADDR"),
                proxy_tls_addr.as_ref().map(|_| "PROXY_TLS_ADDR"),
            ]
            .into_iter()
            .flatten()
            .collect();
            if !shorthand.is_empty() {
                return Err(ConfigError {
                    var: "ENTRY_POINTS",
                    reason: format!(
                        "cannot be set together with {}: they are the shorthand for the entry points web and websecure; use one or the other",
                        shorthand.join(" and ")
                    )
                    .into(),
                });
            }
            if raw.trim().is_empty() {
                return Err(ConfigError {
                    var: "ENTRY_POINTS",
                    reason: "is empty".into(),
                });
            }
            config.entry_points = entry::parse_list(&raw).map_err(|err| ConfigError {
                var: "ENTRY_POINTS",
                reason: err.to_string().into(),
            })?;
        } else {
            if let Some(raw) = proxy_addr {
                config.entry_points = vec![EntryPoint::web(parse_addr("PROXY_ADDR", &raw)?)];
            }
            if let Some(raw) = proxy_tls_addr {
                config
                    .entry_points
                    .push(EntryPoint::websecure(parse_addr("PROXY_TLS_ADDR", &raw)?));
            }
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
        if let Some(raw) = lookup("BASIC_AUTH_MAX_CONCURRENT") {
            let workers: NonZeroUsize = raw.trim().parse().map_err(|err| ConfigError {
                var: "BASIC_AUTH_MAX_CONCURRENT",
                reason: format!("{raw:?} is not a whole number in 1..={WASM_WORKERS_MAX} ({err})")
                    .into(),
            })?;
            if workers.get() > WASM_WORKERS_MAX {
                return Err(ConfigError {
                    var: "BASIC_AUTH_MAX_CONCURRENT",
                    reason: format!("{workers} is outside 1..={WASM_WORKERS_MAX}").into(),
                });
            }
            config.basic_auth_max_concurrent = workers;
        }
        if let Some(raw) = lookup("HEALTH_MAX_CONCURRENT") {
            let probes: NonZeroUsize = raw.trim().parse().map_err(|err| ConfigError {
                var: "HEALTH_MAX_CONCURRENT",
                reason: format!("{raw:?} is not a whole number in 1..={HEALTH_PROBES_MAX} ({err})")
                    .into(),
            })?;
            if probes.get() > HEALTH_PROBES_MAX {
                return Err(ConfigError {
                    var: "HEALTH_MAX_CONCURRENT",
                    reason: format!("{probes} is outside 1..={HEALTH_PROBES_MAX}").into(),
                });
            }
            config.health_max_concurrent = probes;
        }
        if let Some(raw) = lookup("STATIC_MAX_CONCURRENT_READS") {
            let reads: NonZeroUsize = raw.trim().parse().map_err(|err| ConfigError {
                var: "STATIC_MAX_CONCURRENT_READS",
                reason: format!("{raw:?} is not a whole number in 1..={WASM_WORKERS_MAX} ({err})")
                    .into(),
            })?;
            if reads.get() > WASM_WORKERS_MAX {
                return Err(ConfigError {
                    var: "STATIC_MAX_CONCURRENT_READS",
                    reason: format!("{reads} is outside 1..={WASM_WORKERS_MAX}").into(),
                });
            }
            config.static_max_concurrent_reads = reads;
        }
        if let Some(raw) = lookup("CACHE_TENANT_MAX_PERCENT") {
            config.cache_tenant_max_percent = raw
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|percent| (1..=100).contains(percent))
                .ok_or_else(|| ConfigError {
                    var: "CACHE_TENANT_MAX_PERCENT",
                    reason: format!("{raw:?} is not a whole number in 1..=100").into(),
                })?;
        }
        if let Some(raw) = lookup("UPSTREAM_POOL_SIZE") {
            let size: NonZeroUsize = raw.trim().parse().map_err(|err| ConfigError {
                var: "UPSTREAM_POOL_SIZE",
                reason: format!("{raw:?} is not a whole number in 1..={UPSTREAM_POOL_MAX} ({err})")
                    .into(),
            })?;
            if size.get() > UPSTREAM_POOL_MAX {
                return Err(ConfigError {
                    var: "UPSTREAM_POOL_SIZE",
                    reason: format!("{size} is outside 1..={UPSTREAM_POOL_MAX}").into(),
                });
            }
            config.upstream_pool_size = size;
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
        if let Some(raw) = lookup("ACME_DNS_ZONES") {
            config.acme_dns_zones =
                acme::dns01::parse_zones(&raw).map_err(|reason| ConfigError {
                    var: "ACME_DNS_ZONES",
                    reason: reason.into(),
                })?;
        }
        config.upstream_policy_file = non_empty("UPSTREAM_POLICY_FILE")?.map(PathBuf::from);
        config.access_log_file = non_empty("ACCESS_LOG_FILE")?.map(PathBuf::from);
        if let Some(raw) = non_empty("METRICS_ADDR")? {
            config.metrics_addr = Some(parse_addr("METRICS_ADDR", &raw)?);
        }
        if let Some(raw) = lookup("METRICS_SERIES_PER_TENANT") {
            config.metrics_series_per_tenant = raw.trim().parse().map_err(|err| ConfigError {
                var: "METRICS_SERIES_PER_TENANT",
                reason: format!("{raw:?} is not a whole number of series, at least 1 ({err})")
                    .into(),
            })?;
        }
        if let Some(raw) = non_empty("TLS_MIN_VERSION")? {
            config.tls_min_version = match raw.as_str() {
                "1.2" => TlsVersion::V1_2,
                "1.3" => TlsVersion::V1_3,
                _ => {
                    return Err(ConfigError {
                        var: "TLS_MIN_VERSION",
                        reason: format!("{raw:?} is not `1.2` or `1.3`").into(),
                    });
                }
            };
        }
        config.otel = ExportConfig::from_lookup(&lookup)?;
        config.static_roots_file = non_empty("STATIC_ROOTS_FILE")?.map(PathBuf::from);
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
            ("BASIC_AUTH_MAX_CONCURRENT", "3"),
            ("HEALTH_MAX_CONCURRENT", "8"),
            ("STATIC_MAX_CONCURRENT_READS", "5"),
            ("UPSTREAM_POOL_SIZE", "64"),
            ("STATIC_ROOTS_FILE", "/etc/podgate/static-roots.json"),
            ("NODE_NAME", "n1"),
            ("ACME_CA_FILE", "/etc/acme-root.pem"),
            ("ACME_DNS_ZONES", "Example.com, sub.example.org."),
            ("UPSTREAM_POLICY_FILE", "/etc/podgate/upstream-policy.json"),
            ("ACCESS_LOG_FILE", "/var/log/podgate/access.log"),
            ("METRICS_ADDR", "127.0.0.1:9100"),
            ("METRICS_SERIES_PER_TENANT", "50"),
            ("TLS_MIN_VERSION", "1.3"),
            ("CATCH_ALL_TENANTS", "t1, t2,,"),
            ("CACHE_TENANT_MAX_PERCENT", "40"),
        ]);
        assert_eq!(
            parsed,
            Ok(Config {
                entry_points: vec![
                    EntryPoint::web(SocketAddr::from(([0, 0, 0, 0], 9000))),
                    EntryPoint::websecure(SocketAddr::from(([0, 0, 0, 0], 9443))),
                ],
                admin_socket: PathBuf::from("/tmp/admin.sock"),
                request_timeout_secs: NonZeroU16::new(5).expect("5 is not zero"),
                log_format: LogFormat::Json,
                wasm_max_concurrent: NonZeroUsize::new(2).expect("2 is not zero"),
                wasm_queue_timeout_ms: NonZeroU16::new(250).expect("250 is not zero"),
                basic_auth_max_concurrent: NonZeroUsize::new(3).expect("3 is not zero"),
                health_max_concurrent: NonZeroUsize::new(8).expect("8 is not zero"),
                static_max_concurrent_reads: NonZeroUsize::new(5).expect("5 is not zero"),
                upstream_pool_size: NonZeroUsize::new(64).expect("64 is not zero"),
                static_roots_file: Some(PathBuf::from("/etc/podgate/static-roots.json")),
                node_name: Some("n1".into()),
                acme_ca_file: Some(PathBuf::from("/etc/acme-root.pem")),
                acme_dns_zones: vec!["example.com".into(), "sub.example.org".into()],
                upstream_policy_file: Some(PathBuf::from("/etc/podgate/upstream-policy.json")),
                access_log_file: Some(PathBuf::from("/var/log/podgate/access.log")),
                tls_min_version: TlsVersion::V1_3,
                otel: ExportConfig::default(),
                catch_all_tenants: vec!["t1".into(), "t2".into()],
                metrics_addr: Some(SocketAddr::from(([127, 0, 0, 1], 9100))),
                metrics_series_per_tenant: NonZeroU32::new(50).expect("50 is not zero"),
                cache_tenant_max_percent: 40,
            })
        );
    }

    #[test]
    fn errors_name_the_variable() {
        for (var, value) in [
            ("PROXY_ADDR", "nope"),
            ("PROXY_TLS_ADDR", "nope"),
            ("ENTRY_POINTS", " "),
            ("ENTRY_POINTS", "web=nope/http"),
            ("ENTRY_POINTS", "web=127.0.0.1:80"),
            ("ADMIN_SOCKET", " "),
            ("REQUEST_TIMEOUT_SECS", "0"),
            ("REQUEST_TIMEOUT_SECS", "abc"),
            ("LOG_FORMAT", "xml"),
            ("WASM_MAX_CONCURRENT", "0"),
            ("WASM_MAX_CONCURRENT", "257"),
            ("WASM_MAX_CONCURRENT", "many"),
            ("WASM_QUEUE_TIMEOUT_MS", "0"),
            ("WASM_QUEUE_TIMEOUT_MS", "60001"),
            ("BASIC_AUTH_MAX_CONCURRENT", "0"),
            ("BASIC_AUTH_MAX_CONCURRENT", "257"),
            ("HEALTH_MAX_CONCURRENT", "0"),
            ("HEALTH_MAX_CONCURRENT", "4097"),
            ("HEALTH_MAX_CONCURRENT", "lots"),
            ("STATIC_MAX_CONCURRENT_READS", "0"),
            ("STATIC_MAX_CONCURRENT_READS", "257"),
            ("UPSTREAM_POOL_SIZE", "0"),
            ("UPSTREAM_POOL_SIZE", "65537"),
            ("UPSTREAM_POOL_SIZE", "many"),
            ("STATIC_ROOTS_FILE", " "),
            ("CACHE_TENANT_MAX_PERCENT", "0"),
            ("CACHE_TENANT_MAX_PERCENT", "101"),
            ("CACHE_TENANT_MAX_PERCENT", "half"),
            ("NODE_NAME", " "),
            ("ACME_CA_FILE", ""),
            ("ACME_DNS_ZONES", " "),
            ("ACME_DNS_ZONES", "*.example.com"),
            ("ACME_DNS_ZONES", "a b"),
            ("UPSTREAM_POLICY_FILE", " "),
            ("ACCESS_LOG_FILE", " "),
            ("METRICS_ADDR", "nope"),
            ("METRICS_ADDR", " "),
            ("METRICS_SERIES_PER_TENANT", "0"),
            ("METRICS_SERIES_PER_TENANT", "many"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "nope"),
            ("OTEL_MAX_SPANS_PER_SEC", "0"),
        ] {
            let err = config(&[(var, value)]).expect_err("value must be rejected");
            assert_eq!(err.var, var);
            assert!(
                err.to_string().starts_with(&format!("invalid {var}:")),
                "{err}"
            );
        }
    }

    #[test]
    fn otel_header_values_never_print() {
        let parsed = config(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
            (
                "OTEL_EXPORTER_OTLP_HEADERS",
                "x-api-key=s3cret-key,authorization=Bearer s3cret-token",
            ),
        ])
        .expect("parses");
        assert_eq!(parsed.otel.headers.len(), 2);
        for shown in [format!("{parsed:?}"), format!("{parsed:#?}")] {
            assert!(
                !shown.contains("s3cret"),
                "Config's Debug leaks a header value: {shown}"
            );
        }
        for bad in ["x-api-key=s3cret\nkey", "s3cret-no-equals"] {
            let err = config(&[("OTEL_EXPORTER_OTLP_HEADERS", bad)]).expect_err("refused");
            assert!(!err.to_string().contains("s3cret"), "{err}");
        }
    }

    #[test]
    fn entry_points_replace_the_shorthand() {
        let parsed = config(&[(
            "ENTRY_POINTS",
            "public=0.0.0.0:80/http,internal=127.0.0.1:81/http,secure=0.0.0.0:443/https",
        )])
        .expect("parses");
        let names: Vec<&str> = parsed.entry_points.iter().map(|e| &*e.name).collect();
        assert_eq!(names, ["public", "internal", "secure"]);
    }

    #[test]
    fn entry_points_refuse_the_shorthand_and_name_both() {
        for shorthand in ["PROXY_ADDR", "PROXY_TLS_ADDR"] {
            let err = config(&[
                ("ENTRY_POINTS", "web=127.0.0.1:80/http"),
                (shorthand, "127.0.0.1:81"),
            ])
            .expect_err("both set");
            let text = err.to_string();
            assert!(
                text.contains("ENTRY_POINTS") && text.contains(shorthand),
                "{text}"
            );
        }
    }

    #[test]
    fn a_bad_entry_is_printed_with_the_variable() {
        let err =
            config(&[("ENTRY_POINTS", "a=127.0.0.1:80/http,b=oops/http")]).expect_err("bad entry");
        assert_eq!(
            err.to_string(),
            "invalid ENTRY_POINTS: entry \"b=oops/http\": \"oops\" is not a socket address like 0.0.0.0:8080 (invalid socket address syntax)"
        );
    }

    #[test]
    fn tls_min_version_is_1_2_or_1_3() {
        for bad in ["1.1", "TLS1.3", "1", ""] {
            let err = config(&[("TLS_MIN_VERSION", bad)]).expect_err(bad);
            assert_eq!(err.var, "TLS_MIN_VERSION", "{bad:?}");
        }
    }
}
