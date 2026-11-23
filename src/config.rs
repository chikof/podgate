//! Settings read from environment variables, once at startup.

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

use crate::acme;
use crate::entry::{self, EntryPoint};
use crate::fairq::Settings as BackendLimiterSettings;
use crate::h3;
use crate::middleware::basic_auth::Htpasswd;
use crate::middleware::plugin::Plugins;
use crate::observe::metrics::DEFAULT_SERIES_PER_TENANT;
use crate::observe::tracing::ExportConfig;
use crate::ratelimit_store::Stores;
use crate::service::health;
use crate::service::resolve;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::service::{FastcgiRoots, StaticRoots};
use crate::spiffe::{Policy as SpiffePolicy, Spiffe};
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
/// | `ENTRY_POINTS` | unset | Named listeners, `name=address/protocol[;proxy_protocol][;http3[=port]]` comma separated, protocol `http`, `https`, `tcp` or `udp`. `;http3` also serves the `https` entry point over HTTP/3 on the same UDP port and advertises it with `Alt-Svc`; `=port` advertises another port. Replaces `PROXY_ADDR` and `PROXY_TLS_ADDR`; setting both is an error. |
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
/// | `SPIFFE_ENDPOINT_SOCKET` | unset | The SPIFFE Workload API agent's unix socket (`/run/spire/sockets/agent.sock` or `unix:///...`). Needs `SPIFFE_POLICY_FILE`. Unset: no SPIFFE. |
/// | `SPIFFE_POLICY_FILE` | unset | JSON file with the SPIFFE policy: per tenant its SVID hint, the server IDs it may talk to, the client trust domains it may verify. Needs `SPIFFE_ENDPOINT_SOCKET`. |
/// | `ACCESS_LOG_FILE` | unset | File the access log is appended to; unset writes it to stdout. The file is reopened when its inode changes, so renaming it rotates it. Whether anything is logged is the snapshot's `observability.access_log`. |
/// | `METRICS_ADDR` | unset | TCP address of the read-only metrics listener, which serves `GET /metrics` and nothing else. Unset: no listener. |
/// | `METRICS_SERIES_PER_TENANT` | `500` | Metric series each tenant may own before new ones collapse into `other`, at least 1. |
/// | `DASHBOARD_ADDR` | unset | TCP address of the read-only dashboard (a web UI over the overview and explain APIs). Unset: no dashboard. A non-loopback address needs `DASHBOARD_AUTH_FILE` or startup stops. Reference: `docs/ref/dashboard.md`. |
/// | `DASHBOARD_AUTH_FILE` | unset | htpasswd file (`user:hash` lines, bcrypt or argon2, the limits of `basic_auth`) the dashboard asks for. Read once at startup; a bad entry stops startup. Only valid with `DASHBOARD_ADDR`. |
/// | `DASHBOARD_HOSTS` | unset | Comma-separated host names the dashboard's `Host` header may carry besides its bound address and, on a loopback or wildcard bind, `localhost`. Needed when the dashboard is reached under a name, such as through podgate itself. Only valid with `DASHBOARD_ADDR`. |
/// | `TLS_MIN_VERSION` | `1.2` | Lowest TLS version the HTTPS entry points serve, `1.2` or `1.3`. Pingora builds one rustls config per listener, so a connection below it is refused after the handshake (`421`), or at the ClientHello when the client offers no TLS 1.3 suite. An app's `tls.min_version` can only raise it. |
/// | `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | Base URL of an OTLP/HTTP collector, `http://` or `https://`; spans are POSTed to `<endpoint>/v1/traces` as protobuf. Unset: nothing is exported (requests are still sampled and their trace context propagated). Never part of a snapshot. |
/// | `OTEL_EXPORTER_OTLP_HEADERS` | unset | `name=value,...` sent with every export, such as an API key. Values are used as written and never logged. |
/// | `OTEL_EXPORTER_OTLP_CERTIFICATE` | unset | PEM file with the roots to trust for an `https` collector instead of the platform's. |
/// | `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | `http/protobuf` or `grpc`. With `grpc` the endpoint is `http://host:4317` or `https://host:4317` without a path and spans go as the unary `TraceService/Export` call; a plaintext endpoint must be on loopback unless `OTEL_EXPORTER_OTLP_INSECURE=true`. Never part of a snapshot. Reference: `docs/ref/tracing-grpc.md`. |
/// | `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY` | unset | PEM client certificate chain and key for mutual TLS to a `grpc` collector; set together. |
/// | `OTEL_EXPORTER_OTLP_COMPRESSION` | `none` | `gzip` or `none`; `grpc` only. |
/// | `OTEL_EXPORTER_OTLP_INSECURE` | `false` | `true` allows a plaintext `grpc` endpoint that is not on loopback (logged at warn level at startup); `grpc` only. |
/// | `OTEL_EXPORTER_OTLP_TIMEOUT` | `3000` | Milliseconds one export may take, connecting included, 1..=10000. |
/// | `OTEL_SERVICE_NAME` | `podgate` | The `service.name` of exported spans. |
/// | `OTEL_MAX_SPANS_PER_SEC` | `1000` | Spans a second this node lets be traced, whoever asks (a traced request is two spans), 1..=1000000. Each tenant may use half of it. Requests over either cap are not traced. |
/// | `STATIC_ROOTS_FILE` | unset | JSON file with the directories static services may serve, `{"<tenant id>": {"<root name>": "/absolute/dir"}}`, read and opened once at startup; a bad entry stops startup. Unset: no tenant has a static root. A snapshot names a root; it never supplies a path. |
/// | `FASTCGI_FILE` | unset | JSON file with the PHP-FPM (or other FastCGI) applications `fastcgi` services may run, `{"<tenant id>": {"<name>": {"address": "unix:/run/php/acme.sock" or "127.0.0.1:9000", "root": "/absolute/dir", "max_connections": 16, "dial_timeout_secs": 3, "read_timeout_secs": 30}}}`, read once at startup; a bad entry stops startup. Never part of a snapshot, which names an entry of its own tenant and never supplies an address or a root. Unset: no tenant has a FastCGI upstream. Reference: `docs/ref/svc-fastcgi.md`. |
/// | `BACKEND_LIMITER_FILE` | unset | JSON file with the operator's settings for the per-backend adaptive limiter and fair queue, `{"default": {"max_limit": 512}, "backends": {"10.0.0.0/8": {"queue_wait_ms": 1000}, "10.1.2.3:8080": {"enabled": false}}}`, read once at startup; a bad field stops startup. Fields: `enabled`, `initial_limit`, `min_limit`, `max_limit`, `window_samples`, `tolerance`, `min_gradient`, `smoothing`, `baseline_drift`, `queue_size`, `queue_wait_ms`. An entry is an exact `ip:port`, a CIDR or a bare address, and the most specific one wins field by field. `enabled: false` means no adaptive limit and no queue; the tenant's `max_inflight` still applies. Never part of a snapshot. Unset: every backend runs with the built-in values. Reference: `docs/ref/backend-limiter.md`. |
/// | `RATE_LIMIT_STORES_FILE` | unset | JSON file with the Redis-compatible stores cluster-scope `rate_limit` middlewares may use, `{"<store>": {"url": "redis[s]://host[:port]", "username": "...", "password_file": "...", "tls_ca_file": "...", "tenants": ["<tenant id>"], "max_connections": 16, "timeout_ms": 20}}`, read once at startup; a bad entry stops startup. Never part of a snapshot, which names a store and only for the tenants its entry lists. `rediss://` needs `tls_ca_file`. Unset: no cluster-scope limit can compile. Reference: `docs/ref/ratelimit-cluster.md`. |
/// | `PLUGINS_FILE` | unset | JSON file with the out-of-process plugins `plugin` middlewares may use, `{"<plugin>": {"socket": "/run/podgate/plugins/x.sock", "tenants": ["<tenant id>"], "managed": true, "command": "/opt/x", "args": [], "env": {}, "user": "x", "group": "x", "limits": {"memory_max_bytes": 268435456, "pids_max": 64, "cpu_percent": 100}, "max_concurrent": 256}}`, read once at startup; a bad entry stops startup, as does a plugin that does not answer `Describe` within 5 seconds. Never part of a snapshot, which names a plugin and only for the tenants its entry lists. A managed plugin is started and restarted by podgate; an unmanaged one is run by the operator. Unset: no `plugin` middleware can compile. Reference: `docs/ref/mw-plugin.md`. |
/// | `PLUGINS_CGROUP_ROOT` | unset | A delegated cgroup v2 directory in which podgate creates one cgroup per managed plugin to write its `memory.max`, `pids.max` and `cpu.max` into. Unset: a plugin entry that declares `limits` stops startup. Needs `PLUGINS_FILE`. |
/// | `STATIC_MAX_CONCURRENT_READS` | available cores times 4, at most 256 | Blocking file-system operations static services run at once, 1..=256; an operation that finds no free slot within a second answers `503` with `retry-after`. |
/// | `CACHE_TENANT_MAX_PERCENT` | `50` | Most a tenant's response cache may hold, as a percent of its `max_buffer_bytes`, 1..=100; the upper limit for any `cache` middleware's `max_bytes`. |
/// | `UPSTREAM_POOL_SIZE` | `128` | Idle upstream connections kept for reuse, per worker thread (one thread per core): Pingora keeps one LRU for the whole process, so the pool holds this times the thread count and evicts the least recently used past it. 1..=65536. A transport's `max_idle_per_host` is refused for the same reason. |
/// | `DNS_SERVERS` | system configuration | Comma-separated name servers (`10.0.0.2`, `10.0.0.2:5353`, `[fd00::2]:53`) that resolve the host names of upstream servers, instead of `/etc/resolv.conf`. |
/// | `DNS_MIN_TTL_SECS` | `1` | Shortest time an answer is kept whatever its TTL says, 1..=86400, at most `DNS_MAX_TTL_SECS`. |
/// | `DNS_MAX_TTL_SECS` | `60` | Longest time an answer is kept before the name is resolved again, 1..=86400. |
/// | `DNS_TIMEOUT_MS` | `2000` | Longest one lookup takes, 1..=60000. |
/// | `DNS_MAX_STALE_SECS` | `300` | How long after its TTL ran out the last good answer is still used while resolution fails, 0..=86400. Then the name has no address and its requests get `503`. |
/// | `DNS_MAX_QUERIES_PER_SEC` | `200` | Lookups a second this node sends in all, 1..=100000. |
/// | `OCSP_ALLOWED_HOSTS` | unset | Comma-separated host suffixes (`ocsp.example.com`, `.example.com`) an OCSP responder URL must match. Unset: any host the upstream address policy allows. The URL itself is read from the certificate and is never part of a snapshot. |
/// | `H3_MAX_CONNECTIONS` | `10000` | QUIC connections the node serves at once, handshakes included, 1..=1000000. Past it new connections are turned away. |
/// | `H3_MAX_HANDSHAKES` | `256` | QUIC handshakes in flight at once, 1..=65536. Past it new connections are turned away. |
/// | `H3_RETRY` | `on_load` | When a client whose address is not proven must send a retry token: `always`, `on_load` (handshakes in flight past half of `H3_MAX_HANDSHAKES` or connections past 80% of `H3_MAX_CONNECTIONS`) or `never`. |
/// | `H3_UDP_RECV_BUFFER` | `2097152` | Kernel receive buffer asked for the HTTP/3 UDP sockets, in bytes, 65536..=268435456; the kernel caps it at `net.core.rmem_max`. |
/// | `H3_MAX_STREAMS` | `100` | Request streams one HTTP/3 connection may have open, 1..=1000. |
/// | `H3_CONNECTION_WINDOW` | `262144` | Bytes of QUIC flow control per connection, for receiving and for sending, 131072..=16777216. A connection reserves twice this plus 65535 bytes of its tenant's `max_buffer_bytes` (`docs/ref/http3.md`). |
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
    /// Unix socket of the SPIFFE Workload API agent (`unix://` prefix accepted). Absent: no
    /// SPIFFE. Needs [`Config::spiffe_policy_file`].
    pub spiffe_endpoint_socket: Option<PathBuf>,
    /// File with the SPIFFE policy: which identity each tenant uses and which it may talk to.
    /// Read once at startup by [`Config::spiffe`].
    pub spiffe_policy_file: Option<PathBuf>,
    /// File the access log is appended to. Absent: standard output.
    pub access_log_file: Option<PathBuf>,
    /// TCP address of the read-only metrics listener (`GET /metrics` and nothing else). Absent:
    /// no listener; the admin socket still serves `GET /metrics`.
    pub metrics_addr: Option<SocketAddr>,
    /// Series each tenant may own for its routers, services and servers before they collapse
    /// into `other` (see [`crate::observe::metrics`]).
    pub metrics_series_per_tenant: NonZeroU32,
    /// TCP address of the read-only dashboard. Absent: no dashboard.
    pub dashboard_addr: Option<SocketAddr>,
    /// htpasswd file the dashboard checks credentials against; required unless
    /// [`Self::dashboard_addr`] is loopback. Read once at startup by [`Config::dashboard_auth`].
    pub dashboard_auth_file: Option<PathBuf>,
    /// Host names besides the bound address the dashboard's `Host` header may carry
    /// (`DASHBOARD_HOSTS`).
    pub dashboard_hosts: Vec<Box<str>>,
    /// Lowest TLS version served (`TLS_MIN_VERSION`); the floor of every app's `tls.min_version`.
    pub tls_min_version: TlsVersion,
    /// Where traces go and how many a node allows; see [`ExportConfig`]. No endpoint: nothing is
    /// exported.
    pub otel: ExportConfig,
    /// File with the directories of static services, per tenant. Absent: none. Read once at
    /// startup by [`Config::static_roots`].
    pub static_roots_file: Option<PathBuf>,
    /// File with the FastCGI applications and code roots of `fastcgi` services, per tenant.
    /// Absent: none. Read once at startup by [`Config::fastcgi`].
    pub fastcgi_file: Option<PathBuf>,
    /// File with the operator's settings of the per-backend limiter. Absent: the built-in
    /// values. Read once at startup by [`Config::backend_limiter`].
    pub backend_limiter_file: Option<PathBuf>,
    /// File with the stores of cluster-scope `rate_limit` middlewares. Absent: none. Read once at
    /// startup by [`Config::rate_limit_stores`].
    pub rate_limit_stores_file: Option<PathBuf>,
    /// File with the plugins `plugin` middlewares may name. Absent: none. Read once at startup
    /// by [`Config::plugins`].
    pub plugins_file: Option<PathBuf>,
    /// The cgroup v2 directory managed plugins' cgroups are created in (`PLUGINS_CGROUP_ROOT`).
    /// Absent: no limits can be set and a plugin that declares any stops startup.
    pub plugins_cgroup_root: Option<PathBuf>,
    /// File-system operations static services run at once, across all tenants.
    pub static_max_concurrent_reads: NonZeroUsize,
    /// Percent of a tenant's `max_buffer_bytes` its response cache may hold at most
    /// (`CACHE_TENANT_MAX_PERCENT`), 1..=100.
    pub cache_tenant_max_percent: u8,
    /// Idle upstream connections the pool keeps per worker thread.
    pub upstream_pool_size: NonZeroUsize,
    /// How servers named by host name are resolved (`DNS_*`).
    pub dns: resolve::Settings,
    /// Host suffixes an OCSP responder must match (`OCSP_ALLOWED_HOSTS`). Empty: any host the
    /// upstream address policy allows.
    pub ocsp_allowed_hosts: Vec<Box<str>>,
    /// HTTP/3 limits (`H3_*`), used by the entry points with `;http3`.
    pub h3: h3::Settings,
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
            spiffe_endpoint_socket: None,
            spiffe_policy_file: None,
            access_log_file: None,
            metrics_addr: None,
            metrics_series_per_tenant: DEFAULT_SERIES_PER_TENANT,
            dashboard_addr: None,
            dashboard_auth_file: None,
            dashboard_hosts: Vec::new(),
            tls_min_version: TlsVersion::V1_2,
            otel: ExportConfig::default(),
            static_roots_file: None,
            fastcgi_file: None,
            backend_limiter_file: None,
            rate_limit_stores_file: None,
            plugins_file: None,
            plugins_cgroup_root: None,
            static_max_concurrent_reads: default_static_reads(),
            cache_tenant_max_percent: crate::cache::DEFAULT_TENANT_MAX_PERCENT,
            upstream_pool_size: DEFAULT_UPSTREAM_POOL,
            dns: resolve::Settings::default(),
            ocsp_allowed_hosts: Vec::new(),
            h3: h3::Settings::default(),
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

/// The dashboard has no write action but it shows the whole fleet, so a reachable one asks for a
/// password; and a password file or host list without a dashboard is a mistake worth stopping for.
fn check_dashboard(config: &Config) -> Result<(), ConfigError> {
    match (&config.dashboard_addr, &config.dashboard_auth_file) {
        (Some(addr), None) if !addr.ip().to_canonical().is_loopback() => Err(ConfigError {
            var: "DASHBOARD_ADDR",
            reason: format!(
                "{addr} is not a loopback address, so DASHBOARD_AUTH_FILE is required (htpasswd lines, bcrypt or argon2); set it, or bind a loopback address and expose the dashboard through podgate"
            )
            .into(),
        }),
        (None, Some(_)) => Err(ConfigError {
            var: "DASHBOARD_AUTH_FILE",
            reason: "is set but DASHBOARD_ADDR is not; the dashboard is off without an address"
                .into(),
        }),
        (None, None) if !config.dashboard_hosts.is_empty() => Err(ConfigError {
            var: "DASHBOARD_HOSTS",
            reason: "is set but DASHBOARD_ADDR is not; the dashboard is off without an address"
                .into(),
        }),
        _ => Ok(()),
    }
}

impl Config {
    /// Loads the dashboard's credentials: the htpasswd file named by `DASHBOARD_AUTH_FILE`, or
    /// `None` for a loopback dashboard without one.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming `DASHBOARD_ADDR` and `DASHBOARD_AUTH_FILE` when the address is not
    /// loopback and there is no file, and naming `DASHBOARD_AUTH_FILE` when the file cannot be
    /// read or holds a refused entry (never repeating a hash).
    pub fn dashboard_auth(&self) -> Result<Option<Htpasswd>, ConfigError> {
        check_dashboard(self)?;
        let Some(path) = &self.dashboard_auth_file else {
            return Ok(None);
        };
        crate::dashboard::load_auth(path, self.basic_auth_max_concurrent.get())
            .map(Some)
            .map_err(|reason| ConfigError {
                var: "DASHBOARD_AUTH_FILE",
                reason: format!("{}: {reason}", path.display()).into(),
            })
    }

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

    /// Loads the FastCGI upstreams: the applications and code roots named by `FASTCGI_FILE`, each
    /// root opened as a directory handle, or none when it is unset. No connection is made.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for `FASTCGI_FILE` when the file cannot be read or is malformed, or an
    /// entry has an address that is neither `unix:/path` nor `host:port`, a root that is not an
    /// absolute directory, or a limit out of range; the reason names the file, the tenant and the
    /// upstream.
    pub fn fastcgi(&self) -> Result<FastcgiRoots, ConfigError> {
        match &self.fastcgi_file {
            None => Ok(FastcgiRoots::default()),
            Some(path) => FastcgiRoots::load(path).map_err(|err| ConfigError {
                var: "FASTCGI_FILE",
                reason: err.to_string().into(),
            }),
        }
    }

    /// Loads the backend limiter settings: the file named by `BACKEND_LIMITER_FILE`, or the
    /// built-in values when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for `BACKEND_LIMITER_FILE` when the file cannot be read or is invalid;
    /// the reason names the file and the field that is wrong.
    pub fn backend_limiter(&self) -> Result<BackendLimiterSettings, ConfigError> {
        match &self.backend_limiter_file {
            None => Ok(BackendLimiterSettings::default()),
            Some(path) => BackendLimiterSettings::load(path).map_err(|err| ConfigError {
                var: "BACKEND_LIMITER_FILE",
                reason: format!("{}: {err}", path.display()).into(),
            }),
        }
    }

    /// Loads the cluster rate limit stores: the file named by `RATE_LIMIT_STORES_FILE`, or none
    /// when it is unset. No store is contacted.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for `RATE_LIMIT_STORES_FILE` when the file or a file it names (a password
    /// or CA file) cannot be read, or an entry is invalid; the reason never quotes a credential.
    pub fn rate_limit_stores(&self) -> Result<Stores, ConfigError> {
        match &self.rate_limit_stores_file {
            None => Ok(Stores::default()),
            Some(path) => Stores::load(path).map_err(|err| ConfigError {
                var: "RATE_LIMIT_STORES_FILE",
                reason: format!("{}: {err}", path.display()).into(),
            }),
        }
    }

    /// Loads the plugins: the file named by `PLUGINS_FILE`, or none when it is unset. Nothing
    /// is started or contacted; [`Plugins::start`] does that.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for `PLUGINS_FILE` when the file cannot be read or an entry is invalid
    /// (the reason names the plugin), or for `PLUGINS_CGROUP_ROOT` when it is set without
    /// `PLUGINS_FILE`.
    pub fn plugins(&self) -> Result<Plugins, ConfigError> {
        match (&self.plugins_file, &self.plugins_cgroup_root) {
            (None, None) => Ok(Plugins::default()),
            (None, Some(_)) => Err(ConfigError {
                var: "PLUGINS_CGROUP_ROOT",
                reason: "is set and PLUGINS_FILE is not".into(),
            }),
            (Some(path), root) => Plugins::load(path, root.as_deref(), self.request_timeout())
                .map_err(|err| ConfigError {
                    var: "PLUGINS_FILE",
                    reason: format!("{}: {err}", path.display()).into(),
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

    /// The process's SPIFFE configuration: the Workload API socket and the policy file. Off
    /// when neither is set.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when only one of `SPIFFE_ENDPOINT_SOCKET` and `SPIFFE_POLICY_FILE` is
    /// set (a socket with no policy lets no tenant use an identity, a policy with no socket has
    /// none to hand out), or the policy file cannot be read or is invalid.
    pub fn spiffe(&self) -> Result<Spiffe, ConfigError> {
        match (&self.spiffe_endpoint_socket, &self.spiffe_policy_file) {
            (None, None) => Ok(Spiffe::default()),
            (Some(socket), Some(file)) => {
                let policy = SpiffePolicy::load(file).map_err(|err| ConfigError {
                    var: "SPIFFE_POLICY_FILE",
                    reason: format!("{}: {err}", file.display()).into(),
                })?;
                Ok(Spiffe::new(socket.clone(), policy))
            }
            (Some(_), None) => Err(ConfigError {
                var: "SPIFFE_POLICY_FILE",
                reason: "is required with SPIFFE_ENDPOINT_SOCKET".into(),
            }),
            (None, Some(_)) => Err(ConfigError {
                var: "SPIFFE_ENDPOINT_SOCKET",
                reason: "is required with SPIFFE_POLICY_FILE".into(),
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
        config.spiffe_endpoint_socket = non_empty("SPIFFE_ENDPOINT_SOCKET")?
            .map(|raw| PathBuf::from(raw.strip_prefix("unix://").unwrap_or(&raw)));
        config.spiffe_policy_file = non_empty("SPIFFE_POLICY_FILE")?.map(PathBuf::from);
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
        if let Some(raw) = non_empty("DASHBOARD_ADDR")? {
            config.dashboard_addr = Some(parse_addr("DASHBOARD_ADDR", &raw)?);
        }
        config.dashboard_auth_file = non_empty("DASHBOARD_AUTH_FILE")?.map(PathBuf::from);
        if let Some(raw) = non_empty("DASHBOARD_HOSTS")? {
            config.dashboard_hosts =
                crate::dashboard::parse_hosts(&raw).map_err(|reason| ConfigError {
                    var: "DASHBOARD_HOSTS",
                    reason: reason.into(),
                })?;
        }
        check_dashboard(&config)?;
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
        config.fastcgi_file = non_empty("FASTCGI_FILE")?.map(PathBuf::from);
        config.backend_limiter_file = non_empty("BACKEND_LIMITER_FILE")?.map(PathBuf::from);
        config.rate_limit_stores_file = non_empty("RATE_LIMIT_STORES_FILE")?.map(PathBuf::from);
        config.plugins_file = non_empty("PLUGINS_FILE")?.map(PathBuf::from);
        config.plugins_cgroup_root = non_empty("PLUGINS_CGROUP_ROOT")?.map(PathBuf::from);
        config.dns = resolve::Settings::from_lookup(&lookup)?;
        if let Some(list) = lookup("CATCH_ALL_TENANTS") {
            config.catch_all_tenants = list
                .split(',')
                .map(str::trim)
                .filter(|tenant| !tenant.is_empty())
                .map(Box::from)
                .collect();
        }
        if let Some(list) = lookup("OCSP_ALLOWED_HOSTS") {
            config.ocsp_allowed_hosts = list
                .split(',')
                .map(|host| host.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|host| !host.is_empty())
                .map(Box::from)
                .collect();
        }
        config.h3 = h3::Settings::from_lookup(&lookup)?;
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
            ("DNS_SERVERS", "10.0.0.2, [fd00::2]:5353"),
            ("DNS_MIN_TTL_SECS", "2"),
            ("DNS_MAX_TTL_SECS", "30"),
            ("DNS_TIMEOUT_MS", "500"),
            ("DNS_MAX_STALE_SECS", "0"),
            ("DNS_MAX_QUERIES_PER_SEC", "7"),
            ("STATIC_ROOTS_FILE", "/etc/podgate/static-roots.json"),
            ("FASTCGI_FILE", "/etc/podgate/fastcgi.json"),
            ("BACKEND_LIMITER_FILE", "/etc/podgate/backend-limiter.json"),
            ("RATE_LIMIT_STORES_FILE", "/etc/podgate/limit-stores.json"),
            ("PLUGINS_FILE", "/etc/podgate/plugins.json"),
            ("PLUGINS_CGROUP_ROOT", "/sys/fs/cgroup/podgate"),
            ("NODE_NAME", "n1"),
            ("ACME_CA_FILE", "/etc/acme-root.pem"),
            ("ACME_DNS_ZONES", "Example.com, sub.example.org."),
            ("UPSTREAM_POLICY_FILE", "/etc/podgate/upstream-policy.json"),
            (
                "SPIFFE_ENDPOINT_SOCKET",
                "unix:///run/spire/sockets/agent.sock",
            ),
            ("SPIFFE_POLICY_FILE", "/etc/podgate/spiffe-policy.json"),
            ("ACCESS_LOG_FILE", "/var/log/podgate/access.log"),
            ("METRICS_ADDR", "127.0.0.1:9100"),
            ("METRICS_SERIES_PER_TENANT", "50"),
            ("DASHBOARD_ADDR", "127.0.0.1:9200"),
            ("DASHBOARD_AUTH_FILE", "/etc/podgate/dashboard.htpasswd"),
            ("DASHBOARD_HOSTS", "dash.example, Ops.Example"),
            ("TLS_MIN_VERSION", "1.3"),
            ("CATCH_ALL_TENANTS", "t1, t2,,"),
            ("CACHE_TENANT_MAX_PERCENT", "40"),
            ("OCSP_ALLOWED_HOSTS", "OCSP.Example.com, .Digicert.com,,"),
            ("H3_MAX_CONNECTIONS", "50"),
            ("H3_MAX_HANDSHAKES", "8"),
            ("H3_RETRY", "always"),
            ("H3_UDP_RECV_BUFFER", "1048576"),
            ("H3_MAX_STREAMS", "10"),
            ("H3_CONNECTION_WINDOW", "524288"),
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
                dns: resolve::Settings {
                    servers: vec![
                        SocketAddr::from(([10, 0, 0, 2], 53)),
                        "[fd00::2]:5353".parse().expect("socket address"),
                    ],
                    min_ttl: Duration::from_secs(2),
                    max_ttl: Duration::from_secs(30),
                    timeout: Duration::from_millis(500),
                    max_stale: Duration::ZERO,
                    max_queries_per_sec: NonZeroU32::new(7).expect("7 is not zero"),
                },
                static_roots_file: Some(PathBuf::from("/etc/podgate/static-roots.json")),
                fastcgi_file: Some(PathBuf::from("/etc/podgate/fastcgi.json")),
                backend_limiter_file: Some(PathBuf::from("/etc/podgate/backend-limiter.json")),
                rate_limit_stores_file: Some(PathBuf::from("/etc/podgate/limit-stores.json")),
                plugins_file: Some(PathBuf::from("/etc/podgate/plugins.json")),
                plugins_cgroup_root: Some(PathBuf::from("/sys/fs/cgroup/podgate")),
                node_name: Some("n1".into()),
                acme_ca_file: Some(PathBuf::from("/etc/acme-root.pem")),
                acme_dns_zones: vec!["example.com".into(), "sub.example.org".into()],
                upstream_policy_file: Some(PathBuf::from("/etc/podgate/upstream-policy.json")),
                spiffe_endpoint_socket: Some(PathBuf::from("/run/spire/sockets/agent.sock")),
                spiffe_policy_file: Some(PathBuf::from("/etc/podgate/spiffe-policy.json")),
                access_log_file: Some(PathBuf::from("/var/log/podgate/access.log")),
                tls_min_version: TlsVersion::V1_3,
                otel: ExportConfig::default(),
                catch_all_tenants: vec!["t1".into(), "t2".into()],
                metrics_addr: Some(SocketAddr::from(([127, 0, 0, 1], 9100))),
                metrics_series_per_tenant: NonZeroU32::new(50).expect("50 is not zero"),
                dashboard_addr: Some(SocketAddr::from(([127, 0, 0, 1], 9200))),
                dashboard_auth_file: Some(PathBuf::from("/etc/podgate/dashboard.htpasswd")),
                dashboard_hosts: vec!["dash.example".into(), "ops.example".into()],
                cache_tenant_max_percent: 40,
                ocsp_allowed_hosts: vec!["ocsp.example.com".into(), "digicert.com".into()],
                h3: h3::Settings {
                    max_connections: 50,
                    max_handshakes: 8,
                    retry: h3::Retry::Always,
                    udp_recv_buffer: 1_048_576,
                    max_streams: 10,
                    connection_window: 524_288,
                },
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
            ("DNS_SERVERS", " "),
            ("DNS_SERVERS", "ns.example.com"),
            ("DNS_MIN_TTL_SECS", "0"),
            ("DNS_MIN_TTL_SECS", "86401"),
            ("DNS_MAX_TTL_SECS", "0"),
            ("DNS_TIMEOUT_MS", "0"),
            ("DNS_TIMEOUT_MS", "60001"),
            ("DNS_MAX_STALE_SECS", "-1"),
            ("DNS_MAX_QUERIES_PER_SEC", "0"),
            ("STATIC_MAX_CONCURRENT_READS", "257"),
            ("UPSTREAM_POOL_SIZE", "0"),
            ("UPSTREAM_POOL_SIZE", "65537"),
            ("UPSTREAM_POOL_SIZE", "many"),
            ("STATIC_ROOTS_FILE", " "),
            ("FASTCGI_FILE", " "),
            ("BACKEND_LIMITER_FILE", " "),
            ("RATE_LIMIT_STORES_FILE", " "),
            ("PLUGINS_FILE", " "),
            ("PLUGINS_CGROUP_ROOT", " "),
            ("CACHE_TENANT_MAX_PERCENT", "0"),
            ("CACHE_TENANT_MAX_PERCENT", "101"),
            ("CACHE_TENANT_MAX_PERCENT", "half"),
            ("NODE_NAME", " "),
            ("ACME_CA_FILE", ""),
            ("ACME_DNS_ZONES", " "),
            ("ACME_DNS_ZONES", "*.example.com"),
            ("ACME_DNS_ZONES", "a b"),
            ("UPSTREAM_POLICY_FILE", " "),
            ("SPIFFE_ENDPOINT_SOCKET", " "),
            ("SPIFFE_POLICY_FILE", " "),
            ("ACCESS_LOG_FILE", " "),
            ("METRICS_ADDR", "nope"),
            ("METRICS_ADDR", " "),
            ("METRICS_SERIES_PER_TENANT", "0"),
            ("METRICS_SERIES_PER_TENANT", "many"),
            ("DASHBOARD_ADDR", "nope"),
            ("DASHBOARD_ADDR", " "),
            ("DASHBOARD_ADDR", "0.0.0.0:9200"),
            ("DASHBOARD_AUTH_FILE", " "),
            ("DASHBOARD_AUTH_FILE", "/etc/podgate/dashboard.htpasswd"),
            ("DASHBOARD_HOSTS", "a:80"),
            ("DASHBOARD_HOSTS", "dash.example"),
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
        assert_eq!(parsed.otel.collector.headers.len(), 2);
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

    #[test]
    fn backend_limiter_file_names_the_variable_the_file_and_the_field() {
        assert!(
            Config::default().backend_limiter().is_ok(),
            "no file: the built-in settings"
        );
        let dir = std::env::temp_dir().join(format!("podgate-limiter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("backend-limiter.json");
        let mut config = Config {
            backend_limiter_file: Some(file.clone()),
            ..Config::default()
        };
        std::fs::write(&file, r#"{"default": {"max_limit": 99}}"#).expect("write");
        assert!(config.backend_limiter().is_ok());
        std::fs::write(&file, r#"{"default": {"max_limit": -1}}"#).expect("write");
        let err = config.backend_limiter().expect_err("a negative limit");
        assert_eq!(err.var, "BACKEND_LIMITER_FILE");
        let text = err.to_string();
        assert!(
            text.contains(&file.display().to_string()) && text.contains("default.max_limit"),
            "{text}"
        );
        config.backend_limiter_file = Some(dir.join("missing.json"));
        let err = config.backend_limiter().expect_err("no such file");
        assert!(err.to_string().contains("missing.json"), "{err}");
        drop(std::fs::remove_dir_all(&dir));
    }
}
