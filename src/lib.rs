//! `podgate`: memory-safe reverse proxy for our PaaS, built on Pingora.
//!
//! The PaaS control plane pushes routing snapshots over a unix-socket admin API; the proxy
//! routes requests by `Host` with the latest snapshot. The target design is in
//! `docs/architecture.md`. `main.rs` stays thin; everything testable lives here:
//!
//! - [`Config`]: settings read from environment variables.
//! - [`Snapshot`]: the JSON model of a pushed snapshot.
//! - [`RoutingTable`] and [`TableHandle`]: the compiled snapshot and its atomic swap.
//! - [`sni`]: the TLS check that the request host matches the negotiated SNI.
//! - [`Gateway`]: the Pingora `ProxyHttp` implementation.
//! - [`EventFeed`] and [`Inflight`]: the event feed and the per-revision in-flight counters that
//!   report drained revisions into it.
//! - [`admin`]: the admin API router and its background service.
//! - [`AppError`]: the one error type clients see; renders as `{"error": "..."}`.
//! - [`run`]: builds the Pingora server and runs it until shutdown.

pub mod admin;
pub mod config;
pub mod conflict;
pub mod error;
pub mod events;
pub mod host;
pub mod inflight;
pub mod proxy;
pub mod respond;
pub mod route;
pub mod snapshot;
pub mod sni;
pub mod table;
pub mod tls;

use anyhow::Context;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::{RunArgs, Server};
use pingora::services::background::background_service;
use tracing_subscriber::EnvFilter;

pub use admin::{AdminService, AppState};
pub use config::{Config, ConfigError, LogFormat};
pub use conflict::Conflict;
pub use error::AppError;
pub use events::{Event, EventFeed, EventKind};
pub use inflight::{Inflight, InflightGuard};
pub use proxy::{Ctx, Gateway};
pub use snapshot::Snapshot;
pub use table::{ApplyError, CompileError, RoutingTable, TableHandle};

/// Builds the Pingora server from `config` and runs it until SIGTERM, SIGINT or SIGQUIT.
///
/// Services: the HTTP proxy listener, the HTTPS listener when `PROXY_TLS_ADDR` is set, and the
/// admin API on the unix socket. `/readyz` reports the admin API, not the proxy listeners: Pingora
/// binds them on its own schedule and retries while a port is busy. On SIGTERM
/// `/readyz` turns `503`, the proxy stops accepting, and the process exits after
/// `REQUEST_TIMEOUT_SECS` so in-flight requests finish.
///
/// # Errors
///
/// Fails when the admin socket cannot be bound or the TLS listener cannot be configured.
pub fn run(config: &Config) -> anyhow::Result<()> {
    let table = TableHandle::new();
    let events = EventFeed::new();
    let inflight = Inflight::new(events.clone());
    let timeout = config.request_timeout();
    let admin_listener = admin::bind(&config.admin_socket)
        .with_context(|| format!("cannot bind admin socket {}", config.admin_socket.display()))?;

    let server_conf = ServerConf {
        threads: std::thread::available_parallelism().map_or(1, usize::from),
        grace_period_seconds: Some(timeout.as_secs()),
        ..ServerConf::default()
    };
    let mut server = Server::new_with_opt_and_conf(None::<Opt>, server_conf);
    server.bootstrap();

    let mut proxy = http_proxy_service(
        &server.configuration,
        Gateway::new(table.clone(), inflight.clone(), timeout),
    );
    proxy.add_tcp(&config.proxy_addr.to_string());
    if let Some(tls_addr) = config.proxy_tls_addr {
        let settings = tls::listener_settings(table.clone())
            .map_err(|err| anyhow::anyhow!("cannot configure the TLS listener: {err}"))?;
        proxy.add_tls_with_settings(&tls_addr.to_string(), None, settings);
    }
    server.add_service(proxy);
    server.add_service(background_service(
        "admin API",
        AdminService::new(
            admin_listener,
            AppState::new(table, events, inflight),
            timeout,
        ),
    ));

    tracing::info!(
        proxy = %config.proxy_addr,
        tls = ?config.proxy_tls_addr,
        admin = %config.admin_socket.display(),
        "starting"
    );
    server.run(RunArgs::default());
    tracing::info!("stopped");
    Ok(())
}

/// Installs the global `tracing` subscriber. Filter comes from `RUST_LOG`, default `info`.
///
/// Call once, early in `main`. A second call is ignored. Pingora's `log` records are bridged
/// into `tracing` too.
pub fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    // `try_init` fails only when a subscriber is already set; keep the first one.
    let _ = match format {
        LogFormat::Pretty => builder.pretty().try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
}
