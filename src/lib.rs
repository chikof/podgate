//! `podgate`: memory-safe reverse proxy for our PaaS, built on Pingora.
//!
//! The PaaS control plane pushes routing snapshots over a unix-socket admin API; the proxy
//! routes requests with the latest snapshot: a router (a matcher tree over host, path and
//! method) picks the app, its middleware chain runs, and a service picks the server. The design
//! is in `docs/architecture.md`. `main.rs` stays thin; everything testable lives here:
//!
//! - [`Config`]: settings read from environment variables.
//! - [`podgate_model::Snapshot`]: the JSON model of a pushed snapshot.
//! - [`wasm`]: WASM request filters (proxy-wasm subset) with fuel and memory limits.
//! - [`acme`]: HA ACME issuance with ARI renewal, HTTP-01 answers and on-demand TLS.
//! - [`RoutingTable`] and [`TableHandle`]: the compiled snapshot and its atomic swap.
//! - [`sni`]: the TLS check that the request host matches the negotiated SNI.
//! - [`clientauth`]: client certificates per app (`tls.client_ca_pem`), asked for by SNI and checked per request.
//! - [`pool`]: upstream connection pool isolation per tenant, app and revision, and NTLM pinning.
//! - [`skew`]: the signed cookie that keeps a browser session on the revision that first served it.
//! - [`Gateway`]: the Pingora `ProxyHttp` implementation.
//! - [`EventFeed`] and [`Inflight`]: the event feed and the per-revision in-flight counters that
//!   report drained revisions into it.
//! - [`explain`]: why a request goes where it goes, behind `GET /v1/explain`.
//! - [`wake`]: scale to zero: holds requests for a sleeping app, reports idle apps.
//! - [`canary`]: ramps one revision up while its 5xx rate stays under the limit, pulls it back when not.
//! - [`admin`]: the admin API router and its background service.
//! - [`Failures`]: the per-app rings of failed requests, listed and replayed over the admin API.
//! - [`Outcomes`]: per-revision response outcomes over a sliding window; [`plan`] diffs snapshots
//!   and [`revert`] undoes a snapshot that makes the apps it changed fail.
//! - [`Backends`]: the adaptive concurrency limit per upstream and the weighted fair queues of the
//!   tenants waiting for it.
//! - [`service::upstream_policy`]: the operator's rule for which addresses a tenant's servers may
//!   have, checked by the compiler and before every connection.
//! - [`AppError`]: the one error type clients see; renders as `{"error": "..."}`.
//! - [`run`]: builds the Pingora server and runs it until shutdown.

pub mod acme;
pub mod admin;
pub mod budget;
pub mod canary;
pub mod clientauth;
pub mod compile;
pub mod compress;
pub mod config;
pub mod conflict;
pub mod entry;
pub mod error;
pub mod events;
pub mod explain;
pub mod failures;
pub mod fairq;
pub mod host;
pub mod inflight;
pub mod l4;
pub mod middleware;
pub mod observe;
pub mod outcomes;
pub mod pipeline;
pub mod plan;
pub mod pool;
pub mod proxy;
pub mod respond;
pub mod revert;
pub mod route;
pub mod router;
pub mod service;
pub mod skew;
pub mod sni;
pub mod table;
pub mod tls;
pub mod wake;
pub mod wasm;

use std::sync::Arc;

use anyhow::Context;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::{RunArgs, Server};
use pingora::services::background::background_service;
use tracing_subscriber::EnvFilter;

pub use acme::Acme;
pub use admin::{AdminService, AppState};
pub use budget::Budgets;
pub use canary::CanaryService;
pub use config::{Config, ConfigError, LogFormat};
pub use conflict::Conflict;
pub use error::AppError;
pub use events::{Event, EventFeed, EventKind};
pub use failures::Failures;
pub use fairq::Backends;
pub use inflight::{Inflight, InflightGuard};
pub use outcomes::Outcomes;
pub use proxy::{Ctx, Gateway};
pub use table::{ApplyError, CompileError, RoutingTable, TableHandle};
pub use wake::{Wake, WakeService};

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
/// Fails when `UPSTREAM_POLICY_FILE` is invalid, the admin socket cannot be bound or the TLS
/// listener cannot be configured.
pub fn run(config: &Config) -> anyhow::Result<()> {
    let upstream_policy = config.upstream_policy()?;
    let table = TableHandle::with_context(
        entry::CompileContext::default()
            .with_catch_all_tenants(config.catch_all_tenants.iter().map(AsRef::as_ref))
            .with_upstream_policy(upstream_policy.clone()),
    );
    let events = EventFeed::new();
    let inflight = Inflight::new(events.clone());
    let budgets = Budgets::new();
    let wake = Wake::new(events.clone());
    let outcomes = Outcomes::new();
    let acme = Acme::new(
        table.clone(),
        events.clone(),
        config.node_name.clone(),
        config.acme_ca_file.clone(),
    );
    let backends = Backends::new();
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

    let failures = Failures::new();
    let mut proxy = http_proxy_service(
        &server.configuration,
        Gateway::new(table.clone(), inflight.clone(), timeout)
            .with_budgets(budgets.clone())
            .with_backends(backends.clone())
            .with_failures(failures.clone())
            .with_wake(wake.clone())
            .with_outcomes(outcomes.clone())
            .with_upstream_policy(upstream_policy.clone())
            .with_wasm(wasm::Executor::new(
                config.wasm_max_concurrent.get(),
                config.wasm_queue_timeout(),
            )),
    );
    proxy.add_tcp(&config.proxy_addr.to_string());
    if let Some(tls_addr) = config.proxy_tls_addr {
        let settings = tls::listener_settings(table.clone())
            .map_err(|err| anyhow::anyhow!("cannot configure the TLS listener: {err}"))?;
        proxy.add_tls_with_settings(&tls_addr.to_string(), None, settings);
        proxy
            .endpoints()
            .set_pre_tls_callback(Arc::new(clientauth::ClearDecision(acme.clone())));
    }
    server.add_service(proxy);
    server.add_service(background_service("acme issuer", acme));
    server.add_service(background_service(
        "scale to zero",
        WakeService::new(wake, table.clone()),
    ));
    server.add_service(background_service(
        "canary",
        CanaryService::new(table.clone(), outcomes.clone(), events.clone()),
    ));
    server.add_service(background_service(
        "admin API",
        AdminService::new(
            admin_listener,
            AppState::new(table, events, inflight)
                .with_budgets(budgets)
                .with_backends(backends)
                .with_failures(failures)
                .with_upstream_policy(upstream_policy)
                .with_outcomes(outcomes),
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
