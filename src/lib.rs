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
//! - [`client_ip`]: who the client is behind trusted proxies, the forged forwarding headers dropped, and the `client_ip` matcher's address.
//! - [`clientauth`]: client certificates per app (`tls.client_ca_pem`), asked for by SNI and checked per request.
//! - [`pool`]: upstream connection pool isolation per tenant, app and revision, and NTLM pinning.
//! - [`skew`]: the signed cookie that keeps a browser session on the revision that first served it.
//! - [`Gateway`]: the Pingora `ProxyHttp` implementation.
//! - [`EventFeed`] and [`Inflight`]: the event feed and the per-revision in-flight counters that
//!   report drained revisions into it.
//! - [`explain`]: why a request goes where it goes, behind `GET /v1/explain`.
//! - [`overview`]: what is configured and how it is doing, behind `GET /v1/overview`.
//! - [`wake`]: scale to zero: holds requests for a sleeping app, reports idle apps.
//! - [`canary`]: ramps one revision up while its 5xx rate stays under the limit, pulls it back when not.
//! - [`admin`]: the admin API router and its background service.
//! - [`observe::metrics`]: Prometheus series per entry point, router and service, with a series cap per tenant, rendered by `GET /metrics` on the admin socket and on `METRICS_ADDR`.
//! - [`Failures`]: the per-app rings of failed requests, listed and replayed over the admin API.
//! - [`Outcomes`]: per-revision response outcomes over a sliding window; [`plan`] diffs snapshots
//!   and [`revert`] undoes a snapshot that makes the apps it changed fail.
//! - [`Backends`]: the adaptive concurrency limit per upstream and the weighted fair queues of the
//!   tenants waiting for it.
//! - [`service::upstream_policy`]: the operator's rule for which addresses a tenant's servers may
//!   have, checked by the compiler and before every connection.
//! - [`observe::access_log`]: the structured access log: fields, filters, sampling, a bounded
//!   queue and a stdout or file sink that never delays a request.
//! - [`service::health`]: active health checks: probes each declared server of a service with a
//!   `health_check` and writes the flag the balancers read.
//! - [`observe::tracing`]: OpenTelemetry tracing: W3C trace context to the upstream, spans exported over OTLP/HTTP
//!   to the operator's collector from a bounded queue, a node-wide rate cap on what gets traced.
//! - [`AppError`]: the one error type clients see; renders as `{"error": "..."}`.
//! - [`run`]: builds the Pingora server and runs it until shutdown.

pub mod acme;
pub mod admin;
pub mod budget;
pub mod canary;
pub mod client_ip;
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
pub mod forwarded;
pub mod host;
pub mod inflight;
pub mod l4;
pub mod middleware;
pub mod observe;
pub mod outcomes;
pub mod overview;
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
use pingora::proxy::http_proxy_service_with_name;
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
pub use observe::access_log::AccessLog;
pub use observe::tracing::Tracer;
pub use outcomes::Outcomes;
pub use proxy::{Ctx, Gateway};
pub use table::{ApplyError, CompileError, RoutingTable, TableHandle};
pub use wake::{Wake, WakeService};

/// Builds the Pingora server from `config` and runs it until SIGTERM, SIGINT or SIGQUIT.
///
/// Services: one HTTP or HTTPS proxy listener per entry point (`ENTRY_POINTS`, or `PROXY_ADDR` and
/// `PROXY_TLS_ADDR`), and the admin API on the unix socket. `/readyz` reports the admin API, not
/// the proxy listeners: Pingora binds them on its own schedule and retries while a port is busy.
/// On SIGTERM `/readyz` turns `503`, the proxy stops accepting, and the process exits after
/// `REQUEST_TIMEOUT_SECS` so in-flight requests finish.
///
/// # Errors
///
/// Fails when `UPSTREAM_POLICY_FILE` or `STATIC_ROOTS_FILE` is invalid, an entry point is `tcp`
/// or `udp` or sets `proxy_protocol` (not built yet), a TLS listener cannot be configured, the
/// admin socket cannot be bound, or an `OTEL_EXPORTER_OTLP_CERTIFICATE` file cannot be read.
pub fn run(config: &Config) -> anyhow::Result<()> {
    let upstream_policy = config.upstream_policy()?;
    let static_roots = config.static_roots()?;
    let table = TableHandle::with_context(
        entry::CompileContext::of_entry_points(&config.entry_points)
            .with_catch_all_tenants(config.catch_all_tenants.iter().map(AsRef::as_ref))
            .with_acme_dns_zones(config.acme_dns_zones.iter().map(AsRef::as_ref))
            .with_upstream_policy(upstream_policy.clone())
            .with_tls_floor(config.tls_min_version)
            .with_static_roots(static_roots),
    )
    .with_metrics(observe::metrics::Registry::new(
        config.metrics_series_per_tenant,
    ));
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
    let access_log = AccessLog::new();
    let access_sink: Box<dyn observe::access_log::LineSink> = match &config.access_log_file {
        Some(path) => Box::new(observe::access_log::FileSink::new(path.clone())),
        None => Box::new(observe::access_log::StdoutSink),
    };
    let tracer = config.otel.tracer();
    let timeout = config.request_timeout();

    let server_conf = ServerConf {
        threads: std::thread::available_parallelism().map_or(1, usize::from),
        grace_period_seconds: Some(timeout.as_secs()),
        ..ServerConf::default()
    };
    let mut server = Server::new_with_opt_and_conf(None::<Opt>, server_conf);
    server.bootstrap();

    let failures = Failures::new();
    let gateway = Gateway::new(table.clone(), inflight.clone(), timeout)
        .with_budgets(budgets.clone())
        .with_backends(backends.clone())
        .with_failures(failures.clone())
        .with_wake(wake.clone())
        .with_outcomes(outcomes.clone())
        .with_upstream_policy(upstream_policy.clone())
        .with_static_reads(service::StaticReads::bounded(
            config.static_max_concurrent_reads.get(),
        ))
        .with_access_log(access_log.clone())
        .with_tracer(tracer.clone())
        .with_events(events.clone())
        .with_node_name(config.node_name.as_deref())
        .with_wasm(wasm::Executor::new(
            config.wasm_max_concurrent.get(),
            config.wasm_queue_timeout(),
        ))
        .with_basic_auth(middleware::basic_auth::Pool::new(
            config.basic_auth_max_concurrent.get(),
            std::time::Duration::from_secs(1),
        ));
    for point in &config.entry_points {
        let mut proxy = http_proxy_service_with_name(
            &server.configuration,
            gateway.clone().with_entry_point(&point.name),
            &format!("entry point {}", point.name),
        );
        let addr = point.addr.to_string();
        match point.protocol {
            entry::Protocol::Http => proxy.add_tcp(&addr),
            entry::Protocol::Https => {
                let settings = tls::listener_settings(table.clone()).map_err(|err| {
                    anyhow::anyhow!("cannot configure the TLS entry point {}: {err}", point.name)
                })?;
                proxy.add_tls_with_settings(&addr, None, settings);
                proxy
                    .endpoints()
                    .set_pre_tls_callback(Arc::new(clientauth::ClearDecision(
                        tls::PreHandshake::new(acme.clone(), table.clone()),
                    )));
            }
            entry::Protocol::Tcp | entry::Protocol::Udp => anyhow::bail!(
                "entry point {} is {}: TCP and UDP entry points are not built yet",
                point.name,
                point.protocol.as_str()
            ),
        }
        if point.proxy_protocol {
            anyhow::bail!(
                "entry point {}: proxy_protocol is not built yet",
                point.name
            );
        }
        server.add_service(proxy);
    }
    let admin_listener = admin::bind(&config.admin_socket)
        .with_context(|| format!("cannot bind admin socket {}", config.admin_socket.display()))?;
    if let Some(addr) = config.metrics_addr {
        let listener = observe::metrics::bind(addr)
            .with_context(|| format!("cannot bind METRICS_ADDR {addr}"))?;
        server.add_service(background_service(
            "metrics",
            observe::metrics::MetricsService::new(
                listener,
                observe::metrics::Sources {
                    table: table.clone(),
                    budgets: budgets.clone(),
                    backends: backends.clone(),
                    upstream_policy: upstream_policy.clone(),
                    access_log: access_log.clone(),
                    tracer: tracer.clone(),
                },
                timeout,
            ),
        ));
    }
    server.add_service(background_service("acme issuer", acme));
    server.add_service(background_service(
        "access log",
        access_log.service(access_sink),
    ));
    if let Some(exporter) = observe::tracing::TraceService::new(&tracer, &config.otel)? {
        server.add_service(background_service("trace exporter", exporter));
    }
    server.add_service(background_service(
        "scale to zero",
        WakeService::new(wake, table.clone()),
    ));
    server.add_service(background_service(
        "canary",
        CanaryService::new(table.clone(), outcomes.clone(), events.clone()),
    ));
    server.add_service(background_service(
        "health checks",
        service::health::HealthService::new(
            table.clone(),
            upstream_policy.clone(),
            config.health_max_concurrent,
        ),
    ));
    server.add_service(background_service(
        "admin API",
        AdminService::new(
            admin_listener,
            AppState::new(table, events, inflight)
                .with_budgets(budgets)
                .with_backends(backends)
                .with_failures(failures)
                .with_access_log(access_log)
                .with_tracer(tracer)
                .with_upstream_policy(upstream_policy)
                .with_outcomes(outcomes)
                .with_entry_points(config.entry_points.clone())
                .with_metrics_addr(config.metrics_addr),
            timeout,
        ),
    ));

    tracing::info!(
        entry_points = %config
            .entry_points
            .iter()
            .map(|point| format!("{}={}/{}", point.name, point.addr, point.protocol.as_str()))
            .collect::<Vec<_>>()
            .join(","),
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
