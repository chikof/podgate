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
//! - [`spiffe`]: SPIFFE workload identity: SVIDs from a Workload API agent, one per tenant, for upstream mutual TLS and client identity.
//! - [`skew`]: the signed cookie that keeps a browser session on the revision that first served it.
//! - [`Gateway`]: the Pingora `ProxyHttp` implementation.
//! - [`EventFeed`] and [`Inflight`]: the event feed and the per-revision in-flight counters that
//!   report drained revisions into it.
//! - [`explain`]: why a request goes where it goes, behind `GET /v1/explain`.
//! - [`overview`]: what is configured and how it is doing, behind `GET /v1/overview`.
//! - [`wake`]: scale to zero: holds requests for a sleeping app, reports idle apps.
//! - [`canary`]: ramps one revision up while its 5xx rate stays under the limit, pulls it back when not.
//! - [`admin`]: the admin API router and its background service.
//! - [`dashboard`]: the read-only web UI on `DASHBOARD_ADDR`, over the overview and explain APIs, with the assets compiled in.
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
//! - [`h3`]: HTTP/3 over QUIC for HTTPS entry points with `;http3`: a quinn endpoint that bridges each request into the entry point's pipeline over an internal HTTP/2 connection, with per-connection and per-tenant memory budgets and the QUIC denial-of-service defences.
//! - [`tls::ocsp`]: OCSP stapling: verified responses fetched through the upstream address policy and stapled to the certificates the listener serves.
//! - [`run`]: builds the Pingora server and runs it until shutdown.

pub mod acme;
pub mod admin;
pub mod budget;
pub mod cache;
pub mod canary;
pub mod client_ip;
pub mod clientauth;
pub mod compile;
pub mod compress;
pub mod config;
pub mod conflict;
pub mod dashboard;
pub mod entry;
pub mod error;
pub mod events;
pub mod explain;
pub mod failures;
pub mod fairq;
pub mod forwarded;
pub mod h3;
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
pub mod ratelimit_store;
pub mod respond;
pub mod revert;
pub mod route;
pub mod router;
pub mod service;
pub mod skew;
pub mod sni;
pub mod spiffe;
pub mod table;
pub mod tls;
pub mod wake;
pub mod wasm;

use std::sync::Arc;

use anyhow::Context;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::{RunArgs, Server};
use pingora::services::background::background_service;
use tracing_subscriber::EnvFilter;

pub use acme::Acme;
pub use admin::{AdminService, AppState};
pub use budget::Budgets;
pub use cache::Cache;
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
/// Fails when `UPSTREAM_POLICY_FILE`, `STATIC_ROOTS_FILE`, `FASTCGI_FILE`, `RATE_LIMIT_STORES_FILE` or
/// `DASHBOARD_AUTH_FILE` is invalid, a non-loopback `DASHBOARD_ADDR` has no
/// `DASHBOARD_AUTH_FILE`, a `udp` entry point sets `proxy_protocol`, a UDP socket cannot be
/// bound, a TLS listener
/// cannot be configured, the admin socket or the dashboard address cannot be bound, an
/// `OTEL_EXPORTER_OTLP_CERTIFICATE` file cannot be read, `PLUGINS_FILE` is invalid, or a plugin
/// cannot be started or does not answer `Describe` within five seconds.
pub fn run(config: &Config) -> anyhow::Result<()> {
    let upstream_policy = config.upstream_policy()?;
    let resolver = service::resolve::Resolver::new(config.dns.clone(), upstream_policy.clone());
    let static_roots = config.static_roots()?;
    let fastcgi = config.fastcgi()?;
    let rate_limit_stores = config.rate_limit_stores()?;
    let spiffe = config.spiffe()?;
    let plugins = config.plugins()?;
    let dashboard_auth = config.dashboard_auth()?;
    let table = TableHandle::with_context(
        entry::CompileContext::of_entry_points(&config.entry_points)
            .with_catch_all_tenants(config.catch_all_tenants.iter().map(AsRef::as_ref))
            .with_acme_dns_zones(config.acme_dns_zones.iter().map(AsRef::as_ref))
            .with_cache_tenant_max_percent(config.cache_tenant_max_percent)
            .with_upstream_policy(upstream_policy.clone())
            .with_tls_floor(config.tls_min_version)
            .with_static_roots(static_roots)
            .with_fastcgi(fastcgi)
            .with_rate_limit_stores(rate_limit_stores.clone())
            .with_plugins(plugins.clone())
            .with_resolver(resolver.clone())
            .with_spiffe(spiffe.clone()),
    )
    .with_metrics(observe::metrics::Registry::new(
        config.metrics_series_per_tenant,
    ));
    let events = EventFeed::new();
    let inflight = Inflight::new(events.clone());
    let budgets = Budgets::new();
    let cache = Cache::new();
    let wake = Wake::new(events.clone());
    let outcomes = Outcomes::new();
    let acme = Acme::new(
        table.clone(),
        events.clone(),
        config.node_name.clone(),
        config.acme_ca_file.clone(),
    );
    let backends = Backends::new();
    let staples = tls::ocsp::Staples::default();
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
        upstream_keepalive_pool_size: config.upstream_pool_size.get(),
        ..ServerConf::default()
    };
    let mut server = Server::new_with_opt_and_conf(None::<Opt>, server_conf);
    server.bootstrap();

    let failures = Failures::new();
    let gateway = Gateway::new(table.clone(), inflight.clone(), timeout)
        .with_budgets(budgets.clone())
        .with_rate_limit_stores(rate_limit_stores.clone())
        .with_cache(cache.clone())
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
    let udp_sessions = l4::udp::Tenants::new();
    for point in &config.entry_points {
        let gate = point
            .proxy_protocol
            .then(|| entry::proxy_protocol::hook::Gate::new(table.clone(), &point.name));
        let mut entry_gateway = gateway.clone().with_entry_point(&point.name);
        if let Some(port) = point.http3 {
            entry_gateway = entry_gateway.with_alt_svc(h3::AltSvc::new(port));
        }
        let mut proxy = entry::app::service(
            &server.configuration,
            entry_gateway,
            table.clone(),
            &point.name,
            &format!("entry point {}", point.name),
            gate.clone()
                .filter(|_| point.protocol == entry::Protocol::Http),
        );
        let addr = point.addr.to_string();
        match point.protocol {
            entry::Protocol::Http => proxy.add_tcp(&addr),
            entry::Protocol::Https => {
                let settings =
                    tls::listener_settings(table.clone(), staples.clone()).map_err(|err| {
                        anyhow::anyhow!(
                            "cannot configure the TLS entry point {}: {err}",
                            point.name
                        )
                    })?;
                proxy.add_tls_with_settings(&addr, None, settings);
                if point.http3.is_some() {
                    // The front reaches the pipeline of this entry point over its own gateway,
                    // which never advertises HTTP/3: a response over HTTP/3 carries no `Alt-Svc`.
                    let pipeline = entry::app::policed(
                        &server.configuration,
                        gateway.clone().with_entry_point(&point.name),
                        table.clone(),
                        &point.name,
                    );
                    let front = h3::Service::new(
                        &point.name,
                        point.addr,
                        h3::link_path(&config.admin_socket, &point.name),
                        pipeline,
                        h3::Parts {
                            table: table.clone(),
                            budgets: budgets.clone(),
                            settings: config.h3.clone(),
                            staples: staples.clone(),
                        },
                    )
                    .with_context(|| format!("cannot bind the HTTP/3 front of {}", point.name))?;
                    let mut service =
                        background_service(&format!("http3 entry point {}", point.name), front);
                    service.threads = std::thread::available_parallelism().ok().map(usize::from);
                    server.add_service(service);
                }
                let hello =
                    clientauth::ClearDecision(tls::PreHandshake::new(acme.clone(), table.clone()));
                // The PROXY header comes first on the wire, so its gate runs before the
                // ClientHello reader.
                match gate {
                    Some(gate) => proxy.endpoints().set_pre_tls_callback(Arc::new(
                        entry::proxy_protocol::hook::BeforeTls::new(gate, hello),
                    )),
                    None => proxy.endpoints().set_pre_tls_callback(Arc::new(hello)),
                }
            }
            entry::Protocol::Udp => {
                anyhow::ensure!(
                    !point.proxy_protocol,
                    "entry point {}: proxy_protocol is not available on a udp entry point",
                    point.name
                );
                let socket = l4::udp::bind(point.addr)
                    .with_context(|| format!("cannot bind udp entry point {}", point.name))?;
                server.add_service(background_service(
                    &format!("udp entry point {}", point.name),
                    l4::udp::Listener::new(
                        &point.name,
                        socket,
                        table.clone(),
                        budgets.clone(),
                        upstream_policy.clone(),
                        udp_sessions.clone(),
                    ),
                ));
                continue;
            }
            entry::Protocol::Tcp => {
                let terminator = l4::tls::Terminator::new(acme.clone(), staples.clone())
                    .map_err(|err| anyhow::anyhow!("tcp entry point {}: {err}", point.name))?;
                let app = l4::tcp::Listener::new(
                    &point.name,
                    table.clone(),
                    budgets.clone(),
                    upstream_policy.clone(),
                    terminator,
                    timeout,
                )
                .map_err(|err| anyhow::anyhow!("tcp entry point {}: {err}", point.name))?;
                let mut listener = pingora::services::listening::Service::new(
                    format!("tcp entry point {}", point.name),
                    entry::proxy_protocol::hook::Fronted::new(gate, app),
                );
                listener.add_tcp(&addr);
                server.add_service(listener);
                continue;
            }
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
                    cache: cache.clone(),
                },
                timeout,
            ),
        ));
    }
    server.add_service(background_service("acme issuer", acme));
    if let Some(service) = spiffe.service() {
        server.add_service(background_service("spiffe workload api", service));
    }
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
    let admin_state = AppState::new(table.clone(), events, inflight)
        .with_budgets(budgets)
        .with_cache(cache)
        .with_backends(backends)
        .with_failures(failures)
        .with_access_log(access_log)
        .with_tracer(tracer)
        .with_upstream_policy(upstream_policy.clone())
        .with_outcomes(outcomes)
        .with_entry_points(config.entry_points.clone())
        .with_metrics_addr(config.metrics_addr);
    if let Some(addr) = config.dashboard_addr {
        let listener =
            dashboard::bind(addr).with_context(|| format!("cannot bind DASHBOARD_ADDR {addr}"))?;
        server.add_service(background_service(
            "dashboard",
            dashboard::DashboardService::new(
                listener,
                dashboard::Access {
                    addr,
                    hosts: config.dashboard_hosts.clone(),
                    auth: dashboard_auth,
                },
                admin_state.clone(),
                timeout,
            ),
        ));
    }
    server.add_service(background_service(
        "dns resolver",
        service::resolve::ResolveService::new(resolver.clone(), table.clone()),
    ));
    server.add_service(background_service(
        "ocsp stapling",
        tls::ocsp::OcspService::new(
            table.clone(),
            staples,
            tls::ocsp::Runner::new(
                upstream_policy.clone(),
                tls::ocsp::AllowedHosts::new(config.ocsp_allowed_hosts.iter().map(AsRef::as_ref)),
                resolver,
            ),
        ),
    ));
    server.add_service(background_service(
        "admin API",
        AdminService::new(admin_listener, admin_state, timeout),
    ));
    // Last before the server runs: nothing above can fail after a plugin process exists.
    plugins.start()?;
    server.add_service(background_service("plugins", plugins.supervisor()));

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
