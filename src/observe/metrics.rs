//! Prometheus metrics: per entry point, router and service series with a series cap per tenant,
//! and the one [`render`] function the endpoints share.
//!
//! - [`Registry`]: the series that outlive routing tables, the snapshot counters and the cap. One
//!   per process, owned by [`crate::TableHandle`] ([`crate::TableHandle::with_metrics`]).
//! - [`Series`]: the atomics of one entry point, router or service: requests by status class and
//!   a fixed-bucket latency histogram.
//! - [`TableSeries`]: the handles a compiled table carries, resolved when it goes live, so a
//!   request records without a lookup, a lock or an allocation.
//! - [`InFlight`]: what one request holds: it counts the request open on its entry point and
//!   records it when it finishes.
//! - [`MetricsService`]: the optional read-only `METRICS_ADDR` listener that serves `/metrics`
//!   over TCP, because Prometheus cannot scrape the admin API's unix socket.
//!
//! The reference for operators is `docs/ref/metrics.md`.

mod entry;
mod export;
mod listener;
mod otlp;
mod registry;
mod scrape;
mod series;
mod table;
mod text;

use crate::budget::Budgets;
use crate::cache::Cache;
use crate::fairq::Backends;
use crate::observe::access_log::AccessLog;
use crate::observe::tracing::Tracer;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::table::TableHandle;

pub use entry::{EntrySeries, InFlight};
pub use export::{MetricsExportConfig, MetricsExportService};
pub use listener::{MetricsService, Sources, bind};
pub use registry::{DEFAULT_SERIES_PER_TENANT, RETENTION, Registry};
pub use series::Series;
pub use table::{RouteSeries, TableSeries};

/// The OTLP metrics messages the exporter sends, for a collector that decodes them.
pub mod proto {
    pub use super::otlp::*;
}

/// The `Content-Type` of the text exposition.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The whole exposition: the per-tenant series (`budgets`), the per-backend series (`backends`),
/// the refusals of the upstream address policy, the access log counters, the ejected servers of passive outlier detection, then the per entry point, router and service
/// series, the server, certificate and snapshot gauges of the live table behind `table`.
///
/// Both endpoints, the admin socket's `GET /metrics` and the `METRICS_ADDR` listener, call this
/// and add nothing, so they cannot disagree.
#[must_use]
pub fn render(
    table: &TableHandle,
    budgets: &Budgets,
    backends: &Backends,
    upstream_policy: &UpstreamPolicy,
    access_log: &AccessLog,
    tracer: &Tracer,
    cache: &Cache,
) -> String {
    let live = table.load();
    let mut out = budgets.render(&live);
    out.push_str(&backends.render());
    out.push_str(&upstream_policy.render());
    out.push_str(&access_log.render());
    out.push_str(&tracer.render());
    out.push_str(&cache.render());
    out.push_str(&crate::service::outlier::render(&live));
    crate::middleware::pass_tls_client_cert::render(&mut out);
    crate::forwarded::render(&mut out);
    crate::tls::ocsp::render(&mut out);
    out.push_str(&crate::middleware::limits::render(&live));
    crate::ratelimit_store::render(&mut out);
    crate::middleware::plugin::render(&mut out);
    crate::middleware::in_flight_req::render(&mut out);
    crate::service::mirroring::render(&mut out);
    crate::service::extras::render(&mut out);
    out.push_str(&crate::middleware::jwt_auth::render(&live));
    crate::middleware::mcp::render(&mut out, &live, table.metrics().series_per_tenant());
    crate::mcp_audit::render(&mut out);
    out.push_str(&crate::router::matcher::cel_metrics(&live));
    crate::l4::tcp::render(&mut out);
    out.push_str(&crate::l4::health::render(&live));
    crate::l4::udp::render(&mut out);
    out.push_str(&crate::middleware::oidc::render(&live));
    out.push_str(&crate::middleware::ai_token_limit::render(&live));
    crate::h3::render(&mut out);
    export::render(&mut out);
    table.metrics().render(&mut out, &live);
    out
}
