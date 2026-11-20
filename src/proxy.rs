//! The Pingora proxy: [`Gateway`] implements `ProxyHttp`.
//!
//! # Adding a feature
//!
//! Each callback below is a short sequence of calls into per-feature modules; the logic lives
//! in those modules, not here. A feature adds
//!
//! 1. its own module (`src/<feature>.rs`) with the logic as plain functions over [`Ctx`] fields,
//! 2. its own field on [`Ctx`] (default in [`Gateway::new_ctx`]), and
//! 3. one line in each callback it hooks, and one callback method when it needs a new hook.
//!
//! Core host routing is `route.rs`; this file never matches hosts or picks backends itself.
//!
//! # Callback order
//!
//! `request_filter` runs SNI, route, in-flight admission, tenant admission, backend admission
//! (where a request waits when its upstream is at its limit), then starts the
//! failure capture, so a request refused earlier is never recorded. `response_filter` and
//! `response_body_filter` run the failure capture first, then compression, so a recorded failure
//! shows the upstream's headers and uncompressed body. `logging` records the failure first and
//! then releases the tenant slot, so the recorder sees the final status the client got. The
//! backend slot is released when the upstream response ends, before the client has read it all.
//!
//! # The middleware chain
//!
//! [`middleware_chain`] lists, in order, the request-path stages [`Gateway::request_filter`]
//! runs for an app. `GET /v1/explain` (see [`crate::explain`]) reports it, so it must match
//! the code. A feature that adds a stage to `request_filter` adds one line to
//! [`middleware_chain`], in the same position as its call, and nothing else.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::Error;
use pingora::ErrorType::InternalError;
use pingora::http::ResponseHeader;
use pingora::protocols::Digest;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::acme;
use crate::budget::{Budgets, TenantSlot};
use crate::compress::{self, Gzip};
use crate::error::AppError;
use crate::failures::{self, Failures};
use crate::fairq::{self, Backends};
use crate::inflight::{Inflight, InflightGuard};
use crate::outcomes::{self, Outcomes};
use crate::pool;
use crate::respond;
use crate::route::{self, RouteError, Selected};
use crate::skew;
use crate::sni;
use crate::table::{CompiledApp, RoutingTable, TableHandle};
use crate::wake::{self, Wake};
use crate::wasm;

/// Routing attempts before a request gives up; see `Gateway::request_filter`.
const MAX_ROUTE_ATTEMPTS: u8 = 3;

/// The request-path stages `request_filter` runs for `app`, in the order it runs them; `tls`
/// says the request arrived over a TLS connection. A stage that cannot act for this app is
/// left out: `sni_check` never refuses an app that sets `allow_domain_fronting`, and
/// `wasm_filters` only runs for an app with filters.
///
/// Every stage appends one line here, next to where `request_filter` calls it.
#[must_use]
pub fn middleware_chain(app: &CompiledApp, tls: bool) -> Vec<&'static str> {
    let mut chain = Vec::new();
    if !tls {
        chain.push("acme_http01");
    }
    if tls && !app.allow_domain_fronting() {
        chain.push("sni_check");
    }
    chain.push("route");
    if app.scale_to_zero().is_some() {
        chain.push("wake_hold");
    }
    chain.push("inflight_admit");
    chain.push("tenant_admit");
    chain.push("backend_admit");
    chain.push("failure_capture");
    if !app.filters().is_empty() {
        chain.push("wasm_filters");
    }
    chain
}

/// State of one proxied request, created by [`Gateway::new_ctx`] and passed to every callback.
///
/// One field per concern. A feature adds its own field next to the existing ones and documents
/// it there; it does not reuse another feature's field.
#[derive(Debug)]
pub struct Ctx {
    /// The routing table this request started with. Loaded once, so a snapshot swap in the
    /// middle of the request cannot change its routing.
    pub table: Arc<RoutingTable>,
    /// The routing decision, set by `request_filter` when the host has a route.
    pub route: Option<Selected>,
    /// Keeps this request counted on its revision (see [`crate::inflight`]); set by
    /// `request_filter` with `route`, released when the request ends and the `Ctx` drops.
    pub inflight: Option<InflightGuard>,
    /// The tenant's in-flight slot (see [`crate::budget`]), taken by `request_filter` after the
    /// revision is counted and freed in `logging`.
    pub tenant_slot: Option<TenantSlot>,
    /// The gzip encoder of this response, when it is being compressed.
    pub compression: Option<Gzip>,
    /// Pool partition state of the downstream connection, see [`pool`].
    pub pool: pool::State,
    /// Failed-request capture, begun by `request_filter` for a routed request.
    pub failures: failures::Capture,
    /// Wake and idle state for apps that scale to zero.
    pub wake: wake::State,
    /// Set when podgate answers with a capacity refusal ([`AppError::is_capacity_refusal`]):
    /// the request says the proxy or tenant is busy, not that the deploy is broken, so
    /// [`crate::outcomes::record_request`] does not count it.
    pub capacity_refusal: bool,
    /// The backend slot and latency timer (see [`crate::fairq`]), taken by `request_filter` after
    /// the tenant slot and freed when the upstream response ends, or in `logging`.
    pub backend: fairq::Slot,
}

/// The reverse proxy logic: one instance serves every listener.
#[derive(Debug)]
pub struct Gateway {
    table: TableHandle,
    inflight: Inflight,
    upstream_timeout: Duration,
    budgets: Budgets,
    backends: Backends,
    failures: Failures,
    wake: Wake,
    outcomes: Outcomes,
    wasm: wasm::Executor,
}

impl Gateway {
    /// Creates a gateway that routes with the live table behind `table` and counts requests in
    /// `inflight`. Connecting to, writing to and reading from an upstream each give up after
    /// `upstream_timeout`.
    #[must_use]
    pub fn new(table: TableHandle, inflight: Inflight, upstream_timeout: Duration) -> Self {
        Self {
            table,
            inflight,
            upstream_timeout,
            budgets: Budgets::new(),
            failures: Failures::new(),
            wake: Wake::default(),
            outcomes: Outcomes::new(),
            wasm: wasm::Executor::default(),
            backends: Backends::new(),
        }
    }

    /// Charges tenants against `budgets`, a registry shared with the admin API's metrics.
    #[must_use]
    pub fn with_budgets(mut self, budgets: Budgets) -> Self {
        self.budgets = budgets;
        self
    }

    /// Records failed requests into `failures`, the recorder the admin API shares.
    #[must_use]
    pub fn with_failures(mut self, failures: Failures) -> Self {
        self.failures = failures;
        self
    }

    /// Holds requests for sleeping apps with `wake`, the bookkeeping the idle sweep also reads.
    #[must_use]
    pub fn with_wake(mut self, wake: Wake) -> Self {
        self.wake = wake;
        self
    }

    /// Records every finished request into `outcomes`, a registry shared with auto-revert.
    #[must_use]
    pub fn with_outcomes(mut self, outcomes: Outcomes) -> Self {
        self.outcomes = outcomes;
        self
    }

    /// Runs WASM filters through `wasm`, the executor that bounds their workers and memory.
    #[must_use]
    pub fn with_wasm(mut self, wasm: wasm::Executor) -> Self {
        self.wasm = wasm;
        self
    }

    /// Admits requests to their backends through `backends`, a registry shared with the admin
    /// API's metrics.
    #[must_use]
    pub fn with_backends(mut self, backends: Backends) -> Self {
        self.backends = backends;
        self
    }
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx {
            table: self.table.load(),
            route: None,
            inflight: None,
            tenant_slot: None,
            compression: None,
            pool: pool::State::default(),
            failures: failures::Capture::default(),
            wake: wake::State::default(),
            capacity_refusal: false,
            backend: fairq::Slot::default(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> pingora::Result<bool> {
        // Before routing: a validation request names a host that may have no route yet.
        if acme::serve_challenge(session, &ctx.table).await? {
            return Ok(true);
        }
        // Before routing: a misdirected request learns nothing about the route it named.
        if let Err(err) = sni::check(session, &ctx.table) {
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        let mut attempts = 0;
        loop {
            let selected = match route::resolve(&ctx.table, session.req_header()) {
                Ok(selected) => selected,
                Err(RouteError::NoUpstream) => {
                    let held = self.wake.hold(
                        &mut ctx.wake,
                        &mut ctx.table,
                        &self.table,
                        &self.budgets,
                        session.req_header(),
                    );
                    if let Err(err) = held.await {
                        ctx.capacity_refusal = err.is_capacity_refusal();
                        respond::write_error(session, &err).await?;
                        return Ok(true);
                    }
                    continue;
                }
                Err(err) => {
                    respond::write_error(session, &AppError::from(err)).await?;
                    return Ok(true);
                }
            };
            if let Some(guard) = self.inflight.admit(&ctx.table, &selected) {
                match self
                    .wake
                    .admit(&mut ctx.wake, &self.budgets, &ctx.table, selected.app)
                {
                    Ok(slot) => ctx.tenant_slot = slot,
                    Err(err) => {
                        ctx.capacity_refusal = err.is_capacity_refusal();
                        respond::write_error(session, &err).await?;
                        return Ok(true);
                    }
                }
                match self.backends.admit(&ctx.table, &selected).await {
                    Ok(slot) => ctx.backend = slot,
                    Err(err) => {
                        ctx.capacity_refusal = err.is_capacity_refusal();
                        respond::write_error(session, &err).await?;
                        return Ok(true);
                    }
                }
                ctx.route = Some(selected);
                ctx.inflight = Some(guard);
                let keep_bodies = ctx
                    .table
                    .app(selected.app)
                    .is_some_and(CompiledApp::record_bodies);
                ctx.failures.begin(keep_bodies);
                // After routing and every admission: a filter-answered request releases its
                // guards with the context.
                let tenant = ctx.tenant_slot.as_ref().map(TenantSlot::tenant);
                return wasm::run_filters(
                    session,
                    &ctx.table,
                    selected.app,
                    tenant,
                    &self.wasm,
                    &mut ctx.capacity_refusal,
                )
                .await;
            }
            // The revision drained after this request loaded its table: route again with the
            // live one. Repeated refusals mean snapshots are landing right now; give up.
            attempts += 1;
            if attempts == MAX_ROUTE_ATTEMPTS {
                respond::write_error(session, &AppError::from(RouteError::NoUpstream)).await?;
                return Ok(true);
            }
            ctx.table = self.table.load();
        }
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        ctx.failures.upstream_response(upstream_response);
        skew::set_cookie(session, &ctx.table, ctx.route.as_ref(), upstream_response)?;
        if let Some(slot) = &ctx.tenant_slot {
            ctx.compression =
                compress::start(session.req_header(), upstream_response, slot.tenant());
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> pingora::Result<Option<Duration>> {
        ctx.failures.response_chunk(body.as_ref());
        compress::filter(&mut ctx.compression, body, end_of_stream)
            .map_err(|err| Error::because(InternalError, "gzip encoding failed", err))?;
        if end_of_stream {
            ctx.backend.release();
        }
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, _error: Option<&Error>, ctx: &mut Ctx) {
        self.failures.log(session, ctx);
        outcomes::record_request(&self.outcomes, session, ctx);
        ctx.compression = None;
        ctx.tenant_slot = None;
        ctx.backend.release();
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<Box<HttpPeer>> {
        let selected = ctx
            .route
            .ok_or_else(|| Error::explain(InternalError, "upstream_peer without a route"))?;
        let mut peer = HttpPeer::new(selected.upstream, false, String::new());
        peer.options.connection_timeout = Some(self.upstream_timeout);
        peer.options.read_timeout = Some(self.upstream_timeout);
        peer.options.write_timeout = Some(self.upstream_timeout);
        let identity = pool::Identity::of(&ctx.table, &selected)
            .ok_or_else(|| Error::explain(InternalError, "route points outside the table"))?;
        pool::observe(&mut ctx.pool, session.req_header());
        pool::isolate(&mut peer, identity, ctx.pool, session);
        Ok(Box::new(peer))
    }

    fn persist_connection_context(
        &self,
        _session: &Session,
        ctx: &Ctx,
    ) -> Option<Box<dyn Any + Send + Sync>> {
        pool::persist(ctx.pool)
    }

    fn on_connection_reuse(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        prev_ctx: Box<dyn Any + Send + Sync>,
    ) {
        pool::restore(&mut ctx.pool, prev_ctx);
    }

    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        _fd: std::os::unix::io::RawFd,
        _digest: Option<&Digest>,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        ctx.backend.connected();
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        ctx.backend.responded(upstream_response.status.as_u16());
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        ctx.failures.request_chunk(body.as_ref());
        Ok(())
    }
}
