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
//! A feature that is a middleware (a per-route stage tenants configure) adds no line here at
//! all: it is one type in `src/middleware/` and one line in the `kinds!` list, and the chain
//! runner below calls it. Core routing is `route.rs` and `router.rs`; this file never matches
//! hosts or picks backends itself.
//!
//! # Callback order
//!
//! `request_filter` runs, in this order (`GET /v1/explain` reports it, see [`crate::pipeline`]):
//! the ACME challenge answer, path normalization and the forwarded-header view, the route match, the SNI check, the failure
//! capture start, the router's middleware chain, then the backend selection (where a request for
//! a sleeping app waits), in-flight admission, tenant admission and backend admission (where a
//! request waits when its upstream is at its limit). The chain runs before any slot is taken or
//! app woken, so unauthenticated or rate-limited traffic costs the tenant nothing. A request
//! refused by admission is never recorded as a failure. `response_filter` and
//! `response_body_filter` run the failure capture first, then compression, then the chain's
//! response hooks in reverse order. `logging` records the failure first and then releases the
//! tenant slot, so the recorder sees the final status the client got. The backend slot is
//! released when the upstream response ends, before the client has read it all.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::Error;
use pingora::ErrorType::{HTTPStatus, InternalError};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::protocols::Digest;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::acme;
use crate::budget::{Budgets, TenantSlot};
use crate::client_ip::ForwardedView;
use crate::clientauth;
use crate::compress::{self, Gzip};
use crate::entry;
use crate::error::AppError;
use crate::failures::{self, Failures};
use crate::fairq::{self, Backends};
use crate::inflight::{Inflight, InflightGuard};
use crate::middleware::{self, Flow, RequestCx};
use crate::outcomes::{self, Outcomes};
use crate::pool;
use crate::respond;
use crate::route::{self, RouteError, Selected};
use crate::router::Matched;
use crate::service::Lease;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::skew;
use crate::sni;
use crate::table::{RoutingTable, TableHandle};
use crate::wake::{self, Wake};
use crate::wasm;

/// Routing attempts before a request gives up; see `Gateway::request_filter`.
const MAX_ROUTE_ATTEMPTS: u8 = 3;

/// State of one proxied request, created by [`Gateway::new_ctx`] and passed to every callback.
///
/// One field per concern. A feature adds its own field next to the existing ones and documents
/// it there; it does not reuse another feature's field.
#[derive(Debug)]
pub struct Ctx {
    /// The routing table this request started with. Loaded once, so a snapshot swap in the
    /// middle of the request cannot change its routing.
    pub table: Arc<RoutingTable>,
    /// The name of the entry point the request arrived on (`web`, `websecure`, or a name from
    /// `ENTRY_POINTS`): the listener, not a guess from the TLS flag.
    pub entry_point: Arc<str>,
    /// The router the request matched, set by `request_filter`. Indices into `table`.
    pub matched: Option<Matched>,
    /// Who the client is and what scheme and host it used, decided in the stage that normalizes
    /// the path: forged inbound forwarding headers are already gone (see [`crate::client_ip`]).
    pub forwarded: ForwardedView,
    /// The routing decision, set by `request_filter` once a revision and backend are chosen and
    /// every admission passed.
    pub route: Option<Selected>,
    /// Per-request state of the middleware chain (see [`crate::middleware`]).
    pub chain: middleware::State,
    /// Set when a middleware answered the request: it has a router but no revision or backend,
    /// which the failure recorder needs to know.
    pub chain_answered: bool,
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
    /// Failed-request capture, begun by `request_filter` for a matched request.
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
    /// The request's claim on the server it was sent to (see [`crate::service::state`]): counts
    /// it as active there and carries its latency to the balancer. Set with `route`, dropped in
    /// `logging`.
    pub lease: Option<Lease>,
}

/// The reverse proxy logic: one instance per entry point, all sharing the same handles.
#[derive(Debug, Clone)]
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
    upstream_policy: UpstreamPolicy,
    entry_point: Arc<str>,
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
            upstream_policy: UpstreamPolicy::builtin(),
            backends: Backends::new(),
            entry_point: Arc::from(entry::WEB),
        }
    }

    /// Serves the entry point called `name`: requests this gateway handles arrive on that
    /// listener, and only routers that listen on it match. Without this the gateway is `web`.
    #[must_use]
    pub fn with_entry_point(mut self, name: &str) -> Self {
        self.entry_point = Arc::from(name);
        self
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

    /// Checks every upstream address a request dials against `policy`. Without this
    /// a gateway runs the built-in policy: loopback, link-local, metadata, unspecified and
    /// multicast addresses are refused.
    #[must_use]
    pub fn with_upstream_policy(mut self, policy: UpstreamPolicy) -> Self {
        self.upstream_policy = policy;
        self
    }

    /// Refuses the connection to `selected.upstream` unless the upstream address policy lets the
    /// app's tenant dial it. `upstream_peer` calls this before anything is dialled, so it also
    /// covers addresses the compiler never saw.
    ///
    /// # Errors
    ///
    /// A `502` error (and one count in `podgate_upstream_refused_total{tenant}`) when the policy
    /// refuses the address; an internal error when the route points outside `table`.
    pub fn check_upstream(&self, table: &RoutingTable, selected: &Selected) -> pingora::Result<()> {
        let app = table
            .app(selected.app)
            .ok_or_else(|| Error::explain(InternalError, "route points outside the table"))?;
        self.upstream_policy
            .check(app.tenant(), selected.upstream.ip())
            .map_err(|refused| {
                Error::because(
                    HTTPStatus(502),
                    "upstream address refused by policy",
                    refused,
                )
            })
    }

    /// Runs the router's middleware chain on the request. `true` when a middleware answered it.
    async fn run_chain(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        matched: Matched,
    ) -> pingora::Result<bool> {
        let table = Arc::clone(&ctx.table);
        let Some((app, router)) = table.router(matched) else {
            return Ok(false);
        };
        if router.chain().is_empty() {
            return Ok(false);
        }
        let tenant = table
            .tenant_budget(app.tenant())
            .map(|limits| self.budgets.tenant(app.tenant(), limits));
        let mut cx = RequestCx {
            session,
            app,
            tenant: tenant.as_ref(),
            executor: &self.wasm,
            capacity_refusal: &mut ctx.capacity_refusal,
        };
        let flow =
            middleware::run_request(app.stages(), router.chain(), &mut cx, &mut ctx.chain).await?;
        ctx.chain_answered = flow == Flow::Respond;
        Ok(ctx.chain_answered)
    }
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx {
            table: self.table.load(),
            entry_point: Arc::clone(&self.entry_point),
            matched: None,
            forwarded: ForwardedView::default(),
            route: None,
            chain: middleware::State::default(),
            chain_answered: false,
            inflight: None,
            tenant_slot: None,
            compression: None,
            pool: pool::State::default(),
            failures: failures::Capture::default(),
            wake: wake::State::default(),
            capacity_refusal: false,
            backend: fairq::Slot::default(),
            lease: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> pingora::Result<bool> {
        // Before routing: a validation request names a host that may have no route yet.
        if acme::serve_challenge(session, &ctx.table).await? {
            return Ok(true);
        }
        // Before matching: the path that is matched is the path that is served.
        let tls = entry::is_tls(session);
        if let Err(refused) = entry::normalize_request(session.req_header_mut()) {
            let err = AppError::BadRequest(refused.to_string().into());
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        ctx.forwarded =
            ForwardedView::of(session, tls, ctx.table.forwarded_trust(&ctx.entry_point));
        let found = route::matching(
            &ctx.table,
            session.req_header(),
            &ctx.entry_point,
            tls,
            ctx.forwarded.known_client(),
        );
        // Right after matching and before anything answers: a misdirected request gets `421`
        // whether or not a router matched, and the matched app decides fronting.
        if let Err(err) = sni::check(session, &ctx.table, found) {
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        // Right after the match: the app the router really belongs to decides whether a client
        // certificate is required, however the router matched (exact host, regexp, no host).
        if let Err(err) = clientauth::admit(session, &ctx.table, found) {
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        let Some(mut matched) = found else {
            respond::write_error(session, &AppError::from(RouteError::NoRoute)).await?;
            return Ok(true);
        };
        ctx.matched = Some(matched);
        let keep_bodies = ctx
            .table
            .app(matched.app)
            .is_some_and(crate::table::CompiledApp::record_bodies);
        ctx.failures.begin(keep_bodies);
        // The tenant's chain, before any slot is taken or app woken.
        if self.run_chain(session, ctx, matched).await? {
            return Ok(true);
        }
        let mut attempts = 0;
        loop {
            let (selected, lease) = match route::select(&ctx.table, matched, session.req_header()) {
                Ok(chosen) => chosen,
                Err(RouteError::NoUpstream) => {
                    let held = self.wake.hold(
                        &mut ctx.wake,
                        &mut ctx.table,
                        &self.table,
                        &self.budgets,
                        &mut matched,
                    );
                    if let Err(err) = held.await {
                        ctx.capacity_refusal = err.is_capacity_refusal();
                        respond::write_error(session, &err).await?;
                        return Ok(true);
                    }
                    ctx.matched = Some(matched);
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
                ctx.lease = Some(lease);
                ctx.inflight = Some(guard);
                return Ok(false);
            }
            // The revision drained after this request loaded its table: select again with the
            // live one, on the same router (see `RoutingTable::rematch`). Repeated refusals
            // mean snapshots are landing right now; give up.
            attempts += 1;
            let live = self.table.load();
            let rematched = live.rematch(&ctx.table, matched);
            match rematched {
                Some(next) if attempts < MAX_ROUTE_ATTEMPTS => {
                    ctx.table = live;
                    matched = next;
                    ctx.matched = Some(matched);
                }
                _ => {
                    respond::write_error(session, &AppError::from(RouteError::NoUpstream)).await?;
                    return Ok(true);
                }
            }
        }
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        if let Some((app, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) {
            middleware::run_upstream_request(
                app.stages(),
                router.chain(),
                upstream_request,
                &mut ctx.chain,
            )?;
        }
        Ok(())
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
        if let Some((app, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) {
            middleware::run_response(
                app.stages(),
                router.chain(),
                upstream_response,
                &mut ctx.chain,
            )?;
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
        if let Some((app, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) {
            middleware::run_response_body(
                app.stages(),
                router.chain(),
                body,
                end_of_stream,
                &mut ctx.chain,
            )?;
        }
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
        ctx.lease = None;
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<Box<HttpPeer>> {
        let selected = ctx
            .route
            .ok_or_else(|| Error::explain(InternalError, "upstream_peer without a route"))?;
        // The one place a proxied request dials: every address, whatever produced it, is checked.
        self.check_upstream(&ctx.table, &selected)?;
        let outside = || Error::explain(InternalError, "route points outside the table");
        let upstream = ctx
            .table
            .app(selected.app)
            .and_then(|app| app.service(selected.revision, selected.router))
            .and_then(|service| service.upstream(selected.upstream))
            .ok_or_else(outside)?;
        let mut peer = upstream.peer();
        peer.options.connection_timeout = Some(self.upstream_timeout);
        peer.options.read_timeout = Some(self.upstream_timeout);
        peer.options.write_timeout = Some(self.upstream_timeout);
        let identity =
            pool::Identity::of(&ctx.table, &selected, upstream.pool_key()).ok_or_else(outside)?;
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
        let status = upstream_response.status.as_u16();
        ctx.backend.responded(status);
        if let Some(lease) = &mut ctx.lease {
            lease.responded(status);
        }
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
