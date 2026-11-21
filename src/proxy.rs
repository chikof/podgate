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
//! a sleeping app waits), the chain's `routed` hooks (the response cache answers a hit here,
//! before any slot is taken), in-flight admission, tenant admission and backend admission (where a
//! request waits when its upstream is at its limit). The chain runs before any slot is taken or
//! app woken, so unauthenticated or rate-limited traffic costs the tenant nothing. A request
//! refused by admission is never recorded as a failure. `response_filter` and
//! `response_body_filter` run the failure capture first, then compression, then the chain's
//! response hooks in reverse order; the chain's `response_head` hooks run before compression, so
//! a middleware can replace an oversized response with an error. Before all of that,
//! `response_filter` (an upstream response) and `fail_to_proxy` (an error podgate made after it
//! chose a server) ask the chain's `Kind::response_page` hooks for an error page; a page is
//! written whole and the original response is dropped (`errors`).
//! `request_body_filter` counts the
//! body through the chain's `request_body` hooks. `logging` records the failure first, then the
//! outcome, then tells the chain's middlewares the request is over (`Kind::finished`), and then releases the
//! tenant slot, so the recorder sees the final status the client got. The backend slot is
//! released when the upstream response ends, before the client has read it all.
//!
//! A router whose service is `static` has no server: after the tenant admission `request_filter`
//! takes no backend slot, answers from the operator's directory (`crate::service`'s
//! `static_files`), passing the response through `response_filter` and `response_body_filter`
//! itself, and returns `Ok(true)`.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use pingora::Error;
use pingora::ErrorSource;
use pingora::ErrorType::{
    ConnectionClosed, H2Downgrade, HTTPStatus, InternalError, InvalidH2, ReadError, WriteError,
};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::protocols::{ALPN, Digest};
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::acme;
use crate::budget::{Budgets, TenantSlot};
use crate::cache::{self, Cache};
use crate::client_ip::ForwardedView;
use crate::clientauth;
use crate::compress::{self, Encoder};
use crate::entry;
use crate::error::AppError;
use crate::events::EventFeed;
use crate::failures::{self, Failures};
use crate::fairq::{self, Backends};
use crate::forwarded;
use crate::h3::AltSvc;
use crate::inflight::{Inflight, InflightGuard};
use crate::middleware::{self, Failure, Flow, RequestCx, RoutedCx, errors, retry};
use crate::observe::access_log::{self, AccessLog};
use crate::observe::metrics;
use crate::observe::tracing as trace;
use crate::outcomes::{self, Outcomes};
use crate::pool;
use crate::respond;
use crate::route::{self, RouteError, Selected};
use crate::router::Matched;
use crate::router::matcher::Hello;
use crate::service::extras;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::service::{Lease, StaticReads, mirroring, outlier, serve_fastcgi, serve_static, sticky};
use crate::skew;
use crate::sni;
use crate::table::{RoutingTable, TableHandle};
use crate::tls;
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
    /// The encoder of this response, when it is being compressed.
    pub compression: Option<Encoder>,
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
    /// What the access log notes while the request runs: the clock, upstream timing, retries and
    /// the refusal reason.
    pub access: access_log::Pending,
    /// Counts the request open on its entry point and records it in `logging`, under its
    /// entry point, router and service (see [`crate::observe::metrics`]).
    pub metrics: metrics::InFlight,
    /// The trace context of the request and its sampling verdict.
    pub trace: trace::State,
    /// Whether an error page was tried for this response, the loop guard of the `errors`
    /// middleware.
    pub error_page: errors::Attempt,
    /// What the request did about its mirrors.
    pub mirror: mirroring::State,
    /// Whether a stage read the whole request body into the session's replay buffer, so a
    /// retry can send it to another server (`buffering`).
    pub body_held: bool,
    /// What the `retry` middleware keeps: the servers tried and the attempt to start next
    ///.
    pub retry: retry::Progress,
    /// The tunnel this request may become or is: its limits from the transport, and the
    /// timers that end it.
    pub tunnel: extras::State,
}

/// The reverse proxy logic: one instance per entry point, all sharing the same handles.
#[derive(Debug, Clone)]
pub struct Gateway {
    table: TableHandle,
    inflight: Inflight,
    upstream_timeout: Duration,
    budgets: Budgets,
    backends: Backends,
    static_reads: StaticReads,
    failures: Failures,
    wake: Wake,
    outcomes: Outcomes,
    wasm: wasm::Executor,
    basic_auth: middleware::basic_auth::Pool,
    upstream_policy: UpstreamPolicy,
    entry_point: Arc<str>,
    entry: Arc<metrics::EntrySeries>,
    events: EventFeed,
    access_log: Option<AccessLog>,
    tracer: trace::Tracer,
    page_fetcher: errors::fetch::Fetcher,
    node: Option<HeaderValue>,
    cache: Cache,
    auth_client: middleware::forward_auth::Client,
    rate_limit_stores: crate::ratelimit_store::Stores,
    alt_svc: Option<AltSvc>,
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
            basic_auth: middleware::basic_auth::Pool::default(),
            upstream_policy: UpstreamPolicy::builtin(),
            events: EventFeed::new(),
            backends: Backends::new(),
            static_reads: StaticReads::default(),
            entry_point: Arc::from(entry::WEB),
            access_log: None,
            page_fetcher: errors::fetch::Fetcher::default(),
            auth_client: middleware::forward_auth::Client::new(upstream_timeout),
            rate_limit_stores: crate::ratelimit_store::Stores::default(),
            entry: Arc::default(),
            tracer: trace::Tracer::default(),
            node: None,
            cache: Cache::new(),
            alt_svc: None,
        }
    }

    /// Serves the entry point called `name`: requests this gateway handles arrive on that
    /// listener, and only routers that listen on it match. Without this the gateway is `web`.
    #[must_use]
    pub fn with_entry_point(mut self, name: &str) -> Self {
        self.entry_point = Arc::from(name);
        self.entry = self.table.metrics().entry_point(name);
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

    /// Reports what middlewares observe (a circuit opening, say) into `events`, the feed the
    /// admin API serves.
    #[must_use]
    pub fn with_events(mut self, events: EventFeed) -> Self {
        self.events = events;
        self
    }

    /// Verifies `basic_auth` passwords through `pool`, the executor that bounds their workers.
    #[must_use]
    pub fn with_basic_auth(mut self, pool: middleware::basic_auth::Pool) -> Self {
        self.basic_auth = pool;
        self
    }

    /// Counts cluster-scope `rate_limit` requests in `stores`, the shared stores of
    /// `RATE_LIMIT_STORES_FILE`.
    #[must_use]
    pub fn with_rate_limit_stores(mut self, stores: crate::ratelimit_store::Stores) -> Self {
        self.rate_limit_stores = stores;
        self
    }

    /// Reads static files through `reads`, the pool that bounds the blocking file-system work
    /// of every tenant.
    #[must_use]
    pub fn with_static_reads(mut self, reads: StaticReads) -> Self {
        self.static_reads = reads;
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

    /// Writes an access log line for every request the live policy selects, into `access_log`.
    #[must_use]
    pub fn with_access_log(mut self, access_log: AccessLog) -> Self {
        self.access_log = Some(access_log);
        self
    }

    /// Traces requests through `tracer`: the per-node rate cap and the span queue the exporter
    /// drains. Without this a gateway still propagates trace context but exports nothing.
    #[must_use]
    pub fn with_tracer(mut self, tracer: trace::Tracer) -> Self {
        self.tracer = tracer;
        self
    }

    /// Names this node in `X-Forwarded-Server` for apps that ask for it. A name that is not a
    /// valid header value, or none, leaves that header out.
    #[must_use]
    pub fn with_node_name(mut self, name: Option<&str>) -> Self {
        self.node = name.and_then(|name| HeaderValue::from_str(name).ok());
        self
    }

    /// Stores responses in `cache`, the registry the admin API's purge and metrics share.
    #[must_use]
    pub fn with_cache(mut self, cache: Cache) -> Self {
        self.cache = cache;
        self
    }

    /// Advertises HTTP/3 on every response of an app that allows it, as `alt_svc` says (spec
    /// 0086). Set it only on the gateway of an `https` entry point with `;http3`: a response
    /// over HTTP/3 itself, or over plain HTTP, never advertises it.
    #[must_use]
    pub fn with_alt_svc(mut self, alt_svc: AltSvc) -> Self {
        self.alt_svc = Some(alt_svc);
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

    /// What the router's `retry` middleware says about the attempt that failed with `failure`:
    /// see [`retry::on_upstream_error`]. The next server must pass the upstream address policy.
    fn retry_after(&self, session: &mut Session, ctx: &mut Ctx, failure: Failure) -> Option<bool> {
        retry::on_upstream_error(
            session,
            ctx,
            failure,
            self.upstream_timeout,
            &self.events,
            |table, selected| self.check_upstream(table, selected).is_ok(),
        )
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
            forwarded: &ctx.forwarded,
            tenant: tenant.as_ref(),
            executor: &self.wasm,
            capacity_refusal: &mut ctx.capacity_refusal,
            events: &self.events,
            hashing: &self.basic_auth,
            auth: &self.auth_client,
            stores: &self.rate_limit_stores,
            policy: &self.upstream_policy,
            body_held: &mut ctx.body_held,
            reason: &mut ctx.access.reason,
        };
        let flow =
            middleware::run_request(app.stages(), router.chain(), &mut cx, &mut ctx.chain).await?;
        ctx.chain_answered = flow == Flow::Respond;
        Ok(ctx.chain_answered)
    }

    /// Runs the chain's routed hooks, once a revision and server are chosen and before any
    /// admission. `true` when one answered the request.
    async fn run_routed(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        matched: Matched,
        selected: &Selected,
        tls: bool,
    ) -> pingora::Result<bool> {
        let table = Arc::clone(&ctx.table);
        let Some((app, router)) = table.router(matched) else {
            return Ok(false);
        };
        if !middleware::has_routed(app.stages(), router.chain()) {
            return Ok(false);
        }
        let tenant = table
            .tenant_budget(app.tenant())
            .map(|limits| self.budgets.tenant(app.tenant(), limits));
        let entry_point = Arc::clone(&ctx.entry_point);
        let mut cx = RoutedCx {
            session,
            table: &table,
            app,
            selected,
            forwarded: &ctx.forwarded,
            tls,
            entry_point: &entry_point,
            tenant: tenant.as_ref(),
            cache: &self.cache,
            alt_svc: self.alt_svc.as_ref(),
            original: None,
            pages: Vec::new(),
            credentialed: false,
        };
        let flow =
            middleware::run_routed(app.stages(), router.chain(), &mut cx, &mut ctx.chain).await?;
        if flow == Flow::Respond {
            ctx.chain_answered = true;
        }
        Ok(flow == Flow::Respond)
    }

    /// Tells the router's middleware chain the request is over.
    fn finish_chain(&self, session: &Session, error: Option<&Error>, ctx: &mut Ctx) {
        let table = Arc::clone(&ctx.table);
        let Some((app, router)) = ctx.matched.and_then(|matched| table.router(matched)) else {
            return;
        };
        if router.chain().is_empty() {
            return;
        }
        let status = if ctx.capacity_refusal {
            None
        } else {
            session
                .response_written()
                .map(|response| response.status.as_u16())
        };
        let cx = middleware::FinishCx {
            events: &self.events,
            status,
            upstream_error: error.is_some_and(|err| err.esource == ErrorSource::Upstream),
        };
        middleware::run_finished(app.stages(), router.chain(), &cx, &mut ctx.chain);
    }

    /// The page the router's chain offers for a response with `status`, fetched at most once
    /// per request ([`errors::Attempt`] is the loop guard) and never for `HEAD`. `None` leaves
    /// the response as it is: no page for this status, no tenant to charge, or a failed fetch.
    async fn error_page(
        &self,
        request: &RequestHeader,
        ctx: &mut Ctx,
        status: u16,
    ) -> Option<errors::Page> {
        if ctx.error_page != errors::Attempt::Untried {
            return None;
        }
        ctx.error_page = errors::Attempt::Tried;
        if request.method == Method::HEAD {
            return None;
        }
        let table = Arc::clone(&ctx.table);
        let (app, router) = ctx.matched.and_then(|matched| table.router(matched))?;
        if router.chain().is_empty() {
            return None;
        }
        let cx = middleware::PageCx {
            request,
            app,
            revision: ctx.route.as_ref().map(|selected| selected.revision),
            status,
            tenant: ctx.tenant_slot.as_ref()?.tenant(),
            policy: &self.upstream_policy,
            fetcher: &self.page_fetcher,
        };
        middleware::run_page(app.stages(), router.chain(), &cx).await
    }

    /// Writes `page` as the response with `status`: its content type and length, the cookies
    /// podgate sets itself and the chain's response hooks, then the body.
    async fn write_page(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        status: u16,
        page: &errors::Page,
    ) -> pingora::Result<()> {
        let mut head = ResponseHeader::build(status, Some(3))?;
        if let Some(content_type) = page.content_type() {
            head.insert_header("content-type", content_type.clone())?;
        }
        head.insert_header("content-length", page.body().len().to_string())?;
        skew::set_cookie(session, &ctx.table, ctx.route.as_ref(), &mut head)?;
        sticky::set_cookie(session, &ctx.table, ctx.route.as_ref(), &mut head)?;
        let table = Arc::clone(&ctx.table);
        if let Some((app, router)) = ctx.matched.and_then(|matched| table.router(matched)) {
            middleware::run_response(app.stages(), router.chain(), &mut head, &mut ctx.chain)?;
        }
        session.write_response_header(Box::new(head), false).await?;
        session
            .write_response_body(Some(page.body().clone()), true)
            .await
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
            access: access_log::Pending::new(),
            metrics: metrics::InFlight::begin(&self.entry),
            trace: trace::State::default(),
            error_page: errors::Attempt::default(),
            mirror: mirroring::State::default(),
            body_held: false,
            retry: retry::Progress::default(),
            tunnel: extras::State::default(),
        }
    }

    /// The response cache revalidates through a subrequest (`cache::refresh`).
    fn allow_spawning_subrequest(&self, _session: &Session, _ctx: &Ctx) -> bool {
        true
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> pingora::Result<bool> {
        // A cache refresh subrequest has no connection of its own: it carries what the request
        // that spawned it knew, and skips the checks that read the client's connection.
        let inherited = cache::refresh::inherited(session);
        if let Some(inherited) = &inherited {
            ctx.entry_point = Arc::clone(&inherited.entry_point);
        }
        // Before routing: a validation request names a host that may have no route yet.
        if inherited.is_none() && acme::serve_challenge(session, &ctx.table).await? {
            return Ok(true);
        }
        // The entry point's policy: head limits and header rules first, then the session timeouts.
        let table = Arc::clone(&ctx.table);
        let policy = table.entry_policy(&ctx.entry_point);
        if inherited.is_none() {
            if let Err(err) = policy.check_head(session.req_header_mut()) {
                respond::write_error(session, &err).await?;
                return Ok(true);
            }
            policy.apply_timeouts(session);
        }
        // Before matching: the path that is matched is the path that is served.
        let tls = inherited
            .as_ref()
            .map_or_else(|| entry::is_tls(session), |inherited| inherited.tls);
        if let Err(refused) =
            entry::normalize_request(session.req_header_mut(), policy.allow_encoded_slash())
        {
            let err = AppError::BadRequest(refused.to_string().into());
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        // Whatever the route: no client-supplied certificate header ever reaches an upstream.
        middleware::pass_tls_client_cert::strip(session.req_header_mut());
        crate::spiffe::strip(session.req_header_mut());
        ctx.forwarded = match &inherited {
            Some(inherited) => inherited.forwarded.clone(),
            None => ForwardedView::of(session, tls, ctx.table.forwarded_trust(&ctx.entry_point)),
        };
        // The entry point may answer every request with a redirect, before routing. A refresh
        // subrequest was not redirected, or it would not exist.
        if inherited.is_none() && policy.redirect(session, &ctx.forwarded).await? {
            return Ok(true);
        }
        let found = route::matching(
            &ctx.table,
            session.req_header(),
            &ctx.entry_point,
            tls,
            ctx.forwarded.known_client(),
            Hello {
                server_name: sni::server_name(session),
                alpn: &[],
                version: session
                    .digest()
                    .and_then(|digest| digest.ssl_digest.as_ref())
                    .map(|tls| &*tls.version),
            },
        );
        // Right after matching and before anything answers: a misdirected request gets `421`
        // whether or not a router matched, and the matched app decides fronting.
        if inherited.is_none()
            && let Err(err) = sni::check(session, &ctx.table, found)
        {
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        // The TLS options of the matched app (version, suite, ALPN), judged on what the
        // connection negotiated.
        if let Err(err) = tls::enforce(session, &ctx.table, found) {
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        // Right after the match: the app the router really belongs to decides whether a client
        // certificate is required, however the router matched (exact host, regexp, no host).
        if inherited.is_none()
            && let Err(err) = clientauth::admit(session, &ctx.table, found)
        {
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        if inherited.is_none() {
            clientauth::forward_spiffe_id(session, &ctx.table, found)?;
        }
        let Some(mut matched) = found else {
            respond::write_error(session, &AppError::from(RouteError::NoRoute)).await?;
            return Ok(true);
        };
        ctx.matched = Some(matched);
        trace::begin(&self.tracer, session, ctx);
        let keep_bodies = ctx
            .table
            .app(matched.app)
            .is_some_and(crate::table::CompiledApp::record_bodies);
        ctx.failures.begin(keep_bodies);
        // Before the chain, so a `headers` middleware can still override the headers and a
        // `wasm` filter sees them.
        let set = ctx
            .table
            .app(matched.app)
            .map(crate::table::CompiledApp::forwarded)
            .unwrap_or_default();
        match forwarded::apply(
            session.req_header_mut(),
            &ctx.forwarded,
            set,
            self.node.as_ref(),
        ) {
            Ok(()) => {}
            Err(forwarded::Error::Set(err)) => return Err(err),
            Err(refused @ forwarded::Error::Nominated(_)) => {
                let err = AppError::BadRequest(refused.to_string().into());
                ctx.access.refused(&err);
                respond::write_error(session, &err).await?;
                return Ok(true);
            }
        }
        // The tenant's chain, before any slot is taken or app woken.
        if self.run_chain(session, ctx, matched).await? {
            return Ok(true);
        }
        let mut attempts = 0;
        loop {
            let (selected, lease) = match route::select(
                &ctx.table,
                matched,
                session.req_header(),
                ctx.forwarded.known_client(),
            ) {
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
                        ctx.access.refused(&err);
                        respond::write_error(session, &err).await?;
                        return Ok(true);
                    }
                    ctx.matched = Some(matched);
                    continue;
                }
                Err(err) => {
                    let err = AppError::from(err);
                    ctx.access.refused(&err);
                    respond::write_error(session, &err).await?;
                    return Ok(true);
                }
            };
            let (serves_static, serves_fastcgi) =
                ctx.table.app(selected.app).map_or((false, false), |app| {
                    (
                        app.static_site(selected.revision, selected.router)
                            .is_some(),
                        app.fastcgi_site(selected.revision, selected.router)
                            .is_some(),
                    )
                });
            let serves_files = serves_static || serves_fastcgi;
            // The revision and server are chosen: a middleware may answer from its own store
            // before any slot is taken. The lease drops with the answer.
            if self
                .run_routed(session, ctx, matched, &selected, tls)
                .await?
            {
                return Ok(true);
            }
            if let Some(guard) = self.inflight.admit(&ctx.table, &selected) {
                match self
                    .wake
                    .admit(&mut ctx.wake, &self.budgets, &ctx.table, selected.app)
                {
                    Ok(slot) => ctx.tenant_slot = slot,
                    Err(err) => {
                        ctx.capacity_refusal = err.is_capacity_refusal();
                        ctx.access.refused(&err);
                        respond::write_error(session, &err).await?;
                        return Ok(true);
                    }
                }
                if !serves_files {
                    match self.backends.admit(&ctx.table, &selected).await {
                        Ok(slot) => ctx.backend = slot,
                        Err(err) => {
                            ctx.capacity_refusal = err.is_capacity_refusal();
                            ctx.access.refused(&err);
                            respond::write_error(session, &err).await?;
                            return Ok(true);
                        }
                    }
                }
                ctx.route = Some(selected);
                ctx.lease = Some(lease);
                ctx.inflight = Some(guard);
                if serves_files {
                    // No server to dial, no backend slot to take: answer from the directory.
                    if serves_fastcgi {
                        serve_fastcgi(self, &self.budgets, self.upstream_timeout, session, ctx)
                            .await?;
                    } else {
                        serve_static(self, &self.static_reads, &self.budgets, session, ctx).await?;
                    }
                    return Ok(true);
                }
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
        session: &mut Session,
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
        ctx.trace.inject(upstream_request)?;
        // Last: the copy of the request is the upstream request as it goes out.
        mirroring::begin(
            &self.backends,
            &self.upstream_policy,
            session,
            upstream_request,
            ctx,
        );
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        ctx.failures.upstream_response(upstream_response);
        // An error page replaces the whole response, its headers and body. It is written here
        // and the request then ends with an error, so Pingora sends nothing more: an upstream
        // response with no body never reaches `response_body_filter`, which could not carry it.
        let status = upstream_response.status.as_u16();
        if let Some(page) = self.error_page(session.req_header(), ctx, status).await {
            self.write_page(session, ctx, status, &page).await?;
            ctx.error_page = errors::Attempt::Replaced;
            return Err(Error::explain(
                HTTPStatus(status),
                "replaced by an error page",
            ));
        }
        // Before compression: the chain judges the response as the upstream sent it.
        if let Some((app, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) {
            let cx = middleware::ResponseCx {
                request: session.req_header(),
                response: upstream_response,
                tenant: ctx.tenant_slot.as_ref().map(TenantSlot::tenant),
            };
            let head =
                middleware::run_response_head(app.stages(), router.chain(), &cx, &mut ctx.chain);
            if let Err(err) = head {
                ctx.capacity_refusal = err.is_capacity_refusal();
                return Err(respond::abort(session, &err).await);
            }
        }
        if let Some(slot) = &ctx.tenant_slot {
            let settings = ctx
                .matched
                .and_then(|matched| ctx.table.router(matched))
                .and_then(|(app, router)| middleware::compression(app.stages(), router.chain()))
                .unwrap_or_else(|| compress::Settings::platform());
            ctx.compression = compress::start(
                session.req_header(),
                upstream_response,
                slot.tenant(),
                settings,
            );
        }
        let mut complete = None;
        if let Some((app, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) {
            middleware::run_response(
                app.stages(),
                router.chain(),
                upstream_response,
                &mut ctx.chain,
            )?;
            complete =
                middleware::run_response_complete(app.stages(), router.chain(), &mut ctx.chain);
        }
        // A head that is all the upstream sent (a gRPC trailers-only response) ends the stream
        // before any body task exists, so no body hook could add the body a stage needs. Like an
        // error page, it is written here and the request then ends with an error Pingora does
        // not send.
        if let Some(body) = complete {
            let mut head = upstream_response.clone();
            // As Pingora does for every response it forwards from an HTTP/2 upstream.
            head.set_version(http::Version::HTTP_11);
            session.write_response_header(Box::new(head), false).await?;
            session.write_response_body(Some(body), true).await?;
            ctx.error_page = errors::Attempt::Replaced;
            return Err(Error::explain(
                HTTPStatus(status),
                "completed by a middleware",
            ));
        }
        // Last, so a Cache-Control that the chain set counts: see `shared_cacheable`.
        skew::set_cookie(session, &ctx.table, ctx.route.as_ref(), upstream_response)?;
        sticky::set_cookie(session, &ctx.table, ctx.route.as_ref(), upstream_response)?;
        if let (Some(alt_svc), Some((app, _))) = (
            &self.alt_svc,
            ctx.matched.and_then(|matched| ctx.table.router(matched)),
        ) {
            alt_svc.apply(upstream_response, app);
        }
        Ok(())
    }

    /// The body is over but its last DATA frame did not say so: the encoder is finished here,
    /// as at a normal end. Its last bytes go through the chain's body hooks like every other
    /// compressed byte, so a stage that holds the body back holds them too, then the chain
    /// releases what it holds.
    fn response_body_before_trailers(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<Option<Bytes>> {
        let mut tail = None;
        compress::filter(&mut ctx.compression, &mut tail, true)
            .map_err(|err| Error::because(InternalError, "compression failed", err))?;
        let Some((app, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) else {
            return Ok(tail);
        };
        if tail.is_some() {
            middleware::run_response_body(
                app.stages(),
                router.chain(),
                &mut tail,
                false,
                &mut ctx.chain,
            )?;
        }
        let released =
            middleware::run_response_before_trailers(app.stages(), router.chain(), &mut ctx.chain)?;
        // What a stage held back is older than the encoder's last bytes.
        Ok(match (released, tail) {
            (Some(held), Some(tail)) => Some(Bytes::from([held, tail].concat())),
            (held, tail) => held.or(tail),
        })
    }

    async fn response_trailer_filter(
        &self,
        _session: &mut Session,
        trailers: &mut HeaderMap,
        ctx: &mut Ctx,
    ) -> pingora::Result<Option<Bytes>> {
        Ok(ctx
            .matched
            .and_then(|matched| ctx.table.router(matched))
            .and_then(|(app, router)| {
                middleware::run_response_trailers(
                    app.stages(),
                    router.chain(),
                    trailers,
                    &mut ctx.chain,
                )
            }))
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
            .map_err(|err| Error::because(InternalError, "compression failed", err))?;
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
            ctx.access.upstream_done();
            ctx.trace.upstream_done();
        }
        Ok(None)
    }

    fn suppress_error_log(&self, _session: &Session, ctx: &Ctx, _error: &Error) -> bool {
        // A tunnel ended by its own limit is not an error worth an `ERROR` line.
        ctx.error_page == errors::Attempt::Replaced || ctx.tunnel.limit_fired()
    }

    async fn fail_to_proxy(&self, session: &mut Session, e: &Error, ctx: &mut Ctx) -> FailToProxy {
        // Pingora's own choice of status, so a page replaces exactly the answer it would send,
        // but for an upstream timeout, which is a `504`.
        let code = match e.etype() {
            HTTPStatus(code) => *code,
            _ => match e.esource() {
                ErrorSource::Upstream if crate::service::timed_out(e) => 504,
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    WriteError | ReadError | ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };
        if code > 0 {
            // An error podgate made on the way to or from the upstream, with nothing written
            // yet: the chain may offer a page for it.
            let proxying = ctx.route.is_some() && *e.esource() != ErrorSource::Downstream;
            if proxying
                && session.response_written().is_none()
                && let Some(page) = self.error_page(session.req_header(), ctx, code).await
                && self.write_page(session, ctx, code, &page).await.is_ok()
            {
                return FailToProxy {
                    error_code: code,
                    can_reuse_downstream: false,
                };
            }
            session.respond_error(code).await.unwrap_or_else(|err| {
                tracing::error!("failed to send error response to downstream: {err}");
            });
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Ctx) {
        // A replaced response ends with the synthetic error `response_filter` returns; the
        // observers judge the response that was written, not that error.
        let error = error.filter(|_| ctx.error_page != errors::Attempt::Replaced);
        ctx.tunnel.finished(error);
        self.failures.log(session, ctx);
        outlier::observe(session, error, ctx);
        outcomes::record_request(&self.outcomes, session, ctx);
        if let Some(status) = session.response_written().map(|head| head.status.as_u16()) {
            ctx.metrics
                .finish(&ctx.table, ctx.matched, ctx.route.is_some(), status);
        }
        self.finish_chain(session, error, ctx);
        mirroring::finish(ctx);
        access_log::log(self.access_log.as_ref(), session, ctx);
        trace::finish(&self.tracer, session, error, ctx);
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
        retry::begin_attempt(&self.backends, session, ctx).await?;
        let selected = ctx
            .route
            .ok_or_else(|| Error::explain(InternalError, "upstream_peer without a route"))?;
        // The one place a proxied request dials: every address, whatever produced it, is checked.
        self.check_upstream(&ctx.table, &selected)?;
        ctx.trace.upstream_starting();
        let outside = || Error::explain(InternalError, "route points outside the table");
        let service = ctx
            .table
            .app(selected.app)
            .and_then(|app| app.leaf(&selected))
            .ok_or_else(outside)?;
        // The servers of a name follow its DNS answers: the one picked may have just left.
        let (mut peer, pool_key, extras) = service
            .with_upstream(selected.upstream, |upstream| {
                let peer = upstream.http_peer(self.upstream_timeout);
                let key = upstream.pool_key(&peer);
                (peer, key, upstream.extras())
            })
            .ok_or_else(|| {
                Error::explain(HTTPStatus(503), "the upstream server left its service")
            })?;
        // Pingora's HTTP/2 client has no Upgrade: a WebSocket request asks the TLS server for
        // HTTP/1.1 even when the transport offers h2.
        if session.is_upgrade_req() && matches!(peer.options.alpn, ALPN::H2H1) {
            peer.options.alpn = ALPN::H1;
        }
        let identity = pool::Identity::of(&ctx.table, &selected, pool_key).ok_or_else(outside)?;
        pool::observe(&mut ctx.pool, session.req_header());
        // A PROXY protocol header names the client, so its connection belongs to that client
        // address alone.
        let mut client = None;
        if let Some(version) = extras.proxy_protocol {
            client = session
                .client_addr()
                .and_then(|addr| addr.as_inet().copied());
            let server = session
                .server_addr()
                .and_then(|addr| addr.as_inet().copied());
            extras::set_client_header(&mut peer, version, client, server);
        }
        pool::isolate(&mut peer, identity, ctx.pool, session, client);
        if session.is_upgrade_req() {
            ctx.tunnel.plan(extras.tunnel);
        }
        Ok(Box::new(peer))
    }

    fn tunnel(&self, _session: &Session, ctx: &mut Ctx) -> Option<pingora::proxy::Tunnel> {
        ctx.tunnel.hook()
    }

    fn fail_to_connect(
        &self,
        session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if let Some(retry) = self.retry_after(session, ctx, Failure::Connect) {
            e.set_retry(retry);
        }
        e
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut Ctx,
        client_reused: bool,
    ) -> Box<Error> {
        let mut e = e.more_context(format!("Peer: {peer}"));
        e.retry.decide_reuse(client_reused);
        // A protocol downgrade retries on the same server and a client that went away is no
        // server's failure: neither is for the chain to judge.
        let judged = e.retry()
            && *e.esource() != ErrorSource::Downstream
            && !matches!(e.etype, H2Downgrade | InvalidH2);
        let decided = judged
            .then(|| self.retry_after(session, ctx, Failure::Reused))
            .flatten();
        match decided {
            Some(retry) => e.set_retry(retry),
            // No `retry` middleware: Pingora's own rule.
            None if !session.req_header().method.is_idempotent()
                || session.retry_buffer_truncated() =>
            {
                e.set_retry(false);
            }
            None => {}
        }
        e
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
        ctx.access.upstream_connected();
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        let status = upstream_response.status.as_u16();
        if status == 101 && session.is_upgrade_req() {
            let read = ctx.table.entry_policy(&ctx.entry_point).read_timeout();
            let key = ctx
                .route
                .as_ref()
                .and_then(|selected| extras::Key::of(&ctx.table, selected));
            ctx.tunnel.opened(session, read, &self.table, key);
        }
        ctx.backend.responded(status);
        if let Some(lease) = &mut ctx.lease {
            lease.responded(status);
        }
        ctx.access.upstream_responded();
        ctx.trace.upstream_responded(status);
        Ok(())
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        ctx.failures.request_chunk(body.as_ref());
        mirroring::tee(
            &self.backends,
            &self.upstream_policy,
            body.as_ref(),
            end_of_stream,
            ctx,
        );
        if let Some((app, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) {
            let read = u64::try_from(session.body_bytes_read()).unwrap_or(u64::MAX);
            let counted =
                middleware::run_request_body(app.stages(), router.chain(), read, &mut ctx.chain);
            if let Err(err) = counted {
                return Err(respond::abort(session, &err).await);
            }
            let chunk = middleware::run_request_body_chunk(
                app.stages(),
                router.chain(),
                body,
                end_of_stream,
                &mut ctx.chain,
            );
            if let Err(err) = chunk {
                return Err(respond::abort(session, &err).await);
            }
        }
        Ok(())
    }
}
