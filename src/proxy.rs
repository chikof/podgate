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

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::Error;
use pingora::ErrorType::InternalError;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::budget::{self, Budgets, TenantSlot};
use crate::compress::{self, Gzip};
use crate::error::AppError;
use crate::inflight::{Inflight, InflightGuard};
use crate::respond;
use crate::route::{self, RouteError, Selected};
use crate::sni;
use crate::table::{RoutingTable, TableHandle};

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
}

/// The reverse proxy logic: one instance serves every listener.
#[derive(Debug)]
pub struct Gateway {
    table: TableHandle,
    inflight: Inflight,
    upstream_timeout: Duration,
    budgets: Budgets,
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
        }
    }

    /// Charges tenants against `budgets`, a registry shared with the admin API's metrics.
    #[must_use]
    pub fn with_budgets(mut self, budgets: Budgets) -> Self {
        self.budgets = budgets;
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
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> pingora::Result<bool> {
        // Before routing: a misdirected request learns nothing about the route it named.
        if let Err(err) = sni::check(session, &ctx.table) {
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        let mut attempts = 0;
        loop {
            let selected = match route::resolve(&ctx.table, session.req_header()) {
                Ok(selected) => selected,
                Err(err) => {
                    respond::write_error(session, &AppError::from(err)).await?;
                    return Ok(true);
                }
            };
            if let Some(guard) = self.inflight.admit(&ctx.table, &selected) {
                match budget::admit(&self.budgets, &ctx.table, selected.app) {
                    Ok(slot) => ctx.tenant_slot = slot,
                    Err(err) => {
                        respond::write_error(session, &err).await?;
                        return Ok(true);
                    }
                }
                ctx.route = Some(selected);
                ctx.inflight = Some(guard);
                return Ok(false);
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
        compress::filter(&mut ctx.compression, body, end_of_stream)
            .map_err(|err| Error::because(InternalError, "gzip encoding failed", err))?;
        Ok(None)
    }

    async fn logging(&self, _session: &mut Session, _error: Option<&Error>, ctx: &mut Ctx) {
        ctx.compression = None;
        ctx.tenant_slot = None;
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<Box<HttpPeer>> {
        let selected = ctx
            .route
            .ok_or_else(|| Error::explain(InternalError, "upstream_peer without a route"))?;
        let mut peer = HttpPeer::new(selected.upstream, false, String::new());
        peer.options.connection_timeout = Some(self.upstream_timeout);
        peer.options.read_timeout = Some(self.upstream_timeout);
        peer.options.write_timeout = Some(self.upstream_timeout);
        Ok(Box::new(peer))
    }
}
