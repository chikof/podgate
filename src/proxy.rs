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
use pingora::Error;
use pingora::ErrorType::InternalError;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::error::AppError;
use crate::respond;
use crate::route::{self, Selected};
use crate::sni;
use crate::table::{RoutingTable, TableHandle};

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
}

/// The reverse proxy logic: one instance serves every listener.
#[derive(Debug)]
pub struct Gateway {
    table: TableHandle,
    upstream_timeout: Duration,
}

impl Gateway {
    /// Creates a gateway that routes with the live table behind `table`. Connecting to, writing
    /// to and reading from an upstream each give up after `upstream_timeout`.
    #[must_use]
    pub fn new(table: TableHandle, upstream_timeout: Duration) -> Self {
        Self {
            table,
            upstream_timeout,
        }
    }
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx {
            table: self.table.load(),
            route: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> pingora::Result<bool> {
        // Before routing: a misdirected request learns nothing about the route it named.
        if let Err(err) = sni::check(session, &ctx.table) {
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
        match route::resolve(&ctx.table, session.req_header()) {
            Ok(selected) => {
                ctx.route = Some(selected);
                Ok(false)
            }
            Err(err) => {
                respond::write_error(session, &AppError::from(err)).await?;
                Ok(true)
            }
        }
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
