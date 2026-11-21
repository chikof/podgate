//! The Pingora application of one `tcp` entry point.
//!
//! Pingora's listening service accepts the connection and hands its `Stream` to
//! [`ServerApp::process_new`]; its accept loop, TCP options and shutdown signal stay Pingora's.
//! Servers are reached through [`TransportConnector::new_stream`] on a `BasicPeer` (a cleartext
//! TCP peer), so the dial timeout, the socket options and the connect path are Pingora's too.
//!
//! One connection:
//!
//! 1. The client address (the PROXY protocol source when the entry point has the header gate)
//!    picks the router among the routers of the live table that listen here.
//! 2. It takes a `max_inflight` slot of the router's tenant and charges its two copy buffers to
//!    `max_buffer_bytes`; either refusal closes it at once.
//! 3. It tries up to [`CONNECT_ATTEMPTS`] servers: the balancer picks one (skipping the ones
//!    already tried), the upstream address policy checks its exact address, and that address is
//!    dialled. A failed dial moves on to the next server. No byte of the client has been read
//!    into a server by then, which is why a retry is safe; after a connect succeeds there is no
//!    retry, whatever happens next.
//! 4. [`super::copy::relay`] copies both ways until the connection ends.
//!
//! The table the connection routed by is let go before the copy starts: a connection that
//! outlives a snapshot holds its server's lease, its slot and its buffers, and nothing of the
//! table. A snapshot that removes its router or service therefore changes what new connections
//! do and lets this one finish.
//!
//! A PROXY protocol header towards the server goes on the stream `dial` returns,
//! before `relay` copies the first byte.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::apps::ServerApp;
use pingora::connectors::TransportConnector;
use pingora::http::RequestHeader;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use pingora::upstreams::peer::BasicPeer;
use tokio::time::timeout;

use super::copy::relay;
use super::stats::{Refused, STATS};
use super::{CONNECT_ATTEMPTS, CONNECTION_BYTES, Router, Service};
use crate::budget::Budgets;
use crate::client_ip::normalize;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::table::{CompiledApp, RoutingTable, TableHandle};

/// Where a router of this entry point is in the table the plan was built from.
#[derive(Debug, Clone, Copy)]
struct Route {
    app: usize,
    router: usize,
}

/// The routers of one entry point in one table, best first. Rebuilt when the table is swapped.
#[derive(Debug)]
struct Plan {
    /// The table it was built from. A `Weak`, so a plan does not keep an old table alive, and
    /// its allocation lives as long as the plan, so its address cannot name another table.
    table: Weak<RoutingTable>,
    routes: Box<[Route]>,
}

impl Plan {
    fn empty() -> Self {
        Self {
            table: Weak::new(),
            routes: Box::default(),
        }
    }

    fn of(table: &Arc<RoutingTable>, entry_point: &str) -> Self {
        let mut routes: Vec<(Route, (bool, u32))> = table
            .apps()
            .iter()
            .enumerate()
            .flat_map(|(app, compiled)| {
                compiled
                    .l4()
                    .tcp()
                    .routers()
                    .iter()
                    .enumerate()
                    .filter(|(_, router)| router.listens_on(entry_point))
                    .map(move |(router_at, router)| {
                        (
                            Route {
                                app,
                                router: router_at,
                            },
                            router.rank(),
                        )
                    })
            })
            .collect();
        routes.sort_by_key(|(_, rank)| std::cmp::Reverse(*rank));
        Self {
            table: Arc::downgrade(table),
            routes: routes.into_iter().map(|(route, _)| route).collect(),
        }
    }
}

/// Why a server could not be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dial {
    /// The upstream address policy refused the address.
    Forbidden,
    /// The connect failed or timed out.
    Failed,
}

/// The application of one `tcp` entry point.
pub struct App {
    entry_point: Box<str>,
    table: TableHandle,
    budgets: Budgets,
    policy: UpstreamPolicy,
    connector: TransportConnector,
    /// The request head the matcher and balancer interfaces ask for; no TCP code reads it.
    probe: RequestHeader,
    /// How long one connect may take.
    dial: Duration,
    /// How long a connection may go on after shutdown began.
    grace: Duration,
    plan: ArcSwap<Plan>,
}

impl App {
    /// The application of the entry point called `entry_point`: routes by the live `table`,
    /// charges `budgets`, checks every address against `policy` before dialling it. `timeout`
    /// bounds a connect and is the grace a live connection gets at shutdown
    /// (`REQUEST_TIMEOUT_SECS`).
    ///
    /// # Errors
    ///
    /// Pingora's error when the placeholder request head cannot be built.
    pub fn new(
        entry_point: &str,
        table: TableHandle,
        budgets: Budgets,
        policy: UpstreamPolicy,
        timeout: Duration,
    ) -> pingora::Result<Self> {
        Ok(Self {
            entry_point: entry_point.into(),
            table,
            budgets,
            policy,
            connector: TransportConnector::new(None),
            probe: RequestHeader::build("GET", b"/", None)?,
            dial: timeout,
            grace: timeout,
            plan: ArcSwap::from_pointee(Plan::empty()),
        })
    }

    /// The routers of the entry point in `live`, best first.
    fn plan(&self, live: &Arc<RoutingTable>) -> Arc<Plan> {
        let plan = self.plan.load_full();
        if std::ptr::eq(plan.table.as_ptr(), Arc::as_ptr(live)) {
            return plan;
        }
        let fresh = Arc::new(Plan::of(live, &self.entry_point));
        self.plan.store(Arc::clone(&fresh));
        fresh
    }

    /// The router that takes a connection from `client`, with its app and service.
    fn route<'a>(
        &self,
        live: &'a RoutingTable,
        plan: &Plan,
        client: IpAddr,
    ) -> Option<(&'a CompiledApp, &'a Router, &'a Service)> {
        plan.routes.iter().find_map(|route| {
            let app = live.app(route.app)?;
            let (router, service) = app.l4().tcp().route(route.router)?;
            router
                .matches(&self.entry_point, client, &self.probe)
                .then_some((app, router, service))
        })
    }

    /// Connects to `addr` for `tenant`, after the policy has checked the exact address.
    async fn dial(&self, tenant: &str, addr: SocketAddr) -> Result<Stream, Dial> {
        if self.policy.check(tenant, addr.ip()).is_err() {
            return Err(Dial::Forbidden);
        }
        let mut peer = BasicPeer::new(&addr.to_string());
        peer.options.connection_timeout = Some(self.dial);
        peer.options.total_connection_timeout = Some(self.dial);
        match timeout(self.dial, Box::pin(self.connector.new_stream(&peer))).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(err)) => {
                tracing::debug!(%addr, %err, "cannot connect to a TCP server");
                Err(Dial::Failed)
            }
            Err(_) => {
                tracing::debug!(%addr, "connecting to a TCP server timed out");
                Err(Dial::Failed)
            }
        }
    }

    async fn serve(&self, mut client: Stream, shutdown: ShutdownWatch) {
        STATS.accepted();
        let Some(peer) = client
            .get_socket_digest()
            .and_then(|digest| digest.peer_addr().and_then(|addr| addr.as_inet().copied()))
            .map(|addr| normalize(addr.ip()))
        else {
            STATS.refused(Refused::NoRoute);
            return;
        };
        let live = self.table.load();
        let plan = self.plan(&live);
        let Some((app, _, service)) = self.route(&live, &plan, peer) else {
            STATS.refused(Refused::NoRoute);
            return;
        };
        let tenant = app.tenant();
        let Some(limits) = live.tenant_budget(tenant) else {
            STATS.refused(Refused::NoRoute);
            return;
        };
        let account = self.budgets.tenant(tenant, limits);
        let Some(_slot) = account.admit() else {
            STATS.refused(Refused::OverInflight);
            return;
        };
        let Some(_bytes) = account.charge(CONNECTION_BYTES) else {
            STATS.refused(Refused::OverBudget);
            return;
        };
        let mut tried = Vec::with_capacity(CONNECT_ATTEMPTS);
        let mut forbidden = 0_usize;
        let connected = loop {
            if tried.len() == CONNECT_ATTEMPTS {
                break None;
            }
            let Some((addr, lease)) = service.pick(Some(peer), &tried, &self.probe) else {
                break None;
            };
            tried.push(addr);
            match self.dial(tenant, addr).await {
                Ok(stream) => break Some((stream, lease)),
                Err(Dial::Forbidden) => forbidden += 1,
                Err(Dial::Failed) => STATS.connect_failed(),
            }
        };
        let idle = service.idle();
        drop(live);
        let Some((mut server, _lease)) = connected else {
            STATS.refused(if forbidden > 0 && forbidden == tried.len() {
                Refused::UpstreamForbidden
            } else {
                Refused::NoServer
            });
            return;
        };
        let _open = Open::new();
        STATS.closed(relay(&mut client, &mut server, idle, shutdown, self.grace).await);
    }
}

/// A connection that reached a server, counted open until it drops.
struct Open;

impl Open {
    fn new() -> Self {
        STATS.opened();
        Self
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        STATS.ended();
    }
}

#[async_trait]
impl ServerApp for App {
    async fn process_new(
        self: &Arc<Self>,
        client: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        self.serve(client, shutdown.clone()).await;
        None
    }
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("entry_point", &self.entry_point)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod test {
    use tokio::net::TcpListener;

    use super::*;
    use crate::entry::{CompileContext, Protocol};

    fn app(policy: UpstreamPolicy) -> App {
        App::new(
            "pg",
            TableHandle::with_context(CompileContext::new([("pg", Protocol::Tcp)])),
            Budgets::new(),
            policy,
            Duration::from_secs(2),
        )
        .expect("app")
    }

    #[tokio::test]
    async fn tcp_dial_obeys_upstream_policy_at_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let denying = UpstreamPolicy::parse(r#"{"deny": ["127.0.0.0/8"]}"#).expect("policy");
        assert_eq!(
            app(denying).dial("t", addr).await.err(),
            Some(Dial::Forbidden)
        );
        let allowing = app(UpstreamPolicy::allow_all());
        assert!(allowing.dial("t", addr).await.is_ok());
        // A closed port is a failed connect, not a refusal of the policy.
        drop(listener);
        assert_eq!(allowing.dial("t", addr).await.err(), Some(Dial::Failed));
    }
}
