//! The Pingora application of one `tcp` entry point.
//!
//! Pingora's listening service accepts the connection and hands its `Stream` to
//! [`ServerApp::process_new`]; its accept loop, TCP options and shutdown signal stay Pingora's.
//! Servers are reached through [`TransportConnector::new_stream`] on an `HttpPeer`: a cleartext
//! TCP peer, or a TLS one for a server with `tls: true` (see [`crate::l4::upstream`]), so the dial
//! timeout, the socket options and the connect path are Pingora's too.
//!
//! One connection:
//!
//! 1. When a router of the entry point has `tls`, the start of the connection is
//!    read first: [`super::super::tls::peek`] reads the ClientHello (5 seconds, 16 KiB) and the
//!    router's `sni`, `sni_regexp` and `alpn` leaves match what it offered. The PROXY protocol
//!    header, when the entry point has the gate, was read before this, by `Fronted`.
//! 2. The client address (the PROXY protocol source when the entry point has the header gate)
//!    and that offer pick the router among the routers of the live table that listen here. A
//!    router with `tls` that is not limited to literal server names never takes a name another
//!    tenant claims.
//! 3. The router's `chain` runs on the client address (`ip_allow_list`,
//!    `in_flight_conn`), before the tenant's slot is taken and before any server is dialled; a
//!    refused connection is closed without a byte and counted. Then it takes a `max_inflight`
//!    slot of the router's tenant and charges its two copy buffers to `max_buffer_bytes`; either
//!    refusal closes it at once. The bytes read in step 1 go back to the stream, and a
//!    terminating router (`tls` without `passthrough`) runs the TLS handshake with the app's
//!    certificates and `client_auth` before any server is dialled.
//! 4. It tries up to [`CONNECT_ATTEMPTS`] servers: the balancer picks one (skipping the ones
//!    already tried), the upstream address policy checks its exact address, and that address is
//!    dialled. A failed dial moves on to the next server. No byte of the client has been read
//!    into a server by then, which is why a retry is safe; after a connect succeeds there is no
//!    retry, whatever happens next.
//! 5. [`super::copy::relay`] copies both ways until the connection ends: the client's stream
//!    (the decrypted one for a terminating router) and the server's.
//!
//! The table the connection routed by is let go before the copy starts: a connection that
//! outlives a snapshot holds its server's lease, its slot and its buffers, and nothing of the
//! table. A snapshot that removes its router or service therefore changes what new connections
//! do and lets this one finish.
//!
//! A PROXY protocol header towards the server is written by the dial itself
//! ([`crate::l4::upstream`]): after the TCP connect and before the TLS handshake of a `tls`
//! server, so before the first payload byte, which for a passthrough router is the client's
//! ClientHello.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::apps::ServerApp;
use pingora::connectors::TransportConnector;
use pingora::http::RequestHeader;
use pingora::protocols::GetSocketDigest;
use pingora::protocols::Stream;
use pingora::protocols::l4::socket::SocketAddr as PingoraAddr;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::server::ShutdownWatch;
use pingora::upstreams::peer::HttpPeer;
use tokio::time::timeout;

use super::copy::relay;
use super::stats::{Refused, STATS};
use super::{CONNECT_ATTEMPTS, CONNECTION_BYTES, Router, Service, Tls};
use crate::budget::Budgets;
use crate::client_ip::normalize;
use crate::l4::middleware;
use crate::l4::tls::{self, Cause, Failed, Offer, Owners, Terminator};
use crate::l4::upstream::Flow;
use crate::router::matcher::Spec;
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
    /// Whether some router has `tls`: the connection's start is read before it is routed.
    needs_hello: bool,
    /// Who claims each server name of the table; only built when `needs_hello`.
    owners: Arc<Owners>,
}

impl Plan {
    fn empty() -> Self {
        Self {
            table: Weak::new(),
            routes: Box::default(),
            needs_hello: false,
            owners: Arc::default(),
        }
    }

    fn of(table: &Arc<RoutingTable>, entry_point: &str) -> Self {
        let mut routes: Vec<(Route, (bool, Spec))> = table
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
        let needs_hello = routes.iter().any(|(route, _)| {
            table
                .app(route.app)
                .and_then(|app| app.l4().tcp().routers().get(route.router))
                .is_some_and(|router| router.tls().is_some())
        });
        Self {
            table: Arc::downgrade(table),
            routes: routes.into_iter().map(|(route, _)| route).collect(),
            needs_hello,
            owners: Arc::new(if needs_hello {
                Owners::of(table)
            } else {
                Owners::default()
            }),
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
    terminator: Terminator,
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
    /// charges `budgets`, checks every address against `policy` before dialling it, completes
    /// the handshake of terminating routers with `terminator`. `timeout` bounds a connect and
    /// is the grace a live connection gets at shutdown (`REQUEST_TIMEOUT_SECS`).
    ///
    /// # Errors
    ///
    /// Pingora's error when the placeholder request head cannot be built.
    pub fn new(
        entry_point: &str,
        table: TableHandle,
        budgets: Budgets,
        policy: UpstreamPolicy,
        terminator: Terminator,
        timeout: Duration,
    ) -> pingora::Result<Self> {
        Ok(Self {
            entry_point: entry_point.into(),
            table,
            budgets,
            policy,
            terminator,
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

    /// The router that takes a connection from `client` that offered `offer`, with its app and
    /// service.
    fn route<'a>(
        &self,
        live: &'a RoutingTable,
        plan: &Plan,
        client: IpAddr,
        offer: &Offer,
    ) -> Option<(&'a CompiledApp, &'a Router, &'a Service)> {
        plan.routes.iter().find_map(|route| {
            let app = live.app(route.app)?;
            let (router, service) = app.l4().tcp().route(route.router)?;
            if !router.matches(&self.entry_point, client, &self.probe, offer) {
                return None;
            }
            // A TLS router that is not limited to literal names takes whatever name arrives,
            // so it must leave the names another tenant claims to that tenant's routers.
            let foreign = router.tls().is_some()
                && !router.is_claimed()
                && offer
                    .server_name()
                    .and_then(|name| plan.owners.tenant_of(name))
                    .is_some_and(|owner| owner != app.tenant());
            (!foreign).then_some((app, router, service))
        })
    }

    /// Connects to `addr` for `tenant` through `peer`, after the policy has checked the exact
    /// address. `limit` bounds the connect, the PROXY header and the TLS handshake together.
    async fn dial(
        &self,
        tenant: &str,
        addr: SocketAddr,
        peer: &HttpPeer,
        limit: Duration,
    ) -> Result<Stream, Dial> {
        if self.policy.check(tenant, addr.ip()).is_err() {
            return Err(Dial::Forbidden);
        }
        match timeout(limit, Box::pin(self.connector.new_stream(peer))).await {
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

    async fn serve(&self, mut client: L4Stream, shutdown: ShutdownWatch) {
        STATS.accepted();
        let Some(digest) = client.get_socket_digest() else {
            STATS.refused(Refused::NoRoute);
            return;
        };
        let inet = |addr: Option<&PingoraAddr>| addr.and_then(|addr| addr.as_inet().copied());
        let (Some(source), Some(entry)) = (inet(digest.peer_addr()), inet(digest.local_addr()))
        else {
            STATS.refused(Refused::NoRoute);
            return;
        };
        let peer = normalize(source.ip());
        let flow = Flow {
            client: SocketAddr::new(peer, source.port()),
            entry,
        };
        let live = self.table.load();
        let plan = self.plan(&live);
        let (offer, seen) = if plan.needs_hello {
            match tls::peek(&mut client).await {
                Ok(read) => read,
                Err(Cause::Timeout) => {
                    STATS.refused(Refused::HelloTimeout);
                    return;
                }
                Err(Cause::Invalid) => {
                    STATS.refused(Refused::HelloInvalid);
                    return;
                }
            }
        } else {
            (Offer::none(), Vec::new())
        };
        let Some((app, router, service)) = self.route(&live, &plan, peer, &offer) else {
            STATS.refused(Refused::NoRoute);
            return;
        };
        let tenant = app.tenant();
        let Some(limits) = live.tenant_budget(tenant) else {
            STATS.refused(Refused::NoRoute);
            return;
        };
        let account = self.budgets.tenant(tenant, limits);
        // The chain runs before the tenant's slot, so a connection it refuses costs the tenant
        // nothing; its permits are held until the connection ends.
        let _held =
            match middleware::admit(app.l4().tcp().middlewares(), router.chain(), peer, &account) {
                Ok(held) => held,
                Err(refusal) => {
                    STATS.refused(match refusal {
                        middleware::Refusal::NotAllowed => Refused::IpNotAllowed,
                        middleware::Refusal::OverSource => Refused::OverConnections,
                        middleware::Refusal::OverBudget => Refused::OverBudget,
                    });
                    return;
                }
            };
        let Some(_slot) = account.admit() else {
            STATS.refused(Refused::OverInflight);
            return;
        };
        let Some(_bytes) = account.charge(CONNECTION_BYTES) else {
            STATS.refused(Refused::OverBudget);
            return;
        };
        // The peek buffer is dropped here, once the stream holds its bytes: the connection
        // never has it and the copy buffers at once.
        client.rewind(&seen);
        drop(seen);
        let mut client: Stream = match router.tls() {
            Some(Tls::Terminate) => {
                let accepted = Box::pin(self.terminator.accept(
                    client,
                    &live,
                    &plan.owners,
                    app,
                    &offer,
                    router.protocols(),
                ))
                .await;
                match accepted {
                    Ok(stream) => stream,
                    Err(Failed::Handshake) => {
                        STATS.refused(Refused::TlsHandshake);
                        return;
                    }
                    Err(Failed::Policy) => {
                        STATS.refused(Refused::TlsPolicy);
                        return;
                    }
                    Err(Failed::ClientCert) => {
                        STATS.refused(Refused::ClientCert);
                        return;
                    }
                }
            }
            _ => Box::new(client),
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
            let Some((server, limit)) =
                service
                    .upstream()
                    .peer(service.balancer(), addr, self.dial, flow)
            else {
                // The name the address came from resolved to something else in between.
                STATS.connect_failed();
                continue;
            };
            match self.dial(tenant, addr, &server, limit).await {
                Ok(stream) => break Some((stream, lease)),
                Err(Dial::Forbidden) => forbidden += 1,
                Err(Dial::Failed) => STATS.connect_failed(),
            }
        };
        let idle = service.idle();
        let delay = service.upstream().termination_delay();
        // No attempt was made because the health check has marked every server down.
        let unhealthy = connected.is_none() && tried.is_empty() && service.all_down();
        drop(live);
        let Some((mut server, _lease)) = connected else {
            STATS.refused(if forbidden > 0 && forbidden == tried.len() {
                Refused::UpstreamForbidden
            } else if unhealthy {
                Refused::NoHealthyServer
            } else {
                Refused::NoServer
            });
            return;
        };
        let _open = Open::new();
        STATS.closed(relay(&mut client, &mut server, idle, delay, shutdown, self.grace).await);
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
        // A plaintext listener hands over the accepted socket itself: the TLS bytes are read
        // here, and a stream that is not the socket has nothing to read them from.
        let client = client.into_any().downcast::<L4Stream>().ok()?;
        Box::pin(self.serve(*client, shutdown.clone())).await;
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
    use crate::acme::Acme;
    use crate::entry::{CompileContext, Protocol};
    use crate::events::EventFeed;
    use crate::tls::ocsp::Staples;

    fn app(policy: UpstreamPolicy) -> App {
        let table = TableHandle::with_context(CompileContext::new([("pg", Protocol::Tcp)]));
        let acme = Acme::new(table.clone(), EventFeed::new(), None, None);
        App::new(
            "pg",
            table,
            Budgets::new(),
            policy,
            Terminator::new(acme, Staples::default()).expect("terminator"),
            Duration::from_secs(2),
        )
        .expect("app")
    }

    #[tokio::test]
    async fn tcp_dial_obeys_upstream_policy_at_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let peer = HttpPeer::new(addr, false, String::new());
        let limit = Duration::from_secs(2);
        let denying = UpstreamPolicy::parse(r#"{"deny": ["127.0.0.0/8"]}"#).expect("policy");
        assert_eq!(
            app(denying).dial("t", addr, &peer, limit).await.err(),
            Some(Dial::Forbidden)
        );
        let allowing = app(UpstreamPolicy::allow_all());
        assert!(allowing.dial("t", addr, &peer, limit).await.is_ok());
        // A closed port is a failed connect, not a refusal of the policy.
        drop(listener);
        assert_eq!(
            allowing.dial("t", addr, &peer, limit).await.err(),
            Some(Dial::Failed)
        );
    }
}
