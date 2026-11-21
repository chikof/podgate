//! The socket loop of one `udp` entry point, run as a Pingora background service.
//!
//! One task reads the entry point's socket and owns the session table. A new client costs a
//! session: a connected upstream socket, a task that relays the upstream's datagrams back to the
//! client from the entry point's socket, 4 KiB of the tenant's `max_buffer_bytes` and a slot of
//! the tenant's and the node's session caps. The reservations are taken before the socket is
//! opened and sit in the session's handle ([`Link`]), so every way a session ends (expiry,
//! eviction, a removed server, shutdown) releases them and stops the relay.
//!
//! Nothing is ever queued: a datagram that cannot be forwarded now is dropped and counted. The
//! only path to a client is the relay of its own session, one datagram out for one datagram the
//! upstream sent, so podgate has no way to send to an address the upstream did not answer for.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::net::UdpSocket;
use tokio::task::AbortHandle;
use tokio::time::MissedTickBehavior;

use super::stats::{Close, Dropped, STATS};
use super::table::{Shared, Table};
use super::tenants::{Slot, Tenants};
use super::{DATAGRAM_MAX, SESSION_BYTES};
use crate::budget::{Budgets, BufferGuard};
use crate::service::upstream_policy::UpstreamPolicy;
use crate::table::{RoutingTable, TableHandle};
use podgate_model::Budget;

/// How often idle sessions are looked for. A session is also checked when its client sends.
const SWEEP: Duration = Duration::from_millis(250);

/// Binds the UDP socket of an entry point. Done before the server runs, so a busy address stops
/// the process at startup like a TCP entry point.
///
/// # Errors
///
/// The error of binding `addr` or of making the socket non-blocking.
pub fn bind(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// The UDP service of one entry point.
#[derive(Debug)]
pub struct Listener {
    entry_point: Box<str>,
    socket: std::net::UdpSocket,
    table: TableHandle,
    budgets: Budgets,
    policy: UpstreamPolicy,
    tenants: Tenants,
}

impl Listener {
    /// Serves the entry point called `entry_point` on `socket` (from [`bind`]) with the routers
    /// of the live table. Sessions charge `budgets` and `tenants`, and every upstream is checked
    /// against `policy` before a socket connects to it.
    #[must_use]
    pub fn new(
        entry_point: &str,
        socket: std::net::UdpSocket,
        table: TableHandle,
        budgets: Budgets,
        policy: UpstreamPolicy,
        tenants: Tenants,
    ) -> Self {
        Self {
            entry_point: entry_point.into(),
            socket,
            table,
            budgets,
            policy,
            tenants,
        }
    }
}

#[async_trait]
impl BackgroundService for Listener {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let socket = match self.socket.try_clone().and_then(UdpSocket::from_std) {
            Ok(socket) => Arc::new(socket),
            Err(err) => {
                tracing::error!(entry_point = %self.entry_point, %err, "cannot serve the UDP entry point");
                return;
            }
        };
        tracing::info!(entry_point = %self.entry_point, "UDP entry point ready");
        let mut swapped = self.table.subscribe();
        let mut sweep = tokio::time::interval(SWEEP);
        sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut serving = Serving::new(self, Arc::clone(&socket));
        let mut buf = vec![0_u8; DATAGRAM_MAX + 1];
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = swapped.changed() => serving.refresh(),
                _ = sweep.tick() => serving.maintain(),
                received = socket.recv_from(&mut buf) => match received {
                    Ok((len, from)) => serving.datagram(from, &buf[..len]).await,
                    Err(err) => {
                        STATS.dropped(Dropped::SocketError);
                        tracing::warn!(entry_point = %self.entry_point, %err, "UDP receive failed");
                    }
                },
            }
        }
        serving.close_all();
        tracing::info!(entry_point = %self.entry_point, "UDP entry point stopped");
    }
}

/// Who a session belongs to, to tell after a swap whether the table still says the same.
#[derive(Debug)]
struct Owner {
    tenant: Box<str>,
    app: Box<str>,
    router: Box<str>,
    server: SocketAddr,
}

/// Everything that goes away with a session.
struct Link {
    upstream: Arc<UdpSocket>,
    relay: AbortHandle,
    owner: Owner,
    _slot: Slot,
    _bytes: BufferGuard,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.relay.abort();
        STATS.session_ended();
    }
}

/// Where the router of the entry point is in the live table.
#[derive(Debug, Clone, Copy)]
struct Route {
    app: usize,
    router: usize,
}

/// The state of the loop.
struct Serving<'a> {
    owner: &'a Listener,
    socket: Arc<UdpSocket>,
    sessions: Table<Link>,
    live: Arc<RoutingTable>,
    route: Option<Route>,
    epoch: Instant,
}

impl<'a> Serving<'a> {
    fn new(owner: &'a Listener, socket: Arc<UdpSocket>) -> Self {
        let live = owner.table.load();
        let route = locate(&live, &owner.entry_point);
        Self {
            owner,
            socket,
            sessions: Table::new(),
            live,
            route,
            epoch: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Follows the live table when it was swapped, and closes the sessions it no longer backs.
    fn refresh(&mut self) {
        let live = self.owner.table.load();
        if Arc::ptr_eq(&live, &self.live) {
            return;
        }
        self.route = locate(&live, &self.owner.entry_point);
        self.live = live;
        self.maintain();
    }

    /// Closes the sessions the table no longer backs and those idle for too long.
    fn maintain(&mut self) {
        let now = self.now_ms();
        let live = &self.live;
        let backing = self.route.and_then(|route| resolve(live, route));
        self.sessions.close_where(
            |shared, link| {
                let Some((app, router, service)) = &backing else {
                    return Some(Close::RouterRemoved);
                };
                let owner = &link.owner;
                if *owner.app != *app.id()
                    || *owner.tenant != *app.tenant()
                    || *owner.router != *router.name()
                {
                    Some(Close::RouterRemoved)
                } else if !service.servers().contains(&owner.server) {
                    Some(Close::ServerRemoved)
                } else if shared.idle_ms(now) > millis(service.timeout()) {
                    Some(Close::Expired)
                } else {
                    None
                }
            },
            |reason| STATS.closed(reason),
        );
    }

    fn close_all(&mut self) {
        self.sessions
            .close_where(|_, _| Some(Close::Shutdown), |reason| STATS.closed(reason));
    }

    async fn datagram(&mut self, from: SocketAddr, payload: &[u8]) {
        STATS.received(payload.len());
        if payload.len() > DATAGRAM_MAX {
            STATS.dropped(Dropped::Oversize);
            return;
        }
        if from.ip().is_unspecified() || from.ip().is_multicast() || from.port() == 0 {
            STATS.dropped(Dropped::BadSource);
            return;
        }
        self.refresh();
        let live = Arc::clone(&self.live);
        let Some((app, router, service)) = self.route.and_then(|route| resolve(&live, route))
        else {
            STATS.dropped(Dropped::NoRoute);
            return;
        };
        let now = self.now_ms();
        if let Some((shared, link)) = self.sessions.get(&from) {
            if shared.idle_ms(now) <= millis(service.timeout()) {
                shared.client_sent(now);
                if link.upstream.try_send(payload).is_err() {
                    STATS.dropped(Dropped::SendError);
                }
                return;
            }
            self.sessions.remove(&from);
            STATS.closed(Close::Expired);
        }
        let Some(budget) = live.tenant_budget(app.tenant()) else {
            STATS.dropped(Dropped::NoRoute);
            return;
        };
        match self
            .open(
                from,
                payload,
                (app.tenant(), app.id(), router, service),
                budget,
                now,
            )
            .await
        {
            Ok(link) => {
                STATS.session_opened();
                let shared = link.1;
                self.sessions.insert(from, shared, link.0);
            }
            Err(reason) => STATS.dropped(reason),
        }
    }

    /// Admits a new client: takes the reservations (giving up the oldest single-datagram session once
    /// when the table or a cap is full), checks the policy, connects an upstream socket, sends
    /// the first datagram and starts the relay.
    async fn open(
        &mut self,
        client: SocketAddr,
        first: &[u8],
        (tenant, app, router, service): (&str, &str, &super::Router, &super::Service),
        budget: Budget,
        now: u64,
    ) -> Result<(Link, Arc<Shared>), Dropped> {
        let (slot, bytes) = self.reserve(tenant, router, budget)?;
        let server = service.pick().ok_or(Dropped::NoRoute)?;
        if self.owner.policy.check(tenant, server.ip()).is_err() {
            return Err(Dropped::UpstreamForbidden);
        }
        let upstream = dial(server).await.map_err(|err| {
            tracing::warn!(%server, %err, "cannot open a UDP upstream socket");
            Dropped::SocketError
        })?;
        // `send`, not `try_send`: a fresh socket has not been polled for writability yet, so
        // `try_send` would report `WouldBlock`. It also leaves the socket's readiness known for
        // the `try_send` of this session's later datagrams.
        if upstream.send(first).await.is_err() {
            return Err(Dropped::SendError);
        }
        let shared = Shared::new(first.len(), now);
        let relay = tokio::spawn(relay(
            Arc::clone(&upstream),
            Arc::clone(&self.socket),
            client,
            Arc::clone(&shared),
            router.max_reply_ratio(),
            self.epoch,
        ))
        .abort_handle();
        let link = Link {
            upstream,
            relay,
            owner: Owner {
                tenant: tenant.into(),
                app: app.into(),
                router: router.name().into(),
                server,
            },
            _slot: slot,
            _bytes: bytes,
        };
        Ok((link, shared))
    }

    fn reserve(
        &mut self,
        tenant: &str,
        router: &super::Router,
        budget: Budget,
    ) -> Result<(Slot, BufferGuard), Dropped> {
        let account = self.owner.budgets.tenant(tenant, budget);
        let mut evicted = false;
        loop {
            let refused = if self.sessions.len() >= router.max_sessions() as usize {
                Dropped::TableFull
            } else {
                match self.owner.tenants.acquire(tenant) {
                    Err(reason) => reason,
                    Ok(slot) => match account.charge(SESSION_BYTES) {
                        Some(bytes) => return Ok((slot, bytes)),
                        None => Dropped::OverBudget,
                    },
                }
            };
            // One eviction per newcomer: it frees one session's worth of everything, and a
            // refusal that giving up a session here cannot cure (the cap is held by other entry
            // points) must not empty the single-datagram part of this table.
            if evicted {
                return Err(refused);
            }
            let Some(link) = self.sessions.evict_single() else {
                return Err(refused);
            };
            drop(link);
            STATS.closed(Close::Evicted);
            evicted = true;
        }
    }
}

/// The router, and its service, at `route` in `live`, with the app that owns them.
fn resolve(
    live: &RoutingTable,
    route: Route,
) -> Option<(&crate::table::CompiledApp, &super::Router, &super::Service)> {
    let app = live.app(route.app)?;
    let (router, service) = app.l4().udp().route(route.router)?;
    Some((app, router, service))
}

/// Finds the router of `entry_point` in `live`.
fn locate(live: &RoutingTable, entry_point: &str) -> Option<Route> {
    live.apps().iter().enumerate().find_map(|(app, compiled)| {
        let router = compiled.l4().udp().locate(entry_point)?;
        Some(Route { app, router })
    })
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// A socket connected to `server`, from an ephemeral port on the server's address family.
async fn dial(server: SocketAddr) -> io::Result<Arc<UdpSocket>> {
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(server).await?;
    Ok(Arc::new(socket))
}

/// Carries one session's replies to its client: each datagram the upstream sends goes to the
/// client, once, from the entry point's socket.
async fn relay(
    upstream: Arc<UdpSocket>,
    entry: Arc<UdpSocket>,
    client: SocketAddr,
    shared: Arc<Shared>,
    ratio: Option<u32>,
    epoch: Instant,
) {
    let mut buf = vec![0_u8; DATAGRAM_MAX + 1];
    loop {
        let len = match upstream.recv(&mut buf).await {
            Ok(len) => len,
            // An ICMP port-unreachable of an earlier datagram, reported once on a connected
            // socket; the next datagram may find the server back.
            Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => continue,
            Err(_) => {
                STATS.dropped(Dropped::SocketError);
                return;
            }
        };
        shared.upstream_sent(u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX));
        if len > DATAGRAM_MAX {
            STATS.dropped(Dropped::Oversize);
        } else if !shared.allow_reply(len, ratio) {
            STATS.dropped(Dropped::ReplyRatio);
        } else if entry.send_to(&buf[..len], client).await.is_ok() {
            STATS.sent(len);
        } else {
            STATS.dropped(Dropped::SendError);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::entry::{CompileContext, Protocol};
    use podgate_model::Snapshot;
    use tokio::sync::watch;

    fn table(server: SocketAddr) -> TableHandle {
        let handle = TableHandle::with_context(CompileContext::new([("dns", Protocol::Udp)]));
        let snapshot: Snapshot = serde_json::from_value(serde_json::json!({
            "version": 1,
            "tenants": [{"id": "t", "weight": 1,
                         "budget": {"max_inflight": 10, "max_buffer_bytes": 1_048_576}}],
            "entry_points": [{"name": "dns", "tenants": ["t"]}],
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "test", "tls": {"mode": "acme"},
                "routers": [], "revisions": [],
                "udp": {
                    "routers": [{"name": "r", "entry_points": ["dns"], "service": "s"}],
                    "services": [{"name": "s", "type": "loadbalancer",
                                  "servers": [{"address": server.to_string()}]}],
                },
            }],
        }))
        .expect("snapshot");
        handle.apply(&snapshot).expect("applies");
        handle
    }

    struct Running {
        entry: SocketAddr,
        stop: watch::Sender<bool>,
        done: tokio::task::JoinHandle<()>,
        budgets: Budgets,
        tenants: Tenants,
    }

    fn run(server: SocketAddr, policy: UpstreamPolicy) -> Running {
        let socket = bind("127.0.0.1:0".parse().expect("addr")).expect("bind");
        let entry = socket.local_addr().expect("entry addr");
        let (budgets, tenants) = (Budgets::new(), Tenants::new());
        let listener = Listener::new(
            "dns",
            socket,
            table(server),
            budgets.clone(),
            policy,
            tenants.clone(),
        );
        let (stop, watch) = watch::channel(false);
        let done = tokio::spawn(async move { listener.start(watch).await });
        Running {
            entry,
            stop,
            done,
            budgets,
            tenants,
        }
    }

    async fn serve_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let addr = socket.local_addr().expect("server addr");
        let task = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                if socket.send_to(&buf[..len], from).await.is_err() {
                    return;
                }
            }
        });
        (addr, task)
    }

    #[tokio::test]
    async fn udp_dial_obeys_upstream_policy_at_connect() {
        let (server, task) = serve_echo().await;
        // The compiler has no policy here, so the table compiles; only the dial can refuse.
        let policy = UpstreamPolicy::parse(r#"{"deny": ["127.0.0.0/8"]}"#).expect("policy");
        let running = run(server, policy);
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client.send_to(b"hi", running.entry).await.expect("send");
        let mut buf = [0_u8; 8];
        let reply = tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf));
        assert!(
            reply.await.is_err(),
            "nothing may reach a server the policy forbids"
        );
        assert_eq!(running.tenants.held("t"), 0);
        assert!(
            running
                .budgets
                .get("t")
                .is_none_or(|budget| budget.buffered() == 0)
        );
        let _ = running.stop.send(true);
        running.done.await.expect("the loop ends");
        task.abort();
    }

    #[tokio::test]
    async fn udp_shutdown_releases_reservations() {
        let (server, task) = serve_echo().await;
        let running = run(server, UpstreamPolicy::allow_all());
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client.send_to(b"hi", running.entry).await.expect("send");
        let mut buf = [0_u8; 8];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("a reply")
            .expect("recv");
        assert_eq!(&buf[..len], b"hi");
        let held = running.budgets.get("t").expect("tenant budget");
        assert_eq!(held.buffered(), SESSION_BYTES);
        assert_eq!(running.tenants.held("t"), 1);
        let _ = running.stop.send(true);
        running.done.await.expect("the loop ends");
        assert_eq!(held.buffered(), 0, "the session's bytes are released");
        assert_eq!(running.tenants.held("t"), 0, "and its slot");
        task.abort();
    }
}
