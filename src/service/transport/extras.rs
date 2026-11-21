//! Transport extras: the PROXY protocol header towards an HTTP upstream, and the
//! limits of a tunnel (an upgraded connection, WebSocket or other).
//!
//! # PROXY protocol
//!
//! `proxy_protocol: {"version": 1|2}` on a `servers_transport` makes every new connection to its
//! servers start with a header, written by `Dial`: Pingora 0.9.1 calls `PeerOptions::custom_l4`
//! instead of its own TCP dial (`pingora-core` `connectors/l4.rs:120`), and what the dial returns
//! is the stream TLS and HTTP are layered on, so the header is the first thing on the wire, before
//! a ClientHello and before the request line. A proxied request carries its client's address and
//! the entry point's ([`set_client_header`]); everything else a transport reaches (health probes,
//! the `errors` page fetch, `forward_auth`, failure replay) is not a client's request and carries
//! a `LOCAL` header ([`set_local_header`]). [`crate::pool`] keys the connection on the client
//! address, so a header is never shown to another client's request.
//!
//! # Tunnels
//!
//! After the `101` a tunnel is bound by the transport's three tunnel fields and by nothing else
//! of the transport: `tunnel_idle_timeout_secs` replaces the read timeouts of both sockets
//! (the entry point's `timeouts.read_secs` stays a ceiling for the client side), and the two
//! timers end it from outside through the vendored `pingora-proxy`'s [`Tunnel`] hook.
//! [`State`] lives on the request's context from `upstream_peer` to `logging`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use pingora::connectors::L4Connect;
use pingora::protocols::l4::socket::SocketAddr as PingoraAddr;
use pingora::protocols::l4::stream::Stream;
use pingora::proxy::{Session, Tunnel};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::compile::Invalid;
use crate::entry::proxy_protocol::{Addresses, Header, Version};
use crate::route::Selected;
use crate::table::{RoutingTable, TableHandle};

/// The longest a tunnel timer may be set to: a day.
pub(super) const MAX_TUNNEL_SECS: u64 = 86_400;

/// How long a dial with no timeout of its own waits for TCP to connect: the same number as the
/// default `REQUEST_TIMEOUT_SECS`. A proxied request's dial uses its transport's dial timeout.
pub const PEER_DIAL_LIMIT: Duration = Duration::from_secs(30);

/// The `proxy_protocol` object of a `servers_transport`; the same object a TCP service takes
///.
#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyProtocolConfig {
    /// `1` writes the text line, `2` the binary header.
    #[schemars(range(min = 1, max = 2))]
    pub version: u8,
}

impl ProxyProtocolConfig {
    fn wire(self) -> Option<Version> {
        match self.version {
            1 => Some(Version::V1),
            2 => Some(Version::V2),
            _ => None,
        }
    }
}

/// What a tunnel is bound by once it is open.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limits {
    /// No traffic in either direction for this long closes it. `None`: never.
    pub idle: Option<Duration>,
    /// It closes this long after the `101`. `None`: never.
    pub lifetime: Option<Duration>,
    /// It closes this long after a snapshot left its server out of the table. `None`: never.
    pub close_delay: Option<Duration>,
}

/// What a transport sets beyond its TLS and timeouts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extras {
    /// The PROXY protocol version written first on every new connection.
    pub proxy_protocol: Option<Version>,
    /// The limits of a tunnel through the transport.
    pub tunnel: Limits,
}

/// What explain shows of [`Extras`]: only what the transport sets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// The PROXY protocol version, `1` or `2`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<u8>,
    /// The idle timeout of a tunnel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_idle_timeout_secs: Option<u64>,
    /// The longest a tunnel lives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_stream_lifetime_secs: Option<u64>,
    /// How long a tunnel lives on after its server was removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_close_delay_secs: Option<u64>,
}

fn tunnel_secs(name: &str, value: Option<u64>) -> Result<Option<Duration>, Invalid> {
    match value {
        None => Ok(None),
        Some(secs @ 1..=MAX_TUNNEL_SECS) => Ok(Some(Duration::from_secs(secs))),
        Some(_) => Err(Invalid::new(
            "invalid_transport",
            format!("{name} must be between 1 and {MAX_TUNNEL_SECS} seconds"),
        )),
    }
}

impl Extras {
    /// Checks the four declared values.
    ///
    /// # Errors
    ///
    /// `invalid_transport` for a PROXY protocol version other than 1 or 2, and for a tunnel
    /// timer outside 1..=86400 seconds.
    pub(super) fn compile(
        proxy_protocol: Option<ProxyProtocolConfig>,
        idle: Option<u64>,
        lifetime: Option<u64>,
        close_delay: Option<u64>,
    ) -> Result<Self, Invalid> {
        let proxy_protocol = match proxy_protocol {
            None => None,
            Some(config) => Some(config.wire().ok_or_else(|| {
                Invalid::new("invalid_transport", "proxy_protocol.version must be 1 or 2")
            })?),
        };
        Ok(Self {
            proxy_protocol,
            tunnel: Limits {
                idle: tunnel_secs("tunnel_idle_timeout_secs", idle)?,
                lifetime: tunnel_secs("max_stream_lifetime_secs", lifetime)?,
                close_delay: tunnel_secs("stream_close_delay_secs", close_delay)?,
            },
        })
    }

    /// The values the pool fingerprint hashes, one per field, `None` when unset.
    pub(super) fn fingerprint_fields(self) -> [Option<String>; 4] {
        let secs = |value: Option<Duration>| value.map(|value| value.as_secs().to_string());
        [
            self.proxy_protocol.map(|version| match version {
                Version::V1 => "1".to_owned(),
                Version::V2 => "2".to_owned(),
            }),
            secs(self.tunnel.idle),
            secs(self.tunnel.lifetime),
            secs(self.tunnel.close_delay),
        ]
    }

    /// Whether any field is set, which explain shows even for a plain server.
    #[must_use]
    pub fn is_set(self) -> bool {
        self != Self::default()
    }

    /// What explain shows.
    #[must_use]
    pub fn summary(self) -> Summary {
        let secs = |value: Option<Duration>| value.map(|value| value.as_secs());
        Summary {
            proxy_protocol: self.proxy_protocol.map(|version| match version {
                Version::V1 => 1,
                Version::V2 => 2,
            }),
            tunnel_idle_timeout_secs: secs(self.tunnel.idle),
            max_stream_lifetime_secs: secs(self.tunnel.lifetime),
            stream_close_delay_secs: secs(self.tunnel.close_delay),
        }
    }
}

// --- PROXY protocol ---------------------------------------------------------------------------

/// The header of a connection made for `client`, who connected to `server` (the entry point's
/// address). Without both addresses the header is `LOCAL`. The two addresses must be of one
/// family: when they are not (an IPv4 client on a dual-stack listener), the IPv4 one is written
/// as an IPv4-mapped IPv6 address.
#[must_use]
pub fn header_bytes(
    version: Version,
    client: Option<SocketAddr>,
    server: Option<SocketAddr>,
) -> Vec<u8> {
    let header = match (client, server) {
        (Some(source), Some(destination)) => {
            let (source, destination) = same_family(source, destination);
            Addresses::new(source, destination).map_or(Header::Local, |addresses| Header::Proxied {
                addresses,
                authority: None,
            })
        }
        _ => Header::Local,
    };
    let mut out = Vec::with_capacity(64);
    let encoded = header.encode(version, &mut out);
    debug_assert!(encoded.is_ok(), "a header with no authority always encodes");
    out
}

fn same_family(left: SocketAddr, right: SocketAddr) -> (SocketAddr, SocketAddr) {
    let mapped = |addr: SocketAddr| match addr.ip() {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port()),
        IpAddr::V6(_) => addr,
    };
    if left.is_ipv4() == right.is_ipv4() {
        (left, right)
    } else {
        (mapped(left), mapped(right))
    }
}

/// Connects to a server and writes a fixed header before anything else.
#[derive(Debug)]
struct Dial {
    header: Box<[u8]>,
    limit: Duration,
}

#[async_trait]
impl L4Connect for Dial {
    async fn connect(&self, addr: &PingoraAddr) -> pingora::Result<Stream> {
        let Some(addr) = addr.as_inet().copied() else {
            return Error::e_explain(
                ErrorType::ConnectError,
                "a PROXY protocol header needs a TCP server",
            );
        };
        let dial = async {
            let mut tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true)?;
            tcp.write_all(&self.header).await?;
            Ok::<_, io::Error>(tcp)
        };
        match timeout(self.limit, dial).await {
            Ok(Ok(tcp)) => Ok(tcp.into()),
            Ok(Err(err)) => {
                let kind = match err.kind() {
                    io::ErrorKind::ConnectionRefused => ErrorType::ConnectRefused,
                    io::ErrorKind::TimedOut => ErrorType::ConnectTimedout,
                    _ => ErrorType::ConnectError,
                };
                Error::e_because(kind, format!("Fail to connect to {addr}"), err)
            }
            Err(_) => Error::e_explain(
                ErrorType::ConnectTimedout,
                format!("timeout {:?} connecting to server {addr}", self.limit),
            ),
        }
    }
}

fn install(peer: &mut HttpPeer, header: Vec<u8>, limit: Duration) {
    peer.options.custom_l4 = Some(Arc::new(Dial {
        header: header.into_boxed_slice(),
        limit,
    }));
}

/// Makes new connections of `peer` start with the header of `client`, who connected to
/// `server`. The dial is bounded by the peer's `connection_timeout`.
pub fn set_client_header(
    peer: &mut HttpPeer,
    version: Version,
    client: Option<SocketAddr>,
    server: Option<SocketAddr>,
) {
    let limit = peer.options.connection_timeout.unwrap_or(PEER_DIAL_LIMIT);
    install(peer, header_bytes(version, client, server), limit);
}

/// Makes new connections of `peer` start with a `LOCAL` header, for a connection that is not a
/// client's request.
pub fn set_local_header(peer: &mut HttpPeer, version: Version, limit: Option<Duration>) {
    install(
        peer,
        header_bytes(version, None, None),
        limit.unwrap_or(PEER_DIAL_LIMIT),
    );
}

// --- Tunnels ----------------------------------------------------------------------------------

/// Why a tunnel ended, in the order of [`LABELS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// A side hung up.
    Closed,
    /// No traffic for `tunnel_idle_timeout_secs` (or the entry point's `read_secs`).
    IdleTimeout,
    /// `max_stream_lifetime_secs` passed.
    MaxLifetime,
    /// `stream_close_delay_secs` passed after the server left the table.
    ServerRemoved,
    /// A failure that is none of the others.
    Error,
}

const LABELS: [&str; 5] = [
    "closed",
    "idle_timeout",
    "max_lifetime",
    "server_removed",
    "error",
];

/// Marker of "no timer fired" in [`Run::reason`].
const UNSET: u8 = u8::MAX;

static CLOSED: [AtomicU64; LABELS.len()] = [const { AtomicU64::new(0) }; LABELS.len()];

fn count(reason: Reason) {
    if let Some(total) = CLOSED.get(reason as usize) {
        total.fetch_add(1, Ordering::Relaxed);
    }
}

/// The `podgate_tunnel_closed_total` series, for `GET /metrics`.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "# HELP podgate_tunnel_closed_total Upgraded connections (tunnels) that ended, by reason: a side hung up, idle, lifetime, server removed, or error.\n# TYPE podgate_tunnel_closed_total counter"
    );
    for (label, total) in LABELS.iter().zip(&CLOSED) {
        let _ = writeln!(
            out,
            "podgate_tunnel_closed_total{{reason=\"{label}\"}} {}",
            total.load(Ordering::Relaxed)
        );
    }
}

/// Which server a tunnel runs to, by names that survive a snapshot swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    tenant: Box<str>,
    app: Box<str>,
    revision: Box<str>,
    addr: SocketAddr,
}

impl Key {
    /// The key of the server `selected` points at in `table`.
    #[must_use]
    pub fn of(table: &RoutingTable, selected: &Selected) -> Option<Self> {
        let app = table.app(selected.app)?;
        let revision = app.revisions().get(selected.revision)?;
        Some(Self {
            tenant: app.tenant().into(),
            app: app.id().into(),
            revision: revision.id().into(),
            addr: selected.upstream,
        })
    }

    /// Whether `table` still has the server: the app, the revision and the address among the
    /// servers of one of the revision's services (or of the app's shared ones).
    #[must_use]
    pub fn served_by(&self, table: &RoutingTable) -> bool {
        let Some((_, app)) = table.app_by_id(&self.app) else {
            return false;
        };
        if app.tenant() != &*self.tenant {
            return false;
        }
        let Some(revision) = app
            .revisions()
            .iter()
            .find(|revision| revision.id() == &*self.revision)
        else {
            return false;
        };
        app.services()
            .iter()
            .chain(revision.services())
            .any(|named| {
                named
                    .service
                    .servers()
                    .iter()
                    .any(|server| server.addr == self.addr)
            })
    }
}

/// The tunnel of one request: planned by `upstream_peer`, started by the `101`, ended by
/// `logging`.
#[derive(Debug, Default)]
pub struct State {
    plan: Option<Plan>,
    run: Option<Run>,
}

#[derive(Debug)]
struct Plan {
    limits: Limits,
    cancel: Arc<Notify>,
}

/// The timers of an open tunnel. Dropping it stops them.
#[derive(Debug)]
struct Run {
    reason: Arc<AtomicU8>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Run {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn fire(reason: &AtomicU8, cancel: &Notify, why: Reason) {
    // The first timer wins; a later one finds the tunnel ending already.
    let _ = reason.compare_exchange(UNSET, why as u8, Ordering::AcqRel, Ordering::Acquire);
    cancel.notify_one();
}

async fn watch_removal(
    table: TableHandle,
    key: Key,
    delay: Duration,
    reason: Arc<AtomicU8>,
    cancel: Arc<Notify>,
) {
    // Subscribe first so a swap between the check and the wait is not missed.
    let mut swaps = table.subscribe();
    loop {
        if !key.served_by(&table.load()) {
            sleep(delay).await;
            fire(&reason, &cancel, Reason::ServerRemoved);
            return;
        }
        if swaps.changed().await.is_err() {
            return;
        }
    }
}

impl State {
    /// Plans the tunnel an upgrade request may become, with the limits of the transport that
    /// reaches its server. Called by every `upstream_peer` of an upgrade request, so a retry
    /// replaces the plan of the failed attempt.
    pub fn plan(&mut self, limits: Limits) {
        self.plan = Some(Plan {
            limits,
            cancel: Arc::new(Notify::new()),
        });
    }

    /// The answer of the vendored `ProxyHttp::tunnel` hook: the upstream read timeout after the
    /// `101` and the handle the timers end the tunnel with.
    #[must_use]
    pub fn hook(&self) -> Option<Tunnel> {
        self.plan.as_ref().map(|plan| Tunnel {
            read_timeout: plan.limits.idle,
            cancel: Arc::clone(&plan.cancel),
        })
    }

    /// The upstream answered `101`: the tunnel is open. Sets the client side's read timeout to
    /// the shorter of `entry_read` (the entry point's `timeouts.read_secs`, when the operator
    /// set one) and the transport's idle timeout, in place of Pingora's own default, and starts
    /// the lifetime timer and the removal watcher the transport asks for.
    pub fn opened(
        &mut self,
        session: &mut Session,
        entry_read: Option<Duration>,
        table: &TableHandle,
        key: Option<Key>,
    ) {
        let Some(plan) = &self.plan else { return };
        let limits = plan.limits;
        session.set_read_timeout([entry_read, limits.idle].into_iter().flatten().min());
        let reason = Arc::new(AtomicU8::new(UNSET));
        let mut tasks = Vec::new();
        if let Some(lifetime) = limits.lifetime {
            let (reason, cancel) = (Arc::clone(&reason), Arc::clone(&plan.cancel));
            tasks.push(tokio::spawn(async move {
                sleep(lifetime).await;
                fire(&reason, &cancel, Reason::MaxLifetime);
            }));
        }
        if let (Some(delay), Some(key)) = (limits.close_delay, key) {
            tasks.push(tokio::spawn(watch_removal(
                table.clone(),
                key,
                delay,
                Arc::clone(&reason),
                Arc::clone(&plan.cancel),
            )));
        }
        self.run = Some(Run { reason, tasks });
    }

    /// The timer that ended the tunnel, if one did.
    fn fired(&self) -> Option<Reason> {
        match self.run.as_ref()?.reason.load(Ordering::Acquire) {
            code if code == Reason::MaxLifetime as u8 => Some(Reason::MaxLifetime),
            code if code == Reason::ServerRemoved as u8 => Some(Reason::ServerRemoved),
            _ => None,
        }
    }

    /// Whether a lifetime or close-delay timer ended the tunnel: a planned end, not a failure.
    #[must_use]
    pub fn limit_fired(&self) -> bool {
        self.fired().is_some()
    }

    /// The request ended: counts the tunnel, if one was open, and stops its timers.
    pub fn finished(&mut self, error: Option<&Error>) {
        let fired = self.fired();
        self.plan = None;
        if self.run.take().is_some() {
            count(fired.unwrap_or_else(|| classify(error)));
        }
    }
}

/// How a tunnel no timer of ours ended: a hang-up, an idle read timeout, or a failure.
fn classify(error: Option<&Error>) -> Reason {
    let Some(error) = error else {
        return Reason::Closed;
    };
    match error.etype() {
        ErrorType::ReadTimedout => Reason::IdleTimeout,
        ErrorType::ConnectionClosed | ErrorType::ReadError | ErrorType::WriteError => {
            Reason::Closed
        }
        _ => Reason::Error,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("socket address")
    }

    #[test]
    fn header_v1_names_both_addresses() {
        let bytes = header_bytes(
            Version::V1,
            Some(addr("203.0.113.7:51000")),
            Some(addr("198.51.100.1:443")),
        );
        assert_eq!(bytes, b"PROXY TCP4 203.0.113.7 198.51.100.1 51000 443\r\n");
    }

    #[test]
    fn header_v2_local_and_mixed_families() {
        let local = header_bytes(Version::V2, None, None);
        assert_eq!(&local[12..16], &[0x20, 0x00, 0, 0]);
        let mixed = header_bytes(
            Version::V1,
            Some(addr("203.0.113.7:51000")),
            Some(addr("[2001:db8::1]:443")),
        );
        assert_eq!(
            mixed,
            b"PROXY TCP6 ::ffff:203.0.113.7 2001:db8::1 51000 443\r\n"
        );
        assert_eq!(header_bytes(Version::V1, None, None), b"PROXY UNKNOWN\r\n");
    }

    #[test]
    fn extras_validate_versions_and_tunnel_timers() {
        let proxy = |version| Some(ProxyProtocolConfig { version });
        assert!(Extras::compile(proxy(1), Some(1), Some(86_400), Some(5)).is_ok());
        for bad in [
            Extras::compile(proxy(0), None, None, None),
            Extras::compile(proxy(3), None, None, None),
            Extras::compile(None, Some(0), None, None),
            Extras::compile(None, None, Some(86_401), None),
            Extras::compile(None, None, None, Some(0)),
        ] {
            assert_eq!(bad.expect_err("refused").code, "invalid_transport");
        }
        assert!(!Extras::default().is_set());
    }
}
