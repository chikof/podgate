//! The listener side of PROXY protocol: who may send a header, and putting the decoded address
//! where the rest of podgate reads the client from.
//!
//! [`Trusted`] is `EntryPointPolicy.proxy_protocol`, `{"trusted_ips": [...], "insecure": false}`;
//! the operator writes it (never a tenant) and the routing table keeps it per entry point.
//! [`Gate`] is one entry point's connection check: it admits a peer only when the live policy
//! trusts the connection's own address, reads the header (strictly, within
//! [`READ_TIMEOUT`], nothing else buffered) and replaces the address
//! Pingora reports for the peer with the one the header carries. A refused connection is closed;
//! there is no mode in which a connection is served without its header.
//!
//! The same gate runs in two places because Pingora's pre-TLS hook exists only for TLS listeners
//! (`pingora-core` `listeners/mod.rs:318-322`):
//!
//! - [`BeforeTls`] wraps the TLS listener's own pre-handshake hook: the header is read first and
//!   the ClientHello reader of [`crate::tls::PreHandshake`] runs second, on the same stream, so it
//!   sees the TLS bytes directly behind the header.
//! - [`Fronted`] wraps the application of a plaintext listener: it reads the header before the
//!   first request and then runs the inner keep-alive loop itself.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use pingora::apps::ServerApp;
use pingora::listeners::PreTlsProcess;
use pingora::protocols::GetSocketDigest;
use pingora::protocols::Stream;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::server::ShutdownWatch;
use pingora::{Error, ErrorType};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::{READ_TIMEOUT, ReadError, read_header};
use crate::client_ip::{Cidr, normalize};
use crate::compile::Invalid;
use crate::table::TableHandle;

/// The `kind` strings of the posture changes a PROXY protocol policy reports in a plan.
pub mod kind {
    /// `insecure: true`: every peer may send a header, so every peer chooses its own address.
    pub const INSECURE: &str = "proxy_protocol_insecure";
    /// `trusted_ips` covers addresses it did not: more peers may now choose the client address.
    pub const TRUSTED_IPS_WIDENED: &str = "proxy_protocol_trusted_ips_widened";
}

/// `EntryPointPolicy.proxy_protocol`: which peers may send a header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trusted {
    insecure: bool,
    peers: Box<[Cidr]>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Addresses and blocks of the peers (the load balancers) allowed to send a PROXY header.
    #[serde(default)]
    trusted_ips: Vec<Cidr>,
    /// Trust every peer. A posture change: any client that can reach the port chooses its own
    /// address.
    #[serde(default)]
    insecure: bool,
}

impl Trusted {
    /// Reads the policy: `{"trusted_ips": ["10.0.0.0/8", "2001:db8::1"], "insecure": false}`, both
    /// fields optional. Neither field set trusts nobody, so every connection is closed.
    ///
    /// # Errors
    ///
    /// `invalid_proxy_protocol` for an unknown field or an entry that is not an address or CIDR
    /// block.
    pub fn parse(value: &Value) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(value.clone()).map_err(|err| {
            Invalid::new("invalid_proxy_protocol", format!("proxy_protocol: {err}"))
        })?;
        Ok(Self {
            insecure: config.insecure,
            peers: config.trusted_ips.into(),
        })
    }

    /// Whether `peer` may send a header: always with `insecure`, else when it is in
    /// `trusted_ips`. A connection with no IP peer is trusted only with `insecure`.
    #[must_use]
    pub fn trusts(&self, peer: Option<IpAddr>) -> bool {
        self.insecure
            || peer.is_some_and(|peer| self.peers.iter().any(|block| block.contains(peer)))
    }

    /// Whether every peer is trusted.
    #[must_use]
    pub fn is_insecure(&self) -> bool {
        self.insecure
    }

    /// How this policy trusts more than `before` (`None`: the entry point had no policy and so
    /// trusted nobody), as a [`kind`], for the posture changes of a plan.
    #[must_use]
    pub fn relaxation(&self, before: Option<&Self>) -> Option<&'static str> {
        if self.insecure && !before.is_some_and(|old| old.insecure) {
            return Some(kind::INSECURE);
        }
        let widened = self
            .peers
            .iter()
            .any(|block| !before.is_some_and(|old| old.peers.iter().any(|b| b.covers(block))));
        widened.then_some(kind::TRUSTED_IPS_WIDENED)
    }
}

/// Why a connection was closed instead of served.
#[derive(Debug, Error)]
enum Refused {
    #[error("the peer is not in the trusted list of the entry point")]
    Untrusted,
    #[error(transparent)]
    Header(#[from] ReadError),
}

/// One entry point's PROXY protocol check, reading the live policy from the routing table.
#[derive(Debug, Clone)]
pub struct Gate {
    table: TableHandle,
    entry_point: Arc<str>,
}

impl Gate {
    /// The gate of the entry point called `entry_point`.
    #[must_use]
    pub fn new(table: TableHandle, entry_point: &str) -> Self {
        Self {
            table,
            entry_point: Arc::from(entry_point),
        }
    }

    /// Reads the header of the connection `stream` and makes its source the peer address. Done
    /// once per connection, before anything else is read from it.
    async fn admit(&self, stream: &mut L4Stream) -> Result<(), Refused> {
        let peer = stream
            .get_socket_digest()
            .and_then(|digest| digest.peer_addr().and_then(|addr| addr.as_inet().copied()))
            .map(|addr| normalize(addr.ip()));
        let trusted = {
            let table = self.table.load();
            table
                .entry_policy(&self.entry_point)
                .proxy_protocol()
                .is_some_and(|policy| policy.trusts(peer))
        };
        if !trusted {
            return Err(Refused::Untrusted);
        }
        if let Some(source) = read_header(stream, READ_TIMEOUT).await?.source() {
            set_peer(stream, source);
        }
        Ok(())
    }

    fn refuse(&self, refused: &Refused, stream: &L4Stream) {
        let peer = stream
            .get_socket_digest()
            .and_then(|digest| digest.peer_addr().map(ToString::to_string));
        tracing::debug!(
            entry_point = &*self.entry_point,
            peer = peer.as_deref().unwrap_or("unknown"),
            reason = %refused,
            "closing a connection without a valid PROXY protocol header"
        );
    }
}

/// Installs a socket digest whose peer address is `source`. Pingora fills the digest's address
/// when it accepts the connection and a `OnceCell` cannot be set twice, so the digest is
/// replaced; the local address is still looked up from the same socket.
fn set_peer(stream: &mut L4Stream, source: SocketAddr) {
    let digest = pingora::protocols::SocketDigest::from_raw_fd(stream.as_raw_fd());
    let set = digest.peer_addr.set(Some(source.into()));
    debug_assert!(set.is_ok(), "a new digest has no peer address yet");
    stream.set_socket_digest(digest);
}

/// The pre-TLS hook of a TLS entry point with `;proxy_protocol`: the header, then `next`.
#[derive(Debug)]
pub struct BeforeTls<H> {
    gate: Gate,
    next: H,
}

impl<H> BeforeTls<H> {
    /// Runs `gate` and then `next` on every connection.
    #[must_use]
    pub fn new(gate: Gate, next: H) -> Self {
        Self { gate, next }
    }
}

#[async_trait]
impl<H: PreTlsProcess> PreTlsProcess for BeforeTls<H> {
    async fn process(&self, stream: &mut L4Stream) -> pingora::Result<()> {
        if let Err(refused) = self.gate.admit(stream).await {
            self.gate.refuse(&refused, stream);
            return Err(Error::explain(
                ErrorType::HandshakeError,
                "no acceptable PROXY protocol header",
            ));
        }
        self.next.process(stream).await
    }
}

/// The application of an HTTP entry point: `inner`, behind the PROXY protocol gate when the
/// entry point has `;proxy_protocol` (a TLS entry point has none here: its gate is
/// [`BeforeTls`]).
#[derive(Debug)]
pub struct Fronted<A> {
    gate: Option<Gate>,
    inner: Arc<A>,
}

impl<A> Fronted<A> {
    /// Runs `gate`, when there is one, on every connection before `inner` sees it.
    #[must_use]
    pub fn new(gate: Option<Gate>, inner: A) -> Self {
        Self {
            gate,
            inner: Arc::new(inner),
        }
    }
}

impl<A: ServerApp + Send + Sync + 'static> Fronted<A> {
    /// The connection of an entry point with a gate: the header is read once, then the
    /// connection is served.
    async fn gated(&self, gate: &Gate, stream: Stream, shutdown: &ShutdownWatch) -> Option<Stream> {
        // A plaintext listener hands over the accepted socket itself. Anything else is not a
        // connection the gate can read a header from, so it is dropped.
        let Ok(l4) = stream.into_any().downcast::<L4Stream>() else {
            return None;
        };
        let mut l4 = *l4;
        if let Err(refused) = gate.admit(&mut l4).await {
            gate.refuse(&refused, &l4);
            return None;
        }
        // Pingora calls `process_new` again with the stream a keep-alive request returns. The
        // header is read once, so the loop that would make those calls runs here and Pingora
        // sees only new connections.
        let mut next = self.inner.process_new(Box::new(l4), shutdown).await;
        while let Some(stream) = next {
            next = self.inner.process_new(stream, shutdown).await;
        }
        None
    }
}

#[async_trait]
impl<A: ServerApp + Send + Sync + 'static> ServerApp for Fronted<A> {
    // Not an `async fn` for the common case: without a gate this only hands the connection on,
    // and `async_trait` would box one more future per request for it.
    fn process_new<'life0, 'life1, 'async_trait>(
        self: &'life0 Arc<Self>,
        stream: Stream,
        shutdown: &'life1 ShutdownWatch,
    ) -> Pin<Box<dyn Future<Output = Option<Stream>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        match &self.gate {
            None => self.inner.process_new(stream, shutdown),
            Some(gate) => Box::pin(self.gated(gate, stream, shutdown)),
        }
    }

    async fn cleanup(&self) {
        self.inner.cleanup().await;
    }
}
