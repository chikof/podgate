//! What a TCP service does between choosing a server and copying bytes: the peer a
//! dial uses, the PROXY protocol header, and how long a reply may outlive its client.
//!
//! ```json
//! { "name": "primary", "type": "loadbalancer", "transport": "internal",
//!   "proxy_protocol": { "version": 2 }, "termination_delay_ms": 100,
//!   "servers": [ { "address": "10.0.0.5:5432", "tls": true } ] }
//! ```
//!
//! - **Peer.** A server with `tls: true` is reached through `Upstream::base_peer`, the peer of
//!   the HTTP load balancer: the SNI is the transport's `server_name`, else the DNS name the
//!   server was declared by (an IP literal is verified against the certificate's IP SAN and sends
//!   no SNI), the trust anchors are the transport's `ca_pem` or the platform roots, the client
//!   certificate is its `client_cert`, and `insecure_skip_verify` is the same posture change.
//!   The handshake offers ALPN `http/1.1` and nothing else: raw TCP has no ALPN of its own.
//! - **Header.** `proxy_protocol` makes [`extras::set_client_header`] write the header as the
//!   first bytes of the connection, by the `custom_l4` dial of [`crate::service::extras`], so it
//!   goes after the connect and before the TLS handshake of a `tls: true` server and before the
//!   first payload byte, which for a passthrough router is the client's ClientHello. The source
//!   is the client's address (the PROXY protocol source when the entry point reads a header,
//!   change 0029) and the destination is the entry point's. A header that cannot be written is a
//!   failed connect, so the next server is tried, as no client byte has been read yet.
//! - **Delay.** `termination_delay_ms` (default 100) is how long the server's side of the
//!   connection lives on after the client half-closed, so a reply that is still on its way is not
//!   cut (`copy::relay`).

use std::net::SocketAddr;
use std::time::Duration;

use pingora::upstreams::peer::HttpPeer;

use crate::compile::Invalid;
use crate::entry::proxy_protocol::Version;
use crate::service::extras::{self, ProxyProtocolConfig};
use crate::service::{self, Upstream};

/// Milliseconds a reply may outlive its client when the service does not say.
pub const DEFAULT_TERMINATION_DELAY_MS: u64 = 100;
/// Longest `termination_delay_ms`: a day, the bound of `idle_timeout_secs`.
pub const MAX_TERMINATION_DELAY_MS: u64 = 86_400_000;

/// The addresses a PROXY header names: who connected and where they connected to.
#[derive(Debug, Clone, Copy)]
pub(super) struct Flow {
    /// The client, with its real port.
    pub client: SocketAddr,
    /// The entry point's socket.
    pub entry: SocketAddr,
}

/// A TCP service's `proxy_protocol` and `termination_delay_ms`, checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    proxy_protocol: Option<Version>,
    termination_delay: Duration,
}

impl Settings {
    /// Checks the two declared values.
    ///
    /// # Errors
    ///
    /// `invalid_service` for a PROXY protocol version other than 1 or 2 and for a delay above
    /// [`MAX_TERMINATION_DELAY_MS`].
    pub(super) fn compile(
        proxy_protocol: Option<ProxyProtocolConfig>,
        termination_delay_ms: Option<u64>,
    ) -> Result<Self, Invalid> {
        let invalid =
            |why: &str| Invalid::new("invalid_service", format!("tcp loadbalancer: {why}"));
        let proxy_protocol = match proxy_protocol {
            None => None,
            Some(config) => Some(
                config
                    .wire()
                    .ok_or_else(|| invalid("proxy_protocol.version must be 1 or 2"))?,
            ),
        };
        let delay = termination_delay_ms.unwrap_or(DEFAULT_TERMINATION_DELAY_MS);
        if delay > MAX_TERMINATION_DELAY_MS {
            return Err(invalid(&format!(
                "termination_delay_ms is {delay}, between 0 and {MAX_TERMINATION_DELAY_MS} is allowed"
            )));
        }
        Ok(Self {
            proxy_protocol,
            termination_delay: Duration::from_millis(delay),
        })
    }

    /// The PROXY protocol version written to the servers, `1` or `2`.
    #[must_use]
    pub fn proxy_protocol(&self) -> Option<u8> {
        self.proxy_protocol.map(|version| match version {
            Version::V1 => 1,
            Version::V2 => 2,
        })
    }

    /// How long the server's side lives on after the client half-closed.
    #[must_use]
    pub fn termination_delay(&self) -> Duration {
        self.termination_delay
    }

    /// The peer for a connection of `flow` to the server at `addr` of `balancer`, and how long
    /// connecting to it (the TCP connect, the header and the TLS handshake together) may take:
    /// the transport's `dial_timeout_secs`, else `dial`. `None` when `addr` is no longer a
    /// server of the service (the answer of its DNS name changed since it was picked).
    pub(super) fn peer(
        &self,
        balancer: &service::Service,
        addr: SocketAddr,
        dial: Duration,
        flow: Flow,
    ) -> Option<(HttpPeer, Duration)> {
        let (mut peer, limit) = balancer.with_upstream(addr, |upstream: Upstream<'_>| {
            let limit = upstream.transport.dial_timeout().unwrap_or(dial);
            (upstream.base_peer(), limit)
        })?;
        peer.options.connection_timeout = Some(limit);
        peer.options.total_connection_timeout = Some(limit);
        if let Some(version) = self.proxy_protocol {
            extras::set_client_header(&mut peer, version, Some(flow.client), Some(flow.entry));
        }
        Some((peer, limit))
    }
}
