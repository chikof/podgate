//! The QUIC endpoint of an HTTPS entry point with `;http3`: the UDP socket, the TLS and
//! transport configuration, and the decision about each new connection before it costs anything.
//!
//! - [`bind`] opens the UDP socket at the entry point's address at startup, so a busy address
//!   stops the process like a TCP entry point does, and asks for [`Settings::udp_recv_buffer`].
//! - [`server_config`] builds the rustls server (TLS 1.3, ALPN `h3` only, no client
//!   certificates, 0-RTT off) over the same certificates as the TCP listener, and the transport
//!   limits derived from [`Settings`].
//! - [`accept`] is the accept loop. It decides each [`quinn::Incoming`] before any handshake work:
//!   past `H3_MAX_CONNECTIONS` or `H3_MAX_HANDSHAKES` it is turned away, an unvalidated address
//!   under load must first send back a retry token, and only then is it accepted.
//!
//! # Certificates and on-demand hosts
//!
//! [`Resolver`] chooses the certificate of a handshake from the live table, as the TCP
//! listener's resolver does, with the same OCSP staples. It serves only names an app claims, and
//! only when every app that may serve the name allows HTTP/3 (see [`super::alt_svc::allowed`]):
//! an app with a client CA, cipher suites or `http3: false` is refused at the handshake, never
//! served with its policy dropped.
//!
//! A host with no certificate yet is refused, even when it belongs to an `on_demand` app: rustls
//! asks its resolver synchronously inside the handshake, so waiting for an issuance would block
//! the endpoint's connection state, and a QUIC client's address is not validated at that point,
//! so a spoofed source could make podgate order certificates. The TCP listener waits and orders
//!; a browser learns about HTTP/3 from `Alt-Svc` on a response that name already
//! got over TCP, by which time the certificate exists.
//!
//! # Work per packet
//!
//! A flood costs a bounded amount of CPU: quinn's endpoint driver reads at most a fixed number of
//! datagrams per wakeup and yields, `ServerConfig::max_incoming` and the incoming buffer sizes
//! cap what an unaccepted connection can hold, and the handshake and connection caps above stop
//! work before the TLS handshake.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use pingora::server::ShutdownWatch;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{EndpointConfig, IdleTimeout, TokioRuntime, TransportConfig, VarInt};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use thiserror::Error;

use super::alt_svc;
use super::front::Front;
use super::limits::{
    CONNECTIONS, Declined, HANDSHAKES, IDLE_TIMEOUT, Refused, STATS, Settings, UNI_STREAMS,
};
use crate::host;
use crate::table::TableHandle;
use crate::tls::ocsp::Staples;

/// The ALPN protocol of HTTP/3, the only one the endpoint offers.
pub(crate) const ALPN: &[u8] = b"h3";

/// Pending connections the endpoint may hold per handshake slot, and some for bursts.
const INCOMING_PER_HANDSHAKE: usize = 4;
/// Most bytes buffered for one connection that is not accepted yet: an Initial flight.
const INCOMING_BUFFER: u64 = 64 * 1024;
/// Most bytes buffered for all connections that are not accepted yet.
const INCOMING_BUFFER_TOTAL: u64 = 4 * 1024 * 1024;

/// Why the QUIC endpoint cannot be built.
#[derive(Debug, Error)]
pub(crate) enum EndpointError {
    /// The TLS configuration was refused.
    #[error("the TLS configuration for QUIC is invalid")]
    Tls(#[source] rustls::Error),
    /// The crypto provider has no cipher suite QUIC's initial packets can use.
    #[error("the crypto provider has no suite for QUIC initial packets")]
    NoInitialSuite,
    /// The UDP socket could not be handed to quinn.
    #[error("cannot start the QUIC endpoint")]
    Socket(#[source] io::Error),
}

/// Binds the UDP socket of the entry point at `addr`, non-blocking, asking the kernel for
/// `recv_buffer` bytes of receive buffer. The kernel caps the request at `net.core.rmem_max`;
/// what it granted is logged when that is less.
///
/// # Errors
///
/// The error of binding `addr`, or of making the socket non-blocking.
pub(crate) fn bind(addr: SocketAddr, recv_buffer: u32) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    let asked = usize::try_from(recv_buffer).unwrap_or(usize::MAX);
    if let Err(err) = rustix::net::sockopt::set_socket_recv_buffer_size(&socket, asked) {
        tracing::warn!(%addr, %err, "cannot size the HTTP/3 UDP receive buffer");
    } else if let Ok(granted) = rustix::net::sockopt::socket_recv_buffer_size(&socket) {
        // Linux reports twice what it reserves for the bookkeeping, so half is what holds data.
        if granted / 2 < asked {
            tracing::warn!(%addr, asked, granted = granted / 2, "the kernel gave the HTTP/3 UDP socket a smaller receive buffer than H3_UDP_RECV_BUFFER; raise net.core.rmem_max");
        }
    }
    Ok(socket)
}

/// Chooses the certificate of a QUIC handshake. See the module documentation.
#[derive(Debug)]
struct Resolver {
    table: TableHandle,
    staples: Staples,
}

impl Resolver {
    /// The certificate for `name`, or why there is none.
    fn choose(&self, name: Option<&str>) -> Result<Arc<CertifiedKey>, Declined> {
        let name = name.ok_or(Declined::NoName)?;
        let host = host::normalize(name);
        let table = self.table.load();
        if table.claimant(&host).is_none() {
            return Err(Declined::UnknownHost);
        }
        let mut strict = false;
        for app in table.may_serve(&host) {
            if !alt_svc::allowed(app.tls()) {
                return Err(Declined::NotAllowed);
            }
            strict |= app
                .tls_options()
                .is_some_and(|options| options.sni_strict());
        }
        let certificates = table.certificates();
        certificates
            .lookup(&host)
            .or_else(|| {
                certificates
                    .default_certificate()
                    .filter(|_| !strict)
                    .cloned()
            })
            .map(|key| self.staples.attach(key))
            .ok_or(Declined::NoCertificate)
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match self.choose(client_hello.server_name()) {
            Ok(key) => Some(key),
            Err(reason) => {
                STATS.declined(reason);
                None
            }
        }
    }
}

/// The QUIC server configuration: TLS 1.3 with ALPN `h3`, no client certificates, no 0-RTT, the
/// certificates of `table`, and the transport limits of `settings`.
///
/// # Errors
///
/// [`EndpointError`] when rustls or quinn refuses the configuration.
pub(crate) fn server_config(
    table: TableHandle,
    staples: Staples,
    settings: &Settings,
) -> Result<quinn::ServerConfig, EndpointError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(EndpointError::Tls)?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(Resolver { table, staples }));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    // `max_early_data_size` stays 0: a 0-RTT request could be replayed. quinn refuses a
    // configuration that sets anything else but "all", and the test pins this.
    debug_assert_eq!(tls.max_early_data_size, 0);
    let crypto = QuicServerConfig::try_from(tls).map_err(|_| EndpointError::NoInitialSuite)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config
        .transport_config(Arc::new(transport(settings)))
        // The client address is fixed when the internal connection opens (it is the source of
        // the PROXY header and so of every `ip_allow_list` and rate limit), so a connection that
        // moves to another address must start over.
        .migration(false)
        .max_incoming(
            usize::try_from(settings.max_handshakes)
                .unwrap_or(usize::MAX)
                .saturating_mul(INCOMING_PER_HANDSHAKE)
                .saturating_add(64),
        )
        .incoming_buffer_size(INCOMING_BUFFER)
        .incoming_buffer_size_total(INCOMING_BUFFER_TOTAL);
    Ok(config)
}

/// The transport limits that fix what one connection can hold: the windows, the stream counts,
/// the idle timeout. No datagrams, no keep-alive.
pub(crate) fn transport(settings: &Settings) -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .receive_window(VarInt::from_u32(settings.connection_window))
        .stream_receive_window(VarInt::from_u32(settings.stream_window()))
        .send_window(u64::from(settings.connection_window))
        .max_concurrent_bidi_streams(VarInt::from_u32(settings.max_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(UNI_STREAMS))
        .max_idle_timeout(IdleTimeout::try_from(IDLE_TIMEOUT).ok())
        .keep_alive_interval(None)
        .datagram_receive_buffer_size(None);
    transport
}

/// The quinn endpoint on `socket`, serving `config`.
///
/// # Errors
///
/// [`EndpointError::Socket`] when quinn cannot use the socket. Call it inside the runtime that
/// will run [`accept`].
pub(crate) fn endpoint(
    socket: UdpSocket,
    config: quinn::ServerConfig,
) -> Result<quinn::Endpoint, EndpointError> {
    quinn::Endpoint::new(
        EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(EndpointError::Socket)
}

/// Accepts connections on `endpoint` until `shutdown` fires, then stops taking new ones; the
/// ones open go on until their own end or the process's.
pub(crate) async fn accept(
    front: Arc<Front>,
    endpoint: quinn::Endpoint,
    mut shutdown: ShutdownWatch,
) {
    loop {
        let incoming = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
        };
        admit(&front, incoming);
    }
    endpoint.set_server_config(None);
}

/// The decision about one new connection, taken before any handshake work.
fn admit(front: &Arc<Front>, incoming: quinn::Incoming) {
    let settings = front.settings();
    let validated = incoming.remote_address_validated();
    let (connections, handshakes) = (CONNECTIONS.load(), HANDSHAKES.load());
    let reason = if connections >= settings.max_connections {
        Some(Refused::ConnectionCap)
    } else if handshakes >= settings.max_handshakes {
        Some(Refused::HandshakeCap)
    } else {
        None
    };
    if let Some(reason) = reason {
        STATS.refused(reason);
        // Answering an address nobody proved is how a reflection attack is built: stay silent.
        if validated {
            incoming.refuse();
        } else {
            incoming.ignore();
        }
        return;
    }
    if !validated && incoming.may_retry() && settings.demands_retry(handshakes, connections) {
        STATS.retry();
        if let Err(err) = incoming.retry() {
            tracing::debug!(%err, "cannot demand a retry token");
        }
        return;
    }
    match incoming.accept() {
        Ok(connecting) => {
            let connection = CONNECTIONS.take();
            let handshake = HANDSHAKES.take();
            tokio::spawn(Arc::clone(front).handshake(connecting, connection, handshake));
        }
        Err(err) => tracing::debug!(%err, "cannot accept a QUIC connection"),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::table::TableHandle;

    fn config() -> quinn::ServerConfig {
        server_config(TableHandle::new(), Staples::default(), &Settings::default()).expect("builds")
    }

    #[test]
    fn the_server_config_builds_with_zero_rtt_off() {
        let _ = config();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver {
            table: TableHandle::new(),
            staples: Staples::default(),
        }));
        assert_eq!(tls.max_early_data_size, 0, "0-RTT is off by default");
        // quinn enables 0-RTT only for `u32::MAX`, so 0 keeps it off.
    }

    #[test]
    fn a_handshake_without_a_name_or_an_app_is_declined() {
        let resolver = Resolver {
            table: TableHandle::new(),
            staples: Staples::default(),
        };
        assert_eq!(resolver.choose(None).err(), Some(Declined::NoName));
        assert_eq!(
            resolver.choose(Some("nobody.test")).err(),
            Some(Declined::UnknownHost)
        );
    }
}
