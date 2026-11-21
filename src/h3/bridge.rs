//! The internal connection between the QUIC front and the pipeline.
//!
//! The front never routes. For each QUIC connection it opens one HTTP/2 cleartext connection to a
//! unix socket (`<ADMIN_SOCKET dir>/h3-<entry>.sock`), and sends each HTTP/3 request through it
//! as an HTTP/2 stream into the same Pingora application an HTTPS entry point runs
//! ([`crate::entry::app::Policed`]), so routing, middlewares, budgets, access logs and metrics
//! apply unchanged.
//!
//! The pipeline has to know two things the socket cannot say: who the client is and which
//! server name the QUIC handshake carried. The first thing on the connection says both:
//!
//! 1. a 32-byte credential, random per process, which only the front knows;
//! 2. a PROXY protocol v2 header ([`Header::encode`]) with the client's address as the source and
//!    the server name as the authority TLV.
//!
//! [`serve`] accepts on the socket and lets nothing through that fails any of four checks: the
//! socket file is `0600` and private to the user podgate runs as, the peer's uid is that user's
//! (`SO_PEERCRED`), the credential matches (compared in constant time), and a valid header with an
//! authority follows within [`READ_TIMEOUT`]. A refused peer is closed before a byte of HTTP is
//! read. The header is trusted only here: no other listener reads one from this socket.
//!
//! An accepted connection becomes a [`Link`]: Pingora's own unix stream, whose socket digest
//! carries the client's address (so the client address, `X-Forwarded-For`, `ip_allow_list`, rate
//! limits and the access log see the client, not the socket), and whose TLS digest says the
//! connection is TLS (so `X-Forwarded-Proto: https` and the SNI against `Host` check of
//! [`crate::sni`] apply). Pingora offers no per-connection slot for a stream that is not TLS, so
//! the server name travels in the digest's `organization` field under a cipher name no real
//! handshake produces ([`LINK_CIPHER`]); [`is_front_link`] is the only reader.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use h2::client::SendRequest;
use pingora::apps::ServerApp;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::raw_connect::ProxyDigest;
use pingora::protocols::tls::SslDigest;
use pingora::protocols::{
    ALPN, GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType,
};
use pingora::server::ShutdownWatch;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::task::AbortHandle;

use super::limits::INTERNAL_WINDOW;
use crate::entry::app::Policed;
use crate::entry::proxy_protocol::{
    Addresses, EncodeError, Header, READ_TIMEOUT, ReadError, Version, read_header,
};
use crate::host;

/// The cipher name of the TLS digest of a front link. It is not the name of any cipher suite,
/// so no TLS handshake can produce a digest [`is_front_link`] accepts.
pub(crate) const LINK_CIPHER: &str = "podgate-h3-link";
/// The TLS version of a front link: the only one QUIC speaks.
const LINK_VERSION: &str = "TLSv1_3";
const TOKEN_LEN: usize = 32;
/// Longest the front waits to connect and handshake with the pipeline.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether `tls` is the digest of a front link, which carries the QUIC handshake's server name.
pub(crate) fn is_front_link(tls: &SslDigest) -> bool {
    tls.cipher == LINK_CIPHER
}

/// The credential of the front: 32 random bytes, made once per process and shared by the front
/// and the socket it connects to.
#[derive(Clone)]
pub(crate) struct Token(Arc<[u8; TOKEN_LEN]>);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    /// A new random credential.
    ///
    /// # Errors
    ///
    /// Fails when the system has no randomness.
    pub(crate) fn generate() -> io::Result<Self> {
        let mut bytes = [0_u8; TOKEN_LEN];
        getrandom::fill(&mut bytes)
            .map_err(|err| io::Error::other(format!("the system has no randomness: {err}")))?;
        Ok(Self(Arc::new(bytes)))
    }

    fn matches(&self, presented: &[u8; TOKEN_LEN]) -> bool {
        bool::from(self.0[..].ct_eq(&presented[..]))
    }
}

/// What the front puts in front of the HTTP/2 connection: the credential and the PROXY header of
/// the client. `local_ip` is the address the client connected to, when the socket knows it.
///
/// # Errors
///
/// [`EncodeError`] when `server_name` is empty or longer than the authority TLV allows.
pub(crate) fn preamble(
    token: &Token,
    client: SocketAddr,
    local_ip: Option<IpAddr>,
    local_port: u16,
    server_name: &str,
) -> Result<Vec<u8>, EncodeError> {
    let addresses = match client.ip().to_canonical() {
        IpAddr::V4(source) => Addresses::V4 {
            source: SocketAddrV4::new(source, client.port()),
            destination: SocketAddrV4::new(
                match local_ip.map(|ip| ip.to_canonical()) {
                    Some(IpAddr::V4(ip)) => ip,
                    _ => Ipv4Addr::UNSPECIFIED,
                },
                local_port,
            ),
        },
        IpAddr::V6(source) => Addresses::V6 {
            source: SocketAddrV6::new(source, client.port(), 0, 0),
            destination: SocketAddrV6::new(
                match local_ip.map(|ip| ip.to_canonical()) {
                    Some(IpAddr::V6(ip)) => ip,
                    _ => Ipv6Addr::UNSPECIFIED,
                },
                local_port,
                0,
                0,
            ),
        },
    };
    let header = Header::Proxied {
        addresses,
        authority: Some(server_name.into()),
    };
    let mut out = Vec::with_capacity(TOKEN_LEN + 64);
    out.extend_from_slice(&token.0[..]);
    header.encode(Version::V2, &mut out)?;
    Ok(out)
}

/// Why the pipeline's socket let a peer go.
#[derive(Debug, Error)]
enum Refused {
    #[error("the peer's uid is not the one podgate runs as")]
    Uid,
    #[error("the peer could not be identified")]
    Unidentified,
    #[error("the credential is missing or wrong")]
    Token,
    #[error("no acceptable PROXY header with a server name")]
    Header(#[source] Option<ReadError>),
}

/// The pipeline's side: a unix socket that only the front gets through.
///
/// [`serve`] is its accept loop.
pub(crate) struct LinkServer {
    listener: std::os::unix::net::UnixListener,
    owner: u32,
    token: Token,
    app: Arc<Policed>,
    path: PathBuf,
}

impl std::fmt::Debug for LinkServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkServer")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl LinkServer {
    /// Binds `path` (mode `0600`, replacing a stale socket) for the pipeline `app`, which only
    /// the holder of `token` may use.
    ///
    /// # Errors
    ///
    /// The error of binding the socket or reading its owner.
    pub(crate) fn bind(path: &Path, token: Token, app: Policed) -> io::Result<Self> {
        let listener = crate::admin::bind(path)?;
        let owner = std::fs::metadata(path)?.uid();
        Ok(Self {
            listener,
            owner,
            token,
            app: Arc::new(app),
            path: path.to_path_buf(),
        })
    }

    /// Accepts connections until `shutdown` fires, serving each admitted one as an HTTP/2
    /// connection of the pipeline.
    pub(crate) async fn serve(self, mut shutdown: ShutdownWatch) {
        let listener = match UnixListener::from_std(self.listener) {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(%err, path = %self.path.display(), "cannot serve the HTTP/3 internal socket");
                return;
            }
        };
        loop {
            let accepted = tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                accepted = listener.accept() => accepted,
            };
            let stream = match accepted {
                Ok((stream, _)) => stream,
                Err(err) => {
                    tracing::warn!(%err, "accepting on the HTTP/3 internal socket failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let (owner, token, app, shutdown) = (
                self.owner,
                self.token.clone(),
                Arc::clone(&self.app),
                shutdown.clone(),
            );
            tokio::spawn(async move {
                match admit(stream, owner, &token).await {
                    Ok(link) => {
                        // An HTTP/2 connection is not reusable: whatever comes back is dropped.
                        drop(ServerApp::process_new(&app, Box::new(link), &shutdown).await);
                    }
                    Err(refused) => {
                        tracing::warn!(reason = %refused, "refused a peer of the HTTP/3 internal socket");
                    }
                }
            });
        }
        drop(std::fs::remove_file(&self.path));
    }
}

/// The checks of [`LinkServer`] on one accepted connection.
async fn admit(mut stream: UnixStream, owner: u32, token: &Token) -> Result<Link, Refused> {
    let peer = stream.peer_cred().map_err(|_| Refused::Unidentified)?;
    if peer.uid() != owner {
        return Err(Refused::Uid);
    }
    let mut presented = [0_u8; TOKEN_LEN];
    tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut presented))
        .await
        .map_err(|_| Refused::Token)?
        .map_err(|_| Refused::Token)?;
    if !token.matches(&presented) {
        return Err(Refused::Token);
    }
    let header = read_header(&mut stream, READ_TIMEOUT)
        .await
        .map_err(|err| Refused::Header(Some(err)))?;
    Link::new(stream, &header).ok_or(Refused::Header(None))
}

/// An admitted connection of the front, as the pipeline sees it.
#[derive(Debug)]
pub(crate) struct Link {
    stream: L4Stream,
    tls: Arc<SslDigest>,
    socket: Arc<SocketDigest>,
}

impl Link {
    /// The link of `stream` as `header` describes its client; `None` unless the header names
    /// the client and the server name.
    fn new(stream: UnixStream, header: &Header) -> Option<Self> {
        let source = header.source()?;
        let name = host::normalize(header.authority()?);
        let stream = L4Stream::from(stream);
        let socket = SocketDigest::from_raw_fd(stream.as_raw_fd());
        let _ = socket.peer_addr.set(Some(source.into()));
        let _ = socket.local_addr.set(header.destination().map(Into::into));
        Some(Self {
            tls: Arc::new(SslDigest::new(
                LINK_CIPHER,
                LINK_VERSION,
                Some(name.into_owned()),
                None,
                Vec::new(),
            )),
            socket: Arc::new(socket),
            stream,
        })
    }
}

impl AsyncRead for Link {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Link {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

#[async_trait]
impl Shutdown for Link {
    async fn shutdown(&mut self) {
        Shutdown::shutdown(&mut self.stream).await;
    }
}

impl UniqueID for Link {
    fn id(&self) -> UniqueIDType {
        self.stream.id()
    }
}

impl Ssl for Link {
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        Some(Arc::clone(&self.tls))
    }

    fn selected_alpn_proto(&self) -> Option<ALPN> {
        Some(ALPN::H2)
    }
}

#[async_trait]
impl Peek for Link {
    async fn try_peek(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        self.stream.try_peek(buf).await
    }
}

impl GetTimingDigest for Link {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.stream.get_timing_digest()
    }

    fn get_read_pending_time(&self) -> Duration {
        self.stream.get_read_pending_time()
    }

    fn get_write_pending_time(&self) -> Duration {
        self.stream.get_write_pending_time()
    }
}

impl GetProxyDigest for Link {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.stream.get_proxy_digest()
    }
}

impl GetSocketDigest for Link {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        Some(Arc::clone(&self.socket))
    }
}

/// Why the front could not reach the pipeline.
#[derive(Debug, Error)]
pub(crate) enum UplinkError {
    /// Connecting to the socket or writing the preamble failed or timed out.
    #[error("cannot connect to the pipeline")]
    Connect(#[source] io::Error),
    /// The HTTP/2 handshake failed.
    #[error("the pipeline did not complete the HTTP/2 handshake")]
    Handshake(#[source] h2::Error),
}

/// The front's side of one QUIC connection's internal connection: opened on the first request,
/// shared by all the requests of the connection, and opened again if the pipeline closed it.
#[derive(Debug)]
pub(crate) struct Uplink {
    path: PathBuf,
    preamble: Vec<u8>,
    open: Mutex<Option<(SendRequest<Bytes>, AbortHandle)>>,
}

impl Uplink {
    /// An uplink to `path` that opens with `preamble`; nothing is connected yet.
    pub(crate) fn new(path: &Path, preamble: Vec<u8>) -> Self {
        Self {
            path: path.to_path_buf(),
            preamble,
            open: Mutex::new(None),
        }
    }

    /// The HTTP/2 sender of the connection, connecting first when there is none or it closed.
    ///
    /// # Errors
    ///
    /// [`UplinkError`] when the pipeline cannot be reached.
    pub(crate) async fn sender(&self) -> Result<SendRequest<Bytes>, UplinkError> {
        let mut open = self.open.lock().await;
        if let Some((sender, driver)) = open.as_ref()
            && !driver.is_finished()
        {
            return Ok(sender.clone());
        }
        let (sender, driver) = self.connect().await?;
        *open = Some((sender.clone(), driver));
        Ok(sender)
    }

    /// Forgets a sender that failed, so the next [`Self::sender`] connects again.
    pub(crate) async fn forget(&self) {
        if let Some((_, driver)) = self.open.lock().await.take() {
            driver.abort();
        }
    }

    async fn connect(&self) -> Result<(SendRequest<Bytes>, AbortHandle), UplinkError> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
            let mut stream = UnixStream::connect(&self.path).await?;
            stream.write_all(&self.preamble).await?;
            io::Result::Ok(stream)
        })
        .await
        .map_err(|_| UplinkError::Connect(io::ErrorKind::TimedOut.into()))?
        .map_err(UplinkError::Connect)?;
        // One window per connection and per stream, so what the bridge holds is bounded.
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(INTERNAL_WINDOW)
            .initial_connection_window_size(INTERNAL_WINDOW)
            .enable_push(false)
            .handshake::<_, Bytes>(stream)
            .await
            .map_err(UplinkError::Handshake)?;
        let driver = tokio::spawn(async move {
            // The connection ends when the pipeline closes it or the last sender drops.
            drop(connection.await);
        });
        Ok((sender, driver.abort_handle()))
    }
}

impl Drop for Uplink {
    fn drop(&mut self) {
        if let Some((_, driver)) = self.open.get_mut().take() {
            driver.abort();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::entry::proxy_protocol::{Parse, parse};

    #[test]
    fn the_preamble_is_the_token_then_a_header_the_codec_reads_back() {
        let token = Token::generate().expect("random");
        let client: SocketAddr = "198.51.100.7:50000".parse().expect("addr");
        let bytes = preamble(
            &token,
            client,
            Some("203.0.113.1".parse().expect("ip")),
            443,
            "a.test",
        )
        .expect("encodes");
        assert_eq!(&bytes[..TOKEN_LEN], &token.0[..]);
        let Ok(Parse::Header(header, used)) = parse(&bytes[TOKEN_LEN..]) else {
            panic!("not a header");
        };
        assert_eq!(used, bytes.len() - TOKEN_LEN);
        assert_eq!(header.source(), Some(client));
        assert_eq!(
            header.destination(),
            Some("203.0.113.1:443".parse().expect("addr"))
        );
        assert_eq!(header.authority(), Some("a.test"));
    }

    #[test]
    fn a_mapped_ipv4_client_and_an_unknown_local_address_still_pair() {
        let token = Token::generate().expect("random");
        let client: SocketAddr = "[::ffff:198.51.100.7]:50000".parse().expect("addr");
        let bytes = preamble(&token, client, None, 443, "a.test").expect("encodes");
        let Ok(Parse::Header(header, _)) = parse(&bytes[TOKEN_LEN..]) else {
            panic!("not a header");
        };
        assert_eq!(
            header.source(),
            Some("198.51.100.7:50000".parse().expect("addr"))
        );
        assert_eq!(
            header.destination(),
            Some("0.0.0.0:443".parse().expect("addr"))
        );
    }

    #[test]
    fn a_server_name_the_authority_cannot_carry_is_an_error() {
        let token = Token::generate().expect("random");
        let client: SocketAddr = "198.51.100.7:50000".parse().expect("addr");
        assert!(preamble(&token, client, None, 443, "").is_err());
        assert!(preamble(&token, client, None, 443, &"a".repeat(256)).is_err());
    }

    #[test]
    fn only_the_same_token_matches() {
        let one = Token::generate().expect("random");
        let two = Token::generate().expect("random");
        assert!(one.matches(&one.0));
        assert!(!one.matches(&two.0));
    }

    #[test]
    fn a_front_link_is_told_by_its_cipher_name() {
        let link = SslDigest::new(
            LINK_CIPHER,
            LINK_VERSION,
            Some("a.test".into()),
            None,
            vec![],
        );
        assert!(is_front_link(&link));
        let tls = SslDigest::new(
            "TLS13_AES_128_GCM_SHA256",
            "TLSv1_3",
            Some("a.test".into()),
            None,
            vec![],
        );
        assert!(!is_front_link(&tls));
    }
}
