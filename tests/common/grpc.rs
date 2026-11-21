//! A gRPC server and client on the `h2` crate, written at the frame level.
//!
//! No `tonic`: a hand-written peer is also what lets a test send what a client library never
//! would (a reset in the middle of a stream, a response with no head, a trailers-only error).
//!
//! - [`Server`]: an upstream over cleartext HTTP/2 ([`Server::h2c`]) or TLS with ALPN `h2`
//!   ([`Server::tls`]). The method name picks the behaviour, see [`path`].
//! - [`Client`]: one HTTP/2 connection (prior knowledge or TLS with ALPN `h2`); [`Call`] is one
//!   stream on it, with the length-prefixed message framing on both directions.
//! - [`Ca`]: a private certificate authority whose leaf certificates carry `127.0.0.1`.
//! - [`code_for_http`]: the gRPC status a client derives from the HTTP status of an answer that
//!   has no `grpc-status`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::{ResponseFuture, SendRequest};
use h2::server::SendResponse;
use h2::{Reason, RecvStream, SendStream};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Longest any single read, write or wait of a test peer may take.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Bytes in one message of the streaming methods.
pub const MESSAGE: usize = 64 * 1024;

/// The methods [`Server`] answers; any other path is answered `UNIMPLEMENTED` (12) in a
/// trailers-only response.
pub mod path {
    /// Reads one message and answers `echo:` and that message, with the trailers
    /// `grpc-status: 0`, `grpc-message: fine` and `x-custom-trailer: kept`.
    pub const UNARY: &str = "/test.Echo/Unary";
    /// Reads messages until the client ends the stream, answers one message `<count> <bytes>`.
    pub const CLIENT_STREAM: &str = "/test.Echo/ClientStream";
    /// The request message is a count and a size (two big-endian `u32`); answers that many
    /// messages of that many bytes, the first byte of message `i` being `i % 251`.
    pub const SERVER_STREAM: &str = "/test.Echo/ServerStream";
    /// Answers every message with itself the moment it arrives, ends when the client does.
    pub const BIDI: &str = "/test.Echo/Bidi";
    /// A trailers-only error: `grpc-status: 5`, `grpc-message: no such thing`, `x-meta: kept`.
    pub const FAIL: &str = "/test.Echo/Fail";
    /// One message, then trailers with `grpc-status: 3`, `grpc-message: bad thing`.
    pub const FAIL_AFTER_DATA: &str = "/test.Echo/FailAfterData";
    /// Answers the head and one message, then waits for a permit of [`super::Server::release`]
    /// before it ends. One more permit per further message of the three it sends.
    pub const PACED: &str = "/test.Echo/Paced";
    /// Answers the head and one message, then waits for a permit before the trailers.
    pub const HOLD: &str = "/test.Echo/Hold";
    /// Sends nothing and waits until the peer resets the stream.
    pub const HANG: &str = "/test.Echo/Hang";
    /// Sends the head and one message, then waits until the peer resets the stream.
    pub const HANG_AFTER_HEAD: &str = "/test.Echo/HangAfterHead";
    /// Sends the head and one message, then resets the stream with `INTERNAL_ERROR`.
    pub const RESET_AFTER_HEAD: &str = "/test.Echo/ResetAfterHead";
    /// Resets the stream with `REFUSED_STREAM` before it sent anything.
    pub const RESET_BEFORE_HEAD: &str = "/test.Echo/ResetBeforeHead";
    /// A message whose flag byte says compressed, under `grpc-encoding: gzip`; the payload is
    /// not gzip, so only a proxy that touches the body notices.
    pub const COMPRESSED: &str = "/test.Echo/Compressed";
    /// A response `cache-control: max-age=60` with one message.
    pub const CACHEABLE: &str = "/test.Echo/Cacheable";
}

// ---------------------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------------------

/// A length-prefixed gRPC message: the flag byte `flag`, a big-endian length, the payload.
pub fn frame_with(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(flag);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("a message under 4 GiB")
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out
}

/// [`frame_with`] flag `0`.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    frame_with(0, payload)
}

/// The request message of [`path::SERVER_STREAM`].
pub fn stream_request(count: u32, size: u32) -> Vec<u8> {
    [count.to_be_bytes(), size.to_be_bytes()].concat()
}

/// Bytes that arrive in pieces and leave as whole messages.
#[derive(Default)]
pub struct Messages(Vec<u8>);

impl Messages {
    pub fn push(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    /// The next whole `(flag, payload)`.
    pub fn next(&mut self) -> Option<(u8, Vec<u8>)> {
        let header = self.0.get(..5)?;
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if self.0.len() < 5 + len {
            return None;
        }
        let flag = self.0[0];
        let payload = self.0[5..5 + len].to_vec();
        self.0.drain(..5 + len);
        Some((flag, payload))
    }

    /// Bytes of an unfinished message.
    pub fn pending(&self) -> usize {
        self.0.len()
    }
}

/// What a gRPC client library makes of an HTTP answer that carries no `grpc-status`: the table
/// of `grpc/doc/http-grpc-status-mapping.md`.
pub fn code_for_http(status: u16) -> u32 {
    match status {
        400 => 13,
        401 => 16,
        403 => 7,
        404 => 12,
        429 | 502..=504 => 14,
        _ => 2,
    }
}

// ---------------------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------------------

/// A private certificate authority.
pub struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    /// The CA certificate, PEM: the `ca_pem` of a transport.
    pub pem: String,
}

impl Ca {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("CA key"))
            .expect("self-signed CA");
        let pem = issuer.pem();
        Self { issuer, pem }
    }

    /// A TLS acceptor for `127.0.0.1` that offers only `h2`.
    pub fn acceptor(&self) -> TlsAcceptor {
        let key = KeyPair::generate().expect("leaf key");
        let params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("leaf params");
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        let key = PrivateKeyDer::try_from(key.serialize_der()).expect("key");
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .expect("server config");
        config.alpn_protocols = vec![b"h2".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }
}

// ---------------------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------------------

/// What an upstream saw of one request head.
#[derive(Clone, Debug)]
pub struct Seen {
    pub path: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    /// The number of the connection it came on, from 1.
    pub connection: u64,
}

impl Seen {
    /// The first header called `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct State {
    calls: Mutex<Vec<Seen>>,
    /// How each stream ended on the server side: `reset:<REASON>`, `closed` for a connection
    /// that went away, `done` for a stream the server finished.
    ends: Mutex<Vec<(Instant, String)>>,
    connections: AtomicU64,
    /// Permits the paced methods take.
    gate: Semaphore,
}

/// A gRPC upstream. The tasks end with the test's runtime.
pub struct Server {
    pub addr: SocketAddr,
    tls: bool,
    state: Arc<State>,
}

impl Server {
    /// Cleartext HTTP/2 by prior knowledge: the target of an `h2c://` server.
    pub async fn h2c() -> Self {
        Self::start(None).await
    }

    /// HTTP/2 over TLS with ALPN `h2`, for an `https://` server whose transport trusts `ca`.
    pub async fn tls(ca: &Ca) -> Self {
        Self::start(Some(ca.acceptor())).await
    }

    async fn start(acceptor: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the gRPC server");
        let addr = listener.local_addr().expect("addr");
        let state = Arc::new(State {
            calls: Mutex::default(),
            ends: Mutex::default(),
            connections: AtomicU64::new(0),
            gate: Semaphore::new(0),
        });
        let tls = acceptor.is_some();
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let number = shared.connections.fetch_add(1, Ordering::Relaxed) + 1;
                // Small WINDOW_UPDATE frames must not wait on a delayed ACK (Nagle).
                drop(tcp.set_nodelay(true));
                let (state, acceptor) = (Arc::clone(&shared), acceptor.clone());
                tokio::spawn(async move {
                    match acceptor {
                        None => connection(tcp, number, state).await,
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(tcp).await {
                                connection(stream, number, state).await;
                            }
                        }
                    }
                });
            }
        });
        Self { addr, tls, state }
    }

    /// The `url` of this server in a service.
    pub fn url(&self) -> String {
        format!("{}://{}", if self.tls { "https" } else { "h2c" }, self.addr)
    }

    /// Every request head seen so far, in arrival order.
    pub fn calls(&self) -> Vec<Seen> {
        self.state.calls.lock().expect("calls").clone()
    }

    /// How many requests for `path` arrived.
    pub fn calls_to(&self, path: &str) -> usize {
        self.calls().iter().filter(|seen| seen.path == path).count()
    }

    /// The connections accepted so far.
    pub fn connections(&self) -> u64 {
        self.state.connections.load(Ordering::Relaxed)
    }

    /// Waits until `n` requests for `path` have arrived.
    pub async fn wait_calls(&self, path: &str, n: usize) {
        let deadline = Instant::now() + IO_TIMEOUT;
        while self.calls_to(path) < n {
            assert!(
                Instant::now() < deadline,
                "{n} calls to {path} never arrived: {:?}",
                self.calls()
            );
            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Lets `n` paced streams take their next step.
    pub fn release(&self, n: usize) {
        self.state.gate.add_permits(n);
    }

    /// How the streams ended so far.
    pub fn ends(&self) -> Vec<String> {
        self.state
            .ends
            .lock()
            .expect("ends")
            .iter()
            .map(|(_, how)| how.clone())
            .collect()
    }

    /// Waits until a stream ended with `how` after `since`, and says how long after `since`.
    pub async fn wait_end(&self, how: &str, since: Instant, within: Duration) -> Duration {
        let deadline = since + within;
        loop {
            let found = self
                .state
                .ends
                .lock()
                .expect("ends")
                .iter()
                .find(|(at, ended)| *at >= since && ended.starts_with(how))
                .map(|(at, _)| at.duration_since(since));
            if let Some(after) = found {
                return after;
            }
            assert!(
                Instant::now() < deadline,
                "no stream ended with {how} within {within:?} of the cancel: {:?}",
                self.ends()
            );
            sleep(Duration::from_millis(10)).await;
        }
    }
}

impl State {
    fn ended(&self, how: impl Into<String>) {
        self.ends
            .lock()
            .expect("ends")
            .push((Instant::now(), how.into()));
    }
}

async fn connection<S>(stream: S, number: u64, state: Arc<State>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::Builder::new()
        .max_frame_size(65_536)
        .initial_window_size(1 << 20)
        .initial_connection_window_size(1 << 20)
        .handshake::<_, Bytes>(stream)
        .await
    else {
        return;
    };
    while let Some(Ok((request, respond))) = connection.accept().await {
        let state = Arc::clone(&state);
        tokio::spawn(handle(request, respond, number, state));
    }
}

fn head(extra: &[(&str, &str)]) -> Response<()> {
    let mut head = Response::builder()
        .status(200)
        .header("content-type", "application/grpc");
    for (name, value) in extra {
        head = head.header(*name, *value);
    }
    head.body(()).expect("response")
}

fn trailers(status: u32, extra: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert("grpc-status", HeaderValue::from(status));
    for (name, value) in extra {
        map.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("name"),
            HeaderValue::from_str(value).expect("value"),
        );
    }
    map
}

/// Sends `data` as DATA frames, waiting for the peer's flow-control window as it must.
async fn send_flow(send: &mut SendStream<Bytes>, mut data: Bytes) -> Result<(), h2::Error> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| h2::Error::from(Reason::CANCEL))??;
        if capacity > 0 {
            send.send_data(data.split_to(capacity.min(data.len())), false)?;
        }
    }
    Ok(())
}

/// The request body as whole messages.
struct Incoming {
    body: RecvStream,
    buffer: Messages,
    ended: bool,
}

impl Incoming {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, h2::Error> {
        loop {
            if let Some((_, payload)) = self.buffer.next() {
                return Ok(Some(payload));
            }
            if self.ended {
                return Ok(None);
            }
            match self.body.data().await {
                Some(Ok(chunk)) => {
                    drop(self.body.flow_control().release_capacity(chunk.len()));
                    self.buffer.push(&chunk);
                }
                Some(Err(err)) => return Err(err),
                None => self.ended = true,
            }
        }
    }
}

async fn handle(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    connection: u64,
    state: Arc<State>,
) {
    let path = request.uri().path().to_owned();
    state.calls.lock().expect("calls").push(Seen {
        path: path.clone(),
        method: request.method().to_string(),
        headers: request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect(),
        connection,
    });
    let mut incoming = Incoming {
        body: request.into_body(),
        buffer: Messages::default(),
        ended: false,
    };
    let how = match answer(&path, &mut incoming, &mut respond, &state).await {
        Ok(()) => "done".to_owned(),
        Err(err) => match err.reason() {
            Some(reason) => format!("reset:{reason:?}"),
            None => "closed".to_owned(),
        },
    };
    state.ended(how);
}

// One arm per method of the test server.
#[allow(clippy::too_many_lines)]
async fn answer(
    path: &str,
    incoming: &mut Incoming,
    respond: &mut SendResponse<Bytes>,
    state: &State,
) -> Result<(), h2::Error> {
    match path {
        path::UNARY => {
            let message = incoming.next().await?.unwrap_or_default();
            while incoming.next().await?.is_some() {}
            let mut send = respond.send_response(head(&[("x-custom-header", "kept")]), false)?;
            send_flow(
                &mut send,
                Bytes::from(frame(&[b"echo:".as_slice(), &message].concat())),
            )
            .await?;
            send.send_trailers(trailers(
                0,
                &[("grpc-message", "fine"), ("x-custom-trailer", "kept")],
            ))
        }
        path::CLIENT_STREAM => {
            let (mut count, mut bytes) = (0_u64, 0_u64);
            while let Some(message) = incoming.next().await? {
                count += 1;
                bytes += message.len() as u64;
            }
            let mut send = respond.send_response(head(&[]), false)?;
            send.send_data(
                Bytes::from(frame(format!("{count} {bytes}").as_bytes())),
                false,
            )?;
            send.send_trailers(trailers(0, &[]))
        }
        path::SERVER_STREAM => {
            let request = incoming.next().await?.unwrap_or_default();
            let number = |at: usize| {
                request
                    .get(at..at + 4)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map_or(0, u32::from_be_bytes)
            };
            let (count, size) = (number(0), number(4) as usize);
            let mut send = respond.send_response(head(&[]), false)?;
            for index in 0..count {
                let payload = vec![u8::try_from(index % 251).unwrap_or(0); size];
                send_flow(&mut send, Bytes::from(frame(&payload))).await?;
            }
            send.send_trailers(trailers(0, &[]))
        }
        path::BIDI => {
            let mut send = respond.send_response(head(&[]), false)?;
            while let Some(message) = incoming.next().await? {
                send_flow(&mut send, Bytes::from(frame(&message))).await?;
            }
            send.send_trailers(trailers(0, &[]))
        }
        path::FAIL => {
            respond.send_response(
                Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "5")
                    .header("grpc-message", "no such thing")
                    .header("x-meta", "kept")
                    .body(())
                    .expect("response"),
                true,
            )?;
            Ok(())
        }
        path::FAIL_AFTER_DATA => {
            let mut send = respond.send_response(head(&[]), false)?;
            send.send_data(Bytes::from(frame(b"partial")), false)?;
            send.send_trailers(trailers(
                3,
                &[("grpc-message", "bad thing"), ("x-meta", "kept")],
            ))
        }
        path::PACED => {
            let mut send = respond.send_response(head(&[]), false)?;
            for (index, message) in [b"msg1", b"msg2", b"msg3"].iter().enumerate() {
                if index > 0 {
                    state.gate.acquire().await.expect("gate open").forget();
                }
                send.send_data(Bytes::from(frame(*message)), false)?;
            }
            send.send_trailers(trailers(0, &[]))
        }
        path::HOLD => {
            let mut send = respond.send_response(head(&[]), false)?;
            send.send_data(Bytes::from(frame(b"first")), false)?;
            state.gate.acquire().await.expect("gate open").forget();
            send.send_trailers(trailers(0, &[]))
        }
        path::HANG => {
            let reason = std::future::poll_fn(|cx| respond.poll_reset(cx)).await?;
            Err(h2::Error::from(reason))
        }
        path::HANG_AFTER_HEAD => {
            let mut send = respond.send_response(head(&[]), false)?;
            send.send_data(Bytes::from(frame(b"first")), false)?;
            let reason = std::future::poll_fn(|cx| send.poll_reset(cx)).await?;
            Err(h2::Error::from(reason))
        }
        path::RESET_AFTER_HEAD => {
            let mut send = respond.send_response(head(&[]), false)?;
            send.send_data(Bytes::from(frame(b"first")), false)?;
            // Long enough for the peer to read the head and the message before the reset.
            sleep(Duration::from_millis(200)).await;
            send.send_reset(Reason::INTERNAL_ERROR);
            Ok(())
        }
        path::RESET_BEFORE_HEAD => {
            respond.send_reset(Reason::REFUSED_STREAM);
            Ok(())
        }
        path::COMPRESSED => {
            let mut send = respond.send_response(head(&[("grpc-encoding", "gzip")]), false)?;
            send.send_data(Bytes::from(frame_with(1, b"not really gzip")), false)?;
            send.send_trailers(trailers(0, &[]))
        }
        path::CACHEABLE => {
            let mut send =
                respond.send_response(head(&[("cache-control", "max-age=60")]), false)?;
            send.send_data(Bytes::from(frame(b"fresh")), false)?;
            send.send_trailers(trailers(0, &[]))
        }
        _ => {
            respond.send_response(
                Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "12")
                    .header("grpc-message", "unimplemented")
                    .body(())
                    .expect("response"),
                true,
            )?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------------------

/// One HTTP/2 connection to a proxy.
#[derive(Clone)]
pub struct Client {
    send: SendRequest<Bytes>,
    scheme: &'static str,
    authority: String,
    alpn: Option<Vec<u8>>,
}

impl Client {
    /// Cleartext HTTP/2 with prior knowledge, `:authority` `authority`.
    pub async fn h2c(addr: SocketAddr, authority: &str) -> Self {
        let tcp = timeout(IO_TIMEOUT, TcpStream::connect(addr))
            .await
            .expect("connect in time")
            .expect("connect");
        tcp.set_nodelay(true).expect("nodelay");
        Self::over(tcp, "http", authority, None).await
    }

    /// TLS with ALPN `h2`, SNI `sni`, trusting only `trusted`, `:authority` `sni`.
    pub async fn tls(addr: SocketAddr, sni: &str, trusted: &CertificateDer<'static>) -> Self {
        Box::pin(Self::tls_boxed(addr, sni, trusted)).await
    }

    async fn tls_boxed(addr: SocketAddr, sni: &str, trusted: &CertificateDer<'static>) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(trusted.clone()).expect("trust the certificate");
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let name = ServerName::try_from(sni.to_owned()).expect("server name");
        let tcp = timeout(IO_TIMEOUT, TcpStream::connect(addr))
            .await
            .expect("connect in time")
            .expect("connect");
        tcp.set_nodelay(true).expect("nodelay");
        let stream = timeout(
            IO_TIMEOUT,
            TlsConnector::from(Arc::new(config)).connect(name, tcp),
        )
        .await
        .expect("handshake in time")
        .expect("TLS handshake");
        let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        Self::over(stream, "https", sni, alpn).await
    }

    async fn over<S>(
        stream: S,
        scheme: &'static str,
        authority: &str,
        alpn: Option<Vec<u8>>,
    ) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (send, connection) = h2::client::Builder::new()
            .max_frame_size(65_536)
            .initial_window_size(1 << 20)
            .initial_connection_window_size(1 << 20)
            .handshake::<_, Bytes>(stream)
            .await
            .expect("HTTP/2 handshake");
        tokio::spawn(async move {
            drop(connection.await);
        });
        Self {
            send,
            scheme,
            authority: authority.to_owned(),
            alpn,
        }
    }

    /// The ALPN protocol the TLS handshake selected, `None` for cleartext.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The same connection with another `:authority`.
    #[must_use]
    pub fn with_authority(&self, authority: &str) -> Self {
        Self {
            authority: authority.to_owned(),
            ..self.clone()
        }
    }

    /// Starts a call to `path` with `headers` besides the gRPC ones. The request is not ended.
    pub async fn start(&self, path: &str, headers: &[(&str, &str)]) -> Call {
        self.start_with("application/grpc", path, headers).await
    }

    /// [`Self::start`] with another `content-type` (gRPC-Web).
    pub async fn start_with(
        &self,
        content_type: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Call {
        self.start_request("POST", content_type, path, headers)
            .await
    }

    /// [`Self::start_with`] with any method: gRPC is always `POST`, a test that probes what a
    /// proxy does with anything else is not.
    pub async fn start_request(
        &self,
        method: &str,
        content_type: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Call {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{}://{}{path}", self.scheme, self.authority))
            .header("content-type", content_type)
            .header("te", "trailers")
            .header("user-agent", "podgate-test-grpc");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(()).expect("request");
        let mut send = self.send.clone().ready().await.expect("connection ready");
        let (response, stream) = send.send_request(request, false).expect("send request");
        Call {
            send: stream,
            response: Some(response),
            head: None,
            body: None,
            buffer: Messages::default(),
            trailers: None,
            ended: false,
        }
    }

    /// A whole unary call: one message in, everything out.
    pub async fn unary(&self, path: &str, payload: &[u8], headers: &[(&str, &str)]) -> Outcome {
        let mut call = self.start(path, headers).await;
        call.send(payload).await;
        call.finish();
        call.collect().await
    }

    /// [`Self::unary`], the response read as plain bytes: for an answer that is not gRPC.
    pub async fn unary_raw(&self, path: &str, payload: &[u8], headers: &[(&str, &str)]) -> Raw {
        let mut call = self.start(path, headers).await;
        call.send(payload).await;
        call.finish();
        call.raw().await
    }
}

/// A response read as plain bytes.
#[derive(Debug)]
pub struct Raw {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub trailers: Option<HeaderMap>,
}

impl Raw {
    /// The first value of response header `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// The body as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {:?}", self.body))
    }
}

/// What a call returned.
#[derive(Debug)]
pub struct Outcome {
    pub status: u16,
    pub headers: HeaderMap,
    pub messages: Vec<(u8, Vec<u8>)>,
    pub trailers: Option<HeaderMap>,
}

impl Outcome {
    /// The `grpc-status` of the trailers, or of a trailers-only head.
    pub fn grpc_status(&self) -> Option<u32> {
        self.trailers
            .as_ref()
            .and_then(|map| map.get("grpc-status"))
            .or_else(|| self.headers.get("grpc-status"))
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.parse().ok())
    }

    /// The first value of response header or trailer `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .or_else(|| self.trailers.as_ref().and_then(|map| map.get(name)))
            .and_then(|value| value.to_str().ok())
    }

    /// The payloads of the messages.
    pub fn payloads(&self) -> Vec<&[u8]> {
        self.messages
            .iter()
            .map(|(_, payload)| payload.as_slice())
            .collect()
    }
}

/// One stream of a [`Client`].
pub struct Call {
    send: SendStream<Bytes>,
    response: Option<ResponseFuture>,
    head: Option<http::response::Parts>,
    body: Option<RecvStream>,
    buffer: Messages,
    trailers: Option<HeaderMap>,
    ended: bool,
}

impl Call {
    /// Sends one message, waiting for flow control as it must.
    pub async fn send(&mut self, payload: &[u8]) {
        self.try_send(Bytes::from(frame(payload)))
            .await
            .expect("the message goes out");
    }

    /// Sends `bytes` as DATA, in as many frames as the peer's window allows.
    pub async fn try_send(&mut self, mut data: Bytes) -> Result<(), h2::Error> {
        while !data.is_empty() {
            self.send.reserve_capacity(data.len());
            let capacity = timeout(
                IO_TIMEOUT,
                std::future::poll_fn(|cx| self.send.poll_capacity(cx)),
            )
            .await
            .expect("flow control in time")
            .ok_or_else(|| h2::Error::from(Reason::CANCEL))??;
            if capacity > 0 {
                self.send
                    .send_data(data.split_to(capacity.min(data.len())), false)?;
            }
        }
        Ok(())
    }

    /// Ends the request stream.
    pub fn finish(&mut self) {
        self.send
            .send_data(Bytes::new(), true)
            .expect("the request ends");
    }

    /// Resets the stream, as a client that gave up does.
    pub fn reset(&mut self) {
        self.send.send_reset(Reason::CANCEL);
    }

    /// The response head; waits for it.
    pub async fn head(&mut self) -> &http::response::Parts {
        self.try_head().await.expect("a response head")
    }

    /// [`Self::head`], the error of a stream that ended before one.
    pub async fn try_head(&mut self) -> Result<&http::response::Parts, h2::Error> {
        if self.head.is_none() {
            let response = self.response.take().expect("a response future");
            let (parts, body) = timeout(IO_TIMEOUT, response)
                .await
                .expect("a response head in time")?
                .into_parts();
            self.head = Some(parts);
            self.body = Some(body);
        }
        Ok(self.head.as_ref().expect("head"))
    }

    /// The next whole message; `None` once the body ended.
    pub async fn message(&mut self) -> Option<(u8, Vec<u8>)> {
        self.try_message().await.expect("the body reads")
    }

    /// [`Self::message`], the error of a stream that was reset.
    pub async fn try_message(&mut self) -> Result<Option<(u8, Vec<u8>)>, h2::Error> {
        self.try_head().await?;
        loop {
            if let Some(message) = self.buffer.next() {
                return Ok(Some(message));
            }
            if self.ended {
                return Ok(None);
            }
            let body = self.body.as_mut().expect("a body");
            match timeout(IO_TIMEOUT, body.data())
                .await
                .expect("body data in time")
            {
                Some(Ok(chunk)) => {
                    drop(body.flow_control().release_capacity(chunk.len()));
                    self.buffer.push(&chunk);
                }
                Some(Err(err)) => return Err(err),
                None => {
                    self.ended = true;
                    self.trailers = timeout(IO_TIMEOUT, body.trailers())
                        .await
                        .expect("trailers in time")?;
                }
            }
        }
    }

    /// Reads to the end and returns everything; the trailers are `None` when there were none.
    pub async fn collect(&mut self) -> Outcome {
        self.try_collect().await.expect("the response reads")
    }

    /// [`Self::collect`], the error of a stream that was reset.
    pub async fn try_collect(&mut self) -> Result<Outcome, h2::Error> {
        let mut messages = Vec::new();
        while let Some(message) = self.try_message().await? {
            messages.push(message);
        }
        assert_eq!(self.buffer.pending(), 0, "the body ended inside a message");
        let head = self.head.as_ref().expect("head");
        Ok(Outcome {
            status: head.status.as_u16(),
            headers: head.headers.clone(),
            messages,
            trailers: self.trailers.take(),
        })
    }

    /// Reads the body to its end as plain bytes, without the message framing.
    pub async fn raw(&mut self) -> Raw {
        self.head().await;
        let head = self.head.as_ref().expect("head");
        let (status, headers) = (head.status.as_u16(), head.headers.clone());
        let mut body = Vec::new();
        let stream = self.body.as_mut().expect("a body");
        while let Some(chunk) = timeout(IO_TIMEOUT, stream.data())
            .await
            .expect("body data in time")
        {
            let chunk = chunk.expect("the body reads");
            drop(stream.flow_control().release_capacity(chunk.len()));
            body.extend_from_slice(&chunk);
        }
        let trailers = timeout(IO_TIMEOUT, stream.trailers())
            .await
            .expect("trailers in time")
            .expect("the trailers read");
        Raw {
            status,
            headers,
            body,
            trailers,
        }
    }
}
