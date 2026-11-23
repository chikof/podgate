//! The HTTP/3 front: one task per QUIC connection, one per request stream, and the bridge of each
//! request into the pipeline over the internal connection ([`super::bridge`]).
//!
//! A connection goes through four steps, each of which can end it:
//!
//! 1. The handshake, within [`HANDSHAKE_TIMEOUT`], counted in `H3_MAX_HANDSHAKES`.
//! 2. The tenant. The server name that the handshake carried names the app that claims it, and
//!    so the tenant; [`Settings::reservation`] is charged to that tenant's `max_buffer_bytes`
//!    until the connection ends. A tenant over budget gets the connection closed with
//!    `H3_EXCESSIVE_LOAD`.
//! 3. The HTTP/3 connection with the limits of [`super::limits`]: request header sections up to
//!    64 KiB, no datagrams, no WebTransport, no extended CONNECT.
//! 4. The requests. The internal connection to the pipeline is opened by the first one, so a
//!    connection that only idles costs no file descriptor and no pipeline state.
//!
//! A request is bridged without buffering: the request body flows from the QUIC stream into an
//! HTTP/2 stream and the response body back, each chunk waiting for the flow control of the side
//! it goes to, so a slow reader slows the sender instead of growing a queue. Trailers go both
//! ways. A request that has no body is sent with its headers alone (`END_STREAM`), so the
//! upstream does not see a chunked `GET`. When either side resets, the other is reset too; a
//! client that resets more than [`super::limits::RESETS_PER_SECOND`] streams in a second loses the connection
//! (the HTTP/3 form of the rapid reset attack).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use h2::client::{ResponseFuture, SendRequest};
use h2::{Reason, SendStream};
use h3::error::{Code, StreamError};
use h3::server::{RequestResolver, RequestStream};
use http::header::{
    CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderName, TE, TRANSFER_ENCODING, UPGRADE,
};
use http::{Method, Request, Response, StatusCode, Version};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::bridge::{LinkServer, Token, Uplink, UplinkError, preamble};
use super::endpoint;
use super::limits::{
    Closed, H3_EXCESSIVE_LOAD, H3_NO_ERROR, HANDSHAKE_TIMEOUT, Held, MAX_FIELD_SECTION_SIZE,
    Refused, ResetWindow, STATS, Settings,
};
use crate::budget::Budgets;
use crate::host;
use crate::table::TableHandle;
use crate::tls::ocsp::Staples;

type Resolver = RequestResolver<h3_quinn::Connection, Bytes>;
type SendHalf = RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type RecvHalf = RequestStream<h3_quinn::RecvStream, Bytes>;

/// Longest a request stream may take to send its header section.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest a `GET` or similar waits for its first body event before the request goes on as one
/// that may have a body.
const BODY_PROBE: Duration = Duration::from_millis(50);

/// Connection-specific headers: they have no meaning in HTTP/2 or HTTP/3 and are never copied.
const HOP_BY_HOP: [HeaderName; 4] = [CONNECTION, TRANSFER_ENCODING, UPGRADE, TE];

/// What the process holds for one HTTPS entry point's HTTP/3 front.
#[derive(Debug)]
pub(crate) struct Front {
    entry: Arc<str>,
    port: u16,
    table: TableHandle,
    budgets: Budgets,
    settings: Settings,
    link: PathBuf,
    token: Token,
    shutdown: ShutdownWatch,
}

impl Front {
    pub(super) fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Finishes the QUIC handshake of `connecting`, then serves the connection. The two guards
    /// count it in the node's caps: `handshake` ends with the handshake, `connection` with the
    /// connection.
    pub(super) async fn handshake(
        self: Arc<Self>,
        connecting: quinn::Connecting,
        connection: Held,
        handshake: Held,
    ) {
        let connected = timeout(HANDSHAKE_TIMEOUT, connecting).await;
        drop(handshake);
        let connection_open = match connected {
            Ok(Ok(open)) => open,
            Ok(Err(err)) => {
                tracing::debug!(entry_point = &*self.entry, %err, "QUIC handshake failed");
                return;
            }
            Err(_) => {
                tracing::debug!(entry_point = &*self.entry, "QUIC handshake timed out");
                return;
            }
        };
        Box::pin(self.serve(connection_open, connection)).await;
    }

    /// Charges the tenant, then runs the HTTP/3 connection until it ends.
    async fn serve(&self, connection: quinn::Connection, _open: Held) {
        let Some(name) = server_name(&connection) else {
            STATS.refused(Refused::NoTenant);
            connection.close(excessive(), b"no server name");
            return;
        };
        let host = host::normalize(&name).into_owned();
        let account = {
            let table = self.table.load();
            table.claimant(&host).and_then(|tenant| {
                table
                    .tenant_budget(tenant)
                    .map(|limits| self.budgets.tenant(tenant, limits))
            })
        };
        let Some(account) = account else {
            STATS.refused(Refused::NoTenant);
            connection.close(excessive(), b"no tenant for the server name");
            return;
        };
        let Some(_reservation) = account.charge(self.settings.reservation()) else {
            STATS.refused(Refused::OverBudget);
            STATS.closed(Closed::OverBudget);
            connection.close(excessive(), b"tenant over its connection budget");
            return;
        };
        let local = connection.local_ip();
        let port = self.port;
        let Ok(bytes) = preamble(&self.token, connection.remote_address(), local, port, &host)
        else {
            connection.close(excessive(), b"server name cannot be forwarded");
            return;
        };
        let peer = Arc::new(Peer {
            uplink: Uplink::new(&self.link, bytes),
            resets: Mutex::new(ResetWindow::new(Instant::now())),
            connection: connection.clone(),
        });
        Box::pin(self.run(&connection, &peer)).await;
        // The connection is over: wake whatever still waits on it, and free the reservation.
        connection.close(quinn::VarInt::from_u32(H3_NO_ERROR), b"");
        #[cfg(feature = "h3-stats")]
        Self::log_stats(&connection);
    }

    /// What QUIC loss recovery did on a connection, as one `podgate_h3_stats` event.
    /// The counters of `quinn::ConnectionStats` have no probe timeout count: one shows as a ping
    /// frame, or as stream frames sent a second time.
    #[cfg(feature = "h3-stats")]
    fn log_stats(connection: &quinn::Connection) {
        let stats = connection.stats();
        tracing::info!(
            target: "podgate_h3_stats",
            sent_packets = stats.path.sent_packets,
            lost_packets = stats.path.lost_packets,
            lost_bytes = stats.path.lost_bytes,
            congestion_events = stats.path.congestion_events,
            ping_frames_tx = stats.frame_tx.ping,
            ping_frames_rx = stats.frame_rx.ping,
            stream_frames_tx = stats.frame_tx.stream,
            stream_frames_rx = stats.frame_rx.stream,
            ack_frames_tx = stats.frame_tx.acks,
            udp_datagrams_tx = stats.udp_tx.datagrams,
            udp_datagrams_rx = stats.udp_rx.datagrams,
        );
    }

    async fn run(&self, connection: &quinn::Connection, peer: &Arc<Peer>) {
        let mut builder = h3::server::builder();
        builder
            .max_field_section_size(MAX_FIELD_SECTION_SIZE)
            .enable_webtransport(false)
            .enable_extended_connect(false)
            .enable_datagram(false);
        let mut h3 = match builder
            .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
        {
            Ok(h3) => h3,
            Err(err) => {
                tracing::debug!(entry_point = &*self.entry, %err, "HTTP/3 setup failed");
                return;
            }
        };
        let mut shutdown = self.shutdown.clone();
        let mut draining = false;
        let mut tasks = JoinSet::new();
        loop {
            // Reap finished requests so the set does not grow with the connection's age.
            while tasks.try_join_next().is_some() {}
            let accepted = tokio::select! {
                biased;
                _ = shutdown.changed(), if !draining => {
                    draining = true;
                    // Tell the client to open no more requests; those in flight finish.
                    drop(h3.shutdown(0).await);
                    continue;
                }
                accepted = h3.accept() => accepted,
            };
            match accepted {
                Ok(Some(resolver)) => {
                    tasks.spawn(request(resolver, Arc::clone(peer)));
                }
                Ok(None) => break,
                Err(err) => {
                    tracing::debug!(entry_point = &*self.entry, %err, "HTTP/3 connection ended");
                    break;
                }
            }
        }
    }
}

/// The application error code of `H3_EXCESSIVE_LOAD`.
fn excessive() -> quinn::VarInt {
    quinn::VarInt::from_u32(H3_EXCESSIVE_LOAD)
}

/// The server name the QUIC handshake carried.
fn server_name(connection: &quinn::Connection) -> Option<String> {
    let data = connection.handshake_data()?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    data.server_name
}

/// What the requests of one connection share.
#[derive(Debug)]
struct Peer {
    uplink: Uplink,
    resets: Mutex<ResetWindow>,
    connection: quinn::Connection,
}

impl Peer {
    /// Counts a stream the client reset; closes the connection when that is too many.
    fn reset(&self) {
        let exceeded = self
            .resets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(Instant::now());
        if exceeded {
            STATS.closed(Closed::RapidReset);
            self.connection
                .close(excessive(), b"too many stream resets");
        }
    }
}

/// Why a request ended before its response did.
#[derive(Debug)]
enum Abort {
    /// The client reset the stream or the connection went away.
    Client(Box<StreamError>),
    /// The pipeline refused or reset the stream.
    Pipeline(h2::Error),
}

impl From<StreamError> for Abort {
    fn from(err: StreamError) -> Self {
        Self::Client(Box::new(err))
    }
}

impl From<h2::Error> for Abort {
    fn from(err: h2::Error) -> Self {
        Self::Pipeline(err)
    }
}

/// Whether `err` is the client abandoning the stream.
fn is_client_reset(err: &StreamError) -> bool {
    matches!(err, StreamError::RemoteTerminate { .. })
        || matches!(
            err,
            StreamError::StreamError { code, .. } if *code == Code::H3_REQUEST_INCOMPLETE
        )
}

/// What the first look at a request's body found.
enum First {
    /// No body and no trailers: the headers can carry `END_STREAM`.
    End,
    /// The first chunk, already arrived.
    Data(Bytes),
    /// The body is over; trailers may follow.
    BodyDone,
    /// The trailers, with nothing before them.
    Trailers(HeaderMap),
    /// Nothing yet.
    Waiting,
}

/// Polls `future` once; `None` when it is not ready.
fn now_or_never<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

/// One request stream, from its headers to its last response byte.
async fn request(resolver: Resolver, peer: Arc<Peer>) {
    let resolved = timeout(HEAD_TIMEOUT, resolver.resolve_request()).await;
    let (request, stream) = match resolved {
        Ok(Ok(pair)) => pair,
        Ok(Err(err)) => {
            if is_client_reset(&err) {
                peer.reset();
            }
            tracing::debug!(%err, "HTTP/3 request header section refused");
            return;
        }
        Err(_) => {
            tracing::debug!("HTTP/3 request header section timed out");
            return;
        }
    };
    STATS.request();
    let (mut send, mut recv) = stream.split();
    if request.method() == Method::CONNECT {
        refuse(
            &mut send,
            StatusCode::NOT_IMPLEMENTED,
            "CONNECT is not supported over HTTP/3",
        )
        .await;
        return;
    }
    let first = match first_event(&mut recv, &request).await {
        Ok(first) => first,
        Err(err) => {
            if is_client_reset(&err) {
                peer.reset();
            }
            return;
        }
    };
    let ended = matches!(first, First::End);
    let (response, mut upstream) = match open(&peer.uplink, &request, ended).await {
        Ok(opened) => opened,
        Err(err) => {
            tracing::warn!(%err, "cannot send an HTTP/3 request to the pipeline");
            refuse(&mut send, StatusCode::BAD_GATEWAY, "bad gateway").await;
            return;
        }
    };
    let mut head_sent = false;
    let outcome = {
        let up = pump_request(&mut recv, &mut upstream, first);
        let down = pump_response(response, &mut send, &mut head_sent);
        let (mut up, mut down) = (pin!(up), pin!(down));
        let mut uploading = true;
        loop {
            tokio::select! {
                result = &mut up, if uploading => {
                    uploading = false;
                    // The pipeline may answer before it has read the whole body and reset the
                    // request stream; its response decides. Only the client leaving ends it.
                    if let Err(Abort::Client(err)) = result {
                        break Err(Abort::Client(err));
                    }
                }
                result = &mut down => break result,
            }
        }
    };
    match outcome {
        Ok(()) => recv.stop_sending(Code::H3_NO_ERROR),
        Err(Abort::Client(err)) => {
            if is_client_reset(&err) {
                peer.reset();
            }
            upstream.send_reset(Reason::CANCEL);
            send.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
        Err(Abort::Pipeline(err)) => {
            tracing::debug!(%err, "the pipeline ended an HTTP/3 request");
            recv.stop_sending(Code::H3_INTERNAL_ERROR);
            if head_sent {
                send.stop_stream(Code::H3_INTERNAL_ERROR);
            } else {
                refuse(&mut send, StatusCode::BAD_GATEWAY, "bad gateway").await;
            }
        }
    }
}

/// Answers a request podgate itself refuses, with the JSON error shape of the rest of the API.
async fn refuse(send: &mut SendHalf, status: StatusCode, message: &str) {
    let body = Bytes::from(format!("{{\"error\":{message:?}}}"));
    let mut head = Response::new(());
    *head.status_mut() = status;
    head.headers_mut().insert(
        CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    head.headers_mut()
        .insert(CONTENT_LENGTH, http::HeaderValue::from(body.len()));
    if send.send_response(head).await.is_ok() && send.send_data(body).await.is_ok() {
        drop(send.finish().await);
    }
}

/// The next piece of the request body as owned bytes, so nothing keeps `recv` borrowed.
async fn next_chunk(recv: &mut RecvHalf) -> Result<Option<Bytes>, StreamError> {
    Ok(recv
        .recv_data()
        .await?
        .map(|mut chunk| chunk.copy_to_bytes(chunk.remaining())))
}

/// The first body event of a request, found without waiting for a client that is still
/// typing: a method that usually has no body gets [`BODY_PROBE`] to show one, any other is sent
/// on at once.
async fn first_event(recv: &mut RecvHalf, request: &Request<()>) -> Result<First, StreamError> {
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let bodyless_method = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::DELETE | Method::OPTIONS | Method::TRACE
    );
    if declared.is_some_and(|length| length > 0) || !bodyless_method {
        return Ok(First::Waiting);
    }
    let seen = match now_or_never(next_chunk(recv)) {
        Some(seen) => Some(seen),
        None => timeout(BODY_PROBE, next_chunk(recv)).await.ok(),
    };
    match seen {
        None => Ok(First::Waiting),
        Some(Err(err)) => Err(err),
        Some(Ok(Some(chunk))) => Ok(First::Data(chunk)),
        Some(Ok(None)) => match now_or_never(recv.recv_trailers()) {
            Some(Ok(None)) => Ok(First::End),
            Some(Ok(Some(trailers))) => Ok(First::Trailers(trailers)),
            Some(Err(err)) => Err(err),
            None => Ok(First::BodyDone),
        },
    }
}

/// The HTTP/2 form of an HTTP/3 request head: the same method, target and headers, minus the
/// connection-specific ones.
fn head_of(request: &Request<()>) -> Option<Request<()>> {
    let mut head = Request::builder()
        .method(request.method().clone())
        .uri(request.uri().clone())
        .version(Version::HTTP_2)
        .body(())
        .ok()?;
    for (name, value) in request.headers() {
        if !HOP_BY_HOP.contains(name) {
            head.headers_mut().append(name.clone(), value.clone());
        }
    }
    Some(head)
}

/// Sends the request head into the pipeline, reconnecting once if the connection it had is gone.
async fn open(
    uplink: &Uplink,
    request: &Request<()>,
    end_of_stream: bool,
) -> Result<(ResponseFuture, SendStream<Bytes>), OpenError> {
    for _ in 0..2 {
        let head = head_of(request).ok_or(OpenError::Head)?;
        let sender = uplink.sender().await?;
        match send_head(sender, head, end_of_stream).await {
            Ok(opened) => return Ok(opened),
            Err(err) => {
                tracing::debug!(%err, "the internal connection failed; reconnecting");
                uplink.forget().await;
            }
        }
    }
    Err(OpenError::Closed)
}

async fn send_head(
    sender: SendRequest<Bytes>,
    head: Request<()>,
    end_of_stream: bool,
) -> Result<(ResponseFuture, SendStream<Bytes>), h2::Error> {
    sender.ready().await?.send_request(head, end_of_stream)
}

/// Why a request head could not be sent into the pipeline.
#[derive(Debug, thiserror::Error)]
enum OpenError {
    #[error("the request head cannot be expressed over HTTP/2")]
    Head,
    #[error(transparent)]
    Uplink(#[from] UplinkError),
    #[error("the pipeline closed the internal connection twice in a row")]
    Closed,
}

/// Moves the request body and trailers from the QUIC stream into the HTTP/2 stream, each chunk
/// after the pipeline's flow control grants room for it.
async fn pump_request(
    recv: &mut RecvHalf,
    upstream: &mut SendStream<Bytes>,
    first: First,
) -> Result<(), Abort> {
    let mut body_done = false;
    match first {
        First::End => return Ok(()),
        First::Data(chunk) => push(upstream, chunk).await?,
        First::BodyDone => body_done = true,
        First::Trailers(trailers) => {
            upstream.send_trailers(trailers)?;
            return Ok(());
        }
        First::Waiting => {}
    }
    while !body_done {
        match next_chunk(recv).await? {
            Some(chunk) => push(upstream, chunk).await?,
            None => body_done = true,
        }
    }
    match recv.recv_trailers().await? {
        Some(trailers) => upstream.send_trailers(trailers)?,
        None => upstream.send_data(Bytes::new(), true)?,
    }
    Ok(())
}

/// Writes `data` to `upstream` in the pieces its flow control window allows.
async fn push(upstream: &mut SendStream<Bytes>, mut data: Bytes) -> Result<(), Abort> {
    while !data.is_empty() {
        upstream.reserve_capacity(data.len());
        let granted = std::future::poll_fn(|cx| upstream.poll_capacity(cx))
            .await
            .ok_or_else(|| Abort::Pipeline(Reason::CANCEL.into()))??;
        if granted == 0 {
            continue;
        }
        let part = data.split_to(granted.min(data.len()));
        upstream.send_data(part, false)?;
    }
    Ok(())
}

/// Moves the response from the HTTP/2 stream to the QUIC stream: the head, every body chunk
/// (returning its flow control window once the QUIC stream took it), the trailers, the end.
async fn pump_response(
    response: ResponseFuture,
    send: &mut SendHalf,
    head_sent: &mut bool,
) -> Result<(), Abort> {
    let (parts, mut body) = response.await?.into_parts();
    let mut head = Response::new(());
    *head.status_mut() = parts.status;
    for (name, value) in &parts.headers {
        if !HOP_BY_HOP.contains(name) {
            head.headers_mut().append(name.clone(), value.clone());
        }
    }
    send.send_response(head).await?;
    *head_sent = true;
    let mut window = body.flow_control().clone();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let length = chunk.len();
        send.send_data(chunk).await?;
        window.release_capacity(length)?;
    }
    if let Some(trailers) = body.trailers().await? {
        send.send_trailers(trailers).await?;
    }
    send.finish().await?;
    Ok(())
}

/// The HTTP/3 front of one HTTPS entry point, as a Pingora background service.
///
/// Built before the server runs ([`Service::new`] binds the UDP socket and the internal socket,
/// so a busy address stops startup), started with it. It serves the QUIC endpoint and the
/// internal socket until the server shuts down.
#[derive(Debug)]
pub struct Service {
    entry: Arc<str>,
    port: u16,
    table: TableHandle,
    budgets: Budgets,
    settings: Settings,
    staples: Staples,
    link_path: PathBuf,
    token: Token,
    pending: Mutex<Option<(std::net::UdpSocket, LinkServer)>>,
}

impl Service {
    /// The front of the entry point `entry` at `addr`, bridging into `app` over `link_path`.
    ///
    /// # Errors
    ///
    /// The error of binding either socket or of making the credential.
    pub fn new(
        entry: &str,
        addr: SocketAddr,
        link_path: PathBuf,
        app: crate::entry::app::Policed,
        parts: Parts,
    ) -> std::io::Result<Self> {
        let token = Token::generate()?;
        let socket = endpoint::bind(addr, parts.settings.udp_recv_buffer)?;
        let link = LinkServer::bind(&link_path, token.clone(), app)?;
        Ok(Self {
            entry: Arc::from(entry),
            port: addr.port(),
            table: parts.table,
            budgets: parts.budgets,
            settings: parts.settings,
            staples: parts.staples,
            link_path,
            token,
            pending: Mutex::new(Some((socket, link))),
        })
    }
}

/// What the front shares with the rest of the process.
#[derive(Debug)]
pub struct Parts {
    /// The live routing table: certificates, tenants and routers.
    pub table: TableHandle,
    /// Where tenants are charged.
    pub budgets: Budgets,
    /// The operator's `H3_*` settings.
    pub settings: Settings,
    /// OCSP staples attached to the certificates handshakes serve.
    pub staples: Staples,
}

#[async_trait]
impl BackgroundService for Service {
    async fn start(&self, shutdown: ShutdownWatch) {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some((socket, link)) = pending else {
            return;
        };
        let config =
            match endpoint::server_config(self.table.clone(), self.staples.clone(), &self.settings)
            {
                Ok(config) => config,
                Err(err) => {
                    tracing::error!(entry_point = &*self.entry, %err, "cannot configure HTTP/3");
                    return;
                }
            };
        let endpoint = match endpoint::endpoint(socket, config) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                tracing::error!(entry_point = &*self.entry, %err, "cannot start the QUIC endpoint");
                return;
            }
        };
        tokio::spawn(link.serve(shutdown.clone()));
        let front = Arc::new(Front {
            entry: Arc::clone(&self.entry),
            port: self.port,
            table: self.table.clone(),
            budgets: self.budgets.clone(),
            settings: self.settings.clone(),
            link: self.link_path.clone(),
            token: self.token.clone(),
            shutdown: shutdown.clone(),
        });
        tracing::info!(entry_point = &*self.entry, "HTTP/3 front ready");
        endpoint::accept(front, endpoint, shutdown).await;
        tracing::info!(entry_point = &*self.entry, "HTTP/3 front stopped accepting");
    }
}
