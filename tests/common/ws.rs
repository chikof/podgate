//! WebSocket over raw sockets (RFC 6455) for `tests/ws.rs`: a client that upgrades through the
//! proxy and speaks frames, and an echo upstream that answers the upgrade and echoes frames.
//!
//! No WebSocket library: the proxy copies bytes after the `101`, so a test should write and read
//! exactly the bytes the RFC puts on the wire, with the masking and fragmentation it chooses.
//!
//! - [`open`]: send an upgrade request on any stream and get a [`Tunnel`] or the refusal.
//! - [`Echo`]: an upstream that records what reached it and echoes frames.
//! - [`Podgate::sigterm`], [`Podgate::wait_exit`]: end the process the way a deploy does.

use std::io;
use std::net::SocketAddr;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use super::{IO_TIMEOUT, Podgate, Response, parse_response};

/// Continuation frame.
pub const CONTINUATION: u8 = 0x0;
/// Text frame.
pub const TEXT: u8 = 0x1;
/// Binary frame.
pub const BINARY: u8 = 0x2;
/// Close frame.
pub const CLOSE: u8 = 0x8;
/// Ping frame.
pub const PING: u8 = 0x9;
/// Pong frame.
pub const PONG: u8 = 0xa;

/// The `Sec-WebSocket-Key` of RFC 6455 section 1.3, used by every upgrade here.
pub const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// How long the echo upstream takes to answer an upgrade; see `tunnel`.
const UPGRADE_LATENCY: Duration = Duration::from_millis(50);

/// The masking key of every frame [`Tunnel::send`] sends.
const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

/// The longest frame payload the readers here accept.
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// The `Sec-WebSocket-Accept` for `key` (RFC 6455 section 1.3).
pub fn accept_key(key: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(key.as_bytes());
    sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(sha.finalize())
}

/// One frame as it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The FIN bit.
    pub fin: bool,
    /// The opcode.
    pub opcode: u8,
    /// Whether the sender masked it.
    pub masked: bool,
    /// The payload, unmasked.
    pub payload: Vec<u8>,
}

/// The wire form of one frame, masked with `mask` when given.
pub fn encode(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push((u8::from(fin) << 7) | opcode);
    let bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        len if len < 126 => out.push(bit | len as u8),
        len if len <= usize::from(u16::MAX) => {
            out.push(bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.push(bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % 4]),
            );
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// Reads frames from `inner`, keeping what it has read past the last frame.
struct Reader<R> {
    inner: R,
    pending: Vec<u8>,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    fn new(inner: R, pending: Vec<u8>) -> Self {
        Self { inner, pending }
    }

    async fn fill(&mut self, want: usize) -> io::Result<()> {
        while self.pending.len() < want {
            self.pending
                .reserve((want - self.pending.len()).max(16 * 1024));
            if self.inner.read_buf(&mut self.pending).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        Ok(())
    }

    /// The next frame. Safe to drop while waiting: bytes read so far stay in `pending`.
    async fn next(&mut self) -> io::Result<Frame> {
        self.fill(2).await?;
        let fin = self.pending[0] & 0x80 != 0;
        let opcode = self.pending[0] & 0x0f;
        let masked = self.pending[1] & 0x80 != 0;
        let (len, head) = match self.pending[1] & 0x7f {
            126 => {
                self.fill(4).await?;
                (
                    usize::from(u16::from_be_bytes([self.pending[2], self.pending[3]])),
                    4,
                )
            }
            127 => {
                self.fill(10).await?;
                let mut raw = [0_u8; 8];
                raw.copy_from_slice(&self.pending[2..10]);
                let len = usize::try_from(u64::from_be_bytes(raw))
                    .map_err(|_| io::Error::other("frame too long"))?;
                (len, 10)
            }
            short => (usize::from(short), 2),
        };
        if len > MAX_PAYLOAD {
            return Err(io::Error::other("frame too long"));
        }
        let key_len = if masked { 4 } else { 0 };
        let total = head + key_len + len;
        self.fill(total).await?;
        let mut payload = self.pending[head + key_len..total].to_vec();
        if masked {
            let key = [
                self.pending[head],
                self.pending[head + 1],
                self.pending[head + 2],
                self.pending[head + 3],
            ];
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[index % 4];
            }
        }
        self.pending.drain(..total);
        Ok(Frame {
            fin,
            opcode,
            masked,
            payload,
        })
    }
}

/// An upgrade request's outcome.
pub enum Opened<S> {
    /// The server answered `101`.
    Tunnel(Tunnel<S>),
    /// The server answered something else.
    Refused(Response),
}

impl<S> Opened<S> {
    /// The tunnel; panics with the refusal when there is none.
    pub fn tunnel(self) -> Tunnel<S> {
        match self {
            Self::Tunnel(tunnel) => tunnel,
            Self::Refused(response) => panic!("the upgrade was refused: {response:?}"),
        }
    }

    /// The refusal; panics when the upgrade went through.
    pub fn refused(self) -> Response {
        match self {
            Self::Refused(response) => response,
            Self::Tunnel(tunnel) => {
                panic!("the upgrade was accepted: {:?}", tunnel.head)
            }
        }
    }
}

/// A WebSocket connection after the `101`, from the client's side.
pub struct Tunnel<S> {
    /// The `101` response.
    pub head: Response,
    reader: Reader<ReadHalf<S>>,
    writer: WriteHalf<S>,
    /// Frames [`Self::closes_within`] threw away while waiting.
    pub discarded: Vec<Frame>,
}

/// Sends an upgrade request for `path` with `Host: host` and `extra` headers on `stream`, and
/// reads the answer. The key is [`KEY`].
pub async fn open<S>(mut stream: S, host: &str, path: &str, extra: &[(&str, &str)]) -> Opened<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let extra: String = extra
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    );
    timeout(IO_TIMEOUT, async {
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send the upgrade request");
        let mut raw = Vec::with_capacity(4096);
        let end = loop {
            if let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
            let read = stream.read_buf(&mut raw).await.expect("read the answer");
            assert_ne!(read, 0, "closed before an answer: {raw:?}");
        };
        let mut head = parse_response(&raw[..end]);
        let leftover = raw[end..].to_vec();
        if head.status == 101 {
            let (read, writer) = split(stream);
            return Opened::Tunnel(Tunnel {
                head,
                reader: Reader::new(read, leftover),
                writer,
                discarded: Vec::new(),
            });
        }
        let wanted: usize = head
            .header("content-length")
            .and_then(|length| length.parse().ok())
            .unwrap_or(0);
        let mut body = leftover;
        while body.len() < wanted {
            if stream.read_buf(&mut body).await.expect("read the body") == 0 {
                break;
            }
        }
        head.body = String::from_utf8_lossy(&body).into_owned();
        Opened::Refused(head)
    })
    .await
    .expect("the upgrade answered in time")
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tunnel<S> {
    /// Sends one final frame, masked as a client must.
    pub async fn send(&mut self, opcode: u8, payload: &[u8]) {
        self.send_raw(&encode(true, opcode, payload, Some(MASK)))
            .await;
    }

    /// Sends one final frame without a mask. A client must mask; the proxy copies the bytes
    /// whatever they are.
    pub async fn send_unmasked(&mut self, opcode: u8, payload: &[u8]) {
        self.send_raw(&encode(true, opcode, payload, None)).await;
    }

    /// Sends `bytes` as they are.
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        timeout(IO_TIMEOUT, self.writer.write_all(bytes))
            .await
            .expect("write in time")
            .expect("write to the tunnel");
    }

    /// The next frame; panics when the tunnel closed or nothing came within the I/O deadline.
    pub async fn recv(&mut self) -> Frame {
        timeout(IO_TIMEOUT, self.reader.next())
            .await
            .expect("a frame in time")
            .expect("the tunnel is open")
    }

    /// Writes one frame and reads the next at the same time, so a payload larger than every
    /// buffer between here and the echo cannot deadlock the exchange.
    pub async fn round_trip(&mut self, opcode: u8, payload: &[u8]) -> Frame {
        let wire = encode(true, opcode, payload, Some(MASK));
        let Self { reader, writer, .. } = self;
        let (written, read) = timeout(IO_TIMEOUT, async {
            tokio::join!(writer.write_all(&wire), reader.next())
        })
        .await
        .expect("the round trip finished in time");
        written.expect("write to the tunnel");
        read.expect("the tunnel is open")
    }

    /// Whether the tunnel is closed within `limit`: how long that took, or `None` when it is
    /// still open. Frames that arrive meanwhile are kept in [`Self::discarded`].
    pub async fn closes_within(&mut self, limit: Duration) -> Option<Duration> {
        let started = Instant::now();
        let Self {
            reader, discarded, ..
        } = self;
        let waited = timeout(limit, async {
            while let Ok(frame) = reader.next().await {
                discarded.push(frame);
            }
        })
        .await;
        waited.ok().map(|()| started.elapsed())
    }

    /// Bytes read after the last whole frame: a tunnel that ended cleanly has none.
    pub fn trailing(&self) -> &[u8] {
        &self.reader.pending
    }
}

/// What an [`Echo`] saw.
#[derive(Default)]
struct Log {
    heads: Mutex<Vec<String>>,
    frames: Mutex<Vec<(u8, bool)>>,
    connections: AtomicUsize,
    open: AtomicUsize,
}

/// An upstream that answers an upgrade with `101` and echoes frames; any other request gets
/// `200 plain`.
///
/// Text `close` makes it send a close frame and hang up, text `drop` hangs up without one, text
/// `tick` makes it push a `tick` text frame every 400 ms for 6 s and then hang up. Ping
/// is answered with pong, close with close. A request that asks for a subprotocol gets the
/// first one back, and the `101` carries `X-Upstream: echo`.
pub struct Echo {
    /// Where it listens.
    pub addr: SocketAddr,
    log: Arc<Log>,
}

impl Echo {
    /// Starts serving on a free loopback port until the test's runtime ends.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the echo upstream");
        let addr = listener.local_addr().expect("echo address");
        let log = Arc::new(Log::default());
        let shared = Arc::clone(&log);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                shared.connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve(stream, Arc::clone(&shared)));
            }
        });
        Self { addr, log }
    }

    /// Every request head received, lowercased, in arrival order.
    pub fn heads(&self) -> Vec<String> {
        lock(&self.log.heads).clone()
    }

    /// The heads of the requests that asked to upgrade.
    pub fn upgrade_heads(&self) -> Vec<String> {
        self.heads()
            .into_iter()
            .filter(|head| head.contains("upgrade: websocket"))
            .collect()
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.log.connections.load(Ordering::SeqCst)
    }

    /// Tunnels open now: upgraded and not yet hung up.
    pub fn open_tunnels(&self) -> usize {
        self.log.open.load(Ordering::SeqCst)
    }

    /// `(opcode, masked)` of every data and control frame received, in order.
    pub fn frames(&self) -> Vec<(u8, bool)> {
        lock(&self.log.frames).clone()
    }

    /// Waits up to `limit` for `open_tunnels()` to be `count`; whether it got there.
    pub async fn wait_open(&self, count: usize, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if self.open_tunnels() == count {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.open_tunnels() == count
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn serve(mut stream: TcpStream, log: Arc<Log>) {
    let mut seen = Vec::with_capacity(4096);
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let raw = String::from_utf8_lossy(&seen[..end]).into_owned();
            let head = raw.to_ascii_lowercase();
            let leftover = seen.split_off(end + 4);
            lock(&log.heads).push(head.clone());
            if head.contains("upgrade: websocket") {
                tunnel(stream, &raw, leftover, &log).await;
                return;
            }
            let reply =
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nplain";
            if stream.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
            seen = leftover;
        }
        match stream.read_buf(&mut seen).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// The value of header `name` in the raw request `head`, as the client wrote it.
fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

async fn tunnel(mut stream: TcpStream, head: &str, leftover: Vec<u8>, log: &Log) {
    let key = header_value(head, "sec-websocket-key").unwrap_or_default();
    let protocol = header_value(head, "sec-websocket-protocol")
        .and_then(|list| list.split(',').next().map(|first| first.trim().to_owned()))
        .map(|first| format!("Sec-WebSocket-Protocol: {first}\r\n"))
        .unwrap_or_default();
    let reply = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\nX-Upstream: echo\r\n{protocol}\r\n",
        accept_key(&key)
    );
    // An upstream that answers within microseconds of the request head races Pingora 0.9.1's
    // upstream duplex loop (`pingora-proxy/src/proxy_h1.rs:268,326-333`, the `read_response_task`
    // and `rx.recv()` arms of `proxy_1to1`): when the `101` is read before the downstream's end-of-body task, that
    // task ends the "upgraded" request and the tunnel is closed. A real upstream takes
    // longer than the proxy's poll; this one waits, so tests measure podgate and not that race.
    tokio::time::sleep(UPGRADE_LATENCY).await;
    if stream.write_all(reply.as_bytes()).await.is_err() {
        return;
    }
    log.open.fetch_add(1, Ordering::SeqCst);
    let (read, mut write) = split(stream);
    let mut reader = Reader::new(read, leftover);
    while let Ok(frame) = reader.next().await {
        lock(&log.frames).push((frame.opcode, frame.masked));
        let answer = match (frame.opcode, frame.payload.as_slice()) {
            (TEXT, b"drop") => break,
            (TEXT, b"tick") => {
                for _ in 0..15 {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    if write
                        .write_all(&encode(true, TEXT, b"tick", None))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                break;
            }
            (TEXT, b"close") => {
                drop(
                    write
                        .write_all(&encode(true, CLOSE, &[0x03, 0xe8], None))
                        .await,
                );
                break;
            }
            (PING, payload) => encode(true, PONG, payload, None),
            (CLOSE, payload) => {
                drop(write.write_all(&encode(true, CLOSE, payload, None)).await);
                break;
            }
            (PONG, _) => continue,
            (opcode, payload) => encode(frame.fin, opcode, payload, None),
        };
        if write.write_all(&answer).await.is_err() {
            break;
        }
    }
    log.open.fetch_sub(1, Ordering::SeqCst);
}

impl Podgate {
    /// Sends SIGTERM to the process, as a deploy stops it.
    pub fn sigterm(&self) {
        let status = std::process::Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM failed: {status}");
    }

    /// How the process ended, waiting up to `limit`; `None` while it still runs.
    pub async fn wait_exit(&mut self, limit: Duration) -> Option<(ExitStatus, Duration)> {
        let started = Instant::now();
        while started.elapsed() < limit {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some((status, started.elapsed()));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }
}

impl Podgate {
    /// A TLS connection to the HTTPS listener with `sni` as server name, trusting `trusted`.
    pub async fn ws_tls(
        &self,
        sni: &str,
        trusted: &super::TestCert,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        self.tls_connect(sni, trusted)
            .await
            .unwrap_or_else(|err| panic!("TLS handshake for {sni} failed: {err}"))
    }
}
