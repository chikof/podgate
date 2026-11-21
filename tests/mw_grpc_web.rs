//! The `grpc_web` middleware: a browser's gRPC-Web calls reach a real HTTP/2 gRPC
//! server, and what comes back carries its trailers in the body.
//!
//! The upstream is a minimal gRPC server on the `h2` crate, spoken to over `h2c://`. It answers
//! `Unary` (an echo), `Stream` (three messages, each after the test lets it), `Fail` (a
//! trailers-only error), `Overflow` (trailers over the cap), `NoTrailers` (a response that ends
//! without any) and `Big` (as many 64 KiB messages as the request asks for). The client is raw
//! HTTP/1.1 over TCP, which is what a browser without HTTP/2 sends.
//!
//! One test counts heap bytes per thread with a counting global allocator, so the file allows
//! `unsafe_code`; the other threads' allocations are not counted.

// A counting `GlobalAlloc` has no safe form.
#![allow(unsafe_code)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use common::{Podgate, app, snapshot, with_middleware};
use h2::SendStream;
use h2::server::SendResponse;
use http::{HeaderMap, HeaderValue, Request, Response};
use pingora::http::{RequestHeader, ResponseHeader};
use podgate::middleware::grpc_web::GrpcWeb;
use podgate::middleware::grpc_web::codec::{Decoder, MAX_TRAILER_BYTES};
use podgate::middleware::{CompileCx, Kind, ResponseCx};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

/// Longest any single read or write may take.
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Bytes in one message of `Big`.
const MESSAGE: usize = 64 * 1024;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

struct Counting;

fn grow(by: usize) {
    let by = isize::try_from(by).unwrap_or(isize::MAX);
    LIVE.with(|live| {
        let now = live.get().saturating_add(by);
        live.set(now);
        PEAK.with(|peak| peak.set(peak.get().max(now)));
    });
}

fn shrink(by: usize) {
    let by = isize::try_from(by).unwrap_or(isize::MAX);
    LIVE.with(|live| live.set(live.get().saturating_sub(by)));
}

// SAFETY: every method forwards unchanged to `System`, which upholds the `GlobalAlloc`
// contract; the counters are const-initialised thread locals without a destructor, so
// touching them never allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        // SAFETY: same layout and caller obligations as ours.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        shrink(layout.size());
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        // SAFETY: same layout and caller obligations as ours.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            grow(new_size - layout.size());
        } else {
            shrink(layout.size() - new_size);
        }
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

// ---------------------------------------------------------------------------------------
// gRPC framing
// ---------------------------------------------------------------------------------------

/// A length-prefixed gRPC message: the flag byte `0`, a big-endian length, the payload.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend(
        u32::try_from(payload.len())
            .expect("a small message")
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out
}

/// The payload of the first message in `data`, empty when there is none.
fn first_message(data: &[u8]) -> Vec<u8> {
    let Some(header) = data.get(..5) else {
        return Vec::new();
    };
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    data.get(5..5 + len).unwrap_or_default().to_vec()
}

/// Every `(flag, payload)` frame in `bytes`.
fn frames(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut reader = FrameBuffer::default();
    reader.push(bytes);
    let mut out = Vec::new();
    while let Some(next) = reader.next() {
        out.push(next);
    }
    assert!(
        reader.0.is_empty(),
        "{} bytes of a partial frame",
        reader.0.len()
    );
    out
}

/// The `name: value` lines of a trailer frame's payload.
fn lines(payload: &[u8]) -> Vec<String> {
    String::from_utf8(payload.to_vec())
        .expect("trailers are text")
        .split("\r\n")
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Bytes that arrive in pieces and leave as whole frames.
#[derive(Default)]
struct FrameBuffer(Vec<u8>);

impl FrameBuffer {
    fn push(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    fn next(&mut self) -> Option<(u8, Vec<u8>)> {
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
}

// ---------------------------------------------------------------------------------------
// The upstream: a gRPC server over h2c
// ---------------------------------------------------------------------------------------

/// What the upstream saw of one request.
#[derive(Clone, Debug)]
struct Call {
    path: String,
    content_type: Option<String>,
    te: Option<String>,
    body: Vec<u8>,
}

struct Grpc {
    addr: SocketAddr,
    calls: Arc<Mutex<Vec<Call>>>,
    /// `Stream` sends its next message once it takes a permit from here.
    gate: Arc<Semaphore>,
}

impl Grpc {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(Semaphore::new(0));
        let (log, permits) = (Arc::clone(&calls), Arc::clone(&gate));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(connection(tcp, Arc::clone(&log), Arc::clone(&permits)));
            }
        });
        Self { addr, calls, gate }
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("calls").clone()
    }
}

async fn connection(tcp: TcpStream, calls: Arc<Mutex<Vec<Call>>>, gate: Arc<Semaphore>) {
    let Ok(mut connection) = h2::server::handshake(tcp).await else {
        return;
    };
    while let Some(Ok((request, respond))) = connection.accept().await {
        tokio::spawn(handle(
            request,
            respond,
            Arc::clone(&calls),
            Arc::clone(&gate),
        ));
    }
}

fn header_of(request: &Request<h2::RecvStream>, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn grpc_head(status: u32, extra: &[(&str, &str)], trailers_only: bool) -> Response<()> {
    let mut head = Response::builder()
        .status(200)
        .header("content-type", "application/grpc");
    if trailers_only {
        head = head.header("grpc-status", status.to_string());
    }
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
            http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
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
            .ok_or_else(|| h2::Error::from(h2::Reason::CANCEL))??;
        if capacity > 0 {
            send.send_data(data.split_to(capacity.min(data.len())), false)?;
        }
    }
    Ok(())
}

async fn handle(
    request: Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    calls: Arc<Mutex<Vec<Call>>>,
    gate: Arc<Semaphore>,
) {
    let call = Call {
        path: request.uri().path().to_owned(),
        content_type: header_of(&request, "content-type"),
        te: header_of(&request, "te"),
        body: Vec::new(),
    };
    let mut body = request.into_body();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return };
        // The window opens again for what was read.
        drop(body.flow_control().release_capacity(chunk.len()));
        data.extend_from_slice(&chunk);
    }
    calls.lock().expect("calls").push(Call {
        body: data.clone(),
        ..call.clone()
    });
    drop(answer(&call.path, &data, &mut respond, &gate).await);
}

async fn answer(
    path: &str,
    data: &[u8],
    respond: &mut SendResponse<Bytes>,
    gate: &Semaphore,
) -> Result<(), h2::Error> {
    match path {
        "/test.Echo/Unary" => {
            let mut send = respond.send_response(grpc_head(0, &[], false), false)?;
            let echo = [b"echo:".as_slice(), &first_message(data)].concat();
            send.send_data(Bytes::from(frame(&echo)), false)?;
            send.send_trailers(trailers(
                0,
                &[("grpc-message", "fine"), ("x-custom-trailer", "kept")],
            ))
        }
        "/test.Echo/Stream" => {
            let mut send = respond.send_response(grpc_head(0, &[], false), false)?;
            for (index, message) in [b"msg1", b"msg2", b"msg3"].iter().enumerate() {
                if index > 0 {
                    gate.acquire().await.expect("gate open").forget();
                }
                send.send_data(Bytes::from(frame(*message)), false)?;
            }
            send.send_trailers(trailers(0, &[]))
        }
        "/test.Echo/Fail" => {
            respond.send_response(
                grpc_head(
                    5,
                    &[("grpc-message", "no such thing"), ("x-meta", "kept")],
                    true,
                ),
                true,
            )?;
            Ok(())
        }
        "/test.Echo/Overflow" => {
            let mut send = respond.send_response(grpc_head(0, &[], false), false)?;
            send.send_data(Bytes::from(frame(b"data")), false)?;
            send.send_trailers(trailers(
                0,
                &[("x-big", &"x".repeat(MAX_TRAILER_BYTES + 1000))],
            ))
        }
        "/test.Echo/NoTrailers" => {
            let mut send = respond.send_response(grpc_head(0, &[], false), false)?;
            send.send_data(Bytes::from(frame(b"data")), true)
        }
        "/test.Echo/Big" => {
            let count = u32::from_be_bytes(
                first_message(data)
                    .get(..4)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .unwrap_or_default(),
            );
            let mut send = respond.send_response(grpc_head(0, &[], false), false)?;
            for index in 0..count {
                let payload = vec![u8::try_from(index % 251).unwrap_or(0); MESSAGE];
                send_flow(&mut send, Bytes::from(frame(&payload))).await?;
            }
            send.send_trailers(trailers(0, &[]))
        }
        _ => {
            respond.send_response(
                grpc_head(12, &[("grpc-message", "unimplemented")], true),
                true,
            )?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------
// The client: raw HTTP/1.1
// ---------------------------------------------------------------------------------------

#[derive(Debug)]
struct Head {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn with_prefix(&self, prefix: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.as_str())
            .collect()
    }
}

#[derive(Clone, Copy)]
enum Framing {
    Chunked,
    Length(usize),
    Close,
    Done,
}

struct Wire {
    stream: TcpStream,
    buf: Vec<u8>,
    framing: Framing,
}

impl Wire {
    async fn open(addr: SocketAddr) -> Self {
        let stream = timeout(IO_TIMEOUT, TcpStream::connect(addr))
            .await
            .expect("connect in time")
            .expect("connect");
        Self {
            stream,
            buf: Vec::new(),
            framing: Framing::Close,
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        timeout(IO_TIMEOUT, self.stream.write_all(bytes))
            .await
            .expect("write in time")
            .expect("write");
    }

    /// Reads more into the buffer; false at end of stream.
    async fn fill(&mut self) -> bool {
        let mut chunk = vec![0_u8; 64 * 1024];
        let read = timeout(IO_TIMEOUT, self.stream.read(&mut chunk))
            .await
            .expect("read in time")
            .unwrap_or(0);
        self.buf.extend_from_slice(&chunk[..read]);
        read > 0
    }

    async fn head(&mut self) -> Head {
        loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let text = String::from_utf8(self.buf[..end].to_vec()).expect("head is text");
                self.buf.drain(..end + 4);
                let mut lines = text.split("\r\n");
                let status = lines
                    .next()
                    .and_then(|line| line.split(' ').nth(1))
                    .and_then(|code| code.parse().ok())
                    .expect("a status line");
                let headers: Vec<(String, String)> = lines
                    .filter_map(|line| line.split_once(':'))
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                    .collect();
                let head = Head { status, headers };
                self.framing = if head
                    .header("transfer-encoding")
                    .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
                {
                    Framing::Chunked
                } else if let Some(length) = head.header("content-length") {
                    Framing::Length(length.parse().expect("a length"))
                } else {
                    Framing::Close
                };
                return head;
            }
            assert!(self.fill().await, "closed before the response head");
        }
    }

    /// The next piece of the body; `None` at its end.
    async fn chunk(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.framing {
                Framing::Done => return None,
                Framing::Close => {
                    if !self.buf.is_empty() {
                        return Some(std::mem::take(&mut self.buf));
                    }
                    if !self.fill().await {
                        self.framing = Framing::Done;
                        return None;
                    }
                }
                Framing::Length(0) => {
                    self.framing = Framing::Done;
                    return None;
                }
                Framing::Length(left) => {
                    if self.buf.is_empty() {
                        assert!(self.fill().await, "closed inside the body");
                    }
                    let take = left.min(self.buf.len());
                    self.framing = Framing::Length(left - take);
                    return Some(self.buf.drain(..take).collect());
                }
                Framing::Chunked => {
                    if let Some(at) = self.buf.windows(2).position(|w| w == b"\r\n") {
                        let size = usize::from_str_radix(
                            std::str::from_utf8(&self.buf[..at]).expect("a chunk size"),
                            16,
                        )
                        .expect("a hex chunk size");
                        if size == 0 {
                            if self.buf.len() < at + 4 {
                                assert!(self.fill().await, "closed inside the last chunk");
                                continue;
                            }
                            self.framing = Framing::Done;
                            return None;
                        }
                        if self.buf.len() >= at + 2 + size + 2 {
                            let data = self.buf[at + 2..at + 2 + size].to_vec();
                            self.buf.drain(..at + 2 + size + 2);
                            return Some(data);
                        }
                    }
                    assert!(self.fill().await, "closed inside a chunk");
                }
            }
        }
    }

    async fn body(&mut self) -> Vec<u8> {
        let mut all = Vec::new();
        while let Some(chunk) = self.chunk().await {
            all.extend_from_slice(&chunk);
        }
        all
    }
}

/// The body of a gRPC-Web request that carries one message: the frame, base64 for the text kind.
fn request_body(text: bool, payload: &[u8]) -> Vec<u8> {
    let body = frame(payload);
    if text {
        STANDARD.encode(body).into_bytes()
    } else {
        body
    }
}

/// Sends `POST path` with `body` and returns the connection, the response unread.
async fn post(
    podgate: &Podgate,
    path: &str,
    content_type: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> Wire {
    let mut wire = Wire::open(podgate.proxy_addr).await;
    let mut head = format!(
        "POST {path} HTTP/1.1\r\nHost: g.test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    wire.send(head.as_bytes()).await;
    wire.send(body).await;
    wire
}

/// The route `g.test` through a `grpc_web` middleware to the gRPC server over `h2c://`.
fn route(grpc: &Grpc, config: &Value) -> Value {
    let revision = json!({
        "id": "r1", "state": "serving", "weight": 100,
        "services": [{
            "name": "web", "type": "loadbalancer",
            "servers": [{ "url": format!("h2c://{}", grpc.addr) }],
        }],
    });
    snapshot(
        1,
        &[with_middleware(
            app("g", &["g.test"], &[revision]),
            "gw",
            "grpc_web",
            config.clone(),
        )],
    )
}

async fn start(config: Value) -> (Podgate, Grpc) {
    let grpc = Grpc::start().await;
    let podgate = Podgate::start().await;
    let pushed = podgate.push_snapshot(&route(&grpc, &config)).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    (podgate, grpc)
}

const BINARY: &str = "application/grpc-web+proto";
const TEXT: &str = "application/grpc-web-text";

// ---------------------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn grpc_web_binary_unary() {
    let (podgate, grpc) = start(json!({})).await;
    let request = frame(b"hello");
    let mut wire = post(&podgate, "/test.Echo/Unary", BINARY, &request, &[]).await;
    let head = wire.head().await;
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-type"), Some(BINARY));
    assert_eq!(head.header("content-length"), None);
    let body = wire.body().await;
    let got = frames(&body);
    assert_eq!(got.len(), 2, "a message and a trailer frame");
    assert_eq!(got[0], (0, b"echo:hello".to_vec()));
    assert_eq!(got[1].0, 0x80);
    assert!(lines(&got[1].1).contains(&"grpc-status: 0".to_owned()));

    let seen = grpc.calls();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/test.Echo/Unary");
    assert_eq!(seen[0].content_type.as_deref(), Some("application/grpc"));
    assert_eq!(seen[0].te.as_deref(), Some("trailers"));
    assert_eq!(seen[0].body, request);
}

#[tokio::test]
async fn grpc_web_text_unary() {
    let (podgate, grpc) = start(json!({})).await;
    let request = frame(b"hello");
    let encoded = STANDARD.encode(&request);
    let mut wire = post(&podgate, "/test.Echo/Unary", TEXT, encoded.as_bytes(), &[]).await;
    let head = wire.head().await;
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-type"), Some(TEXT));
    let body = wire.body().await;
    // One base64 stream: padding only at its end.
    let decoded = STANDARD
        .decode(&body)
        .unwrap_or_else(|err| panic!("{err}: {:?}", String::from_utf8_lossy(&body)));
    let got = frames(&decoded);
    assert_eq!(got[0], (0, b"echo:hello".to_vec()));
    assert_eq!(got[1].0, 0x80);
    assert!(lines(&got[1].1).contains(&"grpc-status: 0".to_owned()));

    let seen = grpc.calls();
    assert_eq!(seen[0].content_type.as_deref(), Some("application/grpc"));
    assert_eq!(seen[0].te.as_deref(), Some("trailers"));
    assert_eq!(seen[0].body, request, "the upstream got the decoded body");
}

#[tokio::test]
async fn grpc_web_text_request_split_across_chunks() {
    let (podgate, grpc) = start(json!({})).await;
    let request = frame(b"hello world");
    let encoded = STANDARD.encode(&request);
    let mut wire = Wire::open(podgate.proxy_addr).await;
    wire.send(
        format!(
            "POST /test.Echo/Unary HTTP/1.1\r\nHost: g.test\r\nContent-Type: {TEXT}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    // Pieces of 1, 2, 3 and 5 characters: groups of four are cut in every place.
    let mut rest = encoded.as_bytes();
    for size in [1, 2, 3, 5, 1, 2, 3, 5].into_iter().cycle() {
        if rest.is_empty() {
            break;
        }
        let (piece, tail) = rest.split_at(size.min(rest.len()));
        rest = tail;
        wire.send(format!("{:x}\r\n", piece.len()).as_bytes()).await;
        wire.send(piece).await;
        wire.send(b"\r\n").await;
        sleep(Duration::from_millis(20)).await;
    }
    wire.send(b"0\r\n\r\n").await;
    let head = wire.head().await;
    assert_eq!(head.status, 200);
    let decoded = STANDARD.decode(wire.body().await).expect("base64");
    assert_eq!(frames(&decoded)[0], (0, b"echo:hello world".to_vec()));
    assert_eq!(grpc.calls()[0].body, request);
}

#[tokio::test]
async fn grpc_web_text_invalid_base64_is_a_400() {
    let (podgate, grpc) = start(json!({})).await;
    let mut wire = post(&podgate, "/test.Echo/Unary", TEXT, b"@@@@AAAA", &[]).await;
    let head = wire.head().await;
    assert_eq!(head.status, 400);
    assert_eq!(head.header("content-type"), Some("application/json"));
    assert!(grpc.calls().iter().all(|call| call.body.is_empty()));
}

#[tokio::test]
async fn grpc_web_server_streaming_is_incremental() {
    for (content_type, text) in [(BINARY, false), (TEXT, true)] {
        let (podgate, grpc) = start(json!({})).await;
        let body = frame(b"go");
        let body = if text {
            STANDARD.encode(&body).into_bytes()
        } else {
            body
        };
        let mut wire = post(&podgate, "/test.Echo/Stream", content_type, &body, &[]).await;
        let head = wire.head().await;
        assert_eq!(head.status, 200, "{content_type}");
        // The server holds back messages two and three until the test says so, so each one
        // can only arrive if the proxy forwards it before the response is over.
        let mut decoder = Decoder::default();
        let mut buffer = FrameBuffer::default();
        let mut messages = Vec::new();
        let mut trailer = None;
        let mut released = 0;
        while trailer.is_none() {
            while let Some((flag, payload)) = buffer.next() {
                if flag == 0x80 {
                    trailer = Some(lines(&payload));
                } else {
                    messages.push(String::from_utf8(payload).expect("text"));
                    if released < 2 {
                        grpc.gate.add_permits(1);
                        released += 1;
                    }
                }
            }
            if trailer.is_some() {
                break;
            }
            let chunk = wire
                .chunk()
                .await
                .expect("the response ends with a trailer frame");
            if text {
                buffer.push(&decoder.push(&chunk).expect("base64"));
            } else {
                buffer.push(&chunk);
            }
        }
        assert_eq!(messages, ["msg1", "msg2", "msg3"], "{content_type}");
        assert!(
            trailer
                .expect("trailers")
                .contains(&"grpc-status: 0".to_owned())
        );
    }
}

#[tokio::test]
async fn grpc_web_trailers_in_body() {
    let (podgate, _grpc) = start(json!({})).await;
    let mut wire = post(&podgate, "/test.Echo/Unary", BINARY, &frame(b"x"), &[]).await;
    let head = wire.head().await;
    // The trailers went into the body and not onto the wire as trailers.
    assert_eq!(head.header("trailer"), None);
    let body = wire.body().await;
    let got = frames(&body);
    let mut trailer = lines(&got[1].1);
    trailer.sort();
    assert_eq!(
        trailer,
        [
            "grpc-message: fine",
            "grpc-status: 0",
            "x-custom-trailer: kept"
        ]
    );
    // The frame is the flag, the length of its lines, and the lines, and the body ends there.
    let tail = &body[body.len() - got[1].1.len() - 5..];
    assert_eq!(tail[0], 0x80);
    assert_eq!(
        u32::from_be_bytes([tail[1], tail[2], tail[3], tail[4]]) as usize,
        got[1].1.len()
    );
}

#[tokio::test]
async fn grpc_web_trailers_only_error() {
    for (content_type, text) in [(BINARY, false), (TEXT, true)] {
        let (podgate, _grpc) = start(json!({})).await;
        let body = request_body(text, b"x");
        let mut wire = post(&podgate, "/test.Echo/Fail", content_type, &body, &[]).await;
        let head = wire.head().await;
        assert_eq!(head.status, 200, "{content_type}");
        assert_eq!(
            head.header("content-type"),
            Some(if text { TEXT } else { BINARY })
        );
        let body = wire.body().await;
        assert_eq!(
            head.header("content-length"),
            Some(body.len().to_string().as_str()),
            "{content_type}"
        );
        let decoded = if text {
            STANDARD.decode(&body).expect("base64")
        } else {
            body
        };
        let got = frames(&decoded);
        assert_eq!(got.len(), 1, "the trailer frame alone");
        assert_eq!(got[0].0, 0x80);
        let trailer = lines(&got[0].1);
        for expected in [
            "grpc-status: 5",
            "grpc-message: no such thing",
            "x-meta: kept",
        ] {
            assert!(
                trailer.contains(&expected.to_owned()),
                "{expected} in {trailer:?}"
            );
        }
        assert!(
            trailer.iter().all(|line| !line.starts_with("content-type")),
            "head fields are not trailers: {trailer:?}"
        );
    }
}

#[tokio::test]
async fn grpc_web_trailers_over_the_cap_become_status_13() {
    let (podgate, _grpc) = start(json!({})).await;
    let mut wire = post(&podgate, "/test.Echo/Overflow", BINARY, &frame(b"x"), &[]).await;
    assert_eq!(wire.head().await.status, 200);
    let got = frames(&wire.body().await);
    assert_eq!(got[0], (0, b"data".to_vec()));
    let trailer = lines(&got[1].1);
    assert!(
        trailer.contains(&"grpc-status: 13".to_owned()),
        "{trailer:?}"
    );
    assert!(trailer.iter().all(|line| !line.starts_with("x-big")));
    assert!(got[1].1.len() <= MAX_TRAILER_BYTES);
}

#[tokio::test]
async fn grpc_web_a_response_without_trailers_ends_with_status_unknown() {
    for (content_type, text) in [(BINARY, false), (TEXT, true)] {
        let (podgate, _grpc) = start(json!({})).await;
        let mut wire = post(
            &podgate,
            "/test.Echo/NoTrailers",
            content_type,
            &request_body(text, b"x"),
            &[],
        )
        .await;
        assert_eq!(wire.head().await.status, 200);
        let body = wire.body().await;
        let decoded = if text {
            STANDARD.decode(&body).expect("base64")
        } else {
            body
        };
        let got = frames(&decoded);
        assert_eq!(got[0], (0, b"data".to_vec()), "{content_type}");
        assert!(
            lines(&got[1].1).contains(&"grpc-status: 2".to_owned()),
            "{content_type}"
        );
    }
}

#[tokio::test]
async fn grpc_web_non_grpc_web_untouched() {
    let (podgate, grpc) = start(json!({ "allow_origins": ["https://app.example"] })).await;
    for content_type in [
        "application/json",
        "application/grpc",
        "application/grpc-web+json",
    ] {
        let mut wire = post(
            &podgate,
            "/test.Echo/Unary",
            content_type,
            &frame(b"plain"),
            &[("Origin", "https://app.example")],
        )
        .await;
        let head = wire.head().await;
        assert_eq!(head.status, 200, "{content_type}");
        // The response is the upstream's, as it sent it: gRPC, no trailer frame, no CORS.
        assert_eq!(
            head.header("content-type"),
            Some("application/grpc"),
            "{content_type}"
        );
        assert!(
            head.with_prefix("access-control-").is_empty(),
            "{content_type}"
        );
        assert_eq!(head.header("vary"), None, "{content_type}");
        assert_eq!(wire.body().await, frame(b"echo:plain"), "{content_type}");
    }
    let seen = grpc.calls();
    assert_eq!(
        seen.iter()
            .map(|call| call.content_type.clone().expect("a content type"))
            .collect::<Vec<_>>(),
        [
            "application/json",
            "application/grpc",
            "application/grpc-web+json"
        ]
    );
    assert!(
        seen.iter().all(|call| call.te.is_none()),
        "no te added: {seen:?}"
    );
    assert!(seen.iter().all(|call| call.body == frame(b"plain")));
}

async fn options(podgate: &Podgate, origin: &str) -> (Head, Vec<u8>) {
    let mut wire = Wire::open(podgate.proxy_addr).await;
    wire.send(
        format!(
            "OPTIONS /test.Echo/Unary HTTP/1.1\r\nHost: g.test\r\nOrigin: {origin}\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type,x-grpc-web,x-user-agent\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    let head = wire.head().await;
    let body = wire.body().await;
    (head, body)
}

#[tokio::test]
async fn grpc_web_cors_preflight() {
    let (podgate, grpc) = start(json!({
        "allow_origins": ["https://app.example", "https://other.example:8443"]
    }))
    .await;
    for origin in ["https://app.example", "https://other.example:8443"] {
        let (head, body) = options(&podgate, origin).await;
        assert_eq!(head.status, 204, "{origin}");
        assert_eq!(head.header("access-control-allow-origin"), Some(origin));
        assert_eq!(head.header("access-control-allow-methods"), Some("POST"));
        let allowed = head
            .header("access-control-allow-headers")
            .expect("allowed headers");
        assert!(
            allowed.contains('*') && allowed.contains("authorization"),
            "{allowed}"
        );
        assert_eq!(head.header("access-control-max-age"), Some("600"));
        assert_eq!(head.header("vary"), Some("Origin"));
        assert!(body.is_empty());
    }
    assert!(
        grpc.calls().is_empty(),
        "a preflight never reaches the upstream"
    );

    // The call itself: the listed origin may read it, and the two gRPC headers.
    let mut wire = post(
        &podgate,
        "/test.Echo/Unary",
        BINARY,
        &frame(b"x"),
        &[("Origin", "https://app.example")],
    )
    .await;
    let head = wire.head().await;
    assert_eq!(
        head.header("access-control-allow-origin"),
        Some("https://app.example")
    );
    assert_eq!(
        head.header("access-control-expose-headers"),
        Some("grpc-status, grpc-message")
    );
    assert_eq!(head.header("vary"), Some("Origin"));
    assert_eq!(head.header("content-type"), Some(BINARY));
}

#[tokio::test]
async fn grpc_web_cors_unlisted_origin() {
    let (podgate, _grpc) = start(json!({ "allow_origins": ["https://app.example"] })).await;
    // Lookalikes and spellings of a listed origin are not that origin, and nothing is echoed.
    for origin in [
        "https://evil.example",
        "https://app.example.evil.example",
        "http://app.example",
        "https://app.example:444",
        "null",
    ] {
        let (head, _) = options(&podgate, origin).await;
        assert!(
            head.with_prefix("access-control-").is_empty(),
            "{origin}: {:?}",
            head.headers
        );
        let mut wire = post(
            &podgate,
            "/test.Echo/Unary",
            BINARY,
            &frame(b"x"),
            &[("Origin", origin)],
        )
        .await;
        let head = wire.head().await;
        assert_eq!(head.status, 200, "{origin}");
        assert!(
            head.with_prefix("access-control-").is_empty(),
            "{origin}: {:?}",
            head.headers
        );
    }
    // No `allow_origins` at all: no CORS for anyone.
    let (podgate, _grpc) = start(json!({})).await;
    let (head, _) = options(&podgate, "https://app.example").await;
    assert!(head.with_prefix("access-control-").is_empty());
}

// ---------------------------------------------------------------------------------------
// Compile
// ---------------------------------------------------------------------------------------

fn conflict_codes(body: &Value) -> Vec<String> {
    body["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code").to_owned())
        .collect()
}

fn with_servers(servers: &Value, transport: Option<Value>) -> Value {
    let mut service = json!({ "name": "web", "type": "loadbalancer", "servers": servers });
    let mut app = app(
        "g",
        &["g.test"],
        &[json!({ "id": "r1", "state": "serving", "weight": 100, "services": [service.clone()] })],
    );
    if let Some(transport) = transport {
        service["transport"] = json!("t");
        app["transports"] = json!([{ "name": "t", "type": "servers_transport" }]);
        app["transports"][0]
            .as_object_mut()
            .expect("transport")
            .extend(transport.as_object().expect("fields").clone());
        app["revisions"][0]["services"] = json!([service]);
    }
    snapshot(1, &[with_middleware(app, "gw", "grpc_web", json!({}))])
}

#[tokio::test]
async fn grpc_web_requires_h2_upstream() {
    let podgate = Podgate::start().await;
    let refused = |reply: &common::Response| {
        assert_eq!(reply.status, 422, "{}", reply.body);
        assert_eq!(conflict_codes(&reply.json()), ["invalid_middleware"]);
        let text = reply.body.clone();
        assert!(
            text.contains("grpc_web") && text.contains("HTTP/2"),
            "{text}"
        );
    };
    // Plain HTTP/1.1.
    refused(
        &podgate
            .push_snapshot(&with_servers(
                &json!([{ "url": "http://127.0.0.1:9" }]),
                None,
            ))
            .await,
    );
    // HTTPS that is told not to offer HTTP/2.
    refused(
        &podgate
            .push_snapshot(&with_servers(
                &json!([{ "url": "https://127.0.0.1:9" }]),
                Some(json!({ "http2": false })),
            ))
            .await,
    );
    // One bad server among good ones is enough.
    refused(
        &podgate
            .push_snapshot(&with_servers(
                &json!([{ "url": "h2c://127.0.0.1:8" }, { "url": "http://127.0.0.1:9" }]),
                None,
            ))
            .await,
    );
    assert_eq!(
        podgate.get("g.test", "/").await.status,
        404,
        "nothing was applied"
    );
    // h2c, and HTTPS offered HTTP/2, compile.
    for (version, servers) in [
        json!([{ "url": "h2c://127.0.0.1:9" }]),
        json!([{ "url": "https://127.0.0.1:9" }]),
    ]
    .into_iter()
    .enumerate()
    {
        let mut pushed = with_servers(&servers, None);
        pushed["version"] = json!(version + 1);
        let pushed = podgate.push_snapshot(&pushed).await;
        assert_eq!(pushed.status, 200, "{servers}: {}", pushed.body);
    }
}

fn lb(name: &str, url: &str) -> Value {
    json!({ "name": name, "type": "loadbalancer", "servers": [{ "url": url }] })
}

/// A `grpc_web` route over the services of revision `r1`: `web` is the one the router uses.
fn with_graph(version: u64, services: &[Value]) -> Value {
    let revision = json!({ "id": "r1", "state": "serving", "weight": 100, "services": services });
    let mut pushed = snapshot(
        version,
        &[with_middleware(
            app("g", &["g.test"], &[revision]),
            "gw",
            "grpc_web",
            json!({}),
        )],
    );
    pushed["version"] = json!(version);
    pushed
}

#[tokio::test]
async fn grpc_web_requires_h2_through_weighted() {
    let podgate = Podgate::start().await;
    let h2 = lb("good", "h2c://127.0.0.1:9");
    let h1 = lb("bad", "http://127.0.0.1:9");
    let weighted = |children: &[(&str, u16)]| {
        let children: Vec<Value> = children
            .iter()
            .map(|(service, weight)| json!({ "service": service, "weight": weight }))
            .collect();
        json!({ "name": "web", "type": "weighted", "services": children })
    };
    let failover =
        json!({ "name": "web", "type": "failover", "service": "good", "fallback": "bad" });
    let nested =
        json!({ "name": "inner", "type": "failover", "service": "good", "fallback": "bad" });

    // Any reachable leaf that cannot speak HTTP/2 refuses the route, and the message names it.
    let refusing = [
        vec![weighted(&[("good", 1), ("bad", 1)]), h2.clone(), h1.clone()],
        vec![failover, h2.clone(), h1.clone()],
        vec![
            weighted(&[("good", 1), ("inner", 1)]),
            nested,
            h2.clone(),
            h1.clone(),
        ],
    ];
    for (index, services) in refusing.iter().enumerate() {
        let reply = podgate.push_snapshot(&with_graph(1, services)).await;
        assert_eq!(reply.status, 422, "{index}: {}", reply.body);
        assert_eq!(
            conflict_codes(&reply.json()),
            ["invalid_middleware"],
            "{index}"
        );
        let message = reply.json()["conflicts"][0]["message"]
            .as_str()
            .expect("message")
            .to_owned();
        assert!(
            message.contains("grpc_web")
                && message.contains("service bad has the server http://127.0.0.1:9"),
            "{index}: {message}"
        );
    }
    assert_eq!(
        podgate.get("g.test", "/").await.status,
        404,
        "nothing was applied"
    );

    // Every leaf speaks HTTP/2, or the one that does not is never chosen (weight 0).
    for (version, services) in [
        vec![
            weighted(&[("good", 1), ("good2", 3)]),
            h2.clone(),
            lb("good2", "h2c://127.0.0.1:8"),
        ],
        vec![weighted(&[("good", 1), ("bad", 0)]), h2.clone(), h1.clone()],
    ]
    .into_iter()
    .enumerate()
    {
        let reply = podgate
            .push_snapshot(&with_graph(version as u64 + 1, &services))
            .await;
        assert_eq!(reply.status, 200, "{version}: {}", reply.body);
    }
}

// ---------------------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------------------

/// The peak resident size of `pid`, in KiB.
fn peak_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .expect("the process")
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmHWM")
}

#[tokio::test]
async fn grpc_web_streams_100_mib_through_the_proxy() {
    let (podgate, _grpc) = start(json!({})).await;
    // Everything the proxy sets up once is in the baseline.
    let mut warm = post(
        &podgate,
        "/test.Echo/Big",
        BINARY,
        &frame(&4_u32.to_be_bytes()),
        &[],
    )
    .await;
    warm.head().await;
    warm.body().await;
    let before = peak_kib(podgate.pid());

    let count: u32 = 1600;
    let mut wire = post(
        &podgate,
        "/test.Echo/Big",
        BINARY,
        &frame(&count.to_be_bytes()),
        &[],
    )
    .await;
    assert_eq!(wire.head().await.status, 200);
    let mut buffer = FrameBuffer::default();
    let (mut messages, mut trailer) = (0_u32, None);
    while let Some(chunk) = wire.chunk().await {
        buffer.push(&chunk);
        while let Some((flag, payload)) = buffer.next() {
            if flag == 0x80 {
                trailer = Some(lines(&payload));
            } else {
                assert_eq!(payload.len(), MESSAGE);
                assert_eq!(payload[0], u8::try_from(messages % 251).unwrap_or(0));
                messages += 1;
            }
        }
    }
    assert_eq!(messages, count, "100 MiB in {count} messages");
    assert_eq!(trailer.expect("a trailer frame"), ["grpc-status: 0"]);
    let grown = peak_kib(podgate.pid()).saturating_sub(before);
    assert!(
        grown < 48 * 1024,
        "the proxy's peak size grew by {grown} KiB streaming 100 MiB"
    );
}

fn compile_stage() -> GrpcWeb {
    let declared: podgate_model::Declared =
        serde_json::from_value(json!({ "name": "g", "type": "grpc_web" })).expect("declared");
    let app: podgate_model::App = serde_json::from_value(json!({
        "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
        "routers": [], "revisions": []
    }))
    .expect("app");
    let mut engine = podgate::wasm::Compiler::default();
    GrpcWeb::compile(
        &declared,
        &mut CompileCx {
            app: &app,
            engine: &mut engine,
        },
    )
    .expect("compiles")
}

/// The most heap this thread held beyond `baseline` since [`reset_peak`].
fn peak_above(baseline: isize) -> usize {
    usize::try_from(PEAK.with(Cell::get) - baseline).unwrap_or(0)
}

fn reset_peak() -> isize {
    let live = LIVE.with(Cell::get);
    PEAK.with(|peak| peak.set(live));
    live
}

/// 100 MiB goes through the stage's hooks in both directions, a chunk at a time, and what the
/// stage holds beyond the chunk in flight stays inside its documented state: a remainder of
/// at most three characters in, two bytes out, and a trailer frame of at most 8 KiB.
#[test]
fn grpc_web_bounded_memory() {
    const TOTAL: usize = 100 * 1024 * 1024;
    const CHUNK: usize = 64 * 1024;
    let stage = compile_stage();

    // The text request: base64 in 64 KiB pieces, decoded as they come.
    let mut state = <GrpcWeb as Kind>::State::default();
    let mut request = RequestHeader::build("POST", b"/test.Echo/Big", None).expect("request");
    request
        .insert_header("content-type", TEXT)
        .expect("content type");
    let original = request.clone();
    stage
        .upstream_request(&mut request, &mut state)
        .expect("upstream request");
    assert_eq!(
        request.headers.get("content-type").expect("content type"),
        "application/grpc"
    );
    // 65535 bytes are 21845 whole groups: a chunk that ends on a group, then one cut inside it.
    let encoded = Bytes::from(STANDARD.encode(vec![7_u8; CHUNK - 1]));
    let (head, tail) = (
        encoded.slice(..encoded.len() - 2),
        encoded.slice(encoded.len() - 2..),
    );
    let baseline = reset_peak();
    let mut decoded = 0;
    for _ in 0..TOTAL / CHUNK {
        for piece in [head.clone(), tail.clone()] {
            let mut body = Some(piece);
            stage
                .request_body_chunk(&mut body, false, &mut state)
                .expect("decodes");
            decoded += body.map_or(0, |bytes| bytes.len());
        }
    }
    let mut last = None;
    stage
        .request_body_chunk(&mut last, true, &mut state)
        .expect("ends");
    assert_eq!(decoded, TOTAL / CHUNK * (CHUNK - 1));
    let request_peak = peak_above(baseline);
    assert!(
        request_peak <= 2 * CHUNK,
        "decoding held {request_peak} bytes at its peak for {CHUNK}-byte chunks"
    );

    // The text response: gRPC messages in, base64 and a trailer frame out.
    let mut state = <GrpcWeb as Kind>::State::default();
    let mut request = original;
    stage
        .upstream_request(&mut request, &mut state)
        .expect("mode");
    let mut head = ResponseHeader::build(200, None).expect("response");
    head.insert_header("content-type", "application/grpc")
        .expect("content type");
    let upstream = head.clone();
    stage
        .response_head(
            &ResponseCx {
                request: &request,
                response: &upstream,
                tenant: None,
            },
            &mut state,
        )
        .expect("head");
    stage.response(&mut head, &mut state).expect("response");
    assert_eq!(head.headers.get("content-type").expect("type"), TEXT);
    let chunk = Bytes::from(vec![9_u8; CHUNK]);
    let baseline = reset_peak();
    let mut written = 0;
    for _ in 0..TOTAL / CHUNK {
        let mut body = Some(chunk.clone());
        stage
            .response_body(&mut body, false, &mut state)
            .expect("encodes");
        written += body.map_or(0, |bytes| bytes.len());
    }
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    trailers.insert(
        "x-big",
        HeaderValue::from_str(&"b".repeat(MAX_TRAILER_BYTES / 2)).expect("value"),
    );
    let last = stage
        .response_trailers(&mut trailers, &mut state)
        .expect("the trailer frame");
    written += last.len();
    let frame_len = 5 + "grpc-status: 0\r\n".len() + "x-big: ".len() + MAX_TRAILER_BYTES / 2 + 2;
    assert_eq!(
        written,
        (TOTAL + frame_len).div_ceil(3) * 4,
        "every byte, once, as one base64 stream"
    );
    let response_peak = peak_above(baseline);
    // One chunk of output is in flight (4/3 of the input) plus the frame and its encoding.
    let bound = CHUNK / 3 * 4 + 4096 + 2 * (MAX_TRAILER_BYTES + 5) * 4 / 3;
    assert!(
        response_peak <= bound,
        "encoding held {response_peak} bytes at its peak, the bound is {bound}"
    );
}
