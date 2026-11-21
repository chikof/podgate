//! The `compress` middleware, end to end on the real binary: gzip, brotli and zstd
//! decoded by real decoders, negotiation, the skip rules, and the tenant's buffer budget.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use common::grpc::Client;
use common::{Podgate, TestCert, app, serving, snapshot, with_buffering, with_middleware};
use http::{HeaderMap, HeaderValue, Response};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

const MIB: u64 = 1024 * 1024;

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// `len` bytes of text that compresses well.
fn text(len: usize) -> Vec<u8> {
    (0..)
        .flat_map(|n: u32| format!("line {n}: some text that compresses well\n").into_bytes())
        .take(len)
        .collect()
}

/// What the test upstream answers.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    chunked: bool,
}

fn reply(content_type: &str, body: Vec<u8>) -> Reply {
    Reply {
        status: 200,
        headers: vec![("Content-Type", content_type.to_owned())],
        body,
        chunked: false,
    }
}

/// The answer for `path`; the same for every method, a `HEAD` just loses the body.
fn answer(path: &str) -> Reply {
    let plain = |len| reply("text/plain", text(len));
    let with = |mut reply: Reply, name, value: &str| {
        reply.headers.push((name, value.to_owned()));
        reply
    };
    match path {
        "/small" => plain(100),
        "/sse" => reply("text/event-stream", text(5000)),
        "/grpc" => reply("application/grpc+proto", text(5000)),
        "/encoded" => with(plain(5000), "Content-Encoding", "br"),
        "/notransform" => with(plain(5000), "Cache-Control", "public, no-transform"),
        "/range" => Reply {
            status: 206,
            ..with(plain(5000), "Content-Range", "bytes 0-4999/9999")
        },
        "/etag" => with(
            with(plain(5000), "ETag", "\"abc\""),
            "Accept-Ranges",
            "bytes",
        ),
        "/png" => reply("image/png", text(5000)),
        "/css" => reply("text/css", text(5000)),
        "/svg" => reply("image/svg+xml", text(5000)),
        "/chunked" => Reply {
            chunked: true,
            ..plain(20_000)
        },
        "/chunked-small" => Reply {
            chunked: true,
            ..plain(100)
        },
        "/204" => Reply {
            status: 204,
            headers: Vec::new(),
            body: Vec::new(),
            chunked: false,
        },
        "/304" => Reply {
            status: 304,
            ..plain(0)
        },
        _ => plain(20_000),
    }
}

fn wire(reply: &Reply, head_only: bool) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {} X\r\n", reply.status);
    for (name, value) in &reply.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    let bodiless = matches!(reply.status, 204 | 304);
    if reply.chunked {
        out.push_str("Transfer-Encoding: chunked\r\n");
    } else if !bodiless {
        out.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    if head_only || bodiless {
        return bytes;
    }
    if reply.chunked {
        for chunk in reply.body.chunks(4096) {
            bytes.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            bytes.extend_from_slice(chunk);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"0\r\n\r\n");
    } else {
        bytes.extend_from_slice(&reply.body);
    }
    bytes
}

/// An upstream that answers every request by its path through [`answer`].
struct Backend {
    addr: SocketAddr,
}

impl Backend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(stream));
            }
        });
        Self { addr }
    }
}

async fn serve(mut stream: TcpStream) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        while let Some(end) = find(&seen, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            seen.drain(..end + 4);
            let mut words = head.split_whitespace();
            let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or("/"));
            let bytes = wire(&answer(path), method == "HEAD");
            if stream.write_all(&bytes).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// A response as received: the body is as it came off the wire after chunked decoding, still
/// content-encoded.
struct Got {
    status: u16,
    headers: Vec<(String, String)>,
    wire: Vec<u8>,
}

impl Got {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn encoding(&self) -> Option<&str> {
        self.header("content-encoding")
    }

    /// The body after the content encoding is undone by a real decoder.
    fn decoded(&self) -> Vec<u8> {
        decode(self.encoding(), &self.wire)
    }
}

/// `wire` after the content encoding `encoding` is undone by a real decoder.
fn decode(encoding: Option<&str>, wire: &[u8]) -> Vec<u8> {
    match encoding {
        None => wire.to_vec(),
        Some("gzip") => {
            assert_eq!(wire[..3], [0x1f, 0x8b, 8], "gzip header");
            let raw = &wire[10..wire.len() - 8];
            let inflated = miniz_oxide::inflate::decompress_to_vec(raw).expect("deflate");
            let trailer = &wire[wire.len() - 8..];
            assert_eq!(trailer[..4], crc32fast::hash(&inflated).to_le_bytes());
            inflated
        }
        Some("br") => {
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut &*wire, &mut out).expect("valid brotli");
            out
        }
        Some("zstd") => zstd::stream::decode_all(wire).expect("valid zstd"),
        Some(other) => panic!("unexpected content-encoding {other}"),
    }
}

fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let line_end = find(raw, b"\r\n").expect("chunk size line");
        let size = usize::from_str_radix(
            std::str::from_utf8(&raw[..line_end]).expect("ascii size"),
            16,
        )
        .expect("hex chunk size");
        raw = &raw[line_end + 2..];
        if size == 0 {
            return body;
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

/// `method path` to `a.test` with `Accept-Encoding: accept` when given.
async fn fetch(proxy: SocketAddr, method: &str, path: &str, accept: Option<&str>) -> Got {
    timeout(Duration::from_secs(20), async {
        let mut stream = TcpStream::connect(proxy).await.expect("connect");
        let accept = accept.map_or(String::new(), |a| format!("Accept-Encoding: {a}\r\n"));
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: a.test\r\n{accept}Connection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let split = find(&raw, b"\r\n\r\n").expect("header end");
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status line");
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let mut body = raw[split + 4..].to_vec();
        let chunked = headers
            .iter()
            .any(|(name, value)| name == "transfer-encoding" && value == "chunked");
        if chunked {
            body = dechunk(&body);
        }
        Got {
            status,
            headers,
            wire: body,
        }
    })
    .await
    .expect("response in time")
}

/// Starts `podgate` with app `a.test` on `upstream`, with a `compress` middleware configured by
/// `config` when given and none when not.
async fn serve_with(upstream: SocketAddr, config: Option<Value>) -> Podgate {
    let podgate = Podgate::start().await;
    let mut app = app("a", &["a.test"], &[serving("r1", upstream)]);
    if let Some(config) = config {
        app = with_middleware(app, "z", "compress", config);
    }
    let pushed = podgate.push_snapshot(&snapshot(1, &[app])).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    podgate
}

async fn roundtrip(algorithm: &str, token: &str) {
    let backend = Backend::start().await;
    let podgate = serve_with(backend.addr, Some(json!({ "algorithms": [algorithm] }))).await;
    let got = fetch(podgate.proxy_addr, "GET", "/text", Some(token)).await;
    assert_eq!(got.status, 200);
    assert_eq!(got.encoding(), Some(token));
    assert_eq!(got.header("vary"), Some("accept-encoding"));
    assert!(got.header("content-length").is_none());
    assert!(got.wire.len() < 20_000 / 2, "the text got smaller");
    assert_eq!(got.decoded(), text(20_000));
}

#[tokio::test]
async fn compress_gzip_roundtrip() {
    roundtrip("gzip", "gzip").await;
}

#[tokio::test]
async fn compress_brotli_roundtrip() {
    roundtrip("brotli", "br").await;
}

#[tokio::test]
async fn compress_zstd_roundtrip_or_unsupported() {
    // Built: ruzstd with one bounded frame per 32 KiB, so zstd round-trips through libzstd.
    roundtrip("zstd", "zstd").await;
}

#[tokio::test]
async fn compress_prefers_server_order() {
    let backend = Backend::start().await;
    let podgate = serve_with(
        backend.addr,
        Some(json!({ "algorithms": ["zstd", "br", "gzip"] })),
    )
    .await;
    for (accept, expected) in [
        ("gzip, br, zstd", "zstd"),
        ("gzip, br", "br"),
        ("gzip", "gzip"),
        ("gzip, br;q=0.1", "br"),
        ("GZIP;q=1.0, BR;q=0.5", "br"),
        ("*", "zstd"),
    ] {
        let got = fetch(podgate.proxy_addr, "GET", "/text", Some(accept)).await;
        assert_eq!(got.encoding(), Some(expected), "{accept}");
        assert_eq!(got.decoded(), text(20_000), "{accept}");
    }
}

#[tokio::test]
async fn compress_q_zero_refuses() {
    let backend = Backend::start().await;
    let podgate = serve_with(
        backend.addr,
        Some(json!({ "algorithms": ["zstd", "br", "gzip"] })),
    )
    .await;
    for (accept, expected) in [
        ("zstd;q=0, br;q=0, gzip", Some("gzip")),
        ("zstd;q=0, br, gzip", Some("br")),
        ("*;q=0, gzip", Some("gzip")),
        ("gzip;q=0, *", Some("zstd")),
        ("zstd;q=0, br;q=0, gzip;q=0", None),
        ("*;q=0", None),
        ("deflate, identity", None),
    ] {
        let got = fetch(podgate.proxy_addr, "GET", "/text", Some(accept)).await;
        assert_eq!(got.encoding(), expected, "{accept}");
        assert_eq!(got.decoded(), text(20_000), "{accept}");
    }
    let none = fetch(podgate.proxy_addr, "GET", "/text", None).await;
    assert_eq!(none.encoding(), None, "no Accept-Encoding, no encoding");
}

#[tokio::test]
async fn compress_skips_event_stream_and_grpc() {
    let backend = Backend::start().await;
    // An include list that names them does not change it: streams are never compressed.
    let podgate = serve_with(
        backend.addr,
        Some(json!({
            "algorithms": ["gzip"],
            "include_content_types": ["text/event-stream", "application/grpc+proto", "text/*"],
        })),
    )
    .await;
    for path in ["/sse", "/grpc"] {
        let got = fetch(podgate.proxy_addr, "GET", path, Some("gzip, br, zstd")).await;
        assert_eq!(got.status, 200, "{path}");
        assert_eq!(got.encoding(), None, "{path}");
        assert_eq!(
            got.wire,
            text(5000),
            "{path}: bytes as the upstream sent them"
        );
    }
    let platform = Backend::start().await;
    let podgate = serve_with(platform.addr, None).await;
    for path in ["/sse", "/grpc"] {
        let got = fetch(podgate.proxy_addr, "GET", path, Some("gzip")).await;
        assert_eq!(got.encoding(), None, "default chain, {path}");
    }
}

#[tokio::test]
async fn compress_skips_encoded_and_partial() {
    let backend = Backend::start().await;
    let podgate = serve_with(backend.addr, Some(json!({ "algorithms": ["gzip", "br"] }))).await;
    let accept = Some("gzip, br");
    let encoded = fetch(podgate.proxy_addr, "GET", "/encoded", accept).await;
    assert_eq!(
        encoded.encoding(),
        Some("br"),
        "the upstream's encoding stays"
    );
    assert_eq!(encoded.wire, text(5000), "and is not encoded again");
    let notransform = fetch(podgate.proxy_addr, "GET", "/notransform", accept).await;
    assert_eq!(notransform.encoding(), None);
    assert_eq!(notransform.wire, text(5000));
    let partial = fetch(podgate.proxy_addr, "GET", "/range", accept).await;
    assert_eq!(partial.status, 206);
    assert_eq!(partial.encoding(), None);
    assert_eq!(partial.header("content-range"), Some("bytes 0-4999/9999"));
    assert_eq!(partial.wire, text(5000));
    let head = fetch(podgate.proxy_addr, "HEAD", "/text", accept).await;
    assert_eq!(head.status, 200);
    assert_eq!(head.encoding(), None, "HEAD is never encoded");
    assert_eq!(head.header("content-length"), Some("20000"));
    assert_eq!(head.header("vary"), Some("accept-encoding"));
    assert!(head.wire.is_empty());
    let no_content = fetch(podgate.proxy_addr, "GET", "/204", accept).await;
    assert_eq!(no_content.status, 204);
    assert_eq!(no_content.encoding(), None);
    let not_modified = fetch(podgate.proxy_addr, "GET", "/304", accept).await;
    assert_eq!(not_modified.status, 304);
    assert_eq!(not_modified.encoding(), None);
}

#[tokio::test]
async fn compress_adds_vary_and_weakens_etag() {
    let backend = Backend::start().await;
    let podgate = serve_with(backend.addr, Some(json!({ "algorithms": ["gzip"] }))).await;
    let encoded = fetch(podgate.proxy_addr, "GET", "/etag", Some("gzip")).await;
    assert_eq!(encoded.encoding(), Some("gzip"));
    assert_eq!(encoded.header("vary"), Some("accept-encoding"));
    assert_eq!(encoded.header("etag"), Some("W/\"abc\""));
    assert!(encoded.header("accept-ranges").is_none());
    assert!(encoded.header("content-length").is_none());
    assert_eq!(encoded.decoded(), text(5000));

    let identity = fetch(podgate.proxy_addr, "GET", "/etag", None).await;
    assert_eq!(identity.encoding(), None);
    assert_eq!(
        identity.header("vary"),
        Some("accept-encoding"),
        "a response that could have been encoded varies either way"
    );
    assert_eq!(
        identity.header("etag"),
        Some("\"abc\""),
        "identity keeps it strong"
    );
    assert_eq!(identity.header("content-length"), Some("5000"));

    let image = fetch(podgate.proxy_addr, "GET", "/png", Some("gzip")).await;
    assert!(
        image.header("vary").is_none(),
        "an image is never a candidate"
    );
}

#[tokio::test]
async fn compress_min_bytes() {
    let backend = Backend::start().await;
    let default = serve_with(backend.addr, Some(json!({}))).await;
    let small = fetch(default.proxy_addr, "GET", "/small", Some("gzip")).await;
    assert_eq!(
        small.encoding(),
        None,
        "100 bytes is under the default 1024"
    );
    assert!(small.header("vary").is_none());
    assert_eq!(small.wire, text(100));
    let page = fetch(default.proxy_addr, "GET", "/text", Some("gzip")).await;
    assert_eq!(page.encoding(), Some("gzip"));

    let low = serve_with(backend.addr, Some(json!({ "min_bytes": 50 }))).await;
    let small = fetch(low.proxy_addr, "GET", "/small", Some("gzip")).await;
    assert_eq!(small.encoding(), Some("gzip"));
    assert_eq!(small.decoded(), text(100));

    let high = serve_with(backend.addr, Some(json!({ "min_bytes": 30_000 }))).await;
    let page = fetch(high.proxy_addr, "GET", "/text", Some("gzip")).await;
    assert_eq!(page.encoding(), None, "20 KB is under 30,000");
}

#[tokio::test]
async fn compress_content_type_lists() {
    let backend = Backend::start().await;
    let exclude = serve_with(
        backend.addr,
        Some(json!({ "exclude_content_types": ["text/css"] })),
    )
    .await;
    let css = fetch(exclude.proxy_addr, "GET", "/css", Some("gzip")).await;
    assert_eq!(css.encoding(), None, "excluded");
    let plain = fetch(exclude.proxy_addr, "GET", "/text", Some("gzip")).await;
    assert_eq!(plain.encoding(), Some("gzip"));

    let include = serve_with(
        backend.addr,
        Some(json!({ "include_content_types": ["image/svg+xml", "text/css"] })),
    )
    .await;
    let svg = fetch(include.proxy_addr, "GET", "/svg", Some("gzip")).await;
    assert_eq!(svg.encoding(), Some("gzip"), "an include list adds a type");
    assert_eq!(svg.decoded(), text(5000));
    let plain = fetch(include.proxy_addr, "GET", "/text", Some("gzip")).await;
    assert_eq!(plain.encoding(), None, "and replaces the text-like default");
    let png = fetch(include.proxy_addr, "GET", "/png", Some("gzip")).await;
    assert_eq!(png.encoding(), None);

    let family = serve_with(
        backend.addr,
        Some(
            json!({ "include_content_types": ["image/*"], "exclude_content_types": ["image/png"] }),
        ),
    )
    .await;
    let svg = fetch(family.proxy_addr, "GET", "/svg", Some("gzip")).await;
    assert_eq!(svg.encoding(), Some("gzip"), "image/* matches a subtype");
    let png = fetch(family.proxy_addr, "GET", "/png", Some("gzip")).await;
    assert_eq!(png.encoding(), None, "exclude wins over include");
}

#[tokio::test]
async fn compress_unknown_length_small_body() {
    // Pingora writes the response head before it reads any of the body, so a body of unknown
    // length cannot be sized in time: it is compressed whatever its size, `min_bytes` applies
    // to a declared length only. Either way the client gets a valid stream.
    let backend = Backend::start().await;
    let podgate = serve_with(
        backend.addr,
        Some(json!({ "algorithms": ["zstd", "gzip"] })),
    )
    .await;
    let small = fetch(podgate.proxy_addr, "GET", "/chunked-small", Some("zstd")).await;
    assert_eq!(small.status, 200);
    assert_eq!(small.encoding(), Some("zstd"));
    assert_eq!(small.decoded(), text(100));
    let large = fetch(podgate.proxy_addr, "GET", "/chunked", Some("gzip")).await;
    assert_eq!(large.encoding(), Some("gzip"));
    assert_eq!(large.decoded(), text(20_000));

    let excluded = serve_with(
        backend.addr,
        Some(json!({ "exclude_content_types": ["text/plain"] })),
    )
    .await;
    let got = fetch(excluded.proxy_addr, "GET", "/chunked", Some("gzip")).await;
    assert_eq!(got.encoding(), None, "the content-type lists apply to it");
    assert_eq!(got.wire, text(20_000));
}

#[tokio::test]
async fn compress_default_still_gzip() {
    let backend = Backend::start().await;
    let podgate = serve_with(backend.addr, None).await;
    let got = fetch(podgate.proxy_addr, "GET", "/text", Some("zstd, br, gzip")).await;
    assert_eq!(
        got.encoding(),
        Some("gzip"),
        "the platform default is gzip only"
    );
    assert_eq!(got.header("vary"), Some("accept-encoding"));
    assert_eq!(got.decoded(), text(20_000));
    let other = fetch(podgate.proxy_addr, "GET", "/text", Some("br, zstd")).await;
    assert_eq!(other.encoding(), None);
}

#[tokio::test]
async fn compress_algorithms_empty_disables() {
    let backend = Backend::start().await;
    let podgate = serve_with(backend.addr, Some(json!({ "algorithms": [] }))).await;
    let got = fetch(podgate.proxy_addr, "GET", "/text", Some("gzip, br, zstd")).await;
    assert_eq!(
        got.encoding(),
        None,
        "an empty list turns the platform default off"
    );
    assert!(got.header("vary").is_none());
    assert_eq!(got.wire, text(20_000));
}

#[tokio::test]
async fn compress_runs_after_the_response_head_limit() {
    // The upstream's 20,000-byte response is over the 10,000-byte limit, although it would be
    // far under it once compressed: the limit judges what the upstream sent.
    let backend = Backend::start().await;
    let podgate = Podgate::start().await;
    let app = with_buffering(
        app("a", &["a.test"], &[serving("r1", backend.addr)]),
        json!({ "max_response_body_bytes": 10_000, "buffer_response": true }),
    );
    let app = with_middleware(app, "z", "compress", json!({ "algorithms": ["gzip"] }));
    let pushed = podgate.push_snapshot(&snapshot(1, &[app])).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    let got = fetch(podgate.proxy_addr, "GET", "/text", Some("gzip")).await;
    assert_eq!(got.status, 502, "over the limit as sent");
    assert_eq!(got.encoding(), None);
    let fits = fetch(podgate.proxy_addr, "GET", "/etag", Some("gzip")).await;
    assert_eq!(fits.status, 200);
    assert_eq!(fits.encoding(), Some("gzip"));
    assert_eq!(fits.decoded(), text(5000));
}

#[tokio::test]
async fn compress_bad_settings_are_refused() {
    let backend = Backend::start().await;
    let podgate = Podgate::start().await;
    for config in [
        json!({ "algorithms": ["deflate"] }),
        json!({ "algorithms": ["gzip", "gzip"] }),
        json!({ "level": 9 }),
        json!({ "include_content_types": ["text"] }),
        json!({ "windowBits": 24 }),
    ] {
        let app = with_middleware(
            app("a", &["a.test"], &[serving("r1", backend.addr)]),
            "z",
            "compress",
            config.clone(),
        );
        let pushed = podgate.push_snapshot(&snapshot(1, &[app])).await;
        assert_eq!(pushed.status, 422, "{config}: {pushed:?}");
        assert_eq!(
            pushed.json()["conflicts"][0]["code"],
            "invalid_middleware",
            "{config}"
        );
    }
}

/// A backend that sends its headers and half of its body, waits, then sends the rest, so
/// responses overlap in the proxy.
async fn slow_backend(body: Arc<[u8]>, delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(slow_serve(stream, Arc::clone(&body), delay));
        }
    });
    addr
}

async fn slow_serve(mut stream: TcpStream, body: Arc<[u8]>, delay: Duration) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let (first, second) = body.split_at(body.len() / 2);
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = find(&seen, b"\r\n\r\n") {
            seen.drain(..end + 4);
            let sent = async {
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(first).await?;
                stream.flush().await?;
                sleep(delay).await;
                stream.write_all(second).await
            }
            .await;
            if sent.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// Value of the series `name{tenant="t1"}` in a Prometheus text body.
fn series(metrics: &str, name: &str) -> u64 {
    let prefix = format!("{name}{{tenant=\"t1\"}} ");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.parse().expect("integer sample"))
}

#[tokio::test]
async fn compress_budget_holds_all_algorithms() {
    for (algorithm, token) in [("gzip", "gzip"), ("brotli", "br"), ("zstd", "zstd")] {
        let body: Arc<[u8]> = text(480_000).into();
        let addr = slow_backend(Arc::clone(&body), Duration::from_millis(400)).await;
        let podgate = Arc::new(Podgate::start().await);
        let app = with_middleware(
            app("a", &["a.test"], &[serving("r1", addr)]),
            "z",
            "compress",
            json!({ "algorithms": [algorithm] }),
        );
        let mut snapshot = snapshot(1, &[app]);
        snapshot["tenants"][0]["budget"] = json!({ "max_inflight": 1000, "max_buffer_bytes": MIB });
        let pushed = podgate.push_snapshot(&snapshot).await;
        assert_eq!(pushed.status, 200, "{pushed:?}");

        let sampled_max = Arc::new(AtomicU64::new(0));
        let sampler = tokio::spawn({
            let (podgate, sampled_max) = (Arc::clone(&podgate), Arc::clone(&sampled_max));
            async move {
                loop {
                    let metrics = podgate.admin_get("/metrics").await.body;
                    let now = series(&metrics, "podgate_tenant_buffer_bytes");
                    sampled_max.fetch_max(now, Ordering::Relaxed);
                    sleep(Duration::from_millis(10)).await;
                }
            }
        });

        let proxy = podgate.proxy_addr;
        let requests: Vec<_> = (0..200)
            .map(|_| tokio::spawn(fetch(proxy, "GET", "/", Some(token))))
            .collect();
        let (mut compressed, mut identity) = (0, 0);
        for request in requests {
            let got = request.await.expect("request task");
            assert_eq!(got.status, 200, "{algorithm}: every response is served");
            assert_eq!(got.decoded(), *body, "{algorithm}: the body arrives intact");
            match got.encoding() {
                Some(encoding) if encoding == token => compressed += 1,
                None => identity += 1,
                Some(other) => panic!("{algorithm}: unexpected content-encoding {other}"),
            }
        }
        sampler.abort();

        assert!(compressed > 0, "{algorithm}: some responses fit the budget");
        assert!(identity > 0, "{algorithm}: the rest degrade to identity");
        let metrics = podgate.admin_get("/metrics").await.body;
        let peak = series(&metrics, "podgate_tenant_buffer_bytes_peak");
        assert!(peak > 0, "{algorithm}: compression was charged: {metrics}");
        assert!(
            peak <= MIB,
            "{algorithm}: peak {peak} passed the budget: {metrics}"
        );
        assert!(sampled_max.load(Ordering::Relaxed) <= MIB);
        assert_eq!(series(&metrics, "podgate_tenant_buffer_bytes"), 0);
        assert!(series(&metrics, "podgate_tenant_compression_skipped_total") >= identity);
    }
}

/// An HTTP/2 cleartext upstream whose every response is a `text/plain` body in two DATA frames
/// (`first`, `second`, a pause between) that do not end the stream, then the trailers
/// `x-checksum: abc123`.
async fn trailer_upstream(first: Vec<u8>, second: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (first, second) = (first.clone(), second.clone());
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(tcp).await else {
                    return;
                };
                while let Some(Ok((_request, mut respond))) = connection.accept().await {
                    let (first, second) = (first.clone(), second.clone());
                    tokio::spawn(async move {
                        let head = Response::builder()
                            .status(200)
                            .header("content-type", "text/plain");
                        let Ok(mut send) =
                            respond.send_response(head.body(()).expect("head"), false)
                        else {
                            return;
                        };
                        drop(send.send_data(Bytes::from(first), false));
                        sleep(Duration::from_millis(20)).await;
                        drop(send.send_data(Bytes::from(second), false));
                        sleep(Duration::from_millis(20)).await;
                        let mut trailers = HeaderMap::new();
                        trailers.insert("x-checksum", HeaderValue::from_static("abc123"));
                        drop(send.send_trailers(trailers));
                    });
                }
            });
        }
    });
    addr
}

/// A compressed HTTP/2 upstream response that ends in trailers is a whole encoding: the encoder
/// is finished ahead of the trailers, with and without the buffering middleware holding the
/// body, and the trailers arrive after the body.
#[tokio::test]
async fn compress_finishes_stream_before_h2_trailers() {
    const HOST: &str = "t.test";
    let (first, second) = (text(4000), text(6000));
    let whole = [first.clone(), second.clone()].concat();
    for (algorithm, token) in [("gzip", "gzip"), ("brotli", "br"), ("zstd", "zstd")] {
        for buffered in [false, true] {
            let label = format!("{algorithm}, buffered {buffered}");
            let upstream = trailer_upstream(first.clone(), second.clone()).await;
            let podgate = Podgate::start().await;
            let cert = TestCert::new(&[HOST]);
            let mut revision = serving("r1", upstream);
            revision["services"][0]["servers"][0]["url"] = json!(format!("h2c://{upstream}"));
            let mut app = with_middleware(
                app("t", &[HOST], &[revision]),
                "z",
                "compress",
                json!({ "algorithms": [algorithm] }),
            );
            if buffered {
                let config = json!({ "max_response_body_bytes": 65536, "buffer_response": true });
                app = with_middleware(app, "buffer", "buffering", config);
            }
            let mut pushed = snapshot(1, &[app]);
            pushed["certificates"] = json!([cert.entry(&[HOST])]);
            let reply = podgate.push_snapshot(&pushed).await;
            assert_eq!(reply.status, 200, "{label}: {}", reply.body);

            let client = Client::tls(podgate.tls_addr, HOST, &cert.der).await;
            let mut call = client
                .start_request(
                    "GET",
                    "text/plain",
                    "/",
                    &[("accept-encoding", "gzip, br, zstd")],
                )
                .await;
            call.finish();
            let raw = call.raw().await;
            assert_eq!(raw.status, 200, "{label}");
            assert_eq!(raw.header("content-encoding"), Some(token), "{label}");
            assert_eq!(decode(Some(token), &raw.body), whole, "{label}");
            let trailers = raw.trailers.expect("the trailers arrive");
            assert_eq!(trailers.get("x-checksum").expect("checksum"), "abc123");
        }
    }
}
