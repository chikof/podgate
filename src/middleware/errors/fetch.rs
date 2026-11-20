//! The one-shot HTTP/1.1 client that fetches an error page.
//!
//! It dials through Pingora's `TransportConnector` (the connect path of the proxy and of health
//! probes), so an `https://` server is reached with the transport of its service, and checks the
//! exact IP it is about to dial against the upstream address policy. It speaks HTTP/1.1 by hand
//! so that every size is a number in this file: the response head is read up to `HEAD_LIMIT`
//! bytes, the body up to the cap the caller charged to the tenant, and the whole exchange runs
//! under one timeout. It never follows a redirect and never reuses a connection.
//!
//! The request is `GET <path> HTTP/1.1` with `Host` and `Accept` and nothing else.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use http::HeaderValue;
use pingora::connectors::TransportConnector;
use pingora::upstreams::peer::HttpPeer;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::service::upstream_policy::UpstreamPolicy;

/// The most bytes a response head may take.
const HEAD_LIMIT: usize = 8 * 1024;
/// One read never asks for more than this many bytes.
const READ: usize = 4 * 1024;
/// The most bytes of chunked-body trailers that are read and thrown away.
const TRAILER_LIMIT: usize = 8 * 1024;
/// The longest `Content-Type` that is kept.
const CONTENT_TYPE_LIMIT: usize = 256;

/// What a fetch holds besides the body: the head and the read buffers. A caller charges this plus
/// the body cap to the tenant before it fetches.
pub const ALLOWANCE: u64 = (HEAD_LIMIT + 2 * READ) as u64;

/// Why a page could not be fetched. Every variant leaves the original response in place.
#[derive(Debug, Error)]
pub enum Failure {
    /// The upstream address policy refuses the address of the server.
    #[error("the upstream address policy refuses the server")]
    Policy,
    /// The server is not an IP address.
    #[error("the server is not an IP address")]
    NotInet,
    /// The connection could not be made.
    #[error("connect: {0}")]
    Connect(Box<str>),
    /// The exchange ran past the timeout.
    #[error("timed out")]
    Timeout,
    /// The connection failed while reading or writing.
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    /// The server did not answer `200`-ish with a body.
    #[error("the server answered {0}")]
    Status(u16),
    /// The body is over the cap.
    #[error("the body is over the cap")]
    TooLarge,
    /// The response is not one this client accepts.
    #[error("malformed response: {0}")]
    Malformed(&'static str),
}

/// What to ask for.
#[derive(Debug, Clone, Copy)]
pub struct Query<'a> {
    /// The `Host` header.
    pub host: &'a str,
    /// The `Accept` header.
    pub accept: &'a str,
    /// The request target.
    pub path: &'a str,
}

/// How far a fetch may go.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The most body bytes.
    pub max_body: usize,
    /// The time for connecting, sending and reading, all together.
    pub timeout: Duration,
}

/// A fetched page.
#[derive(Debug)]
pub struct Fetched {
    /// The `Content-Type` of the page, when it sent a usable one.
    pub content_type: Option<HeaderValue>,
    /// The body: at least one byte, at most [`Limits::max_body`].
    pub body: Vec<u8>,
}

/// Dials error page servers. Cheap to clone; clones share the connector.
#[derive(Clone)]
pub struct Fetcher {
    connector: Arc<TransportConnector>,
}

impl Default for Fetcher {
    fn default() -> Self {
        Self {
            connector: Arc::new(TransportConnector::new(None)),
        }
    }
}

impl fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fetcher").finish_non_exhaustive()
    }
}

impl Fetcher {
    /// Fetches `query` from the server `peer` points at, for a tenant `tenant`.
    ///
    /// # Errors
    ///
    /// A [`Failure`]: the policy refuses the address (nothing is dialled), the connection or the
    /// timeout fails, or the answer is not a usable page.
    pub async fn fetch(
        &self,
        mut peer: HttpPeer,
        policy: &UpstreamPolicy,
        tenant: &str,
        query: &Query<'_>,
        limits: Limits,
    ) -> Result<Fetched, Failure> {
        let ip = peer
            ._address
            .as_inet()
            .map(std::net::SocketAddr::ip)
            .ok_or(Failure::NotInet)?;
        // The exact address about to be dialled, every time.
        policy.check(tenant, ip).map_err(|_| Failure::Policy)?;
        peer.options.connection_timeout = Some(limits.timeout);
        peer.options.read_timeout = Some(limits.timeout);
        peer.options.write_timeout = Some(limits.timeout);
        let exchange = async {
            let mut stream = Box::pin(self.connector.new_stream(&peer))
                .await
                .map_err(|err| Failure::Connect(err.to_string().into()))?;
            exchange(&mut stream, query, limits.max_body).await
        };
        timeout(limits.timeout, exchange)
            .await
            .map_err(|_| Failure::Timeout)?
    }
}

/// How the end of the body is found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    Length(usize),
    Chunked,
    Close,
}

#[derive(Debug)]
struct Head {
    framing: Framing,
    content_type: Option<HeaderValue>,
}

/// Sends the request over `stream` and reads the page.
async fn exchange<S>(stream: &mut S, query: &Query<'_>, max_body: usize) -> Result<Fetched, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: {}\r\n\r\n",
        query.path, query.host, query.accept
    );
    stream.write_all(request.as_bytes()).await?;
    let mut buffer: Vec<u8> = Vec::with_capacity(READ);
    let head_end = loop {
        if let Some(end) = find(&buffer, b"\r\n\r\n") {
            break end + 4;
        }
        if buffer.len() >= HEAD_LIMIT {
            return Err(Failure::Malformed("the response head is too long"));
        }
        fill(stream, &mut buffer).await?;
    };
    let head = parse_head(&buffer[..head_end])?;
    buffer.drain(..head_end);
    let body = read_body(stream, buffer, head.framing, max_body).await?;
    if body.is_empty() {
        return Err(Failure::Malformed("the page is empty"));
    }
    Ok(Fetched {
        content_type: head.content_type,
        body,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Reads at most [`READ`] more bytes onto `buffer`; the end of the stream is an error.
async fn fill<S: AsyncRead + Unpin>(stream: &mut S, buffer: &mut Vec<u8>) -> Result<(), Failure> {
    let mut chunk = vec![0_u8; READ];
    match stream.read(&mut chunk).await? {
        0 => Err(Failure::Malformed("the connection closed too early")),
        read => {
            buffer.extend_from_slice(&chunk[..read]);
            Ok(())
        }
    }
}

fn parse_head(raw: &[u8]) -> Result<Head, Failure> {
    let text = std::str::from_utf8(raw).map_err(|_| Failure::Malformed("the head is not text"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0")
        || code.len() != 3
        || !code.bytes().all(|digit| digit.is_ascii_digit())
    {
        return Err(Failure::Malformed("the status line is not HTTP/1.x"));
    }
    let status: u16 = code
        .parse()
        .map_err(|_| Failure::Malformed("the status code"))?;
    if !(200..300).contains(&status) || matches!(status, 204 | 205) {
        return Err(Failure::Status(status));
    }
    let mut length: Option<usize> = None;
    let mut chunked = false;
    let mut content_type = None;
    let mut saw_length = false;
    for line in lines.filter(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) {
            return Err(Failure::Malformed("a folded header"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(Failure::Malformed("a header without a colon"))?;
        let value = value.trim_matches([' ', '\t']);
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if std::mem::replace(&mut saw_length, true) {
                    return Err(Failure::Malformed("two content-length headers"));
                }
                if value.is_empty() || !value.bytes().all(|digit| digit.is_ascii_digit()) {
                    return Err(Failure::Malformed("the content-length"));
                }
                length = Some(value.parse().map_err(|_| Failure::TooLarge)?);
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(Failure::Malformed("a transfer coding other than chunked"));
                }
                chunked = true;
            }
            "content-encoding" => {
                if !value.eq_ignore_ascii_case("identity") {
                    return Err(Failure::Malformed("an encoded body"));
                }
            }
            "content-type" if value.len() <= CONTENT_TYPE_LIMIT => {
                content_type = HeaderValue::from_str(value).ok();
            }
            _ => {}
        }
    }
    let framing = match (chunked, length) {
        (true, Some(_)) => {
            return Err(Failure::Malformed(
                "both content-length and transfer-encoding",
            ));
        }
        (true, None) => Framing::Chunked,
        (false, Some(length)) => Framing::Length(length),
        (false, None) => Framing::Close,
    };
    Ok(Head {
        framing,
        content_type,
    })
}

/// Reads the body, which starts with `buffer` (what the head read brought in beyond the head).
async fn read_body<S>(
    stream: &mut S,
    mut buffer: Vec<u8>,
    framing: Framing,
    cap: usize,
) -> Result<Vec<u8>, Failure>
where
    S: AsyncRead + Unpin,
{
    match framing {
        Framing::Length(length) => {
            if length > cap {
                return Err(Failure::TooLarge);
            }
            let mut body = Vec::with_capacity(length);
            while body.len() < length {
                if buffer.is_empty() {
                    fill(stream, &mut buffer).await?;
                }
                let take = buffer.len().min(length - body.len());
                body.extend_from_slice(&buffer[..take]);
                buffer.drain(..take);
            }
            Ok(body)
        }
        Framing::Close => {
            let mut body = Vec::new();
            loop {
                if body.len() + buffer.len() > cap {
                    return Err(Failure::TooLarge);
                }
                body.append(&mut buffer);
                let mut chunk = vec![0_u8; READ];
                match stream.read(&mut chunk).await? {
                    0 => return Ok(body),
                    read => buffer.extend_from_slice(&chunk[..read]),
                }
            }
        }
        Framing::Chunked => read_chunked(stream, buffer, cap).await,
    }
}

/// Where the chunked decoder is.
enum Chunk {
    Size,
    Data(usize),
    DataEnd,
    Trailer(usize),
}

async fn read_chunked<S>(
    stream: &mut S,
    mut buffer: Vec<u8>,
    cap: usize,
) -> Result<Vec<u8>, Failure>
where
    S: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let mut state = Chunk::Size;
    loop {
        state = match state {
            Chunk::Size => {
                let Some(end) = find(&buffer, b"\r\n") else {
                    if buffer.len() > 64 {
                        return Err(Failure::Malformed("a chunk size line is too long"));
                    }
                    fill(stream, &mut buffer).await?;
                    continue;
                };
                let size = chunk_size(&buffer[..end])?;
                buffer.drain(..end + 2);
                if size == 0 {
                    Chunk::Trailer(0)
                } else if body.len().saturating_add(size) > cap {
                    return Err(Failure::TooLarge);
                } else {
                    Chunk::Data(size)
                }
            }
            Chunk::Data(remaining) => {
                if buffer.is_empty() {
                    fill(stream, &mut buffer).await?;
                }
                let take = buffer.len().min(remaining);
                body.extend_from_slice(&buffer[..take]);
                buffer.drain(..take);
                match remaining - take {
                    0 => Chunk::DataEnd,
                    left => Chunk::Data(left),
                }
            }
            Chunk::DataEnd => {
                while buffer.len() < 2 {
                    fill(stream, &mut buffer).await?;
                }
                if &buffer[..2] != b"\r\n" {
                    return Err(Failure::Malformed("a chunk is not followed by CRLF"));
                }
                buffer.drain(..2);
                Chunk::Size
            }
            Chunk::Trailer(spent) => {
                let Some(end) = find(&buffer, b"\r\n") else {
                    if spent + buffer.len() > TRAILER_LIMIT {
                        return Err(Failure::Malformed("the trailers are too long"));
                    }
                    fill(stream, &mut buffer).await?;
                    continue;
                };
                buffer.drain(..end + 2);
                if end == 0 {
                    return Ok(body);
                }
                Chunk::Trailer(spent + end + 2)
            }
        };
    }
}

/// The size in a chunk size line: hex digits, then optionally an extension that is ignored.
fn chunk_size(line: &[u8]) -> Result<usize, Failure> {
    let digits = line.split(|byte| *byte == b';').next().unwrap_or_default();
    let digits = std::str::from_utf8(digits)
        .map_err(|_| Failure::Malformed("a chunk size"))?
        .trim_matches([' ', '\t']);
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|d| d.is_ascii_hexdigit()) {
        return Err(Failure::Malformed("a chunk size"));
    }
    usize::from_str_radix(digits, 16).map_err(|_| Failure::Malformed("a chunk size"))
}

#[cfg(test)]
mod test {
    use tokio::io::{DuplexStream, duplex};

    use super::*;

    const QUERY: Query<'static> = Query {
        host: "a.test",
        accept: "text/html",
        path: "/503.html",
    };

    /// A server that reads the request, then writes `answer` and closes when `close`.
    fn serve(answer: Vec<u8>, close: bool) -> DuplexStream {
        let (client, mut server) = duplex(64 * 1024);
        tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut chunk = [0_u8; 512];
            while find(&seen, b"\r\n\r\n").is_none() {
                match server.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => seen.extend_from_slice(&chunk[..read]),
                }
            }
            drop(server.write_all(&answer).await);
            if close {
                drop(server.shutdown().await);
            } else {
                std::future::pending::<()>().await;
            }
        });
        client
    }

    async fn get(answer: &[u8], close: bool, cap: usize) -> Result<Fetched, Failure> {
        let mut client = serve(answer.to_vec(), close);
        exchange(&mut client, &QUERY, cap).await
    }

    #[tokio::test]
    async fn sends_only_host_and_accept() {
        let (mut client, mut server) = duplex(4096);
        let seen = tokio::spawn(async move {
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 512];
            while find(&raw, b"\r\n\r\n").is_none() {
                let read = server.read(&mut chunk).await.expect("read");
                raw.extend_from_slice(&chunk[..read]);
            }
            drop(server.shutdown().await);
            String::from_utf8(raw).expect("text")
        });
        drop(exchange(&mut client, &QUERY, 1024).await);
        assert_eq!(
            seen.await.expect("task"),
            "GET /503.html HTTP/1.1\r\nHost: a.test\r\nAccept: text/html\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn reads_a_length_framed_page() {
        let page = get(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello",
            false,
            1024,
        )
        .await
        .expect("page");
        assert_eq!(page.body, b"hello");
        assert_eq!(
            page.content_type,
            Some(HeaderValue::from_static("text/html"))
        );
    }

    #[tokio::test]
    async fn reads_a_chunked_page_with_trailers() {
        let page = get(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nT: v\r\n\r\n",
            false,
            1024,
        )
        .await
        .expect("page");
        assert_eq!(page.body, b"abcde");
        assert_eq!(page.content_type, None);
    }

    #[tokio::test]
    async fn reads_a_page_framed_by_closing() {
        let page = get(b"HTTP/1.0 200 OK\r\n\r\nrest", true, 1024)
            .await
            .expect("page");
        assert_eq!(page.body, b"rest");
    }

    #[tokio::test]
    async fn a_page_over_the_cap_is_refused_in_every_framing() {
        for answer in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n123456789"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n123456789\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n123456789",
        ] {
            let result = get(answer, true, 8).await;
            assert!(matches!(result, Err(Failure::TooLarge)), "{result:?}");
        }
    }

    #[tokio::test]
    async fn an_unhappy_answer_is_no_page() {
        for (answer, ok) in [
            (
                &b"HTTP/1.1 500 Oops\r\nContent-Length: 1\r\n\r\nx"[..],
                false,
            ),
            (b"HTTP/1.1 404 No\r\nContent-Length: 1\r\n\r\nx", false),
            (
                b"HTTP/1.1 302 Moved\r\nLocation: /\r\nContent-Length: 1\r\n\r\nx",
                false,
            ),
            (b"HTTP/1.1 204 None\r\n\r\n", false),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
                false,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
                false,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx",
                false,
            ),
            (b"SMTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", false),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nx", false),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", true),
        ] {
            let result = get(answer, true, 1024).await;
            assert_eq!(
                result.is_ok(),
                ok,
                "{}: {result:?}",
                String::from_utf8_lossy(answer)
            );
        }
    }

    #[tokio::test]
    async fn a_head_that_never_ends_is_refused() {
        let result = get(&vec![b'a'; HEAD_LIMIT + 1024], false, 1024).await;
        assert!(matches!(result, Err(Failure::Malformed(_))), "{result:?}");
    }

    #[tokio::test]
    async fn the_policy_decides_before_anything_is_dialled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let policy = UpstreamPolicy::parse(r#"{"deny": ["127.0.0.0/8"]}"#).expect("policy");
        let limits = Limits {
            max_body: 1024,
            timeout: Duration::from_secs(2),
        };
        let result = Fetcher::default()
            .fetch(
                HttpPeer::new(addr, false, String::new()),
                &policy,
                "t1",
                &QUERY,
                limits,
            )
            .await;
        assert!(matches!(result, Err(Failure::Policy)), "{result:?}");
        let accepted = timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(accepted.is_err(), "the refused address was dialled");
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let policy = UpstreamPolicy::parse(r#"{"deny": ["10.9.0.0/16"]}"#).expect("policy");
        let limits = Limits {
            max_body: 1024,
            timeout: Duration::from_millis(300),
        };
        let held = tokio::spawn(async move {
            let accepted = listener.accept().await;
            std::future::pending::<()>().await;
            drop(accepted);
        });
        let result = Fetcher::default()
            .fetch(
                HttpPeer::new(addr, false, String::new()),
                &policy,
                "t1",
                &QUERY,
                limits,
            )
            .await;
        assert!(matches!(result, Err(Failure::Timeout)), "{result:?}");
        held.abort();
    }
}
