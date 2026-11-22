//! The one-shot HTTP/1.1 client of `forward_auth`.
//!
//! Like the error page client ([`crate::middleware::errors::fetch`]) it dials through Pingora's
//! `TransportConnector`, so an `https://` auth service is reached with the transport it names,
//! and it checks the exact IP it is about to dial against the upstream address policy.
//!
//! A server named by an IP literal is dialled as it is. A server named by a host name is resolved
//! once per call with [`Resolver::resolve_once`], every answer is checked against the policy for
//! the calling tenant, and the first permitted address is dialled. The name is the `Host` the
//! caller sends and the TLS server name; it is never resolved again within the call, so the
//! answer cannot change between the check and the dial (DNS rebinding), and a name whose every
//! answer the policy refuses is refused. Every size is a number here: the response head is read
//! up to [`HEAD_LIMIT`] bytes, the body up to the cap the caller charged to the tenant, and the
//! whole exchange (resolution included) runs under one timeout. It never follows a redirect and
//! never reuses a connection. The request is built by the caller; this file never sees the
//! client's request.
//!
//! The answer is judged strictly because a verdict is read from it: two `Content-Length`
//! headers, a transfer coding other than `chunked`, both framings at once, a content coding, a
//! folded header, a `1xx` or a status outside `200..=599` all fail the call, and a failed call is
//! a denial.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, Uri};
use pingora::connectors::TransportConnector;
use pingora::protocols::l4::socket::SocketAddr as PeerAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::middleware::errors::fetch::{Failure, Framing, HEAD_LIMIT, READ, fill, find, read_body};
use crate::service::resolve::{Resolver, is_host_name};
use crate::service::upstream_policy::UpstreamPolicy;
use crate::service::{Server, Transport, Upstream};

/// The most bytes the request head may take; a longer one is not sent.
pub(in crate::middleware) const REQUEST_LIMIT: usize = 32 * 1024;

/// What a call holds besides the body: the request, the response head and the read buffers. A
/// caller charges this plus the body cap to the tenant before it calls.
pub(in crate::middleware) const ALLOWANCE: u64 = (REQUEST_LIMIT + HEAD_LIMIT + 2 * READ) as u64;

/// The most headers an answer may carry.
const MAX_HEADERS: usize = 100;

/// What the auth service answered.
#[derive(Debug)]
pub(in crate::middleware) struct Answer {
    /// The status, `200..=599`.
    pub(in crate::middleware) status: u16,
    /// Every header of the answer.
    pub(in crate::middleware) headers: HeaderMap,
    /// The body, at most the cap.
    pub(in crate::middleware) body: Vec<u8>,
}

/// Where a call goes and who is sending it.
#[derive(Debug, Clone, Copy)]
pub(in crate::middleware) struct Route<'a> {
    /// The server: its address when the URL has an IP literal, its URL's host name otherwise
    /// (then the address only holds the port, see [`Server::host`]).
    pub(in crate::middleware) server: &'a Server,
    /// How to talk to it: trust anchors, server name, client certificate.
    pub(in crate::middleware) transport: &'a Transport,
    /// Resolves a host name.
    pub(in crate::middleware) resolver: &'a Resolver,
    /// The operator's rule for the addresses the proxy may dial.
    pub(in crate::middleware) policy: &'a UpstreamPolicy,
    /// The tenant the call is made for: the policy is theirs.
    pub(in crate::middleware) tenant: &'a str,
}

impl Route<'_> {
    /// The address to dial: the literal of the URL, or the first address of a fresh resolution
    /// of its host name that the policy permits the tenant. Every candidate is checked, so a
    /// name that answers loopback or a metadata address is refused.
    async fn address(&self) -> Result<IpAddr, Failure> {
        let candidates = match self.server.sni_name() {
            Some(name) => self.resolver.resolve_once(&name).await,
            None => vec![self.server.addr.ip()],
        };
        if candidates.is_empty() {
            return Err(Failure::Connect("the host name did not resolve".into()));
        }
        candidates
            .into_iter()
            .find(|ip| self.policy.check(self.tenant, *ip).is_ok())
            .ok_or(Failure::Policy)
    }
}

/// What a call needs of the URL it was configured with.
#[derive(Debug)]
pub(in crate::middleware) struct Parsed {
    /// The server the URL names. Its `url` is always `scheme://host:port` (the IPv6 literal in
    /// brackets), which is what [`Server::host`] reads: a host name there is resolved per call,
    /// and the address then holds only the port.
    pub(in crate::middleware) server: Server,
    /// The `Host` header of the call: the authority as written.
    pub(in crate::middleware) host: Box<str>,
    /// The request target of the call: the path and query of the URL.
    pub(in crate::middleware) target: Box<str>,
}

/// Reads `text`, the configured `what` (a field name, for the messages), as an absolute `http://`
/// or `https://` URL whose host is an IP literal or a host name.
///
/// # Errors
///
/// The reason `text` is not usable: not absolute, another scheme (`h2c://` too: the call is
/// HTTP/1.1, which an h2c server cannot answer), credentials, a host that is neither an IP
/// address nor a valid name, a port out of range, a path that is not printable ASCII, or longer
/// than `max_len`.
pub(in crate::middleware) fn parse_url(
    text: &str,
    what: &str,
    max_len: usize,
) -> Result<Parsed, String> {
    let bad = || {
        format!(
            "{what} {text:?} must be an absolute http:// or https:// URL with an IP address or host name"
        )
    };
    if text.len() > max_len {
        return Err(format!("{what} is longer than {max_len} bytes"));
    }
    let uri: Uri = text.parse().map_err(|_| bad())?;
    let tls = match uri.scheme_str() {
        Some("http") => false,
        Some("https") => true,
        Some("h2c") => {
            return Err(format!(
                "{what} is h2c://: the call is written as HTTP/1.1, which an h2c server cannot answer"
            ));
        }
        _ => return Err(bad()),
    };
    let authority = uri.authority().ok_or_else(bad)?;
    if authority.as_str().contains('@') {
        return Err(format!("{what} carries credentials; the call sends none"));
    }
    let raw = authority.host();
    let literal = raw.trim_start_matches('[').trim_end_matches(']');
    let default_port = if tls { 443 } else { 80 };
    // `Uri` reads a port out of range as no port: look at the text, so it is never dropped.
    let tail = authority.as_str().get(raw.len()..).unwrap_or_default();
    let port = match tail.strip_prefix(':') {
        None if tail.is_empty() => default_port,
        Some(digits) => digits.parse::<u16>().map_err(|_| bad())?,
        None => return Err(bad()),
    };
    let scheme = if tls { "https" } else { "http" };
    let (url, ip) = match literal.parse::<IpAddr>() {
        Ok(ip) => (format!("{scheme}://{}", SocketAddr::new(ip, port)), ip),
        Err(_) if !raw.starts_with('[') && is_host_name(literal) => {
            let name = literal.strip_suffix('.').unwrap_or(literal);
            (
                format!("{scheme}://{}:{port}", name.to_ascii_lowercase()),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            )
        }
        Err(_) => return Err(bad()),
    };
    let target = uri.path_and_query().map_or("/", |target| target.as_str());
    if !target.bytes().all(|b| b.is_ascii_graphic() && b != b'#') {
        return Err(format!("{what} path is not printable ASCII"));
    }
    Ok(Parsed {
        server: Server {
            url: url.into(),
            addr: SocketAddr::new(ip, port),
            tls,
            h2c: false,
            weight: 1,
            state: Arc::default(),
        },
        host: authority.as_str().into(),
        target: target.into(),
    })
}

/// Dials auth services. Cheap to clone; clones share the connector.
#[derive(Clone)]
pub struct Client {
    connector: Arc<TransportConnector>,
    ceiling: Duration,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("ceiling", &self.ceiling)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client whose calls never run longer than `ceiling` (the process's
    /// `REQUEST_TIMEOUT_SECS`), whatever a middleware asks for.
    #[must_use]
    pub fn new(ceiling: Duration) -> Self {
        Self {
            connector: Arc::new(TransportConnector::new(None)),
            ceiling,
        }
    }

    /// Sends `request` (a complete request head, and the body when it has one) to the server
    /// `route` names, on behalf of its tenant, and reads the answer.
    ///
    /// # Errors
    ///
    /// A [`Failure`]: the host name does not resolve or the policy refuses every address
    /// (nothing is dialled), the connection or the timeout fails, or the answer is over
    /// `max_body` or not one this client accepts.
    pub(in crate::middleware) async fn call(
        &self,
        route: &Route<'_>,
        request: &[u8],
        max_body: usize,
        wait: Duration,
    ) -> Result<Answer, Failure> {
        let wait = wait.min(self.ceiling);
        let exchange = async {
            // The exact address about to be dialled, every time; a name resolves here and
            // nowhere else.
            let ip = route.address().await?;
            let mut peer = Upstream {
                server: route.server,
                transport: route.transport,
            }
            .peer();
            peer._address = PeerAddr::Inet(SocketAddr::new(ip, route.server.addr.port()));
            peer.options.connection_timeout = Some(wait);
            peer.options.read_timeout = Some(wait);
            peer.options.write_timeout = Some(wait);
            let mut stream = Box::pin(self.connector.new_stream(&peer))
                .await
                .map_err(|err| Failure::Connect(err.to_string().into()))?;
            exchange(&mut stream, request, max_body).await
        };
        timeout(wait, exchange)
            .await
            .map_err(|_| Failure::Timeout)?
    }
}

/// Sends `request` over `stream` and reads the answer.
async fn exchange<S>(stream: &mut S, request: &[u8], max_body: usize) -> Result<Answer, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
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
    let (status, headers, framing) = parse_head(&buffer[..head_end])?;
    buffer.drain(..head_end);
    let body = read_body(stream, buffer, framing, max_body).await?;
    Ok(Answer {
        status,
        headers,
        body,
    })
}

/// Parses a complete response head into the status, the headers and how the body is framed.
fn parse_head(raw: &[u8]) -> Result<(u16, HeaderMap, Framing), Failure> {
    let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut slots);
    match response.parse(raw) {
        Ok(httparse::Status::Complete(used)) if used == raw.len() => {}
        _ => return Err(Failure::Malformed("the response head")),
    }
    let status = match response.code {
        Some(code) if (200..=599).contains(&code) => code,
        _ => return Err(Failure::Malformed("the status is not 200 to 599")),
    };
    let mut headers = HeaderMap::with_capacity(response.headers.len());
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for header in response.headers.iter() {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| Failure::Malformed("a header name"))?;
        let value = HeaderValue::from_bytes(header.value)
            .map_err(|_| Failure::Malformed("a header value"))?;
        match name.as_str() {
            "content-length" => {
                if length.is_some() {
                    return Err(Failure::Malformed("two content-length headers"));
                }
                if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
                    return Err(Failure::Malformed("the content-length"));
                }
                let digits = std::str::from_utf8(value.as_bytes())
                    .map_err(|_| Failure::Malformed("the content-length"))?;
                length = Some(digits.parse().map_err(|_| Failure::TooLarge)?);
            }
            "transfer-encoding" => {
                if chunked || !value.as_bytes().eq_ignore_ascii_case(b"chunked") {
                    return Err(Failure::Malformed("a transfer coding other than chunked"));
                }
                chunked = true;
            }
            "content-encoding" if !value.as_bytes().eq_ignore_ascii_case(b"identity") => {
                return Err(Failure::Malformed("an encoded body"));
            }
            _ => {}
        }
        headers.append(name, value);
    }
    let framing = match (status, chunked, length) {
        (204 | 304, _, _) => Framing::Length(0),
        (_, true, Some(_)) => {
            return Err(Failure::Malformed(
                "both content-length and transfer-encoding",
            ));
        }
        (_, true, None) => Framing::Chunked,
        (_, false, Some(length)) => Framing::Length(length),
        (_, false, None) => Framing::Close,
    };
    Ok((status, headers, framing))
}

#[cfg(test)]
mod test {
    use tokio::io::{AsyncReadExt, duplex};

    use super::*;

    fn head(text: &str) -> Result<(u16, HeaderMap, Framing), Failure> {
        parse_head(text.as_bytes())
    }

    /// Runs `exchange` against a server that answers `answer` once it has read a request head.
    async fn get(answer: impl Into<Vec<u8>>, cap: usize) -> Result<Answer, Failure> {
        let answer = answer.into();
        let (mut client, mut server) = duplex(64 * 1024);
        tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut chunk = [0_u8; 256];
            while find(&seen, b"\r\n\r\n").is_none() {
                match server.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => seen.extend_from_slice(&chunk[..read]),
                }
            }
            drop(server.write_all(&answer).await);
            drop(server.shutdown().await);
        });
        exchange(&mut client, b"GET / HTTP/1.1\r\n\r\n", cap).await
    }

    #[test]
    fn a_plain_answer_is_framed_by_its_length() {
        let (status, headers, framing) =
            head("HTTP/1.1 200 OK\r\nX-User: ann\r\nContent-Length: 3\r\n\r\n").expect("parsed");
        assert_eq!(status, 200);
        assert_eq!(headers["x-user"], "ann");
        assert_eq!(framing, Framing::Length(3));
    }

    #[test]
    fn an_ambiguous_or_odd_answer_is_refused() {
        for bad in [
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n folded\r\n\r\n",
            "HTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 099 X\r\n\r\n",
            "HTTP/1.1 600 X\r\n\r\n",
            "HTTP/2 200 OK\r\n\r\n",
            "200 OK\r\n\r\n",
        ] {
            assert!(head(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_answer_with_no_body_status_has_no_body() {
        for status in ["204 No Content", "304 Not Modified"] {
            let (_, _, framing) =
                head(&format!("HTTP/1.1 {status}\r\nContent-Length: 9\r\n\r\n")).expect("parsed");
            assert_eq!(framing, Framing::Length(0), "{status}");
        }
    }

    #[tokio::test]
    async fn the_body_is_capped() {
        let answer = get(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 5)
            .await
            .expect("fits");
        assert_eq!(answer.body, b"hello");
        let over = get(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello!", 5).await;
        assert!(matches!(over, Err(Failure::TooLarge)), "{over:?}");
        let streamed = get(b"HTTP/1.1 200 OK\r\n\r\nhello world", 5).await;
        assert!(matches!(streamed, Err(Failure::TooLarge)), "{streamed:?}");
        let chunked = get(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello!\r\n0\r\n\r\n",
            5,
        )
        .await;
        assert!(matches!(chunked, Err(Failure::TooLarge)), "{chunked:?}");
    }

    #[tokio::test]
    async fn a_short_or_endless_head_is_refused() {
        let early = get(b"HTTP/1.1 200 OK\r\nX: y", 5).await;
        assert!(matches!(early, Err(Failure::Malformed(_))), "{early:?}");
        let long = get(
            format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(HEAD_LIMIT)),
            5,
        )
        .await;
        assert!(matches!(long, Err(Failure::Malformed(_))), "{long:?}");
    }
}
