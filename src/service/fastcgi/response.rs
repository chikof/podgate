//! The application's answer: CGI output (`Status`, headers, a blank line, then the body) read
//! from `FCGI_STDOUT`. The head is parsed once, strictly: a name or value that is not valid HTTP,
//! a folded line or a head over [`MAX_HEAD_BYTES`] makes the whole answer a `502`.

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderName, HeaderValue, StatusCode};

/// Largest head (everything before the blank line) the proxy holds.
pub(super) const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Most header lines an answer may carry.
const MAX_HEADERS: usize = 256;

/// Headers that describe the application's connection or framing, not the response: podgate
/// frames its own answer. `X-Sendfile` and `X-Accel-*` ask a front server to read a file named by
/// the application; podgate never does, and never tells the client either.
const DROPPED: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

/// Why the answer is not usable.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Invalid {
    /// The head passes [`MAX_HEAD_BYTES`] or [`MAX_HEADERS`].
    TooLarge,
    /// A line is not `Name: value`, a name or value is not valid HTTP, or the status is not 200
    /// to 599.
    Syntax(&'static str),
}

/// A parsed head.
#[derive(Debug)]
pub(super) struct Head {
    /// The response status.
    pub status: StatusCode,
    /// The headers to pass on, in order.
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

/// Collects `FCGI_STDOUT` bytes until the head is complete.
#[derive(Debug, Default)]
pub(super) struct HeadParser {
    buf: BytesMut,
}

/// The offset of the blank line that ends the head and the length of the line break itself.
fn head_end(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut start = 0;
    while let Some(offset) = bytes.get(start..)?.iter().position(|byte| *byte == b'\n') {
        let newline = start + offset;
        let next = bytes.get(newline + 1)?;
        if *next == b'\n' {
            return Some((newline, 2));
        }
        if *next == b'\r' && bytes.get(newline + 2) == Some(&b'\n') {
            return Some((newline, 3));
        }
        start = newline + 1;
    }
    None
}

impl HeadParser {
    /// Adds `chunk`. `Ok(None)` while the blank line has not arrived; then the head and the body
    /// bytes that followed it in the same chunk.
    ///
    /// # Errors
    ///
    /// [`Invalid`] for a head that is too large or malformed.
    pub(super) fn push(&mut self, chunk: &[u8]) -> Result<Option<(Head, Bytes)>, Invalid> {
        self.buf.extend_from_slice(chunk);
        // A head that starts with a blank line has no headers at all.
        let (end, skip) = if self.buf.starts_with(b"\n") {
            (0, 1)
        } else if self.buf.starts_with(b"\r\n") {
            (0, 2)
        } else if let Some(found) = head_end(&self.buf) {
            found
        } else if self.buf.len() > MAX_HEAD_BYTES {
            return Err(Invalid::TooLarge);
        } else {
            return Ok(None);
        };
        if end > MAX_HEAD_BYTES {
            return Err(Invalid::TooLarge);
        }
        let head = parse(self.buf.get(..end).unwrap_or_default())?;
        self.buf.advance(end + skip);
        Ok(Some((head, std::mem::take(&mut self.buf).freeze())))
    }
}

fn parse(head: &[u8]) -> Result<Head, Invalid> {
    let mut status = None;
    let mut headers = Vec::new();
    let mut location = false;
    for raw in head.split(|byte| *byte == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(Invalid::Syntax("a folded header line"));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(Invalid::Syntax("a header line without a colon"))?;
        let (name, rest) = line.split_at(colon);
        let value = rest.get(1..).unwrap_or_default().trim_ascii();
        let name = HeaderName::from_bytes(name)
            .map_err(|_| Invalid::Syntax("a header name that is not a token"))?;
        if name == "status" {
            status = Some(parse_status(value)?);
            continue;
        }
        if DROPPED.contains(&name.as_str())
            || name.as_str().starts_with("x-accel-")
            || name == "x-sendfile"
        {
            continue;
        }
        let value = HeaderValue::from_bytes(value)
            .map_err(|_| Invalid::Syntax("a header value with a control character"))?;
        location |= name == "location";
        if headers.len() >= MAX_HEADERS {
            return Err(Invalid::TooLarge);
        }
        headers.push((name, value));
    }
    Ok(Head {
        status: status.unwrap_or(if location {
            StatusCode::FOUND
        } else {
            StatusCode::OK
        }),
        headers,
    })
}

fn parse_status(value: &[u8]) -> Result<StatusCode, Invalid> {
    let digits = value.get(..3).ok_or(Invalid::Syntax("a status"))?;
    if value.get(3).is_some_and(|byte| *byte != b' ') {
        return Err(Invalid::Syntax("a status"));
    }
    let status = StatusCode::from_bytes(digits).map_err(|_| Invalid::Syntax("a status"))?;
    if !(200..=599).contains(&status.as_u16()) {
        return Err(Invalid::Syntax("a status outside 200 to 599"));
    }
    Ok(status)
}

#[cfg(test)]
mod test {
    use super::*;

    fn parse_all(text: &[u8]) -> Result<(Head, Bytes), Invalid> {
        HeadParser::default()
            .push(text)
            .map(|parsed| parsed.expect("a complete head"))
    }

    #[test]
    fn status_headers_and_the_start_of_the_body() {
        let (head, body) =
            parse_all(b"Status: 404 Not Found\r\nContent-Type: text/plain\r\nX-A: 1\r\n\r\nbody")
                .expect("head");
        assert_eq!(head.status, StatusCode::NOT_FOUND);
        assert_eq!(head.headers.len(), 2);
        assert_eq!(&body[..], b"body");
    }

    #[test]
    fn bare_line_feeds_end_the_head_too() {
        let (head, body) = parse_all(b"X-A: 1\n\nrest").expect("head");
        assert_eq!(head.status, StatusCode::OK);
        assert_eq!(&body[..], b"rest");
    }

    #[test]
    fn a_missing_status_is_200_and_a_location_alone_is_302() {
        assert_eq!(
            parse_all(b"X-A: 1\r\n\r\n").expect("head").0.status,
            StatusCode::OK
        );
        assert_eq!(
            parse_all(b"Location: /x\r\n\r\n").expect("head").0.status,
            StatusCode::FOUND
        );
    }

    #[test]
    fn a_blank_first_line_is_an_empty_head() {
        let (head, body) = parse_all(b"\r\nbody").expect("head");
        assert!(head.headers.is_empty());
        assert_eq!(&body[..], b"body");
    }

    #[test]
    fn the_head_arrives_in_pieces() {
        let mut parser = HeadParser::default();
        assert!(parser.push(b"Status: 201 Cre").expect("partial").is_none());
        assert!(
            parser
                .push(b"ated\r\nX-A: 1\r\n")
                .expect("partial")
                .is_none()
        );
        let (head, body) = parser.push(b"\r\nbo").expect("rest").expect("complete");
        assert_eq!(head.status, StatusCode::CREATED);
        assert_eq!(&body[..], b"bo");
    }

    #[test]
    fn framing_and_file_serving_headers_are_dropped() {
        let (head, _) = parse_all(
            b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nX-Accel-Redirect: /secret\r\nX-Accel-Buffering: no\r\nX-Sendfile: /etc/passwd\r\nX-Keep: yes\r\n\r\n",
        )
        .expect("head");
        let names: Vec<&str> = head.headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["x-keep"]);
    }

    #[test]
    fn repeated_headers_are_all_kept() {
        let (head, _) = parse_all(b"Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n").expect("head");
        assert_eq!(head.headers.len(), 2);
    }

    #[test]
    fn invalid_heads_are_refused() {
        for bad in [
            &b"no colon here\r\n\r\n"[..],
            b"Bad Name: x\r\n\r\n",
            b"X-A: 1\r\n folded\r\n\r\n",
            b"X-A: a\x01b\r\n\r\n",
            b"Status: 99 x\r\n\r\n",
            b"Status: 200x\r\n\r\n",
            b"Status: 100 Continue\r\n\r\n",
            b"Status: 600 x\r\n\r\n",
            b"Status: abc\r\n\r\n",
        ] {
            assert!(
                matches!(parse_all(bad), Err(Invalid::Syntax(_))),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_head_over_the_cap_is_too_large_with_or_without_its_blank_line() {
        let mut head = b"X-A: ".to_vec();
        head.extend(vec![b'a'; MAX_HEAD_BYTES]);
        let mut parser = HeadParser::default();
        assert_eq!(parser.push(&head).map(|_| ()), Err(Invalid::TooLarge));
        head.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse_all(&head).map(|_| ()), Err(Invalid::TooLarge));
    }

    #[test]
    fn too_many_headers_are_refused() {
        let mut head = Vec::new();
        for index in 0..=MAX_HEADERS {
            head.extend_from_slice(format!("X-{index}: v\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        assert_eq!(parse_all(&head).map(|_| ()), Err(Invalid::TooLarge));
    }
}
