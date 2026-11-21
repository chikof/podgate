//! The part of RESP2 the source speaks: commands as arrays of bulk strings, and the replies a
//! read-only client meets (status, error, integer, bulk string, null, arrays of those, and the
//! arrays inside the reply of `SCAN`).
//!
//! Every read is bounded, whatever the peer sends. A bulk string longer than the limit is read and
//! thrown away as it arrives, never held, and shows up as [`Reply::Oversize`]; a line, an array
//! and the depth of nesting have their own limits.

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Longest line (status, error, integer or length header) a reply may hold.
const MAX_LINE: usize = 4096;

/// Most elements one array may announce.
const MAX_ARRAY: usize = 65_536;

/// Most elements, over all arrays, one reply may hold.
const MAX_ELEMENTS: usize = 1 << 17;

/// Arrays inside arrays: the reply of `SCAN` is an array of a cursor and an array of keys.
const MAX_DEPTH: usize = 2;

/// Space reserved up front for an array, whatever length it announces.
const PREALLOCATED: usize = 1024;

/// Why a reply could not be read.
#[derive(Debug, thiserror::Error)]
pub(super) enum RespError {
    /// The socket failed or the peer closed it.
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
    /// The peer sent something that is not RESP2 or exceeds a bound.
    #[error("malformed reply: {0}")]
    Protocol(&'static str),
}

/// One reply.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reply {
    /// `+OK`.
    Status(Box<str>),
    /// `-ERR message`.
    Error(Box<str>),
    /// `:n`.
    Int(i64),
    /// `$n` and its bytes.
    Bulk(Box<[u8]>),
    /// A bulk string longer than the reader's limit; its bytes were discarded.
    Oversize,
    /// A null bulk string or null array.
    Nil,
    /// `*n` and its elements.
    Array(Vec<Reply>),
}

/// Appends the command `args` to `out`.
pub(super) fn encode(out: &mut Vec<u8>, args: &[&[u8]]) {
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for arg in args {
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg);
        out.extend_from_slice(b"\r\n");
    }
}

/// Reads replies from one connection; holds the bytes read past the end of the last one.
///
/// A read is not cancel safe: a reply that is dropped half read is lost, so callers read from a
/// connection in one place and drop the connection when a read is abandoned.
#[derive(Debug)]
pub(super) struct Reader {
    buf: BytesMut,
    max_bulk: usize,
}

/// A reply, or the header of an array whose items follow.
enum Element {
    Reply(Reply),
    Array(usize),
}

impl Reader {
    /// A reader that keeps bulk strings of at most `max_bulk` bytes.
    pub(super) fn new(max_bulk: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            max_bulk,
        }
    }

    async fn fill<R: AsyncRead + Unpin>(&mut self, io: &mut R) -> Result<(), RespError> {
        if io.read_buf(&mut self.buf).await? == 0 {
            return Err(RespError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        Ok(())
    }

    async fn line<R: AsyncRead + Unpin>(&mut self, io: &mut R) -> Result<Vec<u8>, RespError> {
        loop {
            if let Some(end) = self.buf.windows(2).position(|pair| pair == b"\r\n") {
                let line = self.buf.split_to(end + 2);
                return Ok(line[..end].to_vec());
            }
            if self.buf.len() > MAX_LINE {
                return Err(RespError::Protocol("line too long"));
            }
            self.fill(io).await?;
        }
    }

    /// The `len` bytes of a bulk string and its terminator, or [`Reply::Oversize`] after
    /// discarding them when `len` is past the limit.
    async fn bulk<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        len: usize,
    ) -> Result<Reply, RespError> {
        if len > self.max_bulk {
            let mut left = len + 2;
            while left > 0 {
                if self.buf.is_empty() {
                    self.fill(io).await?;
                }
                let take = left.min(self.buf.len());
                drop(self.buf.split_to(take));
                left -= take;
            }
            return Ok(Reply::Oversize);
        }
        while self.buf.len() < len + 2 {
            self.fill(io).await?;
        }
        if &self.buf[len..len + 2] != b"\r\n" {
            return Err(RespError::Protocol("bulk string not terminated"));
        }
        let bytes = self.buf.split_to(len + 2);
        Ok(Reply::Bulk(bytes[..len].into()))
    }

    /// Reads one reply.
    ///
    /// # Errors
    ///
    /// [`RespError::Io`] when the socket fails or closes, [`RespError::Protocol`] for anything
    /// that is not RESP2 or exceeds a bound.
    pub(super) async fn reply<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
    ) -> Result<Reply, RespError> {
        // Arrays that are still being filled, each with the number of items it still needs.
        let mut open: Vec<(usize, Vec<Reply>)> = Vec::new();
        let mut budget = MAX_ELEMENTS;
        loop {
            budget = budget
                .checked_sub(1)
                .ok_or(RespError::Protocol("reply holds too many elements"))?;
            let mut item = match self.element(io).await? {
                Element::Reply(reply) => reply,
                Element::Array(0) => Reply::Array(Vec::new()),
                Element::Array(count) => {
                    if open.len() >= MAX_DEPTH {
                        return Err(RespError::Protocol("arrays nested too deep"));
                    }
                    open.push((count, Vec::with_capacity(count.min(PREALLOCATED))));
                    continue;
                }
            };
            loop {
                let Some((needed, items)) = open.last_mut() else {
                    return Ok(item);
                };
                items.push(item);
                *needed -= 1;
                if *needed > 0 {
                    break;
                }
                let Some((_, items)) = open.pop() else {
                    return Err(RespError::Protocol("unbalanced array"));
                };
                item = Reply::Array(items);
            }
        }
    }

    async fn element<R: AsyncRead + Unpin>(&mut self, io: &mut R) -> Result<Element, RespError> {
        let line = self.line(io).await?;
        let Some((&kind, rest)) = line.split_first() else {
            return Err(RespError::Protocol("empty line"));
        };
        let text = || String::from_utf8_lossy(rest).into_owned().into_boxed_str();
        let number = || {
            std::str::from_utf8(rest)
                .ok()
                .and_then(|digits| digits.parse::<i64>().ok())
                .ok_or(RespError::Protocol("bad number"))
        };
        match kind {
            b'+' => Ok(Element::Reply(Reply::Status(text()))),
            b'-' => Ok(Element::Reply(Reply::Error(text()))),
            b':' => Ok(Element::Reply(Reply::Int(number()?))),
            b'$' => match number()? {
                -1 => Ok(Element::Reply(Reply::Nil)),
                len => {
                    let len = usize::try_from(len)
                        .map_err(|_| RespError::Protocol("bad bulk string length"))?;
                    Ok(Element::Reply(self.bulk(io, len).await?))
                }
            },
            b'*' => match number()? {
                -1 => Ok(Element::Reply(Reply::Nil)),
                count => usize::try_from(count)
                    .ok()
                    .filter(|count| *count <= MAX_ARRAY)
                    .map(Element::Array)
                    .ok_or(RespError::Protocol("array too long")),
            },
            _ => Err(RespError::Protocol("unknown reply type")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    async fn parse(bytes: &[u8]) -> Result<Reply, RespError> {
        let mut io = bytes;
        Reader::new(8).reply(&mut io).await
    }

    #[test]
    fn commands_are_arrays_of_bulk_strings() {
        let mut out = Vec::new();
        encode(&mut out, &[b"MGET", b"a", b"bc"]);
        assert_eq!(out, b"*3\r\n$4\r\nMGET\r\n$1\r\na\r\n$2\r\nbc\r\n");
    }

    #[tokio::test]
    async fn every_reply_type_parses() {
        assert_eq!(
            parse(b"+OK\r\n").await.ok(),
            Some(Reply::Status("OK".into()))
        );
        assert_eq!(
            parse(b"-ERR no\r\n").await.ok(),
            Some(Reply::Error("ERR no".into()))
        );
        assert_eq!(parse(b":-7\r\n").await.ok(), Some(Reply::Int(-7)));
        assert_eq!(
            parse(b"$3\r\nabc\r\n").await.ok(),
            Some(Reply::Bulk(b"abc".as_slice().into()))
        );
        assert_eq!(parse(b"$-1\r\n").await.ok(), Some(Reply::Nil));
        assert_eq!(parse(b"*0\r\n").await.ok(), Some(Reply::Array(vec![])));
    }

    #[tokio::test]
    async fn the_reply_of_scan_nests_one_array() {
        let reply = parse(b"*2\r\n$1\r\n0\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n").await;
        assert_eq!(
            reply.ok(),
            Some(Reply::Array(vec![
                Reply::Bulk(b"0".as_slice().into()),
                Reply::Array(vec![
                    Reply::Bulk(b"a".as_slice().into()),
                    Reply::Bulk(b"b".as_slice().into()),
                ]),
            ]))
        );
    }

    #[tokio::test]
    async fn a_long_bulk_string_is_discarded_and_the_next_reply_still_parses() {
        let mut io = b"*2\r\n$12\r\nabcdefghijkl\r\n$1\r\nx\r\n+OK\r\n".as_slice();
        let mut reader = Reader::new(8);
        assert_eq!(
            reader.reply(&mut io).await.ok(),
            Some(Reply::Array(vec![
                Reply::Oversize,
                Reply::Bulk(b"x".as_slice().into())
            ]))
        );
        assert_eq!(
            reader.reply(&mut io).await.ok(),
            Some(Reply::Status("OK".into()))
        );
    }

    #[tokio::test]
    async fn malformed_and_oversized_replies_are_refused() {
        for bytes in [
            b"?x\r\n".as_slice(),
            b":abc\r\n",
            b"$-5\r\n",
            b"*100000\r\n",
            b"*1\r\n*1\r\n*1\r\n:1\r\n",
            b"$3\r\nabcde\r\n",
        ] {
            assert!(
                matches!(parse(bytes).await, Err(RespError::Protocol(_))),
                "{bytes:?}"
            );
        }
        let long = vec![b'+'; MAX_LINE + 10];
        assert!(matches!(parse(&long).await, Err(RespError::Protocol(_))));
        assert!(matches!(parse(b"+OK").await, Err(RespError::Io(_))));
    }
}
