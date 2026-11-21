//! The part of RESP2 the store client speaks: commands as arrays of bulk strings, and the five
//! reply types. Every read is bounded, whatever the peer sends, so a hostile or broken store
//! cannot make a request allocate without limit.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Longest line (status, error, integer or length header) a reply may hold.
const MAX_LINE: usize = 1024;

/// Longest bulk string a reply may hold. The replies this client reads are a script digest and
/// two integers.
const MAX_BULK: usize = 4096;

/// Most elements of a reply array.
const MAX_ARRAY: usize = 8;

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
    /// A null bulk string or null array.
    Nil,
    /// `*n` and its elements, none of which is an array.
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
#[derive(Debug, Default)]
pub(super) struct Reader {
    buf: Vec<u8>,
}

impl Reader {
    async fn fill<R: AsyncRead + Unpin>(&mut self, io: &mut R) -> Result<(), RespError> {
        if io.read_buf(&mut self.buf).await? == 0 {
            return Err(RespError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        Ok(())
    }

    async fn line<R: AsyncRead + Unpin>(&mut self, io: &mut R) -> Result<Vec<u8>, RespError> {
        loop {
            if let Some(end) = self.buf.windows(2).position(|pair| pair == b"\r\n") {
                let line = self.buf[..end].to_vec();
                self.buf.drain(..end + 2);
                return Ok(line);
            }
            if self.buf.len() > MAX_LINE {
                return Err(RespError::Protocol("line too long"));
            }
            self.fill(io).await?;
        }
    }

    async fn bulk<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        len: usize,
    ) -> Result<Box<[u8]>, RespError> {
        while self.buf.len() < len + 2 {
            self.fill(io).await?;
        }
        if &self.buf[len..len + 2] != b"\r\n" {
            return Err(RespError::Protocol("bulk string not terminated"));
        }
        let bytes = self.buf[..len].into();
        self.buf.drain(..len + 2);
        Ok(bytes)
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
        let count = match self.element(io).await? {
            Element::Reply(reply) => return Ok(reply),
            Element::Array(count) => count,
        };
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            match self.element(io).await? {
                Element::Reply(item) => items.push(item),
                Element::Array(_) => return Err(RespError::Protocol("nested array")),
            }
        }
        Ok(Reply::Array(items))
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
                        .ok()
                        .filter(|len| *len <= MAX_BULK)
                        .ok_or(RespError::Protocol("bulk string too long"))?;
                    Ok(Element::Reply(Reply::Bulk(self.bulk(io, len).await?)))
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

/// A reply, or the header of an array whose items follow.
enum Element {
    Reply(Reply),
    Array(usize),
}

#[cfg(test)]
mod test {
    use super::*;

    async fn parse(bytes: &[u8]) -> Result<Reply, RespError> {
        let mut io = bytes;
        Reader::default().reply(&mut io).await
    }

    #[test]
    fn commands_are_arrays_of_bulk_strings() {
        let mut out = Vec::new();
        encode(&mut out, &[b"EVALSHA", b"abc", b"1"]);
        assert_eq!(out, b"*3\r\n$7\r\nEVALSHA\r\n$3\r\nabc\r\n$1\r\n1\r\n");
    }

    #[tokio::test]
    async fn every_reply_type_parses() {
        assert_eq!(
            parse(b"+OK\r\n").await.ok(),
            Some(Reply::Status("OK".into()))
        );
        assert_eq!(
            parse(b"-NOSCRIPT no\r\n").await.ok(),
            Some(Reply::Error("NOSCRIPT no".into()))
        );
        assert_eq!(parse(b":-7\r\n").await.ok(), Some(Reply::Int(-7)));
        assert_eq!(
            parse(b"$3\r\nabc\r\n").await.ok(),
            Some(Reply::Bulk(b"abc".as_slice().into()))
        );
        assert_eq!(parse(b"$-1\r\n").await.ok(), Some(Reply::Nil));
        assert_eq!(
            parse(b"*2\r\n:1\r\n:250\r\n").await.ok(),
            Some(Reply::Array(vec![Reply::Int(1), Reply::Int(250)]))
        );
    }

    #[tokio::test]
    async fn malformed_and_oversized_replies_are_refused() {
        for bytes in [
            b"?x\r\n".as_slice(),
            b":abc\r\n",
            b"$99999\r\n",
            b"*100\r\n",
            b"*1\r\n*1\r\n:1\r\n",
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
