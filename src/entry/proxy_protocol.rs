//! PROXY protocol v1 and v2 (HAProxy's, <https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt>):
//! the codec an entry point (`;proxy_protocol`) decodes with and a TCP upstream
//! is written with. The decoder and the encoder agree byte for byte, so what one
//! writes the other reads back.
//!
//! - [`parse`] is the whole decoder and does no I/O: it turns the bytes seen so far into a
//!   [`Header`] or says how many bytes the header needs at least ([`Parse::More`]). It rejects
//!   as early as the bytes allow, so a TLS ClientHello or an HTTP request line is refused at its
//!   first byte.
//! - [`read_header`] drives [`parse`] over a stream. It reads exactly the header, never a byte
//!   more (the TLS or HTTP bytes behind it stay in the stream), within one deadline.
//! - [`Header::encode`] writes a header in either [`Version`].
//!
//! Strict by construction, because the address in a header decides who the client is. v1 is
//! `PROXY TCP4|TCP6 <src> <dst> <sport> <dport>` or `PROXY UNKNOWN`, ended by CRLF within
//! [`V1_MAX`] bytes; v2 is the 12-byte signature, a version and command, a family and transport,
//! a length, the addresses and then TLVs, within [`V2_MAX`] bytes. Anything else is an error,
//! including a datagram transport, a mixed-family pair, a number with a sign or a leading zero,
//! and TLVs that do not tile the payload exactly. TLVs are walked for their bounds and
//! dropped, except the authority TLV (`PP2_TYPE_AUTHORITY`, the server name the client asked
//! for), which [`Header::authority`] keeps.
//!
//! `UNKNOWN` (v1), `LOCAL` (v2, a health check of the balancer itself), a `PROXY` command with
//! an unspecified or unix family all decode to [`Header::Local`]: the receiver keeps the address
//! of the connection's peer.

use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

/// Longest v1 header, CRLF included (the specification's own limit: `TCP6` with the longest
/// addresses and ports is 104).
pub const V1_MAX: usize = 107;
/// Longest v2 header, the 16 fixed bytes and the TLVs included.
pub const V2_MAX: usize = 2048;
/// How long a peer has to send the whole header before the connection is closed.
pub const READ_TIMEOUT: Duration = Duration::from_secs(3);
/// Longest authority TLV podgate keeps: a DNS name is at most 253 bytes.
pub const AUTHORITY_MAX: usize = 255;

const V1_SIGNATURE: &[u8; 6] = b"PROXY ";
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
/// Signature, version and command, family and transport, and the two length bytes.
const V2_PREFIX: usize = 16;
const V2_INET_BLOCK: usize = 12;
const V2_INET6_BLOCK: usize = 36;
const V2_UNIX_BLOCK: usize = 216;
const PP2_TYPE_AUTHORITY: u8 = 0x02;

/// Which of the two wire formats to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// The text line: `PROXY TCP4 1.2.3.4 5.6.7.8 1000 443`. Cannot carry an authority.
    V1,
    /// The binary header with TLVs.
    V2,
}

/// The two addresses of one proxied connection, of one family: the family is the type, so a
/// header with an IPv4 source and an IPv6 destination cannot be built.
#[allow(
    variant_size_differences,
    reason = "the variants are the two address families; the pair is Copy and short-lived, and boxing an address buys nothing"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addresses {
    /// `TCP4` or `AF_INET`.
    V4 {
        /// The client.
        source: SocketAddrV4,
        /// The address the client connected to.
        destination: SocketAddrV4,
    },
    /// `TCP6` or `AF_INET6`.
    V6 {
        /// The client.
        source: SocketAddrV6,
        /// The address the client connected to.
        destination: SocketAddrV6,
    },
}

impl Addresses {
    /// The pair `source` and `destination`; `None` when they are of different families.
    #[must_use]
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Option<Self> {
        match (source, destination) {
            (SocketAddr::V4(source), SocketAddr::V4(destination)) => Some(Self::V4 {
                source,
                destination,
            }),
            (SocketAddr::V6(source), SocketAddr::V6(destination)) => Some(Self::V6 {
                source,
                destination,
            }),
            _ => None,
        }
    }

    /// The client's address.
    #[must_use]
    pub fn source(&self) -> SocketAddr {
        match *self {
            Self::V4 { source, .. } => SocketAddr::V4(source),
            Self::V6 { source, .. } => SocketAddr::V6(source),
        }
    }

    /// The address the client connected to.
    #[must_use]
    pub fn destination(&self) -> SocketAddr {
        match *self {
            Self::V4 { destination, .. } => SocketAddr::V4(destination),
            Self::V6 { destination, .. } => SocketAddr::V6(destination),
        }
    }
}

/// What a PROXY protocol header says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// No address: the peer of the connection is the client (a v2 `LOCAL` health check, `UNKNOWN`).
    Local,
    /// A proxied connection.
    Proxied {
        /// The client and the address it connected to.
        addresses: Addresses,
        /// The server name the client asked for (v2 `PP2_TYPE_AUTHORITY`).
        authority: Option<Box<str>>,
    },
}

impl Header {
    /// The client's address, when the header names one.
    #[must_use]
    pub fn source(&self) -> Option<SocketAddr> {
        match self {
            Self::Local => None,
            Self::Proxied { addresses, .. } => Some(addresses.source()),
        }
    }

    /// The address the client connected to, when the header names one.
    #[must_use]
    pub fn destination(&self) -> Option<SocketAddr> {
        match self {
            Self::Local => None,
            Self::Proxied { addresses, .. } => Some(addresses.destination()),
        }
    }

    /// The server name the client asked for, when a v2 header carried one.
    #[must_use]
    pub fn authority(&self) -> Option<&str> {
        match self {
            Self::Local => None,
            Self::Proxied { authority, .. } => authority.as_deref(),
        }
    }

    /// Appends the header in `version` to `out`. [`Self::Local`] is `PROXY UNKNOWN` in v1 and a
    /// `LOCAL` command in v2; the authority is written only by v2.
    ///
    /// # Errors
    ///
    /// [`EncodeError::Authority`] for a v2 authority that is empty or longer than
    /// [`AUTHORITY_MAX`]. `out` is not touched then.
    pub fn encode(&self, version: Version, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match version {
            Version::V1 => {
                self.encode_v1(out);
                Ok(())
            }
            Version::V2 => self.encode_v2(out),
        }
    }

    fn encode_v1(&self, out: &mut Vec<u8>) {
        let result = match self {
            Self::Local => out.write_all(b"PROXY UNKNOWN\r\n"),
            Self::Proxied { addresses, .. } => match addresses {
                Addresses::V4 {
                    source,
                    destination,
                } => write!(
                    out,
                    "PROXY TCP4 {} {} {} {}\r\n",
                    source.ip(),
                    destination.ip(),
                    source.port(),
                    destination.port()
                ),
                Addresses::V6 {
                    source,
                    destination,
                } => write!(
                    out,
                    "PROXY TCP6 {} {} {} {}\r\n",
                    source.ip(),
                    destination.ip(),
                    source.port(),
                    destination.port()
                ),
            },
        };
        // A `Vec<u8>` writer has no failure mode.
        debug_assert!(result.is_ok());
    }

    fn encode_v2(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let Self::Proxied {
            addresses,
            authority,
        } = self
        else {
            out.extend_from_slice(V2_SIGNATURE);
            out.extend_from_slice(&[0x20, 0x00, 0, 0]);
            return Ok(());
        };
        // `AUTHORITY_MAX` is `u8::MAX`, so the length of a kept authority is a `u8`.
        let authority = match authority.as_deref() {
            None => None,
            Some(name) => match u8::try_from(name.len()) {
                Ok(len) if len > 0 => Some((name, len)),
                _ => return Err(EncodeError::Authority),
            },
        };
        let block: u16 = match addresses {
            Addresses::V4 { .. } => 12,
            Addresses::V6 { .. } => 36,
        };
        let length = block + authority.map_or(0, |(_, len)| 3 + u16::from(len));
        out.reserve(V2_PREFIX + usize::from(length));
        out.extend_from_slice(V2_SIGNATURE);
        out.push(0x21);
        match addresses {
            Addresses::V4 {
                source,
                destination,
            } => {
                out.push(0x11);
                out.extend_from_slice(&length.to_be_bytes());
                out.extend_from_slice(&source.ip().octets());
                out.extend_from_slice(&destination.ip().octets());
                out.extend_from_slice(&source.port().to_be_bytes());
                out.extend_from_slice(&destination.port().to_be_bytes());
            }
            Addresses::V6 {
                source,
                destination,
            } => {
                out.push(0x21);
                out.extend_from_slice(&length.to_be_bytes());
                out.extend_from_slice(&source.ip().octets());
                out.extend_from_slice(&destination.ip().octets());
                out.extend_from_slice(&source.port().to_be_bytes());
                out.extend_from_slice(&destination.port().to_be_bytes());
            }
        }
        if let Some((name, len)) = authority {
            out.push(PP2_TYPE_AUTHORITY);
            out.extend_from_slice(&u16::from(len).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        Ok(())
    }
}

/// A header [`Header::encode`] cannot write.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodeError {
    /// The v2 authority TLV is empty or longer than [`AUTHORITY_MAX`] bytes.
    #[error("the authority must be 1 to {AUTHORITY_MAX} bytes")]
    Authority,
}

/// The result of [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parse {
    /// A whole header, and how many bytes of the input it used.
    Header(Header, usize),
    /// The header is not complete: it needs at least this many bytes in total, never more than
    /// [`V2_MAX`].
    More(usize),
}

/// Why bytes are not an acceptable PROXY protocol header.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The first bytes are neither signature.
    #[error("not a PROXY protocol header")]
    NotProxy,
    /// The header exceeds the limit of its version.
    #[error("the PROXY protocol header is longer than {limit} bytes")]
    TooLong {
        /// [`V1_MAX`] or [`V2_MAX`].
        limit: usize,
    },
    /// The header has the signature but is invalid; the reason says where.
    #[error("malformed PROXY protocol header: {0}")]
    Malformed(&'static str),
}

/// Decodes the header at the start of `bytes`.
///
/// # Errors
///
/// [`DecodeError`] as soon as `bytes` cannot be the start of an acceptable header.
pub fn parse(bytes: &[u8]) -> Result<Parse, DecodeError> {
    match bytes.first() {
        None => Ok(Parse::More(1)),
        Some(b'P') => parse_v1(bytes),
        Some(b'\r') => parse_v2(bytes),
        Some(_) => Err(DecodeError::NotProxy),
    }
}

fn parse_v1(bytes: &[u8]) -> Result<Parse, DecodeError> {
    let seen = bytes.len().min(V1_SIGNATURE.len());
    if bytes[..seen] != V1_SIGNATURE[..seen] {
        return Err(DecodeError::NotProxy);
    }
    let Some(lf) = bytes.iter().position(|byte| *byte == b'\n') else {
        return if bytes.len() >= V1_MAX {
            Err(DecodeError::TooLong { limit: V1_MAX })
        } else {
            Ok(Parse::More(bytes.len() + 1))
        };
    };
    if lf + 1 > V1_MAX {
        return Err(DecodeError::TooLong { limit: V1_MAX });
    }
    // The signature has no LF, so `lf` is past it; the CR sits at `lf - 1`.
    if bytes[lf - 1] != b'\r' {
        return Err(DecodeError::Malformed("the line does not end in CRLF"));
    }
    let line = std::str::from_utf8(&bytes[V1_SIGNATURE.len()..lf - 1])
        .map_err(|_| DecodeError::Malformed("the line is not ASCII"))?;
    let mut fields = line.split(' ');
    let header = match fields.next() {
        Some("UNKNOWN") => Header::Local,
        Some("TCP4") => {
            let (source, destination) = v1_pair::<Ipv4Addr>(&mut fields)?;
            Header::Proxied {
                addresses: Addresses::V4 {
                    source: SocketAddrV4::new(source.0, source.1),
                    destination: SocketAddrV4::new(destination.0, destination.1),
                },
                authority: None,
            }
        }
        Some("TCP6") => {
            let (source, destination) = v1_pair::<Ipv6Addr>(&mut fields)?;
            Header::Proxied {
                addresses: Addresses::V6 {
                    source: SocketAddrV6::new(source.0, source.1, 0, 0),
                    destination: SocketAddrV6::new(destination.0, destination.1, 0, 0),
                },
                authority: None,
            }
        }
        _ => return Err(DecodeError::Malformed("unknown protocol or family")),
    };
    Ok(Parse::Header(header, lf + 1))
}

/// An address and its port, as one side of a v1 line.
type Endpoint<Ip> = (Ip, u16);

/// `<src> <dst> <sport> <dport>` and nothing after it.
fn v1_pair<'a, Ip: FromStr>(
    fields: &mut impl Iterator<Item = &'a str>,
) -> Result<(Endpoint<Ip>, Endpoint<Ip>), DecodeError> {
    let bad_address = DecodeError::Malformed("not an address of the stated family");
    let mut next = || fields.next().ok_or(DecodeError::Malformed("missing field"));
    let source = next()?.parse().map_err(|_| bad_address)?;
    let destination = next()?.parse().map_err(|_| bad_address)?;
    let source_port = v1_port(next()?)?;
    let destination_port = v1_port(next()?)?;
    if next().is_ok() {
        return Err(DecodeError::Malformed("trailing field"));
    }
    Ok(((source, source_port), (destination, destination_port)))
}

/// Decimal digits only, no sign and no leading zero: what `u16::from_str` alone would let through
/// is wider than the specification.
fn v1_port(text: &str) -> Result<u16, DecodeError> {
    let bad = DecodeError::Malformed("not a port number");
    if text.is_empty()
        || text.len() > 5
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(bad);
    }
    text.parse().map_err(|_| bad)
}

fn parse_v2(bytes: &[u8]) -> Result<Parse, DecodeError> {
    let seen = bytes.len().min(V2_SIGNATURE.len());
    if bytes[..seen] != V2_SIGNATURE[..seen] {
        return Err(DecodeError::NotProxy);
    }
    let Some(&[version_command, family_transport, high, low]) = bytes
        .get(V2_SIGNATURE.len()..V2_PREFIX)
        .and_then(|fixed| <&[u8; 4]>::try_from(fixed).ok())
    else {
        return Ok(Parse::More(V2_PREFIX));
    };
    if version_command >> 4 != 2 {
        return Err(DecodeError::Malformed("not version 2"));
    }
    let total = V2_PREFIX + usize::from(u16::from_be_bytes([high, low]));
    if total > V2_MAX {
        return Err(DecodeError::TooLong { limit: V2_MAX });
    }
    let Some(payload) = bytes.get(V2_PREFIX..total) else {
        return Ok(Parse::More(total));
    };
    let header = match version_command & 0x0f {
        0x0 => Header::Local,
        0x1 => v2_proxy(family_transport, payload)?,
        _ => return Err(DecodeError::Malformed("unknown command")),
    };
    Ok(Parse::Header(header, total))
}

fn v2_proxy(family_transport: u8, payload: &[u8]) -> Result<Header, DecodeError> {
    let short = DecodeError::Malformed("the address block is shorter than its family needs");
    match family_transport {
        0x00 => Ok(Header::Local),
        0x11 => {
            let (block, tlvs) = payload.split_at_checked(V2_INET_BLOCK).ok_or(short)?;
            let ip =
                |at: usize| Ipv4Addr::new(block[at], block[at + 1], block[at + 2], block[at + 3]);
            let port = |at: usize| u16::from_be_bytes([block[at], block[at + 1]]);
            Ok(Header::Proxied {
                addresses: Addresses::V4 {
                    source: SocketAddrV4::new(ip(0), port(8)),
                    destination: SocketAddrV4::new(ip(4), port(10)),
                },
                authority: authority(tlvs)?,
            })
        }
        0x21 => {
            let (block, tlvs) = payload.split_at_checked(V2_INET6_BLOCK).ok_or(short)?;
            let ip = |at: usize| {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&block[at..at + 16]);
                Ipv6Addr::from(octets)
            };
            let port = |at: usize| u16::from_be_bytes([block[at], block[at + 1]]);
            Ok(Header::Proxied {
                addresses: Addresses::V6 {
                    source: SocketAddrV6::new(ip(0), port(32), 0, 0),
                    destination: SocketAddrV6::new(ip(16), port(34), 0, 0),
                },
                authority: authority(tlvs)?,
            })
        }
        // A unix socket has no IP address to believe, so the peer stays the client.
        0x31 if payload.len() >= V2_UNIX_BLOCK => Ok(Header::Local),
        0x31 => Err(short),
        _ => Err(DecodeError::Malformed(
            "unsupported address family or transport",
        )),
    }
}

/// Walks the TLVs to their bounds and returns the authority. A TLV that runs past the payload,
/// a second authority, one that is not UTF-8 or is over [`AUTHORITY_MAX`] bytes is an error; an
/// empty authority is none.
fn authority(mut tlvs: &[u8]) -> Result<Option<Box<str>>, DecodeError> {
    let mut found = None;
    while !tlvs.is_empty() {
        let [kind, high, low, rest @ ..] = tlvs else {
            return Err(DecodeError::Malformed("truncated TLV"));
        };
        let (value, after) = rest
            .split_at_checked(usize::from(u16::from_be_bytes([*high, *low])))
            .ok_or(DecodeError::Malformed("truncated TLV"))?;
        tlvs = after;
        if *kind != PP2_TYPE_AUTHORITY {
            continue;
        }
        if found.is_some() {
            return Err(DecodeError::Malformed("two authority TLVs"));
        }
        if value.len() > AUTHORITY_MAX {
            return Err(DecodeError::Malformed("authority TLV too long"));
        }
        let name = std::str::from_utf8(value)
            .map_err(|_| DecodeError::Malformed("authority TLV is not UTF-8"))?;
        found = Some(name);
    }
    Ok(found.filter(|name| !name.is_empty()).map(Box::from))
}

/// Why [`read_header`] returned no header.
#[derive(Debug, Error)]
pub enum ReadError {
    /// The bytes are not an acceptable header.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// The peer closed the connection before the header was complete.
    #[error("the connection ended inside the PROXY protocol header")]
    Truncated,
    /// The peer did not send the whole header in time.
    #[error("no complete PROXY protocol header within the deadline")]
    Deadline,
    /// Reading failed.
    #[error("reading the PROXY protocol header failed")]
    Io(#[source] io::Error),
}

/// Reads one header from `reader` within `limit` ([`READ_TIMEOUT`] in the listener). It consumes
/// exactly the header: whatever the peer sent after it stays unread.
///
/// # Errors
///
/// [`ReadError`]: the bytes are not a header, the stream ended or failed inside it, or `limit`
/// ran out.
pub async fn read_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: Duration,
) -> Result<Header, ReadError> {
    timeout(limit, read_exact_header(reader))
        .await
        .map_err(|_| ReadError::Deadline)?
}

async fn read_exact_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Header, ReadError> {
    let mut buffer = [0_u8; V2_MAX];
    let mut have = 0;
    loop {
        let want = match parse(&buffer[..have])? {
            Parse::Header(header, used) if used == have => return Ok(header),
            Parse::Header(..) => {
                return Err(DecodeError::Malformed("bytes after the header").into());
            }
            Parse::More(want) => want,
        };
        reader
            .read_exact(&mut buffer[have..want])
            .await
            .map_err(|err| match err.kind() {
                io::ErrorKind::UnexpectedEof => ReadError::Truncated,
                _ => ReadError::Io(err),
            })?;
        have = want;
    }
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("socket address")
    }

    fn proxied(source: &str, destination: &str, authority: Option<&str>) -> Header {
        Header::Proxied {
            addresses: Addresses::new(addr(source), addr(destination)).expect("one family"),
            authority: authority.map(Box::from),
        }
    }

    fn decoded(bytes: &[u8]) -> Header {
        match parse(bytes).expect("parses") {
            Parse::Header(header, used) => {
                assert_eq!(used, bytes.len(), "the header is the whole input");
                header
            }
            Parse::More(more) => panic!("incomplete, wants {more}"),
        }
    }

    fn encoded(header: &Header, version: Version) -> Vec<u8> {
        let mut out = Vec::new();
        header.encode(version, &mut out).expect("encodes");
        out
    }

    /// A v2 header with `command`, `family_transport` and `payload`.
    fn v2(command: u8, family_transport: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = V2_SIGNATURE.to_vec();
        out.push(command);
        out.push(family_transport);
        out.extend_from_slice(&u16::try_from(payload.len()).expect("fits").to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn inet_block(tlvs: &[u8]) -> Vec<u8> {
        let mut block = vec![192, 0, 2, 1, 198, 51, 100, 7, 0x1f, 0x90, 0x01, 0xbb];
        block.extend_from_slice(tlvs);
        block
    }

    #[test]
    fn pp_v1_variants() {
        assert_eq!(
            decoded(b"PROXY TCP4 192.0.2.1 198.51.100.7 8080 443\r\n"),
            proxied("192.0.2.1:8080", "198.51.100.7:443", None)
        );
        assert_eq!(
            decoded(b"PROXY TCP6 2001:db8::1 2001:db8::2 65535 0\r\n"),
            proxied("[2001:db8::1]:65535", "[2001:db8::2]:0", None)
        );
        assert_eq!(
            decoded(b"PROXY TCP6 ::ffff:192.0.2.1 ::1 1 2\r\n").source(),
            Some(addr("[::ffff:192.0.2.1]:1"))
        );
        assert_eq!(decoded(b"PROXY UNKNOWN\r\n"), Header::Local);
        assert_eq!(
            decoded(b"PROXY UNKNOWN ffff::1 ::1 65535 65535\r\n"),
            Header::Local,
            "everything after UNKNOWN is ignored"
        );
        let widest = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        assert_eq!(widest.len(), 104);
        assert!(matches!(parse(widest.as_bytes()), Ok(Parse::Header(..))));
    }

    #[test]
    fn pp_v1_rejects_what_the_specification_does_not_allow() {
        for bad in [
            &b"PROXY TCP4 192.0.2.1 198.51.100.7 8080 443\n"[..],
            b"PROXY TCP4 192.0.2.1 198.51.100.7 8080 443\r\r\n",
            b"PROXY TCP4  192.0.2.1 198.51.100.7 8080 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.7 8080 443 \r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.7 8080\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.7 8080 443 9\r\n",
            b"PROXY TCP4 192.0.2.001 198.51.100.7 8080 443\r\n",
            b"PROXY TCP4 192.0.2.256 198.51.100.7 8080 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.7 +80 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.7 080 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.7 65536 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.7 8080 \r\n",
            b"PROXY TCP4 2001:db8::1 198.51.100.7 8080 443\r\n",
            b"PROXY TCP6 192.0.2.1 2001:db8::1 8080 443\r\n",
            b"PROXY TCP6 2001:db8::1 192.0.2.1 8080 443\r\n",
            b"PROXY UDP4 192.0.2.1 198.51.100.7 8080 443\r\n",
            b"PROXY unknown\r\n",
            b"PROXY \r\n",
            b"PROXY UNKNOWN\xff\r\n",
            b"PROXY\r\n",
            b"PROXY UNKNOWN\r",
        ] {
            assert!(
                !matches!(parse(bad), Ok(Parse::Header(..))),
                "{:?} must not decode",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn pp_v2_variants() {
        let mut v6 = Vec::new();
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().expect("ip").octets());
        v6.extend_from_slice(&[0xff, 0xff, 0x01, 0xbb]);
        assert_eq!(
            decoded(&v2(0x21, 0x11, &inet_block(&[]))),
            proxied("192.0.2.1:8080", "198.51.100.7:443", None)
        );
        assert_eq!(
            decoded(&v2(0x21, 0x21, &v6)),
            proxied("[::1]:65535", "[2001:db8::7]:443", None)
        );
        assert_eq!(decoded(&v2(0x20, 0x00, &[])), Header::Local);
        assert_eq!(
            decoded(&v2(0x20, 0x11, &inet_block(&[]))),
            Header::Local,
            "LOCAL keeps the peer: its addresses are not read"
        );
        assert_eq!(decoded(&v2(0x21, 0x00, &[])), Header::Local, "UNSPEC");
        assert_eq!(decoded(&v2(0x21, 0x31, &[0; V2_UNIX_BLOCK])), Header::Local);
        // Other TLVs (NOOP, SSL, an unknown vendor type) are walked and dropped; the authority stays.
        let tlvs = [
            &[0x04, 0, 2, 0, 0][..],
            &[0x20, 0, 1, 7],
            &[0xee, 0, 0],
            &[0x02, 0, 6, b'a', b'.', b't', b'e', b's', b't'],
        ]
        .concat();
        let header = decoded(&v2(0x21, 0x11, &inet_block(&tlvs)));
        assert_eq!(header.authority(), Some("a.test"));
        assert_eq!(header.source(), Some(addr("192.0.2.1:8080")));
        assert_eq!(header.destination(), Some(addr("198.51.100.7:443")));
    }

    #[test]
    fn pp_v2_rejects_what_it_cannot_trust() {
        let long_name = [&[0x02, 0x01, 0x00][..], &[b'a'; 256]].concat();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("version 1", v2(0x11, 0x11, &inet_block(&[]))),
            ("version 3", v2(0x31, 0x11, &inet_block(&[]))),
            ("command 2", v2(0x22, 0x11, &inet_block(&[]))),
            ("datagram over inet", v2(0x21, 0x12, &inet_block(&[]))),
            (
                "inet with an unspecified transport",
                v2(0x21, 0x10, &inet_block(&[])),
            ),
            ("unspecified family with a transport", v2(0x21, 0x01, &[])),
            ("unix datagram", v2(0x21, 0x32, &[0; V2_UNIX_BLOCK])),
            ("a short unix block", v2(0x21, 0x31, &[0; 10])),
            ("an inet block that is too short", v2(0x21, 0x11, &[0; 11])),
            ("an inet6 block that is too short", v2(0x21, 0x21, &[0; 35])),
            (
                "a TLV that runs off the payload",
                v2(0x21, 0x11, &inet_block(&[0x04, 0, 9, 1])),
            ),
            (
                "a TLV header cut short",
                v2(0x21, 0x11, &inet_block(&[0x04, 0])),
            ),
            (
                "two authorities",
                v2(
                    0x21,
                    0x11,
                    &inet_block(&[0x02, 0, 1, b'a', 0x02, 0, 1, b'b']),
                ),
            ),
            (
                "an authority that is not UTF-8",
                v2(0x21, 0x11, &inet_block(&[0x02, 0, 1, 0xff])),
            ),
            (
                "a 256-byte authority",
                v2(0x21, 0x11, &inet_block(&long_name)),
            ),
        ];
        for (name, bytes) in cases {
            assert!(
                matches!(parse(&bytes), Err(DecodeError::Malformed(_))),
                "{name} must be refused, got {:?}",
                parse(&bytes)
            );
        }
        assert_eq!(
            decoded(&v2(0x21, 0x11, &inet_block(&[0x02, 0, 0]))).authority(),
            None,
            "an empty authority is none"
        );
    }

    #[test]
    fn pp_limits_and_garbage_are_errors_early() {
        assert_eq!(
            parse(&[0x16, 3, 1]),
            Err(DecodeError::NotProxy),
            "a ClientHello"
        );
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Err(DecodeError::NotProxy));
        assert_eq!(parse(b"PRO"), Ok(Parse::More(4)));
        assert_eq!(parse(b"PROX\r"), Err(DecodeError::NotProxy));
        assert_eq!(parse(b"\r\n\r\nX"), Err(DecodeError::NotProxy));
        // v1: 107 bytes without a line end is over the limit, 106 is still waiting.
        let mut line = b"PROXY UNKNOWN ".to_vec();
        line.resize(V1_MAX - 1, b'x');
        assert_eq!(parse(&line), Ok(Parse::More(V1_MAX)));
        line.push(b'x');
        assert_eq!(parse(&line), Err(DecodeError::TooLong { limit: V1_MAX }));
        // a line that ends at byte 108
        let mut long = b"PROXY UNKNOWN ".to_vec();
        long.resize(V1_MAX - 1, b'x');
        long.extend_from_slice(b"\r\n");
        assert_eq!(parse(&long), Err(DecodeError::TooLong { limit: V1_MAX }));
        // a line that ends at byte 107 is fine
        let mut exact = b"PROXY UNKNOWN ".to_vec();
        exact.resize(V1_MAX - 2, b'x');
        exact.extend_from_slice(b"\r\n");
        assert_eq!(decoded(&exact), Header::Local);
        // v2: 2048 is fine, 2049 is not, and the fixed bytes wait for the length.
        let mut at_limit = v2(0x20, 0x00, &[0; V2_MAX - V2_PREFIX]);
        assert_eq!(decoded(&at_limit), Header::Local);
        at_limit.truncate(V2_PREFIX);
        at_limit[14..16].copy_from_slice(
            &u16::try_from(V2_MAX - V2_PREFIX + 1)
                .expect("fits")
                .to_be_bytes(),
        );
        assert_eq!(
            parse(&at_limit),
            Err(DecodeError::TooLong { limit: V2_MAX })
        );
        assert_eq!(parse(&V2_SIGNATURE[..12]), Ok(Parse::More(V2_PREFIX)));
    }

    #[test]
    fn pp_every_truncation_waits_or_fails_never_decodes() {
        let authority = Some("a.test");
        let headers = [
            encoded(
                &proxied("192.0.2.1:1000", "198.51.100.7:443", authority),
                Version::V1,
            ),
            encoded(
                &proxied("[2001:db8::1]:1000", "[2001:db8::2]:443", None),
                Version::V1,
            ),
            encoded(&Header::Local, Version::V1),
            encoded(
                &proxied("192.0.2.1:1000", "198.51.100.7:443", authority),
                Version::V2,
            ),
            encoded(
                &proxied("[2001:db8::1]:1000", "[2001:db8::2]:443", authority),
                Version::V2,
            ),
            encoded(&Header::Local, Version::V2),
        ];
        for bytes in headers {
            for cut in 0..bytes.len() {
                match parse(&bytes[..cut]) {
                    Ok(Parse::More(want)) => {
                        assert!(want > cut && want <= V2_MAX, "{cut} of {}", bytes.len());
                    }
                    other => panic!("{cut} of {} bytes decoded as {other:?}", bytes.len()),
                }
            }
            assert!(matches!(parse(&bytes), Ok(Parse::Header(_, used)) if used == bytes.len()));
        }
    }

    #[test]
    fn pp_encode_decode_roundtrip() {
        let named = Some("app.example.com");
        let v4 = proxied("192.0.2.1:8080", "198.51.100.7:443", named);
        let v6 = proxied("[2001:db8::1]:8080", "[2001:db8::2]:443", named);
        let mapped = proxied("[::ffff:192.0.2.1]:1", "[::ffff:198.51.100.7]:2", None);
        for header in [&v4, &v6, &mapped, &Header::Local] {
            for version in [Version::V1, Version::V2] {
                let bytes = encoded(header, version);
                let expected = match (version, header) {
                    // v1 has no TLVs.
                    (Version::V1, Header::Proxied { addresses, .. }) => Header::Proxied {
                        addresses: *addresses,
                        authority: None,
                    },
                    _ => header.clone(),
                };
                assert_eq!(decoded(&bytes), expected, "{version:?} {header:?}");
            }
        }
        let wire = encoded(&v4, Version::V1);
        assert_eq!(wire, b"PROXY TCP4 192.0.2.1 198.51.100.7 8080 443\r\n");
        let wire = encoded(&v4, Version::V2);
        assert_eq!(
            &wire[..16],
            &[
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
                0x00, 0x1e
            ]
        );
        let widest = proxied(
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
            None,
        );
        assert_eq!(encoded(&widest, Version::V1).len(), 104);
    }

    #[test]
    fn pp_encode_refuses_an_authority_it_cannot_carry() {
        let mut out = vec![9];
        for name in [String::new(), "a".repeat(AUTHORITY_MAX + 1)] {
            let header = proxied("192.0.2.1:1", "192.0.2.2:2", Some(name.as_str()));
            assert_eq!(
                header.encode(Version::V2, &mut out),
                Err(EncodeError::Authority)
            );
        }
        assert_eq!(out, [9], "nothing is written");
        let longest = proxied("[::1]:1", "[::2]:2", Some(&"a".repeat(AUTHORITY_MAX)));
        assert!(encoded(&longest, Version::V2).len() <= V2_MAX);
        assert_eq!(decoded(&encoded(&longest, Version::V2)), longest);
    }

    #[test]
    fn mixed_families_are_not_a_pair() {
        assert!(Addresses::new(addr("192.0.2.1:1"), addr("[::1]:2")).is_none());
        let pair = Addresses::new(addr("192.0.2.1:1"), addr("192.0.2.2:2")).expect("pair");
        assert_eq!(
            pair.source().ip(),
            "192.0.2.1".parse::<IpAddr>().expect("ip")
        );
        assert_eq!(pair.destination(), addr("192.0.2.2:2"));
    }

    const TRAILER: &[u8] = b"GET / HTTP/1.1\r\n";

    /// Writes `bytes` followed by `TRAILER` in `chunk`-sized pieces and reads the header back; the
    /// bytes behind the header must still be unread.
    async fn read_in_chunks(bytes: &[u8], chunk: usize) -> Result<Header, ReadError> {
        let (mut peer, mut server) = duplex(4096);
        let wire = [bytes, TRAILER].concat();
        let writer = tokio::spawn(async move {
            for piece in wire.chunks(chunk) {
                peer.write_all(piece).await.expect("write");
                peer.flush().await.expect("flush");
                tokio::task::yield_now().await;
            }
            peer
        });
        let header = read_header(&mut server, Duration::from_secs(5)).await;
        let _peer = writer.await.expect("writer");
        if header.is_ok() {
            let mut rest = vec![0_u8; TRAILER.len()];
            server.read_exact(&mut rest).await.expect("trailer");
            assert_eq!(rest, TRAILER, "the reader took bytes past the header");
        }
        header
    }

    #[tokio::test]
    async fn pp_split_reads() {
        let headers = [
            proxied("192.0.2.1:8080", "198.51.100.7:443", Some("a.test")),
            proxied("[2001:db8::1]:8080", "[2001:db8::2]:443", Some("a.test")),
            Header::Local,
        ];
        for header in headers {
            for version in [Version::V1, Version::V2] {
                let bytes = encoded(&header, version);
                let expected = decoded(&bytes);
                for chunk in [1, 2, 3, 7, 16, 17, bytes.len(), bytes.len() + TRAILER.len()] {
                    let read = read_in_chunks(&bytes, chunk).await.expect("reads");
                    assert_eq!(read, expected, "{version:?} in chunks of {chunk}");
                }
            }
        }
    }

    #[tokio::test]
    async fn pp_reader_refuses_garbage_and_truncation() {
        let err = read_in_chunks(b"\x16\x03\x01\x02\x00", 5)
            .await
            .expect_err("TLS");
        assert!(
            matches!(err, ReadError::Decode(DecodeError::NotProxy)),
            "{err:?}"
        );
        let valid = encoded(&proxied("192.0.2.1:1", "192.0.2.2:2", None), Version::V2);
        for cut in [0, 1, 11, 15, 16, valid.len() - 1] {
            let (mut peer, mut server) = duplex(4096);
            peer.write_all(&valid[..cut]).await.expect("write");
            drop(peer);
            let err = read_header(&mut server, Duration::from_secs(5))
                .await
                .expect_err("cut");
            assert!(matches!(err, ReadError::Truncated), "cut at {cut}: {err:?}");
        }
    }

    #[tokio::test]
    async fn pp_deadline_closes() {
        let (mut peer, mut server) = duplex(64);
        let started = std::time::Instant::now();
        let err = read_header(&mut server, Duration::from_millis(50))
            .await
            .expect_err("silent");
        assert!(matches!(err, ReadError::Deadline), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
        // A peer that starts a header and stalls is closed too.
        peer.write_all(b"PROXY TCP4 192.0.2.1")
            .await
            .expect("write");
        let err = read_header(&mut server, Duration::from_millis(50))
            .await
            .expect_err("stalled");
        assert!(matches!(err, ReadError::Deadline), "{err:?}");
    }
}
