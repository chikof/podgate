//! FastCGI records (specification version 1.0): framing, name-value pairs, and the one role this
//! client plays, the responder. One request runs on one connection under [`REQUEST_ID`]; there is
//! no multiplexing.

use std::io;

use bytes::{Bytes, BytesMut};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The protocol version in every record header.
const VERSION: u8 = 1;

/// The request id of the only request on a connection.
pub(super) const REQUEST_ID: u16 = 1;

/// Most content bytes one record carries (its length is a `u16`).
pub(super) const MAX_CONTENT: usize = 65535;

/// `FCGI_BEGIN_REQUEST`.
const BEGIN_REQUEST: u8 = 1;
/// `FCGI_END_REQUEST`.
const END_REQUEST: u8 = 3;
/// `FCGI_PARAMS`.
const PARAMS: u8 = 4;
/// `FCGI_STDIN`.
const STDIN: u8 = 5;
/// `FCGI_STDOUT`.
const STDOUT: u8 = 6;
/// `FCGI_STDERR`.
const STDERR: u8 = 7;

/// `FCGI_RESPONDER`.
const ROLE_RESPONDER: u16 = 1;
/// `FCGI_KEEP_CONN`: the application leaves the connection open after the request.
const FLAG_KEEP_CONN: u8 = 1;

/// A record the application sent that this client acts on.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Record {
    /// A piece of the response (`FCGI_STDOUT`). An empty one ends the stream.
    Stdout(Bytes),
    /// A piece of the application's error output (`FCGI_STDERR`).
    Stderr(Bytes),
    /// The request is done.
    End(End),
    /// A record of a type a responder client has no use for; skipped.
    Other,
}

/// `FCGI_END_REQUEST`: how the application finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct End {
    /// The application's exit status.
    pub app_status: u32,
    /// `0` for a request that completed; anything else is the application refusing it.
    pub protocol_status: u8,
}

/// Why a connection stopped speaking FastCGI.
#[derive(Debug, Error)]
pub(super) enum ProtocolError {
    /// The connection failed or closed in the middle of a record.
    #[error("connection: {0}")]
    Io(#[from] io::Error),
    /// A record header with a version other than 1, or a record for another request.
    #[error("unexpected record")]
    Unexpected,
}

fn header(kind: u8, len: usize, padding: u8) -> Result<[u8; 8], ProtocolError> {
    let len = u16::try_from(len).map_err(|_| ProtocolError::Unexpected)?;
    let [id_high, id_low] = REQUEST_ID.to_be_bytes();
    let [len_high, len_low] = len.to_be_bytes();
    Ok([
        VERSION, kind, id_high, id_low, len_high, len_low, padding, 0,
    ])
}

/// Writes `FCGI_BEGIN_REQUEST` for a responder; `keep_conn` asks the application to leave the
/// connection open for the next request.
///
/// # Errors
///
/// The connection's write error.
pub(super) async fn write_begin<W: AsyncWrite + Unpin>(
    out: &mut W,
    keep_conn: bool,
) -> Result<(), ProtocolError> {
    let mut record = [0_u8; 16];
    record[..8].copy_from_slice(&header(BEGIN_REQUEST, 8, 0)?);
    record[8..10].copy_from_slice(&ROLE_RESPONDER.to_be_bytes());
    record[10] = u8::from(keep_conn) * FLAG_KEEP_CONN;
    out.write_all(&record).await?;
    Ok(())
}

/// Appends one name-value pair, the encoding of `FCGI_PARAMS`: each length is one byte below 128
/// and four bytes (high bit set) otherwise.
pub(super) fn encode_pair(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    push_length(out, name.len());
    push_length(out, value.len());
    out.extend_from_slice(name);
    out.extend_from_slice(value);
}

fn push_length(out: &mut Vec<u8>, len: usize) {
    match u8::try_from(len) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => out.extend_from_slice(
            &(u32::try_from(len).unwrap_or(u32::MAX) | 0x8000_0000).to_be_bytes(),
        ),
    }
}

/// Writes `data` as records of `kind`, then the empty record that ends the stream.
async fn write_stream<W: AsyncWrite + Unpin>(
    out: &mut W,
    kind: u8,
    data: &[u8],
) -> Result<(), ProtocolError> {
    for chunk in data.chunks(MAX_CONTENT) {
        out.write_all(&header(kind, chunk.len(), 0)?).await?;
        out.write_all(chunk).await?;
    }
    out.write_all(&header(kind, 0, 0)?).await?;
    Ok(())
}

/// Writes the encoded parameters as `FCGI_PARAMS` records and the empty record that ends them.
///
/// # Errors
///
/// The connection's write error.
pub(super) async fn write_params<W: AsyncWrite + Unpin>(
    out: &mut W,
    encoded: &[u8],
) -> Result<(), ProtocolError> {
    write_stream(out, PARAMS, encoded).await
}

/// Writes one piece of the request body as `FCGI_STDIN` records, without ending the stream.
///
/// # Errors
///
/// The connection's write error.
pub(super) async fn write_stdin<W: AsyncWrite + Unpin>(
    out: &mut W,
    data: &[u8],
) -> Result<(), ProtocolError> {
    for chunk in data.chunks(MAX_CONTENT) {
        out.write_all(&header(STDIN, chunk.len(), 0)?).await?;
        out.write_all(chunk).await?;
    }
    Ok(())
}

/// Writes the empty `FCGI_STDIN` record that ends the request body, and flushes.
///
/// # Errors
///
/// The connection's write error.
pub(super) async fn end_stdin<W: AsyncWrite + Unpin>(out: &mut W) -> Result<(), ProtocolError> {
    out.write_all(&header(STDIN, 0, 0)?).await?;
    out.flush().await?;
    Ok(())
}

/// Reads the next record. Content is at most [`MAX_CONTENT`] bytes, so one call holds at most one
/// 64 KiB allocation.
///
/// # Errors
///
/// [`ProtocolError::Io`] when the connection fails or ends inside a record,
/// [`ProtocolError::Unexpected`] for a version other than 1 or a record of another request.
pub(super) async fn read_record<R: AsyncRead + Unpin>(
    input: &mut R,
) -> Result<Record, ProtocolError> {
    let mut head = [0_u8; 8];
    input.read_exact(&mut head).await?;
    let [
        version,
        kind,
        id_high,
        id_low,
        len_high,
        len_low,
        padding,
        _,
    ] = head;
    if version != VERSION || u16::from_be_bytes([id_high, id_low]) != REQUEST_ID {
        // Id 0 carries management records, which a client that sends none never gets.
        return Err(ProtocolError::Unexpected);
    }
    let len = usize::from(u16::from_be_bytes([len_high, len_low]));
    let mut content = BytesMut::zeroed(len);
    input.read_exact(&mut content).await?;
    let mut skipped = [0_u8; 255];
    input
        .read_exact(&mut skipped[..usize::from(padding)])
        .await?;
    Ok(match kind {
        STDOUT => Record::Stdout(content.freeze()),
        STDERR => Record::Stderr(content.freeze()),
        END_REQUEST => {
            let [a, b, c, d, protocol_status, ..] = content[..] else {
                return Err(ProtocolError::Unexpected);
            };
            Record::End(End {
                app_status: u32::from_be_bytes([a, b, c, d]),
                protocol_status,
            })
        }
        _ => Record::Other,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    fn record(kind: u8, content: &[u8], padding: u8) -> Vec<u8> {
        let mut out = header(kind, content.len(), padding)
            .expect("header")
            .to_vec();
        out.extend_from_slice(content);
        out.extend(std::iter::repeat_n(0, usize::from(padding)));
        out
    }

    #[test]
    fn pairs_use_one_byte_lengths_below_128() {
        let mut out = Vec::new();
        encode_pair(&mut out, b"A", b"bc");
        assert_eq!(out, [1, 2, b'A', b'b', b'c']);
    }

    #[test]
    fn long_values_use_four_byte_lengths() {
        let value = vec![b'x'; 300];
        let mut out = Vec::new();
        encode_pair(&mut out, b"N", &value);
        assert_eq!(&out[..5], [1, 0x80, 0, 1, 0x2c]);
        assert_eq!(out.len(), 5 + 1 + 300);
    }

    #[tokio::test]
    async fn begin_request_asks_for_a_responder() {
        let mut out = Vec::new();
        write_begin(&mut out, true).await.expect("write");
        assert_eq!(
            out,
            [1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0],
            "version, type, id, length, padding, role, flags, reserved"
        );
    }

    #[tokio::test]
    async fn params_are_split_at_the_record_limit_and_closed_by_an_empty_record() {
        let data = vec![7_u8; MAX_CONTENT + 10];
        let mut out = Vec::new();
        write_params(&mut out, &data).await.expect("write");
        let mut reader = &out[..];
        let mut sizes = Vec::new();
        loop {
            let mut head = [0_u8; 8];
            reader.read_exact(&mut head).await.expect("header");
            assert_eq!(head[1], PARAMS);
            let len = usize::from(u16::from_be_bytes([head[4], head[5]]));
            let mut skip = vec![0; len];
            reader.read_exact(&mut skip).await.expect("content");
            sizes.push(len);
            if len == 0 {
                break;
            }
        }
        assert_eq!(sizes, [MAX_CONTENT, 10, 0]);
    }

    #[tokio::test]
    async fn reads_output_error_and_end_records_and_skips_padding() {
        let mut wire = record(STDOUT, b"hello", 3);
        wire.extend(record(STDERR, b"warn", 0));
        wire.extend(record(END_REQUEST, &[0, 0, 0, 7, 0, 0, 0, 0], 0));
        let mut reader = &wire[..];
        assert_eq!(
            read_record(&mut reader).await.expect("stdout"),
            Record::Stdout(Bytes::from_static(b"hello"))
        );
        assert_eq!(
            read_record(&mut reader).await.expect("stderr"),
            Record::Stderr(Bytes::from_static(b"warn"))
        );
        assert_eq!(
            read_record(&mut reader).await.expect("end"),
            Record::End(End {
                app_status: 7,
                protocol_status: 0
            })
        );
    }

    #[tokio::test]
    async fn refuses_a_wrong_version_and_another_request_id() {
        let mut wire = record(STDOUT, b"x", 0);
        wire[0] = 2;
        assert!(matches!(
            read_record(&mut &wire[..]).await,
            Err(ProtocolError::Unexpected)
        ));
        let mut wire = record(STDOUT, b"x", 0);
        wire[3] = 9;
        assert!(matches!(
            read_record(&mut &wire[..]).await,
            Err(ProtocolError::Unexpected)
        ));
    }

    #[tokio::test]
    async fn a_connection_that_ends_mid_record_is_an_io_error() {
        let wire = record(STDOUT, b"hello", 0);
        assert!(matches!(
            read_record(&mut &wire[..9]).await,
            Err(ProtocolError::Io(_))
        ));
    }
}
