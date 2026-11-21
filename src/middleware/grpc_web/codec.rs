//! The wire pieces of gRPC-Web that need no request: an incremental base64 decoder and encoder
//! (`application/grpc-web-text`) and the trailer frame.
//!
//! Nothing here buffers a message. [`Decoder`] holds at most 3 characters between chunks and
//! [`Encoder`] at most 2 bytes; each call returns the bytes of its own chunk and nothing else.
//! The trailer frame is capped at [`MAX_TRAILER_BYTES`]: a response whose trailers are larger
//! gets a frame that says `grpc-status: 13` (internal) instead.

use base64::Engine;
use base64::engine::general_purpose::STANDARD_PAD_INDIFFERENT;
use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderName};
use thiserror::Error;

/// The most a trailer frame carries, in bytes of `name: value\r\n` lines.
pub const MAX_TRAILER_BYTES: usize = 8 * 1024;

/// The flag byte of a trailer frame: the high bit marks trailers, the rest says uncompressed.
const TRAILER_FLAG: u8 = 0x80;

/// `grpc-status` for an internal error.
const INTERNAL: u8 = 13;

/// `grpc-status` for an unknown error.
const UNKNOWN: u8 = 2;

/// A body that is not valid `application/grpc-web-text`.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// A character outside the base64 alphabet, or padding in the wrong place.
    #[error("the body is not valid base64")]
    Invalid,
    /// The body ended with one character of a group, which no input encodes.
    #[error("the body ends inside a base64 group")]
    Truncated,
}

/// Decodes base64 that arrives in chunks of any size.
///
/// A chunk may end anywhere: up to 3 characters of an unfinished group are kept for the next
/// call. A group with `=` padding may appear in the middle of the stream, so a client that
/// encodes each message on its own is understood.
#[derive(Debug, Default)]
pub struct Decoder {
    held: [u8; 3],
    len: u8,
}

impl Decoder {
    /// Decodes `input`, the next bytes of the stream, and returns every byte that is complete.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Invalid`] for a byte that is not base64.
    pub fn push(&mut self, input: &[u8]) -> Result<Bytes, DecodeError> {
        let held = usize::from(self.len);
        let mut out = Vec::with_capacity((held + input.len()) / 4 * 3 + 3);
        let mut rest = input;
        if held > 0 {
            let take = (4 - held).min(rest.len());
            let mut group = [0_u8; 4];
            group[..held].copy_from_slice(&self.held[..held]);
            group[held..held + take].copy_from_slice(&rest[..take]);
            rest = &rest[take..];
            if held + take < 4 {
                self.held[..held + take].copy_from_slice(&group[..held + take]);
                self.len = u8::try_from(held + take).unwrap_or(3);
                return Ok(Bytes::new());
            }
            decode(&group, &mut out)?;
            self.len = 0;
        }
        let (mut whole, tail) = rest.split_at(rest.len() / 4 * 4);
        while !whole.is_empty() {
            // Padding closes a group, and the engine accepts it only at the end of its input,
            // so cut after the group that holds the first `=`.
            let end = whole
                .iter()
                .position(|byte| *byte == b'=')
                .map_or(whole.len(), |at| at / 4 * 4 + 4);
            let (group, after) = whole.split_at(end);
            decode(group, &mut out)?;
            whole = after;
        }
        self.held[..tail.len()].copy_from_slice(tail);
        self.len = u8::try_from(tail.len()).unwrap_or(3);
        Ok(Bytes::from(out))
    }

    /// Ends the stream: decodes the unpadded characters kept from the last call.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] for a single character, [`DecodeError::Invalid`] for padding
    /// that does not fit.
    pub fn finish(&mut self) -> Result<Bytes, DecodeError> {
        let held = usize::from(self.len);
        self.len = 0;
        match held {
            0 => Ok(Bytes::new()),
            1 => Err(DecodeError::Truncated),
            _ => {
                let mut out = Vec::with_capacity(2);
                decode(&self.held[..held], &mut out)?;
                Ok(Bytes::from(out))
            }
        }
    }
}

fn decode(input: &[u8], out: &mut Vec<u8>) -> Result<(), DecodeError> {
    STANDARD_PAD_INDIFFERENT
        .decode_vec(input, out)
        .map_err(|_| DecodeError::Invalid)
}

/// Encodes bytes that arrive in chunks of any size to one base64 stream.
///
/// Up to 2 bytes of an unfinished group are kept between calls, so the stream carries padding
/// only at its end, as one `base64` call over the whole body would.
#[derive(Debug, Default)]
pub struct Encoder {
    held: [u8; 3],
    len: u8,
}

impl Encoder {
    /// Encodes `input`, the next bytes of the stream, and returns every group that is complete.
    pub fn push(&mut self, input: &[u8]) -> Bytes {
        self.run(input, false)
    }

    /// Encodes `last`, the final bytes of the stream, and the kept remainder with padding.
    pub fn finish(&mut self, last: &[u8]) -> Bytes {
        self.run(last, true)
    }

    fn run(&mut self, input: &[u8], flush: bool) -> Bytes {
        let held = usize::from(self.len);
        let total = held + input.len();
        let mut out = String::with_capacity(if flush {
            total.div_ceil(3) * 4
        } else {
            total / 3 * 4
        });
        let mut rest = input;
        let mut len = held;
        if len > 0 {
            let take = (3 - len).min(rest.len());
            self.held[len..len + take].copy_from_slice(&rest[..take]);
            len += take;
            rest = &rest[take..];
            if len == 3 {
                STANDARD_PAD_INDIFFERENT.encode_string(self.held, &mut out);
                len = 0;
            }
        }
        if len == 0 {
            let (whole, tail) = rest.split_at(rest.len() / 3 * 3);
            STANDARD_PAD_INDIFFERENT.encode_string(whole, &mut out);
            self.held[..tail.len()].copy_from_slice(tail);
            len = tail.len();
        }
        if flush && len > 0 {
            STANDARD_PAD_INDIFFERENT.encode_string(&self.held[..len], &mut out);
            len = 0;
        }
        self.len = u8::try_from(len).unwrap_or(2);
        Bytes::from(out.into_bytes())
    }
}

/// The trailer frame of `headers`, minus the names `skip` selects: the flag byte `0x80`, the
/// length of the lines as a big-endian `u32`, then one `name: value\r\n` line per value.
///
/// Over [`MAX_TRAILER_BYTES`] the lines are dropped and the frame says `grpc-status: 13`, so a
/// call never looks successful because its trailers were too big to carry.
#[must_use]
pub fn frame(headers: &HeaderMap, skip: impl Fn(&HeaderName) -> bool) -> Bytes {
    let mut size = 0_usize;
    for (name, value) in headers {
        if !skip(name) {
            size += name.as_str().len() + 2 + value.len() + 2;
            if size > MAX_TRAILER_BYTES {
                return synthetic(INTERNAL, "trailers exceed 8192 bytes");
            }
        }
    }
    let mut out = BytesMut::with_capacity(5 + size);
    out.put_u8(TRAILER_FLAG);
    out.put_u32(u32::try_from(size).unwrap_or(0));
    for (name, value) in headers {
        if !skip(name) {
            out.put_slice(name.as_str().as_bytes());
            out.put_slice(b": ");
            out.put_slice(value.as_bytes());
            out.put_slice(b"\r\n");
        }
    }
    out.freeze()
}

/// A trailer frame the proxy writes itself: `grpc-status: <status>` and `grpc-message`.
#[must_use]
pub fn synthetic(status: u8, message: &str) -> Bytes {
    let lines = format!("grpc-status: {status}\r\ngrpc-message: {message}\r\n");
    let mut out = BytesMut::with_capacity(5 + lines.len());
    out.put_u8(TRAILER_FLAG);
    out.put_u32(u32::try_from(lines.len()).unwrap_or(0));
    out.put_slice(lines.as_bytes());
    out.freeze()
}

/// The frame for an upstream that ended its response without trailers.
#[must_use]
pub fn missing_trailers() -> Bytes {
    synthetic(UNKNOWN, "upstream ended the response without trailers")
}

#[cfg(test)]
mod test {
    use http::HeaderValue;

    use super::*;

    fn decode_chunks(chunks: &[&[u8]]) -> Result<Vec<u8>, DecodeError> {
        let mut decoder = Decoder::default();
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend_from_slice(&decoder.push(chunk)?);
        }
        out.extend_from_slice(&decoder.finish()?);
        Ok(out)
    }

    fn encode_chunks(chunks: &[&[u8]]) -> String {
        let mut encoder = Encoder::default();
        let mut out = Vec::new();
        let (last, rest) = chunks.split_last().expect("a chunk");
        for chunk in rest {
            out.extend_from_slice(&encoder.push(chunk));
        }
        out.extend_from_slice(&encoder.finish(last));
        String::from_utf8(out).expect("ascii")
    }

    #[test]
    fn grpc_web_codec_decodes_at_any_chunk_boundary() {
        let text = b"AAAAAAUAAAABAA==";
        let whole = decode_chunks(&[text]).expect("decodes");
        assert_eq!(whole, [0, 0, 0, 0, 5, 0, 0, 0, 1, 0]);
        for cut in 0..=text.len() {
            let (a, b) = text.split_at(cut);
            assert_eq!(decode_chunks(&[a, b]).expect("two chunks"), whole, "{cut}");
        }
        let singles: Vec<&[u8]> = text.chunks(1).collect();
        assert_eq!(decode_chunks(&singles).expect("one byte chunks"), whole);
    }

    #[test]
    fn grpc_web_codec_takes_padded_groups_in_the_middle_and_unpadded_ends() {
        // Three groups: two padded (`A`, `AB`) and one that needs none (`ABC`).
        assert_eq!(
            decode_chunks(&[b"QQ==QUI=QUJD"]).expect("concatenated"),
            b"AABABC"
        );
        assert_eq!(decode_chunks(&[b"QQ"]).expect("unpadded end"), b"A");
        assert_eq!(decode_chunks(&[b"QUI"]).expect("unpadded end"), b"AB");
    }

    #[test]
    fn grpc_web_codec_refuses_what_is_not_base64() {
        assert_eq!(decode_chunks(&[b"QQ!!"]), Err(DecodeError::Invalid));
        assert_eq!(decode_chunks(&[b"=QQQ"]), Err(DecodeError::Invalid));
        assert_eq!(decode_chunks(&[b"QUJDR"]), Err(DecodeError::Truncated));
        assert_eq!(decode_chunks(&[b"QQ=\n"]), Err(DecodeError::Invalid));
    }

    #[test]
    fn grpc_web_codec_encodes_like_one_call_whatever_the_chunks() {
        let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let expected = STANDARD_PAD_INDIFFERENT.encode(&data);
        for size in [1, 2, 3, 4, 5, 7, 64, 999, 1000] {
            let chunks: Vec<&[u8]> = data.chunks(size).collect();
            assert_eq!(encode_chunks(&chunks), expected, "chunks of {size}");
        }
        assert_eq!(encode_chunks(&[b""]), "");
        assert_eq!(encode_chunks(&[b"a"]), "YQ==");
    }

    #[test]
    fn grpc_web_codec_keeps_at_most_two_bytes_between_chunks() {
        let mut encoder = Encoder::default();
        for _ in 0..50 {
            let _ = encoder.push(&[1, 2, 3, 4]);
            assert!(encoder.len <= 2);
        }
        let mut decoder = Decoder::default();
        for _ in 0..50 {
            let _ = decoder.push(b"QUJDRA").expect("decodes");
            assert!(decoder.len <= 3);
        }
    }

    #[test]
    fn grpc_web_codec_frames_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        trailers.append("x-meta", HeaderValue::from_static("a"));
        let frame = frame(&trailers, |_| false);
        let lines = b"grpc-status: 0\r\nx-meta: a\r\n";
        assert_eq!(frame[0], 0x80);
        assert_eq!(
            u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize,
            lines.len()
        );
        assert_eq!(&frame[5..], lines);
    }

    #[test]
    fn grpc_web_codec_skips_names_and_empty_trailers_make_an_empty_frame() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert("grpc-status", HeaderValue::from_static("3"));
        let frame = frame(&headers, |name| name == "content-type");
        assert_eq!(&frame[5..], b"grpc-status: 3\r\n");
        let empty = super::frame(&HeaderMap::new(), |_| false);
        assert_eq!(&empty[..], [0x80, 0, 0, 0, 0]);
    }

    #[test]
    fn grpc_web_codec_replaces_oversized_trailers_with_status_13() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let big = "x".repeat(MAX_TRAILER_BYTES);
        trailers.insert(
            "x-big",
            HeaderValue::from_str(&big).expect("a valid header value"),
        );
        let frame = frame(&trailers, |_| false);
        let text = std::str::from_utf8(&frame[5..]).expect("ascii");
        assert!(text.starts_with("grpc-status: 13\r\n"), "{text}");
        assert!(!text.contains("x-big"));
        // Exactly at the cap still fits.
        let mut fits = HeaderMap::new();
        let value = "y".repeat(MAX_TRAILER_BYTES - "x-fit".len() - 4);
        fits.insert(
            "x-fit",
            HeaderValue::from_str(&value).expect("a valid header value"),
        );
        let frame = super::frame(&fits, |_| false);
        assert_eq!(frame.len(), 5 + MAX_TRAILER_BYTES);
        assert!(frame[5..].starts_with(b"x-fit: yyy"));
    }
}
