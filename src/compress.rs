//! Gzip compression of proxied responses, with every byte of encoder memory charged to the
//! tenant's buffer budget before it is allocated.
//!
//! Pingora's own compression module hides its encoder allocations from the proxy, so it cannot
//! be budgeted. This module streams the body through [`miniz_oxide`] (pure safe Rust) instead.
//! The memory a response can hold is fixed up front, so one [`RESERVATION_BYTES`] charge covers
//! it all:
//!
//! - the deflate state of [`miniz_oxide`] (dictionary, hash chains, code buffer): 319,326 bytes,
//!   measured with a counting allocator at level 4,
//! - a fixed scratch buffer the encoder writes into (16 KiB),
//! - the compressed output of one body chunk. Pingora reads an upstream body in chunks of at
//!   most 64 KiB, and the encoder holds back at most one more block, so the output of one call
//!   stays under 128 KiB; `Vec` growth can double that.
//!
//! When the charge does not fit, [`start`] returns `None` and the response is served as the
//! upstream sent it. Compression degrades; it never fails a request.

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use miniz_oxide::deflate::core::{CompressorOxide, create_comp_flags_from_zip_params};
use miniz_oxide::deflate::stream::deflate;
use miniz_oxide::{MZFlush, MZStatus};
use pingora::http::{Method, RequestHeader, ResponseHeader, StatusCode, Version};

use crate::budget::{BufferGuard, TenantBudget};

/// Buffer bytes charged for each compressed response.
pub const RESERVATION_BYTES: u64 = 640 * 1024;

/// Size of the buffer the encoder writes into.
const SCRATCH_BYTES: usize = 16 * 1024;

/// Responses known to be smaller than this are not worth compressing.
const MIN_LEN: u64 = 256;

/// Deflate effort, 1 (fastest) to 10 (smallest).
const LEVEL: i32 = 4;

/// The gzip header: deflate, no flags, no mtime, no extra flags, unknown OS.
const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];

/// A response being gzip-compressed. Holds its [`BufferGuard`], so dropping it frees the budget.
pub struct Gzip {
    deflate: Box<CompressorOxide>,
    scratch: Box<[u8]>,
    crc: crc32fast::Hasher,
    len: u32,
    header_pending: bool,
    _charge: BufferGuard,
}

impl std::fmt::Debug for Gzip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gzip")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Decides whether `response` is compressed and, if so, prepares its headers and the encoder.
///
/// Compresses a `200` response to a `GET` or `POST` that accepts gzip, whose content type is
/// text-like, that is not already encoded, and that is not known to be tiny. The response then
/// loses its `content-length` and `accept-ranges`, gains `content-encoding: gzip` and, over
/// HTTP/1.1, `transfer-encoding: chunked`. `vary: accept-encoding` is added to every response
/// that could have been compressed, so a cache tells the two forms apart.
///
/// Returns `None` when the response stays as it is, including when the tenant's buffer budget
/// cannot take [`RESERVATION_BYTES`].
pub fn start(
    request: &RequestHeader,
    response: &mut ResponseHeader,
    tenant: &Arc<TenantBudget>,
) -> Option<Gzip> {
    if !eligible(request, response) {
        return None;
    }
    // Ignored on failure: the response is then simply not varied by a header it did not have.
    drop(response.append_header("vary", "accept-encoding"));
    let charge = tenant.reserve(RESERVATION_BYTES)?;
    let deflate = Box::new(CompressorOxide::new(create_comp_flags_from_zip_params(
        LEVEL, -15, 0,
    )));
    response.remove_header("content-length");
    response.remove_header("accept-ranges");
    weaken_etag(response);
    drop(response.insert_header("content-encoding", "gzip"));
    if request.version == Version::HTTP_11 {
        drop(response.insert_header("transfer-encoding", "chunked"));
    }
    Some(Gzip {
        deflate,
        scratch: vec![0; SCRATCH_BYTES].into_boxed_slice(),
        crc: crc32fast::Hasher::new(),
        len: 0,
        header_pending: true,
        _charge: charge,
    })
}

/// Runs one body chunk through the encoder. `body` becomes the compressed bytes available so
/// far, or `None` when the encoder is still holding them back. At `end` the stream is finished
/// and `compression` is cleared, which frees the charge.
///
/// # Errors
///
/// Fails when the encoder rejects its input; the response cannot continue.
pub fn filter(
    compression: &mut Option<Gzip>,
    body: &mut Option<Bytes>,
    end: bool,
) -> io::Result<()> {
    let Some(gzip) = compression.as_mut() else {
        return Ok(());
    };
    let mut out = Vec::new();
    if gzip.header_pending {
        out.extend_from_slice(&GZIP_HEADER);
        gzip.header_pending = false;
    }
    if let Some(chunk) = body.take() {
        gzip.crc.update(&chunk);
        // Wrapping is what the gzip trailer wants: the length modulo 2^32.
        gzip.len = gzip
            .len
            .wrapping_add(u32::try_from(chunk.len() % (1 << 32)).unwrap_or(0));
        gzip.encode(&chunk, MZFlush::None, &mut out)?;
    }
    if end {
        gzip.encode(&[], MZFlush::Finish, &mut out)?;
        out.extend_from_slice(&gzip.crc.clone().finalize().to_le_bytes());
        out.extend_from_slice(&gzip.len.to_le_bytes());
        *compression = None;
    }
    *body = (!out.is_empty()).then(|| Bytes::from(out));
    Ok(())
}

impl Gzip {
    /// Feeds `input` to the encoder with `flush`, appending what it emits to `out`.
    fn encode(&mut self, mut input: &[u8], flush: MZFlush, out: &mut Vec<u8>) -> io::Result<()> {
        loop {
            let step = deflate(&mut self.deflate, input, &mut self.scratch, flush);
            out.extend_from_slice(&self.scratch[..step.bytes_written]);
            input = &input[step.bytes_consumed..];
            match step.status {
                Ok(MZStatus::StreamEnd) => return Ok(()),
                // A full scratch buffer reports `Ok` with input left; more room is next round.
                Ok(_) if !input.is_empty() || step.bytes_written == self.scratch.len() => {}
                Ok(_) if flush == MZFlush::None => return Ok(()),
                Ok(_) => {}
                Err(err) => {
                    return Err(io::Error::other(format!("deflate failed: {err:?}")));
                }
            }
        }
    }
}

/// Whether `response` to `request` may be compressed. Pure header logic.
fn eligible(request: &RequestHeader, response: &ResponseHeader) -> bool {
    let method_ok = request.method == Method::GET || request.method == Method::POST;
    let version_ok = request.version == Version::HTTP_11 || request.version == Version::HTTP_2;
    let accepts = request
        .headers
        .get_all("accept-encoding")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(accepts_gzip);
    let headers = &response.headers;
    let encoded = headers.contains_key("content-encoding");
    let no_transform = headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.to_ascii_lowercase().contains("no-transform"));
    let tiny = headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|len| len < MIN_LEN);
    let textual = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_compressible);
    method_ok
        && version_ok
        && accepts
        && response.status == StatusCode::OK
        && !encoded
        && !no_transform
        && !tiny
        && textual
}

/// Whether an `Accept-Encoding` value allows gzip: named with a non-zero quality, or allowed by
/// `*` when not named.
fn accepts_gzip(value: &str) -> bool {
    let mut star = false;
    for item in value.split(',') {
        let mut parts = item.split(';');
        let coding = parts.next().unwrap_or_default().trim();
        let quality = parts
            .filter_map(|param| param.trim().strip_prefix("q="))
            .find_map(|q| q.trim().parse::<f32>().ok())
            .unwrap_or(1.0);
        if coding.eq_ignore_ascii_case("gzip") {
            return quality > 0.0;
        }
        if coding == "*" {
            star = quality > 0.0;
        }
    }
    star
}

/// Whether a `content-type` value is text-like.
fn is_compressible(value: &str) -> bool {
    let media = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media.starts_with("text/")
        || media.ends_with("+json")
        || media.ends_with("+xml")
        || matches!(
            media.as_str(),
            "application/json"
                | "application/javascript"
                | "application/xml"
                | "application/x-ndjson"
        )
}

/// A strong `etag` names the bytes of the identity form, which these are not: make it weak.
fn weaken_etag(response: &mut ResponseHeader) {
    let Some(etag) = response.headers.get("etag").and_then(|v| v.to_str().ok()) else {
        return;
    };
    if etag.starts_with("W/") {
        return;
    }
    let weak = format!("W/{etag}");
    drop(response.insert_header("etag", weak));
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::budget::Budgets;
    use podgate_model::Budget;

    fn request(accept: Option<&str>) -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        if let Some(accept) = accept {
            request
                .insert_header("accept-encoding", accept)
                .expect("header");
        }
        request
    }

    fn response(content_type: &str) -> ResponseHeader {
        let mut response = ResponseHeader::build(200, None).expect("response");
        response
            .insert_header("content-type", content_type)
            .expect("header");
        response
    }

    fn tenant(max_buffer_bytes: u64) -> Arc<TenantBudget> {
        Budgets::new().tenant(
            "t1",
            Budget {
                max_inflight: 1,
                max_buffer_bytes,
            },
        )
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        // Test-only reader for the gzip frame: header, raw deflate, 8-byte trailer.
        let raw = &bytes[10..bytes.len() - 8];
        let inflated = miniz_oxide::inflate::decompress_to_vec(raw).expect("valid deflate");
        let trailer = &bytes[bytes.len() - 8..];
        assert_eq!(trailer[..4], crc32fast::hash(&inflated).to_le_bytes());
        assert_eq!(
            trailer[4..],
            u32::try_from(inflated.len()).expect("small").to_le_bytes()
        );
        inflated
    }

    #[test]
    fn accept_encoding_is_parsed() {
        assert!(accepts_gzip("gzip"));
        assert!(accepts_gzip("br, gzip;q=0.5"));
        assert!(accepts_gzip("*"));
        assert!(!accepts_gzip("gzip;q=0"));
        assert!(!accepts_gzip("*;q=0, br"));
        assert!(!accepts_gzip("gzip;q=0, *"));
        assert!(!accepts_gzip("br, deflate"));
    }

    #[test]
    fn only_text_like_types_compress() {
        assert!(is_compressible("text/html; charset=utf-8"));
        assert!(is_compressible("application/json"));
        assert!(is_compressible("application/problem+json"));
        assert!(!is_compressible("image/png"));
        assert!(!is_compressible("application/octet-stream"));
    }

    #[test]
    fn streams_a_valid_gzip_body_and_releases_its_charge() {
        let tenant = tenant(RESERVATION_BYTES);
        let mut head = response("text/plain");
        head.insert_header("content-length", "5000")
            .expect("header");
        head.insert_header("etag", "\"abc\"").expect("header");
        let mut compression = start(&request(Some("gzip")), &mut head, &tenant);
        assert!(compression.is_some());
        assert_eq!(tenant.buffered(), RESERVATION_BYTES);
        assert_eq!(head.headers["content-encoding"], "gzip");
        assert_eq!(head.headers["transfer-encoding"], "chunked");
        assert_eq!(head.headers["vary"], "accept-encoding");
        assert_eq!(head.headers["etag"], "W/\"abc\"");
        assert!(!head.headers.contains_key("content-length"));

        let original: Vec<u8> = (0..200_000_u32)
            .flat_map(|n| format!("line {n}\n").into_bytes())
            .collect();
        let mut wire = Vec::new();
        let chunks: Vec<&[u8]> = original.chunks(65_536).collect();
        for (index, chunk) in chunks.iter().enumerate() {
            let mut body = Some(Bytes::copy_from_slice(chunk));
            filter(&mut compression, &mut body, index + 1 == chunks.len()).expect("encodes");
            wire.extend_from_slice(&body.unwrap_or_default());
        }
        assert!(compression.is_none(), "the stream ended");
        assert_eq!(tenant.buffered(), 0, "the charge is released at the end");
        assert!(wire.len() < original.len() / 2, "the text got smaller");
        assert_eq!(gunzip(&wire), original);
    }

    #[test]
    fn an_empty_body_is_a_valid_gzip_stream() {
        let tenant = tenant(RESERVATION_BYTES);
        let mut compression = start(&request(Some("gzip")), &mut response("text/plain"), &tenant);
        let mut body = None;
        filter(&mut compression, &mut body, true).expect("finishes");
        assert_eq!(gunzip(&body.expect("header and trailer")), b"");
    }

    #[test]
    fn a_full_budget_serves_identity_and_counts_it() {
        let tenant = tenant(RESERVATION_BYTES - 1);
        let mut head = response("text/plain");
        assert!(start(&request(Some("gzip")), &mut head, &tenant).is_none());
        assert!(!head.headers.contains_key("content-encoding"));
        assert_eq!(head.headers["vary"], "accept-encoding");
        assert_eq!(tenant.buffered(), 0);
    }

    #[test]
    fn leaves_ineligible_responses_alone() {
        let tenant = tenant(u64::MAX);
        let start_with = |accept: Option<&str>, mutate: &dyn Fn(&mut ResponseHeader)| {
            let mut head = response("text/plain");
            mutate(&mut head);
            let started = start(&request(accept), &mut head, &tenant).is_some();
            (started, head)
        };
        assert!(!start_with(None, &|_| {}).0, "client did not ask");
        assert!(
            !start_with(Some("br"), &|_| {}).0,
            "client wants something else"
        );
        let set = |name: &'static str, value: &'static str| {
            move |head: &mut ResponseHeader| {
                head.insert_header(name, value).expect("header");
            }
        };
        assert!(!start_with(Some("gzip"), &set("content-encoding", "br")).0);
        assert!(!start_with(Some("gzip"), &set("cache-control", "No-Transform")).0);
        assert!(!start_with(Some("gzip"), &set("content-length", "10")).0);
        assert!(!start_with(Some("gzip"), &set("content-type", "image/png")).0);
        assert!(!start_with(Some("gzip"), &|head| head.set_status(206).expect("status")).0);
        assert!(start_with(Some("gzip"), &set("content-length", "10000")).0);
        assert_eq!(tenant.buffered(), 0, "a dropped encoder frees its charge");
    }
}
