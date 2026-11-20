//! Compression of proxied responses (gzip, brotli, zstd), with every byte of encoder memory
//! charged to the tenant's buffer budget before it is allocated.
//!
//! Pingora's own compression module hides its encoder allocations from the proxy, so it cannot
//! be budgeted. This module streams the body through pure-Rust encoders instead: [`miniz_oxide`]
//! for gzip, the `brotli` crate with a 32 KiB window and quality at most 3, and `ruzstd` with
//! one frame per 32 KiB (see `zstd.rs`). The C zstd library is not used, and no encoder has a
//! window the response can grow.
//!
//! The memory a response can hold is fixed up front, so one [`Algorithm::reservation`] charge
//! covers it all:
//!
//! - the encoder state: gzip's dictionary, hash chains and code buffer; brotli's ring buffer
//!   and match tables; zstd's frame buffers and suffix table,
//! - a fixed scratch or staging buffer the encoder writes into,
//! - the compressed output of one body chunk. Pingora reads an upstream body in chunks of at
//!   most 64 KiB, and an encoder holds back at most one more block, so the output of one call
//!   stays under 128 KiB; `Vec` growth can double that.
//!
//! The reservation of each algorithm is the peak a counting allocator saw in
//! `tests/compress_alloc.rs`, rounded up. When the charge does not fit, [`start`] returns `None`
//! and the response is served as the upstream sent it. Compression degrades; it never fails a
//! request.

mod brotli;
mod zstd;

use std::io;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use miniz_oxide::deflate::core::{CompressorOxide, create_comp_flags_from_zip_params};
use miniz_oxide::deflate::stream::deflate;
use miniz_oxide::{MZFlush, MZStatus};
use pingora::http::{Method, RequestHeader, ResponseHeader, Version};

use crate::budget::{BufferGuard, TenantBudget};

/// The highest `level`. Brotli quality 4 holds 1.8 MiB of match tables and quality 5 holds 35 MiB
/// (measured, `tests/compress_alloc.rs`), which no per-response reservation can defend, so the
/// levels 1 (fast), 2 and 3 (small) map to brotli quality 1 to 3 and to deflate levels 1, 4 and 6.
/// zstd has one level.
pub const MAX_LEVEL: u8 = 3;

/// The effort used when nothing sets one.
pub const DEFAULT_LEVEL: u8 = 2;

/// Responses declared smaller than this are not compressed unless a `compress` middleware sets
/// another limit.
pub const DEFAULT_MIN_BYTES: u64 = 1024;

/// Size of the buffer the gzip encoder writes into.
const SCRATCH_BYTES: usize = 16 * 1024;

/// The gzip header: deflate, no flags, no mtime, no extra flags, unknown OS.
const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];

/// A content encoding podgate can apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// `gzip`, on `miniz_oxide`.
    Gzip,
    /// `br`, on the `brotli` crate.
    Brotli,
    /// `zstd`, on `ruzstd`.
    Zstd,
}

impl Algorithm {
    /// The `Accept-Encoding` and `Content-Encoding` token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
        }
    }

    /// Buffer bytes charged to the tenant for each response compressed with this algorithm,
    /// before the encoder exists. Each is the highest peak `tests/compress_alloc.rs` measured at
    /// any level, on text and on incompressible bytes, rounded up: gzip 466,880 bytes, brotli
    /// 825,788, zstd 790,148.
    #[must_use]
    pub const fn reservation(self) -> u64 {
        match self {
            Self::Gzip => 640 * 1024,
            Self::Brotli | Self::Zstd => 896 * 1024,
        }
    }
}

/// A media-type pattern of a content-type list: `type/subtype` or `type/*`, lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaPattern {
    /// Matches exactly this `type/subtype`.
    Exact(Box<str>),
    /// Matches every subtype of this `type`.
    Type(Box<str>),
}

impl MediaPattern {
    /// Parses `type/subtype` or `type/*`.
    ///
    /// # Errors
    ///
    /// What is wrong with `text`.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let (kind, subtype) = text
            .split_once('/')
            .ok_or("a media type is `type/subtype` or `type/*`")?;
        let token = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
        };
        if !token(kind) {
            return Err("the type of a media type is a token");
        }
        if subtype == "*" {
            return Ok(Self::Type(kind.to_ascii_lowercase().into()));
        }
        if !token(subtype) {
            return Err("the subtype of a media type is a token or `*`, with no parameters");
        }
        Ok(Self::Exact(text.to_ascii_lowercase().into()))
    }

    fn matches(&self, media: &str) -> bool {
        match self {
            Self::Exact(exact) => &**exact == media,
            Self::Type(kind) => media
                .split_once('/')
                .is_some_and(|(found, _)| found == &**kind),
        }
    }

    /// The pattern as written, for explain.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Exact(exact) => exact.to_string(),
            Self::Type(kind) => format!("{kind}/*"),
        }
    }
}

/// What a chain's `compress` decides, or the platform default when the chain has none.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Preference order; the first one the client accepts is used. Empty: no compression.
    pub algorithms: Vec<Algorithm>,
    /// Responses declared shorter than this stay as they are.
    pub min_bytes: u64,
    /// When set, only these content types are compressed; when not, the text-like ones.
    pub include: Option<Vec<MediaPattern>>,
    /// Content types never compressed, on top of event streams and gRPC.
    pub exclude: Vec<MediaPattern>,
    /// Effort, 1 to [`MAX_LEVEL`]; see there for what it means per algorithm.
    pub level: u8,
}

impl Settings {
    /// What a chain without a `compress` middleware gets: gzip of text-like responses.
    #[must_use]
    pub fn platform() -> &'static Self {
        static PLATFORM: LazyLock<Settings> = LazyLock::new(|| Settings {
            algorithms: vec![Algorithm::Gzip],
            min_bytes: DEFAULT_MIN_BYTES,
            include: None,
            exclude: Vec::new(),
            level: DEFAULT_LEVEL,
        });
        &PLATFORM
    }

    /// Whether a response with this `content-type` value may be compressed.
    fn allows(&self, content_type: &str) -> bool {
        let media = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        // A stream is useless buffered: compressing it holds its events back.
        if media == "text/event-stream" || media.starts_with("application/grpc") {
            return false;
        }
        if self.exclude.iter().any(|pattern| pattern.matches(&media)) {
            return false;
        }
        match &self.include {
            Some(include) => include.iter().any(|pattern| pattern.matches(&media)),
            None => is_text_like(&media),
        }
    }
}

/// A response being compressed. Holds its [`BufferGuard`], so dropping it frees the budget.
#[derive(Debug)]
pub struct Encoder {
    body: Body,
    _charge: BufferGuard,
}

enum Body {
    Gzip(Box<Gzip>),
    Brotli(Box<brotli::Brotli>),
    Zstd(Box<zstd::Zstd>),
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Gzip(_) => "Gzip",
            Self::Brotli(_) => "Brotli",
            Self::Zstd(_) => "Zstd",
        })
    }
}

struct Gzip {
    deflate: Box<CompressorOxide>,
    scratch: Box<[u8]>,
    crc: crc32fast::Hasher,
    len: u32,
    header_pending: bool,
}

/// Decides whether `response` is compressed and, if so, prepares its headers and the encoder.
///
/// A response is a candidate when `settings` has an algorithm, its status can carry a body (not
/// `1xx`, `204`, `205`, `206`, `304`), it is not already encoded, `no-transform` or a range, its
/// content type passes the lists, and its declared length is at least `min_bytes`. A candidate
/// gets `vary: accept-encoding`, whoever asks. It is compressed when the request is not `HEAD`,
/// the client accepts one of the algorithms and the tenant's buffer budget takes the algorithm's
/// reservation: the first algorithm of `settings` the client accepts wins. The response then
/// loses its `content-length` and `accept-ranges`, gains `content-encoding` and, over HTTP/1.1,
/// `transfer-encoding: chunked`, and a strong `etag` turns weak.
///
/// A body of unknown length is compressed whatever its size: Pingora writes the head before it
/// reads the body, so the size cannot be known in time.
///
/// Returns `None` when the response stays as it is, including when the budget is full.
pub fn start(
    request: &RequestHeader,
    response: &mut ResponseHeader,
    tenant: &Arc<TenantBudget>,
    settings: &Settings,
) -> Option<Encoder> {
    if !candidate(response, settings) {
        return None;
    }
    add_vary(response);
    if request.method == Method::HEAD
        || !matches!(request.version, Version::HTTP_11 | Version::HTTP_2)
    {
        return None;
    }
    let algorithm = negotiate(request, &settings.algorithms)?;
    let charge = tenant.reserve(algorithm.reservation())?;
    let level = settings.level.clamp(1, MAX_LEVEL);
    let body = match algorithm {
        Algorithm::Gzip => Body::Gzip(Box::new(Gzip::new(level))),
        Algorithm::Brotli => Body::Brotli(Box::new(brotli::Brotli::new(level))),
        Algorithm::Zstd => Body::Zstd(Box::new(zstd::Zstd::new())),
    };
    response.remove_header("content-length");
    response.remove_header("accept-ranges");
    weaken_etag(response);
    // Ignored on failure: the token is a static ASCII string, which always inserts.
    drop(response.insert_header("content-encoding", algorithm.token()));
    if request.version == Version::HTTP_11 {
        drop(response.insert_header("transfer-encoding", "chunked"));
    }
    Some(Encoder {
        body,
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
    compression: &mut Option<Encoder>,
    body: &mut Option<Bytes>,
    end: bool,
) -> io::Result<()> {
    let Some(encoder) = compression.as_mut() else {
        return Ok(());
    };
    let mut out = Vec::new();
    if let Some(chunk) = body.take() {
        encoder.body.feed(&chunk, &mut out)?;
    }
    if end && let Some(encoder) = compression.take() {
        encoder.body.finish(&mut out)?;
    }
    *body = (!out.is_empty()).then(|| Bytes::from(out));
    Ok(())
}

impl Body {
    fn feed(&mut self, chunk: &Bytes, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Gzip(gzip) => gzip.feed(chunk, out),
            Self::Brotli(brotli) => brotli.feed(chunk, out),
            Self::Zstd(zstd) => zstd.feed(chunk, out),
        }
    }

    fn finish(self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Gzip(mut gzip) => gzip.finish(out),
            Self::Brotli(brotli) => brotli.finish(out),
            Self::Zstd(zstd) => zstd.finish(out),
        }
    }
}

impl Gzip {
    fn new(level: u8) -> Self {
        let deflate_level = match level {
            0 | 1 => 1,
            2 => 4,
            _ => 6,
        };
        Self {
            deflate: Box::new(CompressorOxide::new(create_comp_flags_from_zip_params(
                deflate_level,
                -15,
                0,
            ))),
            scratch: vec![0; SCRATCH_BYTES].into_boxed_slice(),
            crc: crc32fast::Hasher::new(),
            len: 0,
            header_pending: true,
        }
    }

    fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        self.header(out);
        self.crc.update(chunk);
        // Wrapping is what the gzip trailer wants: the length modulo 2^32.
        self.len = self
            .len
            .wrapping_add(u32::try_from(chunk.len() % (1 << 32)).unwrap_or(0));
        self.encode(chunk, MZFlush::None, out)
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        self.header(out);
        self.encode(&[], MZFlush::Finish, out)?;
        out.extend_from_slice(&self.crc.clone().finalize().to_le_bytes());
        out.extend_from_slice(&self.len.to_le_bytes());
        Ok(())
    }

    fn header(&mut self, out: &mut Vec<u8>) {
        if self.header_pending {
            out.extend_from_slice(&GZIP_HEADER);
            self.header_pending = false;
        }
    }

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

/// Whether the response could be compressed, judging by the response alone.
fn candidate(response: &ResponseHeader, settings: &Settings) -> bool {
    let status = response.status.as_u16();
    let body_allowed = !matches!(status, 100..=199 | 204 | 205 | 206 | 304);
    let headers = &response.headers;
    let no_transform = headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.to_ascii_lowercase().contains("no-transform"));
    let tiny = headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|len| len < settings.min_bytes);
    let allowed = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| settings.allows(value));
    !settings.algorithms.is_empty()
        && body_allowed
        && !headers.contains_key("content-encoding")
        && !headers.contains_key("content-range")
        && !no_transform
        && !tiny
        && allowed
}

/// The first of `algorithms` the request's `Accept-Encoding` accepts.
fn negotiate(request: &RequestHeader, algorithms: &[Algorithm]) -> Option<Algorithm> {
    let offers = || {
        request
            .headers
            .get_all("accept-encoding")
            .iter()
            .filter_map(|value| value.to_str().ok())
    };
    algorithms
        .iter()
        .copied()
        .find(|algorithm| offers().any(|offer| accepts(offer, algorithm.token())))
}

/// Whether an `Accept-Encoding` value allows `token`: named with a non-zero quality, or allowed
/// by `*` when not named. An unreadable quality does not allow.
fn accepts(value: &str, token: &str) -> bool {
    let mut star = false;
    for item in value.split(',') {
        let mut parts = item.split(';');
        let coding = parts.next().unwrap_or_default().trim();
        let quality = parts
            .find_map(|param| param.trim().strip_prefix("q="))
            .map_or(Some(1.0), |q| q.trim().parse::<f32>().ok())
            .unwrap_or(0.0);
        if coding.eq_ignore_ascii_case(token) {
            return quality > 0.0;
        }
        if coding == "*" {
            star = quality > 0.0;
        }
    }
    star
}

/// Whether a lowercase media type is text-like.
fn is_text_like(media: &str) -> bool {
    media.starts_with("text/")
        || media.ends_with("+json")
        || media.ends_with("+xml")
        || matches!(
            media,
            "application/json"
                | "application/javascript"
                | "application/xml"
                | "application/x-ndjson"
        )
}

/// Adds `vary: accept-encoding` unless the response already varies by it or by everything.
fn add_vary(response: &mut ResponseHeader) {
    let varied = response
        .headers
        .get_all("vary")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|name| {
            let name = name.trim();
            name == "*" || name.eq_ignore_ascii_case("accept-encoding")
        });
    if !varied {
        // Ignored on failure: the response is then simply not varied by a header it did not have.
        drop(response.append_header("vary", "accept-encoding"));
    }
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

    fn all() -> Settings {
        Settings {
            algorithms: vec![Algorithm::Zstd, Algorithm::Brotli, Algorithm::Gzip],
            ..Settings::platform().clone()
        }
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

    fn unbrotli(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        ::brotli::BrotliDecompress(&mut &*bytes, &mut out).expect("valid brotli");
        out
    }

    fn unzstd(bytes: &[u8]) -> Vec<u8> {
        // libzstd, the decoder browsers use: independent of the encoder's crate.
        ::zstd::stream::decode_all(bytes).expect("valid zstd")
    }

    fn text() -> Vec<u8> {
        (0..200_000_u32)
            .flat_map(|n| format!("line {n}\n").into_bytes())
            .collect()
    }

    /// Compresses `original` in 64 KiB chunks with the algorithm `accept` selects.
    fn roundtrip(accept: &str, settings: &Settings, original: &[u8]) -> (ResponseHeader, Vec<u8>) {
        let tenant = tenant(u64::MAX);
        let mut head = response("text/plain");
        head.insert_header("content-length", original.len().to_string())
            .expect("header");
        let mut compression = start(&request(Some(accept)), &mut head, &tenant, settings);
        assert!(compression.is_some());
        let mut wire = Vec::new();
        let chunks: Vec<&[u8]> = original.chunks(65_536).collect();
        for (index, chunk) in chunks.iter().enumerate() {
            let mut body = Some(Bytes::copy_from_slice(chunk));
            filter(&mut compression, &mut body, index + 1 == chunks.len()).expect("encodes");
            wire.extend_from_slice(&body.unwrap_or_default());
        }
        assert!(compression.is_none(), "the stream ended");
        assert_eq!(tenant.buffered(), 0, "the charge is released at the end");
        (head, wire)
    }

    #[test]
    fn accept_encoding_is_parsed() {
        assert!(accepts("gzip", "gzip"));
        assert!(accepts("br, gzip;q=0.5", "gzip"));
        assert!(accepts("GZIP", "gzip"));
        assert!(accepts("*", "zstd"));
        assert!(!accepts("gzip;q=0", "gzip"));
        assert!(!accepts("gzip;q=0.0", "gzip"));
        assert!(!accepts("*;q=0, br", "gzip"));
        assert!(!accepts("gzip;q=0, *", "gzip"));
        assert!(accepts("gzip;q=0, *", "br"));
        assert!(!accepts("br, deflate", "gzip"));
        assert!(!accepts("gzip;q=abc", "gzip"), "unreadable quality refuses");
    }

    #[test]
    fn media_patterns_parse_and_match() {
        let exact = MediaPattern::parse("Text/HTML").expect("exact");
        assert!(exact.matches("text/html"));
        assert!(!exact.matches("text/plain"));
        let family = MediaPattern::parse("image/*").expect("family");
        assert!(family.matches("image/svg+xml"));
        assert!(!family.matches("text/image"));
        for bad in ["", "text", "text/", "/html", "text/html; charset=x", "*/*"] {
            assert!(MediaPattern::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn content_type_lists_apply_after_the_hard_exclusions() {
        let platform = Settings::platform();
        assert!(platform.allows("text/html; charset=utf-8"));
        assert!(platform.allows("application/problem+json"));
        assert!(!platform.allows("image/png"));
        assert!(!platform.allows("text/event-stream"));
        assert!(!platform.allows("application/grpc+proto"));

        let include = Settings {
            include: Some(vec![
                MediaPattern::parse("image/svg+xml").expect("p"),
                MediaPattern::parse("text/event-stream").expect("p"),
            ]),
            exclude: vec![MediaPattern::parse("text/css").expect("p")],
            ..platform.clone()
        };
        assert!(include.allows("image/svg+xml"));
        assert!(
            !include.allows("text/html"),
            "an include list replaces the default"
        );
        assert!(
            !include.allows("text/event-stream"),
            "streams are never compressed"
        );
        let exclude = Settings {
            exclude: vec![MediaPattern::parse("text/css").expect("p")],
            ..platform.clone()
        };
        assert!(!exclude.allows("text/css; charset=utf-8"));
        assert!(exclude.allows("text/html"));
    }

    #[test]
    fn every_algorithm_round_trips_through_a_real_decoder() {
        let original = text();
        let (head, wire) = roundtrip("gzip", &all(), &original);
        assert_eq!(head.headers["content-encoding"], "gzip");
        assert_eq!(gunzip(&wire), original);
        let (head, wire) = roundtrip("br", &all(), &original);
        assert_eq!(head.headers["content-encoding"], "br");
        assert_eq!(unbrotli(&wire), original);
        let (head, wire) = roundtrip("zstd", &all(), &original);
        assert_eq!(head.headers["content-encoding"], "zstd");
        assert_eq!(unzstd(&wire), original);
        assert!(wire.len() < original.len() / 2, "the text got smaller");
    }

    #[test]
    fn an_empty_body_is_a_valid_stream_in_every_algorithm() {
        for (accept, decode) in [
            ("gzip", gunzip as fn(&[u8]) -> Vec<u8>),
            ("br", unbrotli),
            ("zstd", unzstd),
        ] {
            let tenant = tenant(u64::MAX);
            let mut compression = start(
                &request(Some(accept)),
                &mut response("text/plain"),
                &tenant,
                &all(),
            );
            let mut body = None;
            filter(&mut compression, &mut body, true).expect("finishes");
            assert_eq!(decode(&body.expect("header and trailer")), b"", "{accept}");
        }
    }

    #[test]
    fn the_server_order_wins_among_what_the_client_accepts() {
        let tenant = tenant(u64::MAX);
        let encoding = |accept: &str| {
            let mut head = response("text/plain");
            start(&request(Some(accept)), &mut head, &tenant, &all());
            head.headers
                .get("content-encoding")
                .map(|v| v.to_str().expect("ascii").to_owned())
        };
        assert_eq!(encoding("gzip, br, zstd").as_deref(), Some("zstd"));
        assert_eq!(encoding("gzip, br;q=0.1").as_deref(), Some("br"));
        assert_eq!(encoding("gzip, br;q=0, zstd;q=0").as_deref(), Some("gzip"));
        assert_eq!(encoding("*;q=0.5").as_deref(), Some("zstd"));
        assert_eq!(encoding("deflate, identity"), None);
    }

    #[test]
    fn streams_headers_and_releases_the_charge() {
        let tenant = tenant(Algorithm::Gzip.reservation());
        let mut head = response("text/plain");
        head.insert_header("content-length", "5000")
            .expect("header");
        head.insert_header("etag", "\"abc\"").expect("header");
        let compression = start(
            &request(Some("gzip")),
            &mut head,
            &tenant,
            Settings::platform(),
        );
        assert!(compression.is_some());
        assert_eq!(tenant.buffered(), Algorithm::Gzip.reservation());
        assert_eq!(head.headers["content-encoding"], "gzip");
        assert_eq!(head.headers["transfer-encoding"], "chunked");
        assert_eq!(head.headers["vary"], "accept-encoding");
        assert_eq!(head.headers["etag"], "W/\"abc\"");
        assert!(!head.headers.contains_key("content-length"));
        drop(compression);
        assert_eq!(tenant.buffered(), 0, "a dropped encoder frees its charge");
    }

    #[test]
    fn a_full_budget_serves_identity_and_counts_it() {
        for algorithm in [Algorithm::Gzip, Algorithm::Brotli, Algorithm::Zstd] {
            let tenant = tenant(algorithm.reservation() - 1);
            let mut head = response("text/plain");
            let settings = Settings {
                algorithms: vec![algorithm],
                ..Settings::platform().clone()
            };
            let accept = algorithm.token();
            assert!(start(&request(Some(accept)), &mut head, &tenant, &settings).is_none());
            assert!(!head.headers.contains_key("content-encoding"));
            assert_eq!(head.headers["vary"], "accept-encoding");
            assert_eq!(tenant.buffered(), 0);
        }
    }

    #[test]
    fn leaves_ineligible_responses_alone() {
        let tenant = tenant(u64::MAX);
        let settings = Settings::platform();
        let start_with = |accept: Option<&str>, mutate: &dyn Fn(&mut ResponseHeader)| {
            let mut head = response("text/plain");
            mutate(&mut head);
            let started = start(&request(accept), &mut head, &tenant, settings).is_some();
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
        assert!(!start_with(Some("gzip"), &set("content-range", "bytes 0-9/10")).0);
        assert!(!start_with(Some("gzip"), &set("content-type", "image/png")).0);
        assert!(!start_with(Some("gzip"), &set("content-type", "text/event-stream")).0);
        assert!(!start_with(Some("gzip"), &set("content-type", "application/grpc")).0);
        for status in [204, 205, 206, 304] {
            let skipped = start_with(Some("gzip"), &|head| head.set_status(status).expect("ok"));
            assert!(!skipped.0, "{status}");
            assert!(!skipped.1.headers.contains_key("vary"), "{status}");
        }
        assert!(start_with(Some("gzip"), &|head| head.set_status(404).expect("ok")).0);
        assert!(start_with(Some("gzip"), &set("content-length", "10000")).0);
        assert_eq!(tenant.buffered(), 0, "a dropped encoder frees its charge");
    }

    #[test]
    fn head_requests_are_varied_and_not_compressed() {
        let tenant = tenant(u64::MAX);
        let mut head_request = RequestHeader::build("HEAD", b"/", None).expect("request");
        head_request
            .insert_header("accept-encoding", "gzip")
            .expect("header");
        let mut head = response("text/plain");
        assert!(start(&head_request, &mut head, &tenant, Settings::platform()).is_none());
        assert_eq!(head.headers["vary"], "accept-encoding");
        assert!(!head.headers.contains_key("content-encoding"));
    }

    #[test]
    fn vary_is_not_duplicated_and_algorithms_empty_changes_nothing() {
        let tenant = tenant(u64::MAX);
        let mut head = response("text/plain");
        head.insert_header("vary", "Origin, Accept-Encoding")
            .expect("header");
        start(
            &request(Some("gzip")),
            &mut head,
            &tenant,
            Settings::platform(),
        );
        assert_eq!(head.headers.get_all("vary").iter().count(), 1);
        let off = Settings {
            algorithms: Vec::new(),
            ..Settings::platform().clone()
        };
        let mut head = response("text/plain");
        assert!(start(&request(Some("gzip")), &mut head, &tenant, &off).is_none());
        assert!(!head.headers.contains_key("vary"));
    }
}
