//! Zstandard encoding on the pure-Rust `ruzstd` crate.
//!
//! `ruzstd` 0.9 has no push-style streaming encoder: [`FrameCompressor::compress`] pulls one whole
//! frame from a reader. Each slice of at most [`FRAME_BYTES`] of the body is therefore its own
//! frame. Concatenated frames are one valid zstd stream (RFC 8878 section 3.1), and every frame
//! declares a window of 128 KiB at most, so the window never exceeds that whatever the body does.
//! This is what keeps the encoder out of the unbounded-window class of GHSA-x5pf-cqh3-2gv8.
//!
//! The price is ratio: matches never reach across a frame boundary. The frame size is also what
//! sets the memory: the encoder's suffix table has one 8-byte slot per byte of the frame
//! (rounded up to a power of two), so 32 KiB frames hold 256 KiB there and 64 KiB frames 512 KiB.

use std::io::{self, Cursor};

use bytes::Bytes;
use ruzstd::encoding::{CompressionLevel, FrameCompressor, MatchGeneratorDriver};

/// The most body bytes in one frame.
const FRAME_BYTES: usize = 32 * 1024;

/// A zstd stream in progress: one reusable compressor, so each frame reuses the buffers of the
/// last.
pub(super) struct Zstd {
    frames: FrameCompressor<Cursor<Bytes>, Vec<u8>, MatchGeneratorDriver>,
    wrote_any: bool,
}

impl Zstd {
    pub(super) fn new() -> Self {
        Self {
            frames: FrameCompressor::new(CompressionLevel::Fastest),
            wrote_any: false,
        }
    }

    /// Compresses `chunk` as frames, appending them to `out`. An empty chunk writes nothing.
    pub(super) fn feed(&mut self, chunk: &Bytes, out: &mut Vec<u8>) -> io::Result<()> {
        let mut start = 0;
        while start < chunk.len() {
            let end = chunk.len().min(start + FRAME_BYTES);
            self.frame(chunk.slice(start..end), out);
            start = end;
        }
        Ok(())
    }

    /// Ends the stream. A body that had no bytes still gets one empty frame, so the client sees
    /// a valid stream.
    pub(super) fn finish(mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if !self.wrote_any {
            self.frame(Bytes::new(), out);
        }
        Ok(())
    }

    fn frame(&mut self, slice: Bytes, out: &mut Vec<u8>) {
        self.frames.set_source(Cursor::new(slice));
        self.frames.set_drain(std::mem::take(out));
        self.frames.compress();
        self.wrote_any = true;
        if let Some(drain) = self.frames.take_drain() {
            *out = drain;
        }
        drop(self.frames.take_source());
    }
}
