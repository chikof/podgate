//! Brotli encoding on the pure-Rust `brotli` crate, with the window and the effort capped so the
//! encoder's memory is a constant that [`super::Algorithm::reservation`] can charge up front.
//!
//! Measured with a counting allocator (`tests/compress_alloc.rs`), the encoder's match tables
//! hold 0.6 to 0.9 MiB at quality 1 to 3 (depending on the window), 1.8 MiB at quality 4 and
//! 35 MiB at quality 5. Quality 4 and 5 are therefore not offered, although the crate has them.

use std::io::{self, Write};

use ::brotli::CompressorWriter;

/// `lgwin` is fixed at 15: a 32 KiB window. The decoder needs the same, so a client's memory is
/// bounded too (the format's maximum is 16 MiB). Each step down saves about 150 KiB of tables.
const LGWIN: u32 = 15;

/// Bytes the writer stages output in before it hands them to the sink.
const STAGING_BYTES: usize = 16 * 1024;

/// A brotli stream in progress. The output sink is a `Vec` that [`Self::feed`] empties into the
/// caller's buffer, so nothing accumulates here between chunks.
pub(super) struct Brotli {
    writer: CompressorWriter<Vec<u8>>,
}

impl Brotli {
    /// `level` 1 to 3 is the brotli quality.
    pub(super) fn new(level: u8) -> Self {
        Self {
            writer: CompressorWriter::new(
                Vec::new(),
                STAGING_BYTES,
                u32::from(level.clamp(1, super::MAX_LEVEL)),
                LGWIN,
            ),
        }
    }

    /// Feeds `chunk`, appending what the encoder has ready to `out`.
    pub(super) fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        self.writer.write_all(chunk)?;
        out.append(self.writer.get_mut());
        Ok(())
    }

    /// Ends the stream, appending the rest to `out`.
    pub(super) fn finish(self, out: &mut Vec<u8>) -> io::Result<()> {
        out.append(&mut self.writer.into_inner());
        Ok(())
    }
}
