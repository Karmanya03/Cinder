//! Zstandard backend.
//!
//! Levels follow zstd semantics: positive 1..=19, and negative levels
//! (-5..=0) trade ratio for speed on the `--fast=N` path.

use std::io::{Cursor, Read};

use zstd::stream::read::Decoder;

use crate::codec::{bounded_decode, Codec};
use crate::error::{CinderError, Result};

/// Zstd-backed codec at a fixed compression level.
#[derive(Debug, Clone)]
pub struct ZstdCodec {
    level: i32,
}

impl ZstdCodec {
    #[must_use]
    pub const fn new(level: i32) -> Self {
        Self { level }
    }

    /// Streaming decode used by the archive reader: yields exactly `declared`
    /// bytes or fails. Trailing garbage after the frame is rejected because
    /// the decoder must reach clean EOF.
    ///
    /// # Errors
    /// [`CinderError::DecompressionBombSuspected`] when the payload expands
    /// past `max_size` mid-stream; [`CinderError::CorruptArchive`] when it
    /// produces fewer than `declared` bytes.
    pub(crate) fn decode_exact(input: &[u8], declared: u64, max_size: u64) -> Result<Vec<u8>> {
        let reader = Decoder::new(Cursor::new(input))
            .map_err(|e| CinderError::Codec(format!("zstd decoder init failed: {e}")))?;
        finish_exact(reader.take(declared.saturating_add(1)), declared, max_size)
    }
}

/// Shared tail of every bounded streaming decode.
pub(crate) fn finish_exact<R: Read>(
    mut limited: std::io::Take<R>,
    declared: u64,
    max_size: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    limited
        .read_to_end(&mut out)
        .map_err(|e| CinderError::Codec(format!("stream decode failed: {e}")))?;
    let produced = out.len() as u64;
    if produced > declared {
        // The Take cap was hit: payload claims less than it actually expands to.
        return Err(CinderError::DecompressionBombSuspected(max_size));
    }
    if produced < declared {
        return Err(CinderError::CorruptArchive(format!(
            "frame declared {declared} decompressed bytes but yielded {produced}"
        )));
    }
    Ok(out)
}

impl Codec for ZstdCodec {
    fn compress(&self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        // bulk::compress allocates the exact bound internally; handing it a
        // caller-owned buffer would require pre-reserving zstd's worst-case
        // bound, which wastes memory on every chunk.
        let compressed = zstd::bulk::compress(input, self.level)
            .map_err(|e| CinderError::Codec(format!("zstd compress failed: {e}")))?;
        out.clear();
        out.extend_from_slice(&compressed);
        Ok(())
    }

    fn decompress(&self, input: &[u8], out: &mut Vec<u8>, max_size: u64) -> Result<()> {
        // Bounded while streaming via io::Take inside bounded_decode; `out`
        // only ever receives bytes that fit under the ceiling (+1 probe byte).
        let decoded = bounded_decode(|| Decoder::new(Cursor::new(input)), max_size, max_size)?;
        out.clear();
        out.extend_from_slice(&decoded);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "zstd"
    }

    fn id(&self) -> crate::codec::CodecId {
        crate::codec::CodecId::Zstd
    }
}
