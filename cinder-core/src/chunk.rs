//! Content-defined chunking (FastCDC, 2020 formulation).
//!
//! Cut points depend only on content, so identical regions of two files are cut
//! into identical chunks even when their absolute offsets differ. This is the
//! property that makes near-duplicate VM snapshots deduplicate almost entirely.

use blake3::Hash;
use fastcdc::v2020::{FastCDC, Normalization};

use crate::error::{CinderError, Result};
use crate::fingerprint;

/// Chunk size bounds. Defaults chosen to balance dedup granularity against
/// per-chunk framing overhead: 8 KiB minimum keeps tiny edits deduplicable,
/// 512 KiB maximum bounds worst-case memory per in-flight chunk.
#[derive(Debug, Clone)]
pub struct ChunkParams {
    /// Smallest possible chunk.
    pub min: usize,
    /// Target (mean) chunk size; FastCDC normalizes around this.
    pub avg: usize,
    /// Hard upper bound on chunk length.
    pub max: usize,
    /// Normalization level from the 2020 paper; higher = more uniform chunks.
    pub normalization: Normalization,
}

impl Default for ChunkParams {
    fn default() -> Self {
        Self {
            min: 8 * 1024,
            avg: 128 * 1024,
            max: 512 * 1024,
            normalization: Normalization::Level2,
        }
    }
}

impl ChunkParams {
    /// Validate that `min <= avg <= max` and all are non-zero.
    ///
    /// # Errors
    /// [`CinderError::InvalidInput`] when the parameters are nonsensical.
    pub fn validate(&self) -> Result<()> {
        if self.min == 0 || self.avg == 0 || self.max == 0 {
            return Err(CinderError::InvalidInput(
                "chunk sizes must be non-zero".into(),
            ));
        }
        if self.min > self.avg || self.avg > self.max {
            return Err(CinderError::InvalidInput(format!(
                "chunk params must satisfy min ({}) <= avg ({}) <= max ({})",
                self.min, self.avg, self.max
            )));
        }
        Ok(())
    }
}

/// A content-defined chunk: its fingerprint plus where it lives inside the
/// source buffer it was cut from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    pub hash: Hash,
    pub offset: u64,
    pub length: u32,
}

/// Cut `data` into content-defined chunks, hashing each one.
///
/// Empty input yields no chunks (callers model empty files as streams with a
/// zero-length chunk list).
#[must_use]
pub fn cut_chunks(data: &[u8], params: &ChunkParams) -> Vec<ChunkRef> {
    let chunker = FastCDC::with_level(
        data,
        params.min,
        params.avg,
        params.max,
        params.normalization,
    );
    chunker
        .map(|c| ChunkRef {
            hash: fingerprint::hash_chunk(&data[c.offset..c.offset + c.length]),
            offset: c.offset as u64,
            length: c.length as u32,
        })
        .collect()
}
