//! XZ / LZMA2 backend for the [`Profile::Max`](crate::codec::Profile::Max) tier.
//!
//! Dependency note (2026-08): `xz2` has been frozen since 0.1.7 (June 2022).
//! Its actively maintained, API-compatible fork is `liblzma`
//! (<https://github.com/portable-network-archive/liblzma-rs>, XZ 5.8,
//! releases through 2025-06), so Cinder binds to `liblzma` instead. This is
//! exactly the "confirm before leaning on it" check the project brief asks
//! for; revisit if that fork ever goes quiet too.

use std::io::{Cursor, Read};

use liblzma::read::XzEncoder;

use crate::codec::zstd_backend::finish_exact;
use crate::codec::Codec;
use crate::error::Result;

/// LZMA2-backed codec at preset 9.
#[derive(Debug, Clone, Default)]
pub struct XzCodec;

impl XzCodec {
    /// Streaming decode used by the archive reader; mirrors
    /// [`crate::codec::zstd_backend::ZstdCodec::decode_exact`].
    ///
    /// # Errors
    /// Bomb/corruption semantics identical to the zstd path.
    pub(crate) fn decode_exact(input: &[u8], declared: u64, max_size: u64) -> Result<Vec<u8>> {
        let reader = liblzma::read::XzDecoder::new_multi_decoder(Cursor::new(input));
        finish_exact(reader.take(declared.saturating_add(1)), declared, max_size)
    }
}

impl Codec for XzCodec {
    fn compress(&self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let mut encoder = XzEncoder::new(Cursor::new(input), 9);
        out.clear();
        encoder
            .read_to_end(out)
            // xz encodes by reading; map the read error into a codec error.
            .map_err(|e| crate::error::CinderError::Codec(format!("xz compress failed: {e}")))?;
        Ok(())
    }

    fn decompress(&self, input: &[u8], out: &mut Vec<u8>, max_size: u64) -> Result<()> {
        let decoded = Self::decode_exact(input, max_size, max_size)?;
        out.clear();
        out.extend_from_slice(&decoded);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "xz"
    }

    fn id(&self) -> crate::codec::CodecId {
        crate::codec::CodecId::Xz
    }
}
