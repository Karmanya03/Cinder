//! Tiered codec abstraction.
//!
//! Cinder does not implement its own entropy coder; it wraps three profiles
//! around mature codecs:
//!
//! * [`Profile::Fast`]     — zstd levels -5..=3 for data touched again soon.
//! * [`Profile::Balanced`] — zstd level 15, the default.
//! * [`Profile::Max`]      — xz/LZMA level 9 for compress-once data.
//!
//! Every backend must enforce the caller's `max_size` *while decoding*, not
//! after a full decompress. That is where decompression-bomb defense lives.

pub mod xz_backend;
pub mod zstd_backend;

use std::io::Read;

use crate::error::{CinderError, Result};

/// Compression profile tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Fast turnaround, modest ratio (zstd 1-3 or negative `--fast=N`).
    Fast,
    /// Default tier (zstd 15).
    Balanced,
    /// Best ratio, slowest (xz/LZMA 9).
    Max,
}

/// Numeric codec identifier stored in every frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CodecId {
    /// Payload is the raw bytes verbatim (incompressible content).
    Stored = 0,
    /// Zstandard single frame.
    Zstd = 1,
    /// XZ / LZMA2 stream.
    Xz = 2,
}

impl CodecId {
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Stored),
            1 => Some(Self::Zstd),
            2 => Some(Self::Xz),
            _ => None,
        }
    }
}

/// A compression backend. Implementations are cheap to share across threads.
pub trait Codec: Send + Sync {
    fn compress(&self, input: &[u8], out: &mut Vec<u8>) -> Result<()>;
    /// Must enforce `max_size` while streaming, not after a full decompress.
    ///
    /// # Errors
    /// [`CinderError::DecompressionBombSuspected`] when output would exceed
    /// `max_size`; [`CinderError::CorruptArchive`] on malformed payloads.
    fn decompress(&self, input: &[u8], out: &mut Vec<u8>, max_size: u64) -> Result<()>;
    fn name(&self) -> &'static str;
    /// Numeric identifier recorded in frame headers.
    fn id(&self) -> CodecId;
}

/// Decode helper shared by all backends: streams through `io::Take` so a
/// hostile payload can never allocate more than `max_size` (+1 probe byte).
pub(crate) fn bounded_decode<R, F>(make_reader: F, max_size: u64, declared: u64) -> Result<Vec<u8>>
where
    R: Read,
    F: FnOnce() -> std::io::Result<R>,
{
    if declared > max_size {
        return Err(CinderError::DecompressionBombSuspected(max_size));
    }
    let reader =
        make_reader().map_err(|e| CinderError::Codec(format!("decoder init failed: {e}")))?;
    // Allow one extra byte so "produces more than declared" is detectable.
    let mut limited = reader.take(declared.saturating_add(1));
    let mut out = Vec::new();
    limited
        .read_to_end(&mut out)
        .map_err(|e| CinderError::Codec(format!("stream decode failed: {e}")))?;
    let produced = out.len() as u64;
    if produced > declared {
        return Err(CinderError::DecompressionBombSuspected(max_size));
    }
    if produced < declared {
        return Err(CinderError::CorruptArchive(format!(
            "declared {declared} decompressed bytes but payload yielded {produced}"
        )));
    }
    Ok(out)
}

/// Build the backend matching `profile`. `fast_level_override` applies only to
/// [`Profile::Fast`] and encodes negative ("--fast=N") levels as negative values.
#[must_use]
pub fn codec_for_profile(profile: Profile, fast_level_override: Option<i32>) -> Box<dyn Codec> {
    match profile {
        Profile::Fast => {
            let lvl = fast_level_override.unwrap_or(3);
            Box::new(zstd_backend::ZstdCodec::new(lvl.clamp(-5, 19)))
        }
        Profile::Balanced => Box::new(zstd_backend::ZstdCodec::new(15)),
        Profile::Max => Box::new(xz_backend::XzCodec),
    }
}
