//! Cinder container format ("CINDERv1").
//!
//! ```text
//! ┌────────────────────────────┐  offset 0
//! │ archive header (32 B)      │  magic, version, flags, avg-chunk-size
//! ├────────────────────────────┤
//! │ frame 0 (28 B hdr+payload) │  independently decodable chunk frame
//! │ frame 1 ...                │  ...
//! ├────────────────────────────┤
//! │ manifest region (JSON)     │  files, streams, chunk pool (seek table)
//! ├────────────────────────────┤
//! │ footer trailer (48 B)      │  manifest offset/len/checksum, KDF salt
//! └────────────────────────────┘  EOF
//! ```
//!
//! Why a custom container rather than zeekstd-style seekable zstd: dedup
//! requires *per-chunk* independent compression (identical chunks anywhere in
//! any file collapse to one stored frame). A seekable single-stream format
//! cannot express that; conversely, once every chunk is its own frame, random
//! access falls out of the manifest for free — the manifest *is* the seek
//! table. (zeekstd was evaluated 2026-08 and is actively maintained, so this
//! is an architecture call, not a maintenance call.)
//!
//! All multi-byte integers are little-endian. Offsets are absolute byte
//! positions in the archive file.

pub mod manifest;
pub mod reader;
pub mod writer;

use crate::codec::CodecId;
use crate::error::{CinderError, Result};

/// Archive-start magic.
pub const MAGIC: &[u8; 8] = b"CINDERv1";
/// Footer-trailer magic.
pub const FOOTER_MAGIC: &[u8; 8] = b"CNDfoot1";
/// Frame-header magic.
pub const FRAME_MAGIC: &[u8; 8] = b"CNDfrme1";

/// Container format version this build writes and accepts.
pub const VERSION: u32 = 1;

/// Fixed size of the archive header.
pub const HEADER_LEN: u64 = 32;
/// Fixed size of the frame header.
pub const FRAME_HEADER_LEN: u64 = 28;
/// Fixed size of the footer trailer.
pub const TRAILER_LEN: u64 = 48;

/// Header/footer flag: payloads and manifest are authenticated-encrypted.
pub const FLAG_ENCRYPTED: u32 = 1 << 0;
/// Frame-header flag: this frame's payload is AEAD-sealed.
pub const FRAME_FLAG_ENCRYPTED: u8 = 1 << 0;

/// Caps applied while *reading* archives (write-side ceilings are enforced
/// inline where the values are produced).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum decompressed size accepted for a single frame.
    pub max_frame_raw: u64,
    /// Maximum manifest region size accepted.
    pub max_manifest_bytes: u64,
    /// Optional cumulative budget across a whole extraction; `None` disables.
    /// Hostile-input tests set this low to prove the ceiling is honored.
    pub max_total_raw: Option<u64>,
    /// Refuse archives claiming more entries than this.
    pub max_entries: usize,
    /// Refuse paths and link targets longer than this many UTF-8 bytes.
    pub max_path_bytes: usize,
    /// Refuse manifests with more total stream-to-chunk references than this.
    pub max_chunk_references: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_raw: 256 * 1024 * 1024,
            max_manifest_bytes: 512 * 1024 * 1024,
            // A finite default prevents a caller from accidentally turning a
            // hostile archive into an unbounded logical-output generator.
            max_total_raw: Some(256 * 1024 * 1024 * 1024),
            max_entries: 10_000_000,
            max_path_bytes: 4096,
            max_chunk_references: 10_000_000,
        }
    }
}

/// Header flags for a fresh archive.
#[must_use]
pub fn header_flags_encrypted() -> u32 {
    FLAG_ENCRYPTED
}

/// Serialize a frame header.
#[must_use]
pub fn encode_frame_header(codec: CodecId, flags: u8, payload_len: u64, raw_len: u64) -> [u8; 28] {
    let mut h = [0u8; 28];
    h[0..8].copy_from_slice(FRAME_MAGIC);
    h[8] = codec as u8;
    h[9] = flags;
    h[10..12].copy_from_slice(&0u16.to_le_bytes());
    h[12..20].copy_from_slice(&payload_len.to_le_bytes());
    h[20..28].copy_from_slice(&raw_len.to_le_bytes());
    h
}

/// A parsed frame header.
#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    pub codec: CodecId,
    pub encrypted: bool,
    pub payload_len: u64,
    pub raw_len: u64,
}

/// Parse and sanity-check a frame header.
///
/// # Errors
/// [`CinderError::CorruptArchive`] on bad magic, unknown codec/flag bits, or
/// zero lengths (a frame always carries at least one byte of content).
pub fn parse_frame_header(buf: &[u8]) -> Result<FrameHeader> {
    if buf.len() < 28 {
        return Err(CinderError::CorruptArchive(format!(
            "frame header truncated: {} bytes",
            buf.len()
        )));
    }
    if &buf[0..8] != FRAME_MAGIC {
        return Err(CinderError::CorruptArchive("bad frame magic".into()));
    }
    let Some(codec) = CodecId::from_u8(buf[8]) else {
        return Err(CinderError::CorruptArchive(format!(
            "unknown codec id {}",
            buf[8]
        )));
    };
    if buf[9] & !FRAME_FLAG_ENCRYPTED != 0 {
        return Err(CinderError::CorruptArchive(format!(
            "unknown frame flag bits {:#x}",
            buf[9]
        )));
    }
    let payload_len = u64::from_le_bytes(
        buf[12..20]
            .try_into()
            .map_err(|_| CinderError::CorruptArchive("unreachable slice conversion".into()))?,
    );
    let raw_len = u64::from_le_bytes(
        buf[20..28]
            .try_into()
            .map_err(|_| CinderError::CorruptArchive("unreachable slice conversion".into()))?,
    );
    if payload_len == 0 || raw_len == 0 {
        return Err(CinderError::CorruptArchive(
            "frame with zero-length payload or content".into(),
        ));
    }
    Ok(FrameHeader {
        codec,
        encrypted: buf[9] & FRAME_FLAG_ENCRYPTED != 0,
        payload_len,
        raw_len,
    })
}
