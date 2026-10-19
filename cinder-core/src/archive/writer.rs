//! Frame-level writing primitives for the CINDERv1 container.
//!
//! [`FrameSink`] owns the output file and appends frames sequentially. The
//! threaded orchestration that feeds it lives in [`crate::pipeline`].

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use crate::archive::{
    encode_frame_header, parse_frame_header, Limits, FLAG_ENCRYPTED, HEADER_LEN, MAGIC,
    TRAILER_LEN, VERSION,
};
use crate::codec::CodecId;
use crate::crypto::{ArchiveKeys, SALT_LEN};
use crate::error::{CinderError, Result};

/// Where a freshly written frame landed on disk.
#[derive(Debug, Clone, Copy)]
pub struct FramePosition {
    pub offset: u64,
    pub total_len: u32,
}

/// Sequential frame writer for one archive file.
pub struct FrameSink {
    file: File,
    pos: u64,
}

impl FrameSink {
    /// Create a new archive at `path`, writing the 32-byte header.
    ///
    /// # Errors
    /// Propagates filesystem errors; refuses to truncate nothing — creation
    /// always starts a fresh archive.
    pub fn create(path: &Path, encrypted: bool, avg_chunk: u32) -> Result<Self> {
        let mut file = crate::extract::create_destination(path, true)?;
        let mut header = [0u8; 32];
        header[0..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&(if encrypted { FLAG_ENCRYPTED } else { 0 }).to_le_bytes());
        header[16..24].copy_from_slice(&u64::from(avg_chunk).to_le_bytes());
        // 24..32 reserved zeros
        file.write_all(&header)?;
        Ok(Self {
            file,
            pos: HEADER_LEN,
        })
    }

    /// Append one frame. `payload` must already be compressed/sealed as the
    /// worker chose; this layer only records framing.
    ///
    /// # Errors
    /// I/O errors, or a payload too large for the u32 on-disk length field.
    pub fn write_frame(
        &mut self,
        codec: CodecId,
        encrypted: bool,
        payload: &[u8],
        raw_len: u64,
    ) -> Result<FramePosition> {
        let total = crate::archive::FRAME_HEADER_LEN + payload.len() as u64;
        let total_u32 = u32::try_from(total)
            .map_err(|_| CinderError::InvalidInput("frame exceeds 4 GiB on-disk limit".into()))?;
        let header = encode_frame_header(codec, u8::from(encrypted), payload.len() as u64, raw_len);
        self.file.write_all(&header)?;
        self.file.write_all(payload)?;
        let offset = self.pos;
        self.pos = self
            .pos
            .checked_add(total)
            .ok_or_else(|| CinderError::InvalidInput("archive position overflow".into()))?;
        Ok(FramePosition {
            offset,
            total_len: total_u32,
        })
    }

    /// Current append position (== end of the last frame).
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.pos
    }

    /// Write the manifest region plus footer trailer and flush everything.
    ///
    /// Layout: manifest bytes (optionally sealed), then a fixed 48-byte
    /// trailer with the region's absolute offset/length, a BLAKE3 checksum of
    /// the stored region, and the KDF salt when the archive is encrypted.
    ///
    /// # Errors
    /// Propagates I/O errors and manifest sealing failures.
    pub fn finish(
        mut self,
        manifest_region: &[u8],
        keys: Option<&ArchiveKeys>,
        salt: &[u8; SALT_LEN],
    ) -> Result<()> {
        let stored: Vec<u8> = match keys {
            Some(k) => k.seal_manifest(manifest_region)?,
            None => manifest_region.to_vec(),
        };
        let manifest_offset = self.pos;
        let checksum = blake3::hash(&stored);
        self.file.write_all(&stored)?;

        let mut trailer = [0u8; 48];
        trailer[0..8].copy_from_slice(&manifest_offset.to_le_bytes());
        trailer[8..16].copy_from_slice(&(stored.len() as u64).to_le_bytes());
        trailer[16..20].copy_from_slice(&checksum.as_bytes()[..4]);
        // 20..24 reserved
        trailer[24..40].copy_from_slice(salt);
        trailer[40..48].copy_from_slice(crate::archive::FOOTER_MAGIC);
        self.file.write_all(&trailer)?;
        self.file.flush()?;
        self.file.sync_all().ok(); // durability is best-effort; failures surface on read anyway
        Ok(())
    }
}

/// Validate a parsed footer against the physical file length.
///
/// # Errors
/// [`CinderError::CorruptArchive`] when offsets point outside the file.
pub fn validate_footer(
    manifest_offset: u64,
    manifest_len: u64,
    file_len: u64,
    limits: &Limits,
) -> Result<()> {
    let body_end = file_len.saturating_sub(TRAILER_LEN);
    if manifest_offset < HEADER_LEN || manifest_offset > body_end {
        return Err(CinderError::CorruptArchive(format!(
            "manifest offset {manifest_offset} outside frame area [{HEADER_LEN}..{body_end}]"
        )));
    }
    if manifest_len > limits.max_manifest_bytes {
        return Err(crate::error::CinderError::DecompressionBombSuspected(
            limits.max_manifest_bytes,
        ));
    }
    let manifest_end = manifest_offset
        .checked_add(manifest_len)
        .ok_or_else(|| CinderError::CorruptArchive("manifest range overflow".into()))?;
    if manifest_end > body_end {
        return Err(CinderError::CorruptArchive(format!(
            "manifest region [{manifest_offset}..{manifest_end}] overruns frame area ending at {body_end}",
        )));
    }
    Ok(())
}

/// Re-parse helper used by tests and the reader to double-check framing.
///
/// # Errors
/// Propagates [`parse_frame_header`] failures.
pub fn recheck_frame(buf: &[u8]) -> Result<crate::archive::FrameHeader> {
    parse_frame_header(buf)
}

/// Seek convenience shared by reader paths.
///
/// # Errors
/// Propagates seek failures.
pub fn seek_to(file: &mut File, pos: u64) -> Result<()> {
    file.seek(SeekFrom::Start(pos))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_bounds_are_enforced() {
        let limits = Limits::default();
        // file of "100" bytes: body ends at 100-48=52.
        assert!(validate_footer(HEADER_LEN, 10, 100, &limits).is_ok());
        assert!(validate_footer(51, 1, 100, &limits).is_ok());
        assert!(validate_footer(52, 1, 100, &limits).is_err()); // starts past body
        assert!(validate_footer(30, 30, 100, &limits).is_err()); // overruns body
        assert!(validate_footer(0, 10, 100, &limits).is_err()); // inside header
    }
}
