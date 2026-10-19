//! Archive reading: footer discovery, manifest loading, bounded frame
//! decoding with end-to-end BLAKE3 verification.
//!
//! Every byte that comes back out of this module has been size-capped while
//! streaming and hash-verified against the manifest, so hostile archives fail
//! loudly instead of expanding or escaping.

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use blake3::Hash;

use crate::archive::manifest::{ChunkLocation, Manifest};
use crate::archive::writer::validate_footer;
use crate::archive::{
    parse_frame_header, Limits, FLAG_ENCRYPTED, FOOTER_MAGIC, FRAME_HEADER_LEN, HEADER_LEN, MAGIC,
    TRAILER_LEN, VERSION,
};
use crate::codec::xz_backend::XzCodec;
use crate::codec::zstd_backend::ZstdCodec;
use crate::codec::CodecId;
use crate::crypto::{derive_keys, ArchiveKeys, Auth, NONCE_LEN, TAG_LEN};
use crate::error::{CinderError, Result};

/// Minimum encrypted-payload overhead: nonce + authentication tag.
pub(crate) const AEAD_OVERHEAD: u64 = NONCE_LEN as u64 + TAG_LEN as u64;

struct Footer {
    manifest_offset: u64,
    manifest_len: u64,
    checksum4: [u8; 4],
    salt: [u8; 16],
}

/// Single-slot decoded-frame cache. Sequential extraction (and solid-stream
/// reads) keep hitting consecutive chunks of the same packed frame, so one
/// slot recovers nearly all locality while bounding extra memory to a single
/// frame's decompressed size.
struct FrameCache {
    offset: Option<u64>,
    data: Vec<u8>,
}

/// A parsed archive ready for random access.
pub struct ArchiveReader<R: Read + Seek> {
    inner: R,
    file_len: u64,
    pub manifest: Manifest,
    keys: Option<ArchiveKeys>,
    encrypted: bool,
    salt: [u8; 16],
    limits: Limits,
    cache: FrameCache,
    /// Cumulative decompressed bytes produced this session (for total-size budgets).
    pub(crate) produced_bytes: u64,
    /// Logical bytes returned to a caller this session. This is separate from
    /// decoded frame bytes because dedup/cache hits can return many logical
    /// bytes without decoding a new frame.
    logical_bytes: u64,
    /// Raw bytes physically read from the underlying reader this session —
    /// the honest metric for "random access didn't touch the whole archive".
    physical_bytes_read: u64,
}

impl<R: Read + Seek> ArchiveReader<R> {
    /// Open an archive from any seekable reader.
    ///
    /// Key material handling follows [`Auth`]: passphrases are derived here,
    /// after the footer (which carries the Argon2id salt) has been parsed.
    ///
    /// # Errors
    /// [`CinderError::CorruptArchive`] on bad magic/version/footer/manifest;
    /// [`CinderError::Encrypted`] when encrypted and auth is [`Auth::None`];
    /// [`CinderError::DecompressionBombSuspected`] when declared sizes exceed
    /// the configured caps.
    pub fn open(mut inner: R, auth: Auth, limits: Limits) -> Result<Self> {
        let file_len = inner.seek(SeekFrom::End(0))?;
        if file_len < HEADER_LEN + TRAILER_LEN {
            return Err(CinderError::CorruptArchive(format!(
                "file too small to be an archive ({file_len} bytes)"
            )));
        }
        // Header.
        inner.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; 32];
        inner.read_exact(&mut header)?;
        if &header[0..8] != MAGIC {
            return Err(CinderError::CorruptArchive("bad archive magic".into()));
        }
        let version = le_u32(&header[8..12], "header version")?;
        if version != VERSION {
            return Err(CinderError::UnsupportedVersion(version));
        }
        let flags = le_u32(&header[12..16], "header flags")?;
        if flags & !FLAG_ENCRYPTED != 0 || header[24..32].iter().any(|b| *b != 0) {
            return Err(CinderError::CorruptArchive(
                "unknown archive flags or non-zero reserved header bytes".into(),
            ));
        }
        let encrypted = flags & FLAG_ENCRYPTED != 0;

        // Footer trailer.
        let back = i64::try_from(TRAILER_LEN)
            .map_err(|_| CinderError::CorruptArchive("trailer size overflow".into()))?;
        inner.seek(SeekFrom::End(-back))?;
        let mut trailer = [0u8; 48];
        inner.read_exact(&mut trailer)?;
        if &trailer[40..48] != FOOTER_MAGIC {
            return Err(CinderError::CorruptArchive("bad footer magic".into()));
        }
        let footer = Footer {
            manifest_offset: le_u64(&trailer[0..8], "manifest offset")?,
            manifest_len: le_u64(&trailer[8..16], "manifest length")?,
            checksum4: trailer[16..20]
                .try_into()
                .map_err(|_| CinderError::CorruptArchive("trailer truncated".into()))?,
            salt: trailer[24..40]
                .try_into()
                .map_err(|_| CinderError::CorruptArchive("trailer truncated".into()))?,
        };
        if encrypted && matches!(auth, Auth::None) {
            return Err(CinderError::Encrypted);
        }
        validate_footer(
            footer.manifest_offset,
            footer.manifest_len,
            file_len,
            &limits,
        )?;

        // Manifest region.
        inner.seek(SeekFrom::Start(footer.manifest_offset))?;
        let manifest_len = usize::try_from(footer.manifest_len)
            .map_err(|_| CinderError::DecompressionBombSuspected(limits.max_manifest_bytes))?;
        let mut region = Vec::new();
        region
            .try_reserve_exact(manifest_len)
            .map_err(|_| CinderError::DecompressionBombSuspected(limits.max_manifest_bytes))?;
        region.resize(manifest_len, 0);
        inner.read_exact(&mut region)?;
        let got = blake3::hash(&region);
        if got.as_bytes()[..4] != footer.checksum4 {
            return Err(CinderError::CorruptArchive(
                "footer checksum does not match manifest region".into(),
            ));
        }
        // Derive keys only now that the footer salt is known.
        let keys = match auth {
            Auth::None => None,
            Auth::Passphrase(p) => Some(derive_keys(&p, &footer.salt)?),
            Auth::Keys(k) => Some(k),
        };
        if encrypted {
            region = keys
                .as_ref()
                .ok_or(CinderError::Encrypted)?
                .open_manifest(&region)?;
        }
        let manifest = Manifest::decode(&region)?;
        manifest.validate(&limits, file_len)?;

        Ok(Self {
            inner,
            file_len,
            manifest,
            keys,
            encrypted,
            salt: footer.salt,
            limits,
            cache: FrameCache {
                offset: None,
                data: Vec::new(),
            },
            produced_bytes: 0,
            logical_bytes: 0,
            physical_bytes_read: 0,
        })
    }

    /// Raw bytes physically read from the archive so far this session.
    #[must_use]
    pub const fn physical_bytes_read(&self) -> u64 {
        self.physical_bytes_read
    }

    /// Whether this archive's payloads are authenticated-encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// The KDF salt stored in the footer (zeros for plaintext archives).
    #[must_use]
    pub const fn kdf_salt(&self) -> [u8; 16] {
        self.salt
    }

    /// On-disk archive size in bytes.
    #[must_use]
    pub const fn archive_size(&self) -> u64 {
        self.file_len
    }

    /// Sum of all file lengths recorded in the manifest.
    #[must_use]
    pub fn total_input_bytes(&self) -> u64 {
        self.manifest.files.iter().map(|f| f.length).sum()
    }

    /// Paths of all files, in manifest order.
    #[must_use]
    pub fn list_files(&self) -> Vec<&PathBuf> {
        self.manifest.files.iter().map(|f| &f.path).collect()
    }

    /// Read and verify one unique chunk by identity.
    ///
    /// # Errors
    /// Corrupt archives, missing hashes, cap violations, wrong passphrase.
    pub fn read_chunk(&mut self, hash: &Hash) -> Result<Vec<u8>> {
        let loc = *self.manifest.chunk_pool.get(hash).ok_or_else(|| {
            CinderError::CorruptArchive(format!("chunk {hash} missing from pool"))
        })?;
        let frame_offset = loc.frame_offset;

        // Serve from the single-slot cache when the chunk sits in the last
        // decoded frame; the slice is still hash-checked before returning.
        if self.cache.offset == Some(frame_offset)
            && u64::from(loc.payload_offset) + u64::from(loc.payload_length)
                <= self.cache.data.len() as u64
        {
            let start = usize::try_from(loc.payload_offset).ok();
            let len = usize::try_from(loc.payload_length).ok();
            if let (Some(start), Some(len)) = (start, len) {
                if let Some(end) = start.checked_add(len) {
                    let slice = &self.cache.data[start..end];
                    if blake3::hash(slice) == *hash {
                        return Ok(slice.to_vec());
                    }
                }
            }
            // Cache said "same frame" but content disagrees → fall through to
            // the fully verified path, which will fail loudly or correct us.
        }

        let decoded = self.decode_chunk_strict(&loc, hash)?;
        self.produced_bytes = self
            .produced_bytes
            .checked_add(decoded.len() as u64)
            .ok_or(CinderError::DecompressionBombSuspected(
                self.limits.max_frame_raw,
            ))?;
        Ok(decoded)
    }

    /// Materialize `length` bytes of a stream starting at `offset`.
    ///
    /// # Errors
    /// See [`Self::read_chunk`].
    pub fn read_stream_range(
        &mut self,
        stream_id: u32,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        let stream = self
            .manifest
            .streams
            .get(stream_id as usize)
            .ok_or_else(|| CinderError::CorruptArchive(format!("stream {stream_id} missing")))?;
        if offset.saturating_add(length) > stream.length {
            return Err(CinderError::CorruptArchive(format!(
                "range [{offset}..{}] exceeds stream {} length {}",
                offset.saturating_add(length),
                stream_id,
                stream.length
            )));
        }
        // Clone the chunk list so `read_chunk` can take &mut self while we
        // iterate; chunk lists are bounded by the chunker's max size.
        let chunks = stream.chunks.clone();
        let mut out: Vec<u8> = Vec::new();
        let mut cursor = 0u64;
        let target_end = offset.saturating_add(length);
        for ch in &chunks {
            if cursor >= target_end {
                break;
            }
            let data = self.read_chunk(ch)?;
            let len = data.len() as u64;
            let chunk_end = cursor.saturating_add(len);
            let lo = cursor.max(offset);
            let hi = chunk_end.min(target_end);
            if hi > lo {
                let piece_len = hi - lo;
                let next_logical = self
                    .logical_bytes
                    .checked_add(piece_len)
                    .ok_or(CinderError::DecompressionBombSuspected(piece_len))?;
                if let Some(cap) = self.limits.max_total_raw {
                    if next_logical > cap {
                        return Err(CinderError::DecompressionBombSuspected(cap));
                    }
                }
                let piece_len_usize = usize::try_from(piece_len)
                    .map_err(|_| CinderError::DecompressionBombSuspected(piece_len))?;
                out.try_reserve(piece_len_usize).map_err(|_| {
                    CinderError::InvalidInput("unable to reserve extraction buffer".into())
                })?;
                let start = usize::try_from(lo - cursor).map_err(|_| {
                    CinderError::CorruptArchive("chunk slice offset overflow".into())
                })?;
                let end = usize::try_from(hi - cursor)
                    .map_err(|_| CinderError::CorruptArchive("chunk slice end overflow".into()))?;
                out.extend_from_slice(data.get(start..end).ok_or_else(|| {
                    CinderError::CorruptArchive("stream slice outside decoded chunk".into())
                })?);
                self.logical_bytes = next_logical;
            }
            cursor = chunk_end;
        }
        if out.len() as u64 != length {
            return Err(CinderError::CorruptArchive(format!(
                "stream {stream_id} yielded {} bytes, expected {length}",
                out.len()
            )));
        }
        Ok(out)
    }

    /// Strictly verified chunk fetch: bounds-checks the location against the
    /// physical file, decodes under the ceiling, verifies the fingerprint.
    #[allow(clippy::too_many_lines)]
    fn decode_chunk_strict(&mut self, loc: &ChunkLocation, expect: &Hash) -> Result<Vec<u8>> {
        let body_end = self.file_len.saturating_sub(TRAILER_LEN);
        if loc.frame_offset < HEADER_LEN || loc.frame_offset >= body_end {
            return Err(CinderError::CorruptArchive(format!(
                "chunk frame offset {} outside archive body",
                loc.frame_offset
            )));
        }
        let frame_end = loc
            .frame_offset
            .checked_add(u64::from(loc.frame_length))
            .ok_or_else(|| CinderError::CorruptArchive("frame length overflow".into()))?;
        if frame_end > body_end {
            return Err(CinderError::CorruptArchive(format!(
                "frame [{}, {}) overruns archive body ending at {body_end}",
                loc.frame_offset, frame_end
            )));
        }
        // A frame must at least hold its header; smaller frame_length values
        // are structurally impossible and would slice-p panic below.
        if u64::from(loc.frame_length) < FRAME_HEADER_LEN {
            return Err(CinderError::CorruptArchive(format!(
                "frame length {} shorter than a frame header",
                loc.frame_length
            )));
        }
        if u64::from(loc.payload_offset).saturating_add(u64::from(loc.payload_length))
            > self.limits.max_frame_raw
        {
            return Err(CinderError::CorruptArchive(
                "chunk location exceeds the frame size ceiling".into(),
            ));
        }

        self.inner.seek(SeekFrom::Start(loc.frame_offset))?;
        let frame_len = usize::try_from(loc.frame_length)
            .map_err(|_| CinderError::CorruptArchive("frame length does not fit usize".into()))?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(frame_len)
            .map_err(|_| CinderError::DecompressionBombSuspected(self.limits.max_frame_raw))?;
        raw.resize(frame_len, 0);
        self.inner.read_exact(&mut raw)?;
        self.physical_bytes_read = self
            .physical_bytes_read
            .checked_add(raw.len() as u64)
            .ok_or_else(|| CinderError::CorruptArchive("physical read counter overflow".into()))?;
        let hdr = parse_frame_header(&raw[..FRAME_HEADER_LEN as usize])?;
        let payload = &raw[FRAME_HEADER_LEN as usize..];
        if hdr.payload_len != payload.len() as u64 {
            return Err(CinderError::CorruptArchive(format!(
                "frame header claims {} payload bytes, found {}",
                hdr.payload_len,
                payload.len()
            )));
        }
        if hdr.raw_len > self.limits.max_frame_raw {
            return Err(CinderError::DecompressionBombSuspected(
                self.limits.max_frame_raw,
            ));
        }
        if hdr.encrypted != self.encrypted {
            return Err(CinderError::CorruptArchive(
                "frame encryption flag disagrees with archive encryption flag".into(),
            ));
        }
        if hdr.encrypted && hdr.payload_len < AEAD_OVERHEAD + 1 {
            return Err(CinderError::CorruptArchive(
                "encrypted payload shorter than nonce+tag".into(),
            ));
        }

        let plain: Vec<u8> = if hdr.encrypted {
            let k = self.keys.as_ref().ok_or(CinderError::Encrypted)?;
            k.open_frame(payload)?
        } else {
            payload.to_vec()
        };
        if plain.len() as u64 > self.limits.max_frame_raw {
            return Err(CinderError::DecompressionBombSuspected(
                self.limits.max_frame_raw,
            ));
        }

        let decoded = decode_payload(hdr.codec, &plain, hdr.raw_len, self.limits.max_frame_raw)?;

        // Slice + end-to-end integrity: must hash to the requested identity.
        let start = usize::try_from(loc.payload_offset)
            .map_err(|_| CinderError::CorruptArchive("chunk offset does not fit usize".into()))?;
        let end = start
            .checked_add(usize::try_from(loc.payload_length).map_err(|_| {
                CinderError::CorruptArchive("chunk length does not fit usize".into())
            })?)
            .ok_or_else(|| CinderError::CorruptArchive("chunk slice overflow".into()))?;
        if end > decoded.len() {
            return Err(CinderError::CorruptArchive(
                "chunk slice outside decoded frame".into(),
            ));
        }
        if blake3::hash(&decoded[start..end]) != *expect {
            return Err(CinderError::CorruptArchive(format!(
                "chunk content hash mismatch for {expect}"
            )));
        }

        // Populate the single-slot cache with the whole decoded frame.
        if decoded.len() as u64 <= self.limits.max_frame_raw {
            self.cache = FrameCache {
                offset: Some(loc.frame_offset),
                data: decoded.clone(),
            };
        }
        Ok(decoded[start..end].to_vec())
    }
}

fn le_u32(b: &[u8], what: &str) -> Result<u32> {
    b.try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| CinderError::CorruptArchive(format!("truncated {what}")))
}

fn le_u64(b: &[u8], what: &str) -> Result<u64> {
    b.try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| CinderError::CorruptArchive(format!("truncated {what}")))
}

/// Decode a frame payload according to its codec, enforcing both the exact
/// declared length and the caller's hard ceiling while streaming.
///
/// # Errors
/// [`CinderError::DecompressionBombSuspected`] / [`CinderError::CorruptArchive`].
pub(crate) fn decode_payload(
    codec: CodecId,
    payload: &[u8],
    declared: u64,
    max_size: u64,
) -> Result<Vec<u8>> {
    match codec {
        CodecId::Stored => {
            if declared > max_size {
                return Err(CinderError::DecompressionBombSuspected(max_size));
            }
            if payload.len() as u64 != declared {
                return Err(CinderError::CorruptArchive(format!(
                    "stored frame claims {declared} bytes, holds {}",
                    payload.len()
                )));
            }
            Ok(payload.to_vec())
        }
        CodecId::Zstd => ZstdCodec::decode_exact(payload, declared, max_size),
        CodecId::Xz => XzCodec::decode_exact(payload, declared, max_size),
    }
}
