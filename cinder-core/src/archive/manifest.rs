//! Manifest: the archive's logical structure and its chunk seek table.
//!
//! Shape notes relative to the project brief's sketches:
//!
//! * `FileEntry.chunks` moved to [`StreamEntry`]. Files reference a stream
//!   plus a byte range inside it. This one indirection is what makes solid
//!   mode (many small files sharing chunks) and cross-file dedup expressible
//!   without duplicating chunk lists.
//! * `ChunkLocation` keeps the sketched `frame_offset`/`frame_length` pair and
//!   adds the in-frame payload slice, because several consecutive chunks can
//!   share one frame (packing) while dedup means one chunk may serve many
//!   files.
//!
//! The manifest is serialized as JSON: debuggable, hardened by serde_json's
//! parser (no panics on malformed input, recursion-limited), and bounded by
//! the reader's size cap before parsing.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::archive::{Limits, FRAME_HEADER_LEN, HEADER_LEN, TRAILER_LEN};
use crate::error::{CinderError, Result};
use crate::fingerprint;

/// Where a unique chunk lives inside the archive file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkLocation {
    /// Absolute byte offset of the frame header that stores this chunk.
    pub frame_offset: u64,
    /// Total on-disk size of that frame (header + payload).
    pub frame_length: u32,
    /// Offset of this chunk inside the frame's *decompressed* content.
    pub payload_offset: u32,
    /// Length of this chunk inside the frame's decompressed content.
    pub payload_length: u32,
}

/// An ordered sequence of chunks forming one logical byte stream.
///
/// Large files get a stream each; runs of small files are batched into shared
/// "solid" streams so compression sees multi-file context instead of per-file
/// overhead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEntry {
    pub chunks: Vec<blake3::Hash>,
    pub length: u64,
}

/// One regular file inside the archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Archive-relative path, `/`-separated. Never absolute; validated again
    /// on extraction (defense in depth — writers and readers are independent).
    pub path: PathBuf,
    pub mode: u32,
    pub symlink_target: Option<PathBuf>,
    pub stream_id: u32,
    /// Byte range of this file within its stream.
    pub offset: u64,
    pub length: u64,
}

/// A directory record (contents are implied by file paths).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirRecord {
    pub path: PathBuf,
    pub mode: u32,
}

/// The complete logical description of an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub directories: Vec<DirRecord>,
    pub files: Vec<FileEntry>,
    pub streams: Vec<StreamEntry>,
    /// Unique chunks: identity → where to find the bytes. The seek table.
    #[serde(with = "pool_serde")]
    pub chunk_pool: HashMap<blake3::Hash, ChunkLocation>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            format_version: crate::archive::VERSION,
            directories: Vec::new(),
            files: Vec::new(),
            streams: Vec::new(),
            chunk_pool: HashMap::new(),
        }
    }
}

impl Manifest {
    /// Encode to JSON bytes.
    ///
    /// # Errors
    /// Propagates serialization failures (should be unreachable for
    /// well-formed manifests; surfaced rather than ignored).
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CinderError::InvalidInput(format!("manifest encode failed: {e}")))
    }

    /// Decode from JSON bytes after the caller has applied any size cap.
    ///
    /// # Errors
    /// [`CinderError::CorruptArchive`] on malformed JSON or wrong version.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = serde_json::from_slice(bytes)
            .map_err(|e| CinderError::CorruptArchive(format!("manifest parse failed: {e}")))?;
        if m.format_version != crate::archive::VERSION {
            return Err(CinderError::UnsupportedVersion(m.format_version));
        }
        Ok(m)
    }

    /// Validate all attacker-controlled relationships before any extraction
    /// code touches the filesystem. This keeps malformed manifests from
    /// turning later indexing, allocation, or path handling into panics or
    /// unbounded work.
    pub fn validate(&self, limits: &Limits, file_len: u64) -> Result<()> {
        let entry_count = self
            .directories
            .len()
            .checked_add(self.files.len())
            .ok_or_else(|| CinderError::CorruptArchive("manifest entry count overflow".into()))?;
        if entry_count > limits.max_entries
            || self.streams.len() > limits.max_entries
            || self.chunk_pool.len() > limits.max_entries
        {
            return Err(CinderError::DecompressionBombSuspected(
                limits.max_entries as u64,
            ));
        }

        let body_end = file_len.saturating_sub(TRAILER_LEN);
        let mut names = HashSet::with_capacity(entry_count.min(1024));
        for d in &self.directories {
            validate_manifest_path(&d.path, limits)?;
            let name = d.path.to_string_lossy().into_owned();
            if !names.insert(name) {
                return Err(CinderError::CorruptArchive(
                    "duplicate manifest path".into(),
                ));
            }
        }

        let mut references = 0usize;
        for stream in &self.streams {
            references = references.checked_add(stream.chunks.len()).ok_or_else(|| {
                CinderError::CorruptArchive("chunk reference count overflow".into())
            })?;
            if references > limits.max_chunk_references {
                return Err(CinderError::DecompressionBombSuspected(
                    limits.max_chunk_references as u64,
                ));
            }
            let mut stream_bytes = 0u64;
            for hash in &stream.chunks {
                let Some(loc) = self.chunk_pool.get(hash) else {
                    return Err(CinderError::CorruptArchive(
                        "stream references a chunk missing from the pool".into(),
                    ));
                };
                validate_chunk_location(loc, body_end, limits)?;
                stream_bytes = stream_bytes
                    .checked_add(u64::from(loc.payload_length))
                    .ok_or_else(|| CinderError::CorruptArchive("stream length overflow".into()))?;
            }
            if stream_bytes != stream.length {
                return Err(CinderError::CorruptArchive(format!(
                    "stream length is {stream_bytes}, manifest claims {}",
                    stream.length
                )));
            }
        }

        for f in &self.files {
            validate_manifest_path(&f.path, limits)?;
            let name = f.path.to_string_lossy().into_owned();
            if !names.insert(name) {
                return Err(CinderError::CorruptArchive(
                    "duplicate manifest path".into(),
                ));
            }
            if let Some(target) = &f.symlink_target {
                let Some(raw_target) = target.to_str() else {
                    return Err(CinderError::PathTraversal(target.clone()));
                };
                // A link target may legitimately contain `..`; its physical
                // containment is checked later relative to the link. Bound
                // and reject only representation-level hazards here.
                if raw_target.is_empty()
                    || raw_target.len() > limits.max_path_bytes
                    || raw_target.contains('\0')
                {
                    return Err(CinderError::PathTraversal(target.clone()));
                }
                if f.stream_id != u32::MAX || f.offset != 0 || f.length != 0 {
                    return Err(CinderError::CorruptArchive(
                        "symlink carries regular-file stream metadata".into(),
                    ));
                }
            } else {
                let stream = self.streams.get(f.stream_id as usize).ok_or_else(|| {
                    CinderError::CorruptArchive("file references a missing stream".into())
                })?;
                if f.offset
                    .checked_add(f.length)
                    .is_none_or(|end| end > stream.length)
                {
                    return Err(CinderError::CorruptArchive(
                        "file range exceeds its stream".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_manifest_path(path: &Path, limits: &Limits) -> Result<()> {
    let Some(raw) = path.to_str() else {
        return Err(CinderError::CorruptArchive(
            "manifest path is not UTF-8".into(),
        ));
    };
    if raw.is_empty()
        || raw.len() > limits.max_path_bytes
        || raw.contains('\0')
        || raw.contains('\\')
        || raw.contains(':')
        || std::path::Path::new(raw).is_absolute()
    {
        return Err(CinderError::PathTraversal(path.to_path_buf()));
    }
    for part in raw.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(CinderError::PathTraversal(path.to_path_buf()));
        }
    }
    Ok(())
}

fn validate_chunk_location(loc: &ChunkLocation, body_end: u64, limits: &Limits) -> Result<()> {
    if loc.frame_offset < HEADER_LEN
        || u64::from(loc.frame_length) < FRAME_HEADER_LEN
        || loc
            .frame_offset
            .checked_add(u64::from(loc.frame_length))
            .is_none_or(|end| end > body_end)
        || loc.payload_length == 0
        || u64::from(loc.payload_offset)
            .checked_add(u64::from(loc.payload_length))
            .is_none_or(|end| end > limits.max_frame_raw)
    {
        return Err(CinderError::CorruptArchive(
            "chunk location is outside archive limits".into(),
        ));
    }
    Ok(())
}

/// Serde support for `HashMap<blake3::Hash, ChunkLocation>` via hex keys.
mod pool_serde {
    use super::{fingerprint, ChunkLocation};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub(crate) fn serialize<S>(
        pool: &HashMap<blake3::Hash, ChunkLocation>,
        s: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Sorted pairs give deterministic output without leaking key strings.
        let mut pairs: Vec<(String, &ChunkLocation)> = pool
            .iter()
            .map(|(h, loc)| (fingerprint::to_hex(h), loc))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs.serialize(s)
    }

    pub(crate) fn deserialize<'de, D>(
        d: D,
    ) -> Result<HashMap<blake3::Hash, ChunkLocation>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Same sorted-pair shape the serializer emits.
        let raw: Vec<(String, ChunkLocation)> = Vec::deserialize(d)?;
        let mut out = HashMap::with_capacity(raw.len());
        for (k, v) in raw {
            let hash = fingerprint::from_hex(&k).map_err(serde::de::Error::custom)?;
            if out.insert(hash, v).is_some() {
                return Err(serde::de::Error::custom("duplicate chunk hash"));
            }
        }
        Ok(out)
    }
}
