//! Persistent, versioned cross-archive chunk index.
//!
//! The index stores identities and provenance, never plaintext chunk bytes.
//! It is therefore safe to back up as metadata, but it can still reveal that
//! two archives share content; callers should protect it accordingly.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::archive::reader::ArchiveReader;
use crate::crypto::Auth;
use crate::error::{CinderError, Result};
use crate::Limits;

const INDEX_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkRecord {
    length: u32,
    archives: Vec<String>,
    last_seen_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkIndex {
    pub version: u32,
    chunks: BTreeMap<String, ChunkRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkIndexStats {
    pub unique_chunks: usize,
    pub archive_references: usize,
    pub bytes_indexed: u64,
}

impl Default for ChunkIndex {
    fn default() -> Self {
        Self {
            version: INDEX_VERSION,
            chunks: BTreeMap::new(),
        }
    }
}

impl ChunkIndex {
    /// Load an index, returning an empty versioned index when the file is new.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)?;
        let index: Self = serde_json::from_slice(&bytes)
            .map_err(|e| CinderError::CorruptArchive(format!("chunk index parse failed: {e}")))?;
        if index.version != INDEX_VERSION {
            return Err(CinderError::UnsupportedVersion(index.version));
        }
        Ok(index)
    }

    /// Persist atomically through a same-directory temporary file and rename.
    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let lock_path = path.with_extension("lock");
        let _lock = IndexLock::acquire(&lock_path)?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| CinderError::InvalidInput(format!("chunk index encode failed: {e}")))?;
        let temp = path.with_extension(format!("tmp-{}", std::process::id()));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(path)?;
        }
        if let Err(rename_error) = fs::rename(&temp, path) {
            fs::remove_file(&temp).ok();
            return Err(rename_error.into());
        }
        Ok(())
    }

    /// Add all chunk identities from one native archive.
    pub fn add_archive(&mut self, archive: &Path, passphrase: Option<&str>) -> Result<usize> {
        let file = File::open(archive)?;
        let auth = passphrase.map_or(Auth::None, |value| Auth::Passphrase(value.to_owned()));
        let reader = ArchiveReader::open(file, auth, Limits::default())?;
        let archive_name = archive.display().to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let mut added = 0usize;
        for (hash, location) in &reader.manifest.chunk_pool {
            let key = hash.to_hex().to_string();
            let record = self.chunks.entry(key).or_insert_with(|| {
                added += 1;
                ChunkRecord {
                    length: location.payload_length,
                    archives: Vec::new(),
                    last_seen_unix_secs: now,
                }
            });
            record.length = location.payload_length;
            record.last_seen_unix_secs = now;
            if !record.archives.iter().any(|item| item == &archive_name) {
                record.archives.push(archive_name.clone());
                record.archives.sort();
            }
        }
        Ok(added)
    }

    #[must_use]
    pub fn stats(&self) -> ChunkIndexStats {
        ChunkIndexStats {
            unique_chunks: self.chunks.len(),
            archive_references: self.chunks.values().map(|v| v.archives.len()).sum(),
            bytes_indexed: self.chunks.values().map(|v| u64::from(v.length)).sum(),
        }
    }
}

/// Update an index from one archive and commit it atomically.
pub fn update_from_archive(
    index_path: &Path,
    archive: &Path,
    passphrase: Option<&str>,
) -> Result<ChunkIndexStats> {
    let mut index = ChunkIndex::load(index_path)?;
    index.add_archive(archive, passphrase)?;
    index.save(index_path)?;
    Ok(index.stats())
}

struct IndexLock {
    path: PathBuf,
    _file: File,
}

impl IndexLock {
    fn acquire(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    CinderError::InvalidInput(format!("chunk index is locked: {}", path.display()))
                } else {
                    CinderError::Io(e)
                }
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            _file: file,
        })
    }
}

impl Drop for IndexLock {
    fn drop(&mut self) {
        fs::remove_file(&self.path).ok();
    }
}

/// Rebuild an index from a list of archives.
pub fn rebuild(index_path: &Path, archives: &[PathBuf]) -> Result<ChunkIndexStats> {
    let mut index = ChunkIndex::default();
    for archive in archives {
        index.add_archive(archive, None)?;
    }
    index.save(index_path)?;
    Ok(index.stats())
}

#[allow(dead_code)]
fn read_all(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
