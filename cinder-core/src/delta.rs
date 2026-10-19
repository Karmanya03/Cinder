//! Delta snapshots built on top of the existing deterministic archive format.
//!
//! A delta archive contains only added/modified entries. A small sidecar
//! descriptor records the base archive digest and deletions, so applying it is
//! transactional at the logical snapshot level while keeping old `.cnd`
//! readers fully compatible.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::archive::reader::ArchiveReader;
use crate::crypto::Auth;
use crate::error::{CinderError, Result};
use crate::extract::{extract_archive, safe_destination, ExtractOptions};
use crate::pipeline::{compress_path, CompressOptions, ProgressEvent};
use crate::walk::{walk_tree, EntryKind};
use crate::Limits;

const DELTA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaReport {
    pub version: u32,
    pub base_archive_blake3: String,
    pub current_snapshot_blake3: String,
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    pub unchanged: usize,
    pub changed_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DeltaOptions {
    pub compression: CompressOptions,
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeltaDescriptor {
    version: u32,
    base_archive_blake3: String,
    delta_archive_blake3: String,
    report: DeltaReport,
}

/// Compare a live tree with a native archive snapshot.
pub fn compare_snapshot(
    base_archive: &Path,
    current_root: &Path,
    passphrase: Option<&str>,
) -> Result<DeltaReport> {
    let base_hash = hash_file(base_archive)?;
    let file = fs::File::open(base_archive)?;
    let auth = passphrase.map_or(Auth::None, |value| Auth::Passphrase(value.to_owned()));
    let mut reader = ArchiveReader::open(file, auth, Limits::default())?;
    let mut base = BTreeMap::new();
    let base_files = reader.manifest.files.clone();
    for entry in &base_files {
        let key = path_key(&entry.path);
        let digest = if let Some(target) = &entry.symlink_target {
            blake3::hash(target.to_string_lossy().as_bytes())
                .to_hex()
                .to_string()
        } else {
            let chunks = reader
                .manifest
                .streams
                .get(entry.stream_id as usize)
                .ok_or_else(|| CinderError::CorruptArchive("delta base stream missing".into()))?
                .chunks
                .clone();
            let mut hasher = blake3::Hasher::new();
            for chunk in &chunks {
                hasher.update(&reader.read_chunk(chunk)?);
            }
            hasher.finalize().to_hex().to_string()
        };
        base.insert(key, (digest, entry.length));
    }

    let walked = walk_tree(current_root)?;
    let mut current = BTreeMap::new();
    for entry in walked.entries {
        let key = entry.rel_path;
        let (digest, length) = match entry.kind {
            EntryKind::File { size, .. } => (hash_file(&entry.path)?, size),
            EntryKind::Symlink { target, .. } => (
                blake3::hash(target.to_string_lossy().as_bytes())
                    .to_hex()
                    .to_string(),
                0,
            ),
            EntryKind::Dir { .. } => continue,
        };
        current.insert(key, (digest, length));
    }

    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();
    let mut unchanged = 0usize;
    let mut changed_bytes = 0u64;
    for (path, (digest, length)) in &current {
        match base.get(path) {
            None => {
                added.push(path.clone());
                changed_bytes = changed_bytes.saturating_add(*length);
            }
            Some((old_digest, _)) if old_digest != digest => {
                modified.push(path.clone());
                changed_bytes = changed_bytes.saturating_add(*length);
            }
            Some(_) => unchanged += 1,
        }
    }
    for path in base.keys() {
        if !current.contains_key(path) {
            deleted.push(path.clone());
        }
    }
    let current_snapshot_blake3 = hash_tree(current_root)?;
    Ok(DeltaReport {
        version: DELTA_VERSION,
        base_archive_blake3: base_hash,
        current_snapshot_blake3,
        added,
        modified,
        deleted,
        unchanged,
        changed_bytes,
    })
}

/// Build a delta archive and its `.delta.json` descriptor.
pub fn build_delta(
    base_archive: &Path,
    current_root: &Path,
    output_archive: &Path,
    options: &DeltaOptions,
    progress: &Arc<dyn Fn(&ProgressEvent) + Send + Sync>,
) -> Result<DeltaReport> {
    let report = compare_snapshot(base_archive, current_root, options.passphrase.as_deref())?;
    let staging = temp_dir("delta")?;
    let walked = walk_tree(current_root)?;
    let changed: BTreeSet<&str> = report
        .added
        .iter()
        .chain(report.modified.iter())
        .map(String::as_str)
        .collect();
    for entry in walked.entries {
        if !changed.contains(entry.rel_path.as_str()) {
            continue;
        }
        let destination = staging.join(entry.rel_path.replace('/', std::path::MAIN_SEPARATOR_STR));
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        match entry.kind {
            EntryKind::File { .. } => {
                fs::copy(entry.path, destination)?;
            }
            EntryKind::Symlink { target, .. } => create_link(&destination, &target)?,
            EntryKind::Dir { .. } => {}
        }
    }
    compress_path(&staging, output_archive, &options.compression, progress)?;
    let descriptor = DeltaDescriptor {
        version: DELTA_VERSION,
        base_archive_blake3: report.base_archive_blake3.clone(),
        delta_archive_blake3: hash_file(output_archive)?,
        report: report.clone(),
    };
    let sidecar = delta_sidecar_path(output_archive);
    let bytes = serde_json::to_vec_pretty(&descriptor)
        .map_err(|e| CinderError::InvalidInput(format!("delta descriptor encode failed: {e}")))?;
    fs::write(sidecar, bytes)?;
    fs::remove_dir_all(staging).ok();
    Ok(report)
}

/// Apply a base archive plus a delta archive into a complete snapshot tree.
pub fn apply_delta(
    base_archive: &Path,
    delta_archive: &Path,
    output_root: &Path,
    passphrase: Option<&str>,
) -> Result<()> {
    let sidecar = delta_sidecar_path(delta_archive);
    let descriptor: DeltaDescriptor = serde_json::from_slice(&fs::read(sidecar)?)
        .map_err(|e| CinderError::CorruptArchive(format!("delta descriptor parse failed: {e}")))?;
    if descriptor.version != DELTA_VERSION
        || descriptor.base_archive_blake3 != hash_file(base_archive)?
    {
        return Err(CinderError::InvalidInput(
            "delta base archive does not match its descriptor".into(),
        ));
    }
    if descriptor.delta_archive_blake3 != hash_file(delta_archive)? {
        return Err(CinderError::CorruptArchive(
            "delta archive digest does not match its descriptor".into(),
        ));
    }
    let auth_options = ExtractOptions {
        overwrite: true,
        passphrase: passphrase.map(str::to_owned),
        ..ExtractOptions::default()
    };
    extract_archive(base_archive, output_root, &auth_options)?;
    extract_archive(delta_archive, output_root, &auth_options)?;
    let root = output_root.canonicalize()?;
    for deleted in descriptor.report.deleted {
        let destination = safe_destination(&root, &deleted)?;
        if destination.exists() || fs::symlink_metadata(&destination).is_ok() {
            fs::remove_file(&destination).or_else(|_| fs::remove_dir_all(&destination))?;
        }
    }
    let applied_hash = hash_tree(output_root)?;
    if applied_hash != descriptor.report.current_snapshot_blake3 {
        return Err(CinderError::CorruptArchive(format!(
            "applied delta does not reproduce expected snapshot (expected {}, got {})",
            descriptor.report.current_snapshot_blake3, applied_hash
        )));
    }
    Ok(())
}

#[must_use]
pub fn delta_sidecar_path(archive: &Path) -> PathBuf {
    archive.with_extension("delta.json")
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn hash_tree(root: &Path) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    for entry in walk_tree(root)?.entries {
        hasher.update(entry.rel_path.as_bytes());
        hasher.update(&[0]);
        match entry.kind {
            EntryKind::File { .. } => {
                let mut file = fs::File::open(entry.path)?;
                let mut buf = vec![0u8; 128 * 1024];
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
            }
            EntryKind::Symlink { target, .. } => {
                hasher.update(target.to_string_lossy().as_bytes());
            }
            EntryKind::Dir { .. } => {}
        }
        hasher.update(&[0xff]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn temp_dir(label: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "cinder-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&path)?;
    Ok(fs::canonicalize(path)?)
}

#[cfg(unix)]
fn create_link(path: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, path)?;
    Ok(())
}

#[cfg(windows)]
fn create_link(path: &Path, target: &Path) -> Result<()> {
    if target.to_string_lossy().is_empty() {
        return Err(CinderError::InvalidInput("empty delta link target".into()));
    }
    std::os::windows::fs::symlink_file(target, path)
        .or_else(|_| std::os::windows::fs::symlink_dir(target, path))?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_link(_path: &Path, _target: &Path) -> Result<()> {
    Err(CinderError::InvalidInput(
        "symlink deltas are unsupported on this platform".into(),
    ))
}
