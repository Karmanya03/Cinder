//! Hardened extraction.
//!
//! Safety invariants enforced here, proven by tests in `tests/security.rs`:
//!
//! 1. **Path traversal**: no manifest-derived path may resolve outside the
//!    extraction root — checked lexically (components), physically (symlinks
//!    inside the root are refused as path components), and by canonicalization
//!    after creation. The *whole archive* is rejected on the first violation;
//!    nothing is extracted past that point.
//! 2. **Decompression bombs**: every frame decode is bounded while streaming
//!    (`io::Take` inside the codec backends), cross-checked against a per-frame
//!    ceiling, and optionally against a cumulative budget for the whole run.
//! 3. **Symlinks**: recreated only when their resolved destination stays
//!    inside the root and the target string is relative.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use crate::archive::reader::ArchiveReader;
use crate::crypto::Auth;
use crate::error::{CinderError, Result};

/// What to do with symbolic links found in the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymlinkPolicy {
    /// Recreate links whose targets resolve inside the root (default).
    #[default]
    PreserveSafe,
    /// Never create links; write an empty placeholder file instead.
    Skip,
}

/// Caps applied while opening and extracting.
///
/// Single source of truth lives in [`crate::archive::Limits`] so readers,
/// writers and extraction share one type.
pub use crate::archive::Limits;

/// Options for extraction entry points.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    pub limits: Limits,
    pub symlink_policy: SymlinkPolicy,
    /// Overwrite existing files at destination paths.
    pub overwrite: bool,
    /// Passphrase for encrypted archives.
    pub passphrase: Option<String>,
}

/// Measured outcome of an extraction.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExtractStats {
    pub files_written: u64,
    pub dirs_created: u64,
    pub symlinks_created: u64,
    pub symlinks_skipped: u64,
    pub bytes_written: u64,
}

/// Windows reserved device names — creating these via an extractor is never
/// intended behavior.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn traversal(rel: &str) -> CinderError {
    CinderError::PathTraversal(PathBuf::from(rel))
}

fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Validate one archive-relative component of a path.
///
/// # Errors
/// [`CinderError::PathTraversal`] on any violation.
fn validate_component(part: &str, rel: &str) -> Result<()> {
    match part {
        "" | "." | ".." => Err(traversal(rel)),
        p => {
            if p.contains(':') || p.contains('\0') || p.contains('\\') {
                return Err(traversal(rel));
            }
            let stem = p.split('.').next().unwrap_or(p);
            if WINDOWS_RESERVED
                .iter()
                .any(|r| r.eq_ignore_ascii_case(stem))
            {
                return Err(traversal(rel));
            }
            Ok(())
        }
    }
}

/// Validate an archive-relative path and return its absolute destination.
///
/// Lexical pass first (rejects absolute paths, `..`, `.`, drive prefixes,
/// NULs, backslash separators, Windows device names), then every intermediate
/// prefix directory is checked so that a symlink planted earlier in the same
/// extraction cannot redirect later writes outside the root.
///
/// # Errors
/// [`CinderError::PathTraversal`] on any violation.
pub fn safe_destination(root_canonical: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() || rel.len() > 4096 || rel.contains('\0') {
        return Err(traversal(rel));
    }
    if Path::new(rel).is_absolute() {
        return Err(traversal(rel));
    }

    let mut dest = root_canonical.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        validate_component(part, rel)?;
        dest.push(part);
        if i + 1 < parts.len() {
            // Intermediate component must be a plain directory if present.
            if let Ok(md) = fs::symlink_metadata(&dest) {
                if is_symlink_or_reparse(&md) || !md.is_dir() {
                    return Err(CinderError::PathTraversal(dest.clone()));
                }
            }
        }
    }
    Ok(dest)
}

/// Canonicalize-check that stays honest when the leaf doesn't exist yet:
/// walks up to the nearest existing ancestor and verifies containment.
fn assert_within_root(root_canonical: &Path, path: &Path) -> Result<()> {
    let mut probe = path.to_path_buf();
    loop {
        if probe.exists() && !is_symlink_or_reparse(&fs::symlink_metadata(&probe)?) {
            break;
        }
        if !probe.pop() {
            break;
        }
    }
    let canon = probe.canonicalize()?;
    if !canon.starts_with(root_canonical) {
        return Err(CinderError::PathTraversal(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_parent(root_canonical: &Path, path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(CinderError::CorruptArchive("entry without parent".into()));
    };
    fs::create_dir_all(parent)?;
    assert_within_root(root_canonical, parent)
}

// Returns Result on every platform so callers need no cfg-gating; the
// Windows body simply has nothing to fail on today.
#[allow(clippy::unnecessary_wraps)]
fn apply_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// Reject a user-selected root or output parent that would route writes
/// through a pre-existing symlink/reparse point. Archive entries get the same
/// check at each intermediate component via [`safe_destination`].
pub fn ensure_no_symlink_components(path: &Path) -> Result<()> {
    let mut component_path = PathBuf::new();
    for component in path.components() {
        component_path.push(component.as_os_str());
        if let Ok(meta) = fs::symlink_metadata(&component_path) {
            if is_symlink_or_reparse(&meta) {
                return Err(CinderError::PathTraversal(component_path));
            }
        }
    }
    Ok(())
}

/// Budget tracker shared across all writes of one extraction run.
struct Budget {
    spent: u64,
    cap: Option<u64>,
}

impl Budget {
    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.spent =
            self.spent
                .checked_add(bytes)
                .ok_or(CinderError::DecompressionBombSuspected(
                    self.cap.unwrap_or(u64::MAX),
                ))?;
        if let Some(cap) = self.cap {
            if self.spent > cap {
                return Err(CinderError::DecompressionBombSuspected(cap));
            }
        }
        Ok(())
    }
}

/// Open a destination without following a final symlink. The default is
/// create-new; explicit overwrite still uses platform no-follow/reparse-point
/// flags so a destination link cannot redirect an archive write elsewhere.
pub fn create_destination(path: &Path, overwrite: bool) -> Result<File> {
    if let Some(parent) = path.parent() {
        ensure_no_symlink_components(parent)?;
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if is_symlink_or_reparse(&meta) {
            return Err(CinderError::PathTraversal(path.to_path_buf()));
        }
        if !overwrite {
            return Err(CinderError::InvalidInput(format!(
                "refusing to overwrite existing {}",
                path.display()
            )));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(overwrite);
    if !overwrite {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT prevents following a final Windows
        // junction/symlink when overwrite mode is explicitly requested.
        options.custom_flags(0x0020_0000);
    }
    options.open(path).map_err(CinderError::Io)
}

fn entry_rel_string(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        CinderError::CorruptArchive(format!("non-UTF-8 entry path {}", path.display()))
    })
}

/// Resolve a symlink target against its link location and verify it can only
/// land inside the root. Returns nothing on success; rejection is the point.
///
/// # Errors
/// [`CinderError::PathTraversal`] for absolute targets, escapes via `..`, or
/// resolutions that leave the root.
pub fn validate_link_target(root_canonical: &Path, link_dest: &Path, target: &Path) -> Result<()> {
    if target.is_absolute() {
        return Err(CinderError::PathTraversal(target.to_path_buf()));
    }
    let Some(rel_parent) = link_dest.strip_prefix(root_canonical).ok() else {
        return Err(CinderError::PathTraversal(link_dest.to_path_buf()));
    };
    // Start at the link's own directory depth inside the root; every `..`
    // must stay at or below the root.
    let mut level = i64::try_from(rel_parent.components().count()).unwrap_or(i64::MAX);
    for comp in target.components() {
        match comp {
            Component::Normal(_) => level += 1,
            Component::ParentDir => {
                level -= 1;
                if level < 0 {
                    return Err(CinderError::PathTraversal(target.to_path_buf()));
                }
            }
            _ => return Err(CinderError::PathTraversal(target.to_path_buf())),
        }
    }
    // Physical check where the target already exists on disk.
    let joined = link_dest.parent().unwrap_or(root_canonical).join(target);
    if let Ok(canon) = fs::canonicalize(&joined) {
        if !canon.starts_with(root_canonical) {
            return Err(CinderError::PathTraversal(canon));
        }
    }
    Ok(())
}

fn create_symlink(dest: &Path, target: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, dest)?;
    }
    #[cfg(windows)]
    {
        if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, dest)?;
        } else {
            std::os::windows::fs::symlink_file(target, dest)?;
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (dest, target);
        return Err(CinderError::InvalidInput(
            "symlink creation unsupported on this platform".into(),
        ));
    }
    Ok(())
}

fn open_reader(archive: &Path, opts: &ExtractOptions) -> Result<ArchiveReader<fs::File>> {
    let file = fs::File::open(archive)?;
    let auth = match &opts.passphrase {
        Some(p) => Auth::Passphrase(p.clone()),
        None => Auth::None,
    };
    ArchiveReader::open(file, auth, opts.limits.clone())
}

/// Extract an entire archive into `output_root`.
///
/// # Errors
/// Any corruption, traversal attempt, cap breach or I/O failure aborts the
/// whole operation — invariant 1 rejects the archive rather than skipping
/// entries.
pub fn extract_archive(
    archive: &Path,
    output_root: &Path,
    opts: &ExtractOptions,
) -> Result<ExtractStats> {
    let mut reader = open_reader(archive, opts)?;
    // Clone the small manifest vectors up front so the reader is free for
    // `&mut` reads while we iterate.
    let dirs = reader.manifest.directories.clone();
    let files = reader.manifest.files.clone();
    if files.len().saturating_add(dirs.len()) > opts.limits.max_entries {
        return Err(CinderError::DecompressionBombSuspected(
            opts.limits.max_entries as u64,
        ));
    }
    ensure_no_symlink_components(output_root)?;
    fs::create_dir_all(output_root)?;
    let root_canonical = output_root.canonicalize()?;
    let mut budget = Budget {
        spent: 0,
        cap: opts.limits.max_total_raw,
    };
    let mut stats = ExtractStats::default();

    // Directories first so modes apply before children land inside them.
    for d in &dirs {
        let rel = entry_rel_string(&d.path)?;
        let dest = safe_destination(&root_canonical, rel)?;
        ensure_parent(&root_canonical, &dest)?;
        fs::create_dir_all(&dest)?;
        assert_within_root(&root_canonical, &dest)?;
        apply_mode(&dest, d.mode)?;
        stats.dirs_created += 1;
    }

    for f in &files {
        let rel = entry_rel_string(&f.path)?;
        let dest = safe_destination(&root_canonical, rel)?;
        ensure_parent(&root_canonical, &dest)?;

        if let Some(target) = &f.symlink_target {
            match opts.symlink_policy {
                SymlinkPolicy::Skip => {
                    let mut out = create_destination(&dest, opts.overwrite)?;
                    out.write_all(b"")?;
                    stats.symlinks_skipped += 1;
                    continue;
                }
                SymlinkPolicy::PreserveSafe => {
                    validate_link_target(&root_canonical, &dest, target)?;
                    if dest.exists() && !opts.overwrite {
                        return Err(CinderError::InvalidInput(format!(
                            "refusing to overwrite existing {}",
                            dest.display()
                        )));
                    }
                    create_symlink(&dest, target)?;
                    stats.symlinks_created += 1;
                    continue;
                }
            }
        }

        if f.stream_id == u32::MAX {
            // Defensive: writers never emit plain files with the sentinel id.
            return Err(CinderError::CorruptArchive(format!(
                "file {rel} has no stream"
            )));
        }
        if dest.exists() && !opts.overwrite {
            return Err(CinderError::InvalidInput(format!(
                "refusing to overwrite existing {}",
                dest.display()
            )));
        }
        let data = reader.read_stream_range(f.stream_id, f.offset, f.length)?;
        budget.charge(data.len() as u64)?;
        let mut out = create_destination(&dest, opts.overwrite)?;
        out.write_all(&data)?;
        drop(out);
        apply_mode(&dest, f.mode)?;
        stats.files_written += 1;
        stats.bytes_written += data.len() as u64;
    }
    Ok(stats)
}

/// Random-access extraction: pull exactly one member out of an archive,
/// touching only the frames that carry its chunks, and write it to an
/// explicit destination path chosen by the caller (`dest` names a *file*;
/// its parent directories are created on demand).
///
/// This is the Phase-3 showcase path; `physical_bytes_read()` on a reader
/// proves how little of a large archive was touched.
///
/// # Errors
/// Same guarantees as [`extract_archive`]; unknown members are
/// [`CinderError::CorruptArchive`]. The destination is user-supplied, so it
/// may live anywhere; only archive-derived data is confinement-checked.
/// Symlink members resolve against `dest`'s parent as their containment root.
pub fn extract_file(
    archive: &Path,
    member_rel_path: &str,
    dest: &Path,
    opts: &ExtractOptions,
) -> Result<ExtractStats> {
    let mut reader = open_reader(archive, opts)?;
    let normalized = member_rel_path.trim_matches('/');
    let mut entry: Option<crate::archive::manifest::FileEntry> = None;
    for f in &reader.manifest.files {
        if entry_rel_string(&f.path)? == normalized {
            entry = Some(f.clone());
            break;
        }
    }
    let entry = entry
        .ok_or_else(|| CinderError::CorruptArchive(format!("no such member: {member_rel_path}")))?;

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut budget = Budget {
        spent: 0,
        cap: opts.limits.max_total_raw,
    };
    let mut stats = ExtractStats::default();

    if let Some(target) = &entry.symlink_target {
        return match opts.symlink_policy {
            SymlinkPolicy::Skip => {
                let mut out = create_destination(dest, opts.overwrite)?;
                out.write_all(b"")?;
                stats.symlinks_skipped += 1;
                Ok(stats)
            }
            SymlinkPolicy::PreserveSafe => {
                // Containment root for a standalone link is where it lands.
                let virtual_root = dest.parent().unwrap_or(dest).canonicalize()?;
                validate_link_target(&virtual_root, dest, target)?;
                if dest.exists() && !opts.overwrite {
                    return Err(CinderError::InvalidInput(format!(
                        "refusing to overwrite existing {}",
                        dest.display()
                    )));
                }
                create_symlink(dest, target)?;
                stats.symlinks_created += 1;
                Ok(stats)
            }
        };
    }

    if entry.stream_id == u32::MAX {
        return Err(CinderError::CorruptArchive("file has no stream".into()));
    }
    if dest.exists() && !opts.overwrite {
        return Err(CinderError::InvalidInput(format!(
            "refusing to overwrite existing {}",
            dest.display()
        )));
    }
    let data = reader.read_stream_range(entry.stream_id, entry.offset, entry.length)?;
    budget.charge(data.len() as u64)?;
    let mut out = create_destination(dest, opts.overwrite)?;
    out.write_all(&data)?;
    drop(out);
    apply_mode(dest, entry.mode)?;
    stats.files_written = 1;
    stats.bytes_written = data.len() as u64;
    Ok(stats)
}
