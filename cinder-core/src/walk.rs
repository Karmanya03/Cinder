//! Deterministic directory traversal.
//!
//! Produces a flat, sorted list of entries with the metadata Cinder needs to
//! reconstruct the tree: unix mode bits, symlink targets and file sizes.
//! Traversal never follows symlinks, so archives can't loop through them.
//! Special files (fifos, sockets, devices) are counted and skipped rather
//! than silently dropped or fatally failing the whole archive.

use std::collections::HashSet;
use std::fs::Metadata;
use std::path::{Path, PathBuf};

use walkdir::{DirEntry as WalkDirEntry, WalkDir};

/// What kind of filesystem object an entry is.
#[derive(Debug, Clone)]
pub enum EntryKind {
    /// Regular directory; carries reconstructed mode bits.
    Dir { mode: u32 },
    /// Regular file; size in bytes plus mode bits.
    File { size: u64, mode: u32 },
    /// Symbolic link with its literal target string.
    Symlink { target: PathBuf, mode: u32 },
}

/// One walked filesystem entry.
#[derive(Debug, Clone)]
pub struct WalkedEntry {
    /// Absolute path on the source filesystem.
    pub path: PathBuf,
    /// Path relative to the walk root, `/`-separated, archive-canonical form.
    pub rel_path: String,
    pub kind: EntryKind,
}

/// Result of walking a root.
#[derive(Debug, Default)]
pub struct WalkOutput {
    pub entries: Vec<WalkedEntry>,
    /// Fifos/sockets/devices that were skipped.
    pub skipped_specials: u64,
    /// Entries whose metadata could not be read (reported, not fatal).
    pub skipped_errors: u64,
}

#[cfg(unix)]
fn unix_mode(md: &Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode()
}

#[cfg(not(unix))]
fn unix_mode(md: &Metadata) -> u32 {
    // Windows has no unix mode; synthesize one from the read-only bit so
    // permissions survive archive round-trips as faithfully as the OS allows.
    let base = if md.is_dir() { 0o755 } else { 0o644 };
    if md.permissions().readonly() {
        base & !0o222
    } else {
        base
    }
}

/// Convert a path relative to the walk root into archive-canonical form:
/// forward slashes only, no leading separator.
fn rel_string(rel: &Path) -> String {
    let mut s = String::new();
    for comp in rel.components() {
        if !s.is_empty() {
            s.push('/');
        }
        if let std::path::Component::Normal(part) = comp {
            s.push_str(&part.to_string_lossy());
        }
    }
    s
}

/// Walk `root` deterministically (entries sorted by relative path).
///
/// # Errors
/// Only when `root` itself cannot be read; per-entry problems increment
/// [`WalkOutput::skipped_errors`] instead of failing the whole walk.
pub fn walk_tree(root: &Path) -> std::io::Result<WalkOutput> {
    let mut out = WalkOutput::default();
    let root_meta = std::fs::symlink_metadata(root)?;

    if root_meta.is_file() || root_meta.is_symlink() {
        // Single-file input: the archive contains just this file under its name.
        let name = root
            .file_name()
            .map_or_else(|| "file".to_string(), |n| n.to_string_lossy().into_owned());
        out.entries.push(WalkedEntry {
            path: root.to_path_buf(),
            rel_path: name,
            kind: EntryKind::File {
                size: root_meta.len(),
                mode: unix_mode(&root_meta),
            },
        });
        return Ok(out);
    }

    let mut entries: Vec<WalkedEntry> = Vec::new();
    let walker = WalkDir::new(root).follow_links(false);
    for entry in walker {
        match entry {
            Err(_) => out.skipped_errors += 1,
            Ok(dir_entry) => match classify(&dir_entry) {
                Err(_) => out.skipped_errors += 1,
                Ok(None) => out.skipped_specials += 1,
                Ok(Some(kind)) => {
                    let abs = dir_entry.into_path();
                    let Some(rel) = abs.strip_prefix(root).ok() else {
                        continue;
                    };
                    let rel_path = rel_string(rel);
                    if rel_path.is_empty() {
                        continue; // the root itself; recreated implicitly as output dir
                    }
                    entries.push(WalkedEntry {
                        path: abs,
                        rel_path,
                        kind,
                    });
                }
            },
        }
    }
    // Deterministic layout regardless of filesystem ordering quirks.
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    out.entries = entries;
    Ok(out)
}

/// Walk several selected files or folders into one archive namespace.
///
/// A single input keeps [`walk_tree`] semantics. With multiple inputs, each
/// selection gets a top-level name so unrelated files cannot silently
/// overwrite one another. Duplicate paths (including case-only collisions,
/// which are unsafe to move between common filesystems) are rejected.
pub fn walk_paths(inputs: &[PathBuf]) -> std::io::Result<WalkOutput> {
    if inputs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "at least one input path is required",
        ));
    }
    if inputs.len() == 1 {
        return walk_tree(&inputs[0]);
    }

    let mut output = WalkOutput::default();
    let mut names = HashSet::new();
    for input in inputs {
        let metadata = std::fs::symlink_metadata(input)?;
        let root_name = input.file_name().map_or_else(
            || "item".to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        if root_name.is_empty() || root_name == "." || root_name == ".." {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("cannot create a safe archive name for {}", input.display()),
            ));
        }

        let walked = walk_tree(input)?;
        output.skipped_specials = output
            .skipped_specials
            .saturating_add(walked.skipped_specials);
        output.skipped_errors = output.skipped_errors.saturating_add(walked.skipped_errors);

        let entries = if metadata.is_dir() {
            let mut entries = Vec::with_capacity(walked.entries.len().saturating_add(1));
            entries.push(WalkedEntry {
                path: input.clone(),
                rel_path: root_name.clone(),
                kind: EntryKind::Dir {
                    mode: unix_mode(&metadata),
                },
            });
            entries.extend(walked.entries.into_iter().map(|mut entry| {
                entry.rel_path = format!("{root_name}/{}", entry.rel_path);
                entry
            }));
            entries
        } else {
            walked
                .entries
                .into_iter()
                .map(|mut entry| {
                    entry.rel_path.clone_from(&root_name);
                    entry
                })
                .collect()
        };

        for entry in entries {
            let key = entry.rel_path.to_lowercase();
            if !names.insert(key) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "selected inputs produce a duplicate archive path: {}",
                        entry.rel_path
                    ),
                ));
            }
            output.entries.push(entry);
        }
    }
    output.entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(output)
}

fn classify(entry: &WalkDirEntry) -> std::io::Result<Option<EntryKind>> {
    let ft = entry.file_type();
    if ft.is_symlink() {
        let target = std::fs::read_link(entry.path())?;
        let mode = unix_mode(&entry.metadata()?);
        return Ok(Some(EntryKind::Symlink { target, mode }));
    }
    if ft.is_dir() {
        return Ok(Some(EntryKind::Dir {
            mode: unix_mode(&entry.metadata()?),
        }));
    }
    if ft.is_file() {
        let md: Metadata = entry.metadata()?;
        return Ok(Some(EntryKind::File {
            size: md.len(),
            mode: unix_mode(&md),
        }));
    }
    Ok(None)
}
