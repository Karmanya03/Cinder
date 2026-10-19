//! Multi-format archive adapters for Cinder.
//!
//! Cinder's native `.cnd` container is handled by `cinder-core`; this crate
//! makes the CLI and GUI speak the rest of the world's dialects:
//!
//! | Format   | Create | List | Extract | Test |
//! |----------|:------:|:----:|:-------:|:----:|
//! | .7z      | yes    | yes  | yes     | yes  |
//! | .rar     | RAR 1.3–7 | yes | yes | yes |
//! | .zip     | yes    | yes  | yes     | yes  |
//! | .tar     | yes    | yes  | yes     | yes  |
//! | .tar.gz  | yes    | yes* | yes     | yes  |
//! | .tar.zst | yes    | yes* | yes     | yes  |
//! | .tar.xz  | yes    | yes* | yes     | yes  |
//! | .gz/.xz/.zst single-file streams | — | size-only | yes | yes |
//!
//! \* streaming containers are listed by walking the decompressed stream.
//!
//! Safety parity with `.cnd`: every member path goes through
//! [`cinder_core::extract::safe_destination`] before touching disk, so
//! hostile archives (`../`, absolute paths, planted symlinks, Windows device
//! names) are rejected exactly like native ones, and every decompressing read
//! is bounded by a cumulative ceiling.
// Cast ceilings: sizes crossing these casts are bounded by caps and
// container limits long before truncation could matter.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::fs;
use std::io::{BufReader, Read, Take, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

pub mod ops;

pub use ops::{
    create, create_paths, extract, extract_selected, list, list_with_password, test,
    test_with_password, ExtractSelection,
};

/// Uniform error surface shared with the GUI/CLI layers.
#[derive(Debug, Error)]
pub enum FormatsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Core(#[from] cinder_core::CinderError),
    #[error("{context}: {source}")]
    WithContext {
        context: String,
        source: Box<FormatsError>,
    },
    /// A member path failed confinement validation.
    #[error("unsafe archive entry rejected: {0}")]
    UnsafePath(String),
    /// The archive is encrypted and requires a password to read its headers.
    #[error("archive password required or incorrect")]
    PasswordRequired,
}

impl FormatsError {
    fn with_context(self, context: impl Into<String>) -> Self {
        Self::WithContext {
            context: context.into(),
            source: Box::new(self),
        }
    }
}

pub type Result<T> = std::result::Result<T, FormatsError>;

/// Container formats this crate handles directly (`.cnd` lives in core).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    SevenZ,
    Rar,
    Tar,
    TarGz,
    TarZst,
    TarXz,
    GzSingle,
    XzSingle,
    ZstSingle,
}

impl Format {
    /// Canonical file extension including leading dot.
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Zip => ".zip",
            Self::SevenZ => ".7z",
            Self::Rar => ".rar",
            Self::Tar => ".tar",
            Self::TarGz => ".tar.gz",
            Self::TarZst => ".tar.zst",
            Self::TarXz => ".tar.xz",
            Self::GzSingle => ".gz",
            Self::XzSingle => ".xz",
            Self::ZstSingle => ".zst",
        }
    }

    /// Human label for pickers.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Zip => "Zip",
            Self::SevenZ => "7-Zip",
            Self::Rar => "RAR",
            Self::Tar => "Tar",
            Self::TarGz => "Tar + Gzip",
            Self::TarZst => "Tar + Zstandard",
            Self::TarXz => "Tar + XZ",
            Self::GzSingle => "Gzip stream",
            Self::XzSingle => "XZ stream",
            Self::ZstSingle => "Zstandard stream",
        }
    }

    // Input was ASCII-lowercased above, so plain ends_with is exact here;
    // the case-sensitive-comparison lint cannot see that.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn from_extension(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        // Order matters: longer compound extensions first.
        Some(if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            Self::TarGz
        } else if lower.ends_with(".tar.zst") || lower.ends_with(".tzst") {
            Self::TarZst
        } else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
            Self::TarXz
        } else if lower.ends_with(".zip") {
            Self::Zip
        } else if lower.ends_with(".7z") {
            Self::SevenZ
        } else if lower.ends_with(".rar") || is_rar_legacy_volume_name(&lower) {
            Self::Rar
        } else if lower.ends_with(".tar") {
            Self::Tar
        } else if lower.ends_with(".gz") {
            Self::GzSingle
        } else if lower.ends_with(".xz") {
            Self::XzSingle
        } else if lower.ends_with(".zst") {
            Self::ZstSingle
        } else {
            return None;
        })
    }

    fn from_magic(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
            Some(Self::Zip)
        } else if bytes.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
            Some(Self::SevenZ)
        } else if bytes.starts_with(b"RE~^") || bytes.starts_with(b"Rar!\x1A\x07") {
            Some(Self::Rar)
        } else if bytes.starts_with(&[0x1f, 0x8b]) {
            Some(Self::GzSingle)
        } else if bytes.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
            Some(Self::XzSingle)
        } else if bytes.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            Some(Self::ZstSingle)
        } else {
            None // plain tar has no magic
        }
    }
}

fn is_rar_legacy_volume_name(lower: &str) -> bool {
    let Some(extension) = lower.rsplit('.').next() else {
        return false;
    };
    extension.len() == 3
        && extension.as_bytes()[0].is_ascii_lowercase()
        && (b'r'..=b'z').contains(&extension.as_bytes()[0])
        && extension[1..].bytes().all(|b| b.is_ascii_digit())
}

/// Detect a supported format from extension first, then content sniffing.
///
/// Returns `None` for unknown inputs (callers then try the native `.cnd`
/// reader, which has its own magic).
#[must_use]
pub fn detect(path: &Path) -> Option<Format> {
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    if let Some(f) = Format::from_extension(&name) {
        return Some(f);
    }
    let mut probe = [0u8; 8];
    let Ok(mut f) = fs::File::open(path) else {
        return None;
    };
    let read = f.read(&mut probe).ok()?;
    Format::from_magic(&probe[..read])
}

/// One listed member of an archive.
#[derive(Debug, Clone)]
pub struct EntryInfo {
    /// `/`-separated archive-relative path (directories end with `/` for zip
    /// listings; normalized without it elsewhere).
    pub name: String,
    /// Uncompressed size when the container reports it (`None` for
    /// single-stream payloads whose real size is unknown until decoded).
    pub size: Option<u64>,
    /// Compressed footprint when the container reports one.
    pub packed: Option<u64>,
    /// Best-effort modification timestamp string.
    pub modified: Option<String>,
}

/// Knobs for extraction runs.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub overwrite: bool,
    /// Cumulative decompressed-byte ceiling for the whole run.
    pub max_total_raw: u64,
    /// Optional password for encrypted foreign containers that support it.
    pub password: Option<String>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            overwrite: false,
            max_total_raw: 256 * 1024 * 1024 * 1024, // 256 GiB sanity default
            password: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExtractSummary {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
}

/// Compression level hint for creation (deflate/gzip clamp to 1..=9, zstd
/// uses up to 19).
#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub level: i32,
    /// LZMA2 worker count for 7z output. `None` uses available parallelism.
    pub threads: Option<usize>,
    /// Whether to use solid grouping where the target format supports it.
    pub solid: bool,
    /// Optional password for 7z/RAR output. Other foreign formats ignore it.
    pub password: Option<String>,
    /// RAR generation to write. Defaults to the modern RAR 5 format.
    pub rar_version: RarVersion,
    /// Optional RAR volume size in bytes. RAR 5 and 7 volumes stream directly
    /// to disk; legacy generations are intentionally limited to single files.
    pub rar_volume_size: Option<u64>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            level: 9,
            threads: None,
            solid: true,
            password: None,
            rar_version: RarVersion::default(),
            rar_volume_size: None,
        }
    }
}

/// RAR archive generation used for newly created `.rar` files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RarVersion {
    Rar13,
    Rar14,
    Rar15,
    Rar20,
    Rar29,
    Rar30,
    Rar40,
    #[default]
    Rar50,
    Rar70,
}

impl RarVersion {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Rar13 => "RAR 1.3",
            Self::Rar14 => "RAR 1.4",
            Self::Rar15 => "RAR 1.5",
            Self::Rar20 => "RAR 2.0",
            Self::Rar29 => "RAR 2.9",
            Self::Rar30 => "RAR 3.0",
            Self::Rar40 => "RAR 4.0",
            Self::Rar50 => "RAR 5.0",
            Self::Rar70 => "RAR 7.0",
        }
    }

    pub(crate) const fn archive_version(self) -> rars::ArchiveVersion {
        match self {
            Self::Rar13 => rars::ArchiveVersion::Rar13,
            Self::Rar14 => rars::ArchiveVersion::Rar14,
            Self::Rar15 => rars::ArchiveVersion::Rar15,
            Self::Rar20 => rars::ArchiveVersion::Rar20,
            Self::Rar29 => rars::ArchiveVersion::Rar29,
            Self::Rar30 => rars::ArchiveVersion::Rar30,
            Self::Rar40 => rars::ArchiveVersion::Rar40,
            Self::Rar50 => rars::ArchiveVersion::Rar50,
            Self::Rar70 => rars::ArchiveVersion::Rar70,
        }
    }

    #[must_use]
    pub const fn supports_header_encryption(self) -> bool {
        matches!(self, Self::Rar30 | Self::Rar40 | Self::Rar50 | Self::Rar70)
    }

    #[must_use]
    pub const fn supports_streamed_volumes(self) -> bool {
        matches!(self, Self::Rar50 | Self::Rar70)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CreateStats {
    pub files: u64,
    pub dirs: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    /// Number of files written for this archive set (one for single archives).
    pub volume_count: u32,
    /// Foreign containers skip symlinks; the native `.cnd` writer does not.
    pub symlinks_skipped: u64,
}

/// Formats [`create`] can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateFormat {
    SevenZ,
    Rar,
    Zip,
    Tar,
    TarGz,
    TarZst,
    TarXz,
}

// ---------------------------------------------------------------- helpers

struct Budget {
    spent: u64,
    cap: u64,
}

impl Budget {
    fn charge(&mut self, n: u64) -> Result<()> {
        self.spent = self.spent.checked_add(n).ok_or(
            cinder_core::CinderError::DecompressionBombSuspected(self.cap),
        )?;
        if self.spent > self.cap {
            Err(cinder_core::CinderError::DecompressionBombSuspected(self.cap).into())
        } else {
            Ok(())
        }
    }
}

fn open_root(dest_root: &Path) -> Result<PathBuf> {
    cinder_core::extract::ensure_no_symlink_components(dest_root)
        .map_err(|_| FormatsError::UnsafePath(dest_root.display().to_string()))?;
    fs::create_dir_all(dest_root)?;
    Ok(dest_root.canonicalize()?)
}

/// Validate + materialize an entry destination, refusing escapes and planted
/// symlinks exactly like the native extractor.
fn entry_destination(root_canonical: &Path, raw_name: &str) -> Result<PathBuf> {
    if raw_name.len() > 4096 {
        return Err(FormatsError::UnsafePath(
            raw_name.chars().take(256).collect(),
        ));
    }
    let normalized = raw_name.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    let dest = validate_entry_path(root_canonical, trimmed)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
        let canon_parent = parent.canonicalize()?;
        if !canon_parent.starts_with(root_canonical) {
            return Err(FormatsError::UnsafePath(raw_name.to_string()));
        }
    }
    Ok(dest)
}

fn validate_entry_path(root_canonical: &Path, raw_name: &str) -> Result<PathBuf> {
    if raw_name.len() > 4096 {
        return Err(FormatsError::UnsafePath(
            raw_name.chars().take(256).collect(),
        ));
    }
    let normalized = raw_name.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    cinder_core::extract::safe_destination(root_canonical, trimmed).map_err(|e| match e {
        cinder_core::CinderError::PathTraversal(_) => {
            FormatsError::UnsafePath(raw_name.trim_end_matches('/').to_string())
        }
        other => FormatsError::Core(other),
    })
}

/// Bounded copy enforcing `cap` while streaming (+1 probe semantics like core).
fn bounded_copy<R: Read, W: Write>(reader: R, writer: W, cap: u64) -> Result<u64> {
    let mut taken: Take<R> = reader.take(cap.saturating_add(1));
    let mut out = writer;
    // Heap buffer: 128 KiB exceeds the stack-allocation pedantic ceiling.
    let mut buf = vec![0u8; 128 * 1024];
    let mut total = 0u64;
    loop {
        let n = taken.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or(cinder_core::CinderError::DecompressionBombSuspected(cap))?;
        if total > cap {
            return Err(cinder_core::CinderError::DecompressionBombSuspected(cap).into());
        }
        out.write_all(&buf[..n])?;
    }
    Ok(total)
}

fn apply_mode(path: &Path, mode: Option<u32>) {
    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(m & 0o777));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

fn zip_err(e: &zip::result::ZipError) -> FormatsError {
    FormatsError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        e.to_string(),
    ))
    .with_context("zip")
}

fn codify(context: &'static str) -> impl Fn(std::io::Error) -> FormatsError {
    move |e| FormatsError::Io(e).with_context(context)
}

/// Derive the output filename a single-stream payload extracts as.
#[must_use]
pub fn stream_payload_name(archive: &Path) -> String {
    let name = archive.file_name().map_or_else(
        || "payload".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let lower = name.to_ascii_lowercase();
    for suffix in [
        ".tar.gz", ".tgz", ".tar.zst", ".tzst", ".tar.xz", ".txz", ".gz", ".xz", ".zst",
    ] {
        if lower.ends_with(suffix) && name.len() > suffix.len() {
            return name[..name.len() - suffix.len()].to_string();
        }
    }
    format!("{name}.out")
}

fn open_stream_reader(archive: &Path, fmt: Format) -> Result<Box<dyn Read>> {
    let file = BufReader::new(fs::File::open(archive)?);
    Ok(match fmt {
        Format::Tar | Format::GzSingle | Format::XzSingle | Format::ZstSingle => {
            unreachable!("open_stream_reader called for non-compressed format {fmt:?}")
        }
        Format::TarGz => Box::new(flate2::read::MultiGzDecoder::new(file)),
        Format::TarZst => Box::new(zstd::stream::Decoder::new(file)?),
        Format::TarXz => Box::new(liblzma::read::XzDecoder::new_multi_decoder(file)),
        Format::Zip => Box::new(file),
        Format::SevenZ | Format::Rar => {
            unreachable!("open_stream_reader called for archive format {fmt:?}")
        }
    })
}

fn raw_file_reader(archive: &Path, fmt: Format) -> Result<Box<dyn Read>> {
    let file = BufReader::new(fs::File::open(archive)?);
    Ok(match fmt {
        Format::GzSingle => Box::new(flate2::read::MultiGzDecoder::new(file)),
        Format::XzSingle => Box::new(liblzma::read::XzDecoder::new_multi_decoder(file)),
        Format::ZstSingle => Box::new(zstd::stream::Decoder::new(file)?),
        other => {
            return Err(FormatsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{other:?} is not a single compressed stream"),
            )))
        }
    })
}
