//! Typed errors for the whole `cinder-core` public API.

use std::path::PathBuf;

/// Every fallible operation in this crate returns [`CinderError`].
#[derive(thiserror::Error, Debug)]
pub enum CinderError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("archive is corrupt: {0}")]
    CorruptArchive(String),
    /// A path stored in the archive resolves outside the extraction root.
    /// Per the safety invariant the *whole archive* is rejected, not just the entry.
    #[error("extraction path escapes target directory: {0}")]
    PathTraversal(PathBuf),
    #[error("decompressed size exceeds configured limit of {0} bytes")]
    DecompressionBombSuspected(u64),
    #[error("codec error: {0}")]
    Codec(String),
    #[error("unsupported archive version {0} (this build supports version 1)")]
    UnsupportedVersion(u32),
    #[error("archive is encrypted; a passphrase is required")]
    Encrypted,
    #[error("{0}")]
    InvalidInput(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, CinderError>;
