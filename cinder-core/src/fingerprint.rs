//! Content fingerprinting.
//!
//! Every chunk is fingerprinted with BLAKE3. The hash doubles as the chunk's
//! identity in the archive-wide pool, so two near-identical multi-gigabyte
//! snapshots share almost every chunk.

use crate::error::{CinderError, Result};

/// Length of a BLAKE3 digest in bytes.
pub const HASH_LEN: usize = 32;

/// Fingerprint a chunk of bytes.
#[must_use]
pub fn hash_chunk(data: &[u8]) -> blake3::Hash {
    blake3::hash(data)
}

/// Lowercase hex encoding of a hash, used for manifest serialization and CLI output.
#[must_use]
pub fn to_hex(hash: &blake3::Hash) -> String {
    hash.to_hex().to_string()
}

/// Parse a lowercase hex string back into a [`blake3::Hash`].
///
/// # Errors
/// Returns [`CinderError::CorruptArchive`] when the string is not valid
/// 64-character lowercase hex.
pub fn from_hex(s: &str) -> Result<blake3::Hash> {
    blake3::Hash::from_hex(s)
        .map_err(|e| CinderError::CorruptArchive(format!("invalid chunk hash `{s}`: {e}")))
}
