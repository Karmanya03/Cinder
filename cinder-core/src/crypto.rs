//! Optional authenticated-encryption layer.
//!
//! * Payload: XChaCha20-Poly1305, a fresh 24-byte random nonce per frame.
//! * Key derivation: Argon2id (64 MiB, t=3, p=1) from the user passphrase.
//! * The Argon2id output is split into two independent subkeys via BLAKE3
//!   `derive_key`, so frame and manifest keys are domain-separated.
//!
//! Encryption is archive-level and strictly opt-in; every frame carries an
//! authentication tag, so tampering or truncation is detected on read.

use chacha20poly1305::aead::{Aead, Generate, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{CinderError, Result};

/// Symmetric key length in bytes.
pub const KEY_LEN: usize = 32;
/// Argon2id salt length in bytes.
pub const SALT_LEN: usize = 16;
/// XChaCha20 nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Domain-separated subkey material.
#[derive(Clone)]
pub struct ArchiveKeys {
    frame_key: Zeroizing<[u8; KEY_LEN]>,
    manifest_key: Zeroizing<[u8; KEY_LEN]>,
}

/// Authentication credentials for opening an archive.
///
/// Key derivation must happen *after* the footer is parsed (the Argon2id salt
/// lives there), which is why callers hand over an [`Auth`] rather than
/// ready-made keys: `ArchiveReader::open` derives subkeys internally from the
/// passphrase and the freshly-read salt.
#[derive(Clone, Default)]
pub enum Auth {
    /// Plaintext archive; refuse encrypted ones.
    #[default]
    None,
    /// Derive keys inside `open` from this passphrase and the footer salt.
    Passphrase(String),
    /// Callers that already possess derived keys (tests, session reuse).
    Keys(ArchiveKeys),
}

/// Fill a buffer with OS CSPRNG bytes.
fn os_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| CinderError::Codec(format!("OS randomness unavailable: {e}")))
}

/// Random salt for key derivation.
///
/// # Errors
/// Only when the OS entropy source fails, which is fatal for security.
pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    os_random(&mut salt)?;
    Ok(salt)
}

/// Derive the archive's two subkeys from a passphrase and stored salt.
///
/// # Errors
/// [`CinderError::InvalidInput`] on an empty passphrase (Argon2id rejects it).
pub fn derive_keys(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<ArchiveKeys> {
    if passphrase.is_empty() {
        return Err(CinderError::InvalidInput(
            "passphrase must not be empty".into(),
        ));
    }
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|e| CinderError::InvalidInput(format!("bad argon2 params: {e}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, master.as_mut())
        .map_err(|e| CinderError::Codec(format!("argon2 failed: {e}")))?;
    let frame_key = Zeroizing::new(blake3::derive_key("cinder v1 frame key", master.as_ref()));
    let manifest_key = Zeroizing::new(blake3::derive_key(
        "cinder v1 manifest key",
        master.as_ref(),
    ));
    Ok(ArchiveKeys {
        frame_key,
        manifest_key,
    })
}

impl ArchiveKeys {
    /// Encrypt a frame payload. Output layout: `nonce || ciphertext || tag`.
    ///
    /// # Errors
    /// In practice infallible (fixed-length key and nonce); surfaced as
    /// [`CinderError::Codec`] should the AEAD ever reject them.
    pub(crate) fn seal_frame(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        seal(&self.frame_key, plaintext)
    }

    /// Decrypt a frame payload produced by [`Self::seal_frame`].
    ///
    /// # Errors
    /// [`CinderError::CorruptArchive`] on tag failure or malformed blob —
    /// indistinguishable between wrong passphrase and corruption by design.
    pub(crate) fn open_frame(&self, blob: &[u8]) -> Result<Vec<u8>> {
        open(&self.frame_key, blob)
    }

    /// Encrypt the manifest region.
    ///
    /// # Errors
    /// See [`Self::seal_frame`].
    pub(crate) fn seal_manifest(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        seal(&self.manifest_key, plaintext)
    }

    /// Decrypt the manifest region.
    ///
    /// # Errors
    /// See [`Self::open_frame`].
    pub(crate) fn open_manifest(&self, blob: &[u8]) -> Result<Vec<u8>> {
        open(&self.manifest_key, blob)
    }
}

fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = <XNonce as Generate>::generate();
    let sealed = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CinderError::Codec(format!("aead seal failed: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(CinderError::CorruptArchive(format!(
            "encrypted blob too short: {} bytes",
            blob.len()
        )));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::try_from(nonce_bytes)
        .map_err(|_| CinderError::CorruptArchive("nonce length mismatch".into()))?;
    cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        CinderError::CorruptArchive(
            "authentication failed (wrong passphrase or corrupt data)".into(),
        )
    })
}
