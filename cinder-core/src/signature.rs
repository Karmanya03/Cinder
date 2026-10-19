//! Detached Ed25519 signatures for native archive manifests.
//!
//! The signature covers both the deterministic manifest bytes and the full
//! archive digest. The detached `.sig.json` format keeps CINDERv1 readers
//! compatible while making signatures easy to distribute beside releases.

use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::archive::reader::ArchiveReader;
use crate::crypto::Auth;
use crate::error::{CinderError, Result};
use crate::Limits;

const SIGNATURE_VERSION: u32 = 1;
const DOMAIN: &[u8] = b"CINDER-MANIFEST-SIGNATURE-v1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub version: u32,
    pub archive_blake3: String,
    pub manifest_blake3: String,
    pub public_key: String,
    pub signature: String,
}

/// Generate a new private signing key file and return its public key hex.
pub fn generate_signing_key(path: &Path) -> Result<String> {
    if path.exists() {
        return Err(CinderError::InvalidInput(format!(
            "refusing to overwrite signing key {}",
            path.display()
        )));
    }
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|e| CinderError::Codec(format!("OS randomness unavailable: {e}")))?;
    let key = SigningKey::from_bytes(&secret);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes_to_hex(&secret).as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(bytes_to_hex(key.verifying_key().as_bytes()))
}

/// Sign a native archive and write a detached JSON signature.
pub fn sign_archive(
    archive: &Path,
    key_path: &Path,
    signature_path: &Path,
    passphrase: Option<&str>,
) -> Result<SignedManifest> {
    let secret = read_key(key_path)?;
    let signing_key = SigningKey::from_bytes(&secret);
    let file = File::open(archive)?;
    let auth = passphrase.map_or(Auth::None, |value| Auth::Passphrase(value.to_owned()));
    let reader = ArchiveReader::open(file, auth, Limits::default())?;
    let manifest = reader.manifest.encode()?;
    let archive_blake3 = hash_file(archive)?;
    let manifest_blake3 = blake3::hash(&manifest).to_hex().to_string();
    let message = signing_message(&archive_blake3, &manifest_blake3);
    let signature = signing_key.sign(&message);
    let signed = SignedManifest {
        version: SIGNATURE_VERSION,
        archive_blake3,
        manifest_blake3,
        public_key: bytes_to_hex(signing_key.verifying_key().as_bytes()),
        signature: bytes_to_hex(&signature.to_bytes()),
    };
    let bytes = serde_json::to_vec_pretty(&signed)
        .map_err(|e| CinderError::InvalidInput(format!("signature encode failed: {e}")))?;
    fs::write(signature_path, bytes)?;
    Ok(signed)
}

/// Verify a detached signature against the archive's current bytes and
/// deterministic manifest.
pub fn verify_signature(
    archive: &Path,
    signature_path: &Path,
    passphrase: Option<&str>,
) -> Result<SignedManifest> {
    let signed: SignedManifest = serde_json::from_slice(&fs::read(signature_path)?)
        .map_err(|e| CinderError::CorruptArchive(format!("signature parse failed: {e}")))?;
    if signed.version != SIGNATURE_VERSION {
        return Err(CinderError::UnsupportedVersion(signed.version));
    }
    let archive_blake3 = hash_file(archive)?;
    if signed.archive_blake3 != archive_blake3 {
        return Err(CinderError::CorruptArchive(
            "archive digest does not match manifest signature".into(),
        ));
    }
    let file = File::open(archive)?;
    let auth = passphrase.map_or(Auth::None, |value| Auth::Passphrase(value.to_owned()));
    let reader = ArchiveReader::open(file, auth, Limits::default())?;
    let manifest_blake3 = blake3::hash(&reader.manifest.encode()?)
        .to_hex()
        .to_string();
    if signed.manifest_blake3 != manifest_blake3 {
        return Err(CinderError::CorruptArchive(
            "manifest digest does not match signature".into(),
        ));
    }
    let public_key = VerifyingKey::from_bytes(&read_fixed_hex::<32>(&signed.public_key)?)
        .map_err(|e| CinderError::CorruptArchive(format!("invalid signing public key: {e}")))?;
    let signature = Signature::from_bytes(&read_fixed_hex::<64>(&signed.signature)?);
    public_key
        .verify(
            &signing_message(&signed.archive_blake3, &signed.manifest_blake3),
            &signature,
        )
        .map_err(|_| {
            CinderError::CorruptArchive("manifest signature verification failed".into())
        })?;
    Ok(signed)
}

fn signing_message(archive: &str, manifest: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + archive.len() + manifest.len() + 2);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(archive.as_bytes());
    message.push(0);
    message.extend_from_slice(manifest.as_bytes());
    message
}

fn read_key(path: &Path) -> Result<[u8; 32]> {
    let raw = fs::read_to_string(path)?;
    read_fixed_hex::<32>(raw.trim())
}

fn read_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err(CinderError::InvalidInput(format!("expected {N} hex bytes")));
    }
    let mut out = [0u8; N];
    for (i, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_digit(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(CinderError::InvalidInput(
            "invalid hexadecimal key material".into(),
        )),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[must_use]
pub fn default_signature_path(archive: &Path) -> PathBuf {
    archive.with_extension("sig.json")
}
