//! # cinder-core
//!
//! Library core of **Cinder**, a compressor/archiver built for real
//! workloads rather than benchmark showcases:
//!
//! * **Dedup** — content-defined chunking (FastCDC) + BLAKE3 fingerprints +
//!   a chunk pool, so near-identical multi-gigabyte snapshots collapse.
//! * **Solid mode** — small files batch into shared streams so compression
//!   sees multi-file context instead of per-file overhead.
//! * **Skip logic** — already-compressed media is detected (magic bytes +
//!   entropy probe) and stored verbatim instead of wasting CPU.
//! * **Seekability** — every chunk lives in an independently decodable frame
//!   with a manifest seek table; single-file extraction touches only the
//!   frames that carry it.
//! * **Optional AEAD** — XChaCha20-Poly1305 payloads under Argon2id-derived
//!   keys, strictly opt-in.
//!
//! ## Safety invariants (enforced from first commit, tested not just reviewed)
//!
//! 1. Archive paths may never resolve outside the extraction root; the whole
//!    archive is rejected on the first violation. See [`extract`].
//! 2. Decompression is bounded *while streaming* by caller-supplied caps.
//! 3. Parsing malformed input returns errors; it never panics. The fuzz
//!    targets in `fuzz/` are the proof.
//!
//! The CLI (`cinder-cli`) is thin; everything interesting lives here.

#![warn(clippy::pedantic)]
// Allowed pedantic exceptions, each with a reason:
#![allow(
    clippy::missing_errors_doc,      // every fallible fn documents Errors in its own words
    clippy::missing_panics_doc,      // no data-dependent panics exist; see unwrap policy below
    clippy::module_name_repetitions, // archive::writer::FrameSink etc. read better repeated
    clippy::must_use_candidate,      // noise for an IO-heavy library
    clippy::needless_pass_by_value,  // ownership transfer at API boundaries is intentional
    clippy::cast_possible_truncation,// framing fields are range-checked before casting
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::similar_names,           // seq/seen/streams coexist naturally here
    clippy::doc_markdown             // mixed-case identifiers in docs trigger false positives
)]

pub mod archive;
pub mod benchmark;
pub mod chunk;
pub mod codec;
pub mod crypto;
pub mod delta;
pub mod error;
pub mod extract;
pub mod fingerprint;
pub mod index;
pub mod pipeline;
pub mod signature;
pub mod walk;

pub use archive::manifest::{ChunkLocation, DirRecord, FileEntry, Manifest, StreamEntry};
pub use archive::reader::ArchiveReader;
pub use benchmark::{benchmark_path, BenchmarkOptions, BenchmarkReport};
/// Re-exported so downstream crates can name [`blake3::Hash`] without adding
/// their own matching version of the dependency.
pub use blake3;
pub use chunk::{ChunkParams, ChunkRef};
pub use codec::Profile;
pub use delta::{
    apply_delta, build_delta, compare_snapshot, delta_sidecar_path, DeltaOptions, DeltaReport,
};
pub use error::{CinderError, Result};
pub use extract::{
    extract_archive, extract_file, ExtractOptions, ExtractStats, Limits, SymlinkPolicy,
};
pub use fingerprint::hash_chunk;
pub use index::{rebuild as rebuild_chunk_index, update_from_archive, ChunkIndex, ChunkIndexStats};
pub use pipeline::{
    compress_path, compress_paths, CompressOptions, CompressionStats, ProgressEvent,
};
pub use signature::{
    default_signature_path, generate_signing_key, sign_archive, verify_signature, SignedManifest,
};

/// Format version string reported by `--version` and embedded in manifests.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
