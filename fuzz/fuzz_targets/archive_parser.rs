//! Fuzz the archive parser: header, footer, manifest, frame bounds.
//!
//! Contract (safety invariant 3): malformed input returns `Err`, never
//! panics. Run with:
//!
//! ```text
//! cargo +nightly fuzz run archive_parser -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use cinder_core::archive::Limits;
use cinder_core::crypto::Auth;
use cinder_core::ArchiveReader;

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_frame_raw: 1024 * 1024,
        max_manifest_bytes: 64 * 1024,
        max_total_raw: Some(4 * 1024 * 1024),
        ..Limits::default()
    };
    if let Ok(mut reader) = ArchiveReader::open(Cursor::new(data.to_vec()), Auth::None, limits) {
        // Manifest parsed; exercising reads must also stay panic-free.
        let hashes: Vec<_> = reader.manifest.chunk_pool.keys().copied().collect();
        for h in hashes.iter().take(16) {
            let _ = reader.read_chunk(h);
        }
        for f in reader.manifest.files.clone() {
            let _ = reader.read_stream_range(f.stream_id, f.offset, f.length.min(64 * 1024));
        }
    }
});
