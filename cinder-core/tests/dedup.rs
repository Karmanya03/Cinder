// Tests favor directness over style: numeric casts below are exact for
// these magnitudes and unwrap/expect in fixtures is standard test practice.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
//! Phase-1 and solid-mode acceptance.
//!
//! * Two near-identical large files in ONE archive must come out far smaller
//!   than two independent archives of the same inputs, with the delta
//!   attributable to chunk dedup (`duplicate_chunks` counter).
//! * A folder of thousands of similar small files must compress visibly
//!   better in solid mode than one-file-at-a-time.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use cinder_core::{compress_path, CompressOptions, Profile, ProgressEvent};

fn write_bytes(path: impl AsRef<std::path::Path>, data: &[u8]) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("mkdir");
    }
    fs::write(path, data).expect("write");
}

fn quiet() -> std::sync::Arc<dyn Fn(&ProgressEvent) + Send + Sync> {
    std::sync::Arc::new(|_| {})
}

fn tempdir(tag: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let p = base.join(format!(
        "cinder-dedup-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&p).expect("tempdir");
    // macOS exposes the temporary directory through `/var`, which aliases
    // `/private/var`. Keep fixtures on the canonical path so archive walk
    // tests exercise portable relative names rather than the alias.
    fs::canonicalize(p).expect("canonical tempdir")
}

/// Deterministic xorshift64* fill.
fn fill(buf: &mut [u8], seed: u64) {
    let mut s = seed.max(1);
    for b in buf.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s >> 32) as u8;
    }
}

const BASE_SIZE: usize = 8 * 1024 * 1024;

#[test]
fn near_duplicate_files_dedupe_in_one_archive() {
    let dir = tempdir("near-dup");

    // Base: pseudo-random-but-repeating structure so zstd has something to
    // chew while FastCDC still finds content-defined boundaries.
    let mut base = vec![0u8; BASE_SIZE];
    fill(&mut base, 0x00C0_FFEE);
    for block in base.chunks_mut(64 * 1024) {
        // Make every 64 KiB block start with shared context so cut points are
        // stable across the small mid-file edit below.
        block[..16].copy_from_slice(b"BLOCKHEADER-2026");
    }

    // Near copy: identical except a 4 KiB patch in the middle.
    let mut copy = base.clone();
    let patch_at = BASE_SIZE / 2;
    fill(&mut copy[patch_at..patch_at + 4096], 0x1234);

    let combined_src = dir.join("combined");
    write_bytes(combined_src.join("base.bin"), &base);
    write_bytes(combined_src.join("copy.bin"), &copy);

    let solo_base = dir.join("solo-base");
    write_bytes(solo_base.join("base.bin"), &base);
    let solo_copy = dir.join("solo-copy");
    write_bytes(solo_copy.join("copy.bin"), &copy);

    let combined_archive = dir.join("combined.cnd");
    let stats = compress_path(
        &combined_src,
        &combined_archive,
        &CompressOptions {
            profile: Profile::Balanced,
            ..CompressOptions::default()
        },
        &quiet(),
    )
    .expect("compress combined");

    let ab = dir.join("a.cnd");
    compress_path(&solo_base, &ab, &CompressOptions::default(), &quiet()).expect("compress base");
    let bb = dir.join("b.cnd");
    compress_path(&solo_copy, &bb, &CompressOptions::default(), &quiet()).expect("compress copy");

    let independent_sum = fs::metadata(&ab).unwrap().len() + fs::metadata(&bb).unwrap().len();
    let combined_size = fs::metadata(&combined_archive).unwrap().len();

    // ~8 MiB at avg 128 KiB ⇒ roughly 64 chunks; nearly all of the second
    // file must hit the pool as duplicates.
    assert!(
        stats.duplicate_chunks >= 55,
        "expected the near-duplicate's unchanged chunks to dedupe, got {}",
        stats.duplicate_chunks
    );
    // The acceptance criterion: clearly attributable to dedup, not noise.
    // The second copy should cost almost nothing beyond manifest entries.
    assert!(
        (combined_size as f64) < (independent_sum as f64) * 0.60,
        "combined {combined_size} bytes vs independent sum {independent_sum} bytes — \
         dedup is not doing its job"
    );
    // Sanity: the second copy's marginal cost is tiny relative to its size.
    let marginal = combined_size as f64 - (independent_sum as f64 / 2.0);
    assert!(
        marginal < (BASE_SIZE as f64) * 0.05,
        "marginal cost of near-duplicate ({marginal} B) exceeds 5% of file size"
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn solid_mode_beats_per_file_compression_on_small_files() {
    const FILES: usize = 600;
    const SIZE: usize = 3 * 1024; // classic "many small similar files"

    let dir = tempdir("solid");
    let src = dir.join("tree");
    for i in 0..FILES {
        // Highly similar text bodies with small per-file variation — the
        // rotated-logs / wordlist workload from the brief.
        let mut body = String::new();
        let _ = writeln!(body, "# log segment {i}");
        for line in 0..SIZE / 32 {
            let _ = writeln!(
                body,
                "INFO worker={:>04} processed batch line={} status=ok checksum=0x{:08x}",
                i,
                line,
                (i as u32).wrapping_mul(2_654_435_761)
            );
        }
        let seg = src.join(format!("seg-{i:04}.log"));
        fs::create_dir_all(&src).unwrap();
        fs::write(seg, body).unwrap();
    }

    let solid = dir.join("solid.cnd");
    compress_path(
        &src,
        &solid,
        &CompressOptions {
            solid_small_files: true,
            ..CompressOptions::default()
        },
        &quiet(),
    )
    .expect("compress solid");

    let per_file = dir.join("perfile.cnd");
    compress_path(
        &src,
        &per_file,
        &CompressOptions {
            solid_small_files: false,
            ..CompressOptions::default()
        },
        &quiet(),
    )
    .expect("compress per-file");

    let solid_size = fs::metadata(&solid).unwrap().len();
    let per_file_size = fs::metadata(&per_file).unwrap().len();

    assert!(
        solid_size < per_file_size * 9 / 10,
        "solid mode ({solid_size} B) must beat per-file ({per_file_size} B) by >10%"
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn skip_logic_stores_media_without_ratio_regression_on_text() {
    let dir = tempdir("skip");
    let src = dir.join("mixed");

    // Fake "already-compressed media": zip magic + high-entropy tail.
    let mut media = vec![0u8; 1024 * 1024];
    media[..4].copy_from_slice(b"PK\x03\x04");
    fill(&mut media[4..], 0x0BAD_C0DE);
    write_bytes(src.join("photo.zip"), &media);

    // Plain text that MUST still compress well.
    let mut text = String::new();
    for i in 0..20_000 {
        let _ = writeln!(text, "the quick brown fox jumps over lazy dog {i}");
    }
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("notes.txt"), text.as_bytes()).unwrap();

    let archive = dir.join("mixed.cnd");
    let stats = compress_path(&src, &archive, &CompressOptions::default(), &quiet())
        .expect("compress mixed");

    assert!(
        stats.stored_frames >= 1,
        "high-entropy zip-like blob should have been stored, not compressed"
    );

    // Media is stored verbatim (~1.02 MiB with framing); everything beyond
    // that must be the compressed text at a small fraction of its size.
    let logical_text = text.len() as u64;
    let on_disk = fs::metadata(&archive).unwrap().len();
    let text_budget: u64 = 1024 * 1024 + 1024 * 1024 / 10; // stored media + 10%
    assert!(
        on_disk < text_budget,
        "media framing overhead exploded: {on_disk} B on disk"
    );
    assert!(
        on_disk - (on_disk.min(1024 * 1024)) < logical_text / 3,
        "text ratio regressed: {} B on disk for {logical_text} B of text",
        on_disk.saturating_sub(1024 * 1024)
    );
    fs::remove_dir_all(dir).ok();
}
