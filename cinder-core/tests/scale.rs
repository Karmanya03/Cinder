// Scale-harness exceptions: reporting math uses f64 deliberately; fixture
// sizes stay far below any precision boundary, and the harness is a
// measurement script, not library code.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::items_after_statements
)]
//! Scale acceptance runs (env-gated: `CINDER_SCALE=1 cargo test --release ...`).
//!
//! These discharge the v1 `DoD` measurement items at a reduced-but-honest
//! scale (hundreds of MiB rather than multi-hundred-GiB). Every number
//! printed here is meant to be copied verbatim into docs/BENCHMARKS.md.
//!
//! Baseline semantics:
//! * "zstd -15 single-threaded" = streaming `copy_encode` at level 15 over the
//!   exact same byte sequence (the entropy-coder parity check).
//! * "tar|zstd equivalent" = the two files' bytes concatenated and compressed
//!   as ONE stream at level 15 (no cross-file awareness possible).

use std::fmt::Write as _;
use std::fs;
use std::io::{Seek, Write};
use std::path::PathBuf;

use cinder_core::{compress_path, CompressOptions, ProgressEvent};

fn quiet() -> std::sync::Arc<dyn Fn(&ProgressEvent) + Send + Sync> {
    std::sync::Arc::new(|_| {})
}

fn tempdir(tag: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let p = base.join(format!(
        "cinder-scale-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&p).expect("tempdir");
    p
}

/// VM-snapshot-flavoured filler: zero runs + a repeating 4 MiB page-pool +
/// low-entropy text region, tiled until `size` bytes exist.
fn build_snapshot(path: &std::path::Path, size: u64) {
    // Deterministic pseudo-random page pool.
    let mut pool = vec![0u8; 4 * 1024 * 1024];
    let mut s = 0x1234_5678_9ABC_DEF0u64;
    for b in &mut pool {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s >> 24) as u8;
    }
    let zeros = vec![0u8; 2 * 1024 * 1024];
    let mut text = String::new();
    for i in 0..24_000u32 {
        let _ = writeln!(text, "sector log entry {i} status=ok crc=0x{i:08x}");
    }
    let text = text.as_bytes();

    let f = fs::File::create(path).expect("create fixture");
    let mut w = std::io::BufWriter::with_capacity(8 * 1024 * 1024, f);
    let mut written = 0u64;
    while written < size {
        w.write_all(&zeros).unwrap();
        w.write_all(&pool).unwrap();
        w.write_all(text).unwrap();
        written += (zeros.len() + pool.len() + text.len()) as u64;
    }
    w.flush().unwrap();
}

/// Non-repeating text fixture for the coder-parity check: every line embeds
/// a strictly increasing counter, so no block ever duplicates another and
/// dedup cannot contribute — the comparison isolates chunked-zstd-15 vs
/// single-stream-zstd-15 on genuinely unique content.
fn build_unique_text(path: &std::path::Path, size: u64) {
    let f = fs::File::create(path).expect("create fixture");
    let mut w = std::io::BufWriter::with_capacity(8 * 1024 * 1024, f);
    let mut s = 0xDEAD_BEEF_CAFE_F00Du64;
    let mut n: u64 = 0;
    let mut written = 0u64;
    while written < size {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let line = format!(
            "record {n} ts=2026-08-22T10:{:02}:{:02}Z host=node-{} metric=req_latency_ms value={:.3} region={}\n",
            (s % 60) as u32,
            ((s >> 8) % 60) as u32,
            (s >> 16) % 64,
            ((s >> 24) % 10_000) as f64 / 1000.0,
            ["eu-west", "us-east", "ap-south"][(s >> 40) as usize % 3],
        );
        w.write_all(line.as_bytes()).unwrap();
        written += line.len() as u64;
        n += 1;
    }
    w.flush().unwrap();
}

fn zstd15_stream(src: &std::path::Path, dst: &std::path::Path) -> u64 {
    let mut r = fs::File::open(src).unwrap();
    let mut w = fs::File::create(dst).unwrap();
    zstd::stream::copy_encode(&mut r, &mut w, 15).unwrap();
    fs::metadata(dst).unwrap().len()
}

#[test]
#[ignore = "heavy scale run: CINDER_SCALE=1 cargo test --release --test scale -- --ignored --nocapture"]
fn run_scale_acceptance() {
    if std::env::var("CINDER_SCALE").as_deref() != Ok("1") {
        return;
    }
    let t0 = std::time::Instant::now();
    let unit = 512u64 * 1024 * 1024;
    let dir = tempdir("main");

    // --- A: entropy-coder parity (unique content; dedup is a no-op) -------
    let solo_dir = dir.join("solo");
    fs::create_dir_all(&solo_dir).unwrap();
    let unique_path = solo_dir.join("unique.log");
    let t_unique = std::time::Instant::now();
    build_unique_text(&unique_path, unit);
    eprintln!(
        "unique fixture built in {:.1}s",
        t_unique.elapsed().as_secs_f32()
    );
    let arc_a = dir.join("a.cnd");
    let ta = std::time::Instant::now();
    let stats_a = compress_path(&solo_dir, &arc_a, &CompressOptions::default(), &quiet())
        .expect("compress A");
    let cinder_a_size = stats_a.archive_bytes;
    let zstd_a_size = zstd15_stream(&unique_path, &dir.join("a.zst"));
    eprintln!(
        "A ratio-parity: input={} cinder-balanced={} ({:.2}%) zstd15={} ({:.2}%) cinder-delta={:+.2}% time_cinder={:.1}s dup_chunks={}",
        human(unit),
        human(cinder_a_size),
        pct(cinder_a_size, unit),
        human(zstd_a_size),
        pct(zstd_a_size, unit),
        100.0 * (cinder_a_size as f64 - zstd_a_size as f64) / zstd_a_size.max(1) as f64,
        ta.elapsed().as_secs_f32(),
        stats_a.duplicate_chunks,
    );

    // --- B: dedup vs concatenated-stream baseline --------------------------
    let pair_dir = dir.join("pair");
    fs::create_dir_all(&pair_dir).unwrap();
    let base_path = pair_dir.join("base.img");
    let copy_path = pair_dir.join("copy.img");
    build_snapshot(&base_path, unit);
    build_snapshot(&copy_path, unit);
    // Near-duplicate: flip 4 KiB in the middle of the copy.
    let mid = unit / 2;
    let patch = vec![0xFFu8; 4096];
    let mut f = fs::OpenOptions::new().write(true).open(&copy_path).unwrap();
    f.seek(std::io::SeekFrom::Start(mid)).unwrap();
    f.write_all(&patch).unwrap();
    drop(f);

    let arc_b = dir.join("b.cnd");

    let stats_b = compress_path(&pair_dir, &arc_b, &CompressOptions::default(), &quiet())
        .expect("compress B");
    let cinder_pair = stats_b.archive_bytes;

    // Baseline: concat both files into one stream, compress once.
    let concat = dir.join("concat.bin");
    {
        let mut out = fs::File::create(&concat).unwrap();
        for name in ["base.img", "copy.img"] {
            let mut r = fs::File::open(pair_dir.join(name)).unwrap();
            std::io::copy(&mut r, &mut out).unwrap();
        }
    }
    let baseline_pair = zstd15_stream(&concat, &dir.join("pair-baseline.zst"));

    eprintln!(
        "B dedup-vs-tar|zstd: inputs=2x{} cinder-combined={} ({:.2}% of input) tar-zstd-equiv={} ({:.2}%) saving={:.1}% dup_chunks={}",
        human(unit),
        human(cinder_pair),
        pct(cinder_pair, 2 * unit),
        human(baseline_pair),
        pct(baseline_pair, 2 * unit),
        100.0 * (baseline_pair.saturating_sub(cinder_pair)) as f64 / baseline_pair.max(1) as f64,
        stats_b.duplicate_chunks,
    );
    assert!(
        cinder_pair < baseline_pair,
        "dedup must beat plain concatenation baseline on this workload"
    );
    eprintln!("total wall: {:.1}s", t0.elapsed().as_secs_f32());
}

fn human(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

fn pct(part: u64, whole: u64) -> f64 {
    part as f64 * 100.0 / whole.max(1) as f64
}
