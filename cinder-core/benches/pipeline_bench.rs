// Tests favor directness over style: numeric casts below are exact for
// these magnitudes and unwrap/expect in fixtures is standard test practice.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
//! Criterion benchmarks over a deterministic synthetic corpus.
//!
//! These measure Cinder against ITSELF (profiles, chunking, dedup overhead).
//! Cross-tool comparisons (`tar | zstd`, 7-Zip, borgbackup) live in
//! `docs/BENCHMARKS.md` and are only ever filled from recorded runs on real
//! hardware â€” see the measured-numbers policy in the README.

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use cinder_core::archive::Limits;
use cinder_core::chunk::{cut_chunks, ChunkParams};
use cinder_core::codec::{codec_for_profile, Profile};
use cinder_core::crypto::Auth;
use cinder_core::{
    compress_path, extract_archive, ArchiveReader, CompressOptions, ExtractOptions, ProgressEvent,
};

fn quiet() -> Arc<dyn Fn(&ProgressEvent) + Send + Sync> {
    Arc::new(|_| {})
}

/// Deterministic corpus mixing compressible text, repetitive structure and
/// pseudo-random regions â€” small enough for CI, shaped like the workloads.
fn build_corpus() -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 * 1024 * 1024);
    // Text-ish region.
    for i in 0..40_000u64 {
        buf.extend_from_slice(
            format!(
                "log line {i}: worker={:04} status=ok payload=0x{:08x}\n",
                i % 997,
                i
            )
            .as_bytes(),
        );
    }
    // Pseudo-random region (xorshift).
    let mut s = 0x9E37_79B9_7F4A_7C15_u64;
    while buf.len() < 3 * 1024 * 1024 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        buf.push((s >> 32) as u8);
    }
    // Zero region.
    buf.resize(4 * 1024 * 1024, 0);
    buf
}

fn bench_codecs(c: &mut Criterion) {
    let corpus = build_corpus();
    let mut group = c.benchmark_group("codec-compress");
    group.throughput(criterion::Throughput::Bytes(corpus.len() as u64));
    for (name, profile) in [
        ("fast", Profile::Fast),
        ("balanced", Profile::Balanced),
        ("max", Profile::Max),
    ] {
        let codec = codec_for_profile(profile, None);
        group.bench_with_input(BenchmarkId::new("raw", name), &corpus, |b, data| {
            b.iter(|| {
                let mut out = Vec::with_capacity(data.len() / 2);
                codec.compress(black_box(data), &mut out).unwrap();
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_chunking(c: &mut Criterion) {
    let corpus = build_corpus();
    let mut group = c.benchmark_group("chunking");
    group.throughput(criterion::Throughput::Bytes(corpus.len() as u64));
    group.bench_function("fastcdc-128k-avg", |b| {
        b.iter(|| {
            let cuts = cut_chunks(black_box(&corpus), &ChunkParams::default());
            black_box(cuts.len())
        });
    });
    group.finish();
}

fn bench_pipeline_roundtrip(c: &mut Criterion) {
    let dir = std::env::temp_dir().join(format!("cinder-bench-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let corpus = build_corpus();
    std::fs::write(dir.join("src/corpus.bin"), &corpus).unwrap();

    let mut group = c.benchmark_group("pipeline");
    group.throughput(criterion::Throughput::Bytes(corpus.len() as u64));

    let archive = dir.join("b.cnd");
    group.bench_function("compress-balanced", |b| {
        b.iter(|| {
            compress_path(
                &dir.join("src"),
                &archive,
                &CompressOptions::default(),
                &quiet(),
            )
            .unwrap();
        });
    });

    group.bench_function("extract-balanced", |b| {
        b.iter(|| {
            extract_archive(&archive, &dir.join("out"), &ExtractOptions::default()).unwrap();
            std::fs::remove_dir_all(dir.join("out")).ok();
        });
    });

    // Random access vs sequential: the honest Phase-3 metric, in miniature.
    group.bench_function("random-access-single-file", |b| {
        b.iter(|| {
            let file = std::fs::File::open(&archive).unwrap();
            let mut r = ArchiveReader::open(file, Auth::None, Limits::default()).unwrap();
            let h = r.manifest.chunk_pool.keys().copied().next().unwrap();
            black_box(r.read_chunk(&h).unwrap());
            black_box(r.physical_bytes_read());
        });
    });
    group.bench_function("full-decode-all-chunks", |b| {
        b.iter(|| {
            // Touch every chunk in the archive: what "read it all" costs,
            // against which random-access savings are judged.
            let file = std::fs::File::open(&archive).unwrap();
            let mut r = ArchiveReader::open(file, Auth::None, Limits::default()).unwrap();
            let hashes: Vec<_> = r.manifest.chunk_pool.keys().copied().collect();
            for h in hashes {
                black_box(r.read_chunk(&h).unwrap());
            }
        });
    });

    group.finish();
    std::fs::remove_dir_all(dir).ok();
}

criterion_group!(
    benches,
    bench_codecs,
    bench_chunking,
    bench_pipeline_roundtrip
);
criterion_main!(benches);
