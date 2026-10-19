//! Reproducible adaptive codec benchmarking over a real input corpus.
//!
//! The benchmark deliberately measures complete Cinder archives, including
//! chunking, deduplication, manifest writing, extraction, and verification.
//! A bounded sample is also compressed with every candidate profile first; it
//! provides a deterministic recommendation before the full corpus runs.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::codec::{codec_for_profile, Profile};
use crate::error::{CinderError, Result};
use crate::extract::{extract_archive, ExtractOptions};
use crate::pipeline::{compress_path, CompressOptions, ProgressEvent};
use crate::walk::{walk_tree, EntryKind};

const REPORT_VERSION: u32 = 1;
const DEFAULT_SAMPLE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BenchmarkOptions {
    pub profiles: Vec<Profile>,
    pub sample_bytes: u64,
    pub worker_count: Option<usize>,
}

impl Default for BenchmarkOptions {
    fn default() -> Self {
        Self {
            profiles: vec![Profile::Fast, Profile::Balanced, Profile::Max],
            sample_bytes: DEFAULT_SAMPLE_BYTES,
            worker_count: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSample {
    pub profile: String,
    pub input_bytes: u64,
    pub compressed_bytes: u64,
    pub ratio_percent: f64,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub profile: String,
    pub input_bytes: u64,
    pub archive_bytes: u64,
    pub compression_ms: u128,
    pub extraction_ms: u128,
    pub compression_mib_per_sec: f64,
    pub extraction_mib_per_sec: f64,
    pub ratio_percent: f64,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub report_version: u32,
    pub input: String,
    pub input_blake3: String,
    pub input_bytes: u64,
    pub sample_bytes: u64,
    pub samples: Vec<BenchmarkSample>,
    pub results: Vec<BenchmarkResult>,
    pub recommended_profile: String,
    pub generated_unix_secs: u64,
}

impl BenchmarkReport {
    /// Render a compact Markdown report suitable for CI artifacts or README
    /// attachments.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = format!(
            "# Cinder adaptive benchmark\n\n- Input: `{}`\n- BLAKE3: `{}`\n- Logical bytes: `{}`\n- Sample bytes: `{}`\n- Recommended profile: **{}**\n\n",
            self.input,
            self.input_blake3,
            self.input_bytes,
            self.sample_bytes,
            self.recommended_profile
        );
        out.push_str("| Profile | Archive bytes | Ratio | Compress | Extract | Verified |\n|---|---:|---:|---:|---:|:---:|\n");
        for result in &self.results {
            let _ = writeln!(
                out,
                "| `{}` | {} | {:.2}% | {:.2} MiB/s | {:.2} MiB/s | {} |\n",
                result.profile,
                result.archive_bytes,
                result.ratio_percent,
                result.compression_mib_per_sec,
                result.extraction_mib_per_sec,
                if result.verified { "yes" } else { "NO" }
            );
        }
        out
    }
}

/// Benchmark all requested profiles and return a machine-readable report.
///
/// # Errors
/// Returns filesystem, compression, extraction, or serialization failures.
pub fn benchmark_path(input: &Path, options: &BenchmarkOptions) -> Result<BenchmarkReport> {
    if options.profiles.is_empty() {
        return Err(CinderError::InvalidInput(
            "benchmark requires at least one profile".into(),
        ));
    }
    let corpus = sample_corpus(input, options.sample_bytes)?;
    let input_digest = hash_path(input)?;
    let samples = sample_profiles(&corpus, &options.profiles)?;
    let work = unique_temp_dir("benchmark")?;
    let quiet: Arc<dyn Fn(&ProgressEvent) + Send + Sync> = Arc::new(|_| {});
    let mut results = Vec::with_capacity(options.profiles.len());

    let full_input_bytes = walk_tree(input)?
        .entries
        .iter()
        .filter_map(|entry| match entry.kind {
            EntryKind::File { size, .. } => Some(size),
            _ => None,
        })
        .sum();

    for profile in &options.profiles {
        let name = profile_name(*profile);
        let archive = work.join(format!("{name}.cnd"));
        let started = std::time::Instant::now();
        let stats = compress_path(
            input,
            &archive,
            &CompressOptions {
                profile: *profile,
                worker_count: options.worker_count,
                ..CompressOptions::default()
            },
            &quiet,
        )?;
        let compression_ms = started.elapsed().as_millis();

        let restored = work.join(format!("restored-{name}"));
        let extraction_started = std::time::Instant::now();
        extract_archive(&archive, &restored, &ExtractOptions::default())?;
        let extraction_ms = extraction_started.elapsed().as_millis();
        let verified = hash_path(&restored)? == input_digest;
        let compress_rate = mib_per_sec(full_input_bytes, compression_ms);
        let extract_rate = mib_per_sec(full_input_bytes, extraction_ms);
        results.push(BenchmarkResult {
            profile: name,
            input_bytes: stats.input_bytes,
            archive_bytes: stats.archive_bytes,
            compression_ms,
            extraction_ms,
            compression_mib_per_sec: compress_rate,
            extraction_mib_per_sec: extract_rate,
            ratio_percent: ratio(stats.input_bytes, stats.archive_bytes),
            verified,
        });
        fs::remove_file(archive).ok();
        fs::remove_dir_all(restored).ok();
    }

    let recommended_profile = recommend(&samples, &results);
    let report = BenchmarkReport {
        report_version: REPORT_VERSION,
        input: input.display().to_string(),
        input_blake3: input_digest,
        input_bytes: full_input_bytes,
        sample_bytes: corpus.len() as u64,
        samples,
        results,
        recommended_profile,
        generated_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs(),
    };
    fs::remove_dir_all(work).ok();
    Ok(report)
}

fn sample_corpus(input: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if limit == 0 {
        return Ok(out);
    }
    for entry in walk_tree(input)?.entries {
        let EntryKind::File { .. } = entry.kind else {
            continue;
        };
        let remaining = limit.saturating_sub(out.len() as u64);
        if remaining == 0 {
            break;
        }
        let mut file = fs::File::open(entry.path)?;
        let mut buf = vec![
            0u8;
            usize::try_from(remaining.min(1024 * 1024)).map_err(|_| {
                CinderError::InvalidInput("benchmark sample size does not fit memory".into())
            })?
        ];
        let n = file.read(&mut buf)?;
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn sample_profiles(corpus: &[u8], profiles: &[Profile]) -> Result<Vec<BenchmarkSample>> {
    profiles
        .iter()
        .map(|profile| {
            let codec = codec_for_profile(*profile, None);
            let started = std::time::Instant::now();
            let mut compressed = Vec::new();
            codec.compress(corpus, &mut compressed)?;
            Ok(BenchmarkSample {
                profile: profile_name(*profile),
                input_bytes: corpus.len() as u64,
                compressed_bytes: compressed.len() as u64,
                ratio_percent: ratio(corpus.len() as u64, compressed.len() as u64),
                elapsed_ms: started.elapsed().as_millis(),
            })
        })
        .collect()
}

fn recommend(samples: &[BenchmarkSample], results: &[BenchmarkResult]) -> String {
    // The sample steers the recommendation toward the best ratio, while the
    // full run breaks close calls in favor of speed and rejects failed checks.
    let sample_best = samples
        .iter()
        .min_by(|a, b| a.compressed_bytes.cmp(&b.compressed_bytes))
        .map(|s| s.profile.as_str());
    results
        .iter()
        .filter(|r| r.verified)
        .min_by(|a, b| {
            let a_bias = i32::from(Some(a.profile.as_str()) != sample_best);
            let b_bias = i32::from(Some(b.profile.as_str()) != sample_best);
            (a_bias, a.archive_bytes, a.compression_ms).cmp(&(
                b_bias,
                b.archive_bytes,
                b.compression_ms,
            ))
        })
        .map_or_else(|| "none".into(), |r| r.profile.clone())
}

fn profile_name(profile: Profile) -> String {
    match profile {
        Profile::Fast => "fast".into(),
        Profile::Balanced => "balanced".into(),
        Profile::Max => "max".into(),
    }
}

fn ratio(input: u64, output: u64) -> f64 {
    if input == 0 {
        100.0
    } else {
        output as f64 * 100.0 / input as f64
    }
}

fn mib_per_sec(bytes: u64, millis: u128) -> f64 {
    let seconds = (millis as f64 / 1000.0).max(0.001);
    bytes as f64 / 1_048_576.0 / seconds
}

fn hash_path(path: &Path) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    if path.is_file() {
        if let Some(name) = path.file_name() {
            hasher.update(name.to_string_lossy().as_bytes());
            hasher.update(&[0]);
        }
        let mut file = fs::File::open(path)?;
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    } else {
        for entry in walk_tree(path)?.entries {
            if let EntryKind::File { .. } = entry.kind {
                hasher.update(entry.rel_path.as_bytes());
                hasher.update(&[0]);
                let mut file = fs::File::open(entry.path)?;
                let mut buf = vec![0u8; 128 * 1024];
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
            }
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn unique_temp_dir(label: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "cinder-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}
