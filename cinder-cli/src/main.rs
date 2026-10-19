//! cinder-cli - thin binary over `cinder-core`.
//!
//! All logic lives in the library; this file only parses arguments, renders
//! progress, and maps errors to exit codes.

// Presentation-layer exceptions, each intentional:
// - float casts: human-readable throughput/percent display never sees values
//   near f64's 2^53 exactness boundary for realistic archive sizes.
// - too_many_lines: `run` is one match over subcommands; splitting it would
//   scatter the CLI narrative across helpers without reducing complexity.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::collections::HashSet;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};

use anyhow::bail;
use cinder_core::codec::Profile;
use cinder_core::{
    compress_path, extract_archive, extract_file, ArchiveReader, ChunkParams, CompressOptions,
    ExtractOptions, Limits, ProgressEvent, SymlinkPolicy,
};

const BANNER: &str = r#"
   ____ _           _
  / ___(_)_ __   __| | ___ _ __
 | |   | | '_ \ / _` |/ _ \ '__|
 | |___| | | | | (_| |  __/ |
  \____|_|_| |_|\__,_|\___|_|

  deduplicate. protect. move fast.
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Tier {
    Fast,
    Balanced,
    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutFormat {
    Cinder,
    SevenZ,
    Rar,
    Zip,
    Tar,
    TarGz,
    TarZst,
    TarXz,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum RarGeneration {
    Rar13,
    Rar14,
    Rar15,
    Rar20,
    Rar29,
    Rar30,
    Rar40,
    Rar50,
    Rar70,
}

impl From<RarGeneration> for cinder_formats::RarVersion {
    fn from(version: RarGeneration) -> Self {
        match version {
            RarGeneration::Rar13 => Self::Rar13,
            RarGeneration::Rar14 => Self::Rar14,
            RarGeneration::Rar15 => Self::Rar15,
            RarGeneration::Rar20 => Self::Rar20,
            RarGeneration::Rar29 => Self::Rar29,
            RarGeneration::Rar30 => Self::Rar30,
            RarGeneration::Rar40 => Self::Rar40,
            RarGeneration::Rar50 => Self::Rar50,
            RarGeneration::Rar70 => Self::Rar70,
        }
    }
}

impl From<Tier> for Profile {
    fn from(t: Tier) -> Self {
        match t {
            Tier::Fast => Profile::Fast,
            Tier::Balanced => Profile::Balanced,
            Tier::Max => Profile::Max,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "cinder",
    version,
    about = "Deduplicating, seekable, optionally encrypted compressor/archiver"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an archive from a file or directory tree.
    Compress {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "balanced")]
        profile: Tier,
        /// Native negative zstd level (e.g. --fast=3 means -3); for foreign
        /// formats this is the codec level. Implies --profile fast.
        #[arg(long, value_parser = clap::value_parser!(i32).range(1..=5))]
        fast: Option<i32>,
        /// Disable solid batching of small files where the format supports it.
        #[arg(long)]
        no_solid: bool,
        /// Container format for the output.
        #[arg(long, value_enum, default_value = "cinder")]
        format: OutFormat,
        /// Encrypt supported outputs (Cinder, 7z, RAR); passphrase via `CINDER_PASSPHRASE`.
        #[arg(long)]
        encrypt: bool,
        /// Native/7z compression worker count. Defaults to a bounded host-aware value.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=256))]
        threads: Option<u16>,
        /// RAR writer generation, from RAR 1.3 through RAR 7.0.
        #[arg(long, value_enum, default_value = "rar50")]
        rar_version: RarGeneration,
        /// Split RAR 5/7 output into volumes (e.g. 100MB, 650MiB).
        #[arg(long, value_parser = parse_volume_size, value_name = "SIZE")]
        volume_size: Option<u64>,
    },
    /// Extract an archive into a directory.
    Extract {
        archive: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Overwrite existing files.
        #[arg(long)]
        overwrite: bool,
        /// Never recreate symlinks (write placeholders instead).
        #[arg(long)]
        no_symlinks: bool,
        /// Passphrase override; falls back to `CINDER_PASSPHRASE`.
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Pull a single member out of an archive without touching the rest.
    Get {
        archive: PathBuf,
        /// Archive-relative path of the member (forward slashes).
        member: String,
        #[arg(short, long)]
        output: PathBuf,
        /// Passphrase override; falls back to `CINDER_PASSPHRASE`.
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Extract ANY supported archive (auto-detects .cnd, zip, tar, tgz, -).
    X {
        archive: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Overwrite existing files.
        #[arg(long)]
        overwrite: bool,
        /// Passphrase override; falls back to `CINDER_PASSPHRASE`.
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// List archive contents.
    List {
        archive: PathBuf,
        /// Passphrase override; falls back to `CINDER_PASSPHRASE`.
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Verify every chunk hash in the archive.
    Verify {
        archive: PathBuf,
        /// Passphrase override; falls back to `CINDER_PASSPHRASE`.
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Adaptively benchmark all profiles and emit a JSON/Markdown corpus report.
    Bench {
        input: PathBuf,
        /// Write the report to this path; `.json` and `.md` siblings are emitted.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Maximum bytes sampled before the full profile runs.
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        sample_bytes: u64,
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=256))]
        threads: Option<u16>,
    },
    /// Maintain a persistent metadata-only cross-archive chunk index.
    Index {
        index: PathBuf,
        archive: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Create or apply a changed-files delta snapshot.
    Delta {
        #[command(subcommand)]
        command: DeltaCommand,
    },
    /// Generate a new Ed25519 private signing key.
    Keygen { output: PathBuf },
    /// Sign a native archive manifest into a detached `.sig.json` file.
    Sign {
        archive: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        signature: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Verify a detached native archive manifest signature.
    VerifySignature {
        archive: PathBuf,
        #[arg(long)]
        signature: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
    },
}

#[derive(Subcommand)]
enum DeltaCommand {
    /// Compare a live tree against a base archive without writing output.
    Compare {
        base: PathBuf,
        current: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Write a delta archive and its sidecar descriptor.
    Create {
        base: PathBuf,
        current: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value = "balanced")]
        profile: Tier,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Apply a base archive plus delta archive to a complete output tree.
    Apply {
        base: PathBuf,
        delta: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },
}

fn read_passphrase(explicit: Option<&String>) -> Result<String> {
    if let Some(p) = explicit {
        if p.is_empty() {
            bail!("passphrase must not be empty");
        }
        return Ok(p.clone());
    }
    if let Ok(value) = std::env::var("CINDER_PASSPHRASE") {
        if value.is_empty() {
            bail!("CINDER_PASSPHRASE must not be empty");
        }
        return Ok(value);
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        bail!("passphrase required: use CINDER_PASSPHRASE or an interactive terminal prompt");
    }
    rpassword::prompt_password("Cinder passphrase: ")
        .context("unable to read passphrase securely")
        .and_then(|value| {
            if value.is_empty() {
                bail!("passphrase must not be empty");
            }
            Ok(value)
        })
}

fn read_foreign_password(explicit: Option<&String>) -> Result<Option<String>> {
    if explicit.is_some() || std::env::var_os("CINDER_PASSPHRASE").is_some() {
        Ok(Some(read_passphrase(explicit)?))
    } else {
        Ok(None)
    }
}

fn new_bar(total: Option<u64>) -> ProgressBar {
    let bar = match total {
        Some(n) => ProgressBar::new(n),
        None => ProgressBar::new_spinner(),
    };
    bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} {bytes:>10} / {total_bytes:<10} {msg}",
        )
        .expect("static template")
        .progress_chars("=>-"),
    );
    bar
}

fn compress_progress(bar: &ProgressBar) -> Arc<dyn Fn(&ProgressEvent) + Send + Sync> {
    let seen = Arc::new(AtomicU64::new(0));
    let bar = bar.clone();
    Arc::new(move |ev| match ev {
        ProgressEvent::WalkDone { files, bytes } => {
            bar.set_length(*bytes);
            bar.set_message(format!("{files} files"));
        }
        ProgressEvent::BytesRead(total) => {
            bar.set_position(*total);
            let _ = seen.load(Ordering::Relaxed);
        }
        ProgressEvent::StreamStart { name } => {
            bar.set_message(name.to_string());
        }
        ProgressEvent::FramesWritten(n) => {
            let _ = n;
        }
    })
}

fn human_duration(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s >= 60.0 {
        format!("{:.1}m", s / 60.0)
    } else {
        format!("{s:.2}s")
    }
}

fn throughput(bytes: u64, d: Duration) -> String {
    let secs = d.as_secs_f64().max(1e-9);
    format!("{}/s", HumanBytes((bytes as f64 / secs) as u64))
}

fn parse_volume_size(value: &str) -> std::result::Result<u64, String> {
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (amount, unit) = value.split_at(split);
    let amount = amount
        .parse::<u64>()
        .map_err(|_| "volume size must begin with a whole number".to_string())?;
    if amount == 0 {
        return Err("volume size must be greater than zero".into());
    }
    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "ki" | "kib" => 1 << 10,
        "m" | "mb" => 1_000_000,
        "mi" | "mib" => 1 << 20,
        "g" | "gb" => 1_000_000_000,
        "gi" | "gib" => 1 << 30,
        "t" | "tb" => 1_000_000_000_000,
        "ti" | "tib" => 1u64 << 40,
        _ => return Err("use bytes or a size such as 100MB, 650MiB, or 4GiB".into()),
    };
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| "volume size is too large".to_string())
}

fn rar_first_volume_path(output: &std::path::Path) -> PathBuf {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let base = if output
        .extension()
        .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("rar"))
    {
        output
            .file_stem()
            .unwrap_or_else(|| output.file_name().unwrap_or_default())
    } else {
        output.file_name().unwrap_or_default()
    };
    let mut name = base.to_os_string();
    name.push(".part01.rar");
    parent.join(name)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!("{BANNER}");
    run(cli)
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Compress {
            input,
            output,
            profile,
            fast,
            no_solid,
            encrypt,
            format,
            threads,
            rar_version,
            volume_size,
        } => {
            if volume_size.is_some() && format != OutFormat::Rar {
                bail!("--volume-size is available only with --format rar");
            }
            if format != OutFormat::Rar && rar_version != RarGeneration::Rar50 {
                bail!("--rar-version is available only with --format rar");
            }
            // Foreign containers route through cinder-formats; only .cnd gets
            // native compression profiles. 7z and RAR support passwords.
            if format != OutFormat::Cinder {
                let rar_version: cinder_formats::RarVersion = rar_version.into();
                if volume_size.is_some() && !rar_version.supports_streamed_volumes() {
                    bail!("RAR volume creation requires --rar-version rar50 or rar70");
                }
                if encrypt && !matches!(format, OutFormat::SevenZ | OutFormat::Rar) {
                    bail!("--encrypt is supported only with cinder, 7z, or rar output");
                }
                let fmt = match format {
                    OutFormat::SevenZ => cinder_formats::CreateFormat::SevenZ,
                    OutFormat::Rar => cinder_formats::CreateFormat::Rar,
                    OutFormat::Zip => cinder_formats::CreateFormat::Zip,
                    OutFormat::Tar => cinder_formats::CreateFormat::Tar,
                    OutFormat::TarGz => cinder_formats::CreateFormat::TarGz,
                    OutFormat::TarZst => cinder_formats::CreateFormat::TarZst,
                    OutFormat::TarXz => cinder_formats::CreateFormat::TarXz,
                    OutFormat::Cinder => unreachable!(),
                };
                let level = if let Some(n) = fast {
                    i32::clamp(n, 1, 19)
                } else {
                    let tier_idx = match profile {
                        Tier::Fast => 0,
                        Tier::Balanced => 1,
                        Tier::Max => 2,
                    };
                    match format {
                        OutFormat::SevenZ => [0, 3, 9][tier_idx],
                        OutFormat::Rar => [0, 1, 5][tier_idx],
                        OutFormat::Zip | OutFormat::TarGz => [3, 6, 9][tier_idx],
                        OutFormat::TarZst => [3, 12, 19][tier_idx],
                        OutFormat::TarXz => [2, 4, 9][tier_idx],
                        OutFormat::Tar => 0,
                        OutFormat::Cinder => unreachable!(),
                    }
                };
                let started = Instant::now();
                let password = if encrypt {
                    Some(read_passphrase(None)?)
                } else {
                    None
                };
                let stats = cinder_formats::create(
                    &input,
                    &output,
                    fmt,
                    cinder_formats::CreateOptions {
                        level,
                        threads: threads.map(usize::from),
                        solid: !no_solid,
                        password,
                        rar_version,
                        rar_volume_size: volume_size,
                    },
                )?;
                let output_path = if stats.volume_count > 1 {
                    rar_first_volume_path(&output)
                } else {
                    output.clone()
                };
                let set_label = if stats.volume_count > 1 {
                    format!("{} volumes", stats.volume_count)
                } else {
                    "single archive".to_string()
                };
                println!(
                    "{} -> {} ({set_label}): {} -> {} ({:.1}%), {} files, {} dirs, {} symlinks skipped, {}",
                    input.display(),
                    output_path.display(),
                    HumanBytes(stats.input_bytes),
                    HumanBytes(stats.output_bytes),
                    ratio_pct(stats.input_bytes, stats.output_bytes),
                    stats.files,
                    stats.dirs,
                    stats.symlinks_skipped,
                    human_duration(started.elapsed()),
                );
                return Ok(());
            }

            let passphrase = if encrypt {
                Some(read_passphrase(None)?)
            } else {
                None
            };
            // --fast=N selects the fast tier with a negative zstd level.
            let profile = if fast.is_some() {
                Profile::Fast
            } else {
                profile.into()
            };
            let opts = CompressOptions {
                profile,
                fast_level_override: fast.map(|n| -n),
                solid_small_files: !no_solid,
                chunk_params: ChunkParams::default(),
                worker_count: threads.map(usize::from),
                encryption_passphrase: passphrase,
            };
            let bar = new_bar(Some(0));
            let sink = compress_progress(&bar);
            let started = Instant::now();
            let stats =
                compress_path(&input, &output, &opts, &sink).map_err(anyhow::Error::from)?;
            bar.finish_and_clear();
            println!(
                "{} -> {}: {} -> {} ({:.1}%), {} chunks ({} deduped), {}",
                input.display(),
                output.display(),
                HumanBytes(stats.input_bytes),
                HumanBytes(stats.archive_bytes),
                ratio_pct(stats.input_bytes, stats.archive_bytes),
                stats.unique_chunks,
                stats.duplicate_chunks,
                human_duration(started.elapsed()),
            );
            println!(
                "throughput {} (compress), {} frames written{}",
                throughput(stats.input_bytes.max(1), stats.elapsed),
                stats.frame_count,
                if stats.skipped_specials > 0 {
                    format!(", {} special files skipped", stats.skipped_specials)
                } else {
                    String::new()
                }
            );
        }
        Command::Extract {
            archive,
            output,
            overwrite,
            no_symlinks,
            passphrase,
        } => {
            let native = looks_like_cinder(&archive);
            if !native {
                let opts = cinder_formats::ExtractOptions {
                    overwrite,
                    password: read_foreign_password(passphrase.as_ref())?,
                    ..cinder_formats::ExtractOptions::default()
                };
                let started = Instant::now();
                let summary = cinder_formats::extract(&archive, &output, &opts)?;
                println!(
                    "extracted {} files ({} dirs), {} in {}",
                    summary.files,
                    summary.dirs,
                    HumanBytes(summary.bytes),
                    human_duration(started.elapsed())
                );
                return Ok(());
            }
            let needs_pw = native && archive_is_encrypted(&archive)?;
            let opts = ExtractOptions {
                limits: Limits::default(),
                symlink_policy: if no_symlinks {
                    SymlinkPolicy::Skip
                } else {
                    SymlinkPolicy::PreserveSafe
                },
                overwrite,
                passphrase: if needs_pw {
                    Some(read_passphrase(passphrase.as_ref())?)
                } else {
                    None
                },
            };
            let started = Instant::now();
            let stats = extract_archive(&archive, &output, &opts)?;
            println!(
                "extracted {} files ({} dirs, {} symlinks), {} in {}",
                stats.files_written,
                stats.dirs_created,
                stats.symlinks_created,
                HumanBytes(stats.bytes_written),
                human_duration(started.elapsed()),
            );
        }
        Command::Get {
            archive,
            member,
            output,
            passphrase,
        } => {
            if !looks_like_cinder(&archive) {
                let started = Instant::now();
                let normalized = member.replace('\\', "/");
                let temp = tempfile_dir()?;
                let opts = cinder_formats::ExtractOptions {
                    password: read_foreign_password(passphrase.as_ref())?,
                    ..cinder_formats::ExtractOptions::default()
                };
                let selection = cinder_formats::ExtractSelection::only(
                    [normalized.clone()].into_iter().collect::<HashSet<_>>(),
                );
                let result = cinder_formats::extract_selected(&archive, &temp, &opts, &selection);
                let summary = match result {
                    Ok(summary) => summary,
                    Err(error) => {
                        fs::remove_dir_all(&temp).ok();
                        return Err(error.into());
                    }
                };
                let source = temp.join(normalized.replace('/', std::path::MAIN_SEPARATOR_STR));
                if !source.is_file() {
                    fs::remove_dir_all(&temp).ok();
                    bail!("member not found: {member}");
                }
                if let Some(parent) = output.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut source_file = fs::File::open(&source)?;
                let mut output_file = cinder_core::extract::create_destination(&output, false)?;
                std::io::copy(&mut source_file, &mut output_file)?;
                fs::remove_dir_all(&temp).ok();
                println!(
                    "pulled {} -> {} ({} bytes) in {}",
                    member,
                    output.display(),
                    summary.bytes,
                    human_duration(started.elapsed())
                );
                return Ok(());
            }
            let mut opts = ExtractOptions::default();
            if looks_like_cinder(&archive) && archive_is_encrypted(&archive)? {
                opts.passphrase = Some(read_passphrase(passphrase.as_ref())?);
            }
            let started = Instant::now();
            let stats = extract_file(&archive, &member.replace('\\', "/"), &output, &opts)?;
            println!(
                "pulled {} -> {} ({} bytes) in {}",
                member,
                output.display(),
                stats.bytes_written,
                human_duration(started.elapsed())
            );
        }
        Command::X {
            archive,
            output,
            overwrite,
            passphrase,
        } => {
            let started = Instant::now();
            if looks_like_cinder(&archive) {
                let needs_pw = archive_is_encrypted(&archive)?;
                let opts = ExtractOptions {
                    limits: Limits::default(),
                    symlink_policy: SymlinkPolicy::PreserveSafe,
                    overwrite,
                    passphrase: if needs_pw {
                        Some(read_passphrase(passphrase.as_ref())?)
                    } else {
                        None
                    },
                };
                let stats = extract_archive(&archive, &output, &opts)?;
                println!(
                    "extracted {} files ({} dirs), {} in {} [cinder native]",
                    stats.files_written,
                    stats.dirs_created,
                    HumanBytes(stats.bytes_written),
                    human_duration(started.elapsed())
                );
            } else {
                let opts = cinder_formats::ExtractOptions {
                    overwrite,
                    password: read_foreign_password(passphrase.as_ref())?,
                    ..cinder_formats::ExtractOptions::default()
                };
                let summary = cinder_formats::extract(&archive, &output, &opts)?;
                println!(
                    "extracted {} files ({} dirs), {} in {}",
                    summary.files,
                    summary.dirs,
                    HumanBytes(summary.bytes),
                    human_duration(started.elapsed())
                );
            }
        }
        Command::List {
            archive,
            passphrase,
        } => {
            if !looks_like_cinder(&archive) {
                let password = read_foreign_password(passphrase.as_ref())?;
                let entries = cinder_formats::list_with_password(&archive, password.as_deref())?;
                println!("{:>10}  {:<12}  path", "size", "packed");
                for e in &entries {
                    println!(
                        "{:>10}  {:<12}  {}",
                        e.size
                            .map_or_else(|| "-".to_string(), |v| HumanBytes(v).to_string()),
                        e.packed
                            .map_or_else(|| "-".to_string(), |v| HumanBytes(v).to_string()),
                        e.name
                    );
                }
                return Ok(());
            }
            let file = std::fs::File::open(&archive)?;
            let auth = if archive_is_encrypted(&archive)? {
                cinder_core::crypto::Auth::Passphrase(read_passphrase(None)?)
            } else {
                cinder_core::crypto::Auth::None
            };
            let reader = ArchiveReader::open(file, auth, Limits::default())?;
            println!("{:>8}  {:<6}  path", "size", "mode");
            for d in &reader.manifest.directories {
                println!("{:>8}  {:<6o}  {}", "-", d.mode, d.path.display());
            }
            for f in &reader.manifest.files {
                let target = f
                    .symlink_target
                    .as_ref()
                    .map_or_else(String::new, |t| format!(" -> {}", t.display()));
                println!(
                    "{:>8}  {:<6o}  {}{}",
                    HumanBytes(f.length),
                    f.mode,
                    f.path.display(),
                    target
                );
            }
            let logical = reader.total_input_bytes();
            println!(
                "\n{} members, {} logical, {} on disk ({:.1}%), {} unique chunks",
                reader.manifest.files.len(),
                HumanBytes(logical),
                HumanBytes(reader.archive_size()),
                ratio_pct(logical, reader.archive_size()),
                reader.manifest.chunk_pool.len(),
            );
        }
        Command::Verify {
            archive,
            passphrase,
        } => {
            if !looks_like_cinder(&archive) {
                let password = read_foreign_password(passphrase.as_ref())?;
                let rep =
                    cinder_formats::test_with_password(&archive, u64::MAX, password.as_deref())?;
                println!(
                    "OK - {} entries, {} decompressed cleanly.",
                    rep.entries,
                    HumanBytes(rep.bytes)
                );
                return Ok(());
            }
            let file = std::fs::File::open(&archive)?;
            let auth = if archive_is_encrypted(&archive)? {
                cinder_core::crypto::Auth::Passphrase(read_passphrase(passphrase.as_ref())?)
            } else {
                cinder_core::crypto::Auth::None
            };
            let mut reader = ArchiveReader::open(file, auth, Limits::default())?;
            let pool = reader.manifest.chunk_pool.clone();
            let bar = new_bar(Some(pool.len() as u64));
            let started = Instant::now();
            for (i, hash) in pool.keys().enumerate() {
                reader.read_chunk(hash).map_err(anyhow::Error::from)?;
                bar.set_position(i as u64 + 1);
            }
            bar.finish_and_clear();
            println!(
                "verified {} unique chunks ({} archive bytes touched) in {}",
                pool.len(),
                HumanBytes(reader.physical_bytes_read()),
                human_duration(started.elapsed()),
            );
        }
        Command::Bench {
            input,
            output,
            sample_bytes,
            threads,
        } => {
            bench(
                &input,
                output.as_deref(),
                sample_bytes,
                threads.map(usize::from),
            )?;
        }
        Command::Index {
            index,
            archive,
            passphrase,
        } => {
            let secret = optional_passphrase(&archive, passphrase.as_ref())?;
            let stats = cinder_core::update_from_archive(&index, &archive, secret.as_deref())?;
            println!(
                "indexed {} unique chunks, {} archive references, {} logical chunk bytes",
                stats.unique_chunks, stats.archive_references, stats.bytes_indexed
            );
        }
        Command::Delta { command } => match command {
            DeltaCommand::Compare {
                base,
                current,
                passphrase,
            } => {
                let secret = optional_passphrase(&base, passphrase.as_ref())?;
                let report = cinder_core::compare_snapshot(&base, &current, secret.as_deref())?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            DeltaCommand::Create {
                base,
                current,
                output,
                profile,
                passphrase,
            } => {
                let secret = optional_passphrase(&base, passphrase.as_ref())?;
                let options = cinder_core::DeltaOptions {
                    compression: CompressOptions {
                        profile: profile.into(),
                        encryption_passphrase: secret.clone(),
                        ..CompressOptions::default()
                    },
                    passphrase: secret,
                };
                let quiet: Arc<dyn Fn(&ProgressEvent) + Send + Sync> = Arc::new(|_| {});
                let report = cinder_core::build_delta(&base, &current, &output, &options, &quiet)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            DeltaCommand::Apply {
                base,
                delta,
                output,
                passphrase,
            } => {
                let secret = optional_passphrase(&base, passphrase.as_ref())?;
                cinder_core::apply_delta(&base, &delta, &output, secret.as_deref())?;
                println!("delta applied successfully to {}", output.display());
            }
        },
        Command::Keygen { output } => {
            let public_key = cinder_core::generate_signing_key(&output)?;
            println!("created private key {}", output.display());
            println!("public key: {public_key}");
        }
        Command::Sign {
            archive,
            key,
            signature,
            passphrase,
        } => {
            let signature =
                signature.unwrap_or_else(|| cinder_core::default_signature_path(&archive));
            let secret = optional_passphrase(&archive, passphrase.as_ref())?;
            let signed = cinder_core::sign_archive(&archive, &key, &signature, secret.as_deref())?;
            println!("signed manifest written to {}", signature.display());
            println!("public key: {}", signed.public_key);
        }
        Command::VerifySignature {
            archive,
            signature,
            passphrase,
        } => {
            let signature =
                signature.unwrap_or_else(|| cinder_core::default_signature_path(&archive));
            let secret = optional_passphrase(&archive, passphrase.as_ref())?;
            let signed = cinder_core::verify_signature(&archive, &signature, secret.as_deref())?;
            println!("signature verified for public key {}", signed.public_key);
        }
    }
    Ok(())
}

fn looks_like_cinder(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok_and(|()| &magic == b"CINDERv1")
}

fn ratio_pct(input: u64, stored: u64) -> f64 {
    if input == 0 {
        100.0
    } else {
        stored as f64 * 100.0 / input as f64
    }
}

fn archive_is_encrypted(path: &std::path::Path) -> Result<bool> {
    use std::io::{Read, Seek};
    let mut f = std::fs::File::open(path)?;
    let mut hdr = [0u8; 16];
    f.read_exact(&mut hdr)?;
    if &hdr[0..8] != b"CINDERv1" {
        bail!("not a cinder archive: {}", path.display());
    }
    let _ = f.seek(std::io::SeekFrom::Start(0));
    Ok(u32::from_le_bytes(hdr[12..16].try_into()?) & 1 != 0)
}

/// Internal baseline measurement across profiles. External comparisons
/// (tar|zstd, 7-Zip, borgbackup) are recorded separately per the project's
/// measured-numbers-only policy.
fn bench(
    input: &std::path::Path,
    output: Option<&std::path::Path>,
    sample_bytes: u64,
    worker_count: Option<usize>,
) -> Result<()> {
    let report = cinder_core::benchmark_path(
        input,
        &cinder_core::BenchmarkOptions {
            sample_bytes,
            worker_count,
            ..cinder_core::BenchmarkOptions::default()
        },
    )?;
    println!("{}", report.to_markdown());
    if let Some(path) = output {
        let json_path = if path.extension().is_some_and(|ext| ext == "json") {
            path.to_path_buf()
        } else {
            path.with_extension("json")
        };
        let markdown_path = if path.extension().is_some_and(|ext| ext == "md") {
            path.to_path_buf()
        } else {
            path.with_extension("md")
        };
        std::fs::write(&json_path, serde_json::to_vec_pretty(&report)?)?;
        std::fs::write(&markdown_path, report.to_markdown())?;
        println!(
            "reports written to {} and {}",
            json_path.display(),
            markdown_path.display()
        );
    }
    Ok(())
}

fn optional_passphrase(
    archive: &std::path::Path,
    explicit: Option<&String>,
) -> Result<Option<String>> {
    if !looks_like_cinder(archive) || !archive_is_encrypted(archive)? {
        return Ok(None);
    }
    Ok(Some(read_passphrase(explicit)?))
}

fn tempfile_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    let uniq = format!(
        "cinder-bench-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let p = base.join(uniq);
    std::fs::create_dir_all(&p)?;
    Ok(p)
}
