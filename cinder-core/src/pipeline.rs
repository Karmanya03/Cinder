//! The compression pipeline.
//!
//! Three stages connected by bounded channels so memory stays flat regardless
//! of input size:
//!
//! ```text
//! producer (calling thread)     rayon workers               writer thread
//! ─────────────────────────    ──────────────────────      ─────────────────────
//! walk · assemble ·       ──▶  skip-check · compress ──▶   reorder by seq ·
//! FastCDC · BLAKE3             · AEAD-seal                 append frames in
//! · dedup check                                            order · seek table
//! ```
//!
//! Packing contract: one [`WorkItem`] is exactly one archive *frame* holding
//! one or more consecutive chunks that are all new to the pool. The worker
//! compresses/seals the concatenation; the writer appends the frame and
//! records every member hash against its slice inside the frame's decompressed
//! content. Frames land in production order, so archives are reproducible,
//! and the producer parks at each stream boundary until the writer has caught
//! up, bounding in-flight memory to a couple of frames per worker.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use blake3::Hash;
use crossbeam_channel::{bounded, Receiver, Sender};
use memmap2::Mmap;

use crate::archive::manifest::{ChunkLocation, DirRecord, FileEntry, Manifest, StreamEntry};
use crate::archive::writer::FrameSink;
use crate::chunk::{cut_chunks, ChunkParams};
use crate::codec::{codec_for_profile, Codec, CodecId, Profile};
use crate::crypto::{derive_keys, random_salt, ArchiveKeys};
use crate::error::{CinderError, Result};
use crate::walk::{walk_paths, EntryKind, WalkedEntry};

/// Target decompressed bytes per packed frame. Consecutive new chunks pack
/// into one frame until this is reached: bigger frames give zstd more window
/// context (better ratio), smaller frames make random access cheaper.
const PACK_TARGET_BYTES: usize = 2 * 1024 * 1024;
/// Files smaller than this are candidates for solid batching.
const SOLID_FILE_THRESHOLD: u64 = 1024 * 1024;
/// Solid group caps keep assembly buffers bounded.
const SOLID_GROUP_MAX_BYTES: u64 = 32 * 1024 * 1024;
const SOLID_GROUP_MAX_FILES: usize = 2048;
/// Files this size or larger are read through a memory map.
const MMAP_THRESHOLD: u64 = 256 * 1024;
/// Progress callback throttle.
const PROGRESS_STEP: u64 = 8 * 1024 * 1024;

/// Progress notifications surfaced to callers (the CLI feeds indicatif).
pub enum ProgressEvent<'a> {
    /// Walk finished: file count and total input size.
    WalkDone { files: usize, bytes: u64 },
    /// A stream began processing; name is its first member's path.
    StreamStart { name: &'a str },
    /// Cumulative source bytes cut into chunks so far.
    BytesRead(u64),
    /// Cumulative frames appended to the archive.
    FramesWritten(u64),
}

/// Knobs for one compression run.
#[derive(Debug, Clone)]
pub struct CompressOptions {
    pub profile: Profile,
    /// Negative levels (`--fast=N` → `-N`) apply only to [`Profile::Fast`].
    pub fast_level_override: Option<i32>,
    /// Batch small files into shared solid streams (default true).
    pub solid_small_files: bool,
    pub chunk_params: ChunkParams,
    /// Number of compression workers. `None` selects a bounded host-aware
    /// default; explicit values make benchmarking and low-memory deployments
    /// reproducible.
    pub worker_count: Option<usize>,
    /// When set, payloads and manifest are sealed with XChaCha20-Poly1305
    /// under an Argon2id-derived key.
    pub encryption_passphrase: Option<String>,
}

impl Default for CompressOptions {
    fn default() -> Self {
        Self {
            profile: Profile::Balanced,
            fast_level_override: None,
            solid_small_files: true,
            chunk_params: ChunkParams::default(),
            worker_count: None,
            encryption_passphrase: None,
        }
    }
}

/// Measured outcome of a compression run.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionStats {
    pub input_bytes: u64,
    pub archive_bytes: u64,
    pub file_count: usize,
    pub dir_count: usize,
    pub symlink_count: usize,
    pub unique_chunks: usize,
    pub duplicate_chunks: usize,
    pub frame_count: u64,
    pub skipped_specials: u64,
    /// Frames stored verbatim because the gate deemed them incompressible.
    pub stored_frames: u64,
    pub elapsed: std::time::Duration,
}

struct WorkItem {
    seq: u64,
    /// Chunk identities in order inside `raw`.
    hashes: Vec<(Hash, u32)>,
    raw: Vec<u8>,
}

struct DoneItem {
    seq: u64,
    hashes: Vec<(Hash, u32)>,
    codec: CodecId,
    encrypted: bool,
    payload: Vec<u8>,
    raw_len: u64,
}

type DoneMsg = Result<DoneItem>;

/// State shared across the pipeline threads.
struct Shared {
    /// Contiguous prefix of frames fully appended (`count` frames, ids 0..count).
    written_count: Mutex<u64>,
    written_cv: Condvar,
    stored_bytes: AtomicU64,
    stored_frames: AtomicU64,
    first_error: Mutex<Option<CinderError>>,
}

impl Shared {
    fn new() -> Self {
        Self {
            written_count: Mutex::new(0),
            written_cv: Condvar::new(),
            stored_bytes: AtomicU64::new(0),
            stored_frames: AtomicU64::new(0),
            first_error: Mutex::new(None),
        }
    }

    /// Record the first fatal error and wake anyone parked on the barrier.
    ///
    /// Lock poisoning here can only come from a panicking sibling thread, not
    /// from filesystem/user data, so recovery-by-ignore is sound: the panic
    /// itself propagates and aborts the run loudly.
    fn fail(&self, e: CinderError) {
        if let Ok(mut slot) = self.first_error.lock() {
            if slot.is_none() {
                *slot = Some(e);
            }
        }
        self.written_cv.notify_all();
    }

    fn snapshot_error(&self) -> Option<CinderError> {
        self.first_error
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(std::string::ToString::to_string))
            .map(CinderError::CorruptArchive)
    }

    /// Block until frame `seq` is durably appended, or any thread failed.
    ///
    /// `.expect()` guards mutex poisoning by sibling-thread panics only —
    /// outside the project's no-unwrap rule targeting data-dependent paths.
    fn wait_written(&self, seq: u64) -> Result<()> {
        let mut guard = self.written_count.lock().expect("written_count poisoned");
        loop {
            if *guard > seq {
                return Ok(());
            }
            if let Some(e) = self.snapshot_error() {
                return Err(e);
            }
            guard = self
                .written_cv
                .wait(guard)
                .expect("written_count poisoned while waiting");
        }
    }
}

enum StreamPlan {
    SingleFile { entry_index: usize },
    SolidGroup { entry_indices: Vec<usize> },
}

fn file_size_of(e: &WalkedEntry) -> u64 {
    match e.kind {
        EntryKind::File { size, .. } => size,
        _ => 0,
    }
}

fn file_mode_of(e: &WalkedEntry) -> u32 {
    match e.kind {
        EntryKind::File { mode, .. }
        | EntryKind::Symlink { mode, .. }
        | EntryKind::Dir { mode } => mode,
    }
}

/// Partition walked files into compression streams.
fn plan_streams(files: &[WalkedEntry], solid_enabled: bool) -> Vec<StreamPlan> {
    let mut plans = Vec::new();
    if !solid_enabled {
        for i in 0..files.len() {
            plans.push(StreamPlan::SingleFile { entry_index: i });
        }
        return plans;
    }
    let mut group: Vec<usize> = Vec::new();
    let mut group_bytes = 0u64;
    for (i, f) in files.iter().enumerate() {
        let size = file_size_of(f);
        if size >= SOLID_FILE_THRESHOLD
            || group.len() >= SOLID_GROUP_MAX_FILES
            || (!group.is_empty() && group_bytes.saturating_add(size) > SOLID_GROUP_MAX_BYTES)
        {
            flush_group(&mut plans, &mut group, &mut group_bytes);
            if size >= SOLID_FILE_THRESHOLD {
                plans.push(StreamPlan::SingleFile { entry_index: i });
                continue;
            }
        }
        group.push(i);
        group_bytes = group_bytes.saturating_add(size);
    }
    flush_group(&mut plans, &mut group, &mut group_bytes);
    plans
}

fn flush_group(plans: &mut Vec<StreamPlan>, group: &mut Vec<usize>, group_bytes: &mut u64) {
    match group.len() {
        0 => {}
        1 => plans.push(StreamPlan::SingleFile {
            entry_index: group[0],
        }),
        _ => plans.push(StreamPlan::SolidGroup {
            entry_indices: std::mem::take(group),
        }),
    }
    *group_bytes = 0;
}

/// Memory-mapped read-only view of a source file.
///
/// This is the only `unsafe` in cinder-core. SAFETY CONTRACT: memmap2
/// requires that the underlying file not be truncated while mapped, else
/// reads fault. We open the descriptor read-only, map it, and drop both
/// together before returning. Concurrent external mutation of the *source* is
/// outside our control (the same trade-off restic/borg accept): worst case is
/// an OS-level fault surfaced as an error in this process — it cannot violate
/// safe-Rust aliasing rules, and any resulting archive is caught downstream
/// by BLAKE3 verification.
struct MappedInput {
    #[allow(dead_code)] // held so the mapping stays valid for its lifetime
    file: fs::File,
    map: Mmap,
}

/// Read-only byte source for one stream.
enum SourceBytes {
    Owned(Vec<u8>),
    Mapped(MappedInput),
}

impl SourceBytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(v) => v.as_slice(),
            Self::Mapped(m) => &m.map[..],
        }
    }
}

fn read_source(path: &Path, size: u64) -> Result<SourceBytes> {
    if size >= MMAP_THRESHOLD {
        let file = fs::File::open(path)?;
        // SAFETY: see the MappedInput contract above.
        let map = unsafe { Mmap::map(&file)? };
        return Ok(SourceBytes::Mapped(MappedInput { file, map }));
    }
    Ok(SourceBytes::Owned(fs::read(path)?))
}

fn reject_output_alias(input: &Path, output: &Path) -> Result<()> {
    let input_canonical = fs::canonicalize(input)?;
    if let Ok(output_canonical) = fs::canonicalize(output) {
        if output_canonical == input_canonical {
            return Err(CinderError::InvalidInput(
                "output must not replace the input".into(),
            ));
        }
    }
    if input_canonical.is_dir() {
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        let parent_canonical = fs::canonicalize(parent)?;
        if parent_canonical.starts_with(&input_canonical) {
            return Err(CinderError::InvalidInput(
                "output must not be placed inside the input tree".into(),
            ));
        }
    }
    Ok(())
}

/// Incompressibility gate applied before spending CPU on a real codec pass.
///
/// Two cheap checks: known already-compressed magic bytes, then a zstd-1
/// probe on a small prefix sample. Media that would expand or barely shrink
/// gets framed as `Stored` instead.
fn looks_incompressible(data: &[u8]) -> bool {
    const SIGS: &[&[u8]] = &[
        b"PK\x03\x04",         // zip
        b"PK\x05\x06",         // empty zip
        b"\x1f\x8b",           // gzip
        b"\x28\xb5\x2f\xfd",   // zstd
        b"\xfd7zXZ\x00",       // xz
        b"7z\xbc\xaf\x27\x1c", // 7z
        b"BZh",                // bzip2
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff", // jpeg
        b"OggS",
        b"fLaC",
    ];
    for sig in SIGS {
        if data.starts_with(sig) {
            return true;
        }
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return true; // MP4/QuickTime container
    }
    // Prefix probe: if level-1 zstd barely shrinks the sample, a full pass
    // will not pay for itself either.
    let sample_len = data.len().min(16 * 1024);
    let sample = &data[..sample_len];
    match zstd::bulk::compress(sample, 1) {
        Ok(c) => c.len() * 20 >= sample.len() * 19, // ratio worse than ~0.95
        Err(_) => false,                            // probe failure → attempt full pass anyway
    }
}

fn process_frame(item: &WorkItem, codec: &dyn Codec, keys: Option<&ArchiveKeys>) -> DoneMsg {
    let (codec_id, payload) = if item.raw.is_empty() {
        // A frame always carries ≥1 chunk ≥1 byte; defensive only.
        return Err(CinderError::CorruptArchive("empty frame produced".into()));
    } else if looks_incompressible(&item.raw) {
        (CodecId::Stored, item.raw.clone())
    } else {
        let mut out = Vec::with_capacity(item.raw.len() / 2 + 16);
        codec.compress(&item.raw, &mut out)?;
        if out.len() >= item.raw.len() {
            (CodecId::Stored, item.raw.clone())
        } else {
            (codec.id(), out)
        }
    };
    let mut encrypted = false;
    let final_payload = match keys {
        Some(k) => {
            encrypted = true;
            k.seal_frame(&payload)?
        }
        None => payload,
    };
    Ok(DoneItem {
        seq: item.seq,
        hashes: item.hashes.clone(),
        codec: codec_id,
        encrypted,
        payload: final_payload,
        raw_len: item.raw.len() as u64,
    })
}

fn worker_loop(
    work_rx: &Receiver<WorkItem>,
    done_tx: &Sender<DoneMsg>,
    codec: Arc<dyn Codec>,
    keys: Option<ArchiveKeys>,
) {
    while let Ok(item) = work_rx.recv() {
        let msg = process_frame(&item, codec.as_ref(), keys.as_ref());
        if done_tx.send(msg).is_err() {
            break; // writer gone; abort already recorded
        }
    }
}

struct WriterOutcome {
    sink: FrameSink,
    frames_written: u64,
    stored_frames: u64,
    pool: HashMap<Hash, ChunkLocation>,
}

fn writer_loop(
    mut sink: FrameSink,
    done_rx: Receiver<DoneMsg>,
    shared: Arc<Shared>,
    progress: &(dyn Fn(&ProgressEvent) + Sync),
) -> Result<WriterOutcome> {
    let mut next_seq: u64 = 0;
    let mut pending: HashMap<u64, DoneItem> = HashMap::new();
    let mut pool: HashMap<Hash, ChunkLocation> = HashMap::new();
    let mut stored_frames: u64 = 0;

    while let Ok(msg) = done_rx.recv() {
        let done = match msg {
            Err(e) => {
                shared.fail(e);
                continue;
            }
            Ok(d) => d,
        };
        pending.insert(done.seq, done);
        // Append in production order as the sequence gap closes. Once any
        // error exists, stop writing but keep draining the channel so
        // senders never block.
        loop {
            if shared.snapshot_error().is_some() {
                break;
            }
            let Some(d) = pending.remove(&next_seq) else {
                break;
            };
            match sink.write_frame(d.codec, d.encrypted, &d.payload, d.raw_len) {
                Ok(pos) => {
                    if d.codec == CodecId::Stored {
                        stored_frames += 1;
                        shared.stored_frames.fetch_add(1, Ordering::Relaxed);
                    }
                    let mut slice_off: u32 = 0;
                    for (h, len) in d.hashes {
                        pool.insert(
                            h,
                            ChunkLocation {
                                frame_offset: pos.offset,
                                frame_length: pos.total_len,
                                payload_offset: slice_off,
                                payload_length: len,
                            },
                        );
                        slice_off = slice_off.checked_add(len).ok_or_else(|| {
                            CinderError::CorruptArchive("packed frame slice overflow".into())
                        })?;
                    }
                    shared
                        .stored_bytes
                        .fetch_add(u64::from(pos.total_len), Ordering::Relaxed);
                    next_seq += 1;
                    if let Ok(mut n) = shared.written_count.lock() {
                        *n = next_seq;
                    }
                    shared.written_cv.notify_all();
                    (progress)(&ProgressEvent::FramesWritten(next_seq));
                }
                Err(e) => {
                    shared.fail(e);
                }
            }
        }
    }

    if let Some(e) = shared.snapshot_error() {
        return Err(e);
    }
    if !pending.is_empty() {
        return Err(CinderError::CorruptArchive(format!(
            "pipeline lost {} frame(s) before write",
            pending.len()
        )));
    }
    Ok(WriterOutcome {
        sink,
        frames_written: next_seq,
        stored_frames,
        pool,
    })
}

/// Per-stream bookkeeping accumulated during production.
struct StreamBuild {
    chunks: Vec<Hash>,
    length: u64,
}

/// Compress a file or directory tree into a Cinder archive.
///
/// The function is long but linear: walk → plan → keys → threaded pipeline →
/// manifest/footer. Splitting it would thread six pieces of mutable state
/// through helper signatures for no review benefit.
#[allow(clippy::too_many_lines)]
///
/// # Errors
/// Propagates walk/read/write failures, invalid options, and any pipeline
/// error raised by workers or the writer thread. On error the partial output
/// file may remain on disk; callers should treat it as garbage (the CLI
/// removes it).
pub fn compress_path(
    input: &Path,
    output: &Path,
    opts: &CompressOptions,
    progress: &Arc<dyn Fn(&ProgressEvent) + Send + Sync>,
) -> Result<CompressionStats> {
    compress_paths(&[input.to_path_buf()], output, opts, progress)
}

/// Compress several files and folders into one archive.
///
/// Multiple inputs are placed under their own top-level name. Duplicate
/// archive paths are rejected before the output file is opened.
#[allow(clippy::too_many_lines)]
pub fn compress_paths(
    inputs: &[PathBuf],
    output: &Path,
    opts: &CompressOptions,
    progress: &Arc<dyn Fn(&ProgressEvent) + Send + Sync>,
) -> Result<CompressionStats> {
    opts.chunk_params.validate()?;
    if opts.worker_count == Some(0) {
        return Err(CinderError::InvalidInput(
            "worker_count must be at least 1".into(),
        ));
    }
    if opts.chunk_params.max > PACK_TARGET_BYTES * 8 {
        return Err(CinderError::InvalidInput(
            "chunk max size exceeds pipeline packing sanity bound".into(),
        ));
    }
    if inputs.is_empty() {
        return Err(CinderError::InvalidInput(
            "at least one input path is required".into(),
        ));
    }
    for input in inputs {
        if !input.exists() {
            return Err(CinderError::InvalidInput(format!(
                "input {} does not exist",
                input.display()
            )));
        }
        reject_output_alias(input, output)?;
    }
    let started = std::time::Instant::now();

    // ---- phase 1: walk & plan -------------------------------------------
    let walked = walk_paths(inputs)?;
    let skipped_specials = walked.skipped_specials;

    let mut dirs: Vec<DirRecord> = Vec::new();
    let mut files: Vec<WalkedEntry> = Vec::new();
    let mut symlink_entries: Vec<FileEntry> = Vec::new();
    for e in walked.entries {
        match e.kind {
            EntryKind::Dir { mode } => dirs.push(DirRecord {
                path: PathBuf::from(&e.rel_path),
                mode,
            }),
            EntryKind::File { .. } => files.push(e),
            EntryKind::Symlink { target, mode } => symlink_entries.push(FileEntry {
                path: PathBuf::from(&e.rel_path),
                mode,
                symlink_target: Some(target),
                stream_id: u32::MAX, // content lives in the link target string
                offset: 0,
                length: 0,
            }),
        }
    }
    let dir_count = dirs.len();
    let symlink_count = symlink_entries.len();

    let total_input = files.iter().try_fold(0u64, |total, file| {
        total
            .checked_add(file_size_of(file))
            .ok_or_else(|| CinderError::InvalidInput("input size overflow".into()))
    })?;
    (progress)(&ProgressEvent::WalkDone {
        files: files.len(),
        bytes: total_input,
    });
    let plans = plan_streams(&files, opts.solid_small_files);

    // ---- phase 2: crypto -------------------------------------------------
    let salt = random_salt()?;
    let keys = Arc::new(match &opts.encryption_passphrase {
        Some(p) => Some(derive_keys(p, &salt)?),
        None => None,
    });

    // ---- phase 3: threaded pipeline --------------------------------------
    let sink = FrameSink::create(
        output,
        keys.is_some(),
        u32::try_from(opts.chunk_params.avg)
            .map_err(|_| CinderError::InvalidInput("avg chunk size overflow".into()))?,
    )?;
    let shared = Arc::new(Shared::new());
    let host_workers = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .clamp(1, 64);
    let workers = opts.worker_count.unwrap_or(host_workers).clamp(1, 256);
    let (work_tx, work_rx) = bounded::<WorkItem>(workers * 2);
    let (done_tx, done_rx) = bounded::<DoneMsg>(workers * 2);
    let codec: Arc<dyn Codec> =
        Arc::from(codec_for_profile(opts.profile, opts.fast_level_override));

    let writer_shared = Arc::clone(&shared);
    let writer_progress = Arc::clone(progress);
    let writer_handle = std::thread::Builder::new()
        .name("cinder-writer".into())
        .spawn(move || writer_loop(sink, done_rx, writer_shared, writer_progress.as_ref()))
        .map_err(|e| CinderError::Io(std::io::Error::other(format!("writer spawn: {e}"))))?;

    let mut streams: Vec<StreamBuild> = Vec::with_capacity(plans.len());
    let mut file_meta: Vec<(u32, u64, u64)> = vec![(0, 0, 0); files.len()];
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut duplicate_chunks_total = 0usize;
    let mut bytes_read_total = 0u64;
    let mut next_progress_mark = PROGRESS_STEP;
    let producer_err: Mutex<Option<CinderError>> = Mutex::new(None);

    {
        // Workers live in a rayon scope so they share this call's lifetime.
        let producer_err_ref = &producer_err;
        rayon::scope(|s| {
            for _ in 0..workers {
                let rx = work_rx.clone();
                let tx = done_tx.clone();
                let codec_c = Arc::clone(&codec);
                let keys_c = Arc::clone(&keys);
                s.spawn(move |_| worker_loop(&rx, &tx, codec_c, keys_c.as_ref().clone()));
            }
            drop(work_rx);
            drop(done_tx);

            // Producer: assemble → cut → dedup-check → enqueue packed frames.
            let mut produce = || -> Result<()> {
                let mut seq_counter: u64 = 0;
                let mut open_job_raw: Vec<u8> = Vec::with_capacity(PACK_TARGET_BYTES + 1024);
                let mut open_job_hashes: Vec<(Hash, u32)> = Vec::new();

                for plan in &plans {
                    let (entry_indices, name): (Vec<usize>, String) = match plan {
                        StreamPlan::SingleFile { entry_index } => {
                            (vec![*entry_index], files[*entry_index].rel_path.clone())
                        }
                        StreamPlan::SolidGroup { entry_indices } => (
                            entry_indices.clone(),
                            files[entry_indices[0]].rel_path.clone(),
                        ),
                    };
                    (progress)(&ProgressEvent::StreamStart { name: &name });

                    // Assemble source bytes. Member ranges come from bytes
                    // actually read, not walk-time metadata, so a source that
                    // changed between walk and read can never desync the map.
                    let mut member_starts: Vec<u64> = Vec::new();
                    let source: SourceBytes = if entry_indices.len() == 1 {
                        let f = &files[entry_indices[0]];
                        read_source(&f.path, file_size_of(f))?
                    } else {
                        let mut buf: Vec<u8> = Vec::new();
                        for idx in &entry_indices {
                            member_starts.push(buf.len() as u64);
                            buf.extend_from_slice(&fs::read(&files[*idx].path)?);
                        }
                        SourceBytes::Owned(buf)
                    };
                    let data: &[u8] = source.as_slice();

                    let stream_id = streams.len() as u32;
                    streams.push(StreamBuild {
                        chunks: Vec::new(),
                        length: data.len() as u64,
                    });

                    // Record each member's byte range inside the stream.
                    if entry_indices.len() == 1 {
                        let idx = entry_indices[0];
                        file_meta[idx] = (stream_id, 0, data.len() as u64);
                    } else {
                        for (slot, idx) in entry_indices.iter().enumerate() {
                            let start = member_starts[slot];
                            // Members are contiguous and adjacent in `data`;
                            // the last one runs to the end of the buffer.
                            let end = member_starts
                                .get(slot + 1)
                                .copied()
                                .unwrap_or(data.len() as u64);
                            file_meta[*idx] = (stream_id, start, end - start);
                        }
                    }

                    let mut stream_last_seq: Option<u64> = None;
                    for c in cut_chunks(data, &opts.chunk_params) {
                        bytes_read_total = bytes_read_total
                            .checked_add(u64::from(c.length))
                            .ok_or_else(|| {
                                CinderError::InvalidInput("read counter overflow".into())
                            })?;
                        if bytes_read_total >= next_progress_mark {
                            (progress)(&ProgressEvent::BytesRead(bytes_read_total));
                            next_progress_mark = bytes_read_total + PROGRESS_STEP;
                        }
                        let start = usize::try_from(c.offset).map_err(|_| {
                            CinderError::CorruptArchive("chunk offset overflow".into())
                        })?;
                        let end = start
                            .checked_add(usize::try_from(c.length).map_err(|_| {
                                CinderError::CorruptArchive("chunk length overflow".into())
                            })?)
                            .ok_or_else(|| {
                                CinderError::CorruptArchive("chunk slice overflow".into())
                            })?;
                        let slice = data.get(start..end).ok_or_else(|| {
                            CinderError::CorruptArchive("chunk slice outside source".into())
                        })?;

                        if seen.contains(&c.hash) {
                            duplicate_chunks_total += 1;
                            flush_open_job(
                                &work_tx,
                                &mut seq_counter,
                                &mut open_job_raw,
                                &mut open_job_hashes,
                                &mut stream_last_seq,
                            );
                            streams[stream_id as usize].chunks.push(c.hash);
                            continue;
                        }
                        seen.insert(c.hash);
                        open_job_raw.extend_from_slice(slice);
                        open_job_hashes.push((c.hash, c.length));
                        // Every chunk — fresh or duplicate — must appear in
                        // its stream's ordered chunk list or extraction can't
                        // reassemble the logical byte sequence.
                        streams[stream_id as usize].chunks.push(c.hash);
                        if open_job_raw.len() >= PACK_TARGET_BYTES {
                            flush_open_job(
                                &work_tx,
                                &mut seq_counter,
                                &mut open_job_raw,
                                &mut open_job_hashes,
                                &mut stream_last_seq,
                            );
                        }
                    }
                    flush_open_job(
                        &work_tx,
                        &mut seq_counter,
                        &mut open_job_raw,
                        &mut open_job_hashes,
                        &mut stream_last_seq,
                    );

                    // Barrier: don't assemble the next stream until this one
                    // is durably on disk — caps in-flight buffering.
                    if let Some(last) = stream_last_seq {
                        shared.wait_written(last)?;
                    }
                }
                (progress)(&ProgressEvent::BytesRead(bytes_read_total));
                Ok(())
            };

            if let Err(e) = produce() {
                if let Ok(mut slot) = producer_err_ref.lock() {
                    *slot = Some(e);
                }
            }
            // Closing the work channel here is what lets workers exit and the
            // scope join complete; dropping anything less would deadlock.
            drop(work_tx);
        });
    }

    // Reap threads in fixed precedence: producer error wins, then writer.
    let outcome = writer_handle
        .join()
        .map_err(|_| CinderError::CorruptArchive("writer thread panicked".into()))??;
    if let Some(e) = producer_err
        .into_inner()
        .expect("producer err slot poisoned")
    {
        return Err(e);
    }

    // ---- phase 4: manifest & footer ---------------------------------------
    let mut files_entries: Vec<FileEntry> = Vec::with_capacity(files.len() + symlink_entries.len());
    for (i, f) in files.iter().enumerate() {
        let (stream_id, offset, length) = file_meta[i];
        files_entries.push(FileEntry {
            path: PathBuf::from(&f.rel_path),
            mode: file_mode_of(f),
            symlink_target: None,
            stream_id,
            offset,
            length,
        });
    }
    files_entries.extend(symlink_entries);
    let file_count_regular = files_entries.len() - symlink_count;
    let manifest = Manifest {
        directories: dirs,
        files: files_entries,
        streams: streams
            .into_iter()
            .map(|s| StreamEntry {
                chunks: s.chunks,
                length: s.length,
            })
            .collect(),
        chunk_pool: outcome.pool,
        ..Manifest::default()
    };

    let region = manifest.encode()?;
    outcome
        .sink
        .finish(&region, keys.as_ref().as_ref(), &salt)?;

    let archive_bytes = fs::metadata(output)?.len();
    Ok(CompressionStats {
        input_bytes: total_input,
        archive_bytes,
        file_count: file_count_regular,
        dir_count,
        symlink_count,
        unique_chunks: manifest.chunk_pool.len(),
        duplicate_chunks: duplicate_chunks_total,
        frame_count: outcome.frames_written,
        stored_frames: outcome.stored_frames,
        skipped_specials,
        elapsed: started.elapsed(),
    })
}

/// Ship the currently accumulating frame job, if any.
fn flush_open_job(
    tx: &Sender<WorkItem>,
    seq_counter: &mut u64,
    raw: &mut Vec<u8>,
    hashes: &mut Vec<(Hash, u32)>,
    last_seq: &mut Option<u64>,
) {
    if hashes.is_empty() {
        return;
    }
    *seq_counter += 1;
    *last_seq = Some(*seq_counter - 1);
    let item = WorkItem {
        seq: *seq_counter - 1,
        hashes: std::mem::take(hashes),
        raw: std::mem::take(raw),
    };
    raw.reserve(PACK_TARGET_BYTES + 1024);
    // A closed channel means the writer already failed; the barrier wait or
    // the final join surfaces that error, so the send result is noise here.
    let _ = tx.send(item);
}
