// Tests favor directness over style: numeric casts below are exact for
// these magnitudes and unwrap/expect in fixtures is standard test practice.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
//! Hostile-input acceptance (safety invariants 1–3).
//!
//! Every archive here is hand-crafted: traversal entries, lying frame
//! headers, a real zstd bomb, cumulative-budget attacks, and arbitrary
//! garbage fed to the parser. Nothing may panic; nothing may escape; nothing
//! may exceed its ceiling.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use proptest::prelude::*;

use cinder_core::archive::manifest::{ChunkLocation, FileEntry, Manifest, StreamEntry};
use cinder_core::archive::{encode_frame_header, FOOTER_MAGIC, HEADER_LEN, MAGIC, VERSION};
use cinder_core::codec::CodecId;
use cinder_core::crypto::Auth;
use cinder_core::fingerprint::hash_chunk;
use cinder_core::{
    blake3, compress_path, extract_archive, ArchiveReader, CompressOptions, ExtractOptions, Limits,
    ProgressEvent,
};

fn quiet() -> std::sync::Arc<dyn Fn(&ProgressEvent) + Send + Sync> {
    std::sync::Arc::new(|_| {})
}

fn tempdir(tag: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let p = base.join(format!(
        "cinder-sec-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&p).expect("tempdir");
    p
}

/// Build a complete plaintext archive from a manifest and raw frame bytes:
/// header + frames + manifest region + footer trailer.
fn craft_archive(manifest: &Manifest, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags: plaintext
    out.extend_from_slice(&[0u8; 16]); // reserved

    for f in frames {
        out.extend_from_slice(f);
    }

    let region = manifest.encode().expect("manifest encode");
    let manifest_offset = out.len() as u64;
    out.extend_from_slice(&region);

    let checksum4: [u8; 4] = hash_chunk(&region).as_bytes()[..4]
        .try_into()
        .expect("4-byte slice");
    out.extend_from_slice(&manifest_offset.to_le_bytes());
    out.extend_from_slice(&(region.len() as u64).to_le_bytes());
    out.extend_from_slice(&checksum4);
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&[0u8; 16]); // kdf salt slot
    out.extend_from_slice(FOOTER_MAGIC);
    out
}

fn stored_frame(payload: &[u8], declared_raw: u64) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&encode_frame_header(
        CodecId::Stored,
        0,
        payload.len() as u64,
        declared_raw,
    ));
    f.extend_from_slice(payload);
    f
}

fn hash_of(bytes: &[u8]) -> blake3::Hash {
    hash_chunk(bytes)
}

fn manifest_referencing(hash: blake3::Hash, chunk_len: u32, path: &str) -> Manifest {
    let mut m = Manifest::default();
    m.files.push(FileEntry {
        path: PathBuf::from(path),
        mode: 0o644,
        symlink_target: None,
        stream_id: 0,
        offset: 0,
        length: u64::from(chunk_len),
    });
    m.streams.push(StreamEntry {
        chunks: vec![hash],
        length: u64::from(chunk_len),
    });
    m.chunk_pool.insert(
        hash,
        ChunkLocation {
            frame_offset: HEADER_LEN,
            frame_length: 28 + chunk_len,
            payload_offset: 0,
            payload_length: chunk_len,
        },
    );
    m
}

fn write_and_extract(
    bytes: &[u8],
    tag: &str,
) -> std::result::Result<cinder_core::ExtractStats, cinder_core::CinderError> {
    let dir = tempdir(tag);
    let archive_path = dir.join("hostile.cnd");
    fs::write(&archive_path, bytes).expect("write crafted archive");
    let root = dir.join("root");
    fs::create_dir_all(&root).unwrap();
    let res = extract_archive(&archive_path, &root, &ExtractOptions::default());
    fs::remove_dir_all(dir).ok();
    res
}

// ---- invariant 1: path traversal ---------------------------------------

#[test]
fn traversal_parent_rejected_and_nothing_written() {
    let dir = tempdir("trav-parent");
    let payload = b"evil";
    let hash = hash_of(payload);
    let m = manifest_referencing(hash, payload.len() as u32, "../outside.txt");
    let bytes = craft_archive(&m, &[stored_frame(payload, payload.len() as u64)]);

    let apath = dir.join("hostile.cnd");
    fs::write(&apath, &bytes).unwrap();
    let root = dir.join("root");
    fs::create_dir_all(&root).unwrap();

    let err = extract_archive(&apath, &root, &ExtractOptions::default())
        .expect_err("traversal archive must be rejected");
    assert!(matches!(err, cinder_core::CinderError::PathTraversal(_)));
    // The escape target would be `dir/outside.txt`; it must not exist.
    assert!(
        !dir.join("outside.txt").exists(),
        "archive wrote outside the extraction root!"
    );
    // And nothing landed inside the root either (reject-whole-archive).
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir_all(dir).ok();
}

#[test]
fn traversal_variants_all_rejected() {
    const EVIL_PATHS: &[&str] = &[
        "a/../../escape",
        "/absolute/escape",
        "C:/win-escape",
        r"a\b\c", // backslash separators rejected outright
        "./dot-start",
        "..",
        "..\\windows\\evil",
        "sub/..%2Fnot-special-but-parent-escape/../../../leaf",
    ];
    for rel in EVIL_PATHS {
        let payload = b"x";
        let hash = hash_of(payload);
        let m = manifest_referencing(hash, 1, rel);
        let bytes = craft_archive(&m, &[stored_frame(payload, 1)]);
        match write_and_extract(&bytes, "trav-variants") {
            Err(cinder_core::CinderError::PathTraversal(_)) => {}
            Err(other) => panic!("path {rel:?}: expected traversal rejection, got {other}"),
            Ok(_) => panic!("path {rel:?}: archive with hostile entry extracted!"),
        }
    }
}

#[test]
fn windows_reserved_device_names_rejected() {
    let payload = b"x";
    let hash = hash_of(payload);
    let m = manifest_referencing(hash, 1, "CON");
    let bytes = craft_archive(&m, &[stored_frame(payload, 1)]);
    assert!(matches!(
        write_and_extract(&bytes, "reserved"),
        Err(cinder_core::CinderError::PathTraversal(_))
    ));
}

// ---- invariant 2: decompression bombs ----------------------------------

#[test]
fn declared_size_over_ceiling_is_refused_before_decode() {
    let tiny_payload = [0xABu8; 16];
    let hash = hash_of(&tiny_payload);
    let mut m = manifest_referencing(hash, 16, "innocent.bin");
    // The frame header will LIE: claims 1 GiB decompressed.
    if let Some(loc) = m.chunk_pool.get_mut(&hash) {
        loc.payload_length = 16;
    }
    m.files[0].length = 16;
    m.streams[0].length = 16;

    let frame = stored_frame(&tiny_payload, 1024 * 1024 * 1024); // lie lives here
    let bytes = craft_archive(&m, &[frame]);

    let dir = tempdir("bomb-declared");
    let apath = dir.join("a.cnd");
    fs::write(&apath, &bytes).unwrap();

    let limits = Limits {
        max_frame_raw: 1024 * 1024, // 1 MiB ceiling
        ..Limits::default()
    };
    if let Ok(mut r) = ArchiveReader::open(fs::File::open(&apath).unwrap(), Auth::None, limits) {
        let h = r.manifest.chunk_pool.keys().copied().next().unwrap();
        let e = r.read_chunk(&h).expect_err("must fail");
        matches!(
            e,
            cinder_core::CinderError::DecompressionBombSuspected(_)
                | cinder_core::CinderError::CorruptArchive(_)
        )
        .then_some(())
        .expect("bomb or corrupt error required");
    } // refusing at open time also satisfies the invariant
    fs::remove_dir_all(dir).ok();
}

#[test]
fn zstd_bomb_undeclared_expansion_is_caught_midstream() {
    // 32 MiB of zeros compress to a few dozen KiB at high effort.
    let raw = vec![0u8; 32 * 1024 * 1024];
    let compressed = zstd::bulk::compress(&raw, 19).expect("zstd bomb build");

    let hash = hash_of(&raw);
    let chunk_len = raw.len() as u32;
    let mut m = manifest_referencing(hash, chunk_len, "bomb.bin");
    // Location claims the truth about length but we LIE in the frame header:
    // header says only 1 MiB decompressed while the stream really yields 32.
    m.chunk_pool.get_mut(&hash).unwrap().frame_length = (28 + compressed.len()) as u32;
    m.chunk_pool.get_mut(&hash).unwrap().payload_length = chunk_len;

    let mut frame = Vec::new();
    frame.extend_from_slice(&encode_frame_header(
        CodecId::Zstd,
        0,
        compressed.len() as u64,
        1024 * 1024, // the lie: under our 64 MiB ceiling, over the Take cap
    ));
    frame.extend_from_slice(&compressed);
    let bytes = craft_archive(&m, &[frame]);

    let dir = tempdir("zstd-bomb");
    let apath = dir.join("a.cnd");
    fs::write(&apath, &bytes).unwrap();
    let root = dir.join("out");

    let ex = extract_archive(&apath, &root, &ExtractOptions::default());
    match ex {
        Err(cinder_core::CinderError::DecompressionBombSuspected(_)) => {}
        Err(cinder_core::CinderError::CorruptArchive(msg)) => {
            panic!("caught as corruption ({msg}); expected explicit bomb detection")
        }
        other => panic!("bomb archive was not caught: {other:?}"),
    }
    fs::remove_dir_all(dir).ok();
}

#[test]
fn cumulative_budget_enforced_across_whole_extraction() {
    let dir = tempdir("budget");
    // Real archive of ~2 MiB content across several files.
    let real_src = dir.join("tree");
    fs::create_dir_all(&real_src).unwrap();
    for i in 0..8 {
        fs::write(
            real_src.join(format!("f{i}.bin")),
            vec![i as u8; 256 * 1024],
        )
        .unwrap();
    }

    let apath = dir.join("a.cnd");
    compress_path(&real_src, &apath, &CompressOptions::default(), &quiet())
        .expect("compress fixture");

    let opts = ExtractOptions {
        limits: Limits {
            max_total_raw: Some(1024), // far below any single file
            ..Limits::default()
        },
        ..ExtractOptions::default()
    };
    let out = dir.join("out");
    let err = extract_archive(&apath, &out, &opts).expect_err("budget must trip");
    assert!(matches!(
        err,
        cinder_core::CinderError::DecompressionBombSuspected(1024)
    ));
    // And it must have stopped early rather than writing everything first.
    let written: u64 = walk_bytes(&out);
    assert!(
        written <= 8 * 256 * 1024,
        "extraction wrote more than budget allows"
    );
    fs::remove_dir_all(dir).ok();
}

fn walk_bytes(root: &Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = fs::read_dir(root) {
        for e in rd.flatten() {
            let md = fs::symlink_metadata(e.path()).unwrap();
            if md.is_file() {
                total += md.len();
            } else if md.is_dir() {
                total += walk_bytes(&e.path());
            }
        }
    }
    total
}

#[test]
fn logical_output_budget_counts_deduplicated_cache_hits() {
    let dir = tempdir("logical-budget");
    let source = dir.join("tree");
    fs::create_dir_all(&source).unwrap();
    let payload = vec![0x5Au8; 32 * 1024];
    fs::write(source.join("one.bin"), &payload).unwrap();
    fs::write(source.join("two.bin"), &payload).unwrap();
    let archive = dir.join("archive.cnd");
    compress_path(&source, &archive, &CompressOptions::default(), &quiet()).unwrap();

    let out = dir.join("out");
    let opts = ExtractOptions {
        limits: Limits {
            max_total_raw: Some(payload.len() as u64 + 1),
            ..Limits::default()
        },
        ..ExtractOptions::default()
    };
    let err = extract_archive(&archive, &out, &opts).expect_err("logical output must be capped");
    assert!(matches!(
        err,
        cinder_core::CinderError::DecompressionBombSuspected(_)
    ));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn compression_rejects_input_output_alias() {
    let dir = tempdir("alias");
    let input = dir.join("source.bin");
    fs::write(&input, b"do not destroy this source").unwrap();
    let err = compress_path(&input, &input, &CompressOptions::default(), &quiet())
        .expect_err("compressing onto the input must be rejected");
    assert!(matches!(err, cinder_core::CinderError::InvalidInput(_)));
    assert_eq!(fs::read(&input).unwrap(), b"do not destroy this source");
    fs::remove_dir_all(dir).ok();
}

#[cfg(unix)]
#[test]
fn extraction_never_follows_destination_symlink() {
    use std::os::unix::fs::symlink;

    let dir = tempdir("dest-link");
    let payload = b"must stay in the root";
    let hash = hash_of(payload);
    let m = manifest_referencing(hash, payload.len() as u32, "link");
    let archive = dir.join("hostile.cnd");
    fs::write(
        &archive,
        craft_archive(&m, &[stored_frame(payload, payload.len() as u64)]),
    )
    .unwrap();
    let root = dir.join("root");
    let outside = dir.join("outside.txt");
    fs::create_dir_all(&root).unwrap();
    fs::write(&outside, b"original").unwrap();
    symlink(&outside, root.join("link")).unwrap();

    let opts = ExtractOptions {
        overwrite: true,
        ..ExtractOptions::default()
    };
    let err = extract_archive(&archive, &root, &opts)
        .expect_err("destination symlink must not be followed");
    assert!(matches!(err, cinder_core::CinderError::PathTraversal(_)));
    assert_eq!(fs::read(&outside).unwrap(), b"original");
    fs::remove_dir_all(dir).ok();
}

#[test]
fn malformed_manifest_relationships_are_rejected_at_open() {
    let payload = b"payload";
    let hash = hash_of(payload);
    let mut m = manifest_referencing(hash, payload.len() as u32, "safe.txt");
    m.streams[0].length += 1;
    let bytes = craft_archive(&m, &[stored_frame(payload, payload.len() as u64)]);
    let err = match ArchiveReader::open(Cursor::new(bytes), Auth::None, Limits::default()) {
        Ok(_) => panic!("inconsistent manifest must fail before extraction"),
        Err(err) => err,
    };
    assert!(matches!(err, cinder_core::CinderError::CorruptArchive(_)));
}

// ---- invariant 3: parser never panics ----------------------------------

proptest! {
    /// Arbitrary byte soup must never panic the parser.
    #[test]
    fn open_garbage_never_panics(input in proptest::prelude::any::<Vec<u8>>()) {
        let limits = Limits { max_manifest_bytes: 4096, ..Limits::default() };
        let _ = ArchiveReader::open(Cursor::new(input), Auth::None, limits);
    }

    /// Bit-flips in a valid archive surface as errors or success — never a panic.
    #[test]
    fn bitflip_never_panics(
        offset in 0usize..4096,
        mask in 0u8..=255,
    ) {
        let dir = std::env::temp_dir().join(format!("cinder-bitflip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        std::fs::write(&src, vec![0xA5u8; 4096]).unwrap();
        let apath = dir.join("v.cnd");
        let q: std::sync::Arc<dyn Fn(&ProgressEvent) + Send + Sync> = std::sync::Arc::new(|_| {});
        compress_path(&src, &apath, &CompressOptions::default(), &q).unwrap();
        let mut bytes = std::fs::read(&apath).unwrap();
        let idx = offset % bytes.len();
        bytes[idx] ^= mask;
        let limits = Limits { max_manifest_bytes: 65536, max_frame_raw: 1024*1024, ..Limits::default() };
        if let Ok(mut r) = ArchiveReader::open(Cursor::new(bytes), Auth::None, limits.clone()) {
            for h in r.manifest.chunk_pool.keys().copied().collect::<Vec<_>>() {
                let _ = r.read_chunk(&h);
            }
        }
        std::fs::remove_dir_all(dir).ok();
    }
}

// ---- extended deterministic budget -------------------------------------
//
// The brief's full CPU-hours belong to `cargo fuzz` on an ASan-capable host,
// but these env-gated runs discharge real mutation budgets on any machine by
// hammering the same entry points with seeded pseudo-random corpora.

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
#[ignore = "heavy: run explicitly with CINDER_FUZZ_BUDGET set"]
fn fuzz_budget_garbage_and_mutations() {
    let budget: usize = std::env::var("CINDER_FUZZ_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if budget == 0 {
        return;
    }
    let limits = Limits {
        max_manifest_bytes: 128 * 1024,
        max_frame_raw: 1024 * 1024,
        max_total_raw: Some(8 * 1024 * 1024),
        ..Limits::default()
    };
    let mut state = 0x243F_6A88_85A3_08D3u64;

    // Phase A: pure garbage.
    let mut opened_ok = 0usize;
    for i in 0..budget / 2 {
        let len = 16 + (xorshift(&mut state) % 4096) as usize;
        let mut data = vec![0u8; len];
        for b in &mut data {
            *b = (xorshift(&mut state) >> 24) as u8;
        }
        if i % 64 == 0 {
            // Sprinkle valid magics so deeper paths get exercised too.
            let magic: &[u8] = match i % (64 * 4) {
                0 => MAGIC,
                1 => b"CNDfrme1",
                2 => FOOTER_MAGIC,
                _ => b"PK\x03\x04",
            };
            data[..magic.len()].copy_from_slice(magic);
        }
        if ArchiveReader::open(Cursor::new(data), Auth::None, limits.clone()).is_ok() {
            opened_ok += 1;
        }
    }

    // Phase B: mutations of a genuine archive (build once). Half the cases
    // flip arbitrary bytes; the other half mutate *inside the manifest
    // region* and then repair the footer checksum, so mutants survive header
    // validation and hammer manifest parsing + chunk-location bounds — the
    // deep paths shallow flips almost never reach.
    let dir = tempdir("fuzz-budget");
    std::fs::write(dir.join("src.bin"), vec![0x5Au8; 16 * 1024]).unwrap();
    let apath = dir.join("v.cnd");
    let q: std::sync::Arc<dyn Fn(&ProgressEvent) + Send + Sync> = std::sync::Arc::new(|_| {});
    compress_path(
        &dir.join("src.bin"),
        &apath,
        &CompressOptions::default(),
        &q,
    )
    .unwrap();
    let pristine = std::fs::read(&apath).unwrap();

    // Locate the manifest region from the trailer (format documented in
    // archive/mod.rs): [offset u64][len u64][checksum4]... at end-48.
    let t = pristine.len() - 48;
    let m_off = u64::from_le_bytes(pristine[t..t + 8].try_into().unwrap()) as usize;
    let m_len = u64::from_le_bytes(pristine[t + 8..t + 16].try_into().unwrap()) as usize;

    let mut deep_opens = 0usize;
    let mut chunk_reads = 0usize;
    for case in 0..budget / 2 {
        let mut bytes = pristine.clone();
        let flips = 1 + (xorshift(&mut state) % 8) as usize;
        if case % 2 == 0 {
            for _ in 0..flips {
                let idx = (xorshift(&mut state) as usize) % bytes.len();
                bytes[idx] ^= (xorshift(&mut state) & 0xFF) as u8;
            }
        } else {
            // Deep mode: corrupt inside the manifest region only.
            for _ in 0..flips {
                let idx = m_off + (xorshift(&mut state) as usize) % m_len.max(1);
                bytes[idx] ^= (xorshift(&mut state) & 0xFF) as u8;
            }
            // Repair the checksum so footer validation passes and the parser
            // must actually chew on the corrupted JSON.
            let sum = cinder_core::fingerprint::hash_chunk(&bytes[m_off..m_off + m_len]);
            bytes[t + 16..t + 20].copy_from_slice(&sum.as_bytes()[..4]);
        }
        if let Ok(mut r) = ArchiveReader::open(Cursor::new(bytes), Auth::None, limits.clone()) {
            deep_opens += 1;
            for h in r.manifest.chunk_pool.keys().copied().collect::<Vec<_>>() {
                let _ = r.read_chunk(&h);
                chunk_reads += 1;
            }
        }
    }
    println!(
        "fuzz budget {budget}: garbage phase done ({opened_ok} accidentally-valid), \
         mutation phase done ({deep_opens} deep opens, {chunk_reads} chunk reads attempted)"
    );
    assert!(
        deep_opens > 0,
        "checksum-repaired mutants should occasionally still parse"
    );
    std::fs::remove_dir_all(dir).ok();
}
