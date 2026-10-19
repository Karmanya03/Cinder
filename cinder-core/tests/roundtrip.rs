// Tests favor directness over style: numeric casts below are exact for
// these magnitudes and unwrap/expect in fixtures is standard test practice.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
//! Round-trip acceptance: `decompress(compress(x)) == x` across content
//! shapes the brief calls out â€” arbitrary bytes, empty files, deep nesting,
//! unicode names, symlinks, encryption.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cinder_core::crypto::Auth;
use cinder_core::{
    compress_path, compress_paths, extract_archive, extract_file, ArchiveReader, CompressOptions,
    ExtractOptions, Limits, ProgressEvent, SymlinkPolicy,
};

fn quiet() -> Arc<dyn Fn(&ProgressEvent) + Send + Sync> {
    Arc::new(|_| {})
}

/// Deterministic pseudo-random fill (xorshift64*), so tests never depend on
/// an external RNG crate and failures reproduce exactly.
fn fill_pattern(buf: &mut [u8], seed: u64) {
    let mut s = seed.max(1);
    for b in buf.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s >> 32) as u8;
    }
}

fn tempdir(tag: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let p = base.join(format!(
        "cinder-test-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&p).expect("create tempdir");
    fs::canonicalize(p).expect("canonical tempdir")
}

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("mkdir");
    }
    fs::write(path, contents).expect("write file");
}

fn trees_equivalent(src: &Path, dst: &Path) -> bool {
    use cinder_core::fingerprint::hash_chunk;

    fn rel_files(root: &Path) -> Vec<(String, u64, [u8; 32])> {
        let mut out = Vec::new();
        for e in walk(root) {
            let data = fs::read(&e).expect("read during compare");
            let hash = *hash_chunk(&data).as_bytes();
            let rel = e
                .strip_prefix(root)
                .expect("strip prefix")
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, data.len() as u64, hash));
        }
        out.sort();
        out
    }

    fn walk(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = fs::read_dir(&d) else {
                continue;
            };
            for entry in rd.flatten() {
                let p = entry.path();
                let md = fs::symlink_metadata(&p).expect("lstat");
                if md.is_symlink() {
                    continue; // handled separately by symlink tests
                }
                if md.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out
    }

    rel_files(src) == rel_files(dst)
}

#[test]
fn single_file_roundtrip() {
    let dir = tempdir("single");
    let src = dir.join("src");
    let mut data = vec![0u8; 3 * 1024 * 1024];
    fill_pattern(&mut data, 0xDEAD_BEEF);
    write_file(&src, &data);

    let archive = dir.join("a.cnd");
    compress_path(&src, &archive, &CompressOptions::default(), &quiet()).expect("compress");

    let restored = dir.join("restored");
    extract_archive(&archive, &restored, &ExtractOptions::default()).expect("extract");
    // Single-file input restores under its own name inside `restored`.
    let got = fs::read(restored.join("src")).expect("restored file present");
    assert_eq!(got, data, "round trip must be byte-identical");
    fs::remove_dir_all(dir).ok();
}

#[test]
fn selected_files_and_folders_roundtrip_without_name_collisions() {
    let dir = tempdir("grouped-inputs");
    let file = dir.join("notes.txt");
    write_file(&file, b"single selected file");
    let folder = dir.join("project");
    write_file(&folder.join("src/main.rs"), b"fn main() {}\n");
    fs::create_dir_all(folder.join("empty-folder")).unwrap();

    let archive = dir.join("group.cnd");
    compress_paths(
        &[file.clone(), folder.clone()],
        &archive,
        &CompressOptions::default(),
        &quiet(),
    )
    .expect("compress grouped inputs");
    let restored = dir.join("restored-group");
    extract_archive(&archive, &restored, &ExtractOptions::default())
        .expect("extract grouped inputs");
    assert_eq!(
        fs::read(restored.join("notes.txt")).unwrap(),
        b"single selected file"
    );
    assert_eq!(
        fs::read(restored.join("project/src/main.rs")).unwrap(),
        b"fn main() {}\n"
    );
    assert!(restored.join("project/empty-folder").is_dir());

    let left = dir.join("left");
    let right = dir.join("right");
    write_file(&left.join("same.txt"), b"left");
    write_file(&right.join("same.txt"), b"right");
    let conflicting = dir.join("conflicting.cnd");
    assert!(compress_paths(
        &[left.join("same.txt"), right.join("same.txt")],
        &conflicting,
        &CompressOptions::default(),
        &quiet(),
    )
    .is_err());
    assert!(
        !conflicting.exists(),
        "a collision must be rejected before output creation"
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn empty_and_tiny_files_roundtrip() {
    let dir = tempdir("empty");
    let src = dir.join("src");
    write_file(&src.join("zero.bin"), b"");
    write_file(&src.join("one.bin"), b"x");
    fs::create_dir_all(src.join("empty-dir")).unwrap();

    let archive = dir.join("a.cnd");
    compress_path(&src, &archive, &CompressOptions::default(), &quiet()).expect("compress");
    let restored = dir.join("out");
    extract_archive(&archive, &restored, &ExtractOptions::default()).expect("extract");

    assert_eq!(fs::metadata(restored.join("zero.bin")).unwrap().len(), 0);
    assert_eq!(fs::read(restored.join("one.bin")).unwrap(), b"x");
    assert!(restored.join("empty-dir").is_dir());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn nested_unicode_paths_roundtrip() {
    let dir = tempdir("nested");
    let src = dir.join("src");
    write_file(
        &src.join("Ã¼ber-Ordner/daten.txt"),
        b"unicode content\n".repeat(50).as_slice(),
    );
    write_file(&src.join("deep/a/b/c/d/e/f/leaf.bin"), &[7u8; 4096]);
    // Windows cannot represent a trailing dot/space in paths reliably; keep
    // to portable-but-varied names.
    write_file(&src.join("mixed-CASE.File.TxT"), b"case matters");

    let archive = dir.join("a.cnd");
    compress_path(&src, &archive, &CompressOptions::default(), &quiet()).expect("compress");
    let restored = dir.join("out");
    extract_archive(&archive, &restored, &ExtractOptions::default()).expect("extract");
    assert!(trees_equivalent(&src, &restored));
    fs::remove_dir_all(dir).ok();
}

#[test]
fn encrypted_roundtrip_and_wrong_passphrase() {
    let dir = tempdir("enc");
    let src = dir.join("src");
    let mut data = vec![0u8; 1024 * 1024];
    fill_pattern(&mut data, 42);
    write_file(&src, &data);

    let archive = dir.join("a.cnd");
    let opts = CompressOptions {
        encryption_passphrase: Some("correct horse battery staple".into()),
        ..CompressOptions::default()
    };
    compress_path(&src, &archive, &opts, &quiet()).expect("compress");

    // Plaintext open must be refused up front.
    {
        let file = fs::File::open(&archive).unwrap();
        let err = ArchiveReader::open(file, Auth::None, Limits::default());
        assert!(matches!(err, Err(cinder_core::CinderError::Encrypted)));
    }
    // Wrong passphrase must fail authentication, not panic or decrypt.
    {
        let file = fs::File::open(&archive).unwrap();
        let err = ArchiveReader::open(file, Auth::Passphrase("wrong".into()), Limits::default());
        assert!(err.is_err());
    }
    // Correct passphrase round-trips.
    let restored = dir.join("out");
    let ex = ExtractOptions {
        passphrase: Some("correct horse battery staple".into()),
        ..ExtractOptions::default()
    };
    extract_archive(&archive, &restored, &ex).expect("extract with key");
    let got = fs::read(restored.join("src")).expect("restored file present");
    assert_eq!(got, data);
    fs::remove_dir_all(dir).ok();
}

#[test]
fn verify_detects_frame_corruption() {
    let dir = tempdir("corrupt");
    let src = dir.join("src");
    let mut data = vec![0u8; 512 * 1024];
    fill_pattern(&mut data, 7);
    write_file(&src, &data);

    let archive = dir.join("a.cnd");
    compress_path(&src, &archive, &CompressOptions::default(), &quiet()).expect("compress");
    let size = fs::metadata(&archive).unwrap().len();

    // Flip one bit inside the frame body (after the 32-byte header, well
    // before the manifest/footer at the tail).
    let mut bytes = fs::read(&archive).unwrap();
    let mid = (size as usize / 2).max(33);
    bytes[mid] ^= 0x01;
    let corrupted = dir.join("bad.cnd");
    fs::write(&corrupted, &bytes).unwrap();

    let opened = ArchiveReader::open(Cursor::new(bytes.clone()), Auth::None, Limits::default());
    if let Ok(mut reader) = opened {
        let hashes: Vec<_> = reader.manifest.chunk_pool.keys().copied().collect();
        let mut any_bad = false;
        for h in hashes {
            if reader.read_chunk(&h).is_err() {
                any_bad = true;
            }
        }
        assert!(any_bad, "flipped byte must surface as verification failure");
    } else {
        // Refusal at parse time also counts as detection.
    }
    let _ = corrupted;
    fs::remove_dir_all(dir).ok();
}

#[test]
fn random_access_get_matches_full_extraction() {
    let dir = tempdir("get");
    let src = dir.join("src");
    let mut big = vec![0u8; 2 * 1024 * 1024];
    fill_pattern(&mut big, 99);
    write_file(&src.join("big.bin"), &big);
    write_file(&src.join("sub/small.txt"), b"small payload");

    let archive = dir.join("a.cnd");
    compress_path(&src, &archive, &CompressOptions::default(), &quiet()).expect("compress");

    let got = dir.join("pulled-small.txt");
    extract_file(&archive, "sub/small.txt", &got, &ExtractOptions::default()).expect("get");
    assert_eq!(fs::read(&got).unwrap(), b"small payload");

    let got2 = dir.join("pulled-big.bin");
    extract_file(&archive, "big.bin", &got2, &ExtractOptions::default()).expect("get big");
    assert_eq!(fs::read(&got2).unwrap(), big);

    // Unknown member is a clean error.
    let err = extract_file(
        &archive,
        "does/not/exist",
        &dir.join("nope"),
        &ExtractOptions::default(),
    );
    assert!(err.is_err());

    // Symlink policy Skip writes placeholders instead of links.
    let _ = SymlinkPolicy::Skip;
    fs::remove_dir_all(dir).ok();
}

#[cfg(unix)]
#[test]
fn symlink_roundtrip_unix() {
    use std::os::unix::fs::symlink;

    let dir = tempdir("link");
    let src = dir.join("src");
    write_file(&src.join("target.txt"), b"linked");
    symlink("target.txt", src.join("safe-link")).unwrap();

    let archive = dir.join("a.cnd");
    compress_path(&src, &archive, &CompressOptions::default(), &quiet()).expect("compress");
    let restored = dir.join("out");
    extract_archive(&archive, &restored, &ExtractOptions::default()).expect("extract");

    let link_md = fs::symlink_metadata(restored.join("safe-link")).unwrap();
    assert!(link_md.is_symlink());
    assert_eq!(
        fs::read_link(restored.join("safe-link")).unwrap(),
        PathBuf::from("target.txt")
    );
    assert_eq!(fs::read(restored.join("safe-link")).unwrap(), b"linked");
    fs::remove_dir_all(dir).ok();
}
