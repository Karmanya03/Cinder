// Tests favor directness over style; casts here are exact for the fixture
// magnitudes used.
#![allow(clippy::cast_possible_truncation)]
//! Multi-format acceptance: round-trips through every creatable container,
//! hostile zip entries rejected with the same severity as hostile `.cnd`,
//! detection by extension and magic, and selection extraction.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use cinder_formats::{
    create, create_paths, detect, extract, list, stream_payload_name, test, CreateFormat,
    CreateOptions, ExtractOptions, Format, RarVersion,
};

fn tempdir(tag: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let p = base.join(format!(
        "cinder-fmt-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&p).expect("tempdir");
    p
}

fn write_file(path: &std::path::Path, data: &[u8]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, data).expect("write");
}

/// Fixture tree with nesting, unicode names, empty files and varied content.
fn fixture_tree(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let files = vec![
        ("top.txt".to_string(), b"top-level payload\n".repeat(40)),
        ("nested/deep/leaf.bin".to_string(), vec![0xA5u8; 70_000]),
        (
            "Ã¼ber/Ð´Ð°Ñ‚Ð¾Ñ‚ÐµÐºÐ°.txt".to_string(),
            b"unicode path content".to_vec(),
        ),
        ("empty.dat".to_string(), Vec::new()),
    ];
    for (rel, _) in &files {
        write_file(
            &root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR)),
            &[],
        );
    }
    // Rewrite actual contents (the pass above created empty placeholders).
    for (rel, data) in &files {
        fs::write(
            root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR)),
            data,
        )
        .unwrap();
    }
    fs::create_dir_all(root.join("empty-dir")).unwrap();
    files
}

#[test]
fn roundtrip_every_creatable_format() {
    for fmt in [
        CreateFormat::SevenZ,
        CreateFormat::Rar,
        CreateFormat::Zip,
        CreateFormat::Tar,
        CreateFormat::TarGz,
        CreateFormat::TarZst,
        CreateFormat::TarXz,
    ] {
        let dir = tempdir("roundtrip");
        let src = dir.join("tree");
        let expected = fixture_tree(&src);

        let ext = match fmt {
            CreateFormat::SevenZ => ".7z",
            CreateFormat::Rar => ".rar",
            CreateFormat::Zip => ".zip",
            CreateFormat::Tar => ".tar",
            CreateFormat::TarGz => ".tar.gz",
            CreateFormat::TarZst => ".tar.zst",
            CreateFormat::TarXz => ".tar.xz",
        };
        let archive = dir.join(format!("out{ext}"));
        let stats = create(&src, &archive, fmt, CreateOptions::default())
            .unwrap_or_else(|e| panic!("{fmt:?} create failed: {e}"));
        assert_eq!(stats.files as usize, expected.len());
        assert!(
            archive.exists() && fs::metadata(&archive).unwrap().len() > 0,
            "{fmt:?}: archive missing or empty"
        );

        // Listing must contain every file.
        let entries = list(&archive).unwrap_or_else(|e| panic!("{fmt:?} list failed: {e}"));
        for (rel, _) in &expected {
            assert!(
                entries.iter().any(|e| e.name.trim_end_matches('/') == rel),
                "{fmt:?}: {rel} missing from listing"
            );
        }

        // Extraction restores byte-identical trees.
        let out = dir.join("out");
        let summary = extract(&archive, &out, &ExtractOptions::default())
            .unwrap_or_else(|e| panic!("{fmt:?} extract failed: {e}"));
        assert_eq!(summary.files as usize, expected.len());
        for (rel, data) in &expected {
            let got = fs::read(out.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR)))
                .unwrap_or_else(|e| panic!("{fmt:?}: reading back {rel}: {e}"));
            assert_eq!(&got, data, "{fmt:?}: {rel} differs after round trip");
        }

        if matches!(fmt, CreateFormat::SevenZ | CreateFormat::Rar) {
            let selected = dir.join("selected");
            let wanted = "nested/deep/leaf.bin";
            let selection =
                cinder_formats::ExtractSelection::only([wanted.to_string()].into_iter().collect());
            let result = cinder_formats::extract_selected(
                &archive,
                &selected,
                &ExtractOptions::default(),
                &selection,
            )
            .unwrap_or_else(|e| panic!("{fmt:?} selected extract failed: {e}"));
            assert_eq!(result.files, 1);
            let leaf = expected
                .iter()
                .find(|(name, _)| name == wanted)
                .map(|(_, data)| data)
                .unwrap();
            let got = fs::read(selected.join(wanted)).unwrap();
            assert_eq!(got.as_slice(), leaf.as_slice());
            assert!(!selected.join("top.txt").exists());
        }

        // Test pass succeeds and reports the right entry count.
        let report = test(&archive, u64::MAX).expect("integrity");
        assert_eq!(report.entries as usize, expected.len());

        fs::remove_dir_all(dir).ok();
    }
}

#[test]
fn grouped_inputs_create_one_archive_and_reject_duplicate_names() {
    let dir = tempdir("grouped-inputs");
    let note = dir.join("notes.txt");
    write_file(&note, b"notes");
    let folder = dir.join("project");
    write_file(&folder.join("src/main.rs"), b"fn main() {}\n");
    let archive = dir.join("group.zip");
    let stats = create_paths(
        &[note.clone(), folder.clone()],
        &archive,
        CreateFormat::Zip,
        CreateOptions::default(),
    )
    .expect("create grouped ZIP");
    assert_eq!(stats.files, 2);
    let output = dir.join("out");
    extract(&archive, &output, &ExtractOptions::default()).expect("extract grouped ZIP");
    assert_eq!(fs::read(output.join("notes.txt")).unwrap(), b"notes");
    assert_eq!(
        fs::read(output.join("project/src/main.rs")).unwrap(),
        b"fn main() {}\n"
    );

    let left = dir.join("left");
    let right = dir.join("right");
    write_file(&left.join("same.txt"), b"left");
    write_file(&right.join("same.txt"), b"right");
    let conflicting = dir.join("conflicting.zip");
    assert!(create_paths(
        &[left.join("same.txt"), right.join("same.txt")],
        &conflicting,
        CreateFormat::Zip,
        CreateOptions::default(),
    )
    .is_err());
    assert!(
        !conflicting.exists(),
        "name collisions fail before an archive is written"
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn encrypted_sevenz_and_rar_roundtrip() {
    let dir = tempdir("encrypted-foreign");
    let src = dir.join("tree");
    let expected = fixture_tree(&src);
    let password = "correct horse battery staple".to_string();

    for (fmt, ext) in [(CreateFormat::SevenZ, ".7z"), (CreateFormat::Rar, ".rar")] {
        let archive = dir.join(format!("encrypted{ext}"));
        create(
            &src,
            &archive,
            fmt,
            CreateOptions {
                password: Some(password.clone()),
                ..CreateOptions::default()
            },
        )
        .unwrap_or_else(|e| panic!("{fmt:?} encrypted create failed: {e}"));

        let err = cinder_formats::list_with_password(&archive, None)
            .expect_err("encrypted headers must require a password");
        assert!(matches!(
            err,
            cinder_formats::FormatsError::PasswordRequired
        ));
        let wrong = cinder_formats::list_with_password(&archive, Some("not the password"))
            .expect_err("wrong password must not reveal encrypted headers");
        assert!(matches!(
            wrong,
            cinder_formats::FormatsError::PasswordRequired
        ));

        let entries = cinder_formats::list_with_password(&archive, Some(&password))
            .unwrap_or_else(|e| panic!("{fmt:?} encrypted list failed: {e}"));
        for (rel, _) in &expected {
            assert!(
                entries
                    .iter()
                    .any(|entry| entry.name.trim_end_matches('/') == rel),
                "{fmt:?}: {rel} missing from encrypted listing"
            );
        }

        let out = dir.join(format!("restored-{}", ext.trim_matches('.')));
        extract(
            &archive,
            &out,
            &ExtractOptions {
                password: Some(password.clone()),
                ..ExtractOptions::default()
            },
        )
        .unwrap_or_else(|e| panic!("{fmt:?} encrypted extract failed: {e}"));
        for (rel, data) in &expected {
            assert_eq!(
                fs::read(out.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR))).unwrap(),
                *data,
                "{fmt:?}: {rel} differs after encrypted round trip"
            );
        }

        let report = cinder_formats::test_with_password(&archive, u64::MAX, Some(&password))
            .unwrap_or_else(|e| panic!("{fmt:?} encrypted test failed: {e}"));
        assert_eq!(report.entries as usize, expected.len());
    }
    fs::remove_dir_all(dir).ok();
}

#[test]
fn every_rar_generation_creates_and_roundtrips() {
    let dir = tempdir("rar-generations");
    let source = dir.join("source");
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::create_dir_all(source.join("empty-dir")).unwrap();
    let expected = b"compatibility across RAR writer generations".repeat(400);
    fs::write(source.join("nested/payload.txt"), &expected).unwrap();

    for version in [
        RarVersion::Rar13,
        RarVersion::Rar14,
        RarVersion::Rar15,
        RarVersion::Rar20,
        RarVersion::Rar29,
        RarVersion::Rar30,
        RarVersion::Rar40,
        RarVersion::Rar50,
        RarVersion::Rar70,
    ] {
        let archive = dir.join(format!("{}.rar", version.label().replace(' ', "-")));
        create(
            &source,
            &archive,
            CreateFormat::Rar,
            CreateOptions {
                rar_version: version,
                level: 0,
                ..CreateOptions::default()
            },
        )
        .unwrap_or_else(|error| panic!("{} create failed: {error}", version.label()));
        assert!(
            list(&archive)
                .unwrap()
                .iter()
                .any(|member| member.name.trim_end_matches('/') == "nested/payload.txt"),
            "{} list",
            version.label()
        );
        let report = test(&archive, u64::MAX)
            .unwrap_or_else(|error| panic!("{} verify failed: {error}", version.label()));
        assert_eq!(report.entries, 1, "{} test count", version.label());
        let destination = dir.join(format!("restored-{}", version.label().replace(' ', "-")));
        extract(&archive, &destination, &ExtractOptions::default())
            .unwrap_or_else(|error| panic!("{} extract failed: {error}", version.label()));
        assert_eq!(
            fs::read(destination.join("nested/payload.txt")).unwrap(),
            expected
        );
        assert!(destination.join("empty-dir").is_dir());
    }
    fs::remove_dir_all(dir).ok();
}

#[test]
fn password_protection_tracks_each_rar_generation() {
    let dir = tempdir("rar-encryption-generations");
    let source = dir.join("source");
    fs::create_dir_all(&source).unwrap();
    let expected = b"RAR data encryption compatibility".repeat(80);
    fs::write(source.join("secret.txt"), &expected).unwrap();
    let password = "rar generation compatibility password".to_string();

    for version in [
        RarVersion::Rar13,
        RarVersion::Rar14,
        RarVersion::Rar15,
        RarVersion::Rar20,
        RarVersion::Rar29,
        RarVersion::Rar30,
        RarVersion::Rar40,
        RarVersion::Rar50,
        RarVersion::Rar70,
    ] {
        let archive = dir.join(format!(
            "encrypted-{}.rar",
            version.label().replace(' ', "-")
        ));
        create(
            &source,
            &archive,
            CreateFormat::Rar,
            CreateOptions {
                level: 0,
                password: Some(password.clone()),
                rar_version: version,
                ..CreateOptions::default()
            },
        )
        .unwrap_or_else(|error| panic!("{} password create failed: {error}", version.label()));
        let listing = cinder_formats::list_with_password(&archive, None);
        if version.supports_header_encryption() {
            assert!(
                matches!(listing, Err(cinder_formats::FormatsError::PasswordRequired)),
                "{} must keep headers encrypted",
                version.label()
            );
        } else {
            assert_eq!(
                listing.unwrap().len(),
                1,
                "{} header listing",
                version.label()
            );
        }
        let destination = dir.join(format!("secret-{}", version.label().replace(' ', "-")));
        extract(
            &archive,
            &destination,
            &ExtractOptions {
                password: Some(password.clone()),
                ..ExtractOptions::default()
            },
        )
        .unwrap_or_else(|error| panic!("{} password extract failed: {error}", version.label()));
        assert_eq!(fs::read(destination.join("secret.txt")).unwrap(), expected);
    }
    fs::remove_dir_all(dir).ok();
}

#[test]
fn rar5_split_set_lists_tests_and_extracts_from_any_part() {
    let dir = tempdir("rar5-volumes");
    let source = dir.join("source");
    fs::create_dir_all(&source).unwrap();
    let mut state = 0x1234_5678u32;
    let large: Vec<u8> = (0..768 * 1024)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    fs::write(source.join("large.bin"), &large).unwrap();
    fs::write(source.join("small.txt"), b"small sidecar").unwrap();

    let base = dir.join("set.rar");
    let stats = create(
        &source,
        &base,
        CreateFormat::Rar,
        CreateOptions {
            level: 0,
            rar_version: RarVersion::Rar50,
            rar_volume_size: Some(128 * 1024),
            ..CreateOptions::default()
        },
    )
    .expect("create RAR5 volumes");
    assert!(stats.volume_count > 1, "expected multiple output volumes");
    let first = dir.join("set.part01.rar");
    let second = dir.join("set.part02.rar");
    assert!(first.is_file() && second.is_file());

    let members = list(&base).expect("list from the base name");
    assert_eq!(members.len(), 2, "split file must appear once in listing");
    let later_part_members = list(&second).expect("list from a later volume");
    assert_eq!(later_part_members.len(), 2);
    let report = test(&second, u64::MAX).expect("test complete set from a later volume");
    assert_eq!(report.entries, 2);
    assert_eq!(report.bytes, (large.len() + b"small sidecar".len()) as u64);

    let output = dir.join("restored");
    let summary = extract(&second, &output, &ExtractOptions::default())
        .expect("extract complete set from a later volume");
    assert_eq!(summary.files, 2);
    assert_eq!(fs::read(output.join("large.bin")).unwrap(), large);
    assert_eq!(
        fs::read(output.join("small.txt")).unwrap(),
        b"small sidecar"
    );

    let selected = dir.join("selected");
    let selection = cinder_formats::ExtractSelection::only(
        ["small.txt".to_string()]
            .into_iter()
            .collect::<HashSet<_>>(),
    );
    let summary =
        cinder_formats::extract_selected(&first, &selected, &ExtractOptions::default(), &selection)
            .expect("select one member from the set");
    assert_eq!(summary.files, 1);
    assert_eq!(
        fs::read(selected.join("small.txt")).unwrap(),
        b"small sidecar"
    );
    assert!(!selected.join("large.bin").exists());

    fs::remove_file(&second).unwrap();
    let incomplete = dir.join("incomplete");
    assert!(
        extract(&first, &incomplete, &ExtractOptions::default()).is_err(),
        "a split member must fail when a continuation volume is missing"
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn legacy_rar_split_set_uses_rar_and_r00_names() {
    let dir = tempdir("legacy-rar-volumes");
    let mut state = 0x8765_4321u32;
    let expected: Vec<u8> = (0..512 * 1024)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u8
        })
        .collect();
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar29)
        .store(true)
        .volume_size(Some(128 * 1024));
    builder
        .add_bytes(b"legacy.bin".to_vec(), expected.clone(), None, None)
        .unwrap();
    let volumes = builder.build_volumes(None).expect("create legacy volumes");
    assert!(volumes.len() > 1);
    for (index, volume) in volumes.iter().enumerate() {
        let path = if index == 0 {
            dir.join("legacy.rar")
        } else {
            dir.join(format!("legacy.r{:02}", index - 1))
        };
        fs::write(path, volume).unwrap();
    }

    let later_part = dir.join("legacy.r01");
    assert_eq!(detect(&later_part), Some(Format::Rar));
    assert_eq!(list(&later_part).unwrap().len(), 1);
    let destination = dir.join("restored");
    extract(&later_part, &destination, &ExtractOptions::default())
        .expect("extract legacy set from r01");
    assert_eq!(fs::read(destination.join("legacy.bin")).unwrap(), expected);
    assert_eq!(test(&later_part, u64::MAX).unwrap().entries, 1);
    fs::remove_dir_all(dir).ok();
}

#[test]
fn single_stream_gzip_and_zstd_roundtrip() {
    let dir = tempdir("single");
    let src = dir.join("payload.txt");
    fs::write(&src, b"single stream payload\n".repeat(1000)).unwrap();

    // gzip via flate2 directly (creation helper only covers containers).
    {
        let f = fs::File::create(dir.join("payload.gz")).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        enc.write_all(&fs::read(&src).unwrap()).unwrap();
        enc.finish().unwrap();
    }
    // zstd via the core dependency.
    {
        let compressed = zstd::bulk::compress(&fs::read(&src).unwrap(), 3).unwrap();
        fs::write(dir.join("payload.zst"), compressed).unwrap();
    }

    for name in ["payload.gz", "payload.zst"] {
        let apath = dir.join(name);
        assert!(matches!(
            detect(&apath),
            Some(Format::GzSingle | Format::ZstSingle)
        ));
        let entries = list(&apath).unwrap();
        assert_eq!(entries[0].name, stream_payload_name(&apath));

        let out = dir.join(format!("out-{name}"));
        let s = extract(&apath, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(s.files, 1);
        let restored = fs::read(out.join(stream_payload_name(&apath))).unwrap();
        assert_eq!(restored, fs::read(&src).unwrap(), "{name} mismatch");
    }
}

#[test]
fn magic_detection_beats_wrong_extension() {
    let dir = tempdir("magic");
    let zip_path = dir.join("misnamed.dat");
    let f = fs::File::create(dir.join("_real.zip")).unwrap();
    let mut w = zip::ZipWriter::new(f);
    w.start_file("x.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"zip inside").unwrap();
    w.finish().unwrap();
    fs::rename(dir.join("_real.zip"), &zip_path).unwrap();

    assert_eq!(
        detect(&zip_path),
        Some(Format::Zip),
        "PK magic must win over extension"
    );
}

#[test]
fn hostile_zip_traversal_rejected_whole_archive() {
    let dir = tempdir("hostile-zip");
    let f = fs::File::create(dir.join("evil.zip")).unwrap();
    let mut w = zip::ZipWriter::new(f);
    w.start_file("innocent.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"fine on its own").unwrap();
    // A late hostile path must be rejected before `innocent.txt` is written.
    w.start_file("../escaped.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"should never land").unwrap();
    w.finish().unwrap();

    let root = dir.join("root");
    let err = extract(&dir.join("evil.zip"), &root, &ExtractOptions::default())
        .expect_err("hostile zip must be rejected");
    assert!(
        matches!(err, cinder_formats::FormatsError::UnsafePath(_)),
        "expected UnsafePath, got {err}"
    );
    assert!(
        !dir.join("escaped.txt").exists(),
        "file escaped extraction root!"
    );
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        0,
        "partial extraction happened"
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn budget_cap_stops_zip_bombs() {
    let dir = tempdir("bomb-zip");
    let f = fs::File::create(dir.join("zeros.zip")).unwrap();
    let mut w = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    w.start_file("big.zeros", opts).unwrap();
    let chunk = vec![0u8; 1024 * 1024];
    for _ in 0..64 {
        w.write_all(&chunk).unwrap(); // 64 MiB compresses to ~60 KiB
    }
    w.finish().unwrap();

    let root = dir.join("root");
    let err = extract(
        &dir.join("zeros.zip"),
        &root,
        &ExtractOptions {
            max_total_raw: 1024 * 1024, // far below 64 MiB
            ..ExtractOptions::default()
        },
    )
    .expect_err("budget must trip");
    assert!(
        matches!(
            err,
            cinder_formats::FormatsError::Core(
                cinder_core::CinderError::DecompressionBombSuspected(_)
            ) | cinder_formats::FormatsError::WithContext { .. }
        ),
        "expected bomb error, got {err}"
    );
}

#[test]
fn selected_members_extract_without_touching_others() {
    let dir = tempdir("select");
    let src = dir.join("tree");
    let expected = fixture_tree(&src);
    let archive = dir.join("sel.tar.gz");
    create(
        &src,
        &archive,
        CreateFormat::TarGz,
        CreateOptions::default(),
    )
    .unwrap();

    let mut want = HashSet::new();
    want.insert("top.txt".to_string());
    let out = dir.join("out");
    let s = cinder_formats::extract_selected(
        &archive,
        &out,
        &ExtractOptions::default(),
        &cinder_formats::ExtractSelection::only(want),
    )
    .unwrap();
    assert_eq!(s.files, 1);
    assert!(out.join("top.txt").exists());
    assert!(!out.join("empty.dat").exists());
    assert_eq!(expected.len(), 4); // sanity on fixture shape
}
