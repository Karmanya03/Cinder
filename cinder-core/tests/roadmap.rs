use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use cinder_core::{
    benchmark_path, build_delta, compare_snapshot, generate_signing_key, rebuild_chunk_index,
    sign_archive, verify_signature, BenchmarkOptions, CompressOptions, DeltaOptions, ProgressEvent,
};

fn tempdir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cinder-roadmap-{label}-{}", std::process::id()));
    fs::remove_dir_all(&path).ok();
    fs::create_dir_all(&path).unwrap();
    fs::canonicalize(path).unwrap()
}

fn quiet() -> Arc<dyn Fn(&ProgressEvent) + Send + Sync> {
    Arc::new(|_| {})
}

#[test]
fn adaptive_benchmark_emits_verified_report() {
    let dir = tempdir("bench");
    let source = dir.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("data.txt"), b"repeatable data\n".repeat(1024)).unwrap();
    let report = benchmark_path(
        &source,
        &BenchmarkOptions {
            sample_bytes: 4096,
            ..BenchmarkOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report.results.len(), 3);
    assert!(report.results.iter().all(|result| result.verified));
    assert_ne!(report.recommended_profile, "none");
    assert!(report.to_markdown().contains("Recommended profile"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn delta_snapshot_and_persistent_index_round_trip() {
    let dir = tempdir("delta-index");
    let source = dir.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("keep.txt"), b"same").unwrap();
    fs::write(source.join("change.txt"), b"before").unwrap();
    let base = dir.join("base.cnd");
    cinder_core::compress_path(&source, &base, &CompressOptions::default(), &quiet()).unwrap();

    fs::write(source.join("change.txt"), b"after").unwrap();
    fs::remove_file(source.join("keep.txt")).unwrap();
    fs::write(source.join("new.txt"), b"new").unwrap();
    let report = compare_snapshot(&base, &source, None).unwrap();
    assert_eq!(report.added, vec!["new.txt"]);
    assert_eq!(report.modified, vec!["change.txt"]);
    assert_eq!(report.deleted, vec!["keep.txt"]);

    let delta = dir.join("delta.cnd");
    build_delta(&base, &source, &delta, &DeltaOptions::default(), &quiet()).unwrap();
    let restored = dir.join("restored");
    cinder_core::apply_delta(&base, &delta, &restored, None).unwrap();
    assert_eq!(fs::read(restored.join("change.txt")).unwrap(), b"after");
    assert_eq!(fs::read(restored.join("new.txt")).unwrap(), b"new");
    assert!(!restored.join("keep.txt").exists());

    let index_path = dir.join("chunks.cidx");
    let stats = rebuild_chunk_index(&index_path, std::slice::from_ref(&base)).unwrap();
    assert!(stats.unique_chunks > 0);
    let stats_again = rebuild_chunk_index(&index_path, std::slice::from_ref(&delta)).unwrap();
    assert!(stats_again.unique_chunks > 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn detached_manifest_signature_round_trip() {
    let dir = tempdir("signature");
    let source = dir.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("signed.txt"), b"signed content").unwrap();
    let archive = dir.join("signed.cnd");
    cinder_core::compress_path(&source, &archive, &CompressOptions::default(), &quiet()).unwrap();
    let key = dir.join("signing.key");
    let public = generate_signing_key(&key).unwrap();
    let signature = dir.join("signed.sig.json");
    let signed = sign_archive(&archive, &key, &signature, None).unwrap();
    assert_eq!(signed.public_key, public);
    assert_eq!(
        verify_signature(&archive, &signature, None)
            .unwrap()
            .public_key,
        public
    );
    fs::write(&archive, b"tampered").unwrap();
    assert!(verify_signature(&archive, &signature, None).is_err());
    fs::remove_dir_all(dir).unwrap();
}
