# Security policy

Please do not report a suspected archive parser, extraction, cryptography, or
path-confinement vulnerability in a public issue first.

Use GitHub's private vulnerability reporting for the repository, or contact
the maintainers privately with:

- a concise impact statement;
- the smallest reproducer or archive possible;
- affected version / commit;
- operating system and target;
- whether the issue requires an encrypted archive or special filesystem.

Do not include real secrets or private user data in a reproducer. Cinder's
security model is defense in depth, not a guarantee that every foreign format
or operating-system provider is harmless; treat untrusted archives as hostile
and keep the safety limits enabled.

## Hardened security baseline (August 2026)

Cinder is a local archive utility, not a network service. Its security
boundary is hostile archive bytes, archive-derived names and metadata,
user-selected filesystem destinations, passphrases, and the native
desktop/mobile packaging layer.

The current implementation includes:

- bounded header, footer, manifest, entry, path, frame, chunk-reference, and
  logical-output limits before attacker-controlled data is materialized;
- checked arithmetic and fallible allocation on parser, decompression, and
  extraction paths;
- manifest relationship validation before extraction, including duplicate
  paths, stream ranges, chunk references, physical frame bounds, and archive
  version/flag checks;
- lexical and physical path confinement, Windows device-name rejection,
  symlink-target validation, no-follow destination creation, and removal of
  Unix special permission bits during extraction;
- native and foreign-format input/output alias checks, foreign entry-count and
  decompression budgets, and exact-size checks for ZIP/TAR members;
- versioned `.cidx` chunk indexes that store hashes/provenance only, use a
  lock, and atomically replace their JSON state;
- delta descriptors that bind base and delta archive digests, deletion sets,
  and the final snapshot digest before apply;
- detached Ed25519 manifest signatures covering the full archive digest and
  deterministic manifest digest;
- XChaCha20-Poly1305 authenticated encryption with OS-random nonces and
  Argon2id key derivation; passphrases are prompted without terminal echo when
  an interactive CLI prompt is available;
- RustSec (`cargo audit`), license/source/duplicate policy (`cargo deny`),
  Clippy, property tests, hostile-archive tests, and libFuzzer targets in the
  release engineering path.

These controls map the archive tool's applicable risks to OWASP Top 10:2025
(especially A02 Security Misconfiguration, A03 Software Supply Chain
Failures, A04 Cryptographic Failures, A06 Insecure Design, A08 Software/Data
Integrity, and A10 Mishandling Exceptional Conditions) and the 2025 CWE Top 25
(especially path traversal, improper input validation, deserialization,
resource exhaustion, and out-of-bounds classes).

## Mobile security requirements

The repository now includes Android SAF/JNI and iOS SwiftUI document-provider
shell sources. A production wrapper must not bypass the
core limits or turn user-controlled document-provider paths into raw paths.
It must use Android Storage Access Framework / scoped storage, iOS
security-scoped URLs, private temporary storage, non-exported components by
default, no cleartext networking, platform keystore-backed secret handling,
foreground cancellation-safe jobs, and release signing with protected keys.
The mobile shell should be verified against OWASP MASVS-L1 at minimum and
MASVS-L2 for sensitive encrypted archives. No mobile artifact should be
described as security-reviewed until those native-shell tests and signing
checks exist; source shells are not a substitute for platform review.

## Automated checks

Run locally before publishing:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo deny check
cargo fuzz run archive_parser -- -max_total_time=3600
cargo fuzz run extract_paths -- -max_total_time=3600
```

The audit database and standards change over time. Re-run the checks at every
release and after dependency, compiler, OS, Android SDK/NDK, or Xcode changes.
