# Fuzzing

Targets (see `fuzz_targets/`):

- **archive_parser** — feeds arbitrary bytes through
  `ArchiveReader::open` + chunk/stream reads. Contract: errors, never panics.
- **extract_paths** — drives `safe_destination` / `validate_link_target`
  with arbitrary strings. Contracts: never panics; accepted paths are always
  confined to the root (asserted in-target).

## Running

On Linux/macOS (or Windows with LLVM's sanitizer runtime DLLs on PATH):

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run archive_parser   # add e.g. -- -max_total_time=3600
cargo +nightly fuzz run extract_paths
```

Note (2026-08): on this repository's original dev box (Windows/MSVC), the
ASan runtime required by libFuzzer was not installed, so runs there fall back
to the deterministic equivalents in `cinder-core/tests/security.rs`
(`open_garbage_never_panics`, `bitflip_never_panics`) which drive the exact
same library entry points via proptest. The full CPU-hour budget from the
project brief must still be discharged on an ASan-capable host before v1.
