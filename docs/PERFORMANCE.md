# Cinder performance plan

## What can be promised

Cinder guarantees lossless restoration and verified chunk identity. It cannot
guarantee that one codec is the smallest for every possible corpus: WinRAR,
7-Zip, zstd, xz, and specialized tools each win on different data. A fair
comparison must use identical inputs, settings, hardware, filesystem cache
state, and output validation.

## Current hot path

1. deterministic traversal;
2. FastCDC boundaries;
3. BLAKE3 fingerprinting and in-archive deduplication;
4. bounded frame assembly;
5. parallel codec workers;
6. ordered sequential writes;
7. seek-table and manifest serialization.

Large files use read-only memory mapping, small files use owned buffers, and
solid groups are capped at 32 MiB / 2048 files. The worker pool defaults to a
bounded host-aware count and is controllable with `--threads`.

## Tuning guide

| Goal | Setting | Why |
| --- | --- | --- |
| Lowest wall-clock time | `--profile fast --threads <cores>` | Zstd has low latency and parallel workers stay busy. |
| Best mixed-data default | `--profile balanced` | Good ratio without XZ's long tail. |
| Smallest cold archive | `--profile max --threads 1..N` | XZ/LZMA2 spends more CPU for a smaller result on many corpora. |
| Low-memory host | `--threads 1..4` | Reduces in-flight frame pressure. |
| Many related small files | Keep solid mode enabled | Shared history improves ratio and dedup visibility. |
| Already compressed media | Any profile | Stored-frame detection avoids pointless recompression. |

## Comparison protocol

Record the following for every tool and run:

- exact tool version and command line;
- CPU model, RAM, operating system, filesystem, and thermal/power mode;
- cold-cache and warm-cache results separately;
- input bytes, archive bytes, compression time, extraction time, and peak RSS;
- byte-for-byte or cryptographic hash validation after extraction;
- repeated runs and median / p95 values.

Recommended corpus buckets:

```text
vm-snapshots/       near-identical binary images
rotated-logs/       repetitive text with shifted boundaries
small-files/        thousands of related files
mixed-tree/         source, JSON, images, archives, and media
already-packed/     ZIP, JPEG, PNG, MP4, FLAC, and Zstd payloads
```

## Next optimization stages

### Adaptive multi-codec mode — implemented

For a sampled frame, estimate whether Zstd, XZ, or stored bytes wins. For
small frames, use a bounded trial and keep the smallest result; for large
frames, use a cheap entropy / signature gate before committing to the chosen
profile. The sample remains bounded and deterministic; full runs verify
byte-for-byte restoration before a profile can be recommended.

### Persistent dedup index — implemented

The optional `.cidx` sidecar stores hashes and provenance only, uses a lock and
atomic replacement, and has an explicit privacy note because shared hashes can
reveal cross-archive similarity. Delta snapshots use the same deterministic
manifest/chunk relationships to avoid recompressing unchanged files.

### I/O-aware scheduling

Separate source read concurrency from codec worker concurrency. NVMe systems
can tolerate more outstanding reads; network or spinning disks often perform
better with fewer. Expose both knobs only after profiling shows they help.

### Parallel extraction

The current sequential writer protects deterministic output and safety. A
future extractor can decode independent frames concurrently into temporary
validated buffers, then commit files through a bounded writer queue.

Each stage should land with a benchmark, a memory bound, and a round-trip test;
performance changes without those three artifacts do not qualify as release
optimizations.
