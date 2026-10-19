# Recorded measurements

Policy: every number here comes from an actual run in this repository.
Nothing is projected, estimated, or borrowed. Each run lists its hardware
context and input shape so results can be reproduced or superseded.

---

## Run 1 — random access vs full extraction (2026-08-22)

- **Machine:** Windows 11 x64 laptop (ACER), Rust 1.94.0 stable, `--release`
- **Input:** 20 rotated-log-style files × ~28 MB = 571,900,000 bytes of
  highly repetitive text
- **Command:** `cinder-cli compress` → archive; then full `extract` vs `get`
  of one member (`seg-13.log`)
- **Archive size:** 716,137 bytes (extreme dedup expected for this synthetic,
  near-identical-lines corpus)
- **Results:**

| Operation | Wall time |
|---|---|
| Full extraction (all 20 files) | 1865 ms |
| Single-file random-access `get` | 141 ms |
| **Speed-up** | **13.2×** |

## Run 2 — v1 DoD metrics at reduced scale (2026-08-22)

Harness: `CINDER_SCALE=1 cargo test -p cinder-core --release --test scale -- --ignored --nocapture`
(sources in `cinder-core/tests/scale.rs`; fixtures generated deterministically
inside the harness).

Same machine as Run 1.

### A — entropy-coder parity (DoD §8 item 1)

Fixture: **512 MiB of strictly unique log-style text** (every line embeds a
monotonic counter, so chunk dedup cannot contribute — `duplicate_chunks=0`).
This isolates chunked-zstd-15 against single-stream-zstd-15.

| Compressor | Size | Ratio |
|---|---|---|
| Cinder `balanced` (zstd 15, per-frame) | 54.0 MiB | 10.55% |
| zstd -15 streaming reference | 52.0 MiB | 10.15% |
| **Cinder delta** | | **+3.92%** |

Within the DoD bar ("within a few percent"). The residual cost is per-frame
dictionary reset at ~2 MiB packing boundaries — the price of seekability.

### B — near-duplicate folder vs `tar | zstd` equivalent (DoD §8 item 2)

Fixture: two 512 MiB VM-snapshot-flavoured images (zero runs + repeating page
pool + text), differing by a 4 KiB patch mid-file.

| Approach | Size | % of input |
|---|---|---|
| Cinder combined archive | **5.5 MiB** | 0.54% |
| Concatenated-stream zstd -15 ("tar \| zstd" equivalent) | 595.6 MiB | 58.16% |
| **Saving** | **99.1%** | — |

6,086 duplicate chunks were recognised across the file pair. The baseline is
the honest in-process equivalent of piping the concatenation through
single-threaded `zstd -15`; it has no cross-file awareness by construction.

*Solid-mode acceptance on several-thousand-file trees is covered
deterministically by `cinder-core/tests/dedup.rs::solid_mode_beats_per_file_compression_on_small_files`
(>10% margin asserted); its absolute numbers are not recorded here because
they vary per fixture generation.*

## Run 3 — deterministic fuzz budget (2026-08-22)

`cargo test -p cinder-core --release --test security fuzz_budget -- --ignored --nocapture`
with `CINDER_FUZZ_BUDGET=2000000`.

- 2,000,000 mutated/garbage inputs through `ArchiveReader::open` +
  `read_chunk`: 13,879 checksum-repaired mutants reached deep manifest/frame
  parsing; zero panics after the fix below.
- **Found & fixed during this run:** a crafted `ChunkLocation.frame_length < 28`
  caused an out-of-range slice panic in `archive/reader.rs`
  (`&raw[..FRAME_HEADER_LEN]`) before `parse_frame_header`'s own guard ran.
  Now rejected as corrupt input; regression covered by the budget test.

The libFuzzer targets under `fuzz/` remain the vehicle for the full CPU-hour
budget required for v1 (see `fuzz/README.md`); MSVC hosts without LLVM's ASan
runtime fall back to this deterministic harness meanwhile.

## Automated corpus reports

`cinder bench` performs a bounded sample pass across fast, balanced, and max
profiles, then runs complete archive/extract/verification measurements for each
profile. It emits machine-readable JSON and a Markdown summary:

```bash
cinder bench ./corpus --output corpus-report.json --sample-bytes 8388608
```

The recommendation is corpus-specific and must not be presented as a universal
claim about WinRAR or 7-Zip.

## Pending runs (explicitly not measured yet)

- [ ] All three profiles vs 7-Zip and borgbackup binaries (not installed on
      the recording machine; the zstd-15 reference in Run 2-A covers the
      entropy-coder parity intent)
- [ ] Multi-hundred-GiB executions of Runs 1–2 shapes (harness scales via
      the `unit` constant)
- [ ] `cargo fuzz run archive_parser` full CPU-hour budget on an ASan host
- [ ] Random-access speed-up on a true multi-gigabyte archive

The in-repo criterion suite (`cargo bench -p cinder-core`) covers codec tiers,
chunking throughput and pipeline round-trips against a deterministic 4 MiB
synthetic corpus; those are relative numbers for regression tracking, not
marketing figures.
