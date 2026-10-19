# Contributing to Cinder

## Before opening a change

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Archive and extraction changes should include a round-trip test. Changes that
touch untrusted input should include malformed-input, traversal, or budget
coverage as appropriate. Performance changes should include a reproducible
benchmark note in `docs/PERFORMANCE.md` or `docs/BENCHMARKS.md`.

## Pull requests

- Explain the user-visible behavior and the safety impact.
- Keep format changes versioned and backward-compatible where possible.
- Do not claim a compression win without publishing the corpus and settings.
- Keep UI work accessible: keyboard paths, tooltips, empty states, and clear
  error messages matter as much as styling.

## Commit and release hygiene

Do not commit archives, secrets, signing keys, generated `target/` output, or
private benchmark corpora. Release tags use `vMAJOR.MINOR.PATCH` and are built
by the GitHub Actions release workflow.
