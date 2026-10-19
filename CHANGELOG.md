# Changelog

## 1.0.0 - 2026-10-19

- Added file and archive right-click actions, multi-item drag/drop, grouped
  archive extraction, and per-user Windows Explorer menus.
- Added multi-file and multi-folder archive creation with duplicate path checks.
- Made archive replacement explicit and grouped extraction collision-safe.
- Converted the supplied logo into a valid PNG and embedded a multi-size Windows
  icon from the same asset.
- Added bounded, reproducible compression worker control with `--threads`.
- Added release-ready CI and desktop artifact workflows.
- Added detailed README, architecture, performance, security, and mobile
  packaging documentation.
- Separated desktop file dialogs from the future mobile shell boundary.
- Supports RAR 1.3 through RAR 7.0 creation, modern and legacy split RAR
  extraction, and tested multi-volume RAR sets.
