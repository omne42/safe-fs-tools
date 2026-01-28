# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial `SandboxPolicy`/`Root`/`SecretRules` model.
- Library + CLI for `read/glob/grep/edit/patch/delete` with root-bounded access and redaction.
- `read` supports optional line ranges (`start_line`/`end_line`).
- `grep` reports skipped file counts for non-UTF8 / too-large files.
- `grep` matches include `line_truncated` when a matched line is clipped to `limits.max_line_bytes`.
- `edit` preserves CRLF line endings.
- `glob` results are sorted by path; `grep` results are sorted by `(path, line)`.
- Split CLI into `safe-fs-tools-cli` so the library has no CLI-format dependencies.
- Add `limits.max_walk_files` and report `scanned_files` / `scan_limit_reached` in `glob`/`grep` responses.
- Add `limits.max_walk_entries` to cap directory traversal work (helps bound huge directory trees with few files).
- Enforce `limits.max_read_bytes` for `edit`/`patch` file reads (and use bounded reads for `read`/`grep`).
- `delete` unlinks symlinks (does not follow link targets).
- Add stable `Error::code()` for programmatic classification.
- Add `Context` method wrappers and crate-root re-exports for easier library consumption.
- Add `SandboxPolicy::single_root` helper for simpler library integration.
- Add `Context::from_policy_path` helper for a one-call policy+context load (via `policy-io`).
- CLI: add `--error-format json` for structured errors.
- Add `docs/example-survey.md` (notes from `example/` repositories).
- Add optional cargo features: `glob`/`grep`/`patch` (default on) and `policy-io`.

### Changed

- Bump crate editions to Rust 2024.
- Enforce roots are absolute directories (policy validation + context init).
- `glob`/`grep` now include symlinked files (still do not traverse symlinked directories).
- IO errors produced by operations include operation/path context where available.

### Fixed

- `--no-default-features` now builds cleanly (gate `walkdir` error variant behind traversal features).
- `secrets.deny_globs` can no longer be bypassed via symlink paths (deny rules are applied before resolving symlink targets).
- Redaction replacement strings are now treated literally (no `$1` / `$name` capture expansion).
- `edit`/`patch` now write atomically (temp file + rename) and preserve existing file permissions.
