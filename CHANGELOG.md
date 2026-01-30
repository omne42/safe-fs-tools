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
- Add `limits.max_walk_ms` traversal time budget for `glob`/`grep` and report `elapsed_ms` in responses.
- `glob`/`grep` responses now include `scan_limit_reason` (`entries`/`files`/`time`) when traversal caps are hit.
- `glob`/`grep` responses now include traversal diagnostics (`scanned_entries`, `skipped_walk_errors`, `skipped_io_errors`, `skipped_dangling_symlink_targets`).
- Add `traversal.skip_globs` to skip paths during traversal (`glob`/`grep`) without denying direct access.
- Enforce `limits.max_read_bytes` for `edit`/`patch` file reads (and use bounded reads for `read`/`grep`).
- `delete` unlinks symlinks (does not follow link targets).
- Add stable `Error::code()` for programmatic classification.
- Add `Error::InputTooLarge` (code: `input_too_large`) for oversized CLI inputs.
- Add `Context` method wrappers and crate-root re-exports for easier library consumption.
- Add `SandboxPolicy::single_root` helper for simpler library integration.
- Add `Context::from_policy_path` helper for a one-call policy+context load (via `policy-io`).
- CLI: add `--error-format json` for structured errors.
- CLI: add `--max-patch-bytes` to cap patch stdin/file input size (defaults to `limits.max_read_bytes`).
- CLI: include `error.details` in JSON errors for most tool error kinds.
- Add `docs/example-survey.md` (notes from `example/` repositories).
- Add `docs/db-vfs.md` (DB-backed VFS decision + TODOs).
- Add optional cargo features: `glob`/`grep`/`patch` (default on) and `policy-io`.

### Changed

- Bump crate editions to Rust 2024.
- Enforce roots are absolute directories (policy validation + context init).
- `glob`/`grep` now include symlinked files (still do not traverse symlinked directories).
- `glob`/`grep` traversal now uses deterministic entry ordering (stable behavior under truncation caps).
- `glob`/`grep` may narrow traversal scope based on a literal prefix in the glob pattern.
- IO errors produced by operations include operation/path context where available.
- Atomic write on Windows now uses `ReplaceFileW` for true replacement semantics.

### Fixed

- `--no-default-features` now builds cleanly (gate `walkdir` error variant behind traversal features).
- `secrets.deny_globs` can no longer be bypassed via symlink paths (deny rules are applied before resolving symlink targets).
- `secrets.deny_globs` matching now performs lexical normalization (e.g. `sub/../.git/...`), preventing bypass via `..` segments.
- On Windows, glob/deny-glob matching now handles `\\` path separators.
- Redaction replacement strings are now treated literally (no `$1` / `$name` capture expansion).
- `edit`/`patch` now write atomically (temp file + rename) and preserve existing file permissions.
- Atomic write temp files are created with restrictive permissions on Unix to avoid transient exposure.
- Dangling symlinks that would escape a root are now classified as `outside_root` (instead of a generic IO error).
- `glob`/`grep` no longer fail on dangling symlink targets; they skip the entry.
- `glob`/`grep` no longer fail on traversal/read errors (e.g. permission-denied directories/files); they skip the entry and report skip counts.
- Prefix-optimized traversal no longer follows symlink directories (`walkdir` root links are not followed).
