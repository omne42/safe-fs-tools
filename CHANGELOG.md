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
- Add `limits.max_patch_bytes` to cap unified-diff patch input size (defaults to `limits.max_read_bytes`).
- `read`/`edit`/`patch` responses now include `requested_path` (normalized input path).
- `delete` responses now include `requested_path` (normalized input path).
- Add `Context` method wrappers and crate-root re-exports for easier library consumption.
- Add `SandboxPolicy::single_root` helper for simpler library integration.
- Add `Context::from_policy_path` helper for a one-call policy+context load (via `policy-io`).
- CLI: add `--error-format json` for structured errors.
- CLI: add `--max-patch-bytes` to cap patch stdin/file input size.
- CLI: add `--redact-paths` to best-effort redact absolute paths in JSON error output.
- CLI: include `error.details` in JSON errors for most tool error kinds.
- Add `docs/example-survey.md` (notes from `example/` repositories).
- Add `docs/db-vfs.md` (DB-backed VFS decision + TODOs).
- Add optional cargo features: `glob`/`grep`/`patch` (default on) and `policy-io`.

### Changed

- Bump crate editions to Rust 2024.
- `Error` is now `#[non_exhaustive]`; downstream code should include a wildcard match arm.
- Enforce roots are absolute directories (policy validation + context init).
- `glob`/`grep` now include symlinked files (still do not traverse symlinked directories).
- `glob`/`grep` traversal now uses deterministic entry ordering (stable behavior under truncation caps).
- `glob`/`grep` may narrow traversal scope based on a literal prefix in the glob pattern.
- `edit` now checks `limits.max_write_bytes` before constructing the edited output.
- `patch` now enforces patch input size via `limits.max_patch_bytes`/`limits.max_read_bytes` (rejects oversized patch input with `input_too_large`).
- CLI `--max-patch-bytes` defaults to `limits.max_patch_bytes` if set (else `limits.max_read_bytes`) and is capped by policy.
- IO errors produced by operations include operation/path context where available.
- Internal: consolidate lexical path normalization into a shared helper to avoid drift between ops and deny-glob matching.
- Atomic write on Windows now uses `ReplaceFileW` for true replacement semantics.
- On Windows, `secrets.deny_globs` matching is now explicitly case-insensitive.
- On Windows, `glob` patterns and `traversal.skip_globs` matching are now explicitly case-insensitive.
- CLI: JSON `error.details` for `io`/`io_path` now always include `io_kind` and `raw_os_error` (even without `--redact-paths`).
- CLI: add `--redact-paths-strict` for stricter path redaction in JSON errors.
- `policy-io`: `load_policy` now enforces a maximum policy file size (default 4 MiB); use `load_policy_limited` for custom limits.
- Docs: clarify `glob`/`grep` truncation semantics when `limits.max_results` is hit.
- Docs: clarify atomic write durability semantics.
- Docs: clarify `SandboxPolicy::validate` is structural (no filesystem IO).
- Internal: share traversal loop between `glob` and `grep` to reduce drift.

### Fixed

- `--no-default-features` now builds cleanly (gate `walkdir` error variant behind traversal features).
- `delete` now applies `secrets.deny_globs` to the normalized requested path (prevents bypass via symlinked directories).
- `secrets.deny_globs` can no longer be bypassed via symlink paths (deny rules are applied before resolving symlink targets).
- `secrets.deny_globs` matching now performs lexical normalization (e.g. `sub/../.git/...`), preventing bypass via `..` segments.
- Lexical normalization now preserves repeated leading `..` segments (e.g. `../../b`), improving path reporting and deny-glob behavior.
- On Windows, glob/deny-glob matching now handles `\\` path separators.
- On Windows, prefix-optimized traversal rejects drive-letter glob prefixes (e.g. `C:/...`) to prevent escaping the selected root.
- On Windows, prefix-optimized traversal also rejects embedded drive prefixes (e.g. `src/C:foo/*`) to prevent escaping the selected root.
- On Windows, drive-relative paths (e.g. `C:foo`) are now rejected by `SandboxPolicy::resolve_path`.
- Redaction replacement strings are now treated literally (no `$1` / `$name` capture expansion).
- `edit`/`patch` now write atomically (temp file + rename) and preserve existing file permissions.
- Atomic write temp files are created with restrictive permissions on Unix to avoid transient exposure.
- Dangling symlinks that would escape a root are now classified as `outside_root` (instead of a generic IO error).
- `glob`/`grep` no longer fail on dangling symlink targets; they skip the entry.
- `glob`/`grep` no longer fail on traversal/read errors (e.g. permission-denied directories/files); they skip the entry and report skip counts.
- Prefix-optimized traversal no longer follows symlink directories (`walkdir` root links are not followed).
- CLI `--redact-paths` no longer includes raw `walkdir` error messages in JSON `error.details` (which could leak absolute paths).
- On Windows, lexical path normalization no longer drops drive/UNC prefixes (fixes `..` handling for absolute paths).
- Invalid `secrets.redact_regexes` patterns are now rejected as `invalid_policy` (instead of `invalid_regex`).
- CLI `--redact-paths` now omits raw `io` error messages in JSON `error.details` and includes structured `io_kind`/`raw_os_error` instead.
- `outside_root` and related `canonicalize` errors now report the normalized requested path (avoids leaking absolute root paths for relative inputs).
- Root-level traversal (`glob`/`grep`) errors no longer leak absolute paths via `walkdir` errors.
- Absolute path normalization no longer fails when deriving `requested_path` requires canonicalizing a missing/unreadable parent directory.
- `requested_path` no longer serializes as an empty string for `.` inputs.
