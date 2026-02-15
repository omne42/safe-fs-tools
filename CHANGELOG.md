# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Docs overhaul: rebuilt project documentation into a structured portal (`docs/index.md`) with dedicated guides for getting started, concepts, policy/operations/CLI/library references, security usage, deployment/ops, and FAQ.
- Traversal I/O optimization: `walk_traversal_files` now supports per-operation open mode so `grep` reuses a single no-follow open per file and `glob` avoids unnecessary pre-open checks.
- `grep` glob-filter optimization: when `grep.glob` is set, traversal defers file open until after glob match filtering (avoids opening non-matching files).
- Result collection tuning: `glob`/`grep` now cap initial match-vector reservation and skip sorting when zero/one result to reduce avoidable CPU and allocation overhead.
- Large-line memory smoothing: `grep` and `read` line-range loops now trim oversized reusable line buffers after long-line reads to reduce post-spike retained capacity.
- Internal write path cleanup: `commit_write` now consumes `WriteCommitContext` so permission metadata is moved into temp-file commit without an extra `Permissions` clone.
- Redaction compilation cleanup: redact patterns now compile once into `Regex` values (remove duplicate `Regex` + `RegexSet` compilation of the same rules).
- Redaction hot-path allocation trim: per-regex replacement now delays `String` allocation until first match instead of allocating on no-match paths.
- Path-boundary fast path: add internal normalized-path helpers to avoid repeated lexical normalization in hot root-boundary checks.
- Path-boundary helper fast path: avoid normalization allocation for already-clean paths (no `.`/`..` segments).
- Policy docs/hardening note: add explicit TOCTOU warning comment at `resolve_path_checked` return site to emphasize lexical-only guarantees.
- IO read-path allocation trim: preallocate read buffer from known file size when bounded by `max_read_bytes`.
- `grep` match assembly: remove per-file intermediate match vector and append directly to output matches.
- `read` line-range scanning: use a dedicated scratch buffer for pre-range skipped lines to avoid growing output capacity on skipped long lines.
- `glob`/`grep` hot paths: preallocate output match vectors to `limits.max_results`.
- `grep` hot loop: skip redaction regex processing entirely when no redact rules are configured.
- Cleanup: simplify `list_dir` filename extraction and remove avoidable `Metadata` clone in `resolve/dir_ops` create path.
- Context init cleanup: remove redundant runtime duplicate-`root.id` policy error path in `Context` construction and rely on `SandboxPolicy::validate_structural` as the single source of truth.
- `grep` internal allocation trim: per-file match assembly now moves one owned `relative_path` into output and only clones for additional matches in that same file.
- `grep` correctness fix: preserve the first match path when reusing per-file path allocations so multi-match files never emit empty `path` values.
- CLI input IO trim: reuse metadata from no-follow open and preallocate file-read buffers from known file size in `load_text_limited`.
- `grep` read-path memory trim: switch per-file scan from full-buffer reads to streaming `BufRead` line scanning while preserving too-large/non-UTF-8 skip semantics.
- `list_dir` hot path: avoid cloning canonical root `PathBuf` on each call; use borrowed root path directly during entry processing.
- Unix metadata-copy docs: document why Linux/Android xattr preservation uses fd-scoped libc syscalls (std has no xattr API) and clarify syscall-level `unsafe` invariants.
- `grep` readability cleanup: flatten per-line regex/plain query match selection via `Option` combinator (`map_or_else`) in the hot scan loop.
- Delete API cleanup: remove over-designed `DeleteKind`/`&str` `PartialEq` impls and keep comparisons explicit at call sites.
- CLI command dispatch: consume `Cli`/`Command` by value in `command_exec` so request payload fields are moved instead of repeatedly cloned per branch.
- Policy ergonomics: mark `Permissions` as `Copy` (it is a bool-only value type), reducing incidental clone noise at call sites.
- Ops permission-gate cleanup: centralize policy-permission checks in `Context` helpers and route operation entry checks through them to reduce repeated inline guards.
- `write` internals: rename generic lifetime parameter in `WriteCommitContext` to a semantic name (`'ctx`) for clearer ownership intent.
- Redaction internals: factor shared `normalize_path_for_glob` logic into a common helper; Windows keeps only the extra path-separator/non-Unicode handling.
- Policy docs: clarify lexical-only path-check wording for `resolve_path_checked`.
- Combinator cleanup: replace selected small `match`/`if let` return plumbing with `and_then`/`map_or(_else)` chains in traversal/patch helpers.
- Platform boundary cleanup: isolate platform-specific FFI/`unsafe` into `src/platform/{rename,windows_path_compare,unix_metadata}.rs` and keep `ops/io` + `path_utils` on safe wrappers.
- Windows identity hardening: `copy_file`/`delete` now only treat two paths as the same file when all identity fields (`volume_serial_number`, `file_index`) are present on both sides; unknown IDs fail closed instead of `None == None` false positives.
- `read` line-range memory tuning: switch from file-size-based upfront reservation to a small bounded initial capacity to avoid large allocations for narrow line windows.
- Unix metadata portability: fix ownership-preservation `gid` sentinel to use `libc::gid_t::MAX` (instead of `uid_t`) when preserving uid/gid deltas.

## [0.2.0] - 2026-02-14

### Added

- New filesystem operations: `list_dir`, `stat`, `mkdir`, `write_file`, `move_path`, `copy_file` (all root-bounded and policy-gated).
- Policy: add `permissions.{list_dir,stat,mkdir,write,move,copy_file}`.
- CLI: add commands `list-dir`, `stat`, `mkdir`, `write`, `move`, `copy-file` and extend `delete` with `--recursive` and `--ignore-missing`.
- Dev: add GitHub Actions workflows (CI/docs/release) and a shared `scripts/gate.sh`.
- Tests: add a Windows regression test for `rename_replace` overwrite semantics.
- Tests: add large-directory/large-file integration scenarios to exercise `list_dir` and `read` under heavier inputs.

### Changed

- CLI internals now reuse the library's shared no-follow regular-file open helper (`open_regular_readonly_nofollow`) instead of maintaining a separate platform-specific opener implementation.
- Docs/internal comments: align `ops` module notes with the current crate-root `glob`/`grep` export behavior.
- Internal cleanup: `read` line-range scanning now uses a single reusable output buffer, and `Context::new` root-overlap checks reuse existing root runtime entries instead of maintaining a duplicate `(id, canonical_path)` side list.
- API: `Context` now supports `Context::builder(policy).build()` as a forward-compatible construction entrypoint while keeping `Context::new(policy)` behavior unchanged.
- Internal path-resolution cleanup: `resolve_path_in_root_lexically` now keeps `canonical_root` borrowed as `&Path` for intermediate checks and only materializes a `PathBuf` at the return boundary.
- API docs: `ReadRequest.path` now documents the ownership rationale (`PathBuf` request boundary, borrowed hot path) to avoid unnecessary lifetime-driven API complexity.
- Batch review/apply refresh (`10` 并发) across `cli`/`src/ops`/`tests`: tightened error-path consistency, reduced deeply nested control flow, and normalized formatting/readability in hot and boundary-sensitive paths.
- Path-resolution contract hardening: internal lexical resolve flow now uses `resolve_path_checked` for explicit root-boundary validation semantics.
- Batch review-driven maintenance sweep across core ops/CLI/tests: tightened path/permission/error handling contracts, reduced control-flow complexity, and aligned helper APIs with clearer ownership and typing boundaries.
- Review follow-up refactor/hardening sweep: strengthened root-relative path contract validation for mutating ops, tightened IO/path error typing and redaction plumbing, and expanded cross-op regression coverage in `tests/*`.
- Internal refactor: flattened traversal walk error/symlink handling into focused helpers in `src/ops/traversal/walk.rs` to reduce nested control flow.
- `list_dir` now uses a dedicated count-only fast path for `max_entries=0`, avoiding unnecessary entry materialization.
- `stat` responses now include optional `accessed_ms`/`created_ms` timestamps and a `readonly` flag.
- Path utils: mark hot short helpers with `#[inline]` for lower call overhead in tight path-processing loops.
- Internal dedup: extracted shared no-follow read-open helpers (`platform_open`) used by `policy-io`, CLI text-input loading, and core read paths; extracted shared non-root leaf validation for `write`/`delete`.
- Internal refactor: split `resolve` directory-walk enforcement into `src/ops/resolve/dir_ops.rs`, split traversal internals into `src/ops/traversal/{compile,walk}.rs`, and moved CLI command dispatch/validation into `cli/src/command_exec.rs`.
- CI supply-chain hardening: all third-party GitHub Actions in `ci/docs/release` workflows are now pinned to immutable commit SHAs (with version comments for auditability).
- Docs wording cleanup: README and DB-VFS notes now use neutral “future work” wording instead of ad-hoc TODO markers in examples/headings.
- Review follow-up hardening: `grep` now rejects empty/whitespace-only queries, `list_dir` now honors explicit `max_entries=0`, and `edit` no longer inserts an extra blank line when replacement text is empty.
- CI/release reproducibility and least-privilege updates: release workflow now defaults to `contents: read` (publish job keeps write), and release/docs cargo commands now run with `--locked`.
- Hook robustness: `githooks/pre-commit` now protects released changelog sections by diffing all non-`[Unreleased]` content instead of relying on a numeric version-heading regex.
- Tests: tightened regression coverage for `grep` entry-limit reason, `list_dir max_entries=0`, empty-line replacement semantics, readonly write side effects, and TOML policy fixture serialization.

- Hooks/tests hardening from full-file review: tightened `commit-msg` subject validation, strengthened `pre-commit` staged-diff failure handling, and added regression assertions for failure-side-effect invariants.
- Error/CLI contract: `tool_error_details*` now always returns a JSON object, and `patch` error details/messages are path-redaction aware.
- API typing: `stat` response `type` is now modeled by `StatKind` enum in Rust while preserving lowercase JSON serialization.
- Internal API cleanup: `Context::canonical_root` now returns `&Path` instead of `&PathBuf` to avoid leaking storage details.
- Docs: refresh `README`/`SECURITY`/`docs/db-vfs.md`/`AGENTS.md` wording for command naming, disclosure channel, reproducible DB-VFS setup, and execution flow.

- Hooks/scripts: `pre-commit` now parses staged files via `--name-status -z` (including rename/copy cases) and explicitly rejects deleting `CHANGELOG.md`; `scripts/gate.sh` now derives the workspace root from script location instead of caller `pwd`.
- Docs/examples: tighten wording in `README.md`/`AGENTS.md`/`SECURITY.md`, clarify DB-VFS `path_prefix` derivation rules, and make `policy.example.toml` use a neutral absolute-path placeholder with a Windows example.
- Workspace: `cli/Cargo.toml` now uses only the local `path` dependency for `safe-fs-tools` (drops redundant fixed `version`).

- Breaking: consolidate delete APIs as `delete` (remove `delete_file`/`delete_path`); `DeleteRequest` adds `recursive`/`ignore_missing` and the response adds `{deleted, type}`.
- `policy-io`: `parse_policy` now validates by default; use `parse_policy_unvalidated` when raw parse-without-validate is explicitly required.
- Windows: keep atomic overwrite replacement semantics by using `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` behind a single, documented `unsafe` boundary in `rename_replace` (explicitly reject delete+rename fallback for overwrite paths).
- Dev: pre-commit rejects oversized Rust files (default 1000 lines; configurable via `SAFE_FS_MAX_RS_LINES`).
- Docs: expand README and policy example to include new operations and permissions.
- Docs: split MSRV and toolchain-pin wording, pin the dependency example version, and keep troubleshooting terminology consistent in English.
- Docs: `docs/example-survey.md` is now explicitly non-normative and references authority docs (`README.md`/`SECURITY.md`) instead of stale workspace-local paths.
- Docs: `docs/db-vfs.md` now aligns `path_prefix` and delete/CAS contract wording, and uses env-var DSN examples instead of inline Postgres credentials.
- Docs/Security: add an explicit local-first scope statement and detailed rationale for not adopting a full `openat`/`cap-std` descriptor-chain confinement model at this stage.
- Docs: mark DB-VFS decision implemented, reference the `db-vfs` project, clarify `path_prefix`/CAS semantics, and add a Postgres run example for `db-vfs-service`.
- Docs: update the example upstream integration name to `omne-agent`.
- CI: `release` workflow now runs `cargo test --workspace` before publishing artifacts.
- Docs: README now includes a TOC and a "常见失败" troubleshooting section.

### Fixed

- `glob`/`grep` traversal now preserves requested file/symlink-file aliases for file-root walks, so exact patterns like `link.txt` continue matching symlink entries instead of being silently canonicalized to target names.
- `stat` unsupported-platform identity errors now explicitly document that identity revalidation is currently Unix/Windows-only.
- `copy_file` replacement commit path handling now avoids `TempPath::as_ref()` type ambiguity by using an explicit `&Path` binding, restoring clean `cargo check` on current toolchain.
- Regression cleanup after bulk review apply: restored `mkdir` leaf-validation contract, restored default test redaction/permission baseline, aligned read-range error wording back to `invalid line range`, and normalized missing-parent metadata error tagging in directory resolution.
- Tests: expanded `glob` edge coverage for missing derived prefixes and `.` pattern stability.
- CLI tests: Unix FIFO helper now treats `EEXIST` as success, reducing flaky failures in retry/parallel test scenarios.
- `write_file` overwrite path now re-checks canonicalized relative paths against `secrets.deny_globs`, and size conversions avoid lossy `as u64` casts.
- `delete(ignore_missing=true)` now consistently handles `NotFound` races during `remove_file`/`remove_dir_all`.
- `move_path` now delays destination parent creation until after key validations and early-returns `moved=false` for same-entity destinations.
- `mkdir` now re-validates root boundaries for `ignore_existing` directories and rolls back newly-created directories on post-create boundary check failures.
- `policy-io` extension detection is now ASCII case-insensitive (`.JSON`/`.Toml` accepted).
- `pre-commit` now detects `CHANGELOG.md` deletion via rename (`R old -> new`) in addition to direct deletes.

- CLI: strict path redaction now redacts relative paths too (`--redact-paths-strict` no longer leaks path fragments), and stdout `BrokenPipe` handling is centralized.
- Limits/path correctness: `glob`/`grep` now enforce `max_results` before pushing matches; `edit` line indexes now use checked `u64 -> usize` conversion; traversal limit comparisons now avoid lossy integer casts.
- Policy/path safety: `root.id` now rejects leading/trailing whitespace; `policy-io` now treats non-UTF-8 extensions as invalid instead of defaulting to TOML; deny checks now defensively reject parent-relative (`..`) paths.
- Write/move/delete semantics: `copy_file` same-path no-op now still validates source existence/type; `patch` reports `bytes_written=0` on no-op; `move_path`/`delete` now fail closed when root-relative derivation fails instead of falling back to absolute paths.
- `move_path`: destination-exists checks now allow same-entity case-only renames on case-insensitive filesystems.
- `mkdir`: `AlreadyExists` races through symlinks now return explicit symlink errors, and created/accepted directories get an additional canonical post-check against the selected root.
- Platform hardening: on Windows, `policy-io` and CLI input loading now use no-follow (reparse-point) open semantics with handle-based symlink checks; on unsupported non-Unix/non-Windows platforms these paths now fail closed.
- Non-Linux/Android Unix: no-replace rename fallback no longer uses `exists()+rename` (TOCTOU-prone); it now returns `Unsupported` when an atomic primitive is unavailable.

- Unix: file reads and policy/CLI text inputs now open with `O_NOFOLLOW` and validate type on the opened handle, reducing symlink/FIFO TOCTOU windows.
- Non-Windows: `rename_replace(..., replace_existing = false)` now enforces no-replace semantics (Linux/Android uses `renameat2(RENAME_NOREPLACE)`; other Unix fails with `Unsupported` when no atomic primitive exists).
- Unix: atomic rename paths now fsync parent directories after rename for better crash consistency.
- `write_file`: create-new writes now use temp-file + no-replace rename, preventing readers from observing partially written new files.
- `copy_file`/`move_path`/`write_file`: race-time `AlreadyExists` on no-overwrite paths now maps to stable `invalid_path` errors.
- `resolve`: absolute-input requested-path derivation no longer falls back to absolute paths when root-relative derivation fails.
- `secrets.deny_globs`: non-root-relative paths are now denied defensively instead of being implicitly treated as non-matching.
- CI: fix Windows build by using `MoveFileExW` for atomic replacement (avoid missing `ReplaceFileW` bindings).
- CI: fix Windows-only test compilation (`PathBuf` comparison).
- CI: fix Windows `policy_io` TOML tests (avoid backslash escape issues in `path`).
- Docs: add a GitHub Pages root `index.html` redirect so the docs site doesn’t 404.
- CLI: reject symlink paths for patch/content input files loaded by `load_text_limited`.
- CLI: JSON error output now honors `--pretty` and success stdout writes handle `BrokenPipe` without panic.
- CLI: stdin-backed text input errors are now emitted as contextual `io_path` details (`op=read_stdin`, `path=-`).
- `read` line-range mode now validates regular-file type via the opened file handle (instead of split metadata/open checks).
- `patch` errors now include the target relative path for easier diagnostics, and no-op patches avoid unnecessary writes.
- `patch` now performs best-effort same-file identity verification between read and write on Unix (detects inode replacement races).
- `mkdir` now fails closed if root-relative parent derivation fails and handles `create_dir` `AlreadyExists` races more predictably with `ignore_existing`.
- `edit` now normalizes replacement line endings for LF files (converts `\r\n`/`\r` to `\n`) to prevent mixed-EOL output.
- `delete` now returns a consistent missing-path payload (`path=requested_path`) across missing-parent and missing-target branches.
- Hooks/scripts: tighten commit-message bypass rules (`MERGE_HEAD`/`REVERT_HEAD` checks, guarded `fixup!/squash!`), make pre-commit filename-safe with NUL-delimited git plumbing, validate `SAFE_FS_MAX_RS_LINES`, and scope Rust line checks to staged `.rs` files.
- `scripts/gate.sh` now supports configurable core crate name, enforces stricter behavior under CI when workspace metadata is missing, and validates `--no-default-features` with `check+clippy+test` on the core crate.
- `scripts/setup-githooks.sh` now validates/chmods hook files before writing `core.hooksPath` and writes config with `--local`.
- CLI redaction now masks relative-path error inputs to file names, redacts `not_permitted` detail messages, and avoids leaking raw `io`/`not_permitted` text in public redacted messages.
- Hooks/dev scripts: `scripts/gate.sh` now recognizes CI truthy values case-insensitively, fails by default when no workspace is found (with explicit local skip override), and runs cargo gates with `--locked`; `scripts/setup-githooks.sh` now preserves existing non-default `core.hooksPath` and emits success messages on stdout.
- CLI/path guardrails: CLI line-range arguments now enforce `>=1` with early `start_line <= end_line` checks, JSON error fallback remains valid JSON, and text-input `ELOOP` diagnostics now use safer wording.
- Policy/path consistency: `walkdir_root` now has a distinct programmatic error code, policy validation rejects `max_walk_files > max_walk_entries`, policy loading detects unsupported extensions before file reads, and write/copy/delete path checks fail closed more consistently.
- CI/release workflow reliability: CI now has a job timeout, and release tag-version verification now reads `cargo metadata` from a temp file (fixes stdin/here-doc parsing breakage).
- Redaction/policy/tests hardening: empty redaction regex patterns are rejected explicitly, policy byte-limit guard now rejects `>= usize::MAX`, and regression tests were strengthened for readonly delete side effects, FIFO patch input semantics, policy field parsing, symlink-to-secret denial, and Windows traversal skip-glob behavior.

## [0.1.0] - 2026-01-31

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
- `glob`/`grep` responses now include `scan_limit_reason` (`entries`/`files`/`time`/`results`) when a cap is hit.
- `glob`/`grep` responses now include traversal diagnostics (`scanned_entries`, `skipped_walk_errors`, `skipped_io_errors`, `skipped_dangling_symlink_targets`).
- Add `traversal.skip_globs` to skip paths during traversal (`glob`/`grep`) without denying direct access.
- Add `paths.allow_absolute` to optionally reject absolute request paths (require root-relative tool inputs).
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
- Library: expose `path_utils::{starts_with_case_insensitive, strip_prefix_case_insensitive}` helpers (useful for Windows-safe prefix comparisons).

### Changed

- Bump crate editions to Rust 2024.
- `Error` is now `#[non_exhaustive]`; downstream code should include a wildcard match arm.
- `Error::code()` now distinguishes `io` and `io_path`.
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
- `policy-io`: `load_policy` now runs `SandboxPolicy::validate` to catch structural issues early.
- Docs: clarify `glob`/`grep` truncation semantics when `limits.max_results` is hit.
- Docs: clarify atomic write durability semantics.
- Docs: clarify `SandboxPolicy::validate` is structural (no filesystem IO).
- Docs: clarify `glob`/`grep` traversal does not read `.gitignore`.
- Docs: clarify `grep` match text may be empty when `limits.max_line_bytes` is smaller than a UTF-8 character.
- Docs: clarify `edit`/`patch` operate on existing files (do not create new files).
- CLI: success JSON output is now compact by default; use `--pretty` for pretty-printed output.
- Internal: share traversal loop between `glob` and `grep` to reduce drift.
- Internal: deduplicate glob builder configuration across tool and deny/skip patterns to avoid semantic drift.
- Docs: align the `Dev` commands with the `pre-commit` hook gates (`--workspace`, `--no-default-features`).
- Internal: make `Context::canonical_path_in_root` easier to audit without changing behavior.
- Docs: clarify `delete` semantics for directories vs special files.
- Docs: clarify Windows hardening scope for `path` inputs (best-effort; prefer root-relative paths for untrusted inputs).
- Docs: note `SandboxPolicy::resolve_path` rejects drive-relative Windows paths (e.g. `C:foo`).
- Internal: split `ops` implementation into smaller modules for readability.
- Tests: split the large `basic` integration test into smaller per-area test files.
- Internal: make the `delete` directory error message more precise.
- Internal: share lexical root/requested path resolution between `delete` and `canonical_path_in_root`.
- Docs: clarify how `secrets.deny_globs` applies to `delete` (parent canonicalization vs unlink target).

### Fixed

- `read_bytes_limited` now validates file metadata before opening (avoids blocking on FIFOs/special files and hardens special-file rejection).
- Traversal deny/skip filtering now derives relative paths case-insensitively on Windows.
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
- Traversal now fails closed if a root-relative path cannot be derived (avoids falling back to absolute paths).
- `glob`/`grep` now treat missing derived traversal roots as empty results, but surface permission/IO errors for existing but unreadable roots.
- `requested_path` derivation for absolute inputs no longer depends on canonicalizing missing/unreadable parents; it uses lexical normalization and root-relative stripping when possible.
- Paths that are lexically outside the selected root are now rejected before filesystem canonicalization, reducing filesystem probing side-channels for missing/outside paths.
- `requested_path` no longer serializes as an empty string for `.` inputs.
- `canonical_path_in_root` no longer returns an empty `path` for the root itself; it uses `.` for consistency in errors/responses.
- `grep` line truncation now respects UTF-8 character boundaries (avoids replacement characters).
- CLI: redacted JSON error formatting no longer re-loads the policy file; it reuses the already-loaded policy roots for consistent path redaction.
- CLI: redacted JSON error details now include safe `message` strings for `invalid_path`/`invalid_policy`.
- CLI: on Windows, `--redact-paths` now strips root prefixes case-insensitively for more consistent relative paths.
- On Windows, canonical root-boundary checks now compare paths case-insensitively to avoid false `outside_root` errors.
- CLI: `--max-patch-bytes` now rejects `0` (must be > 0).
- Atomic write temp file names are now randomized to reduce pre-creation attacks in untrusted workspaces.
- Internal: add a regression test locking traversal skip-glob directory probe semantics.
- `read` line-range mode now reports `file_too_large.size_bytes` using file metadata when available (instead of scanned bytes).
- Glob patterns now normalize leading `./` for `glob`/`grep` and policy glob rules (`secrets.deny_globs`, `traversal.skip_globs`).
- On Windows, `SandboxPolicy::resolve_path` now rejects paths containing `:` in a normal component (blocks NTFS alternate data stream access like `file.txt:stream`).
- Glob patterns starting with `/` or containing `..` are now rejected early as invalid inputs (instead of being accepted but never matching).
- On Windows, `walkdir` root errors now compute relative paths case-insensitively for more consistent diagnostics.
- `glob`/`grep` no longer fail when `paths.allow_absolute=false` and encountering symlinked files during traversal.
- `read`/`edit`/`patch` now reject non-regular files (FIFOs, sockets, device nodes) to prevent blocking/DoS.
- `policy-io` now rejects non-regular policy files (FIFOs, sockets, device nodes) to prevent blocking/DoS.
- CLI: patch input files now reject non-regular files (FIFOs, sockets, device nodes) to prevent blocking/DoS.
