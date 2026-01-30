# safe-fs-tools

`safe-fs-tools` is a small Rust library + CLI that provides filesystem tools:
`read`, `glob`, `grep`, `edit`, `patch`, `delete`.

The point is **not** the commands — it is the **explicit safety model**:

- `SandboxPolicy`: what is allowed at all
- `Root`: where filesystem access is anchored
- `SecretRules`: what must never be read, and what must be redacted

Important boundaries:

- This is **not** an OS sandbox. It enforces a policy at the tool layer; use OS-level sandboxing (containers, macOS sandbox, Linux Landlock, etc.) if you need strong isolation.
- Root checks are best-effort and **not** hardened against concurrent filesystem adversaries (TOCTOU).
- Text ops (`read`/`edit`/`patch`) are **UTF-8 only**. `grep` skips non-UTF8 / too-large / unreadable files and reports skip counts in its JSON output.
- See `SECURITY.md` for the threat model.

## Semantics

- Roots are configured explicitly in `SandboxPolicy.roots` and canonicalized in `ops::Context::new`.
- `root.path` must be an absolute path to an existing directory (absolute-path validation happens in `SandboxPolicy::validate`; existence/directory checks happen in `Context::new`).
- Relative paths are resolved by `root.path.join(path)`; absolute paths are accepted but must still end up inside the selected root (paths that are lexically outside the root are rejected before filesystem canonicalization).
- Directory traversal (`glob`/`grep`) uses `walkdir` with `follow_links(false)` and is best-effort: unreadable entries are skipped.
- Directory traversal does **not** read or respect `.gitignore` (only policy deny/skip rules).
- Symlinked **files** are treated as files, but their resolved targets must stay within the selected root; symlinked **directories** are not traversed.
- `glob` results are sorted by path; `grep` results are sorted by `(path, line)`.
- On Windows, glob matching (for `glob` patterns, `grep --glob`, `traversal.skip_globs`, and `secrets.deny_globs`) is explicitly case-insensitive.
- `limits.max_results` caps how many matches `glob`/`grep` will return. When hit, the operation stops scanning early and returns `truncated=true`, `scan_limit_reached=true`, `scan_limit_reason=results`. Matches are still returned in the sorted output order described above, but the set itself is only a deterministic *partial* result (based on traversal order), and is **not** guaranteed to equal “the first N” matches of the full (sorted) result set.
- `limits.max_walk_entries` caps how many directory entries `glob`/`grep` will traverse (responses include `scanned_entries`).
- `limits.max_walk_files` caps how many file entries `glob`/`grep` will consider (responses include `scanned_files`).
- `scanned_files` is a best-effort diagnostic counter and may include files later skipped by deny/skip rules, glob filters, or IO errors.
- `limits.max_walk_ms` optionally caps wall-clock traversal time for `glob`/`grep` (responses include `elapsed_ms`).
- When a cap is hit, responses set `scan_limit_reached=true` and `scan_limit_reason` (`entries`/`files`/`time`/`results`).
- `limits.max_read_bytes` is a hard cap (no implicit truncation). `read`/`edit`/`patch` fail if the operation would exceed the cap; `grep` skips files above the cap.
- `limits.max_patch_bytes` optionally caps unified-diff patch *input* size (defaults to `limits.max_read_bytes` if unset).
- For `read` with `start_line/end_line`, the byte cap applies to scanned bytes up to `end_line` (not just returned bytes).
- `read`/`edit`/`patch`/`delete` responses include `requested_path` (normalized input path) and `path` (canonicalized resolved path); for symlinked files these can differ. For absolute inputs, `requested_path` is best-effort and may be returned as root-relative when possible.
- `edit`/`patch` writes are atomic (temp file + fsync + replace/rename), but durability is best-effort: parent directories are not fsynced.
- `delete` removes the path itself (does not follow symlinks); it validates the parent directory is within the selected root.
- `secrets.deny_globs` hides paths from `glob`/`grep` and denies direct access (`read`/`edit`/`patch`/`delete`). Deny checks apply to both the requested path (after `.`/`..` normalization) and the canonicalized resolved path.
- `traversal.skip_globs` skips paths during traversal (`glob`/`grep`) for performance, but does **not** deny direct access.
- `secrets.redact_regexes` are applied to returned text (`read` file content and `grep` matched lines).
- `grep` truncates individual matched lines to `limits.max_line_bytes` and marks matches with `line_truncated=true` (the returned `text` may be empty if the cap is smaller than the first UTF-8 character).
- `glob`/`grep` report skip counts (`skipped_walk_errors`, `skipped_io_errors`, `skipped_dangling_symlink_targets`) to make partial results explainable.
- Errors are classified via a stable `Error::code()` string (useful for JSON error mapping).
- `Error` is `#[non_exhaustive]`; match it with a wildcard arm and/or prefer `Error::code()` for classification.

Non-goals (by design):

- No Mode/approval system (that belongs to higher-level products, not a fs tool).
- No “smart” implicit behavior. If something is lossy/unsupported, return an error.

## CLI

All commands require a policy file (`.toml` or `.json`) and output JSON on success (errors are printed to stderr and exit with code 1). Use `--pretty` for pretty-printed JSON, and `--error-format json` for machine-parsable errors.

For `patch`, you can also cap the patch *input* size (stdin or file) via `--max-patch-bytes` (defaults to `policy.limits.max_patch_bytes` if set, otherwise `policy.limits.max_read_bytes`).

Security note: the CLI is **not** a hard sandbox boundary. The `--policy` path and `patch` input file path are outside the policy model and must be provided by a trusted wrapper.

If you expose tool stderr to untrusted users, use `--error-format json --redact-paths` to avoid leaking absolute paths in error output (best-effort). Paths outside configured roots may still reveal sensitive file names; use `--redact-paths-strict` for stricter redaction.

```bash
safe-fs-tools --policy policy.toml read  --root workspace path/to/file.txt
safe-fs-tools --policy policy.toml read  --root workspace path/to/file.txt --start-line 10 --end-line 20
safe-fs-tools --policy policy.toml glob  --root workspace "**/*.rs"
safe-fs-tools --policy policy.toml grep  --root workspace "TODO" --glob "**/*.rs"
safe-fs-tools --policy policy.toml edit  --root workspace path/to/file.txt --start-line 3 --end-line 4 "replacement\n"
safe-fs-tools --policy policy.toml patch --root workspace path/to/file.txt ./change.diff
# or from stdin:
cat ./change.diff | safe-fs-tools --policy policy.toml patch --root workspace path/to/file.txt -
safe-fs-tools --policy policy.toml delete --root workspace path/to/file.txt
```

## Library

```rust
use safe_fs_tools::{Context, ReadRequest, RootMode, SandboxPolicy};

let mut policy =
    SandboxPolicy::single_root("workspace", "/abs/path/to/workspace", RootMode::ReadOnly);
policy.permissions.read = true;

let ctx = Context::new(policy)?;
let resp = ctx.read_file(ReadRequest {
    root_id: "workspace".to_string(),
    path: "README.md".into(),
    start_line: Some(1),
    end_line: Some(20),
})?;
println!("{}", resp.content);
# Ok::<(), safe_fs_tools::Error>(())
```

## Policy format (TOML)

See `policy.example.toml`.

## Optional: policy-io

If you want the library to load `.toml` / `.json` policies directly, enable the `policy-io` feature:

```toml
safe-fs-tools = { version = "*", features = ["policy-io"] }
```

Then use:

```rust
let policy = safe_fs_tools::policy_io::load_policy("./policy.toml")?;
```

`load_policy` enforces a maximum policy file size (4 MiB). Use `load_policy_limited(path, max_bytes)` for custom limits.

Or, if you just want a ready-to-use context:

```rust
let ctx = safe_fs_tools::Context::from_policy_path("./policy.toml")?;
```

## Cargo features

- Default features: `glob`, `grep`, `patch`
- `glob`: enables `glob_paths` traversal (adds `walkdir`)
- `grep`: enables `grep` traversal (adds `walkdir`)
- `patch`: enables unified-diff patching (adds `diffy`)
- `policy-io`: enables `policy_io::load_policy` (adds `toml` + `serde_json`)
- If `glob`/`grep`/`patch` are disabled, the corresponding functions still exist but return `Error::NotPermitted` (this keeps a stable API while allowing smaller dependency graphs).

## Dev

```bash
cargo fmt
cargo test
cargo clippy --all-targets -- -D warnings
```

See `docs/example-survey.md` for notes on how similar projects model filesystem tool boundaries.
See `docs/db-vfs.md` for the DB-backed VFS (DB-VFS) decision + TODOs.

Build/run the CLI from source:

```bash
cargo run -p safe-fs-tools-cli -- --policy policy.example.toml --help
```

Enable hooks:

```bash
git config core.hooksPath githooks
```
