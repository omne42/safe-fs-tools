# Policy Reference

`SandboxPolicy` is the source of truth for operation authorization and budgets.

## Full Schema

```toml
[[roots]]
id = "workspace"
path = "/abs/path"
mode = "read_only" # or "read_write"

[permissions]
read = true
glob = true
grep = true
list_dir = true
stat = true
edit = false
patch = false
delete = false
mkdir = false
write = false
move = false
copy_file = false

[paths]
allow_absolute = false

[limits]
max_read_bytes = 1048576
# max_patch_bytes = 1048576
max_write_bytes = 1048576
max_results = 2000
max_walk_entries = 500000
max_walk_files = 200000
# max_walk_ms = 1000
max_line_bytes = 4096

[secrets]
deny_globs = [".git/**", "**/.git/**"]
redact_regexes = []
replacement = "***REDACTED***"

[traversal]
skip_globs = ["node_modules/**", "target/**"]
```

## `roots`

- `id`: unique, `[A-Za-z0-9._-]`, max length 64, no surrounding whitespace.
- `path`: absolute path (structural validation); existence and directory checks happen in `Context::new`.
- `mode`:
  - `read_only`
  - `read_write`

## `permissions`

Boolean flags controlling operation entrypoints:

- `read`, `glob`, `grep`, `list_dir`, `stat`, `edit`, `patch`, `delete`, `mkdir`, `write`, `move`, `copy_file`.

Note: TOML key is `move`, mapped to Rust `move_path`.

## `paths`

- `allow_absolute` (default `false`):
  - `false`: request paths must be root-relative.
  - `true`: absolute paths accepted, but must still resolve inside selected root.

## `limits`

Defaults:

- `max_read_bytes = 1_048_576`
- `max_patch_bytes = None` (uses `max_read_bytes`)
- `max_write_bytes = 1_048_576`
- `max_results = 2_000`
- `max_walk_entries = 500_000`
- `max_walk_files = 200_000`
- `max_walk_ms = None`
- `max_line_bytes = 4_096`

Constraints:

- Most limits must be `> 0`.
- `max_walk_files <= max_walk_entries`.
- Hard caps are enforced by validation to prevent pathological policy values.

## `secrets`

- `deny_globs`: root-relative glob patterns denied by path checks.
- `redact_regexes`: regex list applied to returned text.
- `replacement`: replacement string for redaction.

Defaults include `.git` and `.env` deny patterns.

## `traversal`

- `skip_globs`: traversal performance filter for `glob`/`grep` only.
- Does not deny direct file operations.

## Validation Stages

1. `SandboxPolicy::validate()`:
   - structural validation only,
   - no filesystem I/O.

2. `Context::new(policy)`:
   - filesystem checks (root exists, directory, canonicalization),
   - matcher compilation (deny/skip/redaction patterns).

## Recommended Profiles

### Local dev (balanced)

- `allow_absolute = false`
- moderate defaults
- explicit deny globs

### Untrusted integration (strict)

- small `max_*` limits
- `allow_absolute = false`
- `--error-format json --redact-paths-strict` in CLI wrappers
- run inside OS sandbox/container

## See Also

- [`../policy.example.toml`](../policy.example.toml)
- [`security-guide.md`](security-guide.md)
- [`../SECURITY.md`](../SECURITY.md)
