# CLI Reference

Binary: `safe-fs-tools`

## Global Options

- `--policy <PATH>`: policy file (`.toml` / `.json`).
- `--pretty`: pretty-print JSON output.
- `--error-format <text|json>`: error output format.
- `--redact-paths`: best-effort path redaction in JSON errors.
- `--redact-paths-strict`: stricter redaction (implies `--redact-paths`).
- `--max-patch-bytes <N>`: cap patch input bytes (stdin/file), additionally bounded by policy limits.

## Common Notes

- Success output is JSON on stdout.
- Errors go to stderr, exit code is non-zero.
- Use `--error-format json` for machine integrations.

## Commands

### `read`

```bash
safe-fs-tools --policy policy.toml read --root <root_id> <path> [--start-line N --end-line N]
```

### `list-dir`

```bash
safe-fs-tools --policy policy.toml list-dir --root <root_id> [--max-entries N] [path]
```

- Default `path` is `.`.

### `glob`

```bash
safe-fs-tools --policy policy.toml glob --root <root_id> "<pattern>"
```

### `grep`

```bash
safe-fs-tools --policy policy.toml grep --root <root_id> "<query>" [--regex] [--glob "<pattern>"]
```

### `stat`

```bash
safe-fs-tools --policy policy.toml stat --root <root_id> <path>
```

### `edit`

```bash
safe-fs-tools --policy policy.toml edit --root <root_id> <path> --start-line N --end-line N "<replacement>"
```

### `patch`

```bash
safe-fs-tools --policy policy.toml patch --root <root_id> <path> <patch_file>
```

- Use `-` as `<patch_file>` to read from stdin.

### `mkdir`

```bash
safe-fs-tools --policy policy.toml mkdir --root <root_id> <path> [--create-parents] [--ignore-existing]
```

### `write`

```bash
safe-fs-tools --policy policy.toml write --root <root_id> <path> <content_file> [--overwrite] [--create-parents]
```

- Use `-` as `<content_file>` to read from stdin.

### `delete`

```bash
safe-fs-tools --policy policy.toml delete --root <root_id> <path> [--recursive] [--ignore-missing]
```

### `move`

```bash
safe-fs-tools --policy policy.toml move --root <root_id> <from> <to> [--overwrite] [--create-parents]
```

### `copy-file`

```bash
safe-fs-tools --policy policy.toml copy-file --root <root_id> <from> <to> [--overwrite] [--create-parents]
```

## Integration Patterns

### Safer machine-mode wrapper

```bash
safe-fs-tools \
  --policy ./policy.toml \
  --error-format json \
  --redact-paths-strict \
  read --root workspace src/lib.rs
```

### Patch from stdin

```bash
cat change.diff | safe-fs-tools --policy ./policy.toml patch --root workspace src/lib.rs -
```

## Related

- [`operations-reference.md`](operations-reference.md)
- [`policy-reference.md`](policy-reference.md)
- [`faq.md`](faq.md)
