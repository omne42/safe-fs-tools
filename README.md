# safe-fs-tools

`safe-fs-tools` is a small Rust library + CLI that provides filesystem tools:
`read`, `glob`, `grep`, `edit`, `patch`, `delete`.

The point is **not** the commands — it is the **explicit safety model**:

- `SandboxPolicy`: what is allowed at all
- `Root`: where filesystem access is anchored
- `SecretRules`: what must never be read, and what must be redacted

Non-goals (by design):

- No Mode/approval system (that belongs to higher-level products, not a fs tool).
- No “smart” implicit behavior. If something is lossy/unsupported, return an error.

## CLI

All commands require a policy file (`.toml` or `.json`) and output JSON.

```bash
safe-fs-tools --policy policy.toml read  --root workspace path/to/file.txt
safe-fs-tools --policy policy.toml glob  --root workspace "**/*.rs"
safe-fs-tools --policy policy.toml grep  --root workspace "TODO" --glob "**/*.rs"
safe-fs-tools --policy policy.toml edit  --root workspace path/to/file.txt --start-line 3 --end-line 4 "replacement\n"
safe-fs-tools --policy policy.toml patch --root workspace path/to/file.txt ./change.diff
# or from stdin:
cat ./change.diff | safe-fs-tools --policy policy.toml patch --root workspace path/to/file.txt -
safe-fs-tools --policy policy.toml delete --root workspace path/to/file.txt
```

## Policy format (TOML)

See `policy.example.toml`.

## Dev

```bash
cargo fmt
cargo test
cargo clippy --all-targets -- -D warnings
```

Enable hooks:

```bash
git config core.hooksPath githooks
```
