# Getting Started

This guide gets you from zero to a working policy-bounded filesystem tool run.

## Prerequisites

- Rust `1.92.0` (see `rust-toolchain.toml`).
- A local workspace directory you control.

## Install / Build

Build CLI from source:

```bash
cargo build -p safe-fs-tools-cli
```

Run directly without installing:

```bash
cargo run -p safe-fs-tools-cli -- --help
```

## 1. Create a Policy

Start from the template:

```bash
cp policy.example.toml ./policy.toml
```

Edit `policy.toml`:

- Set `[[roots]]` `path` to an absolute directory.
- Choose `mode` (`read_only` or `read_write`).
- Enable only permissions you actually need.

Example minimal read-only policy:

```toml
[[roots]]
id = "workspace"
path = "/abs/path/to/workspace"
mode = "read_only"

[permissions]
read = true

[paths]
allow_absolute = false
```

## 2. Run Basic Commands

Read a file:

```bash
cargo run -p safe-fs-tools-cli -- \
  --policy ./policy.toml \
  read --root workspace README.md
```

List a directory:

```bash
cargo run -p safe-fs-tools-cli -- \
  --policy ./policy.toml \
  list-dir --root workspace .
```

Glob for Rust files:

```bash
cargo run -p safe-fs-tools-cli -- \
  --policy ./policy.toml \
  glob --root workspace "**/*.rs"
```

Grep with optional glob filter:

```bash
cargo run -p safe-fs-tools-cli -- \
  --policy ./policy.toml \
  grep --root workspace "Context" --glob "src/**/*.rs"
```

## 3. JSON Error Output (Recommended for Integrations)

```bash
cargo run -p safe-fs-tools-cli -- \
  --policy ./policy.toml \
  --error-format json \
  --redact-paths \
  read --root workspace missing.txt
```

- `--error-format json`: stable machine-readable errors.
- `--redact-paths`: best-effort path redaction.
- `--redact-paths-strict`: stronger redaction (hides more path detail).

## 4. Use as a Library

Add dependency:

```toml
[dependencies]
safe-fs-tools = { version = "0.2.0" }
```

Minimal usage:

```rust
use safe_fs_tools::{Context, ReadRequest, RootMode, SandboxPolicy};

let mut policy =
    SandboxPolicy::single_root("workspace", "/abs/path/to/workspace", RootMode::ReadOnly);
policy.permissions.read = true;

let ctx = Context::new(policy)?;
let response = ctx.read_file(ReadRequest {
    root_id: "workspace".to_string(),
    path: "README.md".into(),
    start_line: None,
    end_line: None,
})?;

println!("{}", response.content);
# Ok::<(), safe_fs_tools::Error>(())
```

## 5. Next Steps

- Learn the model: [`concepts.md`](concepts.md)
- Full policy schema: [`policy-reference.md`](policy-reference.md)
- All operation contracts: [`operations-reference.md`](operations-reference.md)
- Security guidance: [`security-guide.md`](security-guide.md)
