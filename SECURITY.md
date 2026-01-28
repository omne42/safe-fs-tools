# Security

## Threat Model

`safe-fs-tools` is a library + CLI for performing filesystem operations with an explicit, caller-provided policy (`SandboxPolicy`).

### Not an OS sandbox

This project does **not** provide OS-level security isolation. It enforces policy checks in-process.

If you need strong isolation, run your process inside an OS sandbox / container / VM (e.g. Linux Landlock, macOS sandbox, containers).

### Concurrency / TOCTOU

Root-boundary checks are best-effort and are **not** hardened against a concurrent filesystem adversary (TOCTOU). If you need race-resistant confinement, use capability-based filesystem APIs and/or OS sandboxing.

### Resource limits

Policy limits (e.g. `limits.max_read_bytes`, `limits.max_results`, `limits.max_walk_entries`, `limits.max_walk_files`) are enforced to bound work, but they are **not** a substitute for OS-level resource controls. Pathological inputs (e.g. extremely long lines or huge directory trees) can still cause high CPU/memory usage.

### Out of scope

- OS sandbox escapes (because this is not an OS sandbox)
- Attacks requiring arbitrary code execution inside the same process
- Malicious behavior by the caller (policy is caller-controlled)

## Reporting

If you discover a security issue, please open an issue with:

- A minimal reproduction (commands / policy file / filesystem layout)
- Expected vs actual behavior
- Platform details (OS + Rust version)
