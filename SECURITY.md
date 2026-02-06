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
Some operations (notably `edit`/`patch`) build full in-memory strings and may temporarily allocate more than the input file size (even when `limits.max_read_bytes` is relatively small).
`list_dir` may also be expensive for huge directories: it must consider all entries to preserve sorted/truncation semantics (even though memory is bounded by `max_entries`).

### Special files

Text operations (`read`/`edit`/`patch`) intentionally reject non-regular files (e.g. FIFOs, sockets, device nodes) to avoid blocking behavior and related DoS risks.

### Out of scope

- OS sandbox escapes (because this is not an OS sandbox)
- Attacks requiring arbitrary code execution inside the same process
- Malicious behavior by the caller (policy is caller-controlled)
- CLI argument hardening: the CLI assumes the policy path and patch input are provided by a trusted wrapper.
- Windows reparse-point / junction hardening beyond the explicit lexical checks in `SandboxPolicy::resolve_path` and best-effort root-boundary enforcement.

### Path probing side-channels

If untrusted callers can control `path` inputs and observe detailed errors/timing, they may be able to infer information about files outside the configured roots (existence/permissions).

`safe-fs-tools` performs best-effort, lexical root checks before filesystem canonicalization to reduce this, but it is not a complete mitigation. Prefer root-relative inputs and run inside an OS sandbox for untrusted workloads.

## Reporting

If you discover a security issue, please open an issue with:

- A minimal reproduction (commands / policy file / filesystem layout)
- Expected vs actual behavior
- Platform details (OS + Rust version)
