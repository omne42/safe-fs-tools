# Decision: DB-backed Virtual FS (DB-VFS)

Status: Proposed  
Date: 2026-01-29

## Context

`safe-fs-tools` is designed to enforce an explicit safety model (policy/roots/secrets/limits) while
executing filesystem tools against the **local OS filesystem**.

In server / high-concurrency workloads (docs processing, crawlers, many agents), “local disk as the
shared workspace” is operationally awkward:

- Ephemeral storage and deployment churn make persistence hard.
- Large directory walks are expensive and contend with other workloads.
- TOCTOU issues and cross-process coordination (locks) are harder to reason about.

Key observation from the target workload:

- Concurrency mostly comes from **many users**, not a single user doing huge parallel edits.
- Per-user file counts are usually small, files are small (often **< ~1000 lines**), and operations
  tend to be concentrated under a few directory prefixes (not whole-workspace “search everything”).

This makes a DB-backed “virtual filesystem” feasible if we keep search **scoped** (workspace +
directory prefix) and enforce strict budgets (files/bytes/time).

## Goal

Provide a DB-backed Virtual FS (DB-VFS) that supports tool semantics equivalent to:

- `read` (line ranges + byte caps)
- `glob` (path listing)
- `grep` / rg-like search (regex/substr, returning line numbers + lines)
- `overwrite write` (create/replace)
- `patch` (diff write / unified diff)
- `delete`

This is targeted at docs/crawler workflows (not full “build an entire repo” coding workflows).

## Decision

1. Keep `safe-fs-tools` focused on local filesystem operations and a small dependency graph.
2. Implement DB-VFS as a **separate** project (crate and/or service), reusing semantics and error
   codes where possible.
3. Database support strategy:
   - **P0**: PostgreSQL (production)
   - **P0**: SQLite (dev/test, single-node deployments)
   - **P2**: MySQL (only if infrastructure requires it)

## Rationale

- Adding DB drivers/ORMs would significantly bloat `safe-fs-tools` (compile time, binary size,
  system deps) and often forces async IO into otherwise sync-friendly code paths.
- A DB-backed backend benefits from independent evolution (schema migrations, pooling, quotas,
  indexes) without destabilizing local-fs semantics.
- Given directory-local, small-file workloads, a v1 grep can be “DB scope filter + streaming scan”
  without requiring a full search cluster.

## Compatibility targets (semantics)

- Preserve the explicit safety model shape: **Policy + Secrets + Limits** (or an equivalent).
- Preserve stable error codes where possible; add DB-specific ones as needed:
  `conflict`, `quota_exceeded`, `timeout`.
- Preserve ordering guarantees:
  - `glob` sorted by path
  - `grep` sorted by `(path, line)`

## Proposed API (DB-VFS)

Minimal operations (library or service):

- `read(workspace_id, path, {start_line,end_line}, limits)`
- `write(workspace_id, path, content, expected_version?)` (CAS / optimistic concurrency)
- `patch(workspace_id, path, unified_diff, expected_version)` (atomic apply + CAS)
- `delete(workspace_id, path, expected_version?)`
- `glob(workspace_id, glob, path_prefix?, max_results)`
- `grep(workspace_id, pattern, {glob?, path_prefix?}, budgets)` (streaming)

Notes:

- DB-VFS “roots” are modeled as namespaces: `(workspace_id, path_prefix)` rather than OS paths.
- `expected_version` avoids silent lost updates and makes concurrent edits explicit.

## Minimal schema (Postgres-ish)

Single-table MVP:

`files(workspace_id, path, content, size_bytes, version, created_at, updated_at, metadata_json)`

Key indexes:

- Primary: `(workspace_id, path)`
- Optional: `(workspace_id, updated_at)` for incremental crawls
- Optional: prefix acceleration on `path` (implementation-specific)

Versioning/history is optional and can be added later:

- `file_versions(workspace_id, path, version, content, created_at, actor, op_metadata)`

## Grep strategy (v1)

Implement `rg`-like search as two phases:

1. **Scope reduction in DB**: `workspace_id` + required/encouraged `path_prefix` (+ optional glob).
2. **Streaming scan in app**: line-by-line regex/substr matching to produce `(path, line, text)`
   results, with redaction and strict budgets.

Budgets to enforce:

- `max_files`, `max_bytes_per_file`, `max_matches`, `max_ms`

## Future work (TODO)

1. **Extract a reusable “core” layer**:
   - `Policy`, `SecretRules`, `Limits`, request/response structs, stable error codes, redaction.
2. **DB-VFS MVP**:
   - SQLite backend (in-memory tests) for correctness.
   - Postgres backend + schema migration story.
3. **Conflict semantics**:
   - Require `expected_version` for `patch` (likely yes).
   - Decide whether `write/delete` require `expected_version` or allow unconditional writes with
     audit logs.
4. **Streaming and quotas**:
   - Cursor streaming for `grep`.
   - Per-workspace budgets + rate limits.
5. **Search acceleration (optional)**:
   - Postgres `pg_trgm` / FTS to reduce candidate sets before regex scanning.
6. **Integration points**:
   - Allow higher-level products (e.g. `codex_pm`) to switch file tools to DB-VFS in server mode.

## Open questions

- Library-only vs service-first? (service helps multi-language clients + centralized policy)
- Should `grep` require `path_prefix` by default to prevent whole-workspace scans?
- Do we want an append-only mode for crawlers (write new versions, never mutate)?
