# Example Survey (Filesystem Tool Semantics)

This document is a quick, non-normative survey of the `example/` repositories in this workspace,
focused on filesystem tool semantics and boundaries (roots, traversal, symlinks, limits, and error handling).

It exists to justify and keep `safe-fs-tools`' boundaries explicit and minimal.

## opencode

- `example/opencode/SECURITY.md`: explicitly states the permission system is **not** an OS sandbox ("No Sandbox").

## codex

- `example/codex/codex-rs/file-search/src/lib.rs`: uses `ignore::WalkBuilder` and can be configured to follow symlinks (`follow_links(true)`), with optional gitignore-respecting behavior.

## CodexMonitor

- `example/CodexMonitor/src-tauri/src/workspaces.rs`: workspace file listing uses `ignore::WalkBuilder` and explicitly avoids crawling symlink targets (`follow_links(false)`), with directory skip lists and sorted results.

## agent-gui (1code)

- `example/agent-gui/1code/src/main/lib/git/security/path-validation.ts`: explicit path traversal rejection + structured error codes.
- `example/agent-gui/1code/src/main/lib/git/security/secure-fs.ts`: symlink-aware delete semantics (delete link itself; prevent symlink escape for destructive actions).

## OpenSpec

- `example/OpenSpec/src/commands/artifact-workflow.ts`: validates inputs to prevent path traversal (e.g. change name).
- `example/OpenSpec/src/core/artifact-graph/state.ts`: treats glob patterns as first-class, normalizes paths for cross-platform glob compatibility.

## oh-my-opencode-slim

- `example/oh-my-opencode-slim/src/tools/grep/tools.ts`: grep/search is delegated to `rg`, with explicit timeout/output limit in the tool wrapper.

## ai

- `example/ai/packages/openai/src/tool/apply-patch.ts`: models an `apply_patch` tool schema (operation-based file edits) and streaming deltas; semantics differ from unified-diff patching.

## claude-code

- `example/claude-code/CHANGELOG.md`: tool permission/config evolution; mentions path validation and glob/grep tool improvements (implementation details are not in this workspace subtree).

## claude-code-router

- `example/claude-code-router/packages/shared/src/preset/install.ts`: validates preset names and extracted paths to prevent path traversal (archive extraction hardening).

## litellm

- Primarily application code; contains documentation and unrelated uses of the term "apply_patch". No single reusable filesystem-tool boundary implementation found in this workspace subtree.

## awesome-claude

- No filesystem-tool implementation in this workspace subtree.

## 必读重要意见.md

- `example/必读重要意见.md`: project-level notes (CLI-first, no TUI for early stage; prefer Rust 2024 edition and up-to-date deps). Not a filesystem semantics reference, but useful for aligning packaging choices.

## Notes for safe-fs-tools (tradeoffs)

- **Symlink traversal**: `safe-fs-tools` chooses `follow_links(false)` (CodexMonitor-style) for `glob`/`grep` to avoid crawling symlinked directories, which simplifies root-boundary reasoning. `codex` file-search can enable `follow_links(true)` for UX/search completeness, but that comes with more complex boundary expectations.
- **Search implementation**: projects like `oh-my-opencode-slim` delegate content search to `rg` and enforce time/output limits in the wrapper. `safe-fs-tools` keeps a library-first, dependency-light implementation (WalkDir + bounded reads) so redaction/deny-globs/limits apply uniformly across library + CLI without shelling out.
- **Patch semantics**: `ai`’s `apply_patch` tool is operation-based (and streams deltas) rather than unified-diff based. `safe-fs-tools` intentionally sticks to unified-diff patching (`diffy`) to keep filesystem semantics explicit and minimal.

## Conclusions (for safe-fs-tools)

The “iron rules” this project follows:

- **Explicit policy boundary**: every operation is gated by `SandboxPolicy` (roots/permissions/limits/secrets). No implicit “smart” behavior.
- **Root-bounded paths**: paths are resolved against an explicit root and rejected if they escape it (best-effort; not TOCTOU-hardened).
- **No symlink dir traversal**: traversal uses `walkdir` with `follow_links(false)`; symlinked *files* are allowed only if their targets stay within the root.
- **No `.gitignore` semantics**: traversal ignores `.gitignore`; only policy deny/skip rules apply.
- **Budgets over completeness**: traversal ops (`glob`/`grep`) may return deterministic partial results under strict budgets and explain skips via counters.
