#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$repo_root" ]]; then
  echo "setup-githooks: not a git repository; run: git init" >&2
  exit 1
fi

for hook in pre-commit commit-msg; do
  hook_path="$repo_root/githooks/$hook"
  if [[ ! -f "$hook_path" ]]; then
    echo "setup-githooks: missing hook: $hook_path" >&2
    exit 1
  fi
  chmod +x "$hook_path"
done

git -C "$repo_root" config --local core.hooksPath githooks

echo "Configured git hooks: core.hooksPath=githooks" >&2
echo "Hooks enabled: pre-commit, commit-msg" >&2
