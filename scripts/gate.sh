#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

if [[ ! -f "$repo_root/Cargo.toml" ]]; then
  echo "gate: no Cargo.toml found; skipping." >&2
  exit 0
fi

echo "gate: rust (fmt/check/clippy/test)" >&2
(
  cd "$repo_root"
  cargo fmt --all -- --check
  cargo check --workspace --all-targets
  # Note: `--workspace --no-default-features` is not enough here because workspace members can
  # enable features on each other (feature unification). Check the library crate explicitly.
  cargo check -p safe-fs-tools --all-targets --no-default-features
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
)
