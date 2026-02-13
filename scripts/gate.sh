#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_candidate="$(cd "$script_dir/.." && pwd -P)"
repo_root="$(git -C "$repo_candidate" rev-parse --show-toplevel 2>/dev/null || echo "$repo_candidate")"
core_crate="${SAFE_FS_CORE_CRATE:-safe-fs-tools}"

if [[ ! -f "$repo_root/Cargo.toml" ]]; then
  if [[ "${CI:-}" == "true" || "${CI:-}" == "1" ]]; then
    echo "gate: no Cargo.toml found under CI; failing." >&2
    exit 1
  fi
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
  cargo check -p "$core_crate" --all-targets --no-default-features
  cargo clippy --workspace --all-targets -- -D warnings
  cargo clippy -p "$core_crate" --all-targets --no-default-features -- -D warnings
  cargo test --workspace
  cargo test -p "$core_crate" --no-default-features
)
