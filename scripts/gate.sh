#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_candidate="$(cd "$script_dir/.." && pwd -P)"
repo_root="$repo_candidate"
if [[ ! -f "$repo_root/Cargo.toml" ]]; then
  repo_root="$(git -C "$repo_candidate" rev-parse --show-toplevel 2>/dev/null || echo "$repo_candidate")"
fi
core_crate="${SAFE_FS_CORE_CRATE:-safe-fs-tools}"
ci_flag="$(printf '%s' "${CI:-}" | tr '[:upper:]' '[:lower:]')"
is_ci=0
if [[ "$ci_flag" == "1" || "$ci_flag" == "true" || "$ci_flag" == "yes" ]]; then
  is_ci=1
fi

if [[ ! -f "$repo_root/Cargo.toml" ]]; then
  if [[ "$is_ci" -eq 1 ]]; then
    echo "gate: no Cargo.toml found under CI; failing." >&2
    exit 1
  fi
  if [[ "${SAFE_FS_GATE_ALLOW_SKIP:-}" == "1" ]]; then
    echo "gate: no Cargo.toml found; skipping (SAFE_FS_GATE_ALLOW_SKIP=1)." >&2
    exit 0
  fi
  echo "gate: no Cargo.toml found; failing. Set SAFE_FS_GATE_ALLOW_SKIP=1 to skip locally." >&2
  exit 1
fi

echo "gate: rust (fmt/check/clippy/test)" >&2
(
  cd "$repo_root"
  cargo fmt --all -- --check
  cargo check --locked --workspace --all-targets
  # Note: `--workspace --no-default-features` is not enough here because workspace members can
  # enable features on each other (feature unification). Check the library crate explicitly.
  cargo check --locked -p "$core_crate" --all-targets --no-default-features
  cargo clippy --locked --workspace --all-targets -- -D warnings
  cargo clippy --locked -p "$core_crate" --all-targets --no-default-features -- -D warnings
  cargo test --locked --workspace
  cargo test --locked -p "$core_crate" --no-default-features
)
