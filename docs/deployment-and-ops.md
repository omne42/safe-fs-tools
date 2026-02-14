# Deployment and Operations

This page covers CI, release, local gates, and repository hygiene.

## Local Quality Gates

Run full gates before pushing:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo check -p safe-fs-tools --all-targets --no-default-features
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/gate.sh
```

## Git Hooks

Enable repository hooks once:

```bash
git config core.hooksPath githooks
```

Hooks enforce:

- changelog discipline,
- conventional commits,
- strict Rust file line limits,
- gate consistency.

## CI Workflows

### CI (`.github/workflows/ci.yml`)

- Runs on push/PR.
- Matrix: `ubuntu-latest`, `macos-latest`, `windows-latest`.
- Runs `./scripts/gate.sh`.

### Docs (`.github/workflows/docs.yml`)

- Builds rustdoc with `-D warnings`.
- Publishes GitHub Pages for public repos.

### Release (`.github/workflows/release.yml`)

Triggered by tags matching `v*`.

Pipeline:

1. Build release binaries (Linux/macOS/Windows).
2. Generate checksum artifacts.
3. Re-run workspace tests.
4. Verify tag version matches both crates.
5. Publish GitHub Release assets.

## Release Procedure

1. Ensure clean `main`.
2. Update crate versions (`Cargo.toml`, `cli/Cargo.toml`).
3. Move `CHANGELOG` items from `[Unreleased]` to the new version section.
4. Run all gates.
5. Commit release change.
6. Create annotated tag, e.g. `v0.2.1`.
7. Push commit and tag.

Example:

```bash
git tag -a v0.2.1 -m "v0.2.1"
git push origin main
git push origin v0.2.1
```

## Changelog Policy

- Use Keep a Changelog format.
- Keep released sections immutable by default.
- For intentional release-section edits, use repository-approved override only in release context.

## Operational Recommendations

- Pin Rust toolchain from `rust-toolchain.toml` in CI and local dev.
- Keep dependency updates batched with full gate runs.
- For integrations, consume JSON errors and classify via stable error codes.
