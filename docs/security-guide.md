# Security Guide

This guide provides practical security usage guidance. Normative threat model details are in `SECURITY.md`.

## Security Posture Summary

`safe-fs-tools` is a policy enforcement layer inside your process.

It is **not**:

- an OS sandbox,
- a complete TOCTOU-hard filesystem confinement model.

## Recommended Deployment Modes

### Trusted local automation

- Moderate limits.
- `allow_absolute = false` preferred.
- Minimal required permissions.

### Semi-trusted integration (agent/server wrappers)

- Tight `limits` values.
- Strict deny globs.
- JSON errors + strict redaction.
- OS sandbox/container strongly recommended.

Example CLI wrapper flags:

```bash
--error-format json --redact-paths-strict
```

## Policy Hardening Checklist

- Use root-relative paths only (`allow_absolute = false`).
- Use dedicated roots per workspace.
- Keep `read_only` mode unless mutation is truly required.
- Start from least privilege in `permissions`.
- Set conservative `max_*` limits for untrusted workloads.
- Add deny globs for secrets and SCM metadata.

## Input and Output Hardening

- Treat `--policy` and patch/content file arguments as trusted-wrapper inputs.
- Reject or sanitize untrusted path inputs before calling CLI.
- Avoid exposing raw stderr without redaction in multi-tenant environments.

## Side-Channel Considerations

Even with path checks, error/timing behavior may still leak information in adversarial scenarios.

Mitigation:

- run inside OS/container sandbox,
- reduce error detail exposure,
- constrain roots to minimal scope.

## Platform Notes

- Windows path behavior has dedicated validation (drive-relative and ADS checks).
- Unsupported platform paths fail closed in several identity-sensitive flows.

## Vulnerability Reporting

Use private advisory channel:

- `https://github.com/omne42/safe-fs-tools/security/advisories/new`

Include:

- minimal reproduction,
- expected vs actual behavior,
- OS and Rust version.
