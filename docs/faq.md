# FAQ

## Is this a sandbox?

No. `safe-fs-tools` is policy enforcement inside your process, not OS-level isolation.

## Why are absolute paths sometimes rejected?

If `paths.allow_absolute=false`, absolute request paths are invalid by policy.

## Why does `read` fail instead of truncating?

`read` is fail-closed on byte limits (`max_read_bytes`) to avoid partial-content ambiguity.

## Why does `grep` skip files?

`grep` intentionally skips non-UTF8, too-large, or unreadable files and reports skip counters.

## Why does `glob`/`grep` not follow directory symlinks?

To reduce traversal ambiguity and containment risk. Symlinked files may still be handled under root checks.

## Why do I get `not_permitted` on write/edit/delete?

Either:

- permission flag is disabled, or
- root mode is `read_only`.

## What is the difference between `deny_globs` and `skip_globs`?

- `secrets.deny_globs`: security deny rule (blocks access).
- `traversal.skip_globs`: performance optimization for traversal only.

## Why do I see both `requested_path` and `path` in responses?

`requested_path` is normalized user input; `path` is effective root-relative resolved path.

## Can I disable `glob`, `grep`, or `patch` features?

Yes. API remains stable, and disabled operations return deterministic `Error::NotPermitted`.

## How should I classify errors in integrations?

Use `Error::code()` / JSON `error.code` instead of matching message text.

## Is Windows handled differently?

Yes, path validation includes Windows-specific checks (e.g., drive-relative and ADS-related protections).

## Where should I report security issues?

Use private advisory channel:

- `https://github.com/omne42/safe-fs-tools/security/advisories/new`
