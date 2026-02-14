use std::io::Read;
use std::path::Path;

use crate::{Error, Result, SandboxPolicy};

const DEFAULT_MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;
const HARD_MAX_POLICY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFormat {
    Toml,
    Json,
}

fn open_policy_file(path: &Path) -> Result<std::fs::File> {
    let file = crate::platform_open::open_readonly_nofollow(path).map_err(|err| {
        if crate::platform_open::is_symlink_open_error(&err) {
            return Error::InvalidPath(format!(
                "path {} final component is a symlink; refusing to load policy via symlink final component",
                path.display()
            ));
        }
        if err.kind() == std::io::ErrorKind::Unsupported {
            return Error::InvalidPath(
                "loading policy files on this platform requires an atomic no-follow open primitive"
                    .to_string(),
            );
        }
        Error::io_path("open", path, err)
    })?;
    #[cfg(windows)]
    {
        let meta = file
            .metadata()
            .map_err(|err| Error::io_path("metadata", path, err))?;
        if meta.file_type().is_symlink() {
            return Err(Error::InvalidPath(format!(
                "path {} final component is a symlink; refusing to load policy via symlink final component",
                path.display()
            )));
        }
    }
    Ok(file)
}

pub fn parse_policy(raw: &str, format: PolicyFormat) -> Result<SandboxPolicy> {
    let policy = parse_policy_unvalidated(raw, format)?;
    policy.validate()?;
    Ok(policy)
}

/// Parse a policy without enforcing [`SandboxPolicy::validate`] invariants.
///
/// The returned value may violate policy safety constraints. Prefer [`parse_policy`]
/// unless you explicitly need a partially validated intermediate value.
pub fn parse_policy_unvalidated(raw: &str, format: PolicyFormat) -> Result<SandboxPolicy> {
    match format {
        PolicyFormat::Json => serde_json::from_str(raw)
            .map_err(|err| Error::InvalidPolicy(format!("invalid json policy: {err}"))),
        PolicyFormat::Toml => toml::from_str(raw)
            .map_err(|err| Error::InvalidPolicy(format!("invalid toml policy: {err}"))),
    }
}

pub fn load_policy(path: impl AsRef<Path>) -> Result<SandboxPolicy> {
    load_policy_limited(path, DEFAULT_MAX_POLICY_BYTES)
}

fn detect_policy_format(path: &Path) -> Result<PolicyFormat> {
    match path.extension() {
        None => Ok(PolicyFormat::Toml),
        Some(ext) => match ext.to_str() {
            Some(ext) if ext.eq_ignore_ascii_case("json") => Ok(PolicyFormat::Json),
            Some(ext) if ext.eq_ignore_ascii_case("toml") => Ok(PolicyFormat::Toml),
            Some(other) => Err(Error::InvalidPolicy(format!(
                "unsupported policy format {other:?}; expected .toml or .json"
            ))),
            None => Err(Error::InvalidPolicy(
                "unsupported policy format with non-UTF-8 extension; expected .toml or .json"
                    .to_string(),
            )),
        },
    }
}

/// Load and validate a policy file from disk with a byte limit.
///
/// Format detection is by file extension:
/// - `.json` => JSON
/// - `.toml` or no extension => TOML
///
/// This rejects symlink targets for the final path component and non-regular files
/// (FIFOs, sockets, device nodes) to avoid blocking behavior and related DoS risks.
pub fn load_policy_limited(path: impl AsRef<Path>, max_bytes: u64) -> Result<SandboxPolicy> {
    if max_bytes == 0 {
        return Err(Error::InvalidPolicy(
            "max policy bytes must be > 0".to_string(),
        ));
    }
    if max_bytes > HARD_MAX_POLICY_BYTES {
        return Err(Error::InvalidPolicy(format!(
            "max policy bytes exceeds hard limit ({HARD_MAX_POLICY_BYTES} bytes)"
        )));
    }
    if max_bytes >= usize::MAX as u64 {
        return Err(Error::InvalidPolicy(
            "max policy bytes exceeds platform limits".to_string(),
        ));
    }

    let path = path.as_ref();
    let format = detect_policy_format(path)?;
    let file = open_policy_file(path)?;
    let meta = file
        .metadata()
        .map_err(|err| Error::io_path("metadata", path, err))?;
    if !meta.is_file() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a regular file",
            path.display()
        )));
    }
    let meta_len = meta.len();
    if meta_len > max_bytes {
        return Err(Error::InputTooLarge {
            size_bytes: meta_len,
            max_bytes,
        });
    }

    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|err| Error::io_path("read", path, err))?;

    let read_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if read_size > max_bytes {
        return Err(Error::InputTooLarge {
            size_bytes: read_size,
            max_bytes,
        });
    }

    let raw = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidUtf8(path.to_path_buf()))?;
    parse_policy(raw, format)
}
