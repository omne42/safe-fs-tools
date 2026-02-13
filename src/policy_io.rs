use std::io::Read;
use std::path::Path;

use crate::{Error, Result, SandboxPolicy};

const DEFAULT_MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFormat {
    Toml,
    Json,
}

#[cfg(unix)]
fn is_symlink_open_error(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_open_error(_err: &std::io::Error) -> bool {
    false
}

#[cfg(unix)]
fn open_policy_file(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options.open(path).map_err(|err| {
        if is_symlink_open_error(&err) {
            return Error::InvalidPath(format!(
                "path {} is a symlink; refusing to load policy from symlink paths",
                path.display()
            ));
        }
        Error::io_path("open", path, err)
    })
}

#[cfg(windows)]
fn open_policy_file(path: &Path) -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|err| Error::io_path("open", path, err))?;
    let meta = file
        .metadata()
        .map_err(|err| Error::io_path("metadata", path, err))?;
    if meta.file_type().is_symlink() {
        return Err(Error::InvalidPath(format!(
            "path {} is a symlink; refusing to load policy from symlink paths",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_policy_file(path: &Path) -> Result<std::fs::File> {
    let _ = path;
    Err(Error::InvalidPath(
        "loading policy files on this platform requires an atomic no-follow open primitive"
            .to_string(),
    ))
}

pub fn parse_policy(raw: &str, format: PolicyFormat) -> Result<SandboxPolicy> {
    let policy = parse_policy_unvalidated(raw, format)?;
    policy.validate()?;
    Ok(policy)
}

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
    if max_bytes > usize::MAX as u64 {
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
