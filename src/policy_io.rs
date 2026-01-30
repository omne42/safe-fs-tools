use std::io::Read;
use std::path::Path;

use crate::{Error, Result, SandboxPolicy};

const DEFAULT_MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFormat {
    Toml,
    Json,
}

pub fn parse_policy(raw: &str, format: PolicyFormat) -> Result<SandboxPolicy> {
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

pub fn load_policy_limited(path: impl AsRef<Path>, max_bytes: u64) -> Result<SandboxPolicy> {
    if max_bytes == 0 {
        return Err(Error::InvalidPolicy(
            "max policy bytes must be > 0".to_string(),
        ));
    }

    let path = path.as_ref();
    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();
    std::fs::File::open(path)
        .map_err(|err| Error::io_path("open", path, err))?
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|err| Error::io_path("read", path, err))?;

    if bytes.len() as u64 > max_bytes {
        return Err(Error::InputTooLarge {
            size_bytes: bytes.len() as u64,
            max_bytes,
        });
    }

    let raw = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidUtf8(path.to_path_buf()))?;
    let format = match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => PolicyFormat::Json,
        Some("toml") | None => PolicyFormat::Toml,
        Some(other) => {
            return Err(Error::InvalidPolicy(format!(
                "unsupported policy format {other:?}; expected .toml or .json"
            )));
        }
    };
    parse_policy(raw, format)
}
