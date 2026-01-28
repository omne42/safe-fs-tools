use std::path::Path;

use crate::{Error, Result, SandboxPolicy};

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
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|err| Error::io_path("read", path, err))?;
    let format = match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => PolicyFormat::Json,
        Some("toml") | None => PolicyFormat::Toml,
        Some(other) => {
            return Err(Error::InvalidPolicy(format!(
                "unsupported policy format {other:?}; expected .toml or .json"
            )));
        }
    };
    parse_policy(&raw, format)
}
