use std::path::PathBuf;

#[cfg(any(feature = "glob", feature = "grep"))]
use globset::GlobSet;
use serde::{Deserialize, Serialize};

use crate::policy::SandboxPolicy;
use crate::redaction::SecretRedactor;

mod context;
mod delete;
mod edit;
mod glob;
mod grep;
mod io;
mod patch;
mod read;
mod resolve;
mod traversal;

pub use delete::{DeleteRequest, DeleteResponse, delete_file};
pub use edit::{EditRequest, EditResponse, edit_range};
pub use glob::{GlobRequest, GlobResponse, glob_paths};
pub use grep::{GrepMatch, GrepRequest, GrepResponse, grep};
pub use patch::{PatchRequest, PatchResponse, apply_unified_patch};
pub use read::{ReadRequest, ReadResponse, read_file};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct Context {
    policy: SandboxPolicy,
    redactor: SecretRedactor,
    canonical_roots: Vec<(String, PathBuf)>,
    #[cfg(any(feature = "glob", feature = "grep"))]
    traversal_skip_globs: Option<GlobSet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLimitReason {
    Entries,
    Files,
    Time,
    Results,
}
