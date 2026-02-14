use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(any(feature = "glob", feature = "grep"))]
use globset::GlobSet;
use serde::{Deserialize, Serialize};

use crate::policy::SandboxPolicy;
use crate::redaction::SecretRedactor;

mod context;
mod copy_file;
mod delete;
mod edit;
mod glob;
mod grep;
mod io;
mod list_dir;
mod mkdir;
mod move_path;
mod patch;
mod path_validation;
mod read;
mod resolve;
mod stat;
#[cfg(any(feature = "glob", feature = "grep"))]
mod traversal;
mod write;

pub use copy_file::{CopyFileRequest, CopyFileResponse, copy_file};
pub use delete::{DeleteRequest, DeleteResponse, delete};
pub use edit::{EditRequest, EditResponse, edit_range};
pub use glob::{GlobRequest, GlobResponse, glob_paths};
pub use grep::{GrepMatch, GrepRequest, GrepResponse, grep};
pub use list_dir::{ListDirEntry, ListDirRequest, ListDirResponse, list_dir};
pub use mkdir::{MkdirRequest, MkdirResponse, mkdir};
pub use move_path::{MovePathRequest, MovePathResponse, move_path};
pub use patch::{PatchRequest, PatchResponse, apply_unified_patch};
pub use read::{ReadRequest, ReadResponse, read_file};
pub use stat::{StatKind, StatRequest, StatResponse, stat};
pub use write::{WriteFileRequest, WriteFileResponse, write_file};

#[cfg(test)]
mod tests;

pub struct Context {
    policy: SandboxPolicy,
    redactor: SecretRedactor,
    canonical_roots: HashMap<String, PathBuf>,
    #[cfg(any(feature = "glob", feature = "grep"))]
    traversal_skip_globs: Option<GlobSet>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut root_ids = self.canonical_roots.keys().collect::<Vec<_>>();
        root_ids.sort_unstable();
        f.debug_struct("Context")
            .field("roots", &root_ids)
            .field("permissions", &self.policy.permissions)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ScanLimitReason {
    Entries,
    Files,
    Time,
    Results,
}
