//! `safe-fs-tools` provides policy-bounded filesystem operations for local tooling.
//!
//! The crate enforces an explicit root/permission policy in-process and offers stable request/
//! response types for operations like read/write/edit/delete/glob/grep/copy/move/mkdir/stat/patch.

mod error;
pub mod ops;
#[path = "path_utils.rs"]
mod path_utils_impl;
pub mod path_utils {
    pub use super::path_utils_impl::{starts_with_case_insensitive, strip_prefix_case_insensitive};

    pub(crate) use super::path_utils_impl::{
        build_glob_from_normalized, normalize_glob_pattern_for_matching, normalize_path_lexical,
        validate_root_relative_glob_pattern,
    };
}
mod platform_open;
pub mod policy;
#[cfg(feature = "policy-io")]
pub mod policy_io;
pub mod redaction;

pub use error::{Error, Result};

pub use ops::{
    Context, CopyFileRequest, CopyFileResponse, DeleteRequest, DeleteResponse, EditRequest,
    EditResponse, ListDirEntry, ListDirRequest, ListDirResponse, MkdirRequest, MkdirResponse,
    MovePathRequest, MovePathResponse, PatchRequest, PatchResponse, ReadRequest, ReadResponse,
    ScanLimitReason, StatKind, StatRequest, StatResponse, WriteFileRequest, WriteFileResponse,
    apply_unified_patch, copy_file, delete, edit_range, list_dir, mkdir, move_path, read_file,
    stat, write_file,
};
#[cfg(feature = "glob")]
pub use ops::{GlobRequest, GlobResponse, glob_paths};
#[cfg(feature = "grep")]
pub use ops::{GrepMatch, GrepRequest, GrepResponse, grep};

pub use policy::{
    Limits, PathRules, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};
