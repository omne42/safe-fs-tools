//! `safe-fs-tools` provides policy-bounded filesystem operations for local tooling.
//!
//! The crate enforces an explicit root/permission policy in-process and offers stable request/
//! response types for operations like read/write/edit/delete/glob/grep.

mod error;
pub mod ops;
pub mod path_utils;
#[doc(hidden)]
pub mod platform_open;
pub mod policy;
#[cfg(feature = "policy-io")]
pub mod policy_io;
pub mod redaction;

pub use error::{Error, Result};

pub use ops::{
    Context, CopyFileRequest, CopyFileResponse, DeleteRequest, DeleteResponse, EditRequest,
    EditResponse, GlobRequest, GlobResponse, GrepMatch, GrepRequest, GrepResponse, ListDirEntry,
    ListDirRequest, ListDirResponse, MkdirRequest, MkdirResponse, MovePathRequest,
    MovePathResponse, PatchRequest, PatchResponse, ReadRequest, ReadResponse, ScanLimitReason,
    StatRequest, StatResponse, WriteFileRequest, WriteFileResponse, apply_unified_patch, copy_file,
    delete, edit_range, glob_paths, grep, list_dir, mkdir, move_path, read_file, stat, write_file,
};

pub use policy::{
    Limits, PathRules, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};
