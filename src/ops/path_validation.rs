use std::ffi::OsStr;
use std::path::Path;

use crate::error::{Error, Result};

pub(super) fn ensure_non_root_leaf<'a>(
    requested_path: &'a Path,
    raw_input_path: &Path,
    op_name: &'static str,
    missing_segment_label: &'static str,
    root_rejection_message: &'static str,
) -> Result<&'a OsStr> {
    let requested_is_root = requested_path
        .components()
        .all(|component| matches!(component, std::path::Component::CurDir));
    if requested_is_root {
        return Err(Error::InvalidPath(root_rejection_message.to_string()));
    }

    let file_name = requested_path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid {op_name} path {:?}: missing final {missing_segment_label}",
            raw_input_path
        ))
    })?;

    if file_name == OsStr::new(".") || file_name == OsStr::new("..") {
        return Err(Error::InvalidPath(format!(
            "invalid {op_name} path {:?}",
            raw_input_path
        )));
    }

    Ok(file_name)
}
