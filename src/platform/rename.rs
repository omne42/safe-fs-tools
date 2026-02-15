use std::fs;
use std::path::Path;

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let parent_dir = fs::File::open(parent)?;
    parent_dir.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_rename_parents(src_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    sync_parent_directory(dest_path)?;
    let src_parent = src_path.parent();
    let dest_parent = dest_path.parent();
    if src_parent != dest_parent {
        sync_parent_directory(src_path)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_rename_parents(_src_path: &Path, _dest_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
pub(crate) fn rename_replace(
    src_path: &Path,
    dest_path: &Path,
    replace_existing: bool,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    fn to_wide_null(p: &Path) -> Vec<u16> {
        let mut wide: Vec<u16> = p.as_os_str().encode_wide().collect();
        wide.push(0);
        wide
    }

    let src_w = to_wide_null(src_path);
    let dest_w = to_wide_null(dest_path);

    let flags = if replace_existing {
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
    } else {
        MOVEFILE_WRITE_THROUGH
    };

    // DESIGN INVARIANT (Windows atomic replacement):
    // - `safe-fs-tools` guarantees overwrite semantics via atomic replacement (temp file -> target).
    // - A delete-then-rename fallback is not equivalent on Windows and creates an observable gap where
    //   the destination can disappear.
    // - `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` is the required primitive to preserve this
    //   contract; std alone does not expose a stronger overwrite-atomic API for this case.
    //
    // SAFETY:
    // - `src_w` and `dest_w` are owned, NUL-terminated UTF-16 buffers.
    // - Passed pointers stay valid for this synchronous call and do not escape.
    // - Win32 does not retain these pointers after return.
    let moved = unsafe { MoveFileExW(src_w.as_ptr(), dest_w.as_ptr(), flags) };
    if moved == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn rename_replace(
    src_path: &Path,
    dest_path: &Path,
    replace_existing: bool,
) -> std::io::Result<()> {
    if replace_existing {
        fs::rename(src_path, dest_path)?;
    } else {
        rename_no_replace(src_path, dest_path)?;
    }
    sync_rename_parents(src_path, dest_path).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("rename already applied, but failed to sync parent directories: {err}"),
        )
    })
}

#[cfg(all(unix, not(windows), any(target_os = "linux", target_os = "android")))]
fn rename_no_replace(src_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src = CString::new(src_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source path contains interior NUL byte",
        )
    })?;
    let dest = CString::new(dest_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination path contains interior NUL byte",
        )
    })?;

    // DESIGN INVARIANT (Linux/Android no-replace rename):
    // - We need an atomic "fail if destination exists" primitive to close overwrite races.
    // - std currently does not expose this operation.
    // - `renameat2(..., RENAME_NOREPLACE)` is the platform syscall that matches this contract.
    //
    // SAFETY:
    // - Both C strings are NUL-terminated and valid for this synchronous call.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src.as_ptr(),
            libc::AT_FDCWD,
            dest.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

#[cfg(all(
    unix,
    not(windows),
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    )
))]
fn rename_no_replace(src_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src = CString::new(src_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source path contains interior NUL byte",
        )
    })?;
    let dest = CString::new(dest_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination path contains interior NUL byte",
        )
    })?;

    // DESIGN INVARIANT (Darwin no-replace rename):
    // - We need an atomic "destination must not exist" primitive.
    // - std currently does not expose this operation.
    // - `renamex_np(..., RENAME_EXCL)` is the platform primitive with these semantics.
    //
    // SAFETY:
    // - Both C strings are NUL-terminated and valid for this synchronous call.
    let rc = unsafe { libc::renamex_np(src.as_ptr(), dest.as_ptr(), libc::RENAME_EXCL) };
    if rc == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

#[cfg(all(
    unix,
    not(windows),
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
fn rename_no_replace(src_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    let _ = src_path;
    let _ = dest_path;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace rename is unsupported on this platform",
    ))
}
