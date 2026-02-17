use std::fs;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn preserve_unix_security_metadata(
    src_file: &fs::File,
    src_meta: &fs::Metadata,
    tmp_file: &fs::File,
    copy_xattrs: bool,
) -> std::io::Result<()> {
    use std::collections::HashSet;
    use std::ffi::{CStr, CString};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    // DESIGN INVARIANT (Linux/Android xattrs):
    // - Rust std provides ownership/mode timestamps, but does not expose extended attributes.
    // - We must preserve xattrs on already-open file handles so metadata copy remains bound to the
    //   same inode and does not reopen by path (which would widen TOCTOU/symlink races).
    // - Therefore this function uses fd-scoped libc xattr syscalls:
    //   `flistxattr`, `fgetxattr`, `fsetxattr`, and `fremovexattr`.
    // - All `unsafe` below is confined to syscall boundaries; pointer validity and buffer lengths
    //   are checked at each call site.
    // - The kernel reports xattr sizes dynamically; we enforce conservative caps to avoid
    //   pathological one-shot allocations from corrupted or hostile filesystems.

    const MAX_XATTR_VALUE_BYTES: usize = 1024 * 1024;
    const MAX_XATTR_NAME_LIST_BYTES: usize = 4 * 1024 * 1024;
    const MAX_XATTR_RACE_RETRIES: usize = 4;

    fn checked_kernel_len(len: libc::ssize_t, cap: usize, what: &str) -> std::io::Result<usize> {
        let len = usize::try_from(len).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{what} overflow"))
        })?;
        if len > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{what} exceeds cap ({len} > {cap})"),
            ));
        }
        Ok(len)
    }

    #[inline]
    fn is_retryable_xattr_race(err: &std::io::Error) -> bool {
        err.raw_os_error() == Some(libc::ERANGE)
    }

    fn xattr_read_fd_required(fd: libc::c_int, name: &CStr) -> std::io::Result<Vec<u8>> {
        for _ in 0..MAX_XATTR_RACE_RETRIES {
            // SAFETY: `name` is NUL-terminated and both pointers are valid for this call.
            let len = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
            if len < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let len = checked_kernel_len(len, MAX_XATTR_VALUE_BYTES, "xattr value length")?;
            if len == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0_u8; len];
            // SAFETY: destination buffer is valid for `buf.len()` bytes.
            let read = unsafe {
                libc::fgetxattr(
                    fd,
                    name.as_ptr(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if read < 0 {
                let err = std::io::Error::last_os_error();
                if is_retryable_xattr_race(&err) {
                    continue;
                }
                return Err(err);
            }
            let read = usize::try_from(read).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr read length overflow",
                )
            })?;
            buf.truncate(read);
            return Ok(buf);
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            "xattr value changed concurrently during read",
        ))
    }

    fn xattr_read_fd(fd: libc::c_int, name: &CStr) -> std::io::Result<Option<Vec<u8>>> {
        for _ in 0..MAX_XATTR_RACE_RETRIES {
            // SAFETY: `name` is NUL-terminated and both pointers are valid for this call.
            let len = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
            if len < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENODATA) {
                    return Ok(None);
                }
                return Err(err);
            }
            let len = checked_kernel_len(len, MAX_XATTR_VALUE_BYTES, "xattr value length")?;
            if len == 0 {
                return Ok(Some(Vec::new()));
            }
            let mut buf = vec![0_u8; len];
            // SAFETY: destination buffer is valid for `buf.len()` bytes.
            let read = unsafe {
                libc::fgetxattr(
                    fd,
                    name.as_ptr(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if read < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENODATA) {
                    return Ok(None);
                }
                if is_retryable_xattr_race(&err) {
                    continue;
                }
                return Err(err);
            }
            let read = usize::try_from(read).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr read length overflow",
                )
            })?;
            buf.truncate(read);
            return Ok(Some(buf));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            "xattr value changed concurrently during read",
        ))
    }

    fn xattr_list_fd(fd: libc::c_int) -> std::io::Result<Vec<CString>> {
        for _ in 0..MAX_XATTR_RACE_RETRIES {
            // SAFETY: null buffer with size 0 asks kernel for the required size.
            let list_len = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
            if list_len < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let list_len = checked_kernel_len(
                list_len,
                MAX_XATTR_NAME_LIST_BYTES,
                "xattr name list length",
            )?;
            if list_len == 0 {
                return Ok(Vec::new());
            }

            let mut names = vec![0_u8; list_len];
            // SAFETY: `names` is a writable buffer of `names.len()` bytes.
            let list_read = unsafe {
                libc::flistxattr(fd, names.as_mut_ptr().cast::<libc::c_char>(), names.len())
            };
            if list_read < 0 {
                let err = std::io::Error::last_os_error();
                if is_retryable_xattr_race(&err) {
                    continue;
                }
                return Err(err);
            }
            let list_read = checked_kernel_len(
                list_read,
                MAX_XATTR_NAME_LIST_BYTES,
                "xattr name list read length",
            )?;

            return names[..list_read]
                .split(|byte| *byte == 0)
                .filter(|raw_name| !raw_name.is_empty())
                .map(|raw_name| {
                    CString::new(raw_name).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "xattr name contains interior NUL byte",
                        )
                    })
                })
                .collect();
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            "xattr name list changed concurrently during read",
        ))
    }

    let tmp_meta = tmp_file.metadata()?;
    let src_uid: libc::uid_t = src_meta.uid();
    let src_gid: libc::gid_t = src_meta.gid();
    let tmp_uid: libc::uid_t = tmp_meta.uid();
    let tmp_gid: libc::gid_t = tmp_meta.gid();
    if src_uid != tmp_uid || src_gid != tmp_gid {
        let uid: libc::uid_t = if src_uid == tmp_uid {
            libc::uid_t::MAX
        } else {
            src_uid
        };
        let gid: libc::gid_t = if src_gid == tmp_gid {
            libc::gid_t::MAX
        } else {
            src_gid
        };
        // SAFETY: fd comes from a live file handle and uid/gid values are plain integers.
        let chown_rc = unsafe { libc::fchown(tmp_file.as_raw_fd(), uid, gid) };
        if chown_rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    if !copy_xattrs {
        return Ok(());
    }

    let src_fd = src_file.as_raw_fd();
    let fd = tmp_file.as_raw_fd();

    let src_names = xattr_list_fd(src_fd)?;
    let dst_names = xattr_list_fd(fd)?;
    let dst_names_empty = dst_names.is_empty();
    if src_names.is_empty() {
        for dst_name in dst_names {
            // SAFETY: xattr name pointer is valid for this synchronous call.
            let remove_rc = unsafe { libc::fremovexattr(fd, dst_name.as_ptr()) };
            if remove_rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENODATA) {
                    continue;
                }
                return Err(err);
            }
        }
        return Ok(());
    }

    if !dst_names_empty {
        let mut src_name_set = HashSet::<&[u8]>::with_capacity(src_names.len());
        src_name_set.extend(src_names.iter().map(|name| name.as_bytes()));
        for dst_name in dst_names {
            if src_name_set.contains(dst_name.as_bytes()) {
                continue;
            }
            // SAFETY: xattr name pointer is valid for this synchronous call.
            let remove_rc = unsafe { libc::fremovexattr(fd, dst_name.as_ptr()) };
            if remove_rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENODATA) {
                    continue;
                }
                return Err(err);
            }
        }
    }

    for name in src_names {
        let name_cstr = name.as_c_str();
        let src_value = xattr_read_fd_required(src_fd, name_cstr)?;
        if !dst_names_empty {
            let dst_value = xattr_read_fd(fd, name_cstr)?;
            if dst_value.as_deref() == Some(src_value.as_slice()) {
                continue;
            }
        }
        // SAFETY: xattr name/value buffers are valid for this synchronous call.
        let set_rc = unsafe {
            libc::fsetxattr(
                fd,
                name_cstr.as_ptr(),
                src_value.as_ptr().cast::<libc::c_void>(),
                src_value.len(),
                0,
            )
        };
        if set_rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn preserve_unix_security_metadata(
    _src_file: &fs::File,
    src_meta: &fs::Metadata,
    tmp_file: &fs::File,
    _copy_xattrs: bool,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let tmp_meta = tmp_file.metadata()?;
    let src_uid: libc::uid_t = src_meta.uid().into();
    let src_gid: libc::gid_t = src_meta.gid().into();
    let tmp_uid: libc::uid_t = tmp_meta.uid().into();
    let tmp_gid: libc::gid_t = tmp_meta.gid().into();
    if src_uid != tmp_uid || src_gid != tmp_gid {
        let uid: libc::uid_t = if src_uid == tmp_uid {
            libc::uid_t::MAX
        } else {
            src_uid
        };
        let gid: libc::gid_t = if src_gid == tmp_gid {
            libc::gid_t::MAX
        } else {
            src_gid
        };
        // SAFETY: fd comes from a live file handle and uid/gid values are plain integers.
        let chown_rc = unsafe { libc::fchown(tmp_file.as_raw_fd(), uid, gid) };
        if chown_rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::ffi::CString;
    use std::fs::{self, OpenOptions};
    use std::os::fd::AsRawFd;

    fn xattr_not_supported(err: &std::io::Error) -> bool {
        matches!(err.raw_os_error(), Some(code) if [
            libc::ENOTSUP,
            libc::EOPNOTSUPP,
            libc::EPERM,
            libc::EACCES
        ]
        .contains(&code))
    }

    fn set_xattr(file: &fs::File, name: &str, value: &[u8]) -> std::io::Result<()> {
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "xattr name contained NUL")
        })?;
        // SAFETY: fd is valid, and name/value buffers remain alive for the syscall duration.
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast::<libc::c_void>(),
                value.len(),
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn get_xattr(file: &fs::File, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "xattr name contained NUL")
        })?;
        // SAFETY: fd and name pointer are valid; null buffer probes required length.
        let len =
            unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if len < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODATA) {
                return Ok(None);
            }
            return Err(err);
        }
        let len = usize::try_from(len).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "xattr length overflow")
        })?;
        let mut out = vec![0_u8; len];
        // SAFETY: destination buffer is valid for `out.len()` bytes.
        let read = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                out.as_mut_ptr().cast::<libc::c_void>(),
                out.len(),
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let read = usize::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr read length overflow",
            )
        })?;
        out.truncate(read);
        Ok(Some(out))
    }

    fn remove_xattr(file: &fs::File, name: &str) -> std::io::Result<()> {
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "xattr name contained NUL")
        })?;
        // SAFETY: fd and name pointer are valid for syscall duration.
        let rc = unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENODATA) {
            return Ok(());
        }
        Err(err)
    }

    fn supports_user_xattrs(file: &fs::File) -> bool {
        const PROBE: &str = "user.safe_fs_tools_probe";
        match set_xattr(file, PROBE, b"1") {
            Ok(()) => {
                let _ = remove_xattr(file, PROBE);
                true
            }
            Err(err) if xattr_not_supported(&err) => false,
            Err(err) => panic!("xattr probe failed: {err}"),
        }
    }

    #[test]
    fn preserve_unix_security_metadata_syncs_and_prunes_xattrs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        fs::write(&src_path, "src").expect("write src");
        fs::write(&dst_path, "dst").expect("write dst");

        let src_file = OpenOptions::new()
            .read(true)
            .open(&src_path)
            .expect("open src");
        let dst_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dst_path)
            .expect("open dst");
        if !supports_user_xattrs(&src_file) || !supports_user_xattrs(&dst_file) {
            return;
        }

        set_xattr(&src_file, "user.safe_fs_tools_keep", b"keep").expect("set src keep");
        set_xattr(&src_file, "user.safe_fs_tools_update", b"new").expect("set src update");
        set_xattr(&dst_file, "user.safe_fs_tools_update", b"old").expect("set dst update");
        set_xattr(&dst_file, "user.safe_fs_tools_remove", b"gone").expect("set dst remove");

        super::preserve_unix_security_metadata(
            &src_file,
            &src_file.metadata().expect("src metadata"),
            &dst_file,
            true,
        )
        .expect("preserve metadata");

        assert_eq!(
            get_xattr(&dst_file, "user.safe_fs_tools_keep").expect("get dst keep"),
            Some(b"keep".to_vec())
        );
        assert_eq!(
            get_xattr(&dst_file, "user.safe_fs_tools_update").expect("get dst update"),
            Some(b"new".to_vec())
        );
        assert_eq!(
            get_xattr(&dst_file, "user.safe_fs_tools_remove").expect("get dst remove"),
            None
        );
    }

    #[test]
    fn preserve_unix_security_metadata_keeps_dst_xattrs_when_copy_disabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        fs::write(&src_path, "src").expect("write src");
        fs::write(&dst_path, "dst").expect("write dst");

        let src_file = OpenOptions::new()
            .read(true)
            .open(&src_path)
            .expect("open src");
        let dst_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dst_path)
            .expect("open dst");
        if !supports_user_xattrs(&src_file) || !supports_user_xattrs(&dst_file) {
            return;
        }

        set_xattr(&src_file, "user.safe_fs_tools_src_only", b"src-only").expect("set src xattr");
        set_xattr(&dst_file, "user.safe_fs_tools_dst_only", b"dst-only").expect("set dst xattr");

        super::preserve_unix_security_metadata(
            &src_file,
            &src_file.metadata().expect("src metadata"),
            &dst_file,
            false,
        )
        .expect("preserve metadata");

        assert_eq!(
            get_xattr(&dst_file, "user.safe_fs_tools_src_only").expect("get dst src-only"),
            None
        );
        assert_eq!(
            get_xattr(&dst_file, "user.safe_fs_tools_dst_only").expect("get dst dst-only"),
            Some(b"dst-only".to_vec())
        );
    }
}
