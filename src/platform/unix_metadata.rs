use std::fs;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn preserve_unix_security_metadata(
    src_file: &fs::File,
    src_meta: &fs::Metadata,
    tmp_file: &fs::File,
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

    fn xattr_read_fd_required(fd: libc::c_int, name: &CStr) -> std::io::Result<Vec<u8>> {
        // SAFETY: `name` is NUL-terminated and both pointers are valid for this call.
        let len = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
        if len < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let len = usize::try_from(len).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "xattr length overflow")
        })?;
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
            return Err(std::io::Error::last_os_error());
        }
        let read = usize::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr read length overflow",
            )
        })?;
        buf.truncate(read);
        Ok(buf)
    }

    fn xattr_read_fd(fd: libc::c_int, name: &CStr) -> std::io::Result<Option<Vec<u8>>> {
        // SAFETY: `name` is NUL-terminated and both pointers are valid for this call.
        let len = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
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
            return Err(std::io::Error::last_os_error());
        }
        let read = usize::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr read length overflow",
            )
        })?;
        buf.truncate(read);
        Ok(Some(buf))
    }

    fn xattr_list_fd(fd: libc::c_int) -> std::io::Result<Vec<CString>> {
        // SAFETY: null buffer with size 0 asks kernel for the required size.
        let list_len = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if list_len < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let list_len = usize::try_from(list_len).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr name list length overflow",
            )
        })?;
        if list_len == 0 {
            return Ok(Vec::new());
        }

        let mut names = vec![0_u8; list_len];
        // SAFETY: `names` is a writable buffer of `names.len()` bytes.
        let list_read =
            unsafe { libc::flistxattr(fd, names.as_mut_ptr().cast::<libc::c_char>(), names.len()) };
        if list_read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let list_read = usize::try_from(list_read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr name list read length overflow",
            )
        })?;

        names[..list_read]
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
            .collect()
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
            libc::uid_t::MAX
        } else {
            src_gid
        };
        // SAFETY: fd comes from a live file handle and uid/gid values are plain integers.
        let chown_rc = unsafe { libc::fchown(tmp_file.as_raw_fd(), uid, gid) };
        if chown_rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    let src_fd = src_file.as_raw_fd();
    let fd = tmp_file.as_raw_fd();

    let src_names = xattr_list_fd(src_fd)?;
    let src_name_set: HashSet<Vec<u8>> = src_names
        .iter()
        .map(|name| name.as_bytes().to_vec())
        .collect();
    for dst_name in xattr_list_fd(fd)? {
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

    for name in src_names {
        let name_cstr = name.as_c_str();
        let src_value = xattr_read_fd_required(src_fd, name_cstr)?;
        let dst_value = xattr_read_fd(fd, name_cstr)?;
        if dst_value.as_deref() == Some(src_value.as_slice()) {
            continue;
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
            libc::uid_t::MAX
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
