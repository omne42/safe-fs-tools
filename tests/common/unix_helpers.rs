use std::ffi::CString;
use std::io::{self, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

pub fn create_fifo(path: &Path) {
    create_fifo_result(path).unwrap_or_else(|err| {
        panic!("mkfifo failed for {}: {}", path.display(), err);
    });
}

pub fn create_fifo_result(path: &Path) -> io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid fifo path (contains NUL): {:?}", path),
        )
    })?;

    loop {
        // Safety: `CString::new` guarantees a NUL-terminated C string with no interior NUL bytes,
        // and the pointer remains valid for the duration of each call.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if rc == 0 {
            return Ok(());
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EEXIST) => {
                let metadata = std::fs::symlink_metadata(path)?;
                if metadata.file_type().is_fifo() {
                    return Ok(());
                }
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!("mkfifo target exists but is not a fifo: {}", path.display()),
                ));
            }
            _ => return Err(err),
        }
    }
}
