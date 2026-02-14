use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;

pub fn create_fifo(path: &std::path::Path) {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .unwrap_or_else(|_| panic!("invalid fifo path (contains NUL): {:?}", path));
    // Safety: `CString::new` guarantees a NUL-terminated C string with no interior NUL bytes, and
    // the pointer remains valid for the duration of the call.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            let metadata = std::fs::symlink_metadata(path).unwrap_or_else(|meta_err| {
                panic!("stat failed for {}: {}", path.display(), meta_err)
            });
            if metadata.file_type().is_fifo() {
                return;
            }
            panic!("mkfifo target exists but is not a fifo: {}", path.display());
        }
        panic!("mkfifo failed for {}: {}", path.display(), err);
    }
}
