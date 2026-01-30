use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

pub fn create_fifo(path: &std::path::Path) {
    let c_path = CString::new(path.as_os_str().as_bytes()).expect("c path");
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    if rc != 0 {
        panic!("mkfifo failed: {}", std::io::Error::last_os_error());
    }
}
