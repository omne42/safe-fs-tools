use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

// DESIGN INVARIANT (Windows OsStr comparison):
// - We must compare `OsStr` directly under Windows path semantics without lossy UTF-8 conversion.
// - std does not provide a locale-invariant, case-insensitive comparator for `OsStr`/`Path`.
// - ASCII lowercasing is insufficient for non-ASCII path components.
// - `CompareStringOrdinal(..., ignore_case=1)` performs ordinal, case-insensitive UTF-16 comparison
//   on Windows-native code units and preserves lexical boundary semantics.
//
// SAFETY (declaration): foreign function declaration for `CompareStringOrdinal`.
#[link(name = "Kernel32")]
unsafe extern "system" {
    #[link_name = "CompareStringOrdinal"]
    fn compare_string_ordinal(
        string1: *const u16,
        count1: i32,
        string2: *const u16,
        count2: i32,
        ignore_case: i32,
    ) -> i32;
}

pub(crate) fn os_str_eq_case_insensitive(a: &OsStr, b: &OsStr) -> bool {
    const CSTR_EQUAL: i32 = 2;

    // Fast path: exact `OsStr` equality avoids UTF-16 allocations and FFI call.
    if a == b {
        return true;
    }

    let a_wide: Vec<u16> = a.encode_wide().collect();
    let b_wide: Vec<u16> = b.encode_wide().collect();
    let Ok(a_len) = i32::try_from(a_wide.len()) else {
        return false;
    };
    let Ok(b_len) = i32::try_from(b_wide.len()) else {
        return false;
    };

    let a_ptr = if a_wide.is_empty() {
        ptr::null()
    } else {
        a_wide.as_ptr()
    };
    let b_ptr = if b_wide.is_empty() {
        ptr::null()
    } else {
        b_wide.as_ptr()
    };

    // SAFETY:
    // - `a_ptr`/`b_ptr` are null for empty strings or valid UTF-16 buffers for the given lengths.
    // - `a_wide`/`b_wide` live across the call and pointers do not escape.
    // - `ignore_case = 1` requests ordinal, case-insensitive comparison.
    unsafe { compare_string_ordinal(a_ptr, a_len, b_ptr, b_len, 1) == CSTR_EQUAL }
}
