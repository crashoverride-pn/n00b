//! FFI helpers shared by every service module.
//!
//! The patterns here are stable and the per-service modules pull them
//! in verbatim. Anything that's expected to change shape across
//! services stays in the service module.

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use crate::N00bAwsShimStatus;

/// Owned `Option<String>` from a C pointer.
///
/// NULL or empty → None. Otherwise an owned UTF-8 String copy of the
/// caller's bytes.
pub(crate) fn cstr_optional(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    match unsafe { CStr::from_ptr(p) }.to_str() {
        Ok(s) if !s.is_empty() => Some(s.to_owned()),
        _ => None,
    }
}

/// Owned `Option<String>` for required inputs — same as `cstr_optional`;
/// callers translate `None` into `ErrInvalidArg`.
pub(crate) fn cstr_required(p: *const c_char) -> Option<String> {
    cstr_optional(p)
}

/// Build a `Vec<String>` from a (pointer-array, count) pair. NULL /
/// empty entries are skipped.
pub(crate) fn collect_cstrs(ptr: *const *const c_char, count: usize) -> Vec<String> {
    if ptr.is_null() || count == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let p = unsafe { *ptr.add(i) };
        if let Some(s) = cstr_optional(p) {
            out.push(s);
        }
    }
    out
}

/// Collect parallel (key, value) cstr arrays into `Vec<(String, String)>`.
/// If `key_count != value_count` the function returns an empty Vec —
/// the caller likely passed mismatched lists.
pub(crate) fn collect_cstr_kv(
    keys: *const *const c_char,
    values: *const *const c_char,
    count: usize,
) -> Vec<(String, String)> {
    let ks = collect_cstrs(keys, count);
    let vs = collect_cstrs(values, count);
    if ks.len() != vs.len() {
        return Vec::new();
    }
    ks.into_iter().zip(vs.into_iter()).collect()
}

/// Build an owned `*mut c_char` holding a NUL-terminated copy of @p s
/// (or an empty buffer when @p s is None / contains embedded NULs).
pub(crate) fn cstring_or_empty(s: Option<&str>) -> *mut c_char {
    let text = s.unwrap_or("");
    match CString::new(text) {
        Ok(c) => c.into_raw(),
        Err(_) => CString::new("").unwrap().into_raw(),
    }
}

/// Build a `*mut c_char` from an owned String.
pub(crate) fn cstring_from_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => CString::new("").unwrap().into_raw(),
    }
}

/// Free a `CString::into_raw` pointer; tolerates NULL.
pub(crate) fn free_cstring_ptr(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

/// Free an array of `*mut c_char` allocated via `cstring_*_into_raw`.
/// The array itself is allocated by `Box::into_raw(Vec<*mut c_char>::into_boxed_slice())`.
pub(crate) fn free_cstring_array(arr: *mut *mut c_char, count: usize) {
    if arr.is_null() || count == 0 {
        return;
    }
    // Reconstruct the boxed slice so Rust drops it as a unit, then
    // free each element.
    let slice = unsafe { core::slice::from_raw_parts_mut(arr, count) };
    for p in slice.iter_mut() {
        free_cstring_ptr(*p);
        *p = ptr::null_mut();
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
            arr, count,
        )));
    }
}

/// Allocate a `*mut *mut c_char` of length `vec.len()` populated with
/// `into_raw` copies of the input strings. Caller stores `len` and
/// frees with `free_cstring_array`.
pub(crate) fn vec_to_cstring_array(vec: Vec<String>) -> (*mut *mut c_char, usize) {
    if vec.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let len = vec.len();
    let mut items: Vec<*mut c_char> = vec.into_iter().map(|s| cstring_from_string(s)).collect();
    let boxed: Box<[*mut c_char]> = items.into_boxed_slice();
    let raw = Box::into_raw(boxed) as *mut *mut c_char;
    (raw, len)
}

/// Build an owned `Vec<String>` from `&[String]` references.
pub(crate) fn owned_strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// Status mapping used by every service. The error variants that
/// belong to one service (e.g. `QueueDoesNotExist` in SQS) get
/// classified at the service-specific layer; this helper only knows
/// about transport-level + identity-level errors.
pub(crate) fn classify_generic_sdk_error<E, R>(
    err: &aws_smithy_runtime_api::client::result::SdkError<E, R>,
) -> N00bAwsShimStatus {
    use aws_smithy_runtime_api::client::result::SdkError;
    match err {
        SdkError::ConstructionFailure(_) => N00bAwsShimStatus::ErrClient,
        SdkError::TimeoutError(_) => N00bAwsShimStatus::ErrTimeout,
        SdkError::DispatchFailure(_) => N00bAwsShimStatus::ErrNetwork,
        SdkError::ResponseError(_) => N00bAwsShimStatus::ErrService,
        SdkError::ServiceError(_) => N00bAwsShimStatus::ErrService,
        _ => N00bAwsShimStatus::ErrInternal,
    }
}
