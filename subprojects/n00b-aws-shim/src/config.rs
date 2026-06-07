//! Opaque `SdkConfig` handle the shim's FFI surface hands back to C.
//!
//! libn00b_aws holds the handle behind `n00b_aws_config_t` and
//! arranges a finalizer that calls `n00b_aws_shim_config_free` when
//! the n00b GC reclaims the wrapper. The Rust side never aliases the
//! pointer past its handover to C.

use std::ffi::{c_char, CStr};
use std::ptr;

use aws_config::{BehaviorVersion, Region};

use crate::runtime::runtime;

/// Wrapper exposed to C as an opaque pointer.
pub struct N00bAwsShimConfig {
    pub inner: aws_config::SdkConfig,
}

/// Build a default `SdkConfig` using aws-sdk-rust's standard
/// resolution chain (env vars → AWS profile file → IMDS / IRSA).
///
/// `region_cstr` may be NULL to inherit the SDK's region resolution.
/// `endpoint_cstr` may be NULL; pass an endpoint to override the
/// service URL (used for LocalStack / VPC endpoints).
///
/// Returns NULL on argument error or runtime failure. The returned
/// pointer must be freed with `n00b_aws_shim_config_free`.
#[no_mangle]
pub extern "C" fn n00b_aws_shim_config_new(
    region_cstr: *const c_char,
    endpoint_cstr: *const c_char,
) -> *mut N00bAwsShimConfig {
    // SAFETY: we treat NULL as "unset"; otherwise the caller asserts
    // the pointer is a NUL-terminated UTF-8 byte string. The to-owned
    // step copies the bytes so we don't hold the caller's storage
    // past return.
    let region = if region_cstr.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(region_cstr) }.to_str() {
            Ok(s) if !s.is_empty() => Some(s.to_owned()),
            _ => return ptr::null_mut(),
        }
    };
    let endpoint = if endpoint_cstr.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(endpoint_cstr) }.to_str() {
            Ok(s) if !s.is_empty() => Some(s.to_owned()),
            _ => None,
        }
    };

    let cfg = runtime().block_on(async {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Some(r) = region {
            loader = loader.region(Region::new(r));
        }
        if let Some(ep) = endpoint {
            loader = loader.endpoint_url(ep);
        }
        loader.load().await
    });

    Box::into_raw(Box::new(N00bAwsShimConfig { inner: cfg }))
}

/// Release a config returned by `n00b_aws_shim_config_new`. Passing
/// NULL is a no-op. Passing the same pointer twice is undefined
/// behaviour — libn00b_aws's GC finalizer is the single owner that
/// calls this.
#[no_mangle]
pub extern "C" fn n00b_aws_shim_config_free(cfg: *mut N00bAwsShimConfig) {
    if !cfg.is_null() {
        // SAFETY: `cfg` was produced by `Box::into_raw` in
        // `n00b_aws_shim_config_new`. The C side passes it back here
        // exactly once.
        unsafe {
            drop(Box::from_raw(cfg));
        }
    }
}
