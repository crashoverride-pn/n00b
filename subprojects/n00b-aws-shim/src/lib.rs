//! n00b-aws-shim — Rust cdylib that exposes aws-sdk-rust operations
//! to libn00b_aws through a stable C ABI.
//!
//! Build the cdylib (`cargo build --release`), then point libn00b_aws
//! at the resulting `target/release/libn00b_aws_shim.{dylib,so,dll}`.
//! At build time meson runs `dsymutil` (macOS) and `~/slop/bin/demangle`
//! against the cdylib to produce a C header full of typed `extern`
//! declarations; libn00b_aws includes that header and link-time-links
//! against this dylib via `-ln00b_aws_shim`.
//!
//! ABI rules in this crate:
//!
//!   * Every public symbol is `#[no_mangle] extern "C" fn`. Internal
//!     helpers stay private and do not appear in the cdylib's exports.
//!   * All public symbols share the `n00b_aws_shim_` prefix so the
//!     dynamic-linker namespace is unambiguous.
//!   * No panics ever cross the FFI boundary — `panic = "abort"` in
//!     `Cargo.toml` makes every panic terminate the process rather
//!     than reach C code. Recoverable conditions are returned as
//!     status codes (the `N00B_AWS_SHIM_*` enum in C-land).
//!   * Heap state allocated on this side is freed through a matching
//!     `n00b_aws_shim_*_free` entry-point; the n00b GC proxies that
//!     through `n00b_add_finalizer`. The C++-style placement-new /
//!     manual-destructor dance is gone — pure malloc/free across the
//!     FFI, owned and managed in Rust.
//!
//! Phase 3c first wrap — STS GetCallerIdentity. Once you sign off on
//! the pattern, the same shape extends to every aws-sdk-* operation
//! across SQS / SNS / S3 / etc.

mod config;
mod dynamodb;
mod ffi_util;
mod runtime;
mod s3;
mod sns;
mod sqs;
mod sts;

use std::ffi::c_char;

/// Returns a pointer to a NUL-terminated, static crate version string.
/// The buffer lives for the lifetime of the loaded dylib; the caller
/// must not free it.
#[no_mangle]
pub extern "C" fn n00b_aws_shim_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

/// Coarse status enum surfaced to C. Identical to the
/// `n00b_aws_status_t` declared in `include/aws/n00b_aws.h`. The two
/// are kept in lock-step manually until we have a cbindgen step in
/// the publishing pipeline.
#[repr(i32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum N00bAwsShimStatus {
    Ok = 0,
    ErrInvalidArg = -1,
    ErrNotInitialized = -2,
    ErrNoCredentials = -3,
    ErrAuthz = -4,
    ErrNotFound = -5,
    ErrThrottled = -6,
    ErrTimeout = -7,
    ErrNetwork = -8,
    ErrService = -9,
    ErrClient = -10,
    ErrInternal = -11,
    ErrExists = -12,
}

/// Re-export the status as an `i32` for use inside individual
/// extern "C" wrappers — they return `i32` so demangle's emitted
/// `extern int32_t n00b_aws_shim_*` declarations match exactly.
impl N00bAwsShimStatus {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}
