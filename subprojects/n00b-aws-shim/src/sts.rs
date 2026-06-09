//! STS wrappers — full `aws-sdk-sts` Smithy surface.
//!
//! Pattern (per op):
//!   * one `#[no_mangle] extern "C" fn n00b_aws_shim_sts_<op>(cfg, ..., out) -> i32`
//!   * one `#[repr(C)]` output struct, allocated by us, freed by a
//!     matching `_free` entry-point that the n00b GC finalizer calls.
//!   * For ops with more than ~3 scalar inputs, an input struct
//!     keeps the FFI signature flat.
//!
//! Optional fields:
//!   * `*const c_char` / `*mut c_char`: NULL means "absent". Helper
//!     `cstr_owned` produces `Some(String)` for non-empty, non-NULL
//!     inputs.
//!   * Scalar optionals (e.g. `duration_seconds`): zero/negative as
//!     "use SDK default". Per-op comment documents the cutoff.
//!   * List inputs (policy_arns, tags, transitive_tag_keys): NULL or
//!     count=0 means "omit". Otherwise paired pointer + length.

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use aws_sdk_sts::types::{PolicyDescriptorType, Tag};
use aws_sdk_sts::Client as StsClient;

use crate::config::N00bAwsShimConfig;
use crate::runtime::runtime;
use crate::N00bAwsShimStatus;

/* =========================================================================
 * Shared output building blocks
 * =========================================================================
 *
 * Credentials and AssumedRoleUser appear in many STS responses; we
 * define them once and reuse the layout. Each struct is `repr(C)`
 * with `*mut c_char` fields the C wrap copies into `n00b_string_t`
 * and then asks us to free.
 */

#[repr(C)]
pub struct N00bAwsShimAwsCredentials {
    pub access_key_id: *mut c_char,
    pub secret_access_key: *mut c_char,
    pub session_token: *mut c_char,
    /// Expiration as unix-ms-since-epoch. -1 if absent.
    pub expiration_ms: i64,
}

#[repr(C)]
pub struct N00bAwsShimAssumedRoleUser {
    pub assumed_role_id: *mut c_char,
    pub arn: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimFederatedUser {
    pub federated_user_id: *mut c_char,
    pub arn: *mut c_char,
}

/* =========================================================================
 * GetCallerIdentity
 * =========================================================================
 */

#[repr(C)]
pub struct N00bAwsShimStsCallerIdentity {
    pub account_id: *mut c_char,
    pub arn: *mut c_char,
    pub user_id: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_get_caller_identity(
    cfg: *const N00bAwsShimConfig,
    out_identity: *mut *mut N00bAwsShimStsCallerIdentity,
) -> i32 {
    if !out_identity.is_null() {
        unsafe {
            *out_identity = ptr::null_mut();
        }
    }
    if cfg.is_null() || out_identity.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome =
        runtime().block_on(async { StsClient::new(sdk_cfg).get_caller_identity().send().await });

    match outcome {
        Ok(resp) => {
            let identity = N00bAwsShimStsCallerIdentity {
                account_id: cstring_or_empty(resp.account()),
                arn: cstring_or_empty(resp.arn()),
                user_id: cstring_or_empty(resp.user_id()),
            };
            unsafe {
                *out_identity = Box::into_raw(Box::new(identity));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_caller_identity_free(p: *mut N00bAwsShimStsCallerIdentity) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.account_id);
    free_cstring_ptr(boxed.arn);
    free_cstring_ptr(boxed.user_id);
}

/* =========================================================================
 * AssumeRole
 * =========================================================================
 */

#[repr(C)]
pub struct N00bAwsShimStsAssumeRoleInput {
    pub role_arn: *const c_char,
    pub role_session_name: *const c_char,
    /// 0 → SDK default; otherwise 900-43200.
    pub duration_seconds: i32,
    pub external_id: *const c_char,
    pub serial_number: *const c_char, // MFA device serial
    pub token_code: *const c_char,    // MFA token
    pub policy: *const c_char,        // inline JSON policy
    pub source_identity: *const c_char,
    /// Pointer + count for the managed-policy ARN list. NULL/0 omits.
    pub policy_arns: *const *const c_char,
    pub policy_arns_count: usize,
    /// Parallel key/value lists for session tags. Lengths must match.
    pub session_tag_keys: *const *const c_char,
    pub session_tag_values: *const *const c_char,
    pub session_tags_count: usize,
    /// Tag keys to forward when the session is chained into another
    /// role. NULL/0 omits.
    pub transitive_tag_keys: *const *const c_char,
    pub transitive_tag_keys_count: usize,
}

#[repr(C)]
pub struct N00bAwsShimStsAssumeRoleOutput {
    pub credentials: *mut N00bAwsShimAwsCredentials,
    pub assumed_role_user: *mut N00bAwsShimAssumedRoleUser,
    /// -1 if absent.
    pub packed_policy_size: i32,
    pub source_identity: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_assume_role(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimStsAssumeRoleInput,
    out: *mut *mut N00bAwsShimStsAssumeRoleOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || input.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };
    let inp = unsafe { &*input };

    let role_arn = match cstr_required(inp.role_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let role_session_name = match cstr_required(inp.role_session_name) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };

    let outcome = runtime().block_on(async {
        let client = StsClient::new(sdk_cfg);
        let mut b = client
            .assume_role()
            .role_arn(role_arn)
            .role_session_name(role_session_name);
        if inp.duration_seconds > 0 {
            b = b.duration_seconds(inp.duration_seconds);
        }
        if let Some(s) = cstr_optional(inp.external_id) {
            b = b.external_id(s);
        }
        if let Some(s) = cstr_optional(inp.serial_number) {
            b = b.serial_number(s);
        }
        if let Some(s) = cstr_optional(inp.token_code) {
            b = b.token_code(s);
        }
        if let Some(s) = cstr_optional(inp.policy) {
            b = b.policy(s);
        }
        if let Some(s) = cstr_optional(inp.source_identity) {
            b = b.source_identity(s);
        }
        for arn in collect_cstrs(inp.policy_arns, inp.policy_arns_count) {
            let pdt = PolicyDescriptorType::builder().arn(arn).build();
            b = b.policy_arns(pdt);
        }
        let keys = collect_cstrs(inp.session_tag_keys, inp.session_tags_count);
        let vals = collect_cstrs(inp.session_tag_values, inp.session_tags_count);
        if keys.len() == vals.len() {
            for (k, v) in keys.iter().zip(vals.iter()) {
                if let Ok(tag) = Tag::builder().key(k).value(v).build() {
                    b = b.tags(tag);
                }
            }
        }
        for k in collect_cstrs(inp.transitive_tag_keys, inp.transitive_tag_keys_count) {
            b = b.transitive_tag_keys(k);
        }
        b.send().await
    });

    match outcome {
        Ok(resp) => {
            let out_struct = N00bAwsShimStsAssumeRoleOutput {
                credentials: resp
                    .credentials()
                    .map(build_credentials)
                    .map(|c| Box::into_raw(Box::new(c)))
                    .unwrap_or(ptr::null_mut()),
                assumed_role_user: resp
                    .assumed_role_user()
                    .map(|u| N00bAwsShimAssumedRoleUser {
                        assumed_role_id: cstring_or_empty(Some(u.assumed_role_id())),
                        arn: cstring_or_empty(Some(u.arn())),
                    })
                    .map(|u| Box::into_raw(Box::new(u)))
                    .unwrap_or(ptr::null_mut()),
                packed_policy_size: resp.packed_policy_size().unwrap_or(-1),
                source_identity: cstring_or_empty(resp.source_identity()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(out_struct));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_assume_role_free(p: *mut N00bAwsShimStsAssumeRoleOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_credentials_ptr(boxed.credentials);
    free_assumed_role_user_ptr(boxed.assumed_role_user);
    free_cstring_ptr(boxed.source_identity);
}

/* =========================================================================
 * AssumeRoleWithWebIdentity — the IRSA mechanism on EKS.
 * =========================================================================
 */

#[repr(C)]
pub struct N00bAwsShimStsAssumeRoleWithWebIdentityInput {
    pub role_arn: *const c_char,
    pub role_session_name: *const c_char,
    pub web_identity_token: *const c_char,
    pub provider_id: *const c_char,
    pub policy: *const c_char,
    pub duration_seconds: i32,
    pub policy_arns: *const *const c_char,
    pub policy_arns_count: usize,
}

#[repr(C)]
pub struct N00bAwsShimStsAssumeRoleWithWebIdentityOutput {
    pub credentials: *mut N00bAwsShimAwsCredentials,
    pub assumed_role_user: *mut N00bAwsShimAssumedRoleUser,
    pub subject_from_web_identity: *mut c_char,
    pub provider: *mut c_char,
    pub audience: *mut c_char,
    pub source_identity: *mut c_char,
    pub packed_policy_size: i32,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_assume_role_with_web_identity(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimStsAssumeRoleWithWebIdentityInput,
    out: *mut *mut N00bAwsShimStsAssumeRoleWithWebIdentityOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || input.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };
    let inp = unsafe { &*input };

    let role_arn = cstr_required(inp.role_arn);
    let role_session_name = cstr_required(inp.role_session_name);
    let web_identity = cstr_required(inp.web_identity_token);
    if role_arn.is_none() || role_session_name.is_none() || web_identity.is_none() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }

    let outcome = runtime().block_on(async {
        let client = StsClient::new(sdk_cfg);
        let mut b = client
            .assume_role_with_web_identity()
            .role_arn(role_arn.unwrap())
            .role_session_name(role_session_name.unwrap())
            .web_identity_token(web_identity.unwrap());
        if let Some(s) = cstr_optional(inp.provider_id) {
            b = b.provider_id(s);
        }
        if let Some(s) = cstr_optional(inp.policy) {
            b = b.policy(s);
        }
        if inp.duration_seconds > 0 {
            b = b.duration_seconds(inp.duration_seconds);
        }
        for arn in collect_cstrs(inp.policy_arns, inp.policy_arns_count) {
            let pdt = PolicyDescriptorType::builder().arn(arn).build();
            b = b.policy_arns(pdt);
        }
        b.send().await
    });

    match outcome {
        Ok(resp) => {
            let out_struct = N00bAwsShimStsAssumeRoleWithWebIdentityOutput {
                credentials: resp
                    .credentials()
                    .map(build_credentials)
                    .map(|c| Box::into_raw(Box::new(c)))
                    .unwrap_or(ptr::null_mut()),
                assumed_role_user: resp
                    .assumed_role_user()
                    .map(|u| N00bAwsShimAssumedRoleUser {
                        assumed_role_id: cstring_or_empty(Some(u.assumed_role_id())),
                        arn: cstring_or_empty(Some(u.arn())),
                    })
                    .map(|u| Box::into_raw(Box::new(u)))
                    .unwrap_or(ptr::null_mut()),
                subject_from_web_identity: cstring_or_empty(resp.subject_from_web_identity_token()),
                provider: cstring_or_empty(resp.provider()),
                audience: cstring_or_empty(resp.audience()),
                source_identity: cstring_or_empty(resp.source_identity()),
                packed_policy_size: resp.packed_policy_size().unwrap_or(-1),
            };
            unsafe {
                *out = Box::into_raw(Box::new(out_struct));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_assume_role_with_web_identity_free(
    p: *mut N00bAwsShimStsAssumeRoleWithWebIdentityOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_credentials_ptr(boxed.credentials);
    free_assumed_role_user_ptr(boxed.assumed_role_user);
    free_cstring_ptr(boxed.subject_from_web_identity);
    free_cstring_ptr(boxed.provider);
    free_cstring_ptr(boxed.audience);
    free_cstring_ptr(boxed.source_identity);
}

/* =========================================================================
 * GetSessionToken
 * =========================================================================
 */

#[repr(C)]
pub struct N00bAwsShimStsGetSessionTokenOutput {
    pub credentials: *mut N00bAwsShimAwsCredentials,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_get_session_token(
    cfg: *const N00bAwsShimConfig,
    duration_seconds: i32, // 0 = SDK default
    serial_number: *const c_char,
    token_code: *const c_char,
    out: *mut *mut N00bAwsShimStsGetSessionTokenOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let client = StsClient::new(sdk_cfg);
        let mut b = client.get_session_token();
        if duration_seconds > 0 {
            b = b.duration_seconds(duration_seconds);
        }
        if let Some(s) = cstr_optional(serial_number) {
            b = b.serial_number(s);
        }
        if let Some(s) = cstr_optional(token_code) {
            b = b.token_code(s);
        }
        b.send().await
    });

    match outcome {
        Ok(resp) => {
            let out_struct = N00bAwsShimStsGetSessionTokenOutput {
                credentials: resp
                    .credentials()
                    .map(build_credentials)
                    .map(|c| Box::into_raw(Box::new(c)))
                    .unwrap_or(ptr::null_mut()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(out_struct));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_get_session_token_free(
    p: *mut N00bAwsShimStsGetSessionTokenOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_credentials_ptr(boxed.credentials);
}

/* =========================================================================
 * GetFederationToken
 * =========================================================================
 */

#[repr(C)]
pub struct N00bAwsShimStsGetFederationTokenInput {
    pub name: *const c_char,
    pub policy: *const c_char,
    pub duration_seconds: i32,
    pub policy_arns: *const *const c_char,
    pub policy_arns_count: usize,
    pub tag_keys: *const *const c_char,
    pub tag_values: *const *const c_char,
    pub tags_count: usize,
}

#[repr(C)]
pub struct N00bAwsShimStsGetFederationTokenOutput {
    pub credentials: *mut N00bAwsShimAwsCredentials,
    pub federated_user: *mut N00bAwsShimFederatedUser,
    pub packed_policy_size: i32,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_get_federation_token(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimStsGetFederationTokenInput,
    out: *mut *mut N00bAwsShimStsGetFederationTokenOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || input.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };
    let inp = unsafe { &*input };

    let name = match cstr_required(inp.name) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };

    let outcome = runtime().block_on(async {
        let client = StsClient::new(sdk_cfg);
        let mut b = client.get_federation_token().name(name);
        if let Some(s) = cstr_optional(inp.policy) {
            b = b.policy(s);
        }
        if inp.duration_seconds > 0 {
            b = b.duration_seconds(inp.duration_seconds);
        }
        for arn in collect_cstrs(inp.policy_arns, inp.policy_arns_count) {
            let pdt = PolicyDescriptorType::builder().arn(arn).build();
            b = b.policy_arns(pdt);
        }
        let keys = collect_cstrs(inp.tag_keys, inp.tags_count);
        let vals = collect_cstrs(inp.tag_values, inp.tags_count);
        if keys.len() == vals.len() {
            for (k, v) in keys.iter().zip(vals.iter()) {
                if let Ok(tag) = Tag::builder().key(k).value(v).build() {
                    b = b.tags(tag);
                }
            }
        }
        b.send().await
    });

    match outcome {
        Ok(resp) => {
            let out_struct = N00bAwsShimStsGetFederationTokenOutput {
                credentials: resp
                    .credentials()
                    .map(build_credentials)
                    .map(|c| Box::into_raw(Box::new(c)))
                    .unwrap_or(ptr::null_mut()),
                federated_user: resp
                    .federated_user()
                    .map(|u| N00bAwsShimFederatedUser {
                        federated_user_id: cstring_or_empty(Some(u.federated_user_id())),
                        arn: cstring_or_empty(Some(u.arn())),
                    })
                    .map(|u| Box::into_raw(Box::new(u)))
                    .unwrap_or(ptr::null_mut()),
                packed_policy_size: resp.packed_policy_size().unwrap_or(-1),
            };
            unsafe {
                *out = Box::into_raw(Box::new(out_struct));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_get_federation_token_free(
    p: *mut N00bAwsShimStsGetFederationTokenOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_credentials_ptr(boxed.credentials);
    free_federated_user_ptr(boxed.federated_user);
}

/* =========================================================================
 * DecodeAuthorizationMessage
 * =========================================================================
 */

#[repr(C)]
pub struct N00bAwsShimStsDecodedMessage {
    pub decoded_message: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_decode_authorization_message(
    cfg: *const N00bAwsShimConfig,
    encoded_message: *const c_char,
    out: *mut *mut N00bAwsShimStsDecodedMessage,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let encoded = match cstr_required(encoded_message) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        StsClient::new(sdk_cfg)
            .decode_authorization_message()
            .encoded_message(encoded)
            .send()
            .await
    });

    match outcome {
        Ok(resp) => {
            let out_struct = N00bAwsShimStsDecodedMessage {
                decoded_message: cstring_or_empty(resp.decoded_message()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(out_struct));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_decoded_message_free(p: *mut N00bAwsShimStsDecodedMessage) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.decoded_message);
}

/* =========================================================================
 * GetAccessKeyInfo
 * =========================================================================
 */

#[repr(C)]
pub struct N00bAwsShimStsAccessKeyInfo {
    pub account: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_get_access_key_info(
    cfg: *const N00bAwsShimConfig,
    access_key_id: *const c_char,
    out: *mut *mut N00bAwsShimStsAccessKeyInfo,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let id = match cstr_required(access_key_id) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        StsClient::new(sdk_cfg)
            .get_access_key_info()
            .access_key_id(id)
            .send()
            .await
    });

    match outcome {
        Ok(resp) => {
            let out_struct = N00bAwsShimStsAccessKeyInfo {
                account: cstring_or_empty(resp.account()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(out_struct));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_access_key_info_free(p: *mut N00bAwsShimStsAccessKeyInfo) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.account);
}

/* =========================================================================
 * AssumeRoleWithSAML
 * =========================================================================
 */

#[repr(C)]
pub struct N00bAwsShimStsAssumeRoleWithSamlInput {
    pub role_arn: *const c_char,
    pub principal_arn: *const c_char,
    pub saml_assertion: *const c_char,
    pub policy: *const c_char,
    pub duration_seconds: i32,
    pub policy_arns: *const *const c_char,
    pub policy_arns_count: usize,
}

#[repr(C)]
pub struct N00bAwsShimStsAssumeRoleWithSamlOutput {
    pub credentials: *mut N00bAwsShimAwsCredentials,
    pub assumed_role_user: *mut N00bAwsShimAssumedRoleUser,
    pub packed_policy_size: i32,
    pub subject: *mut c_char,
    pub subject_type: *mut c_char,
    pub issuer: *mut c_char,
    pub audience: *mut c_char,
    pub name_qualifier: *mut c_char,
    pub source_identity: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_assume_role_with_saml(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimStsAssumeRoleWithSamlInput,
    out: *mut *mut N00bAwsShimStsAssumeRoleWithSamlOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || input.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };
    let inp = unsafe { &*input };
    let role_arn = cstr_required(inp.role_arn);
    let principal_arn = cstr_required(inp.principal_arn);
    let saml_assertion = cstr_required(inp.saml_assertion);
    if role_arn.is_none() || principal_arn.is_none() || saml_assertion.is_none() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }

    let outcome = runtime().block_on(async {
        let client = StsClient::new(sdk_cfg);
        let mut b = client
            .assume_role_with_saml()
            .role_arn(role_arn.unwrap())
            .principal_arn(principal_arn.unwrap())
            .saml_assertion(saml_assertion.unwrap());
        if let Some(s) = cstr_optional(inp.policy) {
            b = b.policy(s);
        }
        if inp.duration_seconds > 0 {
            b = b.duration_seconds(inp.duration_seconds);
        }
        for arn in collect_cstrs(inp.policy_arns, inp.policy_arns_count) {
            let pdt = PolicyDescriptorType::builder().arn(arn).build();
            b = b.policy_arns(pdt);
        }
        b.send().await
    });

    match outcome {
        Ok(resp) => {
            let out_struct = N00bAwsShimStsAssumeRoleWithSamlOutput {
                credentials: resp
                    .credentials()
                    .map(build_credentials)
                    .map(|c| Box::into_raw(Box::new(c)))
                    .unwrap_or(ptr::null_mut()),
                assumed_role_user: resp
                    .assumed_role_user()
                    .map(|u| N00bAwsShimAssumedRoleUser {
                        assumed_role_id: cstring_or_empty(Some(u.assumed_role_id())),
                        arn: cstring_or_empty(Some(u.arn())),
                    })
                    .map(|u| Box::into_raw(Box::new(u)))
                    .unwrap_or(ptr::null_mut()),
                packed_policy_size: resp.packed_policy_size().unwrap_or(-1),
                subject: cstring_or_empty(resp.subject()),
                subject_type: cstring_or_empty(resp.subject_type()),
                issuer: cstring_or_empty(resp.issuer()),
                audience: cstring_or_empty(resp.audience()),
                name_qualifier: cstring_or_empty(resp.name_qualifier()),
                source_identity: cstring_or_empty(resp.source_identity()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(out_struct));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sts_assume_role_with_saml_free(
    p: *mut N00bAwsShimStsAssumeRoleWithSamlOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_credentials_ptr(boxed.credentials);
    free_assumed_role_user_ptr(boxed.assumed_role_user);
    free_cstring_ptr(boxed.subject);
    free_cstring_ptr(boxed.subject_type);
    free_cstring_ptr(boxed.issuer);
    free_cstring_ptr(boxed.audience);
    free_cstring_ptr(boxed.name_qualifier);
    free_cstring_ptr(boxed.source_identity);
}

/* =========================================================================
 * Shared helpers
 * =========================================================================
 */

fn build_credentials(c: &aws_sdk_sts::types::Credentials) -> N00bAwsShimAwsCredentials {
    N00bAwsShimAwsCredentials {
        access_key_id: cstring_or_empty(Some(c.access_key_id())),
        secret_access_key: cstring_or_empty(Some(c.secret_access_key())),
        session_token: cstring_or_empty(Some(c.session_token())),
        expiration_ms: c.expiration().to_millis().unwrap_or(-1),
    }
}

fn free_credentials_ptr(p: *mut N00bAwsShimAwsCredentials) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.access_key_id);
    free_cstring_ptr(boxed.secret_access_key);
    free_cstring_ptr(boxed.session_token);
}

fn free_assumed_role_user_ptr(p: *mut N00bAwsShimAssumedRoleUser) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.assumed_role_id);
    free_cstring_ptr(boxed.arn);
}

fn free_federated_user_ptr(p: *mut N00bAwsShimFederatedUser) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.federated_user_id);
    free_cstring_ptr(boxed.arn);
}

/// "absent" semantics: NULL or empty C string → None. Otherwise a
/// freshly-owned `String` copy of the caller's bytes.
fn cstr_optional(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    match unsafe { CStr::from_ptr(p) }.to_str() {
        Ok(s) if !s.is_empty() => Some(s.to_owned()),
        _ => None,
    }
}

/// Required input: NULL or empty C string → None (callers translate
/// to `ErrInvalidArg`). Non-empty → owned String copy.
fn cstr_required(p: *const c_char) -> Option<String> {
    cstr_optional(p)
}

/// Build a Vec<String> from a (pointer-array, count) pair. Skips
/// NULL / empty entries.
fn collect_cstrs(ptr: *const *const c_char, count: usize) -> Vec<String> {
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

fn cstring_or_empty(s: Option<&str>) -> *mut c_char {
    let text = s.unwrap_or("");
    match CString::new(text) {
        Ok(c) => c.into_raw(),
        Err(_) => CString::new("").unwrap().into_raw(),
    }
}

fn free_cstring_ptr(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

fn classify_sdk_error<E, R>(err: &aws_sdk_sts::error::SdkError<E, R>) -> N00bAwsShimStatus {
    use aws_sdk_sts::error::SdkError;
    match err {
        SdkError::ConstructionFailure(_) => N00bAwsShimStatus::ErrClient,
        SdkError::TimeoutError(_) => N00bAwsShimStatus::ErrTimeout,
        SdkError::DispatchFailure(_) => N00bAwsShimStatus::ErrNetwork,
        SdkError::ResponseError(_) => N00bAwsShimStatus::ErrService,
        SdkError::ServiceError(_) => N00bAwsShimStatus::ErrService,
        _ => N00bAwsShimStatus::ErrInternal,
    }
}
