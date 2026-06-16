//! DynamoDB wrappers — Phase 1 lays the foundation; Phases 2-5 fill
//! in the per-operation surface.  The pattern matches `sts.rs` /
//! `sqs.rs`:
//!
//!   * Each public Operation has a `#[no_mangle] extern "C" fn
//!     n00b_aws_shim_dynamodb_<op>(...)` that blocks on the shared
//!     tokio runtime, marshals inputs from C-friendly types into the
//!     SDK builder, and converts outputs into `#[repr(C)]` structs
//!     consumed by the libn00b_aws C wrap.
//!   * Each output struct that owns heap memory pairs with a
//!     `n00b_aws_shim_dynamodb_<thing>_free` entry; the libn00b GC
//!     finalizer calls that to release the Rust allocations after
//!     marshalling the data into n00b types.
//!   * Status codes come from `N00bAwsShimStatus` — every Operation
//!     funnels SDK errors through `classify_generic_sdk_error`.
//!
//! Phase 1 wraps `DescribeTable` end-to-end (production-quality —
//! not a stub).  The response models the canonical TableDescription
//! fields a downstream consumer (entitlements-svc / any DDB-touching
//! ncc service) cares about for both happy-path and not-found paths.
//!
//! Attribute-value handling: the tagged-union surface for attribute
//! values lives at the libn00b C layer (`include/aws/n00b_aws_dynamodb.h`).
//! `DescribeTable` does NOT return attribute values, so the shim's
//! Rust→C marshaling for that type is deferred to Phase 2's item
//! operations — at which point we add an `N00bAwsShimDdbAttribute`
//! repr(C) shape alongside the new operation wraps.

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use aws_sdk_dynamodb::Client as DdbClient;

use crate::config::N00bAwsShimConfig;
use crate::ffi_util::{classify_generic_sdk_error, cstring_from_string};
use crate::runtime::runtime;
use crate::N00bAwsShimStatus;

/* =========================================================================
 * Shared DescribeTable output types
 * ========================================================================= */

/// One element of a table's key schema (partition / sort).
///
/// `key_type` is the `KeyType` enum spelled as a C string —
/// canonical values are `"HASH"` (partition key) and `"RANGE"` (sort
/// key).  The shim returns the SDK's `as_str()` so future
/// `KeyType::Unknown(...)` variants would surface without code
/// changes.
#[repr(C)]
pub struct N00bAwsShimDdbKeySchemaElement {
    pub attribute_name: *mut c_char,
    pub key_type:       *mut c_char,
}

/// One element of a table's attribute-definition list.
///
/// `attribute_type` is `S`, `N`, or `B`.  Same `as_str()` rule as
/// `key_type` above.
#[repr(C)]
pub struct N00bAwsShimDdbAttributeDefinition {
    pub attribute_name: *mut c_char,
    pub attribute_type: *mut c_char,
}

/// Output of `DescribeTable`.
///
/// Modeled to cover the high-traffic TableDescription fields a
/// real consumer (the WP-034b entitlements-svc, etc.) needs.
/// Less-used fields (`LocalSecondaryIndexes`,
/// `GlobalSecondaryIndexes`, `StreamSpecification`, replication,
/// throughput metrics) are intentionally absent — Phase 4 extends
/// this struct (or adds sibling operations) as those features are
/// touched by real consumers.  Every field that's potentially
/// absent from the SDK response defaults to a sensible "absent"
/// value (`-1` for numeric, empty string for textual) so the C
/// wrap never needs to NULL-check inside a returned struct.
#[repr(C)]
pub struct N00bAwsShimDdbDescribeTableOutput {
    pub table_name:       *mut c_char,
    /// SDK's `TableStatus::as_str()` — `"ACTIVE"`, `"CREATING"`,
    /// `"DELETING"`, etc.
    pub table_status:     *mut c_char,
    /// Empty string when the SDK doesn't return an ARN (rare).
    pub table_arn:        *mut c_char,
    /// Empty string when absent.
    pub table_id:         *mut c_char,
    /// Bytes used by the table, or -1 if absent.
    pub table_size_bytes: i64,
    /// Approximate item count, or -1 if absent.
    pub item_count:       i64,
    /// Table creation time, unix-ms-since-epoch.  -1 if absent.
    pub creation_ms:      i64,
    /// `"PROVISIONED"` / `"PAY_PER_REQUEST"` / `""` if absent.
    pub billing_mode:     *mut c_char,
    /// 1 if deletion-protection is on, 0 if off, -1 if absent.
    pub deletion_protection_enabled: i32,
    /// SSE description's `Status` field as a string, or empty.
    pub sse_status:       *mut c_char,
    /// `KeySchema` array (owned by the output, freed in `_free`).
    pub key_schema:        *mut N00bAwsShimDdbKeySchemaElement,
    pub key_schema_count:  usize,
    /// `AttributeDefinitions` array.
    pub attribute_definitions:        *mut N00bAwsShimDdbAttributeDefinition,
    pub attribute_definitions_count:  usize,
}

/* =========================================================================
 * DescribeTable
 * =========================================================================
 */

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_describe_table(
    cfg:        *const N00bAwsShimConfig,
    table_name: *const c_char,
    out:        *mut *mut N00bAwsShimDdbDescribeTableOutput,
) -> i32 {
    if !out.is_null() {
        unsafe { *out = ptr::null_mut(); }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let name = match cstr_required(table_name) {
        Some(s) => s,
        None    => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        DdbClient::new(sdk_cfg)
            .describe_table()
            .table_name(name)
            .send()
            .await
    });

    match outcome {
        Ok(resp) => {
            let table = match resp.table {
                Some(t) => t,
                None    => return N00bAwsShimStatus::ErrService.as_i32(),
            };

            /* Key schema. */
            let ks_slice: &[aws_sdk_dynamodb::types::KeySchemaElement]
                = table.key_schema.as_deref().unwrap_or(&[]);
            let (ks_ptr, ks_count) = build_key_schema(ks_slice);

            /* Attribute definitions. */
            let ad_slice: &[aws_sdk_dynamodb::types::AttributeDefinition]
                = table.attribute_definitions.as_deref().unwrap_or(&[]);
            let (ad_ptr, ad_count) = build_attribute_definitions(ad_slice);

            let creation_ms = table
                .creation_date_time
                .and_then(|dt| dt.to_millis().ok())
                .unwrap_or(-1);

            let billing_mode = table
                .billing_mode_summary
                .as_ref()
                .and_then(|s| s.billing_mode.as_ref())
                .map(|b| b.as_str().to_owned())
                .unwrap_or_default();

            let sse_status = table
                .sse_description
                .as_ref()
                .and_then(|s| s.status.as_ref())
                .map(|s| s.as_str().to_owned())
                .unwrap_or_default();

            /* `deletion_protection_enabled` is an `Option<bool>` —
             * surface "absent" as -1 to distinguish from explicit
             * false. */
            let dpe = match table.deletion_protection_enabled {
                Some(true)  => 1,
                Some(false) => 0,
                None        => -1,
            };

            let table_name_s   = table.table_name.unwrap_or_default();
            let table_status_s = table
                .table_status
                .map(|s| s.as_str().to_owned())
                .unwrap_or_default();
            let table_arn_s    = table.table_arn.unwrap_or_default();
            let table_id_s     = table.table_id.unwrap_or_default();

            /* `table_size_bytes` / `item_count` are
             * `Option<i64>`.  Map None → -1 so the C wrap can
             * distinguish "absent" from "zero". */
            let table_size_bytes = table.table_size_bytes.unwrap_or(-1);
            let item_count       = table.item_count.unwrap_or(-1);

            let out_struct = N00bAwsShimDdbDescribeTableOutput {
                table_name:                  cstring_from_string(table_name_s),
                table_status:                cstring_from_string(table_status_s),
                table_arn:                   cstring_from_string(table_arn_s),
                table_id:                    cstring_from_string(table_id_s),
                table_size_bytes,
                item_count,
                creation_ms,
                billing_mode:                cstring_from_string(billing_mode),
                deletion_protection_enabled: dpe,
                sse_status:                  cstring_from_string(sse_status),
                key_schema:                  ks_ptr,
                key_schema_count:            ks_count,
                attribute_definitions:       ad_ptr,
                attribute_definitions_count: ad_count,
            };

            unsafe { *out = Box::into_raw(Box::new(out_struct)); }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_dynamodb_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_describe_table_free(
    p: *mut N00bAwsShimDdbDescribeTableOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring(boxed.table_name);
    free_cstring(boxed.table_status);
    free_cstring(boxed.table_arn);
    free_cstring(boxed.table_id);
    free_cstring(boxed.billing_mode);
    free_cstring(boxed.sse_status);
    free_key_schema(boxed.key_schema, boxed.key_schema_count);
    free_attribute_definitions(
        boxed.attribute_definitions, boxed.attribute_definitions_count);
}

/* =========================================================================
 * DynamoDB-specific error classification
 *
 * `classify_generic_sdk_error` handles the transport-level variants;
 * here we look one level deeper at DDB's modeled errors so the
 * caller can distinguish "not found" from "service error".
 * =========================================================================
 */

fn classify_dynamodb_error<E, R>(
    err: &aws_smithy_runtime_api::client::result::SdkError<E, R>,
) -> N00bAwsShimStatus
where E: std::fmt::Debug,
{
    use aws_smithy_runtime_api::client::result::SdkError;
    if let SdkError::ServiceError(svc) = err {
        let msg = format!("{:?}", svc.err());
        if msg.contains("ResourceNotFoundException") {
            return N00bAwsShimStatus::ErrNotFound;
        }
        if msg.contains("ProvisionedThroughputExceededException")
            || msg.contains("ThrottlingException")
            || msg.contains("RequestLimitExceeded")
        {
            return N00bAwsShimStatus::ErrThrottled;
        }
        if msg.contains("AccessDeniedException") {
            return N00bAwsShimStatus::ErrAuthz;
        }
        if msg.contains("ValidationException") {
            return N00bAwsShimStatus::ErrInvalidArg;
        }
    }
    classify_generic_sdk_error(err)
}

/* =========================================================================
 * Helpers — kept local so the file is self-contained.
 * =========================================================================
 */

fn build_key_schema(
    items: &[aws_sdk_dynamodb::types::KeySchemaElement],
) -> (*mut N00bAwsShimDdbKeySchemaElement, usize) {
    if items.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let v: Vec<N00bAwsShimDdbKeySchemaElement> = items
        .iter()
        .map(|k| N00bAwsShimDdbKeySchemaElement {
            attribute_name: cstring_from_string(k.attribute_name().to_owned()),
            key_type:       cstring_from_string(k.key_type().as_str().to_owned()),
        })
        .collect();
    let len   = v.len();
    let boxed = v.into_boxed_slice();
    let raw   = Box::into_raw(boxed) as *mut N00bAwsShimDdbKeySchemaElement;
    (raw, len)
}

fn free_key_schema(
    p:     *mut N00bAwsShimDdbKeySchemaElement,
    count: usize,
) {
    if p.is_null() || count == 0 {
        return;
    }
    /* Reconstruct the boxed slice for the array's own deallocation,
     * but first walk the elements to free their owned cstrings. */
    let slice = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for el in slice.iter_mut() {
        free_cstring(el.attribute_name);
        free_cstring(el.key_type);
        el.attribute_name = ptr::null_mut();
        el.key_type       = ptr::null_mut();
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, count)));
    }
}

fn build_attribute_definitions(
    items: &[aws_sdk_dynamodb::types::AttributeDefinition],
) -> (*mut N00bAwsShimDdbAttributeDefinition, usize) {
    if items.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let v: Vec<N00bAwsShimDdbAttributeDefinition> = items
        .iter()
        .map(|a| N00bAwsShimDdbAttributeDefinition {
            attribute_name: cstring_from_string(a.attribute_name().to_owned()),
            attribute_type: cstring_from_string(a.attribute_type().as_str().to_owned()),
        })
        .collect();
    let len = v.len();
    let boxed: Box<[N00bAwsShimDdbAttributeDefinition]> = v.into_boxed_slice();
    let raw  = Box::into_raw(boxed) as *mut N00bAwsShimDdbAttributeDefinition;
    (raw, len)
}

fn free_attribute_definitions(
    p:     *mut N00bAwsShimDdbAttributeDefinition,
    count: usize,
) {
    if p.is_null() || count == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for el in slice.iter_mut() {
        free_cstring(el.attribute_name);
        free_cstring(el.attribute_type);
        el.attribute_name = ptr::null_mut();
        el.attribute_type = ptr::null_mut();
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, count)));
    }
}

fn free_cstring(p: *mut c_char) {
    if !p.is_null() {
        unsafe { drop(CString::from_raw(p)); }
    }
}

fn cstr_required(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    match unsafe { CStr::from_ptr(p) }.to_str() {
        Ok(s) if !s.is_empty() => Some(s.to_owned()),
        _                      => None,
    }
}
