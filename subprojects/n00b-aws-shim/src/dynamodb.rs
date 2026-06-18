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

use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::ptr;

use aws_sdk_dynamodb::types::AttributeValue;
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
        if msg.contains("ConditionalCheckFailedException") {
            // The caller's condition expression evaluated false — the
            // common "put-if-absent" / optimistic-concurrency signal.
            return N00bAwsShimStatus::ErrExists;
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

/* =========================================================================
 * Phase 2 — item operations (GetItem / PutItem / Query / DeleteItem /
 * UpdateItem)
 *
 * The libn00b C layer owns the rich tagged-union attribute-value surface
 * (`n00b_aws_ddb_value_t`, S/N/B/BOOL/NULL/M/L/SS/NS/BS).  At the FFI
 * boundary we marshal that into a FLAT array of `N00bAwsShimDdbAttribute`
 * records — one per item key.  Each record names the attribute and
 * carries exactly one populated value slot, discriminated by `attr_type`
 * (an i32 spelled to match the C `n00b_aws_ddb_attr_type_t` enum).
 *
 * Scalar coverage (S / N / B / BOOL / NULL) is full — those are what the
 * crayon-config / JWK item store needs and what every key + simple value
 * uses.  The collection variants (M / L / SS / NS / BS) are an explicit,
 * documented TODO: they need a recursive / nested marshaling shape that
 * no current consumer exercises.  An item that contains one is rejected
 * with `ErrInvalidArg` rather than silently dropped, so a future caller
 * gets a hard signal instead of corrupted data.
 * ========================================================================= */

/* attr_type discriminants — must match n00b_aws_ddb_attr_type_t in
 * include/aws/n00b_aws_dynamodb.h. */
const DDB_TYPE_S: i32 = 1;
const DDB_TYPE_N: i32 = 2;
const DDB_TYPE_B: i32 = 3;
const DDB_TYPE_BOOL: i32 = 4;
const DDB_TYPE_NULL: i32 = 5;
const DDB_TYPE_M: i32 = 6;
const DDB_TYPE_L: i32 = 7;
const DDB_TYPE_SS: i32 = 8;
const DDB_TYPE_NS: i32 = 9;
const DDB_TYPE_BS: i32 = 10;

/// One attribute of a DynamoDB item, flattened for the C boundary.
///
/// Exactly one value slot is meaningful, selected by `attr_type`:
///   * `S` / `N` → `s_or_n` (NUL-terminated text; for `N` it is the
///     canonical textual number the SDK uses).
///   * `B`       → `b` + `b_len` (raw bytes; not NUL-terminated).
///   * `BOOL`    → `bool_val` (0 / 1).
///   * `NULL`    → no slot populated.
///
/// All unused pointer slots are NULL and `b_len` / `bool_val` are 0.
/// Records flowing C→Rust (inputs) and Rust→C (outputs) share this
/// shape; the matching `_free` walks an array of these and releases the
/// `name`, `s_or_n`, and `b` allocations it owns.
#[repr(C)]
pub struct N00bAwsShimDdbAttribute {
    pub name:     *mut c_char,
    pub attr_type: i32,
    pub s_or_n:   *mut c_char,
    pub b:        *mut u8,
    pub b_len:    usize,
    pub bool_val: i32,
}

/* ---- input marshaling: C array → SDK AttributeValue map -------------- */

/// Convert one inbound C record into an SDK `AttributeValue`.
/// Returns None for an unsupported (collection) variant or a malformed
/// record so the caller can fail the whole op with ErrInvalidArg.
fn attr_in_to_sdk(rec: &N00bAwsShimDdbAttribute) -> Option<AttributeValue> {
    match rec.attr_type {
        DDB_TYPE_S => cstr_to_string(rec.s_or_n).map(AttributeValue::S),
        DDB_TYPE_N => cstr_to_string(rec.s_or_n).map(AttributeValue::N),
        DDB_TYPE_B => {
            // A null pointer with a nonzero length is a malformed record;
            // fail the whole op rather than silently writing an empty Blob.
            if rec.b.is_null() && rec.b_len > 0 {
                return None;
            }
            let bytes = bytes_from_raw(rec.b, rec.b_len);
            Some(AttributeValue::B(aws_smithy_types::Blob::new(bytes)))
        }
        DDB_TYPE_BOOL => Some(AttributeValue::Bool(rec.bool_val != 0)),
        DDB_TYPE_NULL => Some(AttributeValue::Null(true)),
        // Collection variants are a documented TODO — reject loudly.
        DDB_TYPE_M | DDB_TYPE_L | DDB_TYPE_SS | DDB_TYPE_NS | DDB_TYPE_BS => None,
        _ => None,
    }
}

/// Build an SDK item map from a flat C array. Returns None if the array
/// is malformed (missing name) or carries an unsupported variant.
fn build_item_map(
    attrs: *const N00bAwsShimDdbAttribute,
    count: usize,
) -> Option<HashMap<String, AttributeValue>> {
    let mut map = HashMap::with_capacity(count);
    if count == 0 {
        return Some(map);
    }
    if attrs.is_null() {
        return None;
    }
    let slice = unsafe { core::slice::from_raw_parts(attrs, count) };
    for rec in slice {
        let name = cstr_to_string(rec.name)?;
        let val = attr_in_to_sdk(rec)?;
        map.insert(name, val);
    }
    Some(map)
}

/* ---- output marshaling: SDK AttributeValue map → C array ------------- */

/// Convert one SDK `AttributeValue` into an outbound C record body.
/// Collection variants surface as `NULL` (documented TODO) so a returned
/// item is never silently mis-typed — a downstream that needs nested
/// values will see `NULL` rather than a wrong scalar.
fn attr_out_from_sdk(name: &str, v: &AttributeValue) -> N00bAwsShimDdbAttribute {
    let mut rec = N00bAwsShimDdbAttribute {
        name:      cstring_from_string(name.to_owned()),
        attr_type: DDB_TYPE_NULL,
        s_or_n:    ptr::null_mut(),
        b:         ptr::null_mut(),
        b_len:     0,
        bool_val:  0,
    };
    match v {
        AttributeValue::S(s) => {
            rec.attr_type = DDB_TYPE_S;
            rec.s_or_n = cstring_from_string(s.clone());
        }
        AttributeValue::N(n) => {
            rec.attr_type = DDB_TYPE_N;
            rec.s_or_n = cstring_from_string(n.clone());
        }
        AttributeValue::B(blob) => {
            rec.attr_type = DDB_TYPE_B;
            let (ptr, len) = bytes_into_raw(blob.as_ref());
            rec.b = ptr;
            rec.b_len = len;
        }
        AttributeValue::Bool(b) => {
            rec.attr_type = DDB_TYPE_BOOL;
            rec.bool_val = if *b { 1 } else { 0 };
        }
        AttributeValue::Null(_) => {
            rec.attr_type = DDB_TYPE_NULL;
        }
        // Collection variants: documented TODO; surface as NULL.
        _ => {
            rec.attr_type = DDB_TYPE_NULL;
        }
    }
    rec
}

/// Build a `(ptr, count)` C array from an SDK item map.
fn item_map_to_array(
    map: &HashMap<String, AttributeValue>,
) -> (*mut N00bAwsShimDdbAttribute, usize) {
    if map.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let v: Vec<N00bAwsShimDdbAttribute> = map
        .iter()
        .map(|(k, val)| attr_out_from_sdk(k, val))
        .collect();
    let len = v.len();
    let raw = Box::into_raw(v.into_boxed_slice()) as *mut N00bAwsShimDdbAttribute;
    (raw, len)
}

fn free_attr_array(p: *mut N00bAwsShimDdbAttribute, count: usize) {
    if p.is_null() || count == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for el in slice.iter_mut() {
        free_cstring(el.name);
        free_cstring(el.s_or_n);
        free_bytes(el.b, el.b_len);
        el.name   = ptr::null_mut();
        el.s_or_n = ptr::null_mut();
        el.b      = ptr::null_mut();
        el.b_len  = 0;
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, count)));
    }
}

/* small byte/string helpers local to item ops */

fn cstr_to_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(|s| s.to_owned())
}

fn bytes_from_raw(p: *const u8, len: usize) -> Vec<u8> {
    if p.is_null() || len == 0 {
        return Vec::new();
    }
    unsafe { core::slice::from_raw_parts(p, len) }.to_vec()
}

fn bytes_into_raw(bytes: &[u8]) -> (*mut u8, usize) {
    if bytes.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let boxed: Box<[u8]> = bytes.to_vec().into_boxed_slice();
    let len = boxed.len();
    let raw = Box::into_raw(boxed) as *mut u8;
    (raw, len)
}

fn free_bytes(p: *mut u8, len: usize) {
    if p.is_null() || len == 0 {
        return;
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, len)));
    }
}

/* =========================================================================
 * GetItem
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimDdbGetItemOutput {
    pub item:       *mut N00bAwsShimDdbAttribute,
    pub item_count: usize,
    /// 1 when the item was present, 0 when absent.
    pub found:      i32,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_get_item(
    cfg:             *const N00bAwsShimConfig,
    table_name:      *const c_char,
    key:             *const N00bAwsShimDdbAttribute,
    key_count:       usize,
    consistent_read: i32,
    out:             *mut *mut N00bAwsShimDdbGetItemOutput,
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
    let key_map = match build_item_map(key, key_count) {
        Some(m) if !m.is_empty() => m,
        _ => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        DdbClient::new(sdk_cfg)
            .get_item()
            .table_name(name)
            .set_key(Some(key_map))
            .consistent_read(consistent_read != 0)
            .send()
            .await
    });

    match outcome {
        Ok(resp) => {
            let (item_ptr, item_count, found) = match resp.item {
                Some(m) if !m.is_empty() => {
                    let (p, c) = item_map_to_array(&m);
                    (p, c, 1)
                }
                _ => (ptr::null_mut(), 0, 0),
            };
            let out_struct = N00bAwsShimDdbGetItemOutput {
                item: item_ptr,
                item_count,
                found,
            };
            unsafe { *out = Box::into_raw(Box::new(out_struct)); }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_dynamodb_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_get_item_free(
    p: *mut N00bAwsShimDdbGetItemOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_attr_array(boxed.item, boxed.item_count);
}

/* =========================================================================
 * PutItem
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimDdbPutItemOutput {
    pub ok: i32,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_put_item(
    cfg:                  *const N00bAwsShimConfig,
    table_name:           *const c_char,
    item:                 *const N00bAwsShimDdbAttribute,
    item_count:           usize,
    condition_expression: *const c_char,
    out:                  *mut *mut N00bAwsShimDdbPutItemOutput,
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
    let item_map = match build_item_map(item, item_count) {
        Some(m) if !m.is_empty() => m,
        _ => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let cond = cstr_to_string(condition_expression);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = DdbClient::new(sdk_cfg)
            .put_item()
            .table_name(name)
            .set_item(Some(item_map));
        if let Some(c) = cond {
            b = b.condition_expression(c);
        }
        b.send().await
    });

    match outcome {
        Ok(_) => {
            let out_struct = N00bAwsShimDdbPutItemOutput { ok: 1 };
            unsafe { *out = Box::into_raw(Box::new(out_struct)); }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_dynamodb_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_put_item_free(
    p: *mut N00bAwsShimDdbPutItemOutput,
) {
    if p.is_null() {
        return;
    }
    let _boxed = unsafe { Box::from_raw(p) };
}

/* =========================================================================
 * DeleteItem
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimDdbDeleteItemOutput {
    pub ok: i32,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_delete_item(
    cfg:                  *const N00bAwsShimConfig,
    table_name:           *const c_char,
    key:                  *const N00bAwsShimDdbAttribute,
    key_count:            usize,
    condition_expression: *const c_char,
    out:                  *mut *mut N00bAwsShimDdbDeleteItemOutput,
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
    let key_map = match build_item_map(key, key_count) {
        Some(m) if !m.is_empty() => m,
        _ => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let cond = cstr_to_string(condition_expression);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = DdbClient::new(sdk_cfg)
            .delete_item()
            .table_name(name)
            .set_key(Some(key_map));
        if let Some(c) = cond {
            b = b.condition_expression(c);
        }
        b.send().await
    });

    match outcome {
        Ok(_) => {
            let out_struct = N00bAwsShimDdbDeleteItemOutput { ok: 1 };
            unsafe { *out = Box::into_raw(Box::new(out_struct)); }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_dynamodb_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_delete_item_free(
    p: *mut N00bAwsShimDdbDeleteItemOutput,
) {
    if p.is_null() {
        return;
    }
    let _boxed = unsafe { Box::from_raw(p) };
}

/* =========================================================================
 * UpdateItem
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimDdbUpdateItemOutput {
    pub ok: i32,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_update_item(
    cfg:                  *const N00bAwsShimConfig,
    table_name:           *const c_char,
    key:                  *const N00bAwsShimDdbAttribute,
    key_count:            usize,
    update_expression:    *const c_char,
    values:               *const N00bAwsShimDdbAttribute,
    values_count:         usize,
    condition_expression: *const c_char,
    out:                  *mut *mut N00bAwsShimDdbUpdateItemOutput,
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
    let update_expr = match cstr_required(update_expression) {
        Some(s) => s,
        None    => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key_map = match build_item_map(key, key_count) {
        Some(m) if !m.is_empty() => m,
        _ => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    // Expression-attribute values are optional; an empty/absent set is
    // fine for SET expressions that reference no placeholders.  A
    // non-empty array that fails to marshal is a hard error.
    let value_map = if values_count == 0 {
        None
    } else {
        match build_item_map(values, values_count) {
            Some(m) => Some(m),
            None    => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
        }
    };
    let cond = cstr_to_string(condition_expression);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = DdbClient::new(sdk_cfg)
            .update_item()
            .table_name(name)
            .set_key(Some(key_map))
            .update_expression(update_expr);
        if let Some(m) = value_map {
            b = b.set_expression_attribute_values(Some(m));
        }
        if let Some(c) = cond {
            b = b.condition_expression(c);
        }
        b.send().await
    });

    match outcome {
        Ok(_) => {
            let out_struct = N00bAwsShimDdbUpdateItemOutput { ok: 1 };
            unsafe { *out = Box::into_raw(Box::new(out_struct)); }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_dynamodb_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_update_item_free(
    p: *mut N00bAwsShimDdbUpdateItemOutput,
) {
    if p.is_null() {
        return;
    }
    let _boxed = unsafe { Box::from_raw(p) };
}

/* =========================================================================
 * Query
 *
 * Returns a list of items.  Each item is itself a flat
 * `N00bAwsShimDdbAttribute` array; the outer output owns a contiguous
 * array of (ptr,count) descriptors plus the optional last-evaluated-key
 * for pagination.
 * ========================================================================= */

/// One returned item: a flat attribute array.
#[repr(C)]
pub struct N00bAwsShimDdbItem {
    pub attrs:       *mut N00bAwsShimDdbAttribute,
    pub attrs_count: usize,
}

#[repr(C)]
pub struct N00bAwsShimDdbQueryOutput {
    pub items:       *mut N00bAwsShimDdbItem,
    pub items_count: usize,
    /// DynamoDB's `Count` (matched items), -1 if absent.
    pub count:       i64,
    /// LastEvaluatedKey as a flat attribute array; NULL/0 when the query
    /// is fully drained (no more pages).
    pub last_key:        *mut N00bAwsShimDdbAttribute,
    pub last_key_count:  usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_query(
    cfg:                     *const N00bAwsShimConfig,
    table_name:              *const c_char,
    key_condition_expression:*const c_char,
    expression_values:       *const N00bAwsShimDdbAttribute,
    expression_values_count: usize,
    index_name:              *const c_char,
    exclusive_start_key:     *const N00bAwsShimDdbAttribute,
    exclusive_start_key_count: usize,
    limit:                   i64,
    out:                     *mut *mut N00bAwsShimDdbQueryOutput,
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
    let kce = match cstr_required(key_condition_expression) {
        Some(s) => s,
        None    => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let value_map = if expression_values_count == 0 {
        None
    } else {
        match build_item_map(expression_values, expression_values_count) {
            Some(m) => Some(m),
            None    => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
        }
    };
    let start_key = if exclusive_start_key_count == 0 {
        None
    } else {
        match build_item_map(exclusive_start_key, exclusive_start_key_count) {
            Some(m) => Some(m),
            None    => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
        }
    };
    let index = cstr_to_string(index_name);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = DdbClient::new(sdk_cfg)
            .query()
            .table_name(name)
            .key_condition_expression(kce);
        if let Some(m) = value_map {
            b = b.set_expression_attribute_values(Some(m));
        }
        if let Some(i) = index {
            b = b.index_name(i);
        }
        if let Some(k) = start_key {
            b = b.set_exclusive_start_key(Some(k));
        }
        if limit > 0 {
            // The SDK's limit is i32; narrow without wrapping.  Values
            // beyond i32::MAX are nonsensical for a DDB page (the
            // service caps a page at 1 MB ~= a few thousand items), so
            // saturate rather than truncate.
            let lim = i32::try_from(limit).unwrap_or(i32::MAX);
            b = b.limit(lim);
        }
        b.send().await
    });

    match outcome {
        Ok(resp) => {
            let (items_ptr, items_count) = build_item_list(resp.items());
            let (lk_ptr, lk_count) = match resp.last_evaluated_key() {
                Some(m) if !m.is_empty() => item_map_to_array(m),
                _ => (ptr::null_mut(), 0),
            };
            let out_struct = N00bAwsShimDdbQueryOutput {
                items:          items_ptr,
                items_count,
                count:          resp.count() as i64,
                last_key:       lk_ptr,
                last_key_count: lk_count,
            };
            unsafe { *out = Box::into_raw(Box::new(out_struct)); }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_dynamodb_error(&e).as_i32(),
    }
}

fn build_item_list(
    items: &[HashMap<String, AttributeValue>],
) -> (*mut N00bAwsShimDdbItem, usize) {
    if items.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let v: Vec<N00bAwsShimDdbItem> = items
        .iter()
        .map(|m| {
            let (p, c) = item_map_to_array(m);
            N00bAwsShimDdbItem { attrs: p, attrs_count: c }
        })
        .collect();
    let len = v.len();
    let raw = Box::into_raw(v.into_boxed_slice()) as *mut N00bAwsShimDdbItem;
    (raw, len)
}

fn free_item_list(p: *mut N00bAwsShimDdbItem, count: usize) {
    if p.is_null() || count == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for el in slice.iter_mut() {
        free_attr_array(el.attrs, el.attrs_count);
        el.attrs = ptr::null_mut();
        el.attrs_count = 0;
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, count)));
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_dynamodb_query_free(
    p: *mut N00bAwsShimDdbQueryOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_item_list(boxed.items, boxed.items_count);
    free_attr_array(boxed.last_key, boxed.last_key_count);
}
