//! S3 wrappers consumed by libn00b_aws and the S3 VFS adapter.

use std::ffi::c_char;
use std::ptr;

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::Client as S3Client;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_runtime_api::http::Response as SmithyResponse;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;

use crate::config::N00bAwsShimConfig;
use crate::ffi_util::*;
use crate::runtime::runtime;
use crate::N00bAwsShimStatus;

/// Opaque S3 client handle. It owns an aws-sdk-rust S3 client configured from
/// the libn00b_aws shared `SdkConfig`.
pub struct N00bAwsShimS3Client {
    inner: S3Client,
}

#[repr(C)]
pub struct N00bAwsShimS3Object {
    pub data: *mut u8,
    pub data_len: usize,
    pub content_length: u64,
    pub last_modified_ms: i64,
    pub etag: *mut c_char,
    pub content_type: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimS3Stat {
    pub content_length: u64,
    pub last_modified_ms: i64,
    pub etag: *mut c_char,
    pub content_type: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimS3ListEntry {
    pub key: *mut c_char,
    pub size: u64,
    pub last_modified_ms: i64,
    pub etag: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimS3ListOutput {
    pub entries: *mut N00bAwsShimS3ListEntry,
    pub entries_count: usize,
    pub continuation: *mut c_char,
    pub truncated: bool,
}

#[repr(C)]
pub struct N00bAwsShimS3MultipartCreateOutput {
    pub upload_id: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimS3CompletedPart {
    pub part_number: i32,
    pub etag: *mut c_char,
}

fn datetime_millis<T>(dt: Option<&T>) -> i64
where
    T: S3DateTime,
{
    dt.and_then(|d| d.to_millis_ok()).unwrap_or(0)
}

trait S3DateTime {
    fn to_millis_ok(&self) -> Option<i64>;
}

impl S3DateTime for aws_smithy_types::DateTime {
    fn to_millis_ok(&self) -> Option<i64> {
        self.to_millis().ok()
    }
}

fn i64_to_u64(n: i64) -> u64 {
    if n < 0 {
        0
    } else {
        n as u64
    }
}

fn vec_to_bytes(data: Vec<u8>) -> (*mut u8, usize) {
    if data.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let len = data.len();
    let boxed = data.into_boxed_slice();
    let p = Box::into_raw(boxed) as *mut u8;
    (p, len)
}

fn raw_bytes(data: *const u8, data_len: usize) -> Option<Vec<u8>> {
    if data.is_null() {
        return if data_len == 0 {
            Some(Vec::new())
        } else {
            None
        };
    }
    Some(unsafe { core::slice::from_raw_parts(data, data_len) }.to_vec())
}

fn free_bytes(p: *mut u8, len: usize) {
    if p.is_null() || len == 0 {
        return;
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, len)));
    }
}

fn classify_s3_sdk_error<E>(err: &SdkError<E, SmithyResponse>) -> N00bAwsShimStatus
where
    E: ProvideErrorMetadata,
{
    let meta = err.meta();
    match meta.code() {
        Some("PreconditionFailed" | "ConditionalRequestConflict") => {
            return N00bAwsShimStatus::ErrExists;
        }
        Some(
            "NoSuchKey"
            | "NoSuchBucket"
            | "NotFound"
            | "NotFoundException"
            | "ResourceNotFoundException",
        ) => {
            return N00bAwsShimStatus::ErrNotFound;
        }
        Some("AccessDenied" | "Forbidden" | "InvalidAccessKeyId" | "SignatureDoesNotMatch") => {
            return N00bAwsShimStatus::ErrAuthz;
        }
        Some("SlowDown" | "Throttling" | "ThrottlingException" | "TooManyRequestsException") => {
            return N00bAwsShimStatus::ErrThrottled;
        }
        _ => {}
    }

    if let Some(raw) = err.raw_response() {
        match raw.status().as_u16() {
            404 => return N00bAwsShimStatus::ErrNotFound,
            403 => return N00bAwsShimStatus::ErrAuthz,
            409 | 412 => return N00bAwsShimStatus::ErrExists,
            429 => return N00bAwsShimStatus::ErrThrottled,
            _ => {}
        }
    }

    classify_generic_sdk_error(err)
}

fn object_output(
    data: Vec<u8>,
    content_length: u64,
    last_modified_ms: i64,
    etag: Option<&str>,
    content_type: Option<&str>,
) -> N00bAwsShimS3Object {
    let (data, data_len) = vec_to_bytes(data);
    N00bAwsShimS3Object {
        data,
        data_len,
        content_length,
        last_modified_ms,
        etag: cstring_or_empty(etag),
        content_type: cstring_or_empty(content_type),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_client_new(
    cfg: *const N00bAwsShimConfig,
    force_path_style: bool,
) -> *mut N00bAwsShimS3Client {
    if cfg.is_null() {
        return ptr::null_mut();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };
    let conf = aws_sdk_s3::config::Builder::from(sdk_cfg)
        .force_path_style(force_path_style)
        .build();
    Box::into_raw(Box::new(N00bAwsShimS3Client {
        inner: S3Client::from_conf(conf),
    }))
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_client_free(client: *mut N00bAwsShimS3Client) {
    if !client.is_null() {
        unsafe {
            drop(Box::from_raw(client));
        }
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_get_object(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    out: *mut *mut N00bAwsShimS3Object,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if client.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let c = unsafe { &(*client).inner };

    let result = runtime().block_on(async {
        match c.get_object().bucket(bucket).key(key).send().await {
            Ok(r) => {
                let content_length = r.content_length().map(i64_to_u64);
                let last_modified_ms = datetime_millis(r.last_modified());
                let etag = r.e_tag().map(String::from);
                let content_type = r.content_type().map(String::from);
                match r.body.collect().await {
                    Ok(bytes) => {
                        let data = bytes.into_bytes().to_vec();
                        let data_len = data.len() as u64;
                        Ok(object_output(
                            data,
                            content_length.unwrap_or(data_len),
                            last_modified_ms,
                            etag.as_deref(),
                            content_type.as_deref(),
                        ))
                    }
                    Err(_) => Err(N00bAwsShimStatus::ErrNetwork),
                }
            }
            Err(e) => Err(classify_s3_sdk_error(&e)),
        }
    });

    match result {
        Ok(obj) => {
            unsafe {
                *out = Box::into_raw(Box::new(obj));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(status) => status.as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_get_object_range(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    offset: u64,
    length: u64,
    out: *mut *mut N00bAwsShimS3Object,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if client.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    if length == 0 {
        let obj = object_output(Vec::new(), 0, 0, None, None);
        unsafe {
            *out = Box::into_raw(Box::new(obj));
        }
        return N00bAwsShimStatus::Ok.as_i32();
    }
    let Some(end) = offset.checked_add(length - 1) else {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    };
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let range = format!("bytes={offset}-{end}");
    let c = unsafe { &(*client).inner };

    let result = runtime().block_on(async {
        match c
            .get_object()
            .bucket(bucket)
            .key(key)
            .range(range)
            .send()
            .await
        {
            Ok(r) => {
                let content_length = r.content_length().map(i64_to_u64);
                let last_modified_ms = datetime_millis(r.last_modified());
                let etag = r.e_tag().map(String::from);
                let content_type = r.content_type().map(String::from);
                match r.body.collect().await {
                    Ok(bytes) => {
                        let data = bytes.into_bytes().to_vec();
                        let data_len = data.len() as u64;
                        Ok(object_output(
                            data,
                            content_length.unwrap_or(data_len),
                            last_modified_ms,
                            etag.as_deref(),
                            content_type.as_deref(),
                        ))
                    }
                    Err(_) => Err(N00bAwsShimStatus::ErrNetwork),
                }
            }
            Err(e) => Err(classify_s3_sdk_error(&e)),
        }
    });

    match result {
        Ok(obj) => {
            unsafe {
                *out = Box::into_raw(Box::new(obj));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(status) => status.as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_object_free(p: *mut N00bAwsShimS3Object) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_bytes(boxed.data, boxed.data_len);
    free_cstring_ptr(boxed.etag);
    free_cstring_ptr(boxed.content_type);
}

fn put_object(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    data: *const u8,
    data_len: usize,
    content_type: *const c_char,
    if_absent: bool,
) -> i32 {
    if client.is_null() || (data.is_null() && data_len != 0) {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let content_type = cstr_optional(content_type);
    let bytes = if data_len == 0 {
        Vec::new()
    } else {
        unsafe { core::slice::from_raw_parts(data, data_len) }.to_vec()
    };
    let c = unsafe { &(*client).inner };

    let outcome = runtime().block_on(async {
        let mut b = c
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(bytes));
        if let Some(ct) = content_type {
            b = b.content_type(ct);
        }
        if if_absent {
            b = b.if_none_match("*");
        }
        b.send().await
    });

    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_s3_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_put_object(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    data: *const u8,
    data_len: usize,
    content_type: *const c_char,
) -> i32 {
    put_object(client, bucket, key, data, data_len, content_type, false)
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_put_object_if_absent(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    data: *const u8,
    data_len: usize,
    content_type: *const c_char,
) -> i32 {
    put_object(client, bucket, key, data, data_len, content_type, true)
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_delete_object(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
) -> i32 {
    if client.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let c = unsafe { &(*client).inner };

    let outcome = runtime().block_on(async {
        match c.head_object().bucket(&bucket).key(&key).send().await {
            Ok(_) => c
                .delete_object()
                .bucket(bucket)
                .key(key)
                .send()
                .await
                .map(|_| N00bAwsShimStatus::Ok)
                .map_err(|e| classify_s3_sdk_error(&e)),
            Err(e) => Err(classify_s3_sdk_error(&e)),
        }
    });

    match outcome {
        Ok(status) => status.as_i32(),
        Err(status) => status.as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_head_object(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    out: *mut *mut N00bAwsShimS3Stat,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if client.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let c = unsafe { &(*client).inner };

    let outcome =
        runtime().block_on(async { c.head_object().bucket(bucket).key(key).send().await });

    match outcome {
        Ok(r) => {
            let stat = N00bAwsShimS3Stat {
                content_length: r.content_length().map(i64_to_u64).unwrap_or(0),
                last_modified_ms: datetime_millis(r.last_modified()),
                etag: cstring_or_empty(r.e_tag()),
                content_type: cstring_or_empty(r.content_type()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(stat));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_s3_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_stat_free(p: *mut N00bAwsShimS3Stat) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.etag);
    free_cstring_ptr(boxed.content_type);
}

fn list_entries_vec_to_ffi(
    entries: Vec<N00bAwsShimS3ListEntry>,
) -> (*mut N00bAwsShimS3ListEntry, usize) {
    if entries.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let count = entries.len();
    let p = Box::into_raw(entries.into_boxed_slice()) as *mut N00bAwsShimS3ListEntry;
    (p, count)
}

fn free_list_entries(p: *mut N00bAwsShimS3ListEntry, count: usize) {
    if p.is_null() || count == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for e in slice.iter_mut() {
        free_cstring_ptr(e.key);
        free_cstring_ptr(e.etag);
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, count)));
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_list_objects(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    prefix: *const c_char,
    continuation: *const c_char,
    max_keys: u32,
    out: *mut *mut N00bAwsShimS3ListOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if client.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let prefix = cstr_optional(prefix).unwrap_or_default();
    let continuation = cstr_optional(continuation);
    let c = unsafe { &(*client).inner };

    let outcome = runtime().block_on(async {
        let mut b = c.list_objects_v2().bucket(bucket).prefix(prefix);
        if let Some(token) = continuation {
            b = b.continuation_token(token);
        }
        if max_keys != 0 {
            b = b.max_keys(max_keys as i32);
        }
        b.send().await
    });

    match outcome {
        Ok(r) => {
            let entries: Vec<N00bAwsShimS3ListEntry> = r
                .contents()
                .iter()
                .filter_map(|o| {
                    let key = o.key()?;
                    Some(N00bAwsShimS3ListEntry {
                        key: cstring_from_string(key.to_owned()),
                        size: o.size().map(i64_to_u64).unwrap_or(0),
                        last_modified_ms: datetime_millis(o.last_modified()),
                        etag: cstring_or_empty(o.e_tag()),
                    })
                })
                .collect();
            let (entries, entries_count) = list_entries_vec_to_ffi(entries);
            let output = N00bAwsShimS3ListOutput {
                entries,
                entries_count,
                continuation: cstring_or_empty(r.next_continuation_token()),
                truncated: r.is_truncated().unwrap_or(false),
            };
            unsafe {
                *out = Box::into_raw(Box::new(output));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_s3_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_list_output_free(p: *mut N00bAwsShimS3ListOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_list_entries(boxed.entries, boxed.entries_count);
    free_cstring_ptr(boxed.continuation);
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_multipart_create(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    content_type: *const c_char,
    out: *mut *mut N00bAwsShimS3MultipartCreateOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if client.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let content_type = cstr_optional(content_type);
    let c = unsafe { &(*client).inner };

    let outcome = runtime().block_on(async {
        let mut b = c.create_multipart_upload().bucket(bucket).key(key);
        if let Some(ct) = content_type {
            b = b.content_type(ct);
        }
        b.send().await
    });

    match outcome {
        Ok(r) => {
            let upload_id = match r.upload_id() {
                Some(id) if !id.is_empty() => id,
                _ => return N00bAwsShimStatus::ErrInternal.as_i32(),
            };
            let output = N00bAwsShimS3MultipartCreateOutput {
                upload_id: cstring_or_empty(Some(upload_id)),
            };
            unsafe {
                *out = Box::into_raw(Box::new(output));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_s3_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_multipart_create_output_free(
    p: *mut N00bAwsShimS3MultipartCreateOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.upload_id);
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_multipart_upload_part(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    upload_id: *const c_char,
    part_number: i32,
    data: *const u8,
    data_len: usize,
    out: *mut *mut N00bAwsShimS3CompletedPart,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if client.is_null() || out.is_null() || part_number < 1 {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let upload_id = match cstr_required(upload_id) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let bytes = match raw_bytes(data, data_len) {
        Some(b) => b,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let c = unsafe { &(*client).inner };

    let outcome = runtime().block_on(async {
        c.upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(bytes))
            .send()
            .await
    });

    match outcome {
        Ok(r) => {
            let etag = match r.e_tag() {
                Some(tag) if !tag.is_empty() => tag,
                _ => return N00bAwsShimStatus::ErrInternal.as_i32(),
            };
            let output = N00bAwsShimS3CompletedPart {
                part_number,
                etag: cstring_or_empty(Some(etag)),
            };
            unsafe {
                *out = Box::into_raw(Box::new(output));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_s3_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_completed_part_free(p: *mut N00bAwsShimS3CompletedPart) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.etag);
}

fn completed_upload_from_ffi(
    parts: *const N00bAwsShimS3CompletedPart,
    part_count: usize,
) -> Option<CompletedMultipartUpload> {
    if parts.is_null() || part_count == 0 || part_count > 10_000 {
        return None;
    }

    let mut out = CompletedMultipartUpload::builder();
    for i in 0..part_count {
        let part = unsafe { &*parts.add(i) };
        if part.part_number < 1 || part.part_number > 10_000 {
            return None;
        }
        let etag = cstr_required(part.etag)?;
        out = out.parts(
            CompletedPart::builder()
                .part_number(part.part_number)
                .e_tag(etag)
                .build(),
        );
    }
    Some(out.build())
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_multipart_complete(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    upload_id: *const c_char,
    parts: *const N00bAwsShimS3CompletedPart,
    part_count: usize,
) -> i32 {
    if client.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let upload_id = match cstr_required(upload_id) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let upload = match completed_upload_from_ffi(parts, part_count) {
        Some(u) => u,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let c = unsafe { &(*client).inner };

    let outcome = runtime().block_on(async {
        c.complete_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(upload)
            .send()
            .await
    });

    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_s3_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_multipart_abort(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    upload_id: *const c_char,
) -> i32 {
    if client.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let upload_id = match cstr_required(upload_id) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let c = unsafe { &(*client).inner };

    let outcome = runtime().block_on(async {
        c.abort_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
    });

    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_s3_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_put_object_multipart(
    client: *const N00bAwsShimS3Client,
    bucket: *const c_char,
    key: *const c_char,
    data: *const u8,
    data_len: usize,
    content_type: *const c_char,
    part_size: usize,
) -> i32 {
    if client.is_null() || data_len == 0 || part_size == 0 || part_size > i32::MAX as usize {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let bucket = match cstr_required(bucket) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let key = match cstr_required(key) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let content_type = cstr_optional(content_type);
    let bytes = match raw_bytes(data, data_len) {
        Some(b) => b,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let c = unsafe { &(*client).inner };

    let result = runtime().block_on(async {
        let mut create = c.create_multipart_upload().bucket(&bucket).key(&key);
        if let Some(ct) = content_type {
            create = create.content_type(ct);
        }

        let created = create.send().await.map_err(|e| classify_s3_sdk_error(&e))?;
        let upload_id = created
            .upload_id()
            .filter(|id| !id.is_empty())
            .map(String::from)
            .ok_or(N00bAwsShimStatus::ErrInternal)?;

        let mut parts: Vec<CompletedPart> = Vec::new();
        let mut status = N00bAwsShimStatus::Ok;

        for (ix, chunk) in bytes.chunks(part_size).enumerate() {
            if ix >= 10_000 {
                status = N00bAwsShimStatus::ErrInvalidArg;
                break;
            }
            let part_number = (ix + 1) as i32;
            match c
                .upload_part()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .body(ByteStream::from(chunk.to_vec()))
                .send()
                .await
            {
                Ok(r) => {
                    let Some(etag) = r.e_tag().filter(|tag| !tag.is_empty()) else {
                        status = N00bAwsShimStatus::ErrInternal;
                        break;
                    };
                    parts.push(
                        CompletedPart::builder()
                            .part_number(part_number)
                            .e_tag(etag.to_owned())
                            .build(),
                    );
                }
                Err(e) => {
                    status = classify_s3_sdk_error(&e);
                    break;
                }
            }
        }

        if status != N00bAwsShimStatus::Ok || parts.is_empty() {
            let _ = c
                .abort_multipart_upload()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload_id)
                .send()
                .await;
            return Err(if parts.is_empty() && status == N00bAwsShimStatus::Ok {
                N00bAwsShimStatus::ErrInvalidArg
            } else {
                status
            });
        }

        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        match c
            .complete_multipart_upload()
            .bucket(&bucket)
            .key(&key)
            .upload_id(&upload_id)
            .multipart_upload(upload)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                let status = classify_s3_sdk_error(&e);
                let _ = c
                    .abort_multipart_upload()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(&upload_id)
                    .send()
                    .await;
                Err(status)
            }
        }
    });

    match result {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(status) => status.as_i32(),
    }
}

/// Returns the version string of the underlying S3 shim module.
#[no_mangle]
pub extern "C" fn n00b_aws_shim_s3_sdk_version() -> *const c_char {
    static VERSION: &[u8] = concat!("aws-sdk-s3 ", env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}
