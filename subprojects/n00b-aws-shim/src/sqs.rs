//! SQS wrappers — full `aws-sdk-sqs` Smithy surface.
//!
//! Operation list (every public op in the Smithy model):
//!   - AddPermission                  - PurgeQueue
//!   - CancelMessageMoveTask          - ReceiveMessage
//!   - ChangeMessageVisibility        - RemovePermission
//!   - ChangeMessageVisibilityBatch   - SendMessage
//!   - CreateQueue                    - SendMessageBatch
//!   - DeleteMessage                  - SetQueueAttributes
//!   - DeleteMessageBatch             - StartMessageMoveTask
//!   - DeleteQueue                    - TagQueue
//!   - GetQueueAttributes             - UntagQueue
//!   - GetQueueUrl                    - ListMessageMoveTasks
//!   - ListDeadLetterSourceQueues     - ListQueues
//!   - ListQueueTags

use std::ffi::c_char;
use std::ptr;

use aws_sdk_sqs::types::{
    BatchResultErrorEntry, ChangeMessageVisibilityBatchRequestEntry,
    DeleteMessageBatchRequestEntry, Message, MessageAttributeValue, MessageSystemAttributeName,
    QueueAttributeName, SendMessageBatchRequestEntry,
};
use aws_sdk_sqs::Client as SqsClient;

use crate::config::N00bAwsShimConfig;
use crate::ffi_util::*;
use crate::runtime::runtime;
use crate::N00bAwsShimStatus;

/* =========================================================================
 * Shared types
 * ========================================================================= */

/// One message returned by ReceiveMessage / batch ops.
#[repr(C)]
pub struct N00bAwsShimSqsMessage {
    pub message_id: *mut c_char,
    pub receipt_handle: *mut c_char,
    pub body: *mut c_char,
    pub md5_of_body: *mut c_char,
    pub md5_of_message_attributes: *mut c_char,
    pub approximate_receive_count: i32,
    /// Sent-timestamp / first-receive-timestamp (unix-ms) from the
    /// queue. -1 if absent.
    pub sent_timestamp_ms: i64,
    pub first_receive_timestamp_ms: i64,
}

/// One error entry returned by a batch operation.
#[repr(C)]
pub struct N00bAwsShimSqsBatchError {
    pub id: *mut c_char,
    pub code: *mut c_char,
    pub message: *mut c_char,
    pub sender_fault: bool,
}

/// One queue URL + name pair returned by listing operations.
#[repr(C)]
pub struct N00bAwsShimSqsQueueRef {
    pub url: *mut c_char,
}

/// One key/value pair for attribute / tag returns.
#[repr(C)]
pub struct N00bAwsShimSqsKv {
    pub key: *mut c_char,
    pub value: *mut c_char,
}

/* =========================================================================
 * AddPermission
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsAddPermissionInput {
    pub queue_url: *const c_char,
    pub label: *const c_char,
    pub account_ids: *const *const c_char,
    pub account_ids_count: usize,
    pub actions: *const *const c_char,
    pub actions_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_add_permission(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimSqsAddPermissionInput,
) -> i32 {
    if cfg.is_null() || input.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };
    let inp = unsafe { &*input };

    let queue_url = match cstr_required(inp.queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let label = match cstr_required(inp.label) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg)
            .add_permission()
            .queue_url(queue_url)
            .label(label);
        for id in collect_cstrs(inp.account_ids, inp.account_ids_count) {
            b = b.aws_account_ids(id);
        }
        for act in collect_cstrs(inp.actions, inp.actions_count) {
            b = b.actions(act);
        }
        b.send().await
    });

    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * CancelMessageMoveTask
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsCancelMessageMoveTaskOutput {
    pub approximate_number_of_messages_moved: i64,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_cancel_message_move_task(
    cfg: *const N00bAwsShimConfig,
    task_handle: *const c_char,
    out: *mut *mut N00bAwsShimSqsCancelMessageMoveTaskOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let handle = match cstr_required(task_handle) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SqsClient::new(sdk_cfg)
            .cancel_message_move_task()
            .task_handle(handle)
            .send()
            .await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSqsCancelMessageMoveTaskOutput {
                approximate_number_of_messages_moved: r.approximate_number_of_messages_moved(),
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_cancel_message_move_task_free(
    p: *mut N00bAwsShimSqsCancelMessageMoveTaskOutput,
) {
    if !p.is_null() {
        unsafe {
            drop(Box::from_raw(p));
        }
    }
}

/* =========================================================================
 * ChangeMessageVisibility
 * ========================================================================= */

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_change_message_visibility(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    receipt_handle: *const c_char,
    visibility_timeout: i32,
) -> i32 {
    if cfg.is_null() || visibility_timeout < 0 {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let queue_url = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let receipt = match cstr_required(receipt_handle) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SqsClient::new(sdk_cfg)
            .change_message_visibility()
            .queue_url(queue_url)
            .receipt_handle(receipt)
            .visibility_timeout(visibility_timeout)
            .send()
            .await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * ChangeMessageVisibilityBatch
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsBatchEntryVisibility {
    pub id: *const c_char,
    pub receipt_handle: *const c_char,
    pub visibility_timeout: i32,
}

#[repr(C)]
pub struct N00bAwsShimSqsBatchVisibilityOutput {
    pub successful_ids: *mut *mut c_char,
    pub successful_ids_count: usize,
    pub failures: *mut N00bAwsShimSqsBatchError,
    pub failures_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_change_message_visibility_batch(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    entries: *const N00bAwsShimSqsBatchEntryVisibility,
    entries_count: usize,
    out: *mut *mut N00bAwsShimSqsBatchVisibilityOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() || entries.is_null() || entries_count == 0 {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg)
            .change_message_visibility_batch()
            .queue_url(q);
        for i in 0..entries_count {
            let e = unsafe { &*entries.add(i) };
            let id = cstr_optional(e.id).unwrap_or_default();
            let receipt = cstr_optional(e.receipt_handle).unwrap_or_default();
            if let Ok(entry) = ChangeMessageVisibilityBatchRequestEntry::builder()
                .id(id)
                .receipt_handle(receipt)
                .visibility_timeout(e.visibility_timeout)
                .build()
            {
                b = b.entries(entry);
            }
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let (succ, succ_n) =
                vec_to_cstring_array(r.successful().iter().map(|e| e.id().to_string()).collect());
            let (fail_ptr, fail_n) = batch_errors_to_ffi(r.failed());
            let s = N00bAwsShimSqsBatchVisibilityOutput {
                successful_ids: succ,
                successful_ids_count: succ_n,
                failures: fail_ptr,
                failures_count: fail_n,
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_batch_visibility_free(
    p: *mut N00bAwsShimSqsBatchVisibilityOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_array(boxed.successful_ids, boxed.successful_ids_count);
    free_batch_errors(boxed.failures, boxed.failures_count);
}

/* =========================================================================
 * CreateQueue
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsCreateQueueInput {
    pub queue_name: *const c_char,
    pub attribute_keys: *const *const c_char,
    pub attribute_values: *const *const c_char,
    pub attributes_count: usize,
    pub tag_keys: *const *const c_char,
    pub tag_values: *const *const c_char,
    pub tags_count: usize,
}

#[repr(C)]
pub struct N00bAwsShimSqsCreateQueueOutput {
    pub queue_url: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_create_queue(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimSqsCreateQueueInput,
    out: *mut *mut N00bAwsShimSqsCreateQueueOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || input.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let inp = unsafe { &*input };
    let name = match cstr_required(inp.queue_name) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg).create_queue().queue_name(name);
        for (k, v) in collect_cstr_kv(
            inp.attribute_keys,
            inp.attribute_values,
            inp.attributes_count,
        ) {
            b = b.attributes(QueueAttributeName::from(k.as_str()), v);
        }
        for (k, v) in collect_cstr_kv(inp.tag_keys, inp.tag_values, inp.tags_count) {
            b = b.tags(k, v);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSqsCreateQueueOutput {
                queue_url: cstring_or_empty(r.queue_url()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_create_queue_free(p: *mut N00bAwsShimSqsCreateQueueOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.queue_url);
}

/* =========================================================================
 * DeleteMessage
 * ========================================================================= */

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_delete_message(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    receipt_handle: *const c_char,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let r = match cstr_required(receipt_handle) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SqsClient::new(sdk_cfg)
            .delete_message()
            .queue_url(q)
            .receipt_handle(r)
            .send()
            .await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * DeleteMessageBatch
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsBatchEntryDelete {
    pub id: *const c_char,
    pub receipt_handle: *const c_char,
}

#[repr(C)]
pub struct N00bAwsShimSqsBatchDeleteOutput {
    pub successful_ids: *mut *mut c_char,
    pub successful_ids_count: usize,
    pub failures: *mut N00bAwsShimSqsBatchError,
    pub failures_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_delete_message_batch(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    entries: *const N00bAwsShimSqsBatchEntryDelete,
    entries_count: usize,
    out: *mut *mut N00bAwsShimSqsBatchDeleteOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() || entries.is_null() || entries_count == 0 {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg).delete_message_batch().queue_url(q);
        for i in 0..entries_count {
            let e = unsafe { &*entries.add(i) };
            let id = cstr_optional(e.id).unwrap_or_default();
            let receipt = cstr_optional(e.receipt_handle).unwrap_or_default();
            if let Ok(entry) = DeleteMessageBatchRequestEntry::builder()
                .id(id)
                .receipt_handle(receipt)
                .build()
            {
                b = b.entries(entry);
            }
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let (succ, succ_n) =
                vec_to_cstring_array(r.successful().iter().map(|e| e.id().to_string()).collect());
            let (fail_ptr, fail_n) = batch_errors_to_ffi(r.failed());
            let s = N00bAwsShimSqsBatchDeleteOutput {
                successful_ids: succ,
                successful_ids_count: succ_n,
                failures: fail_ptr,
                failures_count: fail_n,
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_batch_delete_free(p: *mut N00bAwsShimSqsBatchDeleteOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_array(boxed.successful_ids, boxed.successful_ids_count);
    free_batch_errors(boxed.failures, boxed.failures_count);
}

/* =========================================================================
 * DeleteQueue / GetQueueUrl / GetQueueAttributes / PurgeQueue / SetQueueAttributes
 * ========================================================================= */

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_delete_queue(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
) -> i32 {
    simple_queue_op(cfg, queue_url, |c, url| async move {
        c.delete_queue().queue_url(url).send().await.map(|_| ())
    })
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_purge_queue(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
) -> i32 {
    simple_queue_op(cfg, queue_url, |c, url| async move {
        c.purge_queue().queue_url(url).send().await.map(|_| ())
    })
}

#[repr(C)]
pub struct N00bAwsShimSqsGetQueueUrlOutput {
    pub queue_url: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_get_queue_url(
    cfg: *const N00bAwsShimConfig,
    queue_name: *const c_char,
    queue_owner_account: *const c_char,
    out: *mut *mut N00bAwsShimSqsGetQueueUrlOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let name = match cstr_required(queue_name) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let owner = cstr_optional(queue_owner_account);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg).get_queue_url().queue_name(name);
        if let Some(o) = owner {
            b = b.queue_owner_aws_account_id(o);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSqsGetQueueUrlOutput {
                queue_url: cstring_or_empty(r.queue_url()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_get_queue_url_free(p: *mut N00bAwsShimSqsGetQueueUrlOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.queue_url);
}

#[repr(C)]
pub struct N00bAwsShimSqsGetQueueAttributesOutput {
    pub attributes: *mut N00bAwsShimSqsKv,
    pub attributes_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_get_queue_attributes(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    attribute_names: *const *const c_char,
    attribute_names_count: usize,
    out: *mut *mut N00bAwsShimSqsGetQueueAttributesOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg).get_queue_attributes().queue_url(q);
        let names = collect_cstrs(attribute_names, attribute_names_count);
        if names.is_empty() {
            b = b.attribute_names(QueueAttributeName::All);
        } else {
            for n in names {
                b = b.attribute_names(QueueAttributeName::from(n.as_str()));
            }
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let attrs: Vec<(String, String)> = r
                .attributes()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.as_str().to_string(), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            let (ptr, count) = kv_to_ffi(attrs);
            let s = N00bAwsShimSqsGetQueueAttributesOutput {
                attributes: ptr,
                attributes_count: count,
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_get_queue_attributes_free(
    p: *mut N00bAwsShimSqsGetQueueAttributesOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_kv_array(boxed.attributes, boxed.attributes_count);
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_set_queue_attributes(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    attribute_keys: *const *const c_char,
    attribute_values: *const *const c_char,
    attributes_count: usize,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg).set_queue_attributes().queue_url(q);
        for (k, v) in collect_cstr_kv(attribute_keys, attribute_values, attributes_count) {
            b = b.attributes(QueueAttributeName::from(k.as_str()), v);
        }
        b.send().await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * ListDeadLetterSourceQueues / ListMessageMoveTasks / ListQueues
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsListQueuesOutput {
    pub queue_urls: *mut *mut c_char,
    pub queue_urls_count: usize,
    pub next_token: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_list_dead_letter_source_queues(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    next_token: *const c_char,
    max_results: i32,
    out: *mut *mut N00bAwsShimSqsListQueuesOutput,
) -> i32 {
    list_with_paging(
        cfg,
        out,
        max_results,
        next_token,
        queue_url,
        |c, q, tok, max, _qurl| async move {
            let mut b = c.list_dead_letter_source_queues();
            if let Some(q) = q {
                b = b.queue_url(q);
            }
            if let Some(tok) = tok {
                b = b.next_token(tok);
            }
            if max > 0 {
                b = b.max_results(max);
            }
            let r = b.send().await?;
            Ok::<_, _>((
                r.queue_urls().to_vec(),
                r.next_token().map(|s| s.to_string()),
            ))
        },
    )
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_list_queues(
    cfg: *const N00bAwsShimConfig,
    name_prefix: *const c_char,
    next_token: *const c_char,
    max_results: i32,
    out: *mut *mut N00bAwsShimSqsListQueuesOutput,
) -> i32 {
    list_with_paging(
        cfg,
        out,
        max_results,
        next_token,
        name_prefix,
        |c, prefix, tok, max, _qurl| async move {
            let mut b = c.list_queues();
            if let Some(p) = prefix {
                b = b.queue_name_prefix(p);
            }
            if let Some(t) = tok {
                b = b.next_token(t);
            }
            if max > 0 {
                b = b.max_results(max);
            }
            let r = b.send().await?;
            Ok::<_, _>((
                r.queue_urls().to_vec(),
                r.next_token().map(|s| s.to_string()),
            ))
        },
    )
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_list_queues_output_free(
    p: *mut N00bAwsShimSqsListQueuesOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_array(boxed.queue_urls, boxed.queue_urls_count);
    free_cstring_ptr(boxed.next_token);
}

#[repr(C)]
pub struct N00bAwsShimSqsMessageMoveTask {
    pub task_handle: *mut c_char,
    pub source_arn: *mut c_char,
    pub destination_arn: *mut c_char,
    pub status: *mut c_char,
    pub max_number_of_messages_per_second: i32,
    pub approximate_number_of_messages_moved: i64,
    pub approximate_number_of_messages_to_move: i64,
    pub failure_reason: *mut c_char,
    pub started_timestamp_ms: i64,
}

#[repr(C)]
pub struct N00bAwsShimSqsListMessageMoveTasksOutput {
    pub tasks: *mut N00bAwsShimSqsMessageMoveTask,
    pub tasks_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_list_message_move_tasks(
    cfg: *const N00bAwsShimConfig,
    source_arn: *const c_char,
    max_results: i32,
    out: *mut *mut N00bAwsShimSqsListMessageMoveTasksOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(source_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg)
            .list_message_move_tasks()
            .source_arn(arn);
        if max_results > 0 {
            b = b.max_results(max_results);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let tasks: Vec<N00bAwsShimSqsMessageMoveTask> = r
                .results()
                .iter()
                .map(|t| N00bAwsShimSqsMessageMoveTask {
                    task_handle: cstring_or_empty(t.task_handle()),
                    source_arn: cstring_or_empty(t.source_arn()),
                    destination_arn: cstring_or_empty(t.destination_arn()),
                    status: cstring_or_empty(t.status()),
                    max_number_of_messages_per_second: t
                        .max_number_of_messages_per_second()
                        .unwrap_or(0),
                    approximate_number_of_messages_moved: t.approximate_number_of_messages_moved(),
                    approximate_number_of_messages_to_move: t
                        .approximate_number_of_messages_to_move()
                        .unwrap_or(0),
                    failure_reason: cstring_or_empty(t.failure_reason()),
                    started_timestamp_ms: t.started_timestamp(),
                })
                .collect();
            let count = tasks.len();
            let arr_ptr = if count == 0 {
                ptr::null_mut()
            } else {
                let b = tasks.into_boxed_slice();
                Box::into_raw(b) as *mut N00bAwsShimSqsMessageMoveTask
            };
            let s = N00bAwsShimSqsListMessageMoveTasksOutput {
                tasks: arr_ptr,
                tasks_count: count,
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_list_message_move_tasks_free(
    p: *mut N00bAwsShimSqsListMessageMoveTasksOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    if !boxed.tasks.is_null() && boxed.tasks_count > 0 {
        let slice = unsafe { core::slice::from_raw_parts_mut(boxed.tasks, boxed.tasks_count) };
        for t in slice.iter_mut() {
            free_cstring_ptr(t.task_handle);
            free_cstring_ptr(t.source_arn);
            free_cstring_ptr(t.destination_arn);
            free_cstring_ptr(t.status);
            free_cstring_ptr(t.failure_reason);
        }
        unsafe {
            drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                boxed.tasks,
                boxed.tasks_count,
            )));
        }
    }
}

#[repr(C)]
pub struct N00bAwsShimSqsListQueueTagsOutput {
    pub tags: *mut N00bAwsShimSqsKv,
    pub tags_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_list_queue_tags(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    out: *mut *mut N00bAwsShimSqsListQueueTagsOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SqsClient::new(sdk_cfg)
            .list_queue_tags()
            .queue_url(q)
            .send()
            .await
    });
    match outcome {
        Ok(r) => {
            // `tags()` returns Option<&HashMap<String, String>>.
            let tags: Vec<(String, String)> = r
                .tags()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            let (ptr, count) = kv_to_ffi(tags);
            let s = N00bAwsShimSqsListQueueTagsOutput {
                tags: ptr,
                tags_count: count,
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_list_queue_tags_free(
    p: *mut N00bAwsShimSqsListQueueTagsOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_kv_array(boxed.tags, boxed.tags_count);
}

/* =========================================================================
 * ReceiveMessage
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsReceiveOutput {
    pub messages: *mut N00bAwsShimSqsMessage,
    pub messages_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_receive_message(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    max_messages: i32,
    wait_time_seconds: i32,
    visibility_timeout: i32,
    receive_request_attempt_id: *const c_char,
    out: *mut *mut N00bAwsShimSqsReceiveOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let attempt = cstr_optional(receive_request_attempt_id);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg)
            .receive_message()
            .queue_url(q)
            // Ask for the standard system attributes we surface.
            .message_system_attribute_names(MessageSystemAttributeName::ApproximateReceiveCount)
            .message_system_attribute_names(MessageSystemAttributeName::SentTimestamp)
            .message_system_attribute_names(
                MessageSystemAttributeName::ApproximateFirstReceiveTimestamp,
            );
        if max_messages > 0 {
            b = b.max_number_of_messages(max_messages);
        }
        if wait_time_seconds >= 0 {
            b = b.wait_time_seconds(wait_time_seconds);
        }
        if visibility_timeout > 0 {
            b = b.visibility_timeout(visibility_timeout);
        }
        if let Some(a) = attempt {
            b = b.receive_request_attempt_id(a);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let messages: Vec<N00bAwsShimSqsMessage> =
                r.messages().iter().map(message_to_ffi).collect();
            let count = messages.len();
            let arr_ptr = if count == 0 {
                ptr::null_mut()
            } else {
                let b = messages.into_boxed_slice();
                Box::into_raw(b) as *mut N00bAwsShimSqsMessage
            };
            let s = N00bAwsShimSqsReceiveOutput {
                messages: arr_ptr,
                messages_count: count,
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_receive_output_free(p: *mut N00bAwsShimSqsReceiveOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    if !boxed.messages.is_null() && boxed.messages_count > 0 {
        let slice =
            unsafe { core::slice::from_raw_parts_mut(boxed.messages, boxed.messages_count) };
        for m in slice.iter_mut() {
            free_cstring_ptr(m.message_id);
            free_cstring_ptr(m.receipt_handle);
            free_cstring_ptr(m.body);
            free_cstring_ptr(m.md5_of_body);
            free_cstring_ptr(m.md5_of_message_attributes);
        }
        unsafe {
            drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                boxed.messages,
                boxed.messages_count,
            )));
        }
    }
}

/* =========================================================================
 * RemovePermission
 * ========================================================================= */

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_remove_permission(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    label: *const c_char,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let l = match cstr_required(label) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SqsClient::new(sdk_cfg)
            .remove_permission()
            .queue_url(q)
            .label(l)
            .send()
            .await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * SendMessage
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsSendInput {
    pub queue_url: *const c_char,
    pub message_body: *const c_char,
    pub delay_seconds: i32,
    pub message_group_id: *const c_char,
    pub message_deduplication_id: *const c_char,
}

#[repr(C)]
pub struct N00bAwsShimSqsSendOutput {
    pub message_id: *mut c_char,
    pub md5_of_message_body: *mut c_char,
    pub md5_of_message_attributes: *mut c_char,
    pub sequence_number: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_send_message(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimSqsSendInput,
    out: *mut *mut N00bAwsShimSqsSendOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || input.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let inp = unsafe { &*input };
    let q = match cstr_required(inp.queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let body = match cstr_required(inp.message_body) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg)
            .send_message()
            .queue_url(q)
            .message_body(body);
        if inp.delay_seconds > 0 {
            b = b.delay_seconds(inp.delay_seconds);
        }
        if let Some(g) = cstr_optional(inp.message_group_id) {
            b = b.message_group_id(g);
        }
        if let Some(d) = cstr_optional(inp.message_deduplication_id) {
            b = b.message_deduplication_id(d);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSqsSendOutput {
                message_id: cstring_or_empty(r.message_id()),
                md5_of_message_body: cstring_or_empty(r.md5_of_message_body()),
                md5_of_message_attributes: cstring_or_empty(r.md5_of_message_attributes()),
                sequence_number: cstring_or_empty(r.sequence_number()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_send_output_free(p: *mut N00bAwsShimSqsSendOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.message_id);
    free_cstring_ptr(boxed.md5_of_message_body);
    free_cstring_ptr(boxed.md5_of_message_attributes);
    free_cstring_ptr(boxed.sequence_number);
}

/* =========================================================================
 * SendMessageBatch
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsBatchEntrySend {
    pub id: *const c_char,
    pub message_body: *const c_char,
    pub delay_seconds: i32,
    pub message_group_id: *const c_char,
    pub message_deduplication_id: *const c_char,
}

#[repr(C)]
pub struct N00bAwsShimSqsBatchSendSuccess {
    pub id: *mut c_char,
    pub message_id: *mut c_char,
    pub md5_of_message_body: *mut c_char,
    pub md5_of_message_attributes: *mut c_char,
    pub sequence_number: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimSqsBatchSendOutput {
    pub successes: *mut N00bAwsShimSqsBatchSendSuccess,
    pub successes_count: usize,
    pub failures: *mut N00bAwsShimSqsBatchError,
    pub failures_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_send_message_batch(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    entries: *const N00bAwsShimSqsBatchEntrySend,
    entries_count: usize,
    out: *mut *mut N00bAwsShimSqsBatchSendOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() || entries.is_null() || entries_count == 0 {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg).send_message_batch().queue_url(q);
        for i in 0..entries_count {
            let e = unsafe { &*entries.add(i) };
            let id = cstr_optional(e.id).unwrap_or_default();
            let body = cstr_optional(e.message_body).unwrap_or_default();
            let mut eb = SendMessageBatchRequestEntry::builder()
                .id(id)
                .message_body(body);
            if e.delay_seconds > 0 {
                eb = eb.delay_seconds(e.delay_seconds);
            }
            if let Some(g) = cstr_optional(e.message_group_id) {
                eb = eb.message_group_id(g);
            }
            if let Some(d) = cstr_optional(e.message_deduplication_id) {
                eb = eb.message_deduplication_id(d);
            }
            if let Ok(entry) = eb.build() {
                b = b.entries(entry);
            }
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let succ: Vec<N00bAwsShimSqsBatchSendSuccess> = r
                .successful()
                .iter()
                .map(|e| N00bAwsShimSqsBatchSendSuccess {
                    id: cstring_or_empty(Some(e.id())),
                    message_id: cstring_or_empty(Some(e.message_id())),
                    md5_of_message_body: cstring_or_empty(Some(e.md5_of_message_body())),
                    md5_of_message_attributes: cstring_or_empty(e.md5_of_message_attributes()),
                    sequence_number: cstring_or_empty(e.sequence_number()),
                })
                .collect();
            let succ_count = succ.len();
            let succ_ptr = if succ_count == 0 {
                ptr::null_mut()
            } else {
                Box::into_raw(succ.into_boxed_slice()) as *mut N00bAwsShimSqsBatchSendSuccess
            };
            let (fail_ptr, fail_n) = batch_errors_to_ffi(r.failed());
            let s = N00bAwsShimSqsBatchSendOutput {
                successes: succ_ptr,
                successes_count: succ_count,
                failures: fail_ptr,
                failures_count: fail_n,
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_batch_send_free(p: *mut N00bAwsShimSqsBatchSendOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    if !boxed.successes.is_null() && boxed.successes_count > 0 {
        let slice =
            unsafe { core::slice::from_raw_parts_mut(boxed.successes, boxed.successes_count) };
        for s in slice.iter_mut() {
            free_cstring_ptr(s.id);
            free_cstring_ptr(s.message_id);
            free_cstring_ptr(s.md5_of_message_body);
            free_cstring_ptr(s.md5_of_message_attributes);
            free_cstring_ptr(s.sequence_number);
        }
        unsafe {
            drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                boxed.successes,
                boxed.successes_count,
            )));
        }
    }
    free_batch_errors(boxed.failures, boxed.failures_count);
}

/* =========================================================================
 * StartMessageMoveTask
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSqsStartMessageMoveTaskOutput {
    pub task_handle: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_start_message_move_task(
    cfg: *const N00bAwsShimConfig,
    source_arn: *const c_char,
    destination_arn: *const c_char,
    max_messages_per_second: i32,
    out: *mut *mut N00bAwsShimSqsStartMessageMoveTaskOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let src = match cstr_required(source_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let dest = cstr_optional(destination_arn);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg)
            .start_message_move_task()
            .source_arn(src);
        if let Some(d) = dest {
            b = b.destination_arn(d);
        }
        if max_messages_per_second > 0 {
            b = b.max_number_of_messages_per_second(max_messages_per_second);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSqsStartMessageMoveTaskOutput {
                task_handle: cstring_or_empty(r.task_handle()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_start_message_move_task_free(
    p: *mut N00bAwsShimSqsStartMessageMoveTaskOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.task_handle);
}

/* =========================================================================
 * TagQueue / UntagQueue
 * ========================================================================= */

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_tag_queue(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    tag_keys: *const *const c_char,
    tag_values: *const *const c_char,
    tags_count: usize,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg).tag_queue().queue_url(q);
        for (k, v) in collect_cstr_kv(tag_keys, tag_values, tags_count) {
            b = b.tags(k, v);
        }
        b.send().await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sqs_untag_queue(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    tag_keys: *const *const c_char,
    tag_keys_count: usize,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SqsClient::new(sdk_cfg).untag_queue().queue_url(q);
        for k in collect_cstrs(tag_keys, tag_keys_count) {
            b = b.tag_keys(k);
        }
        b.send().await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/// Translate a single SQS `Message` to its repr(C) FFI shape.
fn message_to_ffi(m: &Message) -> N00bAwsShimSqsMessage {
    let attrs = m.attributes();
    let recv_count = attrs
        .and_then(|a| a.get(&MessageSystemAttributeName::ApproximateReceiveCount))
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(0);
    let sent_ms = attrs
        .and_then(|a| a.get(&MessageSystemAttributeName::SentTimestamp))
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(-1);
    let first_recv_ms = attrs
        .and_then(|a| a.get(&MessageSystemAttributeName::ApproximateFirstReceiveTimestamp))
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(-1);
    N00bAwsShimSqsMessage {
        message_id: cstring_or_empty(m.message_id()),
        receipt_handle: cstring_or_empty(m.receipt_handle()),
        body: cstring_or_empty(m.body()),
        md5_of_body: cstring_or_empty(m.md5_of_body()),
        md5_of_message_attributes: cstring_or_empty(m.md5_of_message_attributes()),
        approximate_receive_count: recv_count,
        sent_timestamp_ms: sent_ms,
        first_receive_timestamp_ms: first_recv_ms,
    }
}

/// Convert an SDK batch-error vec into the FFI shape.
fn batch_errors_to_ffi(errs: &[BatchResultErrorEntry]) -> (*mut N00bAwsShimSqsBatchError, usize) {
    let count = errs.len();
    if count == 0 {
        return (ptr::null_mut(), 0);
    }
    let mut out = Vec::with_capacity(count);
    for e in errs {
        out.push(N00bAwsShimSqsBatchError {
            id: cstring_or_empty(Some(e.id())),
            code: cstring_or_empty(Some(e.code())),
            message: cstring_or_empty(e.message()),
            sender_fault: e.sender_fault(),
        });
    }
    let p = Box::into_raw(out.into_boxed_slice()) as *mut N00bAwsShimSqsBatchError;
    (p, count)
}

fn free_batch_errors(p: *mut N00bAwsShimSqsBatchError, count: usize) {
    if p.is_null() || count == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for e in slice.iter_mut() {
        free_cstring_ptr(e.id);
        free_cstring_ptr(e.code);
        free_cstring_ptr(e.message);
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, count)));
    }
}

fn kv_to_ffi(kvs: Vec<(String, String)>) -> (*mut N00bAwsShimSqsKv, usize) {
    if kvs.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let count = kvs.len();
    let items: Vec<N00bAwsShimSqsKv> = kvs
        .into_iter()
        .map(|(k, v)| N00bAwsShimSqsKv {
            key: cstring_from_string(k),
            value: cstring_from_string(v),
        })
        .collect();
    let p = Box::into_raw(items.into_boxed_slice()) as *mut N00bAwsShimSqsKv;
    (p, count)
}

fn free_kv_array(p: *mut N00bAwsShimSqsKv, count: usize) {
    if p.is_null() || count == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for e in slice.iter_mut() {
        free_cstring_ptr(e.key);
        free_cstring_ptr(e.value);
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, count)));
    }
}

/// Run an SDK call that takes only a queue URL and returns success/failure.
fn simple_queue_op<F, Fut, R, E>(
    cfg: *const N00bAwsShimConfig,
    queue_url: *const c_char,
    op: F,
) -> i32
where
    F: FnOnce(SqsClient, String) -> Fut,
    Fut: std::future::Future<
        Output = Result<
            R,
            aws_smithy_runtime_api::client::result::SdkError<
                E,
                aws_smithy_runtime_api::client::orchestrator::HttpResponse,
            >,
        >,
    >,
{
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let q = match cstr_required(queue_url) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };
    let outcome = runtime().block_on(async move {
        let client = SqsClient::new(sdk_cfg);
        op(client, q).await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/// Generic paginated-list helper. Returns a list of strings plus an
/// optional next-page token. The supplied closure is the per-op
/// SDK-call body that has to use the client + 4 optional inputs.
#[allow(clippy::too_many_arguments)]
fn list_with_paging<F, Fut, E>(
    cfg: *const N00bAwsShimConfig,
    out: *mut *mut N00bAwsShimSqsListQueuesOutput,
    max_results: i32,
    next_token: *const c_char,
    extra_str: *const c_char,
    op: F,
) -> i32
where
    F: FnOnce(SqsClient, Option<String>, Option<String>, i32, Option<String>) -> Fut,
    Fut: std::future::Future<
        Output = Result<
            (Vec<String>, Option<String>),
            aws_smithy_runtime_api::client::result::SdkError<
                E,
                aws_smithy_runtime_api::client::orchestrator::HttpResponse,
            >,
        >,
    >,
{
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };
    let extra = cstr_optional(extra_str);
    let token = cstr_optional(next_token);
    let outcome = runtime().block_on(async move {
        op(SqsClient::new(sdk_cfg), extra, token, max_results, None).await
    });
    match outcome {
        Ok((items, next)) => {
            let (arr, count) = vec_to_cstring_array(items);
            let s = N00bAwsShimSqsListQueuesOutput {
                queue_urls: arr,
                queue_urls_count: count,
                next_token: next.map(cstring_from_string).unwrap_or(ptr::null_mut()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

// Suppress unused-import warnings for types we expose via repr(C) but
// don't reference directly in this module after the helper refactor.
#[allow(dead_code)]
fn _force_use(_a: MessageAttributeValue) {}
#[allow(dead_code)]
fn _force_use2(_a: N00bAwsShimSqsQueueRef) {}
