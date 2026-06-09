//! SNS wrappers — full `aws-sdk-sns` Smithy surface.
//!
//! Operations (every public op in the model):
//!   Topic management:        CreateTopic, DeleteTopic, ListTopics,
//!                            Get/SetTopicAttributes
//!   Subscriptions:           Subscribe, Unsubscribe, ConfirmSubscription,
//!                            ListSubscriptions, ListSubscriptionsByTopic,
//!                            Get/SetSubscriptionAttributes
//!   Publishing:              Publish, PublishBatch
//!   Permissions:             AddPermission, RemovePermission
//!   Tagging:                 ListTagsForResource, TagResource, UntagResource
//!   Mobile / SMS / push:     CheckIfPhoneNumberIsOptedOut, ListPhoneNumbersOptedOut,
//!                            OptInPhoneNumber, ListOriginationNumbers,
//!                            CreateSMSSandboxPhoneNumber,
//!                            DeleteSMSSandboxPhoneNumber,
//!                            ListSMSSandboxPhoneNumbers,
//!                            VerifySMSSandboxPhoneNumber,
//!                            GetSMSSandboxAccountStatus, GetSMSAttributes,
//!                            SetSMSAttributes
//!   Platform apps / pushes:  CreatePlatformApplication,
//!                            CreatePlatformEndpoint, DeletePlatformApplication,
//!                            DeleteEndpoint, GetEndpointAttributes,
//!                            GetPlatformApplicationAttributes,
//!                            ListEndpointsByPlatformApplication,
//!                            ListPlatformApplications,
//!                            SetEndpointAttributes, SetPlatformApplicationAttributes
//!   Data protection:         GetDataProtectionPolicy, PutDataProtectionPolicy
//!
//! Per-op shape mirrors `sts.rs` / `sqs.rs`: `#[no_mangle] extern "C"
//! fn n00b_aws_shim_sns_*` with `#[repr(C)]` IO structs and matching
//! `_free` functions.

use std::ffi::c_char;
use std::ptr;

use aws_sdk_sns::types::{MessageAttributeValue, PublishBatchRequestEntry};
use aws_sdk_sns::Client as SnsClient;

use crate::config::N00bAwsShimConfig;
use crate::ffi_util::*;
use crate::runtime::runtime;
use crate::N00bAwsShimStatus;

/* =========================================================================
 * Shared types
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSnsKv {
    pub key: *mut c_char,
    pub value: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimSnsTopic {
    pub topic_arn: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimSnsSubscription {
    pub subscription_arn: *mut c_char,
    pub owner: *mut c_char,
    pub protocol: *mut c_char,
    pub endpoint: *mut c_char,
    pub topic_arn: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimSnsBatchError {
    pub id: *mut c_char,
    pub code: *mut c_char,
    pub message: *mut c_char,
    pub sender_fault: bool,
}

/* =========================================================================
 * Helpers (SNS-local)
 * ========================================================================= */

fn kv_vec_to_ffi(kvs: Vec<(String, String)>) -> (*mut N00bAwsShimSnsKv, usize) {
    if kvs.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let count = kvs.len();
    let items: Vec<N00bAwsShimSnsKv> = kvs
        .into_iter()
        .map(|(k, v)| N00bAwsShimSnsKv {
            key: cstring_from_string(k),
            value: cstring_from_string(v),
        })
        .collect();
    let p = Box::into_raw(items.into_boxed_slice()) as *mut N00bAwsShimSnsKv;
    (p, count)
}

fn free_kv_array(p: *mut N00bAwsShimSnsKv, count: usize) {
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

fn topics_vec_to_ffi(arns: Vec<String>) -> (*mut N00bAwsShimSnsTopic, usize) {
    if arns.is_empty() {
        return (ptr::null_mut(), 0);
    }
    let count = arns.len();
    let items: Vec<N00bAwsShimSnsTopic> = arns
        .into_iter()
        .map(|a| N00bAwsShimSnsTopic {
            topic_arn: cstring_from_string(a),
        })
        .collect();
    let p = Box::into_raw(items.into_boxed_slice()) as *mut N00bAwsShimSnsTopic;
    (p, count)
}

fn free_topics_array(p: *mut N00bAwsShimSnsTopic, count: usize) {
    if p.is_null() || count == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for t in slice.iter_mut() {
        free_cstring_ptr(t.topic_arn);
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, count)));
    }
}

fn subs_vec_to_ffi(
    subs: &[aws_sdk_sns::types::Subscription],
) -> (*mut N00bAwsShimSnsSubscription, usize) {
    let count = subs.len();
    if count == 0 {
        return (ptr::null_mut(), 0);
    }
    let items: Vec<N00bAwsShimSnsSubscription> = subs
        .iter()
        .map(|s| N00bAwsShimSnsSubscription {
            subscription_arn: cstring_or_empty(s.subscription_arn()),
            owner: cstring_or_empty(s.owner()),
            protocol: cstring_or_empty(s.protocol()),
            endpoint: cstring_or_empty(s.endpoint()),
            topic_arn: cstring_or_empty(s.topic_arn()),
        })
        .collect();
    let p = Box::into_raw(items.into_boxed_slice()) as *mut N00bAwsShimSnsSubscription;
    (p, count)
}

fn free_subs_array(p: *mut N00bAwsShimSnsSubscription, count: usize) {
    if p.is_null() || count == 0 {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for s in slice.iter_mut() {
        free_cstring_ptr(s.subscription_arn);
        free_cstring_ptr(s.owner);
        free_cstring_ptr(s.protocol);
        free_cstring_ptr(s.endpoint);
        free_cstring_ptr(s.topic_arn);
    }
    unsafe {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, count)));
    }
}

fn free_batch_errors(p: *mut N00bAwsShimSnsBatchError, count: usize) {
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

/* =========================================================================
 * Topic management
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSnsCreateTopicInput {
    pub name: *const c_char,
    pub attribute_keys: *const *const c_char,
    pub attribute_values: *const *const c_char,
    pub attributes_count: usize,
    pub tag_keys: *const *const c_char,
    pub tag_values: *const *const c_char,
    pub tags_count: usize,
    pub data_protection_policy: *const c_char,
}

#[repr(C)]
pub struct N00bAwsShimSnsCreateTopicOutput {
    pub topic_arn: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_create_topic(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimSnsCreateTopicInput,
    out: *mut *mut N00bAwsShimSnsCreateTopicOutput,
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
    let name = match cstr_required(inp.name) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg).create_topic().name(name);
        for (k, v) in collect_cstr_kv(
            inp.attribute_keys,
            inp.attribute_values,
            inp.attributes_count,
        ) {
            b = b.attributes(k, v);
        }
        for (k, v) in collect_cstr_kv(inp.tag_keys, inp.tag_values, inp.tags_count) {
            if let Ok(tag) = aws_sdk_sns::types::Tag::builder().key(k).value(v).build() {
                b = b.tags(tag);
            }
        }
        if let Some(p) = cstr_optional(inp.data_protection_policy) {
            b = b.data_protection_policy(p);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSnsCreateTopicOutput {
                topic_arn: cstring_or_empty(r.topic_arn()),
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
pub extern "C" fn n00b_aws_shim_sns_create_topic_free(p: *mut N00bAwsShimSnsCreateTopicOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.topic_arn);
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_delete_topic(
    cfg: *const N00bAwsShimConfig,
    topic_arn: *const c_char,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(topic_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };
    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .delete_topic()
            .topic_arn(arn)
            .send()
            .await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[repr(C)]
pub struct N00bAwsShimSnsListTopicsOutput {
    pub topics: *mut N00bAwsShimSnsTopic,
    pub topics_count: usize,
    pub next_token: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_list_topics(
    cfg: *const N00bAwsShimConfig,
    next_token: *const c_char,
    out: *mut *mut N00bAwsShimSnsListTopicsOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let token = cstr_optional(next_token);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg).list_topics();
        if let Some(t) = token {
            b = b.next_token(t);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let arns: Vec<String> = r
                .topics()
                .iter()
                .filter_map(|t| t.topic_arn().map(String::from))
                .collect();
            let (ptr, count) = topics_vec_to_ffi(arns);
            let s = N00bAwsShimSnsListTopicsOutput {
                topics: ptr,
                topics_count: count,
                next_token: cstring_or_empty(r.next_token()),
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
pub extern "C" fn n00b_aws_shim_sns_list_topics_free(p: *mut N00bAwsShimSnsListTopicsOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_topics_array(boxed.topics, boxed.topics_count);
    free_cstring_ptr(boxed.next_token);
}

#[repr(C)]
pub struct N00bAwsShimSnsGetTopicAttributesOutput {
    pub attributes: *mut N00bAwsShimSnsKv,
    pub attributes_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_get_topic_attributes(
    cfg: *const N00bAwsShimConfig,
    topic_arn: *const c_char,
    out: *mut *mut N00bAwsShimSnsGetTopicAttributesOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(topic_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .get_topic_attributes()
            .topic_arn(arn)
            .send()
            .await
    });
    match outcome {
        Ok(r) => {
            let kvs: Vec<(String, String)> = r
                .attributes()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            let (ptr, count) = kv_vec_to_ffi(kvs);
            let s = N00bAwsShimSnsGetTopicAttributesOutput {
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
pub extern "C" fn n00b_aws_shim_sns_get_topic_attributes_free(
    p: *mut N00bAwsShimSnsGetTopicAttributesOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_kv_array(boxed.attributes, boxed.attributes_count);
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_set_topic_attributes(
    cfg: *const N00bAwsShimConfig,
    topic_arn: *const c_char,
    attribute_name: *const c_char,
    attribute_value: *const c_char,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(topic_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let an = match cstr_required(attribute_name) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let av = cstr_optional(attribute_value).unwrap_or_default();
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .set_topic_attributes()
            .topic_arn(arn)
            .attribute_name(an)
            .attribute_value(av)
            .send()
            .await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * Subscriptions
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSnsSubscribeInput {
    pub topic_arn: *const c_char,
    pub protocol: *const c_char,
    pub endpoint: *const c_char,
    pub return_subscription_arn: bool,
    pub attribute_keys: *const *const c_char,
    pub attribute_values: *const *const c_char,
    pub attributes_count: usize,
}

#[repr(C)]
pub struct N00bAwsShimSnsSubscribeOutput {
    pub subscription_arn: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_subscribe(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimSnsSubscribeInput,
    out: *mut *mut N00bAwsShimSnsSubscribeOutput,
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
    let topic = match cstr_required(inp.topic_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let protocol = match cstr_required(inp.protocol) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let endpoint = cstr_optional(inp.endpoint);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg)
            .subscribe()
            .topic_arn(topic)
            .protocol(protocol)
            .return_subscription_arn(inp.return_subscription_arn);
        if let Some(e) = endpoint {
            b = b.endpoint(e);
        }
        for (k, v) in collect_cstr_kv(
            inp.attribute_keys,
            inp.attribute_values,
            inp.attributes_count,
        ) {
            b = b.attributes(k, v);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSnsSubscribeOutput {
                subscription_arn: cstring_or_empty(r.subscription_arn()),
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
pub extern "C" fn n00b_aws_shim_sns_subscribe_free(p: *mut N00bAwsShimSnsSubscribeOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.subscription_arn);
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_unsubscribe(
    cfg: *const N00bAwsShimConfig,
    subscription_arn: *const c_char,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(subscription_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .unsubscribe()
            .subscription_arn(arn)
            .send()
            .await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_confirm_subscription(
    cfg: *const N00bAwsShimConfig,
    topic_arn: *const c_char,
    token: *const c_char,
    authenticate_on_unsubscribe: *const c_char,
    out: *mut *mut N00bAwsShimSnsSubscribeOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(topic_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let tok = match cstr_required(token) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let aoa = cstr_optional(authenticate_on_unsubscribe);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg)
            .confirm_subscription()
            .topic_arn(arn)
            .token(tok);
        if let Some(a) = aoa {
            b = b.authenticate_on_unsubscribe(a);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSnsSubscribeOutput {
                subscription_arn: cstring_or_empty(r.subscription_arn()),
            };
            unsafe {
                *out = Box::into_raw(Box::new(s));
            }
            N00bAwsShimStatus::Ok.as_i32()
        }
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[repr(C)]
pub struct N00bAwsShimSnsListSubscriptionsOutput {
    pub subscriptions: *mut N00bAwsShimSnsSubscription,
    pub subscriptions_count: usize,
    pub next_token: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_list_subscriptions(
    cfg: *const N00bAwsShimConfig,
    next_token: *const c_char,
    out: *mut *mut N00bAwsShimSnsListSubscriptionsOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let tok = cstr_optional(next_token);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg).list_subscriptions();
        if let Some(t) = tok {
            b = b.next_token(t);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let (ptr, count) = subs_vec_to_ffi(r.subscriptions());
            let s = N00bAwsShimSnsListSubscriptionsOutput {
                subscriptions: ptr,
                subscriptions_count: count,
                next_token: cstring_or_empty(r.next_token()),
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
pub extern "C" fn n00b_aws_shim_sns_list_subscriptions_free(
    p: *mut N00bAwsShimSnsListSubscriptionsOutput,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_subs_array(boxed.subscriptions, boxed.subscriptions_count);
    free_cstring_ptr(boxed.next_token);
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_list_subscriptions_by_topic(
    cfg: *const N00bAwsShimConfig,
    topic_arn: *const c_char,
    next_token: *const c_char,
    out: *mut *mut N00bAwsShimSnsListSubscriptionsOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(topic_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let tok = cstr_optional(next_token);
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg)
            .list_subscriptions_by_topic()
            .topic_arn(arn);
        if let Some(t) = tok {
            b = b.next_token(t);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let (ptr, count) = subs_vec_to_ffi(r.subscriptions());
            let s = N00bAwsShimSnsListSubscriptionsOutput {
                subscriptions: ptr,
                subscriptions_count: count,
                next_token: cstring_or_empty(r.next_token()),
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
pub extern "C" fn n00b_aws_shim_sns_get_subscription_attributes(
    cfg: *const N00bAwsShimConfig,
    subscription_arn: *const c_char,
    out: *mut *mut N00bAwsShimSnsGetTopicAttributesOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(subscription_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .get_subscription_attributes()
            .subscription_arn(arn)
            .send()
            .await
    });
    match outcome {
        Ok(r) => {
            let kvs: Vec<(String, String)> = r
                .attributes()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            let (ptr, count) = kv_vec_to_ffi(kvs);
            let s = N00bAwsShimSnsGetTopicAttributesOutput {
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
pub extern "C" fn n00b_aws_shim_sns_set_subscription_attributes(
    cfg: *const N00bAwsShimConfig,
    subscription_arn: *const c_char,
    attribute_name: *const c_char,
    attribute_value: *const c_char,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(subscription_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let an = match cstr_required(attribute_name) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let av = cstr_optional(attribute_value).unwrap_or_default();
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .set_subscription_attributes()
            .subscription_arn(arn)
            .attribute_name(an)
            .attribute_value(av)
            .send()
            .await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * Publishing
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSnsPublishInput {
    pub topic_arn: *const c_char,
    pub target_arn: *const c_char,
    pub phone_number: *const c_char,
    pub message: *const c_char,
    pub subject: *const c_char,
    pub message_structure: *const c_char,
    pub message_group_id: *const c_char,
    pub message_deduplication_id: *const c_char,
}

#[repr(C)]
pub struct N00bAwsShimSnsPublishOutput {
    pub message_id: *mut c_char,
    pub sequence_number: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_publish(
    cfg: *const N00bAwsShimConfig,
    input: *const N00bAwsShimSnsPublishInput,
    out: *mut *mut N00bAwsShimSnsPublishOutput,
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
    let message = match cstr_required(inp.message) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg).publish().message(message);
        if let Some(s) = cstr_optional(inp.topic_arn) {
            b = b.topic_arn(s);
        }
        if let Some(s) = cstr_optional(inp.target_arn) {
            b = b.target_arn(s);
        }
        if let Some(s) = cstr_optional(inp.phone_number) {
            b = b.phone_number(s);
        }
        if let Some(s) = cstr_optional(inp.subject) {
            b = b.subject(s);
        }
        if let Some(s) = cstr_optional(inp.message_structure) {
            b = b.message_structure(s);
        }
        if let Some(s) = cstr_optional(inp.message_group_id) {
            b = b.message_group_id(s);
        }
        if let Some(s) = cstr_optional(inp.message_deduplication_id) {
            b = b.message_deduplication_id(s);
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSnsPublishOutput {
                message_id: cstring_or_empty(r.message_id()),
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
pub extern "C" fn n00b_aws_shim_sns_publish_free(p: *mut N00bAwsShimSnsPublishOutput) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.message_id);
    free_cstring_ptr(boxed.sequence_number);
}

#[repr(C)]
pub struct N00bAwsShimSnsPublishBatchEntry {
    pub id: *const c_char,
    pub message: *const c_char,
    pub subject: *const c_char,
    pub message_structure: *const c_char,
    pub message_group_id: *const c_char,
    pub message_deduplication_id: *const c_char,
}

#[repr(C)]
pub struct N00bAwsShimSnsPublishBatchSuccess {
    pub id: *mut c_char,
    pub message_id: *mut c_char,
    pub sequence_number: *mut c_char,
}

#[repr(C)]
pub struct N00bAwsShimSnsPublishBatchOutput {
    pub successes: *mut N00bAwsShimSnsPublishBatchSuccess,
    pub successes_count: usize,
    pub failures: *mut N00bAwsShimSnsBatchError,
    pub failures_count: usize,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_publish_batch(
    cfg: *const N00bAwsShimConfig,
    topic_arn: *const c_char,
    entries: *const N00bAwsShimSnsPublishBatchEntry,
    entries_count: usize,
    out: *mut *mut N00bAwsShimSnsPublishBatchOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() || entries.is_null() || entries_count == 0 {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(topic_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg).publish_batch().topic_arn(arn);
        for i in 0..entries_count {
            let e = unsafe { &*entries.add(i) };
            let id = cstr_optional(e.id).unwrap_or_default();
            let msg = cstr_optional(e.message).unwrap_or_default();
            let mut eb = PublishBatchRequestEntry::builder().id(id).message(msg);
            if let Some(s) = cstr_optional(e.subject) {
                eb = eb.subject(s);
            }
            if let Some(s) = cstr_optional(e.message_structure) {
                eb = eb.message_structure(s);
            }
            if let Some(s) = cstr_optional(e.message_group_id) {
                eb = eb.message_group_id(s);
            }
            if let Some(s) = cstr_optional(e.message_deduplication_id) {
                eb = eb.message_deduplication_id(s);
            }
            if let Ok(entry) = eb.build() {
                b = b.publish_batch_request_entries(entry);
            }
        }
        b.send().await
    });
    match outcome {
        Ok(r) => {
            let succ: Vec<N00bAwsShimSnsPublishBatchSuccess> = r
                .successful()
                .iter()
                .map(|e| N00bAwsShimSnsPublishBatchSuccess {
                    id: cstring_or_empty(e.id()),
                    message_id: cstring_or_empty(e.message_id()),
                    sequence_number: cstring_or_empty(e.sequence_number()),
                })
                .collect();
            let succ_count = succ.len();
            let succ_ptr = if succ_count == 0 {
                ptr::null_mut()
            } else {
                Box::into_raw(succ.into_boxed_slice()) as *mut N00bAwsShimSnsPublishBatchSuccess
            };
            let fail_vec: Vec<N00bAwsShimSnsBatchError> = r
                .failed()
                .iter()
                .map(|e| N00bAwsShimSnsBatchError {
                    id: cstring_or_empty(Some(e.id())),
                    code: cstring_or_empty(Some(e.code())),
                    message: cstring_or_empty(e.message()),
                    sender_fault: e.sender_fault(),
                })
                .collect();
            let fail_count = fail_vec.len();
            let fail_ptr = if fail_count == 0 {
                ptr::null_mut()
            } else {
                Box::into_raw(fail_vec.into_boxed_slice()) as *mut N00bAwsShimSnsBatchError
            };
            let s = N00bAwsShimSnsPublishBatchOutput {
                successes: succ_ptr,
                successes_count: succ_count,
                failures: fail_ptr,
                failures_count: fail_count,
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
pub extern "C" fn n00b_aws_shim_sns_publish_batch_free(p: *mut N00bAwsShimSnsPublishBatchOutput) {
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
 * Permissions
 * ========================================================================= */

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_add_permission(
    cfg: *const N00bAwsShimConfig,
    topic_arn: *const c_char,
    label: *const c_char,
    aws_account_ids: *const *const c_char,
    aws_account_ids_count: usize,
    action_names: *const *const c_char,
    action_names_count: usize,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(topic_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let label = match cstr_required(label) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg)
            .add_permission()
            .topic_arn(arn)
            .label(label);
        for id in collect_cstrs(aws_account_ids, aws_account_ids_count) {
            b = b.aws_account_id(id);
        }
        for act in collect_cstrs(action_names, action_names_count) {
            b = b.action_name(act);
        }
        b.send().await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_remove_permission(
    cfg: *const N00bAwsShimConfig,
    topic_arn: *const c_char,
    label: *const c_char,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(topic_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let label = match cstr_required(label) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .remove_permission()
            .topic_arn(arn)
            .label(label)
            .send()
            .await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * Tagging
 * ========================================================================= */

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_list_tags_for_resource(
    cfg: *const N00bAwsShimConfig,
    resource_arn: *const c_char,
    out: *mut *mut N00bAwsShimSnsGetTopicAttributesOutput,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(resource_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .list_tags_for_resource()
            .resource_arn(arn)
            .send()
            .await
    });
    match outcome {
        Ok(r) => {
            let kvs: Vec<(String, String)> = r
                .tags()
                .iter()
                .map(|t| (t.key().to_string(), t.value().to_string()))
                .collect();
            let (ptr, count) = kv_vec_to_ffi(kvs);
            let s = N00bAwsShimSnsGetTopicAttributesOutput {
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
pub extern "C" fn n00b_aws_shim_sns_tag_resource(
    cfg: *const N00bAwsShimConfig,
    resource_arn: *const c_char,
    tag_keys: *const *const c_char,
    tag_values: *const *const c_char,
    tags_count: usize,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(resource_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg).tag_resource().resource_arn(arn);
        for (k, v) in collect_cstr_kv(tag_keys, tag_values, tags_count) {
            if let Ok(tag) = aws_sdk_sns::types::Tag::builder().key(k).value(v).build() {
                b = b.tags(tag);
            }
        }
        b.send().await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_untag_resource(
    cfg: *const N00bAwsShimConfig,
    resource_arn: *const c_char,
    tag_keys: *const *const c_char,
    tag_keys_count: usize,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(resource_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        let mut b = SnsClient::new(sdk_cfg).untag_resource().resource_arn(arn);
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
 * Data protection
 * ========================================================================= */

#[repr(C)]
pub struct N00bAwsShimSnsDataProtectionPolicy {
    pub data_protection_policy: *mut c_char,
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_get_data_protection_policy(
    cfg: *const N00bAwsShimConfig,
    resource_arn: *const c_char,
    out: *mut *mut N00bAwsShimSnsDataProtectionPolicy,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    if cfg.is_null() || out.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(resource_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .get_data_protection_policy()
            .resource_arn(arn)
            .send()
            .await
    });
    match outcome {
        Ok(r) => {
            let s = N00bAwsShimSnsDataProtectionPolicy {
                data_protection_policy: cstring_or_empty(r.data_protection_policy()),
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
pub extern "C" fn n00b_aws_shim_sns_data_protection_policy_free(
    p: *mut N00bAwsShimSnsDataProtectionPolicy,
) {
    if p.is_null() {
        return;
    }
    let boxed = unsafe { Box::from_raw(p) };
    free_cstring_ptr(boxed.data_protection_policy);
}

#[no_mangle]
pub extern "C" fn n00b_aws_shim_sns_put_data_protection_policy(
    cfg: *const N00bAwsShimConfig,
    resource_arn: *const c_char,
    data_protection_policy: *const c_char,
) -> i32 {
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let arn = match cstr_required(resource_arn) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let p = match cstr_required(data_protection_policy) {
        Some(s) => s,
        None => return N00bAwsShimStatus::ErrInvalidArg.as_i32(),
    };
    let sdk_cfg = unsafe { &(*cfg).inner };

    let outcome = runtime().block_on(async {
        SnsClient::new(sdk_cfg)
            .put_data_protection_policy()
            .resource_arn(arn)
            .data_protection_policy(p)
            .send()
            .await
    });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(e) => classify_generic_sdk_error(&e).as_i32(),
    }
}

/* =========================================================================
 * Internal: simple-op helper
 * =========================================================================
 *
 * The SNS surface has many one-shot ops with shape "validate input,
 * call SDK, ignore body, return status". The `simple_op` helper
 * collapses the boilerplate. We use a tiny local error enum so the
 * closure can short-circuit on a missing required argument.
 */

#[allow(dead_code)]
struct NoArgError;

#[allow(dead_code)]
enum SdkOrArg<E, R> {
    Sdk(aws_smithy_runtime_api::client::result::SdkError<E, R>),
    NoArg,
}

#[allow(dead_code)]
impl<E, R> From<NoArgError> for SdkOrArg<E, R> {
    fn from(_: NoArgError) -> Self {
        SdkOrArg::NoArg
    }
}

fn simple_op<F, Fut, R, E>(cfg: *const N00bAwsShimConfig, op: F) -> i32
where
    F: FnOnce(SnsClient) -> Fut,
    Fut: std::future::Future<
        Output = Result<R, SdkOrArg<E, aws_smithy_runtime_api::client::orchestrator::HttpResponse>>,
    >,
{
    if cfg.is_null() {
        return N00bAwsShimStatus::ErrInvalidArg.as_i32();
    }
    let sdk_cfg = unsafe { &(*cfg).inner };
    let outcome = runtime().block_on(async move { op(SnsClient::new(sdk_cfg)).await });
    match outcome {
        Ok(_) => N00bAwsShimStatus::Ok.as_i32(),
        Err(SdkOrArg::NoArg) => N00bAwsShimStatus::ErrInvalidArg.as_i32(),
        Err(SdkOrArg::Sdk(e)) => classify_generic_sdk_error(&e).as_i32(),
    }
}

// Suppress unused-import warnings; we keep these referenced via repr(C)
// types that downstream callers consume.
#[allow(dead_code)]
fn _force_message_attr(_: MessageAttributeValue) {}
