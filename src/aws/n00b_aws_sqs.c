/* src/aws/n00b_aws_sqs.c — libn00b_aws's SQS wrap.
 *
 * Phase 3c surface focused on what SKP's Phase 3d ingest worker
 * exercises (receive / delete / change-visibility / send /
 * get-queue-url / get-queue-attributes). The Rust shim already
 * exports the full Smithy surface; the wraps below grow over time.
 *
 * Same conventions as n00b_aws_sts.c — STW suspend/resume bracket
 * around every blocking SDK call, n00b_string_from_cstr on every
 * Rust-owned C string before we drop the shim-side allocation.
 */

#include "n00b.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/stw.h"
#include "adt/list.h"
#include "adt/result.h"

#include "util/queue.h"
#include "aws/n00b_aws.h"
#include "aws/n00b_aws_config.h"
#include "aws/n00b_aws_sqs.h"

#include "n00b_aws_shim_generated.h"
#include "internal/aws/config.h"

/* =========================================================================
 * Receive
 * ========================================================================= */

n00b_result_t(n00b_aws_sqs_receive_batch_t *)
n00b_aws_sqs_receive(n00b_aws_config_t *cfg,
                     n00b_string_t     *queue_url) _kargs {
    int32_t         max_messages                = 10;
    int32_t         wait_time_seconds           = 20;
    int32_t         visibility_timeout          = 0;
    n00b_string_t  *receive_request_attempt_id  = nullptr;
}
{
    if (!cfg || !cfg->shim || !queue_url || queue_url->u8_bytes == 0) {
        return n00b_result_err(n00b_aws_sqs_receive_batch_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    const char *attempt = receive_request_attempt_id
                              ? receive_request_attempt_id->data
                              : nullptr;
    n00b_aws_shim_sqs_receive_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sqs_receive_message(cfg->shim,
                                               queue_url->data,
                                               max_messages,
                                               wait_time_seconds,
                                               visibility_timeout,
                                               attempt,
                                               &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_sqs_receive_batch_t *, rc);
    }

    n00b_aws_sqs_receive_batch_t *out
        = n00b_alloc(n00b_aws_sqs_receive_batch_t);
    out->count = raw->messages_count;
    if (out->count > 0) {
        out->messages = n00b_alloc_array(n00b_aws_sqs_message_t *, out->count);
        for (size_t i = 0; i < out->count; i++) {
            n00b_aws_shim_sqs_message_t *m = &raw->messages[i];
            n00b_aws_sqs_message_t      *n = n00b_alloc(n00b_aws_sqs_message_t);
            n->message_id     = n00b_string_from_cstr(m->message_id     ? m->message_id     : "");
            n->receipt_handle = n00b_string_from_cstr(m->receipt_handle ? m->receipt_handle : "");
            n->body           = n00b_string_from_cstr(m->body           ? m->body           : "");
            n->md5_of_body    = n00b_string_from_cstr(m->md5_of_body    ? m->md5_of_body    : "");
            n->approximate_receive_count  = m->approximate_receive_count;
            n->sent_timestamp_ms          = m->sent_timestamp_ms;
            n->first_receive_timestamp_ms = m->first_receive_timestamp_ms;
            out->messages[i] = n;
        }
    }
    else {
        out->messages = nullptr;
    }
    n00b_aws_shim_sqs_receive_output_free(raw);
    return n00b_result_ok(n00b_aws_sqs_receive_batch_t *, out);
}

/* =========================================================================
 * Delete / Change visibility / Send
 * ========================================================================= */

n00b_aws_status_t
n00b_aws_sqs_delete_message(n00b_aws_config_t *cfg,
                            n00b_string_t     *queue_url,
                            n00b_string_t     *receipt_handle)
{
    if (!cfg || !cfg->shim
        || !queue_url || queue_url->u8_bytes == 0
        || !receipt_handle || receipt_handle->u8_bytes == 0) {
        return N00B_AWS_ERR_INVALID_ARG;
    }
    int rc;
    {
        rc = n00b_aws_shim_sqs_delete_message(cfg->shim,
                                              queue_url->data,
                                              receipt_handle->data);
    }
    return (n00b_aws_status_t)rc;
}

n00b_aws_status_t
n00b_aws_sqs_change_message_visibility(n00b_aws_config_t *cfg,
                                       n00b_string_t     *queue_url,
                                       n00b_string_t     *receipt_handle,
                                       int32_t            visibility_timeout)
{
    if (!cfg || !cfg->shim
        || !queue_url || queue_url->u8_bytes == 0
        || !receipt_handle || receipt_handle->u8_bytes == 0
        || visibility_timeout < 0) {
        return N00B_AWS_ERR_INVALID_ARG;
    }
    int rc;
    {
        rc = n00b_aws_shim_sqs_change_message_visibility(cfg->shim,
                                                         queue_url->data,
                                                         receipt_handle->data,
                                                         visibility_timeout);
    }
    return (n00b_aws_status_t)rc;
}

n00b_result_t(n00b_aws_sqs_send_result_t *)
n00b_aws_sqs_send_message(n00b_aws_config_t *cfg,
                          n00b_string_t     *queue_url,
                          n00b_string_t     *body) _kargs {
    int32_t         delay_seconds            = 0;
    n00b_string_t  *message_group_id         = nullptr;
    n00b_string_t  *message_deduplication_id = nullptr;
}
{
    if (!cfg || !cfg->shim
        || !queue_url || queue_url->u8_bytes == 0
        || !body) {
        return n00b_result_err(n00b_aws_sqs_send_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_sqs_send_input_t inp = {
        .queue_url                 = queue_url->data,
        .message_body              = body->data,
        .delay_seconds             = delay_seconds,
        .message_group_id          = message_group_id         ? message_group_id->data         : nullptr,
        .message_deduplication_id  = message_deduplication_id ? message_deduplication_id->data : nullptr,
    };
    n00b_aws_shim_sqs_send_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sqs_send_message(cfg->shim, &inp, &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_sqs_send_result_t *, rc);
    }
    n00b_aws_sqs_send_result_t *out = n00b_alloc(n00b_aws_sqs_send_result_t);
    out->message_id          = n00b_string_from_cstr(raw->message_id          ? raw->message_id          : "");
    out->md5_of_message_body = n00b_string_from_cstr(raw->md5_of_message_body ? raw->md5_of_message_body : "");
    out->sequence_number     = n00b_string_from_cstr(raw->sequence_number     ? raw->sequence_number     : "");
    n00b_aws_shim_sqs_send_output_free(raw);
    return n00b_result_ok(n00b_aws_sqs_send_result_t *, out);
}

/* =========================================================================
 * Queue management
 * ========================================================================= */

n00b_result_t(n00b_string_t *)
n00b_aws_sqs_get_queue_url(n00b_aws_config_t *cfg,
                           n00b_string_t     *queue_name) _kargs {
    n00b_string_t *queue_owner_account = nullptr;
}
{
    if (!cfg || !cfg->shim
        || !queue_name || queue_name->u8_bytes == 0) {
        return n00b_result_err(n00b_string_t *, N00B_AWS_ERR_INVALID_ARG);
    }

    const char *owner = queue_owner_account
                            ? queue_owner_account->data
                            : nullptr;
    n00b_aws_shim_sqs_get_queue_url_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sqs_get_queue_url(cfg->shim,
                                             queue_name->data,
                                             owner,
                                             &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_string_t *, rc);
    }
    n00b_string_t *out = n00b_string_from_cstr(raw->queue_url
                                                   ? raw->queue_url
                                                   : "");
    n00b_aws_shim_sqs_get_queue_url_free(raw);
    return n00b_result_ok(n00b_string_t *, out);
}

n00b_result_t(n00b_list_t(n00b_string_t *) *)
n00b_aws_sqs_get_queue_attributes(n00b_aws_config_t *cfg,
                                  n00b_string_t     *queue_url) _kargs {
    n00b_list_t(n00b_string_t *) *attribute_names = nullptr;
}
{
    if (!cfg || !cfg->shim
        || !queue_url || queue_url->u8_bytes == 0) {
        return n00b_result_err(n00b_list_t(n00b_string_t *) *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    /* Marshal optional attribute-name list to a parallel cstr array. */
    const char **name_cstrs = nullptr;
    size_t       name_count = 0;
    if (attribute_names) {
        int len = n00b_list_len(*attribute_names);
        if (len > 0) {
            name_count = (size_t)len;
            name_cstrs = n00b_alloc_array(const char *, len);
            for (int i = 0; i < len; i++) {
                n00b_string_t *s = n00b_list_get(*attribute_names, i);
                name_cstrs[i] = s ? s->data : "";
            }
        }
    }

    n00b_aws_shim_sqs_get_queue_attributes_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sqs_get_queue_attributes(cfg->shim,
                                                    queue_url->data,
                                                    name_cstrs,
                                                    name_count,
                                                    &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_list_t(n00b_string_t *) *, rc);
    }

    /* Flatten the kv array into alternating [k0, v0, k1, v1, …].
     * `n00b_list_t(T)` is a value-typed generic struct, so we put one
     * on the heap and overwrite it with a fresh private list. */
    n00b_list_t(n00b_string_t *) *out = n00b_alloc(n00b_list_t(n00b_string_t *));
    *out = n00b_list_new_private(n00b_string_t *);
    for (size_t i = 0; i < raw->attributes_count; i++) {
        n00b_list_push(*out, n00b_string_from_cstr(
            raw->attributes[i].key ? raw->attributes[i].key : ""));
        n00b_list_push(*out, n00b_string_from_cstr(
            raw->attributes[i].value ? raw->attributes[i].value : ""));
    }
    n00b_aws_shim_sqs_get_queue_attributes_free(raw);
    return n00b_result_ok(n00b_list_t(n00b_string_t *) *, out);
}

n00b_result_t(n00b_string_t *)
n00b_aws_sqs_create_queue(n00b_aws_config_t *cfg,
                          n00b_string_t     *queue_name)
{
    if (!cfg || !cfg->shim
        || !queue_name || queue_name->u8_bytes == 0) {
        return n00b_result_err(n00b_string_t *, N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_sqs_create_queue_input_t input = {
        .queue_name       = queue_name->data,
        .attribute_keys   = nullptr,
        .attribute_values = nullptr,
        .attributes_count = 0,
        .tag_keys         = nullptr,
        .tag_values       = nullptr,
        .tags_count       = 0,
    };
    n00b_aws_shim_sqs_create_queue_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sqs_create_queue(cfg->shim, &input, &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_string_t *, rc);
    }
    n00b_string_t *url = n00b_string_from_cstr(raw->queue_url
                                                   ? raw->queue_url
                                                   : "");
    n00b_aws_shim_sqs_create_queue_free(raw);
    return n00b_result_ok(n00b_string_t *, url);
}

n00b_aws_status_t
n00b_aws_sqs_set_queue_attributes(n00b_aws_config_t            *cfg,
                                  n00b_string_t                *queue_url,
                                  n00b_list_t(n00b_string_t *) *attributes)
{
    if (!cfg || !cfg->shim
        || !queue_url || queue_url->u8_bytes == 0
        || !attributes) {
        return N00B_AWS_ERR_INVALID_ARG;
    }

    /* attributes is an alternating-kv list; split into parallel arrays. */
    int total = n00b_list_len(*attributes);
    if (total <= 0 || (total & 1) != 0) {
        return N00B_AWS_ERR_INVALID_ARG;
    }
    size_t       count = (size_t)(total / 2);
    const char **keys  = n00b_alloc_array(const char *, count);
    const char **vals  = n00b_alloc_array(const char *, count);
    for (size_t i = 0; i < count; i++) {
        n00b_string_t *k = n00b_list_get(*attributes, (int)(2 * i));
        n00b_string_t *v = n00b_list_get(*attributes, (int)(2 * i + 1));
        keys[i] = k ? k->data : "";
        vals[i] = v ? v->data : "";
    }

    int rc;
    {
        rc = n00b_aws_shim_sqs_set_queue_attributes(cfg->shim,
                                                    queue_url->data,
                                                    keys,
                                                    vals,
                                                    count);
    }
    return (n00b_aws_status_t)rc;
}

/* =========================================================================
 * Broker-neutral queue (n00b_queue_t) backend over SQS
 * ========================================================================= */

typedef struct {
    n00b_aws_config_t *cfg;
    n00b_string_t     *queue_url;
} sqs_queue_state_t;

static int
sqs_queue_receive(void                 *self,
                  int                   max_messages,
                  int                   wait_seconds,
                  int                   visibility_seconds,
                  n00b_queue_message_t *out,
                  int                  *out_count)
{
    sqs_queue_state_t *s = self;
    auto rresult = n00b_aws_sqs_receive(
        s->cfg, s->queue_url,
        .max_messages       = max_messages > 10 ? 10 : (int32_t)max_messages,
        .wait_time_seconds  = wait_seconds  > 20 ? 20 : (int32_t)wait_seconds,
        .visibility_timeout = (int32_t)visibility_seconds);
    if (n00b_result_is_err(rresult)) {
        if (out_count) { *out_count = 0; }
        return -1;
    }
    n00b_aws_sqs_receive_batch_t *batch = n00b_result_get(rresult);
    int taken = (int)batch->count;
    if (taken > max_messages) {
        taken = max_messages;
    }
    for (int i = 0; i < taken; i++) {
        n00b_aws_sqs_message_t *m = batch->messages[i];
        out[i].body           = m->body;
        out[i].receipt_handle = m->receipt_handle;
        out[i].receive_count  = (uint32_t)m->approximate_receive_count;
    }
    if (out_count) { *out_count = taken; }
    return 0;
}

static int
sqs_queue_delete(void *self, n00b_string_t *receipt_handle)
{
    sqs_queue_state_t *s = self;
    n00b_aws_status_t status = n00b_aws_sqs_delete_message(s->cfg,
                                                           s->queue_url,
                                                           receipt_handle);
    return status == N00B_AWS_OK ? 0 : 1;
}

static int
sqs_queue_change_visibility(void *self, n00b_string_t *receipt_handle,
                            int seconds)
{
    sqs_queue_state_t *s = self;
    n00b_aws_status_t status = n00b_aws_sqs_change_message_visibility(
        s->cfg, s->queue_url, receipt_handle, (int32_t)seconds);
    return status == N00B_AWS_OK ? 0 : 1;
}

static int
sqs_queue_send(void *self, n00b_string_t *body)
{
    sqs_queue_state_t *s = self;
    auto sresult = n00b_aws_sqs_send_message(s->cfg, s->queue_url, body);
    return n00b_result_is_err(sresult) ? -1 : 0;
}

static const n00b_queue_vtable_t sqs_queue_vtable = {
    .receive_batch     = sqs_queue_receive,
    .delete_one        = sqs_queue_delete,
    .change_visibility = sqs_queue_change_visibility,
    .send              = sqs_queue_send,
    .enqueue_fake      = nullptr,
    .pending_count     = nullptr,
};

n00b_queue_t *
n00b_aws_sqs_queue(n00b_aws_config_t *cfg, n00b_string_t *queue_url) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!cfg || !queue_url || queue_url->u8_bytes == 0) {
        return nullptr;
    }
    sqs_queue_state_t *s = n00b_alloc(sqs_queue_state_t,
                                      N00B_ALLOC_OPTS(allocator));
    s->cfg       = cfg;
    s->queue_url = queue_url;
    return n00b_queue_new_backend(&sqs_queue_vtable, s,
                                  .allocator = allocator);
}
