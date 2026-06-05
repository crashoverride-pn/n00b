/* src/aws/n00b_aws_sns.c — minimal SNS wrap.
 *
 * Two ops + a producer-side `n00b_queue_t` factory. Mirrors the
 * pattern in n00b_aws_sqs.c: bracket every blocking shim call with
 * STW suspend/resume, marshal n00b_string_t to UTF-8 cstr at the
 * boundary, return n00b_result_t for fallible ops.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "core/stw.h"
#include "adt/result.h"
#include "util/queue.h"

#include "aws/n00b_aws.h"
#include "aws/n00b_aws_config.h"
#include "aws/n00b_aws_sns.h"

#include "n00b_aws_shim_generated.h"
#include "internal/aws/config.h"

n00b_result_t(n00b_string_t *)
n00b_aws_sns_subscribe(n00b_aws_config_t *cfg,
                       n00b_string_t     *topic_arn,
                       n00b_string_t     *protocol,
                       n00b_string_t     *endpoint)
{
    if (!cfg || !cfg->shim
        || !topic_arn || topic_arn->u8_bytes == 0
        || !protocol  || protocol->u8_bytes  == 0
        || !endpoint  || endpoint->u8_bytes  == 0) {
        return n00b_result_err(n00b_string_t *, N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_sns_subscribe_input_t input = {
        .topic_arn               = topic_arn->data,
        .protocol                = protocol->data,
        .endpoint                = endpoint->data,
        .return_subscription_arn = true,
        .attribute_keys          = nullptr,
        .attribute_values        = nullptr,
        .attributes_count        = 0,
    };
    n00b_aws_shim_sns_subscribe_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sns_subscribe(cfg->shim, &input, &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_string_t *, rc);
    }
    n00b_string_t *sub_arn = n00b_string_from_cstr(raw->subscription_arn
                                                       ? raw->subscription_arn
                                                       : "");
    n00b_aws_shim_sns_subscribe_free(raw);
    return n00b_result_ok(n00b_string_t *, sub_arn);
}

n00b_result_t(n00b_string_t *)
n00b_aws_sns_publish(n00b_aws_config_t *cfg,
                     n00b_string_t     *topic_arn,
                     n00b_string_t     *message)
{
    if (!cfg || !cfg->shim
        || !topic_arn || topic_arn->u8_bytes == 0
        || !message) {
        return n00b_result_err(n00b_string_t *, N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_sns_publish_input_t input = {
        .topic_arn                = topic_arn->data,
        .target_arn               = nullptr,
        .phone_number             = nullptr,
        .message                  = message->data,
        .subject                  = nullptr,
        .message_structure        = nullptr,
        .message_group_id         = nullptr,
        .message_deduplication_id = nullptr,
    };
    n00b_aws_shim_sns_publish_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sns_publish(cfg->shim, &input, &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_string_t *, rc);
    }
    n00b_string_t *msg_id = n00b_string_from_cstr(raw->message_id
                                                      ? raw->message_id
                                                      : "");
    n00b_aws_shim_sns_publish_free(raw);
    return n00b_result_ok(n00b_string_t *, msg_id);
}

/* =========================================================================
 * Producer-only `n00b_queue_t` backend over an SNS topic
 * ========================================================================= */

typedef struct {
    n00b_aws_config_t *cfg;
    n00b_string_t     *topic_arn;
} sns_publisher_state_t;

static int
sns_publisher_send(void *self, n00b_string_t *body)
{
    sns_publisher_state_t *s = self;
    auto pr = n00b_aws_sns_publish(s->cfg, s->topic_arn, body);
    return n00b_result_is_err(pr) ? -1 : 0;
}

static const n00b_queue_vtable_t sns_publisher_vtable = {
    .receive_batch     = nullptr,
    .delete_one        = nullptr,
    .change_visibility = nullptr,
    .send              = sns_publisher_send,
    .enqueue_fake      = nullptr,
    .pending_count     = nullptr,
};

n00b_queue_t *
n00b_aws_sns_publisher_queue(n00b_aws_config_t *cfg,
                             n00b_string_t     *topic_arn) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!cfg || !topic_arn || topic_arn->u8_bytes == 0) {
        return nullptr;
    }
    sns_publisher_state_t *s = n00b_alloc(sns_publisher_state_t,
                                          N00B_ALLOC_OPTS(allocator));
    s->cfg       = cfg;
    s->topic_arn = topic_arn;
    return n00b_queue_new_backend(&sns_publisher_vtable, s,
                                  .allocator = allocator);
}
