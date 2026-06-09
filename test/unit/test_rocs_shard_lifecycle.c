/** @file test/unit/test_rocs_shard_lifecycle.c - WP-003 lifecycle events. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "util/assert.h"

#include <rocs/shard.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

typedef struct {
    uint64_t marker;
} test_lifecycle_record_t;

static n00b_json_node_t *
test_lifecycle_record(uint64_t marker)
{
    test_lifecycle_record_t *record = n00b_alloc_size_with_opts(
        1,
        sizeof(test_lifecycle_record_t),
        &(n00b_alloc_opts_t){
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });

    record->marker = marker;
    return (n00b_json_node_t *)record;
}

static n00b_conduit_t *
test_lifecycle_conduit(void)
{
    auto conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));

    return n00b_result_get(conduit_r);
}

static n00b_store_lifecycle_topic_t *
test_lifecycle_topic(n00b_conduit_t *conduit)
{
    auto topic_r = n00b_store_lifecycle_topic_get(
        conduit,
        n00b_conduit_str_uri(r"rocs.lifecycle.test"));
    CHECK(n00b_result_is_ok(topic_r));

    return n00b_result_get(topic_r);
}

static n00b_store_lifecycle_inbox_t *
test_lifecycle_inbox(n00b_conduit_t                 *conduit,
                     n00b_store_lifecycle_topic_t  *topic)
{
    auto inbox_r = n00b_store_lifecycle_inbox_new(conduit);
    CHECK(n00b_result_is_ok(inbox_r));

    n00b_store_lifecycle_inbox_t *inbox = n00b_result_get(inbox_r);
    auto handle_r = n00b_store_lifecycle_subscribe(topic, inbox);
    CHECK(n00b_result_is_ok(handle_r));

    n00b_conduit_sub_handle_t handle = n00b_result_get(handle_r);
    CHECK(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);
    CHECK(n00b_conduit_sub_is_active(handle));

    return inbox;
}

static n00b_store_shard_t *
test_lifecycle_shard(uint64_t shard_id, uint64_t open_ts)
{
    auto shard_r = n00b_store_shard_new(.shard_id = shard_id,
                                        .open_ts  = open_ts);
    CHECK(n00b_result_is_ok(shard_r));

    return n00b_result_get(shard_r);
}

static void
test_lifecycle_helpers(void)
{
    auto bad_inbox = n00b_store_lifecycle_inbox_new(nullptr);
    CHECK(n00b_result_is_err(bad_inbox));
    CHECK(n00b_result_get_err(bad_inbox) == N00B_STORE_SHARD_ERR_ARG);

    auto bad_topic = n00b_store_lifecycle_topic_get(
        nullptr,
        n00b_conduit_str_uri(r"rocs.lifecycle.bad"));
    CHECK(n00b_result_is_err(bad_topic));
    CHECK(n00b_result_get_err(bad_topic) == N00B_STORE_SHARD_ERR_EVENT);

    n00b_conduit_t *conduit = test_lifecycle_conduit();
    n00b_store_lifecycle_topic_t *topic = test_lifecycle_topic(conduit);
    n00b_store_lifecycle_inbox_t *inbox =
        test_lifecycle_inbox(conduit, topic);

    CHECK(!n00b_store_lifecycle_inbox_has_messages(inbox));
    n00b_conduit_destroy(conduit);
}

static void
check_sealed_payload(n00b_store_lifecycle_msg_t *msg,
                     n00b_buffer_t              *image)
{
    CHECK(msg != nullptr);
    CHECK(n00b_conduit_msg_type(msg) == N00B_CONDUIT_MSG_USER);
    CHECK(msg->payload.kind == N00B_STORE_LIFECYCLE_SEALED);
    CHECK(msg->payload.shard_id == UINT64_C(0x7001));
    CHECK(msg->payload.record_count == 1);
    CHECK(msg->payload.byte_size == (uint64_t)n00b_buffer_len(image));
    CHECK(msg->payload.open_ts == 11);
    CHECK(msg->payload.seal_ts == 22);
    CHECK(msg->payload.drop_reason == nullptr);
}

static void
test_seal_event(void)
{
    n00b_conduit_t *conduit = test_lifecycle_conduit();
    n00b_store_lifecycle_topic_t *topic = test_lifecycle_topic(conduit);
    n00b_store_lifecycle_inbox_t *inbox =
        test_lifecycle_inbox(conduit, topic);
    n00b_store_shard_t *shard = test_lifecycle_shard(UINT64_C(0x7001), 11);

    auto append_r = n00b_store_shard_append(shard, test_lifecycle_record(1));
    CHECK(n00b_result_is_ok(append_r));

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts = 22,
                                        .topic   = topic);
    CHECK(n00b_result_is_ok(seal_r));
    CHECK(shard->state == N00B_SHARD_STATE_SEALED);
    CHECK(shard->seal_ts == 22);

    n00b_buffer_t *image = n00b_result_get(seal_r);
    CHECK(n00b_store_lifecycle_inbox_has_messages(inbox));

    n00b_store_lifecycle_msg_t *msg =
        n00b_store_lifecycle_inbox_pop(inbox);
    check_sealed_payload(msg, image);
    CHECK(!n00b_store_lifecycle_inbox_has_messages(inbox));

    n00b_conduit_destroy(conduit);
}

static void
test_no_topic_no_event(void)
{
    n00b_conduit_t *conduit = test_lifecycle_conduit();
    n00b_store_lifecycle_topic_t *topic = test_lifecycle_topic(conduit);
    n00b_store_lifecycle_inbox_t *inbox =
        test_lifecycle_inbox(conduit, topic);
    n00b_store_shard_t *shard = test_lifecycle_shard(UINT64_C(0x7002), 33);

    auto seal_r = n00b_store_shard_seal(shard, .seal_ts = 44);
    CHECK(n00b_result_is_ok(seal_r));
    CHECK(shard->state == N00B_SHARD_STATE_SEALED);
    CHECK(!n00b_store_lifecycle_inbox_has_messages(inbox));

    auto drop_r = n00b_store_shard_drop(shard);
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(shard->state == N00B_SHARD_STATE_DROPPED);
    CHECK(!n00b_store_lifecycle_inbox_has_messages(inbox));

    n00b_conduit_destroy(conduit);
}

static void
check_dropped_payload(n00b_store_lifecycle_msg_t *msg,
                      uint64_t                   shard_id,
                      uint64_t                   record_count,
                      uint64_t                   byte_size,
                      uint64_t                   open_ts,
                      uint64_t                   seal_ts,
                      n00b_string_t             *reason)
{
    CHECK(msg != nullptr);
    CHECK(n00b_conduit_msg_type(msg) == N00B_CONDUIT_MSG_USER);
    CHECK(msg->payload.kind == N00B_STORE_LIFECYCLE_DROPPED);
    CHECK(msg->payload.shard_id == shard_id);
    CHECK(msg->payload.record_count == record_count);
    CHECK(msg->payload.byte_size == byte_size);
    CHECK(msg->payload.open_ts == open_ts);
    CHECK(msg->payload.seal_ts == seal_ts);
    CHECK(msg->payload.drop_reason == reason);
}

static n00b_buffer_t *
seal_for_drop(n00b_store_shard_t *shard, uint64_t seal_ts)
{
    auto seal_r = n00b_store_shard_seal(shard, .seal_ts = seal_ts);
    CHECK(n00b_result_is_ok(seal_r));
    CHECK(shard->state == N00B_SHARD_STATE_SEALED);

    return n00b_result_get(seal_r);
}

static void
test_drop_event_with_reason(void)
{
    n00b_conduit_t *conduit = test_lifecycle_conduit();
    n00b_store_lifecycle_topic_t *topic = test_lifecycle_topic(conduit);
    n00b_store_lifecycle_inbox_t *inbox =
        test_lifecycle_inbox(conduit, topic);
    n00b_store_shard_t *shard = test_lifecycle_shard(UINT64_C(0x7003), 55);

    CHECK(n00b_result_is_ok(n00b_store_shard_append(
        shard,
        test_lifecycle_record(10))));
    CHECK(n00b_result_is_ok(n00b_store_shard_append(
        shard,
        test_lifecycle_record(11))));

    n00b_buffer_t  *image      = seal_for_drop(shard, 66);
    uint64_t        image_size = (uint64_t)n00b_buffer_len(image);
    n00b_string_t  *reason     = r"retention-window";
    auto            drop_r     = n00b_store_shard_drop(shard,
                                                       .topic       = topic,
                                                       .drop_reason = reason,
                                                       .byte_size   = image_size);
    CHECK(n00b_result_is_ok(drop_r));
    CHECK(n00b_result_get(drop_r));
    CHECK(shard->state == N00B_SHARD_STATE_DROPPED);

    n00b_store_lifecycle_msg_t *msg =
        n00b_store_lifecycle_inbox_pop(inbox);
    check_dropped_payload(msg,
                          UINT64_C(0x7003),
                          2,
                          image_size,
                          55,
                          66,
                          reason);
    CHECK(!n00b_store_lifecycle_inbox_has_messages(inbox));

    auto append_r = n00b_store_shard_append(shard, test_lifecycle_record(12));
    CHECK(n00b_result_is_err(append_r));
    CHECK(n00b_result_get_err(append_r) == N00B_STORE_SHARD_ERR_STATE);

    auto seal_again = n00b_store_shard_seal(shard, .seal_ts = 77);
    CHECK(n00b_result_is_err(seal_again));
    CHECK(n00b_result_get_err(seal_again) == N00B_STORE_SHARD_ERR_STATE);

    auto drop_again = n00b_store_shard_drop(shard, .topic = topic);
    CHECK(n00b_result_is_err(drop_again));
    CHECK(n00b_result_get_err(drop_again) == N00B_STORE_SHARD_ERR_STATE);

    n00b_conduit_destroy(conduit);
}

static void
test_drop_event_without_reason(void)
{
    n00b_conduit_t *conduit = test_lifecycle_conduit();
    n00b_store_lifecycle_topic_t *topic = test_lifecycle_topic(conduit);
    n00b_store_lifecycle_inbox_t *inbox =
        test_lifecycle_inbox(conduit, topic);
    n00b_store_shard_t *shard = test_lifecycle_shard(UINT64_C(0x7004), 88);

    n00b_buffer_t *image = seal_for_drop(shard, 99);
    uint64_t       size  = (uint64_t)n00b_buffer_len(image);

    auto drop_r = n00b_store_shard_drop(shard,
                                        .topic     = topic,
                                        .byte_size = size);
    CHECK(n00b_result_is_ok(drop_r));

    n00b_store_lifecycle_msg_t *msg =
        n00b_store_lifecycle_inbox_pop(inbox);
    check_dropped_payload(msg, UINT64_C(0x7004), 0, size, 88, 99, nullptr);

    n00b_conduit_destroy(conduit);
}

static void
test_invalid_drop_states(void)
{
    auto null_drop = n00b_store_shard_drop(nullptr);
    CHECK(n00b_result_is_err(null_drop));
    CHECK(n00b_result_get_err(null_drop) == N00B_STORE_SHARD_ERR_ARG);

    n00b_store_shard_t *open = test_lifecycle_shard(UINT64_C(0x7005), 100);
    auto open_drop = n00b_store_shard_drop(open);
    CHECK(n00b_result_is_err(open_drop));
    CHECK(n00b_result_get_err(open_drop) == N00B_STORE_SHARD_ERR_STATE);
    CHECK(open->state == N00B_SHARD_STATE_OPEN);
}

static void
test_event_topic_failure_rolls_back(void)
{
    n00b_conduit_t *conduit = test_lifecycle_conduit();
    n00b_store_lifecycle_topic_t *topic = test_lifecycle_topic(conduit);
    n00b_conduit_topic_close((n00b_conduit_topic_base_t *)topic);

    n00b_store_shard_t *seal_shard = test_lifecycle_shard(UINT64_C(0x7006), 1);
    auto seal_r = n00b_store_shard_seal(seal_shard,
                                        .seal_ts = 2,
                                        .topic   = topic);
    CHECK(n00b_result_is_err(seal_r));
    CHECK(n00b_result_get_err(seal_r) == N00B_STORE_SHARD_ERR_EVENT);
    CHECK(seal_shard->state == N00B_SHARD_STATE_OPEN);
    CHECK(seal_shard->seal_ts == 0);

    n00b_store_shard_t *drop_shard = test_lifecycle_shard(UINT64_C(0x7007), 3);
    n00b_buffer_t      *image      = seal_for_drop(drop_shard, 4);
    auto drop_r = n00b_store_shard_drop(drop_shard,
                                        .topic     = topic,
                                        .byte_size = (uint64_t)n00b_buffer_len(image));
    CHECK(n00b_result_is_err(drop_r));
    CHECK(n00b_result_get_err(drop_r) == N00B_STORE_SHARD_ERR_EVENT);
    CHECK(drop_shard->state == N00B_SHARD_STATE_SEALED);

    n00b_conduit_destroy(conduit);
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_lifecycle_helpers();
    test_seal_event();
    test_no_topic_no_event();
    test_drop_event_with_reason();
    test_drop_event_without_reason();
    test_invalid_drop_states();
    test_event_topic_failure_rolls_back();

    return 0;
}
