/*
 * test_xform_json.c — Tests for JSON conduit transforms.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/xform_json.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/atomic.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_json_node_t *
json_obj_get(n00b_json_node_t *obj, const char *key)
{
    return n00b_json_object_get_cstr(obj, key);
}

static n00b_conduit_t *
make_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static n00b_conduit_topic_t(n00b_buffer_t *) *
make_buf_topic(n00b_conduit_t *c)
{
    static _Atomic(uint64_t) next_id = 8000;
    uint64_t id = n00b_atomic_add(&next_id, 1);
    n00b_conduit_uri_t uri =
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, id);
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_topic_get(c, uri,
            sizeof(n00b_conduit_topic_t(n00b_buffer_t *)));
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_t(n00b_buffer_t *) *topic =
        (n00b_conduit_topic_t(n00b_buffer_t *) *)
            n00b_result_get(tr);
    topic->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_buffer_t *) *);
    topic->inbox = nullptr;
    return topic;
}

static n00b_conduit_topic_t(n00b_json_node_t *) *
make_json_topic(n00b_conduit_t *c)
{
    static _Atomic(uint64_t) next_id = 9000;
    uint64_t id = n00b_atomic_add(&next_id, 1);
    n00b_conduit_uri_t uri =
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, id);
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_topic_get(c, uri,
            sizeof(n00b_conduit_topic_t(n00b_json_node_t *)));
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_t(n00b_json_node_t *) *topic =
        (n00b_conduit_topic_t(n00b_json_node_t *) *)
            n00b_result_get(tr);
    topic->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_json_node_t *) *);
    topic->inbox = nullptr;
    return topic;
}

static void
push_buf(n00b_conduit_topic_t(n00b_buffer_t *) *topic,
         const char *data, size_t len)
{
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_alloc(n00b_conduit_message_t(n00b_buffer_t *));
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = (n00b_conduit_topic_base_t *)topic;
    msg->header.generation = n00b_atomic_load(&topic->generation);
    msg->header.epoch      = n00b_atomic_load(&topic->epoch);
    msg->payload           = n00b_buffer_from_bytes((char *)data, (int64_t)len);
    n00b_conduit_topic_deliver_msg(n00b_buffer_t *, topic, msg,
                                   N00B_CONDUIT_OP_ALL);
}

static void
push_json_node(n00b_conduit_topic_t(n00b_json_node_t *) *topic,
               n00b_json_node_t *node)
{
    n00b_conduit_message_t(n00b_json_node_t *) *msg =
        n00b_alloc(n00b_conduit_message_t(n00b_json_node_t *));
    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = (n00b_conduit_topic_base_t *)topic;
    msg->header.generation = n00b_atomic_load(&topic->generation);
    msg->header.epoch      = n00b_atomic_load(&topic->epoch);
    msg->payload           = node;
    n00b_conduit_topic_deliver_msg(n00b_json_node_t *, topic, msg,
                                   N00B_CONDUIT_OP_ALL);
}

static n00b_json_node_t *
pop_json(n00b_conduit_inbox_t(n00b_json_node_t *) *inbox)
{
    n00b_conduit_message_t(n00b_json_node_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_json_node_t *, inbox);
    if (!msg) return nullptr;
    return msg->payload;
}

static n00b_buffer_t *
pop_buf(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
{
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
    if (!msg) return nullptr;
    return msg->payload;
}

// ============================================================================
// Tests
// ============================================================================

static void
test_json_value_xform_basic(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_json_parse_new(c, src);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    auto out = n00b_conduit_xform_topic(
        n00b_buffer_t *, n00b_json_node_t *, xf);
    out->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_json_node_t *) *);
    out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_json_node_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_json_node_t *));
    n00b_conduit_inbox_init(n00b_json_node_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_json_node_t *, out, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    const char *json = "{\"key\":\"value\"}";
    push_buf(src, json, strlen(json));
    usleep(150000);

    n00b_json_node_t *node = pop_json(inbox);
    assert(node != nullptr);
    assert(n00b_json_is_object(node));

    n00b_json_node_t *val = json_obj_get(node, "key");
    assert(val != nullptr);
    assert(n00b_json_is_string(val));
    assert(strcmp(n00b_json_as_cstr(val), "value") == 0);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] json value xform basic\n");
}

static void
test_json_value_xform_streaming(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_json_parse_new(c, src);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    auto out = n00b_conduit_xform_topic(
        n00b_buffer_t *, n00b_json_node_t *, xf);
    out->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_json_node_t *) *);
    out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_json_node_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_json_node_t *));
    n00b_conduit_inbox_init(n00b_json_node_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_json_node_t *, out, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // Push JSON in two chunks.
    push_buf(src, "{\"n\":", 5);
    usleep(100000);

    // Should not parse yet (incomplete).
    assert(pop_json(inbox) == nullptr);

    push_buf(src, "42}", 3);
    usleep(150000);

    n00b_json_node_t *node = pop_json(inbox);
    assert(node != nullptr);
    assert(n00b_json_is_object(node));

    n00b_json_node_t *n_val = json_obj_get(node, "n");
    assert(n_val != nullptr);
    assert(n00b_json_is_int(n_val));
    assert(n00b_json_as_i64(n_val) == 42);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] json value xform streaming\n");
}

static void
test_json_encode_xform(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_json_node_t *) *src = make_json_topic(c);

    auto r = n00b_conduit_json_encode_new(c, src);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    auto out = n00b_conduit_xform_topic(
        n00b_json_node_t *, n00b_buffer_t *, xf);
    out->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_buffer_t *) *);
    out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_buffer_t *));
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_buffer_t *, out, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // Create a JSON object and push it.
    n00b_json_node_t *obj = n00b_json_object_new();
    n00b_json_object_put(obj, "x", n00b_json_int_new(99));
    push_json_node(src, obj);
    usleep(150000);

    n00b_buffer_t *buf = pop_buf(inbox);
    assert(buf != nullptr);

    int64_t len = 0;
    char *data = n00b_buffer_to_c(buf, &len);
    assert(len > 0);

    // The output should be valid JSON containing "x":99.
    const char *err = nullptr;
    n00b_json_node_t *parsed = n00b_json_parse(data, (size_t)len, &err);
    assert(parsed != nullptr);
    assert(n00b_json_is_object(parsed));

    n00b_json_node_t *x_val = json_obj_get(parsed, "x");
    assert(x_val != nullptr);
    assert(n00b_json_is_int(x_val));
    assert(n00b_json_as_i64(x_val) == 99);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] json encode xform\n");
}

static void
test_json_xform_empty(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    auto r = n00b_conduit_json_parse_new(c, src);
    assert(n00b_result_is_ok(r));
    auto xf = n00b_result_get(r);

    auto out = n00b_conduit_xform_topic(
        n00b_buffer_t *, n00b_json_node_t *, xf);
    out->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_json_node_t *) *);
    out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_json_node_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_json_node_t *));
    n00b_conduit_inbox_init(n00b_json_node_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_json_node_t *, out, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);

    // Push empty buffer — should produce no output.
    push_buf(src, "", 0);
    usleep(100000);

    assert(pop_json(inbox) == nullptr);

    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);
    printf("  [PASS] json xform empty input\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_xform_json:\n");
    fflush(stdout);

    test_json_value_xform_basic();     fflush(stdout);
    test_json_value_xform_streaming(); fflush(stdout);
    test_json_encode_xform();          fflush(stdout);
    test_json_xform_empty();           fflush(stdout);

    printf("All JSON transform tests passed.\n");
    n00b_shutdown();
    return 0;
}
