/*
 * test_xform.c — Tests for the conduit pipeline transform framework.
 *
 * Tests push messages directly to topics instead of using sources.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "conduit/xform.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/atomic.h"
#include "core/thread.h"
#include "adt/option.h"
#include "conduit/xform_linebuf.h"
#include "conduit/xform_ansi_strip.h"

// ============================================================================
// Test payload types
// ============================================================================

typedef struct {
    int value;
} xform_int_t;

typedef struct {
    char buf[32];
} xform_str_t;

// Instantiate typed pipeline for xform_int_t.
N00B_CONDUIT_MESSAGE_IMPL(xform_int_t);
N00B_CONDUIT_INBOX_IMPL_NO_MSG(xform_int_t);
N00B_CONDUIT_SUBSCRIPTION_IMPL(xform_int_t);
N00B_CONDUIT_TOPIC_IMPL(xform_int_t);

// Instantiate typed pipeline for xform_str_t.
N00B_CONDUIT_MESSAGE_IMPL(xform_str_t);
N00B_CONDUIT_INBOX_IMPL_NO_MSG(xform_str_t);
N00B_CONDUIT_SUBSCRIPTION_IMPL(xform_str_t);
N00B_CONDUIT_TOPIC_IMPL(xform_str_t);

// Instantiate identity filter (int -> int).
N00B_CONDUIT_FILTER_IMPL(xform_int_t);

// Instantiate heterogeneous transform (int -> str).
N00B_CONDUIT_XFORM_IMPL(xform_int_t, xform_str_t);

// ============================================================================
// Helpers
// ============================================================================

static n00b_conduit_t *
make_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

// Helper to init typed topic fields (subscription list).
static void
init_int_topic(n00b_conduit_topic_t(xform_int_t) *topic)
{
    topic->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(xform_int_t) *);
    topic->inbox = nullptr;
}

static void
init_str_topic(n00b_conduit_topic_t(xform_str_t) *topic)
{
    topic->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(xform_str_t) *);
    topic->inbox = nullptr;
}

/*
 * Create a typed input topic for feeding messages to a transform.
 * Returns the topic pointer (already registered in the conduit).
 */
static n00b_conduit_topic_t(xform_int_t) *
make_input_topic(n00b_conduit_t *c)
{
    static _Atomic(uint64_t) next_id = 1;
    uint64_t id = n00b_atomic_add(&next_id, 1);
    n00b_conduit_uri_t uri =
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, id);
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_topic_get(c, uri,
            sizeof(n00b_conduit_topic_t(xform_int_t)));
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_t(xform_int_t) *topic =
        (n00b_conduit_topic_t(xform_int_t) *)n00b_result_get(tr);
    init_int_topic(topic);
    return topic;
}

/*
 * Push N int messages (value 1..N) to a typed topic, then send TOPIC_CLOSED.
 * Runs in a separate thread so transforms can process concurrently.
 */
typedef struct {
    n00b_conduit_topic_t(xform_int_t) *topic;
    int count;
} int_pusher_args_t;

static void *
int_pusher_thread(void *raw)
{
    int_pusher_args_t *args = raw;
    n00b_conduit_topic_t(xform_int_t) *topic = args->topic;

    // Claim publisher role.
    n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)topic);

    // Conduit contract: a message delivered via n00b_conduit_topic_deliver_msg
    // must be allocated from the conduit's allocator — the deliver path copies,
    // drops, and (downstream) frees the message with that allocator as the free
    // hint. Allocating from the default heap and freeing against the conduit
    // pool is a cross-pool free.
    n00b_allocator_t *msg_alloc =
        ((n00b_conduit_topic_base_t *)topic)->conduit->allocator;
    for (int i = 1; i <= args->count; i++) {
        n00b_conduit_message_t(xform_int_t) *msg =
            n00b_alloc_with_opts(n00b_conduit_message_t(xform_int_t),
                                 &(n00b_alloc_opts_t){.allocator = msg_alloc});
        msg->header.type       = N00B_CONDUIT_MSG_USER;
        msg->header.topic      = (n00b_conduit_topic_base_t *)topic;
        msg->header.generation = n00b_atomic_load(&topic->generation);
        msg->header.epoch      = n00b_atomic_load(&topic->epoch);
        msg->payload           = (xform_int_t){ .value = i };
        n00b_conduit_topic_deliver_msg(xform_int_t, topic, msg,
                                       N00B_CONDUIT_OP_ALL);
    }

    // Send TOPIC_CLOSED sys message.
    n00b_conduit_topic_deliver_sys(xform_int_t, topic,
        N00B_CONDUIT_MSG_TOPIC_CLOSED, N00B_CONDUIT_OP_ALL);

    n00b_conduit_publish_yield(
        n00b_atomic_load(&topic->publisher));
    return nullptr;
}

/*
 * Push messages to a topic in a background thread.
 * Returns the thread handle for joining.
 */
static n00b_thread_t *
push_ints(n00b_conduit_t *c,
          n00b_conduit_topic_t(xform_int_t) *topic,
          int count)
{
    (void)c;
    int_pusher_args_t *args = n00b_alloc(int_pusher_args_t);
    args->topic = topic;
    args->count = count;
    auto spawn_r = n00b_thread_spawn(int_pusher_thread, args);
    assert(n00b_result_is_ok(spawn_r));
    return n00b_result_get(spawn_r);
}

// ============================================================================
// 1. Identity filter — pass data through unchanged
// ============================================================================

static n00b_option_t(xform_int_t)
identity_xform(n00b_conduit_filter_t(xform_int_t) *xf, xform_int_t input)
{
    (void)xf;
    return n00b_option_set(xform_int_t, input);
}

static n00b_string_t _kind_identity = {
    .data = "identity", .u8_bytes = 8, .codepoints = 8, .styling = nullptr
};

static const n00b_conduit_filter_ops_t(xform_int_t) identity_ops = {
    .transform = identity_xform,
    .kind      = &_kind_identity,
};

static void
test_identity_filter(void)
{
    n00b_conduit_t *c = make_conduit();

    // Create input topic.
    n00b_conduit_topic_t(xform_int_t) *src_topic = make_input_topic(c);

    // Create identity filter connected to input topic.
    auto r = n00b_conduit_filter_new(xform_int_t, c, src_topic,
                                     &identity_ops, 0);
    assert(n00b_result_is_ok(r));
    n00b_conduit_filter_t(xform_int_t) *xf = n00b_result_get(r);

    // Init filter output topic.
    n00b_conduit_topic_t(xform_int_t) *out_topic =
        n00b_conduit_xform_topic(xform_int_t, xform_int_t, xf);
    init_int_topic(out_topic);

    // Subscribe to output.
    n00b_conduit_inbox_t(xform_int_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(xform_int_t));
    n00b_conduit_inbox_init(xform_int_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(xform_int_t, out_topic, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    // Wait for xform thread to start its loop.
    while (!n00b_atomic_load(&xf->running))
        usleep(100);

    // Push 5 ints then TOPIC_CLOSED.
    n00b_thread_t *pusher = push_ints(c, src_topic, 5);
    n00b_thread_join(pusher);

    // Wait for xform to finish (it exits on TOPIC_CLOSED).
    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);

    // Count messages.
    int count = 0;
    while (true) {
        n00b_conduit_message_t(xform_int_t) *msg =
            n00b_conduit_inbox_pop_msg(xform_int_t, inbox);
        if (!msg) break;
        count++;
        assert(msg->payload.value == count);
    }
    assert(count == 5);

    n00b_conduit_destroy(c);

    printf("  [PASS] identity filter\n");
}

// ============================================================================
// 2. Dropping transform — return n00b_option_none, verify no output
// ============================================================================

static n00b_option_t(xform_int_t)
drop_xform(n00b_conduit_filter_t(xform_int_t) *xf, xform_int_t input)
{
    (void)xf;
    (void)input;
    return n00b_option_none(xform_int_t);
}

static n00b_string_t _kind_dropper = {
    .data = "dropper", .u8_bytes = 7, .codepoints = 7, .styling = nullptr
};

static const n00b_conduit_filter_ops_t(xform_int_t) drop_ops = {
    .transform = drop_xform,
    .kind      = &_kind_dropper,
};

static void
test_dropping_transform(void)
{
    n00b_conduit_t *c = make_conduit();

    n00b_conduit_topic_t(xform_int_t) *src_topic = make_input_topic(c);

    auto r = n00b_conduit_filter_new(xform_int_t, c, src_topic,
                                     &drop_ops, 0);
    assert(n00b_result_is_ok(r));
    n00b_conduit_filter_t(xform_int_t) *xf = n00b_result_get(r);

    n00b_conduit_topic_t(xform_int_t) *out_topic =
        n00b_conduit_xform_topic(xform_int_t, xform_int_t, xf);
    init_int_topic(out_topic);

    n00b_conduit_inbox_t(xform_int_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(xform_int_t));
    n00b_conduit_inbox_init(xform_int_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(xform_int_t, out_topic, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    while (!n00b_atomic_load(&xf->running))
        usleep(100);

    n00b_thread_t *pusher = push_ints(c, src_topic, 3);
    n00b_thread_join(pusher);

    // Wait for xform to finish (it exits on TOPIC_CLOSED).
    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);

    // Should have received zero messages.
    assert(!n00b_conduit_inbox_has_msg(xform_int_t, inbox));

    n00b_conduit_destroy(c);

    printf("  [PASS] dropping transform\n");
}

// ============================================================================
// 3. Type-changing transform (int -> str)
// ============================================================================

static n00b_option_t(xform_str_t)
int_to_str_xform(n00b_conduit_xform_t(xform_int_t, xform_str_t) *xf,
                 xform_int_t input)
{
    (void)xf;
    xform_str_t out;
    snprintf(out.buf, sizeof(out.buf), "val=%d", input.value);
    return n00b_option_set(xform_str_t, out);
}

static n00b_string_t _kind_int_to_str = {
    .data = "int_to_str", .u8_bytes = 10, .codepoints = 10, .styling = nullptr
};

static const n00b_conduit_xform_ops_t(xform_int_t, xform_str_t) int_to_str_ops = {
    .transform = int_to_str_xform,
    .kind      = &_kind_int_to_str,
};

static void
test_type_changing_transform(void)
{
    n00b_conduit_t *c = make_conduit();

    n00b_conduit_topic_t(xform_int_t) *src_topic = make_input_topic(c);

    auto r = n00b_conduit_xform_new(xform_int_t, xform_str_t, c, src_topic,
                                    &int_to_str_ops, 0);
    assert(n00b_result_is_ok(r));
    n00b_conduit_xform_t(xform_int_t, xform_str_t) *xf = n00b_result_get(r);

    n00b_conduit_topic_t(xform_str_t) *out_topic =
        n00b_conduit_xform_topic(xform_int_t, xform_str_t, xf);
    init_str_topic(out_topic);

    n00b_conduit_inbox_t(xform_str_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(xform_str_t));
    n00b_conduit_inbox_init(xform_str_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(xform_str_t, out_topic, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    while (!n00b_atomic_load(&xf->running))
        usleep(100);

    n00b_thread_t *pusher = push_ints(c, src_topic, 2);
    n00b_thread_join(pusher);

    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);

    n00b_conduit_message_t(xform_str_t) *m1 =
        n00b_conduit_inbox_pop_msg(xform_str_t, inbox);
    n00b_conduit_message_t(xform_str_t) *m2 =
        n00b_conduit_inbox_pop_msg(xform_str_t, inbox);

    assert(m1 != nullptr);
    assert(strcmp(m1->payload.buf, "val=1") == 0);

    assert(m2 != nullptr);
    assert(strcmp(m2->payload.buf, "val=2") == 0);

    n00b_conduit_destroy(c);

    printf("  [PASS] type-changing transform (int->str)\n");
}

// ============================================================================
// 4. Flush on upstream close
// ============================================================================

static _Atomic(bool) g_flush_called = false;

static n00b_option_t(xform_int_t)
passthru_xform(n00b_conduit_filter_t(xform_int_t) *xf, xform_int_t input)
{
    (void)xf;
    return n00b_option_set(xform_int_t, input);
}

static void
flush_cb(n00b_conduit_filter_t(xform_int_t) *xf)
{
    (void)xf;
    n00b_atomic_store(&g_flush_called, true);
}

static n00b_string_t _kind_flush_test = {
    .data = "flush_test", .u8_bytes = 10, .codepoints = 10, .styling = nullptr
};

static const n00b_conduit_filter_ops_t(xform_int_t) flush_ops = {
    .transform = passthru_xform,
    .flush     = flush_cb,
    .kind      = &_kind_flush_test,
};

static void
test_flush_on_upstream_close(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_atomic_store(&g_flush_called, false);

    n00b_conduit_topic_t(xform_int_t) *src_topic = make_input_topic(c);

    auto r = n00b_conduit_filter_new(xform_int_t, c, src_topic,
                                     &flush_ops, 0);
    assert(n00b_result_is_ok(r));
    n00b_conduit_filter_t(xform_int_t) *xf = n00b_result_get(r);

    n00b_conduit_topic_t(xform_int_t) *out_topic =
        n00b_conduit_xform_topic(xform_int_t, xform_int_t, xf);
    init_int_topic(out_topic);

    n00b_conduit_inbox_t(xform_int_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(xform_int_t));
    n00b_conduit_inbox_init(xform_int_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(xform_int_t, out_topic, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    while (!n00b_atomic_load(&xf->running))
        usleep(100);

    // Push 1 message then TOPIC_CLOSED.
    n00b_thread_t *pusher = push_ints(c, src_topic, 1);
    n00b_thread_join(pusher);

    // Wait for xform to process the TOPIC_CLOSED and call flush.
    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);

    assert(n00b_atomic_load(&g_flush_called));

    n00b_conduit_destroy(c);
    printf("  [PASS] flush on upstream close\n");
}

// ============================================================================
// 5. Stop wakes thread — verify stop completes quickly
// ============================================================================

static n00b_option_t(xform_int_t)
slow_xform(n00b_conduit_filter_t(xform_int_t) *xf, xform_int_t input)
{
    (void)xf;
    return n00b_option_set(xform_int_t, input);
}

static n00b_string_t _kind_slow_test = {
    .data = "slow_test", .u8_bytes = 9, .codepoints = 9, .styling = nullptr
};

static const n00b_conduit_filter_ops_t(xform_int_t) slow_ops = {
    .transform = slow_xform,
    .kind      = &_kind_slow_test,
};

static void
test_stop_wakes_thread(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(xform_int_t) *src_topic = make_input_topic(c);

    auto r = n00b_conduit_filter_new(xform_int_t, c, src_topic,
                                     &slow_ops, 0);
    assert(n00b_result_is_ok(r));
    n00b_conduit_filter_t(xform_int_t) *xf = n00b_result_get(r);

    n00b_conduit_topic_t(xform_int_t) *out_topic =
        n00b_conduit_xform_topic(xform_int_t, xform_int_t, xf);
    init_int_topic(out_topic);

    n00b_conduit_inbox_t(xform_int_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(xform_int_t));
    n00b_conduit_inbox_init(xform_int_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(xform_int_t, out_topic, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    // Wait for xform thread to start its loop.
    while (!n00b_atomic_load(&xf->running))
        usleep(100);

    // Stop should wake the thread immediately (not wait for 50ms timeout).
    n00b_conduit_xform_stop((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);

    // If we got here without hanging, the wake worked.
    n00b_conduit_destroy(c);
    printf("  [PASS] stop wakes thread\n");
}

// ============================================================================
// 6. Destroy during startup — no hang
// ============================================================================

static void
test_destroy_during_startup(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(xform_int_t) *src_topic = make_input_topic(c);

    auto r = n00b_conduit_filter_new(xform_int_t, c, src_topic,
                                     &identity_ops, 0);
    assert(n00b_result_is_ok(r));
    n00b_conduit_filter_t(xform_int_t) *xf = n00b_result_get(r);

    n00b_conduit_topic_t(xform_int_t) *out_topic =
        n00b_conduit_xform_topic(xform_int_t, xform_int_t, xf);
    init_int_topic(out_topic);

    // Destroy immediately — no messages pushed, thread may not have started.
    n00b_conduit_xform_destroy((n00b_conduit_xform_base_t *)xf);
    n00b_conduit_destroy(c);

    printf("  [PASS] destroy during startup\n");
}

// ============================================================================
// 7. Null args — returns error
// ============================================================================

static void
test_null_args(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(xform_int_t) *src_topic = make_input_topic(c);

    // Null conduit.
    auto r1 = n00b_conduit_filter_new(xform_int_t, nullptr, src_topic,
                                      &identity_ops, 0);
    assert(n00b_result_is_err(r1));

    // Null upstream.
    auto r2 = n00b_conduit_filter_new(xform_int_t, c, nullptr,
                                      &identity_ops, 0);
    assert(n00b_result_is_err(r2));

    // Null ops.
    auto r3 = n00b_conduit_filter_new(xform_int_t, c, src_topic,
                                      nullptr, 0);
    assert(n00b_result_is_err(r3));

    // Ops with null transform callback.
    static n00b_string_t _bad_kind = {
        .data = (char *)"bad", .u8_bytes = 3, .codepoints = 3, .styling = nullptr
    };
    static const n00b_conduit_filter_ops_t(xform_int_t) bad_ops = {
        .transform = nullptr,
        .kind      = &_bad_kind,
    };
    auto r4 = n00b_conduit_filter_new(xform_int_t, c, src_topic,
                                      &bad_ops, 0);
    assert(n00b_result_is_err(r4));

    n00b_conduit_destroy(c);
    printf("  [PASS] null args\n");
}

// ============================================================================
// 8. Multi-output emit helper
// ============================================================================

static n00b_option_t(xform_str_t)
multi_out_xform(n00b_conduit_xform_t(xform_int_t, xform_str_t) *xf,
                xform_int_t input)
{
    // Emit two messages per input using the emit helper.
    xform_str_t out1;
    snprintf(out1.buf, sizeof(out1.buf), "a=%d", input.value);
    n00b_conduit_xform_emit(xform_int_t, xform_str_t, xf, out1);

    xform_str_t out2;
    snprintf(out2.buf, sizeof(out2.buf), "b=%d", input.value);
    n00b_conduit_xform_emit(xform_int_t, xform_str_t, xf, out2);

    return n00b_option_none(xform_str_t);
}

static n00b_string_t _kind_multi_out = {
    .data = "multi_out", .u8_bytes = 9, .codepoints = 9, .styling = nullptr
};

static const n00b_conduit_xform_ops_t(xform_int_t, xform_str_t)
    multi_out_ops = {
    .transform = multi_out_xform,
    .kind      = &_kind_multi_out,
};

static void
test_multi_output_emit(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(xform_int_t) *src_topic = make_input_topic(c);

    auto r = n00b_conduit_xform_new(xform_int_t, xform_str_t, c, src_topic,
                                    &multi_out_ops, 0);
    assert(n00b_result_is_ok(r));
    n00b_conduit_xform_t(xform_int_t, xform_str_t) *xf = n00b_result_get(r);

    n00b_conduit_topic_t(xform_str_t) *out_topic =
        n00b_conduit_xform_topic(xform_int_t, xform_str_t, xf);
    init_str_topic(out_topic);

    n00b_conduit_inbox_t(xform_str_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(xform_str_t));
    n00b_conduit_inbox_init(xform_str_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(xform_str_t, out_topic, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    while (!n00b_atomic_load(&xf->running))
        usleep(100);

    // Push 2 ints -> should get 4 str messages.
    n00b_thread_t *pusher = push_ints(c, src_topic, 2);
    n00b_thread_join(pusher);

    n00b_conduit_xform_join((n00b_conduit_xform_base_t *)xf);

    int count = 0;
    while (true) {
        n00b_conduit_message_t(xform_str_t) *msg =
            n00b_conduit_inbox_pop_msg(xform_str_t, inbox);
        if (!msg) break;
        count++;
    }
    assert(count == 4);

    n00b_conduit_destroy(c);

    printf("  [PASS] multi-output emit\n");
}

// ============================================================================
// 9. Chain API: two-stage pipeline (linebuf + ansi_strip)
// ============================================================================

static n00b_conduit_topic_t(n00b_buffer_t *) *
make_buf_topic(n00b_conduit_t *c)
{
    static _Atomic(uint64_t) next_buf_id = 5000;
    uint64_t id = n00b_atomic_add(&next_buf_id, 1);
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

static char *
pop_buf_str(n00b_conduit_inbox_t(n00b_buffer_t *) *inbox)
{
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
    if (!msg) return nullptr;
    int64_t len = 0;
    char *data = n00b_buffer_to_c(msg->payload, &len);
    char *out = n00b_alloc_array(char, (size_t)len + 1);
    memcpy(out, data, (size_t)len);
    out[len] = '\0';
    return out;
}

static void
test_chain_two_stage(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    // Chain: linebuf (split lines) -> ansi_strip (remove escapes).
    // Build the chain manually to inspect intermediate topics.
    n00b_conduit_xform_base_t *linebuf_xf =
        n00b_conduit_linebuf_default_spec.base.create(
            c, (n00b_conduit_topic_base_t *)src,
            &n00b_conduit_linebuf_default_spec);
    assert(linebuf_xf != nullptr);
    n00b_conduit_topic_base_t *linebuf_out = linebuf_xf->topic;

    n00b_conduit_xform_base_t *ansi_xf =
        n00b_conduit_ansi_strip_default_spec.base.create(
            c, linebuf_out, &n00b_conduit_ansi_strip_default_spec);
    assert(ansi_xf != nullptr);
    n00b_conduit_topic_base_t *final_topic = ansi_xf->topic;

    assert(final_topic != nullptr);
    assert((void*)final_topic != (void*)src);
    assert((void*)final_topic != (void*)linebuf_out);

    // Init the final output topic for subscriptions.
    n00b_conduit_topic_t(n00b_buffer_t *) *out =
        (n00b_conduit_topic_t(n00b_buffer_t *) *)final_topic;
    out->subscriptions =
        n00b_list_new(n00b_conduit_subscription_t(n00b_buffer_t *) *);
    out->inbox = nullptr;

    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_buffer_t *));
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    n00b_conduit_subscribe(n00b_buffer_t *, out, inbox,
                           .operations = N00B_CONDUIT_OP_ALL);

    // Wait for both xform threads to start.
    while (!n00b_atomic_load(&linebuf_xf->running))
        usleep(100);
    while (!n00b_atomic_load(&ansi_xf->running))
        usleep(100);

    n00b_result_t(n00b_conduit_publisher_t *) src_pub_res =
        n00b_conduit_publish_claim((n00b_conduit_topic_base_t *)src);
    assert(n00b_result_is_ok(src_pub_res));
    n00b_conduit_publisher_t *src_pub = n00b_result_get(src_pub_res);
    push_buf(src, "\033[1mhello\033[0m\n\033[31mworld\033[0m\n", 29);

    // Send TOPIC_CLOSED so xforms drain and exit.
    n00b_conduit_topic_deliver_sys(n00b_buffer_t *, src,
        N00B_CONDUIT_MSG_TOPIC_CLOSED, N00B_CONDUIT_OP_ALL);
    n00b_conduit_publish_yield(src_pub);

    // Wait for both xforms to finish.
    n00b_conduit_xform_join(linebuf_xf);
    n00b_conduit_xform_join(ansi_xf);

    char *line1 = pop_buf_str(inbox);
    assert(line1 != nullptr);
    assert(strcmp(line1, "hello") == 0);

    char *line2 = pop_buf_str(inbox);
    assert(line2 != nullptr);
    assert(strcmp(line2, "world") == 0);

    n00b_conduit_destroy(c);
    printf("  [PASS] chain two stage (linebuf + ansi_strip)\n");
}

// ============================================================================
// 10. Chain API: null/zero returns nullptr
// ============================================================================

static void
test_chain_null_spec(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    // Zero count => nullptr.
    n00b_conduit_topic_base_t *r1 = n00b_conduit_chain_from_specs(
        c, (n00b_conduit_topic_base_t *)src, nullptr, 0);
    assert(r1 == nullptr);

    // Null conduit => nullptr.
    const n00b_conduit_xform_spec_base_t *specs[] = {
        (const n00b_conduit_xform_spec_base_t *)&n00b_conduit_linebuf_default_spec,
    };
    n00b_conduit_topic_base_t *r2 = n00b_conduit_chain_from_specs(
        nullptr, (n00b_conduit_topic_base_t *)src, specs, 1);
    assert(r2 == nullptr);

    // Null source => nullptr.
    n00b_conduit_topic_base_t *r3 = n00b_conduit_chain_from_specs(
        c, nullptr, specs, 1);
    assert(r3 == nullptr);

    n00b_conduit_destroy(c);
    printf("  [PASS] chain null spec\n");
}

// ============================================================================
// 11. Chain API: bad create returns nullptr
// ============================================================================

static n00b_conduit_xform_base_t *
bad_create(n00b_conduit_t *c, n00b_conduit_topic_base_t *upstream,
           const void *spec)
{
    (void)c; (void)upstream; (void)spec;
    return nullptr;
}

static const n00b_conduit_xform_spec_base_t bad_spec = {
    .create = bad_create,
};

static void
test_chain_bad_create(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(n00b_buffer_t *) *src = make_buf_topic(c);

    n00b_conduit_topic_base_t *r = n00b_conduit_chain(
        c, (n00b_conduit_topic_base_t *)src,
        &bad_spec);
    assert(r == nullptr);

    n00b_conduit_destroy(c);
    printf("  [PASS] chain bad create\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_xform:\n");
    fflush(stdout);

    test_identity_filter();
    fflush(stdout);
    test_dropping_transform();
    fflush(stdout);
    test_type_changing_transform();
    fflush(stdout);
    test_flush_on_upstream_close();
    fflush(stdout);
    test_stop_wakes_thread();
    fflush(stdout);
    test_destroy_during_startup();
    fflush(stdout);
    test_null_args();
    fflush(stdout);
    test_multi_output_emit();
    fflush(stdout);
    test_chain_two_stage();
    fflush(stdout);
    test_chain_null_spec();
    fflush(stdout);
    test_chain_bad_create();
    fflush(stdout);

    printf("All xform tests passed.\n");
    n00b_shutdown();
    return 0;
}
