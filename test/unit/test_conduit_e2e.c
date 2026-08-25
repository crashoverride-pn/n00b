/*
 * test_conduit_e2e.c — End-to-end tests for conduit typed pub/sub.
 *
 * Exercises the full pipeline: typed topic, typed inbox, typed
 * subscription, message delivery, system message delivery,
 * topic close notification, and destroy cleanup.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#ifdef _WIN32
#include <process.h>
#define test_getpid _getpid
#else
#include <unistd.h>
#define test_getpid getpid
#endif

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/proc_lifecycle.h"
#include "conduit/rw.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "core/runtime.h"
#include "core/thread.h"

// ============================================================================
// Test payload type
// ============================================================================

typedef struct {
    int    value;
    int    flags;
} test_payload_t;

// Instantiate the full typed pipeline for test_payload_t.
N00B_CONDUIT_INBOX_IMPL(test_payload_t);
N00B_CONDUIT_SUBSCRIPTION_IMPL(test_payload_t);
N00B_CONDUIT_TOPIC_IMPL(test_payload_t);
N00B_CONDUIT_RW_IMPL(test_payload_t);

// ============================================================================
// Helper: create a conduit + typed topic for FD 200
// ============================================================================

static n00b_conduit_t *
make_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    return n00b_result_get(cr);
}

static n00b_conduit_topic_t(test_payload_t) *
make_typed_topic(n00b_conduit_t *c, int fd)
{
    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_get(
        c, N00B_CONDUIT_URI_FD(fd),
        sizeof(n00b_conduit_topic_t(test_payload_t)));
    assert(n00b_result_is_ok(tr));

    n00b_conduit_topic_t(test_payload_t) *topic =
        (n00b_conduit_topic_t(test_payload_t) *)n00b_result_get(tr);

    // Initialize typed fields (caller responsibility until vtable system).
    topic->subscriptions = n00b_list_new(n00b_conduit_subscription_t(test_payload_t) *);
    topic->inbox         = nullptr;

    return topic;
}

static n00b_conduit_inbox_t(test_payload_t) *
make_test_inbox(n00b_conduit_t *c)
{
    n00b_conduit_inbox_t(test_payload_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);
    return inbox;
}

static void
assert_closed_topic(n00b_conduit_topic_t(test_payload_t) *topic)
{
    assert(!n00b_conduit_topic_is_active((n00b_conduit_topic_base_t *)topic));
    assert(n00b_atomic_load(&topic->sub_list_head) == nullptr);
    for (size_t i = 0; i < n00b_list_len(topic->subscriptions); i++) {
        auto sub = n00b_list_get(topic->subscriptions, i);
        assert(n00b_atomic_load(&sub->state) == N00B_CONDUIT_SUB_REMOVED);
    }
}

// ============================================================================
// 1. Typed message delivery — publish and receive
// ============================================================================

static void
test_typed_message_delivery(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(test_payload_t) *topic = make_typed_topic(c, 200);

    // Create inbox.
    n00b_conduit_inbox_t(test_payload_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    // Subscribe with default config.
    n00b_conduit_sub_handle_t handle =
        n00b_conduit_subscribe(test_payload_t, topic, inbox);
    assert(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);
    assert(n00b_conduit_sub_is_active(handle));

    // Create and deliver a message.
    n00b_conduit_message_t(test_payload_t) *msg =
        n00b_alloc_with_opts(n00b_conduit_message_t(test_payload_t), &(n00b_alloc_opts_t){.allocator = c->allocator});
    msg->header.type = N00B_CONDUIT_MSG_READABLE;
    msg->payload.value = 42;
    msg->payload.flags = 0xFF;

    n00b_conduit_topic_deliver_msg(test_payload_t, topic, msg,
                                   N00B_CONDUIT_OP_ALL);

    // Pop from inbox and verify.
    assert(n00b_conduit_inbox_has_msg(test_payload_t, inbox));
    n00b_conduit_message_t(test_payload_t) *popped =
        n00b_conduit_inbox_pop_msg(test_payload_t, inbox);
    assert(popped != nullptr);
    assert(n00b_conduit_msg_type(popped) == N00B_CONDUIT_MSG_READABLE);
    assert(popped->payload.value == 42);
    assert(popped->payload.flags == 0xFF);

    // No more messages.
    assert(!n00b_conduit_inbox_has_msg(test_payload_t, inbox));

    n00b_conduit_sub_cancel(handle);
    n00b_conduit_destroy(c);
    printf("  [PASS] typed message delivery\n");
}

// ============================================================================
// 2. Multiple subscribers receive the same message
// ============================================================================

static void
test_multiple_subscribers(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(test_payload_t) *topic = make_typed_topic(c, 201);

    // Two inboxes, two subscriptions.
    n00b_conduit_inbox_t(test_payload_t) *inbox1 =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox1, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    n00b_conduit_inbox_t(test_payload_t) *inbox2 =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox2, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    n00b_conduit_sub_handle_t h1 =
        n00b_conduit_subscribe(test_payload_t, topic, inbox1);
    n00b_conduit_sub_handle_t h2 =
        n00b_conduit_subscribe(test_payload_t, topic, inbox2);

    assert(h1 != h2);

    // Deliver one message.
    n00b_conduit_message_t(test_payload_t) *msg =
        n00b_alloc_with_opts(n00b_conduit_message_t(test_payload_t), &(n00b_alloc_opts_t){.allocator = c->allocator});
    msg->header.type   = N00B_CONDUIT_MSG_READABLE;
    msg->payload.value = 99;

    n00b_conduit_topic_deliver_msg(test_payload_t, topic, msg,
                                   N00B_CONDUIT_OP_ALL);

    // Both inboxes should have a message.
    assert(n00b_conduit_inbox_has_msg(test_payload_t, inbox1));
    assert(n00b_conduit_inbox_has_msg(test_payload_t, inbox2));

    n00b_conduit_message_t(test_payload_t) *m1 =
        n00b_conduit_inbox_pop_msg(test_payload_t, inbox1);
    n00b_conduit_message_t(test_payload_t) *m2 =
        n00b_conduit_inbox_pop_msg(test_payload_t, inbox2);

    assert(m1 != nullptr && m1->payload.value == 99);
    assert(m2 != nullptr && m2->payload.value == 99);
    assert(m1 != m2);

    n00b_conduit_sub_cancel(h1);
    n00b_conduit_sub_cancel(h2);
    n00b_conduit_destroy(c);
    printf("  [PASS] multiple subscribers\n");
}

// ============================================================================
// 3. Suspended subscriber does not receive messages
// ============================================================================

static void
test_suspended_sub_no_delivery(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(test_payload_t) *topic = make_typed_topic(c, 202);

    n00b_conduit_inbox_t(test_payload_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    n00b_conduit_sub_handle_t h =
        n00b_conduit_subscribe(test_payload_t, topic, inbox);

    // Suspend.
    n00b_conduit_sub_suspend(h);
    assert(!n00b_conduit_sub_is_active(h));

    // Deliver — should not reach suspended subscriber.
    n00b_conduit_message_t(test_payload_t) *msg =
        n00b_alloc_with_opts(n00b_conduit_message_t(test_payload_t), &(n00b_alloc_opts_t){.allocator = c->allocator});
    msg->header.type   = N00B_CONDUIT_MSG_READABLE;
    msg->payload.value = 77;

    n00b_conduit_topic_deliver_msg(test_payload_t, topic, msg,
                                   N00B_CONDUIT_OP_ALL);

    assert(!n00b_conduit_inbox_has_msg(test_payload_t, inbox));

    // Resume and deliver again — should receive.
    n00b_conduit_sub_resume(h);
    n00b_conduit_message_t(test_payload_t) *msg2 =
        n00b_alloc_with_opts(n00b_conduit_message_t(test_payload_t), &(n00b_alloc_opts_t){.allocator = c->allocator});
    msg2->header.type   = N00B_CONDUIT_MSG_READABLE;
    msg2->payload.value = 88;

    n00b_conduit_topic_deliver_msg(test_payload_t, topic, msg2,
                                   N00B_CONDUIT_OP_ALL);

    assert(n00b_conduit_inbox_has_msg(test_payload_t, inbox));
    n00b_conduit_message_t(test_payload_t) *popped =
        n00b_conduit_inbox_pop_msg(test_payload_t, inbox);
    assert(popped->payload.value == 88);

    n00b_conduit_sub_cancel(h);
    n00b_conduit_destroy(c);
    printf("  [PASS] suspended sub no delivery\n");
}

// ============================================================================
// 4. Topic close delivers TOPIC_CLOSED system message
// ============================================================================

static void
test_topic_close_sys_message(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(test_payload_t) *topic = make_typed_topic(c, 203);

    n00b_conduit_inbox_t(test_payload_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    n00b_conduit_sub_handle_t h =
        n00b_conduit_subscribe(test_payload_t, topic, inbox);
    assert(n00b_conduit_sub_is_active(h));

    // Close the topic.
    n00b_conduit_topic_close((n00b_conduit_topic_base_t *)topic);

    // Subscription should be removed.
    assert(n00b_conduit_sub_state(h) == N00B_CONDUIT_SUB_REMOVED);

    // System queue should have a TOPIC_CLOSED message.
    assert(n00b_conduit_inbox_has_sys(inbox));
    n00b_conduit_sys_msg_t *sys = n00b_conduit_inbox_pop_sys(inbox);
    assert(sys != nullptr);
    assert(sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED);

    n00b_conduit_destroy(c);
    printf("  [PASS] topic close sys message\n");
}

// ============================================================================
// 5. Conduit destroy closes all topics and notifies subscribers
// ============================================================================

static void
test_destroy_notifies(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(test_payload_t) *topic = make_typed_topic(c, 204);

    n00b_conduit_inbox_t(test_payload_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    n00b_conduit_sub_handle_t h =
        n00b_conduit_subscribe(test_payload_t, topic, inbox);

    // Destroy the conduit — should close all topics and notify.
    n00b_conduit_destroy(c);

    assert(n00b_conduit_sub_state(h) == N00B_CONDUIT_SUB_REMOVED);
    assert(n00b_conduit_inbox_has_sys(inbox));

    n00b_conduit_sys_msg_t *sys = n00b_conduit_inbox_pop_sys(inbox);
    assert(sys != nullptr);
    assert(sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED);

    printf("  [PASS] destroy notifies subscribers\n");
}

// ============================================================================
// 6. Operation filter on delivery
// ============================================================================

static void
test_op_filter_delivery(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(test_payload_t) *topic = make_typed_topic(c, 205);

    n00b_conduit_inbox_t(test_payload_t) *inbox_read =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox_read, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    n00b_conduit_inbox_t(test_payload_t) *inbox_write =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox_write, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    // Subscribe with READABLE filter.
    n00b_conduit_sub_handle_t h_read = n00b_conduit_subscribe(
        test_payload_t, topic, inbox_read,
        .operations = N00B_CONDUIT_OP_READABLE);

    // Subscribe with WRITABLE filter.
    n00b_conduit_sub_handle_t h_write = n00b_conduit_subscribe(
        test_payload_t, topic, inbox_write,
        .operations = N00B_CONDUIT_OP_WRITABLE);

    // Deliver with READABLE filter.
    n00b_conduit_message_t(test_payload_t) *msg =
        n00b_alloc_with_opts(n00b_conduit_message_t(test_payload_t), &(n00b_alloc_opts_t){.allocator = c->allocator});
    msg->header.type   = N00B_CONDUIT_MSG_READABLE;
    msg->payload.value = 1;

    n00b_conduit_topic_deliver_msg(test_payload_t, topic, msg,
                                   N00B_CONDUIT_OP_READABLE);

    // Only the read subscriber should receive it.
    assert(n00b_conduit_inbox_has_msg(test_payload_t, inbox_read));
    assert(!n00b_conduit_inbox_has_msg(test_payload_t, inbox_write));

    n00b_conduit_sub_cancel(h_read);
    n00b_conduit_sub_cancel(h_write);
    n00b_conduit_destroy(c);
    printf("  [PASS] operation filter delivery\n");
}

// ============================================================================
// 7. One-shot subscription cleanup
// ============================================================================

static void
test_one_shot_subscription_cleanup(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(test_payload_t) *topic = make_typed_topic(c, 206);

    n00b_conduit_inbox_t(test_payload_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox, c,
                            N00B_CONDUIT_BP_UNBOUNDED, 0);

    n00b_conduit_sub_handle_t h =
        n00b_conduit_subscribe(test_payload_t, topic, inbox,
                               .flags = N00B_CONDUIT_SUB_F_ONE_SHOT);
    assert(h != N00B_CONDUIT_INVALID_SUB_HANDLE);
    assert(n00b_list_len(topic->subscriptions) == 1);

    n00b_conduit_message_t(test_payload_t) *msg =
        n00b_alloc_with_opts(n00b_conduit_message_t(test_payload_t), &(n00b_alloc_opts_t){.allocator = c->allocator});
    msg->header.type   = N00B_CONDUIT_MSG_READABLE;
    msg->payload.value = 123;
    n00b_conduit_topic_deliver_msg(test_payload_t, topic, msg,
                                   N00B_CONDUIT_OP_ALL);

    assert(n00b_conduit_sub_state(h) == N00B_CONDUIT_SUB_REMOVED);
    assert(n00b_conduit_inbox_msg_count(test_payload_t, inbox) == 1);

    n00b_conduit_sub_cancel(h);
    assert(n00b_list_len(topic->subscriptions) == 0);

    n00b_conduit_destroy(c);
    printf("  [PASS] one-shot subscription cleanup\n");
}

// ============================================================================
// 8. Inbox backpressure — DROP_NEWEST
// ============================================================================

static void
test_inbox_backpressure_drop_newest(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(test_payload_t) *topic = make_typed_topic(c, 207);

    n00b_conduit_inbox_t(test_payload_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox, c,
                            N00B_CONDUIT_BP_DROP_NEWEST, 2);

    n00b_conduit_sub_handle_t h =
        n00b_conduit_subscribe(test_payload_t, topic, inbox);

    // Push 3 messages — third should be dropped.
    for (int i = 0; i < 3; i++) {
        n00b_conduit_message_t(test_payload_t) *msg =
            n00b_alloc_with_opts(n00b_conduit_message_t(test_payload_t), &(n00b_alloc_opts_t){.allocator = c->allocator});
        msg->header.type   = N00B_CONDUIT_MSG_READABLE;
        msg->payload.value = i + 1;
        n00b_conduit_topic_deliver_msg(test_payload_t, topic, msg,
                                       N00B_CONDUIT_OP_ALL);
    }

    // Should have exactly 2 messages: values 1 and 2.
    assert(n00b_conduit_inbox_msg_count(test_payload_t, inbox) == 2);

    n00b_conduit_message_t(test_payload_t) *m1 =
        n00b_conduit_inbox_pop_msg(test_payload_t, inbox);
    assert(m1->payload.value == 1);
    n00b_conduit_message_t(test_payload_t) *m2 =
        n00b_conduit_inbox_pop_msg(test_payload_t, inbox);
    assert(m2->payload.value == 2);
    assert(!n00b_conduit_inbox_has_msg(test_payload_t, inbox));

    n00b_conduit_sub_cancel(h);
    n00b_conduit_destroy(c);
    printf("  [PASS] inbox backpressure DROP_NEWEST\n");
}

// ============================================================================
// 8b. Inbox backpressure — DROP_OLDEST
// ============================================================================
//
// Producer-side push must NOT touch head/tail-when-solo — that's MPSC
// consumer territory. When over limit + DROP_OLDEST, push bumps a
// `drop_credits` counter; the consumer pop drains credits (discarding
// head entries) before returning a real message. Net effect: keep the
// newest `limit` entries.

static void
test_inbox_backpressure_drop_oldest(void)
{
    n00b_conduit_t *c = make_conduit();
    n00b_conduit_topic_t(test_payload_t) *topic = make_typed_topic(c, 208);

    n00b_conduit_inbox_t(test_payload_t) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(test_payload_t));
    n00b_conduit_inbox_init(test_payload_t, inbox, c,
                            N00B_CONDUIT_BP_DROP_OLDEST, 3);

    n00b_conduit_sub_handle_t h =
        n00b_conduit_subscribe(test_payload_t, topic, inbox);

    // Push 5 messages. Oldest 2 (values 1, 2) must be dropped; the
    // consumer should observe 3, 4, 5 in order.
    for (int i = 0; i < 5; i++) {
        n00b_conduit_message_t(test_payload_t) *msg =
            n00b_alloc_with_opts(n00b_conduit_message_t(test_payload_t), &(n00b_alloc_opts_t){.allocator = c->allocator});
        msg->header.type   = N00B_CONDUIT_MSG_READABLE;
        msg->payload.value = i + 1;
        n00b_conduit_topic_deliver_msg(test_payload_t, topic, msg,
                                       N00B_CONDUIT_OP_ALL);
    }

    n00b_conduit_message_t(test_payload_t) *m3 =
        n00b_conduit_inbox_pop_msg(test_payload_t, inbox);
    assert(m3 != nullptr);
    assert(m3->payload.value == 3);
    n00b_conduit_message_t(test_payload_t) *m4 =
        n00b_conduit_inbox_pop_msg(test_payload_t, inbox);
    assert(m4 != nullptr);
    assert(m4->payload.value == 4);
    n00b_conduit_message_t(test_payload_t) *m5 =
        n00b_conduit_inbox_pop_msg(test_payload_t, inbox);
    assert(m5 != nullptr);
    assert(m5->payload.value == 5);
    assert(n00b_conduit_inbox_pop_msg(test_payload_t, inbox) == nullptr);

    n00b_conduit_sub_cancel(h);
    n00b_conduit_destroy(c);
    printf("  [PASS] inbox backpressure DROP_OLDEST\n");
}

// ============================================================================
// 9. Process lifecycle topics initialize typed subscription storage
// ============================================================================

static void
test_proc_topic_has_typed_subscriptions(void)
{
    n00b_conduit_t *c = make_conduit();

    n00b_result_t(n00b_conduit_io_backend_t *) ir =
        n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    pid_t pid = (pid_t)test_getpid();
    n00b_result_t(n00b_conduit_topic_base_t *) tr =
        n00b_conduit_proc_topic(c, pid, N00B_CONDUIT_PROC_EXIT);
    assert(n00b_result_is_ok(tr));

    n00b_conduit_topic_t(n00b_conduit_proc_payload_t) *topic =
        (n00b_conduit_topic_t(n00b_conduit_proc_payload_t) *)n00b_result_get(tr);
    assert(topic->subscriptions.data != nullptr);
    assert(n00b_list_len(topic->subscriptions) == 0);

    n00b_conduit_proc_inbox_t *inbox = n00b_conduit_proc_inbox_new(c);
    n00b_conduit_sub_handle_t h = n00b_conduit_proc_subscribe(topic, inbox);
    assert(h != N00B_CONDUIT_INVALID_SUB_HANDLE);
    assert(n00b_list_len(topic->subscriptions) == 1);

    n00b_conduit_sub_cancel(h);
    n00b_conduit_proc_unwatch(c, pid);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    printf("  [PASS] proc topic typed subscriptions\n");
}

typedef struct {
    char events[2];
    int  count;
    bool active;
} callback_state_t;

static void
record_first_subscriber(n00b_conduit_topic_base_t *topic, void *raw)
{
    callback_state_t *state = raw;
    n00b_rwlock_t *lock = n00b_atomic_load(&topic->sub_delivery_lock);
    assert(lock != nullptr);
    assert(n00b_lock_already_owner((n00b_lock_base_t *)lock));
    assert(!state->active && state->count == 0);
    state->events[state->count++] = 'F';
    state->active = true;
}

static void
record_last_subscriber(n00b_conduit_topic_base_t *topic, void *raw)
{
    callback_state_t *state = raw;
    n00b_rwlock_t *lock = n00b_atomic_load(&topic->sub_delivery_lock);
    assert(lock != nullptr);
    assert(n00b_lock_already_owner((n00b_lock_base_t *)lock));
    assert(state->active && state->count == 1);
    state->events[state->count++] = 'L';
    state->active = false;
}

static void
test_subscription_close_ordering(void)
{
    n00b_conduit_t *c = make_conduit();

    auto topic = make_typed_topic(c, 300);
    auto inbox = make_test_inbox(c);
    auto handle = n00b_conduit_subscribe(test_payload_t, topic, inbox);
    assert(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);
    n00b_conduit_topic_close((n00b_conduit_topic_base_t *)topic);
    assert_closed_topic(topic);
    assert(n00b_conduit_sub_state(handle) == N00B_CONDUIT_SUB_REMOVED);

    auto closed_topic = make_typed_topic(c, 301);
    auto closed_inbox = make_test_inbox(c);
    n00b_conduit_topic_close((n00b_conduit_topic_base_t *)closed_topic);
    handle = n00b_conduit_subscribe(test_payload_t, closed_topic, closed_inbox);
    assert(handle == N00B_CONDUIT_INVALID_SUB_HANDLE);
    assert(n00b_list_len(closed_topic->subscriptions) == 0);
    assert_closed_topic(closed_topic);

    n00b_conduit_inbox_destroy(test_payload_t, inbox);
    n00b_conduit_inbox_destroy(test_payload_t, closed_inbox);
    n00b_conduit_destroy(c);
    printf("  [PASS] subscription close ordering\n");
}

static void
test_membership_callbacks(void)
{
    n00b_conduit_t *c = make_conduit();

    for (int i = 0; i < 2; i++) {
        auto topic = make_typed_topic(c, 302 + i);
        auto inbox = make_test_inbox(c);
        callback_state_t state = {0};
        topic->on_first_subscribe = record_first_subscriber;
        topic->on_first_subscribe_ctx = &state;
        topic->on_last_unsubscribe = record_last_subscriber;
        topic->on_last_unsubscribe_ctx = &state;

        auto handle = n00b_conduit_subscribe(test_payload_t, topic, inbox);
        assert(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);
        if (i == 0) {
            n00b_conduit_sub_cancel(handle);
        }
        else {
            n00b_conduit_topic_close((n00b_conduit_topic_base_t *)topic);
        }

        assert(state.count == 2);
        assert(state.events[0] == 'F' && state.events[1] == 'L');
        assert(!state.active);
        assert(n00b_atomic_load(&topic->sub_list_head) == nullptr);
        n00b_conduit_inbox_destroy(test_payload_t, inbox);
    }

    n00b_conduit_destroy(c);
    printf("  [PASS] membership callbacks\n");
}

typedef struct {
    n00b_conduit_topic_t(test_payload_t) *topic;
    n00b_conduit_inbox_t(test_payload_t) *inbox;
    _Atomic(bool)                        *start;
    n00b_conduit_sub_handle_t             handle;
} close_race_args_t;

static void *
subscribe_racer(void *raw)
{
    close_race_args_t *args = raw;
    while (!n00b_atomic_load(args->start)) {}
    args->handle = n00b_conduit_subscribe(test_payload_t,
                                           args->topic,
                                           args->inbox);
    return nullptr;
}

static void *
close_racer(void *raw)
{
    close_race_args_t *args = raw;
    while (!n00b_atomic_load(args->start)) {}
    n00b_conduit_topic_close((n00b_conduit_topic_base_t *)args->topic);
    return nullptr;
}

static void
test_concurrent_subscribe_close(void)
{
    n00b_conduit_t *c = make_conduit();

    for (int i = 0; i < 64; i++) {
        auto topic = make_typed_topic(c, 400 + i);
        auto inbox = make_test_inbox(c);
        _Atomic(bool) start = false;
        close_race_args_t args = {
            .topic = topic,
            .inbox = inbox,
            .start = &start,
            .handle = N00B_CONDUIT_INVALID_SUB_HANDLE,
        };
        auto subscribe_result = n00b_thread_spawn(subscribe_racer, &args);
        auto close_result = n00b_thread_spawn(close_racer, &args);
        assert(n00b_result_is_ok(subscribe_result));
        assert(n00b_result_is_ok(close_result));
        n00b_atomic_store(&start, true);
        n00b_thread_join(n00b_result_get(subscribe_result));
        n00b_thread_join(n00b_result_get(close_result));

        assert_closed_topic(topic);
        if (args.handle != N00B_CONDUIT_INVALID_SUB_HANDLE) {
            assert(n00b_conduit_sub_state(args.handle)
                   == N00B_CONDUIT_SUB_REMOVED);
        }
        n00b_conduit_inbox_destroy(test_payload_t, inbox);
    }

    n00b_conduit_destroy(c);
    printf("  [PASS] concurrent subscribe close\n");
}

typedef struct {
    n00b_conduit_topic_t(test_payload_t) *topic;
    _Atomic(bool)                        *start;
    n00b_err_t                            error;
} read_close_args_t;

static void *
read_close_racer(void *raw)
{
    read_close_args_t *args = raw;
    while (!n00b_atomic_load(args->start)) {}
    auto result = n00b_conduit_read(test_payload_t,
                                     args->topic,
                                     .timeout_ms = 1000);
    args->error = n00b_result_is_err(result)
                      ? n00b_result_get_err(result)
                      : N00B_CONDUIT_ERR_NONE;
    return nullptr;
}

static void
test_concurrent_read_close(void)
{
    n00b_conduit_t *c = make_conduit();

    for (int i = 0; i < 16; i++) {
        auto topic = make_typed_topic(c, 470 + i);
        _Atomic(bool) start = false;
        read_close_args_t read_args = {
            .topic = topic,
            .start = &start,
        };
        close_race_args_t close_args = {
            .topic = topic,
            .start = &start,
        };
        auto read_result = n00b_thread_spawn(read_close_racer, &read_args);
        auto close_result = n00b_thread_spawn(close_racer, &close_args);
        assert(n00b_result_is_ok(read_result));
        assert(n00b_result_is_ok(close_result));
        n00b_atomic_store(&start, true);
        n00b_thread_join(n00b_result_get(read_result));
        n00b_thread_join(n00b_result_get(close_result));
        assert(read_args.error == N00B_CONDUIT_ERR_CLOSED);
        assert_closed_topic(topic);
    }

    n00b_conduit_destroy(c);
    printf("  [PASS] concurrent read close\n");
}

typedef struct {
    n00b_conduit_sub_handle_t             handle;
    n00b_conduit_topic_t(test_payload_t) *topic;
    _Atomic(bool)                        *start;
    bool                                  saw_link_after_cancel;
} cancel_race_args_t;

static void *
cancel_racer(void *raw)
{
    cancel_race_args_t *args = raw;
    while (!n00b_atomic_load(args->start)) {}
    n00b_conduit_sub_cancel(args->handle);
    args->saw_link_after_cancel =
        n00b_atomic_load(&args->topic->sub_list_head) != nullptr;
    return nullptr;
}

static void
test_double_cancel(void)
{
    n00b_conduit_t *c = make_conduit();

    for (int i = 0; i < 32; i++) {
        auto topic = make_typed_topic(c, 500 + i);
        auto inbox = make_test_inbox(c);
        auto handle = n00b_conduit_subscribe(test_payload_t, topic, inbox);
        assert(handle != N00B_CONDUIT_INVALID_SUB_HANDLE);
        _Atomic(bool) start = false;
        cancel_race_args_t args[2] = {
            {.handle = handle, .topic = topic, .start = &start},
            {.handle = handle, .topic = topic, .start = &start},
        };
        auto first = n00b_thread_spawn(cancel_racer, &args[0]);
        auto second = n00b_thread_spawn(cancel_racer, &args[1]);
        assert(n00b_result_is_ok(first));
        assert(n00b_result_is_ok(second));
        n00b_atomic_store(&start, true);
        n00b_thread_join(n00b_result_get(first));
        n00b_thread_join(n00b_result_get(second));

        assert(!args[0].saw_link_after_cancel);
        assert(!args[1].saw_link_after_cancel);
        assert(n00b_atomic_load(&topic->sub_list_head) == nullptr);
        n00b_conduit_topic_close((n00b_conduit_topic_base_t *)topic);
        assert(!n00b_conduit_inbox_has_sys(inbox));
        n00b_conduit_inbox_destroy(test_payload_t, inbox);
    }

    n00b_conduit_destroy(c);
    printf("  [PASS] double cancel\n");
}

static void
test_closed_subscription_helpers(void)
{
    n00b_conduit_t *c = make_conduit();
    auto topic = make_typed_topic(c, 600);
    auto inbox = make_test_inbox(c);
    n00b_conduit_topic_close((n00b_conduit_topic_base_t *)topic);

    auto blocking = n00b_conduit_read(test_payload_t, topic, .timeout_ms = 1);
    assert(n00b_result_is_err(blocking));
    assert(n00b_result_get_err(blocking) == N00B_CONDUIT_ERR_CLOSED);
    auto async = n00b_conduit_read_async(test_payload_t, topic, inbox);
    assert(n00b_result_is_err(async));
    assert(n00b_result_get_err(async) == N00B_CONDUIT_ERR_CLOSED);
    assert(n00b_list_len(topic->subscriptions) == 0);

    auto source = n00b_conduit_topic_init(
        n00b_buffer_t *, c,
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, 601));
    auto done = (n00b_conduit_topic_t(n00b_conduit_topic_base_t *) *)
        n00b_atomic_load(&source->done_topic);
    assert(done != nullptr);
    n00b_conduit_topic_close((n00b_conduit_topic_base_t *)done);
    auto write = n00b_conduit_write(n00b_buffer_t *, source,
                                     n00b_buffer_from_bytes("x", 1));
    assert(n00b_result_is_err(write));
    assert(n00b_result_get_err(write) == N00B_CONDUIT_ERR_CLOSED);
    assert(n00b_atomic_load(&done->sub_list_head) == nullptr);

    n00b_conduit_inbox_destroy(test_payload_t, inbox);
    n00b_conduit_destroy(c);
    printf("  [PASS] closed subscription helpers\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_conduit_e2e:\n");
    fflush(stdout);

    test_typed_message_delivery();
    fflush(stdout);
    test_multiple_subscribers();
    fflush(stdout);
    test_suspended_sub_no_delivery();
    fflush(stdout);
    test_topic_close_sys_message();
    fflush(stdout);
    test_destroy_notifies();
    fflush(stdout);
    test_op_filter_delivery();
    fflush(stdout);
    test_one_shot_subscription_cleanup();
    fflush(stdout);
    test_inbox_backpressure_drop_newest();
    fflush(stdout);
    test_inbox_backpressure_drop_oldest();
    fflush(stdout);
    test_proc_topic_has_typed_subscriptions();
    fflush(stdout);
    test_subscription_close_ordering();
    fflush(stdout);
    test_membership_callbacks();
    fflush(stdout);
    test_concurrent_subscribe_close();
    fflush(stdout);
    test_concurrent_read_close();
    fflush(stdout);
    test_double_cancel();
    fflush(stdout);
    test_closed_subscription_helpers();
    fflush(stdout);

    printf("All conduit e2e tests passed.\n");
    n00b_shutdown();
    return 0;
}
