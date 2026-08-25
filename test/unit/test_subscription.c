/*
 * test_subscription.c — Tests for conduit subscription management.
 *
 * Since the typed subscribe() lives in topic.h header macros and
 * requires full typed topic/inbox/subscription instantiation,
 * we test the handle-based API (cancel, suspend, resume, state)
 * via the _n00b_conduit_sub_register() internal hook.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "core/alloc.h"
#include "core/runtime.h"

// ============================================================================
// The subscription management functions operate on handles stored in a
// global dict. We use _n00b_conduit_sub_register() to inject fake
// subscriptions and then test cancel/suspend/resume via handles.
//
// _n00b_conduit_sub_register is declared extern in subscription.c.
// ============================================================================

extern void
_n00b_conduit_sub_register(n00b_conduit_sub_handle_t handle,
                            void *sub_ptr,
                            n00b_conduit_topic_base_t *topic);

/*
 * Minimal subscription-like struct matching the layout expected by
 * subscription.c's _n00b_conduit_sub_base_t.
 */
typedef struct {
    n00b_conduit_sub_handle_t    handle;
    void                        *inbox;
    n00b_conduit_sys_queue_t    *sys_queue;
    uint32_t                     operations;
    uint64_t                     generation;
    uint64_t                     epoch;
    _Atomic(int)                 state;
    bool                         one_shot;
    bool                         dedicated_inbox;
    bool                         notify_on_delivery;
    bool                         confirm_cancel;
    bool                         notify_unsub;
    bool                         timeout_relative;
    uint32_t                     timeout_ms;
    n00b_conduit_backpressure_t  backpressure;
    uint32_t                     inbox_limit;
    n00b_conduit_topic_base_t   *topic;
    void                        *next_for_topic;
} test_sub_t;

static test_sub_t
make_test_sub(n00b_conduit_sub_handle_t handle,
              n00b_conduit_topic_base_t *topic)
{
    test_sub_t sub;
    memset(&sub, 0, sizeof(sub));
    sub.handle = handle;
    atomic_store(&sub.state, N00B_CONDUIT_SUB_ACTIVE);
    sub.topic = topic;
    return sub;
}

// ============================================================================
// 1. Subscribe and check active
// ============================================================================

static void
test_sub_active(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 100);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    test_sub_t sub = make_test_sub(1001, topic);
    _n00b_conduit_sub_register(1001, &sub, topic);

    assert(n00b_conduit_sub_is_active(1001));
    assert(n00b_conduit_sub_state(1001) == N00B_CONDUIT_SUB_ACTIVE);

    n00b_conduit_destroy(c);
    printf("  [PASS] subscribe and check active\n");
}

// ============================================================================
// 2. Suspend and resume
// ============================================================================

static void
test_suspend_resume(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 101);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    test_sub_t sub = make_test_sub(1002, topic);
    _n00b_conduit_sub_register(1002, &sub, topic);

    assert(n00b_conduit_sub_is_active(1002));

    n00b_conduit_sub_suspend(1002);
    assert(!n00b_conduit_sub_is_active(1002));
    assert(n00b_conduit_sub_state(1002) == N00B_CONDUIT_SUB_SUSPENDED);

    n00b_conduit_sub_resume(1002);
    assert(n00b_conduit_sub_is_active(1002));

    n00b_conduit_destroy(c);
    printf("  [PASS] suspend and resume\n");
}

// ============================================================================
// 3. Cancel
// ============================================================================

static void
test_cancel(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 102);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    test_sub_t sub = make_test_sub(1003, topic);
    _n00b_conduit_sub_register(1003, &sub, topic);

    assert(n00b_conduit_sub_is_active(1003));

    n00b_conduit_sub_cancel(1003);
    assert(!n00b_conduit_sub_is_active(1003));
    assert(n00b_conduit_sub_state(1003) == N00B_CONDUIT_SUB_REMOVED);
    assert(n00b_atomic_load(&topic->sub_delivery_lock) == nullptr);
    assert(n00b_atomic_load(&topic->sub_list_head) == nullptr);

    n00b_conduit_destroy(c);
    printf("  [PASS] cancel\n");
}

// ============================================================================
// 4. Cancel from suspended state
// ============================================================================

static void
test_cancel_from_suspended(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 103);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    test_sub_t sub = make_test_sub(1004, topic);
    _n00b_conduit_sub_register(1004, &sub, topic);

    n00b_conduit_sub_suspend(1004);
    assert(n00b_conduit_sub_state(1004) == N00B_CONDUIT_SUB_SUSPENDED);

    n00b_conduit_sub_cancel(1004);
    assert(n00b_conduit_sub_state(1004) == N00B_CONDUIT_SUB_REMOVED);

    n00b_conduit_destroy(c);
    printf("  [PASS] cancel from suspended\n");
}

// ============================================================================
// 5. Invalid handle
// ============================================================================

static void
test_invalid_handle(void)
{
    assert(!n00b_conduit_sub_is_active(N00B_CONDUIT_INVALID_SUB_HANDLE));
    assert(n00b_conduit_sub_state(N00B_CONDUIT_INVALID_SUB_HANDLE) ==
           N00B_CONDUIT_SUB_REMOVED);

    // Should not crash.
    n00b_conduit_sub_cancel(N00B_CONDUIT_INVALID_SUB_HANDLE);
    n00b_conduit_sub_suspend(N00B_CONDUIT_INVALID_SUB_HANDLE);
    n00b_conduit_sub_resume(N00B_CONDUIT_INVALID_SUB_HANDLE);

    // Non-existent handle.
    assert(!n00b_conduit_sub_is_active(999999));
    assert(n00b_conduit_sub_state(999999) == N00B_CONDUIT_SUB_REMOVED);

    printf("  [PASS] invalid handle\n");
}

// ============================================================================
// 6. Resume has no effect on active sub
// ============================================================================

static void
test_resume_active_noop(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 104);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    test_sub_t sub = make_test_sub(1005, topic);
    _n00b_conduit_sub_register(1005, &sub, topic);

    // Resume on an already-active sub should be a no-op.
    n00b_conduit_sub_resume(1005);
    assert(n00b_conduit_sub_is_active(1005));

    n00b_conduit_destroy(c);
    printf("  [PASS] resume active is no-op\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_subscription:\n");
    fflush(stdout);

    test_sub_active();
    fflush(stdout);
    test_suspend_resume();
    fflush(stdout);
    test_cancel();
    fflush(stdout);
    test_cancel_from_suspended();
    fflush(stdout);
    test_invalid_handle();
    fflush(stdout);
    test_resume_active_noop();
    fflush(stdout);

    printf("All subscription tests passed.\n");
    n00b_shutdown();
    return 0;
}
