/*
 * test_publisher.c — Tests for conduit publisher claim/yield/liveness.
 */

#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/thread.h"

// ============================================================================
// 1. Basic claim and yield
// ============================================================================

static void
test_claim_yield(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 1);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    // Claim publisher.
    n00b_result_t(n00b_conduit_publisher_t *) pr = n00b_conduit_publish_try_claim(topic);
    assert(n00b_result_is_ok(pr));
    n00b_conduit_publisher_t *pub = n00b_result_get(pr);

    assert(n00b_conduit_publish_state(pub) == N00B_CONDUIT_PUB_ACTIVE);
    assert(n00b_conduit_publish_is_owner(topic));
    assert(n00b_result_get(n00b_conduit_publish_topic(pub)) == topic);

    // Yield.
    n00b_conduit_publish_yield(pub);
    assert(n00b_conduit_publish_state(pub) == N00B_CONDUIT_PUB_YIELDED);
    assert(!n00b_conduit_publish_is_owner(topic));

    n00b_conduit_destroy(c);
    printf("  [PASS] claim and yield\n");
}

// ============================================================================
// 2. Re-entrant claim (same thread)
// ============================================================================

static void
test_reentrant_claim(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 2);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    n00b_result_t(n00b_conduit_publisher_t *) pr1 = n00b_conduit_publish_try_claim(topic);
    assert(n00b_result_is_ok(pr1));
    n00b_conduit_publisher_t *pub1 = n00b_result_get(pr1);

    // Same thread re-claims — should get the same publisher back.
    n00b_result_t(n00b_conduit_publisher_t *) pr2 = n00b_conduit_publish_try_claim(topic);
    assert(n00b_result_is_ok(pr2));
    n00b_conduit_publisher_t *pub2 = n00b_result_get(pr2);
    assert(pub1 == pub2);

    n00b_conduit_publish_yield(pub1);
    n00b_conduit_destroy(c);
    printf("  [PASS] re-entrant claim\n");
}

// ============================================================================
// 3. Competing claim from another thread
// ============================================================================

struct competing_claim_args {
    n00b_conduit_topic_base_t *topic;
    _Atomic(int)               result; // 0 = not run, 1 = claimed, 2 = failed
};

static void *
competing_claimer(void *arg)
{
    struct competing_claim_args *a = arg;

    n00b_result_t(n00b_conduit_publisher_t *) pr =
        n00b_conduit_publish_try_claim(a->topic);

    if (n00b_result_is_ok(pr)) {
        n00b_conduit_publisher_t *pub = n00b_result_get(pr);
        n00b_conduit_publish_yield(pub);
        atomic_store(&a->result, 1);
    }
    else {
        atomic_store(&a->result, 2);
    }

    return nullptr;
}

static void
test_competing_claim(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 3);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    // Main thread claims first.
    n00b_result_t(n00b_conduit_publisher_t *) pr = n00b_conduit_publish_try_claim(topic);
    assert(n00b_result_is_ok(pr));
    n00b_conduit_publisher_t *pub = n00b_result_get(pr);

    // Other thread tries to claim — should fail.
    struct competing_claim_args args = {.topic = topic};
    atomic_store(&args.result, 0);

    // Competing claim runs on an n00b-spawned worker (NOT pthread_create), so
    // it has a real TCB and n00b_conduit_publish_try_claim resolves its owning
    // thread correctly; it must observe main's claim and fail.
    n00b_result_t(n00b_thread_t *) thr = n00b_thread_spawn(competing_claimer,
                                                           &args);
    assert(n00b_result_is_ok(thr));
    n00b_thread_join(n00b_result_get(thr));

    assert(atomic_load(&args.result) == 2); // Failed.

    n00b_conduit_publish_yield(pub);
    n00b_conduit_destroy(c);
    printf("  [PASS] competing claim\n");
}

// ============================================================================
// 4. Claim after yield
// ============================================================================

static void
test_claim_after_yield(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 4);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    // Claim and yield.
    n00b_result_t(n00b_conduit_publisher_t *) pr1 = n00b_conduit_publish_try_claim(topic);
    assert(n00b_result_is_ok(pr1));
    n00b_conduit_publish_yield(n00b_result_get(pr1));

    // Claim again — should succeed.
    n00b_result_t(n00b_conduit_publisher_t *) pr2 = n00b_conduit_publish_try_claim(topic);
    assert(n00b_result_is_ok(pr2));
    n00b_conduit_publish_yield(n00b_result_get(pr2));

    n00b_conduit_destroy(c);
    printf("  [PASS] claim after yield\n");
}

// ============================================================================
// 5. Publisher finishing state
// ============================================================================

static void
test_publisher_finishing(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 5);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    n00b_result_t(n00b_conduit_publisher_t *) pr = n00b_conduit_publish_try_claim(topic);
    assert(n00b_result_is_ok(pr));
    n00b_conduit_publisher_t *pub = n00b_result_get(pr);

    assert(n00b_conduit_publish_state(pub) == N00B_CONDUIT_PUB_ACTIVE);

    n00b_conduit_publish_finishing(pub);
    assert(n00b_conduit_publish_state(pub) == N00B_CONDUIT_PUB_FINISHING);

    n00b_conduit_publish_yield(pub);
    assert(n00b_conduit_publish_state(pub) == N00B_CONDUIT_PUB_YIELDED);

    n00b_conduit_destroy(c);
    printf("  [PASS] publisher finishing state\n");
}

// ============================================================================
// 6. Liveness check
// ============================================================================

static void
test_liveness_check(void)
{
    n00b_result_t(n00b_conduit_t *) cr = n00b_conduit_new();
    assert(n00b_result_is_ok(cr));
    n00b_conduit_t *c = n00b_result_get(cr);

    n00b_result_t(n00b_conduit_topic_base_t *) tr = n00b_conduit_topic_for_fd(c, 6);
    assert(n00b_result_is_ok(tr));
    n00b_conduit_topic_base_t *topic = n00b_result_get(tr);

    // No publisher — liveness should return true (vacuously).
    assert(n00b_conduit_publish_check_liveness(topic));

    // Claim.
    n00b_result_t(n00b_conduit_publisher_t *) pr = n00b_conduit_publish_try_claim(topic);
    assert(n00b_result_is_ok(pr));

    // Our thread is alive — should return true.
    assert(n00b_conduit_publish_check_liveness(topic));

    n00b_conduit_publish_yield(n00b_result_get(pr));
    n00b_conduit_destroy(c);
    printf("  [PASS] liveness check\n");
}

// ============================================================================
// 7. Null arg handling
// ============================================================================

static void
test_null_args(void)
{
    assert(n00b_result_is_err(n00b_conduit_publish_try_claim(nullptr)));
    assert(!n00b_conduit_publish_is_owner(nullptr));
    assert(n00b_result_is_err(n00b_conduit_publish_topic(nullptr)));

    n00b_conduit_publish_yield(nullptr);     // Should not crash.
    n00b_conduit_publish_finishing(nullptr);  // Should not crash.

    assert(n00b_conduit_publish_state(nullptr) == N00B_CONDUIT_PUB_YIELDED);
    assert(n00b_conduit_publish_check_liveness(nullptr));

    printf("  [PASS] null arg handling\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_publisher:\n");
    fflush(stdout);

    test_claim_yield();
    fflush(stdout);
    test_reentrant_claim();
    fflush(stdout);
    test_competing_claim();
    fflush(stdout);
    test_claim_after_yield();
    fflush(stdout);
    test_publisher_finishing();
    fflush(stdout);
    test_liveness_check();
    fflush(stdout);
    test_null_args();
    fflush(stdout);

    printf("All publisher tests passed.\n");
    n00b_shutdown();
    return 0;
}
