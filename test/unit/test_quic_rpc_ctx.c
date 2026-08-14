/*
 * test_quic_rpc_ctx.c — Phase 4 § 4.8.  Local cancel + deadline ctx.
 *
 * What we test:
 *   1. Lifecycle: new → cancel → is_cancelled → close.
 *   2. Deadline math: remaining_ns; deadline elapses ⇒ is_cancelled.
 *   3. Cascading cancel: parent → child → grandchild.
 *   4. Cancel one child only — parent + sibling unaffected.
 *   5. Deadline inheritance: child's effective deadline = min(parent, child).
 *   6. wait_until: cancel before deadline ⇒ true; deadline elapses ⇒ false.
 *   7. Waiter wakeup on cancel: spawn thread, cancel, observe wakeup.
 *   8. Sticky cancel: cancel twice; close after cancel; is_cancelled
 *      stays true post-close.
 *   9. Close idempotent.
 *  10. Born-cancelled: child of an already-cancelled parent starts
 *      cancelled.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "core/thread.h"

#include "n00b.h"
#include "core/runtime.h"
#include "core/time.h"
#include "net/quic/rpc_ctx.h"

static int64_t
now_ns(void)
{
    return n00b_ns_timestamp();
}

static int64_t
ms_from_now(int64_t ms)
{
    return now_ns() + ms * 1000LL * 1000LL;
}

static void
test_lifecycle(void)
{
    n00b_rpc_ctx_t *c = n00b_rpc_ctx_new();
    assert(c != nullptr);
    assert(!n00b_rpc_ctx_is_cancelled(c));
    n00b_rpc_ctx_cancel(c);
    assert(n00b_rpc_ctx_is_cancelled(c));
    /* Sticky: second cancel is a no-op. */
    n00b_rpc_ctx_cancel(c);
    assert(n00b_rpc_ctx_is_cancelled(c));
    n00b_rpc_ctx_close(c);
    /* Cancel survives close. */
    assert(n00b_rpc_ctx_is_cancelled(c));
    /* Close idempotent. */
    n00b_rpc_ctx_close(c);
    printf("  [PASS] lifecycle: new / cancel sticky / close idempotent\n");
}

static void
test_remaining_ns(void)
{
    /* No deadline. */
    n00b_rpc_ctx_t *root = n00b_rpc_ctx_new();
    assert(n00b_rpc_ctx_remaining_ns(root) == -1);

    /* Deadline ~100ms in the future. */
    n00b_rpc_ctx_t *c = n00b_rpc_ctx_with_deadline(nullptr, ms_from_now(100));
    int64_t r = n00b_rpc_ctx_remaining_ns(c);
    assert(r > 0 && r <= 100LL * 1000 * 1000);

    /* Past deadline ⇒ is_cancelled + remaining=0. */
    n00b_rpc_ctx_t *expired =
        n00b_rpc_ctx_with_deadline(nullptr, now_ns() - 1000);
    assert(n00b_rpc_ctx_is_cancelled(expired));
    assert(n00b_rpc_ctx_remaining_ns(expired) == 0);

    /* Cancelled child: remaining is 0. */
    n00b_rpc_ctx_t *cc = n00b_rpc_ctx_with_deadline(nullptr, ms_from_now(1000));
    n00b_rpc_ctx_cancel(cc);
    assert(n00b_rpc_ctx_remaining_ns(cc) == 0);

    /* nullptr safety. */
    assert(n00b_rpc_ctx_remaining_ns(nullptr) == -1);

    n00b_rpc_ctx_close(root);
    n00b_rpc_ctx_close(c);
    n00b_rpc_ctx_close(expired);
    n00b_rpc_ctx_close(cc);
    printf("  [PASS] remaining_ns: no-deadline / future / past / cancelled\n");
}

static void
test_cascading_cancel(void)
{
    n00b_rpc_ctx_t *root  = n00b_rpc_ctx_new();
    n00b_rpc_ctx_t *child = n00b_rpc_ctx_with_cancel(root);
    n00b_rpc_ctx_t *grand = n00b_rpc_ctx_with_cancel(child);
    n00b_rpc_ctx_t *grand2 = n00b_rpc_ctx_with_cancel(child);

    assert(!n00b_rpc_ctx_is_cancelled(root));
    assert(!n00b_rpc_ctx_is_cancelled(child));
    assert(!n00b_rpc_ctx_is_cancelled(grand));

    n00b_rpc_ctx_cancel(root);

    assert(n00b_rpc_ctx_is_cancelled(root));
    assert(n00b_rpc_ctx_is_cancelled(child));
    assert(n00b_rpc_ctx_is_cancelled(grand));
    assert(n00b_rpc_ctx_is_cancelled(grand2));

    n00b_rpc_ctx_close(grand2);
    n00b_rpc_ctx_close(grand);
    n00b_rpc_ctx_close(child);
    n00b_rpc_ctx_close(root);
    printf("  [PASS] cascading cancel: parent → all descendants\n");
}

static void
test_isolated_cancel(void)
{
    n00b_rpc_ctx_t *root   = n00b_rpc_ctx_new();
    n00b_rpc_ctx_t *child1 = n00b_rpc_ctx_with_cancel(root);
    n00b_rpc_ctx_t *child2 = n00b_rpc_ctx_with_cancel(root);

    n00b_rpc_ctx_cancel(child1);

    assert(n00b_rpc_ctx_is_cancelled(child1));
    assert(!n00b_rpc_ctx_is_cancelled(child2));
    assert(!n00b_rpc_ctx_is_cancelled(root));

    n00b_rpc_ctx_close(child1);
    n00b_rpc_ctx_close(child2);
    n00b_rpc_ctx_close(root);
    printf("  [PASS] cancel propagates DOWN only, not UP\n");
}

static void
test_deadline_inheritance(void)
{
    /* parent: 100ms; child requests 5s ⇒ effective 100ms (parent's). */
    n00b_rpc_ctx_t *parent =
        n00b_rpc_ctx_with_deadline(nullptr, ms_from_now(100));
    n00b_rpc_ctx_t *child =
        n00b_rpc_ctx_with_deadline(parent, ms_from_now(5000));
    int64_t pr = n00b_rpc_ctx_remaining_ns(parent);
    int64_t cr = n00b_rpc_ctx_remaining_ns(child);
    assert(cr <= pr + 1000 /* tiny clock-read slop */);
    assert(cr <= 100LL * 1000 * 1000);

    /* parent: no deadline; child: 100ms ⇒ child gets its own. */
    n00b_rpc_ctx_t *p2 = n00b_rpc_ctx_new();
    n00b_rpc_ctx_t *c2 =
        n00b_rpc_ctx_with_deadline(p2, ms_from_now(100));
    assert(n00b_rpc_ctx_remaining_ns(p2) == -1);
    int64_t c2r = n00b_rpc_ctx_remaining_ns(c2);
    assert(c2r > 0 && c2r <= 100LL * 1000 * 1000);

    n00b_rpc_ctx_close(child);
    n00b_rpc_ctx_close(parent);
    n00b_rpc_ctx_close(c2);
    n00b_rpc_ctx_close(p2);
    printf("  [PASS] deadline inheritance: child = min(parent, requested)\n");
}

static void
test_wait_until_cancel(void)
{
    /* wait_until returns true when cancelled before the cap. */
    n00b_rpc_ctx_t *c = n00b_rpc_ctx_with_cancel(nullptr);
    n00b_rpc_ctx_cancel(c);
    bool fired = n00b_rpc_ctx_wait_until(c, ms_from_now(1000));
    assert(fired);

    /* wait_until returns false when cap elapses before cancel. */
    n00b_rpc_ctx_t *live = n00b_rpc_ctx_with_cancel(nullptr);
    int64_t before = now_ns();
    bool tripped = n00b_rpc_ctx_wait_until(live, ms_from_now(50));
    int64_t after = now_ns();
    assert(!tripped);
    assert(after - before >= 40LL * 1000 * 1000);

    n00b_rpc_ctx_close(c);
    n00b_rpc_ctx_close(live);
    printf("  [PASS] wait_until: cancel returns true; cap returns false\n");
}

static void *
cancel_after_delay(void *arg)
{
    n00b_rpc_ctx_t *c = arg;
    /* 50ms delay then cancel. */
    base_nanosleep_ns(50ULL * 1000ULL * 1000ULL);
    n00b_rpc_ctx_cancel(c);
    return nullptr;
}

static void
test_waiter_wakeup(void)
{
    n00b_rpc_ctx_t *c = n00b_rpc_ctx_with_cancel(nullptr);
    auto tr = n00b_thread_spawn(cancel_after_delay, c);
    assert(n00b_result_is_ok(tr));
    n00b_thread_t *t = n00b_result_get(tr);

    int64_t before = now_ns();
    n00b_rpc_ctx_wait(c);  /* should return when cancelled, ~50ms in */
    int64_t after = now_ns();
    assert(n00b_rpc_ctx_is_cancelled(c));
    /* Verify the wait actually blocked (took at least ~40ms) AND
     * that the wakeup was prompt (under ~500ms even on a busy CI). */
    int64_t elapsed_ms = (after - before) / 1000000;
    assert(elapsed_ms >= 30 && elapsed_ms < 500);

    n00b_thread_join(t);
    n00b_rpc_ctx_close(c);
    printf("  [PASS] waiter wakeup on cross-thread cancel (~%lldms)\n",
           (long long)elapsed_ms);
}

static void
test_deadline_triggers_wait_unblock(void)
{
    /* wait should unblock when the ctx's own deadline elapses. */
    n00b_rpc_ctx_t *c =
        n00b_rpc_ctx_with_deadline(nullptr, ms_from_now(50));
    int64_t before = now_ns();
    n00b_rpc_ctx_wait(c);
    int64_t after = now_ns();
    assert(n00b_rpc_ctx_is_cancelled(c));
    int64_t elapsed_ms = (after - before) / 1000000;
    assert(elapsed_ms >= 40 && elapsed_ms < 500);
    n00b_rpc_ctx_close(c);
    printf("  [PASS] wait unblocks on own deadline (~%lldms)\n",
           (long long)elapsed_ms);
}

static void
test_born_cancelled(void)
{
    /* Child of an already-cancelled parent starts cancelled. */
    n00b_rpc_ctx_t *p = n00b_rpc_ctx_new();
    n00b_rpc_ctx_cancel(p);
    n00b_rpc_ctx_t *c = n00b_rpc_ctx_with_cancel(p);
    assert(n00b_rpc_ctx_is_cancelled(c));
    n00b_rpc_ctx_close(c);
    n00b_rpc_ctx_close(p);
    printf("  [PASS] child of cancelled parent is born-cancelled\n");
}

static void
test_nullptr_safety(void)
{
    /* All public functions must be nullptr-safe. */
    n00b_rpc_ctx_cancel(nullptr);
    assert(!n00b_rpc_ctx_is_cancelled(nullptr));
    assert(n00b_rpc_ctx_remaining_ns(nullptr) == -1);
    n00b_rpc_ctx_wait(nullptr);
    assert(!n00b_rpc_ctx_wait_until(nullptr, ms_from_now(10)));
    n00b_rpc_ctx_close(nullptr);
    printf("  [PASS] nullptr safety on every public entry point\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_rpc_ctx:\n");
    test_lifecycle();
    test_remaining_ns();
    test_cascading_cancel();
    test_isolated_cancel();
    test_deadline_inheritance();
    test_wait_until_cancel();
    test_waiter_wakeup();
    test_deadline_triggers_wait_unblock();
    test_born_cancelled();
    test_nullptr_safety();
    printf("All quic_rpc_ctx tests passed.\n");

    n00b_shutdown();
    return 0;
}
