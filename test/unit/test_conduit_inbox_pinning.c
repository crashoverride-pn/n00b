/*
 * test_conduit_inbox_pinning.c — gate for the embedded-condition pinning rule.
 *
 * Every conduit inbox struct embeds an n00b_condition_t BY VALUE
 * (conduit/inbox.h:170). The lock-accounting registry keys locks by
 * *address*, so any struct embedding one must be allocated from a
 * non-moving allocator. If it lands in a relocating arena, the first GC
 * pass moves the struct and the next acquire-accounting check on the
 * now-stale lock aborts with:
 *
 *   "Lock at address ... was not initialized before use."
 *
 * That failure surfaces in a downstream gateway rather than here — it is
 * how wax#431 and wax#799 were both found, by consumers. Until this test
 * the rule was held together only by a comment and by whoever noticed;
 * n00b#324 caught two constructors that had drifted off it (fixed in
 * n00b#325), which is what prompted n00b#326 and this gate.
 *
 * The check: the collector only relocates objects in a managed_segment or
 * sys_segment (gc.c's forwarding switch). Pools are never moved. So the
 * invariant is exactly `!n00b_mmap_is_arena_segment(region)`.
 */

#include <assert.h>
#include <stdio.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "conduit/file_change.h"
#include "conduit/local.h"
#include "conduit/proc_lifecycle.h"
#include "conduit/service.h"
#include "conduit/signal.h"
#include "conduit/socket.h"
#include "conduit/socket_udp.h"
#include "conduit/timer.h"
#include "conduit/user_event.h"
#include "core/alloc.h"
#include "core/mmaps.h"
#include "core/pool.h"
#include "core/runtime.h"

static int checked = 0;

/* Assert `ptr` cannot be relocated by the collector. */
static void
assert_non_moving(const char *what, void *ptr)
{
    assert(ptr != nullptr);

    auto region_opt = n00b_mmap_by_address(ptr);
    if (!n00b_option_is_set(region_opt)) {
        /* Unregistered memory is not walked by the collector's forwarding
         * pass at all, so it cannot be moved. Pools register their pages
         * (mmaps.h:218 fixes the kind at n00b_mmap_pool), so in practice
         * this branch means "not GC-managed" -- still non-moving. */
        printf("  [PASS] %-34s unregistered (non-moving)\n", what);
        checked++;
        return;
    }

    n00b_mmap_info_t *region = n00b_option_get(region_opt);
    if (n00b_mmap_is_arena_segment(region)) {
        printf("  [FAIL] %s: allocated in a RELOCATING arena segment "
               "(kind=%d). It embeds an n00b_condition_t, so a GC pass will "
               "move it and invalidate the lock registry's address key.\n",
               what,
               (int)n00b_mmap_get_kind(region));
        assert(!"inbox embedding n00b_condition_t is in a moving region");
    }

    printf("  [PASS] %-34s kind=%d (non-moving)\n",
           what,
           (int)n00b_mmap_get_kind(region));
    checked++;
}

/* Exercise every *_inbox_new constructor against conduit `c`. */
static void
check_all_inboxes(n00b_conduit_t *c, const char *label)
{
    printf("%s\n", label);

    assert_non_moving("fd_status_inbox_new", n00b_conduit_fd_status_inbox_new(c));
    assert_non_moving("fd_write_inbox_new", n00b_conduit_fd_write_inbox_new(c));
    assert_non_moving("fd_write_req_inbox_new", n00b_conduit_fd_write_req_inbox_new(c));
    assert_non_moving("fd_write_done_inbox_new", n00b_conduit_fd_write_done_inbox_new(c));
    assert_non_moving("fd_stream_inbox_new", n00b_conduit_fd_stream_inbox_new(c));
    assert_non_moving("local_accept_inbox_new", n00b_conduit_local_accept_inbox_new(c));
    assert_non_moving("local_status_inbox_new", n00b_conduit_local_status_inbox_new(c));
    assert_non_moving("sock_accept_inbox_new", n00b_conduit_sock_accept_inbox_new(c));
    assert_non_moving("sock_status_inbox_new", n00b_conduit_sock_status_inbox_new(c));
    assert_non_moving("udp_inbox_new", n00b_conduit_udp_inbox_new(c));
    assert_non_moving("signal_inbox_new", n00b_conduit_signal_inbox_new(c));
    assert_non_moving("user_event_inbox_new", n00b_conduit_user_event_inbox_new(c));
    assert_non_moving("timer_inbox_new", n00b_conduit_timer_inbox_new(c));
    assert_non_moving("file_change_inbox_new", n00b_conduit_file_change_inbox_new(c));
    assert_non_moving("proc_inbox_new", n00b_conduit_proc_inbox_new(c));
}

/* Default conduit: c->allocator falls back to the runtime conduit_pool. */
static void
test_default_conduit(void)
{
    n00b_result_t(n00b_conduit_t *) r = n00b_conduit_new();
    assert(n00b_result_is_ok(r));
    n00b_conduit_t *c = n00b_result_get(r);

    check_all_inboxes(c, "default conduit (conduit_pool):");

    n00b_conduit_destroy(c);
}

/*
 * Explicit-allocator conduit. n00b_conduit_new documents that a caller
 * whose messages carry GC'd pointers may pass a GC-visible allocator;
 * wax's raw gateway does exactly this (ingest.c:2464 passes user_pool).
 * Every inbox must then come from THAT allocator -- which is what n00b#326
 * converged timer.h onto. Before that it hardcoded conduit_pool, so this
 * conduit's timer inbox silently came from a different pool than its other
 * fourteen.
 */
static void
test_explicit_allocator_conduit(void)
{
    n00b_allocator_t *user_pool
        = (n00b_allocator_t *)&n00b_get_runtime()->user_pool;

    n00b_result_t(n00b_conduit_t *) r = n00b_conduit_new(.allocator = user_pool);
    assert(n00b_result_is_ok(r));
    n00b_conduit_t *c = n00b_result_get(r);
    assert(c->allocator == user_pool);

    check_all_inboxes(c, "explicit-allocator conduit (user_pool):");

    /* Every inbox must honour the conduit's allocator, not just be
     * non-moving. This is the part that was silently false for the timer
     * inbox before n00b#326. */
    void *timer_inbox = n00b_conduit_timer_inbox_new(c);
    auto  owner_opt   = n00b_mem_get_allocator(timer_inbox);
    assert(n00b_option_is_set(owner_opt));
    assert(n00b_option_get(owner_opt) == user_pool);
    printf("  [PASS] timer inbox honours c->allocator\n");
    checked++;

    n00b_conduit_destroy(c);
}

/*
 * n00b#326 item 3: the rule is about embedded n00b_condition_t, not about
 * inboxes. `n00b_conduit_service_t` embeds one directly (service.h:89
 * `n00b_condition_t job_cv`) and is allocated at service.c:206. It is
 * already correct -- but by the author's care, not by anything that would
 * catch a regression. That is what this covers.
 *
 * The full audit is a grep for `n00b_condition_t ` with no `*`:
 * conduit/inbox.h:170 (all 15 inboxes), conduit/service.h:89, and
 * conduit/xform.h:98,411 -- where inbox_cv is a POINTER, so the containing
 * struct is free to move and is not subject to this rule.
 */
static void
test_embedded_condition_beyond_inboxes(void)
{
    printf("embedded-condition structs beyond inboxes:\n");

    n00b_result_t(n00b_conduit_t *) r = n00b_conduit_new();
    assert(n00b_result_is_ok(r));
    n00b_conduit_t *c = n00b_result_get(r);

    n00b_result_t(n00b_conduit_service_t *) sr = n00b_conduit_service_new(c);
    assert(n00b_result_is_ok(sr));
    n00b_conduit_service_t *svc = n00b_result_get(sr);

    assert_non_moving("conduit_service_new (job_cv)", svc);

    n00b_conduit_destroy(c);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_default_conduit();
    test_explicit_allocator_conduit();
    test_embedded_condition_beyond_inboxes();

    printf("\n%d allocations checked; all non-moving.\n", checked);

    n00b_shutdown();
    return 0;
}
