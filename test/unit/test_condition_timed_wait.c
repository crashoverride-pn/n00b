/* test/unit/test_condition_timed_wait.c
 *
 * A timed n00b_condition_wait on a condition variable nobody notifies must
 * return by its deadline, whatever spurious wakes it absorbs on the way.
 *
 * One thread loops short timed waits and publishes each wait's start time. A
 * second thread issues one raw wake on the waiter's own cv_wake futex per
 * wait, aimed at start + budget - lead with the lead swept one microsecond at
 * a time. The wake-to-timestamp latency is unknown, so one of the leads makes
 * base_wait measure the elapsed time as exactly the budget; a remaining budget
 * of zero must be reported as a timeout, never re-waited without a deadline.
 *
 * The waiter is also the detector: a wait that runs 100 ms past a 500 us
 * budget is a hang. The main thread frees a hung waiter by notifying the CV
 * so the test fails instead of wedging the runner.
 */

#define N00B_USE_INTERNAL_API

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "n00b.h"
#include "core/atomic.h"
#include "core/condition.h"
#include "core/futex.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/time.h"
#include "util/assert.h"

#define BUDGET_NS   (500ull * 1000ull)
#define HANG_NS     (100ull * 1000ull * 1000ull)
#define RUN_NS      (20ull * 1000ull * 1000ull * 1000ull)
#define LEAD_SWEEP  40u

static n00b_condition_t g_cv;
static _Atomic bool     g_stop;
static _Atomic bool     g_hung;
static _Atomic uint64_t g_iterations;
static _Atomic uint64_t g_wait_seq;
static _Atomic uint64_t g_wait_started_ns;
static _Atomic(n00b_thread_t *) g_waiter;

static void *
waiter_main(void *arg)
{
    (void)arg;
    n00b_atomic_store(&g_waiter, n00b_thread_self());

    while (!n00b_atomic_load(&g_stop)) {
        uint64_t t0 = (uint64_t)n00b_ns_timestamp();
        n00b_atomic_store(&g_wait_started_ns, t0);
        n00b_atomic_add(&g_wait_seq, 1);

        n00b_condition_lock(&g_cv);
        (void)n00b_condition_wait(&g_cv,
                                  .auto_unlock = true,
                                  .timeout     = (int64_t)BUDGET_NS);

        uint64_t took = (uint64_t)n00b_ns_timestamp() - t0;
        n00b_atomic_add(&g_iterations, 1);
        if (took > BUDGET_NS + HANG_NS) {
            n00b_atomic_store(&g_hung, true);
            n00b_atomic_store(&g_stop, true);
        }
    }
    return nullptr;
}

static void *
poker_main(void *arg)
{
    (void)arg;
    uint64_t seen = 0;
    uint64_t i    = 0;

    while (!n00b_atomic_load(&g_stop)) {
        uint64_t seq = n00b_atomic_load(&g_wait_seq);
        if (seq == seen) {
            continue;
        }
        seen = seq;
        uint64_t t0 = n00b_atomic_load(&g_wait_started_ns);
        if (t0 == 0) {
            continue;
        }
        uint64_t lead   = 1000ull * (1 + (i++ % LEAD_SWEEP));
        uint64_t target = t0 + BUDGET_NS - lead;
        while ((uint64_t)n00b_ns_timestamp() < target
               && n00b_atomic_load(&g_wait_seq) == seq) {
        }
        if (n00b_atomic_load(&g_wait_seq) != seq) {
            continue;
        }
        n00b_thread_t *w = n00b_atomic_load(&g_waiter);
        if (w != nullptr) {
            n00b_futex_wake(&w->cv_wake, false);
        }
    }
    return nullptr;
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);
    n00b_condition_init(&g_cv);

    auto tw = n00b_thread_spawn(waiter_main, nullptr);
    n00b_require(n00b_result_is_ok(tw), "waiter spawn failed");
    n00b_thread_t *waiter = n00b_result_get(tw);
    auto tp = n00b_thread_spawn(poker_main, nullptr);
    n00b_require(n00b_result_is_ok(tp), "poker spawn failed");
    n00b_thread_t *poker = n00b_result_get(tp);

    uint64_t deadline = (uint64_t)n00b_ns_timestamp() + RUN_NS;
    while (!n00b_atomic_load(&g_stop)
           && (uint64_t)n00b_ns_timestamp() < deadline) {
        base_nanosleep_ns(20ull * 1000ull * 1000ull);
        // A waiter that is still inside one wait long past its budget is hung
        // even though it has not returned to report it; free it so the run
        // ends with a failure rather than a wedged test.
        uint64_t started = n00b_atomic_load(&g_wait_started_ns);
        uint64_t now     = (uint64_t)n00b_ns_timestamp();
        if (started != 0 && now > started
            && now - started > BUDGET_NS + 20ull * HANG_NS) {
            n00b_atomic_store(&g_hung, true);
            n00b_atomic_store(&g_stop, true);
            n00b_condition_lock(&g_cv);
            n00b_condition_notify(&g_cv, .all = true, .auto_unlock = true);
        }
    }
    n00b_atomic_store(&g_stop, true);
    (void)n00b_thread_join(poker);
    (void)n00b_thread_join(waiter);

    bool hung = n00b_atomic_load(&g_hung);
    printf("condition_timed_wait: %s after %llu waits\n",
           hung ? "a timed wait did not return by its deadline" : "ok",
           (unsigned long long)n00b_atomic_load(&g_iterations));
    n00b_shutdown();
    return hung ? 1 : 0;
}
