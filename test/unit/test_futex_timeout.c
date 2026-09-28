/* test/unit/test_futex_timeout.c
 *
 * Timeout semantics of the futex helpers in core/futex.h, which must agree
 * on every platform:
 *   - a 0ns wait polls;
 *   - a timeout over one second waits that long and reports ETIMEDOUT;
 *   - n00b_futex_wait_forever blocks until a wake;
 *   - an untimed condition wait sleeps in the kernel;
 *   - n00b_futex_timed_wait_for_value gives up promptly once its budget is
 *     spent, whether it starts spent or runs out between wakes.
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

#if defined(__APPLE__)
#include <mach/mach.h>
#endif

#define MS_NS          (1000ll * 1000ll)
#define PROMPT_NS      (250ll * MS_NS)
#define LONG_WAIT_NS   (1100ll * MS_NS)
#define LATE_SLACK_NS  (1500ll * MS_NS)
#define HOLD_NS        (50ll * MS_NS)
#define CPU_HOLD_NS    (200ll * MS_NS)
#define CPU_MAX_NS     (20ll * MS_NS)
#define BUDGET_NS      (20ll * MS_NS)

static int g_failures;

#define STATUS(f0) (g_failures == (f0) ? "PASS" : "FAIL")

#define EXPECT(cond, ...)                          \
    do {                                           \
        if (!(cond)) {                             \
            printf("  [FAIL] %s:%d: ", __FILE__,   \
                   __LINE__);                      \
            printf(__VA_ARGS__);                   \
            printf("\n");                          \
            g_failures++;                          \
        }                                          \
    } while (0)

static int64_t
elapsed_since(int64_t t0)
{
    return n00b_ns_timestamp() - t0;
}

// Barrier shared by the helper threads below: the helper counts itself in,
// then holds until main raises the go flag.
static _Atomic uint32_t g_ready;
static _Atomic bool     g_go;
static _Atomic bool     g_stop;

static void
barrier_arrive(void)
{
    n00b_atomic_add(&g_ready, 1);
    while (!n00b_atomic_load(&g_go)) {
        __asm__ volatile("" ::: "memory");
    }
}

static void
barrier_release(uint32_t n)
{
    while (n00b_atomic_load(&g_ready) < n) {
        __asm__ volatile("" ::: "memory");
    }
    n00b_atomic_store(&g_go, true);
}

static void
barrier_reset(void)
{
    n00b_atomic_store(&g_ready, 0);
    n00b_atomic_store(&g_go, false);
    n00b_atomic_store(&g_stop, false);
}

// ============================================================================
// 1. A zero timeout polls
// ============================================================================

static void
test_zero_timeout_polls(void)
{
    int f0 = g_failures;

    n00b_futex_t word = 1;

    int64_t t0 = n00b_ns_timestamp();
    int     rc = n00b_futex_wait(&word, 1, 0);
    int64_t dt = elapsed_since(t0);
    EXPECT(rc == ETIMEDOUT, "0ns wait on a matching word returned %d", rc);
    EXPECT(dt < PROMPT_NS, "0ns wait took %lld ns", (long long)dt);

    t0 = n00b_ns_timestamp();
    rc = n00b_futex_wait(&word, 2, 0);
    dt = elapsed_since(t0);
    EXPECT(rc == 0, "0ns wait on a non-matching word returned %d", rc);
    EXPECT(dt < PROMPT_NS, "0ns non-matching wait took %lld ns", (long long)dt);

    t0 = n00b_ns_timestamp();
    rc = n00b_futex_wait_forever(&word, 2);
    dt = elapsed_since(t0);
    EXPECT(rc == 0, "untimed wait on a non-matching word returned %d", rc);
    EXPECT(dt < PROMPT_NS, "untimed non-matching wait took %lld ns", (long long)dt);

    printf("  [%s] zero timeout polls\n", STATUS(f0));
}

// ============================================================================
// 2. A timeout over one second runs to completion
// ============================================================================

// Waits out ns on a word nobody changes.  A signal can interrupt the wait on
// Linux, so an EINTR or a spurious return re-waits for what is left.
static int
wait_out(n00b_futex_t *word, int64_t ns, int *calls)
{
    int64_t t0 = n00b_ns_timestamp();
    int     rc;

    *calls = 0;
    for (;;) {
        int64_t left = ns - elapsed_since(t0);
        if (left < 0) {
            left = 0;
        }
        (*calls)++;
        rc = n00b_futex_wait(word, 1, (uint64_t)left);
        if (rc != EINTR && rc != 0) {
            return rc;
        }
        if (*calls > 3) {
            return rc;
        }
    }
}

static void
test_long_timeout(void)
{
    int f0 = g_failures;

    n00b_futex_t word  = 1;
    int          calls = 0;

    int64_t t0 = n00b_ns_timestamp();
    int     rc = wait_out(&word, LONG_WAIT_NS, &calls);
    int64_t dt = elapsed_since(t0);

    EXPECT(rc == ETIMEDOUT, "wait of %lld ns returned %d after %d calls",
           (long long)LONG_WAIT_NS, rc, calls);
    EXPECT(dt >= LONG_WAIT_NS - MS_NS, "wait of %lld ns returned after %lld ns",
           (long long)LONG_WAIT_NS, (long long)dt);
    EXPECT(dt < LONG_WAIT_NS + LATE_SLACK_NS, "wait of %lld ns took %lld ns",
           (long long)LONG_WAIT_NS, (long long)dt);
    EXPECT(calls <= 3, "wait needed %d calls", calls);

    printf("  [%s] timeout over one second (%lld ms)\n",
           STATUS(f0), (long long)(dt / MS_NS));
}

// ============================================================================
// 3. An untimed wait blocks until woken
// ============================================================================

static n00b_futex_t g_word;

static void *
waker_main(void *arg)
{
    (void)arg;
    barrier_arrive();
    base_nanosleep_ns((uint64_t)HOLD_NS);
    n00b_atomic_store(&g_word, 1);
    n00b_futex_wake(&g_word, true);
    return nullptr;
}

static void
test_wait_forever_blocks(void)
{
    int f0 = g_failures;

    barrier_reset();
    n00b_atomic_store(&g_word, 0);

    auto tw = n00b_thread_spawn(waker_main, nullptr);
    n00b_require(n00b_result_is_ok(tw), "waker spawn failed");
    n00b_thread_t *waker = n00b_result_get(tw);

    barrier_release(1);
    int64_t t0    = n00b_ns_timestamp();
    int     calls = 0;
    int     rc    = 0;
    while (n00b_atomic_load(&g_word) == 0 && calls < 1000) {
        rc = n00b_futex_wait_forever(&g_word, 0);
        calls++;
    }
    int64_t dt = elapsed_since(t0);
    (void)n00b_thread_join(waker);

    EXPECT(n00b_atomic_load(&g_word) == 1, "untimed wait returned before the wake");
    // A signal can interrupt the last wait just as the waker stores.
    EXPECT(rc == 0 || rc == EINTR, "untimed wait returned %d", rc);
    EXPECT(calls <= 3, "untimed wait returned %d times before the wake", calls);
    EXPECT(dt >= HOLD_NS / 2, "untimed wait returned after %lld ns, before the wake",
           (long long)dt);

    printf("  [%s] untimed wait blocks until woken (%d calls)\n",
           STATUS(f0), calls);
}

// ============================================================================
// 4. An untimed condition wait does not spin
// ============================================================================

// CPU time the thread has used, or -1 where the platform gives no way to ask
// for another thread's CPU time.
static int64_t
thread_cpu_ns(n00b_thread_t *t)
{
#if defined(__APPLE__)
    thread_basic_info_data_t info;
    mach_msg_type_number_t   count = THREAD_BASIC_INFO_COUNT;
    kern_return_t            kr    = thread_info((thread_act_t)t->os_thread_port,
                                     THREAD_BASIC_INFO,
                                     (thread_info_t)&info,
                                     &count);
    if (kr != KERN_SUCCESS) {
        return -1;
    }
    return ((int64_t)info.user_time.seconds + info.system_time.seconds)
               * (int64_t)N00B_NS_PER_SEC
         + ((int64_t)info.user_time.microseconds + info.system_time.microseconds)
               * 1000;
#elif defined(__linux__)
    if (t->os_tid == 0) {
        return -1;
    }
    // The kernel's per-thread CPU clock id for a tid (MAKE_THREAD_CPUCLOCK
    // with CPUCLOCK_SCHED).
    clockid_t       id = (clockid_t)((~(uint32_t)t->os_tid << 3) | 6u);
    struct timespec ts;
    n00b_linux_clock_gettime_raw(id, &ts);
    return (int64_t)ts.tv_sec * (int64_t)N00B_NS_PER_SEC + ts.tv_nsec;
#else
    (void)t;
    return -1;
#endif
}

static n00b_condition_t g_cv;
static _Atomic bool     g_cv_waiting;
static _Atomic bool     g_cv_done;

static void *
cv_waiter_main(void *arg)
{
    (void)arg;
    n00b_condition_lock(&g_cv);
    n00b_atomic_store(&g_cv_waiting, true);
    (void)n00b_condition_wait(&g_cv, .auto_unlock = true);
    n00b_atomic_store(&g_cv_done, true);
    return nullptr;
}

static void
test_untimed_condition_wait_sleeps(void)
{
    int f0 = g_failures;

    n00b_condition_init(&g_cv);
    n00b_atomic_store(&g_cv_waiting, false);
    n00b_atomic_store(&g_cv_done, false);

    auto tw = n00b_thread_spawn(cv_waiter_main, nullptr);
    n00b_require(n00b_result_is_ok(tw), "condition waiter spawn failed");
    n00b_thread_t *waiter = n00b_result_get(tw);

    while (!n00b_atomic_load(&g_cv_waiting)) {
        __asm__ volatile("" ::: "memory");
    }
    // The waiter holds the CV until it has listed itself, so taking the CV
    // here orders this thread after the listing.
    n00b_condition_lock(&g_cv);
    n00b_condition_unlock(&g_cv);
    base_nanosleep_ns((uint64_t)(10 * MS_NS));

    int64_t cpu0 = thread_cpu_ns(waiter);
    base_nanosleep_ns((uint64_t)CPU_HOLD_NS);
    int64_t cpu1 = thread_cpu_ns(waiter);

    EXPECT(!n00b_atomic_load(&g_cv_done), "condition wait returned without a notify");

    int64_t deadline = n00b_ns_timestamp() + 5000 * MS_NS;
    while (!n00b_atomic_load(&g_cv_done) && n00b_ns_timestamp() < deadline) {
        n00b_condition_notify(&g_cv, .all = true);
        base_nanosleep_ns((uint64_t)MS_NS);
    }
    if (!n00b_atomic_load(&g_cv_done)) {
        // The waiter is parked with no timeout, so shutdown would wait on it
        // forever.  Exit here to report the failure.
        printf("  [FAIL] %s:%d: condition waiter never woke from a notify\n",
               __FILE__, __LINE__);
        fflush(stdout);
        _Exit(1);
    }
    (void)n00b_thread_join(waiter);

    if (cpu0 < 0 || cpu1 < 0) {
        printf("  [SKIP] untimed condition wait CPU check (no thread CPU clock)\n");
        return;
    }
    int64_t used = cpu1 - cpu0;
    EXPECT(used < CPU_MAX_NS,
           "untimed condition waiter used %lld ns of CPU over a %lld ns hold",
           (long long)used, (long long)CPU_HOLD_NS);
    printf("  [%s] untimed condition wait sleeps (%lld us CPU over %lld ms)\n",
           STATUS(f0),
           (long long)(used / 1000), (long long)(CPU_HOLD_NS / MS_NS));
}

// ============================================================================
// 5. timed_wait_for_value gives up once its budget is spent
// ============================================================================

static n00b_futex_t g_churn;

// Moves the word between values the waiter is not waiting for, waking it
// each time, so the waiter's budget runs out between wakes.
static void *
churner_main(void *arg)
{
    (void)arg;
    barrier_arrive();
    uint32_t i = 0;
    while (!n00b_atomic_load(&g_stop)) {
        n00b_atomic_store(&g_churn, 2 + (i++ & 1));
        n00b_futex_wake(&g_churn, true);
        for (int spin = 0; spin < 2000; spin++) {
            __asm__ volatile("" ::: "memory");
        }
    }
    return nullptr;
}

static void
test_timed_wait_for_value_budget(void)
{
    int f0 = g_failures;

    n00b_futex_t word = 1;

    int64_t t0 = n00b_ns_timestamp();
    bool    ok = n00b_futex_timed_wait_for_value(&word, 0, 0);
    int64_t dt = elapsed_since(t0);
    EXPECT(!ok, "zero budget reported the value reached");
    EXPECT(dt < PROMPT_NS, "zero budget took %lld ns", (long long)dt);

    t0 = n00b_ns_timestamp();
    ok = n00b_futex_timed_wait_for_value(&word, 0, -5 * MS_NS);
    dt = elapsed_since(t0);
    EXPECT(!ok, "negative budget reported the value reached");
    EXPECT(dt < PROMPT_NS, "negative budget took %lld ns", (long long)dt);

    t0 = n00b_ns_timestamp();
    ok = n00b_futex_timed_wait_for_value(&word, 0, BUDGET_NS);
    dt = elapsed_since(t0);
    EXPECT(!ok, "quiet budget reported the value reached");
    EXPECT(dt >= BUDGET_NS - MS_NS, "quiet budget returned after %lld ns",
           (long long)dt);
    EXPECT(dt < BUDGET_NS + PROMPT_NS, "quiet budget took %lld ns", (long long)dt);

    EXPECT(n00b_futex_timed_wait_for_value(&word, 1, 0),
           "a word already at the value was not reported reached");

    barrier_reset();
    n00b_atomic_store(&g_churn, 2);
    auto tc = n00b_thread_spawn(churner_main, nullptr);
    n00b_require(n00b_result_is_ok(tc), "churner spawn failed");
    n00b_thread_t *churner = n00b_result_get(tc);

    barrier_release(1);
    t0 = n00b_ns_timestamp();
    ok = n00b_futex_timed_wait_for_value(&g_churn, 0, BUDGET_NS);
    dt = elapsed_since(t0);
    n00b_atomic_store(&g_stop, true);
    (void)n00b_thread_join(churner);

    EXPECT(!ok, "churned budget reported the value reached");
    EXPECT(dt < BUDGET_NS + PROMPT_NS, "churned budget took %lld ns", (long long)dt);

    printf("  [%s] timed_wait_for_value budget\n", STATUS(f0));
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_futex_timeout:\n");
    test_zero_timeout_polls();
    test_long_timeout();
    test_wait_forever_blocks();
    test_untimed_condition_wait_sleeps();
    test_timed_wait_for_value_budget();

    printf("test_futex_timeout: %s\n", g_failures ? "FAILED" : "ok");
    n00b_shutdown();
    return g_failures ? 1 : 0;
}
