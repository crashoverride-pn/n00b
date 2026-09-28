#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/mutex.h"
#include "core/atomic.h"
#include "core/time.h"

// ============================================================================
// 1. Basic lock/unlock
// ============================================================================

static void
test_basic_lock_unlock(void)
{
    n00b_mutex_t mtx = {0};
    n00b_mutex_init(&mtx);

    n00b_mutex_lock(&mtx);
    n00b_mutex_unlock(&mtx);

    printf("  [PASS] basic lock/unlock\n");
}

// ============================================================================
// 2. Recursive (nested) locking
// ============================================================================

static void
test_recursive_locking(void)
{
    n00b_mutex_t mtx = {0};
    n00b_mutex_init(&mtx);

    n00b_mutex_lock(&mtx);
    n00b_mutex_lock(&mtx);   // Should succeed (recursive).
    n00b_mutex_unlock(&mtx); // Still locked (nesting=1).
    n00b_mutex_unlock(&mtx); // Fully unlocked.

    // Lock again to verify it's truly free.
    n00b_mutex_lock(&mtx);
    n00b_mutex_unlock(&mtx);

    printf("  [PASS] recursive locking\n");
}

// ============================================================================
// 3. Contention between two threads
// ============================================================================

static n00b_mutex_t contention_mtx;
static _Atomic int  contention_counter;

static void *
contention_worker(void *arg)
{
    (void)arg;

    for (int i = 0; i < 10000; i++) {
        n00b_mutex_lock(&contention_mtx);
        n00b_atomic_add(&contention_counter, 1);
        n00b_mutex_unlock(&contention_mtx);
    }

    return nullptr;
}

static void
test_contention(void)
{
    memset(&contention_mtx, 0, sizeof(contention_mtx));
    n00b_mutex_init(&contention_mtx);
    atomic_store(&contention_counter, 0);

    // Two n00b-spawned workers contend on the mutex (n00b_thread_spawn, NOT
    // pthread_create: the worker runs on an n00b callstack with a proper TCB,
    // so n00b_thread_self()/the lock machinery resolve — the launcher does the
    // thread init/teardown the worker used to call directly).
    n00b_result_t(n00b_thread_t *) r1 = n00b_thread_spawn(contention_worker,
                                                          nullptr);
    n00b_result_t(n00b_thread_t *) r2 = n00b_thread_spawn(contention_worker,
                                                          nullptr);
    assert(n00b_result_is_ok(r1));
    assert(n00b_result_is_ok(r2));
    n00b_thread_join(n00b_result_get(r1));
    n00b_thread_join(n00b_result_get(r2));

    assert(atomic_load(&contention_counter) == 20000);

    printf("  [PASS] contention (2 threads, counter=%d)\n",
           atomic_load(&contention_counter));
}

// ============================================================================
// 4. try_lock timeouts
// ============================================================================

static n00b_mutex_t try_mtx;

typedef struct {
    int     usec;
    bool    acquired;
    int64_t elapsed_ns;
} try_arg_t;

static void *
try_worker(void *arg)
{
    try_arg_t *t     = arg;
    int64_t    start = n00b_ns_timestamp();

    t->acquired   = n00b_mutex_try_lock(&try_mtx, t->usec);
    t->elapsed_ns = n00b_ns_timestamp() - start;
    if (t->acquired) {
        n00b_mutex_unlock(&try_mtx);
    }
    return nullptr;
}

static void
test_try_lock(void)
{
    memset(&try_mtx, 0, sizeof(try_mtx));
    n00b_mutex_init(&try_mtx);

    assert(n00b_mutex_try_lock(&try_mtx, 1000));
    n00b_mutex_unlock(&try_mtx);

    // Held by main for the whole window: the worker must give up.
    try_arg_t timeout = {.usec = 50000};
    n00b_mutex_lock(&try_mtx);
    auto r = n00b_thread_spawn(try_worker, &timeout);
    assert(n00b_result_is_ok(r));
    n00b_thread_join(n00b_result_get(r));
    n00b_mutex_unlock(&try_mtx);
    assert(!timeout.acquired);
    assert(timeout.elapsed_ns >= 45 * N00B_NS_PER_MS);
    assert(timeout.elapsed_ns < 5 * (int64_t)N00B_NSEC_PER_SEC);

    // Released once the worker is queued as a waiter: it must get the lock.
    try_arg_t late = {.usec = 5 * N00B_USEC_PER_SEC};
    n00b_mutex_lock(&try_mtx);
    r = n00b_thread_spawn(try_worker, &late);
    assert(n00b_result_is_ok(r));
    while (atomic_load(&try_mtx.should_wake) == 0) {
    }
    n00b_mutex_unlock(&try_mtx);
    n00b_thread_join(n00b_result_get(r));
    assert(late.acquired);
    assert(late.elapsed_ns < 5 * (int64_t)N00B_NSEC_PER_SEC);

    n00b_mutex_lock(&try_mtx);
    n00b_mutex_unlock(&try_mtx);

    printf("  [PASS] try_lock (timeout %lld ms, late release %lld ms)\n",
           (long long)(timeout.elapsed_ns / N00B_NS_PER_MS),
           (long long)(late.elapsed_ns / N00B_NS_PER_MS));
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_mutex:\n");
    test_basic_lock_unlock();
    test_recursive_locking();
    test_contention();
    test_try_lock();

    printf("All mutex tests passed.\n");
    n00b_shutdown();
    return 0;
}
