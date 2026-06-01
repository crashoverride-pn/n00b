#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/mutex.h"
#include "core/atomic.h"

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

    printf("All mutex tests passed.\n");
    n00b_shutdown();
    return 0;
}
