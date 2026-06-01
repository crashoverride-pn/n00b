#include <stdio.h>
#include <assert.h>

// test_lock_chain reads the calling thread's lock chain via n00b_thread_self()
// ->record (internal introspection on the main thread), so the internal thread
// surface stays exposed; the contention workers below run on n00b_thread_spawn
// workers (NOT pthread_create + n00b_thread_init).
#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/rwlock.h"
#include "core/lock_common.h"
#include "core/atomic.h"

// ============================================================================
// 1. Basic read/write lock
// ============================================================================

static void
test_basic_rw(void)
{
    n00b_rwlock_t rw = {0};
    n00b_rw_init(&rw);

    // Write lock/unlock.
    n00b_rw_write_lock(&rw);
    n00b_rw_unlock(&rw);

    // Read lock/unlock.
    n00b_rw_read_lock(&rw);
    n00b_rw_unlock(&rw);

    printf("  [PASS] basic rw lock/unlock\n");
}

// ============================================================================
// 2. Write-lock nesting
// ============================================================================

static void
test_write_nesting(void)
{
    n00b_rwlock_t rw = {0};
    n00b_rw_init(&rw);

    n00b_rw_write_lock(&rw);
    n00b_rw_write_lock(&rw); // nested
    n00b_rw_unlock(&rw);     // still held (nesting=1)
    n00b_rw_unlock(&rw);     // fully released

    printf("  [PASS] write nesting\n");
}

// ============================================================================
// 3. Read-lock nesting
// ============================================================================

static void
test_read_nesting(void)
{
    n00b_rwlock_t rw = {0};
    n00b_rw_init(&rw);

    n00b_rw_read_lock(&rw);
    n00b_rw_read_lock(&rw);  // nested read
    n00b_rw_unlock(&rw);     // still reading (level=1)
    n00b_rw_unlock(&rw);     // fully released

    printf("  [PASS] read nesting\n");
}

// ============================================================================
// 4. Read inside write
// ============================================================================

static void
test_read_inside_write(void)
{
    n00b_rwlock_t rw = {0};
    n00b_rw_init(&rw);

    n00b_rw_write_lock(&rw);
    // Acquiring a read lock while holding the write lock should be
    // treated as a write-lock nesting (since we already own it).
    n00b_rw_read_lock(&rw);
    n00b_rw_unlock(&rw);
    n00b_rw_unlock(&rw);

    printf("  [PASS] read inside write\n");
}

// ============================================================================
// 5. Multiple concurrent readers
// ============================================================================

static n00b_rwlock_t reader_rw;
static _Atomic int   reader_active;
static _Atomic int   max_readers_seen;

static void *
reader_worker(void *arg)
{
    (void)arg;

    for (int i = 0; i < 1000; i++) {
        n00b_rw_read_lock(&reader_rw);

        int cur = n00b_atomic_add(&reader_active, 1) + 1;

        // Track max concurrent readers.
        int prev_max = n00b_atomic_load(&max_readers_seen);
        while (cur > prev_max) {
            if (n00b_cas(&max_readers_seen, &prev_max, cur)) {
                break;
            }
        }

        n00b_atomic_add(&reader_active, -1);
        n00b_rw_unlock(&reader_rw);
    }

    return nullptr;
}

static void
test_concurrent_readers(void)
{
    memset(&reader_rw, 0, sizeof(reader_rw));
    n00b_rw_init(&reader_rw);
    atomic_store(&reader_active, 0);
    atomic_store(&max_readers_seen, 0);

    n00b_thread_t *threads[4];
    for (int i = 0; i < 4; i++) {
        n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(reader_worker,
                                                             nullptr);
        assert(n00b_result_is_ok(r));
        threads[i] = n00b_result_get(r);
    }
    for (int i = 0; i < 4; i++) {
        n00b_thread_join(threads[i]);
    }

    printf("  [PASS] concurrent readers (max concurrent: %d)\n",
           atomic_load(&max_readers_seen));
}

// ============================================================================
// 6. Writer exclusion
// ============================================================================

static n00b_rwlock_t excl_rw;
static _Atomic int   excl_counter;

static void *
writer_worker(void *arg)
{
    (void)arg;

    for (int i = 0; i < 5000; i++) {
        n00b_rw_write_lock(&excl_rw);
        n00b_atomic_add(&excl_counter, 1);
        n00b_rw_unlock(&excl_rw);
    }

    return nullptr;
}

static void
test_writer_exclusion(void)
{
    memset(&excl_rw, 0, sizeof(excl_rw));
    n00b_rw_init(&excl_rw);
    atomic_store(&excl_counter, 0);

    n00b_result_t(n00b_thread_t *) r1 = n00b_thread_spawn(writer_worker, nullptr);
    n00b_result_t(n00b_thread_t *) r2 = n00b_thread_spawn(writer_worker, nullptr);
    assert(n00b_result_is_ok(r1));
    assert(n00b_result_is_ok(r2));
    n00b_thread_join(n00b_result_get(r1));
    n00b_thread_join(n00b_result_get(r2));

    assert(atomic_load(&excl_counter) == 10000);

    printf("  [PASS] writer exclusion (counter=%d)\n",
           atomic_load(&excl_counter));
}

// ============================================================================
// 7. Lock chain verification
// ============================================================================

static void
test_lock_chain(void)
{
    n00b_rwlock_t rw1 = {0};
    n00b_rwlock_t rw2 = {0};
    n00b_rw_init(&rw1);
    n00b_rw_init(&rw2);

    n00b_lock_set_debug_name(&rw1, "rw1");
    n00b_lock_set_debug_name(&rw2, "rw2");

    n00b_rw_write_lock(&rw1);
    n00b_rw_write_lock(&rw2);

    // Both should be in the thread's lock chain.
    n00b_thread_t        *self = n00b_thread_self();
    n00b_thread_record_t *rec  = self->record;
    n00b_lock_base_t     *head = n00b_atomic_load(&rec->exclusive_locks);

    assert(head != nullptr);
    // rw2 was acquired last, should be at head.
    assert(head == (n00b_lock_base_t *)&rw2);
    n00b_lock_base_t *next = n00b_atomic_load(&head->next_thread_lock);
    assert(next == (n00b_lock_base_t *)&rw1);

    n00b_rw_unlock(&rw2);
    n00b_rw_unlock(&rw1);

    // Chain should be empty now.
    head = n00b_atomic_load(&rec->exclusive_locks);
    assert(head == nullptr);

    printf("  [PASS] lock chain verification\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_rwlock:\n");
    test_basic_rw();
    test_write_nesting();
    test_read_nesting();
    test_read_inside_write();
    test_concurrent_readers();
    test_writer_exclusion();
    test_lock_chain();

    printf("All rwlock tests passed.\n");
    n00b_shutdown();
    return 0;
}
