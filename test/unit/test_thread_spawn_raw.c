#include <stdio.h>
#include <assert.h>
#include <errno.h>

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/callstack.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "util/dynamic_lib.h"

// ============================================================================
// WP-001 Phase 3 regression test: raw worker thread creation + native join.
//
// Spawns several workers via n00b_thread_spawn (now backed by the per-OS
// raw primitive — macOS Mach thread_create + thread_set_state — on an
// n00b callstack, NOT pthread_create), and asserts, per the Phase-3 DoD /
// regression contract:
//   - each worker's n00b_thread_self() returns its own distinct
//     n00b_thread_t * with the correct slot id, recovered from the ID
//     word it wrote into its own callstack (the masking branch);
//   - the main thread's self() stays correct while workers run;
//   - the de-TLS'd dl_last_error / regex_nulls_last are per-thread (a
//     worker writing one does not perturb the main thread's value);
//   - the native (futex) join returns and the joiner observes the
//     worker's observable work (a shared atomic counter + per-thread
//     result word).
// ============================================================================

#define N_WORKERS 6

static _Atomic uint64_t shared_counter = 0;

typedef struct {
    int32_t       expected_slot_seen; // filled by the worker: its own slot id
    uint64_t      self_unique_id;     // filled by the worker
    void         *self_ptr;           // the worker's own n00b_thread_t *
    n00b_thread_t *main_thread;       // captured by the spawner, for non-perturb check
    uint32_t      nulls_marker;       // worker writes this into self()->regex_nulls_last
} worker_io_t;

static void *
worker_fn(void *raw)
{
    worker_io_t *io = (worker_io_t *)raw;

    n00b_thread_t *self = n00b_thread_self();
    assert(self != nullptr);

    // The worker must NOT resolve to the main thread.
    assert(self != io->main_thread);

    io->self_ptr            = self;
    io->expected_slot_seen  = self->id_info.parts.id;
    io->self_unique_id      = self->id_info.unique_id;

    // The recovered slot must point back at this exact struct.
    n00b_runtime_t *rt = n00b_get_runtime();
    assert(n00b_atomic_load(&rt->threads[self->id_info.parts.id].thread)
           == self);

    // The worker's stored callstack ID word holds its own slot id, and the
    // masked region base matches the recorded callstack region.
    void     *base    = nullptr;
    uint64_t *id_word = n00b_callstack_id_word(&self, &base);
    assert((int32_t)*id_word == self->id_info.parts.id);
    assert(self->callstack != nullptr);
    assert(self->callstack->region_start == base);

    // Per-thread folded former-thread_local: write our marker into the
    // worker's own regex_nulls_last; the main thread must not see it.
    self->regex_nulls_last = io->nulls_marker;
    assert(n00b_thread_self()->regex_nulls_last == io->nulls_marker);

    // Observable work the joiner will see.
    n00b_atomic_add(&shared_counter, 1);

    // Return a per-worker result word the joiner reads back.
    return (void *)(uintptr_t)(0x1000 + (uint64_t)self->id_info.parts.id);
}

static void
test_spawn_join_many(void)
{
    n00b_thread_t *main_self = n00b_thread_self();
    assert(main_self != nullptr);

    // Seed the main thread's per-thread nulls slot with a sentinel so we
    // can prove no worker perturbs it.
    main_self->regex_nulls_last = 0xAB;

    worker_io_t    ios[N_WORKERS]     = {};
    n00b_thread_t *children[N_WORKERS] = {};

    for (int i = 0; i < N_WORKERS; i++) {
        ios[i].main_thread  = main_self;
        ios[i].nulls_marker = 0x100u + (uint32_t)i;

        n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(worker_fn, &ios[i]);
        assert(n00b_result_is_ok(r));
        children[i] = n00b_result_get(r);
        assert(children[i] != nullptr);
        // The spawner sees the worker resolve to a distinct struct.
        assert(children[i] != main_self);
    }

    // Distinct n00b_thread_t * per worker.
    for (int i = 0; i < N_WORKERS; i++) {
        for (int j = i + 1; j < N_WORKERS; j++) {
            assert(children[i] != children[j]);
        }
    }

    // Join each worker via the native (non-pthread) join and check its
    // result word.
    for (int i = 0; i < N_WORKERS; i++) {
        void    *ret  = n00b_thread_join(children[i]);
        int32_t  slot = ios[i].expected_slot_seen;
        assert(ios[i].self_ptr == children[i]);
        assert((uintptr_t)ret == (uintptr_t)(0x1000 + (uint64_t)slot));
    }

    // The joiner observes every worker's observable work.
    assert(n00b_atomic_load(&shared_counter) == (uint64_t)N_WORKERS);

    // The main thread's self() is still correct and its per-thread nulls
    // slot was NOT perturbed by any worker.
    assert(n00b_thread_self() == main_self);
    assert(main_self->regex_nulls_last == 0xAB);

    printf("  [PASS] spawn_join_many\n");
}

// ----------------------------------------------------------------------------
// Worker identity is stable across call depth on the raw stack (the
// masking branch resolves every worker SP to the same struct).
// ----------------------------------------------------------------------------

[[gnu::noinline]] static n00b_thread_t *
deep_worker_self(int depth)
{
    if (depth > 0) {
        return deep_worker_self(depth - 1);
    }
    return n00b_thread_self();
}

static void *
depth_worker_fn(void *raw)
{
    n00b_thread_t *top = n00b_thread_self();
    (void)raw;
    for (int d = 0; d < 10; d++) {
        assert(deep_worker_self(d) == top);
    }
    return top;
}

static void
test_worker_identity_stable_across_depth(void)
{
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(depth_worker_fn, nullptr);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    void          *ret   = n00b_thread_join(child);
    assert(ret == child);

    printf("  [PASS] worker_identity_stable_across_depth\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running thread_spawn_raw tests...\n");

    test_spawn_join_many();
    test_worker_identity_stable_across_depth();

    printf("All thread_spawn_raw tests passed.\n");
    n00b_shutdown();
    return 0;
}
