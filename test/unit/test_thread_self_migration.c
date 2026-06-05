#define N00B_USE_INTERNAL_API

#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/stw.h"
#include "core/thread.h"
#include "core/mutex.h"
#include "core/rwlock.h"
#include "core/lock_common.h"
#include "core/atomic.h"

// ============================================================================
// WP-001 Phase 4 regression test: self()-accessor migration through the
// runtime-owned struct + stw.c null-guards, exercised on raw workers.
//
// Phase 4 switched self()'s worker branch to O(1) masking and routed the
// stw.c suspend/resume/checkin/wait paths through the (now-nullable) self().
// This test drives the migrated surface on several raw-spawned workers:
//
//   - each worker takes + releases a per-thread mutex and a per-thread
//     rwlock (write lock).  Acquiring a mutex/rwlock runs the
//     mutex.c / rwlock.c self() lock-accounting AND the stw.h
//     suspend/resume macros (which call self() and capture the stack).
//     We assert lock-ownership accounting is correct PER THREAD via
//     self()->record: the held lock is linked into THIS worker's
//     record->exclusive_locks chain and lock->data.owner is THIS
//     worker's slot id — proving self() resolves to the right
//     runtime-owned struct on each worker, not a shared/stale one.
//   - a stop-the-world / restart-the-world cycle is driven while the
//     workers spin in checkin loops, and we assert every worker observes
//     the STW bit and then fully resumes (no residual STW/BLOCKING/SUSPEND).
// ============================================================================

#define N_WORKERS 6

enum {
    STAGE_INIT = 0,
    STAGE_READY,
    STAGE_RELEASE,
};

typedef struct {
    n00b_mutex_t        mutex;
    n00b_rwlock_t       rwlock;
    int32_t             slot_seen;        // worker's own slot id
    bool                mutex_owner_ok;   // mutex.data.owner == slot while held
    bool                mutex_linked_ok;  // mutex on self()->record->exclusive_locks while held
    bool                rwlock_owner_ok;  // rwlock.data.owner == slot while held
    bool                released_clean;   // exclusive_locks empty after both released
    _Atomic uint32_t    stage;            // STW handshake
    _Atomic uint32_t    resume_bits;      // self_lock bits after STW resume
    n00b_thread_t      *main_thread;      // for the non-perturb check
} worker_io_t;

// Does `lock` appear anywhere on the thread record's exclusive-lock chain?
static bool
chain_contains(n00b_thread_record_t *rec, n00b_lock_base_t *lock)
{
    n00b_lock_base_t *cur = n00b_atomic_load(&rec->exclusive_locks);
    while (cur != nullptr) {
        if (cur == lock) {
            return true;
        }
        cur = n00b_atomic_load(&cur->next_thread_lock);
    }
    return false;
}

// ----------------------------------------------------------------------------
// Worker 1: lock-accounting via self()->record.
// ----------------------------------------------------------------------------
static void *
lock_worker_fn(void *raw)
{
    worker_io_t *io = (worker_io_t *)raw;

    n00b_thread_t *self = n00b_thread_self();
    assert(self != nullptr);
    assert(self != io->main_thread);

    io->slot_seen                = self->id_info.parts.id;
    n00b_thread_record_t *rec    = self->record;
    n00b_lock_base_t     *mbase  = (n00b_lock_base_t *)&io->mutex;
    n00b_lock_base_t     *rwbase = (n00b_lock_base_t *)&io->rwlock;

    // --- mutex: take, inspect accounting via self()->record, release ---
    n00b_mutex_lock(&io->mutex);
    {
        // WP-001: the lock owner is keyed on the OS thread id, not the runtime
        // slot id.
        n00b_core_lock_info_t info = n00b_atomic_load(&mbase->data);
        io->mutex_owner_ok         = (info.owner == n00b_os_thread_id());
        io->mutex_linked_ok        = chain_contains(rec, mbase);
    }

    // --- rwlock (write): take while still holding the mutex ---
    n00b_rw_write_lock(&io->rwlock);
    {
        n00b_core_lock_info_t info = n00b_atomic_load(&rwbase->data);
        io->rwlock_owner_ok        = (info.owner == n00b_os_thread_id());
    }

    n00b_rw_unlock(&io->rwlock);
    n00b_mutex_unlock(&io->mutex);

    // After releasing both, this worker's exclusive-lock chain is empty and
    // neither lock reports an owner.
    n00b_core_lock_info_t mi = n00b_atomic_load(&mbase->data);
    n00b_core_lock_info_t ri = n00b_atomic_load(&rwbase->data);
    io->released_clean       = (n00b_atomic_load(&rec->exclusive_locks) == nullptr)
                         && mi.owner == N00B_NO_OWNER
                         && ri.owner == N00B_NO_OWNER;

    return self;
}

static void
test_per_thread_lock_accounting(void)
{
    n00b_thread_t *main_self = n00b_thread_self();
    assert(main_self != nullptr);

    worker_io_t    ios[N_WORKERS]      = {};
    n00b_thread_t *children[N_WORKERS] = {};

    for (int i = 0; i < N_WORKERS; i++) {
        n00b_mutex_init(&ios[i].mutex);
        n00b_rw_init(&ios[i].rwlock);
        ios[i].main_thread = main_self;

        auto r = n00b_thread_spawn(lock_worker_fn, &ios[i]);
        assert(n00b_result_is_ok(r));
        children[i] = n00b_result_get(r);
        assert(children[i] != nullptr);
        assert(children[i] != main_self);
    }

    for (int i = 0; i < N_WORKERS; i++) {
        void *ret = n00b_thread_join(children[i]);
        assert(ret == children[i]);

        // Each worker resolved self() to its own distinct struct and its
        // lock accounting was correct against THAT struct's record.
        assert(ios[i].slot_seen == children[i]->id_info.parts.id);
        assert(ios[i].mutex_owner_ok);
        assert(ios[i].mutex_linked_ok);
        assert(ios[i].rwlock_owner_ok);
        assert(ios[i].released_clean);
    }

    // Distinct slots per worker.
    for (int i = 0; i < N_WORKERS; i++) {
        for (int j = i + 1; j < N_WORKERS; j++) {
            assert(ios[i].slot_seen != ios[j].slot_seen);
        }
    }

    printf("  [PASS] per-thread lock accounting via self()->record\n");
}

// ----------------------------------------------------------------------------
// Worker 2: spin in a checkin loop so the STW initiator can stop + resume it.
// ----------------------------------------------------------------------------
static void *
stw_worker_fn(void *raw)
{
    worker_io_t *io = (worker_io_t *)raw;

    atomic_store(&io->stage, STAGE_READY);

    // Pure-preemptive STW (WP-001): a tight RUNNING spin with NO checkin.  The
    // STW initiator preempts this thread; there is no cooperative park.
    while (atomic_load(&io->stage) == STAGE_READY) {
    }

    atomic_store(&io->resume_bits,
                 n00b_atomic_load(&n00b_thread_self()->self_lock));

    return n00b_thread_self();
}

static void
test_stw_cycle_resumes_all_workers(void)
{
    worker_io_t    ios[N_WORKERS]      = {};
    n00b_thread_t *children[N_WORKERS] = {};

    for (int i = 0; i < N_WORKERS; i++) {
        atomic_store(&ios[i].stage, STAGE_INIT);
        atomic_store(&ios[i].resume_bits, UINT32_MAX);

        auto r = n00b_thread_spawn(stw_worker_fn, &ios[i]);
        assert(n00b_result_is_ok(r));
        children[i] = n00b_result_get(r);
        assert(children[i] != nullptr);
    }

    // Wait until every worker is spinning in its checkin loop.
    for (int i = 0; i < N_WORKERS; i++) {
        while (atomic_load(&ios[i].stage) != STAGE_READY) {
        }
    }

    n00b_stop_the_world();

    // Pure-preemptive STW (WP-001 Phase 3): the workers spin in a checkin loop
    // that no longer parks, so the initiator suspends each one and captures its
    // registers.  Each worker is therefore preemptively stopped — this is the
    // assertion that used to be `& N00B_BLOCKING` and failed under parallel load
    // (workers were RUNNING when STW checked them, so they were preempted, never
    // cooperatively parked).
    for (int i = 0; i < N_WORKERS; i++) {
        assert(n00b_atomic_load(&children[i]->gc_preempt_suspended));
    }

    // Release the loops and restart the world.
    for (int i = 0; i < N_WORKERS; i++) {
        atomic_store(&ios[i].stage, STAGE_RELEASE);
    }
    n00b_restart_the_world();

    // Every worker resumes cleanly (no residual STW/BLOCKING/SUSPEND bits).
    for (int i = 0; i < N_WORKERS; i++) {
        void *ret = n00b_thread_join(children[i]);
        assert(ret == children[i]);
        // self_lock carries no STW/BLOCKING/SUSPEND state under pure-preemptive
        // STW (those cooperative bits are gone); the worker resuming cleanly and
        // returning its own handle is the resume proof.
        uint32_t bits = atomic_load(&ios[i].resume_bits);
        assert(bits == 0);
    }

    printf("  [PASS] STW/restart cycle resumes all raw workers\n");
}

// ----------------------------------------------------------------------------
// WP-001 Phase 1: a NON-main thread can preemptively stop + resume the MAIN
// thread.  Pre-Phase-1 the main thread had os_thread_port == 0, so
// _n00b_preempt_suspend_capture(main) returned false and a worker-initiated STW
// fell back to the cooperative path — which spins forever when main is RUNNING
// and never checking in.  Now main carries a real control handle, so the worker
// preemptively suspends it (gc_preempt_suspended set) and resumes it cleanly.
// ----------------------------------------------------------------------------
typedef struct {
    n00b_thread_t   *main_thread;
    _Atomic uint32_t main_ready;   // main has entered its no-checkin spin
    _Atomic uint32_t release;      // worker tells main to leave the spin
    bool             saw_main_preempted; // main->gc_preempt_suspended seen under STW
} stop_main_io_t;

static void *
stop_main_worker_fn(void *raw)
{
    stop_main_io_t *io = (stop_main_io_t *)raw;

    // Wait until main is RUNNING in its tight no-checkin loop.
    while (atomic_load(&io->main_ready) == 0) {
    }

    // Stop the world from a NON-main thread.  This must PREEMPTIVELY suspend
    // main (it is running and never checks in); pre-Phase-1 it would hang here.
    n00b_stop_the_world();

    // With the world stopped, main must be preemptively suspended with its
    // registers captured.
    io->saw_main_preempted = n00b_atomic_load(&io->main_thread->gc_preempt_suspended);

    // Let main leave its spin once resumed (it cannot observe this while
    // suspended).
    atomic_store(&io->release, 1);

    n00b_restart_the_world();
    return n00b_thread_self();
}

static void
test_worker_stops_main(void)
{
    stop_main_io_t io = {};
    io.main_thread    = n00b_thread_self();
    assert(io.main_thread != nullptr);

    auto r = n00b_thread_spawn(stop_main_worker_fn, &io);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *worker = n00b_result_get(r);
    assert(worker != nullptr);

    // Enter a tight RUNNING loop with NO checkin, so the only way the worker's
    // STW can stop us is the preemptive suspend+capture added in Phase 1.
    atomic_store(&io.main_ready, 1);
    while (atomic_load(&io.release) == 0) {
        // Deliberately no n00b_thread_checkin() here.
    }

    void *ret = n00b_thread_join(worker);
    assert(ret == worker);

    // The worker observed main preemptively suspended under STW, and main's
    // flag is cleared again now that the world restarted.
    assert(io.saw_main_preempted);
    assert(!n00b_atomic_load(&io.main_thread->gc_preempt_suspended));

    printf("  [PASS] a worker preemptively stops + resumes the main thread\n");
}

// ----------------------------------------------------------------------------
// WP-001 Phase 2: spawn churn overlapping STW cycles, exercising the launch
// window — a freshly-published worker must be suspendable (control handle) and
// scannable (stack map + top) BEFORE its first allocation.  The init reorder
// sets all of that on the worker before it is published into rt->threads[].
// (Pre-cut the cooperative path still backstops the window; this guards the
// reorder against regressions and seeds the post-cut load test.)
// ----------------------------------------------------------------------------
static void *
churn_worker_fn(void *raw)
{
    (void)raw;
    // A little work so init/early-run overlaps the STW cycles.  No checkin
    // (WP-001): a worker is preempted by the STW initiator, not cooperatively
    // parked.
    volatile uint64_t acc = 0;
    for (int i = 0; i < 64; i++) {
        acc += (uint64_t)i;
    }
    (void)acc;
    return n00b_thread_self();
}

static void
test_spawn_churn_under_stw(void)
{
    enum { ROUNDS = 20, KIDS = 8 };

    for (int round = 0; round < ROUNDS; round++) {
        n00b_thread_t *kids[KIDS] = {};

        for (int i = 0; i < KIDS; i++) {
            auto r = n00b_thread_spawn(churn_worker_fn, nullptr);
            assert(n00b_result_is_ok(r));
            kids[i] = n00b_result_get(r);
            assert(kids[i] != nullptr);
        }

        // Hammer a STW cycle while the just-spawned workers are still
        // initialising / early-running — this is the launch window.
        n00b_stop_the_world();
        n00b_restart_the_world();

        for (int i = 0; i < KIDS; i++) {
            assert(n00b_thread_join(kids[i]) == kids[i]);
        }
    }

    printf("  [PASS] spawn churn under STW cycles (launch window)\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running thread_self_migration tests...\n");

    test_per_thread_lock_accounting();
    test_stw_cycle_resumes_all_workers();
    test_worker_stops_main();
    test_spawn_churn_under_stw();

    printf("All thread_self_migration tests passed.\n");
    n00b_shutdown();
    return 0;
}
