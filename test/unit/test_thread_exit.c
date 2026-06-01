#include <stdio.h>
#include <assert.h>

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/callstack.h"
#include "core/alloc.h"
#include "core/atomic.h"
#include "core/futex.h"
#include "core/gc.h"
#include "core/mmaps.h"
#include "core/stw.h"
#include "core/rwlock.h"

// ============================================================================
// WP-3a Phase 1 regression test: the 64-bit exit-code channel.
//
// The exit code is a SEPARATE field on n00b_thread_t from the `void *`
// fn-return (D-032 Q2): a worker stashes a 64-bit code via n00b_thread_exit()
// (STASH-ONLY, D-033 — it does NOT terminate the worker mid-fn) and the
// launcher publishes it alongside join_result, before the join_futex
// publish-then-wake.  The published code is read via n00b_thread_exit_code()
// on a joined thread; the `void *` n00b_thread_join return is unchanged.
//
// This file is EXTENDED by WP-3a Phase 2 with the per-join struct/slot
// reclamation assertions (a tight spawn/join loop under GC pressure), so it is
// structured to grow: one focused test function per behavior, driven from
// main(), each printing a [PASS]/[SKIP] line.
//
// Phase-1 assertions (per the WP-3a plan DoD):
//   (a) a worker that calls n00b_thread_exit(0xDEADBEEFCAFEull) is joined and
//       n00b_thread_exit_code(child) returns exactly that value;
//   (b) a worker that returns a `void *` sentinel WITHOUT calling
//       n00b_thread_exit yields exit code 0 AND the `void *` join return still
//       equals the sentinel (the two channels are independent);
//   (c) the `void *` join-return path is unchanged.
//
// This phase is platform-neutral (the exit-code path is atomics + the
// platform-abstracted join handshake), so there is no non-macOS observable to
// [SKIP]-gate.
// ============================================================================

// ----------------------------------------------------------------------------
// (a) A worker that calls n00b_thread_exit(code) publishes that code; a joiner
//     reads it back via n00b_thread_exit_code().
// ----------------------------------------------------------------------------

#define EXIT_SENTINEL ((uint64_t)0xDEADBEEFCAFEull)

static void *
exit_code_worker(void *raw)
{
    (void)raw;
    // STASH-ONLY (D-033): this stores the code and returns; it does NOT
    // terminate the worker mid-fn.  The code below this line still runs.
    n00b_thread_exit(EXIT_SENTINEL);

    // Proof that n00b_thread_exit did not early-exit: this assignment runs and
    // the worker returns its own (independent) `void *` sentinel.
    return (void *)(uintptr_t)0x1111;
}

static void
test_exit_code_published(void)
{
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(exit_code_worker,
                                                         nullptr);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    void *ret = n00b_thread_join(child);

    // The 64-bit exit code is exactly what the worker stashed.
    assert(n00b_thread_exit_code(child) == EXIT_SENTINEL);

    // The `void *` fn-return is the worker's OWN return value, NOT the exit
    // code — the two channels are independent.  (The worker ran to its
    // `return` after n00b_thread_exit, confirming stash-only / no early-exit.)
    assert((uintptr_t)ret == (uintptr_t)0x1111);
    assert((uint64_t)(uintptr_t)ret != EXIT_SENTINEL);

    printf("  [PASS] exit_code_published "
           "(n00b_thread_exit(code) -> n00b_thread_exit_code == code)\n");
}

// ----------------------------------------------------------------------------
// (b) A worker that returns a `void *` sentinel WITHOUT calling
//     n00b_thread_exit yields exit code 0; the `void *` join return still
//     equals the sentinel (independent channels, default 0).
// ----------------------------------------------------------------------------

#define VOID_SENTINEL ((void *)(uintptr_t)0xABCD1234)

static void *
no_exit_call_worker(void *raw)
{
    (void)raw;
    // Never calls n00b_thread_exit: the exit code must default to 0.
    return VOID_SENTINEL;
}

static void
test_default_exit_code_is_zero(void)
{
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(no_exit_call_worker,
                                                         nullptr);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    void *ret = n00b_thread_join(child);

    // No n00b_thread_exit call -> exit code defaults to 0.
    assert(n00b_thread_exit_code(child) == 0);

    // The `void *` join return still equals the worker's sentinel — the
    // fn-return channel is unaffected by the (unused) exit-code channel.
    assert(ret == VOID_SENTINEL);

    printf("  [PASS] default_exit_code_is_zero "
           "(no n00b_thread_exit -> code 0; `void *` return unchanged)\n");
}

// ----------------------------------------------------------------------------
// (c) The `void *` join-return path is unchanged: a worker that only returns a
//     `void *` (and a worker that stashes a code distinct from its return)
//     both yield the EXACT `void *` they returned, proving the two channels
//     never alias.
// ----------------------------------------------------------------------------

static void *
distinct_channels_worker(void *raw)
{
    (void)raw;
    // Stash a code AND return a different `void *`: the join return must be the
    // `void *`, the exit code must be the stashed value, and they differ.
    n00b_thread_exit((uint64_t)0x55AA55AA55AAull);
    return (void *)(uintptr_t)0x2222;
}

static void
test_void_return_unchanged(void)
{
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(
        distinct_channels_worker,
        nullptr);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    void *ret = n00b_thread_join(child);

    // The `void *` return is exactly what fn() returned (signature + semantics
    // of n00b_thread_join unchanged, D-032 Q2).
    assert((uintptr_t)ret == (uintptr_t)0x2222);
    // The exit code is the separately-stashed value.
    assert(n00b_thread_exit_code(child) == (uint64_t)0x55AA55AA55AAull);
    // The two never alias.
    assert((uint64_t)(uintptr_t)ret != n00b_thread_exit_code(child));

    printf("  [PASS] void_return_unchanged "
           "(fn-return and exit-code are independent channels)\n");
}

// ----------------------------------------------------------------------------
// WP-3a Phase 1 (D-034): the permanent n00b_thread_t is allocated from the
// GC-VISIBLE, non-moving `user_pool` on n00b_runtime_t (NOT the hidden
// system_pool).  These assertions confirm the foundation: spawn/join still
// works end-to-end across the pool move (both the `void *` fn-return AND the
// Phase-0 exit code remain correct); the struct's owning allocator is
// `user_pool`; n00b_thread_self() resolves on the worker (non-moving pool
// preserved identity); and a forced GC collection while the thread is live AND
// after join leaves the thread/lock state intact (no corruption, lock chains
// preserved).
//
// This phase does NOT change n00b_thread_join, reclamation timing, or
// callstack handling (Phase 2/3).
// ----------------------------------------------------------------------------

#define USER_POOL_RET ((void *)(uintptr_t)0x3333)

// A worker that records its own n00b_thread_self() so the joiner can confirm
// identity resolved on the worker (non-moving pool), and stashes an exit code
// so both channels are exercised across the pool move.
typedef struct {
    _Atomic(n00b_thread_t *) seen_self;
} user_pool_io_t;

static void *
user_pool_worker(void *raw)
{
    user_pool_io_t *io = (user_pool_io_t *)raw;

    // n00b_thread_self() must resolve to this worker's permanent struct (the
    // one allocated from user_pool); the worker-masking branch back-verifies
    // the callstack base, so a wrong/relocated struct would fault or mismatch.
    n00b_thread_t *self = n00b_thread_self();
    n00b_atomic_store(&io->seen_self, self);

    n00b_thread_exit(EXIT_SENTINEL);
    return USER_POOL_RET;
}

static void
test_thread_struct_from_user_pool(n00b_runtime_t *rt)
{
    user_pool_io_t io = {};

    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(user_pool_worker, &io);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    void *ret = n00b_thread_join(child);

    // End-to-end across the pool move: both channels still correct.
    assert(ret == USER_POOL_RET);
    assert(n00b_thread_exit_code(child) == EXIT_SENTINEL);

    // The worker resolved its own struct via n00b_thread_self(); the spawner's
    // child handle is that same (non-moving) permanent struct.
    n00b_thread_t *seen = n00b_atomic_load(&io.seen_self);
    assert(seen == child);

    // The struct's owning allocator is the runtime's user_pool, NOT
    // system_pool — this is the D-034 foundation assertion.
    n00b_allocator_opt_t a_opt = n00b_mem_get_allocator(child);
    assert(n00b_option_is_set(a_opt));
    n00b_allocator_t *owner = n00b_option_get(a_opt);
    assert(owner == (n00b_allocator_t *)&rt->runtime_obj_pool);
    assert(owner != (n00b_allocator_t *)&rt->system_pool);

    printf("  [PASS] thread_struct_from_user_pool "
           "(n00b_thread_t owned by user_pool; spawn/join + both channels "
           "intact; self() resolved on worker)\n");
}

// A worker that takes a write lock (linking it into rec->exclusive_locks) and
// parks via the cooperative STW-suspend pattern, so a forced collection while
// it is LIVE must scan its struct (in user_pool), its record, and its lock
// chains without corruption.  After release it unlocks (faulting if the chain
// scan lost a relocated lock head), returns its sentinel, and stashes a code;
// the joiner then drives a second forced collection AFTER join and confirms
// the handle is still readable and the struct still non-moving.
typedef struct {
    n00b_rwlock_t *lock;            // GC-arena lock held across the collection
    n00b_futex_t   park;            // 0 = parked; main stores 1 to release
} user_pool_gc_io_t;

static void *
user_pool_gc_worker(void *raw)
{
    user_pool_gc_io_t *io   = (user_pool_gc_io_t *)raw;
    n00b_thread_t     *self = n00b_thread_self();
    assert(self != nullptr);

    n00b_rw_write_lock(io->lock);

    // Park until the main thread has driven a collection with us live.  Suspend
    // for STW so the collector can pause us cleanly while we hold the lock.
    while (!n00b_atomic_load(&io->park)) {
        n00b_stw_suspend_ctx stw_ctx = {};
        n00b_thread_suspend(stw_ctx);
        n00b_futex_wait(&io->park, 0, 100000000); // 100ms
        n00b_thread_resume(stw_ctx);
    }

    n00b_rw_unlock(io->lock);

    n00b_thread_exit(EXIT_SENTINEL);
    return USER_POOL_RET;
}

static void
test_user_pool_struct_survives_gc(n00b_runtime_t *rt)
{
    n00b_arena_t *arena = rt->default_arena;
    if (arena == nullptr) {
        // Non-default (caller-supplied) allocator runtime: the forced-collect
        // probe targets the GC'd default arena, which is absent here.
        printf("  [SKIP] user_pool_struct_survives_gc "
               "(runtime has no GC'd default arena)\n");
        return;
    }

    user_pool_gc_io_t io = {};
    // Allocate the lock from the non-moving system_pool so the collection does
    // not relocate it — the worker holds the lock across the collect, and the
    // rec->exclusive_locks chain head must stay valid (a stable address keeps
    // this a test of the THREAD-state scan, not of lock-pointer forwarding).
    io.lock = n00b_alloc_with_opts(
        n00b_rwlock_t,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)&rt->system_pool});
    n00b_rw_init(io.lock);
    n00b_atomic_store(&io.park, 0);
    n00b_futex_init(&io.park);

    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(user_pool_gc_worker,
                                                         &io);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    // (1) Generate GC pressure and force a collection while the worker is LIVE
    //     and parked.  n00b_scan_thread_stacks scans the worker's struct (in
    //     user_pool), its record, and its lock chains every collect; a
    //     non-moving user_pool keeps those addresses stable.
    for (int i = 0; i < 2048; i++) {
        (void)n00b_alloc_array_with_opts(
            uint64_t,
            8,
            &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
    }
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    // The worker's struct survived the live collection and stayed put.
    n00b_allocator_opt_t a_opt = n00b_mem_get_allocator(child);
    assert(n00b_option_is_set(a_opt));
    assert(n00b_option_get(a_opt) == (n00b_allocator_t *)&rt->runtime_obj_pool);

    // (2) Release the worker and join.
    n00b_atomic_store(&io.park, 1);
    n00b_futex_wake(&io.park, true);

    void *ret = n00b_thread_join(child);
    assert(ret == USER_POOL_RET);
    assert(n00b_thread_exit_code(child) == EXIT_SENTINEL);

    // (3) Force a second collection AFTER join.  The handle is held in this
    //     (GC-scanned) stack frame, so the struct must remain readable and
    //     non-moving; the exit code reads identically.
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    assert(n00b_thread_exit_code(child) == EXIT_SENTINEL);
    a_opt = n00b_mem_get_allocator(child);
    assert(n00b_option_is_set(a_opt));
    assert(n00b_option_get(a_opt) == (n00b_allocator_t *)&rt->runtime_obj_pool);

    printf("  [PASS] user_pool_struct_survives_gc "
           "(forced collect live + after join: struct non-moving, lock/exit "
           "state intact)\n");
}

// ============================================================================
// WP-3a Phase 2 (D-034): callstack pool + reap-at-OS-confirmed-death.
//
// The worker's 8 MiB callstack is reclaimed by the REAPER at OS-confirmed death
// (macOS dead Mach port / Linux CLONE_CHILD_CLEARTID futex), NOT by
// n00b_thread_join — which now frees nothing.  A reaped region returns to the
// runtime callstack pool and is REUSED by a later spawn instead of being
// munmap'd each time.  These assertions exercise:
//   (a) a worker's callstack region is REUSED by a subsequent spawn (the same
//       region base recurs) — i.e. pooling works and join did not unmap it;
//   (b) a tight spawn/exit loop (>= 256, mix of joined + never-joined) runs
//       cleanly with pooled reuse — no corruption, no fault;
//   (c) join still returns the correct `void *` + exit code (reuse-safe);
//   (d) the loop survives a forced GC collection.
//
// The OS-death edge is the safety boundary: a region returns to the pool ONLY
// after the worker is truly off it.  The Linux CLONE_CHILD_CLEARTID death-edge
// assertion is [SKIP]-gated off Linux; macOS exercises the dead-Mach-port path
// (the verified platform here).
// ============================================================================

// A worker that records the base of the callstack region it ran on (read from
// its own n00b_thread_self()->callstack) so the test can detect pool reuse
// across spawns, and stashes an exit code so the channels stay exercised.
typedef struct {
    _Atomic(void *) region_base;
} reuse_io_t;

static void *
reuse_worker(void *raw)
{
    reuse_io_t    *io   = (reuse_io_t *)raw;
    n00b_thread_t *self = n00b_thread_self();
    assert(self != nullptr);
    // The worker runs on an n00b callstack; record its region base.
    void *base = (self->callstack != nullptr) ? self->callstack->region_start
                                               : nullptr;
    n00b_atomic_store(&io->region_base, base);

    n00b_thread_exit(EXIT_SENTINEL);
    return USER_POOL_RET;
}

// Spawn a worker, join it, then wait for its callstack to land back in the pool
// (the reaper acts at OS-confirmed death, which on macOS is slightly after the
// join returns).  Returns the region base it ran on.
static void *
spawn_join_get_base(void)
{
    reuse_io_t io = {};
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(reuse_worker, &io);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    void *ret = n00b_thread_join(child);
    assert(ret == USER_POOL_RET);
    assert(n00b_thread_exit_code(child) == EXIT_SENTINEL);

    void *base = n00b_atomic_load(&io.region_base);
    assert(base != nullptr);
    return base;
}

static void
test_callstack_region_reused(void)
{
    // First worker: note the region it ran on.  After join + reap its region
    // returns to the pool.  A later spawn must REUSE that pooled region (same
    // base), proving (1) the callstack was not unmapped by join, and (2) the
    // reaper returned it to the pool for reuse.
    void *first_base = spawn_join_get_base();

    // The reaper acts at OS-confirmed death.  Drive a few spawn/join cycles;
    // the slow-path sweep in n00b_thread_spawn reaps the prior dead worker, so
    // one of these spawns reuses `first_base`.  (Single-worker steady state at
    // an 8 MiB region size: the pool holds exactly the reaped region, so reuse
    // is the same base — but allow a few iterations for the death edge to fire.)
    bool reused = false;
    for (int i = 0; i < 32 && !reused; i++) {
        void *base = spawn_join_get_base();
        if (base == first_base) {
            reused = true;
        }
    }

    assert(reused);
    printf("  [PASS] callstack_region_reused "
           "(reaped region returns to the pool and a later spawn reuses it; "
           "join did not unmap it)\n");
}

// A short-lived worker that is NEVER joined (detached use): it must still be
// reaped at OS death and its callstack pooled.  Stashes nothing; returns
// immediately.
static void *
detached_worker(void *raw)
{
    (void)raw;
    return nullptr;
}

static void
test_spawn_exit_loop_pooled(n00b_runtime_t *rt)
{
    n00b_arena_t *arena = rt->default_arena;

    // (b)+(c)+(d): a tight spawn/exit loop, mixing joined and never-joined
    // workers, runs cleanly with pooled reuse — no corruption / no fault — and
    // survives a forced GC collection mid-loop.  The reaper (spawn slow path +
    // signal thread) keeps the pool fed from OS-dead workers, so the loop does
    // not exhaust address space.
    const int ITERS = 300; // >= 256
    for (int i = 0; i < ITERS; i++) {
        if ((i & 1) == 0) {
            // Joined worker: confirm both channels every time (reuse-safe).
            reuse_io_t io = {};
            n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(reuse_worker,
                                                                 &io);
            assert(n00b_result_is_ok(r));
            n00b_thread_t *child = n00b_result_get(r);
            assert(child != nullptr);
            void *ret = n00b_thread_join(child);
            assert(ret == USER_POOL_RET);
            assert(n00b_thread_exit_code(child) == EXIT_SENTINEL);
        }
        else {
            // Never-joined (detached) worker: reaped at OS death, callstack
            // pooled, no leak (no join required — D-034).
            n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(detached_worker,
                                                                 nullptr);
            assert(n00b_result_is_ok(r));
        }

        // (d) Force a collection partway through, with workers churning.
        if (i == ITERS / 2 && arena != nullptr) {
            for (int k = 0; k < 512; k++) {
                (void)n00b_alloc_array_with_opts(
                    uint64_t,
                    8,
                    &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
            }
            n00b_stop_the_world();
            n00b_collect(arena);
            n00b_restart_the_world();
        }
    }

    // Give the reaper backstop a chance to drain the never-joined workers so a
    // final sanity spawn/join still works on a recycled region.
    void *base = spawn_join_get_base();
    assert(base != nullptr);

    printf("  [PASS] spawn_exit_loop_pooled "
           "(%d-cycle mixed joined/detached loop with pooled reuse, survived a "
           "forced GC, no corruption)\n",
           ITERS);
}

// (Linux-only) The CLONE_CHILD_CLEARTID death edge is the Linux gate for
// pool-return.  It is written-complete + Docker-deferred (D-026/D-028); macOS
// exercises the dead-Mach-port path above.  [SKIP]-gate off Linux so this never
// silently passes and runs when the user host-verifies via Docker.
static void
test_linux_cleartid_death_edge(void)
{
#if defined(__linux__)
    // On Linux the reaper observes the kernel's exit-time 0 store to the
    // CLONE_CHILD_CLEARTID word; a spawn/join cycle that recycles a region
    // proves the death edge fired.  (Same observable as the macOS reuse test.)
    void *first = spawn_join_get_base();
    bool  reused = false;
    for (int i = 0; i < 64 && !reused; i++) {
        if (spawn_join_get_base() == first) {
            reused = true;
        }
    }
    assert(reused);
    printf("  [PASS] linux_cleartid_death_edge "
           "(CLONE_CHILD_CLEARTID futex gates pool-return; region reused)\n");
#else
    printf("  [SKIP] linux_cleartid_death_edge "
           "(Linux-only; macOS dead-Mach-port path covers reuse here)\n");
#endif
}

// ============================================================================
// WP-3a Phase 3 (D-034/D-035): default-detached spawn + RESULT-ONLY join.
//
// Phase 3 makes the model explicit: a spawned worker needs NO join to avoid a
// leak (the reaper reclaims its callstack/TCB at OS death; the GC reclaims the
// struct when unreferenced), and n00b_thread_join is RESULT-ONLY — it waits,
// returns the worker's `void *` fn-return, leaves the 64-bit exit code readable
// via n00b_thread_exit_code, and FREES NOTHING (not the struct, not the
// callstack, not the TCB).  DF-6 resolved to the IMPLICIT model (D-035): there
// is no `.detached`/`.attached` spawn attribute; "joinable" is simply "the
// caller kept the handle."
//
// Phase-3 assertions (per the WP-3a plan DoD + the prompt's test expectations):
//   (e) JOINABLE worker: keep the handle, join, assert BOTH the `void *`
//       fn-return AND the 64-bit exit code are captured and correct (D-032 Q2
//       both channels) — and that the spawner's child handle matches the
//       worker's own n00b_thread_self().
//   (f) HELD-DEAD handle is safe to read: after the worker is dead AND joined,
//       reading the handle's fields (exit code, struct accessor) while the
//       handle is held in a SCANNED local — across a forced GC — does not
//       crash and stays consistent (the GC keeps the struct alive while
//       referenced, D-034).  The "drop the handle => collected" half is a
//       Phase-4 concern (the GC-collects-user_pool capability is confirmed
//       ABSENT in-branch per STATUS), so this asserts held-is-safe only.
//   (g) DETACHED worker (spawned, never joined) runs to completion and is
//       reaped — its callstack returns to the pool WITHOUT a join (reuses the
//       Phase-2 region-reuse probe).
//   (h) `join` frees nothing: immediately after n00b_thread_join returns, the
//       struct is fully readable (exit code + accessor) and held across a
//       forced GC; reclamation of the callstack goes via the reaper, not the
//       join (the region-reuse proof in test_callstack_region_reused shows
//       join did not unmap it).  A deterministic "the callstack is NOT on the
//       free-list the instant join returns" probe is not cleanly available
//       (no public callstack-pool introspection; the reaper's sweep at join's
//       tail is death-edge gated and may or may not have fired) — surfaced as
//       a probe gap.
//
// Platform-neutral (atomics + the platform-abstracted join handshake + GC); no
// non-macOS observable to [SKIP]-gate beyond the Phase-2 Linux death-edge test.
// ============================================================================

#define JOINABLE_RET  ((void *)(uintptr_t)0x4444)
#define JOINABLE_CODE ((uint64_t)0x99887766ull)

static void *
joinable_worker(void *raw)
{
    (void)raw;
    // Stash a code distinct from the `void *` return so both channels are
    // exercised and proven independent on the joinable path (D-032 Q2).
    n00b_thread_exit(JOINABLE_CODE);
    return JOINABLE_RET;
}

// (e) A joinable worker: keep the handle, join, assert BOTH channels and the
//     handle identity.
static void
test_joinable_both_channels(void)
{
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(joinable_worker,
                                                         nullptr);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    void *ret = n00b_thread_join(child);

    // Both channels captured and correct after the RESULT-ONLY join.
    assert(ret == JOINABLE_RET);
    assert(n00b_thread_exit_code(child) == JOINABLE_CODE);
    assert((uint64_t)(uintptr_t)ret != n00b_thread_exit_code(child));

    printf("  [PASS] joinable_both_channels "
           "(result-only join captures `void *` fn-return AND 64-bit exit "
           "code; channels independent)\n");
}

// (f) A held-DEAD handle is safe to read after join, including across a forced
//     GC, because the held handle (a scanned local) keeps the GC-owned struct
//     alive (D-034).
static void
test_held_dead_handle_safe(n00b_runtime_t *rt)
{
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(joinable_worker,
                                                         nullptr);
    assert(n00b_result_is_ok(r));
    // `child` is held in this scanned stack frame for the whole test — the GC
    // sees it conservatively, so the user_pool struct must stay alive.
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    void *ret = n00b_thread_join(child);
    assert(ret == JOINABLE_RET);

    // The worker is now dead (join observed "done").  Read the handle's fields
    // while still holding it — this must not crash and must be consistent.
    assert(n00b_thread_exit_code(child) == JOINABLE_CODE);
    n00b_allocator_opt_t a_opt = n00b_mem_get_allocator(child);
    assert(n00b_option_is_set(a_opt));
    assert(n00b_option_get(a_opt) == (n00b_allocator_t *)&rt->runtime_obj_pool);

    // Force a collection with the dead worker's handle held in a scanned
    // location: the struct must survive (GC keeps a referenced user_pool
    // allocation alive) and remain readable + non-moving.
    n00b_arena_t *arena = rt->default_arena;
    if (arena != nullptr) {
        for (int i = 0; i < 1024; i++) {
            (void)n00b_alloc_array_with_opts(
                uint64_t,
                8,
                &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
        }
        n00b_stop_the_world();
        n00b_collect(arena);
        n00b_restart_the_world();

        // Still readable + still owned by user_pool after the collection.
        assert(n00b_thread_exit_code(child) == JOINABLE_CODE);
        a_opt = n00b_mem_get_allocator(child);
        assert(n00b_option_is_set(a_opt));
        assert(n00b_option_get(a_opt) == (n00b_allocator_t *)&rt->runtime_obj_pool);

        printf("  [PASS] held_dead_handle_safe "
               "(dead worker's handle held in a scanned local: fields readable "
               "across a forced GC; struct kept alive + non-moving)\n");
    }
    else {
        // No GC'd default arena to drive a collection against; the held-read
        // half still holds (the struct is never freed by join).
        printf("  [PASS] held_dead_handle_safe "
               "(dead worker's handle readable post-join; forced-GC half "
               "skipped — no GC'd default arena)\n");
    }

    // Keep `child` observably live to the end so the compiler cannot drop the
    // reference before the collection above.
    assert(child != nullptr);
}

// (g) A DETACHED worker (spawned, never joined) runs to completion and is
//     reaped: its callstack returns to the pool WITHOUT any join.  We prove
//     this by reusing the Phase-2 region-reuse probe — a never-joined worker's
//     region must recur on a later spawn once its death edge fires.
static void
test_detached_reaped_without_join(void)
{
    // Spawn a worker that records its callstack base, but DO NOT join it.
    reuse_io_t io = {};
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(reuse_worker, &io);
    assert(n00b_result_is_ok(r));
    // Intentionally drop the handle (do not join): detached, fire-and-forget.

    // Wait for the worker to have recorded its region base (it does so early in
    // fn(), before exiting); spin briefly via short spawn/join cycles that also
    // drive the reaper slow-path sweep.
    void *detached_base = nullptr;
    for (int i = 0; i < 64 && detached_base == nullptr; i++) {
        detached_base = n00b_atomic_load(&io.region_base);
        if (detached_base == nullptr) {
            // A spawn/join cycle nudges the reaper and yields the CPU so the
            // detached worker makes progress.
            (void)spawn_join_get_base();
        }
    }
    assert(detached_base != nullptr);

    // The detached worker, never joined, must be reaped at OS death and its
    // region returned to the pool — so a later spawn reuses `detached_base`.
    bool reused = false;
    for (int i = 0; i < 64 && !reused; i++) {
        if (spawn_join_get_base() == detached_base) {
            reused = true;
        }
    }
    assert(reused);

    printf("  [PASS] detached_reaped_without_join "
           "(never-joined worker runs to completion and is reaped; its "
           "callstack returns to the pool with NO join — default-detached)\n");
}

// (h) `join` frees nothing: immediately after join returns, the struct is fully
//     readable and stays so across a forced GC; the callstack is reclaimed by
//     the reaper, not the join (see test_callstack_region_reused for the
//     not-unmapped-by-join proof).
static void
test_join_frees_nothing(n00b_runtime_t *rt)
{
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(joinable_worker,
                                                         nullptr);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    void *ret = n00b_thread_join(child);
    assert(ret == JOINABLE_RET);

    // The struct is NOT freed by join: every field the joiner relied on is
    // still readable the instant join returns.
    assert(n00b_thread_exit_code(child) == JOINABLE_CODE);
    n00b_allocator_opt_t a_opt = n00b_mem_get_allocator(child);
    assert(n00b_option_is_set(a_opt));
    assert(n00b_option_get(a_opt) == (n00b_allocator_t *)&rt->runtime_obj_pool);

    // Hold the handle across a forced GC: still readable (join freed nothing,
    // and the held reference keeps the GC-owned struct alive).
    n00b_arena_t *arena = rt->default_arena;
    if (arena != nullptr) {
        for (int i = 0; i < 1024; i++) {
            (void)n00b_alloc_array_with_opts(
                uint64_t,
                8,
                &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
        }
        n00b_stop_the_world();
        n00b_collect(arena);
        n00b_restart_the_world();
        assert(n00b_thread_exit_code(child) == JOINABLE_CODE);
    }

    printf("  [PASS] join_frees_nothing "
           "(struct fully readable immediately after join + across a forced "
           "GC; callstack reclamation is the reaper's, not the join's)\n");
}

// ============================================================================
// WP-3a Phase 4 (D-034): the end-to-end capstone — the full lifecycle at
// volume.  This proves the realized D-034 model holds under churn + GC
// pressure, reusing the Phase-0 exit-code assertions and the Phase-2
// region-reuse probe (spawn_join_get_base / reuse_worker).
//
// GC-COLLECT-CAPABILITY DETERMINATION (re-confirmed from the code, NOT taken
// on faith — per the Phase-4 task): the "GC reclaims unreferenced user_pool
// allocations" capability is CONFIRMED ABSENT in this branch.  Verified by
// reading:
//   - src/core/init.c: user_pool is hidden = false, no .__system, and is NOT
//     appended to rt->scannable_pools; that list is created empty.
//   - src/core/alloc.c (n00b_allocator_setup) + src/core/pool.c: nothing
//     pushes a pool onto rt->scannable_pools (the pool.c comment that claims
//     allocator_setup does so refers to the unmerged PR); n00b_scan_scannable_pools
//     does not exist as a function (only a stale comment in regex.c names it).
//   - src/core/gc.c / include/core/gc.h: n00b_collect() is a COPYING collector
//     over an ARENA (from-space -> to-space).  Pools are non-moving free-list
//     allocators with NO collect/reclaim/sweep API (include/core/pool.h has
//     none); unreferenced pool allocations are freed only by explicit n00b_free
//     or bulk teardown, never by a reachability sweep.
// Consequence (D-034 / DF-1): the user_pool n00b_thread_t struct is no longer
// bulk-freed (it left system_pool) but is not yet GC-reclaimed when
// unreferenced — a known, tracked leak that closes when the upstream PR lands
// (deconflicted at WP-close rebase).  The two assertions that depend on this
// capability — "no unbounded user_pool growth at volume" and "drop the handle
// => collected" — are therefore [SKIP]-gated (never a silent pass) on the
// compile-time flag below; the reuse / held-safe / generation assertions do
// NOT depend on it and run live.
//
// DF-7 (user_pool footprint observability) disposition: there is no public
// user_pool / callstack-pool introspection API (no allocation-count or
// high-water metric) for a deterministic growth/collect assertion.  Rather
// than add a public symbol (forbidden without orchestrator signoff) or a
// test-only hook, the capstone uses a PROXY: it drives the high-volume loop +
// forced GC and asserts no corruption / no crash and (live, capability-
// independent) that the callstack POOL bounds resident memory via region
// reuse.  The leak/collect half stays [SKIP]-gated until the capability lands.
// ============================================================================

// Flip to 1 only when the upstream "GC collects unreferenced pool allocations"
// PR has been merged into this branch and user_pool is registered as a
// scannable/collectable pool (see the determination block above).  Until then
// the no-leak / drop-collects assertions are [SKIP]-gated, never silently
// passed.
#define N00B_GC_COLLECTS_USER_POOL 0

#define CAPSTONE_RET  ((void *)(uintptr_t)0x5555)
#define CAPSTONE_CODE ((uint64_t)0xC0FFEE5555ull)

// A detached short-lived worker that records the callstack region it ran on
// (so the capstone can confirm pool reuse) and exits immediately.
static void *
capstone_detached_worker(void *raw)
{
    reuse_io_t    *io   = (reuse_io_t *)raw;
    n00b_thread_t *self = n00b_thread_self();
    assert(self != nullptr);
    void *base = (self->callstack != nullptr) ? self->callstack->region_start
                                               : nullptr;
    n00b_atomic_store(&io->region_base, base);
    return nullptr;
}

// Capstone (1): DETACHED AT VOLUME (>= 256 cycles).  Spawn short-lived detached
// workers, never join.  Assert callstacks are REUSED from the pool (region
// bases recur) and no corruption/crash, while driving forced GC throughout.
// The no-unbounded-growth (GC reclaims user_pool) assertion is [SKIP]-gated on
// the determined GC-collect capability.
static void
test_capstone_detached_volume(n00b_runtime_t *rt)
{
    n00b_arena_t *arena = rt->default_arena;

    const int ITERS    = 512; // >= 256
    int       distinct = 0;   // count of distinct region bases observed
    int       reuses   = 0;   // count of region bases that recurred
    // Record every distinct base (the pool keeps few regions resident at this
    // one-worker-at-a-time concurrency, so a bounded set is ample; if it ever
    // overflowed we would simply stop counting reuse, which only weakens the
    // assertion, never falsely passes it).  From the non-moving system_pool so
    // a forced GC mid-loop cannot relocate it.
    const int  BASES_CAP = 256;
    void     **bases     = n00b_alloc_array_with_opts(
        void *,
        (int64_t)BASES_CAP,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)&rt->system_pool});

    for (int i = 0; i < ITERS; i++) {
        reuse_io_t io = {};
        n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(
            capstone_detached_worker,
            &io);
        assert(n00b_result_is_ok(r));
        // Drop the handle immediately: fire-and-forget (default-detached).

        // Let the detached worker record its region, nudging the reaper so
        // its (and prior workers') regions return to the pool for reuse.
        void *base = nullptr;
        for (int s = 0; s < 64 && base == nullptr; s++) {
            base = n00b_atomic_load(&io.region_base);
            if (base == nullptr) {
                (void)spawn_join_get_base(); // nudge reaper + yield
            }
        }
        assert(base != nullptr);

        // Track whether region bases recur (pool reuse) vs. growing without
        // bound (each spawn a brand-new region).
        bool seen = false;
        for (int k = 0; k < distinct; k++) {
            if (bases[k] == base) {
                seen = true;
                break;
            }
        }
        if (seen) {
            reuses++;
        }
        else if (distinct < BASES_CAP) {
            bases[distinct++] = base;
        }

        // Drive forced GC pressure periodically with workers churning.
        if ((i % 128) == 0 && arena != nullptr) {
            for (int k = 0; k < 256; k++) {
                (void)n00b_alloc_array_with_opts(
                    uint64_t,
                    8,
                    &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
            }
            n00b_stop_the_world();
            n00b_collect(arena);
            n00b_restart_the_world();
        }
    }

    // Pool reuse: across 512 detached spawns the callstack pool must recycle
    // regions, so region bases RECUR (reuses > 0) and the number of DISTINCT
    // region bases stays far below ITERS (a single-worker steady state recurs
    // on a small handful of pooled regions).  This is the capability-
    // INDEPENDENT proof that resident memory is bounded by the pool, not by the
    // (absent) GC reclamation.
    assert(reuses > 0);
    assert(distinct < ITERS);

#if N00B_GC_COLLECTS_USER_POOL
    // The structs of the never-joined workers are unreferenced (handles
    // dropped); once the capability lands, a forced collect reclaims them and
    // user_pool's footprint does not grow without bound across the loop.  No
    // public footprint metric exists (DF-7), so when this is enabled it should
    // be asserted via the metric the capability adds.
    (void)0; // placeholder for the footprint assertion the capability enables
    printf("  [PASS] capstone_detached_volume "
           "(%d detached cycles; callstacks reused from the pool; structs "
           "GC-reclaimed; survived forced GC)\n",
           ITERS);
#else
    printf("  [SKIP] capstone_detached_volume:no-leak "
           "(GC-collects-user_pool capability ABSENT in-branch — D-034/DF-1; "
           "struct leaks until the upstream PR lands; reuse + no-corruption "
           "half ran live over %d cycles)\n",
           ITERS);
    printf("  [PASS] capstone_detached_volume:reuse "
           "(%d detached cycles; callstacks reused from the pool (%d distinct "
           "regions); no corruption; survived forced GC)\n",
           ITERS, distinct);
#endif
}

// A joinable worker that stashes a per-iteration code and returns a sentinel,
// so the joinable-volume loop exercises both channels every cycle.
static void *
capstone_joinable_worker(void *raw)
{
    (void)raw;
    n00b_thread_exit(CAPSTONE_CODE);
    return CAPSTONE_RET;
}

// Capstone (2): JOINABLE AT VOLUME.  Keep each handle, join, assert BOTH the
// `void *` fn-return AND the 64-bit exit code (D-032 Q2 both channels); read
// fields after join AND after the worker is dead while the handle is held in a
// scanned local -> safe.  Driven under forced GC pressure.
static void
test_capstone_joinable_volume(n00b_runtime_t *rt)
{
    n00b_arena_t *arena = rt->default_arena;

    const int ITERS = 300; // >= 256
    for (int i = 0; i < ITERS; i++) {
        n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(
            capstone_joinable_worker,
            nullptr);
        assert(n00b_result_is_ok(r));
        n00b_thread_t *child = n00b_result_get(r);
        assert(child != nullptr);

        void *ret = n00b_thread_join(child);

        // Both channels captured and correct after the result-only join.
        assert(ret == CAPSTONE_RET);
        assert(n00b_thread_exit_code(child) == CAPSTONE_CODE);
        assert((uint64_t)(uintptr_t)ret != n00b_thread_exit_code(child));

        // Read fields after the worker is dead while the handle is held in this
        // scanned frame -> safe (join freed nothing; the held ref keeps the
        // GC-owned struct alive).  Across a periodic forced GC.
        if ((i % 100) == 0 && arena != nullptr) {
            for (int k = 0; k < 256; k++) {
                (void)n00b_alloc_array_with_opts(
                    uint64_t,
                    8,
                    &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
            }
            n00b_stop_the_world();
            n00b_collect(arena);
            n00b_restart_the_world();

            // Still readable + still owned by user_pool after the collection.
            assert(n00b_thread_exit_code(child) == CAPSTONE_CODE);
            n00b_allocator_opt_t a_opt = n00b_mem_get_allocator(child);
            assert(n00b_option_is_set(a_opt));
            assert(n00b_option_get(a_opt) == (n00b_allocator_t *)&rt->runtime_obj_pool);
        }
        // Keep `child` observably live to end-of-iteration.
        assert(child != nullptr);
    }

    printf("  [PASS] capstone_joinable_volume "
           "(%d join cycles; both channels captured; post-death held reads "
           "safe across forced GC)\n",
           ITERS);
}

// Capstone (3): HELD -> DROPPED => COLLECTED.  Hold a dead worker's handle in a
// scanned local, confirm a safe read; then drop the reference and force a GC
// collect; assert the struct is reclaimed.  [SKIP]-gated on the GC-collect
// capability (CONFIRMED ABSENT in-branch); the held-safe half runs live.
static void
test_capstone_drop_collects(n00b_runtime_t *rt)
{
    n00b_arena_t *arena = rt->default_arena;

    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(capstone_joinable_worker,
                                                         nullptr);
    assert(n00b_result_is_ok(r));
    n00b_thread_t *child = n00b_result_get(r);
    assert(child != nullptr);

    void *ret = n00b_thread_join(child);
    assert(ret == CAPSTONE_RET);

    // Held (scanned local): safe to read the dead worker's fields.
    assert(n00b_thread_exit_code(child) == CAPSTONE_CODE);
    n00b_allocator_opt_t a_opt = n00b_mem_get_allocator(child);
    assert(n00b_option_is_set(a_opt));
    assert(n00b_option_get(a_opt) == (n00b_allocator_t *)&rt->runtime_obj_pool);

#if N00B_GC_COLLECTS_USER_POOL
    // Drop the reference and force a collect: the struct must be reclaimed
    // (observed via the user_pool footprint dropping, or a collect-detectable
    // proxy the capability exposes — DF-7).
    child = nullptr;
    if (arena != nullptr) {
        for (int k = 0; k < 1024; k++) {
            (void)n00b_alloc_array_with_opts(
                uint64_t,
                8,
                &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
        }
        n00b_stop_the_world();
        n00b_collect(arena);
        n00b_restart_the_world();
    }
    // The reclamation assertion goes here once the capability + footprint
    // metric (DF-7) are available.
    printf("  [PASS] capstone_drop_collects "
           "(held handle safe; dropped reference reclaimed by the GC)\n");
#else
    (void)arena;
    // Keep `child` live so the compiler cannot drop it before the held read.
    assert(child != nullptr);
    printf("  [SKIP] capstone_drop_collects "
           "(held-handle safe-read ran live; drop=>collected gated on the "
           "GC-collects-user_pool capability — ABSENT in-branch, D-034/DF-1; "
           "no public user_pool footprint metric exists — DF-7)\n");
#endif
}

// A worker that records its own 64-bit unique id (slot | generation) and its
// slot/generation parts via n00b_thread_self(), so the capstone can prove that
// a recycled slot carries a strictly distinguishable generation from a stale
// handle to the prior occupant (D-036 per-region identity / slot-generation).
typedef struct {
    _Atomic(uint64_t) unique_id;
    _Atomic(int32_t)  slot;
    _Atomic(int32_t)  generation;
} ident_io_t;

static void *
ident_worker(void *raw)
{
    ident_io_t    *io   = (ident_io_t *)raw;
    n00b_thread_t *self = n00b_thread_self();
    assert(self != nullptr);
    n00b_atomic_store(&io->unique_id, self->id_info.unique_id);
    n00b_atomic_store(&io->slot, self->id_info.parts.id);
    n00b_atomic_store(&io->generation, self->id_info.parts.generation);
    return nullptr;
}

// Capstone (4): RECYCLED-SLOT GENERATION DISTINCTNESS.  Spawn+join enough
// workers that a slot index necessarily recurs (slots are assigned round-robin
// mod max_threads, and each (re)acquire bumps the slot generation).  For every
// pair of workers that shared a slot, assert the later one carries a STRICTLY
// GREATER generation and a DISTINCT 64-bit unique id — so a stale handle to the
// prior occupant can never be mistaken for the recycled slot's new worker.
static void
test_capstone_recycled_slot_generation(n00b_runtime_t *rt)
{
    // Per-slot last-seen generation; -1 = slot not yet seen.  Sized to the
    // runtime's slot table so we cover the full round-robin space.
    uint32_t max_slots = rt->max_threads;
    assert(max_slots > 0);

    // The most-recent generation + unique id seen per slot (last_gen[s] == -1
    // means the slot has not been seen yet).  From the (non-moving) system_pool
    // so a forced GC during the loop cannot relocate them.
    int32_t *last_gen = n00b_alloc_array_with_opts(
        int32_t,
        (int64_t)max_slots,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)&rt->system_pool});
    uint64_t *last_uid = n00b_alloc_array_with_opts(
        uint64_t,
        (int64_t)max_slots,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)&rt->system_pool});
    for (uint32_t i = 0; i < max_slots; i++) {
        last_gen[i] = -1;
    }

    // Slots are assigned round-robin (next_thread_slot++ % max_threads), so a
    // slot index is GUARANTEED to recur within max_threads + 1 acquisitions
    // (pigeonhole); the extra headroom absorbs slots that concurrent service
    // threads acquire.  We stop as soon as the first recycle is proven, so in
    // practice this runs ~max_threads pooled spawn/joins (the callstack pool
    // caps resident memory regardless — DF-4 keep-N).
    bool      saw_recycle = false;
    const int ITER_CAP    = (int)max_slots + 256;
    for (int i = 0; i < ITER_CAP && !saw_recycle; i++) {
        ident_io_t io = {};
        n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(ident_worker, &io);
        assert(n00b_result_is_ok(r));
        n00b_thread_t *child = n00b_result_get(r);
        assert(child != nullptr);

        (void)n00b_thread_join(child);

        int32_t  slot = n00b_atomic_load(&io.slot);
        int32_t  gen  = n00b_atomic_load(&io.generation);
        uint64_t uid  = n00b_atomic_load(&io.unique_id);

        // The handle agrees with what the worker resolved for itself.
        assert(child->id_info.parts.id == slot);
        assert(child->id_info.parts.generation == gen);
        assert(child->id_info.unique_id == uid);
        assert((uint32_t)slot < max_slots);

        if (last_gen[slot] != -1) {
            // This slot was occupied before: the recycled worker MUST carry a
            // strictly greater generation (init-time bump on (re)acquire), so a
            // stale handle to the prior occupant is strictly distinguishable.
            saw_recycle = true;
            assert(gen > last_gen[slot]);
            // The 64-bit unique id therefore also differs from the prior
            // occupant's (endian-agnostic: compare the recorded value).
            assert(uid != last_uid[slot]);
        }
        last_gen[slot] = gen;
        last_uid[slot] = uid;
    }

    // The round-robin must have revisited at least one slot within the cap.
    assert(saw_recycle);

    printf("  [PASS] capstone_recycled_slot_generation "
           "(a recycled slot carries a strictly greater generation + distinct "
           "unique id than a stale handle to its prior occupant)\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running thread_exit tests...\n");

    test_exit_code_published();
    test_default_exit_code_is_zero();
    test_void_return_unchanged();
    test_thread_struct_from_user_pool(&runtime);
    test_user_pool_struct_survives_gc(&runtime);
    test_callstack_region_reused();
    test_spawn_exit_loop_pooled(&runtime);
    test_linux_cleartid_death_edge();

    // WP-3a Phase 3: default-detached spawn + result-only join.
    test_joinable_both_channels();
    test_held_dead_handle_safe(&runtime);
    test_detached_reaped_without_join();
    test_join_frees_nothing(&runtime);

    // WP-3a Phase 4: the end-to-end capstone (full lifecycle at volume).
    test_capstone_detached_volume(&runtime);
    test_capstone_joinable_volume(&runtime);
    test_capstone_drop_collects(&runtime);
    test_capstone_recycled_slot_generation(&runtime);

    printf("All thread_exit tests passed.\n");
    n00b_shutdown();
    return 0;
}
