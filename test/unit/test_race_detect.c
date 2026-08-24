/*
 * The race detector, tested against itself.
 *
 * The detector's whole value is the two answers it gives: a report where the
 * accesses really are unsynchronized, and silence where an ordering exists
 * that the lockset half cannot see. Both are worth a test, and the second one
 * more, because a detector that reports everything gets switched off and then
 * finds nothing at all.
 *
 * Each case moves n00b_race_reports() or does not, and the assertion is on
 * the delta rather than the total, so the cases stay independent.
 */

#define __N00B_THREAD_INTERNAL

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/race_detect.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "util/assert.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

#ifndef N00B_DEBUG

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    fprintf(stderr, "test_race_detect: needs a debug build; skipping.\n");
    return 0;
}

#else

#define SPINS 200

// The shared fields. Distinct addresses per case so one case's shadow entry
// cannot answer for another's.
typedef struct {
    uint64_t        unguarded;
    uint64_t        unguarded_again;
    uint64_t        guarded;
    uint64_t        handed_off;
    uint64_t        published;
    n00b_mutex_t    lock;
    n00b_rwlock_t   rw;
    _Atomic(bool)   go;
} shared_t;

static shared_t shared;

static void
wait_for_go(void)
{
    while (!atomic_load(&shared.go)) {
        ;
    }
}

// ---------------------------------------------------------------------------
// Two threads, no lock in common. The report this exists to produce.
// ---------------------------------------------------------------------------

typedef struct {
    uint64_t   *addr;
    const char *name;
} target_t;

static void *
unguarded_writer(void *raw)
{
    target_t *t = (target_t *)raw;

    wait_for_go();
    for (int i = 0; i < SPINS; i++) {
        n00b_race_write(t->addr, t->name);
        (*t->addr)++;
    }
    return nullptr;
}

// Both unguarded cases run this. A cell that has reported once is marked
// lock-free and never reports again, so each case needs its own address or the
// second one is measuring the first one's silence.
static void
run_unguarded_pair(target_t *t)
{
    n00b_race_write(t->addr, t->name);
    *t->addr = 1;

    atomic_store(&shared.go, false);
    auto a_r = n00b_thread_spawn(unguarded_writer, t);
    CHECK(n00b_result_is_ok(a_r));
    auto b_r = n00b_thread_spawn(unguarded_writer, t);
    CHECK(n00b_result_is_ok(b_r));
    atomic_store(&shared.go, true);

    n00b_thread_join(n00b_result_get(a_r));
    n00b_thread_join(n00b_result_get(b_r));
}

static void
test_unguarded_pair_reports(void)
{
    uint64_t before = n00b_race_reports();
    target_t t      = {.addr = &shared.unguarded, .name = "unguarded"};

    run_unguarded_pair(&t);

    CHECK(n00b_race_reports() > before);
    n00b_printf("  [PASS] two unguarded writers report");
}

// ---------------------------------------------------------------------------
// The same shape under one common lock. Must stay silent.
// ---------------------------------------------------------------------------

static void *
guarded_writer(void *ignored)
{
    (void)ignored;
    wait_for_go();
    for (int i = 0; i < SPINS; i++) {
        n00b_mutex_lock(&shared.lock);
        n00b_race_write(&shared.guarded, "guarded");
        shared.guarded++;
        n00b_mutex_unlock(&shared.lock);
    }
    return nullptr;
}

static void
test_common_lock_is_silent(void)
{
    uint64_t before = n00b_race_reports();

    atomic_store(&shared.go, false);
    auto a_r = n00b_thread_spawn(guarded_writer, nullptr);
    CHECK(n00b_result_is_ok(a_r));
    auto b_r = n00b_thread_spawn(guarded_writer, nullptr);
    CHECK(n00b_result_is_ok(b_r));
    atomic_store(&shared.go, true);

    n00b_thread_join(n00b_result_get(a_r));
    n00b_thread_join(n00b_result_get(b_r));

    CHECK(n00b_race_reports() == before);
    CHECK(shared.guarded == (uint64_t)(2 * SPINS));
    n00b_printf("  [PASS] one common lock stays silent");
}

// ---------------------------------------------------------------------------
// A writer thread, joined, then the parent reads. Ordered by the join edge
// and by nothing else. This is the case a pure lockset detector cannot get
// right, and the one that regressed while fork/join edges were missing.
// ---------------------------------------------------------------------------

static void *
handoff_writer(void *ignored)
{
    (void)ignored;
    for (int i = 0; i < SPINS; i++) {
        n00b_race_write(&shared.handed_off, "handed_off");
        shared.handed_off++;
    }
    return nullptr;
}

static void
test_join_orders_a_handoff(void)
{
    uint64_t before = n00b_race_reports();

    n00b_race_write(&shared.handed_off, "handed_off");
    shared.handed_off = 0;

    auto t_r = n00b_thread_spawn(handoff_writer, nullptr);
    CHECK(n00b_result_is_ok(t_r));
    n00b_thread_join(n00b_result_get(t_r));

    // Unlocked, from a different thread than the one that wrote it, and
    // correct: the join ordered them.
    n00b_race_read(&shared.handed_off, "handed_off");
    CHECK(shared.handed_off == (uint64_t)SPINS);

    CHECK(n00b_race_reports() == before);
    n00b_printf("  [PASS] a joined handoff is not reported");
}

// ---------------------------------------------------------------------------
// A writer publishing under an rwlock's write lock, a reader taking it for
// read. The lockset sees the shared lock, but so must happens-before: this is
// the edge that read-lock accounting was not contributing.
// ---------------------------------------------------------------------------

static void *
rw_publisher(void *ignored)
{
    (void)ignored;
    wait_for_go();
    for (int i = 0; i < SPINS; i++) {
        n00b_rw_write_lock(&shared.rw);
        n00b_race_write(&shared.published, "published");
        shared.published++;
        n00b_rw_unlock(&shared.rw);
    }
    return nullptr;
}

static void *
rw_consumer(void *ignored)
{
    (void)ignored;
    wait_for_go();
    for (int i = 0; i < SPINS; i++) {
        n00b_rw_read_lock(&shared.rw);
        n00b_race_read(&shared.published, "published");
        (void)shared.published;
        n00b_rw_unlock(&shared.rw);
    }
    return nullptr;
}

static void
test_rwlock_orders_publish(void)
{
    uint64_t before = n00b_race_reports();

    atomic_store(&shared.go, false);
    auto w_r = n00b_thread_spawn(rw_publisher, nullptr);
    CHECK(n00b_result_is_ok(w_r));
    auto r_r = n00b_thread_spawn(rw_consumer, nullptr);
    CHECK(n00b_result_is_ok(r_r));
    atomic_store(&shared.go, true);

    n00b_thread_join(n00b_result_get(w_r));
    n00b_thread_join(n00b_result_get(r_r));

    CHECK(n00b_race_reports() == before);
    n00b_printf("  [PASS] an rwlock orders publish to a reader");
}

// ---------------------------------------------------------------------------
// Slot collision. Two addresses that land in the same shadow slot, hammered
// from two threads. Nothing here should report: each address is touched by
// one thread only. What this catches is the table tearing under itself, which
// it did while the stripe was hashed from the address instead of the slot.
// ---------------------------------------------------------------------------

#define COLLIDE_SPINS 20000

typedef struct {
    uint64_t *addr;
    char      name[16];
} collide_arg_t;

static void *
collide_worker(void *raw)
{
    collide_arg_t *arg = (collide_arg_t *)raw;

    wait_for_go();
    for (int i = 0; i < COLLIDE_SPINS; i++) {
        n00b_race_write(arg->addr, arg->name);
        n00b_race_read(arg->addr, arg->name);
    }
    return nullptr;
}

// The shadow slot is the low bits of a murmur3 finalizer over the address.
// Search a block of candidates for a second address that lands on the first
// one's slot, so the collision is real rather than assumed.
static uint64_t
shadow_slot(const void *p)
{
    uint64_t h = (uint64_t)(uintptr_t)p;
    h ^= h >> 33;
    h *= UINT64_C(0xFF51AFD7ED558CCD);
    h ^= h >> 33;
    return h & 4095;
}

static void
test_slot_collision_is_guarded(void)
{
    uint64_t before = n00b_race_reports();

    enum { POOL = 1u << 17 };
    uint64_t *pool = n00b_alloc_array_with_opts(
        uint64_t,
        POOL,
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_NONE});
    CHECK(pool != nullptr);

    uint64_t *a = &pool[0];
    uint64_t *b = nullptr;
    for (unsigned i = 1; i < POOL; i++) {
        if (shadow_slot(&pool[i]) == shadow_slot(a)) {
            b = &pool[i];
            break;
        }
    }
    CHECK(b != nullptr);
    n00b_printf("  two addresses share shadow slot «#»", (int64_t)shadow_slot(a));

    collide_arg_t arg_a = {.addr = a, .name = "collide_a"};
    collide_arg_t arg_b = {.addr = b, .name = "collide_b"};

    atomic_store(&shared.go, false);
    auto a_r = n00b_thread_spawn(collide_worker, &arg_a);
    CHECK(n00b_result_is_ok(a_r));
    auto b_r = n00b_thread_spawn(collide_worker, &arg_b);
    CHECK(n00b_result_is_ok(b_r));
    atomic_store(&shared.go, true);

    n00b_thread_join(n00b_result_get(a_r));
    n00b_thread_join(n00b_result_get(b_r));

    // Each address had exactly one accessing thread, so neither can have
    // reached shared-modified honestly. A report here is the table losing
    // track of which address a cell describes.
    CHECK(n00b_race_reports() == before);
    n00b_printf("  [PASS] colliding shadow slots do not report");
}

// ---------------------------------------------------------------------------
// Slot reclamation. Run more threads than the clock table has slots and then
// check the detector still works. It went permanently silent at this point
// while slots were never returned.
// ---------------------------------------------------------------------------

static void *
brief_worker(void *ignored)
{
    (void)ignored;
    return nullptr;
}

static void
test_detector_survives_many_threads(void)
{
    // N00B_RACE_THREADS is 64; go well past it, one at a time.
    for (int i = 0; i < 150; i++) {
        auto t_r = n00b_thread_spawn(brief_worker, nullptr);
        CHECK(n00b_result_is_ok(t_r));
        n00b_thread_join(n00b_result_get(t_r));
    }

    // The same shape as the first case, on its own address, which must still
    // report: a detector out of thread slots treats every access as ordered
    // and goes quiet without saying so.
    uint64_t before = n00b_race_reports();
    target_t t      = {.addr = &shared.unguarded_again,
                       .name = "unguarded_again"};

    run_unguarded_pair(&t);

    CHECK(n00b_race_reports() > before);
    n00b_printf("  [PASS] still reporting after 150 threads have come and gone");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    n00b_mutex_init(&shared.lock);
    n00b_rw_init(&shared.rw);

    test_unguarded_pair_reports();
    test_common_lock_is_silent();
    test_join_orders_a_handoff();
    test_rwlock_orders_publish();
    test_slot_collision_is_guarded();
    test_detector_survives_many_threads();

    n00b_printf("test_race_detect: all cases passed");
    n00b_shutdown();
    return 0;
}

#endif
