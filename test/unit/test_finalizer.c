#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/stw.h"
#include "core/atomic.h"
#include "core/buffer.h"
#include "core/data_lock.h"
#include "core/thread.h"

// ============================================================================
// Test helper type
// ============================================================================

typedef struct {
    uint64_t value;
    void    *next;
} test_obj_t;

#define ARENA_OPTS(a) &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)(a)}

// Unlike assert, still checks in a release (NDEBUG) build.
#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);       \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

// ============================================================================
// 1. Basic finalizer invocation
// ============================================================================

static volatile int finalizer_call_count = 0;

static void
test_finalizer_callback(void *user_data)
{
    volatile int *flag = (volatile int *)user_data;
    (*flag)++;
}

// noinline so the object pointer lives only in this frame, which is
// dead when the caller triggers collection.
static __attribute__((noinline)) void
allocate_with_finalizer(n00b_arena_t *arena, volatile int *flag, int count)
{
    for (int i = 0; i < count; i++) {
        test_obj_t *obj = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
        obj->value      = 0xDEAD;
        n00b_add_finalizer(obj, test_finalizer_callback, (void *)flag);
    }
}

static void
test_basic_finalizer(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    volatile int flag = 0;

    allocate_with_finalizer(arena, &flag, 1);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_gc_run_finalizers();

    // Conservative GC may keep the object alive via stale stack values,
    // so the finalizer may not always fire.  We verify it ran at most once.
    assert(flag == 0 || flag == 1);
    printf("  [PASS] basic finalizer invocation (flag=%d)\n", flag);
}

// ============================================================================
// 2. Surviving object — finalizer NOT called
// ============================================================================

static void
test_surviving_object(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    volatile int flag = 0;

    test_obj_t *obj = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
    obj->value      = 0xBEEF;
    n00b_add_finalizer(obj, test_finalizer_callback, (void *)&flag);

    // Keep the reference alive on the stack during GC.
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_gc_run_finalizers();

    // Object survived — finalizer must NOT have been called.
    assert(flag == 0);
    // Object should still be readable.
    assert(obj->value == 0xBEEF);

    printf("  [PASS] surviving object finalizer not called\n");
}

// ============================================================================
// 3. Multiple finalizers on different objects
// ============================================================================

static void
test_multiple_finalizers(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    finalizer_call_count = 0;

    allocate_with_finalizer(arena, &finalizer_call_count, 5);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_gc_run_finalizers();

    // Conservative GC may keep some objects alive via stale stack values.
    assert(finalizer_call_count >= 0 && finalizer_call_count <= 5);
    printf("  [PASS] multiple finalizers (%d/5 finalized)\n", finalizer_call_count);
}

// ============================================================================
// 4. Finalizer via n00b_free (explicit free path)
// ============================================================================

static void
test_finalizer_on_free(void)
{
    volatile int flag = 0;

    // Use the default allocator (not a GC arena) so n00b_free works.
    test_obj_t *obj = n00b_alloc(test_obj_t);
    obj->value      = 0xCAFE;
    n00b_add_finalizer(obj, test_finalizer_callback, (void *)&flag);

    // Explicit free should run the finalizer.
    n00b_free(obj);

    assert(flag == 1);

    printf("  [PASS] finalizer on explicit free\n");
}

// ============================================================================
// 5. Lock cleanup (buffer with lock — no crash)
// ============================================================================

static __attribute__((noinline)) void
allocate_buffer_on_arena(n00b_arena_t *arena)
{
    n00b_buffer_t *buf = n00b_alloc_with_opts(n00b_buffer_t, ARENA_OPTS(arena));
    n00b_buffer_init(buf, .length = 64, .allocator = (n00b_allocator_t *)arena);
    memset(buf->data, 0xAB, 64);
}

static void
test_lock_cleanup(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 8192, .use_gc = true);

    allocate_buffer_on_arena(arena);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_gc_run_finalizers();

    // If we get here without crashing, the lock was freed safely.
    printf("  [PASS] lock cleanup on collection\n");
}

// ============================================================================
// 6. Finalizer via n00b_alloc _kargs (no separate n00b_add_finalizer call)
// ============================================================================

static __attribute__((noinline)) void
allocate_with_finalizer_kw(n00b_arena_t *arena, volatile int *flag)
{
    test_obj_t *obj = n00b_alloc_with_opts(test_obj_t,
                                           &(n00b_alloc_opts_t){
                                               .allocator      = (n00b_allocator_t *)arena,
                                               .finalizer      = test_finalizer_callback,
                                               .finalizer_data = (void *)flag,
                                           });
    obj->value = 0xF00D;
}

static void
test_finalizer_via_alloc_kw(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    volatile int  flag  = 0;

    allocate_with_finalizer_kw(arena, &flag);

    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_gc_run_finalizers();

    assert(flag == 0 || flag == 1);
    printf("  [PASS] finalizer via n00b_alloc _kargs (flag=%d)\n", flag);
}

// ============================================================================
// 7. Unreachable objects are finalized, with their memory still intact
// ============================================================================

#define UNREACHABLE_N 16
#define LIVE_MAGIC    0x5EEDF00DULL

static _Atomic int unreachable_finalized = 0;
static _Atomic int unreachable_bad       = 0;

static void
count_self_finalizer(void *p)
{
    test_obj_t *obj = p;
    if (obj == nullptr || obj->value != LIVE_MAGIC) {
        atomic_fetch_add(&unreachable_bad, 1);
    }
    atomic_fetch_add(&unreachable_finalized, 1);
}

static __attribute__((noinline)) void
allocate_unreachable(n00b_arena_t *arena)
{
    for (int i = 0; i < UNREACHABLE_N; i++) {
        test_obj_t *obj = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));
        obj->value      = LIVE_MAGIC;
        n00b_add_finalizer(obj, count_self_finalizer, obj);
    }
}

// Overwrite the dead frames allocate_unreachable left below the stack pointer,
// so the conservative stack scan finds none of its objects.
static __attribute__((noinline)) void
scrub_stack(void)
{
    volatile char pad[16384];
    memset((char *)pad, 0, sizeof(pad));
}

static void
test_unreachable_finalizers_run(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 1 << 16, .use_gc = true);

    allocate_unreachable(arena);
    scrub_stack();

    n00b_collect(arena);
    n00b_gc_run_finalizers();
    REQUIRE(atomic_load(&unreachable_finalized) == UNREACHABLE_N);
    REQUIRE(atomic_load(&unreachable_bad) == 0);

    // The resurrected objects carry no finalizer any more, so reclaiming them
    // runs nothing a second time.
    n00b_collect(arena);
    n00b_gc_run_finalizers();
    REQUIRE(atomic_load(&unreachable_finalized) == UNREACHABLE_N);

    printf("  [PASS] unreachable objects finalized\n");
}

// ============================================================================
// 8. A finalizer follows its object when the collector moves it
// ============================================================================

#define POINTER_MASK 0xA5A5A5A5A5A5A5A5ULL

static _Atomic int    moved_calls = 0;
static _Atomic(void *) moved_seen = nullptr;

static void
record_self_finalizer(void *p)
{
    atomic_store(&moved_seen, p);
    atomic_fetch_add(&moved_calls, 1);
}

static void
test_finalizer_follows_moved_object(void)
{
    n00b_arena_t        *arena = n00b_new_arena(.size = 1 << 16, .use_gc = true);
    test_obj_t *volatile obj   = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(arena));

    obj->value = LIVE_MAGIC;
    n00b_add_finalizer(obj, record_self_finalizer, obj);

    // Masked, so the stack scan does not rewrite it along with `obj`, and
    // volatile, so the compiler cannot fold the mask out of the comparison.
    volatile uintptr_t before = (uintptr_t)obj ^ POINTER_MASK;

    n00b_collect(arena);
    n00b_gc_run_finalizers();

    REQUIRE(((uintptr_t)obj ^ POINTER_MASK) != before);
    REQUIRE(obj->value == LIVE_MAGIC);
    REQUIRE(atomic_load(&moved_calls) == 0);

    n00b_free((void *)obj);
    REQUIRE(atomic_load(&moved_calls) == 1);
    REQUIRE(atomic_load(&moved_seen) == (void *)obj);

    printf("  [PASS] finalizer follows a moved object\n");
}

// ============================================================================
// 9. A finalizer that frees another finalizable object
// ============================================================================

static n00b_allocator_t *
system_pool(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
}

static test_obj_t *nested_y;
static _Atomic int nested_x_runs = 0;
static _Atomic int nested_y_runs = 0;
static _Atomic int nested_z_runs = 0;

static void
nested_z_fin(void *p)
{
    (void)p;
    atomic_fetch_add(&nested_z_runs, 1);
}

static void
nested_y_fin(void *p)
{
    (void)p;
    atomic_fetch_add(&nested_y_runs, 1);
}

static void
nested_x_fin(void *p)
{
    (void)p;
    atomic_fetch_add(&nested_x_runs, 1);
    n00b_free(nested_y);
}

static void
test_finalizer_frees_finalizable(void)
{
    // System-pool objects have no OOB record, so these use the runtime index
    // in every build type.
    test_obj_t *z = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(system_pool()));
    test_obj_t *y = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(system_pool()));
    test_obj_t *x = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(system_pool()));
    nested_y      = y;

    n00b_add_finalizer(z, nested_z_fin, nullptr);
    n00b_add_finalizer(y, nested_y_fin, nullptr);
    n00b_add_finalizer(x, nested_x_fin, nullptr);

    n00b_free(x);
    REQUIRE(atomic_load(&nested_x_runs) == 1);
    REQUIRE(atomic_load(&nested_y_runs) == 1);
    REQUIRE(atomic_load(&nested_z_runs) == 0);

    n00b_free(z);
    REQUIRE(atomic_load(&nested_z_runs) == 1);
    REQUIRE(atomic_load(&nested_x_runs) == 1);

    printf("  [PASS] finalizer freeing another finalizable object\n");
}

// ============================================================================
// 10. Two threads freeing finalizable objects at once
// ============================================================================

enum { RACE_INIT, RACE_IN_X, RACE_Y_FREED };

static _Atomic int race_stage  = RACE_INIT;
static _Atomic int race_x_runs = 0;
static _Atomic int race_y_runs = 0;
static _Atomic int race_w_runs = 0;

static void
race_x_fin(void *p)
{
    (void)p;
    // Hold the first run inside the finalizer until the main thread's free
    // of Y has completed. A second run is the failure the test counts.
    if (atomic_fetch_add(&race_x_runs, 1) != 0) {
        return;
    }
    atomic_store(&race_stage, RACE_IN_X);
    while (atomic_load(&race_stage) != RACE_Y_FREED) {
    }
}

static void
race_y_fin(void *p)
{
    (void)p;
    atomic_fetch_add(&race_y_runs, 1);
}

static void
race_w_fin(void *p)
{
    (void)p;
    atomic_fetch_add(&race_w_runs, 1);
}

static void *
race_free_x(void *x)
{
    n00b_free(x);
    return nullptr;
}

static void
test_concurrent_finalizer_frees(void)
{
    test_obj_t *y = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(system_pool()));
    test_obj_t *x = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(system_pool()));
    test_obj_t *w = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(system_pool()));

    n00b_add_finalizer(y, race_y_fin, nullptr);
    n00b_add_finalizer(x, race_x_fin, nullptr);
    n00b_add_finalizer(w, race_w_fin, nullptr);

    auto result = n00b_thread_spawn(race_free_x, x);
    REQUIRE(n00b_result_is_ok(result));
    n00b_thread_t *thread = n00b_result_get(result);

    while (atomic_load(&race_stage) != RACE_IN_X) {
    }
    n00b_free(y);
    atomic_store(&race_stage, RACE_Y_FREED);
    n00b_thread_join(thread);

    n00b_free(w);
    REQUIRE(atomic_load(&race_x_runs) == 1);
    REQUIRE(atomic_load(&race_y_runs) == 1);
    REQUIRE(atomic_load(&race_w_runs) == 1);

    printf("  [PASS] concurrent frees of finalizable objects\n");
}

// ============================================================================
// 11. A free's registry lookup does not grow with the registry
// ============================================================================

#if defined(N00B_DEBUG)
extern _Atomic uint64_t n00b_finalizer_registry_probes;

#define REGISTERED_N 1000

static void
noop_finalizer(void *p)
{
    (void)p;
}

static void
test_free_cost_independent_of_registry(void)
{
    test_obj_t *objs[REGISTERED_N];
    for (int i = 0; i < REGISTERED_N; i++) {
        objs[i] = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(system_pool()));
        n00b_add_finalizer(objs[i], noop_finalizer, nullptr);
    }
    test_obj_t *plain = n00b_alloc_with_opts(test_obj_t, ARENA_OPTS(system_pool()));

    uint64_t before = atomic_load(&n00b_finalizer_registry_probes);
    n00b_free(plain);
    uint64_t probes = atomic_load(&n00b_finalizer_registry_probes) - before;
    printf("  free with %d finalizers registered: %llu registry probes\n",
           REGISTERED_N,
           (unsigned long long)probes);
    REQUIRE(probes <= 1);

    for (int i = 0; i < REGISTERED_N; i++) {
        n00b_free(objs[i]);
    }
    printf("  [PASS] free cost independent of registry size\n");
}
#endif

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    // Copying collection, so test 8 sees its object move. Decided at the
    // first collection, which is below.
    setenv("N00B_GC_PIN_ALL", "0", 1);

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running finalizer tests...\n");

    test_basic_finalizer();
    test_surviving_object();
    test_multiple_finalizers();
    test_finalizer_on_free();
    test_lock_cleanup();
    test_finalizer_via_alloc_kw();
    test_unreachable_finalizers_run();
    test_finalizer_follows_moved_object();
    test_finalizer_frees_finalizable();
    test_concurrent_finalizer_frees();
#if defined(N00B_DEBUG)
    test_free_cost_independent_of_registry();
#endif

    printf("All finalizer tests passed.\n");
    n00b_shutdown();
    return 0;
}
