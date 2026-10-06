// Small allocations from the default arena are served from a per-thread
// buffer: no shared bump-pointer commit and no critical_execution acquisition
// per object. Counted with the debug-build work counters, not timed.

#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "core/thread.h"

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);       \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

#define ALLOCS  10000
#define THREADS 4

typedef struct small_t {
    uint64_t        a;
    struct small_t *next;
} small_t;

static uint64_t
count_work(void)
{
    uint64_t bumps0 = n00b_atomic_load(&n00b_arena_shared_bumps);
    uint64_t gates0 = n00b_atomic_load(&n00b_arena_extent_gates);

    for (int i = 0; i < ALLOCS; i++) {
        small_t *s = n00b_alloc(small_t);
        s->a       = (uint64_t)i;
    }

    uint64_t bumps = n00b_atomic_load(&n00b_arena_shared_bumps) - bumps0;
    uint64_t gates = n00b_atomic_load(&n00b_arena_extent_gates) - gates0;
    printf("  %d allocations: %llu shared bumps, %llu extent gates\n",
           ALLOCS,
           (unsigned long long)bumps,
           (unsigned long long)gates);

    // One commit and one gate per object without a buffer; with one, the
    // shared pointer moves once per 32KB and the gate is taken once per
    // buffer for objects this size.
    REQUIRE(bumps * 50 <= ALLOCS);
    REQUIRE(gates * 50 <= ALLOCS);
    return bumps;
}

// Each worker builds a linked list across collections and checks it after, so
// buffers retired by a collection hand out no space that is still in use.
static _Atomic int go;

static void *
churn(void *arg)
{
    (void)arg;
    while (!atomic_load(&go)) {
    }

    small_t *volatile head = nullptr;
    for (int i = 0; i < ALLOCS; i++) {
        small_t *s = n00b_alloc(small_t);
        s->a       = (uint64_t)i;
        s->next    = head;
        head       = s;
        if (i % 2500 == 0) {
            n00b_collect(n00b_get_runtime()->default_arena);
        }
    }

    uint64_t expect = ALLOCS;
    small_t *s      = head;
    while (s != nullptr) {
        REQUIRE(s->a == --expect);
        s = s->next;
    }
    REQUIRE(expect == 0);
    return nullptr;
}

// A collection that lands after a thread reads its buffer and before it
// publishes the reservation retires that buffer. The allocation must then come
// from a fresh buffer, never from the one the collection retired.
enum { HOOK_IDLE, HOOK_ARMED, HOOK_HELD, HOOK_RELEASED };

static _Atomic int hook_stage = HOOK_IDLE;
static _Atomic int served_from_fresh_buffer;

static void
hold_before_publish(void)
{
    int armed = HOOK_ARMED;
    if (atomic_compare_exchange_strong(&hook_stage, &armed, HOOK_HELD)) {
        while (atomic_load(&hook_stage) != HOOK_RELEASED) {
        }
    }
}

static void *
alloc_across_collect(void *arg)
{
    (void)arg;
    small_t *warm = n00b_alloc(small_t);
    warm->a       = 1;

    atomic_store(&hook_stage, HOOK_ARMED);
    small_t *s = n00b_alloc(small_t);
    s->a       = 2;

    n00b_thread_t *self = n00b_thread_self();
    char          *end  = atomic_load(&self->tlab_end);
    atomic_store(&served_from_fresh_buffer,
                 end != nullptr && (char *)s >= end - N00B_TLAB_SIZE && (char *)s < end);
    return nullptr;
}

static void
test_collect_between_read_and_publish(void)
{
    n00b_arena_tlab_publish_hook = hold_before_publish;

    auto r = n00b_thread_spawn(alloc_across_collect, nullptr);
    REQUIRE(n00b_result_is_ok(r));
    n00b_thread_t *thread = n00b_result_get(r);

    while (atomic_load(&hook_stage) != HOOK_HELD) {
    }
    n00b_collect(n00b_get_runtime()->default_arena);
    atomic_store(&hook_stage, HOOK_RELEASED);
    n00b_thread_join(thread);

    n00b_arena_tlab_publish_hook = nullptr;
    REQUIRE(atomic_load(&served_from_fresh_buffer));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    (void)count_work();
    printf("  [PASS] buffered allocation counts\n");

    n00b_thread_t *threads[THREADS];
    for (int i = 0; i < THREADS; i++) {
        auto r = n00b_thread_spawn(churn, nullptr);
        REQUIRE(n00b_result_is_ok(r));
        threads[i] = n00b_result_get(r);
    }
    atomic_store(&go, 1);
    for (int i = 0; i < THREADS; i++) {
        n00b_thread_join(threads[i]);
    }
    printf("  [PASS] buffers across concurrent collections\n");

    test_collect_between_read_and_publish();
    printf("  [PASS] collection between buffer read and publish\n");

    n00b_shutdown();
    return 0;
}
