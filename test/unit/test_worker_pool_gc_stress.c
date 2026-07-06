/* test/unit/test_worker_pool_gc_stress.c - isolation repro (rocs-free).
 *
 * Pin down the async-seal corruption with NO rocs: one worker-pool thread
 * allocating GC strings, concurrent with the main thread doing configurable
 * work.  Ablation toggles (env):
 *   MAIN_ALLOC=0   -> main does NOT allocate while jobs are in flight.
 *   MAIN_COLLECT=0 -> main does NOT force n00b_collect.
 *   WORKER_COLLECT=1 -> the worker ALSO forces a collect (default off).
 * The worker never forces a collect by default; it only allocates strings.
 */

#include <stdint.h>
#include <stdlib.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/gc.h"
#include "conduit/print.h"
#include "util/assert.h"
#include "util/worker_pool.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

typedef struct {
    int64_t n;
} job_t;

static n00b_runtime_t *g_rt           = nullptr;
static bool            g_main_alloc    = true;
static bool            g_main_collect  = true;
static bool            g_worker_collect = false;

// Worker: allocate GC strings (the thing the marshal does internally).
static bool g_worker_private_arena = false; // PRIVATE_ARENA=1

static void
worker_fn(void *job_v, void *user_data)
{
    (void)user_data;
    job_t *job = job_v;

    static bool once = false;
    if (!once) {
        once = true;
        n00b_thread_t *self = n00b_thread_self();
        n00b_eprintf("WORKER self: gc_isolated=[|#|] gc_stack_policy=[|#|] "
                     "stack_map=[|#|] stack_top=[|#|]\n",
                     (int64_t)(self ? self->gc_isolated : -1),
                     (int64_t)(self ? self->gc_stack_policy : -1),
                     (uint64_t)(self ? (uintptr_t)self->stack_map : 0),
                     (uint64_t)(self ? (uintptr_t)self->stack_top : 0));
    }

    // EXPERIMENT: if PRIVATE_ARENA, redirect the worker's allocations OFF the
    // shared rt->default_allocator (which main collects) into a private pool.
    n00b_pool_t       wpool = {};
    n00b_allocator_t *prev  = nullptr;
    if (g_worker_private_arena) {
        n00b_allocator_t *wa = n00b_pool_init(&wpool,
                                              .hidden = true,
                                              .name   = "worker_private");
        prev                 = n00b_set_current_allocator(wa);
    }

    for (int j = 0; j < 256; j++) {
        (void)n00b_cformat("worker garbage [|#|]:[|#|]", job->n, (int64_t)j);
    }

    if (g_worker_private_arena) {
        n00b_restore_current_allocator(prev);
        n00b_allocator_destroy((n00b_allocator_t *)&wpool);
    }
    if (g_worker_collect) {
        n00b_collect(g_rt->default_arena);
    }
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);
    g_rt = &rt;

    const char *ma = getenv("MAIN_ALLOC");
    const char *mc = getenv("MAIN_COLLECT");
    const char *wc = getenv("WORKER_COLLECT");
    if (ma != nullptr && ma[0] == '0') g_main_alloc = false;
    if (mc != nullptr && mc[0] == '0') g_main_collect = false;
    if (wc != nullptr && wc[0] == '1') g_worker_collect = true;
    const char *pa = getenv("PRIVATE_ARENA");
    if (pa != nullptr && pa[0] == '1') g_worker_private_arena = true;
    n00b_eprintf("config: main_alloc=[|#|] main_collect=[|#|] worker_collect=[|#|]\n",
                 (int64_t)g_main_alloc,
                 (int64_t)g_main_collect,
                 (int64_t)g_worker_collect);

    const int pools         = 6;
    const int jobs_per_pool = 64;

    for (int p = 0; p < pools; p++) {
        n00b_worker_pool_t *pool = n00b_worker_pool_new(1, 8, worker_fn, nullptr);
        CHECK(pool != nullptr);

        for (int i = 0; i < jobs_per_pool; i++) {
            job_t *job = n00b_alloc(job_t);
            job->n     = (int64_t)(p * 1000 + i);
            n00b_worker_pool_submit(pool, job);

            if (g_main_alloc) {
                for (int j = 0; j < 64; j++) {
                    (void)n00b_cformat("producer garbage [|#|]:[|#|]",
                                       (int64_t)i,
                                       (int64_t)j);
                }
            }
            if (g_main_collect) {
                n00b_collect(rt.default_arena);
            }
        }

        n00b_worker_pool_shutdown(pool);
        n00b_eprintf("  [pool [|#|]] clean\n", (int64_t)p);
    }

    n00b_eprintf("test_worker_pool_gc_stress OK\n");
    n00b_shutdown();
    return 0;
}
