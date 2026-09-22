/* test/unit/test_gc_large_alloc_churn.c - multi-thread churn of allocations
 * large enough to force arena segment adds, concurrent with forced collects.
 *
 * Deliberately dependency-free (no new APIs) so it can be built against any
 * revision for bisecting.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "n00b.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "conduit/print.h"
#include "util/assert.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

static int N_THREADS = 6;
static int N_ALLOCS  = 200;
static int N_COLLECTS = 120;
static int ALLOC_SZ  = 4 * 1024 * 1024;

static _Atomic int64_t g_done  = 0;
static _Atomic int64_t g_total = 0;

static void *
churn_main(void *arg)
{
    int64_t id = (int64_t)(intptr_t)arg;

    for (int i = 0; i < N_ALLOCS; i++) {
        char *p = n00b_alloc_array_with_opts(char,
                                             ALLOC_SZ,
                                             &(n00b_alloc_opts_t){});
        p[0]            = (char)('a' + (id & 15));
        p[ALLOC_SZ - 1] = (char)('a' + (id & 15));
        CHECK(p[0] == p[ALLOC_SZ - 1]);
        n00b_atomic_add(&g_total, 1);
    }

    n00b_atomic_add(&g_done, 1);
    return nullptr;
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    if (getenv("CHURN_THREADS")) {
        N_THREADS = atoi(getenv("CHURN_THREADS"));
    }
    if (getenv("CHURN_ALLOCS")) {
        N_ALLOCS = atoi(getenv("CHURN_ALLOCS"));
    }
    if (getenv("CHURN_SZ")) {
        ALLOC_SZ = atoi(getenv("CHURN_SZ"));
    }

    n00b_arena_t   *arena = n00b_get_runtime()->default_arena;
    n00b_thread_t **threads = calloc((size_t)N_THREADS, sizeof(*threads));

    for (int64_t i = 0; i < N_THREADS; i++) {
        auto r = n00b_thread_spawn(churn_main, (void *)(intptr_t)i);
        CHECK(n00b_result_is_ok(r));
        threads[i] = n00b_result_get(r);
    }

    for (int i = 0; i < N_COLLECTS && n00b_atomic_load(&g_done) < N_THREADS; i++) {
        n00b_collect(arena);
    }

    for (int i = 0; i < N_THREADS; i++) {
        n00b_thread_join(threads[i]);
    }

    n00b_collect(arena);

    n00b_eprintf("gc large-alloc churn: threads=[|#|] sz=[|#|] allocs=[|#|]\n",
                 (int64_t)N_THREADS,
                 (int64_t)ALLOC_SZ,
                 (int64_t)n00b_atomic_load(&g_total));

    CHECK(n00b_atomic_load(&g_total) == (int64_t)N_THREADS * N_ALLOCS);

    n00b_eprintf("test_gc_large_alloc_churn OK\n");
    return 0;
}
