/* test/unit/test_worker_pool_http_compression_stress.c
 *
 * Reproduces the reported `free(): invalid size` / SIGABRT crash
 * (brotli dlopen probe / zlib inflate-deflate) using ONLY n00b's own
 * sanctioned APIs and idioms -- no raw pthread_create, no raw libc
 * malloc/free, no manual n00b_thread_spawn. This mirrors
 * test_worker_pool_gc_stress.c (the project's own established idiom for
 * finding worker-pool/GC races -- it previously pinned down the
 * "async-seal use-after-reclaim" bug fixed in commit 0374ef83) as closely
 * as possible, since that is the pattern real n00b applications
 * (crayon/wax) are expected to use for background work.
 *
 * Difference from test_worker_pool_gc_stress.c: instead of each worker
 * job just allocating garbage GC strings, jobs call the REAL
 * n00b_http_have_brotli() (hence the real brotli_probe() -> dlopen())
 * and n00b_http_decompress() (hence the real inflate_buffer() /
 * inflateEnd()) -- the exact two call sites the original bug report
 * found, run from a worker-pool thread exactly as
 * n00b_http_request_sync()'s real callers would exercise them.
 */

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "conduit/print.h"
#include "internal/net/http/http_compression.h"
#include "util/assert.h"
#include "util/worker_pool.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

typedef struct {
    int64_t n;
} job_t;

static n00b_runtime_t *g_rt = nullptr;

static void
do_zlib_roundtrip(void) {
    const char *msg    = "hello world, compression round trip payload";
    uLong       srclen = (uLong)strlen(msg);
    uLong       bound  = compressBound(srclen);
    unsigned char *comp = malloc(bound);
    uLongf      complen = bound;
    compress(comp, &complen, (const unsigned char *)msg, srclen);

    n00b_buffer_t *body = n00b_buffer_from_bytes((char *)comp, (int64_t)complen);
    n00b_http_decompress(body, "gzip");
    free(comp);
}

/* Worker job: exercises the real brotli dlopen probe (memoized after its
 * first call process-wide) and a real zlib round trip (not memoized --
 * every job gets a fresh inflateInit2/inflateEnd cycle) from a
 * worker-pool thread, exactly as the real HTTP response path would. */
static void
worker_fn(void *job_v, void *user_data) {
    (void)user_data;
    job_t *job = job_v;

    if (job->n % 50 == 0) {
        bool have = n00b_http_have_brotli();
        n00b_eprintf("[worker] job [|#|]: brotli probe -> [|#|]\n",
                     job->n,
                     (int64_t)have);
    }

    do_zlib_roundtrip();

    /* Also allocate ordinary GC-managed garbage, like the established
     * test_worker_pool_gc_stress.c pattern, so the worker's own thread
     * exercises n00b's normal allocation path too, not just the
     * interposed one. */
    for (int j = 0; j < 32; j++) {
        (void)n00b_cformat("worker garbage [|#|]:[|#|]", job->n, (int64_t)j);
    }
}

int
main(int argc, char *argv[]) {
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);
    g_rt = &rt;

    /* Restore default OS crash behavior so a real core dump is produced --
     * n00b's own crash handler calls its own exit routine directly instead
     * of re-raising, which otherwise suppresses core generation entirely. */
    signal(SIGSEGV, SIG_DFL);
    signal(SIGABRT, SIG_DFL);

    const int pools         = 8;
    const int jobs_per_pool = 64;

    for (int p = 0; p < pools; p++) {
        n00b_worker_pool_t *pool = n00b_worker_pool_new(2, 8, worker_fn, nullptr);
        CHECK(pool != nullptr);

        for (int i = 0; i < jobs_per_pool; i++) {
            job_t *job = n00b_alloc(job_t);
            job->n     = (int64_t)(p * 1000 + i);
            n00b_worker_pool_submit(pool, job);

            /* Producer (main-thread) garbage + forced collect, exactly
             * matching test_worker_pool_gc_stress.c's established
             * pattern -- this is what actually creates the STW pressure
             * concurrent with the worker's dlopen/zlib calls. */
            for (int j = 0; j < 64; j++) {
                (void)n00b_cformat("producer garbage [|#|]:[|#|]",
                                   (int64_t)i,
                                   (int64_t)j);
            }
            n00b_collect(rt.default_arena);
        }

        n00b_worker_pool_shutdown(pool);
        n00b_eprintf("  [pool [|#|]] clean\n", (int64_t)p);
    }

    n00b_eprintf("test_worker_pool_http_compression_stress OK\n");
    n00b_shutdown();
    return 0;
}
