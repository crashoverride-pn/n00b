/* test/unit/test_worker_pool_collector_rig.c - n00b#309 reproducer.
 *
 * Standalone version of the wax pipeline stress rig that crashed 15 times in
 * one night against b169ca0b (crashappsec/wax test_754_stress): producers
 * allocate small job messages from rt->user_pool, hand them to an
 * n00b_worker_pool, workers read the job, allocate a large block of GC-arena
 * garbage, occasionally resubmit the job, and otherwise n00b_free it back to
 * the pool. A helper thread forces n00b_collect(rt->default_arena) on a fixed
 * cadence the whole time.
 *
 * Every site #309 lists is exercised and checked, not just executed:
 *
 *   - worker, first read of its job message .......... job->magic check
 *   - dispatcher `pool->queue[pool->tail] = job` ...... n00b_worker_pool_submit
 *   - worker, first write into a fresh GC block ....... g[0] / g[n-1] stores
 *   - lock in the pool struct (work_cv) ............... POOL=arena places the
 *                                                        pool struct in the
 *                                                        MOVING arena, the shape
 *                                                        of wax's AI work pool
 *   - pointer from a pool object into the arena ....... job->tag validated
 *                                                        word-for-word after
 *                                                        any number of collects
 *
 * Knobs (env, all optional):
 *   N00B_RIG_SECONDS      run length (default 20; CI-sized)
 *   N00B_RIG_PRODUCERS    producer threads (4)
 *   N00B_RIG_WORKERS      pool workers (2)
 *   N00B_RIG_CAP          pool ring capacity (256)
 *   N00B_RIG_GARBAGE_KB   GC-arena bytes each job allocates (256)
 *   N00B_RIG_GC_MS        forced-collect cadence, 0 disables (150)
 *   N00B_RIG_REENTER_PCT  percent of jobs a worker resubmits once (5)
 *   N00B_RIG_HOOK_US      per-job sleep in the worker (300)
 *   N00B_RIG_POOL         user | arena: where the worker pool struct lives
 *                         (default user, wax's enrichment pool; arena is wax's
 *                         AI work pool, created with no .allocator)
 *
 * Exit 0 only if every job round-tripped intact and the process is still
 * standing; any fault is the finding.
 */
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/gc.h"
#include "core/gc_map.h"
#include "core/mmaps.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "util/worker_pool.h"

#define RIG_JOB_MAGIC 0x3039A11Cu
#define RIG_JOB_DEAD  0x3039DEADu
#define RIG_TAG_WORDS 8

// tag_orig / probe are the scan-mode oracle. tag_orig stores the tag's
// original address with the top 16 bits set, so no scan can mistake it for a
// pointer; the worker compares it with job->tag to learn whether the tag array
// moved. probe is tag|1: a misaligned interior pointer to the same array. A
// PRECISE scan of rig_job_t leaves probe alone (it is not a pointer field); a
// CONSERVATIVE scan resolves it into the tag allocation and rewrites it to the
// forwarded address. So after a move: probe == tag|1 means the job was scanned
// conservatively, probe == tag_orig|1 means precisely.
#define RIG_ORIG_MASK 0xFFFF000000000000ull
typedef struct {
    uint32_t  magic;
    uint32_t  producer;
    uint64_t  seq;
    uint64_t *tag; // GC-arena array; the worker checks every word
    uint64_t  tag_orig;
    uint64_t  probe;
    uint32_t  hops;
    uint32_t  pad;
} rig_job_t;

static struct {
    int  seconds;
    int  producers;
    int  workers;
    int  cap;
    int  garbage_kb;
    int  gc_ms;
    int  reenter_pct;
    int  hook_us;
    bool arena_pool;
} cfg;

static n00b_runtime_t     *g_rt;
static n00b_worker_pool_t *g_pool;
static _Atomic bool        g_stop;
static _Atomic uint64_t    g_produced;
static _Atomic uint64_t    g_completed;
static _Atomic uint64_t    g_reentered;
static _Atomic uint64_t    g_collects;
static _Atomic uint64_t    g_tag_moved;
static _Atomic uint64_t    g_probe_rewritten;

static int
env_int(const char *name, int dflt)
{
    const char *v = getenv(name);
    return (v != nullptr && v[0] != '\0') ? atoi(v) : dflt;
}

static inline uint64_t
tag_word(uint32_t producer, uint64_t seq, int i)
{
    return (seq * 0x9E3779B97F4A7C15ull) ^ ((uint64_t)producer << 56) ^ (uint64_t)i;
}

static void
describe(const char *what, const void *p)
{
    auto m = n00b_mmap_by_address((void *)p);
    if (n00b_option_is_set(m)) {
        n00b_mmap_info_t *info = n00b_option_get(m);
        fprintf(stderr, "  %s=%p kind=%d\n", what, p, (int)info->kind);
    }
    else {
        fprintf(stderr, "  %s=%p (unregistered)\n", what, p);
    }
}

static void
dump_job(const rig_job_t *job)
{
    const uint64_t *w = (const uint64_t *)job;
    for (int i = 0; i < (int)(sizeof(*job) / sizeof(uint64_t)); i++) {
        fprintf(stderr, "  job[%d]=%016llx", i, (unsigned long long)w[i]);
        // Does the word decode as an address the registry knows?
        auto m = n00b_mmap_by_address((void *)(uintptr_t)w[i]);
        if (n00b_option_is_set(m)) {
            fprintf(stderr, "  -> registered kind=%d", (int)n00b_option_get(m)->kind);
        }
        fprintf(stderr, "\n");
    }
}

static void
worker_fn(void *jobp, void *user_data)
{
    (void)user_data;
    rig_job_t *job = jobp;

    // Site: first read of the job message.
    if (job->magic != RIG_JOB_MAGIC) {
        fprintf(stderr, "rig: job magic %08x (want %08x)\n", job->magic, RIG_JOB_MAGIC);
        describe("job", job);
        dump_job(job);
        abort();
    }

    // Scan-mode oracle (see rig_job_t).
    {
        uint64_t orig = job->tag_orig ^ RIG_ORIG_MASK;
        if ((uint64_t)(uintptr_t)job->tag != orig) {
            atomic_fetch_add(&g_tag_moved, 1);
            if (job->probe == ((uint64_t)(uintptr_t)job->tag | 1)) {
                atomic_fetch_add(&g_probe_rewritten, 1);
            }
            else if (job->probe != (orig | 1)) {
                fprintf(stderr, "rig: probe neither old nor new: probe=%016llx tag=%p orig=%016llx\n",
                        (unsigned long long)job->probe, (void *)job->tag, (unsigned long long)orig);
                dump_job(job);
                abort();
            }
        }
    }

    // Site: pointer from a pool object into the arena, after N collections.
    for (int i = 0; i < RIG_TAG_WORDS; i++) {
        uint64_t want = tag_word(job->producer, job->seq, i);
        if (job->tag[i] != want) {
            fprintf(stderr,
                    "rig: tag[%d] mismatch producer=%u seq=%llu got=%016llx want=%016llx\n",
                    i,
                    job->producer,
                    (unsigned long long)job->seq,
                    (unsigned long long)job->tag[i],
                    (unsigned long long)want);
            describe("job", job);
            describe("tag", job->tag);
            abort();
        }
    }

    // Site: first write into a block just received from the default allocator.
    if (cfg.garbage_kb > 0) {
        size_t   n = (size_t)cfg.garbage_kb * 1024;
        uint8_t *g = n00b_alloc_array(uint8_t, n);
        volatile uint8_t *vg = g;
        vg[0]     = 0xA5;
        vg[n - 1] = 0x5A;
        if (vg[0] != 0xA5 || vg[n - 1] != 0x5A) {
            fprintf(stderr, "rig: fresh block readback failed\n");
            describe("block", g);
            abort();
        }
    }

    if (cfg.hook_us > 0) {
        usleep((useconds_t)cfg.hook_us);
    }

    // wax's re-entrant 5%: a worker resubmits its own job. Only when the ring
    // has headroom so two blocked workers cannot deadlock a full ring.
    if (cfg.reenter_pct > 0 && job->hops == 0 && !atomic_load(&g_stop)
        && (int)(job->seq % 100) < cfg.reenter_pct
        && n00b_worker_pool_pending(g_pool) < cfg.cap / 2) {
        job->hops++;
        atomic_fetch_add(&g_reentered, 1);
        n00b_worker_pool_submit(g_pool, job);
        return;
    }

    job->magic = RIG_JOB_DEAD;
    n00b_free(job);
    atomic_fetch_add(&g_completed, 1);
}

static void *
producer_main(void *arg)
{
    uint32_t          id  = (uint32_t)(uintptr_t)arg;
    uint64_t          seq = 0;
    n00b_allocator_t *up  = (n00b_allocator_t *)&g_rt->user_pool;

    while (!atomic_load(&g_stop)) {
        rig_job_t *job = n00b_alloc_with_opts(rig_job_t,
                                              &(n00b_alloc_opts_t){.allocator = up});
        uint64_t  *tag = n00b_alloc_array(uint64_t, RIG_TAG_WORDS);
        for (int i = 0; i < RIG_TAG_WORDS; i++) {
            tag[i] = tag_word(id, seq, i);
        }
        job->magic    = RIG_JOB_MAGIC;
        job->producer = id;
        job->seq      = seq;
        job->tag      = tag;
        job->tag_orig = (uint64_t)(uintptr_t)tag ^ RIG_ORIG_MASK;
        job->probe    = (uint64_t)(uintptr_t)tag | 1;
        job->hops     = 0;

        // Site: dispatcher `pool->queue[pool->tail] = job`.
        n00b_worker_pool_submit(g_pool, job);
        seq++;
        atomic_fetch_add(&g_produced, 1);
    }
    return nullptr;
}

static void *
collector_main(void *arg)
{
    (void)arg;
    while (!atomic_load(&g_stop)) {
        n00b_collect(g_rt->default_arena);
        atomic_fetch_add(&g_collects, 1);
        usleep((useconds_t)cfg.gc_ms * 1000);
    }
    return nullptr;
}

static void
tick(int t)
{
    n00b_mmap_registry_stats_t st = n00b_mmap_registry_stats();
    fprintf(stderr,
            "rig t=%3ds produced=%llu completed=%llu reentered=%llu collects=%llu "
            "pending=%d in_flight=%d | mmap pool_count=%llu pool_bytes=%.1fMB "
            "user_pool_mapped=%.1fMB\n",
            t,
            (unsigned long long)atomic_load(&g_produced),
            (unsigned long long)atomic_load(&g_completed),
            (unsigned long long)atomic_load(&g_reentered),
            (unsigned long long)atomic_load(&g_collects),
            n00b_worker_pool_pending(g_pool),
            n00b_worker_pool_in_flight(g_pool),
            (unsigned long long)st.pool_count,
            (double)st.pool_bytes / (1024.0 * 1024.0),
            (double)n00b_pool_mapped_bytes(&g_rt->user_pool) / (1024.0 * 1024.0));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);
    g_rt = n00b_get_runtime();

    cfg.seconds     = env_int("N00B_RIG_SECONDS", 20);
    cfg.producers   = env_int("N00B_RIG_PRODUCERS", 4);
    cfg.workers     = env_int("N00B_RIG_WORKERS", 2);
    cfg.cap         = env_int("N00B_RIG_CAP", 256);
    cfg.garbage_kb  = env_int("N00B_RIG_GARBAGE_KB", 256);
    cfg.gc_ms       = env_int("N00B_RIG_GC_MS", 150);
    cfg.reenter_pct = env_int("N00B_RIG_REENTER_PCT", 5);
    cfg.hook_us     = env_int("N00B_RIG_HOOK_US", 300);
    const char *pp  = getenv("N00B_RIG_POOL");
    cfg.arena_pool  = (pp != nullptr && strcmp(pp, "arena") == 0);

    // The allocation macros key the dictionary by the POINTER type's hash.
    fprintf(stderr,
            "rig gc: rig_job_t in type map=%s, pin-all=%s\n",
            n00b_gc_type_map_lookup(typehash(rig_job_t *)) != nullptr ? "yes" : "no",
            n00b_gc_pin_all_policy() ? "yes" : "no");
    fprintf(stderr,
            "rig start seconds=%d producers=%d workers=%d cap=%d garbage_kb=%d gc_ms=%d "
            "reenter_pct=%d hook_us=%d pool=%s\n",
            cfg.seconds,
            cfg.producers,
            cfg.workers,
            cfg.cap,
            cfg.garbage_kb,
            cfg.gc_ms,
            cfg.reenter_pct,
            cfg.hook_us,
            cfg.arena_pool ? "arena" : "user_pool");

    if (cfg.arena_pool) {
        // wax rocs_cache.c AI work pool: no .allocator, so the pool struct, its
        // ring, and the embedded work_cv all live in the moving GC arena.
        g_pool = n00b_worker_pool_new(cfg.workers, cfg.cap, worker_fn, nullptr);
    }
    else {
        // wax pipeline.c enrichment pool: everything in the non-moving user_pool.
        g_pool = n00b_worker_pool_new(cfg.workers,
                                      cfg.cap,
                                      worker_fn,
                                      nullptr,
                                      .allocator = (n00b_allocator_t *)&g_rt->user_pool);
    }
    n00b_require(g_pool != nullptr, "worker pool creation failed");

    n00b_thread_t **producers = n00b_alloc_array_with_opts(
        n00b_thread_t *,
        cfg.producers,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)&g_rt->user_pool});
    for (int i = 0; i < cfg.producers; i++) {
        auto r = n00b_thread_spawn(producer_main, (void *)(uintptr_t)i);
        n00b_require(n00b_result_is_ok(r), "producer spawn failed");
        producers[i] = n00b_result_get(r);
    }

    n00b_thread_t *collector = nullptr;
    if (cfg.gc_ms > 0) {
        auto r = n00b_thread_spawn(collector_main, nullptr);
        n00b_require(n00b_result_is_ok(r), "collector spawn failed");
        collector = n00b_result_get(r);
    }

    for (int t = 1; t <= cfg.seconds; t++) {
        sleep(1);
        tick(t);
    }

    atomic_store(&g_stop, true);
    for (int i = 0; i < cfg.producers; i++) {
        n00b_thread_join(producers[i]);
    }
    if (collector != nullptr) {
        n00b_thread_join(collector);
    }
    n00b_worker_pool_shutdown(g_pool);
    tick(cfg.seconds);

    uint64_t produced  = atomic_load(&g_produced);
    uint64_t completed = atomic_load(&g_completed);
    if (produced != completed) {
        fprintf(stderr, "rig: produced=%llu completed=%llu after drain\n",
                (unsigned long long)produced, (unsigned long long)completed);
        abort();
    }
    fprintf(stderr,
            "rig oracle: tag_moved=%llu probe_rewritten=%llu (rewritten==moved means "
            "user_pool objects are scanned conservatively and rewritten)\n",
            (unsigned long long)atomic_load(&g_tag_moved),
            (unsigned long long)atomic_load(&g_probe_rewritten));
    printf("  [PASS] worker_pool_collector_rig (%llu jobs, %llu collects)\n",
           (unsigned long long)completed,
           (unsigned long long)atomic_load(&g_collects));
    n00b_shutdown();
    return 0;
}
