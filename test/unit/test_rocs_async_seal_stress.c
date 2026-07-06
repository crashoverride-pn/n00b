/* test/unit/test_rocs_async_seal_stress.c - concurrency stress for the async
 * seal path (keep_standby = true).
 *
 * The async seal hands a detached, large hot shard to a dedicated seal-worker
 * THREAD, which marshals it lock-free (Phase 2) while the ingest thread keeps
 * rotating new hot shards.  A full static thread-safety audit of that path came
 * back clean (pools are spinlock-guarded, hidden-pool objects are never moved
 * by the copying collector so Phase 2's raw pointers survive STW, the VFS uses
 * per-handle buffers, and catalog/standby/counters are commit_lock-guarded).
 *
 * This test exists to PROVE that empirically and to be a regression guard: it
 * drives the exact race window that a real bug would live in --
 *
 *   1. large records => each shard is ~12 MB, so the worker's marshal takes
 *      real wall-clock time (it is genuinely mid-marshal, not instantaneous);
 *   2. a small max_records => the ingest thread rotates constantly, so a new
 *      seal is handed off while the previous one may still be marshaling;
 *   3. forced n00b_collect() STW from the ingest thread on almost every record
 *      => the GC repeatedly suspends, scans, and resumes the seal worker WHILE
 *      it walks the detached shard's pool objects with raw pointers;
 *   4. several store lifecycles back to back, to shake out teardown-vs-inflight
 *      races in the seal-pool barrier/shutdown path.
 *
 * Invariants: the process must not corrupt the heap (any wild write from the
 * worker would crash at a random alloc/hash/list site under this GC pressure),
 * and after flush() every ingested record must be accounted for in a sealed
 * shard (a dropped async seal shows up as a short sealed_records count).  The
 * async result must match the inline path exactly.
 */

#include <stdint.h>
#include <stdlib.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/gc.h"
#include "text/strings/string_ops.h"
#include "conduit/print.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

static n00b_vfs_t *
new_memory_vfs(void)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));

    CHECK(n00b_result_is_ok(n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0)));
    return vfs;
}

static n00b_store_schema_t *
make_schema(void)
{
    n00b_store_schema_t *schema = n00b_result_get(n00b_store_schema_new());
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"term",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    return schema;
}

static n00b_string_t *g_payload = nullptr; // ~256 KB, reused across records

// Ablation toggles (env): isolate which variable triggers the corruption.
//   STRESS_COLLECT=0  -> do NOT force n00b_collect from the ingest thread.
//   STRESS_BIG=0      -> small records + large max_records => marshal is fast,
//                        so the worker never overlaps the next rotation.
static bool g_force_collect = true;
static bool g_big           = true;

static n00b_json_node_t *
make_big_record(int64_t i)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_string_t    *term   = n00b_cformat("term-[|#|]", (int64_t)(i & 0xff));
    n00b_json_object_put_n00b(record,
                              r"term",
                              n00b_json_string_new_from_n00b(term));
    if (g_big) {
        n00b_json_object_put_n00b(record,
                                  r"payload",
                                  n00b_json_string_new_from_n00b(g_payload));
    }
    return record;
}

// Drive one store through a heavy rotate-while-marshaling + STW workload.
// Returns the sealed-record count after flush.
static uint64_t
stress_one_store(n00b_runtime_t *rt, bool keep_standby, int64_t records)
{
    // ~48 records/shard * 256 KB ~= 12 MB shards: big enough that the marshal
    // is genuinely in flight when the next rotation and the forced collect land.
    // With g_big=false, tiny records + a huge max_records make the marshal
    // instantaneous (no overlap window).
    auto seal_r = n00b_store_seal_policy_new(.max_records = g_big ? 48 : 4096);
    CHECK(n00b_result_is_ok(seal_r));

    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       make_schema(),
                                       .seal_policy  = n00b_result_get(seal_r),
                                       .keep_standby = keep_standby);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    for (int64_t i = 0; i < records; i++) {
        auto ing_r = n00b_store_ingest(store, make_big_record(i));
        CHECK(n00b_result_is_ok(ing_r));

        // Pound the GC from the ingest thread so STW repeatedly suspends and
        // resumes the seal worker WHILE it is marshaling a detached shard.
        // Allocate a wad of garbage first so the collect has real work (root
        // scan + sweep) overlapping the worker's pointer walk.
        if (g_force_collect) {
            for (int j = 0; j < 64; j++) {
                (void)n00b_cformat("async-seal-stress garbage [|#|]:[|#|]",
                                   (int64_t)i,
                                   (int64_t)j);
            }
            n00b_collect(rt->default_arena);
        }
    }

    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);

    // No record may be lost or stranded in the hot shard after flush.
    CHECK(stats.hot_record_count == 0);
    CHECK(stats.sealed_records == (uint64_t)records);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
    return stats.sealed_records;
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    const char *envc = getenv("STRESS_COLLECT");
    const char *envb = getenv("STRESS_BIG");
    if (envc != nullptr && envc[0] == '0') {
        g_force_collect = false;
    }
    if (envb != nullptr && envb[0] == '0') {
        g_big = false;
    }
    n00b_eprintf("config: force_collect=[|#|] big=[|#|]\n",
                 (int64_t)g_force_collect,
                 (int64_t)g_big);

    g_payload = n00b_unicode_str_repeat(r"a", 128u << 10); // 128 KB

    const int64_t records    = 192;
    const int     lifecycles = 2;

    uint64_t inline_total = 0;
    uint64_t async_total  = 0;

    for (int k = 0; k < lifecycles; k++) {
        async_total  += stress_one_store(&rt, true, records);
        inline_total += stress_one_store(&rt, false, records);
        n00b_eprintf("  [lifecycle [|#|]] async + inline clean\n", (int64_t)k);
    }

    // Parity: the async path seals exactly what the inline path does.
    CHECK(async_total == inline_total);
    CHECK(async_total == (uint64_t)records * (uint64_t)lifecycles);

    n00b_eprintf("test_rocs_async_seal_stress OK: lifecycles=[|#|] "
                 "records/life=[|#|] sealed=[|#|]\n",
                 (int64_t)lifecycles,
                 records,
                 (int64_t)async_total);

    n00b_shutdown();
    return 0;
}
