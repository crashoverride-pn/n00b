/* test/unit/test_rocs_term_summary.c - n00b#359: proving a TERM value absent
 * must not map every sealed shard in the catalog.
 *
 * Each sealed shard's catalog entry now carries, per TERM-indexed field, the
 * set of column keys (normalized-term hashes) present in that shard, written at
 * seal (catalog format v4). The planner consults it before mapping: a TERM
 * equality whose keys are absent from a shard skips the map entirely.
 *
 * Measured on a 261-shard store before this: a present value cost 0 maps and a
 * value absent from the store cost 261 maps / 32 GB / 110 ms to return nothing.
 * The counter under test is the residency cache's miss count, which is exactly
 * "shards mapped on demand".
 */
#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "rocs/filter.h"
#include "rocs/query.h"
#include "rocs/store.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
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
schema_with_term_kind(void)
{
    n00b_store_schema_t *schema = n00b_result_get(n00b_store_schema_new());
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema,
                                                        r"kind",
                                                        .index_kind = N00B_STORE_INDEX_TERM)));
    return schema;
}

static n00b_store_t *
open_store(n00b_vfs_t *vfs)
{
    auto store_r = n00b_store_open_vfs(vfs, r"/rocs", schema_with_term_kind());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static void
ingest_kind(n00b_store_t *store, const char *kind, int64_t id)
{
    n00b_json_node_t *rec = n00b_json_object_new();
    n00b_json_object_put(rec, "id", n00b_json_int_new(id));
    n00b_json_object_put(rec, "kind", n00b_json_string_new(kind));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, rec)));
}

static void
seal(n00b_store_t *store, uint64_t ts)
{
    CHECK(n00b_result_is_ok(n00b_store_seal_hot_shard(store, .seal_ts = ts)));
}

static uint64_t
misses(n00b_store_t *store)
{
    auto r = n00b_store_residency_stats(store);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r).cache_misses;
}

static uint64_t
count_kind(n00b_store_t *store, const char *kind)
{
    auto field_r = n00b_filter_field(r"kind");
    CHECK(n00b_result_is_ok(field_r));
    auto filter_r = n00b_filter_eq(n00b_result_get(field_r),
                                   n00b_fv_utf8(n00b_string_from_cstr(kind)));
    CHECK(n00b_result_is_ok(filter_r));
    auto query_r = n00b_query_new(n00b_result_get(filter_r), .limit = 1000);
    CHECK(n00b_result_is_ok(query_r));
    auto result_r = n00b_query_run(store, n00b_result_get(query_r));
    CHECK(n00b_result_is_ok(result_r));
    n00b_query_result_t *result = n00b_result_get(result_r);
    uint64_t             n      = n00b_query_count(result);
    (void)n00b_query_result_close(result);
    return n;
}

// Every sealed shard non-resident: n00b_store_residency_trim is a no-op
// without a byte cap in the policy, so reopen the store instead. Each
// reopen also re-reads the catalog from disk, exercising the v4 round trip.
static n00b_store_t *
reopened(n00b_vfs_t *vfs, n00b_store_t *store)
{
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
    return open_store(vfs);
}

static void
test_absent_term_maps_no_shards(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = open_store(vfs);

    // Three sealed shards: two hold proc.exec, one holds file.modify; none
    // holds ai.exec. Plus an empty hot shard.
    ingest_kind(store, "proc.exec", 1);
    ingest_kind(store, "proc.exec", 2);
    seal(store, 1000);
    ingest_kind(store, "file.modify", 3);
    seal(store, 2000);
    ingest_kind(store, "proc.exec", 4);
    seal(store, 3000);

    // Every query below starts from a fresh open: no shard resident, catalog
    // entries (and their summaries) read back from disk.
    store = reopened(vfs, store);

    // Present in two shards: exactly those two are mapped.
    uint64_t before = misses(store);
    CHECK(count_kind(store, "proc.exec") == 3);
    uint64_t proc_maps = misses(store) - before;
    CHECK(proc_maps == 2);

    store  = reopened(vfs, store);
    before = misses(store);
    CHECK(count_kind(store, "file.modify") == 1);
    CHECK(misses(store) - before == 1);

    // Absent everywhere: correct empty answer and NO shard mapped. This is
    // the #359 case; before, it mapped all three.
    store  = reopened(vfs, store);
    before = misses(store);
    CHECK(count_kind(store, "ai.exec") == 0);
    uint64_t absent_maps = misses(store) - before;
    CHECK(absent_maps == 0);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
    n00b_eprintf("  [PASS] absent_term_maps_no_shards (present=[|#:d|] maps, absent=[|#:d|] maps)\n",
                 (int64_t)proc_maps,
                 (int64_t)absent_maps);
}

static void
test_v3_catalog_without_summary_still_maps(void)
{
    // A catalog written before v4 has no summaries: the planner must map as
    // before (correct, just not cheap). Simulated by clearing the summary on
    // the in-memory entries is not possible from the public API, so this
    // checks the weaker public contract: an entry with no summary for the
    // field answers "may contain".
    CHECK(n00b_store_catalog_entry_may_contain_term(nullptr, r"kind", nullptr, 0));
    n00b_eprintf("  [PASS] v3_catalog_without_summary_still_maps\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);
    printf("test_rocs_term_summary:\n");
    test_absent_term_maps_no_shards();
    test_v3_catalog_without_summary_still_maps();
    n00b_shutdown();
    return 0;
}
