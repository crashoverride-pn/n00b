/* test/unit/test_rocs_seal_bench.c
 *
 * Perf check for the marshal home-allocator fast path in scan_node
 * (src/util/marshal.c).  Sealing a hot shard marshals the entire shard graph;
 * before the fast path every pointer paid two global mmap interval-tree
 * searches + a header scan, so a large shard stalled for tens of seconds
 * (observed live: a ~79k-record crayon-gw shard never finished sealing).  With
 * the fast path, home-pool pointers resolve via the pool's O(1) OOB index, so a
 * large seal must complete quickly.  This times the seal of an N-record shard.
 */

#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/atomic.h"
#include "core/runtime.h"
#include "core/time.h"
#include "text/strings/format.h"
#include "conduit/print.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "bench check failed: " #expr);                   \
    } while (0)

static n00b_vfs_t *
new_memory_vfs(void)
{
    n00b_vfs_t *vfs  = n00b_result_get(n00b_vfs_new());
    auto        be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));
    CHECK(n00b_result_is_ok(
        n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0)));
    return vfs;
}

static n00b_store_schema_t *
bench_schema(void)
{
    n00b_store_schema_t *schema = n00b_result_get(n00b_store_schema_new());
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"term",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    return schema;
}

static n00b_store_record_list_t *
record_list_new(void)
{
    n00b_store_record_list_t *records = n00b_alloc(n00b_store_record_list_t);
    *records = n00b_list_new_private(n00b_json_node_t *,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return records;
}

static n00b_json_node_t *
bench_record(int64_t i)
{
    // ~256 distinct terms => posting lists with many ordinals each, mirroring a
    // real hot shard's high-cardinality posting structure (lots of pointers for
    // scan_node to resolve).
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_string_t    *term   = n00b_cformat("term-[|#|]", (int64_t)(i & 0xff));
    n00b_json_object_put_n00b(record,
                              r"term",
                              n00b_json_string_new_from_n00b(term));
    return record;
}

static void
bench_seal(int64_t n)
{
    n00b_store_schema_t *schema = bench_schema();
    // Default (nullptr) seal policy never auto-seals, so all N records land in
    // one hot shard and we force the seal ourselves.  No partition policy =>
    // single "default" route => single shard.
    n00b_store_t *store = n00b_result_get(
        n00b_store_open_vfs(new_memory_vfs(), r"/rocs", schema));

    n00b_store_record_list_t *records = record_list_new();
    for (int64_t i = 0; i < n; i++) {
        n00b_list_push(*records, bench_record(i));
    }

    auto batch_r = n00b_store_ingest_batch(store,
                                           records,
                                           .worker_count   = 2,
                                           .queue_capacity = 256);
    CHECK(n00b_result_is_ok(batch_r));

    int64_t t0     = n00b_ns_timestamp();
    auto    seal_r = n00b_store_seal_hot_shard(store);
    int64_t t1     = n00b_ns_timestamp();
    CHECK(n00b_result_is_ok(seal_r));

    n00b_eprintf("BENCH seal of [|#|] records: [|#|] ms\n",
                 n,
                 (int64_t)((t1 - t0) / 1000000));
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    bench_seal(20000);
    bench_seal(80000);

    return 0;
}
