/* test/unit/test_rocs_large_shard_seal.c - regression for seal status-5 on
 * large shards.
 *
 * The hot shard pool is hidden + inline-header + non-metadata, so the marshal
 * scans the shard graph CONSERVATIVELY (every word treated as a possible
 * pointer).  Once a shard's scalar `byte_estimate` grows into the
 * plausible-pointer range (tens of MB), the conservative scan misreads it as a
 * static pointer, fails the seal with status-5, and the WHOLE shard's records
 * are dropped.  Small shards never hit this (byte_estimate stays a small
 * scalar), which is why only large, busy shards lose data in production.
 *
 * Deterministic repro: ingest large records so a single shard exceeds ~80 MB,
 * seal it on the inline path, and require zero record loss.  Pre-fix this fails
 * (sealed_records short); post-fix it must seal every record.
 */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "conduit/print.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>

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
make_schema(void)
{
    n00b_store_schema_t *schema = n00b_result_get(n00b_store_schema_new());
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"term",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    return schema;
}

static n00b_string_t *g_payload = nullptr; // ~1 MB, reused across records

static n00b_json_node_t *
make_big_record(int64_t i)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_string_t    *term   = n00b_cformat("term-[|#|]", (int64_t)(i & 0xff));
    n00b_json_object_put_n00b(record,
                              r"term",
                              n00b_json_string_new_from_n00b(term));
    // A large, non-indexed field pushes the shard's record-text byte_estimate
    // into the range the conservative marshal scan misreads.
    n00b_json_object_put_n00b(record,
                              r"payload",
                              n00b_json_string_new_from_n00b(g_payload));
    return record;
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    // ~1 MB per record * 80 records => ~80 MB byte_estimate in one shard, well
    // inside the range the conservative scan misreads as a pointer.
    g_payload = n00b_unicode_str_repeat(r"a", 1u << 20);

    const int64_t        N      = 80;
    n00b_store_schema_t *schema = make_schema();

    auto seal_r = n00b_store_seal_policy_new(.max_records = (uint64_t)N);
    CHECK(n00b_result_is_ok(seal_r));

    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       schema,
                                       .seal_policy  = n00b_result_get(seal_r),
                                       .keep_standby = false);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    for (int64_t i = 0; i < N; i++) {
        auto ing_r = n00b_store_ingest(store, make_big_record(i));
        CHECK(n00b_result_is_ok(ing_r));
    }

    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto stats_r = n00b_store_memory_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    n00b_store_memory_stats_t stats = n00b_result_get(stats_r);

    n00b_eprintf("large-shard seal: ingested=[|#|] sealed_records=[|#|] "
                 "sealed_shards=[|#|] sealed_max_bytes=[|#|] hot_left=[|#|]\n",
                 N,
                 (int64_t)stats.sealed_records,
                 (int64_t)stats.sealed_shards,
                 (int64_t)stats.sealed_max_bytes,
                 (int64_t)stats.hot_record_count);

    // The bug: the big shard's byte_estimate is misread -> status-5 -> the
    // shard is dropped -> sealed_records is short of N.
    CHECK(stats.hot_record_count == 0);
    CHECK(stats.sealed_records == (uint64_t)N);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    n00b_eprintf("test_rocs_large_shard_seal OK\n");
    return 0;
}
