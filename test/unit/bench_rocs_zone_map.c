/* test/unit/bench_rocs_zone_map.c - what zone maps cost.
 *
 * Two numbers were argued for rather than measured when zone maps landed, and
 * both are on paths where being wrong is expensive:
 *
 *   1. Catalog bytes. Bounds are catalog metadata and the catalog is parsed
 *      whole at open, so the cost is paid on every open of every store, by
 *      every reader, forever.
 *   2. Ingest time. Folding a record's values into the shard's bounds is one
 *      dict lookup per declared field per record, on the hot path.
 *
 * This reports both against a real store rather than from the shape of the
 * encoding. It prints rather than asserting a threshold: a machine-dependent
 * number turned into a pass/fail gate fails on somebody else's laptop, and the
 * point here is to know the number.
 */

#include <stdint.h>
#include <stdlib.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/store.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "bench check failed: " #expr);                    \
    } while (0)

// Sizes, overridable so the same binary can run as a cheap correctness check
// and as a measurement.
//
// Registered as a test at the small sizes, which is what keeps it compiling
// and keeps the workload doing what it claims; run it directly for numbers
// worth quoting. Same arrangement as bench_rocs_ingest.
static uint64_t
env_u64(const char *name, uint64_t fallback)
{
    const char *v = getenv(name);
    if (v == nullptr || *v == '\0') {
        return fallback;
    }
    return (uint64_t)strtoull(v, nullptr, 10);
}

#define RECORDS_PER_SHARD 50
// Short runs, many rounds.
//
// A busy machine makes a long run useless: its total says more about what else
// was running than about ingest. A short run has a real chance of landing in a
// quiet slice, and the minimum over many of them is the closest thing to an
// uninterrupted measurement. Interference only ever adds time, so the minimum
// is a bound the true cost sits at or below, never above.

static uint64_t shards         = 200;
static uint64_t ingest_records = 2000;
static uint64_t bench_rounds   = 40;

static n00b_vfs_t *
new_memory_vfs(void)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));
    CHECK(n00b_result_is_ok(
        n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0)));
    return vfs;
}

// `fields` declared fields, each of which a record carries, so each gets an
// interval on every shard.
static n00b_store_t *
open_store(n00b_vfs_t *vfs, uint64_t fields)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);

    for (uint64_t f = 0; f < fields; f++) {
        CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
            schema,
            n00b_cformat("field_«#»", (int64_t)f))));
    }

    auto store_r = n00b_store_open_vfs(vfs, r"/rocs", schema);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_with(uint64_t fields, int64_t seed)
{
    n00b_json_node_t *record = n00b_json_object_new();
    for (uint64_t f = 0; f < fields; f++) {
        n00b_json_object_put_n00b(record,
                                  n00b_cformat("field_«#»", (int64_t)f),
                                  n00b_json_int_new(seed + (int64_t)f));
    }
    return record;
}

static uint64_t
catalog_bytes(n00b_vfs_t *vfs)
{
    auto stat_r = n00b_vfs_stat(vfs, r"/rocs/catalog.rocs");
    if (n00b_result_is_err(stat_r)) {
        return 0;
    }
    return (uint64_t)n00b_result_get(stat_r).size;
}

static void
bench_catalog_growth(void)
{
    n00b_printf("catalog bytes, [|#|] sealed shards:", (int64_t)shards);

    uint64_t widths[] = {0, 1, 4, 16};
    for (uint64_t w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
        uint64_t     fields = widths[w];
        n00b_vfs_t   *vfs   = new_memory_vfs();
        n00b_store_t *store = open_store(vfs, fields);

        for (uint64_t sh = 0; sh < shards; sh++) {
            for (uint64_t r = 0; r < 4; r++) {
                CHECK(n00b_result_is_ok(n00b_store_ingest(
                    store,
                    record_with(fields, (int64_t)(sh * 100 + r)))));
            }
            CHECK(n00b_result_is_ok(
                n00b_store_seal_hot_shard(store, .seal_ts = 1000 + sh)));
        }

        uint64_t bytes = catalog_bytes(vfs);
        n00b_printf("  [|#|] fields: [|#|] bytes total, [|#|] per shard",
                    (int64_t)fields,
                    (int64_t)bytes,
                    (int64_t)(bytes / shards));
        CHECK(n00b_result_is_ok(n00b_store_close(store)));
    }
}

// One ingest run, in nanoseconds per record.
static int64_t
ingest_run(uint64_t fields, bool zones)
{
    n00b_store_zone_maps_set_enabled(zones);

    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = open_store(vfs, fields);

    // Records built up front, so the loop measures ingest rather than JSON
    // construction.
    n00b_json_node_t **records = n00b_alloc_array(n00b_json_node_t *,
                                                  ingest_records);
    for (uint64_t i = 0; i < ingest_records; i++) {
        records[i] = record_with(fields, (int64_t)i);
    }

    int64_t start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < ingest_records; i++) {
        CHECK(n00b_result_is_ok(n00b_store_ingest(store, records[i])));
    }
    int64_t elapsed = n00b_ns_timestamp() - start;

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
    return elapsed / ingest_records;
}

// Both arms in one process, alternating, reporting the minimum of each.
//
// A rebuild-and-compare cannot measure this: between two runs of the same
// binary this machine drifts by more than the bounds cost, which shows up as
// the zero-field arm -- where the observer does nothing at all -- appearing to
// differ. Alternating inside one process cancels the drift, and the zero-field
// row stays as the control that says so.
static void
bench_ingest_cost(void)
{
    n00b_printf("ingest, [|#|] records, min of [|#|] alternating rounds:",
                (int64_t)ingest_records,
                (int64_t)bench_rounds);

    uint64_t widths[] = {0, 1, 4, 16};
    for (uint64_t w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
        uint64_t fields   = widths[w];
        int64_t  best_on  = INT64_MAX;
        int64_t  best_off = INT64_MAX;

        for (uint64_t round = 0; round < bench_rounds; round++) {
            int64_t off = ingest_run(fields, false);
            int64_t on  = ingest_run(fields, true);
            if (off < best_off) {
                best_off = off;
            }
            if (on < best_on) {
                best_on = on;
            }
        }

        n00b_printf(
            "  [|#|] fields: off [|#|] ns, on [|#|] ns, delta [|#|] ns/record",
            (int64_t)fields,
            best_off,
            best_on,
            best_on - best_off);
    }

    n00b_store_zone_maps_set_enabled(true);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    shards         = env_u64("ROCS_BENCH_SHARDS", 200);
    ingest_records = env_u64("ROCS_BENCH_RECORDS", 2000);
    bench_rounds   = env_u64("ROCS_BENCH_ROUNDS", 40);

    bench_catalog_growth();
    bench_ingest_cost();

    n00b_shutdown();
    return 0;
}
