/*
 * What indexing a record costs, per index kind and per arrival order.
 *
 * Posting lists carry a maintained count, they are ordered on demand rather
 * than on arrival, and sealing sorts what reaches it. Each of those trades
 * work between ingest, seal and query, so each stage is timed separately;
 * one total would hide which way a trade went.
 *
 * Registered as a test at a small size, where what it checks is that every
 * workload still indexes and seals what it claims to. Run the binary directly
 * for the timings.
 */

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/index.h"
#include "rocs_test_support.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "ingest bench check failed: " #expr);              \
    } while (0)

static uint64_t records = 4096;

static uint64_t
env_u64(const char *name, uint64_t fallback)
{
    const char *v = getenv(name);
    if (v == nullptr || *v == '\0') {
        return fallback;
    }
    return (uint64_t)strtoull(v, nullptr, 10);
}

static int64_t
now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * INT64_C(1000000) + (int64_t)ts.tv_nsec / 1000;
}

// One shard of `records` rows. `distinct` controls how many values the term
// field takes: 1 puts every row in one posting list, `records` gives each its
// own. Posting-list length is what every write-path cost here scales with.
static n00b_store_shard_t *
shard_of(uint64_t id, uint64_t distinct, n00b_string_t *text)
{
    auto r = n00b_store_shard_new(.shard_id  = id,
                                  .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(r));
    n00b_store_shard_t *shard = n00b_result_get(r);

    for (uint64_t i = 0; i < records; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        n00b_json_object_put_n00b(
            rec,
            r"kind",
            n00b_json_string_new_from_n00b(
                n00b_cformat("k«#»", (int64_t)(i % distinct))));
        n00b_json_object_put_n00b(rec,
                                  r"message",
                                  n00b_json_string_new_from_n00b(text));
        CHECK(n00b_result_is_ok(n00b_store_shard_append(shard, rec)));
    }
    return shard;
}

typedef enum {
    ORDER_ASCENDING = 0,
    ORDER_DESCENDING,
    ORDER_INTERLEAVED,
} arrival_t;

static n00b_string_t *
arrival_name(arrival_t a)
{
    switch (a) {
    case ORDER_ASCENDING:
        return r"ascending  ";
    case ORDER_DESCENDING:
        return r"descending ";
    default:
        return r"interleaved";
    }
}

static void
workload(n00b_string_t          *label,
         n00b_store_index_kind_t kind,
         uint64_t                distinct,
         n00b_string_t          *text,
         arrival_t               arrival,
         uint64_t                id)
{
    n00b_store_shard_t *shard = shard_of(id, distinct, text);
    n00b_string_t      *field = kind == N00B_STORE_INDEX_TERM ? r"kind"
                                                              : r"message";
    n00b_store_index_t *index = index_of(field, kind);

    int64_t start = now_us();
    switch (arrival) {
    case ORDER_ASCENDING:
        for (uint64_t i = 0; i < records; i++) {
            CHECK(n00b_result_is_ok(n00b_store_index_add(index, shard, i)));
        }
        break;
    case ORDER_DESCENDING:
        for (uint64_t i = records; i > 0; i--) {
            CHECK(n00b_result_is_ok(
                n00b_store_index_add(index, shard, i - 1)));
        }
        break;
    default:
        // Odds then evens: no posting list sees a rising run.
        for (uint64_t pass = 0; pass < 2; pass++) {
            for (uint64_t i = pass == 0 ? 1 : 0; i < records; i += 2) {
                CHECK(n00b_result_is_ok(
                    n00b_store_index_add(index, shard, i)));
            }
        }
        break;
    }
    int64_t index_us = now_us() - start;

    // Sealing is where an unordered list is sorted, so the cost the index
    // loop saved has to be looked for here rather than assumed away.
    start = now_us();
    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 99,
                                        .base_address = 0x40000u);
    CHECK(n00b_result_is_ok(seal_r));
    int64_t seal_us = now_us() - start;

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    // A count read off the sealed image, which is what a planner asks for.
    n00b_json_node_t *probe = n00b_json_string_new_from_n00b(
        kind == N00B_STORE_INDEX_TERM ? r"k0" : r"error");
    start = now_us();
    uint64_t df = 0;
    for (int i = 0; i < 64; i++) {
        auto df_r = n00b_store_index_df_mapped(index,
                                               n00b_result_get(root_r),
                                               probe);
        if (n00b_result_is_ok(df_r)) {
            df = n00b_result_get(df_r);
        }
    }
    int64_t df_us = now_us() - start;

    n00b_printf("  «#» «#»  index «#»us  seal «#»us  df/64 «#»us  df=«#»",
                label,
                arrival_name(arrival),
                (int64_t)index_us,
                (int64_t)seal_us,
                (int64_t)df_us,
                (int64_t)df);

    CHECK(n00b_result_is_ok(n00b_store_map_close(n00b_result_get(map_r))));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    records = env_u64("ROCS_BENCH_RECORDS", 4096);
    CHECK(records >= 16);

    n00b_printf("rocs ingest bench, «#» records", (int64_t)records);

    // One posting list holding every row: the length every per-push cost
    // scales with, and the shape a common term takes.
    workload(r"term  one-value  ", N00B_STORE_INDEX_TERM, 1,
             r"an error opening the log", ORDER_ASCENDING, 0x1001);
    workload(r"term  one-value  ", N00B_STORE_INDEX_TERM, 1,
             r"an error opening the log", ORDER_DESCENDING, 0x1002);
    workload(r"term  one-value  ", N00B_STORE_INDEX_TERM, 1,
             r"an error opening the log", ORDER_INTERLEAVED, 0x1003);

    // Every row its own value: many short lists instead of one long one.
    workload(r"term  all-distinct", N00B_STORE_INDEX_TERM, records,
             r"an error opening the log", ORDER_ASCENDING, 0x1004);

    // Full text, where one record contributes the same term more than once
    // and the posting list is unique-keyed.
    workload(r"fulltext repeated ", N00B_STORE_INDEX_FULLTEXT, 1,
             r"error error error opening the error log", ORDER_ASCENDING,
             0x1005);
    workload(r"fulltext repeated ", N00B_STORE_INDEX_FULLTEXT, 1,
             r"error error error opening the error log", ORDER_DESCENDING,
             0x1006);

    // N-grams: the widest expansion per record in the system.
    workload(r"ngram             ", N00B_STORE_INDEX_NGRAM, 1,
             r"an error opening the log", ORDER_ASCENDING, 0x1007);

    n00b_shutdown();
    return 0;
}
