/*
 * Concurrent ingest into a dense posting list.
 *
 * A dense field keeps membership as a bitmap rather than an ordinal list, and
 * rocs picks that for the low-cardinality fields every record carries:
 * `kind`, `class`, `schema`, `source.family` in the wax schema. So two threads
 * ingesting into one shard write the same bitmap, and record ordinals that
 * arrive together share a 64-bit word.
 *
 * Setting a bit is a read-modify-write of that word, and growing the bitmap
 * reallocates it, so both run under the flag set's write lock. Two writers
 * take alternating ordinals here, so every pair of them lands in one word,
 * which is the arrangement an unguarded read-modify-write loses a bit in.
 *
 * The check is on membership, not on a report: every ordinal that was added
 * has to be found.
 */

#define __N00B_THREAD_INTERNAL

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/index.h"
#include "rocs_test_support.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

// Enough to span many words and to force several bitmap growths, which start
// at 64 bits.
#define ROWS    UINT64_C(4096)
#define WRITERS 2

typedef struct {
    n00b_store_shard_t *shard;
    n00b_store_index_t *index;
    _Atomic(bool)      *start;
    uint64_t            first;   // this writer's phase: first, first+WRITERS, ...
} writer_arg_t;

static void *
dense_writer(void *raw)
{
    writer_arg_t *arg = (writer_arg_t *)raw;

    while (!atomic_load(arg->start)) {
        ;
    }
    for (uint64_t ord = arg->first; ord < ROWS; ord += WRITERS) {
        CHECK(n00b_result_is_ok(
            n00b_store_index_add(arg->index, arg->shard, ord)));
    }
    return nullptr;
}

static void
test_dense_ingest_from_two_threads(void)
{
    auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0xDE05),
                                        .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));
    n00b_store_shard_t *shard = n00b_result_get(shard_r);

    auto index_r = n00b_store_index_new(r"kind",
                                        N00B_STORE_INDEX_TERM,
                                        .postings = N00B_STORE_POSTINGS_DENSE);
    CHECK(n00b_result_is_ok(index_r));
    n00b_store_index_t *index = n00b_result_get(index_r);

    // One value across every record, so all of them land in one posting list.
    for (uint64_t i = 0; i < ROWS; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        n00b_json_object_put_n00b(rec,
                                  r"kind",
                                  n00b_json_string_new_from_n00b(r"log"));
        CHECK(n00b_result_is_ok(n00b_store_shard_append(shard, rec)));
    }

    _Atomic(bool)  start = false;
    writer_arg_t   args[WRITERS];
    n00b_thread_t *workers[WRITERS];

    for (int i = 0; i < WRITERS; i++) {
        args[i]  = (writer_arg_t){.shard = shard,
                                  .index = index,
                                  .start = &start,
                                  .first = (uint64_t)i};
        auto t_r = n00b_thread_spawn(dense_writer, &args[i]);
        CHECK(n00b_result_is_ok(t_r));
        workers[i] = n00b_result_get(t_r);
    }
    atomic_store(&start, true);
    for (int i = 0; i < WRITERS; i++) {
        n00b_thread_join(workers[i]);
    }

    // Every ordinal was added by exactly one writer and none was removed, so
    // every one of them is a member.
    auto probe_r = n00b_store_index_probe_hot(index,
                                              shard,
                                              n00b_json_string_new_from_n00b(r"log"));
    CHECK(n00b_result_is_ok(probe_r));
    n00b_store_index_probe_t *probe = n00b_result_get(probe_r);

    uint64_t missing = 0;
    uint64_t first_missing = UINT64_MAX;
    for (uint64_t ord = 0; ord < ROWS; ord++) {
        auto has_r = n00b_store_index_probe_contains(probe, ord);
        CHECK(n00b_result_is_ok(has_r));
        if (!n00b_result_get(has_r)) {
            if (first_missing == UINT64_MAX) {
                first_missing = ord;
            }
            missing++;
        }
    }

    n00b_printf("  «#» of «#» ordinals missing",
                (int64_t)missing,
                (int64_t)ROWS);
    if (missing != 0) {
        n00b_printf("  first missing ordinal: «#»", (int64_t)first_missing);
    }

    CHECK(missing == 0);
    n00b_printf("  [PASS] two writers into one dense posting list lose nothing");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_dense_ingest_from_two_threads();

    n00b_shutdown();
    return 0;
}
